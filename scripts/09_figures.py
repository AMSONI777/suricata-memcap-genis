"""Figures and summary tables for the final report.

Reads results/retention_all.csv, results/runs_summary.csv and results/separate_limits.csv (all written by
earlier scripts) and writes PNG figures to figures/ and summary tables to results/. It does not read eve.json,
so it runs in a few seconds and can be re-run after any new batch.

A run counts as "lost alerts" when its retention is below 99.9 %. The largest run-to-run difference between
identical reference runs was 5 of 5,963 alerts (0.08 %, attack-bruteforce-ssh-ftp), so anything below 99.9 % is
outside that noise floor.
"""
import csv
import os
import statistics
from collections import defaultdict

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.colors import LinearSegmentedColormap

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RES = os.path.join(ROOT, 'results')
FIG = os.path.join(ROOT, 'figures')
LOSS = 0.999

CAPS = ['attack-dos-hulk', 'attack-dos-slowloris', 'attack-bruteforce-ssh', 'attack-bruteforce-ssh-ftp',
        'attack-bruteforce-smb', 'benign-admin-activity', 'benign-background-activity', 'benign-user-activity']
SHORT = {'attack-dos-hulk': 'DoS Hulk', 'attack-dos-slowloris': 'DoS Slowloris',
         'attack-bruteforce-ssh': 'Brute force SSH', 'attack-bruteforce-ssh-ftp': 'Brute force SSH+FTP',
         'attack-bruteforce-smb': 'Brute force SMB', 'benign-admin-activity': 'Benign admin',
         'benign-background-activity': 'Benign background', 'benign-user-activity': 'Benign user'}
LEVELS = ['L1', 'L2', 'L3', 'L4']
LEVEL_LABEL = {'L1': 'L1\n64/256 MB', 'L2': 'L2\n16/64 MB', 'L3': 'L3\n4/16 MB', 'L4': 'L4\n1/4 MB'}
POLICIES = ['ignore', 'drop-packet', 'drop-flow', 'pass-flow', 'bypass']

# Colours (validated reference palette, light mode)
SURFACE = '#fcfcfb'
TEXT = '#0b0b0b'
TEXT2 = '#52514e'
GRID = '#e4e3df'
BLUE = '#2a78d6'
ORANGE = '#eb6834'
AQUA = '#1baf7a'
SEQ = ['#fcfcfb', '#cde2fb', '#9ec5f4', '#6da7ec', '#3987e5', '#256abf', '#184f95', '#0d366b']

plt.rcParams.update({
    'figure.facecolor': SURFACE, 'axes.facecolor': SURFACE, 'savefig.facecolor': SURFACE,
    'font.size': 9, 'axes.edgecolor': GRID, 'axes.linewidth': 0.8, 'axes.labelcolor': TEXT2,
    'xtick.color': TEXT2, 'ytick.color': TEXT2, 'text.color': TEXT, 'axes.titlesize': 10,
    'axes.titleweight': 'bold', 'axes.titlelocation': 'left', 'axes.spines.top': False,
    'axes.spines.right': False, 'legend.frameon': False, 'grid.color': GRID, 'grid.linewidth': 0.6,
})


def read(name):
    with open(os.path.join(RES, name)) as fh:
        return list(csv.DictReader(fh))


def save(fig, name):
    os.makedirs(FIG, exist_ok=True)
    fig.savefig(os.path.join(FIG, name), dpi=200, bbox_inches='tight')
    plt.close(fig)
    print('wrote figures/' + name)


def write_csv(name, header, rows):
    with open(os.path.join(RES, name), 'w', newline='') as fh:
        w = csv.writer(fh)
        w.writerow(header)
        w.writerows(rows)
    print('wrote results/' + name)


ret_rows = read('retention_all.csv')
runs = defaultdict(list)  # (capture, level, policy) -> list of run rows
for r in ret_rows:
    runs[(r['capture'], r['level'], r['policy'])].append(r)


def cell(cap, lv, pol):
    rs = runs.get((cap, lv, pol), [])
    vals = [float(r['retention']) for r in rs]
    return vals, sum(v < LOSS for v in vals)


# ---------------------------------------------------------------- tables
table = []
for cap in CAPS:
    for lv in LEVELS:
        for pol in POLICIES:
            vals, k = cell(cap, lv, pol)
            if not vals:
                continue
            rs = runs[(cap, lv, pol)]
            et = [float(r['retention_et']) for r in rs if r['retention_et'] != '']
            hit = sum(int(r['memcap_flows']) > 0 for r in rs)
            table.append([cap, lv, pol, len(vals), k, hit, round(100 * statistics.median(vals), 1),
                          round(100 * min(vals), 1), round(100 * max(vals), 1),
                          round(100 * statistics.median(et), 1) if et else '',
                          max(int(r['signatures_lost']) for r in rs)])
write_csv('table_loss_k_of_n.csv',
          ['capture', 'level', 'policy', 'runs', 'runs_with_loss', 'runs_memory_limit_hit', 'median_retention_pct',
           'min_retention_pct', 'max_retention_pct', 'median_et_retention_pct', 'max_signatures_lost'], table)

onset = []
for cap in CAPS:
    row = [cap]
    for pol in POLICIES:
        first = ''
        for lv in LEVELS:
            vals, k = cell(cap, lv, pol)
            if k:
                first = '%s (%d/%d)' % (lv, k, len(vals))
                break
        row.append(first or 'none')
    onset.append(row)
write_csv('table_loss_onset.csv', ['capture'] + ['first_level_with_loss_' + p for p in POLICIES], onset)

hit_tab = defaultdict(lambda: [0, 0])
for r in ret_rows:
    if r['level'] == 'L0':
        continue
    key = int(r['memcap_flows']) > 0
    hit_tab[key][0] += 1
    hit_tab[key][1] += float(r['retention']) < LOSS
no_hit = [float(r['retention']) for r in ret_rows if r['level'] != 'L0' and int(r['memcap_flows']) == 0]
write_csv('table_limit_hit_vs_loss.csv', ['memory_limit_hit', 'runs', 'runs_with_loss', 'lowest_retention_pct'],
          [['no', hit_tab[False][0], hit_tab[False][1], round(100 * min(no_hit), 2)],
           ['yes', hit_tab[True][0], hit_tab[True][1],
            round(100 * min(float(r['retention']) for r in ret_rows
                            if r['level'] != 'L0' and int(r['memcap_flows']) > 0), 2)]])

peak = defaultdict(list)
for r in read('runs_summary.csv'):
    if r['policy'] == 'ignore' and r.get('peak_mem_kb'):
        peak[(r['capture'], r['level'])].append(int(r['peak_mem_kb']) / 1024)
write_csv('table_peak_memory.csv', ['capture', 'level', 'runs_with_peak', 'median_peak_mb'],
          [[c, l, len(v), round(statistics.median(v))] for (c, l), v in sorted(peak.items())])


# ---------------------------------------------------------------- figure helpers
def heat(ax, pol, show_y=True, short_x=False):
    cmap = LinearSegmentedColormap.from_list('loss', SEQ)
    grid = []
    for cap in CAPS:
        grid.append([100 - 100 * statistics.median(cell(cap, lv, pol)[0]) for lv in LEVELS])
    ax.imshow(grid, cmap=cmap, vmin=0, vmax=100, aspect='auto')
    for i, cap in enumerate(CAPS):
        for j, lv in enumerate(LEVELS):
            vals, k = cell(cap, lv, pol)
            med = 100 * statistics.median(vals)
            txt = '%.0f' % med if med < 99.95 else '100'
            if k and len(vals) > 1:
                txt += '\n%d/%d lost' % (k, len(vals))
            ax.text(j, i, txt, ha='center', va='center', fontsize=7.5,
                    color='white' if 100 - med > 55 else TEXT)
    ax.set_xticks(range(len(LEVELS)))
    ax.set_xticklabels(LEVELS if short_x else [LEVEL_LABEL[lv] for lv in LEVELS], fontsize=7.5)
    ax.set_yticks(range(len(CAPS)))
    ax.set_yticklabels([SHORT[c] for c in CAPS] if show_y else [], fontsize=8)
    ax.tick_params(length=0)
    for s in ax.spines.values():
        s.set_visible(False)
    ax.set_xticks([x - 0.5 for x in range(1, len(LEVELS))], minor=True)
    ax.set_yticks([y - 0.5 for y in range(1, len(CAPS))], minor=True)
    ax.grid(which='minor', color=SURFACE, linewidth=2)
    ax.tick_params(which='minor', length=0)


# Figure 1: retention heat map, ignore policy
fig, ax = plt.subplots(figsize=(5.6, 4.4))
heat(ax, 'ignore')
ax.set_title('Alert retention (%) by capture and memory level, ignore policy')
fig.text(0.0, -0.04, 'Median over repeated runs. "k/n lost" marks cells where only some runs lost alerts. '
         'Darker = more alerts lost.\nLevel labels give stream.memcap / stream.reassembly.memcap. '
         'L1 is the Suricata default.', fontsize=7, color=TEXT2)
save(fig, 'fig1_heatmap_ignore.png')

# Figure A1: heat map per policy (appendix)
fig, axes = plt.subplots(1, 5, figsize=(15, 4.4))
for n, (ax, pol) in enumerate(zip(axes, POLICIES)):
    heat(ax, pol, show_y=(n == 0), short_x=True)
    ax.set_title(pol)
fig.suptitle('Alert retention (%) by capture, memory level and exception policy (median over runs)',
             x=0.01, ha='left', fontweight='bold', fontsize=11)
fig.text(0.01, -0.03, 'L1 64/256 MB (default), L2 16/64 MB, L3 4/16 MB, L4 1/4 MB (stream.memcap / '
         'stream.reassembly.memcap). "k/n lost" = runs that lost alerts out of runs made.', fontsize=7.5, color=TEXT2)
save(fig, 'figA1_heatmap_all_policies.png')


# Figure 2: policy comparison, every run shown
def policy_panel(ax, cap, lv):
    for x, pol in enumerate(POLICIES):
        vals, _ = cell(cap, lv, pol)
        n = len(vals)
        xs = [x + (i - (n - 1) / 2) * 0.09 for i in range(n)]
        ax.scatter(xs, [100 * v for v in vals], s=34, color=BLUE, edgecolor=SURFACE, linewidth=1.2, zorder=3)
        med = 100 * statistics.median(vals)
        ax.plot([x - 0.28, x + 0.28], [med, med], color=TEXT2, linewidth=1.2, zorder=2)
    ax.set_xticks(range(len(POLICIES)))
    ax.set_xticklabels(POLICIES, rotation=30, ha='right', fontsize=8)
    ax.set_ylim(0, 105)
    ax.yaxis.grid(True)
    ax.set_axisbelow(True)
    ax.set_title('%s, %s' % (SHORT[cap], lv), fontsize=9)


cells = [('attack-dos-hulk', 'L3'), ('attack-dos-hulk', 'L4'), ('attack-bruteforce-smb', 'L3'),
         ('attack-bruteforce-smb', 'L4'), ('attack-dos-slowloris', 'L4'), ('attack-bruteforce-ssh-ftp', 'L4')]
fig, axes = plt.subplots(2, 3, figsize=(10, 6.2), sharey=True)
for ax, (cap, lv) in zip(axes.flat, cells):
    policy_panel(ax, cap, lv)
for ax in axes[:, 0]:
    ax.set_ylabel('Alert retention (%)')
fig.suptitle('Retention under each exception policy once memory runs out (one dot per run, line = median)',
             x=0.01, ha='left', fontweight='bold', fontsize=11)
fig.tight_layout()
save(fig, 'fig2_policy_comparison.png')

# Figure 3: memory limit hit vs retention
fig, (a0, a1) = plt.subplots(1, 2, figsize=(9, 3.8), sharey=True, gridspec_kw={'width_ratios': [1, 4]})
nh = [100 * v for v in no_hit]
a0.scatter([((i * 7919) % 100) / 100 - 0.5 for i in range(len(nh))], nh, s=14, color=BLUE, alpha=0.6,
           edgecolor='none')
a0.set_xlim(-1, 1)
a0.set_xticks([])
a0.set_title('Limit never hit\n(%d runs)' % len(nh), fontsize=9)
a0.set_ylabel('Alert retention (%)')
a0.set_ylim(0, 105)
a0.yaxis.grid(True)
a0.set_axisbelow(True)
hit_runs = [r for r in ret_rows if r['level'] != 'L0' and int(r['memcap_flows']) > 0]
a1.scatter([int(r['memcap_flows']) for r in hit_runs], [100 * float(r['retention']) for r in hit_runs],
           s=14, color=BLUE, alpha=0.6, edgecolor='none')
a1.set_xscale('log')
a1.set_xlabel('Flows that hit a stream memory limit (log scale)')
a1.set_title('Limit hit (%d runs, %d lost alerts)' % (len(hit_runs), sum(float(r['retention']) < LOSS
             for r in hit_runs)), fontsize=9)
a1.yaxis.grid(True)
a1.set_axisbelow(True)
a0.annotate('lowest: %.2f%%' % min(nh), xy=(0, min(nh)), xytext=(0, 70), ha='center', fontsize=7.5,
            color=TEXT2, arrowprops=dict(arrowstyle='-', color=TEXT2, lw=0.6))
fig.suptitle('Alerts are lost only when Suricata hits a stream memory limit (all runs below L0)',
             x=0.01, ha='left', fontweight='bold', fontsize=11)
fig.tight_layout()
save(fig, 'fig3_limit_hit_vs_loss.png')

# Figure 4: separate limits
sep = read('separate_limits.csv')
SEP_LV = ['S3', 'R3', 'L3', 'S4', 'R4', 'L4']
SEP_LABEL = {'S3': 'S3\nsessions\nonly', 'R3': 'R3\nreassembly\nonly', 'L3': 'L3\nboth',
             'S4': 'S4\nsessions\nonly', 'R4': 'R4\nreassembly\nonly', 'L4': 'L4\nboth'}
fig, axes = plt.subplots(1, 3, figsize=(12, 4), sharey=True)
for ax, cap in zip(axes, ['attack-dos-hulk', 'attack-bruteforce-smb', 'attack-dos-slowloris']):
    for x, lv in enumerate(SEP_LV):
        rs = [r for r in sep if r['capture'] == cap and r['level'] == lv]
        for i, r in enumerate(rs):
            off = (i - (len(rs) - 1) / 2) * 0.08
            ax.scatter(x - 0.14 + off, 100 * float(r['retention']), s=30, color=BLUE, marker='o',
                       edgecolor=SURFACE, linewidth=1, zorder=3, label='All alerts' if x == 0 and i == 0 else None)
            ax.scatter(x + 0.14 + off, 100 * float(r['retention_et']), s=34, color=ORANGE, marker='D',
                       edgecolor=SURFACE, linewidth=1, zorder=3,
                       label='ET Open alerts only' if x == 0 and i == 0 else None)
    ax.axvline(2.5, color=GRID, linewidth=1)
    ax.set_xticks(range(len(SEP_LV)))
    ax.set_xticklabels([SEP_LABEL[lv] for lv in SEP_LV], fontsize=7.5)
    ax.set_ylim(0, 105)
    ax.yaxis.grid(True)
    ax.set_axisbelow(True)
    ax.set_title(SHORT[cap], fontsize=9)
axes[0].set_ylabel('Alert retention (%)')
axes[0].legend(loc='lower left', fontsize=8)
fig.suptitle('Which memory limit causes the loss? Session and reassembly limits tightened separately '
             '(ignore policy, one marker per run)', x=0.01, ha='left', fontweight='bold', fontsize=11)
fig.tight_layout()
save(fig, 'fig4_separate_limits.png')

# Figure 5: memory saved vs detection kept (Hulk and SMB, ignore policy)
fig, ax = plt.subplots(figsize=(6.4, 4.2))
for cap, col, mk in [('attack-dos-hulk', BLUE, 'o'), ('attack-bruteforce-smb', ORANGE, 'D')]:
    pts = []
    for lv in ['L0'] + LEVELS:
        if (cap, lv) not in peak:
            continue
        vals, _ = cell(cap, lv, 'ignore') if lv != 'L0' else ([1.0], 0)
        pts.append((statistics.median(peak[(cap, lv)]), 100 * statistics.median(vals), lv))
    ax.plot([p[0] for p in pts], [p[1] for p in pts], color=col, linewidth=2, zorder=2)
    ax.scatter([p[0] for p in pts], [p[1] for p in pts], color=col, marker=mk, s=44, edgecolor=SURFACE,
               linewidth=1.2, zorder=3, label=SHORT[cap])
    for x, y, lv in pts:
        if cap == 'attack-bruteforce-smb' and lv in ('L1', 'L2'):
            continue
        label = 'L0-L2' if (cap == 'attack-bruteforce-smb' and lv == 'L0') else lv
        dy = -13 if cap == 'attack-bruteforce-smb' else 5
        ax.annotate(label, (x, y), xytext=(6, dy), textcoords='offset points', fontsize=7.5, color=TEXT2)
ax.set_xlabel('Peak resident memory of Suricata (MB, median)')
ax.set_ylabel('Alert retention (%)')
ax.set_ylim(0, 105)
ax.grid(True)
ax.set_axisbelow(True)
ax.legend(loc='lower right', fontsize=8)
ax.set_title('Memory saved vs detection kept (ignore policy)')
fig.text(0.0, -0.05, 'About 0.5 GB of the peak is the loaded ruleset, which no stream setting can reduce. '
         'Hulk has no peak value at L1 (recorded before peak tracking was added).', fontsize=7, color=TEXT2)
save(fig, 'fig5_memory_vs_retention.png')

# Figure 6: Experiment D, hidden attack alone vs under the Hulk flood
cover_path = os.path.join(RES, 'cover.csv')
if os.path.exists(cover_path):
    cov = read('cover.csv')
    fig, axes = plt.subplots(1, 2, figsize=(10, 4), sharey=True)
    for ax, hid in zip(axes, ['attack-bruteforce-ssh', 'attack-bruteforce-smb']):
        lvls = ['L0', 'L1', 'L2', 'L3']
        for x, lv in enumerate(lvls):
            for cond, col, mk, dx in [('alone', BLUE, 'o', -0.15), ('with flood', ORANGE, 'D', 0.15)]:
                vals = [100 * float(r['hidden_retention']) for r in cov
                        if r['hidden_attack'] == hid and r['level'] == lv and r['condition'] == cond]
                n = len(vals)
                xs = [x + dx + (i - (n - 1) / 2) * 0.06 for i in range(n)]
                ax.scatter(xs, vals, s=34, color=col, marker=mk, edgecolor=SURFACE, linewidth=1, zorder=3,
                           label=({'alone': 'Attack alone', 'with flood': 'Attack under the Hulk flood'}[cond]
                                  if x == 1 else None))
        ax.set_xticks(range(len(lvls)))
        ax.set_xticklabels([lv if lv == 'L0' else LEVEL_LABEL[lv] for lv in lvls], fontsize=7.5)
        ax.set_ylim(50, 102)
        ax.yaxis.grid(True)
        ax.set_axisbelow(True)
        ax.set_title('Hidden attack: ' + SHORT[hid], fontsize=9)
    axes[0].set_ylabel("Hidden attack's alerts kept in the flood window (%)")
    axes[0].legend(loc='lower left', fontsize=8)
    fig.suptitle('Experiment D: does a DoS flood hide another attack? (ignore policy, one marker per run)',
                 x=0.01, ha='left', fontweight='bold', fontsize=11)
    fig.text(0.01, -0.04, 'L0 under the flood is the control (merging alone changes nothing). There is no "alone" '
             'marker at L0 because the alone L0 run is the reference. Y axis starts at 50 %.', fontsize=7, color=TEXT2)
    fig.tight_layout()
    save(fig, 'fig6_flood_cover.png')
