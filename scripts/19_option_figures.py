#!/usr/bin/env python3
"""Figures for the memory-sizing model (Option 1), the multi-threaded check (Option 2) and the alert-key check.

Reads results/peak_sessions.csv, sizing_safe_limits.csv, key_sensitivity.csv and autofp.csv and writes
figures/fig7_peak_held_onset.png ... fig12_key_robustness.png. Retention in these figures uses the host-pair key
(signature, protocol, source, destination), so that the thresholded SMB rule is not counted as loss; for the
session pool both keys give the same loss verdicts (results/key_sensitivity.csv).
"""
import csv
import os
import re
from collections import defaultdict

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.ticker import FuncFormatter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RES = os.path.join(ROOT, 'results')
FIG = os.path.join(ROOT, 'figures')

SURFACE, TEXT, TEXT2, GRID = '#fcfcfb', '#0b0b0b', '#52514e', '#e4e3df'
BLUE, ORANGE, AQUA, YELLOW, MAGENTA = '#2a78d6', '#eb6834', '#1baf7a', '#eda100', '#e87ba4'
NEUTRAL = '#8a8984'
plt.rcParams.update({
    'figure.facecolor': SURFACE, 'axes.facecolor': SURFACE, 'savefig.facecolor': SURFACE,
    'font.size': 9, 'axes.edgecolor': GRID, 'axes.linewidth': 0.8, 'axes.labelcolor': TEXT2,
    'xtick.color': TEXT2, 'ytick.color': TEXT2, 'text.color': TEXT, 'axes.titlesize': 10,
    'axes.titleweight': 'bold', 'axes.titlelocation': 'left', 'axes.spines.top': False,
    'axes.spines.right': False, 'legend.frameon': False, 'grid.color': GRID, 'grid.linewidth': 0.6,
})

# Fixed identity per capture: colour and marker never change between figures.
CAP = {
    'attack-dos-hulk': ('DoS Hulk', BLUE, 'o'),
    'attack-bruteforce-ssh-ftp': ('Brute force SSH+FTP', ORANGE, 's'),
    'attack-bruteforce-smb': ('Brute force SMB', AQUA, 'D'),
    'attack-dos-slowloris': ('DoS Slowloris', YELLOW, '^'),
    'attack-bruteforce-ssh': ('Brute force SSH', MAGENTA, 'v'),
    'benign-user-activity': ('Benign user', NEUTRAL, 'P'),
    'benign-background-activity': ('Benign background', NEUTRAL, 'X'),
    'benign-admin-activity': ('Benign admin', NEUTRAL, '*'),
}
ATTACKS = ['attack-dos-hulk', 'attack-bruteforce-ssh-ftp', 'attack-bruteforce-smb', 'attack-dos-slowloris',
           'attack-bruteforce-ssh']
UNIT = {'K': 1024, 'M': 1024 ** 2, 'G': 1024 ** 3}


def read(name):
    with open(os.path.join(RES, name)) as fh:
        return list(csv.DictReader(fh))


def save(fig, name):
    os.makedirs(FIG, exist_ok=True)
    fig.savefig(os.path.join(FIG, name), dpi=200, bbox_inches='tight')
    plt.close(fig)
    print('wrote figures/' + name)


def lim_bytes(level):
    m = re.fullmatch(r'(SP|RP)(\d+)([KMG])', level)
    return (m.group(1), int(m.group(2)) * UNIT[m.group(3)]) if m else (None, None)


def med(v):
    v = sorted(v)
    return v[len(v) // 2] if len(v) % 2 else (v[len(v) // 2 - 1] + v[len(v) // 2]) / 2


def mb_fmt(x, _):
    return ('%g MB' % x) if x >= 1 else ('%g KB' % (x * 1024))


peak = {r['capture']: r for r in read('peak_sessions.csv')}
ks = read('key_sensitivity.csv')
for r in ks:
    r['rh'] = 100 * float(r['retention_hosts'])
    r['mf'] = int(r['memcap_flows'])

# ---------------------------------------------------------------- fig 7: held sessions explain the onset of loss
onset = {}
for r in read('table_loss_onset.csv'):
    lv = [v.split(' ')[0] for k, v in r.items() if k.startswith('first_level') and v != 'none']
    onset[r['capture']] = min(lv) if lv else 'none'
order = sorted(peak, key=lambda c: int(peak[c]['peak_held']))
fig, ax = plt.subplots(figsize=(6.6, 3.3))
for i, c in enumerate(order):
    name, col, mk = CAP[c]
    held, act = int(peak[c]['peak_held']), int(peak[c]['peak_active'])
    ax.barh(i, held, height=0.55, color=col, edgecolor=SURFACE, linewidth=2, zorder=2)
    ax.scatter(act, i, s=40, marker='|', color=TEXT, linewidth=2, zorder=3)
    lab = 'no loss at any level' if onset[c] == 'none' else 'loss from %s' % onset[c]
    ax.text(held * 1.35, i, '%s held  -  %s' % ('{:,}'.format(held), lab), va='center', fontsize=7.5, color=TEXT2)
ax.set_yticks(range(len(order)))
ax.set_yticklabels([CAP[c][0] for c in order], fontsize=8)
ax.set_xscale('log')
ax.set_xlim(1, 2e6)
ax.set_xlabel('TCP sessions at the same moment (log scale)')
ax.grid(axis='x', zorder=0)
from matplotlib.patches import Patch
handles = [plt.Line2D([], [], marker='|', color=TEXT, linestyle='none', markersize=9, markeredgewidth=2,
                      label='active (first to last packet)'),
           Patch(color=NEUTRAL, label='held by Suricata (until the flow times out)')]
ax.legend(handles=handles, loc='lower right', fontsize=7.5)
ax.set_title('Peak sessions held by Suricata, and the memory level where alerts are first lost')
save(fig, 'fig7_peak_held_onset.png')

# ---------------------------------------------------------------- fig 8: session-pool sweep per held session
fig, ax = plt.subplots(figsize=(6.6, 3.6))
ax.axvspan(390, 470, color=GRID, zorder=0)
ax.text(428, 3, 'grey zone\n390-470 B', ha='center', fontsize=7, color=TEXT2)
ax.axvline(1024, color=TEXT2, linewidth=1, linestyle='--', zorder=1)
ax.text(1080, 3, '1 KB rule', fontsize=7.5, color=TEXT2)
for c in ATTACKS:
    name, col, mk = CAP[c]
    ph = int(peak[c]['peak_held'])
    pts = defaultdict(list)
    for r in ks:
        pool, b = lim_bytes(r['level'])
        if r['capture'] == c and pool == 'SP' and r['policy'] == 'ignore':
            pts[b / ph].append(r['rh'])
    xs = sorted(pts)
    ax.plot(xs, [med(pts[x]) for x in xs], color=col, linewidth=2, zorder=2)
    for x in xs:
        ax.scatter([x] * len(pts[x]), pts[x], s=36, marker=mk, color=col, edgecolor=SURFACE, linewidth=1, zorder=3)
    ax.scatter([], [], s=36, marker=mk, color=col, label=name)
ax.set_xscale('log')
ax.xaxis.set_major_formatter(FuncFormatter(lambda x, _: '{:,.0f} B'.format(x)))
ax.set_xlabel('stream.memcap divided by the capture\'s peak held sessions (bytes per held session, log scale)')
ax.set_ylabel('Alerts kept (%)')
ax.set_ylim(0, 105)
ax.grid(zorder=0)
ax.legend(loc='lower right', fontsize=7.5)
ax.set_title('Session pool only: one scale fits all five attacks')
save(fig, 'fig8_session_sweep.png')

# ---------------------------------------------------------------- fig 9: reassembly-pool sweep
fig, ax = plt.subplots(figsize=(6.6, 3.4))
ax.axvline(128, color=TEXT2, linewidth=1, linestyle='--', zorder=1)
ax.text(120, 28, 'every capture\nsafe at 128 MB', ha='right', fontsize=7.5, color=TEXT2)
ax.axvline(256, color=GRID, linewidth=1.5, zorder=1)
ax.text(262, 2, 'default\n256 MB', ha='left', fontsize=7, color=TEXT2)
for c in ATTACKS + ['benign-user-activity']:
    name, col, mk = CAP[c]
    pts = defaultdict(list)
    for r in ks:
        pool, b = lim_bytes(r['level'])
        if r['capture'] == c and pool == 'RP' and r['policy'] == 'ignore':
            pts[b / 1024 ** 2].append(r['rh'])
    xs = sorted(pts)
    ax.plot(xs, [med(pts[x]) for x in xs], color=col, linewidth=2, zorder=2)
    for x in xs:
        ax.scatter([x] * len(pts[x]), pts[x], s=36, marker=mk, color=col, edgecolor=SURFACE, linewidth=1, zorder=3)
    ax.scatter([], [], s=36, marker=mk, color=col, label=name)
ax.set_xscale('log', base=2)
ax.xaxis.set_major_formatter(FuncFormatter(mb_fmt))
ax.set_xlabel('stream.reassembly.memcap (session limit 1 GB)')
ax.set_ylabel('Alerts kept (%)')
ax.set_ylim(0, 108)
ax.grid(zorder=0)
ax.set_xlim(1.7, 420)
ax.legend(loc='lower center', bbox_to_anchor=(0.5, -0.45), ncol=3, fontsize=7.5)
ax.set_title('Reassembly pool only: Hulk needs the most, all fit in half the default')
save(fig, 'fig9_reassembly_sweep.png')

# ---------------------------------------------------------------- fig 10: measured limits vs the 1 KB rule
# Largest session limit with a lossy run, and smallest limit from which no run lost alerts (host-pair key).
sess = defaultdict(lambda: defaultdict(list))
for r in ks:
    pool, b = lim_bytes(r['level'])
    if pool == 'SP' and r['policy'] == 'ignore' and b < 128 * 1024 ** 2 and b in (2 ** k * 512 * 1024 for k in range(8)):
        sess[r['capture']][b].append(r['rh'])
def lossy_safe(c):
    by = sess[c]
    lossy = max(b for b in by if any(v < 99.9 for v in by[b]))
    ok = None
    for b in sorted(by, reverse=True):
        if all(v >= 99.9 for v in by[b]):
            ok = b
        else:
            break
    return lossy / 1024 ** 2, ok / 1024 ** 2
fig, ax = plt.subplots(figsize=(6.6, 3.3))
for i, c in enumerate(ATTACKS):
    name, col, mk = CAP[c]
    ph = int(peak[c]['peak_held'])
    lossy, ok = lossy_safe(c)
    rule = ph / 1024
    ax.plot([lossy, ok], [i, i], color=GRID, linewidth=6, zorder=1, solid_capstyle='round')
    ax.scatter(lossy, i, s=60, marker='x', color=ORANGE, linewidth=2, zorder=3, label='largest limit that lost alerts' if i == 0 else None)
    ax.scatter(ok, i, s=60, marker='o', color=AQUA, edgecolor=SURFACE, linewidth=1, zorder=3, label='smallest limit with no loss' if i == 0 else None)
    ax.scatter(rule, i, s=70, marker='D', color=BLUE, edgecolor=SURFACE, linewidth=1, zorder=4, label='1 KB x peak held sessions' if i == 0 else None)
    ax.text(rule, i + 0.36, '%.1f MB' % rule, va='center', ha='center', fontsize=7.5, color=BLUE)
ax.axvline(64, color=TEXT2, linewidth=1, linestyle='--', zorder=1)
ax.text(70, -0.35, 'default 64 MB', ha='left', fontsize=7, color=TEXT2)
ax.set_yticks(range(len(ATTACKS)))
ax.set_yticklabels([CAP[c][0] for c in ATTACKS], fontsize=8)
ax.set_xscale('log', base=2)
ax.xaxis.set_major_formatter(FuncFormatter(mb_fmt))
ax.set_xlim(0.35, 160)
ax.set_ylim(len(ATTACKS) - 0.2, -0.6)
ax.set_xlabel('stream.memcap (log scale)')
ax.grid(axis='x', zorder=0)
ax.legend(loc='lower center', bbox_to_anchor=(0.5, -0.42), ncol=3, fontsize=7.5)
ax.set_title('The 1 KB rule against the measured limits')
save(fig, 'fig10_sizing_rule.png')

# ---------------------------------------------------------------- fig 11: single vs multi-threaded
af = read('autofp.csv')
cells = [('attack-dos-hulk', 'L2'), ('attack-dos-hulk', 'L3'), ('attack-dos-hulk', 'L4'),
         ('attack-bruteforce-smb', 'L3'), ('attack-bruteforce-smb', 'L4')]
fig, axes = plt.subplots(1, 2, figsize=(6.8, 3.1), sharey=True)
for ax, pol in zip(axes, ('ignore', 'drop-flow')):
    for j, (mode, col) in enumerate((('single', BLUE), ('autofp', ORANGE))):
        for i, (c, lv) in enumerate(cells):
            v = [100 * float(r['retention_hosts']) for r in af if r['capture'] == c and r['level'] == lv
                 and r['policy'] == pol and r['mode'] == mode]
            if not v:
                continue
            x = i + (j - 0.5) * 0.36
            ax.bar(x, med(v), width=0.34, color=col, edgecolor=SURFACE, linewidth=2, zorder=2,
                   label=('single thread' if mode == 'single' else 'multi-threaded (autofp)') if i == 0 else None)
            ax.plot([x, x], [min(v), max(v)], color=TEXT, linewidth=1, zorder=3)
    ax.set_xticks(range(len(cells)))
    ax.set_xticklabels(['%s\n%s' % ('Hulk' if 'hulk' in c else 'SMB', lv) for c, lv in cells], fontsize=8)
    ax.set_title('policy: ' + pol, fontsize=9)
    ax.grid(axis='y', zorder=0)
    ax.set_ylim(0, 105)
axes[0].set_ylabel('Alerts kept (%)')
fig.legend(*axes[0].get_legend_handles_labels(), loc='lower center', bbox_to_anchor=(0.5, -0.13), ncol=2, fontsize=7.5)
fig.suptitle('Single-threaded and multi-threaded Suricata under the same memory limits', x=0.01, ha='left',
             fontsize=10, fontweight='bold', y=1.04)
save(fig, 'fig11_autofp.png')

# ---------------------------------------------------------------- fig 12: alert-key robustness
fig, ax = plt.subplots(figsize=(4.6, 4.2))
below = [r for r in ks if r['level'] != 'L0']
oth = [r for r in below if r['capture'] != 'attack-bruteforce-smb']
smb = [r for r in below if r['capture'] == 'attack-bruteforce-smb']
ax.plot([0, 100], [0, 100], color=GRID, linewidth=1.5, zorder=1)
ax.scatter([100 * float(r['retention_endpoint']) for r in oth], [r['rh'] for r in oth], s=16, color=BLUE,
           alpha=0.6, edgecolor='none', zorder=2, label='other captures (%d runs)' % len(oth))
ax.scatter([100 * float(r['retention_endpoint']) for r in smb], [r['rh'] for r in smb], s=22, marker='D',
           color=AQUA, edgecolor=SURFACE, linewidth=0.6, zorder=3, label='SMB brute force (%d runs)' % len(smb))
ax.set_xlabel('Alerts kept, endpoint key (%)')
ax.set_ylabel('Alerts kept, host-pair key (%)')
ax.set_xlim(0, 102)
ax.set_ylim(0, 102)
ax.grid(zorder=0)
ax.legend(loc='lower right', fontsize=7.5)
ax.set_title('Every run scored with both alert keys')
save(fig, 'fig12_key_robustness.png')
