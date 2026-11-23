#!/usr/bin/env python3
"""Sensitivity of every result to the alert key.

The study matches a run's alerts to the L0 reference on the endpoint key
(signature, protocol, source, destination, destination port). Thresholded rules alert on every Nth matching event
(e.g. sid 2102924, count 10 by_dst). When sessions are dropped or processed in another order, the Nth event can
fall in another session of the same host pair: the alert survives, but its client port changes, so the endpoint
key counts it as lost. This script rescores every finished run in results/runs/ with a hosts key
(signature, protocol, source, destination; no ports) and re-checks each headline finding with both keys.

No new runs. Writes results/key_sensitivity.csv.
"""
import csv
import glob
import importlib.util
import os
import re
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location('an', os.path.join(HERE, '07_analyze.py'))
an = importlib.util.module_from_spec(spec)
spec.loader.exec_module(an)

OUT = os.path.join(an.ROOT, 'results', 'key_sensitivity.csv')
LOSS = 0.999
KEYS = ('endpoint', 'hosts')


def hosts(counter):
    out = Counter()
    for k, n in counter.items():
        out[k[:4]] += n
    return out


def ret(run, ref):
    tot = sum(ref.values())
    return an.matched_count(run, ref) / tot if tot else 1.0


def med(v):
    v = sorted(v)
    return v[len(v) // 2] if len(v) % 2 else (v[len(v) // 2 - 1] + v[len(v) // 2]) / 2


def level_order(lv):
    m = re.fullmatch(r'L(\d)', lv)
    if m:
        return (0, int(m.group(1)), 0)
    if lv in ('S3', 'R3', 'S4', 'R4'):
        return (1, ('S3', 'R3', 'S4', 'R4').index(lv), 0)
    m = re.fullmatch(r'(SP|RP)(\d+)([KMG])', lv)
    if m:
        mult = {'K': 1, 'M': 1024, 'G': 1024 ** 2}[m.group(3)]
        return (2 if m.group(1) == 'SP' else 3, int(m.group(2)) * mult, 0)
    return (9, 0, lv)


def main():
    rows = []
    for cap_dir in sorted(glob.glob(os.path.join(an.RUNS, '*'))):
        cap = os.path.basename(cap_dir)
        ref_path = os.path.join(cap_dir, 'L0_ignore', 'eve.json.gz')
        if not os.path.exists(ref_path):
            continue
        c, _, _, _ = an.load_run(ref_path)
        ref = {'endpoint': c[an.PRIMARY]}
        ref['hosts'] = hosts(ref['endpoint'])
        for d in sorted(glob.glob(os.path.join(cap_dir, '*'))):
            if not os.path.exists(os.path.join(d, 'DONE')):
                continue
            level, policy, rep = an.parse_name(os.path.basename(d))
            c, _, _, ep = an.load_run(os.path.join(d, 'eve.json.gz'))
            run = {'endpoint': c[an.PRIMARY]}
            run['hosts'] = hosts(run['endpoint'])
            r = {'capture': cap, 'level': level, 'policy': policy, 'rep': rep,
                 'memcap_flows': sum(n for k, n in ep.items() if 'memcap' in k)}
            for k in KEYS:
                r['retention_' + k] = round(ret(run[k], ref[k]), 4)
                r['loss_' + k] = int(r['retention_' + k] < LOSS)
            rows.append(r)
    if not rows:
        raise SystemExit('No runs found under results/runs/.')
    with open(OUT, 'w', newline='') as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)

    caps = sorted({r['capture'] for r in rows})
    below = [r for r in rows if r['level'] != 'L0']
    grid = [r for r in below if re.fullmatch(r'L[1-4]', r['level'])]

    print('A. L0 repeats against the L0 reference (determinism), lowest retention per key')
    for cap in caps:
        l0 = [r for r in rows if r['capture'] == cap and r['level'] == 'L0']
        print('   %-28s %d runs   endpoint %6.2f %%   hosts %6.2f %%' % (
            cap, len(l0), 100 * min(r['retention_endpoint'] for r in l0), 100 * min(r['retention_hosts'] for r in l0)))

    print()
    print('B. Runs below L0 whose loss verdict (retention < 99.9 %) differs between the keys')
    diff = [r for r in below if r['loss_endpoint'] != r['loss_hosts']]
    print('   %d of %d runs differ' % (len(diff), len(below)))
    for r in sorted(diff, key=lambda r: (r['capture'], level_order(r['level']), r['policy'], r['rep'])):
        print('   %-28s %-8s %-11s r%d  endpoint %6.2f %%  hosts %6.2f %%  memcap flows %d' % (
            r['capture'], r['level'], r['policy'], r['rep'], 100 * r['retention_endpoint'],
            100 * r['retention_hosts'], r['memcap_flows']))

    print()
    print('C. Finding: the defaults (L1) lose no alerts')
    for k in KEYS:
        l1 = [r for r in grid if r['level'] == 'L1']
        lossy = [r for r in l1 if r['loss_' + k]]
        print('   %-8s %d of %d L1 runs lossy; lowest retention %.2f %%' % (
            k, len(lossy), len(l1), 100 * min(r['retention_' + k] for r in l1)))

    print()
    print('D. Finding: loss only when a memory limit was hit (all runs below L0 in results/runs)')
    for k in KEYS:
        nohit = [r for r in below if r['memcap_flows'] == 0]
        hit = [r for r in below if r['memcap_flows'] > 0]
        print('   %-8s no limit hit: %d runs, %d lossy (lowest %.2f %%)   limit hit: %d runs, %d lossy' % (
            k, len(nohit), sum(r['loss_' + k] for r in nohit),
            100 * min(r['retention_' + k] for r in nohit) if nohit else 100,
            len(hit), sum(r['loss_' + k] for r in hit)))

    print()
    print('E. Finding: loss onset per capture, ignore policy (first grid level with a lossy run, k of n)')
    for cap in caps:
        parts = []
        for k in KEYS:
            onset = 'none'
            for lv in ('L1', 'L2', 'L3', 'L4'):
                rs = [r for r in grid if r['capture'] == cap and r['level'] == lv and r['policy'] == 'ignore']
                n_l = sum(r['loss_' + k] for r in rs)
                if n_l:
                    onset = '%s (%d/%d)' % (lv, n_l, len(rs))
                    break
            parts.append('%s %-10s' % (k, onset))
        print('   %-28s %s' % (cap, '   '.join(parts)))

    print()
    print('F. Median retention per grid cell (L1-L4, all policies) where the keys differ by more than 1 point')
    cells = defaultdict(list)
    for r in grid:
        cells[(r['capture'], r['level'], r['policy'])].append(r)
    shown = 0
    for (cap, lv, po), rs in sorted(cells.items(), key=lambda x: (x[0][0], level_order(x[0][1]), x[0][2])):
        me, mh = med([r['retention_endpoint'] for r in rs]), med([r['retention_hosts'] for r in rs])
        if abs(me - mh) > 0.01:
            shown += 1
            print('   %-28s %-3s %-11s n=%d  endpoint %6.1f %%  hosts %6.1f %%' % (cap, lv, po, len(rs), 100 * me, 100 * mh))
    if not shown:
        print('   none')

    print()
    print('G. Finding: SMB at L4, ignore against the other policies (min-max per key)')
    for po in ('ignore', 'drop-packet', 'drop-flow', 'pass-flow', 'bypass'):
        rs = cells.get(('attack-bruteforce-smb', 'L4', po), [])
        if rs:
            print('   %-11s n=%d  endpoint %5.1f-%5.1f %%   hosts %5.1f-%5.1f %%' % (
                po, len(rs), 100 * min(r['retention_endpoint'] for r in rs), 100 * max(r['retention_endpoint'] for r in rs),
                100 * min(r['retention_hosts'] for r in rs), 100 * max(r['retention_hosts'] for r in rs)))

    print()
    print('H. Separate limits and sizing runs (median retention per key where the keys differ by more than 1 point)')
    other = defaultdict(list)
    for r in below:
        if not re.fullmatch(r'L[1-4]', r['level']):
            other[(r['capture'], r['level'], r['policy'])].append(r)
    shown = 0
    for (cap, lv, po), rs in sorted(other.items(), key=lambda x: (x[0][0], level_order(x[0][1]), x[0][2])):
        me, mh = med([r['retention_endpoint'] for r in rs]), med([r['retention_hosts'] for r in rs])
        loss_e, loss_h = sum(r['loss_endpoint'] for r in rs), sum(r['loss_hosts'] for r in rs)
        if abs(me - mh) > 0.01 or loss_e != loss_h:
            shown += 1
            print('   %-28s %-8s %-7s n=%d  endpoint %6.1f %% (%d lossy)  hosts %6.1f %% (%d lossy)' % (
                cap, lv, po, len(rs), 100 * me, loss_e, 100 * mh, loss_h))
    if not shown:
        print('   none')
    print('Wrote results/key_sensitivity.csv (%d runs)' % len(rows))


if __name__ == '__main__':
    main()
