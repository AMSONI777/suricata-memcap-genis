#!/usr/bin/env python3
"""Option 2: multi-threaded check (--runmode autofp).

The main study used --runmode single. This script reads the autofp runs in results/runs_autofp/ and answers:
  1. Does autofp at L0 raise the same alerts as single at L0? (both directions, same alert key as 07_analyze.py)
  2. Under memory pressure, is retention under autofp similar to single for the same capture, level and policy?
     Retention is computed against the L0 reference of the same engine mode.
  3. Does the policy ranking (ignore vs drop-flow) still hold?

Alerts are matched with two keys: the main study's endpoint key, and a hosts key without ports (see hosts()).
Single-thread runs of the same cells are read from results/runs/ and scored the same way, so both modes are
compared like for like. Writes results/autofp.csv.
"""
import csv
import glob
import importlib.util
import os
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location('an', os.path.join(HERE, '07_analyze.py'))
an = importlib.util.module_from_spec(spec)
spec.loader.exec_module(an)

AUTO = os.path.join(an.ROOT, 'results', 'runs_autofp')
OUT = os.path.join(an.ROOT, 'results', 'autofp.csv')
LOSS = 0.999


def hosts(counter):
    """Collapse the endpoint key (sid, proto, src_ip, dest_ip, dest_port) to (sid, proto, src_ip, dest_ip).

    Needed because some ET rules are thresholded (they alert on every Nth matching event). Under autofp, which
    session becomes the Nth one depends on thread timing, so the alert can land on another session of the same
    host pair, whose client port differs, although the alert total is unchanged."""
    out = Counter()
    for k, n in counter.items():
        out[k[:4]] += n
    return out


def load(path):
    c, names, _, ep = an.load_run(path)
    p = c[an.PRIMARY]
    sess = sum(n for k, n in ep.items() if k.startswith('stream_memcap:'))
    reas = sum(n for k, n in ep.items() if k.startswith('stream_reassembly_memcap:'))
    return p, names, sess, reas


def ret(run, ref):
    tot = sum(ref.values())
    return an.matched_count(run, ref) / tot if tot else 1.0


def runs_in(base, cap):
    out = []
    for d in sorted(glob.glob(os.path.join(base, cap, '*'))):
        if os.path.exists(os.path.join(d, 'DONE')):
            level, policy, rep = an.parse_name(os.path.basename(d))
            out.append((level, policy, rep, os.path.join(d, 'eve.json.gz')))
    return out


def rng(v):
    return '%5.1f-%5.1f' % (100 * min(v), 100 * max(v)) if v else '      -    '


def med(v):
    v = sorted(v)
    return v[len(v) // 2] if len(v) % 2 else (v[len(v) // 2 - 1] + v[len(v) // 2]) / 2


def main():
    rows = []
    print('1. L0 agreement (alerts in both runs / alerts in the reference), by key')
    print('   endpoint = signature, protocol, source, destination, destination port (as in the main study)')
    print('   hosts    = signature, protocol, source, destination (no ports)')
    caps = sorted(os.path.basename(d) for d in glob.glob(os.path.join(AUTO, '*')))
    for cap in caps:
        a_runs, s_runs = runs_in(AUTO, cap), runs_in(an.RUNS, cap)
        a0 = {r: p for lv, po, r, p in a_runs if lv == 'L0' and po == 'ignore'}
        s0 = {r: p for lv, po, r, p in s_runs if lv == 'L0' and po == 'ignore'}
        if 1 not in a0 or 1 not in s0:
            print('   %s: an L0 reference is missing, skipped' % cap)
            continue
        A, _, _, _ = load(a0[1])
        S, names, _, _ = load(s0[1])
        pairs = [('single r1 vs autofp r1', S, A)]
        if 2 in a0:
            pairs.append(('autofp r1 vs autofp r2', A, load(a0[2])[0]))
        if 2 in s0:
            pairs.append(('single r1 vs single r2', S, load(s0[2])[0]))
        for label, X, Y in pairs:
            print('   %-24s %-24s alerts %5d / %5d   endpoint %6.2f %%   hosts %6.2f %%' % (
                cap, label, sum(X.values()), sum(Y.values()), 100 * ret(Y, X), 100 * ret(hosts(Y), hosts(X))))

        # Every cell (level, policy) that has autofp runs, compared with single runs of the same cell.
        cells = sorted({(lv, po) for lv, po, _, _ in a_runs if lv != 'L0'})
        for lv, po in cells:
            for mode, runs, ref in (('single', s_runs, S), ('autofp', a_runs, A)):
                for l2, p2, rep, path in runs:
                    if (l2, p2) != (lv, po):
                        continue
                    R, _, sess, reas = load(path)
                    rows.append({'capture': cap, 'level': lv, 'policy': po, 'mode': mode, 'rep': rep,
                                 'alerts': sum(R.values()),
                                 'retention_endpoint': round(ret(R, ref), 4),
                                 'retention_hosts': round(ret(hosts(R), hosts(ref)), 4),
                                 'flows_hit_session_limit': sess, 'flows_hit_reassembly_limit': reas})
    if not rows:
        raise SystemExit('No autofp runs found under results/runs_autofp/.')
    with open(OUT, 'w', newline='') as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)

    print()
    print('2. Retention against the L0 reference of the same mode (min-max over runs)')
    print('%-24s %-3s %-10s | %-12s %-12s | %-12s %-12s' % ('capture', 'lvl', 'policy', 'single endpt',
                                                         'single hosts', 'autofp endpt', 'autofp hosts'))
    grp = defaultdict(lambda: defaultdict(list))
    for r in rows:
        g = grp[(r['capture'], r['level'], r['policy'])]
        g[r['mode'] + '_e'].append(r['retention_endpoint'])
        g[r['mode'] + '_h'].append(r['retention_hosts'])
        g[r['mode'] + '_n'].append(1)
    for (cap, lv, po), g in sorted(grp.items()):
        print('%-24s %-3s %-10s | %-12s %-12s | %-12s %-12s  (runs: single %d, autofp %d)' % (
            cap, lv, po, rng(g['single_e']), rng(g['single_h']), rng(g['autofp_e']), rng(g['autofp_h']),
            len(g['single_n']), len(g['autofp_n'])))

    print()
    print('3. ignore vs drop-flow, median retention (hosts key)')
    for cap, lv in sorted({(c, l) for c, l, _ in grp}):
        i, d = grp.get((cap, lv, 'ignore')), grp.get((cap, lv, 'drop-flow'))
        if not (i and d):
            continue
        parts = []
        for mode in ('single', 'autofp'):
            if i[mode + '_h'] and d[mode + '_h']:
                mi, md = med(i[mode + '_h']), med(d[mode + '_h'])
                parts.append('%s: ignore %5.1f %% vs drop-flow %5.1f %% (%s)' % (
                    mode, 100 * mi, 100 * md, 'ignore higher' if mi > md else ('equal' if mi == md else 'drop-flow higher')))
        print('  %-24s %-3s %s' % (cap, lv, '   '.join(parts)))
    print('Wrote results/autofp.csv (%d runs: single and autofp runs of the same cells)' % len(rows))


if __name__ == '__main__':
    main()
