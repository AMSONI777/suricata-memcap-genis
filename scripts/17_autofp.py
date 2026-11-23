#!/usr/bin/env python3
"""Option 2: multi-threaded check (--runmode autofp).

The main study used --runmode single. This script reads the autofp runs in results/runs_autofp/ and answers:
  1. Does autofp at L0 raise the same alerts as single at L0? (both directions, same alert key as 07_analyze.py)
  2. Under memory pressure, is retention under autofp similar to single for the same capture, level and policy?
     Retention is computed against the autofp L0 reference (same engine mode) and, for comparison, against the
     single-thread L0 reference used everywhere else in the study.
  3. Does the policy ranking (ignore vs drop-flow) still hold?

Single-thread retention for the same cell comes from results/retention_all.csv (all reps: min-max).
Writes results/autofp.csv.
"""
import csv
import glob
import importlib.util
import os
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location('an', os.path.join(HERE, '07_analyze.py'))
an = importlib.util.module_from_spec(spec)
spec.loader.exec_module(an)

AUTO = os.path.join(an.ROOT, 'results', 'runs_autofp')
OUT = os.path.join(an.ROOT, 'results', 'autofp.csv')
LOSS = 0.999


def ref(path):
    c, names, _, _ = an.load_run(path)
    p = c[an.PRIMARY]
    et = {s for s, nm in names.items() if not nm.startswith('SURICATA')}
    return p, et


def main():
    single = defaultdict(list)
    p = os.path.join(an.ROOT, 'results', 'retention_all.csv')
    if os.path.exists(p):
        for r in csv.DictReader(open(p)):
            single[(r['capture'], r['level'], r['policy'])].append(float(r['retention']))

    rows = []
    print('1. L0 reference: autofp against single (alerts matched by signature, protocol, client, server, port)')
    for cap_dir in sorted(glob.glob(os.path.join(AUTO, '*'))):
        cap = os.path.basename(cap_dir)
        a_ref_path = os.path.join(cap_dir, 'L0_ignore', 'eve.json.gz')
        s_ref_path = os.path.join(an.RUNS, cap, 'L0_ignore', 'eve.json.gz')
        if not (os.path.exists(a_ref_path) and os.path.exists(s_ref_path)):
            print('  %s: L0 reference missing (autofp or single), skipped' % cap)
            continue
        a_ref, et = ref(a_ref_path)
        s_ref, _ = ref(s_ref_path)
        a_tot, s_tot = sum(a_ref.values()), sum(s_ref.values())
        both = an.matched_count(a_ref, s_ref)
        print('  %-24s autofp %5d alerts, single %5d alerts, in both %5d (%.2f %% of single, %.2f %% of autofp)'
              % (cap, a_tot, s_tot, both, 100 * both / s_tot, 100 * both / a_tot))
        et_ref = sum(n for k, n in a_ref.items() if k[0] in et)
        for d in sorted(glob.glob(os.path.join(cap_dir, '*'))):
            if not os.path.exists(os.path.join(d, 'DONE')):
                continue
            level, policy, rep = an.parse_name(os.path.basename(d))
            c, _n, _f, ep = an.load_run(os.path.join(d, 'eve.json.gz'))
            run_p = c[an.PRIMARY]
            m_a = an.matched_count(run_p, a_ref)
            m_s = an.matched_count(run_p, s_ref)
            m_et = an.matched_count(run_p, a_ref, et)
            sess = sum(n for k, n in ep.items() if k.startswith('stream_memcap:'))
            reas = sum(n for k, n in ep.items() if k.startswith('stream_reassembly_memcap:'))
            st = single.get((cap, level, policy), [])
            rows.append({
                'capture': cap, 'level': level, 'policy': policy, 'rep': rep,
                'alerts': sum(run_p.values()),
                'retention_vs_autofp_L0': round(m_a / a_tot, 4),
                'retention_vs_single_L0': round(m_s / s_tot, 4),
                'retention_et_vs_autofp_L0': round(m_et / et_ref, 4) if et_ref else '',
                'flows_hit_session_limit': sess, 'flows_hit_reassembly_limit': reas,
                'single_runs': len(st),
                'single_min': round(min(st), 4) if st else '', 'single_max': round(max(st), 4) if st else '',
            })
    if not rows:
        raise SystemExit('No autofp runs found under results/runs_autofp/.')
    with open(OUT, 'w', newline='') as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)

    print()
    print('2. Retention under autofp (vs autofp L0 and vs single L0) next to single-thread runs of the same cell')
    print('%-24s %-3s %-10s %3s %9s %9s %9s %9s  %s' % ('capture', 'lvl', 'policy', 'rep', 'vsAutoL0', 'vsSingL0',
                                                      'sess_hit', 'reas_hit', 'single (min-max, n)'))
    for r in sorted(rows, key=lambda r: (r['capture'], r['level'], r['policy'], r['rep'])):
        sg = ('%.1f-%.1f, %d' % (100 * r['single_min'], 100 * r['single_max'], r['single_runs'])
              if r['single_runs'] else '-')
        print('%-24s %-3s %-10s %3d %9.1f %9.1f %9d %9d  %s' % (
            r['capture'], r['level'], r['policy'], r['rep'], 100 * r['retention_vs_autofp_L0'],
            100 * r['retention_vs_single_L0'], r['flows_hit_session_limit'], r['flows_hit_reassembly_limit'], sg))

    print()
    print('3. ignore vs drop-flow under autofp (median retention vs autofp L0)')
    cells = defaultdict(list)
    for r in rows:
        cells[(r['capture'], r['level'], r['policy'])].append(r['retention_vs_autofp_L0'])
    for cap, lv in sorted({(c, l) for c, l, _ in cells if l != 'L0'}):
        def med(v):
            v = sorted(v)
            return v[len(v) // 2] if len(v) % 2 else (v[len(v) // 2 - 1] + v[len(v) // 2]) / 2
        i, d = cells.get((cap, lv, 'ignore')), cells.get((cap, lv, 'drop-flow'))
        if i and d:
            print('  %-24s %-3s ignore %5.1f %%   drop-flow %5.1f %%   %s' % (
                cap, lv, 100 * med(i), 100 * med(d), 'ignore higher' if med(i) > med(d) else
                ('equal' if med(i) == med(d) else 'drop-flow higher')))
    print('Wrote results/autofp.csv (%d runs)' % len(rows))


if __name__ == '__main__':
    main()
