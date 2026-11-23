#!/usr/bin/env python3
"""Option 1, Step B: per-pool memory sweeps (ignore policy).

SP* runs lower only the session pool (stream.memcap; reassembly at 4gb).
RP* runs lower only the reassembly pool (stream.reassembly.memcap; sessions at 1gb).

For every finished SP*/RP* run, compares its alerts with the capture's L0_ignore reference using the loaders of
07_analyze.py (same alert key, same ET Open / built-in split, same loss threshold as the main study) and counts
how many flows hit each memory limit (flow.exception_policy targets, as in 11_separate_limits.py).

Writes
  results/sizing_sweep.csv        one row per run
  results/sizing_safe_limits.csv  per capture and pool: the smallest limit from which every run at every larger limit kept
                                  >= 99.9 % of alerts and hit no limit ("safe"), the largest limit that lost
                                  alerts, and the safe limit per held session (peak_held from results/peak_sessions.csv)
"""
import csv
import glob
import importlib.util
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location('an', os.path.join(HERE, '07_analyze.py'))
an = importlib.util.module_from_spec(spec)
spec.loader.exec_module(an)

OUT_RUNS = os.path.join(an.ROOT, 'results', 'sizing_sweep.csv')
OUT_SAFE = os.path.join(an.ROOT, 'results', 'sizing_safe_limits.csv')
LOSS = 0.999
UNIT = {'K': 1024, 'M': 1024 ** 2, 'G': 1024 ** 3}


def level_bytes(level):
    m = re.fullmatch(r'(SP|RP)(\d+)([KMG])', level)
    return (m.group(1), int(m.group(2)) * UNIT[m.group(3)]) if m else (None, None)


def mb(b):
    return '%g' % (b / 1024 ** 2)


def main():
    peak = {}
    p = os.path.join(an.ROOT, 'results', 'peak_sessions.csv')
    if os.path.exists(p):
        for r in csv.DictReader(open(p)):
            peak[r['capture']] = int(r['peak_held'])

    rows = []
    for cap_dir in sorted(glob.glob(os.path.join(an.RUNS, '*'))):
        cap = os.path.basename(cap_dir)
        runs = []
        for d in glob.glob(os.path.join(cap_dir, '*')):
            if not os.path.exists(os.path.join(d, 'DONE')):
                continue
            level, policy, rep = an.parse_name(os.path.basename(d))
            pool, b = level_bytes(level)
            if pool and policy == 'ignore':
                runs.append((pool, b, rep, level, d))
        if not runs:
            continue
        ref = os.path.join(cap_dir, 'L0_ignore', 'eve.json.gz')
        ref_c, ref_names, _, _ = an.load_run(ref)
        ref_p = ref_c[an.PRIMARY]
        ref_total = sum(ref_p.values())
        et_sids = {s for s, nm in ref_names.items() if not nm.startswith('SURICATA')}
        et_ref = sum(n for k, n in ref_p.items() if k[0] in et_sids)
        ref_sigs = {k[0] for k in ref_p}
        for pool, b, rep, level, d in sorted(runs, key=lambda x: (x[0], x[1], x[2])):
            c, _n, _f, ep = an.load_run(os.path.join(d, 'eve.json.gz'))
            run_p = c[an.PRIMARY]
            matched = an.matched_count(run_p, ref_p)
            et_matched = an.matched_count(run_p, ref_p, et_sids)
            run_sigs = {k[0] for k in run_p}
            sess = sum(n for k, n in ep.items() if k.startswith('stream_memcap:'))
            reas = sum(n for k, n in ep.items() if k.startswith('stream_reassembly_memcap:'))
            rows.append({
                'capture': cap, 'pool': 'session' if pool == 'SP' else 'reassembly', 'level': level,
                'limit_mb': mb(b), 'limit_bytes': b, 'rep': rep,
                'ref_alerts': ref_total, 'matched': matched,
                'retention': round(matched / ref_total, 4) if ref_total else 1.0,
                'retention_et': round(et_matched / et_ref, 4) if et_ref else '',
                'signatures_lost': len(ref_sigs - run_sigs),
                'flows_hit_session_limit': sess, 'flows_hit_reassembly_limit': reas,
            })

    if not rows:
        raise SystemExit('No SP*/RP* runs found under results/runs/.')
    with open(OUT_RUNS, 'w', newline='') as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)

    print('%-26s %-10s %8s %3s %8s %7s %5s %9s %9s' % ('capture', 'pool', 'limitMB', 'rep', 'retain%', 'ET%', 'lost',
                                                       'sess_hit', 'reas_hit'))
    for r in rows:
        print('%-26s %-10s %8s %3d %8.1f %7s %5d %9d %9d' % (
            r['capture'], r['pool'], r['limit_mb'], r['rep'], 100 * r['retention'],
            '%.1f' % (100 * r['retention_et']) if r['retention_et'] != '' else '-',
            r['signatures_lost'], r['flows_hit_session_limit'], r['flows_hit_reassembly_limit']))

    safe_rows = []
    for cap in sorted({r['capture'] for r in rows}):
        for pool in ('session', 'reassembly'):
            rs = [r for r in rows if r['capture'] == cap and r['pool'] == pool]
            if not rs:
                continue
            hit_key = 'flows_hit_session_limit' if pool == 'session' else 'flows_hit_reassembly_limit'
            # Group repeats by limit. A limit is clean only if EVERY run at it kept >= 99.9 % and hit no limit.
            by_limit = {}
            for r in rs:
                by_limit.setdefault(r['limit_bytes'], []).append(r)
            limits = sorted(by_limit, reverse=True)
            clean = {L: all(r['retention'] >= LOSS and r[hit_key] == 0 for r in by_limit[L]) for L in limits}
            lossy_n = {L: sum(r['retention'] < LOSS for r in by_limit[L]) for L in limits}
            safe = None
            for L in limits:                   # walk down from the largest limit
                if clean[L]:
                    safe = L
                else:
                    break
            lossy_limits = [L for L in limits if lossy_n[L] > 0]
            largest_lossy = max(lossy_limits) if lossy_limits else None
            # Non-monotonic: some smaller limit had no lossy run while a larger one had one.
            nonmono = any(lossy_n[lo] == 0 and lo < hi for hi in lossy_limits for lo in limits)
            ph = peak.get(cap)
            safe_rows.append({
                'capture': cap, 'pool': pool, 'peak_held': ph if ph is not None else '',
                'safe_limit_mb': mb(safe) if safe else '',
                'runs_at_safe': len(by_limit[safe]) if safe else '',
                'largest_lossy_limit_mb': mb(largest_lossy) if largest_lossy else 'none',
                'lossy_k_of_n': '%d/%d' % (lossy_n[largest_lossy], len(by_limit[largest_lossy])) if largest_lossy else '',
                'non_monotonic': 'yes' if nonmono else 'no',
                'lossy_bytes_per_held_session': round(largest_lossy / ph) if largest_lossy and ph else '',
                'safe_bytes_per_held_session': round(safe / ph) if safe and ph else '',
            })
    with open(OUT_SAFE, 'w', newline='') as fh:
        w = csv.DictWriter(fh, fieldnames=list(safe_rows[0]))
        w.writeheader()
        w.writerows(safe_rows)
    print()
    print('%-26s %-10s %9s %7s %5s %9s %6s %8s %9s %9s' % ('capture', 'pool', 'peak_held', 'safeMB', 'runs',
                                                            'lossyMB', 'k/n', 'nonmono', 'B/held_L', 'B/held_S'))
    for r in safe_rows:
        print('%-26s %-10s %9s %7s %5s %9s %6s %8s %9s %9s' % (
            r['capture'], r['pool'], r['peak_held'], r['safe_limit_mb'], r['runs_at_safe'],
            r['largest_lossy_limit_mb'], r['lossy_k_of_n'], r['non_monotonic'],
            r['lossy_bytes_per_held_session'], r['safe_bytes_per_held_session']))
    print('safeMB: smallest limit from which every run at every larger limit kept >= 99.9 % and hit no limit; '
          'lossyMB: largest limit with a lossy run (k of n runs lossy); B/held_L and B/held_S: those limits per held session')
    print('Wrote results/sizing_sweep.csv (%d runs) and results/sizing_safe_limits.csv' % len(rows))


if __name__ == '__main__':
    main()
