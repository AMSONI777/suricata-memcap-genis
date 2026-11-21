"""Retention of EVERY finished run (first runs and repeats) against the L0_ignore reference of its capture.

Reads results/runs/*/*/eve.json.gz with the loaders of 07_analyze.py (same alert key, same ET/built-in split)
and writes results/retention_all.csv. For each configuration that has more than one run it prints the retention
of every run side by side, so run-to-run variation is visible.
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

OUT = os.path.join(an.ROOT, 'results', 'retention_all.csv')


def main():
    runs = {}
    for f in sorted(glob.glob(os.path.join(an.RUNS, '*', '*', 'eve.json.gz'))):
        d = os.path.dirname(f)
        if os.path.exists(os.path.join(d, 'DONE')):
            runs[(os.path.basename(os.path.dirname(d)), os.path.basename(d))] = f
    rows = []
    for cap in sorted({c for c, _ in runs}):
        if (cap, 'L0_ignore') not in runs:
            continue
        ref_c, ref_names, _, _ = an.load_run(runs[(cap, 'L0_ignore')])
        ref_p = ref_c[an.PRIMARY]
        ref_total = sum(ref_p.values())
        ref_by_sig = Counter()
        for k, n in ref_p.items():
            ref_by_sig[k[0]] += n
        et_sids = {s for s, nm in ref_names.items() if not nm.startswith('SURICATA')}
        et_ref = sum(n for k, n in ref_p.items() if k[0] in et_sids)
        for (c, name), path in sorted(runs.items()):
            if c != cap:
                continue
            level, policy, rep = an.parse_name(name)
            counters, _names, ep_flows, ep_detail = an.load_run(path)
            run_p = counters[an.PRIMARY]
            run_total = sum(run_p.values())
            matched = an.matched_count(run_p, ref_p)
            et_matched = an.matched_count(run_p, ref_p, et_sids)
            run_by_sig = Counter()
            for k, n in run_p.items():
                run_by_sig[k[0]] += n
            lost = sum(1 for s in ref_by_sig if run_by_sig.get(s, 0) == 0)
            memcap_flows = sum(n for k, n in ep_detail.items() if 'memcap' in k)
            rows.append([cap, level, policy, rep, ref_total, run_total, matched, run_total - matched,
                         round(matched / ref_total, 4) if ref_total else 1.0,
                         et_ref, et_matched, round(et_matched / et_ref, 4) if et_ref else '',
                         len(ref_by_sig), lost, memcap_flows])
    with open(OUT, 'w', newline='') as fh:
        w = csv.writer(fh)
        w.writerow(['capture', 'level', 'policy', 'rep', 'ref_alerts', 'run_alerts', 'matched', 'new_unmatched',
                    'retention', 'ref_et_alerts', 'matched_et_alerts', 'retention_et', 'ref_signatures',
                    'signatures_lost', 'memcap_flows'])
        w.writerows(rows)
    groups = defaultdict(list)
    for r in rows:
        groups[(r[0], r[1], r[2])].append(r)
    print('%-26s %-3s %-11s %4s  %s' % ('capture', 'lvl', 'policy', 'runs', 'retention % per run (run 1, 2, ...)   memcap flows'))
    for key, rs in sorted(groups.items()):
        if len(rs) < 2 or key[1] == 'L0':
            continue
        rs.sort(key=lambda r: r[3])
        print('%-26s %-3s %-11s %4d  %s   %s' % (key[0], key[1], key[2], len(rs),
              ' '.join('%5.1f' % (100 * r[8]) for r in rs), ' '.join(str(r[14]) for r in rs)))
    print('Wrote results/retention_all.csv (%d runs)' % len(rows))


if __name__ == '__main__':
    main()
