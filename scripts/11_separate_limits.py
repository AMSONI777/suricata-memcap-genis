"""Experiment C (separate limits). For Hulk, SMB and Slowloris under the ignore policy, compares runs where only
the session limit is tight (S3, S4), only the reassembly limit is tight (R3, R4), or both (L3, L4).
Prints retention against L0 (from results/retention_all.csv) and how many flows hit each memory limit
(flow.exception_policy targets), and writes results/separate_limits.csv.
"""
import csv
import glob
import importlib.util
import os

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location('an', os.path.join(HERE, '07_analyze.py'))
an = importlib.util.module_from_spec(spec)
spec.loader.exec_module(an)

CAPS = ['attack-dos-hulk', 'attack-bruteforce-smb', 'attack-dos-slowloris']
LEVELS = ['S3', 'R3', 'L3', 'S4', 'R4', 'L4']
OUT = os.path.join(an.ROOT, 'results', 'separate_limits.csv')

ret = {}
with open(os.path.join(an.ROOT, 'results', 'retention_all.csv')) as fh:
    for r in csv.DictReader(fh):
        ret[(r['capture'], r['level'], r['policy'], int(r['rep']))] = r

rows = []
for cap in CAPS:
    found = []
    for d in glob.glob(os.path.join(an.RUNS, cap, '*')):
        if not os.path.exists(os.path.join(d, 'DONE')):
            continue
        level, policy, rep = an.parse_name(os.path.basename(d))
        if level in LEVELS and policy == 'ignore':
            found.append((LEVELS.index(level), rep, level, d))
    for _, rep, level, d in sorted(found):
        _c, _n, _f, ep = an.load_run(os.path.join(d, 'eve.json.gz'))
        sess = sum(n for k, n in ep.items() if k.startswith('stream_memcap:'))
        reas = sum(n for k, n in ep.items() if k.startswith('stream_reassembly_memcap:'))
        r = ret[(cap, level, 'ignore', rep)]
        rows.append([cap, level, rep, r['retention'], r['retention_et'], r['signatures_lost'], sess, reas])

with open(OUT, 'w', newline='') as fh:
    w = csv.writer(fh)
    w.writerow(['capture', 'level', 'rep', 'retention', 'retention_et', 'signatures_lost',
                'flows_hit_session_limit', 'flows_hit_reassembly_limit'])
    w.writerows(rows)
print('%-22s %-3s %3s %9s %8s %5s %9s %9s' % ('capture', 'lvl', 'rep', 'retain%', 'ET%', 'lost', 'sess_lim', 'reas_lim'))
for r in rows:
    print('%-22s %-3s %3d %9.1f %8.1f %5s %9d %9d' % (r[0], r[1], r[2], 100 * float(r[3]),
          100 * float(r[4]) if r[4] != '' else 0, r[5], r[6], r[7]))
print('Wrote results/separate_limits.csv (%d runs)' % len(rows))
