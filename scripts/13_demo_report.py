"""Side-by-side report for demo.sh: the same Hulk capture with plenty of memory (L0) and with tight memory (L4)."""
import csv
import importlib.util
import os
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location('an', os.path.join(HERE, '07_analyze.py'))
an = importlib.util.module_from_spec(spec)
spec.loader.exec_module(an)

CAP = 'attack-dos-hulk'
D = os.path.join(an.ROOT, 'demo')
with open(os.path.join(D, 'runs_summary.csv')) as fh:
    summ = {r['level']: r for r in csv.DictReader(fh)}

ref_c, names, _, ep0 = an.load_run(os.path.join(D, 'runs', CAP, 'L0_ignore', 'eve.json.gz'))
run_c, names4, _, ep = an.load_run(os.path.join(D, 'runs', CAP, 'L4_ignore', 'eve.json.gz'))
names.update(names4)
ref, run = ref_c[an.PRIMARY], run_c[an.PRIMARY]
et = {s for s, n in names.items() if not n.startswith('SURICATA')}

s0, s4 = summ['L0'], summ['L4']
print('\n=== DoS Hulk capture (%s packets), same traffic, two memory settings ===\n' % s0['packets'])
print('%-40s %18s %18s' % ('', 'L0 (1 GB / 4 GB)', 'L4 (1 MB / 4 MB)'))
print('%-40s %18s %18s' % ('TCP sessions tracked', s0['sessions'], s4['sessions']))
print('%-40s %18s %18s' % ('Sessions refused (tcp.ssn_memcap_drop)', s0['ssn_memcap_drop'], s4['ssn_memcap_drop']))
print('%-40s %18s %18d' % ('Flows that hit a stream memory limit',
      sum(n for k, n in ep0.items() if 'memcap' in k), sum(n for k, n in ep.items() if 'memcap' in k)))
print('%-40s %18s %18s' % ('Alerts raised', s0['alerts'], s4['alerts']))
print('%-40s %18s %18s' % ('Peak memory (MB)', int(s0['peak_mem_kb'] or 0) // 1024, int(s4['peak_mem_kb'] or 0) // 1024))
m = an.matched_count(run, ref)
me = an.matched_count(run, ref, et)
te = sum(n for k, n in ref.items() if k[0] in et)
print('\nAlerts kept from the L0 run: %d of %d (%.1f %%)' % (m, sum(ref.values()), 100.0 * m / sum(ref.values())))
print('ET Open alerts kept:         %d of %d (%.1f %%)' % (me, te, 100.0 * me / te))

by0, by4 = Counter(), Counter()
for k, n in ref.items():
    by0[k[0]] += n
for k, n in run.items():
    by4[k[0]] += n
print('\nTop signatures in the L0 run:')
print('%-9s %-62s %6s %6s' % ('SID', 'signature', 'L0', 'L4'))
for sid, n in by0.most_common(10):
    print('%-9s %-62s %6d %6d%s' % (sid, names.get(sid, '')[:62], n, by4.get(sid, 0),
                                    '   <- gone' if by4.get(sid, 0) == 0 else ''))
lost = [s for s in by0 if by4.get(s, 0) == 0]
print('\nSignatures that fired at L0 but never at L4: %d of %d' % (len(lost), len(by0)))
