"""Compares the short re-run made by reproduce.sh (verify/runs) with the recorded results.

Checks:
  1-3  L0 reference runs of benign-admin-activity, attack-bruteforce-smb and attack-dos-hulk: alert and session
       counts must equal the recorded first runs exactly (reference runs are deterministic).
  4    Hulk at L1 (Suricata defaults) keeps all alerts (retention >= 99.9 %).
  5    Hulk at L4 keeps a share of alerts inside the recorded range, widened by 1 percentage point.
  6    Hulk with only the session limit tight (S4): same number of lost signatures as recorded, retention in range.
  7    Hulk with only the reassembly limit tight (R4): ET Open retention in the recorded range.
Retention in checks 4-7 is measured against the L0 run made in this check, with the same alert key as the study.
Prints MATCH or MISMATCH per check and exits with status 1 if any check fails.
"""
import csv
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location('an', os.path.join(HERE, '07_analyze.py'))
an = importlib.util.module_from_spec(spec)
spec.loader.exec_module(an)

ROOT = an.ROOT
VER = os.path.join(ROOT, 'verify', 'runs')
TOL = 0.01
HULK = 'attack-dos-hulk'


def read(path):
    with open(path) as fh:
        return list(csv.DictReader(fh))


recorded = {(r['capture'], r['level']): r for r in read(os.path.join(ROOT, 'results', 'runs_summary.csv'))
            if r['policy'] == 'ignore' and r['rep'] == '1'}
now = {(r['capture'], r['level']): r for r in read(os.path.join(ROOT, 'verify', 'runs_summary.csv'))}
ret_all = read(os.path.join(ROOT, 'results', 'retention_all.csv'))
sep = read(os.path.join(ROOT, 'results', 'separate_limits.csv'))


def span(rows, field):
    vals = [float(r[field]) for r in rows]
    return min(vals) - TOL, max(vals) + TOL


def eve(cap, level):
    return os.path.join(VER, cap, '%s_ignore' % level, 'eve.json.gz')


checks = []


def check(name, expected, got, ok):
    checks.append((name, expected, got, ok))


for cap in ['benign-admin-activity', 'attack-bruteforce-smb', HULK]:
    rec, cur = recorded[(cap, 'L0')], now.get((cap, 'L0'))
    if cur is None:
        check('%s L0' % cap, 'run present', 'missing', False)
        continue
    exp = 'alerts=%s sessions=%s' % (rec['alerts'], rec['sessions'])
    got = 'alerts=%s sessions=%s' % (cur['alerts'], cur['sessions'])
    check('%s L0 reference' % cap, exp, got, exp == got)

ref_c, ref_names, _, _ = an.load_run(eve(HULK, 'L0'))
ref_p = ref_c[an.PRIMARY]
ref_total = sum(ref_p.values())
et_sids = {s for s, nm in ref_names.items() if not nm.startswith('SURICATA')}
et_total = sum(n for k, n in ref_p.items() if k[0] in et_sids)
ref_sigs = {k[0] for k in ref_p}


def measure(level):
    c, _n, _f, ep = an.load_run(eve(HULK, level))
    p = c[an.PRIMARY]
    ret = an.matched_count(p, ref_p) / ref_total
    ret_et = an.matched_count(p, ref_p, et_sids) / et_total
    lost = len(ref_sigs - {k[0] for k in p})
    hit = sum(n for k, n in ep.items() if 'memcap' in k)
    return ret, ret_et, lost, hit


r, _, _, hit = measure('L1')
check('Hulk L1 (defaults) retention', '>= 99.9 %', '%.1f %% (limit hit by %d flows)' % (100 * r, hit), r >= 0.999)

lo, hi = span([x for x in ret_all if x['capture'] == HULK and x['level'] == 'L4' and x['policy'] == 'ignore'],
              'retention')
r, _, _, hit = measure('L4')
check('Hulk L4 retention', '%.1f-%.1f %%' % (100 * lo, 100 * hi), '%.1f %% (limit hit by %d flows)' % (100 * r, hit),
      lo <= r <= hi)

s4 = [x for x in sep if x['capture'] == HULK and x['level'] == 'S4']
lo, hi = span(s4, 'retention')
lost_rec = sorted({int(x['signatures_lost']) for x in s4})
r, _, lost, _ = measure('S4')
check('Hulk S4 (sessions only) retention', '%.1f-%.1f %%' % (100 * lo, 100 * hi), '%.1f %%' % (100 * r),
      lo <= r <= hi)
check('Hulk S4 signatures lost', '/'.join(map(str, lost_rec)), str(lost), lost in lost_rec)

r4 = [x for x in sep if x['capture'] == HULK and x['level'] == 'R4']
lo, hi = span(r4, 'retention_et')
_, r_et, _, _ = measure('R4')
check('Hulk R4 (reassembly only) ET retention', '%.1f-%.1f %%' % (100 * lo, 100 * hi), '%.1f %%' % (100 * r_et),
      lo <= r_et <= hi)

print('%-42s %-28s %-36s %s' % ('check', 'recorded', 'this run', 'result'))
for name, exp, got, ok in checks:
    print('%-42s %-28s %-36s %s' % (name, exp, got, 'MATCH' if ok else 'MISMATCH'))
bad = sum(not c[3] for c in checks)
print('\n%d of %d checks match.' % (len(checks) - bad, len(checks)))
print('REPRODUCED' if not bad else 'NOT REPRODUCED')
sys.exit(1 if bad else 0)
