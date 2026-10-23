import csv
import glob
import gzip
import hashlib
import json
import os
import sys
from collections import Counter

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
RUNS = os.path.join(ROOT, 'results', 'runs')
OUT_RET = os.path.join(ROOT, 'results', 'retention.csv')
OUT_SIG = os.path.join(ROOT, 'results', 'per_signature.csv')
OUT_DET = os.path.join(ROOT, 'results', 'determinism.csv')


def parse_name(name):
    parts = name.split('_')
    level, policy = parts[0], parts[1]
    rep = int(parts[2][1:]) if len(parts) > 2 and parts[2].startswith('r') else 1
    return level, policy, rep


def load_run(path):
    """Return (alert Counter keyed by event, signature names, ep flow count, ep detail Counter)."""
    alerts = Counter()
    names = {}
    ep_flows = 0
    ep_detail = Counter()
    with gzip.open(path, 'rt') as fh:
        for line in fh:
            if '"event_type":"alert"' in line:
                ev = json.loads(line)
                a = ev['alert']
                key = (a['signature_id'], ev.get('proto'), ev.get('src_ip'), ev.get('src_port'),
                       ev.get('dest_ip'), ev.get('dest_port'), ev.get('timestamp'))
                alerts[key] += 1
                names[a['signature_id']] = a.get('signature', '')
            elif '"event_type":"flow"' in line and '"exception_policy"' in line:
                ev = json.loads(line)
                ep_flows += 1
                ep_detail[json.dumps(ev.get('exception_policy'), sort_keys=True)] += 1
    return alerts, names, ep_flows, ep_detail


def digest(alerts):
    h = hashlib.sha256()
    for k in sorted(alerts, key=lambda x: tuple(str(i) for i in x)):
        h.update((repr(k) + ':' + str(alerts[k]) + '\n').encode())
    return h.hexdigest()


def main():
    runs = {}
    for f in sorted(glob.glob(os.path.join(RUNS, '*', '*', 'eve.json.gz'))):
        d = os.path.dirname(f)
        if not os.path.exists(os.path.join(d, 'DONE')):
            continue
        cap, name = os.path.basename(os.path.dirname(d)), os.path.basename(d)
        runs[(cap, name)] = f
    if not runs:
        print('No finished runs found in results/runs')
        sys.exit(1)

    cache = {}

    def get(key):
        if key not in cache:
            cache[key] = load_run(runs[key])
        return cache[key]

    ret_rows, sig_rows, det_rows = [], [], []
    caps = sorted({c for c, _ in runs})
    for cap in caps:
        ref_key = (cap, 'L0_ignore')
        if ref_key not in runs:
            print('No L0_ignore reference for', cap, '- skipped')
            continue
        ref, ref_names, _, _ = get(ref_key)
        ref_total = sum(ref.values())
        ref_by_sig = Counter()
        for k, n in ref.items():
            ref_by_sig[k[0]] += n

        reps = sorted(n for c, n in runs if c == cap and n.startswith('L0_ignore'))
        if len(reps) > 1:
            hashes = {n: digest(get((cap, n))[0]) for n in reps}
            det_rows.append([cap, len(reps), ';'.join(reps), len(set(hashes.values())) == 1,
                             list(hashes.values())[0][:16]])

        for (c, name), _path in sorted(runs.items()):
            if c != cap:
                continue
            level, policy, rep = parse_name(name)
            if rep != 1:
                continue
            alerts, names, ep_flows, ep_detail = get((c, name))
            matched = sum(min(n, ref.get(k, 0)) for k, n in alerts.items())
            run_total = sum(alerts.values())
            new = run_total - matched
            run_by_sig = Counter()
            for k, n in alerts.items():
                run_by_sig[k[0]] += n
            lost = [s for s in ref_by_sig if run_by_sig.get(s, 0) == 0]
            et_sids = {x for x, nm in ref_names.items() if not nm.startswith('SURICATA')}
            et_ref = sum(n for k, n in ref.items() if k[0] in et_sids)
            et_matched = sum(min(n, ref.get(k, 0)) for k, n in alerts.items() if k[0] in et_sids)
            retention = (matched / ref_total) if ref_total else 1.0
            ret_rows.append([cap, level, policy, ref_total, run_total, matched, new,
                             round(retention, 4), len(ref_by_sig), len(lost), ep_flows,
                             '; '.join('%s x%d' % (k, v) for k, v in ep_detail.most_common(3)),
                             et_ref, et_matched])
            for s in sorted(set(ref_by_sig) | set(run_by_sig)):
                nm = ref_names.get(s, names.get(s, ''))
                origin = 'suricata-builtin' if nm.startswith('SURICATA') else 'ET-Open'
                sig_rows.append([cap, level, policy, s, nm, origin, ref_by_sig.get(s, 0), run_by_sig.get(s, 0)])

    with open(OUT_RET, 'w', newline='') as fh:
        w = csv.writer(fh)
        w.writerow(['capture', 'level', 'policy', 'ref_alerts', 'run_alerts', 'matched', 'new_unmatched',
                    'retention', 'ref_signatures', 'signatures_lost', 'ep_flows', 'ep_detail',
                    'ref_et_alerts', 'matched_et_alerts'])
        w.writerows(ret_rows)
    with open(OUT_SIG, 'w', newline='') as fh:
        w = csv.writer(fh)
        w.writerow(['capture', 'level', 'policy', 'sid', 'signature', 'origin', 'ref_count', 'run_count'])
        w.writerows(sig_rows)
    if det_rows:
        with open(OUT_DET, 'w', newline='') as fh:
            w = csv.writer(fh)
            w.writerow(['capture', 'runs_compared', 'run_names', 'identical', 'hash_prefix'])
            w.writerows(det_rows)

    print('%-26s %-5s %-12s %6s %6s %9s %5s %6s %8s' % ('capture', 'level', 'policy', 'ref', 'run', 'retention', 'new', 'lostS', 'ET kept'))
    for r in ret_rows:
        print('%-26s %-5s %-12s %6d %6d %8.1f%% %5d %3d/%-2d %4d/%d' % (r[0], r[1], r[2], r[3], r[4], r[7] * 100, r[6], r[9], r[8], r[13], r[12]))
    for r in det_rows:
        print('determinism %-24s %d runs identical=%s' % (r[0], r[1], r[3]))
    print('Wrote results/retention.csv, results/per_signature.csv' + (', results/determinism.csv' if det_rows else ''))


main()
