import csv
import glob
import gzip
import hashlib
import json
import os
import sys
from collections import Counter, defaultdict

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
RUNS = os.path.join(ROOT, 'results', 'runs')
OUT_RET = os.path.join(ROOT, 'results', 'retention.csv')
OUT_SIG = os.path.join(ROOT, 'results', 'per_signature.csv')
OUT_DET = os.path.join(ROOT, 'results', 'determinism.csv')

# Alert identity at three levels of detail. Event key layout:
# (sid, proto, src_ip, src_port, dest_ip, dest_port, timestamp)
TIERS = ('endpoint', 'no_ts', 'strict')
PRIMARY = 0


def tier_keys(k):
    return (
        (k[0], k[1], k[2], k[4], k[5]),   # endpoint: signature, client host, server host:port
        k[:-1],                           # no_ts: adds the client source port
        k,                                # strict: adds the timestamp
    )


def parse_name(name):
    parts = name.split('_')
    level, policy = parts[0], parts[1]
    rep = int(parts[2][1:]) if len(parts) > 2 and parts[2].startswith('r') else 1
    return level, policy, rep


def base_name(name):
    level, policy, _ = parse_name(name)
    return '%s_%s' % (level, policy)


def load_run(path):
    """Return (list of Counters, one per tier, signature names, exception-policy flow count, detail Counter)."""
    counters = [Counter() for _ in TIERS]
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
                for c, k in zip(counters, tier_keys(key)):
                    c[k] += 1
                names[a['signature_id']] = a.get('signature', '')
            elif '"event_type":"flow"' in line and '"exception_policy"' in line:
                ev = json.loads(line)
                ep_flows += 1
                ep_detail[json.dumps(ev.get('exception_policy'), sort_keys=True)] += 1
    return counters, names, ep_flows, ep_detail


def digest(alerts):
    h = hashlib.sha256()
    for k in sorted(alerts, key=lambda x: tuple(str(i) for i in x)):
        h.update((repr(k) + ':' + str(alerts[k]) + '\n').encode())
    return h.hexdigest()


def matched_count(run, ref, sids=None):
    return sum(min(n, ref.get(k, 0)) for k, n in run.items() if sids is None or k[0] in sids)


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
    for cap in sorted({c for c, _ in runs}):
        ref_key = (cap, 'L0_ignore')
        if ref_key not in runs:
            print('No L0_ignore reference for', cap, '- skipped')
            continue
        ref_c, ref_names, _, _ = get(ref_key)
        ref_p = ref_c[PRIMARY]
        ref_total = sum(ref_p.values())
        ref_by_sig = Counter()
        for k, n in ref_p.items():
            ref_by_sig[k[0]] += n
        et_sids = {x for x, nm in ref_names.items() if not nm.startswith('SURICATA')}
        et_ref = sum(n for k, n in ref_p.items() if k[0] in et_sids)

        groups = defaultdict(list)
        for (c, name) in runs:
            if c == cap:
                groups[base_name(name)].append(name)
        for base, members in sorted(groups.items()):
            if len(members) > 1:
                members = sorted(members)
                flags, devs = [], []
                first = get((cap, members[0]))[0]
                for t in range(len(TIERS)):
                    flags.append(len({digest(get((cap, n))[0][t]) for n in members}) == 1)
                    devs.append(max(max(sum((first[t] - get((cap, n))[0][t]).values()),
                                        sum((get((cap, n))[0][t] - first[t]).values())) for n in members))
                det_rows.append([cap, base, len(members), ';'.join(members)] + flags + devs +
                                [digest(first[PRIMARY])[:16]])

        for (c, name), _path in sorted(runs.items()):
            if c != cap:
                continue
            level, policy, rep = parse_name(name)
            if rep != 1:
                continue
            counters, names, ep_flows, ep_detail = get((c, name))
            run_p = counters[PRIMARY]
            matched = matched_count(run_p, ref_p)
            run_total = sum(run_p.values())
            new = run_total - matched
            run_by_sig = Counter()
            for k, n in run_p.items():
                run_by_sig[k[0]] += n
            lost = [s for s in ref_by_sig if run_by_sig.get(s, 0) == 0]
            et_matched = matched_count(run_p, ref_p, et_sids)
            alt = [matched_count(counters[t], ref_c[t]) / (sum(ref_c[t].values()) or 1) for t in range(len(TIERS))]
            ret_rows.append([cap, level, policy, ref_total, run_total, matched, new,
                             round(matched / ref_total if ref_total else 1.0, 4), len(ref_by_sig), len(lost),
                             ep_flows, '; '.join('%s x%d' % (k, v) for k, v in ep_detail.most_common(3)),
                             et_ref, et_matched, round(alt[1], 4), round(alt[2], 4)])
            for s in sorted(set(ref_by_sig) | set(run_by_sig)):
                nm = ref_names.get(s, names.get(s, ''))
                origin = 'suricata-builtin' if nm.startswith('SURICATA') else 'ET-Open'
                sig_rows.append([cap, level, policy, s, nm, origin, ref_by_sig.get(s, 0), run_by_sig.get(s, 0)])

    with open(OUT_RET, 'w', newline='') as fh:
        w = csv.writer(fh)
        w.writerow(['capture', 'level', 'policy', 'ref_alerts', 'run_alerts', 'matched', 'new_unmatched',
                    'retention', 'ref_signatures', 'signatures_lost', 'ep_flows', 'ep_detail',
                    'ref_et_alerts', 'matched_et_alerts', 'retention_no_ts', 'retention_strict'])
        w.writerows(ret_rows)
    with open(OUT_SIG, 'w', newline='') as fh:
        w = csv.writer(fh)
        w.writerow(['capture', 'level', 'policy', 'sid', 'signature', 'origin', 'ref_count', 'run_count'])
        w.writerows(sig_rows)
    if det_rows:
        with open(OUT_DET, 'w', newline='') as fh:
            w = csv.writer(fh)
            w.writerow(['capture', 'config', 'runs_compared', 'run_names'] +
                       ['identical_' + t for t in TIERS] + ['max_unmatched_' + t for t in TIERS] + ['hash_prefix'])
            w.writerows(det_rows)

    print('%-24s %-5s %-12s %6s %6s %9s %7s %7s %5s %6s %9s' % ('capture', 'level', 'policy', 'ref', 'run', 'retention', 'no_ts', 'strict', 'new', 'lostS', 'ET kept'))
    for r in ret_rows:
        print('%-24s %-5s %-12s %6d %6d %8.1f%% %6.1f%% %6.1f%% %5d %3d/%-2d %5d/%d' % (r[0], r[1], r[2], r[3], r[4], r[7] * 100, r[14] * 100, r[15] * 100, r[6], r[9], r[8], r[13], r[12]))
    for r in det_rows:
        print('determinism %-22s %-10s %d runs identical: endpoint=%s no_ts=%s strict=%s | max unmatched alerts: endpoint=%d no_ts=%d strict=%d' % (r[0], r[1], r[2], r[4], r[5], r[6], r[7], r[8], r[9]))
    print('Wrote results/retention.csv, results/per_signature.csv' + (', results/determinism.csv' if det_rows else ''))


if __name__ == '__main__':
    main()
