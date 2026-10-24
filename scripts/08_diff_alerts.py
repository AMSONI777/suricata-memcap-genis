import gzip
import json
import os
import sys
from collections import Counter

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
FIELDS = ('sid', 'proto', 'src_ip', 'src_port', 'dest_ip', 'dest_port', 'timestamp')


def load(capture, level, policy):
    path = os.path.join(ROOT, 'results', 'runs', capture, (level if '_' in level else '%s_%s' % (level, policy)), 'eve.json.gz')
    alerts = Counter()
    with gzip.open(path, 'rt') as fh:
        for line in fh:
            if '"event_type":"alert"' in line:
                ev = json.loads(line)
                alerts[(ev['alert']['signature_id'], ev.get('proto'), ev.get('src_ip'), ev.get('src_port'),
                        ev.get('dest_ip'), ev.get('dest_port'), ev.get('timestamp'))] += 1
    return alerts


def expand(counter):
    out = []
    for k, n in counter.items():
        out.extend([k] * n)
    return sorted(out, key=lambda x: tuple(str(i) for i in x))


def main():
    if len(sys.argv) < 4:
        sys.exit('usage: 08_diff_alerts.py <capture> <levelA> <levelB> [policy]')
    capture, la, lb = sys.argv[1], sys.argv[2], sys.argv[3]
    policy = sys.argv[4] if len(sys.argv) > 4 else 'ignore'
    a, b = load(capture, la, policy), load(capture, lb, policy)
    only_a = expand(a - b)
    only_b = expand(b - a)
    print('%s: %s alerts=%d | %s alerts=%d' % (capture, la, sum(a.values()), lb, sum(b.values())))
    print('only in %s: %d | only in %s: %d' % (la, len(only_a), lb, len(only_b)))

    ea, eb = Counter(), Counter()
    for k, n in a.items():
        ea[(k[0], k[1], k[2], k[4], k[5])] += n
    for k, n in b.items():
        eb[(k[0], k[1], k[2], k[4], k[5])] += n
    diffs = [(k, ea[k], eb[k]) for k in sorted(set(ea) | set(eb), key=lambda x: tuple(str(i) for i in x)) if ea[k] != eb[k]]
    print('Endpoint-level differences (signature, proto, client, server, port): %d' % len(diffs))
    for k, x, y in diffs[:12]:
        print('  %s  %d -> %d' % (k, x, y))

    pool = list(only_b)
    tally = Counter()
    pairs = []
    for ka in only_a:
        best, best_diff = None, None
        for kb in pool:
            if kb[0] != ka[0]:
                continue
            diff = tuple(FIELDS[i] for i in range(len(FIELDS)) if ka[i] != kb[i])
            if best is None or len(diff) < len(best_diff):
                best, best_diff = kb, diff
        if best is None:
            tally['no partner with same sid'] += 1
        else:
            pool.remove(best)
            tally[', '.join(best_diff) or 'identical'] += 1
            pairs.append((ka, best, best_diff))
    print('\nHow the unmatched alerts differ (closest partner with the same sid):')
    for k, n in tally.most_common():
        print('  %4d  differs in: %s' % (n, k))
    print('\nFirst examples (A -> B):')
    for ka, kb, diff in pairs[:6]:
        print('  sid %s differs in %s' % (ka[0], ', '.join(diff)))
        print('    A: %s' % (ka[1:],))
        print('    B: %s' % (kb[1:],))


if __name__ == '__main__':
    main()
