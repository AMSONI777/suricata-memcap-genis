#!/usr/bin/env python3
"""Option 1, Step A: peak concurrent TCP sessions per capture, from the existing L0 reference runs.

Reads results/runs/<capture>/L0_ignore/eve.json.gz (flow records only; no new Suricata runs) and writes
results/peak_sessions.csv with, for each capture:
  tcp_flows          TCP flow records logged by Suricata
  active_min         first TCP flow start to last TCP flow end, in minutes (not the capture duration)
  flows_per_active_min  tcp_flows / active_min
  peak_active        largest number of TCP flows between their first and last packet at the same moment
  peak_held          largest number of TCP flows Suricata still holds at the same moment: from the first packet
                     until the last packet plus the TCP flow timeout for the flow's final state, read from
                     flow-timeouts.tcp in configs/suricata.yaml. A session's memory is only freed when its flow
                     times out, so this is the session count the memory limits actually have to hold.
  peak_held_time     when peak_held occurred (UTC)

Why from L0: at L0 no memory limit is hit, so every session is tracked and logged; a constrained run would
undercount the sessions that the memory model has to account for.
"""
import csv, gzip, json, os, sys
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RUNS = os.path.join(ROOT, 'results', 'runs')
OUT = os.path.join(ROOT, 'results', 'peak_sessions.csv')
CAPS = ['attack-dos-hulk', 'attack-dos-slowloris', 'attack-bruteforce-ssh', 'attack-bruteforce-ssh-ftp',
        'attack-bruteforce-smb', 'benign-admin-activity', 'benign-background-activity', 'benign-user-activity']


def tcp_timeouts():
    """Read flow-timeouts -> tcp from configs/suricata.yaml with a small line parser (no PyYAML needed)."""
    t, path = {}, os.path.join(ROOT, 'configs', 'suricata.yaml')
    in_ft = in_tcp = False
    ft_ind = tcp_ind = -1
    for raw in open(path):
        line = raw.split('#', 1)[0].rstrip()
        if not line.strip():
            continue
        ind = len(line) - len(line.lstrip())
        key, _, val = line.strip().partition(':')
        if key == 'flow-timeouts':
            in_ft, ft_ind = True, ind
            continue
        if in_ft and ind <= ft_ind:
            break
        if in_ft and key == 'tcp':
            in_tcp, tcp_ind = True, ind
            continue
        if in_tcp:
            if ind <= tcp_ind:
                in_tcp = False
                continue
            if val.strip().isdigit():
                t[key] = int(val.strip())
    for k in ('new', 'established', 'closed'):
        if k not in t:
            sys.exit(f'flow-timeouts.tcp.{k} not found in {path}')
    return t


TO = None


def ts(s):
    return datetime.strptime(s, '%Y-%m-%dT%H:%M:%S.%f%z').timestamp()


def analyse(path):
    events, held = [], []
    first, last = None, None
    with gzip.open(path, 'rt') as fh:
        for line in fh:
            if '"flow"' not in line:
                continue
            e = json.loads(line)
            if e.get('event_type') != 'flow' or e.get('proto') != 'TCP':
                continue
            f = e.get('flow', {})
            if 'start' not in f or 'end' not in f:
                continue
            a, b = ts(f['start']), ts(f['end'])
            if b < a:
                b = a
            events.append((a, 1))
            events.append((b, -1))
            state = f.get('state', 'established')
            held.append((a, 1))
            held.append((b + TO.get(state, TO['established']), -1))
            first = a if first is None or a < first else first
            last = b if last is None or b > last else last
    if not events:
        return None
    # At equal timestamps, process ends before starts, so a flow that ends exactly when another starts
    # is not counted as overlapping it.
    peak, _ = sweep(events)
    peak_h, peak_h_t = sweep(held)
    flows = len(events) // 2
    dur_min = max((last - first) / 60.0, 1e-9)
    return {
        'tcp_flows': flows,
        'active_min': round(dur_min, 2),
        'flows_per_active_min': round(flows / dur_min, 1),
        'peak_active': peak,
        'peak_held': peak_h,
        'peak_held_time': datetime.fromtimestamp(peak_h_t, timezone.utc).strftime('%Y-%m-%d %H:%M:%S'),
    }


def sweep(ev):
    ev.sort(key=lambda x: (x[0], x[1]))
    cur = peak = 0
    peak_t = ev[0][0]
    for t, d in ev:
        cur += d
        if cur > peak:
            peak, peak_t = cur, t
    return peak, peak_t


def main():
    global TO
    TO = tcp_timeouts()
    print('TCP flow timeouts from configs/suricata.yaml (s):', ', '.join(f'{k}={v}' for k, v in sorted(TO.items())))
    rows = []
    for cap in CAPS:
        p = os.path.join(RUNS, cap, 'L0_ignore', 'eve.json.gz')
        if not os.path.isfile(p):
            print(f'missing  {cap}: {p}')
            continue
        r = analyse(p)
        if r is None:
            print(f'no TCP flow records  {cap}')
            continue
        r = {'capture': cap, **r}
        rows.append(r)
        print(f"{cap:28s} flows={r['tcp_flows']:>6}  active_min={r['active_min']:>7}  "
              f"peak_active={r['peak_active']:>5}  peak_held={r['peak_held']:>6}  at {r['peak_held_time']}")
    if not rows:
        sys.exit('No L0 runs found under results/runs/.')
    with open(OUT, 'w', newline='') as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    print('wrote', os.path.relpath(OUT, ROOT))


if __name__ == '__main__':
    main()
