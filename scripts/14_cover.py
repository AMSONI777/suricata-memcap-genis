"""Experiment D: can a flood hide another attack?

  build <hidden-capture>   Builds data/raw/cover-hulk-<x>.pcapng: the DoS Hulk flood merged with a hidden attack whose
                           busiest 2,068-second alert window (the length of the Hulk capture) is shifted with editcap
                           to start at Hulk's first packet. Writes docs/cover-hulk-<x>.json with the shift and window.
  analyze                  For every merged capture that has runs in results/cover_runs, measures how many of the hidden
                           attack's alerts inside the window survive, (a) with the flood and (b) alone at the same
                           memory level (the existing runs in results/runs). Writes results/cover.csv.

Retention uses the study's alert key (signature, protocol, client, server, server port) and counts only alerts whose
packet time falls inside the window (for merged runs, after removing the shift). The reference is the hidden attack's
own L0 run, restricted to the same window.
"""
import csv
import datetime as dt
import gzip
import hashlib
import importlib.util
import json
import os
import statistics
import subprocess
import sys
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location('an', os.path.join(HERE, '07_analyze.py'))
an = importlib.util.module_from_spec(spec)
spec.loader.exec_module(an)

ROOT = an.ROOT
FLOOD = 'attack-dos-hulk'
COVER_RUNS = os.path.join(ROOT, 'results', 'cover_runs')
LOSS = 0.999
EDGE = 0.5  # seconds of slack at both window edges, so float rounding of the shift cannot move an alert out


def epoch(ts):
    return dt.datetime.strptime(ts, '%Y-%m-%dT%H:%M:%S.%f%z').timestamp()


def utc(t):
    return dt.datetime.fromtimestamp(t, dt.timezone.utc).strftime('%Y-%m-%d %H:%M:%S')


def alerts(path, lo=None, hi=None, shift=0.0):
    """Endpoint-key Counter and signature names for alerts with (time - shift) in [lo, hi]."""
    keys, names = Counter(), {}
    with gzip.open(path, 'rt') as fh:
        for line in fh:
            if '"event_type":"alert"' not in line:
                continue
            ev = json.loads(line)
            t = epoch(ev['timestamp']) - shift
            if lo is not None and not (lo - EDGE <= t <= hi + EDGE):
                continue
            a = ev['alert']
            k = (a['signature_id'], ev.get('proto'), ev.get('src_ip'), ev.get('src_port'),
                 ev.get('dest_ip'), ev.get('dest_port'), ev.get('timestamp'))
            keys[an.tier_keys(k)[an.PRIMARY]] += 1
            names[a['signature_id']] = a.get('signature', '')
    return keys, names


def first_packet(pcap):
    out = subprocess.run(['capinfos', '-a', '-S', '-T', '-r', pcap], check=True, capture_output=True,
                         text=True).stdout.strip()
    return float(out.split('\t')[-1])


def duration(pcap):
    out = subprocess.run(['capinfos', '-u', '-T', '-r', pcap], check=True, capture_output=True,
                         text=True).stdout.strip()
    return float(out.split('\t')[-1])


def build(hidden):
    name = 'cover-hulk-' + hidden.replace('attack-bruteforce-', '')
    raw = os.path.join(ROOT, 'data', 'raw')
    flood_pcap = os.path.join(raw, FLOOD + '.pcapng')
    hid_pcap = os.path.join(raw, hidden + '.pcapng')
    out_pcap = os.path.join(raw, name + '.pcapng')
    width = duration(flood_pcap)

    times = []
    with gzip.open(os.path.join(an.RUNS, hidden, 'L0_ignore', 'eve.json.gz'), 'rt') as fh:
        for line in fh:
            if '"event_type":"alert"' in line:
                times.append(epoch(json.loads(line)['timestamp']))
    times.sort()
    best, start, j = 0, times[0], 0
    for i in range(len(times)):
        while times[i] - times[j] > width:
            j += 1
        if i - j + 1 > best:
            best, start = i - j + 1, times[j]

    shift = first_packet(flood_pcap) - start
    tmp = out_pcap + '.shifted.tmp'
    subprocess.run(['editcap', '-t', '%.6f' % shift, hid_pcap, tmp], check=True)
    subprocess.run(['mergecap', '-w', out_pcap, flood_pcap, tmp], check=True)
    os.remove(tmp)

    h = hashlib.sha256()
    with open(out_pcap, 'rb') as fh:
        for block in iter(lambda: fh.read(1 << 20), b''):
            h.update(block)
    info = {'name': name, 'flood': FLOOD, 'hidden': hidden, 'window_seconds': round(width, 6),
            'window_start_epoch': start, 'window_end_epoch': start + width,
            'window_start_utc': utc(start), 'window_end_utc': utc(start + width),
            'hidden_alerts_total_L0': len(times), 'hidden_alerts_in_window_L0': best,
            'shift_seconds': round(shift, 6), 'merged_sha256': h.hexdigest(),
            'merged_first_packet_epoch': first_packet(out_pcap)}
    with open(os.path.join(ROOT, 'docs', name + '.json'), 'w') as fh:
        json.dump(info, fh, indent=2)
    for k, v in info.items():
        print('%-28s %s' % (k, v))


def analyze():
    rows = []
    with open(os.path.join(ROOT, 'results', 'cover_runs_summary.csv')) as fh:
        summ = {(r['capture'], r['level'], r['rep']): r for r in csv.DictReader(fh)}
    for name in sorted(os.listdir(COVER_RUNS)):
        with open(os.path.join(ROOT, 'docs', name + '.json')) as fh:
            info = json.load(fh)
        hid, lo, hi, shift = info['hidden'], info['window_start_epoch'], info['window_end_epoch'], info['shift_seconds']
        ref, names = alerts(os.path.join(an.RUNS, hid, 'L0_ignore', 'eve.json.gz'), lo, hi)
        total = sum(ref.values())
        et = {s for s, n in names.items() if not n.startswith('SURICATA')}
        et_total = sum(n for k, n in ref.items() if k[0] in et)
        print('\n%s: %d alerts of %s inside the window %s to %s UTC (%d ET Open)' % (
            name, total, hid, info['window_start_utc'], info['window_end_utc'], et_total))

        def measure(path, sh):
            got, _ = alerts(path, lo, hi, sh)
            return an.matched_count(got, ref) / total, an.matched_count(got, ref, et) / et_total if et_total else 1.0

        for cond, base, sh, cap in [('alone', an.RUNS, 0.0, hid), ('with flood', COVER_RUNS, shift, name)]:
            d = os.path.join(base, cap)
            for run in sorted(os.listdir(d)):
                if not os.path.exists(os.path.join(d, run, 'DONE')):
                    continue
                level, policy, rep = an.parse_name(run)
                if policy != 'ignore' or level not in ('L0', 'L1', 'L2', 'L3', 'L4'):
                    continue
                if cond == 'alone' and level == 'L0':
                    continue
                r, r_et = measure(os.path.join(d, run, 'eve.json.gz'), sh)
                s = summ.get((name, level, str(rep)), {}) if cond == 'with flood' else {}
                rows.append([name, hid, cond, level, rep, round(r, 4), round(r_et, 4),
                             s.get('sessions', ''), s.get('ssn_memcap_drop', '')])

    with open(os.path.join(ROOT, 'results', 'cover.csv'), 'w', newline='') as fh:
        w = csv.writer(fh)
        w.writerow(['merged_capture', 'hidden_attack', 'condition', 'level', 'rep', 'hidden_retention',
                    'hidden_retention_et', 'sessions', 'ssn_memcap_drop'])
        w.writerows(rows)

    print('\n%-20s %-5s %-34s %-34s' % ('merged capture', 'level', 'hidden attack alone', 'hidden attack with flood'))
    for name in sorted({r[0] for r in rows}):
        for lv in ['L0', 'L1', 'L2', 'L3', 'L4']:
            cells = []
            for cond in ('alone', 'with flood'):
                v = [r[5] for r in rows if r[0] == name and r[3] == lv and r[2] == cond]
                if not v:
                    cells.append('-')
                    continue
                k = sum(x < LOSS for x in v)
                cells.append('%5.1f-%5.1f %%  lost in %d/%d' % (100 * min(v), 100 * max(v), k, len(v)))
            if cells != ['-', '-']:
                print('%-20s %-5s %-34s %-34s' % (name, lv, cells[0], cells[1]))
    print('\nWrote results/cover.csv (%d runs)' % len(rows))


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == 'build':
        build(sys.argv[2])
    elif len(sys.argv) == 2 and sys.argv[1] == 'analyze':
        analyze()
    else:
        print(__doc__)
        sys.exit(1)
