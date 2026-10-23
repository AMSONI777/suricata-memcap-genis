#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="jasonish/suricata:8.0.5"
PCAP="data/raw/attack-dos-hulk.pcapng"
OUTROOT="$ROOT/results/feasibility"
SUMMARY="$ROOT/docs/feasibility.txt"
[ -f "$ROOT/$PCAP" ] || { echo "Missing $PCAP. Run scripts/02_extract_manifest.sh first."; exit 1; }
mkdir -p "$OUTROOT"

echo "[1/4] Container check"
docker run --rm --entrypoint suricata "$IMAGE" -V 2>&1 | grep -m1 'This is Suricata' \
  || { echo "Could not start suricata this way. Send me this message."; exit 1; }

run_one() {  # label, stream.memcap, stream.reassembly.memcap
  local label="$1" sm="$2" rsm="$3" out="$OUTROOT/$1"
  rm -rf "$out"; mkdir -p "$out"
  local cmd=(docker run --rm -e "OWN=$(id -u):$(id -g)" -e "OUTDIR=/work/results/feasibility/$label"
    --entrypoint sh -v "$ROOT":/work "$IMAGE" -c
    'suricata "$@"; rc=$?; chown -R "$OWN" "$OUTDIR"; exit $rc' sh
    -r "/work/$PCAP" -k none --runmode single -S /dev/null
    -l "/work/results/feasibility/$label"
    --set "stream.memcap=$sm" --set "stream.reassembly.memcap=$rsm"
    --set "stream.prealloc-sessions=128" --set "stream.reassembly.segment-prealloc=128"
    --set "flow.memcap=1gb" --set "defrag.memcap=256mb")
  printf '%q ' "${cmd[@]}" > "$OUTROOT/$label.cmd.txt"
  local t0=$SECONDS
  if ! "${cmd[@]}" > "$OUTROOT/$label.console.txt" 2>&1; then
    echo "Run $label FAILED. Last lines of its console output:"
    tail -n 15 "$OUTROOT/$label.console.txt"; exit 1
  fi
  echo "  $label done in $((SECONDS - t0)) s (stream.memcap=$sm, reassembly.memcap=$rsm)"
}

echo "[2/4] Reference run L0 (1 GiB / 4 GiB)"
run_one L0 1gb 4gb
echo "[3/4] Constrained run L4 (1 MiB / 4 MiB)"
run_one L4 1mb 4mb

counter() {  # label, counter name -> last value in stats.log, or "absent"
  awk -v k="$2" '$1==k {v=$NF} END{print (v==""?"absent":v)}' "$OUTROOT/$1/stats.log"
}
[ -f "$OUTROOT/L0/stats.log" ] && [ -f "$OUTROOT/L4/stats.log" ] || { echo "stats.log missing"; exit 1; }
[ "$(counter L0 decoder.pkts)" != "absent" ] || { echo "decoder.pkts missing: stats not usable"; exit 1; }

echo "[4/4] Result"
{
  echo "Memory-exhaustion check on attack-dos-hulk.pcapng"
  echo "Date: $(date '+%Y-%m-%d %H:%M')   Image: $(cat "$ROOT/docs/image_digest.txt")"
  printf '%-30s %-14s %-14s\n' "counter" "L0 (1G/4G)" "L4 (1M/4M)"
  for k in decoder.pkts tcp.sessions tcp.ssn_memcap_drop tcp.segment_memcap_drop \
           tcp.reassembly_gap tcp.stream_depth_reached tcp.memuse tcp.reassembly_memuse flow.memuse; do
    printf '%-30s %-14s %-14s\n' "$k" "$(counter L0 "$k")" "$(counter L4 "$k")"
  done
  a="$(counter L4 tcp.ssn_memcap_drop)"; b="$(counter L4 tcp.segment_memcap_drop)"
  [ "$a" = "absent" ] && a=0; [ "$b" = "absent" ] && b=0
  if [ "$((a + b))" -gt 0 ]; then
    echo "VERDICT: memcap counters rose at L4 -> memcap design is usable as written."
  else
    echo "VERDICT: memcap counters stayed at zero at L4 -> use the stream.reassembly.depth fallback."
  fi
} | tee "$SUMMARY"

docker run --rm --entrypoint cat "$IMAGE" /etc/suricata/suricata.yaml > "$ROOT/configs/base_image.yaml"
echo
echo "Base config saved: configs/base_image.yaml ($(wc -l < "$ROOT/configs/base_image.yaml") lines)"
grep -n -E '^(outputs|stream|flow|defrag):|^  - (eve-log|stats):|^ *types:|memcap:|prealloc' "$ROOT/configs/base_image.yaml" | head -40 || true
