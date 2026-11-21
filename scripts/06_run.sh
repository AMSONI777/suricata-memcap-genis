#!/usr/bin/env bash
# Usage: scripts/06_run.sh "<captures>" "<levels>" "<policies>"
# Example: scripts/06_run.sh "attack-dos-hulk" "L0 L4" "ignore"
# Environment: REP=2 (repeat reference runs), FORCE=1 (redo finished runs),
#   RUNS_SUB / SUMMARY_FILE (output folder and summary file, relative to the repo; used by reproduce.sh and demo.sh)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="jasonish/suricata:8.0.5"
ALL_CAPS="attack-dos-hulk attack-dos-slowloris attack-bruteforce-ssh attack-bruteforce-ssh-ftp attack-bruteforce-smb benign-admin-activity benign-background-activity benign-user-activity"
CAPS="${1:-$ALL_CAPS}"
LEVELS="${2:-L0 L1 L2 L3 L4}"
POLICIES="${3:-ignore drop-packet drop-flow pass-flow bypass}"
REP="${REP:-}"

declare -A SM=([L0]=1gb [L1]=64mb [L2]=16mb [L3]=4mb [L4]=1mb [S3]=4mb [R3]=1gb [S4]=1mb [R4]=1gb)
declare -A RM=([L0]=4gb [L1]=256mb [L2]=64mb [L3]=16mb [L4]=4mb [S3]=4gb [R3]=16mb [S4]=4gb [R4]=4mb)
RUNS_SUB="${RUNS_SUB:-results/runs}"
SUMMARY="$ROOT/${SUMMARY_FILE:-results/runs_summary.csv}"

[ -f "$ROOT/configs/suricata.yaml" ] || { echo "Missing configs/suricata.yaml. Run scripts/05_make_config.sh first."; exit 1; }
[ -s "$ROOT/rules/rules/suricata.rules" ] || { echo "Missing rules. Run scripts/04_rules.sh first."; exit 1; }
for lv in $LEVELS; do [ -n "${SM[$lv]:-}" ] || { echo "Unknown level: $lv"; exit 1; }; done
for pol in $POLICIES; do
  case "$pol" in ignore|drop-packet|drop-flow|pass-flow|bypass) ;; *) echo "Unknown policy: $pol"; exit 1;; esac
done
for cap in $CAPS; do [ -f "$ROOT/data/raw/$cap.pcapng" ] || { echo "Missing capture: $cap"; exit 1; }; done

mkdir -p "$ROOT/$RUNS_SUB"
[ -f "$SUMMARY" ] || echo "capture,level,policy,rep,exit,wall_s,packets,sessions,ssn_memcap_drop,seg_memcap_drop,reassembly_gap,alerts,peak_mem_kb" > "$SUMMARY"
if ! head -n 1 "$SUMMARY" | grep -q peak_mem_kb; then
  awk 'NR==1{print $0",peak_mem_kb"; next} {print $0","}' "$SUMMARY" > "$SUMMARY.tmp" && mv "$SUMMARY.tmp" "$SUMMARY"
fi

for cap in $CAPS; do
  for lv in $LEVELS; do
    for pol in $POLICIES; do
      if [ "$lv" = "L0" ] && [ "$pol" != "ignore" ]; then continue; fi
      name="${lv}_${pol}${REP:+_r$REP}"
      dir="$ROOT/$RUNS_SUB/$cap/$name"
      if [ -f "$dir/DONE" ] && [ -z "${FORCE:-}" ]; then echo "skip   $cap $name (already done)"; continue; fi
      rm -rf "$dir"; mkdir -p "$dir"
      cmd=(docker run --rm -e "OWN=$(id -u):$(id -g)" -e "OUTDIR=/work/$RUNS_SUB/$cap/$name"
        --entrypoint sh -v "$ROOT":/work "$IMAGE" -c
        'suricata "$@" & pid=$!; peak=0
         while kill -0 "$pid" 2>/dev/null; do
           if [ -r "/proc/$pid/status" ]; then
             while read -r k v r; do if [ "$k" = "VmHWM:" ]; then peak=$v; break; fi; done < "/proc/$pid/status"
           fi
           sleep 0.5
         done
         wait "$pid"; rc=$?
         echo "$peak" > "$OUTDIR/peak_mem_kb.txt"
         chown -R "$OWN" "$OUTDIR"; exit $rc' sh
        -r "/work/data/raw/$cap.pcapng" -c /work/configs/suricata.yaml -S /work/rules/rules/suricata.rules
        -k none --runmode single -l "/work/$RUNS_SUB/$cap/$name"
        --set "classification-file=/work/rules/rules/classification.config"
        --set "stream.memcap=${SM[$lv]}" --set "stream.reassembly.memcap=${RM[$lv]}"
        --set "stream.memcap-policy=$pol" --set "stream.reassembly.memcap-policy=$pol"
        --set "stream.prealloc-sessions=128" --set "stream.reassembly.segment-prealloc=128"
        --set "flow.memcap=1gb" --set "defrag.memcap=256mb")
      printf '%q ' "${cmd[@]}" > "$dir/cmd.txt"
      t0=$SECONDS
      set +e; "${cmd[@]}" > "$dir/console.txt" 2>&1; rc=$?; set -e
      wall=$((SECONDS - t0))
      if [ "$rc" -ne 0 ]; then
        echo "FAILED $cap $name (exit $rc). Last lines:"; tail -n 15 "$dir/console.txt"; exit 1
      fi
      st="$dir/stats.log"
      cnt() { awk -v k="$1" '$1==k {v=$NF} END{print (v==""?0:v)}' "$st"; }
      alerts="$(grep -c '"event_type":"alert"' "$dir/eve.json" || true)"
      peak="$(cat "$dir/peak_mem_kb.txt" 2>/dev/null || true)"
      gzip -f "$dir/eve.json"
      touch "$dir/DONE"
      echo "$cap,$lv,$pol,${REP:-1},$rc,$wall,$(cnt decoder.pkts),$(cnt tcp.sessions),$(cnt tcp.ssn_memcap_drop),$(cnt tcp.segment_memcap_drop),$(cnt tcp.reassembly_gap),$alerts,$peak" >> "$SUMMARY"
      printf 'done   %-26s %-18s %4ss  sessions=%s ssn_drop=%s alerts=%s peak=%sMB\n' "$cap" "$name" "$wall" "$(cnt tcp.sessions)" "$(cnt tcp.ssn_memcap_drop)" "$alerts" "$((${peak:-0} / 1024))"
    done
  done
done
