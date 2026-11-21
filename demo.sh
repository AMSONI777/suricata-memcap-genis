#!/usr/bin/env bash
# demo.sh - live demonstration (about 2-3 minutes).
# Replays the DoS Hulk capture twice through the same Suricata, rules and config:
# once with plenty of stream memory (L0) and once with tight memory (L4, 1 MB / 4 MB), then prints both side by side.
# Output goes to demo/ and never touches results/.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"
export RUNS_SUB=demo/runs SUMMARY_FILE=demo/runs_summary.csv
rm -rf demo

echo "Run 1 of 2: DoS Hulk with plenty of stream memory (L0: 1 GB sessions / 4 GB reassembly)"
scripts/06_run.sh "attack-dos-hulk" "L0" "ignore"
echo
echo "Run 2 of 2: the same traffic with tight stream memory (L4: 1 MB sessions / 4 MB reassembly)"
scripts/06_run.sh "attack-dos-hulk" "L4" "ignore"

python3 scripts/13_demo_report.py
