#!/usr/bin/env bash
# reproduce.sh - short reproducibility check (about 10 minutes, 7 Suricata runs).
#
# Re-runs a small subset of the study and compares it with the recorded results in results/:
#   - three L0 reference runs (alert and session counts must match exactly), and
#   - four Hulk runs: L1 (defaults, no loss), L4 (both limits tight), S4 (session limit only), R4 (reassembly only).
# Output goes to verify/ and never touches results/.
#
# Needs: Docker, Python 3, the GeNIS captures in data/raw/ (scripts/01_setup.sh and 02_extract_manifest.sh),
# the archived ET Open snapshot in rules/rules/suricata.rules and configs/suricata.yaml (scripts/05_make_config.sh).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"
IMAGE="jasonish/suricata:8.0.5"
fail() { echo "STOP: $1"; exit 1; }

echo "[1/4] Checking inputs"
command -v docker >/dev/null || fail "Docker is not installed."
command -v python3 >/dev/null || fail "Python 3 is not installed."
docker image inspect "$IMAGE" >/dev/null 2>&1 || docker pull "$IMAGE"
want="$(cat docs/image_digest.txt)"
got="$(docker inspect --format '{{index .RepoDigests 0}}' "$IMAGE")"
[ "$got" = "$want" ] && echo "  ok  Suricata image $got" || fail "image digest $got differs from recorded $want."

[ -s rules/rules/suricata.rules ] || fail "rules/rules/suricata.rules is missing. Use the ruleset snapshot from the project archive (a fresh download gives a different ruleset)."
want="$(awk '/^SHA-256:/{print $2}' docs/ruleset.txt)"
got="$(sha256sum rules/rules/suricata.rules | cut -d' ' -f1)"
[ "$got" = "$want" ] && echo "  ok  ET Open snapshot $got" || fail "ruleset SHA-256 $got differs from recorded $want. Use the archived snapshot."

[ -s configs/suricata.yaml ] || fail "configs/suricata.yaml is missing. Run scripts/05_make_config.sh."
echo "  ok  configs/suricata.yaml"

for cap in benign-admin-activity attack-bruteforce-smb attack-dos-hulk; do
  f="data/raw/$cap.pcapng"
  [ -f "$f" ] || fail "$f is missing. Run scripts/01_setup.sh and scripts/02_extract_manifest.sh."
  if [ -f docs/manifest.csv ]; then
    want="$(awk -F, -v c="$cap" '$1==c{print $3}' docs/manifest.csv)"
    got="$(sha256sum "$f" | cut -d' ' -f1)"
    [ "$got" = "$want" ] && echo "  ok  $cap capture" || fail "$cap SHA-256 differs from docs/manifest.csv."
  else
    echo "  --  $cap capture present (docs/manifest.csv not found, hash not checked)"
  fi
done

export RUNS_SUB=verify/runs SUMMARY_FILE=verify/runs_summary.csv
rm -rf verify

echo "[2/4] Reference runs with plenty of memory (L0)"
scripts/06_run.sh "benign-admin-activity attack-bruteforce-smb attack-dos-hulk" "L0" "ignore"

echo "[3/4] Hulk with constrained memory (L1, L4, S4, R4)"
scripts/06_run.sh "attack-dos-hulk" "L1 L4 S4 R4" "ignore"

echo "[4/4] Comparing with the recorded results"
python3 scripts/12_verify.py
