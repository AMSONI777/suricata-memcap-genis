#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="jasonish/suricata:8.0.5"
[ -f "$ROOT/configs/base_image.yaml" ] || { echo "Missing configs/base_image.yaml (made by 03_feasibility.sh)"; exit 1; }
[ -s "$ROOT/rules/rules/suricata.rules" ] || { echo "Missing rules (made by 04_rules.sh)"; exit 1; }

echo "[1/3] Limiting eve.json output to alert, flow and stats events"
python3 "$ROOT/scripts/patch_eve_types.py" "$ROOT/configs/base_image.yaml" "$ROOT/configs/suricata.yaml"

echo "[2/3] Testing the config together with the ET Open rules (30-90 s)"
out="$(docker run --rm --entrypoint suricata -v "$ROOT":/work "$IMAGE" \
  -T -c /work/configs/suricata.yaml -S /work/rules/rules/suricata.rules 2>&1 || true)"
echo "$out" | tail -n 4
echo "$out" | grep -q 'successfully loaded' && echo "CONFIG TEST: OK" || { echo "CONFIG TEST: FAILED"; exit 1; }

echo "[3/3] Is a time tool available inside the image?"
docker run --rm --entrypoint sh "$IMAGE" -c 'command -v time || ls /usr/bin/time 2>/dev/null || echo "no time tool in image"'
