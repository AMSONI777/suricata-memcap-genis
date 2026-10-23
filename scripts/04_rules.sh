#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="jasonish/suricata:8.0.5"
mkdir -p "$ROOT/rules"
grep -qx 'rules/update/' "$ROOT/.gitignore" || echo 'rules/update/' >> "$ROOT/.gitignore"

echo "[1/2] Downloading ET Open ruleset (one-time snapshot)"
docker run --rm -e "OWN=$(id -u):$(id -g)" --entrypoint sh -v "$ROOT/rules":/var/lib/suricata "$IMAGE" -c \
  'suricata-update --no-test --no-reload; rc=$?; chown -R "$OWN" /var/lib/suricata; exit $rc'

R="$ROOT/rules/rules/suricata.rules"
[ -s "$R" ] || { echo "No rules file was produced"; exit 1; }

echo "[2/2] Recording the snapshot"
{
  echo "ET Open ruleset snapshot"
  echo "Downloaded: $(date '+%Y-%m-%d %H:%M')"
  echo "Image: $(cat "$ROOT/docs/image_digest.txt")"
  echo "File: rules/rules/suricata.rules"
  echo "SHA-256: $(sha256sum "$R" | cut -d' ' -f1)"
  echo "Size: $(du -h "$R" | cut -f1)"
  echo "Enabled rules: $(grep -c '^alert' "$R")"
} | tee "$ROOT/docs/ruleset.txt"
