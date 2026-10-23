#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="jasonish/suricata:8.0.5"
ZIP_URL="https://zenodo.org/records/14919237/files/1-packets.zip?download=1"
ZIP_MD5="5afbceaadfe3c3476f54723434d59b4a"
ZIP="$ROOT/data/1-packets.zip"
mkdir -p "$ROOT"/data/raw "$ROOT"/docs "$ROOT"/results "$ROOT"/configs "$ROOT"/rules

echo "[1/4] Suricata image"
docker image inspect "$IMAGE" >/dev/null 2>&1 || docker pull "$IMAGE"
docker inspect --format '{{index .RepoDigests 0}}' "$IMAGE" | tee "$ROOT/docs/image_digest.txt"
docker run --rm "$IMAGE" --build-info | grep -m1 'This is Suricata'

echo "[2/4] GeNIS archive"
if [ ! -f "$ZIP" ]; then wget -c -O "$ZIP" "$ZIP_URL"; fi
GOT="$(md5sum "$ZIP" | cut -d' ' -f1)"
if [ "$GOT" = "$ZIP_MD5" ]; then echo "MD5 OK ($GOT)"; else
  echo "MD5 MISMATCH (got $GOT). Delete $ZIP and run this script again."; exit 1; fi

echo "[3/4] Archive contents"
unzip -l "$ZIP" | tee "$ROOT/docs/zip_listing.txt"

echo "[4/4] Disk"
df -h "$ROOT" | tail -1
