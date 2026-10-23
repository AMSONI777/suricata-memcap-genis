#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ZIP="$ROOT/data/1-packets.zip"
RAW="$ROOT/data/raw"
OUT="$ROOT/docs/manifest.csv"

declare -A SIZE=(
  [attack-dos-hulk]=165985552
  [attack-dos-slowloris]=95941252
  [attack-bruteforce-ssh]=18518420
  [attack-bruteforce-ssh-ftp]=30262616
  [attack-bruteforce-smb]=16418576
  [benign-admin-activity]=1514016
  [benign-background-activity]=29711488
  [benign-user-activity]=319471568
)
ORDER="attack-dos-hulk attack-dos-slowloris attack-bruteforce-ssh attack-bruteforce-ssh-ftp attack-bruteforce-smb benign-admin-activity benign-background-activity benign-user-activity"

command -v capinfos >/dev/null || { echo "capinfos not found. Run: sudo apt-get install -y wireshark-common"; exit 1; }
[ -f "$ZIP" ] || { echo "Missing $ZIP. Run scripts/01_setup.sh first."; exit 1; }
mkdir -p "$RAW"

echo "[1/3] Extracting the 8 TCP captures"
for c in $ORDER; do
  f="$RAW/$c.pcapng"
  if [ ! -f "$f" ] || [ "$(stat -c %s "$f")" != "${SIZE[$c]}" ]; then
    unzip -j -o -q "$ZIP" "1-packets/$c.pcapng" -d "$RAW"
  fi
  got="$(stat -c %s "$f")"
  [ "$got" = "${SIZE[$c]}" ] || { echo "SIZE MISMATCH for $c: $got vs ${SIZE[$c]}"; exit 1; }
  echo "  ok  $c ($got bytes)"
done

echo "[2/3] Building manifest"
echo "capture,size_bytes,sha256,packets,duration_s,first_packet,last_packet" > "$OUT"
for c in $ORDER; do
  f="$RAW/$c.pcapng"
  sha="$(sha256sum "$f" | cut -d' ' -f1)"
  info="$(capinfos -M -c -u -a -e "$f")"
  pk="$(echo "$info" | awk -F': *' '/^Number of packets/{print $2}')"
  du="$(echo "$info" | awk -F': *' '/^Capture duration/{split($2,a," "); print a[1]}')"
  t1="$(echo "$info" | awk -F': *' 'tolower($0) ~ /^(earliest|first) packet time/{print $2}')"
  t2="$(echo "$info" | awk -F': *' 'tolower($0) ~ /^(latest|last) packet time/{print $2}')"
  echo "$c,${SIZE[$c]},$sha,$pk,$du,$t1,$t2" >> "$OUT"
done

echo "[3/3] Manifest"
column -s, -t "$OUT" | cut -c1-200
awk -F, 'NR>1{p+=$4; b+=$2} END{printf "TOTAL: %d packets, %.1f MB across 8 captures\n", p, b/1e6}' "$OUT"
