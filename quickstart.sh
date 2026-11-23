#!/usr/bin/env bash
# quickstart.sh - everything in one command: setup, data, reproducibility check and demo (about 20 minutes).
#
#   git clone https://github.com/AMSONI777/suricata-memcap-genis.git && cd suricata-memcap-genis && ./quickstart.sh
#
# Needs Ubuntu 20.04 or later with Docker, Python 3 and wireshark-common, at least 4 GB of RAM and 5 GB of free disk.
set -euo pipefail
cd "$(dirname "$0")"

say() { printf '\n=== %s ===\n' "$1"; }
need() { command -v "$1" >/dev/null || { echo "STOP: $1 is not installed. $2"; exit 1; }; }

say "Checking the machine"
need docker "Install it with: sudo apt install docker.io"
need python3 "Install it with: sudo apt install python3"
need capinfos "Install it with: sudo apt install wireshark-common"
need wget "Install it with: sudo apt install wget"
need unzip "Install it with: sudo apt install unzip"
docker info >/dev/null 2>&1 || { echo "STOP: Docker is installed but not usable by this user. Run: sudo usermod -aG docker \$USER, then log out and in."; exit 1; }
mem_mb=$(awk '/MemTotal/{print int($2/1024)}' /proc/meminfo)
[ "$mem_mb" -ge 3500 ] || echo "WARNING: ${mem_mb} MB of RAM; at least 4 GB is recommended."
echo "ok"

# Older systems (e.g. Ubuntu 20.04) cannot verify Zenodo's certificate chain. The archive is still verified by MD5
# in scripts/01_setup.sh, so certificate checking is only relaxed when it is the reason the download would fail.
if [ -z "${WGET_OPTS:-}" ] && ! wget -q --spider --timeout=20 https://zenodo.org/ 2>/dev/null; then
  if wget -q --spider --timeout=20 --no-check-certificate https://zenodo.org/ 2>/dev/null; then
    export WGET_OPTS=--no-check-certificate
    echo "Note: this system cannot verify Zenodo's certificate; downloading without that check (MD5 still verified)."
  fi
fi

say "Step 1 of 4: Suricata image and GeNIS archive"
scripts/01_setup.sh
say "Step 2 of 4: extracting and checking the 8 captures"
scripts/02_extract_manifest.sh
say "Step 3 of 4: reproducibility check (7 runs, about 10 minutes)"
./reproduce.sh
say "Step 4 of 4: demonstration, DoS Hulk with plenty of memory and with 1 MB / 4 MB (about 3 minutes)"
./demo.sh
say "Done: see REPRODUCED above, verify/ and demo/"
