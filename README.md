# Blind Under Load

**Measuring Suricata detection loss under stream memory exhaustion using the GeNIS 2025 enterprise intrusion dataset**

CMSC 5323 Network Security, University of Central Oklahoma, Fall 2026. Author: Amit Soni.

## Question

Suricata keeps TCP sessions and reassembled stream data in two memory pools with fixed limits
(`stream.memcap` and `stream.reassembly.memcap`). When a pool is full, Suricata applies an exception policy and keeps
going. This project measures how many alerts are lost when those limits are too small, which traffic is affected first,
which exception policy loses the least, which pool causes which loss, and whether a flood can use the effect to hide a
second attack.

## Main results

All numbers come from the files in `results/` and are drawn in `figures/`.

| Finding | Evidence |
|---|---|
| Suricata's default limits (L1, 64 MB / 256 MB) lost no alerts on any of the 8 captures. | `figures/fig1_heatmap_ignore.png` |
| Alerts were lost only when a stream memory limit was hit: 0 of 181 runs that never hit a limit lost alerts (lowest retention 99.95 %); 128 of 134 runs that hit one did. | `results/table_limit_hit_vs_loss.csv`, `figures/fig3_limit_hit_vs_loss.png` |
| The level where loss starts depends on the traffic: DoS Hulk at L2, SMB brute force at L3, SSH, SSH+FTP and Slowloris at L4. | `results/table_loss_onset.csv` |
| Once memory runs out, the flow-level policies (drop-flow, pass-flow, bypass) lose more than `ignore`, e.g. SMB at L4: 41.2-43.8 % kept with `ignore`, 11.7-16.4 % with the others. | `figures/fig2_policy_comparison.png` |
| The two pools protect different detections. The session limit removes Suricata's built-in `SURICATA STREAM` checks (Hulk S4 loses the same 10 signatures as L4); the reassembly limit removes the content rules (Hulk R4 keeps 6.6-8.8 % of ET Open alerts, like L4). | `results/separate_limits.csv`, `figures/fig4_separate_limits.png` |
| At the defaults a DoS flood hides nothing. Below them it hides part of a brute-force attack: SSH brute force under the Hulk flood at L3 lost alerts in 4 of 4 runs (86.9-99.2 % kept) and in 0 of 3 runs alone. | `results/cover.csv`, `figures/fig6_flood_cover.png` |
| Near a limit, identical runs can give different results, so unstable cells are reported as "lost in k of n runs" with a range. | `results/table_loss_k_of_n.csv` |
| Reference runs (L0) are deterministic; the largest run-to-run difference was 5 of 5,963 alerts (0.08 %, SSH+FTP). | `results/determinism.csv` |

## Design

| Item | Choice |
|---|---|
| Suricata | 8.0.5, Docker image `jasonish/suricata:8.0.5` pinned by digest (`docs/image_digest.txt`), offline replay (`-r`), `--runmode single` |
| Rules | ET Open snapshot of 2026-10-23, 53,249 enabled rules, SHA-256 in `docs/ruleset.txt`, file in `rules/rules/suricata.rules` |
| Data | 8 TCP captures from GeNIS 2025 (Zenodo record 14919237): 5 attacks, 3 benign; hashes in `docs/manifest.csv` |
| Memory levels | L0 1 GB / 4 GB (reference), L1 64 MB / 256 MB (Suricata default), L2 16 / 64 MB, L3 4 / 16 MB, L4 1 / 4 MB |
| Separate limits | S3, S4: only `stream.memcap` tight; R3, R4: only `stream.reassembly.memcap` tight (other pool at L0) |
| Exception policies | `ignore`, `drop-packet`, `drop-flow`, `pass-flow`, `bypass` |
| Metric | Alert retention: alerts of a run that match the capture's L0 alerts by signature, protocol, client, server and server port, divided by the L0 alert count; also reported for ET Open rules only |
| Loss | Retention below 99.9 % (outside the 0.08 % noise floor) |
| Runs | 353 runs on the 8 captures (grid, repeats, separate limits) and 20 runs on the 2 merged flood captures |

## Requirements

Ubuntu 20.04 or later, Docker, Python 3, `wireshark-common` (for `capinfos`, `editcap`, `mergecap`), and matplotlib for
the figures (`pip3 install --user matplotlib`). Free disk for the GeNIS archive (its 12 captures total
3.9 GB uncompressed; 8 are extracted, about 0.7 GB) plus the two merged captures (about 0.4 GB). Runs were made on a VM
with 8 GB RAM; Suricata's peak resident memory was 0.5-0.9 GB.

## Quick start

```bash
scripts/01_setup.sh            # pull the pinned image, download and check the GeNIS archive (MD5)
scripts/02_extract_manifest.sh # extract the 8 captures, check sizes, write docs/manifest.csv
./reproduce.sh                 # 7 runs, about 10 minutes; prints MATCH/MISMATCH per check and REPRODUCED
./demo.sh                      # DoS Hulk at L0 and at L4, side by side, about 3 minutes
```

`reproduce.sh` checks the image digest, the ruleset hash and the capture hashes first, then compares three L0 reference
runs exactly and four DoS Hulk runs (L1, L4, S4, R4) against the recorded ranges. Its output on the study VM is in
`docs/reproduce_log.txt`. It writes to `verify/` and `demo.sh` writes to `demo/`; neither touches `results/`.

Do not re-download the rules: `scripts/04_rules.sh` would fetch today's ET Open, which differs from the snapshot used.

## Full pipeline

| Script | Purpose |
|---|---|
| `scripts/01_setup.sh` | Pull the Suricata image, download and verify the GeNIS archive |
| `scripts/02_extract_manifest.sh` | Extract the 8 captures and record their size, packets, duration and SHA-256 |
| `scripts/03_feasibility.sh` | First check that the container runs and that the memory settings take effect; writes `configs/base_image.yaml` |
| `scripts/04_rules.sh` | One-time ET Open download (already done; snapshot kept in the repo) |
| `scripts/05_make_config.sh` | Build `configs/suricata.yaml` (eve.json limited to alert, flow and stats) and test it with the rules |
| `scripts/06_run.sh` | Run captures x levels x policies: `scripts/06_run.sh "<captures>" "<levels>" "<policies>"`; `REP=n` for repeats |
| `scripts/07_analyze.py` | Per-run counters and the first-run retention tables (`retention.csv`, `per_signature.csv`, `determinism.csv`) |
| `scripts/08_diff_alerts.py` | Alert-by-alert difference between two runs (used for the noise floor) |
| `scripts/10_all_runs.py` | Retention of every run against its capture's L0 run (`results/retention_all.csv`) |
| `scripts/11_separate_limits.py` | Separate-limits table (`results/separate_limits.csv`) |
| `scripts/14_cover.py` | Experiment D: `build <capture>` makes the merged flood capture, `analyze` writes `results/cover.csv` |
| `scripts/09_figures.py` | All figures and the summary tables (`results/table_*.csv`) |
| `scripts/12_verify.py`, `scripts/13_demo_report.py` | Comparison and report steps of `reproduce.sh` and `demo.sh` |
| `scripts/patch_*.py` | One-off patches applied during the study, kept for the record |

The full grid takes several hours. Every run directory gets a `DONE` marker, so an interrupted batch resumes where it
stopped.

## Repository layout

```
configs/     suricata.yaml used for every run, base_image.yaml from the image
data/raw/    the 8 GeNIS captures and the 2 merged flood captures (not in git; rebuilt by the scripts)
docs/        logs of every batch, ruleset and image records, capture manifest, Experiment D build records
docs/archive/  pilot and week-9 notes from the planning phase (superseded, kept for the record)
figures/     report figures
results/     run summaries and all result tables (per-run eve.json output is not in git)
rules/rules/ ET Open snapshot used for all runs
scripts/     the pipeline above
```

## Limitations

Offline replay in single-thread mode, one Suricata version, one ruleset snapshot and one dataset. Live capture,
the multi-threaded `workers` runmode and other memory pools (`flow.memcap`, `defrag.memcap`) were held fixed and not
studied. Runs close to a limit are not repeatable; those cells report the spread over 2-4 runs instead of one value.
