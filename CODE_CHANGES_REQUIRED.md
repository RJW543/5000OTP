# Code Changes Required: Synthetic-Only Harness to Full Exp 1–7 Design

> **IMPLEMENTED 2026-06-16.** All code in this document has been written into the
> repository: the harness changes (`metrics.hpp`, `run_loop.hpp`, `sampler.hpp`,
> and the new `dataset_source.hpp`), the run scripts (`run_experiments.sh`
> bundling workloads, new `run_experiments_saturation.sh` and
> `run_experiments_real.sh`), and `datasets/prepare_real_payloads.py`.  Verified
> in the dev sandbox where dependencies allowed: `dataset_source.hpp` wraparound,
> the 15-column CSV writer including the `packet_id = -1` KEM summary row, the
> seeded PRNG fill, all three scripts (`bash -n`), and the payload script (sample
> run). **Still to do (needs the Pi and the real corpora):** run
> `prepare_real_payloads.py` on the real datasets, build on each device
> (`cmake -DDEVICE=PI5|PI0`), and run the campaigns. The full ARM build with
> liboqs / OpenSSL / libsodium must be done on-device. This document now doubles
> as the implementation reference; see `dev_log.md` Entry 015.

**Original scope note (2026-06-16).** This document specifies every code change needed to move the harness from its prior state (synthetic payloads, four metrics, rate-controlled only, no ML-KEM timing) to the full design in `experiment_definitions.md` (canonical 2026-06-14): five metrics, two regimes, and both synthetic and real-dataset payloads. See `dev_log.md` Entry 013 for the scope decision.

This is written against the actual code in `harness/`, `systems/`, and `run_experiments.sh`, and corrects two places where `experiment_definitions.md` Section 8 does not match the current structure (noted inline).

---

## 1. Gap analysis

| Capability | Current code | Required | Experiment |
|---|---|---|---|
| Encrypt and decrypt latency | Recorded (`encrypt_ns`, `decrypt_ns`) | No change | Exp 2 |
| CPU, RAM, temperature | Sampled once per second | No change | Exp 3, 4 |
| Rate-controlled pacing | Busy-wait limiter; `rate_mbps = 0` already disables it | No change | Exp 2–4 |
| Ring buffer for 64 KB payloads | `MAX_DATA = 65536 + 32` already | No change | Exp 7 |
| Workload parameters | `run_experiments.sh` carries the Entry 012 values | No change | all |
| Maximum throughput at saturation | Limiter can be disabled, but the producer **drops** packets when the ring is full | Block instead of drop; add a saturation runner | Exp 1 |
| ML-KEM overhead | `kem.hpp` runs encaps/decaps but times nothing; no CSV field | Time encaps/decaps, snapshot RSS, write a summary row | Exp 5 |
| Real-dataset payloads | Producer fills a synthetic byte ramp only | Optional payload source reading real bytes from disk | Exp 6 |
| Frame bundling workloads | Not in the run scripts | Add six 32,768 / 65,536 B workloads | Exp 7 |
| Synthetic payload content | Seeded `mt19937_64` fill (was `i & 0xFF` ramp) | Done 2026-06-16 | cross-cutting |

---

## 2. What already works (do not re-implement)

- **Saturation pacing.** In `run_loop.hpp`, `inter_packet_ns` is `0` when `rate_mbps == 0`, and the busy-wait is guarded by `if (inter_packet_ns > 0)`. Passing `rate_mbps = 0` already runs the producer flat out. Only the ring-buffer drop behaviour (Section 3.A) still needs changing for saturation.
- **64 KB payloads.** `ring_buffer.hpp` sets `MAX_DATA = 65536 + 32`, and `run_loop.hpp` accepts `packet_bytes` up to `MAX_DATA - 32 = 65536`. The 2-frame (32,768 B) and 4-frame (65,536 B) bundling sizes fit with no buffer change.
- **Derived workload parameters.** `run_experiments.sh` already uses the corrected Entry 012 values (0.1/0.5/0.62/1.85/2.65/2.69 Mbps; 512/16384 B). The old pending action to replace hardcoded values is closed.
- **Both encrypt and decrypt are on the timed path.** `encrypt_ns` (producer) and `decrypt_ns` (consumer) are already recorded per packet.

---

## 3. Change set by experiment

### A. Experiment 1: saturation throughput

**A1. Ring-buffer backpressure with no drops (`harness/run_loop.hpp`).**
Today the producer retries `ring.push(pkt)` up to 1,000 times, then **drops** the packet and advances `packet_id`. At saturation the consumer cannot always keep up, so drops will occur. For System D (continuous Ascon keystream) any drop desynchronises the producer and consumer states and invalidates the entire run. Change: when running at saturation (`inter_packet_ns == 0`), the producer must block until `push()` succeeds (retry with `yield()` and no drop cap). Keep the 1,000-retry safety only for rate-controlled mode, where a persistent full ring is a genuine fault.

Sketch (producer lambda):

```cpp
const bool saturation = (inter_packet_ns == 0);
int retries = 0;
while (!ring.push(pkt)) {
    stats.ring_overflows.fetch_add(1, std::memory_order_relaxed);
    std::this_thread::yield();
    if (!saturation && ++retries > 1000) { /* existing drop + warning */ break; }
}
```

**A2. `run_experiments_saturation.sh` (new, repo root).**
Sweeps the four packet sizes `512, 16384, 32768, 65536` at `rate_mbps = 0`, 30 repeats, both KEM levels: `4 systems × 2 KEM × 4 sizes × 30 = 960 runs/device`. Use a separate `completed_runs_saturation.log` and a `results_saturation/` output directory. Reuse the thermal pre-check, resume, and pinning logic from `run_experiments.sh`. Optional time-saver: a single KEM level gives 480 runs, justified because the KEM runs once at startup and is outside the 60 s throughput window.

### B. Experiment 5: ML-KEM key-establishment overhead

**B1. Time the KEM operations (`harness/run_loop.hpp`, step 3).**
Bracket `kem.encaps()` and `kem.decaps()` with `now_ns()` to obtain `kem_encaps_ns` and `kem_decaps_ns`. Read RSS immediately before and after the KEM block for `kem_pre_rss_kb` and `kem_post_rss_kb`. Keep `kem.hpp` free of timing; do the timing in `run_loop` (it already owns `now_ns()`). The 1 s sampler is too coarse for an immediate RSS snapshot, but `sampler.hpp` already provides `static Sampler::read_rss_kb()`, which parses `VmRSS` from `/proc/self/status`. Call it directly before and after the KEM block; no new helper is needed.

**B2. Summary row in the CSV (`harness/metrics.hpp`).**
Add `MetricsWriter::write_kem_summary(...)` that writes one row with `packet_id = -1` carrying the four KEM values, written once before the per-packet rows. To keep a single rectangular schema, extend the header with four KEM columns that are `0` on per-packet rows and populated only on the summary row (see Section 4). Add a `write_kem_summary` call in `run_loop` right after `kem.verify()` and before the threads start.

### C. Experiment 6: real-dataset payloads

This is the largest change. It follows `experiment_definitions.md` Section 8, refined to the real code below.

**C1. `datasets/prepare_real_payloads.py` (new).**
Pre-process the four datasets into five flat binary files of fixed-size records (`512, 16384, 32768, 65536` B) using the padding and truncation rules in Section 8.1. Verify each output size is an exact multiple of its record size; print filename, record count, and total MB. Run once on the development machine; copy the `.bin` files to each Pi's **local** storage (for example `~/datasets/real_payloads/`). Never read payloads from a network mount during a run.

**C2. `harness/dataset_source.hpp` (new).**

```cpp
class DatasetSource {
public:
    DatasetSource(const std::string& path, size_t record_size); // fopen(path, "rb")
    bool ok() const;                       // false if the file could not be opened
    void fill(uint8_t* buf, size_t len);   // assert(len == record_size_); fread; rewind on short read
private:
    FILE*  fp_;
    size_t record_size_;
};
```

Sequential `fread` with `rewind()` on EOF; `fclose` in the destructor; no locks (producer-only); never memory-mapped (the 1-frame video file is roughly 22 GB on a 512 MB device).

**C3. Producer payload source (`harness/run_loop.hpp`).**
Today the producer fills one `plaintext` buffer **once** before the loop. Change it to take an optional dataset path:

- There is **no `RunLoopConfig` struct** in the current code (contrary to Section 8.3); `RunLoop<Cipher, Level>::run(argc, argv)` parses the three positional arguments inline. The minimal change is to parse an optional `--dataset-source <path>` (or an optional 4th positional) inside `run()`.
- If a path is set: construct a `DatasetSource` once, then call `dataset_source.fill(plaintext, packet_bytes)` **inside** the loop for every packet (replacing the one-time ramp fill). Abort with a clear message if `!ok()`.
- If unset: keep the current synthetic fill (see Section 3.E).

**C4. System entry points (`systems/*/main.cpp`): no change needed.**
Each `main.cpp` only forwards `argc/argv` to `RunLoop::run()`. Because parsing lives in `run()`, the four `main.cpp` files do **not** need editing. This deliberately diverges from Section 8.4 (which puts parsing in `main.cpp`); doing it in `run_loop` is cleaner and avoids touching four files. The existing three-argument interface stays backward-compatible, so `run_experiments.sh` keeps working unchanged.

**C5. `payload_source` column (`harness/metrics.hpp`).**
Add a `payload_source` column with value `synthetic` or `real`, passed from `run_loop`.

**C6. `run_experiments_real.sh` (new, repo root).**
A mirror of `run_experiments.sh` covering all twelve workloads (six base plus six bundling), appending `--dataset-source <path>` per workload (selected by `packet_bytes` / workload name), writing to `results_real/`, tracking `completed_runs_real.log`, with a pre-flight check that all five `.bin` files exist and are readable. `4 × 2 × 12 × 30 = 2,880 runs/device`.

### D. Experiment 7: frame bundling

**D1. Add six bundling workloads (scripts only).**
Add `video_mean_2frame`, `video_mean_4frame`, `video_p95_2frame`, `video_p95_4frame`, `video_stress_2frame`, `video_stress_4frame` (32,768 / 65,536 B) to `run_experiments.sh` (rate-controlled, for per-frame latency), to `run_experiments_saturation.sh` (sizes 32,768 / 65,536, for the throughput improvement factor), and to `run_experiments_real.sh`. **No binary change**: `packet_bytes` is a command-line argument and the ring buffer already holds 64 KB. This adds `4 × 2 × 6 × 30 = 1,440` synthetic rate-controlled runs/device.

### E. Cross-cutting: synthetic payload now a seeded PRNG (DONE, 2026-06-16)

**Decided by Rhydian and implemented this session.** The producer previously filled plaintext with `plaintext[i] = i & 0xFF`, a deterministic ramp, while the methodology describes synthetic payloads as "PRNG-generated random bytes". The fill is now a fixed-seed `std::mt19937_64` (seed `0x5EEDC0DE5000ABCDULL`), run once before the producer loop, so the payload is pseudo-random as specified yet reproducible across runs and devices. Verified to compile under C++17 (`-Wall -Wextra`) and to produce identical bytes across runs. Content remains independent of throughput and CPU, so no result is biased. When Exp 6 lands, this PRNG fill becomes the `synthetic` branch of the producer and the `real` branch reads from `DatasetSource`. `<random>` was added to the `run_loop.hpp` includes.

---

## 4. CSV schema change

**Before (10 columns):**

```
timestamp_ns,packet_id,plaintext_bytes,encrypt_ns,decrypt_ns,cpu_pct,rss_kb,system,kem_level,temp_c
```

**After (15 columns):**

```
timestamp_ns,packet_id,plaintext_bytes,encrypt_ns,decrypt_ns,cpu_pct,rss_kb,system,kem_level,temp_c,payload_source,kem_encaps_ns,kem_decaps_ns,kem_pre_rss_kb,kem_post_rss_kb
```

- Per-packet rows: the four KEM columns are `0`; `payload_source` is `synthetic` or `real`.
- One summary row per file: `packet_id = -1`; the per-packet timing columns are `0`; the four KEM columns are populated.
- Analysis scripts must (1) discard warm-up rows where `timestamp_ns < run_start + 10 s`, and (2) split on `packet_id == -1` to separate KEM stats from per-packet stats. Every existing analysis script needs this update, so make the schema change once, early.

---

## 5. Consolidated file list

| File | Action | Experiment | Change |
|---|---|---|---|
| `harness/run_loop.hpp` | Modify | 1, 5, 6, E | Saturation no-drop branch; KEM timing and summary-row call; optional `--dataset-source` and per-packet `fill()`; **seeded PRNG synthetic fill (E, done 2026-06-16)** |
| `harness/metrics.hpp` | Modify | 5, 6 | Add four KEM columns and `write_kem_summary()`; add `payload_source` column |
| `harness/sampler.hpp` | No change | 5 | Reuse the existing `static Sampler::read_rss_kb()` |
| `harness/kem.hpp` | No change (recommended) | 5 | Time in `run_loop`, keep this header pure |
| `harness/dataset_source.hpp` | Create | 6 | Sequential fixed-size record reader with wraparound |
| `harness/ring_buffer.hpp` | No change | 7 | Already holds 64 KB |
| `systems/*/main.cpp` | No change | 6 | Parsing lives in `run_loop`; four files untouched |
| `datasets/prepare_real_payloads.py` | Create | 6 | Pre-process datasets into five `.bin` files |
| `run_experiments.sh` | Modify | 7 | Add six bundling workloads |
| `run_experiments_saturation.sh` | Create | 1, 7 | `rate_mbps = 0` sweep over four sizes |
| `run_experiments_real.sh` | Create | 6 | Real-data mirror of all twelve workloads |
| `tests/*` | Re-run, extend | all | KATs must still pass; add a `DatasetSource` wraparound check |

---

## 6. Run-matrix impact

| Campaign | Runs/device | Regime | Payload |
|---|---|---|---|
| Rate-controlled core (Exp 2–5) | 1,440 | rate-controlled | synthetic |
| Saturation (Exp 1, 7) | 960 | saturation | synthetic |
| Synthetic bundling (Exp 7) | 1,440 | rate-controlled | synthetic |
| Real-dataset mirror (Exp 6) | 2,880 | both | real |
| **Total** | **6,720** | | |

Across both devices, 13,440 runs. At 70 s per run that is roughly 130 hours of pure run time per device, before thermal pauses and re-runs. Fallbacks if time is tight: single KEM level at saturation (saves 480/device), and a representative workload subset for the real-data mirror.

---

## 7. Suggested order and validation

Implement in this order, rebuilding and re-running the KATs after each step:

1. **Exp 5** (smallest, self-contained): KEM timing, summary row, schema. Unblocks a whole metric.
2. **Exp 1**: ring-buffer no-drop branch and `run_experiments_saturation.sh`. Unblocks the headline throughput discriminator.
3. **Exp 7**: add the six workloads to the scripts.
4. **Exp 6** (largest): `prepare_real_payloads.py`, `dataset_source.hpp`, the producer branch, `payload_source`, `run_experiments_real.sh`.
5. **(E) Seeded PRNG synthetic fill: done 2026-06-16** (implemented in `run_loop.hpp` and compile-checked).

Validation checklist:

- KATs pass for Systems A–D after every change.
- A 70 s smoke run per system per device completes with `auth_failures = 0`.
- System D at saturation: `packets_produced == packets_consumed` (zero drops).
- The KEM summary row is present with non-zero `kem_encaps_ns` / `kem_decaps_ns`.
- A real-data run reports `payload_source = real`, wraps past EOF without error, and the `.bin` sizes are exact multiples of the record size.
- The Pi Zero 2 W stays within 512 MB with the ~16 MB ring plus a sequential `FILE*` (no mmap).

---

## 8. Documentation to update after the code lands

- `HARNESS_GUIDE.md`: the `metrics.hpp` column list, the `run_loop.hpp` producer path, the new `dataset_source.hpp`, and the KEM timing.
- `IMPLEMENTATION_GUIDE.md`: the "Before You Run Any Benchmarks" and build/run sections, and the new scripts.
- Header comments in `run_loop.hpp` (the twelve-step list) and `metrics.hpp` (the CSV columns block).

---

## 9. Risks

- **Scope on an unfinished base.** Rhydian has accepted the full campaign (about 130 hours per device) and now has full autonomy, so sign-off is no longer a gate (2026-06-16). The remaining practical dependency is that the Pi Zero 2 W Phase 1 validation is still outstanding; finish it before launching the expanded campaign. The fallbacks below are contingency only.
- **Large payload files (capped 2026-06-16).** `prepare_real_payloads.py` caps each file to about 256 MB by default (`--max-mb`, pass 0 for the full corpus), so the five files total about 1.3 GB; uncapped, each video file would be about 22 GB. The cap is immaterial to the metrics, because the ciphers are content-independent and no workload exhausts its file within a single run (see `dev_log.md` Entry 016). Still copy the files to each Pi's local storage and read sequentially.
- **Saturation plus System D.** Drops invalidate the run. The no-drop change (3.A1) is mandatory before any System D saturation run.
- **Schema ripple.** The new columns touch every analysis script. Make the change once, up front.

---

## 10. System B: SNOW-V → SNOW-Vi (2026-07-02, Entry 017)

System B's cipher changes from SNOW-V-GCM to SNOW-Vi-GCM (IACR ePrint 2021/236). Rationale and the validation record are in `dev_log.md` Entry 017; this section lists the code changes only.

**Done (written from the paper's reference, validated in the x86 dev sandbox against the official vectors and cross-checks):**

- `snow-vi.h` — portable, endianness-free SNOW-Vi keystream core, a 1:1 translation of the paper's Listing 4. Reproduces official vectors #1/#2 and matches an SSE translation over 10,000 random key/IV pairs.
- `snowvi_gcm.hpp` — SNOW-Vi-GCM AEAD, the same construction as `snowv_gcm.hpp` with GHASH reused unchanged and only the keystream generator swapped. Round-trip, tamper rejection, and a spec re-derivation of (ciphertext, tag) all pass.

**To do:**

- Move `snow-vi.h` and `snowvi_gcm.hpp` into `libs/snowv/`; add a SNOW-Vi KAT (the three official vectors) to `tests/`.
- Rewire `systems/system_b/cipher.hpp` to call `snowvi_gcm_encrypt` / `snowvi_gcm_decrypt`, and change `CipherB::NAME` from "SNOW-V-GCM" to "SNOW-Vi-GCM".
- Change the `CIPHERS` list in `analyse_synthetic.py` from "SNOW-V-GCM" to "SNOW-Vi-GCM" so new CSVs and figures self-label (existing System B CSVs carry the old name).
- Update `CMakeLists.txt` if the System B target gains source files.
- **Accelerated GHASH — DONE in software (2026-07-02, Entry 018):** `snowvi_ghash.hpp` provides PMULL (Pi 5), a 4-bit Shoup table (Zero), and PCLMUL (x86 dev host); `snowvi_gcm.hpp` now calls it. Validated byte-for-byte against the bitwise reference (table + PCLMUL, 300k field multiplies and 200k full `ghash()`), and the full GCM passes round-trip / tamper / re-derivation in both builds. The PMULL path mirrors the validated PCLMUL and is pending only its on-Pi byte-for-byte + official-vector check.
- **Accelerated FSM — still to do:** AES-instruction (AESE/AESMC) FSM on the Pi 5 (`+crypto`), NEON on the Zero; must reproduce `snow-vi.h` byte-for-byte and pass the official vectors, validated compiled-and-run on each Pi. (SNOW-Vi's cheaper LFSR already helps; the FSM's two AES rounds are the remaining scalar cost.)
- Re-run System B on both devices; only then update the manuscript prose and results (System B is SNOW-Vi throughout).
