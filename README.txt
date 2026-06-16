\section{Introduction}
\label{sec:intro}

Quantum computing continues to advance at a rapid pace~\cite{arute2019quantum}, and with that we get closer to a world where Shor's algorithm~\cite{shor1999polynomial} breaks asymmetric cryptography and Grover's algorithm~\cite{grover1996fast} halves symmetric key strength, making deployed systems vulnerable. Efforts have been made to futureproof these systems (especially in light of the harvest-now-decrypt-later threat~\cite{mosca2018cybersecurity}); however, constrained devices (such as IoT devices) make a comprehensive switch to post-quantum cryptography (PQC) difficult owing to their inherent computational weaknesses.

Prior work has benchmarked PQ primitives in isolation or, where a symmetric layer exists, paired ML-KEM only with AES-GCM; to our knowledge no comparative end-to-end study exists (Section~\ref{sec:related_work}). This paper therefore presents a four-way comparison of complete PQ pipelines, pairing ML-KEM with SNOW-V-GCM, ChaCha20-Poly1305, AES-256-GCM, and a lightweight Ascon-PRNG XOR construction not previously benchmarked in a post-quantum pipeline. The hardware chosen is broadly representative of IoT devices and has been used in similar IoT research~\cite{fitzgibbon_kyber_rpi,seedorf2025smartcity}. Specifically, we use the Pi~5 (Cortex-A76, hardware AES present) and the Pi Zero~2~W (Cortex-A53, no hardware AES), which together span the capability spectrum.

This study has three objectives. The first is to benchmark the full PQC pipelines described above. The second is to test the hypothesis that the unauthenticated Ascon-PRNG XOR construction is the most efficient layer, in throughput and per-byte cost, on hardware lacking AES acceleration; outperforming AES-256-GCM on the Cortex-A53, which runs it in software, is expected a priori, so the discriminating comparisons are against the two software-friendly AEADs, ChaCha20-Poly1305 and SNOW-V-GCM, which themselves need no AES hardware. The third is to test the impact of moving from ML-KEM-768 to ML-KEM-1024. 

This paper uses five evaluation metrics: sustained throughput, stream latency, CPU utilisation, RAM usage, and ML-KEM key-establishment overhead, measured on both synthetic and real dataset payloads, and additionally evaluates frame bundling for video workloads. It is structured into the following sections: [to do: brief 1 sentence for each].===============================================================================
 5000OTP - Benchmarking Post-Quantum KEM with Stream Ciphers on IoT Hardware
===============================================================================

This repository benchmarks four complete post-quantum cryptographic pipelines on
two Raspberry Pi devices. Each pipeline establishes a key with ML-KEM (FIPS 203)
and then protects a packet stream with a different symmetric layer. The harness
runs the whole pipeline in one process on one device, with the sender and
receiver as two pinned threads talking over an in-memory ring buffer, so the
numbers reflect cipher cost rather than network cost.

This file explains: (1) what every file does, (2) the five metrics, (3) the
seven experiments and which script produces each, (4) how to build, (5) how to
run, (6) the output format, and (7) how to test and validate.

Companion documents:
  CODE_CHANGES_REQUIRED.md ......... implementation reference for the harness
  ../COMP 5000/experiment_definitions.md . authoritative experiment spec
  ../COMP 5000/HARNESS_GUIDE.md ........... plain-English code walkthrough
  ../COMP 5000/IMPLEMENTATION_GUIDE.md .... what each system implements
  ../COMP 5000/dev_log.md ................. dated decision record


-------------------------------------------------------------------------------
 1. THE FOUR SYSTEMS
-------------------------------------------------------------------------------

  System A  ML-KEM + AES-256-GCM            (OpenSSL libcrypto)   AEAD
  System B  ML-KEM + SNOW-V-GCM             (in-house GCM layer)  AEAD
  System C  ML-KEM + ChaCha20-Poly1305      (libsodium)           AEAD
  System D  ML-KEM + Ascon-XOF128 XOR       (NIST Ascon ref)      no auth

Each system is built at two security levels, ML-KEM-768 (NIST Level 3) and
ML-KEM-1024 (NIST Level 5), giving eight binaries: system_a_kem768 ...
system_d_kem1024.

Devices:
  Pi 5         Cortex-A76, has the ARMv8 crypto extensions (hardware AES/PMULL)
  Pi Zero 2 W  Cortex-A53, no crypto extensions (AES and GHASH run in software)

System D has no authentication tag and keeps a single continuous Ascon keystream
across packets, so a dropped packet desynchronises it and invalidates the run.


-------------------------------------------------------------------------------
 2. FILE MANIFEST  (what each file is meant to do)
-------------------------------------------------------------------------------

harness/                  Header-only benchmarking library, shared by all systems
  ring_buffer.hpp         Lock-free single-producer/single-consumer ring buffer.
                          Packet slots hold up to 64 KB + 32 B, so 1/2/4-frame
                          video bundles all fit with no change.
  kem.hpp                 Wraps liboqs ML-KEM: keygen / encaps / decaps / verify.
  metrics.hpp             SharedStats (atomic counters) + MetricsWriter (the CSV).
                          Writes the 15-column CSV, the per-packet rows, and the
                          one ML-KEM summary row (packet_id = -1, Experiment 5).
  sampler.hpp             Background thread: samples CPU%, RSS and temperature
                          once per second. Exposes read_rss_kb_now() for the
                          one-shot KEM memory snapshots.
  run_loop.hpp            The orchestrator. Parses args, times the KEM (Exp 5),
                          runs the producer (encrypt) and consumer (decrypt)
                          threads over the ring buffer, drives rate control or
                          saturation, and selects synthetic or real payloads.
  dataset_source.hpp      Reads real dataset payloads from a flat binary file of
                          fixed-size records, sequentially, wrapping at EOF.
                          Used only by Experiment 6.

systems/system_{a,b,c,d}/
  cipher.hpp              The cipher's encrypt()/decrypt() and its constants
                          (NONCE_BYTES, TAG_BYTES, NAME).
  main.cpp                Three lines: instantiate RunLoop<Cipher, Level> and
                          call run(argc, argv). Unchanged by the real-data work
                          (the optional --dataset-source arg is parsed in run()).
                          System B's GCM layer lives in libs/snowv/snowv_gcm.hpp.

libs/
  snowv/                  SNOW-V core (snow-v.h), the in-house SNOW-V-GCM layer
                          (snowv_gcm.hpp), and the KAT validation scripts.
  ascon/                  Ascon-XOF128 (NIST lightweight reference) for System D.

tests/
  kat_system_{a,b,c,d}.cpp  Known-answer / round-trip correctness tests (ctest).
  reference/snowv_gcm_ref.py  Independent reference for the SNOW-V-GCM tag.

datasets/
  prepare_real_payloads.py  Pre-processes the four source datasets into the five
                          fixed-size binary payload files for Experiment 6.
  analyse_datasets.py     Derives the workload rates/sizes from the datasets.

run_experiments.sh              Rate-controlled synthetic campaign (Exp 2-5, 7).
run_experiments_saturation.sh   Saturation throughput campaign (Exp 1, and 7).
run_experiments_real.sh         Real-dataset mirror campaign (Exp 6).

CMakeLists.txt            Build: 8 targets, -DDEVICE=PI5|PI0 sets the CPU flags.
CODE_CHANGES_REQUIRED.md  Implementation reference for the full Exp 1-7 design.
README.txt                This file.


-------------------------------------------------------------------------------
 3. THE FIVE METRICS
-------------------------------------------------------------------------------

  1. Throughput          maximum sustained Mbps (measured at saturation)
  2. Stream latency      per-packet encrypt and decrypt time (nanoseconds)
  3. CPU utilisation     process CPU%, sampled once per second (deployment figure)
  4. RAM usage           resident set size (RSS), sampled once per second
  5. ML-KEM overhead     encapsulation/decapsulation time + RSS delta at startup

Energy was deliberately excluded (no defensible on-die measurement on either
device). CPU% at the IoT target rates is reported as a deployment-capacity
figure, not a cipher ranking, because the busy-wait pacer dominates the producer
core at those rates. The cipher ranking rests on saturation throughput (Exp 1)
and per-byte latency (Exp 2).


-------------------------------------------------------------------------------
 4. THE SEVEN EXPERIMENTS
-------------------------------------------------------------------------------

Two regimes:
  Rate-controlled  producer paced to the workload's target rate; supplies
                   latency, CPU, RAM, and ML-KEM overhead at a realistic load.
  Saturation       rate limiter off (rate_mbps = 0), producer flat out; supplies
                   maximum throughput and the bundling improvement factor.

  Exp 1  Maximum Throughput        saturation, synthetic   run_experiments_saturation.sh
         Mbps each pipeline sustains flat out, across the four packet sizes.
         T = 8 * Np * b / (60 * 1e6).

  Exp 2  Per-Packet Latency        rate-controlled, synth  run_experiments.sh
         encrypt_ns and decrypt_ns per packet; median, p95, p99, IQR.

  Exp 3  CPU Utilisation           rate-controlled, synth  run_experiments.sh
         Mean/peak CPU% as a deployment-capacity figure.

  Exp 4  RAM Footprint             rate-controlled, synth  run_experiments.sh
         Peak RSS and within-run growth (leak screen) vs the 512 MB budget.

  Exp 5  ML-KEM Overhead           startup, every run      (all scripts)
         encaps/decaps time and RSS delta, written as the packet_id = -1 row.
         Compares ML-KEM-768 vs ML-KEM-1024 per device.

  Exp 6  Real-Dataset Validation   rate-controlled, real   run_experiments_real.sh
         Re-runs all twelve workloads with real bytes; reports the
         real-vs-synthetic delta (Wilcoxon) to confirm content-independence.

  Exp 7  Frame Bundling            both regimes, synth+real  all scripts
         Throughput (saturation) and per-frame latency (rate-controlled) for
         1-, 2-, and 4-frame video bundles; improvement factor rho_N = T_N/T_1.

Run matrix per device:
  Rate-controlled core (Exp 2-5)        4 x 2 x  6 x 30 = 1,440
  Rate-controlled bundling (Exp 7)      4 x 2 x  6 x 30 = 1,440
  Saturation (Exp 1, 7)                 4 x 2 x  4 x 30 =   960
  Real-dataset mirror (Exp 6)           4 x 2 x 12 x 30 = 2,880
  -------------------------------------------------------------
  TOTAL per device                                       6,720   (13,440 both)

At 70 s per run this is roughly 130 hours of run time per device before re-runs.
Optional time-saver: the saturation campaign may use a single KEM level (480
runs), since the KEM runs once at startup and is outside the throughput window.


-------------------------------------------------------------------------------
 5. WORKLOADS  (derived from real datasets; see dev_log Entry 012)
-------------------------------------------------------------------------------

  label                 rate_mbps  packet_bytes  source / used in
  telemetry_nbiot       0.10       512           UCI Power + TON_IoT   (Exp 1-6)
  telemetry_ltem        0.50       512           Edge-IIoTset          (Exp 1-6)
  video_low_10fps       0.62       16384         UCF-Crime             (Exp 1-6)
  video_mean_30fps      1.85       16384         UCF-Crime             (Exp 1-6,7)
  video_p95_30fps       2.65       16384         UCF-Crime             (Exp 1-6,7)
  video_stress_max      2.69       16384         UCF-Crime             (Exp 1-6,7)
  video_mean_2frame     1.85       32768         UCF-Crime (2 frames)  (Exp 7)
  video_mean_4frame     1.85       65536         UCF-Crime (4 frames)  (Exp 7)
  video_p95_2frame      2.65       32768         UCF-Crime (2 frames)  (Exp 7)
  video_p95_4frame      2.65       65536         UCF-Crime (4 frames)  (Exp 7)
  video_stress_2frame   2.69       32768         UCF-Crime (2 frames)  (Exp 7)
  video_stress_4frame   2.69       65536         UCF-Crime (4 frames)  (Exp 7)

Video packet size is a fixed slot: real PNG frames (4-11 KB) are zero-padded to
16,384 B; bundles concatenate frames into the 32,768 / 65,536 B slots.


-------------------------------------------------------------------------------
 6. BUILD
-------------------------------------------------------------------------------

Dependencies (install on each Pi):
  liboqs (ML-KEM, build from source), libssl-dev (OpenSSL), libsodium-dev.
  See Utility/setup_env.sh.

Build (the DEVICE flag sets the CPU flags; the Pi 5 build enables hardware AES,
the Pi Zero 2 W build deliberately does not):

  cmake -B build -DDEVICE=PI5      # on the Pi 5
  cmake -B build -DDEVICE=PI0      # on the Pi Zero 2 W
  cmake --build build -j4

This produces ./build/system_{a,b,c,d}_kem{768,1024} - eight binaries.
Then grant the lock-memory capability once (avoids the mlockall warning):

  sudo setcap cap_ipc_lock+ep ./build/system_*_kem*


-------------------------------------------------------------------------------
 7. RUN
-------------------------------------------------------------------------------

A binary takes three positional arguments plus one optional flag:

  ./build/system_a_kem768 <duration_secs> <rate_mbps> <packet_bytes> \
                          [--dataset-source <path>]

  duration_secs   total run, including a 10 s warm-up (use 70 = 10 + 60).
  rate_mbps       target rate; 0 means saturation (no rate limit).
  packet_bytes    plaintext bytes per packet (512 ... 65536).
  --dataset-source  optional; read real bytes from a payload file (Exp 6).

Normally you run the three campaign scripts, once per device. Each is resumable
(it records finished runs in a completed_runs*.log) and does a thermal pre-check
(below 70 C) before every run, but never interrupts a run once started:

  ./run_experiments.sh              # Exp 2-5, and Exp 7 rate-controlled latency
  ./run_experiments_saturation.sh   # Exp 1, and Exp 7 saturation throughput
  ./run_experiments_real.sh         # Exp 6 (real-dataset mirror)

Background a long campaign with:
  nohup ./run_experiments.sh > experiment_log.txt 2>&1 &

Real-dataset preparation (do this before run_experiments_real.sh):
  1. On a machine that holds the datasets:
       python3 datasets/prepare_real_payloads.py --datasets-root /path/to/datasets
     This writes five files to <datasets-root>/real_payloads/:
       real_payloads_telemetry_nbiot.bin   (512 B records)
       real_payloads_telemetry_ltem.bin    (512 B records)
       real_payloads_video_1frame.bin      (16384 B records)
       real_payloads_video_2frame.bin      (32768 B records)
       real_payloads_video_4frame.bin      (65536 B records)
     Each file is capped at ~256 MB by default (~1.3 GB total); the full
     UCF-Crime corpus would otherwise make each video file ~22 GB. The cap is
     immaterial (the ciphers are content-independent and no run exhausts its
     file within a run). Tune with --max-mb (pass 0 for no cap).
  2. Copy them to each Pi's LOCAL storage (default ~/datasets/real_payloads/;
     override with PAYLOAD_DIR=/path ./run_experiments_real.sh). Do not read
     payloads from a network mount during a run.


-------------------------------------------------------------------------------
 8. OUTPUT FORMAT
-------------------------------------------------------------------------------

Each run writes one CSV to the campaign's results directory, named
results_<system>_kem<level>_<device>_<timestamp>.csv. The 15 columns are:

  timestamp_ns, packet_id, plaintext_bytes, encrypt_ns, decrypt_ns,
  cpu_pct, rss_kb, system, kem_level, temp_c, payload_source,
  kem_encaps_ns, kem_decaps_ns, kem_pre_rss_kb, kem_post_rss_kb

  - The FIRST row of every file is the ML-KEM summary row, marked packet_id = -1.
    On it the per-packet timing columns are 0 and the four kem_* columns carry
    the Experiment 5 measurements. payload_source is "synthetic" or "real".
  - On every per-packet row the four kem_* columns are 0.
  - timestamp_ns is the encrypt start time (CLOCK_MONOTONIC).

Analysis rules:
  - Split on packet_id == -1 to separate KEM stats from per-packet stats.
  - Discard warm-up rows where timestamp_ns < (first per-packet timestamp + 10 s).
  - Rows before the first sampler tick have cpu_pct = 0 / rss_kb = 0; exclude
    them from the CPU and RAM metrics only.


-------------------------------------------------------------------------------
 9. HOW TO TEST AND VALIDATE
-------------------------------------------------------------------------------

Correctness gate (no performance numbers until all pass):

  A. Build the tests and run them:
       cmake --build build -j4 && ctest --test-dir build --output-on-failure
     This runs the known-answer / round-trip tests for Systems A-D, including
     the SNOW-V core vectors and the SNOW-V-GCM tag against snowv_gcm_ref.py.

  B. Tamper check: flip one ciphertext byte and confirm the AEAD systems
     (A, B, C) report an authentication failure on decrypt.

  C. System D synchronisation: encrypt and decrypt a few MB and confirm a
     byte-for-byte match (it has no tag to rely on).

  D. Memory budget: run each binary for a few seconds on the Pi Zero 2 W and
     confirm RSS stays well under 512 MB.

Per-run sanity checks (printed in the run summary):

  - "Auth failures : 0" on every AEAD run. Any non-zero value aborts the run.
  - packets_produced == packets_consumed on saturation runs (especially
    System D); a mismatch means packets were dropped and the run is invalid.
  - The CSV begins with a packet_id = -1 row whose kem_encaps_ns / kem_decaps_ns
    are non-zero.

Real-dataset checks:

  - prepare_real_payloads.py prints a per-file record count and size, and
    asserts each file is an exact multiple of its record size.
  - A quick end-to-end test without the full corpora:
       python3 datasets/prepare_real_payloads.py --datasets-root <small_tree> \
               --max-records 1000
    then run one binary with --dataset-source pointing at a generated .bin and
    confirm payload_source = "real" in the CSV and auth_failures = 0.


-------------------------------------------------------------------------------
 10. STATUS
-------------------------------------------------------------------------------

Implemented: the full Exp 1-7 harness, the three campaign scripts, and the
payload pre-processor (see dev_log Entry 015). Phase 1 was validated on the Pi 5;
the Pi Zero 2 W validation is still outstanding. The authoritative build must be
done on each Pi (liboqs / OpenSSL / libsodium on ARM).
