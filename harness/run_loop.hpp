#pragma once

/*
 * run_loop.hpp
 *
 * Wires all harness components together and drives the benchmark loop.
 *
 * RunLoop<Cipher, Level>::run() executes the following twelve steps:
 *
 *   1.  Parse command-line arguments (duration, rate, packet size).
 *   2.  Lock all process memory into RAM (mlockall) to prevent page-fault
 *       latency spikes during measurement.
 *   3.  Run ML-KEM keygen → encaps → decaps; verify both shared secrets match.
 *   4.  Initialise two Cipher instances (one per thread) with the shared key.
 *   5.  Open the output CSV file.
 *   6.  Declare shared state: SharedStats and RingBuffer.
 *   7.  Start the sampler thread on core 0.
 *   8.  Compute the wall-clock run deadline.
 *   9.  Start the consumer thread on core 2.
 *   10. Start the producer thread on core 1.
 *   11. Join all threads.
 *   12. Flush the CSV and print the run summary.
 *
 * Warm-up convention
 * ------------------
 * The full duration_secs window is recorded to the CSV without any in-code
 * exclusion.  The first 10 seconds are designated as warm-up by convention:
 * analysis scripts should discard rows where timestamp_ns < run_start + 10 s.
 * The code itself makes no distinction - all packets are written to the CSV.
 * The recommended invocation of 70 s therefore yields ~60 s of usable data.
 *
 * Usage:   ./system_a_kem768 <duration_secs> <rate_mbps> <packet_bytes>
 * Example: ./system_a_kem768 70 1.5 1400
 *
 * Cipher concept - the Cipher type must provide:
 *   void    init(const uint8_t key[32])
 *   size_t  encrypt(in, plaintext_len, nonce, aad, aad_len, out)
 *   ssize_t decrypt(in, ciphertext_len, nonce, aad, aad_len, out)
 *   static constexpr size_t NONCE_BYTES   (0 for System D / keystream mode)
 *   static constexpr size_t TAG_BYTES
 *   static constexpr const char* NAME
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <thread>
#include <stdexcept>

#include <pthread.h>
#include <sched.h>
#include <sys/mman.h>

#include "ring_buffer.hpp"
#include "metrics.hpp"
#include "sampler.hpp"
#include "kem.hpp"


// ---------------------------------------------------------------------------
// pin_this_thread_to_core() - pins the calling thread to the given CPU core.
// Reduces scheduling jitter by preventing the OS from migrating the thread.
// ---------------------------------------------------------------------------

static void pin_this_thread_to_core(int core) {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(core, &cpuset);
    if (pthread_setaffinity_np(pthread_self(),
                               sizeof(cpu_set_t), &cpuset) != 0) {
        fprintf(stderr,
            "[run_loop] WARNING: could not pin thread to core %d.\n"
            "           Timing results may be noisier than expected.\n", core);
    }
}


// ---------------------------------------------------------------------------
// RunLoop<Cipher, Level>
// ---------------------------------------------------------------------------

template<typename Cipher, KemLevel Level>
class RunLoop {

    // Ring buffer depth.  256 slots gives the producer up to 255 packets of
    // headroom before push() starts returning false.
    static constexpr size_t RING_SIZE = 256;


    // fill_nonce() - constructs the per-packet nonce from the packet counter.
    //
    // Layout: the nonce buffer is zeroed and the 64-bit counter is written
    // into the last 8 bytes via memcpy.  The counter is therefore stored in
    // the native byte order of the host CPU (little-endian on all supported
    // ARM targets - Pi 5 and Pi Zero 2 W).  Both the producer and consumer
    // call this function with the same packet_id, so the nonces always match
    // regardless of endianness, provided both sides share the same hardware.
    // The layout would differ on a big-endian host; do not compare nonce
    // byte sequences across architectures.
    //
    // Does nothing for System D (NONCE_BYTES == 0), which maintains a
    // continuous Ascon keystream with no per-packet nonce.  For System D the
    // nonce pointer passed to encrypt/decrypt is nullptr.
    static void fill_nonce(uint8_t* buf, uint64_t counter) {
        if constexpr (Cipher::NONCE_BYTES > 0) {
            memset(buf, 0, Cipher::NONCE_BYTES);
            const size_t offset = Cipher::NONCE_BYTES - sizeof(uint64_t);
            memcpy(buf + offset, &counter, sizeof(uint64_t));
        }
    }


public:

    int run(int argc, char** argv) {

        // ------------------------------------------------------------------
        // 1. Parse arguments.
        // ------------------------------------------------------------------

        if (argc < 4) {
            fprintf(stderr,
                "Usage: %s <duration_secs> <rate_mbps> <packet_bytes>\n"
                "\n"
                "  duration_secs  Total run time including 10 s warm-up.\n"
                "                 Recommended: 70 (= 10 s warm-up + 60 s measurement).\n"
                "\n"
                "  rate_mbps      Target throughput in Mbps.  Use 0 for max speed.\n"
                "\n"
                "  packet_bytes   Plaintext bytes per packet.\n"
                "                 Examples: 32 (telemetry), 1400 (IP), 40960 (video).\n"
                "\n"
                "Example: %s 70 1.5 1400\n",
                argv[0], argv[0]);
            return 1;
        }

        const uint64_t duration_secs = strtoull(argv[1], nullptr, 10);
        const double   rate_mbps     = strtod  (argv[2], nullptr);
        const size_t   packet_bytes  = strtoull(argv[3], nullptr, 10);

        if (packet_bytes == 0 || packet_bytes > Packet::MAX_DATA - 32) {
            fprintf(stderr,
                "[run_loop] ERROR: packet_bytes must be between 1 and %zu.\n",
                Packet::MAX_DATA - 32);
            return 1;
        }

        // Convert target rate to a per-packet inter-arrival delay in nanoseconds.
        // Set to 0 if rate_mbps is 0, which disables rate limiting.
        const double   rate_bps        = rate_mbps * 1e6;
        const uint64_t inter_packet_ns = (rate_bps > 0.0)
            ? static_cast<uint64_t>(
                (static_cast<double>(packet_bytes) * 8.0 / rate_bps) * 1e9)
            : 0;

        fprintf(stdout,
            "=== %s  KEM-%d ===\n"
            "  duration     : %llu s (first 10 s are warm-up)\n"
            "  target rate  : %.3f Mbps\n"
            "  packet size  : %zu B plaintext\n"
            "  inter-pkt gap: %llu ns\n",
            Cipher::NAME, static_cast<int>(Level),
            (unsigned long long)duration_secs,
            rate_mbps,
            packet_bytes,
            (unsigned long long)inter_packet_ns);

        // ------------------------------------------------------------------
        // 2. Lock all process memory into RAM so the OS does not page any
        //    part of the working set to disk during the experiment.
        //    A page fault mid-run would produce large latency spikes.
        // ------------------------------------------------------------------

        if (mlockall(MCL_CURRENT | MCL_FUTURE) != 0) {
            fprintf(stderr,
                "[run_loop] WARNING: mlockall() failed.\n"
                "           Latency measurements may include OS page-fault spikes.\n"
                "           Run as root, or: sudo setcap cap_ipc_lock+ep %s\n",
                argv[0]);
        }

        // ------------------------------------------------------------------
        // 3. ML-KEM key exchange.
        //    Runs keygen, encaps, decaps, then verifies both secrets match.
        //    Aborts if they do not - the cipher would use the wrong key.
        // ------------------------------------------------------------------

        fprintf(stdout, "[run_loop] Running ML-KEM key exchange...\n");
        MlKem<Level> kem;
        kem.print_info();

        kem.keygen();
        kem.encaps();
        kem.decaps();

        if (!kem.verify()) {
            fprintf(stderr,
                "[run_loop] FATAL: ML-KEM shared secrets do not match!\n"
                "           This is a liboqs bug or build misconfiguration.\n"
                "           Aborting - the cipher would be using the wrong key.\n");
            return 1;
        }
        fprintf(stdout, "[run_loop] Key exchange OK - both secrets match.\n");

        // ------------------------------------------------------------------
        // 4. Initialise two Cipher instances with the shared key.
        //    Two separate instances are required because producer and consumer
        //    run concurrently on different cores and all cipher implementations
        //    maintain internal mutable state (SNOW-V keystream position,
        //    AES-GCM counter, etc.) that is not thread-safe.  Sharing a single
        //    instance would require a mutex, defeating the purpose of the
        //    lock-free ring buffer.
        // ------------------------------------------------------------------

        Cipher cipher_enc;   // given to the producer thread
        Cipher cipher_dec;   // given to the consumer thread
        cipher_enc.init(kem.shared_secret_sender());
        cipher_dec.init(kem.shared_secret_receiver());

        // ------------------------------------------------------------------
        // 5. Open the output CSV file.
        // ------------------------------------------------------------------

        const std::string csv_path = make_output_filename(Cipher::NAME,
                                                          static_cast<int>(Level),
                                                          DEVICE_NAME);
        MetricsWriter writer;
        if (!writer.open(csv_path)) return 1;
        fprintf(stdout, "[run_loop] Writing results to: %s\n\n", csv_path.c_str());

        // ------------------------------------------------------------------
        // 6. Shared state and ring buffer.
        //    Declared here to ensure they outlive all threads.
        // ------------------------------------------------------------------

        SharedStats stats;
        // RingBuffer<256> holds 256 × ~65 KB Packet slots ≈ 16 MB.
        // Declaring it on the stack would overflow the default 8 MB thread
        // stack before a single line of run() executes.  Heap-allocate it.
        auto ring_storage = std::make_unique<RingBuffer<RING_SIZE>>();
        RingBuffer<RING_SIZE>& ring = *ring_storage;

        // ------------------------------------------------------------------
        // 7. Start the sampler on core 0.
        // ------------------------------------------------------------------

        Sampler sampler(stats);
        sampler.start(0);

        // ------------------------------------------------------------------
        // 8. Calculate the wall-clock run deadline.
        // ------------------------------------------------------------------

        const uint64_t run_start_ns = now_ns();
        const uint64_t run_end_ns   = run_start_ns
                                    + duration_secs * 1'000'000'000ULL;

        // ------------------------------------------------------------------
        // 9. Consumer thread (core 2).
        //    Pops packets from the ring, decrypts each one, records timing,
        //    and writes a CSV row.  Exits when the ring is empty and
        //    stats.stop is true.
        // ------------------------------------------------------------------

        std::thread consumer_thread([&]() {
            pin_this_thread_to_core(2);

            // Zero-length arrays are illegal in C++, so the nonce buffer is
            // sized at max(NONCE_BYTES, 1).  For System D this buffer is
            // never read.
            uint8_t nonce[Cipher::NONCE_BYTES > 0 ? Cipher::NONCE_BYTES : 1];
            uint8_t plaintext[Packet::MAX_DATA];

            Packet pkt;

            while (true) {
                if (!ring.pop(pkt)) {
                    if (stats.stop.load(std::memory_order_acquire)) break;
                    std::this_thread::yield();
                    continue;
                }

                // Reconstruct the nonce from the packet ID using the same
                // formula the producer used, so both sides match.
                fill_nonce(nonce, pkt.packet_id);

                const uint64_t dec_start = now_ns();

                ssize_t dec_len = cipher_dec.decrypt(
                    pkt.data,
                    pkt.ciphertext_len,
                    Cipher::NONCE_BYTES > 0 ? nonce : nullptr,
                    nullptr, 0,
                    plaintext);

                const uint64_t dec_end = now_ns();

                if (dec_len < 0) {
                    // Authentication tag mismatch - the ciphertext was
                    // corrupted or the cipher has a bug.  The run summary
                    // will abort if auth_failures is non-zero.
                    stats.auth_failures.fetch_add(1, std::memory_order_relaxed);
                }

                stats.packets_consumed.fetch_add(1, std::memory_order_relaxed);

                writer.write_row(
                    pkt.packet_id,
                    pkt.plaintext_len,
                    pkt.encrypt_start_ns,
                    pkt.encrypt_end_ns  - pkt.encrypt_start_ns,
                    dec_end             - dec_start,
                    stats.cpu_pct.load(std::memory_order_relaxed),
                    stats.rss_kb.load(std::memory_order_relaxed),
                    Cipher::NAME,
                    static_cast<int>(Level),
                    stats.temp_mc.load(std::memory_order_relaxed));
            }
        });


        // ------------------------------------------------------------------
        // 10. Producer thread (core 1).
        //     Encrypts packets and pushes them onto the ring until the
        //     wall-clock deadline is reached.
        //
        //     Rate control: next_send_ns is initialised to now_ns() before
        //     the loop.  If an encrypt() call takes longer than one inter-
        //     packet interval, next_send_ns falls behind now_ns() and the
        //     busy-wait exits immediately for subsequent packets, allowing the
        //     producer to catch up.  This gives a best-effort constant
        //     average rate rather than a strict per-packet schedule.
        //     std::this_thread::sleep() is deliberately avoided because its
        //     resolution is typically 1–10 ms, which is too coarse for
        //     microsecond inter-packet gaps at rates above ~1 Mbps.
        //
        //     Ring overflow handling: if push() fails after 1000 retries
        //     the producer logs a warning and moves on, incrementing both
        //     packets_produced and packet_id.  The dropped packet will not
        //     appear in packets_consumed, creating a measurable discrepancy
        //     in the run summary.  For AEAD systems (A–C) this means a
        //     silently dropped packet; the nonce counter still advances, so
        //     subsequent packets are unaffected.  For System D (Ascon
        //     keystream) any dropped packet desynchronises the cipher states
        //     and corrupts all subsequent decrypts - the results are invalid.
        //
        //     Sets stats.stop when finished so the consumer and sampler exit.
        // ------------------------------------------------------------------

        std::thread producer_thread([&]() {
            pin_this_thread_to_core(1);

            uint8_t plaintext[Packet::MAX_DATA];
            for (size_t i = 0; i < packet_bytes; ++i)
                plaintext[i] = static_cast<uint8_t>(i & 0xFF);

            uint8_t  ciphertext[Packet::MAX_DATA];
            uint8_t  nonce[Cipher::NONCE_BYTES > 0 ? Cipher::NONCE_BYTES : 1];
            uint64_t packet_id    = 0;
            uint64_t next_send_ns = now_ns();

            while (now_ns() < run_end_ns) {

                // Rate control: spin until the next scheduled send time.
                if (inter_packet_ns > 0) {
                    while (now_ns() < next_send_ns) { /* spin */ }
                    next_send_ns += inter_packet_ns;
                }

                fill_nonce(nonce, packet_id);

                const uint64_t enc_start = now_ns();

                size_t ct_len = cipher_enc.encrypt(
                    plaintext,
                    packet_bytes,
                    Cipher::NONCE_BYTES > 0 ? nonce : nullptr,
                    nullptr, 0,
                    ciphertext);

                const uint64_t enc_end = now_ns();

                Packet pkt;
                memcpy(pkt.data, ciphertext, ct_len);
                pkt.ciphertext_len   = ct_len;
                pkt.plaintext_len    = packet_bytes;
                pkt.packet_id        = packet_id;
                pkt.encrypt_start_ns = enc_start;
                pkt.encrypt_end_ns   = enc_end;

                // If the ring is full, yield and retry.  ring_overflows is
                // incremented on every failed push() - including transient
                // failures on packets that eventually succeed - so it counts
                // back-pressure events, not truly dropped packets.  A packet
                // is only truly dropped if the retry limit is exhausted.
                //
                // For System D, any dropped packet desynchronises the Ascon
                // keystream states and invalidates the entire run.
                // For AEAD systems (A–C), a dropped packet is a silent gap:
                // packets_produced will exceed packets_consumed by the number
                // of drops, but surviving packets remain individually valid.
                int retries = 0;
                while (!ring.push(pkt)) {
                    stats.ring_overflows.fetch_add(1, std::memory_order_relaxed);
                    std::this_thread::yield();
                    if (++retries > 1000) {
                        fprintf(stderr,
                            "[producer] WARNING: ring buffer still full after 1000 "
                            "retries on packet %llu. The consumer may have stalled.\n",
                            (unsigned long long)packet_id);
                        break;  // packet is dropped; packet_id still advances
                    }
                }

                stats.packets_produced.fetch_add(1, std::memory_order_relaxed);
                ++packet_id;
            }

            stats.stop.store(true, std::memory_order_release);
        });


        // ------------------------------------------------------------------
        // 11. Wait for all threads to finish.
        // ------------------------------------------------------------------

        producer_thread.join();
        consumer_thread.join();
        sampler.stop();

        // ------------------------------------------------------------------
        // 12. Flush the CSV and print the run summary.
        // ------------------------------------------------------------------

        writer.flush();
        writer.close();

        const uint64_t produced   = stats.packets_produced.load();
        const uint64_t consumed   = stats.packets_consumed.load();
        const uint64_t overflows  = stats.ring_overflows.load();
        const uint64_t auth_fails = stats.auth_failures.load();

        fprintf(stdout,
            "\n=== Run complete ===\n"
            "  Packets produced : %llu\n"
            "  Packets consumed : %llu\n"
            "  Ring overflows   : %llu\n"
            "  Auth failures    : %llu\n"
            "  Results saved to : %s\n",
            (unsigned long long)produced,
            (unsigned long long)consumed,
            (unsigned long long)overflows,
            (unsigned long long)auth_fails,
            csv_path.c_str());

        if (overflows > 0) {
            fprintf(stderr,
                "\n[run_loop] WARNING: %llu ring overflow event(s) recorded.\n"
                "           This counter includes transient retries that eventually\n"
                "           succeeded, so it does not equal the number of dropped\n"
                "           packets.  Check packets_produced vs packets_consumed\n"
                "           for the true drop count.\n"
                "           For System D, any drop invalidates the results - the Ascon\n"
                "           keystream states will have desynchronised.\n"
                "           For all systems, sustained overflows indicate the consumer\n"
                "           cannot keep up at this rate.  Reduce rate_mbps or increase\n"
                "           RING_SIZE.\n",
                (unsigned long long)overflows);
        }

        if (auth_fails > 0) {
            fprintf(stderr,
                "\n[run_loop] FATAL: %llu authentication failure(s) detected.\n"
                "           The cipher is producing incorrect tags or the ring\n"
                "           buffer is corrupting data.  These results are invalid.\n",
                (unsigned long long)auth_fails);
            return 1;
        }

        return 0;
    }
};
