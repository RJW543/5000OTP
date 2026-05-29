#pragma once

/*
 * metrics.hpp
 *
 * Two responsibilities:
 *
 *   SharedStats  - atomic counters and flags shared between all threads.
 *
 *                  Writers:
 *                    sampler   → cpu_pct, rss_kb  (once per second)
 *                    producer  → packets_produced, ring_overflows
 *                    consumer  → packets_consumed, auth_failures
 *
 *                  Reader: stop is set by the producer to signal shutdown;
 *                  it is read by the consumer and sampler to decide when to exit.
 *
 *                  Note: ring_overflows counts every failed push() call,
 *                  including transient failures on packets that eventually
 *                  succeed after retrying.  It is therefore NOT a count of
 *                  dropped packets; it is an indicator of back-pressure.  A
 *                  truly dropped packet (one that exhausted all retries) will
 *                  appear as a discrepancy between packets_produced and
 *                  packets_consumed.
 *
 *   MetricsWriter - creates the output CSV and writes one row per packet.
 *                   Must only be called from the consumer thread.
 *                   Call flush() before close() if you want to ensure all
 *                   buffered C stdio data reaches the OS before the file
 *                   handle is released.
 *
 * CSV columns:
 *   timestamp_ns    - wall-clock time (CLOCK_MONOTONIC ns) at encrypt start
 *   packet_id       - monotonic packet counter (0-based)
 *   plaintext_bytes - original payload size before encryption
 *   encrypt_ns      - nanoseconds spent inside encrypt()
 *   decrypt_ns      - nanoseconds spent inside decrypt()
 *   cpu_pct         - process CPU% at time of writing (1 s resolution;
 *                     may exceed 100% on multi-core - see sampler.hpp)
 *   rss_kb          - resident set size in kB at time of writing
 *   system          - cipher name string (e.g. "AES-256-GCM")
 *   kem_level       - ML-KEM parameter set (768 or 1024)
 *   temp_c          - CPU temperature in degrees Celsius at time of writing
 *                     (1 s resolution; 0.0 until first sampler tick;
 *                     read from /sys/class/thermal/thermal_zone0/temp)
 */

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <string>


// ---------------------------------------------------------------------------
// SharedStats - live counters shared between the producer, consumer, and
// sampler threads.  All fields are atomic to avoid data races.
// ---------------------------------------------------------------------------

struct SharedStats {

    // cpu_pct uses std::atomic<double>.  On ARM (both Pi 5 and Pi Zero 2 W)
    // this is typically lock-based rather than a native atomic instruction,
    // since the architecture does not guarantee atomic double-precision FP
    // operations.  The performance impact is negligible here because the
    // sampler writes this at most once per second and the consumer reads it
    // once per packet - contention is vanishingly rare.
    std::atomic<double>   cpu_pct{0.0};          // latest CPU% reading (1-second resolution; may exceed 100% on multi-core)
    std::atomic<uint64_t> rss_kb{0};             // latest resident RAM reading in kB
    std::atomic<uint64_t> packets_produced{0};   // total packets encrypted (and either pushed or dropped after retries)
    std::atomic<uint64_t> packets_consumed{0};   // total packets decrypted and written to CSV
    std::atomic<uint64_t> ring_overflows{0};     // cumulative push() failures - counts retry attempts, not dropped packets
    std::atomic<uint64_t> auth_failures{0};      // decrypt() failures due to authentication tag mismatch
    std::atomic<bool>     stop{false};           // set by the producer when the time limit is reached; read by consumer and sampler
    std::atomic<uint64_t> temp_mc{0};            // latest CPU temperature in millidegrees Celsius (e.g. 45000 = 45.0 °C); 0 until first sampler tick
};


// ---------------------------------------------------------------------------
// MetricsWriter - creates and writes the output CSV file.
// Not thread-safe; must be called exclusively from the consumer thread.
// ---------------------------------------------------------------------------

class MetricsWriter {
    FILE*       file_ = nullptr;
    std::string path_;

public:

    // open() - creates the CSV at `path` and writes the header row.
    // Returns true on success, false if the file could not be opened.
    bool open(const std::string& path) {
        path_ = path;
        file_ = fopen(path.c_str(), "w");
        if (!file_) {
            fprintf(stderr, "[metrics] ERROR: could not open '%s' for writing.\n"
                            "         Check that the directory exists and is writable.\n",
                    path.c_str());
            return false;
        }

        fprintf(file_,
            "timestamp_ns,packet_id,plaintext_bytes,"
            "encrypt_ns,decrypt_ns,"
            "cpu_pct,rss_kb,"
            "system,kem_level,temp_c\n");
        return true;
    }

    // write_row() - appends one data row for the given packet.
    // All timing values are in nanoseconds.
    //
    // Column mapping note: the CSV column order differs from the function
    // parameter order.  Specifically, encrypt_start_ns is written first
    // as the timestamp_ns column, followed by packet_id - even though
    // packet_id is the first parameter in the signature.  This reordering
    // is intentional: timestamp_ns is the primary sort key in the CSV and
    // conventionally appears as the first column.
    //
    // CSV output order:
    //   timestamp_ns    ← encrypt_start_ns
    //   packet_id       ← packet_id
    //   plaintext_bytes ← plaintext_bytes
    //   encrypt_ns      ← encrypt_ns
    //   decrypt_ns      ← decrypt_ns
    //   cpu_pct         ← cpu_pct
    //   rss_kb          ← rss_kb
    //   system          ← system_name
    //   kem_level       ← kem_level
    //   temp_c          ← temp_mc / 1000.0
    void write_row(uint64_t    packet_id,
                   size_t      plaintext_bytes,
                   uint64_t    encrypt_start_ns,
                   uint64_t    encrypt_ns,
                   uint64_t    decrypt_ns,
                   double      cpu_pct,
                   uint64_t    rss_kb,
                   const char* system_name,
                   int         kem_level,
                   uint64_t    temp_mc)
    {
        if (!file_) return;

        fprintf(file_,
            "%llu,%llu,%zu,"
            "%llu,%llu,"
            "%.2f,%llu,"
            "%s,%d,%.1f\n",
            (unsigned long long)encrypt_start_ns,   // → timestamp_ns column
            (unsigned long long)packet_id,           // → packet_id column
            plaintext_bytes,                         // → plaintext_bytes column
            (unsigned long long)encrypt_ns,
            (unsigned long long)decrypt_ns,
            cpu_pct,
            (unsigned long long)rss_kb,
            system_name,
            kem_level,
            static_cast<double>(temp_mc) / 1000.0); // → temp_c column
    }

    // flush() - pushes any C stdio-layer buffered data to the OS.
    // Call before close() (or at any point mid-run) to reduce data loss if
    // the process is killed.  close() also flushes, so an explicit flush()
    // beforehand is a safety measure rather than strictly necessary.
    void flush() {
        if (file_) fflush(file_);
    }

    // close() - flushes all buffered data and releases the file handle.
    // Safe to call multiple times; subsequent calls are no-ops.
    void close() {
        if (file_) {
            fflush(file_);
            fclose(file_);
            file_ = nullptr;
        }
    }

    const std::string& path() const { return path_; }

    ~MetricsWriter() { close(); }
};


// ---------------------------------------------------------------------------
// now_ns() - returns the current wall-clock time in nanoseconds.
// Uses CLOCK_MONOTONIC, which never jumps backwards and is unaffected by
// NTP adjustments or DST changes.  Note: CLOCK_MONOTONIC epochs differ
// between machines, so values from two separate processes cannot be
// compared directly - they are only meaningful as deltas within a single run.
// ---------------------------------------------------------------------------

inline uint64_t now_ns() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<uint64_t>(ts.tv_sec)  * 1'000'000'000ULL
         + static_cast<uint64_t>(ts.tv_nsec);
}


// ---------------------------------------------------------------------------
// make_output_filename() - builds a timestamped CSV filename so that
// successive runs never overwrite each other.
//
// Example: results_AES-256-GCM_kem768_pi5_20260524_143022.csv
//
// device_name is injected at compile time via the DEVICE_NAME macro
// (set to "pi5" or "pi0" by CMakeLists.txt).  This ensures CSV files
// from the two devices are unambiguously distinguishable without
// renaming files manually after collection.
// ---------------------------------------------------------------------------

inline std::string make_output_filename(const char* system_name,
                                        int         kem_level,
                                        const char* device_name) {
    time_t now = time(nullptr);
    struct tm* t = localtime(&now);
    char buf[256];
    snprintf(buf, sizeof(buf),
             "results_%s_kem%d_%s_%04d%02d%02d_%02d%02d%02d.csv",
             system_name, kem_level, device_name,
             t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
             t->tm_hour, t->tm_min, t->tm_sec);
    return std::string(buf);
}
