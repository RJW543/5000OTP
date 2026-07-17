#pragma once

/*
 * sampler.hpp
 *
 * Runs a background thread that samples CPU usage and resident memory once
 * per second and publishes both readings to SharedStats.  The consumer
 * thread picks up these values when it writes each CSV row.
 *
 * CPU% calculation
 * ----------------
 * CPU% = (process CPU time delta / wall-clock time delta) * 100.
 *
 * CLOCK_PROCESS_CPUTIME_ID accumulates CPU time across ALL threads of the
 * process, not just the sampler.  On a multi-core machine this means the
 * reported value can exceed 100%: a two-thread benchmark running at full
 * tilt on separate cores will show approximately 200%.  On the Pi 5 (four
 * cores, three threads in use) expect ~300% at saturation.  On the single-
 * core Pi Zero 2 W it is bounded by 100% (all four cores are shared by
 * the OS but only one is active at a time under the default scheduler).
 *
 * The reading is refreshed once per second, so each CSV row carries the
 * most recent one-second average, not an instantaneous per-packet value.
 * Packets written in the first second of a run will carry cpu_pct = 0.0
 * until the sampler completes its first measurement cycle.
 *
 * RAM measurement
 * ---------------
 * VmRSS from /proc/self/status - the physical RAM currently mapped into
 * the process's address space.  This excludes swap and shared library pages
 * that are not resident.
 *
 * Core pinning
 * ------------
 * The sampler runs on its own pinned core (recommended: core 0) so that its
 * file I/O and sleep overhead do not appear in the encrypt or decrypt timing
 * columns.
 */

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <thread>
#include <chrono>

#include <pthread.h>
#include <sched.h>
#include <unistd.h>

#include "metrics.hpp"


class Sampler {
    SharedStats& stats_;
    std::thread  thread_;

    // read_temp_mc() - reads the SoC temperature from the kernel's thermal
    // sysfs interface and returns it in millidegrees Celsius.
    //
    // Path /sys/class/thermal/thermal_zone0/temp is present on both the
    // Pi 5 (Cortex-A76) and Pi Zero 2 W (Cortex-A53) under Raspberry Pi OS.
    // Returns 0 if the file cannot be read (e.g. unexpected OS or permissions).
    // The read is a single integer parse of a small sysfs file; overhead is
    // negligible compared to the 1-second sampling interval.
    static uint64_t read_temp_mc() {
        FILE* f = fopen("/sys/class/thermal/thermal_zone0/temp", "r");
        if (!f) return 0;
        uint64_t temp_mc = 0;
        fscanf(f, "%llu", (unsigned long long*)&temp_mc);
        fclose(f);
        return temp_mc;
    }

    // read_rss_kb() - parses /proc/self/status and returns the VmRSS field
    // in kilobytes.  VmRSS is the Resident Set Size: physical RAM pages
    // currently mapped and present (not swapped out).  Returns 0 if the
    // file cannot be opened (e.g., non-Linux platform or permission error).
    static uint64_t read_rss_kb() {
        FILE* f = fopen("/proc/self/status", "r");
        if (!f) return 0;

        char     line[256];
        uint64_t rss = 0;

        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "VmRSS:", 6) == 0) {
                sscanf(line + 6, " %llu", (unsigned long long*)&rss);
                break;
            }
        }

        fclose(f);
        return rss;
    }

    // cpu_time_ns() - returns the total CPU time consumed by this process
    // across ALL threads combined, in nanoseconds.  Because it aggregates
    // every thread, a two-thread process running at full utilisation on two
    // separate cores will accumulate CPU time at ~2× the wall-clock rate.
    static uint64_t cpu_time_ns() {
        struct timespec ts;
        clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts);
        return static_cast<uint64_t>(ts.tv_sec)  * 1'000'000'000ULL
             + static_cast<uint64_t>(ts.tv_nsec);
    }

    // loop() - the sampler thread body.
    //
    // Each iteration: sleep 1 second → compute CPU% over that interval →
    // read VmRSS → publish both to SharedStats → print a progress line.
    //
    // The loop checks stats_.stop at two points: before sleeping (fast exit
    // if the producer already finished) and immediately after waking (avoids
    // a redundant /proc read after shutdown).  A relaxed load is sufficient
    // because the sampler only needs to eventually observe the stop signal  - 
    // there is no data dependency that requires acquire semantics here.
    void loop() {
        uint64_t prev_cpu_ns  = cpu_time_ns();
        uint64_t prev_wall_ns = now_ns();

        // Physical ceiling for a sanity check on each reading: process CPU%
        // cannot exceed (online cores) * 100.  Any higher value is a kernel
        // CPU-time / monotonic-clock accounting glitch, not a real load.
        const double cpu_ceiling =
            static_cast<double>(sysconf(_SC_NPROCESSORS_ONLN)) * 100.0;

        while (!stats_.stop.load(std::memory_order_relaxed)) {

            std::this_thread::sleep_for(std::chrono::seconds(1));

            if (stats_.stop.load(std::memory_order_relaxed)) break;

            const uint64_t cur_cpu_ns  = cpu_time_ns();
            const uint64_t cur_wall_ns = now_ns();

            const uint64_t cpu_delta  = cur_cpu_ns  - prev_cpu_ns;
            const uint64_t wall_delta = cur_wall_ns - prev_wall_ns;

            const double cpu_pct = (wall_delta > 0)
                ? (static_cast<double>(cpu_delta) / static_cast<double>(wall_delta)) * 100.0
                : 0.0;

            // Reject non-physical readings.  If cpu_pct exceeds the core-count
            // ceiling it is a kernel accounting glitch (observed once on the
            // Pi Zero 2 W under peak load): keep the last good published value
            // and re-baseline both clocks from fresh reads, so the glitched
            // sample does not also corrupt the following interval's delta.
            const bool cpu_valid = (cpu_pct <= cpu_ceiling * 1.05);
            if (cpu_valid) {
                prev_cpu_ns  = cur_cpu_ns;
                prev_wall_ns = cur_wall_ns;
            } else {
                prev_cpu_ns  = cpu_time_ns();
                prev_wall_ns = now_ns();
            }

            const uint64_t rss     = read_rss_kb();
            const uint64_t temp_mc = read_temp_mc();

            if (cpu_valid)
                stats_.cpu_pct.store(cpu_pct,  std::memory_order_relaxed);
            stats_.rss_kb.store(rss,       std::memory_order_relaxed);
            stats_.temp_mc.store(temp_mc,  std::memory_order_relaxed);

            fprintf(stdout,
                "[sampler] produced=%-8llu  consumed=%-8llu  overflows=%-4llu"
                "  cpu=%5.1f%%  rss=%llu kB  temp=%.1f°C\n",
                (unsigned long long)stats_.packets_produced.load(std::memory_order_relaxed),
                (unsigned long long)stats_.packets_consumed.load(std::memory_order_relaxed),
                (unsigned long long)stats_.ring_overflows.load(std::memory_order_relaxed),
                cpu_pct,
                (unsigned long long)rss,
                static_cast<double>(temp_mc) / 1000.0);
            fflush(stdout);
        }
    }

public:

    explicit Sampler(SharedStats& stats) : stats_(stats) {}

    // read_rss_kb_now() - one-shot public RSS reading in kB, for callers
    // outside the sampler thread (e.g. the ML-KEM overhead snapshots in
    // run_loop.hpp, Experiment 5).  Wraps the same /proc/self/status parse
    // the sampler loop uses, so both report VmRSS identically.
    static uint64_t read_rss_kb_now() { return read_rss_kb(); }

    // start() - launches the sampler thread and pins it to `core`.
    // Recommended core: 0, leaving cores 1 and 2 exclusively for the
    // producer and consumer.  Affinity failure is silent - the thread
    // continues but may produce noisier CPU% readings if the OS migrates it.
    void start(int core) {
        thread_ = std::thread([this, core]() {
            cpu_set_t cpuset;
            CPU_ZERO(&cpuset);
            CPU_SET(core, &cpuset);
            pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
            loop();
        });
    }

    // stop() - blocks until the sampler thread exits.
    // stats_.stop must already be set to true by the time this is called,
    // otherwise the sampler will sleep indefinitely.  RunLoop sets stop
    // in the producer thread before joining the consumer, and joins the
    // sampler last, so the ordering is always satisfied.
    void stop() {
        if (thread_.joinable())
            thread_.join();
    }

    ~Sampler() { stop(); }
};
