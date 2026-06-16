#pragma once

/*
 * dataset_source.hpp
 *
 * Supplies real-dataset plaintext to the producer thread for Experiment 6
 * (the real-dataset payload validation).  It wraps one flat binary file of
 * fixed-size records, produced offline by datasets/prepare_real_payloads.py,
 * and hands the producer the next record on each call.
 *
 * Each record is exactly record_size bytes and corresponds to one packet's
 * plaintext.  Records are read strictly sequentially; on reaching end of file
 * the reader rewinds to the start and continues, so a run of any length always
 * has payload available.  This adds a single buffered fread per packet and no
 * heap allocation.
 *
 * Why not mmap: the largest payload file (the single-frame video corpus) is on
 * the order of tens of gigabytes, while the Pi Zero 2 W has 512 MB of RAM.
 * Memory-mapping such a file and touching it sequentially would thrash the page
 * cache.  A plain sequential fread keeps the resident footprint to one stdio
 * buffer, which is what the RAM measurement (Experiment 4) must reflect.
 *
 * Threading: fill() is only ever called from the single producer thread, so no
 * locking is required.  Construct the object before the producer starts and let
 * it outlive the producer (RunLoop does this on the main thread).
 */

#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <string>


class DatasetSource {
public:

    // Opens `path` in binary read mode.  record_size is the fixed number of
    // bytes per record (equal to the workload's packet_bytes).  Check ok()
    // before use; the constructor never throws.
    DatasetSource(const std::string& path, size_t record_size)
        : fp_(std::fopen(path.c_str(), "rb")),
          record_size_(record_size) {}

    ~DatasetSource() {
        if (fp_) std::fclose(fp_);
    }

    // Non-copyable: a copy would duplicate the FILE* and double-close it.
    DatasetSource(const DatasetSource&)            = delete;
    DatasetSource& operator=(const DatasetSource&) = delete;

    // ok() - true if the payload file was opened successfully.
    bool ok() const { return fp_ != nullptr; }

    // fill() - copies the next record into buf.  len must equal record_size.
    // On reaching EOF the reader rewinds and continues from the start, so the
    // call always fills the whole buffer.  If the file is smaller than one
    // record (which prepare_real_payloads.py guarantees cannot happen) the
    // tail is zero-padded as a defensive measure.
    void fill(uint8_t* buf, size_t len) {
        if (!fp_) { std::memset(buf, 0, len); return; }

        size_t got = std::fread(buf, 1, len, fp_);
        if (got < len) {
            // End of file reached part-way through a record: wrap around.
            std::rewind(fp_);
            got += std::fread(buf + got, 1, len - got, fp_);
            if (got < len) std::memset(buf + got, 0, len - got);
        }
    }

    size_t record_size() const { return record_size_; }

private:
    std::FILE* fp_;
    size_t     record_size_;
};
