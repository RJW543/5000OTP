#pragma once

/*
 * ring_buffer.hpp
 *
 * A lock-free Single-Producer Single-Consumer (SPSC) ring buffer used to
 * pass encrypted Packet structs from the producer thread to the consumer
 * thread without any mutex.
 *
 * Design overview
 * ---------------
 * The buffer holds N slots arranged in a circular array.  Two atomic
 * indices track progress:
 *
 *   head_  - the index of the NEXT slot the producer will write into.
 *             Only the producer advances head_.
 *
 *   tail_  - the index of the NEXT slot the consumer will read from.
 *             Only the consumer advances tail_.
 *
 * Full condition:  (head_ + 1) % N == tail_
 *   The buffer intentionally keeps one slot permanently empty to
 *   distinguish full from empty.  Maximum occupancy is therefore N-1
 *   packets, not N.
 *
 * Empty condition: head_ == tail_
 *
 * Memory ordering
 * ---------------
 * The producer must ensure its slot write is globally visible BEFORE it
 * publishes the updated head_ to the consumer.  It therefore uses a
 * release store on head_.  The consumer synchronises with this via an
 * acquire load on head_:
 *
 *   Producer: write slot → head_.store(release)  ←synchronises-with→
 *   Consumer: head_.load(acquire) → read slot
 *
 * The mirror holds for tail_:
 *
 *   Consumer: tail_.store(release)  ←synchronises-with→
 *   Producer: tail_.load(acquire)
 *
 * This guarantees the consumer sees the completed slot data before the
 * producer is allowed to reuse that slot - and vice versa - without any
 * lock or fence beyond the acquire/release pair.
 *
 * Thread safety: push() must only be called from the producer thread;
 * pop() must only be called from the consumer thread.
 */

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>


// ---------------------------------------------------------------------------
// Packet - carries one encrypted payload and its associated timing metadata
// from the producer thread to the consumer thread.
// ---------------------------------------------------------------------------

struct Packet {

    // Maximum supported payload size: 64 KB of data plus 32 bytes for
    // the largest possible authentication tag.
    static constexpr size_t MAX_DATA = 65536 + 32;

    uint8_t  data[MAX_DATA];       // encrypted bytes, including auth tag
    size_t   ciphertext_len;       // number of valid bytes in data[]
    size_t   plaintext_len;        // original plaintext size before encryption
    uint64_t packet_id;            // monotonic counter; used to reconstruct the nonce and detect drops
    uint64_t encrypt_start_ns;     // wall-clock time immediately before encrypt()
    uint64_t encrypt_end_ns;       // wall-clock time immediately after encrypt()
};


// ---------------------------------------------------------------------------
// RingBuffer<N> - circular buffer holding N Packet slots.
//
// N must be a power of two.  The producer can be at most N-1 packets ahead
// of the consumer before push() starts returning false.
// ---------------------------------------------------------------------------

template<size_t N>
class RingBuffer {

    static_assert(N >= 2,           "At least 2 slots are needed to distinguish full from empty.");
    static_assert((N & (N-1)) == 0, "N must be a power of two for bitwise index wrapping to work.");

    Packet slots_[N];

    // Placed on separate cache lines to avoid false sharing.
    // Without alignment, head_ and tail_ would likely share a 64-byte cache
    // line.  Each time either thread writes its own index, the CPU would
    // invalidate the other thread's copy of that cache line, causing
    // unnecessary cache-coherency traffic and stalling the other core.
    alignas(64) std::atomic<size_t> head_{0};   // producer advances this; consumer reads it (acquire)
    alignas(64) std::atomic<size_t> tail_{0};   // consumer advances this; producer reads it (acquire)

public:

    // push() - copies pkt into the next available slot and advances head_.
    // Returns true on success, false if the buffer is full (N-1 slots occupied).
    // Must only be called from the producer thread.
    //
    // Ordering notes:
    //   head_.load(relaxed)     - safe: the producer is the sole writer of head_,
    //                             so it always reads its own most recent value.
    //   tail_.load(acquire)     - acquires the consumer's release of a freed slot,
    //                             ensuring the producer sees the slot as available
    //                             before writing into it.
    //   head_.store(release)    - publishes the written slot to the consumer;
    //                             the consumer's acquire load on head_ will not
    //                             see the new index until this store is visible.
    bool push(const Packet& pkt) noexcept {
        const size_t h    = head_.load(std::memory_order_relaxed);
        const size_t next = (h + 1) & (N - 1);

        if (next == tail_.load(std::memory_order_acquire))
            return false;   // buffer is full - one slot is permanently reserved to
                            // distinguish the full condition from the empty condition

        slots_[h] = pkt;
        head_.store(next, std::memory_order_release);
        return true;
    }

    // pop() - copies the oldest packet into pkt and advances tail_.
    // Returns true on success, false if the buffer is empty.
    // Must only be called from the consumer thread.
    //
    // Ordering notes:
    //   tail_.load(relaxed)     - safe: the consumer is the sole writer of tail_,
    //                             so it always reads its own most recent value.
    //   head_.load(acquire)     - synchronises-with the producer's release store
    //                             on head_, guaranteeing the slot data is fully
    //                             written before the consumer reads it.
    //   tail_.store(release)    - publishes the freed slot to the producer;
    //                             the producer's acquire load on tail_ will not
    //                             see the slot as free until this store is visible.
    bool pop(Packet& pkt) noexcept {
        const size_t t = tail_.load(std::memory_order_relaxed);

        if (t == head_.load(std::memory_order_acquire))
            return false;   // buffer is empty

        pkt = slots_[t];
        tail_.store((t + 1) & (N - 1), std::memory_order_release);
        return true;
    }
};
