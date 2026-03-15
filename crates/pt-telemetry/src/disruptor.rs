//! Lock-free telemetry ring buffer using LMAX Disruptor-inspired patterns.
//!
//! This module implements bd-g0q5.2.2: high-performance, wait-free telemetry
//! event recording using a pre-allocated ring buffer and atomic sequences.

use std::sync::atomic::{AtomicU64, Ordering};

/// Maximum length for details string in FixedSizeEvent.
pub const MAX_DETAILS_LEN: usize = 128;

/// A Plain Old Data (POD) telemetry event for zero-copy ring buffer storage.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct FixedSizeEvent {
    /// Unix timestamp in nanoseconds.
    pub timestamp_ns: u64,
    /// Event type discriminant.
    pub event_type: u32,
    /// Process ID associated with the event.
    pub pid: u32,
    /// Fixed-size buffer for event details (UTF-8).
    pub details: [u8; MAX_DETAILS_LEN],
    /// Actual length of the details string.
    pub details_len: u32,
}

impl FixedSizeEvent {
    /// Create a new empty event.
    pub fn new() -> Self {
        Self {
            timestamp_ns: 0,
            event_type: 0,
            pid: 0,
            details: [0u8; MAX_DETAILS_LEN],
            details_len: 0,
        }
    }
}

/// Aligned sequence counter to prevent false sharing.
#[repr(align(64))]
pub struct AlignedSequence {
    pub value: AtomicU64,
}

impl AlignedSequence {
    pub fn new(initial: u64) -> Self {
        Self {
            value: AtomicU64::new(initial),
        }
    }
}

/// A wait-free ring buffer for telemetry events.
pub struct TelemetryRingBuffer {
    /// Pre-allocated buffer of events.
    buffer: Vec<FixedSizeEvent>,
    /// Bitmask for fast index wrapping (buffer size - 1).
    mask: u64,
    /// Sequence counter for the producer (next write position).
    pub producer_sequence: AlignedSequence,
    /// Sequence counter for consumers (minimum read position).
    pub consumer_sequence: AlignedSequence,
}

impl TelemetryRingBuffer {
    /// Create a new ring buffer with the specified capacity.
    ///
    /// Capacity must be a power of two.
    pub fn new(capacity: usize) -> Self {
        assert!(
            capacity.is_power_of_two(),
            "Capacity must be a power of two"
        );

        let mut buffer = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            buffer.push(FixedSizeEvent::new());
        }

        Self {
            buffer,
            mask: (capacity - 1) as u64,
            producer_sequence: AlignedSequence::new(0),
            consumer_sequence: AlignedSequence::new(0),
        }
    }

    /// Get the capacity of the ring buffer.
    pub fn capacity(&self) -> usize {
        self.buffer.len()
    }

    /// Claim the next available sequence for writing.
    ///
    /// Returns the sequence number if available, or None if the buffer is full.
    pub fn claim(&self) -> Option<u64> {
        let current_producer = self.producer_sequence.value.load(Ordering::Relaxed);
        let current_consumer = self.consumer_sequence.value.load(Ordering::Acquire);

        if current_producer - current_consumer >= self.capacity() as u64 {
            return None; // Buffer is full
        }

        // We only have one producer in our design (the core triage loop)
        Some(current_producer)
    }

    /// Commit a claimed sequence, making it available for reading.
    pub fn commit(&self, sequence: u64) {
        // Since we only have one producer, we just increment the sequence.
        // If we had multiple producers, we would need a more complex strategy
        // (e.g. another sequence to indicate completion).
        self.producer_sequence
            .value
            .store(sequence + 1, Ordering::Release);
    }

    /// Try to read the next available event from the buffer.
    ///
    /// Returns the sequence and event if available.
    pub fn try_read(&self, last_consumed: u64) -> Option<(u64, &FixedSizeEvent)> {
        let current_producer = self.producer_sequence.value.load(Ordering::Acquire);

        if last_consumed < current_producer {
            Some((last_consumed, self.get(last_consumed)))
        } else {
            None
        }
    }

    /// Advance the consumer sequence to the specified position.
    pub fn advance_consumer(&self, sequence: u64) {
        self.consumer_sequence
            .value
            .store(sequence + 1, Ordering::Release);
    }

    /// Get an event at the specified sequence position.
    #[inline]
    pub fn get(&self, sequence: u64) -> &FixedSizeEvent {
        &self.buffer[(sequence & self.mask) as usize]
    }

    /// Get a mutable reference to an event at the specified sequence position.
    #[inline]
    pub unsafe fn get_mut(&mut self, sequence: u64) -> &mut FixedSizeEvent {
        &mut self.buffer[(sequence & self.mask) as usize]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ring_buffer_init() {
        let rb = TelemetryRingBuffer::new(1024);
        assert_eq!(rb.capacity(), 1024);
        assert_eq!(rb.producer_sequence.value.load(Ordering::Relaxed), 0);
    }

    #[test]
    #[should_panic]
    fn test_ring_buffer_invalid_size() {
        let _ = TelemetryRingBuffer::new(1000);
    }

    #[test]
    fn test_claim_and_commit() {
        let rb = TelemetryRingBuffer::new(4);

        // Claim 4 slots
        for i in 0..4 {
            let seq = rb.claim().expect("Should be able to claim");
            assert_eq!(seq, i as u64);
            rb.commit(seq);
        }

        // Buffer should be full
        assert!(rb.claim().is_none());

        // Consumer reads one
        let (seq, _) = rb.try_read(0).expect("Should be able to read");
        assert_eq!(seq, 0);
        rb.advance_consumer(seq);

        // Should be able to claim one now
        let seq = rb.claim().expect("Should be able to claim after consume");
        assert_eq!(seq, 4);
    }
}
