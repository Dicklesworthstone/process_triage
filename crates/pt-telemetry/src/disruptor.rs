//! Lock-free telemetry ring buffer using LMAX Disruptor-inspired patterns.
//!
//! This module implements bd-g0q5.2.2: high-performance telemetry event
//! recording using a pre-allocated ring buffer and atomic sequences.

use std::cell::UnsafeCell;
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

    /// Build an event payload from recorder inputs.
    pub fn from_parts(timestamp_ns: u64, event_type: u32, pid: u32, details: &str) -> Self {
        let mut event = Self::new();
        event.timestamp_ns = timestamp_ns;
        event.event_type = event_type;
        event.pid = pid;

        let details_bytes = details.as_bytes();
        let len = details_bytes.len().min(MAX_DETAILS_LEN);
        event.details[..len].copy_from_slice(&details_bytes[..len]);
        event.details_len = len as u32;
        event
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

struct RingSlot {
    event: UnsafeCell<FixedSizeEvent>,
    committed_sequence: AtomicU64,
}

/// A lock-free ring buffer for telemetry events.
pub struct TelemetryRingBuffer {
    /// Pre-allocated buffer of events.
    buffer: Vec<RingSlot>,
    /// Bitmask for fast index wrapping (buffer size - 1).
    mask: u64,
    /// Sequence counter for the producer (next claim position).
    pub producer_sequence: AlignedSequence,
    /// Sequence counter for consumers (minimum read position).
    pub consumer_sequence: AlignedSequence,
}

// Safety: producers claim unique sequence numbers atomically, write only to
// their claimed slot, and publish that slot with a release store. Consumers
// read only slots whose committed sequence matches the requested sequence.
unsafe impl Sync for TelemetryRingBuffer {}

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
            buffer.push(RingSlot {
                event: UnsafeCell::new(FixedSizeEvent::new()),
                committed_sequence: AtomicU64::new(0),
            });
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
        loop {
            let current_producer = self.producer_sequence.value.load(Ordering::Acquire);
            let current_consumer = self.consumer_sequence.value.load(Ordering::Acquire);

            if current_producer - current_consumer >= self.capacity() as u64 {
                return None; // Buffer is full
            }

            if self
                .producer_sequence
                .value
                .compare_exchange_weak(
                    current_producer,
                    current_producer + 1,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                return Some(current_producer);
            }

            std::hint::spin_loop();
        }
    }

    /// Commit a claimed sequence, making it available for reading.
    pub fn commit(&self, sequence: u64) {
        self.slot(sequence)
            .committed_sequence
            .store(sequence + 1, Ordering::Release);
    }

    /// Try to read the next available event from the buffer.
    ///
    /// Returns the sequence and event if available.
    pub fn try_read(&self, last_consumed: u64) -> Option<(u64, FixedSizeEvent)> {
        if self
            .slot(last_consumed)
            .committed_sequence
            .load(Ordering::Acquire)
            == last_consumed + 1
        {
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
    pub fn get(&self, sequence: u64) -> FixedSizeEvent {
        unsafe { *self.slot(sequence).event.get() }
    }

    /// Overwrite a claimed slot with a fully-formed event payload.
    #[inline]
    pub fn write_event(&self, sequence: u64, event: FixedSizeEvent) {
        unsafe {
            *self.slot(sequence).event.get() = event;
        }
    }

    #[inline]
    fn slot(&self, sequence: u64) -> &RingSlot {
        &self.buffer[(sequence & self.mask) as usize]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    use std::thread;

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

    #[test]
    fn test_write_and_read_event_roundtrip() {
        let rb = TelemetryRingBuffer::new(4);
        let seq = rb.claim().expect("Should be able to claim");
        let event = FixedSizeEvent::from_parts(123, 7, 4242, "hello");
        rb.write_event(seq, event);
        rb.commit(seq);

        let (read_seq, read_event) = rb.try_read(0).expect("Should be able to read");
        assert_eq!(read_seq, seq);
        assert_eq!(read_event.timestamp_ns, 123);
        assert_eq!(read_event.event_type, 7);
        assert_eq!(read_event.pid, 4242);
        assert_eq!(read_event.details_len, 5);
        assert_eq!(&read_event.details[..5], b"hello");
    }

    #[test]
    fn test_concurrent_claims_reserve_unique_sequences() {
        let rb = Arc::new(TelemetryRingBuffer::new(8));
        let start = Arc::new(Barrier::new(4));
        let after_claim = Arc::new(Barrier::new(4));

        let handles = (0..4)
            .map(|thread_id| {
                let rb = rb.clone();
                let start = start.clone();
                let after_claim = after_claim.clone();
                thread::spawn(move || {
                    start.wait();
                    let seq = rb.claim().expect("Should be able to claim");
                    after_claim.wait();
                    rb.write_event(
                        seq,
                        FixedSizeEvent::from_parts(
                            thread_id as u64,
                            thread_id as u32,
                            thread_id as u32,
                            "x",
                        ),
                    );
                    rb.commit(seq);
                    seq
                })
            })
            .collect::<Vec<_>>();

        let mut claimed = handles
            .into_iter()
            .map(|handle| handle.join().expect("thread join"))
            .collect::<Vec<_>>();
        claimed.sort_unstable();

        assert_eq!(claimed, vec![0, 1, 2, 3]);
    }
}
