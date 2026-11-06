//! Split virtqueue processing.
//!
//! Queues live in guest memory and are written by the guest, so nothing read from them is
//! trusted. Indices are range-checked, descriptor chains are length-bounded so a cycle
//! cannot hang the host, and each value is read once into a local copy.

use crate::memory::{GuestMemory, OutOfBounds};
use std::sync::atomic::{Ordering, fence};

pub const DESC_F_NEXT: u16 = 1;
pub const DESC_F_WRITE: u16 = 2;
pub const DESC_F_INDIRECT: u16 = 4;

const DESC_SIZE: u64 = 16;
const USED_ELEM_SIZE: u64 = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueueError {
    NotReady,
    BadHead(u16),
    BadNext(u16),
    ChainTooLong,
    IndirectUnsupported,
    AvailIndexOutOfRange,
    Memory(OutOfBounds),
}

impl From<OutOfBounds> for QueueError {
    fn from(e: OutOfBounds) -> Self {
        QueueError::Memory(e)
    }
}

impl std::fmt::Display for QueueError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "virtqueue error: {self:?}")
    }
}

impl std::error::Error for QueueError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Descriptor {
    pub addr: u64,
    pub len: u32,
    pub writable: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Chain {
    pub head: u16,
    pub descriptors: Vec<Descriptor>,
}

#[derive(Clone, Debug, Default)]
pub struct Queue {
    pub max_size: u16,
    pub size: u16,
    pub ready: bool,
    pub desc_table: u64,
    pub avail_ring: u64,
    pub used_ring: u64,
    last_avail: u16,
    next_used: u16,
}

/// Adds to a guest-supplied address. The guest picks ring addresses, so this must not be
/// able to overflow into a panic, or wrap around to some other valid guest address.
fn guest_add(base: u64, delta: u64) -> Result<u64, QueueError> {
    base.checked_add(delta)
        .ok_or(QueueError::Memory(OutOfBounds {
            addr: base,
            len: usize::try_from(delta).unwrap_or(usize::MAX),
        }))
}

impl Queue {
    pub fn new(max_size: u16) -> Self {
        debug_assert!(max_size.is_power_of_two());
        Queue {
            max_size,
            size: max_size,
            ..Queue::default()
        }
    }

    pub fn reset(&mut self) {
        *self = Queue::new(self.max_size);
    }

    fn usable(&self) -> bool {
        self.ready && self.size != 0 && self.size <= self.max_size && self.size.is_power_of_two()
    }

    /// Takes the next available descriptor chain, if the guest has published one.
    pub fn pop(&mut self, mem: &GuestMemory) -> Result<Option<Chain>, QueueError> {
        if !self.usable() {
            return Err(QueueError::NotReady);
        }
        let avail_idx = mem.read_u16(guest_add(self.avail_ring, 2)?)?;
        // Pairs with the guest's write barrier before it publishes the index, so the ring
        // entry read below is at least as new as this index.
        fence(Ordering::Acquire);

        let pending = avail_idx.wrapping_sub(self.last_avail);
        if pending == 0 {
            return Ok(None);
        }
        // A correct driver never has more outstanding than the queue holds.
        if pending > self.size {
            return Err(QueueError::AvailIndexOutOfRange);
        }

        let slot = u64::from(self.last_avail % self.size);
        let head = mem.read_u16(guest_add(self.avail_ring, 4 + slot * 2)?)?;
        self.last_avail = self.last_avail.wrapping_add(1);
        let descriptors = self.walk(mem, head)?;
        Ok(Some(Chain { head, descriptors }))
    }

    fn walk(&self, mem: &GuestMemory, head: u16) -> Result<Vec<Descriptor>, QueueError> {
        if head >= self.size {
            return Err(QueueError::BadHead(head));
        }
        let mut out = Vec::new();
        let mut index = head;
        loop {
            // A chain longer than the table must revisit an entry, which means a cycle.
            if out.len() >= usize::from(self.size) {
                return Err(QueueError::ChainTooLong);
            }
            let at = guest_add(self.desc_table, u64::from(index) * DESC_SIZE)?;
            // Read as one block, so the checks below see a single consistent descriptor.
            let mut raw = [0u8; DESC_SIZE as usize];
            mem.read(at, &mut raw)?;
            let addr = u64::from_le_bytes([
                raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
            ]);
            let len = u32::from_le_bytes([raw[8], raw[9], raw[10], raw[11]]);
            let flags = u16::from_le_bytes([raw[12], raw[13]]);
            let next = u16::from_le_bytes([raw[14], raw[15]]);
            if flags & DESC_F_INDIRECT != 0 {
                return Err(QueueError::IndirectUnsupported);
            }
            out.push(Descriptor {
                addr,
                len,
                writable: flags & DESC_F_WRITE != 0,
            });
            if flags & DESC_F_NEXT == 0 {
                return Ok(out);
            }
            if next >= self.size {
                return Err(QueueError::BadNext(next));
            }
            index = next;
        }
    }

    /// Returns a processed chain to the guest, recording how many bytes were written.
    pub fn add_used(
        &mut self,
        mem: &GuestMemory,
        head: u16,
        written: u32,
    ) -> Result<(), QueueError> {
        let slot = u64::from(self.next_used % self.size);
        let at = guest_add(self.used_ring, 4 + slot * USED_ELEM_SIZE)?;
        let mut element = [0u8; USED_ELEM_SIZE as usize];
        element[..4].copy_from_slice(&u32::from(head).to_le_bytes());
        element[4..].copy_from_slice(&written.to_le_bytes());
        mem.write(at, &element)?;
        let used_index = guest_add(self.used_ring, 2)?;
        self.next_used = self.next_used.wrapping_add(1);
        // The element must be visible before the index that publishes it.
        fence(Ordering::Release);
        mem.write_u16(used_index, self.next_used)?;
        Ok(())
    }
}
