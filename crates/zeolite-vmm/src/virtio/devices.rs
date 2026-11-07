//! virtio block, console and entropy devices.

use super::VirtioDevice;
use super::queue::{Chain, Descriptor, Queue, QueueError};
use crate::memory::GuestMemory;
use std::sync::{Arc, Mutex};

const SECTOR_SIZE: u64 = 512;
const BLK_F_RO: u64 = 1 << 5;
const BLK_F_FLUSH: u64 = 1 << 9;
const BLK_T_IN: u32 = 0;
const BLK_T_OUT: u32 = 1;
const BLK_T_FLUSH: u32 = 4;
const BLK_T_GET_ID: u32 = 8;
const BLK_S_OK: u8 = 0;
const BLK_S_IOERR: u8 = 1;
const BLK_S_UNSUPP: u8 = 2;
const BLK_ID_BYTES: usize = 20;

/// Block device over a shared in-memory image.
pub struct Block {
    image: Arc<Mutex<Vec<u8>>>,
    read_only: bool,
    capacity_sectors: u64,
}

impl Block {
    pub fn new(image: Arc<Mutex<Vec<u8>>>, read_only: bool) -> Self {
        let capacity_sectors = image.lock().map_or(0, |i| i.len() as u64 / SECTOR_SIZE);
        Block {
            image,
            read_only,
            capacity_sectors,
        }
    }

    /// Runs one request and returns the status byte and bytes written to the guest.
    fn handle(&mut self, mem: &GuestMemory, header: &[u8], data: &[Descriptor]) -> (u8, u32) {
        let request_type = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
        let mut sector = [0u8; 8];
        sector.copy_from_slice(&header[8..16]);
        let sector = u64::from_le_bytes(sector);

        match request_type {
            BLK_T_IN | BLK_T_OUT => {
                let is_read = request_type == BLK_T_IN;
                if !is_read && self.read_only {
                    return (BLK_S_IOERR, 0);
                }
                if data.iter().any(|d| d.writable != is_read) {
                    return (BLK_S_IOERR, 0);
                }
                let total: u64 = data.iter().map(|d| u64::from(d.len)).sum();
                if !total.is_multiple_of(SECTOR_SIZE) {
                    return (BLK_S_IOERR, 0);
                }
                let capacity = self.capacity_sectors;
                let in_range = sector
                    .checked_mul(SECTOR_SIZE)
                    .and_then(|start| start.checked_add(total).map(|end| (start, end)))
                    .filter(|(_, end)| *end <= capacity * SECTOR_SIZE);
                let Some((start, _)) = in_range else {
                    return (BLK_S_IOERR, 0);
                };
                let Ok(mut image) = self.image.lock() else {
                    return (BLK_S_IOERR, 0);
                };
                let mut position = start as usize;
                let mut written = 0u32;
                for d in data {
                    let len = d.len as usize;
                    let range = position..position + len;
                    let ok = if is_read {
                        mem.write(d.addr, &image[range]).is_ok()
                    } else {
                        mem.read(d.addr, &mut image[range]).is_ok()
                    };
                    if !ok {
                        return (BLK_S_IOERR, written);
                    }
                    position += len;
                    if is_read {
                        // Images can exceed 4 GiB, but the used-ring length is 32 bits.
                        written = written.saturating_add(d.len);
                    }
                }
                (BLK_S_OK, written)
            }
            BLK_T_FLUSH => (BLK_S_OK, 0),
            BLK_T_GET_ID => {
                let Some(d) = data.first().filter(|d| d.writable) else {
                    return (BLK_S_IOERR, 0);
                };
                let mut id = [0u8; BLK_ID_BYTES];
                id[..11].copy_from_slice(b"zeolite-blk");
                let len = (d.len as usize).min(BLK_ID_BYTES);
                if mem.write(d.addr, &id[..len]).is_err() {
                    return (BLK_S_IOERR, 0);
                }
                (BLK_S_OK, len as u32)
            }
            _ => (BLK_S_UNSUPP, 0),
        }
    }
}

impl VirtioDevice for Block {
    fn device_id(&self) -> u32 {
        2
    }

    fn features(&self) -> u64 {
        let ro = if self.read_only { BLK_F_RO } else { 0 };
        BLK_F_FLUSH | ro
    }

    fn num_queues(&self) -> usize {
        1
    }

    fn read_config(&self, offset: u64, out: &mut [u8]) {
        let capacity = self.capacity_sectors.to_le_bytes();
        for (i, b) in out.iter_mut().enumerate() {
            *b = usize::try_from(offset)
                .ok()
                .and_then(|o| o.checked_add(i))
                .and_then(|o| capacity.get(o))
                .copied()
                .unwrap_or(0);
        }
    }

    fn process_queue(
        &mut self,
        _index: usize,
        queue: &mut Queue,
        mem: &GuestMemory,
    ) -> Result<bool, QueueError> {
        let mut used_any = false;
        while let Some(Chain { head, descriptors }) = queue.pop(mem)? {
            let (status_desc, rest) = match descriptors.split_last() {
                Some((last, rest)) if last.writable && last.len >= 1 && !rest.is_empty() => {
                    (*last, rest)
                }
                // With nowhere to report a status, all that can be done is return the buffer.
                _ => {
                    queue.add_used(mem, head, 0)?;
                    used_any = true;
                    continue;
                }
            };
            let (header_desc, data) = (rest[0], &rest[1..]);
            let (status, written) = if header_desc.writable || header_desc.len < 16 {
                (BLK_S_IOERR, 0)
            } else {
                match mem.read_vec(header_desc.addr, 16) {
                    Ok(header) => self.handle(mem, &header, data),
                    Err(_) => (BLK_S_IOERR, 0),
                }
            };
            mem.write(status_desc.addr, &[status])?;
            queue.add_used(mem, head, written.saturating_add(1))?;
            used_any = true;
        }
        Ok(used_any)
    }
}

/// Console device. Guest output on the transmit queue is captured to a bounded buffer.
pub struct Console {
    output: Arc<Mutex<Vec<u8>>>,
    max_output: usize,
}

impl Console {
    pub fn new(output: Arc<Mutex<Vec<u8>>>, max_output: usize) -> Self {
        Console { output, max_output }
    }
}

impl VirtioDevice for Console {
    fn device_id(&self) -> u32 {
        3
    }

    fn features(&self) -> u64 {
        0
    }

    fn num_queues(&self) -> usize {
        2
    }

    fn read_config(&self, _offset: u64, out: &mut [u8]) {
        out.fill(0);
    }

    fn process_queue(
        &mut self,
        index: usize,
        queue: &mut Queue,
        mem: &GuestMemory,
    ) -> Result<bool, QueueError> {
        // Queue 0 receives into the guest. Nothing is ever sent, so buffers stay posted.
        if index != 1 {
            return Ok(false);
        }
        let mut used_any = false;
        while let Some(chain) = queue.pop(mem)? {
            if let Ok(mut output) = self.output.lock() {
                for d in chain.descriptors.iter().filter(|d| !d.writable) {
                    let room = self.max_output.saturating_sub(output.len());
                    let take = room.min(d.len as usize);
                    if let Ok(bytes) = mem.read_vec(d.addr, take) {
                        output.extend_from_slice(&bytes);
                    }
                }
            }
            queue.add_used(mem, chain.head, 0)?;
            used_any = true;
        }
        Ok(used_any)
    }
}

/// Entropy device, backed by the operating system's random source.
#[derive(Default)]
pub struct Entropy;

impl VirtioDevice for Entropy {
    fn device_id(&self) -> u32 {
        4
    }

    fn features(&self) -> u64 {
        0
    }

    fn num_queues(&self) -> usize {
        1
    }

    fn read_config(&self, _offset: u64, out: &mut [u8]) {
        out.fill(0);
    }

    fn process_queue(
        &mut self,
        _index: usize,
        queue: &mut Queue,
        mem: &GuestMemory,
    ) -> Result<bool, QueueError> {
        const MAX_PER_DESCRIPTOR: usize = 64 << 10;
        let mut used_any = false;
        while let Some(chain) = queue.pop(mem)? {
            let mut written = 0u32;
            for d in chain.descriptors.iter().filter(|d| d.writable) {
                let len = (d.len as usize).min(MAX_PER_DESCRIPTOR);
                let mut buf = vec![0u8; len];
                if getrandom::fill(&mut buf).is_ok() && mem.write(d.addr, &buf).is_ok() {
                    written = written.saturating_add(len as u32);
                }
            }
            queue.add_used(mem, chain.head, written)?;
            used_any = true;
        }
        Ok(used_any)
    }
}
