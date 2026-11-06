//! Drives the virtio stack the way a guest driver would: through the MMIO registers and
//! rings in guest memory. Nothing here needs a hypervisor, so it runs on every platform.

use std::sync::{Arc, Mutex};
use zeolite_vmm::memory::GuestMemory;
use zeolite_vmm::virtio::devices::{Block, Console, Entropy};
use zeolite_vmm::virtio::queue::{DESC_F_INDIRECT, DESC_F_NEXT, DESC_F_WRITE, Queue, QueueError};
use zeolite_vmm::virtio::{MmioTransport, VIRTIO_F_VERSION_1};

const DESC: u64 = 0x1000;
const AVAIL: u64 = 0x2000;
const USED: u64 = 0x3000;
const QUEUE_SIZE: u16 = 16;
const DATA: u64 = 0x10000;

const STATUS_ACK_DRIVER: u32 = 1 | 2;
const STATUS_FEATURES_OK: u32 = 8;
const STATUS_DRIVER_OK: u32 = 4;
const STATUS_NEEDS_RESET: u32 = 64;

const BLK_IN: u32 = 0;
const BLK_OUT: u32 = 1;
const BLK_FLUSH: u32 = 4;
const BLK_GET_ID: u32 = 8;

fn reg_read(t: &mut MmioTransport, offset: u64) -> u32 {
    let mut b = [0u8; 4];
    t.read(offset, &mut b);
    u32::from_le_bytes(b)
}

fn reg_write(t: &mut MmioTransport, mem: &GuestMemory, offset: u64, value: u32) {
    t.write(offset, &value.to_le_bytes(), mem);
}

/// Performs the driver initialization sequence from the virtio specification.
fn negotiate(t: &mut MmioTransport, mem: &GuestMemory, queue: u32, accept_low: u32) {
    reg_write(t, mem, 0x070, 0);
    reg_write(t, mem, 0x070, STATUS_ACK_DRIVER);
    reg_write(t, mem, 0x024, 0);
    reg_write(t, mem, 0x020, accept_low);
    reg_write(t, mem, 0x024, 1);
    reg_write(t, mem, 0x020, (VIRTIO_F_VERSION_1 >> 32) as u32);
    reg_write(t, mem, 0x070, STATUS_ACK_DRIVER | STATUS_FEATURES_OK);
    assert_ne!(reg_read(t, 0x070) & STATUS_FEATURES_OK, 0);
    reg_write(t, mem, 0x030, queue);
    reg_write(t, mem, 0x038, u32::from(QUEUE_SIZE));
    reg_write(t, mem, 0x080, DESC as u32);
    reg_write(t, mem, 0x084, 0);
    reg_write(t, mem, 0x090, AVAIL as u32);
    reg_write(t, mem, 0x094, 0);
    reg_write(t, mem, 0x0A0, USED as u32);
    reg_write(t, mem, 0x0A4, 0);
    reg_write(t, mem, 0x044, 1);
    reg_write(
        t,
        mem,
        0x070,
        STATUS_ACK_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK,
    );
    assert_ne!(reg_read(t, 0x070) & STATUS_DRIVER_OK, 0);
}

fn set_desc(mem: &GuestMemory, index: u16, addr: u64, len: u32, flags: u16, next: u16) {
    let at = DESC + u64::from(index) * 16;
    mem.write_u64(at, addr).unwrap();
    mem.write_u32(at + 8, len).unwrap();
    mem.write_u16(at + 12, flags).unwrap();
    mem.write_u16(at + 14, next).unwrap();
}

/// Publishes `head` in the available ring, as a guest would before notifying.
fn publish(mem: &GuestMemory, head: u16) {
    let idx = mem.read_u16(AVAIL + 2).unwrap();
    mem.write_u16(AVAIL + 4 + u64::from(idx % QUEUE_SIZE) * 2, head)
        .unwrap();
    mem.write_u16(AVAIL + 2, idx.wrapping_add(1)).unwrap();
}

struct BlockRig {
    mem: GuestMemory,
    transport: MmioTransport,
    image: Arc<Mutex<Vec<u8>>>,
}

fn block_rig(sectors: usize, read_only: bool) -> BlockRig {
    let mem = GuestMemory::new(1 << 20).unwrap();
    let mut image = vec![0u8; sectors * 512];
    for (i, b) in image.iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }
    let image = Arc::new(Mutex::new(image));
    let mut transport = MmioTransport::new(Box::new(Block::new(image.clone(), read_only)));
    negotiate(&mut transport, &mem, 0, 0);
    BlockRig {
        mem,
        transport,
        image,
    }
}

impl BlockRig {
    /// Sends one request and returns its status byte.
    fn request(&mut self, kind: u32, sector: u64, data_len: u32, device_writes: bool) -> u8 {
        let header = DATA;
        self.mem.write_u32(header, kind).unwrap();
        self.mem.write_u32(header + 4, 0).unwrap();
        self.mem.write_u64(header + 8, sector).unwrap();
        let buffer = DATA + 0x100;
        let status = DATA + 0x80;
        self.mem.write(status, &[0xEE]).unwrap();

        set_desc(&self.mem, 0, header, 16, DESC_F_NEXT, 1);
        if data_len > 0 {
            let flags = DESC_F_NEXT | if device_writes { DESC_F_WRITE } else { 0 };
            set_desc(&self.mem, 1, buffer, data_len, flags, 2);
            set_desc(&self.mem, 2, status, 1, DESC_F_WRITE, 0);
        } else {
            set_desc(&self.mem, 1, status, 1, DESC_F_WRITE, 0);
        }
        publish(&self.mem, 0);
        reg_write(&mut self.transport, &self.mem, 0x050, 0);
        let mut out = [0u8];
        self.mem.read(status, &mut out).unwrap();
        out[0]
    }
}

#[test]
fn identification_registers_match_the_specification() {
    let mem = GuestMemory::new(1 << 20).unwrap();
    let image = Arc::new(Mutex::new(vec![0u8; 512 * 8]));
    let mut t = MmioTransport::new(Box::new(Block::new(image, false)));
    assert_eq!(reg_read(&mut t, 0x000), 0x7472_6976, "magic");
    assert_eq!(reg_read(&mut t, 0x004), 2, "modern transport");
    assert_eq!(reg_read(&mut t, 0x008), 2, "block device id");
    reg_write(&mut t, &mem, 0x014, 1);
    assert_eq!(reg_read(&mut t, 0x010), (VIRTIO_F_VERSION_1 >> 32) as u32);
    reg_write(&mut t, &mem, 0x030, 0);
    assert_eq!(reg_read(&mut t, 0x034), 256, "queue size");
    reg_write(&mut t, &mem, 0x030, 9);
    assert_eq!(
        reg_read(&mut t, 0x034),
        0,
        "a queue that does not exist reads as zero"
    );

    let mut capacity = [0u8; 8];
    t.read(0x100, &mut capacity);
    assert_eq!(u64::from_le_bytes(capacity), 8);
}

#[test]
fn block_reads_and_writes_reach_the_image() {
    let mut rig = block_rig(8, false);
    assert_eq!(rig.request(BLK_IN, 1, 512, true), 0);
    let got = rig.mem.read_vec(DATA + 0x100, 512).unwrap();
    assert_eq!(got, rig.image.lock().unwrap()[512..1024]);
    assert_eq!(
        rig.mem.read_u16(USED + 2).unwrap(),
        1,
        "used index advanced"
    );
    assert_eq!(
        rig.mem.read_u32(USED + 8).unwrap(),
        513,
        "data plus the status byte"
    );
    assert!(rig.transport.take_irq());
    assert_eq!(
        reg_read(&mut rig.transport, 0x060),
        1,
        "vring interrupt bit"
    );
    reg_write(
        &mut rig.transport,
        &GuestMemory::new(1 << 16).unwrap(),
        0x064,
        1,
    );
    assert_eq!(reg_read(&mut rig.transport, 0x060), 0, "acknowledged");

    rig.mem.write(DATA + 0x100, &[0x77; 512]).unwrap();
    assert_eq!(rig.request(BLK_OUT, 2, 512, false), 0);
    assert_eq!(rig.image.lock().unwrap()[1024..1536], [0x77; 512]);
}

#[test]
fn block_flush_and_id_requests_work() {
    let mut rig = block_rig(8, false);
    assert_eq!(rig.request(BLK_FLUSH, 0, 0, false), 0);
    assert_eq!(rig.request(BLK_GET_ID, 0, 20, true), 0);
    assert_eq!(rig.mem.read_vec(DATA + 0x100, 11).unwrap(), b"zeolite-blk");
}

#[test]
fn block_rejects_out_of_range_and_malformed_requests() {
    let mut rig = block_rig(8, false);
    let before = rig.image.lock().unwrap().clone();

    assert_eq!(
        rig.request(BLK_IN, 8, 512, true),
        1,
        "first sector past the end"
    );
    assert_eq!(rig.request(BLK_IN, 7, 1024, true), 1, "straddles the end");
    assert_eq!(rig.request(BLK_OUT, 8, 512, false), 1);
    assert_eq!(
        rig.request(BLK_IN, u64::MAX / 512, 512, true),
        1,
        "sector arithmetic must not wrap around to a valid offset"
    );
    assert_eq!(rig.request(BLK_IN, u64::MAX, 512, true), 1);
    assert_eq!(
        rig.request(BLK_IN, 0, 100, true),
        1,
        "not a whole number of sectors"
    );
    assert_eq!(
        rig.request(BLK_OUT, 0, 512, true),
        1,
        "wrong buffer direction"
    );
    assert_eq!(
        rig.request(BLK_IN, 0, 512, false),
        1,
        "wrong buffer direction"
    );
    assert_eq!(rig.request(99, 0, 512, true), 2, "unsupported request type");

    assert_eq!(
        *rig.image.lock().unwrap(),
        before,
        "no rejected request may write"
    );
}

#[test]
fn read_only_block_devices_refuse_writes() {
    let mut rig = block_rig(8, true);
    let before = rig.image.lock().unwrap().clone();
    assert_eq!(rig.request(BLK_OUT, 0, 512, false), 1);
    assert_eq!(*rig.image.lock().unwrap(), before);
    assert_eq!(rig.request(BLK_IN, 0, 512, true), 0, "reads still work");
}

#[test]
fn data_buffer_outside_guest_memory_is_an_error_and_not_a_host_fault() {
    let mut rig = block_rig(8, false);
    rig.mem.write_u32(DATA, BLK_IN).unwrap();
    rig.mem.write_u64(DATA + 8, 0).unwrap();
    let status = DATA + 0x80;
    set_desc(&rig.mem, 0, DATA, 16, DESC_F_NEXT, 1);
    set_desc(&rig.mem, 1, 1 << 40, 512, DESC_F_NEXT | DESC_F_WRITE, 2);
    set_desc(&rig.mem, 2, status, 1, DESC_F_WRITE, 0);
    publish(&rig.mem, 0);
    reg_write(&mut rig.transport, &rig.mem, 0x050, 0);
    assert_eq!(rig.mem.read_vec(status, 1).unwrap(), [1]);
}

#[test]
fn a_descriptor_cycle_cannot_hang_the_device() {
    let mut rig = block_rig(8, false);
    set_desc(&rig.mem, 0, DATA, 16, DESC_F_NEXT, 1);
    set_desc(&rig.mem, 1, DATA, 16, DESC_F_NEXT, 0);
    publish(&rig.mem, 0);
    reg_write(&mut rig.transport, &rig.mem, 0x050, 0);
    assert_ne!(
        reg_read(&mut rig.transport, 0x070) & STATUS_NEEDS_RESET,
        0,
        "the device should report that it needs a reset"
    );
    assert_ne!(
        reg_read(&mut rig.transport, 0x060) & 2,
        0,
        "and raise a config interrupt"
    );

    // A broken queue stops processing, but the driver can recover through a reset.
    reg_write(&mut rig.transport, &rig.mem, 0x070, 0);
    assert_eq!(reg_read(&mut rig.transport, 0x070), 0);
    rig.mem.write_u16(AVAIL + 2, 0).unwrap();
    negotiate(&mut rig.transport, &rig.mem, 0, 0);
    assert_eq!(
        rig.request(BLK_IN, 0, 512, true),
        0,
        "recovered after a reset"
    );
}

fn raw_queue(mem: &GuestMemory) -> Queue {
    let mut q = Queue::new(QUEUE_SIZE);
    q.ready = true;
    q.desc_table = DESC;
    q.avail_ring = AVAIL;
    q.used_ring = USED;
    mem.write_u16(AVAIL + 2, 0).unwrap();
    q
}

#[test]
fn queue_rejects_hostile_ring_contents() {
    let mem = GuestMemory::new(1 << 20).unwrap();

    let mut q = raw_queue(&mem);
    publish(&mem, QUEUE_SIZE);
    assert_eq!(q.pop(&mem), Err(QueueError::BadHead(QUEUE_SIZE)));

    let mut q = raw_queue(&mem);
    set_desc(&mem, 0, DATA, 16, DESC_F_NEXT, QUEUE_SIZE);
    publish(&mem, 0);
    assert_eq!(q.pop(&mem), Err(QueueError::BadNext(QUEUE_SIZE)));

    let mut q = raw_queue(&mem);
    set_desc(&mem, 0, DATA, 16, DESC_F_INDIRECT, 0);
    publish(&mem, 0);
    assert_eq!(q.pop(&mem), Err(QueueError::IndirectUnsupported));

    let mut q = raw_queue(&mem);
    set_desc(&mem, 0, DATA, 16, DESC_F_NEXT, 0);
    publish(&mem, 0);
    assert_eq!(q.pop(&mem), Err(QueueError::ChainTooLong));

    let mut q = raw_queue(&mem);
    mem.write_u16(AVAIL + 2, QUEUE_SIZE + 1).unwrap();
    assert_eq!(q.pop(&mem), Err(QueueError::AvailIndexOutOfRange));
}

#[test]
fn queue_rejects_rings_placed_outside_guest_memory() {
    let mem = GuestMemory::new(1 << 16).unwrap();
    let mut q = Queue::new(QUEUE_SIZE);
    q.ready = true;
    q.desc_table = u64::MAX - 8;
    q.avail_ring = u64::MAX - 1;
    q.used_ring = 0;
    assert!(matches!(q.pop(&mem), Err(QueueError::Memory(_))));
}

#[test]
fn hostile_used_ring_address_fails_cleanly() {
    let mem = GuestMemory::new(1 << 20).unwrap();
    let mut q = raw_queue(&mem);
    q.used_ring = u64::MAX - 2;
    assert!(matches!(q.add_used(&mem, 0, 0), Err(QueueError::Memory(_))));

    // An address that would wrap to a valid low address has to fail, not alias guest RAM.
    let mut q = raw_queue(&mem);
    q.desc_table = u64::MAX - 7;
    set_desc(&mem, 0, DATA, 8, 0, 0);
    publish(&mem, 1);
    assert!(matches!(q.pop(&mem), Err(QueueError::Memory(_))));
}

#[test]
fn queue_rejects_invalid_sizes_and_unconfigured_use() {
    let mem = GuestMemory::new(1 << 20).unwrap();
    let mut q = Queue::new(QUEUE_SIZE);
    assert_eq!(q.pop(&mem), Err(QueueError::NotReady), "not ready");
    q.ready = true;
    for bad in [0, 3, QUEUE_SIZE + 1, QUEUE_SIZE * 2] {
        q.size = bad;
        assert_eq!(q.pop(&mem), Err(QueueError::NotReady), "size {bad}");
    }
}

#[test]
fn queue_indices_wrap_at_16_bits() {
    let mem = GuestMemory::new(1 << 20).unwrap();
    let mut q = raw_queue(&mem);
    set_desc(&mem, 0, DATA, 8, 0, 0);
    for _ in 0..70_000u32 {
        publish(&mem, 0);
        let chain = q.pop(&mem).unwrap().expect("a chain was published");
        assert_eq!(chain.head, 0);
        q.add_used(&mem, chain.head, 0).unwrap();
        assert_eq!(q.pop(&mem).unwrap(), None);
    }
    assert_eq!(mem.read_u16(USED + 2).unwrap(), (70_000u32 % 65_536) as u16);
}

#[test]
fn features_the_device_did_not_offer_are_masked() {
    let mem = GuestMemory::new(1 << 20).unwrap();
    let image = Arc::new(Mutex::new(vec![0u8; 512]));
    let mut t = MmioTransport::new(Box::new(Block::new(image, false)));
    reg_write(&mut t, &mem, 0x070, STATUS_ACK_DRIVER);
    // Without VERSION_1 the device has to refuse FEATURES_OK, because legacy mode is not
    // implemented.
    reg_write(&mut t, &mem, 0x024, 0);
    reg_write(&mut t, &mem, 0x020, 0xFFFF_FFFF);
    reg_write(&mut t, &mem, 0x070, STATUS_ACK_DRIVER | STATUS_FEATURES_OK);
    assert_eq!(reg_read(&mut t, 0x070) & STATUS_FEATURES_OK, 0);
}

#[test]
fn queues_cannot_be_reconfigured_after_driver_ok() {
    let mut rig = block_rig(8, false);
    reg_write(&mut rig.transport, &rig.mem, 0x080, 0xDEAD_0000);
    reg_write(&mut rig.transport, &rig.mem, 0x038, 3);
    assert_eq!(
        rig.request(BLK_IN, 0, 512, true),
        0,
        "the original queue still works"
    );
}

#[test]
fn notifications_before_driver_ok_are_ignored() {
    let mem = GuestMemory::new(1 << 20).unwrap();
    let image = Arc::new(Mutex::new(vec![0u8; 512]));
    let mut t = MmioTransport::new(Box::new(Block::new(image, false)));
    reg_write(&mut t, &mem, 0x050, 0);
    reg_write(&mut t, &mem, 0x050, 99);
    assert_eq!(reg_read(&mut t, 0x070), 0);
    assert!(!t.take_irq());
}

#[test]
fn console_captures_transmit_buffers_up_to_a_limit() {
    let mem = GuestMemory::new(1 << 20).unwrap();
    let output = Arc::new(Mutex::new(Vec::new()));
    let mut t = MmioTransport::new(Box::new(Console::new(output.clone(), 8)));
    negotiate(&mut t, &mem, 1, 0);
    mem.write(DATA, b"hello ").unwrap();
    mem.write(DATA + 16, b"world!").unwrap();
    set_desc(&mem, 0, DATA, 6, DESC_F_NEXT, 1);
    set_desc(&mem, 1, DATA + 16, 6, 0, 0);
    publish(&mem, 0);
    reg_write(&mut t, &mem, 0x050, 1);
    assert_eq!(output.lock().unwrap().as_slice(), b"hello wo");
    assert!(t.take_irq());
}

#[test]
fn entropy_fills_writable_buffers() {
    let mem = GuestMemory::new(1 << 20).unwrap();
    let mut t = MmioTransport::new(Box::new(Entropy));
    negotiate(&mut t, &mem, 0, 0);
    set_desc(&mem, 0, DATA, 64, DESC_F_WRITE, 0);
    publish(&mem, 0);
    reg_write(&mut t, &mem, 0x050, 0);
    assert_ne!(mem.read_vec(DATA, 64).unwrap(), vec![0u8; 64]);
    assert_eq!(mem.read_u32(USED + 8).unwrap(), 64);
}
