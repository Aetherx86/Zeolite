//! virtio-mmio transport (specification version 1.x, "modern" devices only) and devices.

pub mod devices;
pub mod queue;

use crate::memory::GuestMemory;
use queue::{Queue, QueueError};

pub const VIRTIO_F_VERSION_1: u64 = 1 << 32;

pub const MMIO_REGION_SIZE: u64 = 0x1000;
const MMIO_MAGIC: u32 = 0x7472_6976;
const MMIO_VERSION: u32 = 2;
const VENDOR_ID: u32 = 0x5A45_4F4C;

const STATUS_ACKNOWLEDGE: u32 = 1;
const STATUS_DRIVER: u32 = 2;
const STATUS_DRIVER_OK: u32 = 4;
const STATUS_FEATURES_OK: u32 = 8;
const STATUS_NEEDS_RESET: u32 = 64;
const STATUS_FAILED: u32 = 128;

const INT_VRING: u32 = 1;

/// Behavior of a concrete device behind the transport.
pub trait VirtioDevice: Send {
    fn device_id(&self) -> u32;
    fn features(&self) -> u64;
    fn num_queues(&self) -> usize;
    /// Size of each queue. Must be a power of two.
    fn queue_size(&self) -> u16 {
        256
    }
    fn read_config(&self, offset: u64, out: &mut [u8]);
    /// Drains the queue, returning whether any buffer was given back to the guest.
    fn process_queue(
        &mut self,
        index: usize,
        queue: &mut Queue,
        mem: &GuestMemory,
    ) -> Result<bool, QueueError>;
}

pub struct MmioTransport {
    device: Box<dyn VirtioDevice>,
    queues: Vec<Queue>,
    status: u32,
    device_features_sel: u32,
    driver_features_sel: u32,
    driver_features: u64,
    queue_sel: u32,
    interrupt_status: u32,
    config_generation: u32,
    irq_requested: bool,
}

impl MmioTransport {
    pub fn new(device: Box<dyn VirtioDevice>) -> Self {
        let queues = (0..device.num_queues())
            .map(|_| Queue::new(device.queue_size()))
            .collect();
        MmioTransport {
            device,
            queues,
            status: 0,
            device_features_sel: 0,
            driver_features_sel: 0,
            driver_features: 0,
            queue_sel: 0,
            interrupt_status: 0,
            config_generation: 0,
            irq_requested: false,
        }
    }

    pub fn device(&self) -> &dyn VirtioDevice {
        self.device.as_ref()
    }

    fn selected(&mut self) -> Option<&mut Queue> {
        self.queues.get_mut(self.queue_sel as usize)
    }

    fn reset(&mut self) {
        for q in &mut self.queues {
            q.reset();
        }
        self.status = 0;
        self.device_features_sel = 0;
        self.driver_features_sel = 0;
        self.driver_features = 0;
        self.queue_sel = 0;
        self.interrupt_status = 0;
    }

    /// Queue addresses and sizes may only change while the driver is setting up.
    fn can_configure_queue(&self) -> bool {
        self.status & STATUS_FEATURES_OK != 0 && self.status & STATUS_DRIVER_OK == 0
    }

    /// Handles a guest read. Only 32-bit register reads are defined by the specification,
    /// other than in the configuration space.
    pub fn read(&mut self, offset: u64, out: &mut [u8]) {
        if offset >= 0x100 {
            self.device.read_config(offset - 0x100, out);
            return;
        }
        let value = if out.len() == 4 {
            self.read_reg(offset)
        } else {
            0
        };
        let bytes = value.to_le_bytes();
        for (i, b) in out.iter_mut().enumerate() {
            *b = bytes.get(i).copied().unwrap_or(0);
        }
    }

    fn read_reg(&mut self, offset: u64) -> u32 {
        match offset {
            0x000 => MMIO_MAGIC,
            0x004 => MMIO_VERSION,
            0x008 => self.device.device_id(),
            0x00C => VENDOR_ID,
            0x010 => {
                let features = self.device.features() | VIRTIO_F_VERSION_1;
                match self.device_features_sel {
                    0 => features as u32,
                    1 => (features >> 32) as u32,
                    _ => 0,
                }
            }
            0x034 => self.selected().map_or(0, |q| u32::from(q.max_size)),
            0x044 => self.selected().map_or(0, |q| u32::from(q.ready)),
            0x060 => self.interrupt_status,
            0x070 => self.status,
            0x0FC => self.config_generation,
            _ => 0,
        }
    }

    /// Handles a guest write, and processes the queue if this is a notification.
    pub fn write(&mut self, offset: u64, data: &[u8], mem: &GuestMemory) {
        if offset >= 0x100 || data.len() != 4 {
            return;
        }
        let value = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        match offset {
            0x014 => self.device_features_sel = value,
            0x020 => {
                // Only features the device offered can be accepted.
                let offered = self.device.features() | VIRTIO_F_VERSION_1;
                if self.status & STATUS_FEATURES_OK == 0 {
                    match self.driver_features_sel {
                        0 => {
                            self.driver_features =
                                (self.driver_features & !0xFFFF_FFFF) | u64::from(value) & offered;
                        }
                        1 => {
                            self.driver_features = (self.driver_features & 0xFFFF_FFFF)
                                | (u64::from(value) << 32) & offered;
                        }
                        _ => {}
                    }
                }
            }
            0x024 => self.driver_features_sel = value,
            0x030 => self.queue_sel = value,
            0x038 => {
                if self.can_configure_queue()
                    && let Some(q) = self.selected()
                {
                    q.size = u16::try_from(value).unwrap_or(0);
                }
            }
            0x044 => {
                if self.can_configure_queue()
                    && let Some(q) = self.selected()
                {
                    q.ready = value == 1;
                }
            }
            0x050 => self.notify(value as usize, mem),
            0x064 => {
                self.interrupt_status &= !value;
            }
            0x070 => self.write_status(value),
            0x080 => self.set_addr(|q| &mut q.desc_table, value, false),
            0x084 => self.set_addr(|q| &mut q.desc_table, value, true),
            0x090 => self.set_addr(|q| &mut q.avail_ring, value, false),
            0x094 => self.set_addr(|q| &mut q.avail_ring, value, true),
            0x0A0 => self.set_addr(|q| &mut q.used_ring, value, false),
            0x0A4 => self.set_addr(|q| &mut q.used_ring, value, true),
            _ => {}
        }
    }

    fn set_addr(&mut self, field: fn(&mut Queue) -> &mut u64, value: u32, high: bool) {
        if !self.can_configure_queue() {
            return;
        }
        if let Some(q) = self.selected() {
            let slot = field(q);
            *slot = if high {
                (*slot & 0xFFFF_FFFF) | (u64::from(value) << 32)
            } else {
                (*slot & !0xFFFF_FFFF) | u64::from(value)
            };
        }
    }

    fn write_status(&mut self, value: u32) {
        if value == 0 {
            self.reset();
            return;
        }
        let mut next = value;
        // FEATURES_OK sticks only if VERSION_1 was negotiated, since legacy mode is not
        // implemented. The driver reads the status back to find out.
        if next & STATUS_FEATURES_OK != 0 && self.driver_features & VIRTIO_F_VERSION_1 == 0 {
            next &= !STATUS_FEATURES_OK;
        }
        // Status bits only accumulate, and DRIVER_OK requires completed negotiation.
        next |= self.status;
        if next & STATUS_DRIVER_OK != 0 && next & STATUS_FEATURES_OK == 0 {
            next &= !STATUS_DRIVER_OK;
        }
        let _ = (STATUS_ACKNOWLEDGE, STATUS_DRIVER, STATUS_FAILED);
        self.status = next;
    }

    fn notify(&mut self, index: usize, mem: &GuestMemory) {
        if self.status & STATUS_DRIVER_OK == 0 || self.status & STATUS_NEEDS_RESET != 0 {
            return;
        }
        let Some(queue) = self.queues.get_mut(index) else {
            return;
        };
        match self.device.process_queue(index, queue, mem) {
            Ok(true) => {
                self.interrupt_status |= INT_VRING;
                self.irq_requested = true;
            }
            Ok(false) => {}
            Err(_) => {
                // A broken queue halts this device, not the VMM. The driver sees the bit
                // and can reset the device.
                self.status |= STATUS_NEEDS_RESET;
                self.interrupt_status |= 2;
                self.config_generation = self.config_generation.wrapping_add(1);
                self.irq_requested = true;
            }
        }
    }

    pub fn take_irq(&mut self) -> bool {
        std::mem::take(&mut self.irq_requested)
    }
}
