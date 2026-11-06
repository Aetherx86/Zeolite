//! Lightweight virtual machine monitor.
//!
//! Boots guests under a hardware hypervisor with no device emulation beyond a serial port
//! and virtio-mmio. Backends:
//!
//! - Linux on x86-64: KVM. Runs raw 16-bit and 64-bit payloads and Linux bzImage kernels.
//! - macOS on Apple Silicon: Hypervisor.framework. Runs raw AArch64 payloads.
//!
//! Boot setup, the serial port and the virtio stack contain no hypervisor calls, so they
//! are tested on every platform.

pub mod boot;
pub mod memory;
pub mod serial;
pub mod virtio;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod kvm;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub mod hvf;

use std::sync::{Arc, Mutex};
use std::time::Duration;

/// What to execute inside the VM.
#[derive(Clone, Debug)]
pub enum Payload {
    /// Machine code entered in 16-bit real mode at [`boot::REAL_MODE_ENTRY`].
    RawX86RealMode(Vec<u8>),
    /// Machine code entered in 64-bit mode at [`boot::KERNEL_ADDR`], with an identity map
    /// of the first 4 GiB.
    RawX86LongMode(Vec<u8>),
    /// A Linux kernel booted through the 64-bit boot protocol.
    LinuxBzImage {
        kernel: Vec<u8>,
        cmdline: String,
        initrd: Option<Vec<u8>>,
    },
    /// Machine code entered at EL1 with the MMU off, at the base of guest RAM.
    RawAarch64(Vec<u8>),
}

#[derive(Clone, Debug)]
pub struct VmConfig {
    pub payload: Payload,
    pub memory_bytes: usize,
    pub timeout: Duration,
    pub max_serial_output: usize,
    /// Backing image for a virtio block device. Linux payloads only.
    pub block_image: Option<Arc<Mutex<Vec<u8>>>>,
    pub block_read_only: bool,
    /// Adds a virtio entropy device. Linux payloads only.
    pub entropy: bool,
}

impl VmConfig {
    pub fn new(payload: Payload) -> Self {
        VmConfig {
            payload,
            memory_bytes: 64 << 20,
            timeout: Duration::from_secs(10),
            max_serial_output: 1 << 20,
            block_image: None,
            block_read_only: false,
            entropy: false,
        }
    }
}

/// How a guest stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VmExit {
    /// The guest executed a halt instruction, or `hvc` or `wfi` on AArch64.
    Halted,
    /// The guest asked for a reset through the keyboard controller.
    Reset,
    /// Triple fault or a guest-requested shutdown.
    Shutdown,
    /// The configured time limit expired, and the guest was stopped.
    TimedOut,
}

#[derive(Clone, Debug)]
pub struct VmOutcome {
    pub exit: VmExit,
    pub serial: Vec<u8>,
    pub elapsed: Duration,
    /// Exits to the VMM, which approximates how much work the host did for the guest.
    pub exits: u64,
}

#[derive(Debug)]
pub enum VmError {
    /// No usable hypervisor on this host. Includes missing hardware, missing permissions
    /// and an unsigned binary on macOS.
    Unavailable(String),
    Config(String),
    Boot(boot::BootError),
    Memory(memory::OutOfBounds),
    GuestFault(String),
    Host {
        context: &'static str,
        source: std::io::Error,
    },
}

impl std::fmt::Display for VmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VmError::Unavailable(m) => write!(f, "hypervisor unavailable: {m}"),
            VmError::Config(m) => write!(f, "invalid configuration: {m}"),
            VmError::Boot(e) => write!(f, "boot failed: {e}"),
            VmError::Memory(e) => write!(f, "{e}"),
            VmError::GuestFault(m) => write!(f, "guest fault: {m}"),
            VmError::Host { context, source } => write!(f, "{context}: {source}"),
        }
    }
}

impl std::error::Error for VmError {}

impl From<boot::BootError> for VmError {
    fn from(e: boot::BootError) -> Self {
        VmError::Boot(e)
    }
}

impl From<memory::OutOfBounds> for VmError {
    fn from(e: memory::OutOfBounds) -> Self {
        VmError::Memory(e)
    }
}

/// Boots the payload and runs it on the calling thread until it stops.
pub fn run(cfg: VmConfig) -> Result<VmOutcome, VmError> {
    if cfg.memory_bytes == 0 {
        return Err(VmError::Config("guest memory size is zero".into()));
    }
    run_backend(cfg)
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn run_backend(cfg: VmConfig) -> Result<VmOutcome, VmError> {
    kvm::run(cfg)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn run_backend(cfg: VmConfig) -> Result<VmOutcome, VmError> {
    hvf::run(cfg)
}

#[cfg(not(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(target_os = "macos", target_arch = "aarch64")
)))]
fn run_backend(_cfg: VmConfig) -> Result<VmOutcome, VmError> {
    Err(VmError::Unavailable(
        "no hypervisor backend exists for this platform".into(),
    ))
}
