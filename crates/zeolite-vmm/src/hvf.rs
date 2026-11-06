//! Apple Hypervisor.framework backend for AArch64 guests on Apple Silicon.
//!
//! The binary must be signed with the `com.apple.security.hypervisor` entitlement. An ad
//! hoc signature is enough, and `scripts/macos-sign-run.sh` applies one during `cargo run`
//! and `cargo test`.
//!
//! The framework allows one VM per process, so runs are serialized here.

use crate::memory::GuestMemory;
use crate::{Payload, VmConfig, VmError, VmExit, VmOutcome};
use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Instant;

type HvReturn = i32;
type HvVcpu = u64;

const HV_SUCCESS: HvReturn = 0;
const HV_DENIED: HvReturn = 0xFAE9_4007_u32 as i32;
const HV_UNSUPPORTED: HvReturn = 0xFAE9_400F_u32 as i32;

const HV_MEMORY_READ: u64 = 1 << 0;
const HV_MEMORY_WRITE: u64 = 1 << 1;
const HV_MEMORY_EXEC: u64 = 1 << 2;

const HV_REG_PC: u32 = 31;
const HV_REG_CPSR: u32 = 34;
const HV_EXIT_REASON_CANCELED: u32 = 0;
const HV_EXIT_REASON_EXCEPTION: u32 = 1;
const HV_EXIT_REASON_VTIMER: u32 = 2;

/// EL1h with all interrupts masked.
const CPSR_EL1H_MASKED: u64 = 0x3C5;

const EC_HVC64: u64 = 0x16;
const EC_DATA_ABORT_LOWER: u64 = 0x24;
const EC_WFX: u64 = 0x01;

/// Guest physical base of RAM. The payload starts executing at this address.
pub const RAM_BASE: u64 = 0x4000_0000;
/// PL011 data register, the only device this backend models.
pub const UART_BASE: u64 = 0x0900_0000;
const UART_SIZE: u64 = 0x1000;

#[repr(C)]
struct HvException {
    syndrome: u64,
    virtual_address: u64,
    physical_address: u64,
}

#[repr(C)]
struct HvVcpuExit {
    reason: u32,
    exception: HvException,
}

#[link(name = "Hypervisor", kind = "framework")]
unsafe extern "C" {
    fn hv_vm_create(config: *mut c_void) -> HvReturn;
    fn hv_vm_destroy() -> HvReturn;
    fn hv_vm_map(addr: *mut c_void, ipa: u64, size: usize, flags: u64) -> HvReturn;
    fn hv_vm_unmap(ipa: u64, size: usize) -> HvReturn;
    fn hv_vcpu_create(
        vcpu: *mut HvVcpu,
        exit: *mut *const HvVcpuExit,
        config: *mut c_void,
    ) -> HvReturn;
    fn hv_vcpu_destroy(vcpu: HvVcpu) -> HvReturn;
    fn hv_vcpu_run(vcpu: HvVcpu) -> HvReturn;
    fn hv_vcpu_set_reg(vcpu: HvVcpu, reg: u32, value: u64) -> HvReturn;
    fn hv_vcpu_get_reg(vcpu: HvVcpu, reg: u32, value: *mut u64) -> HvReturn;
    fn hv_vcpus_exit(vcpus: *const HvVcpu, count: u32) -> HvReturn;
}

fn check(ret: HvReturn, context: &'static str) -> Result<(), VmError> {
    match ret {
        HV_SUCCESS => Ok(()),
        HV_DENIED => Err(VmError::Unavailable(format!(
            "{context}: denied, because the binary lacks the com.apple.security.hypervisor entitlement"
        ))),
        HV_UNSUPPORTED => Err(VmError::Unavailable(format!(
            "{context}: virtualization is not supported on this host"
        ))),
        other => Err(VmError::Host {
            context,
            source: std::io::Error::other(format!("hypervisor error {:#x}", other as u32)),
        }),
    }
}

/// Serializes runs, because the framework permits only one VM per process.
static VM_LOCK: Mutex<()> = Mutex::new(());

struct VmGuard;

impl Drop for VmGuard {
    fn drop(&mut self) {
        // SAFETY: this guard exists only after a successful `hv_vm_create`, and everything
        // created inside the VM is destroyed first by drop order in `run`.
        unsafe {
            hv_vm_destroy();
        }
    }
}

struct Mapping {
    ipa: u64,
    size: usize,
}

impl Drop for Mapping {
    fn drop(&mut self) {
        // SAFETY: this range was mapped successfully and is unmapped exactly once.
        unsafe {
            hv_vm_unmap(self.ipa, self.size);
        }
    }
}

struct Vcpu {
    id: HvVcpu,
    exit: *const HvVcpuExit,
}

impl Drop for Vcpu {
    fn drop(&mut self) {
        // SAFETY: the vCPU was created on this thread, and it is destroyed once.
        unsafe {
            hv_vcpu_destroy(self.id);
        }
    }
}

struct Watchdog {
    state: Arc<(Mutex<bool>, Condvar)>,
    fired: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Watchdog {
    fn start(vcpu: HvVcpu, timeout: std::time::Duration) -> Watchdog {
        let state = Arc::new((Mutex::new(false), Condvar::new()));
        let fired = Arc::new(AtomicBool::new(false));
        let thread_state = state.clone();
        let thread_fired = fired.clone();
        let thread = std::thread::spawn(move || {
            let (lock, cv) = &*thread_state;
            let Ok(guard) = lock.lock() else {
                return;
            };
            let Ok((stopped, wait)) = cv.wait_timeout_while(guard, timeout, |s| !*s) else {
                return;
            };
            if *stopped || !wait.timed_out() {
                return;
            }
            thread_fired.store(true, Ordering::SeqCst);
            // SAFETY: `Watchdog::drop` joins this thread before the vCPU is destroyed.
            unsafe {
                hv_vcpus_exit(&vcpu, 1);
            }
        });
        Watchdog {
            state,
            fired,
            thread: Some(thread),
        }
    }
}

impl Drop for Watchdog {
    fn drop(&mut self) {
        let (lock, cv) = &*self.state;
        if let Ok(mut stopped) = lock.lock() {
            *stopped = true;
        }
        cv.notify_all();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

pub(crate) fn run(cfg: VmConfig) -> Result<VmOutcome, VmError> {
    let Payload::RawAarch64(blob) = &cfg.payload else {
        return Err(VmError::Unavailable(
            "Hypervisor.framework runs AArch64 payloads only".into(),
        ));
    };

    let _lock = VM_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // Timed from here, so waiting behind another VM does not count as boot time.
    let started = Instant::now();
    let memory = GuestMemory::new(cfg.memory_bytes).map_err(|source| VmError::Host {
        context: "allocate guest memory",
        source,
    })?;
    memory.write(0, blob)?;

    // SAFETY: a null configuration requests the default, and `VM_LOCK` is held for the
    // lifetime of the VM.
    check(
        unsafe { hv_vm_create(std::ptr::null_mut()) },
        "hv_vm_create",
    )?;
    let _vm = VmGuard;

    // SAFETY: `memory` is a live, page-aligned allocation that outlives `_mapping`.
    check(
        unsafe {
            hv_vm_map(
                memory.host_ptr().cast(),
                RAM_BASE,
                memory.len(),
                HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC,
            )
        },
        "hv_vm_map",
    )?;
    let _mapping = Mapping {
        ipa: RAM_BASE,
        size: memory.len(),
    };

    let mut id: HvVcpu = 0;
    let mut exit: *const HvVcpuExit = std::ptr::null();
    // SAFETY: both out-pointers refer to live locals, and a null config is the default.
    check(
        unsafe { hv_vcpu_create(&mut id, &mut exit, std::ptr::null_mut()) },
        "hv_vcpu_create",
    )?;
    let vcpu = Vcpu { id, exit };

    // SAFETY: the vCPU belongs to this thread, as the framework requires.
    unsafe {
        check(hv_vcpu_set_reg(vcpu.id, HV_REG_PC, RAM_BASE), "set PC")?;
        check(
            hv_vcpu_set_reg(vcpu.id, HV_REG_CPSR, CPSR_EL1H_MASKED),
            "set CPSR",
        )?;
    }

    let mut serial = Vec::new();
    let mut exits = 0u64;
    let watchdog = Watchdog::start(vcpu.id, cfg.timeout);
    let result = run_loop(
        &vcpu,
        &memory,
        &mut serial,
        cfg.max_serial_output,
        &mut exits,
        &watchdog,
    );
    drop(watchdog);
    let exit_kind = result?;

    Ok(VmOutcome {
        exit: exit_kind,
        serial,
        elapsed: started.elapsed(),
        exits,
    })
}

fn run_loop(
    vcpu: &Vcpu,
    memory: &GuestMemory,
    serial: &mut Vec<u8>,
    max_serial: usize,
    exits: &mut u64,
    watchdog: &Watchdog,
) -> Result<VmExit, VmError> {
    loop {
        // SAFETY: the vCPU is owned by this thread.
        check(unsafe { hv_vcpu_run(vcpu.id) }, "hv_vcpu_run")?;
        *exits += 1;
        // SAFETY: the framework keeps this structure valid for the vCPU's lifetime, and it
        // is stable while the vCPU is stopped.
        let (reason, syndrome, ipa) = unsafe {
            let e = &*vcpu.exit;
            (e.reason, e.exception.syndrome, e.exception.physical_address)
        };
        match reason {
            HV_EXIT_REASON_CANCELED => {
                if watchdog.fired.load(Ordering::SeqCst) {
                    return Ok(VmExit::TimedOut);
                }
            }
            HV_EXIT_REASON_VTIMER => {}
            HV_EXIT_REASON_EXCEPTION => match syndrome >> 26 {
                EC_HVC64 => return Ok(VmExit::Halted),
                EC_WFX => return Ok(VmExit::Halted),
                EC_DATA_ABORT_LOWER => {
                    handle_data_abort(vcpu, syndrome, ipa, memory, serial, max_serial)?;
                }
                other => {
                    return Err(VmError::GuestFault(format!(
                        "unhandled exception class {other:#x}, syndrome {syndrome:#x}"
                    )));
                }
            },
            other => {
                return Err(VmError::GuestFault(format!("unknown exit reason {other}")));
            }
        }
    }
}

fn handle_data_abort(
    vcpu: &Vcpu,
    syndrome: u64,
    ipa: u64,
    _memory: &GuestMemory,
    serial: &mut Vec<u8>,
    max_serial: usize,
) -> Result<(), VmError> {
    const ISV: u64 = 1 << 24;
    const WNR: u64 = 1 << 6;
    if syndrome & ISV == 0 {
        return Err(VmError::GuestFault(format!(
            "data abort at {ipa:#x} without a valid instruction syndrome"
        )));
    }
    if !(UART_BASE..UART_BASE + UART_SIZE).contains(&ipa) {
        return Err(VmError::GuestFault(format!(
            "guest touched unmapped address {ipa:#x}"
        )));
    }
    let register = ((syndrome >> 16) & 0x1F) as u32;
    let is_write = syndrome & WNR != 0;
    if is_write && ipa == UART_BASE {
        let mut value = 0u64;
        // Register 31 means the zero register in this encoding, which the HV_REG numbering
        // does not map to X31.
        if register != 31 {
            // SAFETY: the vCPU is owned by this thread, and `value` is a live local.
            check(
                unsafe { hv_vcpu_get_reg(vcpu.id, register, &mut value) },
                "read guest register",
            )?;
        }
        if serial.len() < max_serial {
            serial.push(value as u8);
        }
    } else if !is_write && register != 31 {
        // Reads from the UART return zero, which reports an idle device.
        // SAFETY: the vCPU is owned by this thread.
        check(
            unsafe { hv_vcpu_set_reg(vcpu.id, register, 0) },
            "write guest register",
        )?;
    }

    let mut pc = 0u64;
    // SAFETY: the vCPU is owned by this thread, and `pc` is a live local.
    unsafe {
        check(hv_vcpu_get_reg(vcpu.id, HV_REG_PC, &mut pc), "read PC")?;
        check(hv_vcpu_set_reg(vcpu.id, HV_REG_PC, pc + 4), "advance PC")?;
    }
    Ok(())
}
