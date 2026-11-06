//! Linux KVM backend, written directly against the `/dev/kvm` ioctl interface.

use crate::boot::{self, LongModeState, Segment};
use crate::memory::GuestMemory;
use crate::serial::Serial;
use crate::virtio::devices::{Block, Entropy};
use crate::virtio::{MMIO_REGION_SIZE, MmioTransport};
use crate::{Payload, VmConfig, VmError, VmExit, VmOutcome};
use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::OpenOptionsExt;
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
use std::sync::{Arc, Condvar, Mutex, Once};
use std::time::Instant;

const KVM_GET_API_VERSION: u64 = 0xAE00;
const KVM_CREATE_VM: u64 = 0xAE01;
const KVM_GET_VCPU_MMAP_SIZE: u64 = 0xAE04;
const KVM_GET_SUPPORTED_CPUID: u64 = 0xC008_AE05;
const KVM_CREATE_VCPU: u64 = 0xAE41;
const KVM_SET_USER_MEMORY_REGION: u64 = 0x4020_AE46;
const KVM_SET_TSS_ADDR: u64 = 0xAE47;
const KVM_SET_IDENTITY_MAP_ADDR: u64 = 0x4008_AE48;
const KVM_CREATE_IRQCHIP: u64 = 0xAE60;
const KVM_IRQ_LINE: u64 = 0x4008_AE61;
const KVM_CREATE_PIT2: u64 = 0x4040_AE77;
const KVM_RUN: u64 = 0xAE80;
const KVM_GET_REGS: u64 = 0x8090_AE81;
const KVM_SET_REGS: u64 = 0x4090_AE82;
const KVM_GET_SREGS: u64 = 0x8138_AE83;
const KVM_SET_SREGS: u64 = 0x4138_AE84;
const KVM_SET_CPUID2: u64 = 0x4008_AE90;

const KVM_API_VERSION: i32 = 12;
const KVM_EXIT_IO: u32 = 2;
const KVM_EXIT_HLT: u32 = 5;
const KVM_EXIT_MMIO: u32 = 6;
const KVM_EXIT_SHUTDOWN: u32 = 8;
const KVM_EXIT_FAIL_ENTRY: u32 = 9;
const KVM_EXIT_INTERNAL_ERROR: u32 = 17;
const KVM_EXIT_SYSTEM_EVENT: u32 = 24;
const KVM_EXIT_IO_OUT: u8 = 1;
const KVM_PIT_SPEAKER_DUMMY: u32 = 1;

const TSS_ADDR: u64 = 0xFFFB_D000;
const IDENTITY_MAP_ADDR: u64 = 0xFFFB_C000;
const MAX_CPUID_ENTRIES: usize = 256;

const SERIAL_BASE: u16 = 0x3F8;
const SERIAL_IRQ: u32 = 4;
const I8042_COMMAND: u16 = 0x64;
const I8042_RESET: u8 = 0xFE;

const VIRTIO_MMIO_BASE: u64 = 0xD000_0000;
const VIRTIO_IRQ_BASE: u32 = 5;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Regs {
    rax: u64,
    rbx: u64,
    rcx: u64,
    rdx: u64,
    rsi: u64,
    rdi: u64,
    rsp: u64,
    rbp: u64,
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    rip: u64,
    rflags: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct KvmSegment {
    base: u64,
    limit: u32,
    selector: u16,
    type_: u8,
    present: u8,
    dpl: u8,
    db: u8,
    s: u8,
    l: u8,
    g: u8,
    avl: u8,
    unusable: u8,
    padding: u8,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct DTable {
    base: u64,
    limit: u16,
    padding: [u16; 3],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Sregs {
    cs: KvmSegment,
    ds: KvmSegment,
    es: KvmSegment,
    fs: KvmSegment,
    gs: KvmSegment,
    ss: KvmSegment,
    tr: KvmSegment,
    ldt: KvmSegment,
    gdt: DTable,
    idt: DTable,
    cr0: u64,
    cr2: u64,
    cr3: u64,
    cr4: u64,
    cr8: u64,
    efer: u64,
    apic_base: u64,
    interrupt_bitmap: [u64; 4],
}

const _: () = {
    // These sizes are encoded in the ioctl numbers above.
    assert!(std::mem::size_of::<Regs>() == 0x90);
    assert!(std::mem::size_of::<Sregs>() == 0x138);
    assert!(std::mem::size_of::<MemoryRegion>() == 0x20);
    assert!(std::mem::size_of::<CpuidEntry>() == 40);
};

#[repr(C)]
struct MemoryRegion {
    slot: u32,
    flags: u32,
    guest_phys_addr: u64,
    memory_size: u64,
    userspace_addr: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CpuidEntry {
    function: u32,
    index: u32,
    flags: u32,
    eax: u32,
    ebx: u32,
    ecx: u32,
    edx: u32,
    padding: [u32; 3],
}

#[repr(C)]
struct Cpuid {
    nent: u32,
    padding: u32,
    entries: [CpuidEntry; MAX_CPUID_ENTRIES],
}

#[repr(C)]
#[derive(Default)]
struct PitConfig {
    flags: u32,
    pad: [u32; 15],
}

#[repr(C)]
struct IrqLevel {
    irq: u32,
    level: u32,
}

/// The fixed prefix of `struct kvm_run` that this VMM uses.
#[repr(C)]
struct KvmRunHeader {
    request_interrupt_window: u8,
    immediate_exit: u8,
    padding1: [u8; 6],
    exit_reason: u32,
    ready_for_interrupt_injection: u8,
    if_flag: u8,
    flags: u16,
    cr8: u64,
    apic_base: u64,
    exit: KvmExitUnion,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct KvmExitIo {
    direction: u8,
    size: u8,
    port: u16,
    count: u32,
    data_offset: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct KvmExitMmio {
    phys_addr: u64,
    data: [u8; 8],
    len: u32,
    is_write: u8,
}

#[repr(C)]
union KvmExitUnion {
    io: KvmExitIo,
    mmio: KvmExitMmio,
    padding: [u8; 256],
}

fn last_error(context: &'static str) -> VmError {
    VmError::Host {
        context,
        source: std::io::Error::last_os_error(),
    }
}

/// # Safety
/// `arg` must be what the ioctl `request` expects on `fd`: an integer or a pointer to a
/// live, correctly sized structure.
unsafe fn ioctl(fd: RawFd, request: u64, arg: u64, context: &'static str) -> Result<i32, VmError> {
    // SAFETY: forwarded from this function's own contract.
    let ret = unsafe { libc::ioctl(fd, request as _, arg) };
    if ret < 0 {
        return Err(last_error(context));
    }
    Ok(ret)
}

fn owned(fd: i32) -> OwnedFd {
    // SAFETY: `fd` was just returned by a successful ioctl that creates a new descriptor,
    // and this is the only owner.
    unsafe { OwnedFd::from_raw_fd(fd) }
}

fn to_kvm_segment(s: &Segment) -> KvmSegment {
    KvmSegment {
        base: s.base,
        limit: s.limit,
        selector: s.selector,
        type_: s.type_,
        present: s.present,
        dpl: s.dpl,
        db: s.db,
        s: s.s,
        l: s.l,
        g: s.g,
        avl: 0,
        unusable: 0,
        padding: 0,
    }
}

fn apply_long_mode(sregs: &mut Sregs, lm: &LongModeState) {
    let (code, data) = (to_kvm_segment(&lm.code), to_kvm_segment(&lm.data));
    sregs.cs = code;
    sregs.ds = data;
    sregs.es = data;
    sregs.fs = data;
    sregs.gs = data;
    sregs.ss = data;
    sregs.tr = to_kvm_segment(&lm.tss);
    sregs.gdt = DTable {
        base: lm.gdt_base,
        limit: lm.gdt_limit,
        padding: [0; 3],
    };
    sregs.idt = DTable {
        base: lm.idt_base,
        limit: lm.idt_limit,
        padding: [0; 3],
    };
    sregs.cr0 = lm.cr0;
    sregs.cr3 = lm.cr3;
    sregs.cr4 = lm.cr4;
    sregs.efer = lm.efer;
}

/// Mapped `struct kvm_run`, unmapped on drop.
struct RunArea {
    ptr: *mut KvmRunHeader,
    size: usize,
}

impl Drop for RunArea {
    fn drop(&mut self) {
        // SAFETY: `ptr` and `size` describe the mapping created for this vCPU.
        unsafe {
            libc::munmap(self.ptr.cast(), self.size);
        }
    }
}

extern "C" fn kick_handler(_signal: libc::c_int) {}

/// Installs a no-op handler, without SA_RESTART, so the kick signal interrupts KVM_RUN.
fn kick_signal() -> libc::c_int {
    static INSTALL: Once = Once::new();
    let signal = libc::SIGRTMIN() + 6;
    INSTALL.call_once(|| {
        // SAFETY: a zeroed sigaction is a valid starting point, and the handler is
        // async-signal-safe because it does nothing.
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = kick_handler as *const () as usize;
            libc::sigemptyset(&mut action.sa_mask);
            libc::sigaction(signal, &action, std::ptr::null_mut());
        }
    });
    signal
}

/// Interrupts the vCPU at the deadline, so a spinning guest cannot hang the host thread.
struct Watchdog {
    state: Arc<(Mutex<bool>, Condvar)>,
    fired: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Watchdog {
    fn start(run: *mut KvmRunHeader, timeout: std::time::Duration) -> Watchdog {
        let state = Arc::new((Mutex::new(false), Condvar::new()));
        let fired = Arc::new(AtomicBool::new(false));
        let signal = kick_signal();
        // SAFETY: `pthread_self` has no preconditions.
        let vcpu_thread = unsafe { libc::pthread_self() };
        let run = AtomicPtr::new(run);

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
            drop(stopped);
            thread_fired.store(true, Ordering::SeqCst);
            let run = run.load(Ordering::SeqCst);
            // `Watchdog::drop` joins this thread before the run area and the vCPU thread
            // go away, so both stay valid for every iteration of this loop.
            loop {
                // SAFETY: see the comment above. `immediate_exit` is a single byte that the
                // kernel reads on KVM_RUN entry, so a volatile write is all it needs.
                unsafe {
                    std::ptr::addr_of_mut!((*run).immediate_exit).write_volatile(1);
                    libc::pthread_kill(vcpu_thread, signal);
                }
                let Ok(guard) = lock.lock() else {
                    return;
                };
                let Ok((stopped, _)) = cv.wait_timeout(guard, std::time::Duration::from_millis(5))
                else {
                    return;
                };
                if *stopped {
                    return;
                }
            }
        });
        Watchdog {
            state,
            fired,
            thread: Some(thread),
        }
    }

    fn fired(&self) -> bool {
        self.fired.load(Ordering::SeqCst)
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

struct Machine {
    vm: OwnedFd,
    vcpu: OwnedFd,
    run: RunArea,
    memory: GuestMemory,
    serial: Serial,
    transports: Vec<MmioTransport>,
    has_irqchip: bool,
    exits: u64,
}

fn open_kvm() -> Result<File, VmError> {
    let kvm = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_CLOEXEC)
        .open("/dev/kvm")
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => VmError::Unavailable("/dev/kvm does not exist".into()),
            std::io::ErrorKind::PermissionDenied => {
                VmError::Unavailable("permission denied opening /dev/kvm".into())
            }
            _ => VmError::Host {
                context: "open /dev/kvm",
                source: e,
            },
        })?;
    // SAFETY: this ioctl takes no argument.
    let version = unsafe {
        ioctl(
            kvm.as_raw_fd(),
            KVM_GET_API_VERSION,
            0,
            "KVM_GET_API_VERSION",
        )?
    };
    if version != KVM_API_VERSION {
        return Err(VmError::Unavailable(format!(
            "unexpected KVM API version {version}"
        )));
    }
    Ok(kvm)
}

fn set_cpuid(kvm: &File, vcpu: &OwnedFd) -> Result<(), VmError> {
    let mut cpuid = Box::new(Cpuid {
        nent: MAX_CPUID_ENTRIES as u32,
        padding: 0,
        entries: [CpuidEntry::default(); MAX_CPUID_ENTRIES],
    });
    let arg = std::ptr::addr_of_mut!(*cpuid) as u64;
    // SAFETY: `cpuid` is a live buffer that holds `nent` entries.
    unsafe {
        ioctl(
            kvm.as_raw_fd(),
            KVM_GET_SUPPORTED_CPUID,
            arg,
            "KVM_GET_SUPPORTED_CPUID",
        )?;
        ioctl(vcpu.as_raw_fd(), KVM_SET_CPUID2, arg, "KVM_SET_CPUID2")?;
    }
    Ok(())
}

impl Machine {
    fn new(
        cfg: &VmConfig,
        needs_irqchip: bool,
        transports: Vec<MmioTransport>,
    ) -> Result<Machine, VmError> {
        let kvm = open_kvm()?;
        let kvm_fd = kvm.as_raw_fd();

        // SAFETY: these ioctls take integer arguments or pointers to live locals.
        let vm = owned(unsafe { ioctl(kvm_fd, KVM_CREATE_VM, 0, "KVM_CREATE_VM")? });
        let vm_fd = vm.as_raw_fd();
        // SAFETY: as above.
        unsafe {
            ioctl(vm_fd, KVM_SET_TSS_ADDR, TSS_ADDR, "KVM_SET_TSS_ADDR")?;
            let identity = IDENTITY_MAP_ADDR;
            ioctl(
                vm_fd,
                KVM_SET_IDENTITY_MAP_ADDR,
                std::ptr::addr_of!(identity) as u64,
                "KVM_SET_IDENTITY_MAP_ADDR",
            )?;
        }

        if needs_irqchip {
            let pit = PitConfig {
                flags: KVM_PIT_SPEAKER_DUMMY,
                ..PitConfig::default()
            };
            // SAFETY: `pit` is a live struct of the size the ioctl encodes.
            unsafe {
                ioctl(vm_fd, KVM_CREATE_IRQCHIP, 0, "KVM_CREATE_IRQCHIP")?;
                ioctl(
                    vm_fd,
                    KVM_CREATE_PIT2,
                    std::ptr::addr_of!(pit) as u64,
                    "KVM_CREATE_PIT2",
                )?;
            }
        }

        let memory = GuestMemory::new(cfg.memory_bytes).map_err(|source| VmError::Host {
            context: "allocate guest memory",
            source,
        })?;
        if memory.len() as u64 > boot::MMIO_HOLE_START {
            return Err(VmError::Config(format!(
                "guest memory is limited to {} bytes",
                boot::MMIO_HOLE_START
            )));
        }
        let region = MemoryRegion {
            slot: 0,
            flags: 0,
            guest_phys_addr: 0,
            memory_size: memory.len() as u64,
            userspace_addr: memory.host_ptr() as u64,
        };
        // SAFETY: `region` describes the live allocation owned by `memory`, which is kept
        // in the returned `Machine` and therefore outlives the VM's use of it.
        unsafe {
            ioctl(
                vm_fd,
                KVM_SET_USER_MEMORY_REGION,
                std::ptr::addr_of!(region) as u64,
                "KVM_SET_USER_MEMORY_REGION",
            )?;
        }

        // SAFETY: this ioctl takes the vCPU id as an integer.
        let vcpu = owned(unsafe { ioctl(vm_fd, KVM_CREATE_VCPU, 0, "KVM_CREATE_VCPU")? });
        set_cpuid(&kvm, &vcpu)?;

        // SAFETY: this ioctl takes no argument.
        let size =
            unsafe { ioctl(kvm_fd, KVM_GET_VCPU_MMAP_SIZE, 0, "KVM_GET_VCPU_MMAP_SIZE")? } as usize;
        if size < std::mem::size_of::<KvmRunHeader>() {
            return Err(VmError::Unavailable(format!(
                "kvm_run mapping is unexpectedly small ({size} bytes)"
            )));
        }
        // SAFETY: mapping the vCPU descriptor with the size KVM reported is how `kvm_run`
        // is exposed. A failed mapping is checked for below.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                vcpu.as_raw_fd(),
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(last_error("mmap kvm_run"));
        }

        Ok(Machine {
            vm,
            vcpu,
            run: RunArea {
                ptr: ptr.cast(),
                size,
            },
            memory,
            serial: Serial::new(cfg.max_serial_output),
            transports,
            has_irqchip: needs_irqchip,
            exits: 0,
        })
    }

    fn get_sregs(&self) -> Result<Sregs, VmError> {
        let mut sregs = Sregs::default();
        // SAFETY: `sregs` is a live struct of the size this ioctl encodes.
        unsafe {
            ioctl(
                self.vcpu.as_raw_fd(),
                KVM_GET_SREGS,
                std::ptr::addr_of_mut!(sregs) as u64,
                "KVM_GET_SREGS",
            )?;
        }
        Ok(sregs)
    }

    fn set_sregs(&self, sregs: &Sregs) -> Result<(), VmError> {
        // SAFETY: `sregs` is a live struct of the size this ioctl encodes.
        unsafe {
            ioctl(
                self.vcpu.as_raw_fd(),
                KVM_SET_SREGS,
                std::ptr::from_ref(sregs) as u64,
                "KVM_SET_SREGS",
            )?;
        }
        Ok(())
    }

    fn set_regs(&self, regs: &Regs) -> Result<(), VmError> {
        // SAFETY: `regs` is a live struct of the size this ioctl encodes.
        unsafe {
            ioctl(
                self.vcpu.as_raw_fd(),
                KVM_SET_REGS,
                std::ptr::from_ref(regs) as u64,
                "KVM_SET_REGS",
            )?;
        }
        Ok(())
    }

    fn regs(&self) -> Result<Regs, VmError> {
        let mut regs = Regs::default();
        // SAFETY: `regs` is a live struct of the size this ioctl encodes.
        unsafe {
            ioctl(
                self.vcpu.as_raw_fd(),
                KVM_GET_REGS,
                std::ptr::addr_of_mut!(regs) as u64,
                "KVM_GET_REGS",
            )?;
        }
        Ok(regs)
    }

    fn pulse_irq(&self, irq: u32) -> Result<(), VmError> {
        if !self.has_irqchip {
            return Ok(());
        }
        for level in [1, 0] {
            let line = IrqLevel { irq, level };
            // SAFETY: `line` is a live struct of the size this ioctl encodes.
            unsafe {
                ioctl(
                    self.vm.as_raw_fd(),
                    KVM_IRQ_LINE,
                    std::ptr::addr_of!(line) as u64,
                    "KVM_IRQ_LINE",
                )?;
            }
        }
        Ok(())
    }

    fn io_read(&mut self, port: u16, out: &mut [u8]) {
        if (SERIAL_BASE..SERIAL_BASE + 8).contains(&port) && out.len() == 1 {
            out[0] = self.serial.read(port - SERIAL_BASE);
            return;
        }
        // Nothing lives on other ports, and a floating bus reads as all ones.
        out.fill(0xFF);
    }

    /// Returns true when the guest asked for a reset.
    fn io_write(&mut self, port: u16, data: &[u8]) -> bool {
        if (SERIAL_BASE..SERIAL_BASE + 8).contains(&port) && data.len() == 1 {
            self.serial.write(port - SERIAL_BASE, data[0]);
            return false;
        }
        port == I8042_COMMAND && data == [I8042_RESET]
    }

    fn mmio(&mut self, addr: u64, data: &mut [u8], is_write: bool) -> Result<(), VmError> {
        let Some(offset) = addr.checked_sub(VIRTIO_MMIO_BASE) else {
            data.fill(0xFF);
            return Ok(());
        };
        let index = (offset / MMIO_REGION_SIZE) as usize;
        let Some(transport) = self.transports.get_mut(index) else {
            if !is_write {
                data.fill(0xFF);
            }
            return Ok(());
        };
        let register = offset % MMIO_REGION_SIZE;
        if is_write {
            transport.write(register, data, &self.memory);
        } else {
            transport.read(register, data);
        }
        if transport.take_irq() {
            self.pulse_irq(VIRTIO_IRQ_BASE + index as u32)?;
        }
        Ok(())
    }

    fn run_loop(&mut self, watchdog: &Watchdog) -> Result<VmExit, VmError> {
        let run = self.run.ptr;
        let vcpu = self.vcpu.as_raw_fd();
        loop {
            // SAFETY: KVM_RUN takes no argument, and `run` stays mapped for this call.
            let ret = unsafe { libc::ioctl(vcpu, KVM_RUN as _, 0) };
            if ret < 0 {
                let error = std::io::Error::last_os_error();
                match error.raw_os_error() {
                    Some(libc::EINTR) | Some(libc::EAGAIN) => {
                        if watchdog.fired() {
                            return Ok(VmExit::TimedOut);
                        }
                        continue;
                    }
                    _ => {
                        return Err(VmError::Host {
                            context: "KVM_RUN",
                            source: error,
                        });
                    }
                }
            }
            self.exits += 1;

            // SAFETY: KVM has finished writing `kvm_run` by the time KVM_RUN returns, and
            // the vCPU is stopped until the next KVM_RUN on this thread.
            let reason = unsafe { std::ptr::addr_of!((*run).exit_reason).read_volatile() };
            match reason {
                KVM_EXIT_IO => {
                    // SAFETY: the kernel filled the `io` member for this exit reason.
                    let io = unsafe { std::ptr::addr_of!((*run).exit.io).read_volatile() };
                    if self.handle_io(io)? {
                        return Ok(VmExit::Reset);
                    }
                    if self.serial.take_irq() {
                        self.pulse_irq(SERIAL_IRQ)?;
                    }
                }
                KVM_EXIT_MMIO => {
                    // SAFETY: the kernel filled the `mmio` member for this exit reason.
                    let mut mmio = unsafe { std::ptr::addr_of!((*run).exit.mmio).read_volatile() };
                    let len = (mmio.len as usize).min(8);
                    let is_write = mmio.is_write != 0;
                    self.mmio(mmio.phys_addr, &mut mmio.data[..len], is_write)?;
                    if !is_write {
                        // SAFETY: KVM copies this field back into the guest on re-entry,
                        // and the vCPU is stopped while it is written.
                        unsafe {
                            std::ptr::addr_of_mut!((*run).exit.mmio.data).write_volatile(mmio.data);
                        }
                    }
                }
                KVM_EXIT_HLT => return Ok(VmExit::Halted),
                KVM_EXIT_SHUTDOWN => return Ok(VmExit::Shutdown),
                KVM_EXIT_SYSTEM_EVENT => return Ok(VmExit::Shutdown),
                KVM_EXIT_FAIL_ENTRY | KVM_EXIT_INTERNAL_ERROR => {
                    let rip = self.regs().map_or(0, |r| r.rip);
                    return Err(VmError::GuestFault(format!(
                        "KVM exit reason {reason} at rip {rip:#x}"
                    )));
                }
                other => {
                    return Err(VmError::GuestFault(format!(
                        "unhandled KVM exit reason {other}"
                    )));
                }
            }
        }
    }

    /// Returns true when the guest asked for a reset.
    fn handle_io(&mut self, io: KvmExitIo) -> Result<bool, VmError> {
        let size = usize::from(io.size);
        let count = io.count as usize;
        let total = size.saturating_mul(count);
        let offset = io.data_offset as usize;
        if !matches!(size, 1 | 2 | 4) || offset.saturating_add(total) > self.run.size {
            return Err(VmError::GuestFault(format!(
                "KVM reported an invalid I/O exit: size {size} count {count} offset {offset}"
            )));
        }
        // SAFETY: the range was checked against the size of the mapping above.
        let base = unsafe { self.run.ptr.cast::<u8>().add(offset) };
        let mut reset = false;
        for i in 0..count {
            let mut chunk = [0u8; 4];
            let chunk = &mut chunk[..size];
            // SAFETY: `i * size + size <= total`, which was bounds-checked above, and the
            // data area does not overlap the local `chunk`.
            let element = unsafe { base.add(i * size) };
            if io.direction == KVM_EXIT_IO_OUT {
                // SAFETY: see above.
                unsafe {
                    std::ptr::copy_nonoverlapping(element, chunk.as_mut_ptr(), size);
                }
                reset |= self.io_write(io.port, chunk);
            } else {
                self.io_read(io.port, chunk);
                // SAFETY: see above.
                unsafe {
                    std::ptr::copy_nonoverlapping(chunk.as_ptr(), element, size);
                }
            }
        }
        Ok(reset)
    }
}

/// Number of virtio devices this configuration creates.
fn build_transports(cfg: &VmConfig) -> Vec<MmioTransport> {
    let mut transports: Vec<MmioTransport> = Vec::new();
    if let Some(image) = &cfg.block_image {
        transports.push(MmioTransport::new(Box::new(Block::new(
            image.clone(),
            cfg.block_read_only,
        ))));
    }
    if cfg.entropy {
        transports.push(MmioTransport::new(Box::new(Entropy)));
    }
    transports
}

pub(crate) fn run(cfg: VmConfig) -> Result<VmOutcome, VmError> {
    let started = Instant::now();
    match &cfg.payload {
        Payload::RawX86RealMode(_) | Payload::RawX86LongMode(_) | Payload::LinuxBzImage { .. } => {}
        Payload::RawAarch64(_) => {
            return Err(VmError::Unavailable(
                "AArch64 payloads need the Hypervisor.framework backend".into(),
            ));
        }
    }
    let is_linux = matches!(cfg.payload, Payload::LinuxBzImage { .. });
    let transports = if is_linux {
        build_transports(&cfg)
    } else {
        Vec::new()
    };
    let device_count = transports.len();
    let mut machine = Machine::new(&cfg, is_linux, transports)?;

    match &cfg.payload {
        Payload::RawX86RealMode(blob) => {
            machine.memory.write(boot::REAL_MODE_ENTRY, blob)?;
            let mut sregs = machine.get_sregs()?;
            for seg in [
                &mut sregs.cs,
                &mut sregs.ds,
                &mut sregs.es,
                &mut sregs.fs,
                &mut sregs.gs,
                &mut sregs.ss,
            ] {
                seg.base = 0;
                seg.selector = 0;
            }
            machine.set_sregs(&sregs)?;
            machine.set_regs(&Regs {
                rip: boot::REAL_MODE_ENTRY,
                rflags: 2,
                rsp: boot::BOOT_STACK,
                ..Regs::default()
            })?;
        }
        Payload::RawX86LongMode(blob) => {
            let lm = boot::setup_long_mode(&machine.memory)?;
            machine.memory.write(boot::KERNEL_ADDR, blob)?;
            let mut sregs = machine.get_sregs()?;
            apply_long_mode(&mut sregs, &lm);
            machine.set_sregs(&sregs)?;
            machine.set_regs(&Regs {
                rip: boot::KERNEL_ADDR,
                rflags: 2,
                rsp: boot::BOOT_STACK,
                ..Regs::default()
            })?;
        }
        Payload::LinuxBzImage {
            kernel,
            cmdline,
            initrd,
        } => {
            let lm = boot::setup_long_mode(&machine.memory)?;
            let mut full = cmdline.clone();
            for i in 0..device_count {
                let addr = VIRTIO_MMIO_BASE + i as u64 * MMIO_REGION_SIZE;
                let irq = VIRTIO_IRQ_BASE + i as u32;
                full.push_str(&format!(" virtio_mmio.device=4K@{addr:#x}:{irq}"));
            }
            let entry = boot::load_linux(&machine.memory, kernel, &full, initrd.as_deref())?;
            let mut sregs = machine.get_sregs()?;
            apply_long_mode(&mut sregs, &lm);
            machine.set_sregs(&sregs)?;
            machine.set_regs(&Regs {
                rip: entry.rip,
                rsi: entry.rsi,
                rflags: 2,
                rsp: boot::BOOT_STACK,
                ..Regs::default()
            })?;
        }
        Payload::RawAarch64(_) => {}
    }

    let watchdog = Watchdog::start(machine.run.ptr, cfg.timeout);
    let exit = machine.run_loop(&watchdog);
    drop(watchdog);
    let exit = exit?;

    let exits = machine.exits;
    Ok(VmOutcome {
        exit,
        serial: std::mem::replace(&mut machine.serial, Serial::new(0)).into_output(),
        elapsed: started.elapsed(),
        exits,
    })
}
