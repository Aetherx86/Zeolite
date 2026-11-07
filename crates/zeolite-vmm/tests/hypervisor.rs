//! Boots real guests under the real hypervisor.
//!
//! When no hypervisor is usable the tests skip and say so, unless ZEOLITE_REQUIRE_HV is set.
//! CI sets that variable on jobs known to have one, so a broken setup there fails loudly
//! instead of skipping silently.

use zeolite_vmm::{VmConfig, VmError, VmOutcome};

/// Runs a config, returning `None` when the test should be skipped.
fn boot(cfg: VmConfig) -> Option<VmOutcome> {
    match zeolite_vmm::run(cfg) {
        Ok(outcome) => Some(outcome),
        Err(VmError::Unavailable(why)) => {
            assert!(
                std::env::var_os("ZEOLITE_REQUIRE_HV").is_none(),
                "a hypervisor is required but unavailable: {why}"
            );
            eprintln!("skipping: {why}");
            None
        }
        Err(other) => panic!("the VM failed to run: {other}"),
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod kvm {
    use super::boot;
    use std::time::{Duration, Instant};
    use zeolite_vmm::{Payload, VmConfig, VmExit};

    /// mov dx, 0x3F8 (the operand-size prefix makes this valid in 64-bit mode too)
    fn set_port(code: &mut Vec<u8>, long_mode: bool) {
        if long_mode {
            code.push(0x66);
        }
        code.extend_from_slice(&[0xBA, 0xF8, 0x03]);
    }

    /// mov al, imm8; out dx, al
    fn emit(code: &mut Vec<u8>, text: &[u8]) {
        for b in text {
            code.extend_from_slice(&[0xB0, *b, 0xEE]);
        }
    }

    const HLT: u8 = 0xF4;

    #[test]
    fn real_mode_guest_prints_and_halts() {
        let mut code = Vec::new();
        set_port(&mut code, false);
        emit(&mut code, b"hello from real mode\n");
        code.push(HLT);
        let Some(out) = boot(VmConfig::new(Payload::RawX86RealMode(code))) else {
            return;
        };
        assert_eq!(out.exit, VmExit::Halted);
        assert_eq!(out.serial, b"hello from real mode\n");
    }

    #[test]
    fn long_mode_guest_prints_and_halts() {
        let mut code = Vec::new();
        set_port(&mut code, true);
        emit(&mut code, b"hello from long mode\n");
        code.push(HLT);
        let Some(out) = boot(VmConfig::new(Payload::RawX86LongMode(code))) else {
            return;
        };
        assert_eq!(out.exit, VmExit::Halted);
        assert_eq!(out.serial, b"hello from long mode\n");
    }

    #[test]
    fn long_mode_is_really_active_and_paging_works() {
        // Writes through a 64-bit register and reads back through memory above 1 MiB, which
        // only works if paging and the 64-bit code segment are set up correctly:
        //   movabs rax, 0x4142434445464748
        //   mov [0x200000], rax
        //   mov rbx, [0x200000]
        //   mov dx, 0x3F8
        //   mov al, bl; out dx, al   (prints 'H')
        let mut code = vec![0x48, 0xB8];
        code.extend_from_slice(&0x4142_4344_4546_4748u64.to_le_bytes());
        code.extend_from_slice(&[0x48, 0x89, 0x04, 0x25, 0x00, 0x00, 0x20, 0x00]);
        code.extend_from_slice(&[0x48, 0x8B, 0x1C, 0x25, 0x00, 0x00, 0x20, 0x00]);
        set_port(&mut code, true);
        code.extend_from_slice(&[0x88, 0xD8, 0xEE, HLT]);
        let Some(out) = boot(VmConfig::new(Payload::RawX86LongMode(code))) else {
            return;
        };
        assert_eq!(out.exit, VmExit::Halted);
        assert_eq!(out.serial, b"H");
    }

    #[test]
    fn string_io_is_delivered_in_order() {
        // rep outsb from a buffer placed right after the code, in real mode.
        let text = b"rep outsb works\n";
        let mut code = Vec::new();
        set_port(&mut code, false);
        code.extend_from_slice(&[0xBE, 0x0E, 0x10]); // mov si, 0x100E
        code.extend_from_slice(&[0xB9, text.len() as u8, 0x00]); // mov cx, len
        code.extend_from_slice(&[0xFC, 0xF3, 0x6E]); // cld; rep outsb
        code.push(HLT);
        code.resize(0x0E, 0x90);
        code.extend_from_slice(text);
        let Some(out) = boot(VmConfig::new(Payload::RawX86RealMode(code))) else {
            return;
        };
        assert_eq!(out.exit, VmExit::Halted);
        assert_eq!(out.serial, text);
    }

    #[test]
    fn a_spinning_guest_is_stopped_at_the_deadline() {
        let mut cfg = VmConfig::new(Payload::RawX86LongMode(vec![0xEB, 0xFE]));
        cfg.timeout = Duration::from_millis(200);
        let started = Instant::now();
        let Some(out) = boot(cfg) else {
            return;
        };
        assert_eq!(out.exit, VmExit::TimedOut);
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "took {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn a_triple_fault_is_reported_as_a_shutdown() {
        // The IDT is empty, so a software interrupt cannot be delivered: the fault escalates
        // to a double fault and then a triple fault, which shuts the VM down.
        let code = vec![0xCD, 0x80];
        let mut cfg = VmConfig::new(Payload::RawX86LongMode(code));
        cfg.timeout = Duration::from_secs(5);
        let Some(out) = boot(cfg) else {
            return;
        };
        assert_eq!(out.exit, VmExit::Shutdown);
    }

    #[test]
    fn keyboard_controller_reset_is_reported() {
        // mov al, 0xFE; out 0x64, al
        let code = vec![0xB0, 0xFE, 0xE6, 0x64, 0xEB, 0xFE];
        let Some(out) = boot(VmConfig::new(Payload::RawX86LongMode(code))) else {
            return;
        };
        assert_eq!(out.exit, VmExit::Reset);
    }

    #[test]
    fn hostile_guest_io_does_not_disturb_the_host() {
        // Touches ports and MMIO that nothing owns, then proves it kept running.
        //   out 0xE9, al; in al, 0x70
        //   movabs rax, [0xD0000000]  (unclaimed MMIO, reached through the identity map).
        // A plain disp32 would sign-extend to an unmapped high address here.
        let mut code = vec![0xE6, 0xE9, 0xE4, 0x70, 0x48, 0xA1];
        code.extend_from_slice(&0xD000_0000u64.to_le_bytes());
        set_port(&mut code, true);
        emit(&mut code, b"ok");
        code.push(HLT);
        let Some(out) = boot(VmConfig::new(Payload::RawX86LongMode(code))) else {
            return;
        };
        assert_eq!(out.exit, VmExit::Halted);
        assert_eq!(out.serial, b"ok");
    }

    #[test]
    fn serial_output_is_bounded_against_a_flooding_guest() {
        // out dx, al in a tight loop.
        let mut code = Vec::new();
        set_port(&mut code, true);
        code.extend_from_slice(&[0xB0, b'x', 0xEE, 0xEB, 0xFD]);
        let mut cfg = VmConfig::new(Payload::RawX86LongMode(code));
        cfg.timeout = Duration::from_millis(300);
        cfg.max_serial_output = 128;
        let Some(out) = boot(cfg) else {
            return;
        };
        assert_eq!(out.exit, VmExit::TimedOut);
        assert_eq!(out.serial.len(), 128);
    }

    /// Boots a real Linux kernel when CI provides one. The kernel has no root filesystem,
    /// so reaching its console is the success condition.
    #[test]
    fn linux_kernel_boots_to_its_console() {
        let Some(path) = std::env::var_os("ZEOLITE_TEST_KERNEL") else {
            eprintln!("skipping: ZEOLITE_TEST_KERNEL is not set");
            return;
        };
        let kernel = std::fs::read(&path).expect("the test kernel should be readable");
        let initrd = std::env::var_os("ZEOLITE_TEST_INITRD")
            .map(|p| std::fs::read(p).expect("the test initrd should be readable"));
        let expect_init = initrd.is_some();
        let cmdline = "console=ttyS0 earlyprintk=serial,ttyS0 noapic nolapic reboot=k panic=-1 \
                       pci=off nomodules i8042.noaux tsc=reliable"
            .to_string();
        let mut cfg = VmConfig::new(Payload::LinuxBzImage {
            kernel,
            cmdline,
            initrd,
        });
        cfg.memory_bytes = 1 << 30;
        cfg.timeout = Duration::from_secs(120);
        cfg.max_serial_output = 4 << 20;
        cfg.entropy = true;
        let started = Instant::now();
        let Some(out) = boot(cfg) else {
            return;
        };
        let console = String::from_utf8_lossy(&out.serial);
        eprintln!(
            "--- guest console ({} bytes, exit {:?}, {:?}, {} VM exits)\n{console}\n--- end",
            out.serial.len(),
            out.exit,
            started.elapsed(),
            out.exits
        );
        assert!(
            console.contains("Linux version"),
            "the kernel never reached its console"
        );
        if expect_init {
            assert!(
                console.contains("zeolite-init: reached userspace"),
                "the kernel never reached the init process"
            );
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod hvf {
    use super::boot;
    use std::time::{Duration, Instant};
    use zeolite_vmm::{Payload, VmConfig, VmError, VmExit};

    fn words(code: &[u32]) -> Vec<u8> {
        code.iter().flat_map(|w| w.to_le_bytes()).collect()
    }

    /// Prints a NUL-terminated string through the UART, then executes `hvc #0`.
    fn hello(text: &[u8]) -> Vec<u8> {
        let mut blob = words(&[
            0xD2A1_2000, // movz x0, #0x0900, lsl #16
            0x1000_00C1, // adr  x1, message (24 bytes ahead)
            0x3840_1422, // loop: ldrb w2, [x1], #1
            0x3400_0062, // cbz  w2, done
            0x3900_0002, // strb w2, [x0]
            0x17FF_FFFD, // b    loop
            0xD400_0002, // done: hvc #0
        ]);
        blob.extend_from_slice(text);
        blob.push(0);
        blob
    }

    #[test]
    fn aarch64_guest_prints_and_stops() {
        let Some(out) = boot(VmConfig::new(Payload::RawAarch64(hello(
            b"hello from el1\n",
        )))) else {
            return;
        };
        assert_eq!(out.exit, VmExit::Halted);
        assert_eq!(out.serial, b"hello from el1\n");
    }

    #[test]
    fn a_spinning_guest_is_stopped_at_the_deadline() {
        let mut cfg = VmConfig::new(Payload::RawAarch64(words(&[0x1400_0000]))); // b .
        cfg.timeout = Duration::from_millis(200);
        let started = Instant::now();
        let Some(out) = boot(cfg) else {
            return;
        };
        assert_eq!(out.exit, VmExit::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn touching_unmapped_memory_is_a_guest_fault_and_not_a_host_crash() {
        // mov x0, #0x10000; str x0, [x0]: a store to an address with no mapping.
        let blob = words(&[0xD2A0_0020, 0xF900_0000, 0xD400_0002]);
        match zeolite_vmm::run(VmConfig::new(Payload::RawAarch64(blob))) {
            Err(VmError::GuestFault(message)) => {
                assert!(message.contains("unmapped"), "got {message}");
            }
            Err(VmError::Unavailable(why)) => eprintln!("skipping: {why}"),
            other => panic!("expected a guest fault, got {other:?}"),
        }
    }

    #[test]
    fn x86_payloads_are_refused_clearly() {
        let result = zeolite_vmm::run(VmConfig::new(Payload::RawX86LongMode(vec![0xF4])));
        assert!(matches!(result, Err(VmError::Unavailable(_))));
    }

    #[test]
    fn runs_can_be_repeated_and_are_fast() {
        for _ in 0..5 {
            let Some(out) = boot(VmConfig::new(Payload::RawAarch64(hello(b"again")))) else {
                return;
            };
            assert_eq!(out.serial, b"again");
            eprintln!("boot to halt: {:?} with {} exits", out.elapsed, out.exits);
        }
    }

    #[test]
    fn serial_output_is_bounded() {
        let mut cfg = VmConfig::new(Payload::RawAarch64(hello(&[b'x'; 500])));
        cfg.max_serial_output = 10;
        let Some(out) = boot(cfg) else {
            return;
        };
        assert_eq!(out.serial.len(), 10);
    }
}

#[cfg(not(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(target_os = "macos", target_arch = "aarch64")
)))]
#[test]
fn other_platforms_report_no_backend() {
    let cfg = VmConfig::new(zeolite_vmm::Payload::RawX86LongMode(vec![0xF4]));
    assert!(matches!(
        zeolite_vmm::run(cfg),
        Err(VmError::Unavailable(_))
    ));
    let _: Option<VmOutcome> = None;
    let _ = boot;
}
