//! x86-64 boot setup: identity page tables, a GDT, and the Linux 64-bit boot protocol.
//!
//! Everything here only writes to [`GuestMemory`], so it is architecture-independent code
//! that runs and is tested on any host. Kernel images are treated as untrusted input.

use crate::memory::{GuestMemory, OutOfBounds};

pub const GDT_ADDR: u64 = 0x500;
pub const IDT_ADDR: u64 = 0x530;
/// Grows down, so it sits directly below the zero page and never overwrites it.
pub const BOOT_STACK: u64 = 0x7000;
pub const BOOT_PARAMS_ADDR: u64 = 0x7000;
pub const PML4_ADDR: u64 = 0x9000;
pub const PDPT_ADDR: u64 = 0xA000;
pub const PD_ADDR: u64 = 0xB000;
pub const CMDLINE_ADDR: u64 = 0x20000;
pub const CMDLINE_MAX: usize = 0x10000;
pub const KERNEL_ADDR: u64 = 0x10_0000;
pub const REAL_MODE_ENTRY: u64 = 0x1000;

/// Base of the 32-bit MMIO hole. RAM may not extend past this in the current layout.
pub const MMIO_HOLE_START: u64 = 0xC000_0000;

pub const SELECTOR_CODE: u16 = 0x10;
pub const SELECTOR_DATA: u16 = 0x18;
pub const SELECTOR_TSS: u16 = 0x20;

const CR0_PE: u64 = 1;
const CR0_MP: u64 = 1 << 1;
const CR0_ET: u64 = 1 << 4;
const CR0_NE: u64 = 1 << 5;
const CR0_PG: u64 = 1 << 31;
const CR4_PAE: u64 = 1 << 5;
const EFER_LME: u64 = 1 << 8;
const EFER_LMA: u64 = 1 << 10;

const PTE_PRESENT: u64 = 1;
const PTE_WRITABLE: u64 = 1 << 1;
const PTE_HUGE: u64 = 1 << 7;

// Offsets from the Linux x86 boot protocol.
const HDR_SETUP_SECTS: usize = 0x1F1;
const HDR_VID_MODE: usize = 0x1FA;
const HDR_BOOT_FLAG: usize = 0x1FE;
const HDR_JUMP: usize = 0x200;
const HDR_MAGIC: usize = 0x202;
const HDR_VERSION: usize = 0x206;
const HDR_TYPE_OF_LOADER: usize = 0x210;
const HDR_LOADFLAGS: usize = 0x211;
const HDR_RAMDISK_IMAGE: usize = 0x218;
const HDR_RAMDISK_SIZE: usize = 0x21C;
const HDR_HEAP_END: usize = 0x224;
const HDR_CMD_LINE_PTR: usize = 0x228;
const HDR_INITRD_ADDR_MAX: usize = 0x22C;
const HDR_CMDLINE_SIZE: usize = 0x238;
const HDR_XLOADFLAGS: usize = 0x236;
const HDR_INIT_SIZE: usize = 0x260;
const E820_ENTRIES: u64 = 0x1E8;
const E820_TABLE: u64 = 0x2D0;
const E820_MAX_ENTRIES: u8 = 128;

const LOADED_HIGH: u8 = 1;
const CAN_USE_HEAP: u8 = 0x80;
const XLF_KERNEL_64: u16 = 1;
const E820_RAM: u32 = 1;
const E820_RESERVED: u32 = 2;
const EBDA_START: u64 = 0x9_FC00;
const HIGH_MEMORY: u64 = 0x10_0000;
const MIN_BOOT_VERSION: u16 = 0x020C;

// The low-memory layout, checked at compile time. Two of these once failed: a five-entry
// GDT ran into the IDT, and the stack grew down into the zero page.
const _: () = {
    assert!(GDT_ADDR + 5 * 8 <= IDT_ADDR);
    assert!(IDT_ADDR + 8 <= REAL_MODE_ENTRY);
    assert!(REAL_MODE_ENTRY < BOOT_STACK);
    assert!(BOOT_STACK <= BOOT_PARAMS_ADDR);
    assert!(BOOT_PARAMS_ADDR + 0x1000 <= PML4_ADDR);
    assert!(PD_ADDR + 4 * 0x1000 <= CMDLINE_ADDR);
    assert!(CMDLINE_ADDR + CMDLINE_MAX as u64 <= EBDA_START);
};

/// Offset of the 64-bit entry point from the start of the loaded protected-mode kernel.
const ENTRY_64_OFFSET: u64 = 0x200;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BootError {
    ImageTooSmall,
    BadBootFlag,
    BadMagic,
    UnsupportedProtocol(u16),
    NoLongModeEntry,
    KernelTooLarge { needed: u64, available: u64 },
    TruncatedKernel,
    CommandLineTooLong { len: usize, max: usize },
    CommandLineHasNul,
    InitrdTooLarge,
    MemoryTooSmall,
    Memory(OutOfBounds),
}

impl std::fmt::Display for BootError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BootError::ImageTooSmall => write!(f, "kernel image is too small to hold a header"),
            BootError::BadBootFlag => write!(f, "kernel image has no boot flag"),
            BootError::BadMagic => write!(f, "kernel image has no HdrS signature"),
            BootError::UnsupportedProtocol(v) => {
                write!(f, "boot protocol {v:#06x} is older than the required 2.12")
            }
            BootError::NoLongModeEntry => write!(f, "kernel has no 64-bit entry point"),
            BootError::KernelTooLarge { needed, available } => {
                write!(
                    f,
                    "kernel needs {needed} bytes of memory but only {available} exist"
                )
            }
            BootError::TruncatedKernel => write!(f, "kernel image is shorter than its header says"),
            BootError::CommandLineTooLong { len, max } => {
                write!(f, "command line is {len} bytes but the limit is {max}")
            }
            BootError::CommandLineHasNul => write!(f, "command line contains a NUL byte"),
            BootError::InitrdTooLarge => write!(f, "initrd does not fit in guest memory"),
            BootError::MemoryTooSmall => write!(f, "guest memory is too small to boot"),
            BootError::Memory(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for BootError {}

impl From<OutOfBounds> for BootError {
    fn from(e: OutOfBounds) -> Self {
        BootError::Memory(e)
    }
}

/// A segment register value, independent of any hypervisor's structure layout.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Segment {
    pub base: u64,
    pub limit: u32,
    pub selector: u16,
    pub type_: u8,
    pub present: u8,
    pub dpl: u8,
    pub db: u8,
    pub s: u8,
    pub l: u8,
    pub g: u8,
}

/// Packs a segment into the 8-byte GDT descriptor format.
pub fn gdt_entry(seg: &Segment) -> u64 {
    let base = seg.base;
    let limit = u64::from(seg.limit);
    let access = u64::from(seg.type_)
        | (u64::from(seg.s) << 4)
        | (u64::from(seg.dpl) << 5)
        | (u64::from(seg.present) << 7);
    let flags = (u64::from(seg.l) << 1) | (u64::from(seg.db) << 2) | (u64::from(seg.g) << 3);
    (limit & 0xFFFF)
        | ((base & 0xFF_FFFF) << 16)
        | (access << 40)
        | (((limit >> 16) & 0xF) << 48)
        | (flags << 52)
        | (((base >> 24) & 0xFF) << 56)
}

/// Control and segment state for entering a payload in 64-bit mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LongModeState {
    pub cr0: u64,
    pub cr3: u64,
    pub cr4: u64,
    pub efer: u64,
    pub code: Segment,
    pub data: Segment,
    pub tss: Segment,
    pub gdt_base: u64,
    pub gdt_limit: u16,
    pub idt_base: u64,
    pub idt_limit: u16,
}

/// Writes the GDT and identity page tables covering the first 4 GiB with 2 MiB pages,
/// then returns the register state that activates them.
pub fn setup_long_mode(mem: &GuestMemory) -> Result<LongModeState, BootError> {
    let code = Segment {
        base: 0,
        limit: 0xF_FFFF,
        selector: SELECTOR_CODE,
        type_: 0xB,
        present: 1,
        dpl: 0,
        db: 0,
        s: 1,
        l: 1,
        g: 1,
    };
    let data = Segment {
        base: 0,
        limit: 0xF_FFFF,
        selector: SELECTOR_DATA,
        type_: 0x3,
        present: 1,
        dpl: 0,
        db: 1,
        s: 1,
        l: 0,
        g: 1,
    };
    let tss = Segment {
        base: 0,
        limit: 0xF_FFFF,
        selector: SELECTOR_TSS,
        type_: 0xB,
        present: 1,
        dpl: 0,
        db: 0,
        s: 0,
        l: 0,
        g: 1,
    };

    let gdt = [0u64, 0, gdt_entry(&code), gdt_entry(&data), gdt_entry(&tss)];
    for (i, entry) in gdt.iter().enumerate() {
        mem.write_u64(GDT_ADDR + i as u64 * 8, *entry)?;
    }
    // An empty IDT: any early fault triple-faults, which is reported as a shutdown.
    mem.write_u64(IDT_ADDR, 0)?;

    mem.write_u64(PML4_ADDR, PDPT_ADDR | PTE_PRESENT | PTE_WRITABLE)?;
    for gib in 0..4u64 {
        let pd = PD_ADDR + gib * 0x1000;
        mem.write_u64(PDPT_ADDR + gib * 8, pd | PTE_PRESENT | PTE_WRITABLE)?;
        for i in 0..512u64 {
            let frame = (gib << 30) | (i << 21);
            mem.write_u64(pd + i * 8, frame | PTE_PRESENT | PTE_WRITABLE | PTE_HUGE)?;
        }
    }

    Ok(LongModeState {
        cr0: CR0_PE | CR0_MP | CR0_ET | CR0_NE | CR0_PG,
        cr3: PML4_ADDR,
        cr4: CR4_PAE,
        efer: EFER_LME | EFER_LMA,
        code,
        data,
        tss,
        gdt_base: GDT_ADDR,
        gdt_limit: (gdt.len() * 8 - 1) as u16,
        idt_base: IDT_ADDR,
        idt_limit: 7,
    })
}

/// Where and how to enter a loaded Linux kernel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinuxEntry {
    pub rip: u64,
    pub rsi: u64,
}

fn read_u16(image: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([image[at], image[at + 1]])
}

fn read_u32(image: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([image[at], image[at + 1], image[at + 2], image[at + 3]])
}

/// Loads a bzImage using the 64-bit boot protocol.
///
/// The image, command line and initrd are copied into `mem`, and the zero page is filled
/// in. Page tables come from [`setup_long_mode`], which the caller runs separately.
pub fn load_linux(
    mem: &GuestMemory,
    image: &[u8],
    cmdline: &str,
    initrd: Option<&[u8]>,
) -> Result<LinuxEntry, BootError> {
    const HEADER_MIN: usize = 0x264;
    if image.len() < HEADER_MIN {
        return Err(BootError::ImageTooSmall);
    }
    if read_u16(image, HDR_BOOT_FLAG) != 0xAA55 {
        return Err(BootError::BadBootFlag);
    }
    if &image[HDR_MAGIC..HDR_MAGIC + 4] != b"HdrS" {
        return Err(BootError::BadMagic);
    }
    let version = read_u16(image, HDR_VERSION);
    if version < MIN_BOOT_VERSION {
        return Err(BootError::UnsupportedProtocol(version));
    }
    if read_u16(image, HDR_XLOADFLAGS) & XLF_KERNEL_64 == 0 {
        return Err(BootError::NoLongModeEntry);
    }

    let mem_size = mem.len() as u64;
    if mem_size < HIGH_MEMORY + (1 << 20) {
        return Err(BootError::MemoryTooSmall);
    }
    let ram_end = mem_size.min(MMIO_HOLE_START);

    let setup_sects = match image[HDR_SETUP_SECTS] {
        0 => 4usize,
        n => usize::from(n),
    };
    let kernel_offset = (setup_sects + 1) * 512;
    if kernel_offset >= image.len() {
        return Err(BootError::TruncatedKernel);
    }
    let kernel = &image[kernel_offset..];

    // `init_size` covers the decompressor's working area, not only the stored payload.
    let needed = u64::from(read_u32(image, HDR_INIT_SIZE)).max(kernel.len() as u64);
    let available = ram_end - KERNEL_ADDR;
    if needed > available {
        return Err(BootError::KernelTooLarge { needed, available });
    }

    let cmdline_max = (read_u32(image, HDR_CMDLINE_SIZE) as usize).min(CMDLINE_MAX - 1);
    if cmdline.len() > cmdline_max {
        return Err(BootError::CommandLineTooLong {
            len: cmdline.len(),
            max: cmdline_max,
        });
    }
    if cmdline.as_bytes().contains(&0) {
        return Err(BootError::CommandLineHasNul);
    }

    mem.write(KERNEL_ADDR, kernel)?;
    mem.write(CMDLINE_ADDR, cmdline.as_bytes())?;
    mem.write(CMDLINE_ADDR + cmdline.len() as u64, &[0])?;

    // The zero page starts as a copy of the image's own setup header. The header ends at
    // 0x202 plus the jump offset stored in the byte at 0x201.
    let header_end = (HDR_JUMP + 2 + usize::from(image[HDR_JUMP + 1])).clamp(HEADER_MIN, 0x1000);
    let header_end = header_end.min(image.len());
    mem.write(
        BOOT_PARAMS_ADDR + HDR_SETUP_SECTS as u64,
        &image[HDR_SETUP_SECTS..header_end],
    )?;

    let param = |offset: usize| BOOT_PARAMS_ADDR + offset as u64;
    mem.write_u16(param(HDR_VID_MODE), 0xFFFF)?;
    mem.write(param(HDR_TYPE_OF_LOADER), &[0xFF])?;
    let loadflags = image[HDR_LOADFLAGS] | LOADED_HIGH | CAN_USE_HEAP;
    mem.write(param(HDR_LOADFLAGS), &[loadflags])?;
    mem.write_u16(param(HDR_HEAP_END), 0xFE00)?;
    mem.write_u32(param(HDR_CMD_LINE_PTR), CMDLINE_ADDR as u32)?;

    if let Some(initrd) = initrd {
        let addr_max = u64::from(read_u32(image, HDR_INITRD_ADDR_MAX)).min(ram_end - 1);
        let kernel_end = KERNEL_ADDR + needed;
        let size = initrd.len() as u64;
        let top = (addr_max + 1).min(ram_end);
        let addr = top.checked_sub(size).ok_or(BootError::InitrdTooLarge)? & !0xFFF;
        if addr < kernel_end {
            return Err(BootError::InitrdTooLarge);
        }
        mem.write(addr, initrd)?;
        mem.write_u32(param(HDR_RAMDISK_IMAGE), addr as u32)?;
        mem.write_u32(param(HDR_RAMDISK_SIZE), size as u32)?;
    }

    let e820: [(u64, u64, u32); 3] = [
        (0, EBDA_START, E820_RAM),
        (EBDA_START, 0x10_0000 - EBDA_START, E820_RESERVED),
        (HIGH_MEMORY, ram_end - HIGH_MEMORY, E820_RAM),
    ];
    debug_assert!(e820.len() <= usize::from(E820_MAX_ENTRIES));
    mem.write(BOOT_PARAMS_ADDR + E820_ENTRIES, &[e820.len() as u8])?;
    for (i, (addr, size, kind)) in e820.iter().enumerate() {
        let at = BOOT_PARAMS_ADDR + E820_TABLE + i as u64 * 20;
        mem.write_u64(at, *addr)?;
        mem.write_u64(at + 8, *size)?;
        mem.write_u32(at + 16, *kind)?;
    }

    Ok(LinuxEntry {
        rip: KERNEL_ADDR + ENTRY_64_OFFSET,
        rsi: BOOT_PARAMS_ADDR,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIB: usize = 1 << 20;

    /// Builds a structurally valid bzImage header around a recognizable payload.
    fn fake_bzimage(payload_len: usize) -> Vec<u8> {
        let setup_sects = 3u8;
        let mut image = vec![0u8; (usize::from(setup_sects) + 1) * 512 + payload_len];
        image[HDR_SETUP_SECTS] = setup_sects;
        image[HDR_BOOT_FLAG..HDR_BOOT_FLAG + 2].copy_from_slice(&0xAA55u16.to_le_bytes());
        image[HDR_JUMP] = 0xEB;
        image[HDR_JUMP + 1] = 0x6A;
        image[HDR_MAGIC..HDR_MAGIC + 4].copy_from_slice(b"HdrS");
        image[HDR_VERSION..HDR_VERSION + 2].copy_from_slice(&0x020Fu16.to_le_bytes());
        image[HDR_XLOADFLAGS..HDR_XLOADFLAGS + 2].copy_from_slice(&XLF_KERNEL_64.to_le_bytes());
        image[HDR_CMDLINE_SIZE..HDR_CMDLINE_SIZE + 4].copy_from_slice(&2047u32.to_le_bytes());
        image[HDR_INITRD_ADDR_MAX..HDR_INITRD_ADDR_MAX + 4]
            .copy_from_slice(&0x7FFF_FFFFu32.to_le_bytes());
        let offset = (usize::from(setup_sects) + 1) * 512;
        for (i, byte) in image[offset..].iter_mut().enumerate() {
            *byte = (i % 251) as u8;
        }
        image
    }

    #[test]
    fn gdt_entries_match_known_encodings() {
        let lm = setup_long_mode(&GuestMemory::new(MIB).unwrap()).unwrap();
        // The canonical flat 64-bit kernel code and data descriptors.
        assert_eq!(gdt_entry(&lm.code), 0x00AF_9B00_0000_FFFF);
        assert_eq!(gdt_entry(&lm.data), 0x00CF_9300_0000_FFFF);
    }

    #[test]
    fn setup_leaves_the_tss_descriptor_intact() {
        let mem = GuestMemory::new(MIB).unwrap();
        let lm = setup_long_mode(&mem).unwrap();
        let stored = mem.read_u64(GDT_ADDR + u64::from(SELECTOR_TSS)).unwrap();
        assert_eq!(stored, gdt_entry(&lm.tss));
    }

    #[test]
    fn page_tables_identity_map_with_huge_pages() {
        let mem = GuestMemory::new(MIB).unwrap();
        let lm = setup_long_mode(&mem).unwrap();
        assert_eq!(lm.cr3, PML4_ADDR);

        let walk = |virt: u64| -> u64 {
            let pml4e = mem
                .read_u64(PML4_ADDR + ((virt >> 39) & 0x1FF) * 8)
                .unwrap();
            assert_eq!(pml4e & PTE_PRESENT, PTE_PRESENT);
            let pdpte = mem
                .read_u64((pml4e & !0xFFF) + ((virt >> 30) & 0x1FF) * 8)
                .unwrap();
            assert_eq!(pdpte & PTE_PRESENT, PTE_PRESENT);
            let pde = mem
                .read_u64((pdpte & !0xFFF) + ((virt >> 21) & 0x1FF) * 8)
                .unwrap();
            assert_eq!(pde & (PTE_PRESENT | PTE_HUGE), PTE_PRESENT | PTE_HUGE);
            (pde & !0x1F_FFFF & !0xFFF) | (virt & 0x1F_FFFF)
        };
        for virt in [
            0u64,
            0x1000,
            KERNEL_ADDR,
            0x3FFF_FFFF,
            0x4000_0000,
            0xFFFF_F000,
        ] {
            assert_eq!(walk(virt), virt, "identity mapping failed at {virt:#x}");
        }
        assert_eq!(lm.cr0 & CR0_PG, CR0_PG);
        assert_eq!(lm.cr4 & CR4_PAE, CR4_PAE);
        assert_eq!(lm.efer & (EFER_LME | EFER_LMA), EFER_LME | EFER_LMA);
    }

    #[test]
    fn loads_kernel_and_fills_the_zero_page() {
        let mem = GuestMemory::new(32 * MIB).unwrap();
        let image = fake_bzimage(4096);
        let entry = load_linux(&mem, &image, "console=ttyS0 quiet", None).unwrap();
        assert_eq!(entry.rip, KERNEL_ADDR + 0x200);
        assert_eq!(entry.rsi, BOOT_PARAMS_ADDR);

        assert_eq!(
            mem.read_vec(KERNEL_ADDR, 8).unwrap(),
            [0, 1, 2, 3, 4, 5, 6, 7]
        );
        assert_eq!(
            mem.read_vec(CMDLINE_ADDR, 20).unwrap(),
            b"console=ttyS0 quiet\0"
        );

        let p = BOOT_PARAMS_ADDR;
        assert_eq!(mem.read_vec(p + HDR_MAGIC as u64, 4).unwrap(), b"HdrS");
        assert_eq!(mem.read_u16(p + HDR_BOOT_FLAG as u64).unwrap(), 0xAA55);
        assert_eq!(
            mem.read_u32(p + HDR_CMD_LINE_PTR as u64).unwrap(),
            CMDLINE_ADDR as u32
        );
        assert_eq!(
            mem.read_vec(p + HDR_TYPE_OF_LOADER as u64, 1).unwrap(),
            [0xFF]
        );
        assert_eq!(
            mem.read_vec(p + HDR_LOADFLAGS as u64, 1).unwrap()[0] & (LOADED_HIGH | CAN_USE_HEAP),
            LOADED_HIGH | CAN_USE_HEAP
        );
        assert_eq!(mem.read_u32(p + HDR_RAMDISK_SIZE as u64).unwrap(), 0);
    }

    #[test]
    fn e820_map_excludes_the_legacy_hole() {
        let mem = GuestMemory::new(32 * MIB).unwrap();
        load_linux(&mem, &fake_bzimage(4096), "", None).unwrap();
        let p = BOOT_PARAMS_ADDR;
        assert_eq!(mem.read_vec(p + E820_ENTRIES, 1).unwrap(), [3]);
        let entry = |i: u64| {
            let at = p + E820_TABLE + i * 20;
            (
                mem.read_u64(at).unwrap(),
                mem.read_u64(at + 8).unwrap(),
                mem.read_u32(at + 16).unwrap(),
            )
        };
        assert_eq!(entry(0), (0, EBDA_START, E820_RAM));
        assert_eq!(entry(1).2, E820_RESERVED);
        assert_eq!(
            entry(2),
            (HIGH_MEMORY, 32 * MIB as u64 - HIGH_MEMORY, E820_RAM)
        );
    }

    #[test]
    fn e820_never_claims_ram_inside_the_mmio_hole() {
        let mem = GuestMemory::new(4096 * MIB).unwrap();
        load_linux(&mem, &fake_bzimage(4096), "", None).unwrap();
        let at = BOOT_PARAMS_ADDR + E820_TABLE + 2 * 20;
        let end = mem.read_u64(at).unwrap() + mem.read_u64(at + 8).unwrap();
        assert_eq!(end, MMIO_HOLE_START);
    }

    #[test]
    fn places_initrd_page_aligned_and_inside_memory() {
        let mem = GuestMemory::new(32 * MIB).unwrap();
        let initrd = vec![0xAB; 3000];
        load_linux(&mem, &fake_bzimage(4096), "", Some(&initrd)).unwrap();
        let p = BOOT_PARAMS_ADDR;
        let addr = u64::from(mem.read_u32(p + HDR_RAMDISK_IMAGE as u64).unwrap());
        let size = mem.read_u32(p + HDR_RAMDISK_SIZE as u64).unwrap();
        assert_eq!(size, 3000);
        assert_eq!(addr % 4096, 0);
        assert!(addr + u64::from(size) <= mem.len() as u64);
        assert_eq!(mem.read_vec(addr, 3).unwrap(), [0xAB; 3]);
    }

    #[test]
    fn rejects_malformed_images() {
        let mem = GuestMemory::new(32 * MIB).unwrap();
        let load = |image: &[u8]| load_linux(&mem, image, "", None);

        assert_eq!(load(&[0u8; 16]), Err(BootError::ImageTooSmall));

        let mut bad = fake_bzimage(4096);
        bad[HDR_BOOT_FLAG] = 0;
        assert_eq!(load(&bad), Err(BootError::BadBootFlag));

        let mut bad = fake_bzimage(4096);
        bad[HDR_MAGIC] = b'X';
        assert_eq!(load(&bad), Err(BootError::BadMagic));

        let mut bad = fake_bzimage(4096);
        bad[HDR_VERSION..HDR_VERSION + 2].copy_from_slice(&0x0200u16.to_le_bytes());
        assert_eq!(load(&bad), Err(BootError::UnsupportedProtocol(0x0200)));

        let mut bad = fake_bzimage(4096);
        bad[HDR_XLOADFLAGS..HDR_XLOADFLAGS + 2].copy_from_slice(&0u16.to_le_bytes());
        assert_eq!(load(&bad), Err(BootError::NoLongModeEntry));

        let mut bad = fake_bzimage(0);
        bad[HDR_SETUP_SECTS] = 0xFF;
        assert_eq!(load(&bad), Err(BootError::TruncatedKernel));

        let mut bad = fake_bzimage(4096);
        bad[HDR_INIT_SIZE..HDR_INIT_SIZE + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(load(&bad), Err(BootError::KernelTooLarge { .. })));
    }

    #[test]
    fn rejects_bad_command_lines_and_oversized_payloads() {
        let mem = GuestMemory::new(32 * MIB).unwrap();
        let image = fake_bzimage(4096);
        let long = "x".repeat(2048);
        assert_eq!(
            load_linux(&mem, &image, &long, None),
            Err(BootError::CommandLineTooLong {
                len: 2048,
                max: 2047
            })
        );
        assert_eq!(
            load_linux(&mem, &image, "a\0b", None),
            Err(BootError::CommandLineHasNul)
        );
        let initrd = vec![0u8; 64 * MIB];
        assert_eq!(
            load_linux(&mem, &image, "", Some(&initrd)),
            Err(BootError::InitrdTooLarge)
        );
        let tiny = GuestMemory::new(MIB).unwrap();
        assert_eq!(
            load_linux(&tiny, &image, "", None),
            Err(BootError::MemoryTooSmall)
        );
    }
}
