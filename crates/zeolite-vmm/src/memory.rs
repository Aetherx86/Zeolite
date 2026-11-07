//! Guest physical memory.
//!
//! A running guest can change this memory at any moment, so the host never forms a Rust
//! reference into it. Every access copies bytes in or out through raw pointers. Device
//! code therefore works on private copies, which also closes off double-fetch bugs: a
//! value that was validated cannot change underneath the code that uses it.

use std::ptr::NonNull;

/// Allocation granularity. A multiple of both the 4 KiB and 16 KiB host page sizes.
pub const PAGE_GRANULE: usize = 64 << 10;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutOfBounds {
    pub addr: u64,
    pub len: usize,
}

impl std::fmt::Display for OutOfBounds {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "guest access of {} bytes at {:#x} is out of bounds",
            self.len, self.addr
        )
    }
}

impl std::error::Error for OutOfBounds {}

pub struct GuestMemory {
    ptr: NonNull<u8>,
    len: usize,
}

// SAFETY: `GuestMemory` owns its allocation, and all access goes through raw copies that
// never create references. Concurrent guest writes are inherent to virtualization and are
// handled by treating every value read from guest memory as untrusted.
unsafe impl Send for GuestMemory {}
// SAFETY: see the `Send` impl above.
unsafe impl Sync for GuestMemory {}

impl GuestMemory {
    /// Allocates zeroed memory, rounding `len` up to [`PAGE_GRANULE`].
    pub fn new(len: usize) -> std::io::Result<GuestMemory> {
        let len = len
            .checked_add(PAGE_GRANULE - 1)
            .map(|l| l & !(PAGE_GRANULE - 1))
            .filter(|l| *l > 0)
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "invalid guest memory size",
                )
            })?;
        let ptr = alloc(len)?;
        Ok(GuestMemory { ptr, len })
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Host address of the allocation, for handing to the hypervisor.
    pub fn host_ptr(&self) -> *mut u8 {
        self.ptr.as_ptr()
    }

    fn check(&self, addr: u64, len: usize) -> Result<usize, OutOfBounds> {
        let oob = OutOfBounds { addr, len };
        let start = usize::try_from(addr).map_err(|_| oob)?;
        let end = start.checked_add(len).ok_or(oob)?;
        if end > self.len {
            return Err(oob);
        }
        Ok(start)
    }

    pub fn read(&self, addr: u64, out: &mut [u8]) -> Result<(), OutOfBounds> {
        let start = self.check(addr, out.len())?;
        // SAFETY: `check` proved the range is inside the allocation, and `out` is a
        // distinct host buffer.
        unsafe {
            std::ptr::copy_nonoverlapping(
                self.ptr.as_ptr().add(start),
                out.as_mut_ptr(),
                out.len(),
            );
        }
        Ok(())
    }

    pub fn write(&self, addr: u64, data: &[u8]) -> Result<(), OutOfBounds> {
        let start = self.check(addr, data.len())?;
        // SAFETY: `check` proved the range is inside the allocation, and `data` is a
        // distinct host buffer.
        unsafe {
            std::ptr::copy_nonoverlapping(data.as_ptr(), self.ptr.as_ptr().add(start), data.len());
        }
        Ok(())
    }

    pub fn read_vec(&self, addr: u64, len: usize) -> Result<Vec<u8>, OutOfBounds> {
        self.check(addr, len)?;
        let mut out = vec![0u8; len];
        self.read(addr, &mut out)?;
        Ok(out)
    }

    pub fn read_u16(&self, addr: u64) -> Result<u16, OutOfBounds> {
        let mut b = [0u8; 2];
        self.read(addr, &mut b)?;
        Ok(u16::from_le_bytes(b))
    }

    pub fn read_u32(&self, addr: u64) -> Result<u32, OutOfBounds> {
        let mut b = [0u8; 4];
        self.read(addr, &mut b)?;
        Ok(u32::from_le_bytes(b))
    }

    pub fn read_u64(&self, addr: u64) -> Result<u64, OutOfBounds> {
        let mut b = [0u8; 8];
        self.read(addr, &mut b)?;
        Ok(u64::from_le_bytes(b))
    }

    pub fn write_u16(&self, addr: u64, v: u16) -> Result<(), OutOfBounds> {
        self.write(addr, &v.to_le_bytes())
    }

    pub fn write_u32(&self, addr: u64, v: u32) -> Result<(), OutOfBounds> {
        self.write(addr, &v.to_le_bytes())
    }

    pub fn write_u64(&self, addr: u64, v: u64) -> Result<(), OutOfBounds> {
        self.write(addr, &v.to_le_bytes())
    }
}

impl Drop for GuestMemory {
    fn drop(&mut self) {
        free(self.ptr, self.len);
    }
}

#[cfg(unix)]
fn alloc(len: usize) -> std::io::Result<NonNull<u8>> {
    // SAFETY: an anonymous private mapping with a null hint touches no existing memory.
    let p = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANON,
            -1,
            0,
        )
    };
    if p == libc::MAP_FAILED {
        return Err(std::io::Error::last_os_error());
    }
    NonNull::new(p.cast()).ok_or_else(|| std::io::Error::other("mmap returned null"))
}

#[cfg(unix)]
fn free(ptr: NonNull<u8>, len: usize) {
    // SAFETY: `ptr` and `len` describe the mapping created in `alloc`, unmapped once.
    unsafe {
        libc::munmap(ptr.as_ptr().cast(), len);
    }
}

#[cfg(not(unix))]
fn layout(len: usize) -> std::io::Result<std::alloc::Layout> {
    std::alloc::Layout::from_size_align(len, PAGE_GRANULE)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))
}

#[cfg(not(unix))]
fn alloc(len: usize) -> std::io::Result<NonNull<u8>> {
    // SAFETY: the layout has a non-zero size, guaranteed by `GuestMemory::new`.
    let p = unsafe { std::alloc::alloc_zeroed(layout(len)?) };
    NonNull::new(p).ok_or_else(|| std::io::Error::other("allocation failed"))
}

#[cfg(not(unix))]
fn free(ptr: NonNull<u8>, len: usize) {
    if let Ok(l) = layout(len) {
        // SAFETY: `ptr` was allocated in `alloc` with this same layout.
        unsafe { std::alloc::dealloc(ptr.as_ptr(), l) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rounds_up_and_starts_zeroed() {
        let m = GuestMemory::new(1).unwrap();
        assert_eq!(m.len(), PAGE_GRANULE);
        assert_eq!(m.host_ptr() as usize % 4096, 0);
        assert_eq!(m.read_u64(0).unwrap(), 0);
        assert_eq!(m.read_u64(PAGE_GRANULE as u64 - 8).unwrap(), 0);
    }

    #[test]
    fn round_trips_little_endian_values() {
        let m = GuestMemory::new(PAGE_GRANULE).unwrap();
        m.write_u32(0x10, 0xAABB_CCDD).unwrap();
        assert_eq!(m.read_u16(0x10).unwrap(), 0xCCDD);
        assert_eq!(m.read_vec(0x10, 4).unwrap(), [0xDD, 0xCC, 0xBB, 0xAA]);
    }

    #[test]
    fn rejects_every_out_of_bounds_shape() {
        let m = GuestMemory::new(PAGE_GRANULE).unwrap();
        let end = m.len() as u64;
        assert!(m.write(end - 4, &[0; 4]).is_ok());
        assert!(m.write(end - 3, &[0; 4]).is_err(), "straddles the end");
        assert!(m.write(end, &[0]).is_err(), "starts at the end");
        assert!(
            m.read_u64(u64::MAX - 3).is_err(),
            "address arithmetic would wrap"
        );
        assert!(
            m.read_vec(0, usize::MAX).is_err(),
            "must not try to allocate this"
        );
        assert!(m.read_vec(u64::MAX, 2).is_err());
    }

    #[test]
    fn zero_length_access_at_the_end_is_valid() {
        let m = GuestMemory::new(PAGE_GRANULE).unwrap();
        assert!(m.write(m.len() as u64, &[]).is_ok());
        assert!(m.write(m.len() as u64 + 1, &[]).is_err());
    }
}
