//! Read-only shared mapping of a whole file (two libc calls, no crate). The digest hashes
//! straight out of the page cache instead of `pread`-ing every chunk into a per-thread buffer:
//! nothing is copied, and a fresh process no longer faults in a 1 MiB buffer per thread while it
//! is still spawning threads (KNOWLEDGE.md §10.7).
//!
//! The usual mmap caveat applies: if another process truncates the file while it is mapped,
//! touching the lost pages raises SIGBUS. fastsigner only writes its input after the digest.
//! A file that cannot be mapped (some FUSE file systems) is read into memory instead.

use std::fs::File;
use std::io;
use std::os::raw::{c_int, c_long, c_void};
use std::os::unix::fs::FileExt;
use std::os::unix::io::AsRawFd;

extern "C" {
    fn mmap(addr: *mut c_void, len: usize, prot: c_int, flags: c_int, fd: c_int, off: c_long) -> *mut c_void;
    fn munmap(addr: *mut c_void, len: usize) -> c_int;
    fn madvise(addr: *mut c_void, len: usize, advice: c_int) -> c_int;
}
const PROT_READ: c_int = 1;
const MAP_SHARED: c_int = 1;
const MAP_FAILED: *mut c_void = !0usize as *mut c_void;
const MADV_DONTNEED: c_int = 4;
const PAGE: usize = 4096;

pub struct Mmap {
    ptr: *mut c_void,
    len: usize,
    /// The file's bytes when it could not be mapped; `ptr` then points into this.
    copy: Option<Vec<u8>>,
}

// SAFETY: the mapping (or copy) is read-only and owned by this value; `&[u8]` views of it may be
// shared between threads like any other immutable buffer.
unsafe impl Send for Mmap {}
unsafe impl Sync for Mmap {}

impl Mmap {
    pub fn map(file: &File) -> io::Result<Mmap> {
        let len = usize::try_from(file.metadata()?.len()).map_err(|_| io::Error::other("file too large to map"))?;
        if len == 0 {
            return Ok(Mmap { ptr: std::ptr::NonNull::<u8>::dangling().as_ptr().cast(), len: 0, copy: None });
        }
        // SAFETY: a fresh read-only mapping of an open file descriptor; no existing memory is touched.
        let ptr = unsafe { mmap(std::ptr::null_mut(), len, PROT_READ, MAP_SHARED, file.as_raw_fd(), 0) };
        if ptr != MAP_FAILED {
            return Ok(Mmap { ptr, len, copy: None });
        }
        Mmap::copy(file, len)
    }

    /// The first `len` bytes of `file`, read into memory.
    fn copy(file: &File, len: usize) -> io::Result<Mmap> {
        let mut copy = vec![0u8; len];
        file.read_exact_at(&mut copy, 0)?;
        Ok(Mmap { ptr: copy.as_mut_ptr().cast(), len, copy: Some(copy) })
    }

    /// Unmap the pages under `part`, a slice of this mapping that has been read and is not
    /// needed again. The data stays in the page cache (touching it again just faults it back in),
    /// so this only moves page-table teardown from one `munmap` at the end — ~0.5 ms for a 145 MB
    /// APK on ext4, 3 ms on tmpfs, whose 4 KiB pages are unmapped one by one — onto the threads
    /// that read the pages, while they are still running in parallel.
    pub fn release(&self, part: &[u8]) {
        let (base, start) = (self.ptr as usize, part.as_ptr() as usize);
        assert!(start >= base && start + part.len() <= base + self.len, "release: slice is not part of the mapping");
        if self.copy.is_some() {
            return;
        }
        let (a, b) = ((start + PAGE - 1) & !(PAGE - 1), (start + part.len()) & !(PAGE - 1));
        if b > a {
            // SAFETY: whole pages inside our own read-only shared file mapping; afterwards reads
            // of them fault the same file data back in. An error just leaves the pages mapped.
            unsafe { madvise(a as *mut c_void, b - a, MADV_DONTNEED) };
        }
    }
}

impl std::ops::Deref for Mmap {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        // SAFETY: `ptr` is valid for `len` readable bytes (the mapping, the copy's heap buffer, or
        // dangling with `len == 0`) until drop.
        unsafe { std::slice::from_raw_parts(self.ptr.cast::<u8>(), self.len) }
    }
}

impl Drop for Mmap {
    fn drop(&mut self) {
        if self.len > 0 && self.copy.is_none() {
            // SAFETY: unmaps exactly the region `map` created; no views outlive `self`.
            unsafe { munmap(self.ptr, self.len) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mapped_and_copied_views_read_the_file() {
        let data: Vec<u8> = (0..3 * PAGE + 123).map(|i| (i * 7 % 251) as u8).collect();
        let path = std::env::temp_dir().join(format!("fastsigner-mmap-test-{}", std::process::id()));
        std::fs::write(&path, &data).unwrap();
        let f = File::open(&path).unwrap();
        let m = Mmap::map(&f).unwrap();
        assert!(m.copy.is_none());
        assert_eq!(&m[..], &data[..]);
        // Released pages fault the same bytes back in.
        m.release(&m[100..3 * PAGE + 50]);
        assert_eq!(&m[..], &data[..]);
        let c = Mmap::copy(&f, data.len()).unwrap();
        assert_eq!(&c[..], &data[..]);
        c.release(&c[..]);
        assert_eq!(&c[..], &data[..]);
        std::fs::write(&path, b"").unwrap();
        assert!(Mmap::map(&File::open(&path).unwrap()).unwrap().is_empty());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    #[should_panic(expected = "not part of the mapping")]
    fn release_rejects_foreign_memory() {
        let path = std::env::temp_dir().join(format!("fastsigner-mmap-foreign-{}", std::process::id()));
        std::fs::write(&path, [1u8; 64]).unwrap();
        let m = Mmap::map(&File::open(&path).unwrap()).unwrap();
        std::fs::remove_file(&path).ok();
        m.release(&vec![0u8; PAGE * 2]);
    }
}
