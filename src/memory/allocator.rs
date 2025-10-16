use core::{
    alloc::{GlobalAlloc, Layout},
    arch::x86_64::{_mm_clflush, _mm_mfence, _mm_sfence},
    ffi::c_void,
    fmt::{self, Display},
    sync::atomic::compiler_fence,
};
use std::alloc::System;

use libc::{
    RLIM_INFINITY, RLIMIT_MEMLOCK, explicit_bzero, getrlimit, madvise, mlock, mlock2, munlock,
    rlimit,
};
use log::error;
use macros::stable_api;
use thiserror_no_std::Error;

#[cfg(feature = "debug-alloc")]
use log::warn;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecureAllocErrorCode {
    LockFailed,
    CorruptionDetected,
    CapacityExceeded,
    NullCapacity,
    AlreadyDropped,
    SecurityViolation,
    None,
}

impl SecureAllocErrorCode {
    pub fn is_recoverable(&self) -> bool {
        matches!(self, SecureAllocErrorCode::LockFailed)
    }

    pub fn explain(&self) -> &'static str {
        match self {
            SecureAllocErrorCode::AlreadyDropped => {
                "SecureVec dropped after reuse, which will cause memory corruption"
            }
            SecureAllocErrorCode::CapacityExceeded => {
                "SecureVec's capacity exceeded, which will cause heartbleed"
            }
            SecureAllocErrorCode::CorruptionDetected => {
                "Memory Corrupted, operation safety compromised"
            }
            SecureAllocErrorCode::LockFailed => "SecureVec safe allocation failed",
            SecureAllocErrorCode::SecurityViolation => "Security violated, safety compromised",
            SecureAllocErrorCode::NullCapacity => "Tried to allocate Null memory",
            SecureAllocErrorCode::None => "Not an error code",
        }
    }

    pub fn get_as_str(&self) -> &'static str {
        match self {
            SecureAllocErrorCode::AlreadyDropped => "0x3001",
            SecureAllocErrorCode::CapacityExceeded => "0x2001",
            SecureAllocErrorCode::NullCapacity => "0x2002",
            SecureAllocErrorCode::LockFailed => "0x1001",
            SecureAllocErrorCode::CorruptionDetected => "0x1002",
            SecureAllocErrorCode::SecurityViolation => "0x4001",
            SecureAllocErrorCode::None => "0xFFFF",
        }
    }

    pub fn from_error(error: &str) -> SecureAllocErrorCode {
        match error {
            "0x3001" => SecureAllocErrorCode::AlreadyDropped,
            "0x2001" => SecureAllocErrorCode::CapacityExceeded,
            "0x2002" => SecureAllocErrorCode::NullCapacity,
            "0x1001" => SecureAllocErrorCode::LockFailed,
            "0x1002" => SecureAllocErrorCode::CorruptionDetected,
            "0x4001" => SecureAllocErrorCode::SecurityViolation,
            _ => SecureAllocErrorCode::None,
        }
    }

    pub fn log_level(&self) -> &'static str {
        match self.severity() {
            0 => "DEBUG",
            1 => "WARN",
            2 => "ERROR",
            4 => "CRITICAL",
            5 => "FATAL",
            _ => "UNKNOWN",
        }
    }

    pub fn severity(&self) -> u8 {
        match self {
            SecureAllocErrorCode::LockFailed => 1,
            SecureAllocErrorCode::NullCapacity => 2,
            SecureAllocErrorCode::CorruptionDetected => 4,
            SecureAllocErrorCode::CapacityExceeded => 5,
            SecureAllocErrorCode::SecurityViolation => 5,
            SecureAllocErrorCode::AlreadyDropped => 5,
            SecureAllocErrorCode::None => 0,
        }
    }
}

impl Display for SecureAllocErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.get_as_str())
    }
}

#[derive(Debug, Error)]
pub enum AllocatorError {
    #[error(
            "Capacity exceeded, Max: {0} Got: {1}
                        |
            You can't exceed capacity or it's going to cause Memory Corruption or Heartbleed - Fatal Error
            Error Code: {0}
            "
        )]
    CapacityExceeded(usize, usize, SecureAllocErrorCode),
    #[error(
        "Memory locking failed
                                |
            MLOCK failed to lock memory, which means SecureVec cannot protect anything anymore
            Error Code: {0}
            "
    )]
    LockFailed(SecureAllocErrorCode),
    #[error(
        "SecureVec Already Dropped
                                |
            Do not use any Zeroized/Dropped SecureVec, which will corrupt your memory - Fatal Error
            Error Code: {0}
            "
    )]
    AlreadyDropped(SecureAllocErrorCode),
    #[error(
        "Attempted to allocate Null capacity, SecureVec::with_capacity(0)
                                                                        |
            Error is that you used NULL capacity for Allocation, use capacity >0 - Fatal Error
            Error Code: {0}
            "
    )]
    NullCapacity(SecureAllocErrorCode),
    #[error("RNG Failed: {0}")]
    RngError(String),
    #[error("Mac initialization Failed")]
    MacInitFailed,
}

#[stable_api(since = "0.2.0")]
pub struct SecureAllocator;

unsafe impl GlobalAlloc for SecureAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if layout.size() == 0 {
            return std::ptr::null_mut();
        }

        let mut lim = rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };

        if (unsafe { getrlimit(RLIMIT_MEMLOCK, &mut lim) }) != 0 {
            error!("getrlimit failed");
            return std::ptr::null_mut();
        }

        if lim.rlim_cur != RLIM_INFINITY && (layout.size() as u64) > lim.rlim_cur {
            error!(
                "Allocation size {} exceeds RLIMIT_MEMLOCK ({})",
                layout.size(),
                lim.rlim_cur
            );
            return std::ptr::null_mut();
        }

        unsafe {
            let ptr = System.alloc(layout);
            if !ptr.is_null() {
                #[cfg(target_os = "linux")]
                {
                    if mlock2(ptr as *mut libc::c_void, layout.size(), libc::MLOCK_ONFAULT) != 0
                        && mlock(ptr as *mut libc::c_void, layout.size()) != 0
                    {
                        System.dealloc(ptr, layout);
                        return std::ptr::null_mut();
                    }

                    let _res = madvise(ptr as *mut c_void, layout.size(), libc::MADV_DONTDUMP);
                    #[cfg(feature = "debug-alloc")]
                    if _res != 0 {
                        warn!("madvise(MADV_DONTDUMP) failed (errno={})", unsafe {
                            *libc::__errno_location()
                        });
                    }

                    let _res = madvise(ptr as *mut c_void, layout.size(), libc::MADV_WIPEONFORK);
                    #[cfg(feature = "debug-alloc")]
                    if _res != 0 {
                        warn!(
                            "madvise(MADV_WIPEONFORK) failed or unsupported (errno={})",
                            unsafe { *libc::__errno_location() }
                        );
                    }

                    let _res = madvise(ptr as *mut c_void, layout.size(), libc::MADV_DONTFORK);
                    #[cfg(feature = "debug-alloc")]
                    if _res != 0 {
                        warn!(
                            "madvise(MADV_DONTFORK) failed or unsupported (errno={})",
                            unsafe { *libc::__errno_location() }
                        );
                    }
                }

                #[cfg(target_os = "macos")]
                {
                    if mlock(ptr as *mut libc::c_void, layout.size()) != 0 {
                        System.dealloc(ptr, layout);
                        return std::ptr::null_mut();
                    }
                }

                std::ptr::write_bytes(ptr, 0, layout.size());
            }

            ptr
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe {
            if !ptr.is_null() {
                let size = layout.size();

                explicit_bzero(ptr as *mut c_void, size);
                compiler_fence(core::sync::atomic::Ordering::SeqCst);
                _mm_sfence();

                std::ptr::write_bytes(ptr, 0xFF, size);
                compiler_fence(core::sync::atomic::Ordering::SeqCst);
                _mm_sfence();

                explicit_bzero(ptr as *mut c_void, size);
                compiler_fence(core::sync::atomic::Ordering::SeqCst);
                _mm_sfence();

                for i in 0..size {
                    let byte = std::ptr::read_volatile(ptr.add(i));
                    if byte != 0 {
                        error!(
                            "FATAL: Memory wipe failed at offset {} (got 0x{:02X})",
                            i, byte
                        );
                        return;
                    }
                }

                let mut offset = 0;
                while offset < size {
                    _mm_clflush(ptr.add(offset));
                    offset += 64;
                }
                _mm_mfence();

                if munlock(ptr as *mut libc::c_void, size) != 0 {
                    error!("munlock failed - memory may still be locked");
                }

                System.dealloc(ptr, layout);
            }
        }
    }
}

pub static SECURE_ALLOC: SecureAllocator = SecureAllocator;
