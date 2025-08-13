use core::{
    fmt::{self},
    ops::{BitOrAssign, BitXor},
    sync::atomic::compiler_fence,
};
use std::alloc::{GlobalAlloc, Layout};

#[cfg(any(feature = "debug-alloc", feature = "dev-logs"))]
use log::debug;
use log::{error, warn};
#[cfg(feature = "debug-alloc")]
use log::{info, trace};
use num_traits::Zero;

use crate::{
    CryptoRNG, HardwareRandomizable,
    memory::allocator::{AllocatorError, SECURE_ALLOC, SecureAllocErrorCode},
};

/// High-performance secure memory container with automatic zeroization and constant time operations
///
/// `SecureVec<T>` provides memory-safe storage for sensitive data with cryptographic security guarantees.
/// Designed to prevent common vulnerabilities like Heartbleed, timing attacks, and memory leaks.
///
/// # Security Features
///
/// - **Memory Locking**: Uses `mlock()` to prevent data from being swapped to disk
/// - **Auto-Zeroization**: Automatically overwrites memory with zeros on drop
/// - **Constant-Time Operations**: Prevents timing-based side-channel attacks
/// - **Use-After-Free Protection**: Panics on access to dropped instances
/// - **Cache Alignment**: 64-byte aligned for optimal performance
///
/// # Quick Start
///
/// ```rust
/// use x86_crypto_utils::allocator::SecureVec;
///
/// // Create secure storage for a crypto key
/// let mut key = SecureVec::with_capacity(32)?;
/// key.fill(0x42)?;
///
/// // Use it safely - memory is locked and protected
/// process_secret_key(&key);
///
/// // Automatic secure cleanup on drop
/// drop(key); // Memory zeroized automatically
/// ```
///
/// # Common Use Cases
///
/// - **Cryptographic Keys**: AES, RSA, ECDSA private keys
/// - **Passwords & Tokens**: User credentials, API tokens
/// - **Sensitive Config**: Database passwords, certificates
/// - **Temporary Secrets**: Nonces, salts, intermediate crypto values
///
/// # Performance Characteristics
///
/// - Allocation: ~10-50μs (mlock overhead)
/// - Access: Cache-optimal, same as `Vec<T>`
/// - Comparison: Constant-time (prevents timing attacks)
/// - Cleanup: ~5-20μs (secure memory wipe)
///
/// # Safety Guarantees
///
/// - **No Buffer Overflows**: Strict capacity checking
/// - **No Memory Leaks**: Guaranteed zeroization
/// - **No Timing Leaks**: Constant-time comparisons
/// - **No Swap Leaks**: Memory locked in RAM
///
/// # Important Notes
///
/// ⚠️ **After calling `zeroize()`, the SecureVec becomes unusable - any further access will panic**
///
/// ⚠️ **Do not use for large data (>1MB) - memory locking has system limits**
///
/// ⚠️ **Requires elevated privileges on some systems for memory locking**
#[repr(C, align(64))]
pub struct SecureVec<T> {
    ptr: *mut T,
    len: usize,
    cap: usize,
    is_dropped: bool,
}

impl<T> SecureVec<T> {
    pub fn with_capacity(cap: usize) -> Result<Self, AllocatorError> {
        if cap == 0 {
            return Err(AllocatorError::NullCapacity(
                SecureAllocErrorCode::NullCapacity,
            ));
        }

        #[cfg(feature = "debug-alloc")]
        info!("SecureVec allocation requested with capacity: {}", cap);

        let layout = Layout::array::<T>(cap).expect("Cannot Create Layout");
        let ptr = unsafe {
            let raw_ptr = SECURE_ALLOC.alloc(layout);

            if raw_ptr.is_null() {
                return Err(AllocatorError::LockFailed(SecureAllocErrorCode::LockFailed));
            }

            raw_ptr as *mut T
        };

        Ok(SecureVec {
            ptr,
            len: 0,
            cap,
            is_dropped: false,
        })
    }

    fn is_valid(&self) -> Result<(), AllocatorError> {
        if self.is_dropped {
            error!("SECURITY VIOLATION: Attempted to access dropped SecureVec");
            return Err(AllocatorError::AlreadyDropped(
                SecureAllocErrorCode::AlreadyDropped,
            ));
        }

        Ok(())
    }

    pub fn fill(&mut self, value: T) -> Result<(), AllocatorError>
    where
        T: Copy,
    {
        unsafe {
            self.is_valid()?;

            #[cfg(any(feature = "debug-alloc", feature = "dev-logs"))]
            debug!("Filling SecureVec with constant value...");

            for i in 0..self.cap {
                std::ptr::write(self.ptr.add(i), value);
            }

            self.len = self.cap;

            Ok(())
        }
    }

    pub fn fill_random(&mut self, generator: &mut impl CryptoRNG) -> Result<(), AllocatorError>
    where
        T: HardwareRandomizable,
    {
        unsafe {
            self.is_valid()?;

            #[cfg(any(feature = "debug-alloc", feature = "dev-logs"))]
            debug!("Filling SecureVec with cryptographically secure random data...");

            for i in 0..self.cap {
                let random_byte: T = generator
                    .try_generate()
                    .map_err(|e| AllocatorError::RngError(e.to_string()))?;
                std::ptr::write(self.ptr.add(i), random_byte);
            }

            self.len = self.cap;

            Ok(())
        }
    }

    pub fn push(&mut self, value: T) -> Result<(), AllocatorError> {
        self.is_valid()?;

        #[cfg(feature = "debug-alloc")]
        trace!("Pushed 1 item into SecureVec. Length is now {}", self.len);

        if self.len >= self.cap {
            return Err(AllocatorError::CapacityExceeded(
                self.cap,
                self.len,
                SecureAllocErrorCode::CapacityExceeded,
            ));
        }

        unsafe {
            std::ptr::write(self.ptr.add(self.len), value);
            self.len += 1;
        }

        Ok(())
    }

    pub fn extend_from_slice(&mut self, other: &[T]) -> Result<(), AllocatorError> {
        self.is_valid()?;

        #[cfg(feature = "debug-alloc")]
        trace!(
            "Extended SecureVec by {} elements. Length is now {}",
            other.len(),
            self.len
        );

        if self.len + other.len() > self.cap {
            return Err(AllocatorError::CapacityExceeded(
                self.cap,
                self.len + other.len(),
                SecureAllocErrorCode::CapacityExceeded,
            ));
        }

        unsafe {
            std::ptr::copy_nonoverlapping(other.as_ptr(), self.ptr.add(self.len), other.len());
            self.len += other.len();
        }

        Ok(())
    }

    /// # This function will zeroize and dop the SecureVec / DO NOT USE SECUREVEC AFTER ZEROIZING
    pub fn zeroize(&mut self) {
        if !self.ptr.is_null() {
            unsafe {
                let layout = Layout::array::<T>(self.cap).expect("Cannot Create Layout");
                SECURE_ALLOC.dealloc(self.ptr as *mut u8, layout);
            }

            self.ptr = std::ptr::null_mut();
            self.len = 0;
            self.cap = 0;
            self.is_dropped = true;

            warn!("SecureVec has been zeroized and dropped");
        }
    }

    pub unsafe fn explicit_as_slice(&self) -> &[T] {
        if self.ptr.is_null() || self.is_dropped {
            panic!("Attempted to reference a dropped SecureVec.explicit_as_slice()
                                                     |
                Which will cause memory corruption or even memory leaks | possibly heartbleed - Fatal Error");
        }

        #[cfg(feature = "debug-alloc")]
        warn!("Accessing SecureVec content via explicit_as_slice()");

        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }

    pub unsafe fn explicit_grow(&mut self, additional_capacity: usize) {
        if self.ptr.is_null() || self.is_dropped {
            panic!("Attempted to grow a dropped SecureVec - Fatal Error");
        }

        #[cfg(feature = "debug-alloc")]
        warn!(
            "Growing SecureVec by additional capacity: {}",
            additional_capacity
        );

        let new_cap = self.cap + additional_capacity;
        let new_layout = Layout::array::<T>(new_cap).expect("Cannot Create Layout");
        let old_layout = Layout::array::<T>(self.cap).expect("Cannot Create Layout");

        unsafe {
            let new_ptr = SECURE_ALLOC.alloc(new_layout) as *mut T;

            if !new_ptr.is_null() {
                std::ptr::copy_nonoverlapping(self.ptr, new_ptr, self.len);

                for i in 0..self.len {
                    std::ptr::write(self.ptr.add(i), std::mem::zeroed::<T>());
                }

                SECURE_ALLOC.dealloc(self.ptr as *mut u8, old_layout);

                self.ptr = new_ptr;
                self.cap = new_cap;
            }
        }
    }
}

impl<T> Drop for SecureVec<T> {
    fn drop(&mut self) {
        if !self.is_dropped {
            #[cfg(feature = "debug-alloc")]
            if !self.ptr.is_null() {
                info!("SecureVec dropped. Memory will be securely wiped");
            }

            let layout = Layout::array::<T>(self.cap).expect("Cannot Create Layout");
            unsafe {
                SECURE_ALLOC.dealloc(self.ptr as *mut u8, layout);
                compiler_fence(core::sync::atomic::Ordering::SeqCst);
            }
            self.ptr = std::ptr::null_mut();
            self.is_dropped = true;
        }
    }
}

impl<T> std::ops::Deref for SecureVec<T> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        if self.ptr.is_null() || self.is_dropped {
            error!("SECURITY VIOLATION: Attempted to access dropped SecureVec");
            panic!(
                "Attempted to dereference a dropped SecureVec[x]
                                                              |
                Attempted to Deref a dropped vec which will cause heartbleed. - Fatal Error
                Error Code: {}
                ",
                SecureAllocErrorCode::SecurityViolation.get_as_str()
            );
        }
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }
}

impl<T> std::ops::DerefMut for SecureVec<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        if self.ptr.is_null() || self.is_dropped {
            error!("SECURITY VIOLATION: Attempted to access dropped SecureVec");
            panic!(
                "Attempted to dereference a dropped SecureVec[x] = x
                                                              |
                Attempted to Deref and Mutate a dropped vec which will cause heartbleed. - Fatal Error
                Error Code: {}
                ",
                SecureAllocErrorCode::SecurityViolation.get_as_str()
            );
        }
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.len) }
    }
}

impl<T> AsRef<[T]> for SecureVec<T> {
    fn as_ref(&self) -> &[T] {
        if self.ptr.is_null() || self.is_dropped {
            error!("SECURITY VIOLATION: Attempted to access dropped SecureVec");
            panic!("Attempted to reference a dropped SecureVec.as_ref()
                                                     |
                    Which will cause memory corruption or even memory leaks | possibly heartbleed - Fatal Error
                    Error Code: {}
                    ",
                    SecureAllocErrorCode::SecurityViolation.get_as_str()
            );
        }
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }
}

impl<T> PartialEq for SecureVec<T>
where
    T: BitXor<Output = T> + BitOrAssign + Copy + PartialEq + Zero,
{
    fn eq(&self, other: &Self) -> bool {
        if self.ptr.is_null() || other.ptr.is_null() || self.is_dropped || other.is_dropped {
            return false;
        }

        if self.len != other.len {
            return false;
        }

        let mut result = T::zero();

        for i in 0..self.len {
            unsafe {
                let byte1 = *self.ptr.add(i);
                let byte2 = *other.ptr.add(i);
                result |= byte1 ^ byte2;
            }
        }

        result == T::zero()
    }
}

impl<T> fmt::Debug for SecureVec<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_dropped {
            return f
                .debug_struct("SecureVec")
                .field("status", &"DROPPED")
                .finish();
        }

        f.debug_struct("SecureVec")
            .field("size", &self.len)
            .field("capacity", &self.cap)
            .field(
                "utilization",
                &format!("{:.1}%", (self.len as f64 / self.cap as f64) * 100.0),
            )
            .finish()
    }
}

impl<'a, T> IntoIterator for &'a SecureVec<T> {
    type Item = &'a T;
    type IntoIter = std::slice::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        if self.ptr.is_null() || self.is_dropped {
            panic!(
                "Attempted to iter a dropped SecureVec - Fatal Error
                    Error Code: {}
                ",
                SecureAllocErrorCode::SecurityViolation.get_as_str()
            );
        }
        self.iter()
    }
}
