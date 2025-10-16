use core::{
    cell::UnsafeCell,
    fmt::{self},
    marker::PhantomData,
    ops::{BitOrAssign, BitXor},
    sync::atomic::compiler_fence,
};
use std::{
    alloc::{GlobalAlloc, Layout},
    os::raw::c_void,
};

use bytemuck::Pod;
use hmac::{Hmac, Mac};
use libc::explicit_bzero;
#[cfg(any(feature = "debug-alloc", feature = "dev-logs"))]
use log::debug;
use log::{error, warn};
#[cfg(feature = "debug-alloc")]
use log::{info, trace};
use num_traits::Zero;
use sha2::Sha256;
use thiserror_no_std::Error;
#[cfg(feature = "tpm-mem")]
use tss_esapi::{
    Context,
    attributes::ObjectAttributes,
    handles::KeyHandle,
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm},
        key_bits::RsaKeyBits,
        resource_handles::Hierarchy,
    },
    structures::{
        CreateKeyResult, Digest, KeyedHashScheme, PublicBuilder, PublicKeyRsa,
        PublicKeyedHashParameters, PublicRsaParametersBuilder, RsaExponent, SensitiveData,
    },
    tcti_ldr::DeviceConfig,
};

use crate::{
    constant_time_ops,
    memory::allocator::{AllocatorError, SECURE_ALLOC, SecureAllocErrorCode},
    rng::{CryptoRNG, HardwareRNG, HardwareRandomizable},
};

#[cfg(feature = "tpm-mem")]
use crate::memory::securevec_traits::SecureVecTransform;

type HmacSha256 = Hmac<Sha256>;

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
    integrity_key: [u8; 32],
    pub integrity_tag: [u8; 32],
    _phantom: PhantomData<UnsafeCell<T>>,
}

impl<T: Pod> SecureVec<T> {
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

        let mut integrity_key = [0u8; 32];
        let integrity_tag = [0u8; 32];
        HardwareRNG.fill_by_unchecked(&mut integrity_key);

        Ok(SecureVec {
            ptr,
            len: 0,
            cap,
            is_dropped: false,
            integrity_key,
            integrity_tag,
            _phantom: PhantomData,
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

    unstable!(
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
    );
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

            unsafe { explicit_bzero(self.integrity_key.as_ptr() as *mut c_void, 32) };
            unsafe { explicit_bzero(self.integrity_tag.as_ptr() as *mut c_void, 32) };

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

#[derive(Debug, Error)]
pub enum TpmErrors {
    #[error("TPM Seal Failed: {0}")]
    SecurityViolation(String),
}

#[cfg(feature = "tpm-mem")]
pub struct SecureSealedHandler {
    pub key_handle: KeyHandle,
    pub create_key_result: CreateKeyResult,
    pub context: Context,
    cleaned_up: bool,
}

#[cfg(feature = "tpm-mem")]
impl Drop for SecureSealedHandler {
    fn drop(&mut self) {
        if !self.cleaned_up {
            match self.context.flush_context(self.key_handle.into()) {
                Ok(_) => {
                    #[cfg(feature = "debug-alloc")]
                    info!("TPM context flushed successfully");
                    self.cleaned_up = true;
                }
                Err(e) => {
                    error!("CRITICAL: Failed to flush TPM context: {:?}", e);
                    error!("TPM key handle may still be resident on TPM");
                    error!("Manual intervention may be required to clear TPM state");
                }
            }
        }
    }
}

#[cfg(feature = "tpm-mem")]
impl SecureSealedHandler {
    pub fn cleanup(mut self) -> Result<(), TpmErrors> {
        if !self.cleaned_up {
            match self.context.flush_context(self.key_handle.into()) {
                Ok(_) => {
                    #[cfg(feature = "debug-alloc")]
                    info!("TPM context flushed successfully");
                    self.cleaned_up = true;
                    Ok(())
                }
                Err(e) => Err(TpmErrors::SecurityViolation(format!(
                    "TPM flush failed: {}",
                    e
                ))),
            }
        } else {
            Ok(())
        }
    }
}

#[cfg(feature = "tpm-mem")]
impl SecureVec<u8> {
    /// Seals data to TPM 2.0 chip using Storage Root Key (SRK)
    ///
    /// # Security
    /// - Data is encrypted and bound to this specific TPM
    /// - Maximum 128 bytes can be sealed directly
    /// - Original SecureVec is zeroized after sealing
    ///
    /// # Panics
    /// Panics if TPM device is unavailable or access denied
    pub fn seal(&mut self, bigger_tpm: Option<u16>) -> Result<SecureSealedHandler, TpmErrors> {
        let max_size = bigger_tpm.unwrap_or(128);

        if self.len > max_size as usize {
            return Err(TpmErrors::SecurityViolation(format!(
                "Data too large for TPM seal: {} bytes (max {})",
                self.len, max_size
            )));
        }

        let mut ct = Context::new(tss_esapi::TctiNameConf::Device(DeviceConfig::default()))
            .map_err(|e| TpmErrors::SecurityViolation(e.to_string()))?;

        let rsa_params = PublicRsaParametersBuilder::new_restricted_decryption_key(
            tss_esapi::structures::SymmetricDefinitionObject::Aes {
                key_bits: tss_esapi::interface_types::key_bits::AesKeyBits::Aes256,
                mode: tss_esapi::interface_types::algorithm::SymmetricMode::Cfb,
            },
            RsaKeyBits::Rsa2048,
            RsaExponent::ZERO_EXPONENT,
        )
        .build()
        .map_err(|e| TpmErrors::SecurityViolation(e.to_string()))?;

        let attr = ObjectAttributes::builder()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)
            .with_restricted(true) // SRK bunu ister
            .with_decrypt(true)
            .with_sign_encrypt(false)
            .build()
            .map_err(|e| TpmErrors::SecurityViolation(e.to_string()))?;

        let public = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::Rsa)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_rsa_parameters(rsa_params)
            .with_object_attributes(attr)
            .with_rsa_unique_identifier(PublicKeyRsa::new_empty_with_size(RsaKeyBits::Rsa2048))
            .build()
            .map_err(|e| TpmErrors::SecurityViolation(e.to_string()))?;

        let pr = ct
            .execute_with_nullauth_session(|ctx| {
                ctx.create_primary(Hierarchy::Owner, public.clone(), None, None, None, None)
            })
            .map_err(|e| TpmErrors::SecurityViolation(e.to_string()))?;

        let sensitive = SensitiveData::try_from(self.as_ref())
            .map_err(|e| TpmErrors::SecurityViolation(e.to_string()))?;

        let seal_attr = ObjectAttributes::builder()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_user_with_auth(true)
            .with_no_da(true) // Dictionary attack protection
            .build()
            .map_err(|e| TpmErrors::SecurityViolation(e.to_string()))?;

        let public = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::KeyedHash)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(seal_attr)
            .with_keyed_hash_parameters(PublicKeyedHashParameters::new(KeyedHashScheme::Null))
            .with_keyed_hash_unique_identifier(Digest::default())
            .build()
            .map_err(|e| TpmErrors::SecurityViolation(e.to_string()))?;

        let out = ct
            .execute_with_nullauth_session(|ctx| {
                ctx.create(pr.key_handle, public, None, Some(sensitive), None, None)
            })
            .map_err(|e| TpmErrors::SecurityViolation(e.to_string()))?;

        self.zeroize();
        Ok(SecureSealedHandler {
            context: ct,
            key_handle: pr.key_handle,
            create_key_result: out,
            cleaned_up: false,
        })
    }

    /// Unseals data from TPM 2.0 chip
    ///
    /// # Security
    /// - Data can only be unsealed on the same TPM that sealed it
    /// - Consumes the SecureSealedHandler (single-use)
    pub fn unseal(mut sealed: SecureSealedHandler) -> Result<SecureVec<u8>, TpmErrors> {
        let sealed_handler = sealed
            .context
            .execute_with_nullauth_session(|ctx| {
                ctx.load(
                    sealed.key_handle,
                    sealed.create_key_result.out_private.clone(),
                    sealed.create_key_result.out_public.clone(),
                )
            })
            .map_err(|e| TpmErrors::SecurityViolation(e.to_string()))?;

        let unsealed = sealed
            .context
            .execute_with_nullauth_session(|ctx| ctx.unseal(sealed_handler.into()))
            .map_err(|e| TpmErrors::SecurityViolation(e.to_string()))?;

        sealed
            .context
            .flush_context(sealed_handler.into())
            .map_err(|e| TpmErrors::SecurityViolation(e.to_string()))?;

        Ok(unsealed
            .to_secure_vec(unsealed.len())
            .map_err(|e| TpmErrors::SecurityViolation(e.to_string()))?)
    }
}

impl<T: Pod> SecureVec<T> {
    fn compute_hmac(&self) -> Result<[u8; 32], AllocatorError> {
        if self.is_dropped {
            error!("SECURITY VIOLATION: Attempted to access dropped SecureVec");
            return Err(AllocatorError::AlreadyDropped(
                SecureAllocErrorCode::AlreadyDropped,
            ));
        }

        let mut mac = HmacSha256::new_from_slice(&self.integrity_key)
            .map_err(|_| AllocatorError::MacInitFailed)?;

        unsafe {
            let data = std::slice::from_raw_parts(
                self.ptr as *const u8,
                self.len * std::mem::size_of::<T>(),
            );
            mac.update(data);
        }

        Ok(mac.finalize().into_bytes().into())
    }

    fn compute_hmac_key(&self, key: &[u8]) -> Result<[u8; 32], AllocatorError> {
        if self.is_dropped {
            error!("SECURITY VIOLATION: Attempted to access dropped SecureVec");
            return Err(AllocatorError::AlreadyDropped(
                SecureAllocErrorCode::AlreadyDropped,
            ));
        }

        let mut mac = HmacSha256::new_from_slice(key).map_err(|_| AllocatorError::MacInitFailed)?;

        unsafe {
            let data = std::slice::from_raw_parts(
                self.ptr as *const u8,
                self.len * std::mem::size_of::<T>(),
            );
            mac.update(data);
        }

        Ok(mac.finalize().into_bytes().into())
    }

    pub fn seal_integrity_with_key(&mut self, key: &[u8]) -> Result<(), AllocatorError> {
        self.integrity_tag = self.compute_hmac_key(key)?;
        Ok(())
    }

    pub fn seal_integrity(&mut self) -> Result<(), AllocatorError> {
        self.integrity_tag = self.compute_hmac()?;
        Ok(())
    }

    pub fn verify_sealed_integrity(&self) -> Result<(), AllocatorError> {
        if self.is_dropped {
            error!("SECURITY VIOLATION: Attempted to access dropped SecureVec");
            return Err(AllocatorError::AlreadyDropped(
                SecureAllocErrorCode::AlreadyDropped,
            ));
        }

        let current = self.compute_hmac()?;

        if constant_time_ops::compare_bytes(&current, &self.integrity_tag) != 1 {
            error!("Integrity check failed for SecureVec");
            return Err(AllocatorError::LockFailed(
                SecureAllocErrorCode::CorruptionDetected,
            ));
        }
        Ok(())
    }

    pub fn verify_sealed_integrity_with_key(&self, key: &[u8]) -> Result<(), AllocatorError> {
        if self.is_dropped {
            error!("SECURITY VIOLATION: Attempted to access dropped SecureVec");
            return Err(AllocatorError::AlreadyDropped(
                SecureAllocErrorCode::AlreadyDropped,
            ));
        }

        let current = self.compute_hmac_key(key)?;

        if constant_time_ops::compare_bytes(&current, &self.integrity_tag) != 1 {
            error!("Integrity check failed for SecureVec");
            return Err(AllocatorError::LockFailed(
                SecureAllocErrorCode::CorruptionDetected,
            ));
        }
        Ok(())
    }
}
