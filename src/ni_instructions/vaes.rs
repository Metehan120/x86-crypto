use core::{
    arch::{
        asm,
        x86_64::{
            __m128i, __m256i, _mm_aesimc_si128, _mm256_aesdec_epi128, _mm256_aesdeclast_epi128,
            _mm256_aesenc_epi128, _mm256_aesenclast_epi128, _mm256_loadu_si256,
            _mm256_storeu_si256,
        },
    },
    ops::Deref,
};

#[cfg(feature = "dev-logs")]
use log::warn;

use crate::types;

types! {
    #[derive(Debug, Clone, Copy)]
    /// A type-safe wrapper for an array of 15 `__vaes256key`s, representing the
    /// complete expanded key schedule for an AES-256 cipher.
    ///
    /// Implements `Deref` to allow ergonomic access to the inner array.
    type __vaes256keys: 15 x __vaes256key;
    impl deref __vaes256keys, [__vaes256key; 15]

    #[derive(Debug, Clone, Copy)]
    /// A type-safe wrapper for an array of 23 `__vaes256key`s, representing the
    /// complete expanded key schedule for an AES-256 cipher.
    ///
    /// # THIS TYPE IS FOR FUTURE-PROOFING
    ///
    /// Implements `Deref` to allow ergonomic access to the inner array.
    type __vaes512keys: 23 x __vaes256key;
    impl deref __vaes512keys, [__vaes256key; 23]
}

types! {
    #[derive(Debug, Clone, Copy)]
    /// A type-safe wrapper for a `__m256i` value, representing a 256-bit data block
    /// for an AES operation.
    type __vaes256i: __m256i;
    impl deref __vaes256i, __m256i

    #[derive(Debug, Clone, Copy)]
    /// A type-safe wrapper for a `__m256i` value, representing a 256-bit round key
    /// for a single AES round.
    type __vaes256key: __m256i;
    impl deref __vaes256key, __m256i
}

impl __vaes256i {
    pub fn as_mm256i(&self) -> __m256i {
        self.0
    }
}

#[inline(always)]
pub fn loadu_vaes256keys(keys: [__vaes256key; 15]) -> __vaes256keys {
    #[cfg(feature = "dev-logs")]
    warn!("VAES-256 keys loaded (experimental)");
    __vaes256keys(keys)
}

#[inline(always)]
pub fn loadu_vaes512keys(keys: [__vaes256key; 23]) -> __vaes512keys {
    #[cfg(feature = "dev-logs")]
    warn!("VAES-512 keys loaded (experimental)");
    __vaes512keys(keys)
}

#[inline(always)]
/// Loads 32 bytes from a raw pointer into a `__vaes256i` block.
///
/// This performs an unaligned load.
///
/// # Safety
/// The caller must ensure that `data` points to at least 32 bytes of
/// valid, readable memory.
#[allow(unsafe_op_in_unsafe_fn)]
pub unsafe fn loadu_vaes(data: *const u8) -> __vaes256i {
    #[cfg(feature = "dev-logs")]
    warn!("VAES Data loaded, VAES is experimental use carefully");
    __vaes256i(_mm256_loadu_si256(data as *const __m256i))
}

#[inline(always)]
/// Loads 32 bytes from a `__m256i` into a `__vaes256i` block.
///
/// # Safety
/// The caller must ensure that `data` points to at least 32 bytes of
/// valid, readable memory.
pub fn loadu_vaes256_mm256i(data: __m256i) -> __vaes256i {
    #[cfg(feature = "dev-logs")]
    warn!("VAES Data loaded, VAES is experimental use carefully");
    __vaes256i(data)
}

#[inline(always)]
/// Loads 32 bytes from a raw pointer into a `__vaes256key` block.
///
/// This performs an unaligned load.
///
/// # Safety
/// The caller must ensure that `key` points to at least 32 bytes of
/// valid, readable memory.
#[allow(unsafe_op_in_unsafe_fn)]
pub unsafe fn loadu_vaeskey(key: *const u8) -> __vaes256key {
    #[cfg(feature = "dev-logs")]
    warn!("VAES Keys loaded, VAES is experimental use carefully");
    __vaes256key(_mm256_loadu_si256(key as *const __m256i))
}

#[inline(always)]
/// Loads 32 bytes from a `__m256i` into a `__vaes256key` block.
///
/// # Safety
/// The caller must ensure that `key` points to at least 32 bytes of
/// valid, readable memory.
pub fn loadu_vaeskey_m256i(key: __m256i) -> __vaes256key {
    #[cfg(feature = "dev-logs")]
    warn!("VAES Keys loaded, VAES is experimental use carefully");
    __vaes256key(key)
}

#[inline(always)]
/// Stores 32 bytes from a `__vaes256i` block to a raw pointer.
///
/// This performs an unaligned store.
///
/// # Safety
/// The caller must ensure that `output` points to at least 32 bytes of
/// valid, writable memory.
#[allow(unsafe_op_in_unsafe_fn)]
pub unsafe fn storeu_vaes(output: *mut u8, data: __vaes256i) {
    _mm256_storeu_si256(output as *mut __m256i, data.0)
}

#[inline(always)]
/// Stores 32 bytes from a `__vaes256key` block to a raw pointer.
///
/// This performs an unaligned store.
///
/// # Safety
/// The caller must ensure that `output` points to at least 32 bytes of
/// valid, writable memory.
#[allow(unsafe_op_in_unsafe_fn)]
pub unsafe fn storeu_vaeskey(output: *mut u8, data: __vaes256key) {
    _mm256_storeu_si256(output as *mut __m256i, data.0)
}

#[inline(always)]
#[allow(unsafe_op_in_unsafe_fn)]
pub fn make_dec_keys_128(rk_enc: &[__m128i; 15]) -> [__m128i; 15] {
    unsafe {
        let mut dec: [__m128i; 15] = core::mem::zeroed();
        dec[0] = rk_enc[14];
        for i in 1..14 {
            dec[i] = _mm_aesimc_si128(rk_enc[14 - i]);
        }
        dec[14] = rk_enc[0];
        dec
    }
}

/// Performs one intermediate round of AES encryption using the `vaesenc` instruction.
///
/// # Panics
/// Panics if the host CPU does not support the `vaes` instruction set.
#[target_feature(enable = "vaes,avx")]
pub unsafe fn vaesenc_asm(data: __vaes256i, round_key: __vaes256key) -> __vaes256i {
    let mut result = data.0;
    unsafe {
        asm!(
            "vaesenc {0}, {0}, {1}",
            inout(ymm_reg) result,
            in(ymm_reg) round_key.0,
            options(nostack, nomem, preserves_flags)
        );
    }
    __vaes256i(result)
}

/// Performs one intermediate round of AES decryption using the `vaesdec` instruction.
///
/// # Panics
/// Panics if the host CPU does not support the `vaes` instruction set.
#[target_feature(enable = "vaes,avx")]
pub unsafe fn vaesdec_asm(data: __vaes256i, round_key: __vaes256key) -> __vaes256i {
    let mut result = data.0;

    unsafe {
        asm!(
            "vaesdec {0}, {0}, {1}",
            inout(ymm_reg) result,
            in(ymm_reg) round_key.0,
            options(nostack, nomem, preserves_flags)
        );
    }
    __vaes256i(result)
}

/// Performs the final round of AES encryption using the `vaesenclast` instruction.
///
/// # Panics
/// Panics if the host CPU does not support the `vaes` instruction set.
#[target_feature(enable = "vaes,avx")]
pub unsafe fn vaesenc_last_asm(data: __vaes256i, round_key: __vaes256key) -> __vaes256i {
    let mut result = data.0;
    unsafe {
        asm!(
            "vaesenclast {0}, {0}, {1}",
            inout(ymm_reg) result,
            in(ymm_reg) round_key.0,
            options(nostack, nomem, preserves_flags)
        );
    }
    __vaes256i(result)
}

/// Performs the final round of AES decryption using the `vaesdeclast` instruction.
///
/// # Panics
/// Panics if the host CPU does not support the `vaes` instruction set.
#[target_feature(enable = "vaes,avx")]
pub unsafe fn vaesdec_last_asm(data: __vaes256i, round_key: __vaes256key) -> __vaes256i {
    let mut result = data.0;
    unsafe {
        asm!(
            "vaesdeclast {0}, {0}, {1}",
            inout(ymm_reg) result,
            in(ymm_reg) round_key.0,
            options(nostack, nomem, preserves_flags)
        );
    }
    __vaes256i(result)
}

#[target_feature(enable = "vaes,avx")]
pub fn vaesenc_intrinsic(data: __vaes256i, round_key: __vaes256key) -> __vaes256i {
    __vaes256i(_mm256_aesenc_epi128(data.0, round_key.0))
}

#[target_feature(enable = "vaes,avx")]
pub fn vaesdec_intrinsic(data: __vaes256i, round_key: __vaes256key) -> __vaes256i {
    __vaes256i(_mm256_aesdec_epi128(data.0, round_key.0))
}

#[target_feature(enable = "vaes,avx")]
pub fn vaesenc_last_intrinsic(data: __vaes256i, round_key: __vaes256key) -> __vaes256i {
    __vaes256i(_mm256_aesenclast_epi128(data.0, round_key.0))
}

#[target_feature(enable = "vaes,avx")]
pub fn vaesdec_last_intrinsic(data: __vaes256i, round_key: __vaes256key) -> __vaes256i {
    __vaes256i(_mm256_aesdeclast_epi128(data.0, round_key.0))
}
