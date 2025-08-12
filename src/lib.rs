#![cfg_attr(not(feature = "std"), no_std)]
#![deny(clippy::unwrap_used)]
#![allow(non_camel_case_types)]

use core::arch::x86_64::{__rdtscp, _rdrand16_step, _rdrand32_step, _rdrand64_step};
use core::ops::{Deref, DerefMut};
use core::{
    arch::x86_64::{_rdseed16_step, _rdseed32_step, _rdseed64_step},
    fmt::Display,
    ops::{Add, Bound, RangeBounds, Rem, Sub},
};

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
compile_error!("This library is only developed for the x86 and x86_64 architectures.");

use num_traits::{One, Unsigned};
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, RngCore};
use thiserror_no_std::Error;

use crate::allocator::{AllocatorError, SecureVec};

#[cfg(target_os = "linux")]
#[cfg(feature = "std")]
#[cfg(feature = "secure_memory")]
/// Secure memory allocator for Linux systems that prevents sensitive data from being swapped to disk.
///
/// This module provides `SecureVec<T>`, a specialized container that uses `mlock()` to pin memory
/// and automatically zeros content on drop. Ideal for storing cryptographic keys, passwords, and
/// other sensitive data that should never touch the disk.
///
/// # Features
/// - Memory locking with `mlock2()`/`mlock()` fallback
/// - Automatic zeroization on drop
/// - Cache-aligned (64-byte) allocation
/// - Fixed capacity to prevent reallocation
/// - Constant time comparison
/// - Highly secure Error Handling
///
/// # Example
/// ```rust
/// let mut secure_data = SecureVec::with_capacity(32)?;
/// secure_data.extend_from_slice(&encryption_key)?;
/// // Memory automatically secured and cleaned up
/// ```
pub mod allocator;

/// Low-level cache manipulation operations for timing analysis and performance optimization.
///
/// Provides tools for prefetch, and timing measurements using CPU cycle counters.
/// Useful for side-channel analysis, performance profiling, and cache-aware algorithms.
///
/// # Components
/// - `Prefetcher<T>`: Intelligent cache preloading
pub mod cache_operations;

/// Hardware-seeded ChaCha20 random number generator with cryptographic security guarantees.
///
/// Combines hardware entropy (RDRAND/RDSEED) with ChaCha20 algorithm to provide
/// fast, secure random numbers. Compatible with the `rand` crate ecosystem.
///
/// # Features
/// - Hardware entropy seeding
/// - Cryptographically secure output
/// - Range generation with uniform distribution
/// - Thread-safe implementation
///
/// # Example
/// ```rust
/// let mut rng = HWChaCha20Rng::new()?;
/// let random_key: [u8; 32] = rng.generate_unchecked();
/// let dice_roll = rng.try_generate_range(1..=6)?;
/// ```
pub mod hw_chacha;

/// Safe wrappers for Intel specialized cryptographic instructions (AES-NI, SHA-NI, PCLMULQDQ).
///
/// Provides ergonomic interfaces to hardware-accelerated cryptographic operations using
/// SSE/AVX registers. Each instruction set has its own submodule with trait-based APIs
/// for better type safety and code organization.
///
/// # Submodules
/// - `aesni`: AES encryption/decryption rounds and key generation
/// - `shani`: SHA-256 hash computation rounds
/// - `pclmul`: Carry-less multiplication for GCM and polynomial arithmetic
///
/// # Core Traits
/// - `LoadRegister`: Load data into SSE registers
/// - `StoreRegister`: Store register data back to memory
///
/// # Example
/// ```rust
/// use ni_instructions::aesni::{AesNI, AES};
///
/// let key_reg = key_slice.load();
/// let data_reg = data_slice.load();
/// let encrypted = AesNI.aes_round(key_reg, data_reg);
/// let result: [u8; 16] = encrypted.store();
/// ```
pub mod ni_instructions;

/// SIMD-accelerated operations using AVX2 for high-performance parallel computing.
///
/// Provides vectorized implementations of common operations (XOR, AND, OR, arithmetic)
/// that process multiple values simultaneously. Includes both low-level accelerators
/// and high-level wrapper types.
///
/// # Components
/// - `BasicBitAVX2Accelerator`: Bitwise operations (XOR, AND, OR)
/// - `BasicMathAVX2Accelerator`: Arithmetic operations (add, sub, mul)
/// - `SimdU8/U16/U32/U64`: Type-safe SIMD arrays
/// - `simd_operation!` macro for DSL-style usage
///
/// # Example
/// ```rust
/// let plaintext = SimdU8::load([0x42; 1000]);
/// let key = SimdU8::load([0xAA; 1000]);
/// let encrypted = plaintext ^ key;  // Vectorized XOR
/// ```
pub mod simd;

#[cfg(all(feature = "aes_cipher", feature = "std"))]
pub mod ciphers {
    /// Hardware-accelerated AES (Advanced Encryption Standard) implementations.
    ///
    /// # Security Notice
    /// Uses hardware-accelerated cryptographic primitives and established libraries.
    /// While implementation follows standard practices, independent security
    /// review is recommended for high-stakes applications.
    ///
    /// Provides AES-256 encryption in multiple modes using Intel AES-NI instructions
    /// for maximum performance and security. All implementations use hardware acceleration.
    ///
    /// # Available Modes
    /// - **`Aes256CTR`**: Counter mode for stream encryption
    /// - **`Aes256`**: GCM mode with authentication (recommended default)
    ///
    /// # Performance
    /// - Intel AES-NI hardware acceleration
    /// - Parallel processing with multi-core support
    /// - Typical throughput: 1-8 GB/s depending on mode and CPU
    ///
    /// # Quick Start
    /// ```rust
    /// use x86_crypto::{Aes256, HardwareRNG, CryptoRNG};
    ///
    /// let mut rng = HardwareRNG;
    /// let key: [u8; 32] = rng.try_generate()?;
    /// let nonce: [u8; 12] = rng.try_generate()?;
    ///
    /// let aes = Aes256::new(key);
    /// let encrypted = aes.encrypt(&plaintext, nonce);
    /// let decrypted = aes.decrypt(&encrypted, nonce)?;
    /// ```
    ///
    /// # Mode Selection Guide
    /// - **Production**: Use `Aes256` (GCM mode with authentication)
    /// - **Stream encryption**: Use `Aes256CTR` when you need raw speed
    pub mod aes_cipher;

    /// THIS FEATURE IS EXPERIMENTAL, DO NOT USE IN PRODUCTION, USE IT AT YOUR OWN RISK
    pub mod vaes_cipher;
}

/// Additional x86 specialized instructions beyond the main cryptographic instruction sets.
///
/// Contains hardware-accelerated operations for checksums, bit manipulation, and other
/// performance-critical computations that complement the core crypto instructions.
///
/// # Modules
/// - `CRC32`: Hardware checksum computation
/// - `BMI1/BMI2`: Advanced bit manipulation instructions
pub mod other_instructions;

#[cfg(any(feature = "tls", doc))]
/// TLS message encryption/decryption handler (only enabled with `tls` feature).
///
/// This module provides integration with the TLS record layer, enabling
/// secure communication using AES-GCM via hardware acceleration.
///
/// # THIS FEATURE IS EXPERIMENTAL, DO NOT USE IN PRODUCTION, USE IT AT YOUR OWN RISK
///
/// # Features
/// - Compatible with `rustls` record layer
/// - Implements `MessageEncrypter` and `MessageDecrypter` traits
/// - Uses AES-GCM with hardware-accelerated AES-NI instructions
/// - Constant-time operations and zeroization of sensitive data
///
/// # Usage
/// Enable the `tls` feature in `Cargo.toml`:
/// ```toml
/// [dependencies]
/// x86-crypto = { version = "...", features = ["tls"] }
/// ```
///
/// Then import and use the handler:
/// ```rust
/// use x86_crypto::tls_handler::AesGcmMessageHandler;
/// ```
///
/// # Note
/// This module is **not** included by default.
/// It is only compiled if the `tls` feature is enabled or docs are being built.
pub mod tls_handler;

pub const AES_BLOCK_SIZE: usize = 16;
pub const SHA256_NI_BLOCK_SIZE: usize = 16;
pub const SHA256_HASH_SIZE: usize = 32;

/// High-precision CPU cycle timing utilities using RDTSCP instruction for performance measurement.
///
/// Provides sub-nanosecond timing resolution by directly reading the Time Stamp Counter (TSC)
/// with serialization guarantees. Essential for microbenchmarking, side-channel analysis,
/// and performance-critical code profiling.
///
/// # Core Components
/// - `CycleTimer`: Precise timing measurements with cycle-level accuracy
/// - Benchmark utilities for function execution timing
/// - Constant-time comparison operations
///
/// # Features
/// - CPU cycle-level precision (typically ~0.3ns resolution)
/// - Serialized execution with RDTSCP for accurate measurements
/// - Built-in benchmarking functionality
/// - Side-channel resistant timing comparisons
///
/// # Example
/// ```rust
/// // Measure execution time
/// let mut timer = CycleTimer::new();
/// expensive_operation();
/// let cycles = timer.elapsed();
///
/// // Benchmark a function
/// let (result, cycles) = CycleTimer::benchmark(|| {
///     compute_hash(&data)
/// });
///
/// // Get current timestamp
/// let timestamp = CycleTimer::now();
/// ```
///
/// # Note
/// Results are in CPU cycles, not wall-clock time. Convert using CPU frequency
/// for time measurements. Best used for relative performance comparisons.
pub struct CycleTimer {
    start: u64,
    aux: u32,
}

impl Default for CycleTimer {
    fn default() -> Self {
        Self::new()
    }
}

impl CycleTimer {
    #[inline(always)]
    pub fn new() -> Self {
        let mut aux = 0;
        let start = unsafe { __rdtscp(&mut aux) };

        Self { start, aux }
    }

    #[inline(always)]
    pub fn elapsed(&mut self) -> u64 {
        let end = unsafe { __rdtscp(&mut self.aux) };
        end - self.start
    }

    #[inline(always)]
    pub fn now() -> u64 {
        let mut aux = 0;
        unsafe { __rdtscp(&mut aux) }
    }

    pub fn benchmark<F, R>(f: F) -> (R, u64)
    where
        F: FnOnce() -> R,
    {
        let mut timer = Self::new();
        let result = f();
        let elapsed = timer.elapsed();
        (result, elapsed)
    }
}

impl PartialEq for CycleTimer {
    fn eq(&self, other: &Self) -> bool {
        let diff = self.start ^ other.start;
        diff == 0
    }
}

#[derive(Debug, Error)]
pub enum RngErrors {
    #[error("Failed to generate random byte/bytes")]
    FailedToGenerate,
    #[error("Failed to generate NON-BIAS range")]
    FailedBias,
}

/// Hardware-based random number generator using x86 CPU instructions.
///
/// `HardwareRNG` provides direct access to Intel/AMD hardware entropy sources
/// through RDRAND and RDSEED instructions, offering high-quality randomness
/// with minimal overhead.
///
/// # Security
/// - Uses CPU's hardware entropy pool
/// - Suitable for cryptographic applications
/// - No software-based predictable patterns
///
/// # Performance
/// - Zero-copy hardware instruction calls
/// - Limited by hardware entropy pool refill rate
///
/// # Usage Guidelines
/// - **< 60MB data**: Use `try_*` methods for safety
/// - **> 60MB data**: Use `*_unchecked` methods to avoid pool depletion
///
/// # Example
/// ```rust
/// use x86_crypto::{HardwareRNG, CryptoRNG};
///
/// let generator = HardwareRNG;
/// let random_key: [u8; 32] = generator.try_generate()?;
/// let fast_data: u64 = generator.generate_unchecked();
/// ```
#[derive(Debug, Clone, Copy)]
pub struct HardwareRNG;

unsafe impl Send for HardwareRNG {}
impl CryptoRng for HardwareRNG {}

/// Direct access to hardware entropy using RDSEED instruction.
///
/// Provides the lowest-level interface to CPU entropy sources for maximum
/// security and control. RDSEED offers higher entropy quality than RDRAND
/// but with slower generation rates.
pub trait RawGenerator {
    #[must_use = "Check the error; RNG may fail on unsupported HW."]
    fn try_generate_raw<T>(&self) -> Result<T, RngErrors>
    where
        T: HardwareRandomizable;

    #[must_use = "Check the error; RNG may fail on unsupported HW."]
    fn generate_raw_unchecked<T>(&self) -> T
    where
        T: HardwareRandomizable;

    fn try_fill_raw_by<T>(&self, buffer: &mut [T]) -> Result<(), RngErrors>
    where
        T: HardwareRandomizable,
    {
        for byte in buffer.iter_mut() {
            *byte = self.try_generate_raw::<T>()?;
        }
        Ok(())
    }

    fn fill_raw_by_unchecked<T>(&self, buffer: &mut [T])
    where
        T: HardwareRandomizable,
    {
        for byte in buffer.iter_mut() {
            *byte = self.generate_raw_unchecked::<T>();
        }
    }
}

/// High-level cryptographic random number generation interface.
///
/// Combines hardware entropy with practical utilities like range generation,
/// entropy validation, and bulk operations. Designed for cryptographic
/// applications requiring both security and usability.
pub trait CryptoRNG {
    #[must_use = "Check the error; RNG may fail on unsupported HW."]
    fn try_generate<T>(&mut self) -> Result<T, RngErrors>
    where
        T: HardwareRandomizable;

    #[must_use = "Check the error; RNG may fail on unsupported HW."]
    fn generate_unchecked<T>(&mut self) -> T
    where
        T: HardwareRandomizable;

    #[inline(always)]
    fn try_generate_bool(&mut self) -> Result<bool, RngErrors> {
        let bool: u8 = self.try_generate()?;
        Ok(bool & 1 == 1)
    }

    #[inline(always)]
    fn generate_bool_unchecked(&mut self) -> bool {
        let bool: u8 = self.generate_unchecked();
        bool & 1 == 1
    }

    fn try_generate_range<T, R>(&mut self, range: R) -> Result<T, RngErrors>
    where
        R: RangeBounds<T>,
        T: HardwareRandomizable
            + Copy
            + Add<Output = T>
            + Sub<Output = T>
            + Rem<Output = T>
            + One
            + Display
            + PartialEq
            + PartialOrd
            + Unsigned;

    fn generate_range_unchecked<T, R>(&mut self, range: R) -> T
    where
        R: RangeBounds<T>,
        T: HardwareRandomizable
            + Copy
            + Add<Output = T>
            + Sub<Output = T>
            + Rem<Output = T>
            + One
            + PartialEq
            + PartialOrd
            + Unsigned;

    fn try_fill_by<T>(&mut self, buffer: &mut [T]) -> Result<(), RngErrors>
    where
        T: HardwareRandomizable,
    {
        for byte in buffer.iter_mut() {
            *byte = self.try_generate::<T>()?;
        }
        Ok(())
    }

    fn fill_by_unchecked<T>(&mut self, buffer: &mut [T])
    where
        T: HardwareRandomizable,
    {
        for byte in buffer.iter_mut() {
            *byte = self.generate_unchecked::<T>();
        }
    }

    fn validate_entropy(&self, buffer: &mut [u8]) -> (bool, f64) {
        let entropy = EntropyAnalyzer.estimate_shanon_entropy(&buffer);

        let normal_entropy = match buffer.len() {
            0..128 => 3.0,
            128..1024 => 6.0,
            1024..262144 => 7.7,
            262144..1048576 => 7.95,
            _ => 7.99,
        };

        (entropy > normal_entropy, entropy)
    }

    #[inline(always)]
    fn shuffle_slice<T>(&mut self, data: &mut [T]) {
        for i in (1..data.len()).rev() {
            let j: usize = self.generate_range_unchecked(0..=i);
            data.swap(i, j);
        }
    }
}

/// Types that can be generated from hardware random number sources.
///
/// Enables type-safe random generation from both RDRAND/RDSEED instructions
/// and ChaCha20 PRNG. Automatically handles bit width conversions and
/// provides min/max value bounds.
pub trait HardwareRandomizable: Sized {
    fn from_hardware_rng() -> Result<Self, RngErrors>;
    fn from_hardware_seed() -> Result<Self, RngErrors>;
    fn from_hardware_rng_unchecked() -> Self;
    fn from_hardware_seed_unchecked() -> Self;
    fn from_chacha(rng: &mut ChaCha20Rng) -> Self;
    fn max_value() -> Self;
    fn min_value() -> Self;
}

macro_rules! impl_generator {
    (u8, $generator:expr, $type:ty) => {
        $generator.next_u32() as $type
    };
    (u16, $generator:expr, $type:ty) => {
        $generator.next_u32() as $type
    };
    (u32, $generator:expr, $type:ty) => {
        $generator.next_u32() as $type
    };
    (u64, $generator:expr, $type:ty) => {
        $generator.next_u64() as $type
    };
    (usize, $generator:expr, $type:ty) => {
        $generator.next_u64() as usize
    };
}

macro_rules! impl_hardware_rng {
    ($type:ty, $rdrand_type:ty, $rdrand:ident, $rdseed:ident, $return_type:ty, $chacha_type:tt) => {
        impl HardwareRandomizable for $type {
            #[inline(always)]
            fn from_hardware_rng() -> Result<Self, RngErrors> {
                let mut val: $rdrand_type = 0;
                let is_ok = unsafe { $rdrand(&mut val) };
                if is_ok == 1 {
                    Ok(val as $return_type)
                } else {
                    for _ in 0..10 {
                        let mut val: $rdrand_type = 0;
                        let is_ok = unsafe { $rdrand(&mut val) };

                        if is_ok == 1 {
                            return Ok(val as $return_type);
                        }
                    }

                    Err(RngErrors::FailedToGenerate)
                }
            }

            #[inline(always)]
            fn from_hardware_seed() -> Result<Self, RngErrors> {
                let mut val: $rdrand_type = 0;
                let is_ok = unsafe { $rdseed(&mut val) };
                if is_ok == 1 {
                    Ok(val as $return_type)
                } else {
                    for _ in 0..10 {
                        let mut val: $rdrand_type = 0;
                        let is_ok = unsafe { $rdseed(&mut val) };

                        if is_ok == 1 {
                            return Ok(val as $return_type);
                        }
                    }

                    Err(RngErrors::FailedToGenerate)
                }
            }

            #[inline(always)]
            fn from_hardware_rng_unchecked() -> Self {
                let mut val: $rdrand_type = 0;
                unsafe { $rdrand(&mut val) };
                val as $return_type
            }

            #[inline(always)]
            fn from_hardware_seed_unchecked() -> Self {
                let mut val: $rdrand_type = 0;
                unsafe { $rdseed(&mut val) };
                val as $return_type
            }

            #[inline(always)]
            fn from_chacha(rng: &mut ChaCha20Rng) -> Self {
                impl_generator!($chacha_type, rng, $type)
            }

            #[inline(always)]
            fn max_value() -> Self {
                <$return_type>::MAX
            }

            #[inline(always)]
            fn min_value() -> Self {
                <$return_type>::MIN
            }
        }
    };
}

impl_hardware_rng!(u8, u16, _rdrand16_step, _rdseed16_step, u8, u8);
impl_hardware_rng!(u16, u16, _rdrand16_step, _rdseed16_step, u16, u16);
impl_hardware_rng!(u32, u32, _rdrand32_step, _rdseed32_step, u32, u32);
impl_hardware_rng!(u64, u64, _rdrand64_step, _rdseed64_step, u64, u64);
impl_hardware_rng!(i8, u16, _rdrand16_step, _rdseed16_step, i8, u8);
impl_hardware_rng!(i16, u16, _rdrand16_step, _rdseed16_step, i16, u16);
impl_hardware_rng!(i32, u32, _rdrand32_step, _rdseed32_step, i32, u32);
impl_hardware_rng!(i64, u64, _rdrand64_step, _rdseed64_step, i64, u64);
impl_hardware_rng!(usize, u64, _rdrand64_step, _rdseed64_step, usize, usize);

impl CryptoRNG for HardwareRNG {
    #[inline(always)]
    fn try_generate<T>(&mut self) -> Result<T, RngErrors>
    where
        T: HardwareRandomizable,
    {
        T::from_hardware_rng()
    }

    #[inline(always)]
    fn generate_unchecked<T>(&mut self) -> T
    where
        T: HardwareRandomizable,
    {
        T::from_hardware_rng_unchecked()
    }

    #[inline(always)]
    fn try_generate_range<T, R>(&mut self, range: R) -> Result<T, RngErrors>
    where
        R: RangeBounds<T>,
        T: HardwareRandomizable
            + Copy
            + Add<Output = T>
            + Sub<Output = T>
            + Rem<Output = T>
            + One
            + Display
            + PartialEq
            + PartialOrd,
    {
        let start = match range.start_bound().as_ref() {
            Bound::Included(&n) => *n,
            Bound::Excluded(&n) => *n + T::one(),
            Bound::Unbounded => T::min_value(),
        };

        let end = match range.end_bound().as_ref() {
            Bound::Included(&n) => *n,
            Bound::Excluded(&n) => *n - T::one(),
            Bound::Unbounded => T::max_value(),
        };

        if start == T::min_value() && end == T::max_value() {
            return T::from_hardware_rng();
        }

        let range_size = end - start + T::one();
        let remainder = T::max_value() % range_size;
        let max_valid = T::max_value() - remainder;

        let mut loop_count = 0;
        loop {
            let raw = T::from_hardware_rng()?;
            loop_count += 1;

            if raw <= max_valid {
                return Ok(start + (raw % range_size));
            }

            if loop_count > 10000 {
                return Err(RngErrors::FailedBias);
            }
        }
    }

    #[inline(always)]
    fn generate_range_unchecked<T, R>(&mut self, range: R) -> T
    where
        R: RangeBounds<T>,
        T: HardwareRandomizable
            + Copy
            + Add<Output = T>
            + Sub<Output = T>
            + Rem<Output = T>
            + One
            + PartialEq
            + PartialOrd,
    {
        let start = match range.start_bound().as_ref() {
            Bound::Included(&n) => *n,
            Bound::Excluded(&n) => *n + T::one(),
            Bound::Unbounded => T::min_value(),
        };

        let end = match range.end_bound().as_ref() {
            Bound::Included(&n) => *n,
            Bound::Excluded(&n) => *n - T::one(),
            Bound::Unbounded => T::max_value(),
        };

        if start == T::min_value() && end == T::max_value() {
            return T::from_hardware_rng_unchecked();
        }

        let range_size = end - start + T::one();
        let remainder = T::max_value() % range_size;
        let max_valid = T::max_value() - remainder;

        let mut loop_count = 0;
        loop {
            let raw = T::from_hardware_rng_unchecked();
            loop_count += 1;

            if raw <= max_valid {
                return start + (raw % range_size);
            }

            if loop_count > 10000 {
                return start + (raw % range_size);
            }
        }
    }
}

impl RawGenerator for HardwareRNG {
    fn try_generate_raw<T>(&self) -> Result<T, RngErrors>
    where
        T: HardwareRandomizable,
    {
        T::from_hardware_seed()
    }

    fn generate_raw_unchecked<T>(&self) -> T
    where
        T: HardwareRandomizable,
    {
        T::from_hardware_seed_unchecked()
    }
}

impl RngCore for HardwareRNG {
    fn fill_bytes(&mut self, dst: &mut [u8]) {
        for byte in dst.iter_mut() {
            *byte = self.generate_unchecked()
        }
    }

    fn next_u32(&mut self) -> u32 {
        self.generate_unchecked()
    }

    fn next_u64(&mut self) -> u64 {
        self.generate_unchecked()
    }
}

pub trait BasicStaticalTests {
    #[cfg(feature = "compression_test")]
    fn estimate_compression_entropy(&self, data: &[u8]) -> f64 {
        let compressed = lz4_flex::compress_prepend_size(data);
        compressed.len() as f64 / data.len() as f64
    }

    #[cfg(feature = "compression_test")]
    fn check_compression(&self, data: &[u8]) -> bool {
        let ratio = self.estimate_compression_entropy(data);
        ratio > 90.0
    }

    fn estimate_shanon_entropy(&self, data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }

        let mut frequency = [0usize; 256];
        for &byte in data {
            frequency[byte as usize] += 1;
        }

        let len = data.len() as f64;
        frequency
            .iter()
            .filter(|&&count| count > 0)
            .map(|&count| {
                let p: f64 = count as f64 / len;
                -p * p.log2()
            })
            .sum()
    }

    fn chi_square_test(&self, data: &[u8]) -> f64 {
        let mut freq = [0usize; 256];
        for &byte in data {
            freq[byte as usize] += 1;
        }

        let expected = data.len() as f64 / 256.0;
        freq.iter()
            .map(|&f| (f as f64 - expected).powi(2) / expected)
            .sum()
    }
}

pub struct EntropyAnalyzer;
impl BasicStaticalTests for EntropyAnalyzer {}

/// Constant-time operations to prevent timing side-channel attacks.
///
/// All operations in this module execute in constant time regardless of input values,
/// making them safe for cryptographic applications where timing leaks could reveal
/// sensitive information.
pub mod constant_time_ops {
    use core::hint::black_box;

    #[inline(always)]
    /// Constant-time conditional selection between two u8 values.
    ///
    /// Returns `a` if condition is 1, `b` if condition is 0.
    /// Executes in constant time regardless of condition value.
    pub fn select_u8(condition: u8, a: u8, b: u8) -> u8 {
        let mask = condition.wrapping_sub(1);
        (a & mask) | (b & !mask)
    }

    #[inline(always)]
    /// Constant-time byte array comparison.
    ///
    /// Returns 1 if arrays are equal, 0 otherwise.
    /// Always processes entire arrays to prevent timing attacks.
    pub fn compare_bytes(a: &[u8], b: &[u8]) -> u8 {
        if a.len() != b.len() {
            return 0;
        }

        let mut result = 0u8;
        for i in black_box(0..a.len()) {
            result |= a[i] ^ b[i];
        }

        ((result as u16).wrapping_sub(1) >> 8) as u8
    }

    #[inline(always)]
    /// Constant-time conditional assignment of byte arrays.
    ///
    /// Copies `source` to `target` if condition is 1, leaves unchanged if 0.
    /// Processes all bytes regardless of condition to maintain constant timing.
    pub fn conditional_assign(condition: u8, target: &mut [u8], source: &[u8]) {
        let mask = condition.wrapping_sub(1);
        for i in 0..target.len().min(source.len()) {
            target[i] = (target[i] & mask) | (source[i] & !mask);
        }
    }

    /// Constant-time conditional clearing of byte array.
    ///
    /// Clears data if condition is 1, leaves unchanged if 0.
    /// Always processes entire array for timing safety.
    pub fn clear_on_condition(condition: u8, data: &mut [u8]) {
        let mask = condition.wrapping_sub(1);
        for byte in data.iter_mut() {
            *byte &= mask;
        }
    }
}

/// Timing-safe utilities for cryptographic operations.
///
/// Provides operations designed to resist timing analysis attacks through
/// consistent execution patterns and controlled timing variations.
pub mod timing_safe {
    use core::hint::black_box;

    #[cfg(feature = "std")]
    use crate::{CryptoRNG, HardwareRNG};

    #[inline(always)]
    /// Timing-safe memory comparison.
    ///
    /// Unlike standard memcmp, always processes entire arrays regardless
    /// of where differences occur, preventing early-exit timing leaks.
    pub fn memcmp_secure(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }

        let mut result = 0u8;
        for i in black_box(0..a.len()) {
            result |= a[i] ^ b[i];
        }
        result == 0
    }

    #[inline(always)]
    #[cfg(feature = "std")]
    /// Introduces random timing jitter to mask operation timing.
    ///
    /// Adds 0-1000 microseconds of random sleep to prevent timing analysis.
    /// Useful for protecting critical sections from remote timing attacks.
    pub fn secure_sleep_jitter() {
        let jitter: u32 = HardwareRNG.try_generate().unwrap_or(100) % 1000;
        std::thread::sleep(std::time::Duration::from_micros(jitter as u64));
    }
}

/// Memory obfuscation and secure cleanup utilities.
///
/// Provides tools for scrambling sensitive data in memory and ensuring
/// secure deletion that resists memory forensics and cold boot attacks.
pub mod memory_obfuscation {
    use core::ptr::write_bytes;

    #[cfg(feature = "dev-logs")]
    use log::trace;

    use crate::{CryptoRNG, HardwareRNG, RngErrors};

    /// XOR-based memory scrambler for runtime data protection.
    ///
    /// # DOES NOT PROVIDE ANY SECURITY
    /// # USE IT AT YOUR OWN RISK
    ///
    /// Obfuscates sensitive data in memory using hardware-generated XOR keys.
    /// Protects against memory dumps and reduces plaintext exposure time.
    pub struct MemoryScrambler {
        xor_key: [u8; 64],
    }

    impl MemoryScrambler {
        #[inline(always)]
        /// Creates new scrambler with hardware-generated XOR key.
        pub fn new() -> Result<Self, crate::RngErrors> {
            let mut key = [0u8; 64];
            HardwareRNG.try_fill_by(&mut key)?;
            Ok(Self { xor_key: key })
        }

        #[inline(always)]
        /// XOR-scrambles data in place using internal key.
        pub fn scramble(&self, data: &mut [u8]) {
            for (i, byte) in data.iter_mut().enumerate() {
                *byte ^= self.xor_key[i % 64];
            }
        }

        #[inline(always)]
        /// Descrambles data (same as scramble due to XOR properties).
        pub fn descramble(&self, data: &mut [u8]) {
            self.scramble(data);
        }
    }

    /// Secure memory clearing trait.
    ///
    /// Provides guaranteed zeroing that compilers cannot optimize away.
    pub trait Zeroize {
        fn zeroize(&mut self);
    }

    /// Random-fill-then-zero memory clearing trait.
    ///
    /// Overwrites memory with random data before zeroing to resist
    /// forensic recovery and cold boot attacks.
    pub trait RandZeroize {
        fn rand_zeroize(&mut self) -> Result<(), RngErrors>;
        fn rand_zeroize_unchecked(&mut self) -> ();
    }

    impl RandZeroize for [u8] {
        #[inline(always)]
        fn rand_zeroize(&mut self) -> Result<(), RngErrors> {
            HardwareRNG.try_fill_by(self)?;

            unsafe {
                write_bytes(self.as_mut_ptr(), 0, self.len());
            }

            #[cfg(feature = "dev-logs")]
            trace!("Zeroized memory with random prefill");

            Ok(())
        }

        fn rand_zeroize_unchecked(&mut self) {
            HardwareRNG.fill_by_unchecked(self);

            unsafe {
                write_bytes(self.as_mut_ptr(), 0, self.len());
            }

            #[cfg(feature = "dev-logs")]
            trace!("Zeroized memory with random prefill");
        }
    }

    impl<T> Zeroize for [T] {
        #[inline(always)]
        fn zeroize(&mut self) {
            unsafe {
                write_bytes(self.as_mut_ptr(), 0, self.len());
            }

            #[cfg(feature = "dev-logs")]
            trace!("Zeroized memory (generic)");
        }
    }
}

#[cfg(feature = "std")]
pub struct CpuFeatures;

#[cfg(feature = "std")]
impl CpuFeatures {
    pub fn has_rdrand(&self) -> bool {
        is_x86_feature_detected!("rdrand")
    }
    pub fn has_rdseed(&self) -> bool {
        is_x86_feature_detected!("rdseed")
    }
    pub fn has_aes_ni(&self) -> bool {
        is_x86_feature_detected!("aes")
    }
    pub fn has_sha(&self) -> bool {
        is_x86_feature_detected!("sha")
    }
    pub fn has_avx2(&self) -> bool {
        is_x86_feature_detected!("avx2")
    }
    pub fn has_avx(&self) -> bool {
        is_x86_feature_detected!("avx")
    }
    pub fn has_pclmulqdq(&self) -> bool {
        is_x86_feature_detected!("pclmulqdq")
    }
    pub fn has_crc32(&self) -> bool {
        is_x86_feature_detected!("sse4.2")
    }
    pub fn has_bmi1(&self) -> bool {
        is_x86_feature_detected!("bmi1")
    }
    pub fn has_bmi2(&self) -> bool {
        is_x86_feature_detected!("bmi2")
    }
    pub fn supports_crypto_operations(&self) -> bool {
        self.has_aes_ni()
            && self.has_rdrand()
            && self.has_sha()
            && self.has_pclmulqdq()
            && self.has_rdseed()
    }
}

mod macros {
    #[macro_export]
    macro_rules! evaluate_entropy {
        ($data:expr) => {{
            let analyzer = EntropyAnalyzer;
            let shannon = analyzer.estimate_shanon_entropy($data);
            let chi_square = analyzer.chi_square_test($data);

            println!("=== Entropy Analysis ===");
            println!("Shannon Entropy: {:.4} bits", shannon);
            println!("Chi-Square: {:.4}", chi_square);
            println!("Data length: {} bytes", $data.len());

            if shannon > 7.9 {
                println!("High quality randomness");
            } else if shannon > 7.5 {
                println!("Moderate quality");
            } else {
                println!("Poor randomness");
            }

            (shannon, chi_square)
        }};

        ($data:expr, compression) => {{
            #[cfg(feature = "compression_test")]
            {
                let analyzer = EntropyAnalyzer;
                let shannon = analyzer.estimate_shanon_entropy($data);
                let chi_square = analyzer.chi_square_test($data);
                let compression_ratio = analyzer.estimate_compression_entropy($data);

                println!("=== Extended Entropy Analysis ===");
                println!("Shannon Entropy: {:.4} bits", shannon);
                println!("Chi-Square: {:.4}", chi_square);
                println!("Compression Ratio: {:.4}", compression_ratio);

                (shannon, chi_square, compression_ratio)
            }
            #[cfg(not(feature = "compression_test"))]
            evaluate_entropy!($data)
        }};
    }

    #[macro_export]
    macro_rules! benchmark {
        ($func:expr) => {{
            let (result, cycles) = CycleTimer::benchmark($func);
            println!("Executed in {} cycles", cycles);
            result
        }};
    }
}

#[cfg(feature = "std")]
#[cfg(test)]
mod constant_time_tests {
    use core::hint::black_box;

    use crate::CryptoRNG;

    fn median_and_mad(mut v: Vec<u64>) -> (f64, f64) {
        v.sort_unstable();
        let n = v.len();
        let med = if n % 2 == 0 {
            (v[n / 2 - 1] as f64 + v[n / 2] as f64) * 0.5
        } else {
            v[n / 2] as f64
        };
        let mut dev: Vec<u64> = v
            .into_iter()
            .map(|x| u64::abs_diff(x, med as u64))
            .collect();
        dev.sort_unstable();
        let mad = if n % 2 == 0 {
            (dev[n / 2 - 1] as f64 + dev[n / 2] as f64) * 0.5
        } else {
            dev[n / 2] as f64
        };
        (med, mad)
    }

    #[test]
    fn test_select_u8_timing() {
        use crate::HardwareRNG;
        use crate::constant_time_ops::select_u8;

        const WARMUP: usize = 2048;
        const SAMPLES: usize = 2048;
        const OUTER: usize = 50;
        const DELTA_THRESHOLD: f64 = 5.0;

        for _ in 0..OUTER {
            let mut sink = 0u8;
            for _ in 0..WARMUP {
                sink ^= select_u8(1, 0xAA, 0x55);
            }
            black_box(sink);

            let mut timings_true = Vec::with_capacity(SAMPLES);
            let mut timings_false = Vec::with_capacity(SAMPLES);
            let mut data = [0u8; 256];
            HardwareRNG.fill_by_unchecked(&mut data);

            for i in 0..SAMPLES {
                let x = black_box(data[i & 255]);
                #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
                unsafe {
                    core::arch::x86_64::_mm_lfence()
                }
                let (_, ct) = crate::CycleTimer::benchmark(|| black_box(select_u8(1, x, 0x69)));

                #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
                unsafe {
                    core::arch::x86_64::_mm_lfence()
                }
                let (_, cf) = crate::CycleTimer::benchmark(|| black_box(select_u8(0, x, 0x69)));

                timings_true.push(ct);
                timings_false.push(cf);
            }

            let (med_t, mad_t) = median_and_mad(timings_true);
            let (med_f, mad_f) = median_and_mad(timings_false);
            let delta = (med_t - med_f).abs();

            println!(
                "median(true)={:.2} (MAD {:.2}) | median(false)={:.2} (MAD {:.2}) | Δ={:.2} cycles",
                med_t, mad_t, med_f, mad_f, delta
            );

            assert!(
                delta < DELTA_THRESHOLD,
                "Constant-time check failed: median Δ={delta:.2} cycles"
            );
        }
    }
}

#[doc(hidden)]
#[macro_export]
/// Used like: types! { type: 4 x u32 }
///
/// example:
/// ```rust
/// types! {
///  #[derive(Debug)]
///  #[repr(align(64), C)]
///  type __rsi256keys: 4 // Data size comes here x u8 // Data type comes here
///
///  #[derive(Debug, Clone, Copy)]
///  type __rsi512keys: 4 x u64 // Data typep comes here again
///
///  impl deref __rsi192keys, [u32; 3] // You can implement deref easyly via this
///
///  // More types here
///  // .
///  // .
///  // .
/// }
///
/// types! {
///  type vaes: __m256i;
///  type: aes: u32
/// }
/// ```
macro_rules! types {
    (
        $(
            $(#[$atr:meta])*
            type $name:ident: $size:tt x $type:ty;
            $(impl deref $struct:ident, $target:tt)?
        )*
    ) => (
        $(
            $(#[$atr])*
            #[repr(transparent)]
            pub struct $name([$type; $size]);
            $(
                impl Deref for $struct {
                    type Target = $target;

                    fn deref(&self) -> &Self::Target {
                        &self.0
                    }
                }
            )?
        )*
    );
    (
        $(
            $(#[$atr:meta])*
            type $name:ident: $type:ty;
            $(impl deref $struct:ident, $target:tt)?
        )*
    ) => {
        $(
            $(#[$atr])*
            #[repr(transparent)]
            pub struct $name($type);
            $(
                impl Deref for $struct {
                    type Target = $target;

                    fn deref(&self) -> &Self::Target {
                        &self.0
                    }
                }
            )?
        )*
    };
}

#[repr(transparent)]
pub struct KeyGenerator(SecureVec<u8>);

impl KeyGenerator {
    pub fn new(cap: usize) -> Result<Self, AllocatorError> {
        let mut vec = SecureVec::with_capacity(cap)?;
        vec.fill(0)?;
        Ok(Self(vec))
    }

    pub fn generate(mut self, rng: &mut impl CryptoRNG) -> Result<Self, RngErrors> {
        rng.try_fill_by(&mut self.0)?;
        Ok(self)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl AsRef<[u8]> for KeyGenerator {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Deref for KeyGenerator {
    type Target = SecureVec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for KeyGenerator {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl core::fmt::Debug for KeyGenerator {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Key([REDACTED]; {} bytes)", self.len())
    }
}

#[derive(Debug, Error)]
pub enum KeyGenError {
    #[error("Cannot Generate Random key reason: {0}")]
    KeyError(String),
}

pub fn rand_key<const U: usize>() -> Result<KeyGenerator, KeyGenError> {
    KeyGenerator::new(U)
        .map_err(|e| KeyGenError::KeyError(e.to_string()))?
        .generate(&mut HardwareRNG)
        .map_err(|e| KeyGenError::KeyError(e.to_string()))
}
