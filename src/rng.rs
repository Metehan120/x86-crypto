use core::{
    arch::x86_64::{
        _rdrand16_step, _rdrand32_step, _rdrand64_step, _rdseed16_step, _rdseed32_step,
        _rdseed64_step,
    },
    fmt::Display,
    ops::{Add, Bound, RangeBounds, Rem, Sub},
};

use log::info;
use num_traits::{One, Unsigned};
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use thiserror_no_std::Error;

use crate::{BasicStaticalTests, EntropyAnalyzer};

#[derive(Debug, Error)]
pub enum RngErrors {
    #[error("Failed to generate random byte/bytes")]
    FailedToGenerate,
    #[error("Failed to generate NON-BIAS range")]
    FailedBias,
}

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

    #[must_use = "Check the error; RNG may fail on unsupported HW."]
    fn try_fill_raw_by<T>(&self, buffer: &mut [T]) -> Result<(), RngErrors>
    where
        T: HardwareRandomizable,
    {
        for byte in buffer.iter_mut() {
            *byte = self.try_generate_raw::<T>()?;
        }
        Ok(())
    }

    #[must_use = "Check the error; RNG may fail on unsupported HW."]
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

    #[inline(always)]
    fn try_shuffle_slice<T>(&mut self, data: &mut [T]) -> Result<(), RngErrors> {
        for i in (1..data.len()).rev() {
            let j: usize = self.try_generate_range(0..=i)?;
            data.swap(i, j);
        }

        Ok(())
    }
}

pub trait ShuffleSlice<R: CryptoRNG> {
    fn shuffle(&mut self, rng: &mut R);
    fn try_shuffle(&mut self, rng: &mut R) -> Result<(), RngErrors>;
}

impl<T, R: CryptoRNG> ShuffleSlice<R> for [T] {
    fn shuffle(&mut self, rng: &mut R) {
        for i in (1..self.len()).rev() {
            let j: usize = rng.generate_range_unchecked(0..=i);
            self.swap(i, j);
        }
    }

    fn try_shuffle(&mut self, rng: &mut R) -> Result<(), RngErrors> {
        for i in (1..self.len()).rev() {
            let j: usize = rng.try_generate_range(0..=i)?;
            self.swap(i, j);
        }

        Ok(())
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

#[derive(Debug, Clone)]
pub struct HWChaCha20Rng(ChaCha20Rng);

impl HWChaCha20Rng {
    pub fn new() -> Result<Self, RngErrors> {
        #[cfg(feature = "audit-logs")]
        info!("Created RNG ChaCha20 instance");
        let mut seed = [0u8; 32];
        HardwareRNG.try_fill_raw_by(&mut seed)?;

        Ok(Self(ChaCha20Rng::from_seed(seed)))
    }

    pub fn get_seed(&self) -> [u8; 32] {
        self.0.get_seed()
    }

    pub fn get_stream(&self) -> u64 {
        self.0.get_stream()
    }
}

unsafe impl Send for HWChaCha20Rng {}

impl CryptoRNG for HWChaCha20Rng {
    #[inline(always)]
    fn try_generate<T>(&mut self) -> Result<T, RngErrors>
    where
        T: HardwareRandomizable,
    {
        Ok(T::from_chacha(&mut self.0))
    }

    #[inline(always)]
    fn generate_unchecked<T>(&mut self) -> T
    where
        T: HardwareRandomizable,
    {
        T::from_chacha(&mut self.0)
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
            return Ok(T::from_chacha(&mut self.0));
        }

        let range_size = end - start + T::one();
        let remainder = T::max_value() % range_size;
        let max_valid = T::max_value() - remainder;

        let mut loop_count = 0;
        loop {
            let raw = T::from_chacha(&mut self.0);
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
            return T::from_chacha(&mut self.0);
        }

        let range_size = end - start + T::one();
        let remainder = T::max_value() % range_size;
        let max_valid = T::max_value() - remainder;

        let mut loop_count = 0;
        loop {
            let raw = T::from_chacha(&mut self.0);
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

impl RngCore for HWChaCha20Rng {
    fn fill_bytes(&mut self, dst: &mut [u8]) {
        for byte in dst.iter_mut() {
            *byte = self.generate_unchecked();
        }
    }

    fn next_u32(&mut self) -> u32 {
        self.generate_unchecked()
    }

    fn next_u64(&mut self) -> u64 {
        self.generate_unchecked()
    }
}

impl rand_core::CryptoRng for HWChaCha20Rng {}
