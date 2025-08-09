use core::{
    fmt::Display,
    ops::{Add, Bound, RangeBounds, Rem, Sub},
};

#[cfg(feature = "audit-logs")]
use log::info;
use num_traits::One;
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
use rand_core::RngCore;

use crate::{CryptoRNG, HardwareRNG, HardwareRandomizable, RawGenerator, RngErrors};

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
