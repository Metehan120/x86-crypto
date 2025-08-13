use core::{
    arch::x86_64::{__m128, __m128d, __m128i, __m256, __m256d, __m256i},
    ptr::write_bytes,
};

use crate::{
    CryptoRNG, HardwareRNG, RngErrors,
    ni_instructions::{
        aesni::{__rsi128keys, __rsi192keys, __rsi256keys, __rsi512keys},
        vaes::{__vaes256i, __vaes256key, __vaes256keys, __vaes512keys},
    },
};

/// Random-fill-then-zero memory clearing trait.
///
/// Overwrites memory with random data before zeroing to resist
/// forensic recovery and cold boot attacks.
pub trait RandZeroizeable {
    fn rand_zeroize(&mut self) -> Result<(), RngErrors>;
    fn rand_zeroize_unchecked(&mut self) -> ();
}

macro_rules! randzeroize {
    ($($type:ty)*) => {
        $(impl RandZeroizeable for [$type] {
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
        })*
    };
}

pub trait Zeroizeable {
    fn zeroize(&mut self);
}

macro_rules! zeroize {
    ($($type:ty)*) => {
        $(impl Zeroizeable for [$type] {
            fn zeroize(&mut self) {
                unsafe {
                    write_bytes(self.as_mut_ptr(), 0, self.len());
                }

                #[cfg(feature = "dev-logs")]
                trace!("Zeroized memory with random prefill");
            }
        })*
    };
}

zeroize! { usize u8 u16 u32 u64 i8 i16 i32 i64 String __m128i __m256i __m128 __m256 __m128d __m256d __vaes256i __vaes256key __vaes256keys __vaes512keys __rsi128keys __rsi192keys __rsi256keys __rsi512keys f64 f32 }
randzeroize!(usize u8 u16 u32 u64 i8 i16 i32 i64);
