use core::{
    arch::x86_64::{
        __m128i, _mm_aesdec_si128, _mm_aesdeclast_si128, _mm_aesenc_si128, _mm_aesenclast_si128,
        _mm_aeskeygenassist_si128, _mm_loadu_si128, _mm_shuffle_epi32, _mm_slli_si128,
        _mm_storeu_si128, _mm_xor_si128,
    },
    ops::Deref,
};

#[cfg(feature = "dev-logs")]
use log::debug;

use log::trace;

use crate::{memory::zeroize::Zeroizeable, types};

/// AVX2 Register load function
///
/// **Loads Array/Vec to SIMD register**
pub trait LoadRegister {
    unsafe fn load(&self) -> __m128i;
}

/// AVX2 Register store function
///
/// **Loads SIMD data to Memory**
pub trait StoreRegister {
    unsafe fn store(&self) -> [u8; 16];
}

impl LoadRegister for [u8] {
    #[inline(always)]
    unsafe fn load(&self) -> __m128i {
        unsafe { _mm_loadu_si128(self.as_ptr() as *const __m128i) }
    }
}

impl StoreRegister for __m128i {
    #[inline(always)]
    unsafe fn store(&self) -> [u8; 16] {
        let mut output = [0u8; 16];
        unsafe { _mm_storeu_si128(output.as_mut_ptr() as *mut __m128i, *self) };
        output
    }
}

types! {
    #[derive(Clone)]
    /// A wrapper for AES-128 Round Keys, which is providing type-safe environment
    ///
    /// Can be loaded via `loadu_keys_128` function
    /// RSI = Rounded Structured Integers
    type __rsi128keys: 11 x __m128i;
    impl deref __rsi128keys, [__m128i; 11]
    impl drop __rsi128keys

    #[derive(Clone)]
    /// A wrapper for AES-192 Round Keys, which is providing type-safe environment
    ///
    /// Can be loaded via `loadu_keys_192` function
    /// RSI = Rounded Structured Integers
    type __rsi192keys: 13 x __m128i;
    impl deref __rsi192keys, [__m128i; 13]
    impl drop __rsi192keys

    #[derive(Clone)]
    /// A wrapper for AES-256 Round Keys, which is providing type-safe environment
    ///
    /// Can be loaded via `loadu_keys_256` function
    /// RSI = Rounded Structured Integers
    type __rsi256keys: 15 x __m128i;
    impl deref __rsi256keys, [__m128i; 15]
    impl drop __rsi256keys

    #[derive(Clone)]
    /// A wrapper for AES-512 Round Keys, which is providing type-safe environment
    ///
    /// # THIS TYPE IS FOR FUTURE-PROOFING
    ///
    /// Can be loaded via `loadu_keys_512` function
    /// RSI = Rounded Structured Integers
    type __rsi512keys: 23 x __m128i;
    impl deref __rsi512keys, [__m128i; 23]
    impl drop __rsi512keys
}

/// This function loads your keys to `__rsi128keys` wrapper
///
/// `loadu` means unaligned
#[inline(always)]
pub fn loadu_keys_128(keys: [__m128i; 11]) -> __rsi128keys {
    #[cfg(feature = "dev-logs")]
    debug!("Loaded AES-128 keys into __rsi128keys wrapper");
    __rsi128keys(keys)
}
/// This function loads your keys to `__rsi192keys` wrapper
///
/// `loadu` means unaligned
#[inline(always)]
pub fn loadu_keys_192(keys: [__m128i; 13]) -> __rsi192keys {
    #[cfg(feature = "dev-logs")]
    debug!("Loaded AES-192 keys into __rsi192keys wrapper");
    __rsi192keys(keys)
}
/// This function loads your keys to `__rsi256keys` wrapper
///
/// `loadu` means unaligned
#[inline(always)]
pub fn loadu_keys_256(keys: [__m128i; 15]) -> __rsi256keys {
    #[cfg(feature = "dev-logs")]
    debug!("Loaded AES-256 keys into __rsi256keys wrapper");
    __rsi256keys(keys)
}
/// This function loads your keys to `__rsi512keys` wrapper
///
/// # THIS FUNCTION IS FOR FUTURE-PROOFING
///
/// `loadu` means unaligned
#[inline(always)]
pub fn loadu_keys_512(keys: [__m128i; 23]) -> __rsi512keys {
    #[cfg(feature = "dev-logs")]
    debug!("Loaded AES-512 keys into __rsi512keys wrapper (future-proof)");
    __rsi512keys(keys)
}

#[inline(always)]
pub fn storeu_keys_256(keys: __rsi256keys) -> [__m128i; 15] {
    #[cfg(feature = "dev-logs")]
    debug!("Stored AES-256 keys from __rsi256keys wrapper");
    keys.0
}

#[allow(non_camel_case_types)]
/// AES-NI Instruction wrapper for ease of use
///
/// # Example
/// ```rust
/// let aes = AES_NI;
/// let round_keys = aes.expand_aes256_key([key_low, key_high]);
/// let encrypted = aes.perform_aes256_rounds_block(round_keys, plaintext);
/// ```
pub struct AES_NI;

unsafe impl Send for AES_NI {}

pub trait AES {
    fn aes_round(&self, key: __m128i, chunk: __m128i) -> __m128i;
    fn aes_last_round(&self, key: __m128i, chunk: __m128i) -> __m128i;
    fn aes_inv_round(&self, key: __m128i, chunk: __m128i) -> __m128i;
    fn aes_inv_last_round(&self, key: __m128i, chunk: __m128i) -> __m128i;
    fn aes_key_gen_assist<const RCON: i32>(&self, key: __m128i) -> __m128i;
    fn key_schedule_assist(&self, key: __m128i, temp: __m128i) -> __m128i;
    fn perform_aes256_rounds_block(&self, round_keys: &__rsi256keys, chunk: __m128i) -> __m128i;
    fn perform_aes256_inv_rounds_block(&self, round_keys: __rsi256keys, chunk: __m128i) -> __m128i;
    fn expand_aes256_key(&self, key: [__m128i; 2]) -> __rsi256keys;
}

impl AES for AES_NI {
    #[inline(always)]
    fn aes_round(&self, key: __m128i, chunk: __m128i) -> __m128i {
        unsafe { _mm_aesenc_si128(chunk, key) }
    }

    #[inline(always)]
    fn aes_last_round(&self, key: __m128i, chunk: __m128i) -> __m128i {
        unsafe { _mm_aesenclast_si128(chunk, key) }
    }

    #[inline(always)]
    fn aes_inv_round(&self, key: __m128i, chunk: __m128i) -> __m128i {
        unsafe { _mm_aesdec_si128(chunk, key) }
    }

    #[inline(always)]
    fn aes_inv_last_round(&self, key: __m128i, chunk: __m128i) -> __m128i {
        unsafe { _mm_aesdeclast_si128(chunk, key) }
    }

    #[inline(always)]
    fn aes_key_gen_assist<const RCON: i32>(&self, key: __m128i) -> __m128i {
        unsafe { _mm_aeskeygenassist_si128::<RCON>(key) }
    }

    #[inline(always)]
    fn key_schedule_assist(&self, mut key: __m128i, temp: __m128i) -> __m128i {
        unsafe {
            key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
            key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
            key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
            key = _mm_xor_si128(key, temp);
            key
        }
    }

    #[inline(always)]
    fn perform_aes256_rounds_block(
        &self,
        round_keys: &__rsi256keys,
        mut chunk: __m128i,
    ) -> __m128i {
        chunk = unsafe { _mm_xor_si128(chunk, round_keys[0]) };
        for i in 1..14 {
            chunk = self.aes_round(round_keys[i], chunk);
        }
        chunk = self.aes_last_round(round_keys[14], chunk);
        chunk
    }

    #[inline(always)]
    fn perform_aes256_inv_rounds_block(
        &self,
        round_keys: __rsi256keys,
        mut chunk: __m128i,
    ) -> __m128i {
        chunk = unsafe { _mm_xor_si128(chunk, round_keys[14]) };
        for i in (1..14).rev() {
            chunk = self.aes_inv_round(round_keys[i], chunk);
        }
        chunk = self.aes_inv_last_round(round_keys[0], chunk);
        chunk
    }

    #[inline(always)]
    fn expand_aes256_key(&self, key: [__m128i; 2]) -> __rsi256keys {
        trace!("Key expansion started for AES-256");
        let mut round_keys = [unsafe { core::mem::zeroed() }; 15];

        round_keys[0] = key[0];
        round_keys[1] = key[1];

        let mut key_low = key[0];
        let mut key_high = key[1];

        for i in 1..8 {
            let temp = match i {
                1 => self.aes_key_gen_assist::<0x01>(key_high),
                2 => self.aes_key_gen_assist::<0x02>(key_high),
                3 => self.aes_key_gen_assist::<0x04>(key_high),
                4 => self.aes_key_gen_assist::<0x08>(key_high),
                5 => self.aes_key_gen_assist::<0x10>(key_high),
                6 => self.aes_key_gen_assist::<0x20>(key_high),
                7 => self.aes_key_gen_assist::<0x40>(key_high),
                _ => unreachable!(),
            };

            let temp = unsafe { _mm_shuffle_epi32(temp, 0xff) };
            key_low = self.key_schedule_assist(key_low, temp);
            round_keys[i * 2] = key_low;

            if i < 7 {
                let temp = self.aes_key_gen_assist::<0x00>(key_low);
                let temp = unsafe { _mm_shuffle_epi32(temp, 0xaa) };
                key_high = self.key_schedule_assist(key_high, temp);
                round_keys[i * 2 + 1] = key_high;
            }
        }
        trace!("Key expansion completed (11 rounds)");

        loadu_keys_256(round_keys)
    }
}
