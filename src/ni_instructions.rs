use core::arch::x86_64::{__m128i, _mm_loadu_si128, _mm_storeu_si128};

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

pub mod aesni {
    use core::{
        arch::x86_64::{
            __m128i, _mm_aesdec_si128, _mm_aesdeclast_si128, _mm_aesenc_si128,
            _mm_aesenclast_si128, _mm_aeskeygenassist_si128, _mm_shuffle_epi32, _mm_slli_si128,
            _mm_xor_si128,
        },
        ops::Deref,
    };

    #[cfg(feature = "dev-logs")]
    use log::debug;

    use log::trace;

    use crate::types;

    types! {
        #[derive(Clone, Copy)]
        /// A wrapper for AES-128 Round Keys, which is providing type-safe environment
        ///
        /// Can be loaded via `loadu_keys_128` function
        /// RSI = Rounded Structured Integers
        type __rsi128keys: 11 x __m128i;
        impl deref __rsi128keys, [__m128i; 11]

        #[derive(Clone, Copy)]
        /// A wrapper for AES-192 Round Keys, which is providing type-safe environment
        ///
        /// Can be loaded via `loadu_keys_192` function
        /// RSI = Rounded Structured Integers
        type __rsi192keys: 13 x __m128i;
        impl deref __rsi192keys, [__m128i; 13]

        #[derive(Clone, Copy)]
        /// A wrapper for AES-256 Round Keys, which is providing type-safe environment
        ///
        /// Can be loaded via `loadu_keys_256` function
        /// RSI = Rounded Structured Integers
        type __rsi256keys: 15 x __m128i;
        impl deref __rsi256keys, [__m128i; 15]

        #[derive(Clone, Copy)]
        /// A wrapper for AES-512 Round Keys, which is providing type-safe environment
        ///
        /// # THIS TYPE IS FOR FUTURE-PROOFING
        ///
        /// Can be loaded via `loadu_keys_512` function
        /// RSI = Rounded Structured Integers
        type __rsi512keys: 23 x __m128i;
        impl deref __rsi512keys, [__m128i; 23]
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
        fn perform_aes256_rounds_block(&self, round_keys: __rsi256keys, chunk: __m128i) -> __m128i;
        fn perform_aes256_inv_rounds_block(
            &self,
            round_keys: __rsi256keys,
            chunk: __m128i,
        ) -> __m128i;
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
            round_keys: __rsi256keys,
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
}

pub mod shani {
    use core::arch::x86_64::{
        __m128i, _mm_sha256msg1_epu32, _mm_sha256msg2_epu32, _mm_sha256rnds2_epu32,
    };

    #[allow(non_camel_case_types)]
    /// SHA-NI Instrcution wrapper for ease of use
    ///
    /// # Example
    /// ```rust
    /// let shan256_rnds2 = AES_NI.aes_rodun(state, msg, wk);
    /// ```
    pub struct SHA2_NI;

    unsafe impl Send for SHA2_NI {}

    pub trait SHA2 {
        fn sha256_rnds2(&self, state: __m128i, msg: __m128i, wk: __m128i) -> __m128i;
        fn sha256_msg1(&self, w0: __m128i, w1: __m128i) -> __m128i;
        fn sha256_msg2(&self, w2: __m128i, w3: __m128i) -> __m128i;
    }

    impl SHA2 for SHA2_NI {
        #[inline(always)]
        fn sha256_rnds2(&self, state: __m128i, msg: __m128i, wk: __m128i) -> __m128i {
            unsafe { _mm_sha256rnds2_epu32(state, msg, wk) }
        }

        #[inline(always)]
        fn sha256_msg1(&self, w0: __m128i, w1: __m128i) -> __m128i {
            unsafe { _mm_sha256msg1_epu32(w0, w1) }
        }

        #[inline(always)]
        fn sha256_msg2(&self, w2: __m128i, w3: __m128i) -> __m128i {
            unsafe { _mm_sha256msg2_epu32(w2, w3) }
        }
    }
}

pub mod pclmul {
    use core::arch::x86_64::{__m128i, _mm_clmulepi64_si128};

    /// PclMul wrapper for ease of use
    pub struct PclMul;

    unsafe impl Send for PclMul {}

    pub trait CarrylessMultiply {
        fn clmul_low(&self, a: __m128i, b: __m128i) -> __m128i;
        fn clmul_high(&self, a: __m128i, b: __m128i) -> __m128i;
        fn clmul_low_high(&self, a: __m128i, b: __m128i) -> __m128i;
        fn clmul_high_low(&self, a: __m128i, b: __m128i) -> __m128i;
        fn clmul_custom<const VALUE: i32>(&self, a: __m128i, b: __m128i) -> __m128i;
    }

    impl CarrylessMultiply for PclMul {
        #[inline(always)]
        fn clmul_low(&self, a: __m128i, b: __m128i) -> __m128i {
            unsafe { _mm_clmulepi64_si128(a, b, 0x00) }
        }

        #[inline(always)]
        fn clmul_high(&self, a: __m128i, b: __m128i) -> __m128i {
            unsafe { _mm_clmulepi64_si128(a, b, 0x11) }
        }

        #[inline(always)]
        fn clmul_low_high(&self, a: __m128i, b: __m128i) -> __m128i {
            unsafe { _mm_clmulepi64_si128(a, b, 0x01) }
        }

        #[inline(always)]
        fn clmul_high_low(&self, a: __m128i, b: __m128i) -> __m128i {
            unsafe { _mm_clmulepi64_si128(a, b, 0x10) }
        }
        fn clmul_custom<const VALUE: i32>(&self, a: __m128i, b: __m128i) -> __m128i {
            unsafe { _mm_clmulepi64_si128(a, b, VALUE) }
        }
    }
}

/// Provides low-level, hardware-accelerated access to the VAES (Vector AES)
/// instruction set on x86_64 CPUs.
///
/// This module is optimized for performance and provides a low-level, but safe,
/// interface to VAES instructions via inline assembly.
///
/// **Requires** CPU support for `vaes` and `avx` instructions, checked at runtime.
/// **Warning:** Use at your own risk. Incorrect usage may lead to undefined behavior
/// or process termination if CPU feature checks are bypassed.
pub mod vaes {
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
}
