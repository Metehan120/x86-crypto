use crate::{
    CryptoRNG,
    ciphers::aes_cipher::{AesError, Tag128},
    constant_time_ops,
    memory::zeroize::Zeroizeable,
    ni_instructions::{
        aesni::{AES, AES_NI, LoadRegister, storeu_keys_256},
        vaes::{__vaes256i, loadu_vaes256_mm256i, loadu_vaeskey_m256i},
    },
    types,
};

#[cfg(feature = "vaes_asm_cipher")]
use crate::ni_instructions::vaes::{vaesenc_asm, vaesenc_last_asm};

#[cfg(not(feature = "vaes_asm_cipher"))]
use crate::ni_instructions::vaes::{vaesenc_intrinsic, vaesenc_last_intrinsic};

use core::{
    arch::x86_64::{
        __m256i, _mm256_broadcastsi128_si256, _mm256_loadu_si256, _mm256_storeu_si256,
        _mm256_xor_si256,
    },
    sync::atomic::AtomicU64,
};
use ghash::GHash;
#[cfg(feature = "cipher_prefetch")]
use log::warn;
use rayon::{
    iter::{IndexedParallelIterator, ParallelIterator},
    slice::ParallelSliceMut,
};
use universal_hash::{Key, KeyInit, UniversalHash};

static NONCE_TOKEN: AtomicU64 = AtomicU64::new(0);

types! {
    #[derive(Debug, Clone, Copy)]
    /// 192-bit IV seed used for VAES parallel encryption/decryption.
    ///
    /// Internally stores the same 96-bit nonce twice (n || n),
    /// allowing two 128-bit counter blocks to be processed in parallel
    /// with VAES256 (CTR mode). This does **not** increase entropy,
    /// it’s purely for SIMD parallelism.
    type Nonce192: [u8; 24];
}

impl Nonce192 {
    pub fn generate_nonce(generator: &mut impl CryptoRNG) -> Nonce192 {
        #[cfg(feature = "dev-logs")]
        trace!("Generating Nonce");
        let mut nonce = [0u8; 12];
        generator.fill_by_unchecked(&mut nonce);
        let mut nonce_192 = [0u8; 24];
        nonce_192[..12].copy_from_slice(&nonce);
        nonce_192[12..].copy_from_slice(&nonce);

        #[cfg(feature = "dev-logs")]
        trace!("Generated Nonce: {:02X?}", nonce);
        Nonce192(nonce_192)
    }

    pub fn generate_with_token(generator: &mut impl CryptoRNG) -> (Nonce192, u64) {
        #[cfg(feature = "dev-logs")]
        trace!("Generating Nonce");
        let mut nonce = [0u8; 12];
        generator.fill_by_unchecked(&mut nonce);
        let mut nonce_192 = [0u8; 24];
        nonce_192[..12].copy_from_slice(&nonce);
        nonce_192[12..].copy_from_slice(&nonce);

        let generated = Nonce192(nonce_192);
        let token = NONCE_TOKEN.fetch_add(1, core::sync::atomic::Ordering::Relaxed) + 1;

        #[cfg(feature = "dev-logs")]
        debug!("Nonce+Token pair created for session tracking");
        #[cfg(feature = "dev-logs")]
        trace!(
            "Generated Nonce: {:02X?}, Generated Token: {}",
            nonce, token
        );

        (generated, token)
    }

    pub fn from_bytes(bytes: [u8; 24]) -> Nonce192 {
        Nonce192(bytes)
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.as_slice().to_vec()
    }
}

#[inline]
fn assert_size_ok(len_bytes: usize, start_counter: u32) -> Result<(), AesError> {
    let max_blocks = u64::from(u32::MAX) - u64::from(start_counter) + 1;
    let max_bytes = max_blocks * 16;
    let len_u64 = len_bytes as u64;
    if len_u64 > max_bytes {
        return Err(AesError::MaxSizeExceeded(max_bytes, len_u64));
    }
    Ok(())
}

pub struct Vaes256CTR {
    key: [__m256i; 15],
}

impl Vaes256CTR {
    pub fn new<T: AsRef<[u8]>>(key: T) -> Result<Self, AesError> {
        if is_x86_feature_detected!("vaes") {
            #[cfg(feature = "dev-logs")]
            debug!("Created new AES-256 cipher instance");
            let key = key.as_ref();

            if key.len() != 32 {
                return Err(AesError::InvalidPasswordLenght);
            }

            let key = [unsafe { key[..16].load() }, unsafe { key[16..].load() }];

            let keys = AES_NI.expand_aes256_key(key);
            let key = storeu_keys_256(keys);

            let mut rk256: [__m256i; 15] = unsafe { core::mem::zeroed() };
            for i in 0..15 {
                rk256[i] = unsafe { _mm256_broadcastsi128_si256(key[i]) };
            }

            Ok(Self { key: rk256 })
        } else {
            return Err(AesError::VaesNotSupported);
        }
    }

    #[inline(always)]
    fn encrypt_block(&self, mut plaintext: __m256i) -> __vaes256i {
        plaintext = unsafe { _mm256_xor_si256(plaintext, self.key[0]) };
        let mut block = loadu_vaes256_mm256i(plaintext);

        #[cfg(feature = "vaes_asm_cipher")]
        {
            for i in 1..14 {
                block = unsafe { vaesenc_asm(block, loadu_vaeskey_m256i(self.key[i])) };
            }
            block = unsafe { vaesenc_last_asm(block, loadu_vaeskey_m256i(self.key[14])) };
        }

        #[cfg(not(feature = "vaes_asm_cipher"))]
        {
            for i in 1..14 {
                block = unsafe { vaesenc_intrinsic(block, loadu_vaeskey_m256i(self.key[i])) };
            }
            block = unsafe { vaesenc_last_intrinsic(block, loadu_vaeskey_m256i(self.key[14])) };
        }

        block
    }

    pub fn encrypt(&self, plaintext: &mut [u8], nonce: Nonce192) -> Result<(), AesError> {
        assert_size_ok(plaintext.len(), 1)?;
        let chunk_size = 32;
        let main_len = plaintext.len() / chunk_size * chunk_size;
        let (main, tail) = plaintext.split_at_mut(main_len);

        #[cfg(feature = "cipher_prefetch")]
        warn!("Prefetch issued (speculative memory access – may affect cache side-channels)");

        main.par_chunks_exact_mut(chunk_size)
            .enumerate()
            .for_each(|(i, chunk)| {
                let mut iv = [0u8; 32];

                iv[..12].copy_from_slice(&nonce.0[..12]);
                iv[12..16]
                    .copy_from_slice(&((i as u32).wrapping_mul(2).wrapping_add(1)).to_be_bytes());

                iv[16..28].copy_from_slice(&nonce.0[12..]);
                iv[28..32]
                    .copy_from_slice(&((i as u32).wrapping_mul(2).wrapping_add(2)).to_be_bytes());

                let encrypted_iv = self
                    .encrypt_block(unsafe { _mm256_loadu_si256(iv.as_ptr() as *const __m256i) });

                #[cfg(all(feature = "cipher_prefetch", feature = "cipher-prefetch-warn"))]
                trace!("Prefetch started");
                #[cfg(feature = "cipher_prefetch")]
                unsafe {
                    use core::arch::x86_64::{_MM_HINT_T0, _MM_HINT_T1, _mm_prefetch};
                    _mm_prefetch(chunk.as_ptr() as *const i8, _MM_HINT_T0);
                    _mm_prefetch(chunk.as_ptr() as *const i8, _MM_HINT_T1);
                    _mm_prefetch(chunk.as_ptr() as *const i8, _MM_HINT_T0);
                    _mm_prefetch(chunk.as_ptr() as *const i8, _MM_HINT_T1);
                }
                #[cfg(all(feature = "cipher_prefetch", feature = "cipher-prefetch-warn"))]
                trace!("Prefetch completed");

                let chunk_reg = unsafe { _mm256_loadu_si256(chunk.as_ptr() as *const __m256i) };
                let result = unsafe { _mm256_xor_si256(encrypted_iv.as_mm256i(), chunk_reg) };

                unsafe { _mm256_storeu_si256(chunk.as_mut_ptr() as *mut __m256i, result) };
            });

        if !tail.is_empty() {
            let i = main.len() / chunk_size;
            let mut iv = [0u8; 32];
            iv[..12].copy_from_slice(&nonce.0[12..]);
            iv[12..16].copy_from_slice(&(i as u32 * 2 + 1).to_be_bytes());

            iv[16..28].copy_from_slice(&nonce.0[..12]);
            iv[28..32].copy_from_slice(&(i as u32 * 2 + 2).to_be_bytes());

            let keystream =
                self.encrypt_block(unsafe { _mm256_loadu_si256(iv.as_ptr() as *const __m256i) });

            let mut buf = [0u8; 32];
            unsafe { _mm256_storeu_si256(buf.as_mut_ptr() as *mut __m256i, keystream.as_mm256i()) };

            for j in 0..tail.len() {
                tail[j] ^= buf[j];
            }
        }

        Ok(())
    }

    pub fn decrypt(&self, ciphertext: &mut [u8], nonce: Nonce192) -> Result<(), AesError> {
        self.encrypt(ciphertext, nonce)?;

        Ok(())
    }
}

impl Drop for Vaes256 {
    fn drop(&mut self) {
        #[cfg(feature = "dev-logs")]
        debug!("Dropping AES-256 cipher instance");
        self.key.zeroize();
    }
}

impl Drop for Vaes256CTR {
    fn drop(&mut self) {
        #[cfg(feature = "dev-logs")]
        debug!("Dropping AES-256 CTR cipher instance");
        self.key.zeroize();
    }
}

pub struct Vaes256 {
    key: [__m256i; 15],
}

impl Vaes256 {
    pub fn new<T: AsRef<[u8]>>(key: T) -> Result<Self, AesError> {
        if is_x86_feature_detected!("vaes") {
            #[cfg(feature = "dev-logs")]
            debug!("Created new AES-256 cipher instance");
            let key = key.as_ref();

            if key.len() != 32 {
                return Err(AesError::InvalidPasswordLenght);
            }

            let key = [unsafe { key[..16].load() }, unsafe { key[16..].load() }];

            let keys = AES_NI.expand_aes256_key(key);
            let key = storeu_keys_256(keys);

            let mut rk256: [__m256i; 15] = unsafe { core::mem::zeroed() };
            for i in 0..15 {
                rk256[i] = unsafe { _mm256_broadcastsi128_si256(key[i]) };
            }

            Ok(Self { key: rk256 })
        } else {
            return Err(AesError::VaesNotSupported);
        }
    }

    #[inline(always)]
    fn encrypt_block(&self, mut plaintext: __m256i) -> __vaes256i {
        plaintext = unsafe { _mm256_xor_si256(plaintext, self.key[0]) };
        let mut block = loadu_vaes256_mm256i(plaintext);

        #[cfg(feature = "vaes_asm_cipher")]
        {
            for i in 1..14 {
                block = unsafe { vaesenc_asm(block, loadu_vaeskey_m256i(self.key[i])) };
            }
            block = unsafe { vaesenc_last_asm(block, loadu_vaeskey_m256i(self.key[14])) };
        }

        #[cfg(not(feature = "vaes_asm_cipher"))]
        {
            for i in 1..14 {
                block = unsafe { vaesenc_intrinsic(block, loadu_vaeskey_m256i(self.key[i])) };
            }
            block = unsafe { vaesenc_last_intrinsic(block, loadu_vaeskey_m256i(self.key[14])) };
        }

        block
    }

    fn ctr(&self, src: &mut [u8], nonce: Nonce192) -> Result<(), AesError> {
        assert_size_ok(src.len(), 2)?;
        let chunk_size = 32;
        let main_len = src.len() / chunk_size * chunk_size;
        let (main, tail) = src.split_at_mut(main_len);

        #[cfg(feature = "cipher_prefetch")]
        warn!("Prefetch issued (speculative memory access – may affect cache side-channels)");

        main.par_chunks_exact_mut(chunk_size)
            .enumerate()
            .for_each(|(i, chunk)| {
                let mut iv = [0u8; 32];

                iv[..12].copy_from_slice(&nonce.0[..12]);
                iv[12..16]
                    .copy_from_slice(&((i as u32).wrapping_mul(2).wrapping_add(2)).to_be_bytes());

                iv[16..28].copy_from_slice(&nonce.0[12..]);
                iv[28..32]
                    .copy_from_slice(&((i as u32).wrapping_mul(2).wrapping_add(3)).to_be_bytes());

                let encrypted_iv = self
                    .encrypt_block(unsafe { _mm256_loadu_si256(iv.as_ptr() as *const __m256i) });

                #[cfg(all(feature = "cipher_prefetch", feature = "cipher-prefetch-warn"))]
                trace!("Prefetch started");
                #[cfg(feature = "cipher_prefetch")]
                unsafe {
                    use core::arch::x86_64::{_MM_HINT_T0, _MM_HINT_T1, _mm_prefetch};
                    _mm_prefetch(chunk.as_ptr() as *const i8, _MM_HINT_T0);
                    _mm_prefetch(chunk.as_ptr() as *const i8, _MM_HINT_T1);
                    _mm_prefetch(chunk.as_ptr() as *const i8, _MM_HINT_T0);
                    _mm_prefetch(chunk.as_ptr() as *const i8, _MM_HINT_T1);
                }
                #[cfg(all(feature = "cipher_prefetch", feature = "cipher-prefetch-warn"))]
                trace!("Prefetch completed");

                let chunk_reg = unsafe { _mm256_loadu_si256(chunk.as_ptr() as *const __m256i) };
                let result = unsafe { _mm256_xor_si256(encrypted_iv.as_mm256i(), chunk_reg) };

                unsafe { _mm256_storeu_si256(chunk.as_mut_ptr() as *mut __m256i, result) };
            });

        if !tail.is_empty() {
            let i = main.len() / chunk_size;
            let mut iv = [0u8; 32];
            iv[..12].copy_from_slice(&nonce.0[..12]);
            iv[12..16].copy_from_slice(&(i as u32 * 2 + 2).to_be_bytes());

            iv[16..28].copy_from_slice(&nonce.0[12..]);
            iv[28..32].copy_from_slice(&(i as u32 * 2 + 3).to_be_bytes());

            let keystream =
                self.encrypt_block(unsafe { _mm256_loadu_si256(iv.as_ptr() as *const __m256i) });

            let mut buf = [0u8; 32];
            unsafe { _mm256_storeu_si256(buf.as_mut_ptr() as *mut __m256i, keystream.as_mm256i()) };

            for j in 0..tail.len() {
                tail[j] ^= buf[j];
            }
        }

        Ok(())
    }

    #[inline(always)]
    pub fn compute_tag_vaes(&self, aad: &[u8], nonce: [u8; 12], ct: &[u8]) -> [u8; 16] {
        let mut pair = [0u8; 32];
        pair[16..28].copy_from_slice(&nonce);
        pair[28..32].copy_from_slice(&1u32.to_be_bytes());

        let ks_pair =
            self.encrypt_block(unsafe { _mm256_loadu_si256(pair.as_ptr() as *const __m256i) });

        let mut buf = [0u8; 32];
        unsafe { _mm256_storeu_si256(buf.as_mut_ptr() as *mut __m256i, ks_pair.as_mm256i()) };
        let (auth_key, enc_j0) = (&buf[0..16], &buf[16..32]);

        let mut ghash = GHash::new(Key::<GHash>::from_slice(auth_key));
        ghash.update_padded(aad);
        ghash.update_padded(ct);

        let mut lengths = [0u8; 16];
        lengths[..8].copy_from_slice(&(aad.len() as u64 * 8).to_be_bytes());
        lengths[8..].copy_from_slice(&(ct.len() as u64 * 8).to_be_bytes());
        ghash.update(&[lengths.into()]);

        let s = ghash.finalize();

        let mut tag = [0u8; 16];
        for (t, (a, b)) in tag.iter_mut().zip(enc_j0.iter().zip(s.as_slice())) {
            *t = *a ^ *b;
        }
        tag
    }

    pub fn encrypt(&self, plaintext: &mut [u8], nonce: Nonce192) -> Result<Tag128, AesError> {
        self.ctr(plaintext, nonce)?;
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes.copy_from_slice(&nonce.0[..12]);

        Ok(Tag128::from_array(self.compute_tag_vaes(
            &[],
            nonce_bytes,
            &plaintext,
        )))
    }

    pub fn encrypt_with_aad(
        &self,
        plaintext: &mut [u8],
        nonce: Nonce192,
        aad: &[u8],
    ) -> Result<Tag128, AesError> {
        self.ctr(plaintext, nonce)?;
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes.copy_from_slice(&nonce.0[..12]);

        Ok(Tag128::from_array(self.compute_tag_vaes(
            aad,
            nonce_bytes,
            &plaintext,
        )))
    }

    pub fn decrypt(
        &self,
        ciphertext: &mut [u8],
        nonce: Nonce192,
        tag: &Tag128,
    ) -> Result<(), AesError> {
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes.copy_from_slice(&nonce.0[..12]);
        let mut computed_tag = self.compute_tag_vaes(&[], nonce_bytes, ciphertext);

        if constant_time_ops::compare_bytes(tag.as_bytes(), &computed_tag) == 0 {
            computed_tag.zeroize();
            return Err(AesError::AuthenticationFailed);
        }
        computed_tag.zeroize();

        self.ctr(ciphertext, nonce)?;

        Ok(())
    }

    pub fn decrypt_with_aad(
        &self,
        ciphertext: &mut [u8],
        nonce: Nonce192,
        tag: &Tag128,
        aad: &[u8],
    ) -> Result<(), AesError> {
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes.copy_from_slice(&nonce.0[..12]);
        let mut computed_tag = self.compute_tag_vaes(aad, nonce_bytes, ciphertext);

        if constant_time_ops::compare_bytes(tag.as_bytes(), &computed_tag) == 0 {
            computed_tag.zeroize();
            return Err(AesError::AuthenticationFailed);
        }
        computed_tag.zeroize();

        self.ctr(ciphertext, nonce)?;

        Ok(())
    }
}

#[test]
fn test_vaes_encrypt_aesgcm_decrypt() {
    use crate::{
        ciphers::vaes_cipher::{Nonce192, Vaes256},
        rng::HardwareRNG,
    };
    use aes_gcm::{
        Aes256Gcm,
        aead::{AeadInPlace, KeyInit, generic_array::GenericArray},
    };

    let key = [1u8; 32];

    let vaes = Vaes256::new(&key).unwrap();

    let aes_gcm = Aes256Gcm::new(GenericArray::from_slice(&key));

    let nonce192 = Nonce192::generate_nonce(&mut HardwareRNG);
    let mut nonce96_bytes = [0u8; 12];
    nonce96_bytes.copy_from_slice(&nonce192.0[..12]);

    let mut plaintext = (0u8..255).collect::<Vec<_>>();

    let tag = vaes.encrypt(&mut plaintext, nonce192).unwrap();

    let mut ct_and_tag = plaintext.clone();
    ct_and_tag.extend_from_slice(tag.as_bytes());

    let aes_nonce = aes_gcm::aead::generic_array::GenericArray::from_slice(&nonce96_bytes);

    let mut decrypted = ct_and_tag.clone();
    aes_gcm
        .decrypt_in_place(aes_nonce, b"", &mut decrypted)
        .expect("AES-GCM decrypt failed");

    assert_eq!(decrypted, (0u8..255).collect::<Vec<_>>());

    println!("✅ VAES encrypt → AES-GCM decrypt successful!");
}
