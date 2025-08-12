use crate::{
    CryptoRNG,
    ciphers::aes_cipher::AesError,
    constant_time_ops,
    ni_instructions::{
        LoadRegister,
        aesni::{AES, AES_NI, storeu_keys_256},
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

pub struct Vaes256CTR {
    key: [__m256i; 15],
}

impl Vaes256CTR {
    pub fn new(key: &[u8; 32]) -> Self {
        #[cfg(feature = "dev-logs")]
        debug!("Created new AES-256 cipher instance");

        let key = [unsafe { key[..16].load() }, unsafe { key[16..].load() }];

        let keys = AES_NI.expand_aes256_key(key);
        let key = storeu_keys_256(keys);

        let mut rk256: [__m256i; 15] = unsafe { core::mem::zeroed() };
        for i in 0..15 {
            rk256[i] = unsafe { _mm256_broadcastsi128_si256(key[i]) };
        }

        Self { key: rk256 }
    }

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

    pub fn encrypt(&self, plaintext: &mut [u8], nonce: Nonce192) {
        let (n0, n1) = nonce.0.split_at(12);

        let len = plaintext.len();
        let (chunks, tail) = plaintext.as_mut().split_at_mut(len & !31);

        chunks
            .par_chunks_exact_mut(32)
            .enumerate()
            .for_each(|(i, chunk)| {
                let ctr0 = i.wrapping_add(1);
                let ctr1 = ctr0.wrapping_add(1);

                let mut iv = [0u8; 32];
                iv[0..12].copy_from_slice(n0);
                iv[12..16].copy_from_slice(&(ctr0 as u32).to_be_bytes());
                iv[16..28].copy_from_slice(n1);
                iv[28..32].copy_from_slice(&(ctr1 as u32).to_be_bytes());

                let ks = self
                    .encrypt_block(unsafe { _mm256_loadu_si256(iv.as_ptr() as *const __m256i) });

                #[cfg(feature = "cipher_prefetch")]
                unsafe {
                    use core::arch::x86_64::{_MM_HINT_T0, _mm_prefetch};
                    _mm_prefetch(chunk.as_ptr().add(128) as *const i8, _MM_HINT_T0);
                    _mm_prefetch(chunk.as_ptr().add(256) as *const i8, _MM_HINT_T0);
                }

                let m = unsafe { _mm256_loadu_si256(chunk.as_ptr() as *const __m256i) };
                let c = unsafe { _mm256_xor_si256(ks.as_mm256i(), m) };
                unsafe { _mm256_storeu_si256(chunk.as_mut_ptr() as *mut __m256i, c) };
            });

        if !tail.is_empty() {
            let pairs = chunks.len() / 32;
            let ctr0 = (2 * pairs as u64) + 2;
            let ctr1 = ctr0 + 1;

            let mut iv = [0u8; 32];
            iv[0..12].copy_from_slice(n0);
            iv[12..16].copy_from_slice(&(ctr0 as u32).to_be_bytes());
            iv[16..28].copy_from_slice(n1);
            iv[28..32].copy_from_slice(&(ctr1 as u32).to_be_bytes());

            let ks =
                self.encrypt_block(unsafe { _mm256_loadu_si256(iv.as_ptr() as *const __m256i) });

            let mut buf = [0u8; 32];
            unsafe { _mm256_storeu_si256(buf.as_mut_ptr() as *mut __m256i, ks.as_mm256i()) };
            for (b, k) in tail.iter_mut().zip(buf.iter()) {
                *b ^= *k;
            }
        }
    }

    pub fn decrypt(&self, ciphertext: &mut [u8], nonce: Nonce192) {
        self.encrypt(ciphertext, nonce);
    }
}

pub struct Vaes256 {
    key: [__m256i; 15],
}

impl Vaes256 {
    pub fn new(key: &[u8; 32]) -> Self {
        #[cfg(feature = "dev-logs")]
        debug!("Created new AES-256 cipher instance");

        let key = [unsafe { key[..16].load() }, unsafe { key[16..].load() }];

        let keys = AES_NI.expand_aes256_key(key);
        let key = storeu_keys_256(keys);

        let mut rk256: [__m256i; 15] = unsafe { core::mem::zeroed() };
        for i in 0..15 {
            rk256[i] = unsafe { _mm256_broadcastsi128_si256(key[i]) };
        }

        Self { key: rk256 }
    }

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

    fn ctr(&self, plaintext: &mut [u8], nonce: Nonce192) {
        let (n0, n1) = nonce.0.split_at(12);

        let len = plaintext.len();
        let (chunks, tail) = plaintext.as_mut().split_at_mut(len & !31);

        chunks
            .par_chunks_exact_mut(32)
            .enumerate()
            .for_each(|(i, chunk)| {
                let ctr0 = i.wrapping_add(2);
                let ctr1 = ctr0.wrapping_add(1);

                let mut iv = [0u8; 32];
                iv[0..12].copy_from_slice(n0);
                iv[12..16].copy_from_slice(&(ctr0 as u32).to_be_bytes());
                iv[16..28].copy_from_slice(n1);
                iv[28..32].copy_from_slice(&(ctr1 as u32).to_be_bytes());

                let ks = self
                    .encrypt_block(unsafe { _mm256_loadu_si256(iv.as_ptr() as *const __m256i) });

                #[cfg(feature = "cipher_prefetch")]
                unsafe {
                    use core::arch::x86_64::{_MM_HINT_T0, _mm_prefetch};
                    _mm_prefetch(chunk.as_ptr().add(128) as *const i8, _MM_HINT_T0);
                    _mm_prefetch(chunk.as_ptr().add(256) as *const i8, _MM_HINT_T0);
                }

                let m = unsafe { _mm256_loadu_si256(chunk.as_ptr() as *const __m256i) };
                let c = unsafe { _mm256_xor_si256(ks.as_mm256i(), m) };
                unsafe { _mm256_storeu_si256(chunk.as_mut_ptr() as *mut __m256i, c) };
            });

        if !tail.is_empty() {
            let pairs = chunks.len() / 32;
            let ctr0 = (2 * pairs as u64) + 2;
            let ctr1 = ctr0 + 1;

            let mut iv = [0u8; 32];
            iv[0..12].copy_from_slice(n0);
            iv[12..16].copy_from_slice(&(ctr0 as u32).to_be_bytes());
            iv[16..28].copy_from_slice(n1);
            iv[28..32].copy_from_slice(&(ctr1 as u32).to_be_bytes());

            let ks =
                self.encrypt_block(unsafe { _mm256_loadu_si256(iv.as_ptr() as *const __m256i) });

            let mut buf = [0u8; 32];
            unsafe { _mm256_storeu_si256(buf.as_mut_ptr() as *mut __m256i, ks.as_mm256i()) };
            for (b, k) in tail.iter_mut().zip(buf.iter()) {
                *b ^= *k;
            }
        }
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

    pub fn encrypt(&self, plaintext: &mut [u8], nonce: Nonce192) -> [u8; 16] {
        self.ctr(plaintext, nonce);
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes.copy_from_slice(&nonce.0[..12]);

        self.compute_tag_vaes(&[], nonce_bytes, &plaintext)
    }

    pub fn decrypt(
        &self,
        ciphertext: &mut [u8],
        nonce: Nonce192,
        tag: &[u8; 16],
    ) -> Result<(), AesError> {
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes.copy_from_slice(&nonce.0[..12]);
        let computed_tag = self.compute_tag_vaes(&[], nonce_bytes, ciphertext);

        #[cfg(debug_assertions)]
        if constant_time_ops::compare_bytes(tag, &computed_tag) == 0 {
            return Err(AesError::AuthenticationFailed);
        }

        self.ctr(ciphertext, nonce);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::HardwareRNG;

    use super::*;

    #[test]
    fn test_encrypt() {
        let key = [1u8; 32];
        let cipher = Vaes256CTR::new(&key);
        let nonce = Nonce192::generate_nonce(&mut HardwareRNG);
        let mut plaintext = vec![0u8; 1024 * 1024 * 1024];
        let tag = cipher.encrypt(&mut plaintext, nonce);
        cipher.decrypt(&mut plaintext, nonce);

        println!("Tag: {:?}", tag);
    }
}
