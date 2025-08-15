use core::{
    arch::x86_64::{__m128i, _mm_storeu_si128, _mm_xor_si128},
    ops::Deref,
    sync::atomic::AtomicU64,
};

use ghash::GHash;
#[cfg(all(feature = "cipher_prefetch", feature = "cipher-prefetch-warn"))]
use log::trace;
#[cfg(feature = "cipher_prefetch")]
use log::warn;
use log::{debug, error, info};
use rayon::{
    iter::{IndexedParallelIterator, ParallelIterator},
    slice::ParallelSliceMut,
};
use thiserror_no_std::Error;
use universal_hash::{Key, KeyInit, UniversalHash};

use crate::{
    CryptoRNG, constant_time_ops,
    memory::zeroize::Zeroizeable,
    ni_instructions::aesni::{__rsi256keys, AES, AES_NI, LoadRegister, StoreRegister},
    types,
};

static NONCE_TOKEN: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
#[deprecated(since = "0.2.0", note = "Use [`Nonce96`] instead")]
/// Will be removed in 0.3.0
pub struct Nonce([u8; 12]);
#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub struct Nonce96(pub [u8; 12]);

macro_rules! impl_nonce {
    ($nonce:ident) => {
        #[allow(deprecated)]
        impl $nonce {
            pub fn generate_nonce(generator: &mut impl CryptoRNG) -> $nonce {
                #[cfg(feature = "dev-logs")]
                trace!("Generating Nonce");
                let mut nonce = [0u8; 12];
                generator.fill_by_unchecked(&mut nonce);
                #[cfg(feature = "dev-logs")]
                trace!("Generated Nonce: {:02X?}", nonce);
                $nonce(nonce)
            }

            pub fn generate_with_token(generator: &mut impl CryptoRNG) -> ($nonce, u64) {
                #[cfg(feature = "dev-logs")]
                trace!("Generating Nonce");
                let mut nonce = [0u8; 12];
                generator.fill_by_unchecked(&mut nonce);
                let generated = $nonce(nonce);
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

            pub fn from_bytes(bytes: [u8; 12]) -> $nonce {
                $nonce(bytes)
            }

            pub fn as_slice(&self) -> &[u8] {
                &self.0
            }

            pub fn to_vec(&self) -> Vec<u8> {
                self.as_slice().to_vec()
            }
        }
    };
}

impl_nonce!(Nonce);
impl_nonce!(Nonce96);

types! {
    #[deprecated(
        since = "0.2.0",
        note = "Use [`Tag128`] instead"
    )]
    /// Will be removed in 0.3.0
    type Tag: [u8; 16];

    type Tag128: [u8; 16];
}

macro_rules! impl_tag {
    ($tag:ident) => {
        #[allow(deprecated)]
        impl PartialEq for $tag {
            fn eq(&self, other: &Self) -> bool {
                constant_time_ops::compare_bytes(&self.0, &other.0) == 1
            }
        }

        #[allow(deprecated)]
        impl Drop for $tag {
            fn drop(&mut self) {
                self.0.zeroize();
            }
        }

        #[allow(deprecated)]
        impl AsRef<[u8]> for $tag {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        #[allow(deprecated)]
        impl From<[u8; 16]> for $tag {
            fn from(arr: [u8; 16]) -> Self {
                Self(arr)
            }
        }

        #[allow(deprecated)]
        impl $tag {
            #[inline]
            pub fn from_array(arr: [u8; 16]) -> Self {
                Self(arr)
            }
            #[inline]
            pub fn try_from_slice(s: &[u8]) -> Option<Self> {
                (s.len() == 16).then(|| {
                    let mut a = [0u8; 16];
                    a.copy_from_slice(s);
                    Self(a)
                })
            }
            #[inline]
            pub fn as_bytes(&self) -> &[u8; 16] {
                &self.0
            }
            #[inline]
            pub fn expose<F, R>(&self, f: F) -> R
            where
                F: FnOnce(&[u8; 16]) -> R,
            {
                f(&self.0)
            }
        }
    };
}

#[allow(deprecated)]
impl Deref for Tag {
    type Target = [u8; 16];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl_tag!(Tag);
impl_tag!(Tag128);

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

#[derive(Debug, Error)]
pub enum AesError {
    #[error("Password lenght must be 32")]
    InvalidPasswordLenght,
    #[error("Max size exceeded for CTR: Max {0}, Got {1}")]
    MaxSizeExceeded(u64, u64),
    #[error("Data does not include GCM tag")]
    InvalidLength,
    #[error("Cannot Decrypt, Authentication failed")]
    AuthenticationFailed,
    #[error("AES-NI not supported on this device")]
    AesNiNotSupported,
    #[error("VAES not supported on this device")]
    VaesNotSupported,
}

/// This mode was deprecated before it even saw daylight.
/// May it rest in pieces. 🪦
#[deprecated(
    since = "0.1.0",
    note = "ECB mode is insecure for most use-cases. Use AES-GCM or AES-CTR instead."
)]
pub struct Aes256ECB;

/// AES-256 in CTR (Counter) mode using hardware acceleration.
///
/// # Security Notice
/// Uses hardware-accelerated cryptographic primitives and established libraries.
/// While implementation follows standard practices, independent security
/// review is recommended for high-stakes applications.
///
/// # Overview
/// CTR mode turns AES block cipher into a stream cipher by encrypting sequential
/// counter values and XORing with plaintext. This provides several advantages:
/// - Parallelizable encryption/decryption
/// - Random access to encrypted data
/// - No padding required
/// - Encryption and decryption use same operation
///
/// # Security Properties
/// - **Semantic Security**: Same plaintext produces different ciphertext with different nonces
/// - **No Pattern Leakage**: Unlike ECB, identical blocks don't reveal patterns
/// - **Stream Cipher Benefits**: Can encrypt data of any length
/// - **Parallel Processing**: Each block can be processed independently
///
/// # Critical Requirements
/// - **Nonce MUST be unique** for each encryption with the same key
/// - **Never reuse nonce/key pairs** - this breaks semantic security
/// - **Nonce can be public** but must be transmitted with ciphertext
/// - **Key must be cryptographically random** (use `HardwareRNG`)
///
/// # Thread Safety
/// This implementation is thread-safe for read operations. Multiple threads can
/// encrypt different data with the same key simultaneously (with different nonces).
///
/// # Performance
/// - Uses Intel AES-NI for hardware acceleration
/// - Parallel processing with Rayon for multi-core performance
/// - Typical performance: 1-6 GB/s depending on CPU and data size
pub struct Aes256CTR {
    round_keys: __rsi256keys,
}

impl Aes256CTR {
    pub fn new(key: &impl AsRef<[u8]>) -> Result<Self, AesError> {
        if key.as_ref().len() != 32 {
            return Err(AesError::InvalidPasswordLenght);
        }

        let key_registers = [unsafe { key.as_ref()[..16].load() }, unsafe {
            key.as_ref()[16..].load()
        }];
        let round_keys = AES_NI.expand_aes256_key(key_registers);

        Ok(Self { round_keys })
    }

    fn encrypt_block(&self, plaintext: &[u8]) -> __m128i {
        let aes = AES_NI;
        let block = unsafe { plaintext.load() };
        aes.perform_aes256_rounds_block(&self.round_keys, block)
    }

    pub fn encrypt<T: AsRef<[u8]>>(&self, src: T, nonce: Nonce96) -> Result<Vec<u8>, AesError> {
        assert_size_ok(src.as_ref().len(), 1)?;

        let mut data = src.as_ref().to_vec();

        let chunk_size = 16;
        let tail_len = data.len() % chunk_size;
        let main_body_len = data.len() - tail_len;

        let (main_body, tail) = data.split_at_mut(main_body_len);

        #[cfg(feature = "cipher_prefetch")]
        warn!("Prefetch issued (speculative memory access – may affect cache side-channels)");

        main_body
            .par_chunks_exact_mut(16)
            .enumerate()
            .for_each(|(i, chunk)| {
                let mut iv = [0u8; 16];
                iv[..12].copy_from_slice(&nonce.0);
                iv[12..].copy_from_slice(&((i as u32).wrapping_add(1)).to_be_bytes());

                let encrypted_iv = self.encrypt_block(&iv);

                #[cfg(all(feature = "cipher_prefetch", feature = "cipher-prefetch-warn"))]
                trace!("Prefetch started");
                #[cfg(feature = "cipher_prefetch")]
                unsafe {
                    use core::arch::x86_64::{_MM_HINT_T0, _MM_HINT_T1, _mm_prefetch};
                    _mm_prefetch(chunk.as_ptr() as *const i8, _MM_HINT_T0);
                    _mm_prefetch(chunk.as_ptr() as *const i8, _MM_HINT_T1);
                }
                #[cfg(all(feature = "cipher_prefetch", feature = "cipher-prefetch-warn"))]
                trace!("Prefetch completed");

                let chunk_reg = unsafe { chunk.load() };
                let result = unsafe { _mm_xor_si128(encrypted_iv, chunk_reg) };

                unsafe {
                    _mm_storeu_si128(chunk.as_mut_ptr() as *mut __m128i, result);
                }
            });

        if !tail.is_empty() {
            let i = main_body.len() / chunk_size;
            let mut iv = [0u8; 16];
            iv[..12].copy_from_slice(&nonce.0);
            iv[12..].copy_from_slice(&((i as u32).wrapping_add(1)).to_be_bytes());

            let keystream_block = self.encrypt_block(&iv);
            let keystream_bytes = unsafe { keystream_block.store() };

            for j in 0..tail.len() {
                tail[j] ^= keystream_bytes[j];
            }
        }

        Ok(data)
    }

    pub fn encrypt_inplace(&self, src_dst: &mut [u8], nonce: Nonce96) -> Result<(), AesError> {
        assert_size_ok(src_dst.as_mut().len(), 1)?;

        let chunk_size = 16;
        let tail_len = src_dst.as_mut().len() % chunk_size;
        let main_body_len = src_dst.as_mut().len() - tail_len;

        let (main_body, tail) = src_dst.as_mut().split_at_mut(main_body_len);

        #[cfg(feature = "cipher_prefetch")]
        warn!("Prefetch issued (speculative memory access – may affect cache side-channels)");

        main_body
            .as_mut()
            .par_chunks_exact_mut(16)
            .enumerate()
            .for_each(|(i, chunk)| {
                let mut iv = [0u8; 16];
                iv[..12].copy_from_slice(&nonce.0);
                iv[12..].copy_from_slice(&((i as u32).wrapping_add(1)).to_be_bytes());

                let encrypted_iv = self.encrypt_block(&iv);

                #[cfg(all(feature = "cipher_prefetch", feature = "cipher-prefetch-warn"))]
                trace!("Prefetch started");
                #[cfg(feature = "cipher_prefetch")]
                unsafe {
                    use core::arch::x86_64::{_MM_HINT_T0, _MM_HINT_T1, _mm_prefetch};
                    _mm_prefetch(chunk.as_ptr() as *const i8, _MM_HINT_T0);
                    _mm_prefetch(chunk.as_ptr() as *const i8, _MM_HINT_T1);
                }
                #[cfg(all(feature = "cipher_prefetch", feature = "cipher-prefetch-warn"))]
                trace!("Prefetch completed");

                let chunk_reg = unsafe { chunk.load() };
                let result = unsafe { _mm_xor_si128(encrypted_iv, chunk_reg) };

                unsafe {
                    _mm_storeu_si128(chunk.as_mut_ptr() as *mut __m128i, result);
                }
            });

        if !tail.is_empty() {
            let i = main_body.len() / chunk_size;
            let mut iv = [0u8; 16];
            iv[..12].copy_from_slice(&nonce.0);
            iv[12..].copy_from_slice(&((i as u32).wrapping_add(1)).to_be_bytes());

            let keystream_block = self.encrypt_block(&iv);
            let keystream_bytes = unsafe { keystream_block.store() };

            for j in 0..tail.len() {
                tail[j] ^= keystream_bytes[j];
            }
        }

        Ok(())
    }

    pub fn decrypt<T: AsRef<[u8]>>(&self, src: T, nonce: Nonce96) -> Result<Vec<u8>, AesError> {
        self.encrypt(src, nonce)
    }

    pub fn decrypt_inplace(&self, src_dst: &mut [u8], nonce: Nonce96) -> Result<(), AesError> {
        self.encrypt_inplace(src_dst, nonce)
    }
}

#[cfg(feature = "aes_gcm")]
/// AES-256 in GCM (Galois/Counter Mode) - Authenticated Encryption with Associated Data.
///
/// # Security Notice
/// Uses hardware-accelerated cryptographic primitives and established libraries.
/// While implementation follows standard practices, independent security
/// review is recommended for high-stakes applications.
///
/// # Overview
/// GCM combines CTR mode encryption with GHASH authentication, providing both
/// confidentiality and authenticity in a single operation. This is the gold
/// standard for modern symmetric encryption.
///
/// # Security Properties
/// - **Authenticated Encryption**: Provides both confidentiality and authenticity
/// - **Associated Data**: Can authenticate additional data without encrypting it
/// - **Semantic Security**: Same plaintext produces different ciphertext with different nonces
/// - **Integrity Protection**: Detects any tampering with ciphertext or AAD
/// - **Parallel Processing**: Encryption can be parallelized like CTR mode
///
/// # Critical Requirements
/// - **Nonce MUST be unique** for each encryption with the same key
/// - **Never reuse nonce/key pairs** - catastrophic security failure in GCM
/// - **Always verify authentication** before using decrypted data
/// - **Key must be cryptographically random** (use `HardwareRNG`)
/// - **Nonce should be 96-bits (12 bytes)** for optimal security
///
/// # GCM-Specific Security Notes
/// - **Tag forgery resistance**: 128-bit authentication tag provides 2^128 security
/// - **AAD flexibility**: Can authenticate headers, metadata without encryption
/// - **Constant-time verification**: Implementation uses timing-safe tag comparison
/// - **Length limits**: Maximum 2^32 blocks (64GB) per nonce/key pair
///
/// # Authentication Flow
/// 1. Encrypt plaintext using CTR mode
/// 2. Authenticate ciphertext + AAD using GHASH
/// 3. Output: ciphertext || authentication_tag
/// 4. Decryption: verify tag first, then decrypt
///
/// # Performance
/// - Uses Intel AES-NI + hardware acceleration for both AES and GHASH
/// - Parallel encryption with authentication pipelining
/// - Typical performance: 800MB/s - 4GB/s depending on CPU and data size
pub struct Aes256 {
    round_keys: __rsi256keys,
}

#[cfg(feature = "aes_gcm")]
impl Aes256 {
    pub fn new(key: &impl AsRef<[u8]>) -> Result<Self, AesError> {
        if key.as_ref().len() != 32 {
            error!(
                "AES-GCM initialization failed: Invalid key length (got {})",
                key.as_ref().len()
            );

            return Err(AesError::InvalidPasswordLenght);
        }

        #[cfg(feature = "audit-logs")]
        info!("AES-GCM Instance created");

        let key_registers = [unsafe { key.as_ref()[..16].load() }, unsafe {
            key.as_ref()[16..].load()
        }];
        let round_keys = AES_NI.expand_aes256_key(key_registers);

        Ok(Self { round_keys })
    }

    fn encrypt_block(&self, plaintext: &[u8]) -> __m128i {
        let aes = AES_NI;
        let block = unsafe { plaintext.load() };
        aes.perform_aes256_rounds_block(&self.round_keys, block)
    }

    fn ctr_inplace(&self, src: &mut [u8], nonce: &Nonce96) -> Result<(), AesError> {
        assert_size_ok(src.len(), 2)?;

        let chunk_size = 16;
        let tail_len = src.len() % chunk_size;
        let main_body_len = src.len() - tail_len;

        let (main_body, tail) = src.split_at_mut(main_body_len);

        #[cfg(feature = "cipher_prefetch")]
        warn!("Prefetch issued (speculative memory access – may affect cache side-channels)");

        main_body
            .par_chunks_exact_mut(chunk_size)
            .enumerate()
            .for_each(|(i, chunk)| {
                let mut iv = [0u8; 16];
                iv[..12].copy_from_slice(&nonce.0);
                iv[12..].copy_from_slice(&((i as u32).wrapping_add(2)).to_be_bytes());

                #[cfg(all(feature = "cipher_prefetch", feature = "cipher-prefetch-warn"))]
                trace!("Prefetch started");
                #[cfg(feature = "cipher_prefetch")]
                unsafe {
                    use core::arch::x86_64::{_MM_HINT_T0, _MM_HINT_T1, _mm_prefetch};
                    _mm_prefetch(chunk.as_ptr() as *const i8, _MM_HINT_T0);
                    _mm_prefetch(chunk.as_ptr() as *const i8, _MM_HINT_T1);
                }
                #[cfg(all(feature = "cipher_prefetch", feature = "cipher-prefetch-warn"))]
                trace!("Prefetch completed");

                let encrypted_iv = self.encrypt_block(&iv);
                let chunk_reg = unsafe { chunk.load() };
                let result = unsafe { _mm_xor_si128(encrypted_iv, chunk_reg) };

                unsafe { _mm_storeu_si128(chunk.as_mut_ptr() as *mut __m128i, result) };
            });

        if !tail.is_empty() {
            let i = main_body.len() / chunk_size;
            let mut iv = [0u8; 16];
            iv[..12].copy_from_slice(&nonce.0);
            iv[12..].copy_from_slice(&((i as u32).wrapping_add(2)).to_be_bytes());

            let keystream_block = self.encrypt_block(&iv);
            let keystream_bytes = unsafe { keystream_block.store() };

            for j in 0..tail.len() {
                tail[j] ^= keystream_bytes[j];
            }
        }

        #[cfg(feature = "audit-logs")]
        info!("AES-CTR encryption performed on {} bytes", src.len());
        debug!("Chunked: {} bytes, Tail: {} bytes", main_body_len, tail_len);

        Ok(())
    }

    fn compute_tag(&self, aad: &[u8], nonce: [u8; 12], data: &[u8]) -> [u8; 16] {
        use crate::CycleTimer;

        let mut cycle = CycleTimer::new();
        let auth_key = unsafe { self.encrypt_block(&[0u8; 16]).store() };
        let mut ghash = GHash::new(Key::<GHash>::from_slice(&auth_key));
        ghash.update_padded(&aad);
        ghash.update_padded(&data);

        let mut lengths = [0u8; 16];
        lengths[..8].copy_from_slice(&(aad.len() as u64 * 8).to_be_bytes());
        lengths[8..].copy_from_slice(&(data.len() as u64 * 8).to_be_bytes());
        ghash.update(&[lengths.into()]);

        let tag = ghash.finalize();

        let mut tag_block = [0u8; 16];
        tag_block[..12].copy_from_slice(&nonce);
        tag_block[12..].copy_from_slice(&1u32.to_be_bytes());
        let encrypted_counter = unsafe { self.encrypt_block(&tag_block).store() };

        let mut final_tag = [0u8; 16];
        for i in 0..16 {
            final_tag[i] = tag[i] ^ encrypted_counter[i];
        }

        #[cfg(feature = "audit-logs")]
        info!(
            "GCM tag computed successfully in {} cycles",
            cycle.elapsed()
        );

        final_tag
    }

    pub fn encrypt_with_aad<T: AsRef<[u8]>>(
        &self,
        src: T,
        nonce: Nonce96,
        aad: &[u8],
    ) -> Result<Vec<u8>, AesError> {
        use crate::memory::zeroize::Zeroizeable;

        #[cfg(feature = "audit-logs")]
        info!("Starting GCM encryption");
        let mut data = src.as_ref().to_vec();
        self.ctr_inplace(&mut data, &nonce)?;

        let mut final_tag = self.compute_tag(aad, nonce.0, &data);

        data.extend(final_tag);
        #[cfg(feature = "audit-logs")]
        info!("GCM encryption completed");

        final_tag.zeroize();

        Ok(data)
    }

    pub fn encrypt<T: AsRef<[u8]>>(&self, src: T, nonce: Nonce96) -> Result<Vec<u8>, AesError> {
        self.encrypt_with_aad(src, nonce, &[])
    }

    pub fn encrypt_inplace_with_aad(
        &self,
        src_dst: &mut [u8],
        nonce: Nonce96,
        aad: &[u8],
    ) -> Result<Tag128, AesError> {
        #[cfg(feature = "audit-logs")]
        info!("Starting GCM encryption");
        self.ctr_inplace(src_dst.as_mut(), &nonce)?;
        let tag = self.compute_tag(aad, nonce.0, src_dst.as_mut());
        #[cfg(feature = "audit-logs")]
        info!("GCM encryption completed");
        Ok(Tag128::from_array(tag))
    }

    pub fn encrypt_inplace(&self, src_dst: &mut [u8], nonce: Nonce96) -> Result<Tag128, AesError> {
        self.encrypt_inplace_with_aad(src_dst, nonce, &[])
    }

    pub fn decrypt_with_aad<T: AsRef<[u8]>>(
        &self,
        src: T,
        nonce: Nonce96,
        aad: &[u8],
    ) -> Result<Vec<u8>, AesError> {
        use crate::memory::zeroize::Zeroizeable;

        let data = src.as_ref();
        if data.len() < 16 {
            return Err(AesError::InvalidLength);
        }

        #[cfg(feature = "audit-logs")]
        info!("Starting GCM decryption");

        let (ciphertext, received_tag) = data.split_at(data.len() - 16);
        let mut ciphertext = ciphertext.to_vec();

        let mut computed_tag = self.compute_tag(aad, nonce.0, &ciphertext);
        if constant_time_ops::compare_bytes(&received_tag, &computed_tag) == 0 {
            use crate::memory::zeroize::Zeroizeable;

            #[cfg(feature = "dev-logs")]
            debug!("Expected tag: {:02x?}", computed_tag);
            #[cfg(feature = "dev-logs")]
            debug!("Received tag: {:02x?}", received_tag);
            error!("Authentication failed: GCM tag mismatch detected");
            computed_tag.zeroize();
            return Err(AesError::AuthenticationFailed);
        }
        computed_tag.zeroize();

        #[cfg(feature = "audit-logs")]
        info!("GCM decryption completed");

        self.ctr_inplace(&mut ciphertext, &nonce)?;
        Ok(ciphertext)
    }

    pub fn decrypt<T: AsRef<[u8]>>(&self, src: T, nonce: Nonce96) -> Result<Vec<u8>, AesError> {
        self.decrypt_with_aad(src, nonce, &[])
    }

    pub fn decrypt_inplace_with_tag_aad(
        &self,
        src_dst: &mut [u8],
        nonce: Nonce96,
        aad: &[u8],
        tag: Tag128,
    ) -> Result<(), AesError> {
        #[cfg(feature = "audit-logs")]
        info!("Starting GCM decryption");

        let mut computed_tag = self.compute_tag(aad, nonce.0, src_dst.as_mut());
        if constant_time_ops::compare_bytes(tag.as_bytes(), &computed_tag) == 0 {
            #[cfg(feature = "dev-logs")]
            debug!("Expected tag: {:02x?}", computed_tag);
            #[cfg(feature = "dev-logs")]
            debug!("Received tag: {:02x?}", tag.as_bytes());
            error!("Authentication failed: GCM tag mismatch detected");
            computed_tag.zeroize();
            return Err(AesError::AuthenticationFailed);
        }
        computed_tag.zeroize();

        #[cfg(feature = "audit-logs")]
        info!("GCM decryption completed");

        self.ctr_inplace(src_dst.as_mut(), &nonce)
    }

    pub fn decrypt_inplace_with_tag(
        &self,
        src: &mut [u8],
        nonce: Nonce96,
        tag: Tag128,
    ) -> Result<(), AesError> {
        self.decrypt_inplace_with_tag_aad(src, nonce, &[], tag)
    }
}
