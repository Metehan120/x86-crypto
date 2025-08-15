use core::slice::from_raw_parts_mut;

#[cfg(feature = "dev-logs")]
use log::trace;
use thiserror_no_std::Error;

use crate::{memory::zeroize::Zeroizeable, rng::CryptoRNG, rng::HardwareRNG};

#[cfg(feature = "aes_cipher")]
use crate::ciphers::aes_cipher::{Aes256CTR, AesError, Nonce96};

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
    pub fn new() -> Result<Self, crate::rng::RngErrors> {
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

    #[inline(always)]
    pub unsafe fn scramble_raw(&self, data: *mut u8, size: usize) -> bool {
        let buf = unsafe { from_raw_parts_mut(data, size) };

        self.scramble(buf);
        true
    }

    #[inline(always)]
    pub unsafe fn descramble_raw(&self, data: *mut u8, size: usize) -> bool {
        let buf = unsafe { from_raw_parts_mut(data, size) };

        self.scramble(buf);
        true
    }
}

#[derive(Debug, Error)]
pub enum AesScramblerError {
    #[error("Error: {0}")]
    Error(String),
}

#[cfg(feature = "aes_cipher")]
/// AES-based memory scrambler for runtime data protection.
///
/// Note:
/// - This scrambler does not protect against kernel-level attackers.
/// - Key and nonce are stored in process memory.
/// - Use with SecureVec for best effect.
///
/// # USE IT AT YOUR OWN RISK
///
/// Obfuscates sensitive data in memory using hardware-generated AES keys.
/// Protects against memory dumps and reduces plaintext exposure time.
pub struct AesMemoryScrambler {
    aes: Aes256CTR,
    nonce: Nonce96,
}

#[cfg(feature = "aes_cipher")]
impl AesMemoryScrambler {
    pub fn new() -> Result<Self, AesScramblerError> {
        let mut key = [0u8; 32];
        HardwareRNG
            .try_fill_by(&mut key)
            .map_err(|e| AesScramblerError::Error(e.to_string()))?;
        let aes = Aes256CTR::new(&key).map_err(|e| AesScramblerError::Error(e.to_string()))?;
        key.zeroize();
        let nonce = Nonce96::generate_nonce(&mut HardwareRNG);
        Ok(Self { aes, nonce })
    }

    #[inline(always)]
    pub fn scramble(&self, data: &mut [u8]) -> Result<(), AesError> {
        self.aes.encrypt_inplace(data, self.nonce)
    }

    #[inline(always)]
    pub fn descramble(&self, data: &mut [u8]) -> Result<(), AesError> {
        self.aes.decrypt_inplace(data, self.nonce)
    }

    #[inline(always)]
    pub unsafe fn scramble_raw(&self, data: *mut u8, size: usize) -> bool {
        let buf = unsafe { from_raw_parts_mut(data, size) };

        self.aes.encrypt_inplace(buf, self.nonce).is_ok()
    }

    #[inline(always)]
    pub unsafe fn descramble_raw(&self, data: *mut u8, size: usize) -> bool {
        let buf = unsafe { from_raw_parts_mut(data, size) };

        self.aes.decrypt_inplace(buf, self.nonce).is_ok()
    }
}

impl Drop for MemoryScrambler {
    fn drop(&mut self) {
        self.xor_key.zeroize();
    }
}

impl Drop for AesMemoryScrambler {
    fn drop(&mut self) {
        self.nonce.0.zeroize();
    }
}
