#[cfg(feature = "dev-logs")]
use log::trace;

use crate::{CryptoRNG, rng::HardwareRNG};

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
