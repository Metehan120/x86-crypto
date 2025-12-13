use crate::{hash::sha::ShaFamily, memory::zeroize::Zeroizeable};

pub static BLOCK_SIZE: usize = 64;

pub struct HMAC<const SIZE: usize, Sha: ShaFamily<SIZE> + Clone> {
    sha: Sha,
}

impl<const SIZE: usize, Sha: ShaFamily<SIZE> + Clone> HMAC<SIZE, Sha> {
    pub fn new() -> Self {
        Self { sha: Sha::new() }
    }

    pub fn finalize(&mut self, key: &[u8], msg: &[u8]) -> [u8; SIZE] {
        let mut k = [0u8; 64];

        if key.len() > BLOCK_SIZE {
            let h = self.sha.hash(key);
            k[..h.len()].copy_from_slice(&h);
        } else {
            k[..key.len()].copy_from_slice(key);
        }

        let mut k0 = k.clone();

        k.iter_mut().for_each(|b| {
            *b ^= 0x36;
        });

        let mut inner_hash = self.sha.clone();
        inner_hash.update(&k);
        inner_hash.update(msg);
        let inner = inner_hash.finalize();

        k0.iter_mut().for_each(|b| {
            *b ^= 0x5c;
        });

        let mut msg = [&k0, inner.as_slice()].concat();
        let outter = self.sha.hash(&msg);

        msg.zeroize();
        k.zeroize();
        k0.zeroize();

        outter
    }
}
