#![no_main]
use libfuzzer_sys::fuzz_target;
use x86_crypto::{
    CryptoRNG, HardwareRNG,
    aes_cipher::{Aes256, Aes256CTR, Nonce},
    allocator::SecureVec,
};

fuzz_target!(|data: &[u8]| {
    // SecureVec edge cases
    if data.len() > 0 && data.len() < 100_000 {
        // Capacity edge cases
        if let Ok(mut vec) = SecureVec::with_capacity(data.len()) {
            let _ = vec.extend_from_slice(data);

            // Random operations
            if data[0] % 3 == 0 {
                let _ = vec.push(42);
            }

            // Boundary test
            for i in 0..vec.len() {
                vec[i] = vec[i].wrapping_add(1);
            }

            vec.zeroize();
        }

        // Off-by-one test
        if let Ok(mut vec2) = SecureVec::with_capacity(data.len() + 1) {
            let _ = vec2.extend_from_slice(data);
            let _ = vec2.push(0xFF);
            vec2.zeroize();
        }
    }

    // AES fuzzing
    if data.len() >= 32 {
        let key = &data[..32];
        let rest = &data[32..];

        // CTR mode
        if let Ok(cipher) = Aes256CTR::new(&key) {
            let nonce = Nonce::from_bytes([0; 12]);
            let encrypted = cipher.encrypt(rest, nonce.clone());
            let decrypted = cipher.decrypt(&encrypted, nonce);

            // Verify roundtrip
            assert_eq!(rest, decrypted.as_slice());
        }

        // GCM mode with AAD
        if rest.len() > 16 {
            if let Ok(cipher) = Aes256::new(&key) {
                let nonce = Nonce::from_bytes([0; 12]);
                let aad = &rest[..16];
                let plaintext = &rest[16..];

                let encrypted = cipher.encrypt_with_aad(plaintext, nonce.clone(), aad);
                if let Ok(decrypted) = cipher.decrypt_with_aad(&encrypted, nonce, aad) {
                    assert_eq!(plaintext, decrypted.as_slice());
                }
            }
        }
    }

    // Chaos testing - multiple operations
    if data.len() > 64 {
        if let Ok(mut vec) = SecureVec::with_capacity(64) {
            for chunk in data.chunks(8) {
                let _ = vec.extend_from_slice(chunk);
            }
            vec.zeroize();
        }
    }
});
