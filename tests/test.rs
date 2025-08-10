pub use x86_crypto::*;
use x86_crypto::{
    aes_cipher::{Aes256, Nonce96},
    allocator::SecureVec,
    hw_chacha::HWChaCha20Rng,
    memory_obfuscation::Zeroize,
};

#[test]
fn general() {
    env_logger::init();

    let mut data = vec![0u8; 1024 * 1024];
    let mut key: SecureVec<u8> = SecureVec::with_capacity(32).unwrap();
    key.fill_random(&mut HWChaCha20Rng::new().unwrap()).unwrap();
    let mut key2 = SecureVec::with_capacity(32).unwrap();
    key2.fill(0).unwrap();
    key2.copy_from_slice(&key);

    let test = Aes256::new(&key).unwrap();
    let nonce = Nonce96::generate_nonce(&mut HardwareRNG);
    let mut output = test.encrypt(&data, nonce).unwrap();

    key.zeroize();

    data.zeroize();
    output.zeroize();
}

use aes_gcm::{
    Aes256Gcm,
    aead::{Aead, KeyInit},
};

#[test]
fn compare_with_aes_gcm_no_aad() {
    let key = [0x11u8; 32];
    let nonce = [0x22u8; 12];

    let ours = Aes256::new(&key).unwrap();
    let msg = (0u8..200).collect::<Vec<u8>>();

    // ours: ct||tag
    let out = ours.encrypt(&msg, Nonce96::from_bytes(nonce)).unwrap();
    let (ct_ours, tag_ours) = out.split_at(out.len() - 16);

    // ref
    let ref_cipher = Aes256Gcm::new((&key).into());
    let ref_out = ref_cipher
        .encrypt(aes_gcm::Nonce::from_slice(&nonce), msg.as_slice())
        .unwrap();
    let (ct_ref, tag_ref) = ref_out.split_at(ref_out.len() - 16);

    assert_eq!(ct_ours, ct_ref, "ciphertext mismatch");
    assert_eq!(tag_ours, tag_ref, "tag mismatch");

    // roundtrip both ways
    let dec = ours.decrypt(&out, Nonce96::from_bytes(nonce)).unwrap();
    assert_eq!(dec, msg);

    let ref_dec = ref_cipher
        .decrypt(aes_gcm::Nonce::from_slice(&nonce), ref_out.as_slice())
        .unwrap();
    assert_eq!(ref_dec, msg);
}

#[test]
fn compare_with_aes_gcm_with_aad_and_tails() {
    let key = [0x5Au8; 32];
    let nonce = [0xC3u8; 12];
    let aad = b"associated-data-123";

    let ours = Aes256::new(&key).unwrap();
    for &len in &[0usize, 1, 15, 16, 17, 31, 73, 256] {
        let msg = (0..len).map(|i| i as u8).collect::<Vec<u8>>();

        let out = ours
            .encrypt_with_aad(&msg, Nonce96::from_bytes(nonce), aad)
            .unwrap();
        let (ct_ours, tag_ours) = out.split_at(out.len() - 16);

        let ref_cipher = Aes256Gcm::new((&key).into());
        let ref_out = ref_cipher
            .encrypt(
                aes_gcm::Nonce::from_slice(&nonce),
                aes_gcm::aead::Payload { msg: &msg, aad },
            )
            .unwrap();
        let (ct_ref, tag_ref) = ref_out.split_at(ref_out.len() - 16);

        assert_eq!(ct_ours, ct_ref, "ct mismatch len={len}");
        assert_eq!(tag_ours, tag_ref, "tag mismatch len={len}");

        // verify our decrypt_with_aad accepts ref output as well
        let dec = ours
            .decrypt_with_aad(ref_out.clone(), Nonce96::from_bytes(nonce), aad)
            .unwrap();
        assert_eq!(dec, msg, "cross-decrypt failed len={len}");

        // inplace API cross-check
        let mut buf = msg.clone();
        let tag = ours
            .encrypt_inplace_with_aad(&mut buf, Nonce96::from_bytes(nonce), aad)
            .unwrap();
        // build ct||tag like aes-gcm output
        let mut ours_concat = buf.clone();
        ours_concat.extend_from_slice(tag.as_bytes());
        assert_eq!(ours_concat, ref_out, "inplace vs ref mismatch len={len}");
    }
}
