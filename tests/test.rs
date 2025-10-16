use x86_crypto::{
    ciphers::{
        self,
        aes_cipher::{Aes256, Aes256CTR, Nonce96},
        general::{Payload, PayloadMut},
        vaes_cipher::{Nonce192, Vaes256CTR},
    },
    memory::{securevec::SecureVec, zeroize::Zeroizeable},
    ni_instructions::aesni::LoadRegister,
    rng::{HWChaCha20Rng, HardwareRNG},
};

#[test]
fn cipher_test() {
    println!("start");
    for _ in 0..5 {
        let mut buffer = vec![0u8; 1024 * 1024 * 1024];
        let vaes = Aes256::new(&[0u8; 32]).unwrap();
        vaes.encrypt_inplace(&mut buffer, Nonce96::generate_nonce(&mut HardwareRNG))
            .unwrap();
    }
}

#[test]
fn memory_test() {
    let mut buffer: SecureVec<u8> = SecureVec::with_capacity(32).unwrap();
    buffer.fill(1).unwrap();

    println!("{:?}", &buffer[..]);
}

#[test]
fn decrypt_rejects_modified_tag() {
    use crate::ciphers::aes_cipher::AesError;
    use crate::ciphers::vaes_cipher::{Nonce192, Vaes256};

    let key = [7u8; 32];
    let vaes = Vaes256::new(&key).unwrap();
    let nonce = Nonce192::generate_nonce(&mut HardwareRNG);
    let mut msg = b"attack at dawn".to_vec();
    let tag = vaes.encrypt_inplace(&mut msg, nonce).unwrap();

    let mut bad_tag = tag;
    bad_tag.as_mut_bytes()[0] ^= 0xFF;

    match vaes.decrypt_inplace(&mut msg, nonce, &bad_tag) {
        Err(AesError::AuthenticationFailed) => {}
        other => panic!("beklenen AuthenticationFailed, ama {:?}", other),
    }
}

#[cfg(target_os = "linux")]
#[test]
fn general() {
    use std::time::Instant;

    env_logger::init();

    let start = Instant::now();
    let mut data = vec![1u8; 256];
    let mut key: SecureVec<u8> = SecureVec::with_capacity(32).unwrap();
    key.fill_random(&mut HWChaCha20Rng::new(true).unwrap())
        .unwrap();
    let mut key2 = SecureVec::with_capacity(32).unwrap();
    key2.fill(0).unwrap();
    key2.copy_from_slice(&key);

    let test = Aes256CTR::new(&key).unwrap();
    let nonce = Nonce96::generate_nonce(&mut HardwareRNG);
    let mut output = test.encrypt(&data, nonce).unwrap();
    test.encrypt_inplace(&mut data, nonce).unwrap();
    println!("{:?}", data);

    let ctr = Vaes256CTR::new(&key).unwrap();
    let mut nonce2 = [0u8; 24];
    nonce2[..12].copy_from_slice(nonce.as_slice());
    nonce2[12..].copy_from_slice(nonce.as_slice());
    let nonce = Nonce192::from_bytes(nonce2);

    ctr.decrypt_inplace(&mut output, nonce).unwrap();

    key.zeroize();
    data.zeroize();

    let mut output = vec![0u32; 256];
    output.zeroize();
    let mut vec = SecureVec::with_capacity(256).unwrap();
    vec.extend_from_slice(&[0u32; 256]).unwrap();

    let data = unsafe { vec![0u8; 16].load_128() };
    let mut data = vec![data; 1024 * 1024];

    data.zeroize();
    println!("{:?}", start.elapsed())
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
            .encrypt(
                Payload {
                    prefetch_mode: ciphers::general::PrefetchMode::Off,
                    aad: aad,
                    msg: &msg,
                },
                Nonce96::from_bytes(nonce),
            )
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
            .decrypt(
                Payload {
                    msg: &ref_out,
                    aad: aad,
                    prefetch_mode: ciphers::general::PrefetchMode::Off,
                },
                Nonce96::from_bytes(nonce),
            )
            .unwrap();
        assert_eq!(dec, msg, "cross-decrypt failed len={len}");

        // inplace API cross-check
        let mut buf = msg.clone();
        let tag = ours
            .encrypt_inplace(
                PayloadMut {
                    prefetch_mode: ciphers::general::PrefetchMode::Off,
                    msg: &mut buf,
                    aad,
                },
                Nonce96::from_bytes(nonce),
            )
            .unwrap();
        // build ct||tag like aes-gcm output
        let mut ours_concat = buf.clone();
        ours_concat.extend_from_slice(tag.as_bytes());
        assert_eq!(ours_concat, ref_out, "inplace vs ref mismatch len={len}");
    }
}
