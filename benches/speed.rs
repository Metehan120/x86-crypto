use std::hint::black_box;

use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::AeadMutInPlace};
use criterion::{Criterion, criterion_group, criterion_main};
use x86_crypto::{
    ciphers::aes_cipher::{Aes256CTR, Nonce96},
    key::rand_key,
    rng::{CryptoRNG, HardwareRNG},
};

fn bench_ctr(c: &mut Criterion) {
    let aes = Aes256CTR::new(&rand_key::<32>().unwrap()).unwrap();
    let mut data = vec![0u8; 1024 * 1024 * 100];
    let mut key = [0u8; 32];
    HardwareRNG.try_fill_by(&mut key).unwrap();

    let mut gcm = Aes256Gcm::new(&key.into());
    let nonce = [0x12; 12];
    let mut nonce2 = [0u8; 24];
    nonce2[..12].copy_from_slice(&nonce);
    nonce2[12..].copy_from_slice(&nonce);

    let x86_nonce = Nonce96::from_bytes(nonce);
    let nonce = Nonce::from_slice(&nonce);

    c.bench_function("aes-gcm", |b| {
        b.iter(|| {
            gcm.encrypt_in_place(nonce, "".as_bytes(), &mut data)
                .unwrap()
        });
    });

    c.bench_function("x86-crypto", |b| {
        b.iter(|| aes.encrypt_inplace(black_box(&mut data), x86_nonce));
    });
}

criterion_group!(benches, bench_ctr);
criterion_main!(benches);
