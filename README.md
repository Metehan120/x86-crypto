# x86-crypto — High-Performance Hardware-Accelerated Cryptography in Rust

**x86-crypto** is a Rust cryptography library that is written from scratch and designed for modern x86\_64 processors with AES-NI, VAES, PCLMULQDQ, RDRAND, and RDSEED support. It provides secure, hardware-accelerated implementations of AES (CTR, GCM), ChaCha20, hardware RNG, secure memory allocation, and utilities for constant-time operations.

---

## Features

* **AES-CTR / AES-GCM** with AES-NI acceleration
* **VAES-GCM / VAES-CTR** (parallelized 2× block CTR + GHASH) for VAES-capable CPUs
* **GHASH** accelerated with PCLMULQDQ
* **ChaCha20** with hardware RNG seeding
* **SecureVec**: `mlock`-based, zeroing, capacity-checked secure allocator
* **Hardware RNG**: RDRAND and RDSEED support
* **TLS Handler** integration with `rustls`
* **Constant-time comparisons** and side-channel resistance
* **Cache control utilities** for security-sensitive operations
* **Feature-gated modular design** — include only what you need

## Supported Architectures

- **x86_64** with:
  - AES-NI
  - PCLMULQDQ
  - RDRAND / RDSEED (for hardware RNG)
  - Optional: VAES (for `experimental_vaes` feature)
- **Tested on**:
  - AMD Ryzen (Zen 1+)
  - Majority of tests performed on Ryzen 5 5600X & Ryzen 5 3600
  - Also verified on Ryzen 3 4100 & Ryzen 3 2200

---

## Speed

Benchmarks were run on **AMD Ryzen 5 5600X**, compiled with `--release`.

| Algorithm | Speed (GB/s) |
|-----------|--------------|
| VAES-CTR  |  9.3         |
| VAES-GCM  |  2.3         |
| AES-CTR   |  4.6         |
| AES-GCM   |  1.8         |

---

## Speed Comparison Against `aes-gcm` crate, 100MB buffer

| Crate                      | Criterion (ms) | Relative Speed  |
|----------------------------|----------------|-----------------|
| aes-gcm                    | 57.6 ms        | baseline        |
| x86-crypto (VAES & AES-NI) | 42.7 ms        | **~35% faster** |

---

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
x86-crypto = { git = "https://github.com/Metehan120/x86-crypto" }
```

---

## Example Usage

```rust
use x86_crypto::ciphers::vaes_cipher::{Vaes256, Nonce128};
use x86_crypto::{HardwareRNG, HardwareRandomizable};

fn main() {
    let key = x86_crypto::rand_key::<32>();
    let nonce = Nonce128::generate_nonce(&mut HardwareRNG);

    let mut data = b"Hello, world!".to_vec();
    let cipher = Vaes256::new(&key);
    cipher.encrypt(&mut data, nonce);

    println!("Ciphertext: {:x?}", data);
}
```
---

## Cargo Features

| Feature             | Description                                 |
| ------------------- | ------------------------------------------- |
| `secure_memory`     | Enables mlock-based SecureVec allocator     |
| `aes_cipher`        | AES-CTR and AES-ECB support                 |
| `aes_gcm`           | AES-GCM mode (requires `aes_cipher`)        |
| `vaes`              | VAES-based accelerated AES                  |
| `tls`               | Enables TLS handler integration with rustls |
| `all_aes`           | Enables all AES modes                       |
| `compression_test`  | LZ4 compression benchmarks for testing      |
| ...                 | And more                                    |

* NOTE: Never use Prefetching in production

---

## Security

* All AES operations are constant-time by design (hardware instructions)
* Secure memory allocator uses `mlock` and zeroization
* GHASH implementation is provided by the `ghash` crate — any security issues in GHASH are outside the scope of this library
* Verified against RFC and NIST test vectors, plus AES-GCM ↔ VAES-GCM cross-tests

**Disclaimer:** While this library follows best practices and passes standard test vectors, it has **not** undergone a formal third-party audit (e.g., NCC Group). Use at your own risk — the author accepts no responsibility for any outcome.

---

## License

Licensed under MIT.

## Maintainer
- Metehan Eyyub Zaferoğlu
- metehan@zaferoglu.me
