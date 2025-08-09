# x86-crypto — High-Performance Hardware-Accelerated Cryptography in Rust

**x86-crypto** is a Rust cryptography library that is written from scratch and designed for modern x86\_64 processors with AES-NI, VAES, PCLMULQDQ, RDRAND, and RDSEED support. It provides secure, hardware-accelerated implementations of AES (CTR, GCM), ChaCha20, hardware RNG, secure memory allocation, and utilities for constant-time operations.

---

## Features

* **AES-CTR / AES-GCM** with AES-NI / VAES acceleration
* **GHASH** using PCLMULQDQ
* **ChaCha20** (hardware-assisted RNG integration)
* **SecureVec**: mlock-based, zeroing, capacity-checked secure allocator
* **Hardware RNG**: RDRAND, RDSEED support
* **TLS Handler** with rustls integration
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

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
x86-crypto = { git = "https://github.com/Metehan120/x86-crypto" }
```

---

## Example Usage

```rust
use x86_crypto::aes_cipher::Aes256Ctr;
use x86_crypto::HardwareRandomizable;

fn main() {
    // Generate a random key and nonce
    let key = x86_crypto::rand_key::<32>();
    let nonce = x86_crypto::rand_key::<16>();

    let cipher = Aes256Ctr::new(&key, &nonce);
    let plaintext = b"Hello, world!";
    let ciphertext = cipher.encrypt(plaintext);

    println!("Ciphertext: {:x?}", ciphertext);
}
```

---

## Cargo Features

| Feature             | Description                                 |
| ------------------- | ------------------------------------------- |
| `secure_memory`     | Enables mlock-based SecureVec allocator     |
| `aes_cipher`        | AES-CTR and AES-ECB support                 |
| `aes_gcm`           | AES-GCM mode (requires `aes_cipher`)        |
| `experimental_vaes` | VAES-based accelerated AES (nightly only)   |
| `tls`               | Enables TLS handler integration with rustls |
| `all_aes`           | Enables all AES modes                       |
| `compression_test`  | LZ4 compression benchmarks for testing      |
| ...                 | And more                                    |

---

## Security

* All AES operations are constant-time by design (hardware instructions)
* Secure memory allocator uses `mlock` and zeroization
* GHASH implementation is provided by the `ghash` crate — any security issues in GHASH are outside the scope of this library
* Includes RFC and NIST test vectors for verification

**Disclaimer:** While this library follows best practices and passes standard test vectors, it has **not** undergone a formal third-party audit (e.g., NCC Group). Use at your own risk — the author accepts no responsibility for any outcome.

---

## License

Licensed under MIT.
