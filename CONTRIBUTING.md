# Contributing to x86-crypto

First of all, thank you for your interest in contributing to **x86-crypto**!

This project is focused on high-performance, hardware-accelerated cryptography for modern x86\_64 CPUs, and contributions from the community are very welcome. To ensure a smooth and consistent process, please follow the guidelines below.

---

## How to Contribute

1. **Fork the Repository**

   * Create your own copy of the repository by forking it.

2. **Create a Branch**

   * Work on a dedicated feature or fix branch:

3. **Make Your Changes**

   * Follow Rust best practices and ensure your code is clean, efficient, and documented.
   * Use constant-time operations where applicable.

4. **Run Tests**

   * Make sure all existing tests pass:

     ```bash
     cargo test
     ```
   * Add new tests if you are introducing new functionality.

5. **Commit Your Changes**

   * Write clear and descriptive commit messages:

     ```bash
     git commit -m "feat: add secure memory wipe function"
     ```

6. **Push and Open a Pull Request**

   * Push to your fork

   * Open a Pull Request (PR) describing your changes.

---

## Contribution Rules

* **Code Style**: Follow Rust conventions (run `cargo fmt` and `cargo clippy`).
* **Security First**: Do not introduce unsafe code unless absolutely necessary and justified.
* **Documentation**: Update `README.md` or inline documentation if your change introduces new features.
* **Tests**: Every contribution must include test coverage. Security-sensitive code paths require extensive testing.
* **Commit Messages**: Use [Conventional Commits](https://www.conventionalcommits.org/) style where possible (`feat:`, `fix:`, `chore:`, etc.).

---

## Good Practices

* Keep PRs small and focused.
* Before starting work on large features, open an **issue** to discuss the design and implementation.
* Ensure compatibility with supported architectures and CPU instruction sets (AES-NI, VAES, PCLMULQDQ, RDRAND, RDSEED).
* Avoid introducing new dependencies unless absolutely required.
* Be mindful of side-channel resistance and performance regressions.

---

## Security Considerations

If you discover a security issue, **do not** open a public issue. Instead, please contact the maintainer directly.

---

## License

By contributing, you agree that your contributions will be licensed under the MIT license.

---

## Maintainer
- Metehan Eyyub Zaferoğlu
- metehan@zaferoglu.me

---

Thanks again for helping improve **x86-crypto**!
