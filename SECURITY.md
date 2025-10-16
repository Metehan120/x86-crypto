# Security Policy

## Supported Versions

I aim to support the latest `main` branch and the most recent tagged release.
Security patches will only be backported if absolutely necessary.

| Version   | Supported          |
| --------- | ------------------ |
| < 0.2.0-alpha | ❌                 |
| main      | ✅                 |
| Older     | ❌                 |

---

## Reporting a Vulnerability

If you discover a security issue in **x86-crypto**, please **do not** open a public GitHub issue.
Instead, report it responsibly by contacting the maintainer:

- Maintainer: **Metehan Eyyub Zaferoğlu**
- Email: **metehan@zaferoglu.me**

I take security issues seriously and will respond as quickly as possible.
When reporting, please include:

1. A detailed description of the issue.
2. Steps to reproduce the vulnerability (if applicable).
3. Any potential impact or severity assessment.

---

## Handling of Vulnerabilities

1. Vulnerabilities reported privately will be acknowledged within **48 hours**.
2. An initial assessment and timeline for a fix will usually be shared within **a few days** (often sooner if the issue is critical).
3. Fixes will be developed and tested in private until a secure release is ready.
4. Security advisories will be published via the GitHub repository.

---

## Best Practices

While using **x86-crypto**, please:

- Always run the latest release for security patches.
- Avoid enabling experimental features (like `experimental_tls_decryption`) in production unless you fully understand the risks.
- Do not rely on this library as your sole security measure — defense in depth is recommended.

---

## Disclaimer

This project has **not** undergone a formal third-party security audit.
Use at your own risk — the maintainer accepts no liability for security issues.
