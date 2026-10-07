# MASTG v2 Notes

In-depth research notes on individual **OWASP MASTG (Mobile Application Security Testing Guide)** test cases for Android, written as a structured study companion rather than a copy of the official guide.

Each `MASTG-TEST-XXXX` document follows the same five-part structure:

1. **Explanation** — what the test checks, why it matters, and the technical background needed to understand it
2. **Tools Used for Testing** — required and supporting tools, plus environment prerequisites
3. **Testing Methodology** — the official MASTG steps *and* alternative/complementary approaches using tools outside the official toolchain (grep/ripgrep, Semgrep, CodeQL, Frida, apktool, jadx, etc.)
4. **Recommendations** — concrete remediation guidance
5. **References** — sources beyond the OWASP MASTG page itself (CVEs, Android developer docs, NIST/academic papers, vendor blogs, etc.)

## Contents

112 test cases, organized by MASVS category, available in two languages:

| Folder | Language |
|---|---|
| [`MASTGv2 Notes (id)/`](./MASTGv2%20Notes%20(id)) | Indonesian (original) |
| [`MASTGv2 Notes (en)/`](./MASTGv2%20Notes%20(en)) | English (translated) |

| MASVS Category | # Test Cases | Covers |
|---|---|---|
| `MASVS-STORAGE` | 13 | External/local storage, backups, logs, screenshots, keyboard cache |
| `MASVS-CRYPTO` | 12 | Weak algorithms/modes, key size, hardcoded keys, IV reuse, security provider |
| `MASVS-NETWORK` | 18 | TLS/cleartext traffic, certificate pinning, hostname verification, trust evaluation |
| `MASVS-CODE` | 15 | Build hardening (PIC/stack canary), dependency vulnerabilities, deserialization, SQL injection, implicit intents |
| `MASVS-RESILIENCE` | 18 | Root/debugger/emulator/hook detection, obfuscation, APK signing, StrictMode |
| `MASVS-PLATFORM` | 24 | WebViews, exported components, PendingIntents, deep links, notifications |
| `MASVS-PRIVACY` | 7 | Permissions, PII in traffic, sensitive SDK usage |
| `MASVS-AUTH` | 5 | Biometric authentication edge cases |

Each test document's filename and content map directly to its ID on [mas.owasp.org](https://mas.owasp.org/MASTG/tests/android/).

## Who this is for

Mobile app pentesters, AppSec engineers, and anyone studying for MASTG-based assessments who wants a deeper, more practical breakdown of each test than the official guide alone provides — including alternative tooling, common false positive/negative traps, and cross-references to real-world CVEs where relevant.

## ⚠️ Disclaimer — Please Read Before Relying on These Notes

These notes were drafted with the help of an AI assistant (Claude), using the official OWASP MASTG as the primary source and supplemented with other public references (Android documentation, NIST/academic papers, vendor advisories, CVE databases, etc.).

This means:

- **They have not been fully peer-reviewed by a human security expert.** Technical claims, code snippets, Semgrep/CodeQL rules, and tool commands may contain inaccuracies, outdated details, or subtle misinterpretations of the source material.
- **They should not be treated as an authoritative or final reference.** Always cross-check against the [official OWASP MASTG](https://mas.owasp.org/MASTG/) and other primary sources before applying these notes in a real assessment, report, or production decision.
- **Testing methodologies and tool outputs described here are illustrative, not guaranteed.** Behavior can vary across Android versions, app frameworks, and tool versions.

If you spot an error, an outdated reference, a better testing approach, or anything that doesn't hold up under scrutiny — **contributions and corrections are very welcome**. Please open an issue or a pull request describing:

- Which document and section is affected
- What's wrong or could be improved
- A source/reference backing the correction, if available

This repository is meant to improve over time through real-world feedback, not stand as a finished, authoritative product.

## License / Attribution

These notes reference and build upon the [OWASP MASTG](https://github.com/OWASP/mastg) project. Refer to the official project for the canonical, community-maintained version of each test case.
