# MASTG-TEST-0225 Usage of Insecure APK Signature Key Size

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0225 |
| **Platform** | Android |
| **MASVS Category** | **MASVS-RESILIENCE** (Resilience Against Reverse Engineering and Tampering) |
| **Weakness** | **MASWE-0056** — *Usage of Insecure APK Signature Version* (the same weakness as TEST-0224, covering two different aspects of APK signing) |
| **Test Type** | **Static**, Code |
| **Profile** | **R** (Resilience) |
| **Knowledge** | MASTG-KNOW-0003 (App Signing) |
| **Related Technique** | MASTG-TECH-0116 (Obtaining Information about the APK Signature) |
| **Related Demo** | — (MASTG does not yet provide a demo for this test) |
| **Sibling Test** | **MASTG-TEST-0224** (Usage of Insecure APK Signature Version) — same MASWE-0056 and technique, one `apksigner` command answers both at once |
| **Conceptually Similar Test** | MASTG-TEST-0208 (Insufficient Key Sizes) — but its object is a **data cryptography key**, not an APK signing key (see §1.2) |
| **Related CWE** | CWE-326 (Inadequate Encryption Strength), CWE-345 (Insufficient Verification of Data Authenticity), CWE-310 (Cryptographic Issues) |

---

## 1. Explanation

### 1.1 Testing Objective

Direct excerpt from the MASTG overview:

> *"For Android apps, the cryptographic strength of the APK signature is essential for maintaining the app's integrity and authenticity. Using a signature key with **insufficient length**, such as an **RSA key shorter than 2048 bits**, weakens security, making it easier for attackers to compromise the signature. This vulnerability could allow malicious actors to **forge signatures, tamper with the app's code, or distribute unauthorized, modified versions**."*

This test assesses the **length of the cryptographic key used to sign the APK** — not the length of a content key (code inside the application that encrypts/decrypts user data). This is the certificate key (`.jks`/`.keystore`) belonging to the **developer**, used once per release to affix a digital signature to the entire APK package.

### 1.2 Distinguishing This from MASTG-TEST-0208: Two Entirely Different Kinds of Keys

This confusion often arises because the topic is similarly "insufficient key size". The distinction is fundamental:

| | MASTG-TEST-0208 (Insufficient Key Sizes) | MASTG-TEST-0225 *(this document)* |
|---|---|---|
| **Key being tested** | Cryptographic key **inside the application code** (`KeyGenerator`, `KeyPairGenerator` in Java/Kotlin) | **APK signing** key (the developer's keystore, outside the application code) |
| **Key's function** | Encrypts/decrypts **data** while the application is running (user data, tokens, etc.) | Affixes a **digital signature** to the entire APK package during the build/release process |
| **Who uses it** | Application code, at runtime, repeatedly | Developer/CI-CD pipeline, at release build time, once per version |
| **Detection method** | Static code analysis (semgrep/CodeQL) | Reading certificate metadata from the APK file (`apksigner`) |
| **Impact if weak** | User data can be forcibly decrypted | **The developer's entire identity can be forged** — an attacker can create a fake "official" APK |

Because the object here is the **signing certificate**, not code, **the key strength equivalence table from MASTG-TEST-0208** (RSA vs. bits of security) still applies mathematically — but the risk context is very different: a weak signing key does not directly leak user data, but rather **opens the door to forging the identity of the application itself** (see §1.3).

### 1.3 Why Signing Key Length Is So Critical

A digital signature on an APK serves as a **guarantee of identity and integrity** — it proves to the Android system and its users that: (1) this APK genuinely originates from the developer claiming to have made it, and (2) this APK has not been modified since it was signed.

A weak private key (e.g. RSA < 2048-bit) undermines **both** of these guarantees at once:

- **Signature forgery.** If a private key can be factored/cracked, an attacker can produce a **cryptographically valid-looking** signature for any APK they create — including a version already laced with malware. A user's device and Android will accept it as a "genuine" APK from that developer.
- **Hijacking the update mechanism.** Because Android requires an app update to be signed with the **same** key as the previous version, a leaked/cracked private key allows an attacker to push a malicious "update" that the system accepts as a legitimate continuation of the original application — potentially replacing the official application on a user's device with no warning.
- **Damage to reputation and the chain of trust.** Unlike a user data breach that affects individuals, compromising a signing key threatens **trust in the developer's identity itself** — the impact spreads across the entire user base and the application's entire release history.

**RSA-1024 specifically** provides only about **80-bit security** (see the NIST SP 800-57 equivalence table in MASTG-TEST-0208 §1.2) — long below the threshold considered adequate by any standards body, and has been **disallowed** by NIST for generating new signatures since 2013 (SP 800-131A). This is not merely "suboptimal" — it is **explicitly disapproved** for this kind of use case.

A relevant real-world case as context (not Android-specific, but illustrating the same class of risk): RSA signature-forgery attacks such as **Bleichenbacher's e=3** have successfully bypassed TLS certificate validation in Firefox in the past, and similar vulnerabilities continue to be found in various RSA verification implementations that do not strictly enforce cryptographic structure. This confirms that the risk of weak-RSA-based signature forgery is not merely a theoretical threat.

### 1.4 Supported Algorithms and Key Sizes for APK Signing

Unlike application data cryptography, which is free to choose its algorithm, APK signing is bound to the algorithms supported by the signing scheme (v1/v2/v3 — see MASTG-TEST-0224 for scheme details):

| Algorithm | Key size supported by APK Signature Scheme v2/v3 | Recommendation |
|---|---|---|
| **RSA** | 1024, 2048, 4096, 8192, 16384 bits | **≥ 2048**; the exact threshold set by the MASTG evaluation criteria |
| **DSA** | 1024, 2048, 3072 bits | ≥ 2048 (although 3072 is stronger, `keytool` does not natively support generating 3072-bit DSA) |
| **EC (ECDSA)** | Curves P-256, P-384, P-521 | Curve P-256 and above is considered adequate (equivalent to RSA-3072+) |

The official MASTG evaluation criteria **specifically only mentions RSA < 2048** — the implications for other algorithms need attention (see the assessment note in §3.6).

**Google Play's requirements** are relevant as additional context: Google recommends a key size of **≥ 2048 bits**, and requires the certificate's validity period to **not expire before October 22, 2033**. This combination of key-length and validity-period requirements is not a coincidence — both respond to the long-term projected advancement of cryptanalytic computing capability (§1.3 in MASTG-TEST-0208 discusses a similar issue for the post-quantum context).

---

## 2. Tools Used for Testing

Because this test is the direct pair of MASTG-TEST-0224 with an identical technique (MASTG-TECH-0116), the entire tooling is the same — the only difference is which output line is examined (`key size` instead of `Verified using vX scheme`).

### 2.1 Required Tools (Core)

| Tool | MASTG ID | Function |
|---|---|---|
| **apksigner** | MASTG-TOOL-0123 | **The official MASTG tool.** The single definitive source of truth for signing certificate metadata |

### 2.2 Alternative & Supporting Tools

| Tool | Function |
|---|---|
| **keytool** (part of the JDK) | An alternative for checking the developer's keystore directly (if you have access to the `.jks`/`.keystore` file itself, not just the finished APK) |
| **openssl** | Manually extracting and analyzing the X.509 certificate from the APK's signing block |
| **apkanalyzer** | A GUI/CLI alternative from the Android SDK for viewing certificate info |
| **Python `androguard`** | Scripting for mass auditing of key sizes across many APKs at once |
| **MobSF** | Automated analysis, reports the certificate's key size in the APK report |

### 2.3 Environment Prerequisites

- **No device needed and no root needed** — just the APK file. Fully automatable in CI/CD.
- **Same as TEST-0224**: test the final distributed APK (output of `bundletool`/the Play Store), not just a local build — key configuration under Google Play App Signing is managed separately from the developer's upload key.
- **If you have direct access to the keystore file** (`.jks`/`.keystore`) for internal audit purposes (not just a release APK from another party), `keytool` can inspect the key directly without needing the APK at all — useful for proactive auditing before the first release.

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0116** (*Obtaining Information about the APK Signature*) to list additional signature information.

This is the only official step — this test is very concise because all needed information is already covered by the same single command as MASTG-TEST-0224.

### 3.2 Method A — apksigner *(official MASTG, one command for both sibling tests)*

```bash
apksigner verify --print-certs --verbose YourApp.apk
```

Example output per MASTG-TECH-0116 official documentation (the lines relevant to this test are conceptually underlined):

```
Verifies
Verified using v1 scheme (JAR signing): false
Verified using v2 scheme (APK Signature Scheme v2): true
Verified using v3 scheme (APK Signature Scheme v3): true
Number of signers: 1
Signer #1 certificate DN: CN=Example Developers, OU=Android, O=Example
Signer #1 certificate SHA-256 digest: 1fc4de52d0daa33a9c0e3d67217a77c895b46266ef020fad0d48216a6ad6cb70
Signer #1 certificate SHA-1 digest: 1df329fda8317da4f17f99be83aa64da62af406b
Signer #1 certificate MD5 digest: 3dbdca9c1b56f6c85415b67957d15310
Signer #1 key algorithm: RSA
Signer #1 key size (bits): 2048
Signer #1 public key SHA-256 digest: 296b4e40a31de2dcfa2ed277ccf787db0a524db6fc5eacdcda5e50447b3b1a26
```

> **Note the `Signer #1 key algorithm: RSA` and `Signer #1 key size (bits): 2048` lines** — these two lines are the main object of this test's evaluation.

**If there is more than one signer** (e.g. due to v3 key rotation, or the application signed by more than one party), check **every** signer:

```bash
apksigner verify --print-certs --verbose YourApp.apk | grep -E "Signer #[0-9]+ key"
```

```
Signer #1 key algorithm: RSA
Signer #1 key size (bits): 2048
Signer #2 key algorithm: RSA
Signer #2 key size (bits): 1024
```

### 3.3 Method B — keytool *(if you have direct access to the keystore file)*

Useful for **proactive** auditing before release (e.g. when preparing a new keystore), or when auditing an organization's internal keystore directly.

```bash
keytool -list -v -keystore release.keystore -alias release
```

Example relevant output:

```
Alias name: release
Certificate chain length: 1
Certificate[1]:
Owner: CN=Example Developers, OU=Android, O=Example
...
Signature algorithm name: SHA256withRSA
Subject Public Key Algorithm: 2048-bit RSA key
Version: 3
```

### 3.4 Method C — openssl *(direct X.509 certificate analysis from the APK's signing block)*

Useful as an independent cross-check, especially if you need to extract the certificate for further analysis purposes (e.g. examining EC curve parameters in detail).

```bash
# Extract the certificate from the v1 signing block (if present) via META-INF
unzip -p YourApp.apk "META-INF/*.RSA" > cert.der 2>/dev/null || \
unzip -p YourApp.apk "META-INF/*.DSA" > cert.der 2>/dev/null

openssl pkcs7 -inform DER -in cert.der -print_certs -out cert.pem
openssl x509 -in cert.pem -noout -text | grep -A3 "Public-Key"
```

```
Public-Key: (2048 bit)
```

> Note: this method only extracts the certificate from the **v1** scheme. Examining the certificate in the v2/v3 blocks directly requires a dedicated APK Signing Block format parser — **`apksigner` remains far more reliable** and should remain the primary source of truth, not this method.

### 3.5 Method D — androguard *(scripting for mass auditing)*

```python
# check_key_size.py
import subprocess
import glob
import re

def get_signer_info(apk_path):
    result = subprocess.run(
        ["apksigner", "verify", "--print-certs", "--verbose", apk_path],
        capture_output=True, text=True
    )
    return result.stdout

for apk_path in glob.glob("./apks/*.apk"):
    output = get_signer_info(apk_path)
    algos = re.findall(r"Signer #\d+ key algorithm:\s*(\S+)", output)
    sizes = re.findall(r"Signer #\d+ key size \(bits\):\s*(\d+)", output)

    findings = []
    for algo, size in zip(algos, sizes):
        size = int(size)
        if algo.upper() == "RSA" and size < 2048:
            findings.append(f"RSA {size}-bit (INSECURE)")
        elif algo.upper() == "DSA" and size < 2048:
            findings.append(f"DSA {size}-bit (needs review)")

    verdict = "FAIL" if findings else "PASS"
    print(f"{apk_path}: {list(zip(algos, sizes))} -> {verdict} {findings}")
```

```bash
python3 check_key_size.py
```

### 3.6 Method E — MobSF

```bash
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest
```

Upload the APK → the **Certificate Analysis** section usually displays the algorithm and key size, along with an automatic warning flag if a key under 2048 bits is detected.

### 3.7 Method Comparison: When to Use Which

| Method | Tool | Data source | Needs access to the original keystore? | Suitable for mass auditing? | When to use |
|---|---|---|---|---|---|
| **A** | apksigner (MASTG) | Finished APK file | No | Moderate (scripting needed) | **Official baseline — always used** |
| **B** | keytool | Keystore file (`.jks`) | **Yes** | Low | Proactive pre-release audit; internal keystore access |
| **C** | openssl | Finished APK file (manual extraction) | No | Low | Independent cross-check; reaches only v1 |
| **D** | androguard | Finished APK file | No | ✅ **(best for large scale)** | Auditing a portfolio of many APKs, CI integration |
| **E** | MobSF | Finished APK file | No | Partial | A thorough report ready to cite |

**Minimum recommended combination:** **A (apksigner) always**, plus **B (keytool)** specifically for proactive internal auditing when a new keystore is created — before any application is signed with it. Just as with TEST-0224, `apksigner` already provides a definitive answer in one command, so the multi-tool path here is more for scale/access convenience than closing a methodological gap.

---

### 3.8 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rule:**

> **Observation:** *"The output should contain the information about the key size in a line like: `Signer #1 key size (bits):`."*
>
> **Evaluation:** *"The test case **fails** if any of the key sizes (in bits) is **less than 2048 (RSA)**. For example, `Signer #1 key size (bits): 1024`."*

The criteria are straightforward and **literally specific to RSA**: a key size < 2048 bits → FAIL.

---

#### ❌ FAIL / ISSUE — The check is declared FAILED if:

| No | Condition | Example evidence |
|---|---|---|
| F1 | `Signer #N key algorithm: RSA` with `key size (bits)` < 2048 | `Signer #1 key algorithm: RSA` + `Signer #1 key size (bits): 1024` |
| F2 | There is **more than one signer**, and **one of them** uses RSA < 2048 | `Signer #1: RSA 2048` (safe) but `Signer #2: RSA 1024` (weak) — the "**any** of the key sizes" criterion means one failure is enough to FAIL the whole thing |
| F3 | The upload key for Google Play App Signing uses RSA < 2048, even though the final signing key is managed by Google | The chain of trust is still weakened at the upload point |
| F4 | The certificate is valid in terms of key size, but the **signature algorithm** (not the key algorithm) uses a weak hash such as SHA-1/MD5 | Outside the literal scope of this evaluation criterion, but worth noting as a related finding — see the assessment note in §3.8 |

**Example evidence (illustrative — MASTG does not yet provide an official demo for this test):**

```bash
$ apksigner verify --print-certs --verbose LegacyApp.apk
Verifies
Verified using v1 scheme (JAR signing): true
Verified using v2 scheme (APK Signature Scheme v2): false
Number of signers: 1
Signer #1 certificate DN: CN=Old Developer, OU=Mobile, O=LegacyCorp
Signer #1 key algorithm: RSA
Signer #1 key size (bits): 1024
```

Interpretation: `Signer #1 key size (bits): 1024` — **< 2048** → **FAIL**. This certificate key is equivalent to ~80-bit security, long considered inadequate and `disallowed` by NIST for generating signatures since 2013. If this private key is compromised (e.g. via factorization with sufficient computing resources, or a keystore file leak), an attacker can sign a malicious APK that will be accepted as "genuine" by devices that already have this application installed.

---

#### ✅ PASS — The check is declared PASSED if:

| No | Condition | Example evidence |
|---|---|---|
| P1 | All signers use RSA ≥ 2048 bits | `Signer #1 key size (bits): 2048` or larger |
| P2 | A signer uses an EC (ECDSA) algorithm with a standard curve (P-256 and above) | Mathematically equivalent to or stronger than RSA-2048; **not explicitly mentioned** in the evaluation criteria but consistent with its intent |
| P3 | A signer uses DSA ≥ 2048 bits | `Signer #1 key algorithm: DSA`, `Signer #1 key size (bits): 2048` |
| P4 | There are multiple signers (v3 key rotation), and **all** meet the minimum threshold | Consistent across all entries, none weak |

**Example output indicating PASS:**

```bash
$ apksigner verify --print-certs --verbose ModernApp.apk
Verifies
Verified using v1 scheme (JAR signing): true
Verified using v2 scheme (APK Signature Scheme v2): true
Verified using v3 scheme (APK Signature Scheme v3): true
Number of signers: 1
Signer #1 certificate DN: CN=Example Developers, OU=Android, O=Example
Signer #1 key algorithm: RSA
Signer #1 key size (bits): 2048
```

Interpretation: RSA 2048-bit → **PASS**. Equivalent to ~112-bit security per NIST SP 800-57 — still acceptable, though it will face deprecation pressure heading toward 2030 (see the deeper discussion in MASTG-TEST-0208 §1.2 for the long-term context, though it does not currently factor into this test's FAIL/PASS criteria).

Example of a PASS with v3 key rotation (two signers, both adequate):

```bash
$ apksigner verify --print-certs --verbose RotatedKeyApp.apk
Number of signers: 2
Signer #1 key algorithm: RSA
Signer #1 key size (bits): 2048
Signer #2 key algorithm: RSA
Signer #2 key size (bits): 4096
```

---

#### ⚠️ Important Notes on Assessment

1. **The official MASTG criteria literally only mention RSA.** If `key algorithm` shows **DSA** or **EC**, the explicit FAIL criterion ("< 2048 bit RSA") **does not directly apply** literally. Apply common-sense judgment using the equivalence table (§1.4): DSA < 2048 should still be treated as a finding of equivalent severity (tying back to MASTG-TEST-0208 for the key-strength equivalence table foundation), and EC with a curve below P-256 (rarely found in practice for APK signing, but still worth checking) is also worth noting.

2. **"Any of the key sizes" means checking ALL signers, not just the first one.** On applications with v3 key rotation (multiple signers), one weak key among several strong ones **still makes the overall result FAIL**. Do not stop checking after finding the first safe signer.

3. **Test the final distributed APK, not just a local build** — identical to the note in MASTG-TEST-0224. Google Play App Signing configuration can involve an upload key different from the final signing key; both need to be checked in their appropriate context (the upload key for submission process security, the final key for the security of the APK received by users).

4. **The hash algorithm in the signature (not key size) is a separate dimension not covered by this test's literal criteria, but worth noting.** `keytool`/`openssl` might show `Signature algorithm name: SHA1withRSA` — this is a different issue (weak hash, not key size) that is conceptually close to the MASTG-TEST-0221 area (broken algorithms), though that test focuses on data encryption, not signing certificates. Document as an additional note if found.

5. **An adequate key length does not rescue a leaked key.** This test purely assesses the key's **length** as recorded in the certificate — it does not and cannot assess whether the keystore file itself is stored securely (e.g. stored as plaintext in a code repository, shared via an insecure channel, etc.). That is a separate operational risk that occurs far more often in practice than a mathematically broken key — see the recommendations in §4 for secure keystore management.

6. **An important difference from MASTG-TEST-0208 regarding the "adequate" threshold.** MASTG-TEST-0208 debates whether AES-128 is adequate given long-term quantum threats. For **signing** keys as discussed here, the 2048-bit RSA threshold is **not yet** the subject of similar debate in current MASTG evaluation criteria — but security teams wanting to be proactive may consider RSA-3072/4096 or EC P-256+ as a hardening target beyond the minimum baseline, especially for applications with very long lifespans (§1.4, given the recommended certificate validity of ≥ 25 years).

7. **Severity is modulated by:**

   | Factor | Severity |
   |---|---|
   | RSA < 1024 bits (very weak, almost never found in the wild for modern APKs) | **Critical** |
   | RSA 1024 bits | **High** — per the explicit example in the MASTG evaluation criteria |
   | RSA between 1024–2048 (if technically possible, rare) | **High** |
   | One of several signers (key rotation) is weak, others strong | **High** — still an overall FAIL |
   | RSA ≥ 2048, DSA ≥ 2048, or EC P-256+ | **Not a finding** |

8. **Document:** the complete output of `apksigner verify --print-certs --verbose`, the algorithm and key size for **every** signer, whether the tested APK is a local build or the final distribution output, and — if a weak key is found — key rotation recommendations and their impact on the update mechanism for the application already installed on users' devices (see §4).

---

## 4. Recommendations

### 4.1 Core Principle

**Priority 1 — Use RSA ≥ 2048 bits (ideally 4096) or EC P-256+ when creating a new keystore.**

```bash
# ✅ RSA 4096-bit — exceeds the minimum baseline for long-term security margin
keytool -genkeypair -v \
  -keystore release.keystore \
  -alias release \
  -keyalg RSA \
  -keysize 4096 \
  -validity 10000 \
  -storetype PKCS12

# ✅ Alternative: EC with the P-256 curve (equivalent to/stronger than RSA-3072, smaller file size)
keytool -genkeypair -v \
  -keystore release.keystore \
  -alias release \
  -keyalg EC \
  -groupname secp256r1 \
  -validity 10000 \
  -storetype PKCS12
```

**Priority 2 — If an existing key is detected as weak (RSA < 2048), perform key rotation via APK Signature Scheme v3.** This scenario is far more complex than simply creating a new key, because Android requires signature continuity for the update mechanism:

- **The v3 signing scheme was specifically designed for this case** — allowing an APK to be signed with a **new** key while still including proof that this new key is a legitimate successor to the **old** key, so devices that already have the old version installed can still accept updates without needing to uninstall-reinstall.
- This process is called **key rotation**, and is officially documented by Android as the mechanism for exactly this kind of case (an old key considered weak/risky, but continuity with the existing user base must be maintained).
- **Google Play App Signing** significantly simplifies this scenario — because Google manages the final signing key, the developer only needs to update the **upload** key, and Google handles the final signature transition without disrupting the existing user base.

**Priority 3 — Ensure certificate validity is adequate alongside key-size hardening.** When recreating a keystore, simultaneously apply a validity period per recommendations (≥ 25 years, expiring after October 22, 2033 for Google Play requirements) — see `-validity 10000` (≈ 27.4 years) in the example command above.

**Priority 4 — Migrate to Google Play App Signing if not already done.** This shifts responsibility for managing the final signing key to Google's infrastructure, which applies key security standards consistently, while also providing a safety net in the form of the ability to reset the upload key in case of an incident, without losing the application's final signing identity.

**Priority 5 — Secure keystore file storage regardless of key strength.** Per the assessment note in §3.8 point 5 — a key's mathematical strength is irrelevant if the `.jks`/`.keystore` file itself leaks:
- Never store the keystore file or its password in a source code repository (Git, etc.).
- Use secret management (e.g. GitHub Actions Secrets, HashiCorp Vault, or equivalent) for CI/CD pipelines.
- Restrict access to the keystore file to only the personnel/systems that genuinely need it.
- Keep the keystore backup stored securely and encrypted — losing the keystore is as severe as a security compromise, since the developer loses the ability to publish legitimate updates for that application forever.

**Priority 6 — Integrate key-size checks into the release pipeline**, in line with MASTG-TEST-0224:

```bash
#!/bin/bash
# ci-verify-key-size.sh
APK=$1
apksigner verify --print-certs --verbose "$APK" | \
  awk '/key algorithm: RSA/{getline; if ($0 ~ /key size \(bits\): (10[0-9][0-9]|[1-9][0-9][0-9])$/) exit 1}'

if [ $? -eq 1 ]; then
    echo "[FAILED] Found a signer with an RSA key < 2048 bits"
    exit 1
fi
echo "[OK] Signing key size is adequate"
```

### 4.2 Remediation Checklist

- [ ] Signing key size is verified for **every** signer (not just the first) using `apksigner verify --print-certs --verbose`
- [ ] All signers use RSA ≥ 2048 bits (ideally 4096), or DSA ≥ 2048, or EC P-256+
- [ ] If an existing key is detected as weak: a key rotation plan via APK Signature Scheme v3 is drawn up and executed
- [ ] Migration to Google Play App Signing is considered/already done
- [ ] Certificate validity is adequate (≥ 25 years, expiring after October 22, 2033)
- [ ] The keystore file and its password are **not** stored in a code repository
- [ ] Secret management is used for signing credentials in the CI/CD pipeline
- [ ] The keystore backup is stored securely and encrypted
- [ ] The final distributed APK (Play Store/bundletool) is verified separately from local builds
- [ ] The hash algorithm on the signature (not just key size) is also checked for additional weaknesses (SHA-1/MD5)
- [ ] Key-size checking is integrated as an automated gate in the release CI/CD pipeline
- [ ] **Re-verify:** rerun MASTG-TEST-0225 after every signing key change/rotation
- [ ] **Cross-verify:** run MASTG-TEST-0224 (signing scheme) — the same single `apksigner` command answers both

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0225: Usage of Insecure APK Signature Key Size](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0225/)
- [MASTG-TEST-0224: Usage of Insecure APK Signature Version](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0224/)
- [MASTG-TEST-0208: Insufficient Key Sizes](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0208/)
- [MASWE-0056: Usage of Insecure APK Signature Version](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0056/)
- [MASTG-KNOW-0003: App Signing](https://mas.owasp.org/MASTG/knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0003/)
- [MASTG-BEST-0006: Use Up-to-Date APK Signing Schemes](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0006/)
- [MASTG-TECH-0116: Obtaining Information about the APK Signature](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0116/)
- [MASTG-TOOL-0123: apksigner](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0123/)
- [MASVS-RESILIENCE: Resilience Against Reverse Engineering and Tampering](https://mas.owasp.org/MASVS/11-MASVS-RESILIENCE/)
- [OWASP Mobile Top 10 2024 — M7: Insufficient Binary Protections](https://owasp.org/www-project-mobile-top-10/2023-risks/m7-insufficient-binary-protections.html)

### 5.2 Official Android / Google Documentation

- [Android — Application Signing](https://developer.android.com/studio/publish/app-signing.html)
- [Android — Sign your app (key generation, keytool)](https://developer.android.com/studio/publish/app-signing)
- [Android — APK Signature Scheme v3 (key rotation)](https://source.android.com/docs/security/features/apksigning/v3)
- [Android — apksigner tool reference](https://developer.android.com/tools/apksigner)
- [Android — Google Play App Signing](https://support.google.com/googleplay/android-developer/answer/9842756)
- [Android — Signing Considerations (key size, validity period)](https://developer.android.com/studio/publish/app-signing#considerations)
- [Google Play Console Help — Play App Signing](https://support.google.com/googleplay/android-developer/answer/9842756?hl=en)
- [Guardian Project — How to Migrate Your Android App's Signing Key](https://guardianproject.info/2015/12/29/how-to-migrate-your-android-apps-signing-key/)

### 5.3 Cryptographic Standards & Research

- [NIST SP 800-57 Part 1 Rev. 5 — Recommendation for Key Management](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final)
- [NIST SP 800-131A Rev. 2 — Transitioning the Use of Cryptographic Algorithms and Key Lengths](https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final)
- [CWE-326: Inadequate Encryption Strength](https://cwe.mitre.org/data/definitions/326.html)
- [CWE-345: Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html)
- [CWE-310: Cryptographic Issues](https://cwe.mitre.org/data/definitions/310.html)
- [CERT/CC VU#725167 — node-forge Signature Forgery Vulnerabilities in RSA-PKCS](https://kb.cert.org/vuls/id/725167)
- [Cryptopals — Bleichenbacher's e=3 RSA Attack](https://cryptopals.com/sets/6/challenges/42)
- [NIST SP 800-163 Rev.1 — Vetting the Security of Mobile Applications](https://csrc.nist.gov/publications/detail/sp/800-163/rev-1/final)

### 5.4 Tool Documentation

- [apksigner — Android Developers tool reference](https://developer.android.com/tools/apksigner)
- [keytool — Java key and certificate management tool](https://docs.oracle.com/en/java/javase/17/docs/specs/man/keytool.html)
- [OpenSSL — command-line tools](https://www.openssl.org/docs/man3.0/man1/)
- [Androguard — Android APK/DEX analysis library](https://github.com/androguard/androguard)
- [MobSF — Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)

---

*This document was compiled based on OWASP MASTG (latest release as of September 2026), official Android Open Source Project documentation on the APK Signature Scheme and App Signing, and NIST SP 800-57/800-131A standards. This test does not yet have an official demo (MASTG-DEMO) from MASTG, and is the direct pair of MASTG-TEST-0224, sharing the testing technique (MASTG-TECH-0116) and weakness (MASWE-0056).*
