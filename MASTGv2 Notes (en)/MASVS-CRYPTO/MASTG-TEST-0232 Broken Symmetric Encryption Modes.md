# MASTG-TEST-0232 Broken Symmetric Encryption Modes

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0232 |
| **Platform** | Android |
| **MASVS Category** | MASVS-CRYPTO (MASVS-CRYPTO-1: The app uses cryptography according to industry best practices) |
| **Weakness** | MASWE-0007 — *Improper Encryption* |
| **Test Type** | Static, Code, **Manual** |
| **Profile** | L1, L2 |
| **Best Practice** | MASTG-BEST-0005 (Use Secure Encryption Modes) |
| **Related Techniques** | MASTG-TECH-0013 (Reverse Engineering), MASTG-TECH-0014 (Static Analysis), MASTG-TECH-0023 (Reviewing Decompiled Java Code — further validation required) |
| **Official Rule** | `mastg-android-broken-encryption-modes.yaml` (exists, but has narrow coverage — see §3.2) |
| **Related Demo** | — (MASTG does not yet provide an official demo for this test) |
| **Related Tests** | **MASTG-TEST-0221** (Broken Symmetric Encryption *Algorithms* — DES/RC4/Blowfish; this tests the **algorithm**, whereas TEST-0232 tests the **mode of operation**) |
| **Related CWE** | CWE-327 (Use of a Broken or Risky Cryptographic Algorithm), CWE-326 (Inadequate Encryption Strength), CWE-329 (Generation of Predictable IV with CBC Mode) |

---

## 1. Explanation

### 1.1 Testing Objective

Quote from the official MASTG overview:

> *"To test for the use of broken encryption modes in Android apps, we should focus on methods in cryptographic frameworks and libraries used to configure and apply encryption modes."*

This test focuses on the **block cipher mode of operation** (not the algorithm itself). The distinction from MASTG-TEST-0221 is important to understand from the outset:

| | MASTG-TEST-0221 | MASTG-TEST-0232 *(this document)* |
|---|---|---|
| **What is tested** | Cipher **algorithm** (DES, 3DES, RC4, Blowfish) | Cipher **mode of operation** (ECB) |
| **Example finding** | `Cipher.getInstance("DES/CBC/PKCS5Padding")` — the DES algorithm is already broken regardless of mode | `Cipher.getInstance("AES/ECB/PKCS5Padding")` — the AES algorithm is secure, but the ECB mode is broken |
| **MASWE** | Different (algorithm MASWE) | MASWE-0007 |

On Android, the `Cipher` class (Java Cryptography Architecture/JCA) is the primary API for specifying the encryption mode. `Cipher.getInstance()` accepts a *transformation string* in the format `"Algorithm/Mode/Padding"`, for example `Cipher.getInstance("AES/ECB/PKCS5Padding")`.

### 1.2 Why ECB Is Broken

**ECB (Electronic Codebook)**, defined in **NIST SP 800-38A**, splits the plaintext into fixed-size blocks (128 bits for AES) and encrypts **each block independently with the same key**. This property makes it **deterministic**: identical plaintext blocks will always produce identical ciphertext blocks.

Consequences:
- **Patterns in the data leak without needing to decrypt anything.** A classic example: a bitmap image encrypted with ECB still shows the silhouette of the original image in the ciphertext, because repeated solid-color areas produce identical, repeating ciphertext blocks.
- **Vulnerable to known-plaintext and chosen-plaintext attacks** — if an attacker knows part of the plaintext corresponding to part of the ciphertext, they can build a block-mapping table to break other parts of the ciphertext that use the same plaintext block.
- **No IV (Initialization Vector).** This is a structural difference from secure modes like CBC/GCM — ECB does not randomize the input with a per-operation random value, so encrypting the same data twice with the same key will always produce exactly the same ciphertext.

**Important note from the official overview:** Since 2023, **NIST has officially revised SP 800-38A** and announced that ECB is "generally discouraged" — although not explicitly forbidden in every scenario, its use is severely restricted.

### 1.3 List of Transformation Strings Considered Vulnerable

Per the official overview, the following are **considered vulnerable** (referenced from Google Play Console guidance):

- `"AES"` — uses **ECB mode by default** when only the algorithm name is given without explicit mode/padding specification (default JCA provider behavior)
- `"AES/ECB/NoPadding"`
- `"AES/ECB/PKCS5Padding"`
- `"AES/ECB/ISO10126Padding"`

The bare `"AES"` entry is the one most often overlooked — many developers assume `Cipher.getInstance("AES")` is "safe because it doesn't mention ECB," when in fact the default JCA provider on Android/Java falls back to ECB.

### 1.4 Out of Scope: RSA with "ECB" in the Transformation String

This section is explicitly emphasized by MASTG because it can cause significant **false positives**:

> *"Asymmetric encryption modes, such as RSA, are out of scope for this test because they don't use block modes like ECB."*

In transformation strings such as `"RSA/ECB/OAEPPadding"` or `"RSA/ECB/PKCS1Padding"`, the word **`ECB` here is misleading** — RSA does not operate in a block mode like ECB at all. The `ECB` label in the Java cryptography API for RSA is merely a **historical placeholder** in the provider implementation (see the OpenJDK `RSACipher.java` code snippet referenced by MASTG), not an indication that RSA uses ECB mode. Understanding this nuance is important so testers **do not mistakenly flag** every occurrence of the literal string `"ECB"` as a valid finding — the algorithm context (RSA vs. AES/DES/etc.) must always be checked first.

### 1.5 Real-World Cases: MEGA Android App & CVE-2026-22906

Two real-world examples reinforce the urgency of this test:

- **MEGA Android app**: Security researchers from the Digit Institute (Germany) found `Cipher.getInstance("AES")` at a certain line of code that by default falls back to `"AES/ECB/PKCS5Padding"` — reported via a public GitHub issue (`meganz/android#299`).
- **CVE-2026-22906**: An information disclosure vulnerability caused by the combination of **AES-ECB with a hardcoded key** — user credentials were stored using AES-ECB with a key embedded directly in the application, allowing an unauthenticated attacker who obtains the configuration file to decrypt the plaintext username/password. This case demonstrates that the risk of ECB **compounds** when combined with another issue such as a hardcoded key (MASTG-TEST-0212) — two independent cryptographic weaknesses that mutually amplify the impact.

---

## 2. Tools Used for Testing

### 2.1 Required Tools (Core)

| Tool | MASTG ID | Function |
|---|---|---|
| **jadx** | MASTG-TOOL-0018 | Decompiles DEX → Java (MASTG-TECH-0013), the basis for searching transformation string patterns |
| **semgrep** | MASTG-TOOL | Runs the official `mastg-android-broken-encryption-modes.yaml` rule |
| **grep / ripgrep** | — | Complements the narrow coverage of the official rule (see §3.2) |

### 2.2 Alternative & Supporting Tools

| Tool | Function |
|---|---|
| **CodeQL** | Taint analysis — tracks whether the result of `Cipher.getInstance("AES/ECB/...")` is actually used to encrypt sensitive data, not merely whether the string exists |
| **MobSF** | Automated analysis, often flags ECB usage in the Code Analysis report's cryptography category |
| **mobsfscan** | mobsf-scan CLI, suitable for CI/CD |
| **apktool + baksmali** | Smali analysis for cases where the transformation string is built dynamically/obfuscated such that it is not caught by a clean jadx decompilation |
| **Frida** | Hooking `Cipher.getInstance()` at runtime to capture transformation strings that are **built dynamically** (concatenation, results from remote config) — invisible to pure static analysis |
| **JEB Decompiler / Ghidra** | For cases where encryption is implemented in **native code** (JNI, OpenSSL `EVP_CIPHER_CTX` with `EVP_aes_256_ecb()`), beyond the reach of Java/Kotlin analysis |

### 2.3 Environment Prerequisites

- **No device/root required** for basic static analysis — only the APK and decompilation tools are needed.
- **Device + Frida required** only when a transformation string is suspected to be built dynamically (see §2.2, §3.4).
- As with other cryptography tests (TEST-0208, 0212, 0221), testing should focus on operations that handle **sensitive data** — not every `Cipher` call in the codebase (e.g., a third-party library using ECB internally for non-sensitive data is lower risk, though still worth noting).

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0013** to reverse engineer the application.
2. Use **MASTG-TECH-0014** to search for the relevant APIs.

**Mandatory further validation** (from the official "Further Validation Required" clause):

> *"Inspect each reported code location using MASTG-TECH-0023 to determine whether this is being used to perform encryption or decryption operations on sensitive data."*

This clause explicitly requires that **every finding's code location be manually reviewed** to confirm that the operation actually processes sensitive data — not merely that the string `"ECB"` exists in the code.

### 3.2 Method A — Official Semgrep Rule *(exists, but narrow in coverage)*

The official MASTG rule for this test:

```yaml
rules:
  - id: mastg-android-broken-encryption-modes
    languages:
      - java
    severity: WARNING
    metadata:
      summary: This rule looks for broken encryption modes.
    message: "[MASVS-CRYPTO-1] Broken encryption modes found in use."
    pattern-either:
      - pattern: Cipher.getInstance("AES")
      - pattern-regex: Cipher\.getInstance\("?[A-Za-z0-9]+/ECB(/[A-Za-z0-9]+)?"?\)
```

```bash
jadx -d ./decompiled ./target-app.apk
semgrep --config https://raw.githubusercontent.com/OWASP/mastg/master/rules/mastg-android-broken-encryption-modes.yaml ./decompiled/sources/
```

**Coverage gaps testers should be aware of** (verified directly against the rule content above):

1. **`languages: [java]` only** — although the semgrep Java parser can generally parse syntax similar to decompiled Kotlin, this rule **does not explicitly support Kotlin**. Native Kotlin code using different idiomatic syntax (e.g., named arguments, string templates) may not be caught. **Mitigation:** still run against jadx decompilation output that produces Java-like output, or add a custom rule labeled `languages: [java, kotlin]` (Method B).
2. **Only catches explicit string literals** — patterns such as `Cipher.getInstance(algo + "/ECB/PKCS5Padding")` (concatenation) or `Cipher.getInstance(CIPHER_TRANSFORM_CONST)` (a reference to a constant defined elsewhere) **will not be caught** by the `pattern-regex` which assumes a direct literal inside the call.
3. **Does not cover native/BouncyCastle cryptographic APIs** — ECB implementations via `org.bouncycastle.crypto.modes` or native code (`EVP_aes_256_ecb()`) are beyond the reach of this rule, which purely targets `javax.crypto.Cipher`.
4. **Does not validate sensitive-data context** — per the official "Further Validation Required" clause, this rule only flags *locations*, without assessing whether the operation processes sensitive data.

### 3.3 Method B — grep/ripgrep + Custom Semgrep Rule *(closes the gaps in §3.2)*

```bash
# Catches bare AES literals without explicit mode, and ECB variations
rg -n 'Cipher\.getInstance\(\s*"AES"\s*\)' $D
rg -n 'Cipher\.getInstance\([^)]*ECB[^)]*\)' $D

# Catches concatenation / constant-reference cases (gap #2 of the official rule)
rg -n 'Cipher\.getInstance\(\s*\w+\s*\+' $D                    # concatenation
rg -n 'val\s+\w+\s*=\s*"[A-Za-z0-9]+/ECB' $D                   # Kotlin constant declaration
rg -n 'static final String.*ECB' $D                             # Java constant declaration

# BouncyCastle ECB mode
rg -n 'org\.bouncycastle\.crypto\.modes\.(AESEngine|.*ECB)' $D
```

Custom semgrep rule covering Kotlin and constant patterns:

```yaml
rules:
  - id: custom-broken-encryption-modes-extended
    languages: [java, kotlin]
    severity: WARNING
    message: "[MASVS-CRYPTO-1] Possible use of ECB mode or default AES without an explicit mode"
    pattern-either:
      - pattern: Cipher.getInstance("AES")
      - pattern-regex: 'Cipher\.getInstance\(\s*"?[A-Za-z0-9]+/ECB(/[A-Za-z0-9]+)?"?\s*\)'
      - pattern: Cipher.getInstance($CONST)
        metavariable-regex:
          metavariable: $CONST
          regex: '.*(ECB|AES_ECB|CIPHER_TRANSFORM).*'
```

### 3.4 Method C — Frida (dynamic transformation strings, only visible at runtime)

For cases where the mode is built dynamically (gap #2 in §3.2) — for example, the mode is chosen based on remote configuration or a feature flag — pure static analysis will find nothing. Hooking `Cipher.getInstance()` at runtime captures the **actual transformation string value used**, regardless of how it was constructed:

```javascript
// hook-cipher-getinstance.js
Java.perform(function () {
    var Cipher = Java.use("javax.crypto.Cipher");
    Cipher.getInstance.overload("java.lang.String").implementation = function (transformation) {
        console.log("[Cipher.getInstance] transformation = " + transformation);
        if (transformation.indexOf("ECB") !== -1 ||
            transformation === "AES" ||
            transformation === "DES" ||
            transformation === "Blowfish") {
            console.log("  [!] POTENTIALLY BROKEN MODE (ECB / default) detected at runtime!");
            console.log("  Stack trace:\n" + Java.use("android.util.Log").getStackTraceString(
                Java.use("java.lang.Throwable").$new()));
        }
        return this.getInstance(transformation);
    };
});
```

```bash
frida -U -f com.target.app -l hook-cipher-getinstance.js --no-pause
```

This method is also useful for **confirming** static findings from Method A/B — ensuring that the discovered code is actually executed and is not dead code.

### 3.5 Method D — CodeQL (taint analysis to validate "sensitive data")

Directly addresses the official "Further Validation Required" clause programmatically:

```ql
import java
import semmle.code.java.dataflow.TaintTracking

class SensitiveDataSource extends DataFlow::Node {
  SensitiveDataSource() {
    exists(Variable v |
      v.getName().toLowerCase().regexpMatch(".*(password|token|secret|pin|creditcard|ssn|apikey).*") and
      this.asExpr() = v.getAnAccess()
    )
  }
}

class ECBCipherSink extends DataFlow::Node {
  ECBCipherSink() {
    exists(MethodAccess ma |
      ma.getMethod().hasName("getInstance") and
      ma.getMethod().getDeclaringType().hasQualifiedName("javax.crypto", "Cipher") and
      ma.getAnArgument().(StringLiteral).getValue().matches("%ECB%") |
      this.asExpr() = ma.getAnArgument()
    )
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink
where TaintTracking::localFlow(source, sink)
select sink, source, sink, "Data labeled as sensitive potentially flows into an ECB-mode Cipher operation"
```

### 3.6 Method E — MobSF

```bash
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest
```

MobSF's **Code Analysis** section typically lists findings under a category such as "ECB mode is known to be weak" or similar, based on its own internal rules (independent of the official MASTG rule) — useful as a second **cross-check** against Method A/B.

### 3.7 Method Comparison: When to Use Which

| Method | Tool | Finds explicit literals? | Finds dynamic strings? | Assesses sensitive-data context? | When to use |
|---|---|---|---|---|---|
| **A** | Official semgrep rule | ✅ | ❌ | ❌ | Quick baseline, initial CI/CD gate |
| **B** | grep + custom rule | ✅ (+constants) | Partial (variable references) | ❌ | Closes coverage gaps in the official rule |
| **C** | Frida | ✅ (executed ones) | ✅ | ❌ (but confirms real execution) | Suspected dynamically built transformation string |
| **D** | CodeQL | ✅ | ❌ | ✅ (variable-name heuristic) | Large codebase, reduces manual review burden |
| **E** | MobSF | ✅ | ❌ | ❌ | Quick triage, citable report |

**Recommended minimum combination:** **A (official rule) → B (supplementary grep) → manual MASTG-TECH-0023 review** on every finding to satisfy the official validation clause. Add **C (Frida)** when the app is known to use cryptographic configuration that can change dynamically (e.g., driven by remote config/feature flag), and **D (CodeQL)** for large codebases to narrow down candidates requiring manual review.

---

### 3.8 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rules:**

> **Observation:** *"The output should contain a list of locations where broken encryption modes are used in cryptographic operations."*
>
> **Evaluation:** *"The test case fails if any broken modes are identified in the app."*
>
> **Further Validation Required:** Each location must be inspected to confirm that the operation is actually used for encryption/decryption of sensitive data.

---

#### ❌ FAIL / ISSUE — The check is declared FAILED when:

| No | Condition | Example evidence |
|---|---|---|
| F1 | `Cipher.getInstance("AES")` found without an explicit mode (defaults to ECB) used on sensitive data | `Cipher.getInstance("AES")` used to encrypt a credential field |
| F2 | Explicit literal `"AES/ECB/NoPadding"`, `"AES/ECB/PKCS5Padding"`, or `"AES/ECB/ISO10126Padding"` found on a sensitive-data operation | `Cipher.getInstance("AES/ECB/PKCS5Padding")` for encrypting a session token |
| F3 | ECB mode found via a **dynamically** constructed transformation string, confirmed to execute through runtime hooking (Method C) | Frida hook output shows `transformation = "AES/ECB/PKCS5Padding"` when the app saves data to local storage |
| F4 | ECB implementation found through a non-JCA cryptography library (BouncyCastle `AESEngine` wrapped manually in ECB mode, or native code `EVP_aes_256_ecb()`) for sensitive data | `rg` finds `org.bouncycastle.crypto.modes` combined with ECB in an API payload encryption module |
| F5 | ECB combined with another cryptographic weakness (e.g., hardcoded key from MASTG-TEST-0212), worsening exploitation impact | Pattern similar to CVE-2026-22906: AES-ECB + hardcoded key for storing credentials |

**Example evidence (illustrative — MASTG does not yet provide an official demo for this test):**

```kotlin
// Found in com/example/target/crypto/DataCrypto.kt (jadx decompilation output)
object DataCrypto {
    fun encryptUserProfile(data: ByteArray, key: SecretKey): ByteArray {
        val cipher = Cipher.getInstance("AES")   // line 18 — defaults to ECB, NO IV
        cipher.init(Cipher.ENCRYPT_MODE, key)
        return cipher.doFinal(data)
    }
}
```

```bash
$ rg -n 'Cipher\.getInstance\(\s*"AES"\s*\)' ./decompiled/sources/
com/example/target/crypto/DataCrypto.kt:18:        val cipher = Cipher.getInstance("AES")   // defaults to ECB
```

Interpretation: called from `encryptUserProfile`, which clearly processes user data — **FAIL**. Further verification (MASTG-TECH-0023) should trace the callers of `encryptUserProfile` to confirm the data type (`data: ByteArray`) truly contains sensitive fields from the user profile.

---

#### ✅ PASS — The check is declared PASSED when:

| No | Condition | Example evidence |
|---|---|---|
| P1 | **No** reference to ECB mode or `Cipher.getInstance("AES")` without an explicit mode is found anywhere in the codebase | Semgrep + grep results are empty |
| P2 | The literal `"ECB"` is found but confirmed to be in an **RSA** context (the false positive explained in §1.4), not a symmetric cipher | `Cipher.getInstance("RSA/ECB/OAEPPadding")` — an API placeholder, not a real block cipher mode |
| P3 | ECB mode found, but only used on **non-sensitive** data as proven by manual review (e.g., internal checksums, public data) | ECB encryption used in an internal caching module for non-confidential data that is already public |
| P4 | All sensitive-data encryption operations use an authenticated mode such as **AES/GCM/NoPadding** per MASTG-BEST-0005 recommendations | `Cipher.getInstance("AES/GCM/NoPadding")` with a unique IV per operation |
| P5 | ECB code found but proven to be **dead code**/never called (confirmed via reachability analysis or Frida never capturing its execution) | An old function no longer called anywhere, left over from refactoring |

**Example output indicating PASS:**

```bash
$ rg -n 'Cipher\.getInstance\(\s*"AES"\s*\)|ECB' ./decompiled/sources/ | grep -v "RSA"
# (no results — or all results confirmed to be RSA placeholders / dead code / non-sensitive data)

$ rg -n 'Cipher\.getInstance\(\s*"AES/GCM' ./decompiled/sources/
com/example/target/crypto/DataCrypto.kt:18:        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
```

---

#### ⚠️ Important Notes on Assessment

1. **Do not blindly flag every occurrence of the string `"ECB"`.** Per §1.4, `"RSA/ECB/OAEPPadding"` is a **pure false positive** — RSA does not use block modes. Always check the algorithm preceding `/ECB/` before concluding a finding is valid.

2. **`Cipher.getInstance("AES")` without a mode argument is a frequently missed finding** because it does not literally contain the word "ECB" — this is why the official rule explicitly adds a separate pattern for this case. Do not rely solely on searching for the literal string "ECB" when grepping manually.

3. **The "Further Validation Required" clause is mandatory, not optional.** Unlike some other tests where manual review is mentioned as an additional recommendation, MASTG explicitly requires every finding location to be inspected to confirm it truly is an operation on **sensitive data**. A report that only lists "N ECB locations found" without assessing data context does not meet this test's official evaluation standard.

4. **Dynamic transformation strings are a significant blind spot for pure static analysis.** If the app uses a custom cryptography wrapper that accepts the mode parameter from outside (config, remote flag, or even a `BuildConfig` result), grep/semgrep will not find the literal `"ECB"` at the call site — verification via Frida (Method C) becomes essential in this case.

5. **Severity is modulated by the type of data and scale of exposure:**

   | Factor | Severity |
   |---|---|
   | ECB used for credentials, PII, or financial data, combined with a hardcoded key (CVE-2026-22906 pattern) | **Critical** |
   | ECB used for sensitive data without another combined weakness | **High** |
   | ECB found but only for non-sensitive internal data (confirmed manually) | **Low/Informational** |
   | `"AES"` without a mode found in a bundled third-party library (not the app's own code) | **Medium** — still reported, but remediation priority lies with the library vendor |

6. **Document:** the code location (file + line) from the decompilation, the exact transformation string found, the reachability/taint analysis results (what data flows into the operation), the manual confirmation status (MASTG-TECH-0023), and — where relevant — the runtime hooking results confirming that a dynamic transformation string is actually executed.

---

## 4. Recommendations

### 4.1 Switch to an Authenticated Mode (AES-GCM)

Per **MASTG-BEST-0005**, the primary solution is to replace the insecure mode with an **authenticated encryption mode** such as **AES-GCM** or **AES-CCM** (defined in **NIST SP 800-38D**), which simultaneously provides **confidentiality, integrity, and authenticity** in a single operation:

```kotlin
// BEFORE (broken — ECB, no IV, no integrity authentication)
val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
cipher.init(Cipher.ENCRYPT_MODE, secretKey)
val ciphertext = cipher.doFinal(plaintext)

// AFTER (secure — GCM, unique IV per operation, built-in authentication tag)
val cipher = Cipher.getInstance("AES/GCM/NoPadding")
val iv = ByteArray(12).also { SecureRandom().nextBytes(it) }  // 96-bit IV, MUST be unique per operation
val gcmSpec = GCMParameterSpec(128, iv)                        // 128-bit tag length
cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec)
val ciphertext = cipher.doFinal(plaintext)
// store the IV alongside the ciphertext (the IV need not be secret, but MUST be unique per encryption)
val output = iv + ciphertext
```

**The golden rule of GCM: the IV must never be reused with the same key.** IV reuse in GCM is far more catastrophic than in CBC — it can fully leak the GCM authentication key (the *forbidden attack*). Use `SecureRandom` (not `Random`, see MASTG-TEST-0204) to generate the IV for every operation.

### 4.2 Avoid CBC as a Primary Alternative

The MASTG-BEST-0005 overview explicitly recommends **avoiding CBC** even though CBC is more secure than ECB:

> *"We recommend avoiding CBC, which while being more secure than ECB, improper implementation, especially incorrect padding, can lead to vulnerabilities such as padding oracle attacks."*

If migrating to GCM is not feasible in the short term (e.g., legacy system compatibility), **CBC with a separate HMAC** (encrypt-then-MAC) is a safer compromise than plain CBC — though still more complex and more prone to implementation errors than using GCM directly. Prioritize GCM for new implementations.

### 4.3 Use Android Keystore for Key Management

Combine the mode-of-operation fix with secure key storage via the **Android Keystore System**, instead of hardcoding keys in code (see MASTG-TEST-0212):

```kotlin
val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
keyGenerator.init(
    KeyGenParameterSpec.Builder("myAppKeyAlias", KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)   // only allow GCM mode from the key generation level
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
        .build()
)
val secretKey = keyGenerator.generateKey()
```

By restricting `setBlockModes(KeyProperties.BLOCK_MODE_GCM)` at the Keystore level, using any other mode (including ECB) with that key will be **rejected by the system** — a defense-in-depth mechanism that prevents future regression to an insecure mode.

### 4.4 Integrate the Check into CI/CD

```bash
#!/bin/bash
# ci-check-ecb-mode.sh
APK=$1
jadx -d /tmp/decompiled_check "$APK" 2>/dev/null
FOUND=$(semgrep --config ./rules/mastg-android-broken-encryption-modes.yaml /tmp/decompiled_check/sources/ --json | jq '.results | length')
if [ "$FOUND" -gt "0" ]; then
    echo "[FAILED] Found $FOUND possible ECB mode usages — review and confirm they are not RSA false positives"
    exit 1
fi
```

### 4.5 Remediation Checklist

- [ ] All `Cipher.getInstance()` calls in the codebase have been inventoried (including bare `"AES"` without explicit mode)
- [ ] Every literal `"ECB"` finding has been verified not to be an RSA false positive (§1.4, §3.8 P2)
- [ ] Every valid finding has been manually reviewed (MASTG-TECH-0023) to confirm/deny involvement of sensitive data
- [ ] All sensitive-data encryption operations have migrated to `AES/GCM/NoPadding` with a unique IV per operation via `SecureRandom`
- [ ] Cryptographic keys are managed through Android Keystore with `setBlockModes()` restricted to GCM
- [ ] Dynamic transformation strings (if any) have been verified via runtime hooking (Frida) to confirm they do not fall back to ECB in production
- [ ] Semgrep rules (official + custom §3.3) are integrated as a CI/CD gate
- [ ] **Re-verify:** rerun MASTG-TEST-0232 on the final release APK after remediation

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0232: Broken Symmetric Encryption Modes](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0232/)
- [MASTG-TEST-0221: Broken Symmetric Encryption Algorithms](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0221/)
- [MASWE-0007: Improper Encryption](https://mas.owasp.org/MASWE/MASVS-CRYPTO/MASWE-0007/)
- [MASTG-BEST-0005: Use Secure Encryption Modes](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0005/)
- [MASTG-TECH-0013: Reverse Engineering Android Apps](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/)
- [MASTG-TECH-0014: Static Analysis on Android](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/)
- [MASTG-TECH-0023: Reviewing Decompiled Java Code](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0023/)
- [MASTG Document 0x04g — Testing Cryptography](https://mas.owasp.org/MASTG/0x04g-Testing-Cryptography/)
- [Official rule: mastg-android-broken-encryption-modes.yaml (GitHub)](https://github.com/OWASP/mastg/blob/master/rules/mastg-android-broken-encryption-modes.yaml)
- [OWASP Mobile Top 10 2024 — M10: Insufficient Cryptography](https://owasp.org/www-project-mobile-top-10/2023-risks/m10-insufficient-cryptography)

### 5.2 Standards and Official Documentation

- [NIST SP 800-38A: Recommendation for Block Cipher Modes of Operation](https://csrc.nist.gov/pubs/sp/800/38/a/final)
- [NIST — Decision to Revise NIST SP 800-38A (2023)](https://csrc.nist.gov/news/2023/decision-to-revise-nist-sp-800-38a)
- [NIST IR 8459 — Report on the Block Cipher Modes of Operation in the NIST SP 800-38 Series](https://nvlpubs.nist.gov/nistpubs/ir/2024/NIST.IR.8459.pdf)
- [NIST SP 800-38D: Recommendation for Block Cipher Modes of Operation — GCM and GMAC](https://csrc.nist.gov/pubs/sp/800/38/d/final)
- [Google — Remediation for Unsafe Encryption Mode Usage (Play Console FAQ)](https://support.google.com/faqs/answer/10046138?hl=en)
- [Android Developers — `Cipher` API reference](https://developer.android.com/reference/javax/crypto/Cipher)
- [Android Developers — Cryptography guidance](https://developer.android.com/privacy-and-security/cryptography)
- [Android Developers — Android Keystore System](https://developer.android.com/privacy-and-security/keystore)
- [Wikipedia — Block cipher mode of operation: ECB](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_codebook_(ECB))
- [Wikipedia — Known-plaintext attack](https://en.wikipedia.org/wiki/Known-plaintext_attack)
- [Wikipedia — Chosen-plaintext attack](https://en.wikipedia.org/wiki/Chosen-plaintext_attack)
- [CWE-327: Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)
- [CWE-329: Generation of Predictable IV with CBC Mode](https://cwe.mitre.org/data/definitions/329.html)

### 5.3 Real-World Cases & Third-Party Research

- [CVE-2026-22906: Information Disclosure Vulnerability (AES-ECB + hardcoded key)](https://www.sentinelone.com/vulnerability-database/cve-2026-22906/)
- [meganz/android GitHub Issue #299 — Insecure AES Usage: Defaults to ECB Mode](https://github.com/meganz/android/issues/299)
- [OpenJDK Source — RSACipher.java (explanation of the "ECB" placeholder for RSA)](https://github.com/openjdk/jdk/blob/680ac2cebecf93e5924a441a5de6918cd7adf118/src/java.base/share/classes/com/sun/crypto/provider/RSACipher.java#L126)

### 5.4 Tool Documentation

- [Semgrep — Documentation](https://semgrep.dev/docs/)
- [CodeQL — Documentation](https://codeql.github.com/docs/)
- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [Frida — Dynamic instrumentation toolkit](https://frida.re/docs/javascript-api/#cipher)
- [MobSF — Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)
- [mobsfscan](https://github.com/MobSF/mobsfscan)

---

*This document was compiled based on OWASP MASTG (latest release as of September 2026), NIST SP 800-38A/D publications, official Android Developers documentation, Google Play Console guidance, and real-world research and vulnerability reports (CVE-2026-22906, MEGA Android case). This test has an official semgrep rule but with limited coverage — refer to §3.2–3.3 for coverage gaps and how to close them.*
