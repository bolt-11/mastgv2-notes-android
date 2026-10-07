# MASTG-TEST-0307 References to Asymmetric Key Pairs Used For Multiple Purposes

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0307 |
| **Platform** | Android |
| **MASVS Category** | MASVS-CRYPTO (MASVS-CRYPTO-1) |
| **Weakness** | MASWE-0007 — *Improper Encryption* |
| **Highlighted API** | `java.security.KeyPairGenerator`, `android.security.keystore.KeyGenParameterSpec.Builder`, `android.security.keystore.KeyProperties` |
| **Test Type** | Static, Code |
| **Knowledge** | MASTG-KNOW-0012 (Key Generation) |
| **Related Techniques** | MASTG-TECH-0013, MASTG-TECH-0014 |
| **Related Demo** | — (none) |
| **Official Rule** | `mastg-android-asymmetric-key-pair-used-for-multiple-purposes.yml` — a rule that **honestly** only collects locations for manual review, and **does not** evaluate the `purposes` bitmask value itself (see §3.2) |
| **Related CWE** | CWE-326 (Inadequate Encryption Strength), CWE-320 (Key Management Errors) |

---

## 1. Explanation

### 1.1 Testing Objective and Its Standards Basis

Quote from the official MASTG overview, which explicitly references an international standard:

> *"According to section '5.2 Key Usage' of NIST SP 800-57 part 1 revision 5, cryptographic keys should be assigned a specific purpose and used only for that purpose (e.g., encryption, integrity authentication, key wrapping, random bit generation, or digital signatures). For example, a key intended for encryption should not be used for signing."*

This is one of the tests in this research series whose **theoretical basis** is most directly tied to a formal cryptographic standard (**NIST SP 800-57 Part 1 Rev. 5**, a cryptographic key management recommendation document that is widely referenced across the industry) — not merely a conventional best practice. The principle of **key separation by purpose** is a fundamental foundation in secure cryptographic system design: every key must be restricted to **only** one specific role (encryption, signing, wrapping other keys, etc.), and must not be "reused" across different roles.

### 1.2 Technical Mechanism: The `purposes` Bitmask on `KeyGenParameterSpec`

On Android, creating an asymmetric key pair via `KeyPairGenerator` is configured through `KeyGenParameterSpec.Builder`, which accepts an **integer bitmask** called `purposes` — a combination of `KeyProperties` constants:

```java
KeyProperties.PURPOSE_SIGN      // = 4   — sign data
KeyProperties.PURPOSE_VERIFY    // = 8   — verify a signature
KeyProperties.PURPOSE_ENCRYPT   // = 1   — encrypt data
KeyProperties.PURPOSE_DECRYPT   // = 2   — decrypt data
KeyProperties.PURPOSE_WRAP_KEY  // = 32  — wrap another key
```

Because `purposes` is a **bitmask** (the values are bitwise OR'd together), a single key technically **can** be configured to support any combination of roles — this is exactly what makes this test relevant: **the technical ability to mix roles does not mean it is safe to do so**, per the NIST SP 800-57 principle above.

### 1.3 Table of Acceptable vs. Unacceptable Values — A Crucial Detail from the Official Overview

This is the most precise and actionable part of this test's entire overview — it gives a **concrete numeric example** that forms the basis for the evaluation:

> *"For example, a purpose value of `15` combines all four purposes, which is not acceptable: (`PURPOSE_ENCRYPT`=1) | (`PURPOSE_DECRYPT`=2) | (`PURPOSE_SIGN`=4) | (`PURPOSE_VERIFY`=8) = 15"*

Combinations that are **ACCEPTABLE** (per the official overview) — each representing **a single role** (or a pair of operations that inherently belong to the **same role**, not two distinct roles):

| Bitmask Value | Composition | Role |
|---|---|---|
| `1` | `PURPOSE_ENCRYPT` alone | Encrypt/Decrypt |
| `2` | `PURPOSE_DECRYPT` alone | Encrypt/Decrypt |
| `3` | `PURPOSE_ENCRYPT`\|`PURPOSE_DECRYPT` | Encrypt/Decrypt (one whole role) |
| `4` | `PURPOSE_SIGN` alone | Sign/Verify |
| `8` | `PURPOSE_VERIFY` alone | Sign/Verify |
| `12` | `PURPOSE_SIGN`\|`PURPOSE_VERIFY` | Sign/Verify (one whole role) |
| `32` | `PURPOSE_WRAP_KEY` alone | Key Wrapping |

Combinations that are **UNACCEPTABLE** — any value that **mixes** bits from more than one role group, with the most extreme example being `15` (combining the **entire** Encrypt/Decrypt group **and** the entire Sign/Verify group in the same key) — but also values such as `5` (`ENCRYPT`|`SIGN` = 1+4), `9` (`ENCRYPT`|`VERIFY` = 1+8), `33` (`ENCRYPT`|`WRAP_KEY` = 1+32), and so on — **every** combination that crosses the boundary of the three role groups (Encrypt/Decrypt, Sign/Verify, Key Wrapping) is considered a violation of the separation principle.

### 1.4 Why Mixing Roles Is Dangerous: Theoretical Basis and Empirical Evidence

The risk of mixing key roles is not merely a matter of standards compliance formality — it has a **mathematical basis and real-world attack evidence** in cryptography literature. Academic protocol security research (*"The Dangers of Key Reuse: Practical Attacks on IPsec IKE"*, presented at the USENIX Security Symposium) demonstrates how **reusing a single key pair across different protocols/modes of operation** enables **cross-protocol attacks** — an attacker can leverage an **oracle** formed in one operational context (e.g., a decryption process in protocol/mode A) to **break** the security of another operational context (e.g., a signature verification process in protocol/mode B) that uses the **same cryptographic key**. The underlying mathematical principle: a cryptographic scheme proven secure for one type of operation (e.g., RSA encryption with OAEP padding) is **not automatically** proven secure when the same key is used for a different cryptographic operation (e.g., RSA signing with PKCS#1 padding) — the **security assumptions** underlying the formal proof of a cryptographic scheme often **explicitly assume** that the key is used **only** for the single type of operation being analyzed.

This explains why NIST SP 800-57 — the most authoritative key management standard in the industry — **explicitly** mandates key-role separation as one of its fundamental principles, not merely a cosmetic recommendation.

### 1.5 Additional Context from MASTG-KNOW-0012: Related Practices to Consider Simultaneously

MASTG-KNOW-0012 provides several additional pieces of context relevant to evaluating this test comprehensively:

- **GCM is preferred over CBC** for symmetric encryption modes because it provides built-in *authenticated encryption* — relevant as general context on cryptographic implementation quality, even though it is not the main topic of this test.
- **EC Key limitations since Android 11 (API 30)**: *"AndroidKeyStore does not support encryption or decryption with EC keys. They can only be used for signatures."* — this is a platform restriction that actually **helps** structurally enforce role separation for Elliptic Curve keys (EC cannot be used for encryption at all in modern Keystore, so the risk of role mixing for EC is automatically reduced on recent platforms).
- **Explicit warning about the NDK as a key "hiding place"**: *"There is a widespread false belief that the NDK should be used to hide cryptographic operations and hardcoded keys. However, this mechanism is ineffective."* — relevant as a general reminder that proper role separation **cannot be substituted** by obfuscation/hiding efforts via native code, a misconception that recurs repeatedly in mobile cryptography security audits.

---

## 2. Tools Used for Testing

### 2.1 Required Tools (Core)

| Tool | Function |
|---|---|
| **jadx** | Decompiles DEX → Java for searching `KeyGenParameterSpec.Builder` patterns |
| **grep / ripgrep** | Searching for constructor patterns and extracting `purposes` values |
| **semgrep** | Runs the official rule as a baseline location inventory |

### 2.2 Alternative & Supporting Tools

| Tool | Function |
|---|---|
| **CodeQL** | Traces literal/constant values passed as the `purposes` argument, computes bit combinations programmatically, and automatically classifies whether the combination crosses role-group boundaries (§1.3) |
| **Frida** | Hooks the `KeyGenParameterSpec.Builder` constructor to capture the actual `purposes` value at runtime, including cases where the value is built dynamically/conditionally, which are hard to analyze with pure static analysis |
| **MobSF** | Sometimes displays `KeyGenParameterSpec` usage in the Code Analysis report's cryptography category |

### 2.3 Environment Prerequisites

- **No device/root required** for core static analysis.
- **Basic understanding of bitwise arithmetic** is needed to interpret found `purposes` values, especially when combined indirectly (e.g., via intermediate variables rather than direct literals).

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0013** to reverse engineer the application.
2. Use **MASTG-TECH-0014** to search for the relevant APIs.

### 3.2 Method A — Official Semgrep Rule *(exists, and honestly only functions as a location collector)*

```yaml
rules:
  - id: mastg-android-asymmetric-key-pair-used-for-multiple-purposes
    severity: WARNING
    languages: [java]
    metadata:
      summary: Detects usage of KeyGenParameterSpec.Builder to collect observations for key-purposes evaluation.
    message: |
      [MASVS-CRYPTO-1] Detected usage of KeyGenParameterSpec.Builder. Review the configured purposes to ensure key separation (avoid mixing encryption/decryption with signing/verification or wrapping).
    pattern: |
      new KeyGenParameterSpec.Builder($ALIAS, $PURPOSES)
```

```bash
semgrep --config https://raw.githubusercontent.com/OWASP/mastg/master/rules/mastg-android-asymmetric-key-pair-used-for-multiple-purposes.yml ./decompiled/sources/
```

**An important note that distinguishes this rule from several other rules already analyzed in this research series**: this rule's `summary` **honestly** states that it is only *"to collect observations for key-purposes evaluation"* — it **does not claim** to be able to evaluate on its own whether the found bitmask combination violates the separation principle or not. This is consistent with its pattern, which purely matches the **constructor** `KeyGenParameterSpec.Builder($ALIAS, $PURPOSES)` without any evaluation logic for the `$PURPOSES` value. This rule **functions exactly as claimed** — unlike the misleading claim-vs-implementation pattern found in several other rules in this research series (`checkServerTrusted`, `onReceivedSslError`, `HostnameVerifier`).

### 3.3 Method B — grep/ripgrep with Manual Extraction and Calculation of the Bitmask Value

```bash
D=./decompiled/sources

# Find all KeyGenParameterSpec.Builder constructors along with their purposes argument
rg -n 'new KeyGenParameterSpec\.Builder\([^,]+,\s*([^)]+)\)' $D

# Find combinations using the OR operator (|) — candidates for role mixing
rg -n 'new KeyGenParameterSpec\.Builder\([^,]+,\s*KeyProperties\.\w+\s*\|\s*KeyProperties\.\w+' $D
```

For each result, manually calculate the bitmask value based on the constants found, and compare it against the table of acceptable values (§1.3).

### 3.4 Method C — CodeQL for Automatic Classification

```ql
import java

class KeyGenParameterSpecBuilderCall extends ClassInstanceExpr {
  KeyGenParameterSpecBuilderCall() {
    this.getConstructedType().hasQualifiedName("android.security.keystore", "KeyGenParameterSpec$Builder")
  }
}

from KeyGenParameterSpecBuilderCall call
select call, call.getArgument(1).toString(), "Manual verification: does this purposes value cross a role-group boundary (Encrypt/Decrypt vs Sign/Verify vs Wrap Key)?"
```

For full automatic classification, complement this with a Python script that parses the extracted literal values:

```python
PURPOSE_ENCRYPT, PURPOSE_DECRYPT, PURPOSE_SIGN, PURPOSE_VERIFY, PURPOSE_WRAP_KEY = 1, 2, 4, 8, 32

def classify_purpose(value: int) -> str:
    enc_dec = value & (PURPOSE_ENCRYPT | PURPOSE_DECRYPT)
    sign_verify = value & (PURPOSE_SIGN | PURPOSE_VERIFY)
    wrap = value & PURPOSE_WRAP_KEY

    groups_used = sum([1 for g in [enc_dec, sign_verify, wrap] if g != 0])
    if groups_used > 1:
        return f"FAIL — value {value} crosses {groups_used} role groups at once"
    return f"PASS — value {value} is within a single role group"

# Example from the official overview
print(classify_purpose(15))  # FAIL — crosses 2 groups (enc/dec AND sign/verify)
print(classify_purpose(3))   # PASS — enc/dec only
print(classify_purpose(12))  # PASS — sign/verify only
```

### 3.5 Method D — Frida for Runtime Confirmation

```javascript
// hook-keygenparameterspec-purposes.js
Java.perform(function () {
    var Builder = Java.use("android.security.keystore.KeyGenParameterSpec$Builder");
    Builder.$init.overload("java.lang.String", "int").implementation = function (alias, purposes) {
        console.log("[*] KeyGenParameterSpec.Builder(alias=" + alias + ", purposes=" + purposes + ")");
        var ENC = 1, DEC = 2, SIGN = 4, VERIFY = 8, WRAP = 32;
        var groupsUsed = 0;
        if ((purposes & (ENC | DEC)) !== 0) groupsUsed++;
        if ((purposes & (SIGN | VERIFY)) !== 0) groupsUsed++;
        if ((purposes & WRAP) !== 0) groupsUsed++;
        if (groupsUsed > 1) {
            console.log("    [!] FAIL — purposes crosses " + groupsUsed + " role groups!");
        }
        return this.$init(alias, purposes);
    };
});
```

### 3.6 Method Comparison: When to Use Which

| Method | Tool | Detects presence? | Evaluates bitmask value? | When to use |
|---|---|---|---|---|
| **A** | Official semgrep rule | ✅ | ❌ (honestly, as claimed) | Initial location inventory |
| **B** | grep + manual calculation | ✅ | Manual | Baseline for small codebases |
| **C** | CodeQL + Python script | ✅ | ✅ (automatic) | **Most efficient** for large codebases/many keys |
| **D** | Frida | ✅ (runtime) | ✅ (automatic) | Dynamically built values, hard to analyze statically |

**Recommended minimum combination:** **A (location inventory) → C (automatic bitmask classification)**, supplemented by **D** when a `purposes` value is suspected to be built conditionally/dynamically at runtime.

---

### 3.7 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rule:**

> **Evaluation:** *"The test case fails if you find any keys used for multiple roles (groups of purposes)."*

---

#### ❌ FAIL / ISSUE — The check is declared FAILED when:

| No | Condition |
|---|---|
| F1 | A key's `purposes` value crosses **more than one** role group (Encrypt/Decrypt, Sign/Verify, Wrap Key) — examples: `15`, `5`, `9`, `33`, or any cross-group combination |

**Example evidence (illustrative — MASTG does not yet provide an official demo for this test):**

```java
// Found in com/example/target/crypto/MultiPurposeKeyManager.java
KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(
    "master_key",
    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT |
    KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY
).build();
// purposes value = 1 | 2 | 4 | 8 = 15
```

Interpretation: the `master_key` key is configured for **all four** roles at once — a maximal violation of the NIST SP 800-57 separation principle. **Critical FAIL**.

---

#### ✅ PASS — The check is declared PASSED when:

| No | Condition |
|---|---|
| P1 | Every asymmetric key found is configured with a `purposes` value that falls within only **one** role group (per the table in §1.3) |
| P2 | An app that needs keys for different roles (e.g., one for encryption, one for signing) uses **separate key pairs** for each role, rather than one key configured across roles |

---

#### ⚠️ Important Notes on Assessment

1. **The official rule works exactly as claimed — do not expect more** — it is purely a location-inventory tool; evaluating the bitmask value remains entirely the tester's responsibility (manual or via Method C/D).

2. **Understand that bitmask values can be combined indirectly** — besides the literal `|` operator, a developer could build the `purposes` value through a variable assembled in a different place in the code; data-flow verification (Method C, CodeQL) is more reliable for this case than simple grep.

3. **If an app needs multiple cryptographic roles, the correct solution is multiple keys, not one multi-role key** — this is the most important remediation point to communicate to the development team.

4. **Severity is modulated:**

   | Factor | Severity |
   |---|---|
   | A key handling sensitive data is configured across all 3 role groups (encrypt+sign+wrap) | **High** |
   | A key crosses 2 role groups | **Medium-High** |
   | All keys are already properly separated by role | **Not a finding** |

5. **Document:** the key alias, the exact `purposes` bitmask value found, the role groups involved, and the number of groups violated (if FAIL).

---

## 4. Recommendations

### 4.1 Separate Keys by Role

```java
// BEFORE — one key for all roles
KeyGenParameterSpec badSpec = new KeyGenParameterSpec.Builder(
    "master_key",
    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT |
    KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY
).build();

// AFTER — separate key per role
KeyGenParameterSpec encryptionKeySpec = new KeyGenParameterSpec.Builder(
    "encryption_key",
    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT
).build();

KeyGenParameterSpec signingKeySpec = new KeyGenParameterSpec.Builder(
    "signing_key",
    KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY
).build();
```

### 4.2 Integrate Verification into CI/CD

```bash
#!/bin/bash
# ci-check-key-purpose-separation.sh
jadx -d /tmp/decompiled_check "$1" 2>/dev/null
rg -n 'new KeyGenParameterSpec\.Builder' /tmp/decompiled_check/sources/ | while read -r line; do
    echo "[MANUAL REVIEW] $line"
done
```

### 4.3 Remediation Checklist

- [ ] All `KeyGenParameterSpec.Builder` creations are inventoried along with their `purposes` values
- [ ] Every `purposes` value is verified to fall within a single role group
- [ ] Keys that violate separation are split into separate keys per role
- [ ] **Re-verify:** rerun MASTG-TEST-0307 after every addition of a new cryptographic key

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0307: References to Asymmetric Key Pairs Used For Multiple Purposes](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0307/)
- [MASWE-0007: Improper Encryption](https://mas.owasp.org/MASWE/MASVS-CRYPTO/MASWE-0007/)
- [MASTG-KNOW-0012: Key Generation](https://mas.owasp.org/MASTG/knowledge/android/MASVS-CRYPTO/MASTG-KNOW-0012/)
- [Official rule: mastg-android-asymmetric-key-pair-used-for-multiple-purposes.yml (GitHub)](https://github.com/OWASP/mastg/blob/master/rules/mastg-android-asymmetric-key-pair-used-for-multiple-purposes.yml)

### 5.2 Standards and Official Documentation

- [NIST SP 800-57 Part 1 Revision 5 — Recommendation for Key Management](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf)
- [Android Developers — `KeyGenParameterSpec.Builder`](https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder)
- [Android Developers — `KeyProperties`](https://developer.android.com/reference/android/security/keystore/KeyProperties)
- [Android Developers — Cryptography (Supported Ciphers)](https://developer.android.com/guide/topics/security/cryptography#SupportedCipher)

### 5.3 Academic Research

- [USENIX Security 2018 — The Dangers of Key Reuse: Practical Attacks on IPsec IKE (Felsch et al.)](https://www.usenix.org/conference/usenixsecurity18/presentation/felsch)
- [CWE-326: Inadequate Encryption Strength](https://cwe.mitre.org/data/definitions/326.html)
- [CWE-320: Key Management Errors](https://cwe.mitre.org/data/definitions/320.html)

### 5.4 Tool Documentation

- [Semgrep — Documentation](https://semgrep.dev/docs/)
- [CodeQL — Documentation](https://codeql.github.com/docs/)
- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [Frida — Dynamic instrumentation toolkit](https://frida.re/docs/javascript-api/)

---

*This document was compiled based on OWASP MASTG (latest release as of September 2026), the NIST SP 800-57 Part 1 Revision 5 standard, and USENIX Security academic research on the dangers of cryptographic key reuse across contexts. Unlike several other rules analyzed in this research series, the official semgrep rule for this test **honestly** acknowledges its limitations (purely collecting locations for manual review) — evaluating the `purposes` bitmask value still requires explicit bitwise arithmetic calculation, whether manual or automated via CodeQL/scripts, to determine whether a key violates the role-separation principle set out by NIST SP 800-57.*
