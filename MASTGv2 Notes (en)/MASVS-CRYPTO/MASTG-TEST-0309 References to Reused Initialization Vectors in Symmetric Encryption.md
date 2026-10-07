# MASTG-TEST-0309 References to Reused Initialization Vectors in Symmetric Encryption

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0309 |
| **Platform** | Android |
| **MASVS Category** | MASVS-CRYPTO (MASVS-CRYPTO-1) |
| **Weakness** | MASWE-0007 — *Improper Encryption* |
| **Test Type** | Static, Code |
| **Official MASTG Status** | **`placeholder`** — no complete Overview/Steps/Evaluation yet |
| **Official note (the only content available)** | *"Reusing a symmetric key is acceptable when IVs or nonces follow the rules defined for the mode. NIST SP 800-38A states that CBC requires a fresh or unpredictable IV for every encryption. NIST SP 800-38D states that counter based modes require a nonce that never repeats under the same key. Repeating a key and IV or nonce pair defeats confidentiality and can also undermine integrity."* |
| **Related Tests** | Closely related to MASTG-TEST-0232 (Broken Symmetric Encryption Modes — ECB) and MASTG-TEST-0221 (Broken Symmetric Encryption Algorithms) in this research series — together they form the complete spectrum of Android symmetric encryption misconfigurations |
| **Related Demo** | — (none) |
| **Official Rule** | — (none) |
| **Related CWE** | CWE-1204 (Generation of Weak Initialization Vector), CWE-323 (Reusing a Nonce, Key Pair in Encryption), CWE-329 (Generation of Predictable IV with CBC Mode) |

---

## 1. Explanation

### 1.1 Testing Objective and a Crucial Early Nuance

This test's official note (though brief) already contains an opening sentence that **explicitly prevents the most common misinterpretation**:

> *"Reusing a symmetric key is acceptable when IVs or nonces follow the rules defined for the mode."*

This is important to state up front because **reusing the same symmetric key repeatedly is entirely normal and expected** in cryptographic practice — e.g., one `SecretKey` used to encrypt many messages/data records over time. **The problem is not key reuse itself**, but rather **reusing an identical (key, IV/nonce) pair**. This test specifically targets the **IV/nonce** — not the key — as the component that must always differ on every encryption operation, even though the key remains the same.

### 1.2 Two Different Rules for Two Categories of Mode of Operation

This is the **most important technical nuance** in this entire document — the official note explicitly distinguishes **two different NIST standards** for two different categories of block cipher mode, with **non-identical requirements**:

| Mode | NIST Standard | IV/Nonce Requirement | Key Term |
|---|---|---|---|
| **CBC** (Cipher Block Chaining) | **NIST SP 800-38A** | The IV must be **fresh or unpredictable** for every encryption operation | **Unpredictability** |
| **Counter-based modes** (CTR, **GCM**) | **NIST SP 800-38D** | The nonce must **never repeat** under the same key | **Uniqueness** (not necessarily unpredictable) |

This difference is **very subtle yet technically important**: for **CBC**, the IV must be **unpredictable** (an attacker must not be able to guess the IV that will be used **before** the encryption operation occurs — this prevents attacks like **BEAST**, which exploited predictable CBC IVs in older SSL/TLS). Meanwhile, for **counter-based modes** like **GCM**, the requirement is **looser in one aspect but stricter in another** — the nonce **does not need to be** unpredictable (a nonce that is a **simple sequential counter** such as 0, 1, 2, 3... is fully valid and safe for GCM), but it **must absolutely never repeat** for the lifetime of that key — even a single repetition is enough to **catastrophically** collapse security (discussed in §1.4).

### 1.3 Why IV Repetition on CBC Is Dangerous: Pattern Leakage

For CBC mode, IV repetition (especially when it is **static/hardcoded**, the most commonly found pattern in the field) creates a consequence similar to the ECB mode weakness already discussed in depth in the **MASTG-TEST-0232** document in this research series: **the first identical plaintext block will always produce the first identical ciphertext block**, as long as the key and IV used are the same. This opens a **pattern-matching attack** path without needing to decrypt anything — simply comparing ciphertext is enough.

### 1.4 Why Nonce Repetition on GCM Is Far More Fatal: The "Forbidden Attack"

This is the most crucial part for testers to understand, and it explains why the official note closes with the firm sentence: *"Repeating a key and IV or nonce pair defeats confidentiality and **can also undermine integrity**."* Academic cryptographic research shows that nonce repetition on **AES-GCM is not merely "security degradation"** — it is a **total cryptographic collapse**, via a two-stage attack:

> **Stage 1 — Confidentiality Failure (Keystream Recovery)**: *"If two plaintexts P1 and P2 are encrypted with the same key and the same nonce, their ciphertexts satisfy C1 XOR C2 = P1 XOR P2."* — an attacker can directly obtain the **XOR of two plaintexts** without needing the key at all, simply from two ciphertexts that used the same key-nonce pair.
>
> **Stage 2 — Integrity Failure (Authentication Key Recovery)**: *"Nonce reuse in AES-GCM allows an attacker... to recover P1 ⊕ P2 and, via Joux's 'forbidden attack,' solve a polynomial equation over GF(2^128) for candidate GHASH keys H — enabling tag forgery."*

This technique is known as the **"forbidden attack"** (named after the cryptography researcher Antoine Joux, who first demonstrated it) — with two (plaintext, ciphertext) pairs that used the same key-nonce, an attacker can **solve a polynomial equation** to **fully recover the GHASH authentication key**. Once this authentication key is successfully recovered, the attacker **can not only decrypt** encrypted messages — they can also **forge** new ciphertext that **still passes integrity verification** (a valid *authentication tag*), fully collapsing both the confidentiality **and** the integrity guarantees that are the very reason GCM was chosen as an *authenticated encryption* mode in the first place.

### 1.5 Real-World Case: `InsecureBankv2` and the Static Zero-IV Pattern

The security training app `InsecureBankv2` — explicitly designed to demonstrate real-world vulnerabilities — exemplifies a pattern that is **very commonly** found in actual production applications:

> *"`InsecureBankv2` uses an IV of sixteen zero bytes, hardcoded as a static array... `InsecureBankv2` is a training app, but every single vulnerability in it appears in real production applications. If two users share the same password, their encrypted values in SharedPreferences or on the server are byte-for-byte identical. An attacker who captures one known password can build a lookup table and match it against every other encrypted password in the database — no brute force required, just pattern matching."*

This very concretely illustrates the practical consequences of a static all-zero IV (a `byte[16]` that is not explicitly initialized in Java/Kotlin **defaults** to all zeros — a trap that causes developers who forget to explicitly fill in the IV to **unintentionally** fall into this most-vulnerable pattern without ever consciously writing an IV value).

### 1.6 Real-World CVE Case: CVE-2026-50210

Research uncovered a contemporary CVE that precisely illustrates this pattern at a real product scale:

> *"CVE-2026-50210 documents a cryptographic weakness in a device that encrypts data using AES-CBC with a static, zero-filled Initialization Vector (IV). Attackers observing ciphertext can correlate identical plaintext blocks across sessions, replay captured traffic, and mount known-plaintext decryption attacks."*

This case is also consistent with older historical precedents relevant as additional context: **CVE-2011-3389 (the BEAST attack)** on SSL/TLS, which exploited predictable CBC IVs, and **CVE-2020-1472 (ZeroLogon)**, which exploited a static zero IV on AES-CFB8 in Microsoft's Netlogon authentication protocol — confirming that this class of vulnerability **recurs repeatedly** across platforms and decades, rather than being merely an exotic/specific Android mistake.

---

## 2. Tools Used for Testing

### 2.1 Required Tools (Core)

| Tool | Function |
|---|---|
| **jadx** | Decompiles DEX → Java for searching IV/nonce construction patterns |
| **grep / ripgrep** | Searching for `IvParameterSpec`/`GCMParameterSpec` patterns and the byte sources used |

### 2.2 Alternative & Supporting Tools

| Tool | Function |
|---|---|
| **CodeQL** | Traces whether the byte array passed to `IvParameterSpec`/`GCMParameterSpec` originates from a **static constant/literal** (dangerous) vs. `SecureRandom`/a properly managed counter mechanism (safe) |
| **Frida** | Hooks `Cipher.init()` to capture the actual IV/nonce value used in each call at runtime, and compares whether the same value appears repeatedly |
| **MobSF** | Sometimes flags static IV patterns in the Code Analysis report's cryptography category |

### 2.3 Environment Prerequisites

- **No device/root required** for core static analysis.
- **Identifying the cipher mode used** (CBC vs. GCM/CTR) is a mandatory first step — it determines which NIST standard (SP 800-38A vs. SP 800-38D) is relevant for the assessment (§1.2).

---

## 3. Testing Methodology

Because there are no detailed official steps (placeholder status), the following methodology is constructed by elaborating on the official note and the NIST standards it references.

### 3.1 General Steps

1. Identify all `Cipher.getInstance()` calls using CBC/GCM/CTR mode.
2. For each call, trace the **origin** of the byte array used as the IV (`IvParameterSpec`) or nonce (`GCMParameterSpec`).
3. Classify that source: static literal/constant (FAIL) vs. `SecureRandom`/a correctly managed counter mechanism (candidate PASS).

### 3.2 Method A — grep/ripgrep for Static IV/Nonce Patterns

```bash
D=./decompiled/sources

# The most suspicious pattern: a literal byte array passed as the IV
rg -n 'new IvParameterSpec\(new byte\[\]\s*\{' $D
rg -n 'new GCMParameterSpec\([^,]+,\s*new byte\[\]\s*\{' $D

# Implicit zero-IV pattern (array not explicitly initialized)
rg -n 'new byte\[16\]\s*;' $D -A5 | grep -B5 "IvParameterSpec"

# SAFE pattern that should be found as a comparison baseline
rg -n 'SecureRandom\(\).*nextBytes' $D
```

### 3.3 Method B — CodeQL for Classifying the IV/Nonce Source

```ql
import java

class IvParameterSpecCreation extends ClassInstanceExpr {
  IvParameterSpecCreation() {
    this.getConstructedType().hasQualifiedName("javax.crypto.spec", "IvParameterSpec") or
    this.getConstructedType().hasQualifiedName("javax.crypto.spec", "GCMParameterSpec")
  }
}

from IvParameterSpecCreation creation
where creation.getAnArgument() instanceof ArrayInit  // a direct byte array literal
select creation, "IV/nonce built from a static array literal — potentially repeated on every call"
```

```ql
// Complement: verify SecureRandom is NOT found around the IV creation (strong indicator of a static value)
import java

from IvParameterSpecCreation creation
where not exists(MethodAccess secureRandomCall |
  secureRandomCall.getMethod().getDeclaringType().hasQualifiedName("java.security", "SecureRandom") and
  secureRandomCall.getEnclosingCallable() = creation.getEnclosingCallable())
select creation, "IV/nonce created WITHOUT SecureRandom in the same method — manually verify its source"
```

### 3.4 Method C — Frida for Runtime Confirmation (Detecting Actual Repetition)

```javascript
// hook-iv-nonce-reuse.js
Java.perform(function () {
    var seenIVs = {};
    var GCMParameterSpec = Java.use("javax.crypto.spec.GCMParameterSpec");
    var IvParameterSpec = Java.use("javax.crypto.spec.IvParameterSpec");

    IvParameterSpec.$init.overload("[B").implementation = function (iv) {
        var ivHex = Array.from(Java.array('byte', iv)).map(b => (b & 0xff).toString(16).padStart(2, '0')).join('');
        if (seenIVs[ivHex]) {
            console.log("\n[!!!] REPEATED IV DETECTED: " + ivHex + " (already used before!)");
        }
        seenIVs[ivHex] = (seenIVs[ivHex] || 0) + 1;
        console.log("[*] IvParameterSpec created with IV: " + ivHex + " (occurrence #" + seenIVs[ivHex] + ")");
        return this.$init(iv);
    };
});
```

```bash
frida -U -f com.target.app -l hook-iv-nonce-reuse.js --no-pause
# Explore the app thoroughly, repeatedly trigger encryption operations
```

This method provides the **most definitive evidence** — if an **identical byte-for-byte** IV/nonce is found being used more than once, this directly confirms the FAIL condition without ambiguity.

### 3.5 Method Comparison: When to Use Which

| Method | Tool | Detects static literal IVs? | Detects actual repetition? | When to use |
|---|---|---|---|---|
| **A** | grep | ✅ | ❌ | Quick baseline |
| **B** | CodeQL | ✅ (systematic) | ❌ | Large codebases |
| **C** | Frida | Indirectly | ✅ (definitive evidence) | Final confirmation, especially for dynamically built IVs that still follow a repeating pattern |

**Recommended minimum combination:** **A/B (identify static IV candidates) → C (dynamic confirmation of actual repetition)**.

---

### 3.6 Evaluation Criteria: Positive Case & Negative Case

Because there is no official Evaluation clause (placeholder status), the following criteria are constructed based on the official note and the NIST SP 800-38A/800-38D standards it references.

---

#### ❌ FAIL / ISSUE — The check is declared FAILED when:

| No | Condition |
|---|---|
| F1 | **CBC** mode uses a **static/hardcoded** IV (including an implicit zero IV from an uninitialized array) — violating the *unpredictability* requirement of NIST SP 800-38A |
| F2 | **GCM/CTR** mode uses a nonce **confirmed to repeat** (via Method C) under the same key — violating the *uniqueness* requirement of NIST SP 800-38D, the most critical condition given the "forbidden attack" impact (§1.4) |
| F3 | The IV/nonce is built from a **predictable** source (e.g., a low-precision timestamp, a counter that resets every time the app session restarts without proper persistence) |

**Example evidence (illustrative — MASTG does not yet provide an official demo for this test):**

```java
// Found in com/example/target/crypto/LegacyEncryptor.java
public class LegacyEncryptor {
    private static final byte[] STATIC_IV = new byte[16]; // ALWAYS zero — never populated

    public byte[] encrypt(byte[] data, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(STATIC_IV));
        return cipher.doFinal(data);
    }
}
```

Interpretation: `STATIC_IV` is a 16-byte array that is **never populated** with a value, so it always contains zeros — every call to `encrypt()` uses an **identical** IV. **FAIL**, exactly the pattern found in `InsecureBankv2` and CVE-2026-50210.

---

#### ✅ PASS — The check is declared PASSED when:

| No | Condition |
|---|---|
| P1 | CBC mode uses an IV freshly generated via `SecureRandom` for **every** encryption operation |
| P2 | GCM/CTR mode uses a nonce guaranteed to be **unique** (either via `SecureRandom` with a sufficiently large value space, or a counter that is correctly managed and persisted across app sessions) |
| P3 | Dynamic verification (Method C) confirms no identical IV/nonce value is repeated during a thorough testing session |

---

#### ⚠️ Important Notes on Assessment

1. **Understand the different requirements of CBC vs. GCM/CTR** (§1.2) — do not apply the "must be unpredictable" criterion uniformly across all modes; a **unique** sequential counter nonce is already safe enough for GCM even though it is technically "predictable."

2. **Prioritize findings in GCM mode higher than CBC** if both are found — the consequence of nonce repetition on GCM is far more catastrophic (full authentication key recovery) than IV repetition on CBC (plaintext pattern leakage).

3. **A byte array not explicitly initialized in Java/Kotlin always defaults to zero** — this is a common trap that causes developers to "unintentionally" create a FAIL condition without ever consciously writing an IV value; watch for `new byte[N]` declarations used directly without a subsequent `SecureRandom.nextBytes()` call.

4. **Dynamic confirmation (Method C) is the most convincing proof** — static analysis can only identify **candidate** sources of a dangerous IV; actual repetition can only be definitively proven through runtime observation.

5. **Severity is modulated:**

   | Factor | Severity |
   |---|---|
   | GCM nonce proven to repeat on a key handling sensitive data | **Critical** (risk of full authentication key recovery) |
   | Static/hardcoded CBC IV on sensitive data | **High** |
   | IV/nonce correctly generated but not properly persisted across app restarts (potential future repetition) | **Medium** |

6. **Document:** the cipher mode used, the IV/nonce source (literal/SecureRandom/counter), the dynamic repetition verification results, and the relevant NIST standard violated.

---

## 4. Recommendations

### 4.1 For CBC: Generate a Fresh IV via SecureRandom

```java
byte[] iv = new byte[16];
new SecureRandom().nextBytes(iv);  // A new IV for EVERY encryption operation
Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
// Store the IV alongside the ciphertext — the IV does not need to be secret
```

### 4.2 For GCM: Ensure the Nonce Is Unique, Consider Migrating Away From CBC

```java
byte[] nonce = new byte[12];  // 96-bit, GCM's standard size
new SecureRandom().nextBytes(nonce);
GCMParameterSpec gcmSpec = new GCMParameterSpec(128, nonce);
Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
```

Refer to the MASTG-TEST-0232 document §4 for a complete discussion of why migrating from CBC to GCM is recommended as an overall stronger architectural solution.

### 4.3 Remediation Checklist

- [ ] All `IvParameterSpec`/`GCMParameterSpec` creations are inventoried and their sources verified
- [ ] No IV/nonce is built from a static literal/constant
- [ ] The IV/nonce is generated via `SecureRandom` for every encryption operation
- [ ] Dynamic verification confirms no identical value is repeated
- [ ] Consider migrating from CBC to GCM for new implementations
- [ ] **Re-verify:** rerun MASTG-TEST-0309 after every change to the encryption flow

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0309: References to Reused Initialization Vectors in Symmetric Encryption](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0309/)
- [MASTG-TEST-0232: Broken Symmetric Encryption Modes](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0232/)
- [MASWE-0007: Improper Encryption](https://mas.owasp.org/MASWE/MASVS-CRYPTO/MASWE-0007/)

### 5.2 Official Standards

- [NIST SP 800-38A: Recommendation for Block Cipher Modes of Operation](https://csrc.nist.gov/pubs/sp/800/38/a/final)
- [NIST SP 800-38D: Recommendation for Block Cipher Modes of Operation — GCM and GMAC](https://csrc.nist.gov/pubs/sp/800/38/d/final)
- [CWE-1204: Generation of Weak Initialization Vector (IV)](https://cwe.mitre.org/data/definitions/1204.html)
- [CWE-323: Reusing a Nonce, Key Pair in Encryption](https://cwe.mitre.org/data/definitions/323.html)
- [CWE-329: Generation of Predictable IV with CBC Mode](https://cwe.mitre.org/data/definitions/329.html)

### 5.3 Research and Real-World Cases

- [SentinelOne — CVE-2026-50210: AES-CBC Encryption Weakness Vulnerability](https://www.sentinelone.com/vulnerability-database/cve-2026-50210/)
- [Medium — Tearing Apart InsecureBankv2](https://medium.com/@mohamed0salah213/breaking-insecurebankv2-a-deep-dive-into-android-security-failures-10b18b88e9be)
- [Medium — AES-GCM Nonce Reuse Attack From Scratch](https://medium.com/@patrickl.publique/aes-gcm-nonce-reuse-attack-515f7acec3f7)
- [frereit.de — AES-GCM and Breaking It on Nonce Reuse](https://frereit.de/aes_gcm/)
- [USENIX WOOT16 — Nonce-Disrespecting Adversaries: Practical Forgery Attacks on GCM in TLS](https://www.usenix.org/sites/default/files/conference/protected-files/woot16_slides_bock.pdf)

### 5.4 Tool Documentation

- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [CodeQL — Documentation](https://codeql.github.com/docs/)
- [Frida — Dynamic instrumentation toolkit](https://frida.re/docs/javascript-api/)

---

*This document was compiled entirely from independent research (NIST SP 800-38A/800-38D standards, academic cryptographic research, and real-world cases including CVE-2026-50210) because MASTG-TEST-0309 has **placeholder** status. The most important nuance: CBC and GCM/CTR have different IV/nonce requirements (unpredictability vs. uniqueness) and consequences of violation that differ greatly in severity — nonce repetition on GCM is not merely security degradation, but a total cryptographic collapse via Joux's "forbidden attack," which fully recovers the GHASH authentication key, enabling both decryption and forgery of ciphertext that passes integrity verification.*
