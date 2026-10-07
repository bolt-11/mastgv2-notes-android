# MASTG-TEST-0308 Runtime Use of Asymmetric Key Pairs Used For Multiple Purposes

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0308 |
| **Platform** | Android |
| **MASVS Category** | MASVS-CRYPTO (MASVS-CRYPTO-1) |
| **Weakness** | MASWE-0007 — *Improper Encryption* |
| **Highlighted API** | `Cipher.init(int opmode, Key key, ...)`, `Signature.initSign(PrivateKey)`, `Signature.initVerify(PublicKey)` |
| **Test Type** | **Dynamic, Hooks** |
| **Knowledge** | MASTG-KNOW-0012 (Key Generation) |
| **Related Techniques** | MASTG-TECH-0005 (Install App), MASTG-TECH-0043 (Method Hooking) |
| **Related Tests** | **MASTG-TEST-0307** (References to Asymmetric Key Pairs Used For Multiple Purposes) — the static counterpart; this test's official overview explicitly states *"This test is the dynamic counterpart to MASTG-TEST-0307, but it focuses on intercepting cryptographic operations rather than generating keys with multiple purposes"* |
| **Related Demo** | — (none) |
| **Official Rule** | — (not relevant; a dynamic hooking-based test) |
| **Related CWE** | CWE-326, CWE-320 |

---

## 1. Explanation

### 1.1 The Fundamental Distinction Stated by the Official Overview Itself

The official MASTG overview for this test explicitly and clearly marks **what distinguishes it** from MASTG-TEST-0307, with a sentence whose precision is rarely found elsewhere in this research series:

> *"This test is the dynamic counterpart to MASTG-TEST-0307, **but it focuses on intercepting cryptographic operations rather than generating keys with multiple purposes**."*

This is not merely "a dynamic version of the same thing" — it is a significant **shift in the object being tested**:

| | MASTG-TEST-0307 (Static) | MASTG-TEST-0308 (Dynamic, this document) |
|---|---|---|
| **What is inspected** | The `purposes` bitmask value **at the moment the key is CREATED** (`KeyGenParameterSpec.Builder`) | Cryptographic operations **at the moment the key is actually USED** (`Cipher.init()`, `Signature.initSign/initVerify()`) |
| **Point of observation** | Time of key declaration/configuration | Time of actual execution of the cryptographic operation |
| **Question answered** | "Is this key **configured** for more than one role?" | "Is this key **actually used** for more than one role in practice?" |

### 1.2 Why These Two Questions Can Yield Different Answers

This is an important conceptual point to understand before running both tests together — **the results of MASTG-TEST-0307 and MASTG-TEST-0308 for the same key will not always align**:

- **Scenario A — FAIL in 0307, but not observed in 0308**: a key is configured with `purposes = 15` (all four roles at once, FAIL in MASTG-TEST-0307), yet in practice the app **only ever calls** `Cipher.init(ENCRYPT_MODE, key)` throughout the dynamic testing session — the `Signature.initSign()`/`initVerify()` operations on the same key are **never triggered** because that code path was not exercised by the tester. In this case, **MASTG-TEST-0307 remains a valid FAIL signal** (the dangerous capability still exists structurally and could be exploited at any time by another code path or a future app version), **even though** MASTG-TEST-0308 in that particular testing session did not capture actual evidence of dual usage.
- **Scenario B — PASS in 0307 (textually), but FAIL in 0308**: this is a rarer but still possible scenario — e.g., when the same key alias is reused to reference **a different key object** at different points in the code (a confusing but valid pattern within the Android Keystore API), such that pure static analysis struggles to correlate that the "same" key is logically used across roles, while direct dynamic observation captures the actual cross-role usage via the consistent alias.

This underscores the **complementary value** of both tests — MASTG-TEST-0307 provides **complete structural coverage** (including capabilities that have never been triggered), while MASTG-TEST-0308 provides **real behavioral evidence** of what actually happens when the app is used — refer to the same analogous pattern discussed in depth in the MASTG-TEST-0264 document in this research series (`StrictMode` — hooking vs. logging) regarding how static and dynamic approaches can complement each other's gaps.

### 1.3 The Three Key APIs to Hook and Their Mapping to Role Groups

The official overview clearly maps which APIs are relevant to each role group (identical to the three groups already discussed in depth in the MASTG-TEST-0307 document §1.3):

| API to Hook | Determining Parameter | Role Group |
|---|---|---|
| `Cipher.init(opmode, key, ...)` | `opmode = Cipher.ENCRYPT_MODE` or `Cipher.DECRYPT_MODE` | Encrypt/Decrypt |
| `Cipher.init(opmode, key, ...)` | `opmode = Cipher.WRAP_MODE` or `Cipher.UNWRAP_MODE` | Key Wrapping |
| `Signature.initSign(privateKey)` | — | Sign/Verify |
| `Signature.initVerify(publicKey)` | — | Sign/Verify |

An important technical point: `Cipher.init()` is **a single method that serves two different role groups** (Encrypt/Decrypt **and** Key Wrapping), distinguished **only** by the `opmode` parameter value passed to it. This means a hook on `Cipher.init()` **must** explicitly check the `opmode` value to correctly classify the operation — simply logging "Cipher.init() was called" without distinguishing the mode is not enough to answer this test's evaluation question.

### 1.4 Unique Value: Cross-Call Correlation Based on Key Identity

The main technical challenge in effectively implementing this test is **correlating** whether the `Key`/`PrivateKey`/`PublicKey` object appearing in a `Cipher.init()` call at one code location **is the same key** as the one appearing in `Signature.initSign()`/`initVerify()` at another code location. On Android Keystore, a key's identity is practically represented by its **alias** (the string used when calling `KeyGenParameterSpec.Builder(alias, ...)` or `KeyStore.getKey(alias, ...)`) — so an effective hook needs to capture this **alias** at whatever point possible (e.g., by tracing back from the `Key` object to the `KeyStore.Entry` that produced it), rather than merely logging operations in isolation without key-identity context.

---

## 2. Tools Used for Testing

### 2.1 Required Tools (Core)

| Tool | Function |
|---|---|
| **Frida** | Core dynamic instrumentation — hooking `Cipher.init()` and `Signature.initSign/initVerify()` |
| **frida-tools** (`frida-trace`) | Quick tracing without a custom script |
| **objection** | Ready-to-use Frida wrapper |

### 2.2 Alternative & Supporting Tools

| Tool | Function |
|---|---|
| **Xposed/LSPosed** | An alternative persistent hooking approach per MASTG-TECH-0043 |
| **adb logcat** | Additional correlation if the app logs information related to cryptographic operations (though this itself could become a finding under MASTG-TEST-0203/0231 if it contains sensitive details) |

### 2.3 Environment Prerequisites

- **A device/emulator with a Frida server is required** — this is a purely dynamic test.
- **Thorough interaction with the app** per the official steps — *"exercise the app extensively to trigger as many flows as possible"* — crucial given Scenario A in §1.2: cryptographic operations that are rarely triggered (account recovery flows, rarely used document signature verification) risk going undetected if interaction is not thorough.
- **Ideally run alongside the results of MASTG-TEST-0307** to obtain a list of candidate key aliases that should be prioritized for triggering during the dynamic session.

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0005** to install the app.
2. Use **MASTG-TECH-0043** to hook the relevant API calls.
3. Explore the app thoroughly, entering sensitive data wherever possible.

### 3.2 Method A — Frida Script with Key Alias Correlation *(primary method)*

```javascript
// hook-key-purpose-runtime.js
Java.perform(function () {
    function getBacktrace() {
        return Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());
    }

    // Global map to correlate key aliases with the role groups they have been used for
    var keyUsageMap = {};

    function recordUsage(alias, group) {
        if (!keyUsageMap[alias]) keyUsageMap[alias] = {};
        keyUsageMap[alias][group] = true;
        var groupsUsed = Object.keys(keyUsageMap[alias]);
        if (groupsUsed.length > 1) {
            console.log("\n[!!!] FAIL DETECTED — alias '" + alias + "' used for groups: " + groupsUsed.join(", "));
            console.log("    Backtrace:\n" + getBacktrace());
        }
    }

    function getAliasFromKey(key) {
        try {
            // Heuristic approach: many AndroidKeyStore Key implementations store an alias
            // that can be accessed via reflection or toString()
            return key.toString();
        } catch (e) { return "UNKNOWN_ALIAS"; }
    }

    // 1. Cipher.init() — distinguishing ENCRYPT/DECRYPT vs WRAP/UNWRAP
    var Cipher = Java.use("javax.crypto.Cipher");
    Cipher.init.overload("int", "java.security.Key").implementation = function (opmode, key) {
        var alias = getAliasFromKey(key);
        var ENCRYPT_MODE = 1, DECRYPT_MODE = 2, WRAP_MODE = 3, UNWRAP_MODE = 4;
        var group = (opmode === WRAP_MODE || opmode === UNWRAP_MODE) ? "WRAP_KEY" : "ENCRYPT_DECRYPT";
        console.log("[*] Cipher.init(opmode=" + opmode + ", alias=" + alias + ") -> group: " + group);
        recordUsage(alias, group);
        return this.init(opmode, key);
    };

    // 2. Signature.initSign()
    var Signature = Java.use("java.security.Signature");
    Signature.initSign.overload("java.security.PrivateKey").implementation = function (privateKey) {
        var alias = getAliasFromKey(privateKey);
        console.log("[*] Signature.initSign(alias=" + alias + ") -> group: SIGN_VERIFY");
        recordUsage(alias, "SIGN_VERIFY");
        return this.initSign(privateKey);
    };

    // 3. Signature.initVerify()
    Signature.initVerify.overload("java.security.PublicKey").implementation = function (publicKey) {
        var alias = getAliasFromKey(publicKey);
        console.log("[*] Signature.initVerify(alias=" + alias + ") -> group: SIGN_VERIFY");
        recordUsage(alias, "SIGN_VERIFY");
        return this.initVerify(publicKey);
    };
});
```

```bash
frida -U -f com.target.app -l hook-key-purpose-runtime.js --no-pause
```

### 3.3 Method B — objection (Without Writing a Custom Script)

```bash
objection -g com.target.app explore
android hooking watch class_method javax.crypto.Cipher.init --dump-args --dump-backtrace
android hooking watch class_method java.security.Signature.initSign --dump-args --dump-backtrace
android hooking watch class_method java.security.Signature.initVerify --dump-args --dump-backtrace
```

With this approach, cross-call correlation (whether the same `key` argument appears in both types of hooks) is performed **manually** by the tester from the dump output, unlike Method A, which automates this correlation via `keyUsageMap`.

### 3.4 Method C — frida-trace for a Quick Overview

```bash
frida-trace -U -f com.target.app -m "javax.crypto.Cipher!init" -m "java.security.Signature!init*"
```

### 3.5 Method Comparison: When to Use Which

| Method | Tool | Automatic alias correlation? | When to use |
|---|---|---|---|
| **A** | Custom Frida script | ✅ | Primary baseline, most efficient for automatic detection |
| **B** | objection | ❌ (manual) | Quick initial exploration without scripting |
| **C** | frida-trace | ❌ | Quick overview before detailed hooking |

**Recommended minimum combination:** **A (automatic correlation) with thorough interaction** → correlate the results with **MASTG-TEST-0307** for a complete picture (structural + real behavior).

---

### 3.6 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rule:**

> **Observation:** *"The output should contain a list of all cryptographic operations together with their corresponding keys."*
>
> **Evaluation:** *"The test case fails if you find any keys used for multiple roles."*

---

#### ❌ FAIL / ISSUE — The check is declared FAILED when:

| No | Condition |
|---|---|
| F1 | The same key/alias is confirmed to be used for **more than one** operation group (Encrypt/Decrypt, Sign/Verify, Wrap Key) during the dynamic testing session |

**Example evidence (illustrative — MASTG does not yet provide an official demo for this test):**

```
[*] Cipher.init(opmode=1, alias=master_key) -> group: ENCRYPT_DECRYPT
[*] Signature.initSign(alias=master_key) -> group: SIGN_VERIFY

[!!!] FAIL DETECTED — alias 'master_key' used for groups: ENCRYPT_DECRYPT, SIGN_VERIFY
    Backtrace:
        at com.example.target.crypto.DocumentSigner.signAndEncrypt(DocumentSigner.java:58)
```

Interpretation: the alias `master_key` is confirmed to be **actually** used for both encryption **and** signing operations within the `signAndEncrypt()` flow — definitive dynamic evidence that complements (and strengthens) the static finding from MASTG-TEST-0307 if the same key is also detected being configured with cross-group `purposes`.

---

#### ✅ PASS — The check is declared PASSED when:

| No | Condition |
|---|---|
| P1 | Every key alias observed during the thorough testing session is **only** used for one operation group consistently |

---

#### ⚠️ Important Notes on Assessment

1. **A result of "no dual usage found" does NOT automatically invalidate a FAIL finding from MASTG-TEST-0307** — per §1.2 Scenario A, a dangerous capability configured statically remains a structural risk even if it has not been observed being used in a dual manner during a particular dynamic testing session. **Always report both results separately and clearly — do not let a PASS in 0308 "overshadow" a FAIL in 0307.**

2. **Alias-based correlation is the key to this methodology's success** — ensure the hooking script can genuinely identify a key alias consistently across calls; if `toString()` on the `Key` object does not provide clear alias information, consider an additional reflection approach or correlation based on code location (stack trace) as a proxy for identity.

3. **Thorough interaction is an absolute prerequisite** for a convincing negative result — rarely triggered code paths (verification of uploaded document signatures, account recovery flows) risk being missed if the testing session is not truly comprehensive.

4. **Severity is modulated** following the same pattern as the MASTG-TEST-0307 document — based on the sensitivity of the data processed and the number of role groups mixed.

5. **Document:** the observed key aliases, the operation group detected for each, the stack trace of the call location, and the explicit correlation with the MASTG-TEST-0307 results.

---

## 4. Recommendations

The recommendations are identical to **the MASTG-TEST-0307 document §4** — separate keys by role starting from the creation level (`KeyGenParameterSpec`). If this test (0308) finds dual usage that is **not** detected in 0307 (Scenario B in §1.2), this indicates a possible ambiguous reuse of a key alias in the code — investigate further via MASTG-TECH-0023 to understand why static correlation failed to catch this pattern.

### 4.1 Remediation Checklist

- [ ] Hooking covers all three APIs (`Cipher.init` with opmode distinction, `Signature.initSign`, `Signature.initVerify`)
- [ ] Key alias correlation works reliably across calls
- [ ] Testing interaction covers all flows involving cryptographic operations
- [ ] Results are explicitly correlated with MASTG-TEST-0307
- [ ] **Re-verify:** rerun MASTG-TEST-0308 after every change to the app's cryptographic flows

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0308: Runtime Use of Asymmetric Key Pairs Used For Multiple Purposes](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0308/)
- [MASTG-TEST-0307: References to Asymmetric Key Pairs Used For Multiple Purposes](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0307/)
- [MASWE-0007: Improper Encryption](https://mas.owasp.org/MASWE/MASVS-CRYPTO/MASWE-0007/)
- [MASTG-KNOW-0012: Key Generation](https://mas.owasp.org/MASTG/knowledge/android/MASVS-CRYPTO/MASTG-KNOW-0012/)
- [MASTG-TECH-0005: Installing Apps](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0005/)
- [MASTG-TECH-0043: Method Hooking](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0043/)

### 5.2 Official Android Documentation

- [Android Developers — `Cipher#init()` API reference](https://developer.android.com/reference/javax/crypto/Cipher#init(int,%20java.security.Key,%20java.security.AlgorithmParameters))
- [Android Developers — `Signature#initSign()`](https://developer.android.com/reference/java/security/Signature#initSign(java.security.PrivateKey))
- [Android Developers — `Signature#initVerify()`](https://developer.android.com/reference/java/security/Signature#initVerify(java.security.PublicKey))

### 5.3 Tool Documentation

- [Frida — Dynamic instrumentation toolkit](https://frida.re/docs/javascript-api/)
- [Objection — Runtime Mobile Exploration toolkit](https://github.com/sensepost/objection)
- [frida-trace — Documentation](https://frida.re/docs/frida-trace/)

---

*This document was compiled based on OWASP MASTG (latest release as of September 2026) and official Android Developers documentation. As the dynamic counterpart to MASTG-TEST-0307, this test explicitly shifts the focus from "how a key is configured" to "how a key is actually used" — a shift stated directly by its own official overview. The most important nuance: the results of both tests can complement each other but are not always identical — a dangerous capability detected statically (MASTG-TEST-0307) remains a valid finding even if it has not been observed being used in a dual manner during a particular dynamic testing session, so both results must be reported and assessed separately, not treated as substitutes for one another.*
