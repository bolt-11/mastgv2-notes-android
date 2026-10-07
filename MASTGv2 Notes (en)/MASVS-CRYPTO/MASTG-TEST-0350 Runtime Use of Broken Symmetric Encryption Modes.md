# MASTG-TEST-0350 Runtime Use of Broken Symmetric Encryption Modes

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0350 |
| **Platform** | Android |
| **MASVS Category** | MASVS-CRYPTO |
| **Weakness** | MASWE-0007 — *Improper Encryption* |
| **Test Type** | Dynamic, Hooks, **Manual** |
| **Related Techniques** | MASTG-TECH-0005 (Installing Apps), MASTG-TECH-0043 (Method Hooking), MASTG-TECH-0023 (Reviewing Decompiled Java Code) |
| **Related Best Practice** | MASTG-BEST-0005 (Use Secure Encryption Modes) |
| **Related Tests** | **MASTG-TEST-0232** — the **static** counterpart that analyzes the transformation string in code; this test is a **runtime confirmation** (see §1.2 for its specific added value) |
| **Official Rule** | — (none; a purely dynamic test, consistent with the nature of other tests in this category) |

---

## 1. Explanation

### 1.1 Testing Objective

Quote from the official MASTG overview:

> *"If the app configures cryptographic operations with broken encryption modes at runtime, sensitive data can be exposed to pattern leakage and other cryptographic weaknesses. This test checks whether the running app sets insecure block modes, such as ECB, in security-relevant cryptographic flows."*

This is the dynamic counterpart of **MASTG-TEST-0232**, already discussed earlier in this research series — both tests share the same focus (block cipher mode of operation, particularly ECB), but their **verification method differs fundamentally**.

### 1.2 Specific Added Value Compared to Static Analysis: Capturing Transformation Strings That Are Not Hardcoded

This is the main reason why this dynamic test is needed as a complement to TEST-0232, not a duplication. Static analysis (TEST-0232) works by searching for **string literals** such as `"AES/ECB/PKCS5Padding"` in decompiled code. However, if the transformation string is **built dynamically** — for example, retrieved from a remote configuration file, assembled from multiple variables, or decoded from Base64/obfuscation at runtime — static pattern matching **will never find it**, because that literal string **never appears whole** in the decompiled bytecode.

This dynamic test closes that gap elegantly: by hooking `Cipher.getInstance()` directly, the tester captures the **actual transformation string value** right at the moment it is called at runtime — regardless of whether that string originates from a literal, a concatenation result, a decode, or a value received from a server. This is a pattern of added value consistent with other static/dynamic pairs in this research series (e.g., TEST-0318/0319) — static analysis finds candidates that are *visible* in the code, dynamic analysis captures what *actually happens*, including cases deliberately or accidentally hidden from source-code reading.

### 1.3 Observation Structure: Transformation String Along with Backtrace

> **Observation:** *"The output should contain a list of calls to encryption configuration APIs, including the transformation string argument and backtraces of each call."*

The backtrace (call stack) here plays a role just as important as in other hooking tests in this research series (e.g., TEST-0319, similar TEST-0350-type tests) — it shows the **code path** that triggers the call to `Cipher.getInstance()` with a problematic mode, making it easier for the tester to jump directly to the relevant code location for further investigation (§1.4), without needing to trace through the entire codebase from the start.

### 1.4 Mandatory Further Validation: Not All ECB Usages Are Equally Dangerous

> **Further Validation Required:** *"Using the backtraces from the hook output, inspect the code locations using MASTG-TECH-0023 to determine whether the encryption is applied to sensitive data: Determine whether the data being encrypted or decrypted is sensitive (e.g., personal data, authentication tokens, cryptographic keys, or session identifiers)."*

This is consistent with the principle already discussed in TEST-0232 — ECB is technically "broken" unconditionally (deterministic, leaks patterns), but the **security relevance of a finding** depends on **what is being encrypted**. Finding `Cipher.getInstance("AES/ECB/NoPadding")` called on entirely non-sensitive data (e.g., an internal checksum that contains no confidential information) has far lower urgency than finding it on a flow that encrypts authentication tokens or personal user data.

### 1.5 Why This Test Is Also Given the "Manual" Type

As with several other hooking tests in this research series (e.g., TEST-0334, TEST-0338), the `manual` type here indicates that **raw hook results alone are not sufficient** to conclude a final FAIL — the hook output only provides **candidates** (API calls with a particular mode); the final decision on security relevance requires human judgment of the backtrace and the context of the data being processed, per §1.4.

### 1.6 Relevance of Already-Discussed Real-World Cases: The MEGA App and CVE-2026-22906

Both real-world cases already discussed in depth in the **MASTG-TEST-0232** document — the `Cipher.getInstance("AES")` misconfiguration in the MEGA app (falling back to ECB by default without the developer realizing it) and **CVE-2026-22906** (AES-ECB combined with a hardcoded key, exposing user credentials) — are directly relevant to understanding **why dynamic verification matters**: the MEGA case is specifically an example where the developer **was unaware** that their code fell back to ECB because they only wrote `"AES"` without any explicit mode qualifier. Dynamic verification of the transformation string that is **actually used at runtime** (rather than merely inferring from a literal string in the code) is the most reliable way to confirm such hidden cases — including cases where the default JCA provider used might differ depending on the Android version or the active security provider at the time (see the discussion of the GMS Security Provider in TEST-0295 in this research series).

---

## 2. Tools Used for Testing

### 2.1 Required Tools (Core)

| Tool | Function |
|---|---|
| **Frida** | Hooks `Cipher.getInstance()` to capture the transformation string and backtrace (MASTG-TECH-0043) |
| **ADB** | App installation (MASTG-TECH-0005) |
| **jadx** | Manual review of code locations from the backtrace (MASTG-TECH-0023) |

### 2.2 Alternative & Supporting Tools

| Tool | Function |
|---|---|
| **Objection** | Quick hooking without a custom script, for initial exploration |
| **mitmproxy/Burp** | Correlation with network traffic — assessing whether data encrypted with a problematic mode is also observed being sent off the device |

### 2.3 Environment Prerequisites

- A rooted device/emulator with `frida-server`.
- The target app must be **exercised extensively** to cover as many flows as possible (per the official steps) — a `Cipher.getInstance()` call that only occurs for a specific feature (e.g., backup/restore) will not be captured if that feature is not triggered during the testing session.

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0005** to install the app.
2. Use **MASTG-TECH-0043** to hook the relevant APIs.
3. Exercise the app extensively to trigger as many flows as possible, entering sensitive data wherever possible.

### 3.2 Method A — Frida: Hook Cipher.getInstance() with Full Backtrace

```javascript
Java.perform(function () {
    var Cipher = Java.use("javax.crypto.Cipher");
    Cipher.getInstance.overload('java.lang.String').implementation = function (transformation) {
        if (transformation.indexOf("ECB") !== -1 || transformation === "AES" || transformation === "DES") {
            console.log("[Cipher.getInstance] transformation: " + transformation);
            console.log("Backtrace:\n" +
                Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));
        }
        return this.getInstance(transformation);
    };
});
```

```bash
frida -U -f com.example.targetapp -l hook_ecb.js --no-pause
```

### 3.3 Method B — Objection for Quick Exploration

```bash
objection -g com.example.targetapp explore
# inside the REPL:
android hooking watch class_method javax.crypto.Cipher.getInstance --dump-args --dump-backtrace
```

### 3.4 Method C — Manual Backtrace Review (Mandatory, per MASTG-TECH-0023)

For every result captured from Method A/B:

1. Trace the code location from the backtrace.
2. Identify the type of data passed to the subsequent `encrypt`/`decrypt` operation on that `Cipher` instance.
3. Assess whether that data falls under a sensitive category (§1.4).

### 3.5 Method Comparison: When to Use Which

| Method | Tool | When to use |
|---|---|---|
| **A** | Frida | Mandatory baseline — captures the transformation string and backtrace |
| **B** | Objection | Quick exploration without writing a script |
| **C** | Manual review (mandatory) | The core of the test — assessing sensitive-data relevance |

**Recommended minimum combination:** **A → C (mandatory)**, consistent with this test's manual nature (§1.5).

---

### 3.6 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rule:**

> **Evaluation:** *"The test case fails if broken encryption modes are used in security-relevant cryptographic operations."*

---

#### ❌ FAIL / ISSUE — The check is declared FAILED when:

| No | Condition |
|---|---|
| F1 | The hook captures a transformation string indicating ECB mode (or plain `"AES"` without an explicit mode, per the TEST-0232 §1.3 list) **and** the backtrace leads to an operation that handles sensitive data |

**Example evidence (reflecting the real MEGA App pattern, §1.6):**

```
[Cipher.getInstance] transformation: AES
Backtrace:
  at com.example.app.crypto.LegacyEncryptor.encryptUserToken(LegacyEncryptor.java:27)
  at com.example.app.auth.SessionManager.persistToken(SessionManager.java:55)
```

Interpretation: `Cipher.getInstance("AES")` (falling back to ECB by default) is called in a flow that encrypts the user's session token — clearly sensitive data. **FAIL**.

---

#### ✅ PASS — The check is declared PASSED when:

| No | Condition |
|---|---|
| P1 | No call to `Cipher.getInstance()` with ECB mode/no explicit mode is observed during thorough exercising, **or** |
| P2 | A call with a problematic mode is found, but is **verified** (via manual review) to only handle non-sensitive data |

---

#### ⚠️ Important Notes on Assessment

1. **Raw hook results are only candidates, not final findings** — per this test's manual nature (§1.5), always perform a backtrace review before concluding a FAIL.

2. **Exercise coverage determines the validity of a PASS** — if a flow using problematic encryption was never triggered during the testing session, a PASS result could be a false negative; honestly document which flows were/were not successfully triggered.

3. **Leverage this dynamic test's unique ability for hidden cases** — per §1.2, prioritize this test especially when static analysis (TEST-0232) finds nothing yet the app shows indications of obfuscation/remote configuration retrieval, since such cases can only be confirmed through runtime observation.

4. **Correlate with the MASTG-TEST-0232 results** — if the static analysis found a candidate but the dynamic test never observed it being called, that code may be dead code or on an untested path; conversely, a dynamic finding not found statically indicates a dynamic/hidden transformation string worth investigating further.

5. **Severity is modulated:**

   | Factor | Severity |
   |---|---|
   | ECB confirmed active on highly sensitive data (tokens, credentials, personal data) | **High** |
   | ECB confirmed active but on non-sensitive data | **Low/Informational** |
   | Not found after thorough exercising | **Not a finding** (with a note on coverage limitations) |

6. **Document:** the captured transformation string, the full backtrace, the type of data processed (manual review result), and the coverage of flows successfully triggered during testing.

---

## 4. Recommendations

The recommendations are identical to MASTG-TEST-0232 (its static counterpart) — use an authenticated mode such as AES-GCM per MASTG-BEST-0005:

```java
// BEFORE — falls back to ECB by default
Cipher cipher = Cipher.getInstance("AES");

// AFTER — explicitly uses GCM, authenticated
Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
```

### Remediation Checklist

- [ ] All transformation strings captured at runtime use an authenticated mode (GCM/CCM), not ECB
- [ ] No call to `Cipher.getInstance("AES")` without an explicit mode specification
- [ ] Dynamic testing results are correlated with the static findings of MASTG-TEST-0232 for a complete picture
- [ ] Re-verified after the fix by rerunning the hook to confirm no more problematic mode calls occur

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0350 (source, tests-beta)](https://github.com/OWASP/mastg/blob/master/tests-beta/android/MASVS-CRYPTO/MASTG-TEST-0350.md)
- [MASTG-TEST-0232: Broken Symmetric Encryption Modes (static counterpart — related document in this research series)](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0232/)
- [MASTG-BEST-0005: Use Secure Encryption Modes](https://github.com/OWASP/mastg/blob/master/best-practices/MASTG-BEST-0005.md)
- [MASTG-TECH-0023: Reviewing Decompiled Java Code](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0023/)

### 5.2 Technical References and Real-World Cases

- [NIST SP 800-38A — Recommendation for Block Cipher Modes of Operation](https://csrc.nist.gov/pubs/sp/800/38/d/final)
- [GitHub Issue: meganz/android#299 — Cipher.getInstance("AES") Misconfiguration Falling Back to ECB](https://github.com/meganz/android/issues/299)

### 5.3 Tool Documentation

- [Frida — Dynamic Instrumentation Toolkit](https://frida.re/docs/home/)
- [Objection — Runtime Mobile Exploration](https://github.com/sensepost/objection)

---

*This document was compiled based on official OWASP MASTG content (`tests-beta/android/MASVS-CRYPTO/MASTG-TEST-0350.md`, `MASTG-BEST-0005`), along with an in-depth cross-reference with the MASTG-TEST-0232 document (its static counterpart) in this research series, which already discusses the real-world cases of the MEGA Android App and CVE-2026-22906. The most important methodological nuance: this dynamic test's unique added value compared to its static counterpart is the ability to capture transformation strings that are **not hardcoded** in the code (results of concatenation, decoding, or remote configuration) — cases that are structurally impossible for any purely static pattern-matching to detect. Like its static counterpart, this test is of the manual type — raw hook results are only candidates, and final security relevance requires manual review of the backtrace against the type of data processed.*
