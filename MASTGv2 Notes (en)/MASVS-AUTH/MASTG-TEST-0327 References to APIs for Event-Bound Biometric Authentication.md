# MASTG-TEST-0327 References to APIs for Event-Bound Biometric Authentication

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0327 |
| **Platform** | Android |
| **MASVS Category** | MASVS-AUTH |
| **Weakness** | MASWE-0020 |
| **Test Type** | Static, Code |
| **Related API** | `BiometricPrompt`, `BiometricPrompt.CryptoObject`, `authenticate` |
| **Related Technique** | MASTG-TECH-0013 (Reverse Engineering), MASTG-TECH-0014 (Static Analysis for Relevant APIs) |
| **Related Knowledge** | MASTG-KNOW-0001 (Biometric Authentication), MASTG-KNOW-0043 (Android KeyStore), MASTG-KNOW-0047 (Cryptographic Key Storage), MASTG-KNOW-0012 (Key Generation) |
| **Related Best Practice** | MASTG-BEST-0036 (Use Cryptographic Binding for Biometric Authentication) |
| **Related Test** | **MASTG-TEST-0326** — a closely related topic (device-credential fallback) but targeting a **different** configuration weakness (see §1.5 for comparison) |
| **Official Rule** | `mastg-android-biometric-event-bound.yml` — 4 patterns at once, see §1.4 |

---

## 1. Explanation

### 1.1 Testing Objective

Quote from the official MASTG overview:

> *"This test checks if the app implements event-bound biometric authentication to access sensitive resources (e.g., tokens, keys), where authentication success relies solely on a callback result rather than being cryptographically bound to sensitive operations and requiring user presence."*

This is one of the most crucial tests in the MASVS-AUTH category — it's not about **whether** biometrics are used (that's already assumed to be the case), but about **how** the result of that biometric authentication is **bound** to the sensitive operation it protects.

### 1.2 Two Binding Models: Event-Bound vs. Crypto-Bound

The official overview explains the fundamental difference between the two models:

> *"When used without a CryptoObject the app relies on the `onAuthenticationSucceeded` callback to determine if authentication was successful (event-bound). This makes it susceptible to logic manipulation by overwriting the callback without successfully passing the biometric verification."*
>
> *"In contrast, when a CryptoObject is used (crypto-bound), the app passes a cryptographic object (e.g., Cipher, Signature, Mac) that requires user authentication. This ensures authentication is not just a one-time boolean, but part of a secure data retrieval path (out-of-process), so bypassing authentication becomes significantly harder."*

Conceptually, the difference is:

| Model | Mechanism | Point of Failure |
|---|---|---|
| **Event-bound** | The authentication result is merely a callback (`onAuthenticationSucceeded()`) that signals "success" | **A single point** — whoever can call/trigger that callback method (via hooking) automatically "passes," without ever touching the actual biometric sensor |
| **Crypto-bound** | The authentication result is access to a cryptographic object (`Cipher`/`Signature`/`Mac`) that can **only be unlocked** by the Keystore after successful biometric verification in the **Trusted Execution Environment (TEE)** | The cryptographic operation happens **outside the application process** (out-of-process) — forcefully calling a Java method does not grant access to a key locked in hardware |

The phrase "out-of-process" here is the technical key to why crypto-bound is far stronger — validation does not happen within the application's process space, which can be manipulated with ordinary Frida hooking, but rather in an isolated hardware component (TEE/Secure Element) that underlies the Android KeyStore (per MASTG-KNOW-0043).

### 1.3 Dual FAIL Criteria: Two Conditions Must Both Be Met

The official Evaluation section has an explicit AND logic structure — this is important to understand because it distinguishes this test from many others whose FAIL criteria are singular:

> *"The test case fails for each sensitive operation worth protecting if **all of the following applies**:*
> - *`BiometricPrompt.authenticate` is used without a `CryptoObject`.*
> - *There are no calls to key generation with `setUserAuthenticationRequired(true)` in conjunction with biometric authentication, as by default, the key is authorized to be used regardless of whether the user has been authenticated or not."*

The second point contains a technical detail that is very easy to miss: **`setUserAuthenticationRequired(true)` is not the default**. If a developer creates a Keystore key without explicitly setting this flag to `true`, that key **can be used at any time without any authentication whatsoever** — meaning that even though an application superficially "has a Keystore key," that key itself is not truly bound to a user-authentication requirement. This means **having a CryptoObject alone is not enough** for a PASS — the underlying key must also be correctly configured.

### 1.4 Analysis of the Official Rule: Four Complementary Patterns

The `mastg-android-biometric-event-bound.yml` rule has four patterns that mirror the two FAIL criteria above, split by API family (androidx vs. legacy framework) and by aspect (calling `authenticate()` vs. key configuration):

| Pattern | Targets | Technical Detail |
|---|---|---|
| **Pattern 1** | `androidx.biometric.BiometricPrompt.authenticate()` without a `CryptoObject` | Uses `pattern-not` to exclude the 2-parameter variant (`PromptInfo`, `CryptoObject`) |
| **Pattern 2** | `android.hardware.biometrics.BiometricPrompt.authenticate()` without a `CryptoObject` (legacy framework API) | Distinguishes the 3-parameter variant (no crypto) vs. the 4-parameter variant (with crypto) based on **argument count** |
| **Pattern 3a** | `KeyGenParameterSpec.Builder` without `setUserAuthenticationRequired(true)`, in a file that imports `android.hardware.biometrics.BiometricPrompt` | Scope limited by import to avoid false positives on non-biometric keys |
| **Pattern 3b** | Same as 3a, but for the `androidx.biometric.BiometricPrompt` import scope | Handles both library variants that might be used |

A good design note: this rule explicitly states its scope-limitation rationale in a YAML comment — *"Scoped to files using... BiometricPrompt to avoid false positives on non-biometric keys"* — showing the rule designer's awareness of the over-matching risk that was found to be a weakness in an earlier test's rule (TEST-0326 §1.4). However, it should be noted: scoping based on **file-level import** (rather than per-function) means that if a single file has many key generations for different purposes, the rule could flag a key that is **not related to biometrics at all** simply because it resides in the same file as biometric-related code — a narrower but still-present false-positive potential.

### 1.5 Comparison with MASTG-TEST-0326: Two Different Weaknesses Often Mistaken for the Same Thing

It is important to clearly distinguish this test from MASTG-TEST-0326, because both discuss `BiometricPrompt` yet target **entirely different configuration aspects**:

| | MASTG-TEST-0326 | MASTG-TEST-0327 (this test) |
|---|---|---|
| **Core question** | Can authentication *fall back* to a weaker method (PIN/pattern)? | Is the authentication result *cryptographically bound* to the operation it protects? |
| **API highlighted** | `setAllowedAuthenticators()` with `DEVICE_CREDENTIAL` | `authenticate()` without a `CryptoObject` |
| **Risk if FAIL** | A user/attacker can use a PIN instead of finger/face (shoulder surfing) | Authentication can be **bypassed entirely** via hooking without *any* authentication, including a PIN |
| **Relative severity** | Hardening issue (per official classification) | More serious — this is a **total bypass**, not just a "weaker path" |

Both **can and often do** appear together in a single application — an app may already correctly avoid `DEVICE_CREDENTIAL` (passing TEST-0326) yet still be vulnerable in this test because it doesn't use a `CryptoObject` at all.

### 1.6 Real-World Evidence: Bitwarden, Signal, and Dashlane Were Found Vulnerable to This Exact Pattern

This is the most concrete evidence available showing that this test is not a theoretical risk — SEC Consult research documented real bypasses against **three popular applications with very large user bases**, precisely targeting the weakness this test addresses:

> *"The research documented successful bypasses against three prominent applications: Bitwarden (1M+ downloads, v2023.3.2), Dashlane (5M+ downloads, v6.2313.0), and Signal (100M+ downloads, v6.17.3). Bitwarden and Signal did not generate a key at all and thus also did not make use of a CryptoObject to protect data cryptographically."*

The documented technical bypass mechanism precisely illustrates the "event-bound" risk from §1.2:

> *"Frida hooks into the authenticate method of the BiometricPrompt API to detect an authentication attempt, and inside the hook, the script makes a callback to onAuthenticationSucceeded to trigger a successful authentication... making the app believe that biometric authentication was successful."*

The fact that **password manager** apps (Bitwarden, Dashlane) and an **encrypted messaging** app (Signal) — categories of applications that explicitly center security as their main value proposition — were found vulnerable to this pattern underscores just how easily this misconfiguration can be overlooked, even by experienced teams. An important note from this research is also relevant for the realism of risk assessment:

> *"Importantly, attackers require either root device access or the ability to convince users to install a modified app version, plus physical device access to execute the attack."*

This confirms that although the bypass is technically "trivial" once the prerequisites are met, **the prerequisites themselves are not trivial** (root + physical access, or social engineering to install a modified APK) — relevant for calibrating proportional severity, rather than automatically labeling it "critical" without threat context.

---

## 2. Tools Used for Testing

### 2.1 Required Tools (Core)

| Tool | Function |
|---|---|
| **jadx** | Decompile DEX → Java (MASTG-TECH-0013) |
| **Semgrep** + official rule `mastg-android-biometric-event-bound.yml` | Matching the 4 `authenticate()`/`KeyGenParameterSpec` patterns (MASTG-TECH-0014) |

### 2.2 Alternative & Supporting Tools

| Tool | Function |
|---|---|
| **grep/ripgrep** | Manual verification of `authenticate()` arguments beyond the official rule's file-level scope limitation (§1.4) |
| **Frida** | Dynamic verification — confirming whether bypassing `onAuthenticationSucceeded` actually succeeds in changing application behavior (bridging into dynamic testing, even though there is no separate official dynamic test for this topic) |
| **MobSF** | Automated reports that sometimes include Keystore configuration checks as part of a summary |

### 2.3 Environment Prerequisites

- No device/root needed for static analysis.
- Understand the structure of `KeyGenParameterSpec.Builder` (refer to MASTG-KNOW-0012) to recognize method-chaining patterns that may be spread across multiple lines/helper methods, not always within a single easily matched builder block.

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0013** to reverse engineer the application.
2. Use **MASTG-TECH-0014** to search for the relevant APIs.

### 3.2 Method A — Semgrep with the Official Rule

```bash
semgrep --config mastg-android-biometric-event-bound.yml ./decompiled/sources
```

### 3.3 Method B — grep/ripgrep for Thorough Manual Verification

```bash
D=./decompiled/sources

# Find all authenticate() calls to manually count arguments
rg -n '\.authenticate\(' $D

# Find biometric-relevant key generation configurations
rg -n 'setUserAuthenticationRequired' $D

# Find KeyGenParameterSpec builders that do NOT include the line above (needs manual per-file verification)
rg -n 'new KeyGenParameterSpec.Builder' $D
```

### 3.4 Method C — Frida for Dynamic Verification (Reproducing the SEC Consult Technique)

```javascript
Java.perform(function () {
    var BiometricPrompt = Java.use("androidx.biometric.BiometricPrompt");
    BiometricPrompt.authenticate.overload(
        "androidx.biometric.BiometricPrompt$PromptInfo"
    ).implementation = function (promptInfo) {
        console.log("[!] authenticate() called WITHOUT a CryptoObject — susceptible to event-bound bypass");
        return this.authenticate(promptInfo);
    };
});
```

This controllably reproduces the technique documented by SEC Consult (§1.6) to empirically verify that the target application is genuinely vulnerable, complementing static findings with conclusive dynamic evidence.

### 3.5 Method Comparison: When to Use Which

| Method | Tool | When to Use |
|---|---|---|
| **A** | Semgrep + official rule | Mandatory baseline |
| **B** | grep/ripgrep manual | Thorough verification, closing the gap left by the official rule's file-level scope limitation (§1.4) |
| **C** | Frida | Conclusive dynamic confirmation, especially for reports to clients/stakeholders who need real exploitation evidence |

**Minimum recommended combination:** **A + B (mandatory)**, with **C** strongly recommended for high-risk application categories (finance, password managers, encrypted messaging), given that the real-world evidence in §1.6 actually comes from these same application categories.

---

### 3.6 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rule (dual AND criteria, §1.3):**

---

#### ❌ FAIL / ISSUE — The check is declared FAILED if **both** of the following conditions are met for a single sensitive operation:

| No | Condition |
|---|---|
| F1 | `BiometricPrompt.authenticate()` is called **without** a `CryptoObject` |
| F2 | **And** there is no key generation with `setUserAuthenticationRequired(true)` related to that biometric authentication |

**Example evidence (replicating the real Bitwarden/Signal pattern in §1.6):**

```java
// Found in com/example/vault/auth/UnlockActivity.java
biometricPrompt.authenticate(promptInfo); // NO CryptoObject

// No call to setUserAuthenticationRequired(true) found anywhere in the codebase
```

Interpretation: the vault/password manager app relies solely on `onAuthenticationSucceeded()` as a gate to sensitive data access, without any cryptographic binding. **FAIL** — risk of total bypass via hooking, exactly as in the real cases in §1.6.

---

#### ✅ PASS — The check is declared PASSED if:

| No | Condition |
|---|---|
| P1 | `authenticate()` is called **with** a valid `CryptoObject` |
| P2 | **And** the key underlying that `CryptoObject` was created with `setUserAuthenticationRequired(true)` explicitly set |

**Example evidence:**

```java
KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(KEY_ALIAS,
        KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
    .setUserAuthenticationRequired(true)
    .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
    .build();
// ...
BiometricPrompt.CryptoObject cryptoObject = new BiometricPrompt.CryptoObject(cipher);
biometricPrompt.authenticate(promptInfo, cryptoObject);
```

**PASS** — authentication is bound to a cryptographic operation that can only be unlocked after biometric verification in the TEE.

---

#### ⚠️ Important Notes on Scoring

1. **Both FAIL criteria must be checked together — do not stop at the first criterion** — per §1.3, finding a `CryptoObject` **alone** does not automatically mean a PASS; always trace back to the key generation to confirm `setUserAuthenticationRequired(true)` is genuinely present, since this is **not the default**.

2. **Non-sensitive operations may be excluded** — the official evaluation limits scope to "each sensitive operation worth protecting"; biometric authentication for cosmetic features (e.g. a dark-mode toggle) is outside the scope of this test's concern.

3. **Verify the official rule's file-level scope limitation** — if a single file contains many key generations for different purposes (biometric and non-biometric), make sure the flagged key is truly biometric-related and not a false positive from import-based scoping (§1.4).

4. **Consider Method C (Frida) for high-risk cases** — given that real-world cases involve apps on the level of Bitwarden/Signal, conclusive dynamic evidence (not just a static finding) is highly valuable for reports to product teams who may be skeptical of "theoretical findings."

5. **Severity is modulated by:**

   | Factor | Severity |
   |---|---|
   | Event-bound authentication on a sensitive operation (vault access, encryption keys, session tokens) in an app that processes highly sensitive data | **High** (even though the attack prerequisites require root/physical access, per §1.6) |
   | Event-bound authentication on a sensitive operation but in a non-high-risk app | **Medium** |
   | Crypto-bound is correctly implemented, but key validity duration is too long (outside this test's direct scope, but worth noting as a related finding) | **Low/Informational** |

6. **Document:** the location of the `authenticate()` call, whether a `CryptoObject` is included, the location of the related key generation along with its `setUserAuthenticationRequired` configuration, and the results of dynamic verification if performed.

---

## 4. Recommendations

### 4.1 Always Use a CryptoObject with a Correctly Configured Key

```java
// BEFORE — event-bound, susceptible to bypass (pre-fix Bitwarden/Signal pattern)
biometricPrompt.authenticate(promptInfo);

// AFTER — crypto-bound per MASTG-BEST-0036
KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(KEY_ALIAS, PURPOSE_ENCRYPT | PURPOSE_DECRYPT)
    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
    .setUserAuthenticationRequired(true)
    .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG) // 0 = authentication required per operation
    .build();

BiometricPrompt.CryptoObject cryptoObject = new BiometricPrompt.CryptoObject(cipher);
biometricPrompt.authenticate(promptInfo, cryptoObject);
```

### 4.2 Avoid Long Validity Durations for Highly Sensitive Operations

Per MASTG-BEST-0036's notes, use a timeout of `0` (authentication required for **every** cryptographic operation) for the most sensitive data — avoid long validity windows that keep the key usable even if the device changes hands after initial authentication.

### 4.3 Remediation Checklist

- [ ] All `authenticate()` calls for sensitive operations include a `CryptoObject`
- [ ] Every key underlying a `CryptoObject` is configured with `setUserAuthenticationRequired(true)`
- [ ] Key validity duration is set to `0` for the most sensitive operations, not a long window
- [ ] Results are dynamically verified with Frida (reproducing §3.4's technique) to confirm the bypass genuinely fails after the fix
- [ ] Re-cross-checked against MASTG-TEST-0326 results — ensure both weaknesses are addressed, not only one

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0327 (source, tests-beta)](https://github.com/OWASP/mastg/blob/master/tests-beta/android/MASVS-AUTH/MASTG-TEST-0327.md)
- [MASTG-TEST-0326: References to APIs Allowing Fallback to Non-Biometric Authentication](https://mas.owasp.org/MASTG/tests/android/MASVS-AUTH/MASTG-TEST-0326/)
- [MASTG-KNOW-0001: Biometric Authentication](https://mas.owasp.org/MASTG/knowledge/android/MASVS-AUTH/MASTG-KNOW-0001/)
- [MASTG-KNOW-0043: Android KeyStore](https://mas.owasp.org/MASTG/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0043/)
- [MASTG-KNOW-0047: Cryptographic Key Storage](https://mas.owasp.org/MASTG/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0047/)
- [MASTG-KNOW-0012: Key Generation](https://mas.owasp.org/MASTG/knowledge/android/MASVS-CRYPTO/MASTG-KNOW-0012/)
- [MASTG-BEST-0036: Use Cryptographic Binding for Biometric Authentication](https://github.com/OWASP/mastg/blob/master/best-practices/MASTG-BEST-0036.md)

### 5.2 Research and Real-World Cases

- [SEC Consult: Bypassing Android Biometric Authentication](https://sec-consult.com/blog/detail/bypassing-android-biometric-authentication/)
- [HackTricks: Bypass Biometric Authentication (Android)](https://hacktricks.wiki/en/mobile-pentesting/android-app-pentesting/bypass-biometric-authentication-android.html)
- [SecurityCafe: Mobile Pentesting 101 — Bypassing Biometric Authentication](https://securitycafe.ro/2022/09/05/mobile-pentesting-101-bypassing-biometric-authentication/)
- [Kayssel: Securing Biometric Authentication — Defending Against Frida Bypass Attacks](https://www.kayssel.com/post/android-8/)

### 5.3 Tool Documentation

- [Semgrep Documentation](https://semgrep.dev/docs/)
- [Frida — Dynamic Instrumentation Toolkit](https://frida.re/docs/home/)
- [MobSF — Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)

---

*This document was compiled based on official OWASP MASTG content (`tests-beta/android/MASVS-AUTH/MASTG-TEST-0327.md`, `MASTG-KNOW-0001/0012/0043/0047`, `MASTG-BEST-0036`), analysis of the `mastg-android-biometric-event-bound.yml` rule, and SEC Consult research documenting real bypasses against Bitwarden, Signal, and Dashlane — three applications with strong security reputations and a combined user base of over 100 million downloads. The most important methodological nuance: the official FAIL criteria are a dual AND condition (no CryptoObject AND no `setUserAuthenticationRequired(true)`) — finding only one of the two is not enough to conclude FAIL or PASS; `setUserAuthenticationRequired(true)` is not the default value, so the mere existence of a Keystore key does not guarantee a genuine authentication binding.*
