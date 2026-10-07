# MASTG-TEST-0326 References to APIs Allowing Fallback to Non-Biometric Authentication

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0326 |
| **Platform** | Android |
| **MASVS Category** | MASVS-AUTH |
| **Weakness** | MASWE-0021 |
| **Test Type** | Static, Code |
| **Related API** | `BiometricPrompt`, `BiometricManager.Authenticators`, `setAllowedAuthenticators` |
| **Related Technique** | MASTG-TECH-0013 (Reverse Engineering), MASTG-TECH-0014 (Static Analysis for Relevant APIs) |
| **Related Knowledge** | MASTG-KNOW-0001 (Biometric Authentication) |
| **Related Best Practice** | MASTG-BEST-0031 (Enforce Strong Biometrics for Sensitive Operations) |
| **Official Rule** | `mastg-android-biometric-device-credential-fallback.yml` — a **pattern-coverage weakness was found**, see §1.4 |

---

## 1. Explanation

### 1.1 Testing Objective

Quote from the official MASTG overview:

> *"This test checks if the app uses biometric authentication mechanisms that allow fallback to device credentials (PIN, pattern, or password) for sensitive operations."*

The configuration mechanism being checked:

> *"When the authenticator constant `DEVICE_CREDENTIAL` is included (either alone or combined with biometric authenticators using the OR operator "|"), the authentication allows fallback to device credentials, which is considered weaker than requiring biometrics alone because passcodes are more susceptible to compromise (e.g., through shoulder surfing)."*

As well as the functionally equivalent legacy API:

> *"Similarly, using `setDeviceCredentialAllowed(true)` (deprecated since API 30) also enables fallback to device credentials."*

### 1.2 The Three Authenticator Classes and Why Their Combination Matters

MASTG-KNOW-0001 defines three `BiometricManager.Authenticators` constants that form the core of this test's evaluation:

| Constant | Integer Value | Description |
|---|---|---|
| `BIOMETRIC_STRONG` | 15 (0x000F) | Class 3 biometric authentication — the highest security level |
| `BIOMETRIC_WEAK` | 255 (0x00FF) | Class 2 biometric authentication — more susceptible to spoofing |
| `DEVICE_CREDENTIAL` | 32768 (0x8000) | Device lock-screen PIN, pattern, or password |

These values can be combined via bitwise OR, e.g. `BIOMETRIC_STRONG | DEVICE_CREDENTIAL`. The crucial point the overview emphasizes: **any combination that includes the `DEVICE_CREDENTIAL` bit** — whether alone or combined with any biometric authenticator — is still considered a FAIL, because ultimately the user (or an attacker observing/coercing them) can **choose** the weaker PIN/pattern/password path instead of biometrics.

### 1.3 Why Falling Back to Device Credentials Is Considered Weaker: The Shoulder-Surfing Risk

The technical rationale the overview provides specifically references **shoulder surfing** — an observation attack in which another party can visually see a PIN/pattern as the user enters it. Academic research on the real-world impact of shoulder surfing on smartphone users reinforces why this is not a theoretical risk:

> *"Shoulder surfing is an observation attack where an attacker attempts to observe the authenticator of a victim while being entered on the device. When banking apps fall back to PIN/pattern/password entry, users are vulnerable to this physical attack where observers can see the credentials being entered."*

Unlike biometrics (fingerprint/face), which inherently cannot be "observed" and replicated as easily as memorizing a visible numeric combination, a visually entered PIN/pattern in public settings (public transport, cafes) creates a genuine window of exposure — especially for financial apps used in a variety of public contexts.

### 1.4 Analytical Finding: The Official Rule Has Broader Pattern Coverage Than Claimed

This is the most important part of the rule analysis — the `mastg-android-biometric-device-credential-fallback.yml` pattern does **not only** capture the `DEVICE_CREDENTIAL` case as its description claims, but technically captures **far more** than that:

```yaml
- patterns:
    - pattern: $BUILDER.setAllowedAuthenticators($VALUE)
    - metavariable-pattern:
        metavariable: $VALUE
        patterns:
          - pattern-not: BiometricManager.Authenticators.BIOMETRIC_STRONG
          - pattern-not: 15
```

The logic of this rule is: flag **any** value passed to `setAllowedAuthenticators()` **UNLESS** it is explicitly equal to the literal `BiometricManager.Authenticators.BIOMETRIC_STRONG` or the integer literal `15`. The consequences:

1. **`BIOMETRIC_WEAK` alone (255) will be flagged as "allows fallback to device credentials"** — even though `BIOMETRIC_WEAK` **does not include the `DEVICE_CREDENTIAL` bit (32768) at all**. This is a Class 2 biometric weakness (susceptible to spoofing), not a device-credential fallback — a **different** issue category from what the rule's message claims.
2. **Any combination written as an expression** (e.g. `BIOMETRIC_STRONG | BIOMETRIC_WEAK`, without `DEVICE_CREDENTIAL` at all) **will also be flagged** as a false positive, because Semgrep's `pattern-not` performs syntactic matching against the specified literal, not a semantic bitwise evaluation of the final value of the expression.

This repeats the "rule description vs. implementation mismatch" pattern already found in several other tests in this research series — the rule is **technically over-broad** compared to the claims of its message, though on the other hand it remains **safe enough for initial triage purposes** (false positives are more tolerable here than false negatives, since the test's evaluation direction leans conservatively toward security). Testers must manually verify each match to confirm that `DEVICE_CREDENTIAL` is truly the cause, not merely `BIOMETRIC_WEAK` or a purely biometric combination written as an expression.

The second pattern of this rule (for `canAuthenticate()`) has an identical logic limitation, and the third pattern (`setDeviceCredentialAllowed(true)`) is already precisely targeted without ambiguity.

### 1.5 Severity Classification Nuance: "Hardening Issue", Not "Critical Vulnerability"

The official MASTG notes provide explicit classification guidance that is uncommonly thorough compared to other tests:

> *"Using `DEVICE_CREDENTIAL` is not inherently a vulnerability, but in high-security applications (e.g., finance, government, health), their use can represent a weakness or misconfiguration that reduces the intended security posture. This issue is therefore better categorized as a security weakness or hardening issue, not a critical vulnerability."*

This matters for reporting — findings from this test **should not be labeled "critical vulnerability"** by default. Severity depends entirely on the **application's domain context** (see §3.8 on severity).

### 1.6 Related Context: Greater Risk Arises When Not Paired with a CryptoObject

Independent research (SEC Consult) on Android biometric bypass shows that the `DEVICE_CREDENTIAL` fallback risk often **stacks** with another related but technically distinct implementation weakness:

> *"One bypass method involves the app using the authenticate overload that does NOT require a CryptoObject... When apps use BiometricPrompt with device credential fallback without binding biometric authentication to a CryptoObject, this creates an insecure configuration. This means that once a user authenticates (either biometrically or via PIN/password), the app may treat that single authentication as sufficient for all subsequent sensitive operations."*

This is relevant as additional context when triaging findings from this test — if `DEVICE_CREDENTIAL` fallback is found **and** there is no `CryptoObject` binding (per the Keystore-Backed Authentication concept in MASTG-KNOW-0001 §1.2), the combined risk is higher than evaluating each weakness separately — authentication can not only fall back to a weaker method, but the authentication result itself is not cryptographically bound to the sensitive operation it is supposed to protect.

---

## 2. Tools Used for Testing

### 2.1 Required Tools (Core)

| Tool | Function |
|---|---|
| **jadx** | Decompile DEX → Java (MASTG-TECH-0013) |
| **Semgrep** + official rule `mastg-android-biometric-device-credential-fallback.yml` | Pattern matching for `setAllowedAuthenticators`/`canAuthenticate`/`setDeviceCredentialAllowed` (MASTG-TECH-0014) |

### 2.2 Alternative & Supporting Tools

| Tool | Function |
|---|---|
| **grep/ripgrep** | Manual verification of raw integer values in decompiled bytecode (`15`, `255`, `32768`, or their OR combinations) to close the official rule's false-positive gap (§1.4) |
| **MobSF** | Automated reports that sometimes include biometric configuration checks as part of a security summary |
| **Frida** | Dynamic verification of the actual `$VALUE` passed to `setAllowedAuthenticators()` at runtime — complementing static analysis for cases where the value is generated dynamically/not hardcoded |

### 2.3 Environment Prerequisites

- No device/root needed for static analysis.
- Understand the authenticator integer-value table (§1.2) to manually verify rule matches, since decompiled code often displays **raw integer values** instead of symbolic constant names.

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0013** to reverse engineer the application.
2. Use **MASTG-TECH-0014** to search for the relevant APIs.

### 3.2 Method A — Semgrep with the Official Rule (with Mandatory Manual Verification)

```bash
semgrep --config mastg-android-biometric-device-credential-fallback.yml ./decompiled/sources
```

**Manual follow-up is mandatory** per §1.4 — for each match, check whether the `$VALUE` actually includes the `DEVICE_CREDENTIAL` bit, rather than merely `BIOMETRIC_WEAK` alone or a purely biometric combination.

### 3.3 Method B — grep/ripgrep for Raw Integer Value Verification

```bash
D=./decompiled/sources

# Search for setAllowedAuthenticators calls with explicit integer values
rg -n 'setAllowedAuthenticators\(' $D -A 0

# Manual verification: does the value 32768 (0x8000) appear alone or OR'd in?
rg -n 'setAllowedAuthenticators\(\s*(32768|0x8000|.*\|.*32768)' $D

# Search for the deprecated setDeviceCredentialAllowed pattern
rg -n 'setDeviceCredentialAllowed\(\s*true\s*\)' $D
```

### 3.4 Method C — Frida for Runtime Dynamic Value Verification

```javascript
Java.perform(function () {
    var Builder = Java.use("androidx.biometric.BiometricPrompt$PromptInfo$Builder");
    Builder.setAllowedAuthenticators.implementation = function (value) {
        console.log("[setAllowedAuthenticators] value: " + value +
            " (binary: " + value.toString(2) + ")");
        return this.setAllowedAuthenticators(value);
    };
});
```

Useful for cases where the `$VALUE` is not hardcoded in the code (e.g. it comes from a remote config/feature flag), so static analysis alone cannot determine the final value actually used.

### 3.5 Method Comparison: When to Use Which

| Method | Tool | When to Use |
|---|---|---|
| **A** | Semgrep + official rule | Mandatory baseline, fast initial triage |
| **B** | grep/ripgrep manual | Mandatory verification to rule out false positives from the official rule (§1.4) |
| **C** | Frida | Authenticator value is determined dynamically/not hardcoded |

**Minimum recommended combination:** **A + B (mandatory pairing)**, with **C** as a supplement when there are indications the value is configured dynamically.

---

### 3.6 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rule:**

> **Evaluation:** *"The test case fails if the app uses BiometricPrompt with authenticators that include DEVICE_CREDENTIAL for any sensitive data resource that needs protection."*

---

#### ❌ FAIL / ISSUE — The check is declared FAILED if:

| No | Condition |
|---|---|
| F1 | `setAllowedAuthenticators()` is called with a value that includes the `DEVICE_CREDENTIAL` bit (either alone or OR'd with a biometric authenticator), to protect a sensitive resource/operation |
| F2 | `setDeviceCredentialAllowed(true)` is called (deprecated API, but functionally equivalent to F1) |

**Example evidence:**

```java
// Found in com/example/targetapp/auth/BiometricHelper.java
BiometricPrompt.PromptInfo promptInfo = new BiometricPrompt.PromptInfo.Builder()
    .setTitle("Confirm Transaction")
    .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG
        | BiometricManager.Authenticators.DEVICE_CREDENTIAL)
    .build();
```

Interpretation: authentication for confirming a transaction (sensitive operation) allows fallback to the device PIN/pattern/password. **FAIL** — but classify as a *hardening issue*, not a *critical vulnerability* (§1.5).

---

#### ✅ PASS — The check is declared PASSED if:

| No | Condition |
|---|---|
| P1 | `setAllowedAuthenticators()` only uses `BIOMETRIC_STRONG` (value `15`) without `DEVICE_CREDENTIAL`, for all sensitive operations |
| P2 | **After manual verification** (§1.4), a rule match that was initially flagged turns out to be only `BIOMETRIC_WEAK` alone or a purely biometric combination without the `DEVICE_CREDENTIAL` bit — this is **not a finding for this test** (although `BIOMETRIC_WEAK` alone could be a separate finding related to biometric class strength, not the topic of this test) |

---

#### ⚠️ Important Notes on Scoring

1. **Manual verification is not optional** — per §1.4, the official rule will produce false positives for `BIOMETRIC_WEAK` alone and for purely biometric expression combinations. Do not report raw Semgrep matches as a final finding without confirming the `DEVICE_CREDENTIAL` bit is genuinely present.

2. **Severity depends entirely on the application domain (§1.5)** — do not default to high severity; evaluate whether the target application falls into a high-security category (finance, government, health) before setting remediation urgency.

3. **"Sensitive operation" needs to be clearly defined up front** — the official evaluation limits FAIL to only "resources that need protection"; device-credential fallback for non-sensitive features (e.g. opening a theme preferences view) is logically outside the scope of this test's concern, even if it technically matches the same pattern.

4. **Also check for `CryptoObject` binding** as additional context (§1.6) — a `DEVICE_CREDENTIAL` fallback finding **without** a `CryptoObject` has more serious combined-risk implications than when found alone.

5. **Severity is modulated by:**

   | Factor | Severity |
   |---|---|
   | `DEVICE_CREDENTIAL` fallback on a sensitive operation in a finance/health/government app, without a `CryptoObject` | **Medium-High** (serious hardening issue) |
   | `DEVICE_CREDENTIAL` fallback on a sensitive operation in a general/non-high-security category app | **Low-Medium** |
   | Fallback only for non-sensitive operations | **Not a finding** |

6. **Document:** the code location of the call, the configured authenticator value (from manual verification, not the raw tool output), whether it is paired with a `CryptoObject`, and the application domain classification (high-security or not) to determine final severity.

---

## 4. Recommendations

### 4.1 Restrict to BIOMETRIC_STRONG Only for Sensitive Operations

```java
// BEFORE — allows fallback to PIN/pattern/password
new BiometricPrompt.PromptInfo.Builder()
    .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG
        | BiometricManager.Authenticators.DEVICE_CREDENTIAL)
    .build();

// AFTER — Class 3 biometrics only, per MASTG-BEST-0031
new BiometricPrompt.PromptInfo.Builder()
    .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
    .build();
```

### 4.2 Pair with a CryptoObject for Cryptographic Binding

```java
BiometricPrompt.CryptoObject cryptoObject = new BiometricPrompt.CryptoObject(cipher);
biometricPrompt.authenticate(promptInfo, cryptoObject);
```

This reduces the combined risk described in §1.6 — the authentication result is bound directly to a specific cryptographic operation, rather than being merely a boolean "already authenticated" signal that could be misused for other operations.

### 4.3 Remediation Checklist

- [ ] All sensitive operations are confirmed to use only `BIOMETRIC_STRONG`, with no `DEVICE_CREDENTIAL`
- [ ] No remaining calls to `setDeviceCredentialAllowed(true)` (deprecated API)
- [ ] Biometric authentication is paired with a `CryptoObject` for sensitive cryptographic operations
- [ ] Application domain classification (high-security or not) is documented to determine remediation urgency
- [ ] Semgrep results are manually verified to rule out `BIOMETRIC_WEAK` false positives

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0326 (source, tests-beta)](https://github.com/OWASP/mastg/blob/master/tests-beta/android/MASVS-AUTH/MASTG-TEST-0326.md)
- [MASTG-KNOW-0001: Biometric Authentication](https://mas.owasp.org/MASTG/knowledge/android/MASVS-AUTH/MASTG-KNOW-0001/)
- [MASTG-BEST-0031: Enforce Strong Biometrics for Sensitive Operations](https://github.com/OWASP/mastg/blob/master/best-practices/MASTG-BEST-0031.md)
- [GitHub Issue #3748: Update Android Biometrics MASTG-KNOW-0001 and MASTG-BEST-0031](https://github.com/OWASP/mastg/issues/3748)

### 5.2 Official Android Documentation

- [BiometricPrompt.Builder#setAllowedAuthenticators](https://developer.android.com/reference/android/hardware/biometrics/BiometricPrompt.Builder#setAllowedAuthenticators(int))
- [BiometricManager.Authenticators](https://developer.android.com/reference/android/hardware/biometrics/BiometricManager.Authenticators#constants_1)
- [Android Developers — Secure User Authentication](https://developer.android.com/security/fraud-prevention/authentication)

### 5.3 Research and Real-World Cases

- [SEC Consult: Bypassing Android Biometric Authentication](https://sec-consult.com/blog/detail/bypassing-android-biometric-authentication/)
- [Oversecured: Vulnerabilities That Lead to Account Takeover in Banking and Fintech Mobile Apps](https://oversecured.com/blog/mobile-banking-security-account-takeover-vulnerabilities)
- [arXiv: Towards Baselines for Shoulder Surfing on Mobile Authentication](https://arxiv.org/pdf/1709.04959)
- [Wikipedia: Shoulder Surfing (Computer Security)](https://en.wikipedia.org/wiki/Shoulder_surfing_%28computer_security%29)

### 5.4 Tool Documentation

- [Semgrep Documentation](https://semgrep.dev/docs/)
- [MobSF — Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)
- [Frida — Dynamic Instrumentation Toolkit](https://frida.re/docs/home/)

---

*This document was compiled based on official OWASP MASTG content (`tests-beta/android/MASVS-AUTH/MASTG-TEST-0326.md`, `MASTG-KNOW-0001`, `MASTG-BEST-0031`), direct analysis of the `mastg-android-biometric-device-credential-fallback.yml` rule, and industry research (SEC Consult, Oversecured) on real-world biometric bypasses. The most important methodological nuance: the official Semgrep rule has broader pattern coverage than its description claims — `pattern-not` only excludes the exact literals `BIOMETRIC_STRONG`/`15`, so `BIOMETRIC_WEAK` alone or a purely biometric expression combination (without `DEVICE_CREDENTIAL` at all) will also be flagged as a false positive — manual verification of the `DEVICE_CREDENTIAL` bit value (32768/0x8000) is a mandatory step, not optional, before reporting a final finding.*
