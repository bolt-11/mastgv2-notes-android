# MASTG-TEST-0330 References to APIs for Keys used in Biometric Authentication with Extended Validity Duration

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0330 |
| **Platform** | Android |
| **MASVS Category** | MASVS-AUTH |
| **Weakness** | MASWE-0020 |
| **Test Type** | Static, Code |
| **Related API** | `KeyGenParameterSpec.Builder`, `setUserAuthenticationParameters`, `setUserAuthenticationValidityDurationSeconds` |
| **Related Technique** | MASTG-TECH-0013 (Reverse Engineering), MASTG-TECH-0014 (Static Analysis for Relevant APIs) |
| **Related Knowledge** | MASTG-KNOW-0001, MASTG-KNOW-0043, MASTG-KNOW-0047, MASTG-KNOW-0012 |
| **Related Best Practice** | MASTG-BEST-0036 (Use Cryptographic Binding for Biometric Authentication) |
| **Related Test** | The full MASTG-TEST-0326 through 0330 sequence — five tests that together audit `BiometricPrompt`/`KeyGenParameterSpec` configuration from different angles |
| **Official Rule** | `mastg-android-biometric-validity-duration.yml` — 2 patterns with numeric `metavariable-comparison`, see §1.4 |

---

## 1. Explanation

### 1.1 Testing Objective

Quote from the official MASTG overview:

> *"This test checks if the app configures cryptographic keys with an extended validity duration that allows keys to remain unlocked beyond the immediate operation. When using biometric authentication with CryptoObject, the authentication validity duration determines how long a key remains usable after successful authentication."*

This is the fifth and final test in this research series' audit of `BiometricPrompt`/Keystore configuration. Unlike TEST-0327 (whether authentication is cryptographically bound at all) and TEST-0328 (whether the key survives new enrollment), this test targets the **time** dimension — even with a correctly implemented `CryptoObject` and correct enrollment invalidation, a key can still be a weak point if its **validity window** is configured too long.

### 1.2 Technical Mechanism: Duration 0 vs. Duration > 0

The overview provides a clear and measurable definition:

> *"Duration = 0: The key requires authentication for every cryptographic operation. This is the most secure configuration as each use of the key requires biometric verification."*
>
> *"Duration > 0: The key remains unlocked for the specified duration (in seconds) after successful authentication. When the duration is set to a high value in the range of minutes or hours an attacker with physical access to the phone could trigger sensitive operations without biometric verification."*

A concrete illustration of the risk scenario: if a digital wallet app sets a duration of 1 hour, then once the user performs a single face/fingerprint authentication in the morning, **whoever is holding the device** within the following one-hour window can trigger sensitive transactions **without ever having to pass the biometric sensor at all** — whether that is someone legitimately borrowing the phone, or an attacker who gains brief physical access (stolen, forcibly borrowed, or left unattended on a desk).

### 1.3 Important Nuance of the Legacy API: The Value `-1` as a Special Case That Is Easily Overlooked

Community research reveals an important technical detail of the (deprecated) `setUserAuthenticationValidityDurationSeconds` API that is **not explicitly mentioned** in the official overview but is relevant for a thorough audit:

> *"When setUserAuthenticationValidityDurationSeconds is set to -1, the key can only be unlocked using a biometric identity. If it is set to a different value, the key can be unlocked using a device screenlock too... When this parameter is not set within the range [-1, 0], authentication requirements have no effect, and the device only needs to be unlocked. This represents a critical configuration error."*

This means there are **three categories of values**, not just the two (0 vs. >0) explicitly mentioned by the overview:

| Value | Behavior |
|---|---|
| `-1` | Only pure biometrics can unlock the key (without falling back to a general screen lock) |
| `0` | Authentication required for every operation — but can be via either biometrics OR the screen lock |
| `> 0` | The key remains open for that duration after a single authentication |

This `-1` value is a detail that is easily missed from reading the official overview alone — testers must include it in their pattern search, not only search for positive values per the literal wording of the overview.

### 1.4 Analysis of the Official Rule: A More Precise `metavariable-comparison` Approach

Unlike some other biometric rules in this research series, which rely on `pattern-not` against certain literals (susceptible to false positives, see TEST-0326 §1.4), the rule for this test uses a technically stronger approach — `metavariable-comparison` for genuine numeric evaluation:

```yaml
- patterns:
    - pattern: $BUILDER.setUserAuthenticationParameters($DURATION, ...)
    - metavariable-comparison:
        metavariable: $DURATION
        comparison: $DURATION > 0
```

This approach **mathematically evaluates the literal value** (`$DURATION > 0`), rather than merely matching a text pattern — this is far more precisely targeted than the `pattern-not` approach, which is susceptible to variations in expression syntax. However, a limitation that still clings to this approach: Semgrep's `metavariable-comparison` can only evaluate **literal values** written directly in the code (`3600`, `300`, etc.) — if the duration is passed through a **variable or named constant** (`AUTH_VALIDITY_SECONDS`) defined elsewhere, the rule cannot perform a cross-definition value evaluation, and the match will fail (false negative). This is consistent with the general limitations of static pattern-matching analysis already discussed in several other tests in this series.

### 1.5 Large-Scale Empirical Evidence: The KeyDroid Research on Real Developer Practices

This is the strongest available evidence for this test — the academic **KeyDroid** research (a large-scale analysis of secure key storage in real-world Android apps) provides concrete empirical data on how common long-duration configurations are in practice:

> *"The Android Keystore API allows developers to set a validity duration period in seconds during which the key can be reused without any need to reauthenticate. The most popular durations were 5 seconds (set by 38.53% of keys which set a duration) and 1 hour (set by 4.45% of keys)."*

This data reveals two important insights:

1. **5 seconds is the most popular choice** (38.53% of keys that set a duration) — this is relatively reasonable for the "multiple related operations in quick succession" case mentioned in the official evaluation notes (§1.6), though it is still not `0`.
2. **4.45% of keys set a duration of 1 hour** — this is the most concerning finding; the same research also notes that much shorter duration variations are also common:

> *"13.2% of calls that set a duration set it to 3 seconds or less, meaning that the user can only reuse the key within the next few seconds. For some use cases, unless the user proceeds very quickly this is effectively the same as requiring authentication each time."*

This data provides realistic calibration context for severity (§3.6) — durations of a few seconds are practically close to the security of `duration = 0`, while durations measured in hours (which, according to this research, are practiced by nearly 1 in 20 keys) are a genuine risk deserving serious attention when found.

### 1.6 Severity Classification: Dependent on the Scale of the Duration, Not Binary

The official notes provide more nuanced guidance than the previous fallback/confirmation tests — not simply "present vs. absent," but **the scale of the duration itself** that determines the level of risk:

> *"A non-zero authentication validity duration is not inherently a vulnerability. Short durations in the range of seconds may be acceptable for certain use cases where multiple related operations need to be performed in quick succession. However, for high-security applications and sensitive operations, requiring authentication per use (duration = 0) provides the strongest protection."*

This is consistent with the KeyDroid data in §1.5 — a duration of a few seconds (the 13.2% category and part of the 38.53%) has a very different risk profile from a duration on the scale of hours (the 4.45% category).

---

## 2. Tools Used for Testing

### 2.1 Required Tools (Core)

| Tool | Function |
|---|---|
| **jadx** | Decompile DEX → Java (MASTG-TECH-0013) |
| **Semgrep** + official rule `mastg-android-biometric-validity-duration.yml` | Numeric matching for `setUserAuthenticationParameters`/`setUserAuthenticationValidityDurationSeconds` with duration > 0 (MASTG-TECH-0014) |

### 2.2 Alternative & Supporting Tools

| Tool | Function |
|---|---|
| **grep/ripgrep** | Searching for calls using **named variables/constants** (not literals) to close the official rule's false-negative gap (§1.4), including searching for the value `-1` (§1.3) |
| **Frida** | Dynamic verification of the actual duration value used at runtime, if the value comes from a remote config |
| **MobSF** | Automated reports that sometimes include Keystore configuration checks |

### 2.3 Environment Prerequisites

- No device/root needed for static analysis.
- Prepare a list of common constants/variables that might be used for the duration (`AUTH_TIMEOUT`, `VALIDITY_SECONDS`, etc.) for additional manual searching.

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0013** to reverse engineer the application.
2. Use **MASTG-TECH-0014** to search for the relevant APIs.

### 3.2 Method A — Semgrep with the Official Rule

```bash
semgrep --config mastg-android-biometric-validity-duration.yml ./decompiled/sources
```

### 3.3 Method B — grep/ripgrep to Close the Non-Literal Value and -1 Value Gaps

```bash
D=./decompiled/sources

# Search for all calls, including ones using variables (not caught by the official rule)
rg -n 'setUserAuthenticationParameters\(|setUserAuthenticationValidityDurationSeconds\(' $D

# Search specifically for the value -1 (special case from §1.3 that is often missed)
rg -n 'setUserAuthenticationValidityDurationSeconds\(\s*-1\s*\)' $D

# For results using a variable, trace back its definition
rg -n 'AUTH_VALIDITY|AUTHENTICATION_TIMEOUT|VALIDITY_DURATION' $D
```

### 3.4 Method C — Frida for Dynamic Value Verification

```javascript
Java.perform(function () {
    var Builder = Java.use("android.security.keystore.KeyGenParameterSpec$Builder");
    Builder.setUserAuthenticationParameters.implementation = function (timeout, type) {
        console.log("[setUserAuthenticationParameters] timeout=" + timeout + " type=" + type);
        return this.setUserAuthenticationParameters(timeout, type);
    };
});
```

Useful for cases where the duration value is determined dynamically (e.g. from a feature flag/remote config), so it cannot be confirmed from static analysis alone.

### 3.5 Method Comparison: When to Use Which

| Method | Tool | When to Use |
|---|---|---|
| **A** | Semgrep + official rule | Mandatory baseline — captures positive literal values |
| **B** | grep/ripgrep manual | Mandatory pairing — closes the gap for values via variables and the special `-1` case |
| **C** | Frida | Duration value is determined dynamically/via remote config |

**Minimum recommended combination:** **A + B (mandatory pairing)**, with **C** as a supplement for cases with dynamic values.

---

### 3.6 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rule:**

> **Evaluation:** *"The test case fails if the app configures keys used for sensitive operations with: `setUserAuthenticationParameters(duration, type)` where duration > 0, OR `setUserAuthenticationValidityDurationSeconds(duration)` where duration > 0."*

---

#### ❌ FAIL / ISSUE — The check is declared FAILED if:

| No | Condition |
|---|---|
| F1 | A key protecting a sensitive operation is configured with a duration > 0 (either via the new or the deprecated API) |

**Example evidence (reflecting the real pattern from the KeyDroid data in §1.5):**

```java
// Found in com/example/wallet/crypto/KeyManager.java
KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(KEY_ALIAS, PURPOSE_DECRYPT)
    .setUserAuthenticationRequired(true)
    .setUserAuthenticationParameters(3600, KeyProperties.AUTH_BIOMETRIC_STRONG) // 1 hour
    .build();
```

Interpretation: the digital wallet's key remains open for 1 hour after a single authentication — exactly the highest-risk category found among 4.45% of keys in the KeyDroid research. **FAIL**.

---

#### ✅ PASS — The check is declared PASSED if:

| No | Condition |
|---|---|
| P1 | The duration is explicitly set to `0`, **or** |
| P2 | The duration (deprecated API) is set to `-1` for cases demanding pure biometrics (§1.3), **or** |
| P3 | The method is not called at all, relying on the default that requires authentication per operation |

---

#### ⚠️ Important Notes on Scoring

1. **This is a test with a graduated risk scale, not purely binary** — per §1.6, a duration of a few seconds for sequential operations has a very different risk profile from a duration on the scale of hours; do not treat every value > 0 with the same severity.

2. **Don't miss values passed via variables/constants** — the official rule only evaluates direct numeric literals (§1.4); manual auditing (Method B) is mandatory for code that uses named constants.

3. **Also check for the special case of the value `-1`** in the deprecated API — this value has a different semantic from `0` (§1.3) and is not explicitly mentioned in the official evaluation; make sure not to mistakenly mark it as a FAIL.

4. **Refer to the KeyDroid empirical data for calibrating expectations** — findings of short durations (≤5 seconds) are relatively common and may be acceptable depending on the use case; durations on the minute-to-hour scale deserve more serious attention and higher severity.

5. **Severity is modulated by:**

   | Factor | Severity |
   |---|---|
   | Duration on the scale of hours for a financial/highly sensitive data operation | **High** |
   | Duration on the scale of minutes for a sensitive operation | **Medium** |
   | Duration of a few seconds (≤5 seconds) for a clearly documented sequential-operation case | **Low/acceptable** |
   | Duration `0` or `-1` (pure biometrics) | **Not a finding** |

6. **Document:** the code location, the configured duration value (literal or variable name), the type of operation protected, and the business justification if duration > 0 is deliberately used.

---

## 4. Recommendations

### 4.1 Use Duration 0 for Highly Sensitive Operations

```java
// BEFORE — key remains open for 1 hour after authentication
KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(KEY_ALIAS, PURPOSE_DECRYPT)
    .setUserAuthenticationRequired(true)
    .setUserAuthenticationParameters(3600, KeyProperties.AUTH_BIOMETRIC_STRONG)
    .build();

// AFTER — authentication required for every operation, per MASTG-BEST-0036
KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(KEY_ALIAS, PURPOSE_DECRYPT)
    .setUserAuthenticationRequired(true)
    .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
    .build();
```

### 4.2 If Duration > 0 Is Needed, Limit It to a Single-Digit Second Scale and Document the Reason

Per the "multiple related operations in quick succession" context from the official notes — if genuinely necessary, use the lowest value possible (e.g. 3-5 seconds, in line with the most common practice found in the KeyDroid data) and explicitly record the business justification in the code documentation.

### 4.3 Remediation Checklist

- [ ] All keys protecting sensitive operations use a duration of `0`
- [ ] If duration > 0 is used, it is limited to a single-digit-second scale with documented justification
- [ ] No duration value is determined via a variable/remote config without auditing its actual value
- [ ] Verified with Frida if the duration value is dynamic
- [ ] Correlated with MASTG-TEST-0327/0328/0329 results for a thorough audit of biometric Keystore configuration

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0330 (source, tests-beta)](https://github.com/OWASP/mastg/blob/master/tests-beta/android/MASVS-AUTH/MASTG-TEST-0330.md)
- [MASTG-KNOW-0001: Biometric Authentication](https://mas.owasp.org/MASTG/knowledge/android/MASVS-AUTH/MASTG-KNOW-0001/)
- [MASTG-KNOW-0012: Key Generation](https://mas.owasp.org/MASTG/knowledge/android/MASVS-CRYPTO/MASTG-KNOW-0012/)
- [MASTG-BEST-0036: Use Cryptographic Binding for Biometric Authentication](https://github.com/OWASP/mastg/blob/master/best-practices/MASTG-BEST-0036.md)

### 5.2 Official Android Documentation

- [KeyGenParameterSpec.Builder#setUserAuthenticationParameters](https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder#setUserAuthenticationParameters(int,%20int))
- [KeyGenParameterSpec.Builder#setUserAuthenticationValidityDurationSeconds (deprecated)](https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder#setUserAuthenticationValidityDurationSeconds(int))

### 5.3 Research and Real-World Cases

- [arXiv: KeyDroid — A Large-Scale Analysis of Secure Key Storage in Android Apps](https://arxiv.org/pdf/2507.07927)
- [CodeQL Query Help: Insecurely Generated Keys for Local Authentication](https://codeql.github.com/codeql-query-help/java/java-android-insecure-local-key-gen/)
- [Minded Security: Implementing Secure Biometric Authentication on Mobile Applications](https://blog.mindedsecurity.com/2020/07/implementing-secure-biometric.html)

### 5.4 Tool Documentation

- [Semgrep Documentation — metavariable-comparison](https://semgrep.dev/docs/writing-rules/rule-syntax/#metavariable-comparison)
- [Frida — Dynamic Instrumentation Toolkit](https://frida.re/docs/home/)
- [MobSF — Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)

---

*This document was compiled based on official OWASP MASTG content (`tests-beta/android/MASVS-AUTH/MASTG-TEST-0330.md`, `MASTG-KNOW-0001/0012/0043/0047`, `MASTG-BEST-0036`), analysis of the `mastg-android-biometric-validity-duration.yml` rule, and large-scale empirical data from the academic KeyDroid research, which analyzed real-world practices in configuring biometric validity durations across the Android app ecosystem — finding that 38.53% of keys that set a duration chose 5 seconds, yet 4.45% chose a full 1-hour duration. The most important methodological nuance: this test has a graduated (not binary) risk scale based on the magnitude of the duration, the official rule uses a `metavariable-comparison` that is more precise than other biometric rules yet still limited to literal values (does not capture variables), and the deprecated API has a special `-1` value with a semantic different from `0` that is easily overlooked from reading the official overview alone.*
