# MASTG-TEST-0328 References to APIs Detecting Biometric Enrollment Changes

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0328 |
| **Platform** | Android |
| **MASVS Category** | MASVS-AUTH |
| **Weakness** | MASWE-0022 |
| **Test Type** | Static, Code |
| **Related API** | `KeyGenParameterSpec.Builder`, `setInvalidatedByBiometricEnrollment` |
| **Related Technique** | MASTG-TECH-0013 (Reverse Engineering), MASTG-TECH-0014 (Static Analysis for Relevant APIs) |
| **Related Knowledge** | MASTG-KNOW-0001 (Biometric Authentication) |
| **Related Best Practice** | MASTG-BEST-0037 (Invalidate Biometric Keys on Enrollment Changes) |
| **Related Test** | **MASTG-TEST-0327** — closely related topic (biometric key configuration), targeting a different configuration aspect (see §1.4) |
| **Official Rule** | `mastg-android-biometric-invalidated-enrollment.yml` — a single pattern, see §1.3 |

---

## 1. Explanation

### 1.1 Testing Objective and Threat Model

Quote from the official MASTG overview:

> *"This test checks whether the app fails to protect sensitive operations against unauthorized access following biometric enrollment changes. An attacker who obtains the device passcode could add a new fingerprint or facial representation via system settings and use it to authenticate in the app."*

The threat model here is very specific and differs from the other biometric tests in this research series (TEST-0326, TEST-0327) — it's not about a weakness in the biometric API itself, but about a **two-step** scenario: (1) an attacker successfully obtains the device's **lock-screen passcode** (via shoulder surfing, social engineering, or even some other physical prerequisite), then (2) uses that access to **enroll their own fingerprint/face** via the Android system's Settings menu — an action that **requires no additional authorization** beyond the passcode already possessed. Once enrolled, the attacker's newly registered biometric can, by default, be used to unlock **any** Keystore key already present on the device, unless that key was explicitly configured to reject biometrics enrolled after the key was created.

### 1.2 Technical Mechanism: `setInvalidatedByBiometricEnrollment`

> *"This behaviour occurs when `setInvalidatedByBiometricEnrollment` is set to `false` when keys are generated. By default and when set to `true`, a key becomes permanently invalidated if a new biometric is enrolled. As a result, only users whose biometric data was enrolled when the item was created can unlock it."*

An important point that distinguishes this test from TEST-0327: **`true` is the default behavior** here (unlike `setUserAuthenticationRequired` in TEST-0327, whose default is `false`/not required). MASTG-BEST-0037 emphasizes the nuance of this default-behavior relationship:

> *"Either configure `setInvalidatedByBiometricEnrollment(true)` explicitly, or rely on the default behavior, which invalidates keys when `setUserAuthenticationRequired(true)` is set."*

This means: **automatic invalidation only applies when the key also uses `setUserAuthenticationRequired(true)`** (the TEST-0327 requirement). This creates a cross-dependency between the two tests — if a key fails TEST-0327 (it doesn't require user authentication at all), the question of enrollment invalidation in this test becomes **technically irrelevant**, because that key is already usable without any authentication whatsoever — its vulnerability is already "worse" than what this test addresses.

### 1.3 Analysis of the Official Rule: A Simple, Precisely-Targeted Single Pattern

Unlike the other biometric rules in this research series, which have many patterns and some coverage weaknesses (TEST-0326 §1.4, TEST-0327 §1.4), the rule for this test is very simple:

```yaml
pattern: $BUILDER.setInvalidatedByBiometricEnrollment(false)
```

This rule **is not susceptible to false positives** the way the TEST-0326 rule is — because the only value that is explicitly dangerous is the literal `false`, and the rule only matches exactly that, without the ambiguity of other values that could be misinterpreted. However, this also means the rule **does not capture the "never called at all" case** — since `true` is the default, an application that **never calls this method at all** is automatically safe (provided `setUserAuthenticationRequired(true)` is also called, per §1.2). This is one of the few cases in this research series where **the absence of an API call is safer than calling it with the wrong value** — an evaluation pattern reversed from most resilience/root-detection tests, which demand the presence of a mechanism.

### 1.4 Comparison with MASTG-TEST-0327: Two Independent Key Configuration Aspects

| | MASTG-TEST-0327 | MASTG-TEST-0328 (this test) |
|---|---|---|
| **Core question** | Is authentication *cryptographically bound* to the operation (CryptoObject + `setUserAuthenticationRequired`)? | Does the key remain valid after a **new biometric** is enrolled in the system? |
| **Safe default value** | **Not safe by default** — the developer must explicitly set it to `true` | **Safe by default** — `true` is the default; risk only arises when explicitly set to `false` |
| **Attack prerequisites** | Physical access + root/modified APK (hooking) | Knowledge of the victim's **lock-screen passcode** + brief physical access to the device (no root needed) |
| **Relationship** | Enrollment invalidation (this test) is **only effective** if `setUserAuthenticationRequired(true)` is also set (see §1.2) | — |

This difference in attack prerequisites is important to note — the scenario in this test **requires no root or modified APK** at all, only requiring **knowledge of the victim's lock-screen passcode** (which can be obtained via non-technical means such as shoulder surfing or social engineering) plus brief physical access to the device to enroll a new biometric via Settings. This makes this test's threat scenario realistically **easier to execute** by a non-technical attacker compared to TEST-0327's scenario, which requires Frida hooking skills.

### 1.5 Real-World Context: A Chain of Attacks Starting from the Passcode

Recent security research on Samsung chipsets (CVE-2025-20987, CVE-2025-20988, CVE-2025-20989) illustrates why "obtaining the passcode" is not merely a hypothetical scenario:

> *"Recent critical vulnerabilities affecting Samsung and other devices enable PIN cracking and credential encryption bypass. The PIN controls unlocking the screen, authorizing payments, enrolling or changing biometrics, and decrypting user data."*

This quote explicitly confirms the exact threat chain the official overview discusses — a PIN/passcode not only controls screen unlock, but also **controls new biometric enrollment**, which ultimately controls access to encrypted cryptographic keys. This shows that PIN brute-force/cracking vulnerabilities at the OS/chipset level and `setInvalidatedByBiometricEnrollment` misconfiguration weaknesses at the application level are **two layers of the same attack chain** — weakening one point amplifies the impact of a weakness at the other point.

### 1.6 Balance Warning: Correctly Handling `KeyPermanentlyInvalidatedException`

MASTG-BEST-0037 gives an important note that is often the source of bugs on the other end of the spectrum — if a developer has already correctly set `true` (per the recommendation), they are **required to handle the consequences** properly:

> *"Key invalidation is immediate and permanent when a new biometric is enrolled. The app must handle `KeyPermanentlyInvalidatedException` and guide the user to re-authenticate to create a new key."*

A real case from a public bug report shows this is not a theoretical concern — an open-source crypto wallet reported exactly this issue:

> *"Adding a fingerprint on Android may permanently invalidate the vault's hardware key"* — from GitHub issue `0xMiden/wallet#1307`.

And another report shows a more severe consequence when error handling is not done correctly — not merely a user being prompted to re-enroll, but **endless, repeated crashing**:

> *"resetOnError recurses until the process dies when the fresh key also fails (Samsung, after biometric enrollment)"* — from GitHub issue `flutter_secure_storage#1282`.

This confirms that remediation for this test is **not just a matter of changing a single boolean line** — developers must ensure the exception-handling flow after invalidation runs smoothly (regenerating a new key + prompting re-authentication), rather than causing a permanently locked vault or repeated application crashes. This security-vs-usability trade-off is relevant to include in the recommendations (§4).

---

## 2. Tools Used for Testing

### 2.1 Required Tools (Core)

| Tool | Function |
|---|---|
| **jadx** | Decompile DEX → Java (MASTG-TECH-0013) |
| **Semgrep** + official rule `mastg-android-biometric-invalidated-enrollment.yml` | Matching the `setInvalidatedByBiometricEnrollment(false)` pattern (MASTG-TECH-0014) |

### 2.2 Alternative & Supporting Tools

| Tool | Function |
|---|---|
| **grep/ripgrep** | Cross-checking with `setUserAuthenticationRequired` in the same file/builder, to assess the relevance of the finding per the dependency in §1.2 |
| **MobSF** | Automated reports that sometimes include Keystore configuration checks |
| **adb (manual device testing)** | Genuine dynamic verification — enroll a new biometric in Settings on a test device, then observe whether the application genuinely rejects the old key (see Method C) |

### 2.3 Environment Prerequisites

- No device/root needed for static analysis.
- For dynamic verification (Method C), a physical device/emulator capable of enrolling an additional biometric is required (emulators generally need virtual biometric sensor support).

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0013** to reverse engineer the application.
2. Use **MASTG-TECH-0014** to search for the relevant APIs.

### 3.2 Method A — Semgrep with the Official Rule

```bash
semgrep --config mastg-android-biometric-invalidated-enrollment.yml ./decompiled/sources
```

### 3.3 Method B — grep/ripgrep for Cross-Dependency Verification

```bash
D=./decompiled/sources

# Search for the directly dangerous pattern
rg -n 'setInvalidatedByBiometricEnrollment\(\s*false\s*\)' $D

# Verify whether setUserAuthenticationRequired is also used on the same builder (relevance, §1.2)
rg -n -B5 -A5 'setInvalidatedByBiometricEnrollment' $D | grep -B10 -A10 'setUserAuthenticationRequired'

# Also search for handling of KeyPermanentlyInvalidatedException to assess remediation quality (§1.6)
rg -n 'KeyPermanentlyInvalidatedException' $D
```

### 3.4 Method C — Genuine Dynamic Verification on a Physical Device/Emulator

```
Manual procedure:
1. Ensure the app is logged in and has a Keystore key related to a sensitive operation (e.g. opening a vault/wallet)
2. Enroll a NEW fingerprint/face in the test device's Settings > Security > Biometrics menu
3. Return to the app and try to re-access the sensitive operation with the NEW biometric
4. Observe: does the app reject it (key invalidated, PASS) or still accept it (key still valid, FAIL)?
5. Also observe: does the app handle the rejection gracefully (prompting re-enrollment) or crash (see §1.6)?
```

This is the most conclusive form of testing for this test — it directly reproduces the official threat scenario without reading any code at all, though it requires access to a supporting physical device/emulator.

### 3.5 Method Comparison: When to Use Which

| Method | Tool | When to Use |
|---|---|---|
| **A** | Semgrep + official rule | Mandatory baseline, pattern coverage is already precisely targeted (§1.3) |
| **B** | grep/ripgrep manual | Verify relevance per the `setUserAuthenticationRequired` dependency (§1.2) and exception-handling quality (§1.6) |
| **C** | Manual dynamic verification | The strongest conclusive evidence, directly reproducing the original threat scenario |

**Minimum recommended combination:** **A + B (mandatory)**, with **C** strongly recommended if a test device is available — this is one of the tests where manual dynamic verification is relatively cheap and quick to perform, requiring no specialized tooling such as Frida.

---

### 3.6 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rule:**

> **Evaluation:** *"The test case fails if the app uses `setInvalidatedByBiometricEnrollment(false)` for keys used to protect sensitive data resources."*

---

#### ❌ FAIL / ISSUE — The check is declared FAILED if:

| No | Condition |
|---|---|
| F1 | `setInvalidatedByBiometricEnrollment(false)` is found on a key protecting a sensitive resource/operation |

**Example evidence:**

```java
// Found in com/example/wallet/crypto/KeyManager.java
KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(KEY_ALIAS, PURPOSE_DECRYPT)
    .setUserAuthenticationRequired(true)
    .setInvalidatedByBiometricEnrollment(false) // DELIBERATELY set to false
    .build();
```

Interpretation: the key remains valid even if a new biometric is enrolled afterward — exactly the threat scenario in §1.1. **FAIL**.

---

#### ✅ PASS — The check is declared PASSED if:

| No | Condition |
|---|---|
| P1 | `setInvalidatedByBiometricEnrollment(true)` is explicitly called, **or** |
| P2 | The method is **not called at all** (relying on the default `true`) — still a PASS as long as `setUserAuthenticationRequired(true)` is also present (§1.2) |

**Example evidence:**

```java
KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(KEY_ALIAS, PURPOSE_DECRYPT)
    .setUserAuthenticationRequired(true)
    // does not call setInvalidatedByBiometricEnrollment() -> defaults to true
    .build();
```

**PASS**.

---

#### ⚠️ Important Notes on Scoring

1. **Absence of the API call is a PASS, not a FAIL** — unlike most other tests in the resilience/biometric category, which demand the explicit presence of a mechanism, this test is unique because **the default is already safe**; do not mistakenly mark "no API reference found" as a negative finding here.

2. **Always verify the dependency on `setUserAuthenticationRequired`** — if the key being examined does **not** use `setUserAuthenticationRequired(true)` at all, enrollment invalidation becomes technically irrelevant (§1.2); in such cases, focus the finding on MASTG-TEST-0327, which targets a more fundamental problem.

3. **Consider dynamic verification (Method C) as the strongest evidence** — especially for high-risk application categories (crypto wallets, banking), directly reproducing the threat scenario (enroll a new biometric, attempt access) provides irrefutable evidence compared to merely finding a line of code.

4. **Don't forget to assess exception-handling quality as a separate finding** — if `setInvalidatedByBiometricEnrollment(true)` is already correctly set but `KeyPermanentlyInvalidatedException` is not handled properly (§1.6), this is a **separate usability/stability finding** worth reporting even though this security test technically passes.

5. **Severity is modulated by:**

   | Factor | Severity |
   |---|---|
   | `setInvalidatedByBiometricEnrollment(false)` explicitly set for a financial/crypto-wallet operation, combined with `setUserAuthenticationRequired(true)` | **Medium-High** |
   | Same as above but in a lower-risk category application | **Low-Medium** |
   | `false` found but the key doesn't use `setUserAuthenticationRequired` at all | **Not relevant to this test** — refer to TEST-0327 as the primary finding |

6. **Document:** the code location, the configured value, the presence of `setUserAuthenticationRequired` on the same builder, and the results of dynamic verification if performed.

---

## 4. Recommendations

### 4.1 Avoid Explicitly Setting False Without a Strong Reason

```java
// BEFORE — susceptible to the "attacker enrolls a new biometric" scenario
KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(KEY_ALIAS, PURPOSE_DECRYPT)
    .setUserAuthenticationRequired(true)
    .setInvalidatedByBiometricEnrollment(false)
    .build();

// AFTER — explicitly true, or simply remove this line (default is already true)
KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(KEY_ALIAS, PURPOSE_DECRYPT)
    .setUserAuthenticationRequired(true)
    .setInvalidatedByBiometricEnrollment(true)
    .build();
```

### 4.2 Handle KeyPermanentlyInvalidatedException Properly (Per §1.6)

```java
try {
    cipher.init(Cipher.DECRYPT_MODE, secretKey);
} catch (KeyPermanentlyInvalidatedException e) {
    // DO NOT retry endlessly (see the real case in flutter_secure_storage#1282)
    notifyUserKeyInvalidated();
    regenerateKeyAndPromptReEnrollment();
}
```

### 4.3 Remediation Checklist

- [ ] No `setInvalidatedByBiometricEnrollment(false)` on keys protecting sensitive operations
- [ ] `setUserAuthenticationRequired(true)` is consistently paired (prerequisite for enrollment invalidation to be relevant)
- [ ] `KeyPermanentlyInvalidatedException` is handled by regenerating the key + prompting re-enrollment, not crashing/retrying endlessly
- [ ] Dynamically verified by enrolling a new biometric on a test device (Method C)
- [ ] Correlated with MASTG-TEST-0327 results for a complete picture of biometric key configuration

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0328 (source, tests-beta)](https://github.com/OWASP/mastg/blob/master/tests-beta/android/MASVS-AUTH/MASTG-TEST-0328.md)
- [MASTG-TEST-0327: References to APIs for Event-Bound Biometric Authentication](https://mas.owasp.org/MASTG/tests/android/MASVS-AUTH/MASTG-TEST-0327/)
- [MASTG-KNOW-0001: Biometric Authentication](https://mas.owasp.org/MASTG/knowledge/android/MASVS-AUTH/MASTG-KNOW-0001/)
- [MASTG-BEST-0037: Invalidate Biometric Keys on Enrollment Changes](https://github.com/OWASP/mastg/blob/master/best-practices/MASTG-BEST-0037.md)

### 5.2 Official Android Documentation

- [KeyGenParameterSpec.Builder#setInvalidatedByBiometricEnrollment](https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder#setInvalidatedByBiometricEnrollment(boolean))
- [KeyPermanentlyInvalidatedException](https://developer.android.com/reference/android/security/keystore/KeyPermanentlyInvalidatedException)

### 5.3 Research and Real-World Cases

- [Blackduck: Understanding CVE-2020-7958 — Biometric Data Extraction in Android](https://www.blackduck.com/blog/cve-2020-7958-trustlet-tee-attack.html)
- [arXiv: "Please Enter Your PIN" — On the Risk of Bypass Attacks on Biometric Authentication on Mobile Devices](https://arxiv.org/pdf/1911.07692)
- [GitHub Issue: 0xMiden/wallet#1307 — Adding a Fingerprint on Android May Permanently Invalidate the Vault's Hardware Key](https://github.com/0xMiden/wallet/issues/1307)
- [GitHub Issue: flutter_secure_storage#1282 — resetOnError Recurses Until the Process Dies](https://github.com/juliansteenbakker/flutter_secure_storage/issues/1282)

### 5.4 Tool Documentation

- [Semgrep Documentation](https://semgrep.dev/docs/)
- [MobSF — Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)

---

*This document was compiled based on official OWASP MASTG content (`tests-beta/android/MASVS-AUTH/MASTG-TEST-0328.md`, `MASTG-KNOW-0001`, `MASTG-BEST-0037`), analysis of the `mastg-android-biometric-invalidated-enrollment.yml` rule, recent Samsung CVE research (CVE-2025-20987/20988/20989) on the PIN-cracking-to-biometric-enrollment attack chain, and real public bug reports (0xMiden/wallet, flutter_secure_storage) on the challenges of handling `KeyPermanentlyInvalidatedException`. The most important methodological nuance: this is one of the tests where **the API default is already safe** — the absence of a `setInvalidatedByBiometricEnrollment()` call in the code means a PASS, not a FAIL, unlike the evaluation pattern of most other resilience tests; and the relevance of a FAIL finding depends entirely on the presence of `setUserAuthenticationRequired(true)` on the same key, closely linking this test to MASTG-TEST-0327.*
