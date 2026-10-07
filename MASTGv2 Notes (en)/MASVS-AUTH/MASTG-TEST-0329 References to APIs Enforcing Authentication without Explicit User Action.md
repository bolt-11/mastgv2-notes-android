# MASTG-TEST-0329 References to APIs Enforcing Authentication without Explicit User Action

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0329 |
| **Platform** | Android |
| **MASVS Category** | MASVS-AUTH |
| **Weakness** | MASWE-0020 |
| **Test Type** | Static, Code |
| **Related API** | `BiometricPrompt.PromptInfo.Builder`, `setConfirmationRequired` |
| **Related Technique** | MASTG-TECH-0013 (Reverse Engineering), MASTG-TECH-0014 (Static Analysis for Relevant APIs) |
| **Related Knowledge** | MASTG-KNOW-0001 (Biometric Authentication) |
| **Related Best Practice** | MASTG-BEST-0038 (Require Explicit User Confirmation for Biometric Authentication) |
| **Related Test** | MASTG-TEST-0326, MASTG-TEST-0327, MASTG-TEST-0328 — one full sequence of `BiometricPrompt` configuration checks from different angles |
| **Official Rule** | `mastg-android-biometric-no-confirmation-required.yml` — a simple single pattern, structurally similar to the TEST-0328 rule |

---

## 1. Explanation

### 1.1 Testing Objective

Quote from the official MASTG overview:

> *"This test checks if the app enforces biometric authentication without requiring explicit user action. When using BiometricPrompt API... the `setConfirmationRequired()` method in `BiometricPrompt.Builder` controls whether the user must explicitly confirm their authentication, which is enforced by default."*

Just like MASTG-TEST-0328, this is a test where **the API default is already safe** — `setConfirmationRequired()` defaults to `true`, and risk only arises when a developer **explicitly** sets it to `false`.

### 1.2 Why Explicit Confirmation Matters: Passive vs. Active Biometrics

MASTG-BEST-0038 explains the technical mechanism behind this risk:

> *"When `setConfirmationRequired(false)` is used, passive biometrics such as face recognition can authenticate the user implicitly as soon as the device detects their biometric data. This means authentication can complete without the user actively acknowledging the operation."*

The difference in biometric modality here is crucial:

| Modality | Nature | Implication without Confirmation |
|---|---|---|
| **Fingerprint** | Active — the user must **deliberately** touch the sensor | Lower risk; a finger touch still requires direct physical intent |
| **Face/iris** | Passive — simply **pointing** the camera at the face, without a conscious action from the user | High risk — authentication can complete **without the user being aware or consenting** that anything is happening at all |

Official Android documentation explains the design intent of this feature as a convenience-vs-security trade-off:

> *"If your app shows a biometric authentication dialog for a lower-risk action, you can provide a hint to the system that the user doesn't need to confirm authentication. This hint can allow the user to view content in your app more quickly after re-authenticating using a passive modality."*

However, the same documentation explicitly reverses the recommendation for higher-risk cases:

> *"This configuration is preferable if your app is showing the dialog to confirm a sensitive or high-risk action, such as making a purchase"* — referring to **`setConfirmationRequired(true)`**, not `false`.

### 1.3 Concrete Attack Scenario: Exploiting the Passive Modality Without Consent

The real risk of a `false` configuration on a passive modality is a scenario where **the user does not actively choose to authenticate**, yet the system still accepts the biometric that was "seen" by the sensor:

- **An unwitting camera "flash" attack** — an attacker briefly points the victim's device (already unlocked/held) at the victim's face (for example while the victim is distracted, asleep, or unaware), triggering passive face authentication without the victim ever intending to perform any transaction at all.
- **Lack of an "aware window"** for the user to cancel — in active mode (confirmation required), the user still has a final chance to press a confirm/cancel button after the biometric is verified; in passive mode, the process completes **instantly** the moment a matching face is detected.

### 1.4 Cross-Platform Real-World Evidence: The Face ID Case and Abuse for Fund Transfers

Although a different platform (iOS, not Android), the following case precisely illustrates the **same class of risk** that `setConfirmationRequired(true)` tries to prevent — abuse of passive facial biometrics against an unaware victim to authorize financial transactions:

> *"Researchers demonstrated at the Black Hat USA 2019 conference that they could bypass Face ID using specially modified glasses with tape, and when placing the glasses over a sleeping victim's face, they were able to access the iPhone and send themselves money through a mobile payment app."*

Another real case (reported by media, not controlled research) shows an alleged similar pattern in the field:

> *"Approximately $25,000 had been transferred out of a victim's checking accounts using Zelle, Venmo, CashApp, and investment accounts, and the victim suspected his assailants might have used his unconscious face to unlock his iPhone."*

Although these cases involve iOS Face ID (not the Android `BiometricPrompt` API) and involve bypassing screen unlock generally (not specifically the `setConfirmationRequired` API), **the threat principle is identical** — a passively detected face (without the user consciously choosing to authenticate) can be exploited to authorize high-value financial actions without genuine consent. This is the real-world justification for why MASTG-BEST-0038 specifically names "payments" as the primary example of an operation that **must** use `setConfirmationRequired(true)`.

### 1.5 Important Nuance: This Is Only a "Hint," the System Can Ignore It

A note from official Android documentation that is rarely highlighted yet important for interpreting test results:

> *"Caution: Because this flag is passed as a hint to the system, the system might ignore the value if the user has changed their system settings for biometric authentication."*

This means `setConfirmationRequired(false)` **does not guarantee** passive behavior will actually occur under all conditions — it is a **request**, not an **absolute command**, and the Android system (or user preferences at the OS level) may make a different final decision. The implication for testing: a FAIL finding from static analysis **remains valid as an indication of the developer's flawed intent/configuration**, but actual behavior on a specific device may vary depending on the Android version and user settings — worth noting as an interpretation limitation, not a reason to dismiss the finding.

### 1.6 Severity Classification: Same as TEST-0326, Not Automatically a Critical Vulnerability

The official notes use language similar to TEST-0326 (device-credential fallback):

> *"Using setConfirmationRequired(false) is not inherently a vulnerability. It may be appropriate for low-risk operations, but for sensitive operations like payments or data access, the app should use setConfirmationRequired(true)."*

This confirms that this test, like TEST-0326, is more appropriately categorized as a **hardening/context-dependent issue** — its final severity depends entirely on whether the protected operation is genuinely sensitive (payments, health data access) or merely a matter of convenience (quick login to non-sensitive content).

---

## 2. Tools Used for Testing

### 2.1 Required Tools (Core)

| Tool | Function |
|---|---|
| **jadx** | Decompile DEX → Java (MASTG-TECH-0013) |
| **Semgrep** + official rule `mastg-android-biometric-no-confirmation-required.yml` | Matching the `setConfirmationRequired(false)` pattern (MASTG-TECH-0014) |

### 2.2 Alternative & Supporting Tools

| Tool | Function |
|---|---|
| **grep/ripgrep** | Context verification of the call — whether the same builder is used for a sensitive operation (payment) or a lightweight operation (content login) |
| **MobSF** | Automated reports that sometimes include biometric configuration checks |
| **Physical-device verification (face-unlock device)** | Direct observation of actual behavior — relevant given the "hint, can be ignored by the system" nuance in §1.5 |

### 2.3 Environment Prerequisites

- No device/root needed for static analysis.
- To verify actual behavior (optional), a device with a face/iris sensor that supports passive mode is required.

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0013** to reverse engineer the application.
2. Use **MASTG-TECH-0014** to search for the relevant APIs.

### 3.2 Method A — Semgrep with the Official Rule

```bash
semgrep --config mastg-android-biometric-no-confirmation-required.yml ./decompiled/sources
```

### 3.3 Method B — grep/ripgrep for Operation Context Verification

```bash
D=./decompiled/sources

# Search for the directly dangerous pattern
rg -n 'setConfirmationRequired\(\s*false\s*\)' $D

# Verify the surrounding context of the call — look for indications of method/class names related to payments/sensitive data
rg -n -B10 'setConfirmationRequired(false)' $D | grep -iE 'payment|transfer|checkout|health|medical|sensitive'
```

### 3.4 Method C — Dynamic Verification on a Physical Device with Face Unlock

```
Manual procedure:
1. Run the app on a device with a supporting face/iris sensor
2. Trigger the BiometricPrompt dialog at a point flagged `setConfirmationRequired(false)` from Method A/B
3. Observe: does the operation complete INSTANTLY as soon as the face is detected, without any additional confirmation button?
4. Compare with another point that uses the default/true — does an explicit confirmation button appear?
```

Useful for directly confirming that the `false` hint actually takes effect on the test device (given the note in §1.5 that the system can ignore it).

### 3.5 Method Comparison: When to Use Which

| Method | Tool | When to Use |
|---|---|---|
| **A** | Semgrep + official rule | Mandatory baseline |
| **B** | grep/ripgrep manual | Assessing the relevance of sensitive/non-sensitive context around the call |
| **C** | Physical device verification | Confirming actual behavior, given this flag's "hint" nature |

**Minimum recommended combination:** **A + B (mandatory)**, with **C** as a supplement when a device with a face/iris sensor is available for a high-risk operation found.

---

### 3.6 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rule:**

> **Evaluation:** *"The test case fails if the app sets `setConfirmationRequired()` to `false` for sensitive operations that require explicit user authorization."*

---

#### ❌ FAIL / ISSUE — The check is declared FAILED if:

| No | Condition |
|---|---|
| F1 | `setConfirmationRequired(false)` is called for a sensitive operation that requires explicit user authorization (payment, health data access, etc.) |

**Example evidence:**

```java
// Found in com/example/wallet/payment/PaymentConfirmActivity.java
BiometricPrompt.PromptInfo promptInfo = new BiometricPrompt.PromptInfo.Builder()
    .setTitle("Confirm Payment")
    .setSubtitle("IDR 5,000,000 to John Doe")
    .setConfirmationRequired(false) // risky for a payment operation
    .build();
```

Interpretation: a high-value payment operation is configured to use passive mode without explicit confirmation — exactly the risk scenario warned of in MASTG-BEST-0038 and illustrated by the real-world case in §1.4. **FAIL**.

---

#### ✅ PASS — The check is declared PASSED if:

| No | Condition |
|---|---|
| P1 | `setConfirmationRequired(true)` is explicitly set for a sensitive operation, **or** |
| P2 | The method is **not called at all** (default `true`) for a sensitive operation |
| P3 | `setConfirmationRequired(false)` is **only** used for low-risk operations (e.g. quick login to non-sensitive content), per official Android recommendations |

---

#### ⚠️ Important Notes on Scoring

1. **Absence of the API call is a PASS, not a FAIL** — same as TEST-0328, the default is already safe; focus the evaluation on cases where `false` is **explicitly** written by the developer.

2. **Operation context is the primary determinant of severity, not merely the presence of the pattern** — a `setConfirmationRequired(false)` finding on a non-sensitive feature is **not a finding at all**; always trace the call context (Activity/method name, parameters shown in the dialog) before concluding FAIL.

3. **Remember the "hint" nature of this flag (§1.5)** — do not claim absolute certainty that passive behavior will always occur exactly as the code suggests; where possible, verify with Method C on a real device for a stronger claim in the report.

4. **Severity is modulated by:**

   | Factor | Severity |
   |---|---|
   | `setConfirmationRequired(false)` on a high-value payment/financial operation or health data access | **Medium-High** |
   | `false` on a sensitive but lower-value operation (e.g. edit profile) | **Low-Medium** |
   | `false` on a non-sensitive operation (content login, personalization) | **Not a finding** |

5. **Document:** the code location, the context of the protected operation (feature/Activity name), the configured value, and the results of physical-device verification if performed.

---

## 4. Recommendations

### 4.1 Use Confirmation Required for High-Value Operations

```java
// BEFORE — payment using passive mode without confirmation
new BiometricPrompt.PromptInfo.Builder()
    .setTitle("Confirm Payment")
    .setConfirmationRequired(false)
    .build();

// AFTER — per MASTG-BEST-0038
new BiometricPrompt.PromptInfo.Builder()
    .setTitle("Confirm Payment")
    .setConfirmationRequired(true)
    .build();
```

### 4.2 Separate Configuration Paths Based on Operation Sensitivity

Consider creating separate helper/factory methods for "sensitive-operation biometric prompt" (always `true`) versus "lightweight-operation biometric prompt" (`false` allowed), so new developers do not accidentally use a passive configuration for a new sensitive feature down the line.

### 4.3 Remediation Checklist

- [ ] All payment/financial/sensitive-data operations use `setConfirmationRequired(true)` or the default
- [ ] `setConfirmationRequired(false)` is only used for low-risk operations with a clearly documented rationale
- [ ] Verified on a physical device with a face/iris sensor for any high-risk cases found
- [ ] Correlated with MASTG-TEST-0326/0327/0328 results for a thorough audit of `BiometricPrompt` configuration

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0329 (source, tests-beta)](https://github.com/OWASP/mastg/blob/master/tests-beta/android/MASVS-AUTH/MASTG-TEST-0329.md)
- [MASTG-KNOW-0001: Biometric Authentication](https://mas.owasp.org/MASTG/knowledge/android/MASVS-AUTH/MASTG-KNOW-0001/)
- [MASTG-BEST-0038: Require Explicit User Confirmation for Biometric Authentication](https://github.com/OWASP/mastg/blob/master/best-practices/MASTG-BEST-0038.md)

### 5.2 Official Android Documentation

- [Android Developers: Implement a Custom Biometric Authentication Flow — No Explicit User Action](https://developer.android.com/identity/sign-in/biometric-auth#no-explicit-user-action)
- [BiometricPrompt.Builder#setConfirmationRequired](https://developer.android.com/reference/android/hardware/biometrics/BiometricPrompt.Builder#setConfirmationRequired(boolean))

### 5.3 Research and Real-World Cases

- [MacRumors: Researchers Demonstrated Method for Bypassing Face ID on an 'Unconscious' Victim's iPhone Using Glasses and Tape](https://www.macrumors.com/2019/08/08/face-id-bypassed-glasses-tape/amp)
- [Neowin: Tape and Glasses Are All You Need to Break Apple's FaceID — Alongside a Sleeping Person](https://www.neowin.net/news/tape-and-glasses-are-all-you-need-to-break-apples-faceid---alongside-a-sleeping-person/)

### 5.4 Tool Documentation

- [Semgrep Documentation](https://semgrep.dev/docs/)
- [MobSF — Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)

---

*This document was compiled based on official OWASP MASTG content (`tests-beta/android/MASVS-AUTH/MASTG-TEST-0329.md`, `MASTG-KNOW-0001`, `MASTG-BEST-0038`), official Android documentation on biometric authentication without explicit user action, and real-world (albeit cross-platform, iOS Face ID) cases from Black Hat 2019 research and media reports on the abuse of passive facial biometrics against unaware victims to authorize fund transfers — concrete evidence for why MASTG-BEST-0038 specifically highlights "payments" as the primary example of an operation that must use explicit confirmation. The most important methodological nuance: same as TEST-0328, the API default is already safe (absence of the call = PASS), and this flag is a "hint" that the system can ignore based on user settings — claims of absolute certainty from static analysis alone need to be tempered with this caveat.*
