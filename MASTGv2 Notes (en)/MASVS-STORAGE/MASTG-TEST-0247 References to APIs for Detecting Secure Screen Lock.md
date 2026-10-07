# MASTG-TEST-0247 References to APIs for Detecting Secure Screen Lock

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0247 |
| **Platform** | Android |
| **Official test location** | **MASVS-RESILIENCE** folder in the MASTG source |
| **Weakness** | MASWE-0017 — *Device Secure Lock Not Enforced* (categorized under **MASVS-CRYPTO**) |
| **Official semgrep rule message** | References **`[MASVS-STORAGE]`** |
| **Highlighted APIs** | `KeyguardManager` (`isDeviceSecure()`, `isKeyguardSecure()`), `BiometricManager#canAuthenticate()` |
| **Test Type** | Static, Code |
| **Profile** | **L2 only** |
| **Knowledge** | MASTG-KNOW-0001 *(note: this ID does not actually exist under the MASVS-STORAGE category following the common numbering pattern — the valid MASTG-KNOW-0001 document is titled "Biometric Authentication" under the **MASVS-AUTH** category, see §1.6)* |
| **Related Techniques** | MASTG-TECH-0013 (Reverse Engineering), MASTG-TECH-0014 (Static Analysis) |
| **Related Tests** | Closely related to Android Keystore testing (`setUserAuthenticationRequired`) and biometric authentication (MASVS-AUTH) |
| **Related Demo** | — (none) |
| **Official Rule** | `mastg-android-device-passcode-present.yml` (exists, but its coverage is narrow — see §3.2) |
| **Related CWE** | CWE-287 (Improper Authentication), CWE-862 (Missing Authorization) |

---

## 1. Explanation

### 1.1 Metadata Spotlight: Four Official Sources, Three Different MASVS Categories

Before getting into the technical substance, there is a metadata finding worth highlighting upfront because it is **the most striking one** found throughout this series of research documents. For one and the same test, four official MASTG sources give **mutually different** MASVS category attributions:

| Source | Implied MASVS Category |
|---|---|
| Location of the test file `MASTG-TEST-0247.md` in the repository | **MASVS-RESILIENCE** |
| `maswe: [MASWE-0017]` in the test's frontmatter | Refers to a weakness categorized under **MASVS-CRYPTO** |
| Official semgrep rule message (`mastg-android-device-passcode-present.yml`) | **`[MASVS-STORAGE]`** |
| Technical substance of the API (`KeyguardManager`, `BiometricManager`) | Most conceptually relevant to **MASVS-AUTH** (authentication) |

This is not merely an administrative detail — the categorization confusion has a real impact on how this test's findings are **grouped and prioritized** in audit reports or vulnerability tracking systems that organize results by MASVS category. For practical purposes, this document will follow the technical substance (authentication/access control for cryptographic keys) while still recording all three official attributions as they stand.

### 1.2 Testing Objective

Official MASTG overview quote:

> *"This test verifies whether an app is running on a device with a passcode set. Android apps can determine whether a secure screen lock (such as PIN, or password) is enabled by using platform-provided APIs."*

Two official API pathways this test examines:

1. **`KeyguardManager.isDeviceSecure()`** — returns `true` when the device has a secure lock screen (PIN/pattern/password), distinct from a mere swipe-to-unlock or no lock at all.
2. **`BiometricManager#canAuthenticate(int)`** — can be used as an **alternative pathway** when `KeyguardManager` is unavailable or restricted by certain device vendors, because biometric authentication on Android **requires** a secure screen lock to exist as its fallback.

### 1.3 Why This Matters: The Connection to Android Keystore and `setUserAuthenticationRequired`

This is the most important technical context explaining **why** this test is categorized as cryptography-related (MASWE-0017/MASVS-CRYPTO) even though the API examined looks like a purely authentication issue. The Android Keystore System provides a `setUserAuthenticationRequired(true)` flag when generating a cryptographic key — this flag **ties the ability to use that key** to the device being in an unlocked state via the user's credentials (PIN/pattern/password/biometric).

Per the Android compatibility requirements (Android CDD — Compatibility Definition Document):

> *"Devices MUST NOT authenticate access to keystores if the application has called `KeyGenParameterSpec.Builder.setUserAuthenticationRequired(true)`. Keys MUST be unlocked for third-party developer apps to use when the user unlocks the secure lock screen."*

The crucial consequence: **if the device has no secure lock screen at all**, this "unlock via user credentials" mechanism **can never be triggered** — the system's behavior toward keys protected by `setUserAuthenticationRequired(true)` under this condition varies depending on the Android version and vendor implementation, but generally creates an **ambiguous condition** that the application's security design did not anticipate: the key might remain accessible without the authentication gate that should otherwise apply, or conversely the application experiences unexpected functional failure. A real-world case from an open-source crypto wallet project (`dashpay/platform`, pull request *"keep Keystore's unlocked-device gate from bricking wallets and signing on defective OEM builds"*) illustrates the other side of this problem: certain defective/non-standard OEM builds caused this gate to **brick** the wallet's ability to sign transactions — showing just how fragile the assumption "the device surely has a secure lock" is when not explicitly verified by the application beforehand.

**This is the value of this test**: by checking `isDeviceSecure()` **before** relying on a key protected by `setUserAuthenticationRequired`, the application can proactively display a warning to the user ("Enable a screen lock to use this feature") instead of letting the system's ambiguous behavior occur silently.

### 1.4 Explicitly Acknowledged Limitation: Apps Cannot Force It

The official overview gives an important caveat that must be understood before evaluating findings:

> *"Apps **cannot force** users to enable biometrics at the system level, only enforce their use within the app for accessing sensitive functionality."*

This means the value of this test is **not** about changing the user's system settings, but about **whether the application reacts appropriately** to that condition — e.g., refusing to enable a feature that requires an authentication-protected key, or displaying an explicit warning, rather than silently continuing a sensitive operation without regard to the device's security state at all.

### 1.5 Two Complementary API Methods, Not Duplicates

As noted in §1.2, `BiometricManager#canAuthenticate()` is not merely another way to check the same thing — it has a specific reason for existing: **some device manufacturers restrict or modify the behavior of `KeyguardManager`** beyond the standard AOSP specification (the well-known Android ecosystem fragmentation). Relying on only one API risks producing incorrect results on devices from certain vendors. A robust application ideally has **fallback logic** that attempts both pathways.

### 1.6 Note on MASTG-KNOW-0001

The official frontmatter of this test references `knowledge: [MASTG-KNOW-0001]`, but a direct lookup of that ID under the usual category path (`MASVS-STORAGE`, following the numbering pattern of most early `MASTG-KNOW-00xx` documents that fall under the Storage category) returns no result. The document whose title is most substantively relevant (**"Biometric Authentication"**) is instead found under the **MASVS-AUTH** category. This is consistent with the recurring pattern of metadata reference inconsistencies found repeatedly throughout this series of research documents (see also notes on MASTG-TEST-0226, MASTG-TEST-0245) — possibly indicating that the MASTG-KNOW numbering/categorization scheme is undergoing migration or is not yet fully consistent across all cross-document links.

---

## 2. Tools Used for Testing

### 2.1 Required Tools (Core)

| Tool | Function |
|---|---|
| **jadx** | DEX → Java decompilation for searching `KeyguardManager`/`BiometricManager` patterns |
| **grep / ripgrep** | API pattern searches — supplementing the narrow coverage of the official rule |
| **semgrep** | Running the official rule as a baseline |

### 2.2 Alternative & Supporting Tools

| Tool | Function |
|---|---|
| **CodeQL** | Tracing whether the results of `isDeviceSecure()`/`canAuthenticate()` are actually used to condition access to a cryptographic key (`setUserAuthenticationRequired`), rather than merely being called with no real effect on the security flow |
| **MobSF** | Sometimes flags `KeyguardManager` usage in Code Analysis reports |
| **Frida** | Hooking `KeyguardManager.isDeviceSecure()`/`isKeyguardSecure()` and `BiometricManager.canAuthenticate()` for runtime confirmation — including forcing a fake return value (`false`) to test how the application reacts to a device that does **not** have a secure lock (edge-case behavior testing) |
| **Android emulator without a lock screen** | The most direct dynamic test environment — run the application on an emulator/test device deliberately left without a PIN/pattern/password to observe the application's actual behavior |

### 2.3 Environment Prerequisites

- **No device/root required** for the core static analysis.
- **For dynamic testing**, prepare an emulator/physical device with varying lock screen conditions (secure vs. insecure/no lock) to directly observe differences in application behavior.
- **Also check whether the application uses `setUserAuthenticationRequired`** on its `KeyGenParameterSpec` (refer to the related cryptography documents in this series) — this context determines how crucial this test's finding is for a particular application.

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0013** to reverse engineer the application.
2. Use **MASTG-TECH-0014** to search for the relevant APIs.

### 3.2 Method A — Official Semgrep Rule *(exists, but needs extension)*

```yaml
rules:
  - id: mastg-android-device-passcode-present
    languages:
      - java
    severity: INFO
    metadata:
      summary: This rule searches for API that checks whether the device passcode is set.
    message: "[MASVS-STORAGE] Make sure to verify that your app runs on a device with a passcode set"
    pattern-either:
      - pattern: |
          $X.getSystemService("keyguard");
          ...
          $Y.isDeviceSecure();
      - pattern: |
          BiometricManager $BM = (BiometricManager) $X.getSystemService(BiometricManager.class);
          ...
          $BM.canAuthenticate($VAL);
```

```bash
jadx -d ./decompiled ./target-app.apk
semgrep --config https://raw.githubusercontent.com/OWASP/mastg/master/rules/mastg-android-device-passcode-present.yml ./decompiled/sources/
```

**Known coverage gaps:**

1. **`isKeyguardSecure()` is not covered** — the official overview mentions two methods (`isDeviceSecure()` and `isKeyguardSecure()`), but the rule only matches `isDeviceSecure()`. Code that exclusively uses `isKeyguardSecure()` will not be detected by this rule.
2. **The pattern depends on the literal string `"keyguard"`** as the `getSystemService()` argument — code that uses the `Context.KEYGUARD_SERVICE` constant (actually a more common and idiomatically recommended Android pattern) may or may not match depending on how semgrep handles constant resolution in its pattern-matching engine.
3. **`languages: [java]` only** — a recurring pattern found in several other official rules in this series; pure Kotlin code (not the Java-like output of jadx decompilation) risks not matching fully.
4. **Severity `INFO`** — the lowest severity level found among all official MASTG rules examined so far in this research series, indicating that the MASTG team itself views this as an informational signal rather than a definitive finding — consistent with this test's nature as more of a *best practice* than a directly impactful active vulnerability.

### 3.3 Method B — grep/ripgrep to Close the `isKeyguardSecure()` Gap

```bash
D=./decompiled/sources

# Official pattern covered by the rule
rg -n 'isDeviceSecure\(\)' $D

# Pattern NOT covered by the official rule
rg -n 'isKeyguardSecure\(\)' $D

# Variations of getSystemService calls using the constant
rg -n 'getSystemService\(Context\.KEYGUARD_SERVICE\)|getSystemService\("keyguard"\)' $D

# BiometricManager — including via Jetpack androidx.biometric
rg -n 'BiometricManager.*canAuthenticate|androidx\.biometric\.BiometricManager' $D
```

### 3.4 Method C — CodeQL (Assessing the Real Effect of the Check)

```ql
import java

class KeyguardCheck extends MethodAccess {
  KeyguardCheck() {
    this.getMethod().hasName(["isDeviceSecure", "isKeyguardSecure"]) or
    (this.getMethod().hasName("canAuthenticate") and
     this.getMethod().getDeclaringType().hasQualifiedName(["android.hardware.biometrics", "androidx.biometric"], "BiometricManager"))
  }
}

class UserAuthRequiredKeySpec extends MethodAccess {
  UserAuthRequiredKeySpec() {
    this.getMethod().hasName("setUserAuthenticationRequired")
  }
}

from KeyguardCheck check, UserAuthRequiredKeySpec keySpec
where check.getEnclosingCallable() = keySpec.getEnclosingCallable()
select check, "Secure lock check found in the same method as a setUserAuthenticationRequired key configuration — good correlation"
```

This query helps answer a question of greater security value than simply "is the API called": **does the check actually correlate** with the use of a cryptographic key that depends on the lock screen state (§1.3), or does it stand alone with no real influence on the application's security flow.

### 3.5 Method D — Dynamic Testing (Application Behavior on a Device Without a Secure Lock)

```bash
# On the emulator/test device, remove/disable the lock screen entirely
adb shell locksettings clear --old <OLD_PIN>

# Run the application and observe the behavior of features that should require a secure lock
# (e.g., does it still show the "enable feature X" option without a warning?)
```

Frida hook to force a return value (testing the robustness of the application's logic against both conditions):

```javascript
// hook-force-no-secure-lock.js
Java.perform(function () {
    var KeyguardManager = Java.use("android.app.KeyguardManager");
    KeyguardManager.isDeviceSecure.overload().implementation = function () {
        console.log("[*] isDeviceSecure() called — forcing return false for testing");
        return false;
    };
});
```

```bash
frida -U -f com.target.app -l hook-force-no-secure-lock.js --no-pause
```

Observe whether the application reacts as expected (displaying a warning/restricting a feature) when this API is forced to return `false`, versus not reacting at all.

### 3.6 Method Comparison: When to Use Which

| Method | Tool | Coverage | When to use |
|---|---|---|---|
| **A** | Official semgrep rule | Partial (`isDeviceSecure` only) | Quick baseline |
| **B** | Full grep patterns | Full (including `isKeyguardSecure`) | Recommended primary baseline |
| **C** | CodeQL | Assesses correlation with cryptographic key usage | Answering the actual security value of the check |
| **D** | Dynamic testing + Frida | Actual application behavior | Confirming that the static check genuinely affects UX/security |

**Recommended minimum combination:** **B (full grep, not just the official rule) → C (correlation with cryptographic key usage) → D (dynamic behavior confirmation)**.

---

### 3.7 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rule:**

> **Observation:** *"The output should contain a list of locations where relevant APIs are used."*
>
> **Evaluation:** *"The test case fails if an app doesn't use any APIs to verify the presence of a secure screen lock."*

---

#### ❌ FAIL / ISSUE — The check is declared FAILED when:

| No | Condition |
|---|---|
| F1 | **No reference found** to `KeyguardManager.isDeviceSecure()`/`isKeyguardSecure()` nor `BiometricManager#canAuthenticate()` anywhere in the codebase |
| F2 | The application uses a cryptographic key with `setUserAuthenticationRequired(true)` **without** checking the secure lock status beforehand (confirmed via Method C) — risking exposure to the ambiguous system behavior described in §1.3 |
| F3 | Dynamic testing (Method D) shows the application **does not react** (no warning/feature restriction) when the device has no secure lock, even though sensitive features remain accessible |

---

#### ✅ PASS — The check is declared PASSED when:

| No | Condition |
|---|---|
| P1 | A check for `isDeviceSecure()`/`isKeyguardSecure()` or `canAuthenticate()` is found that is used to condition access to a sensitive feature |
| P2 | Correlation (Method C) confirms the check is performed before or adjacent to the use of a `setUserAuthenticationRequired` key |
| P3 | Dynamic testing (Method D) confirms the application displays an appropriate warning/restricts sensitive features when the device has no secure lock |

---

#### ⚠️ Important Notes on Assessment

1. **The official low severity (`INFO`) reflects this test's nature as a *best practice*, not a directly impactful vulnerability** — do not overstate the urgency of this finding compared to active cryptographic weaknesses (e.g., hardcoded keys, broken algorithms) already covered in other documents in this series.

2. **The real value of this test lies in its correlation with `setUserAuthenticationRequired`** (§1.3) — if the application does not use any cryptographic key tied to the lock screen state at all, the absence of an `isDeviceSecure()` check has a far smaller impact than it would for an application that genuinely depends on it (e.g., crypto wallets, banking apps).

3. **Don't forget `isKeyguardSecure()`** — the official rule only covers `isDeviceSecure()`, so additional manual/grep checks (§3.3) are mandatory to avoid missing implementations that use the other API variant.

4. **Remember the officially acknowledged limitation (§1.4)**: the application cannot force the user to enable a lock screen at the system level — PASS/FAIL evaluation focuses on the **application's reaction** to that condition, not on its ability to change system settings.

5. **Severity modulation:**

   | Factor | Severity |
   |---|---|
   | No check exists, **and** the application uses `setUserAuthenticationRequired` for financial/sensitive credential data | **Medium** |
   | No check exists, the application does not use any authentication-based key at all | **Low/Informational** — matches the official rule severity |
   | A check exists but does not correlate with the use of any sensitive key | **Informational** |

6. **Document:** the location of the check code (if any), the specific API used (`isDeviceSecure` vs. `isKeyguardSecure` vs. `canAuthenticate`), the correlation result with `setUserAuthenticationRequired`, and the dynamic test results of the application's behavior on a device without a secure lock.

---

## 4. Recommendations

### 4.1 Implement the Check with Layered Fallback

```kotlin
fun isDeviceSecureLockEnabled(context: Context): Boolean {
    val keyguardManager = context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
    if (keyguardManager.isDeviceSecure) {
        return true
    }
    // Fallback for devices that restrict KeyguardManager (§1.5)
    val biometricManager = BiometricManager.from(context)
    return biometricManager.canAuthenticate(BiometricManager.Authenticators.DEVICE_CREDENTIAL) ==
            BiometricManager.BIOMETRIC_SUCCESS
}
```

### 4.2 Reject/Restrict Sensitive Features When There Is No Secure Lock

```kotlin
if (!isDeviceSecureLockEnabled(context)) {
    showWarningDialog(
        "This feature requires a secure screen lock (PIN/pattern/password) to protect your data. " +
        "Please enable one in Settings > Security."
    )
    return
}
// Proceed with the operation that uses the setUserAuthenticationRequired key
```

### 4.3 Always Correlate with Cryptographic Key Usage

Ensure that every key created with `setUserAuthenticationRequired(true)` is preceded by this check in the same code flow, so that the user receives a clear message instead of encountering a confusing cryptographic operation failure.

### 4.4 Remediation Checklist

- [ ] A check for `isDeviceSecure()`/`isKeyguardSecure()` with a `BiometricManager` fallback has been implemented
- [ ] Features that use a `setUserAuthenticationRequired` key have been correlated with this check
- [ ] The application displays a clear message when the device has no secure lock
- [ ] Dynamic testing on a device without a secure lock has been performed to verify behavior
- [ ] **Re-verify:** rerun MASTG-TEST-0247 after changes related to authentication/cryptography features

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0247: References to APIs for Detecting Secure Screen Lock](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0247/)
- [MASWE-0017: Device Secure Lock Not Enforced](https://mas.owasp.org/MASWE/MASVS-CRYPTO/MASWE-0017/)
- [MASTG-KNOW: Biometric Authentication (MASVS-AUTH)](https://mas.owasp.org/MASTG/knowledge/android/MASVS-AUTH/MASTG-KNOW-0001/)
- [MASTG-TECH-0013: Reverse Engineering Android Apps](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/)
- [MASTG-TECH-0014: Static Analysis on Android](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/)
- [Official rule: mastg-android-device-passcode-present.yml (GitHub)](https://github.com/OWASP/mastg/blob/master/rules/mastg-android-device-passcode-present.yml)

### 5.2 Official Android Documentation

- [Android Developers — `KeyguardManager` API reference](https://developer.android.com/reference/android/app/KeyguardManager)
- [Android Developers — `KeyguardManager.isDeviceSecure()`](https://developer.android.com/reference/android/app/KeyguardManager#isDeviceSecure())
- [Android Developers — `BiometricManager#canAuthenticate(int)`](https://developer.android.com/reference/android/hardware/biometrics/BiometricManager#canAuthenticate(int))
- [Android Developers — `BiometricPrompt`](https://developer.android.com/reference/android/hardware/biometrics/BiometricPrompt)
- [Android Compatibility Definition Document — Keys and Credentials](https://android.googlesource.com/platform/compatibility/cdd/+/refs/heads/o-mr1-iot-preview-6/9_security-model/9_11_keys-and-credentials.md)
- [Google Support — Set a screen lock on your Android device](https://support.google.com/android/answer/9079129)

### 5.3 Research and Real-World Cases

- [GitHub dashpay/platform#4643 — Keep Keystore's unlocked-device gate from bricking wallets and signing on defective OEM builds](https://github.com/dashpay/platform/pull/4643)
- [Debug Labs — Secure Android App Development Part 1](https://chaitanyaduse.medium.com/secure-android-app-development-part-1-38f9b1b5a902)
- [OSV — ASB-A-407562568 (Keyguard/lockscreen bypass advisory)](https://osv.dev/vulnerability/ASB-A-407562568)
- [CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)
- [CWE-862: Missing Authorization](https://cwe.mitre.org/data/definitions/862.html)

### 5.4 Tool Documentation

- [Semgrep — Documentation](https://semgrep.dev/docs/)
- [CodeQL — Documentation](https://codeql.github.com/docs/)
- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [Frida — Dynamic instrumentation toolkit](https://frida.re/docs/javascript-api/)
- [MobSF — Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)

---

*This document was compiled based on OWASP MASTG (latest release as of September 2026), official Android Developers documentation (including the Android CDD), and real-world cases from open-source crypto wallet security projects. The most striking metadata finding in this research: the same test is referenced with three different MASVS categories by four official sources (file location: RESILIENCE, weakness: CRYPTO, rule message: STORAGE) — recorded as-is since it may affect how findings are grouped in audit reporting.*
