# MASTG-TEST-0316 App Exposing User Authentication Data in Text Input Fields

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0316 |
| **Platform** | Android |
| **MASVS Category** | MASVS-PLATFORM |
| **Weakness** | **MASWE-0036** (Unnecessary Exposure of Sensitive Data via the User Interface) **AND** **MASWE-0040** (Sensitive Data Leaked via Accessibility Services) — the mapping to two weaknesses is key to understanding this test, see §1.3 |
| **Test Type** | Static, Code, **Manual** |
| **Related Techniques** | MASTG-TECH-0013, MASTG-TECH-0014, MASTG-TECH-0023 (further validation required) |
| **Related Demo** | — (none) |
| **Official Rule** | `mastg-android-input-field-usage.yml` — **a rule technically designed to match decompiled/mangled Jetpack Compose bytecode**, not plain Kotlin source code (see §3.2, an interesting technical finding) |
| **Related CWE** | CWE-200, CWE-549 (Missing Password Field Masking) |

---

## 1. Explanation

### 1.1 Testing Objective: Visual Masking, Not Just Keyboard Caching

Official MASTG overview excerpt:

> *"This test verifies that the app handles user input correctly, ensuring that access codes (passwords or pins) and verification codes (OTPs) are not exposed in plain text within text input fields. Proper masking (e.g., dots instead of input characters) of these codes is essential to protect user privacy."*

It is important to distinguish this test from **MASTG-TEST-0258** (References to Keyboard Caching Attributes), already discussed in depth in this research series — both use an **overlapping** configuration mechanism (`android:inputType="textPassword"`), but **their evaluation objectives differ**:

| | MASTG-TEST-0258 | MASTG-TEST-0316 *(this document)* |
|---|---|---|
| **Focus** | Preventing the **keyboard IME** from caching/suggesting words from sensitive input | Preventing the **visual display** from showing the actual characters typed (e.g., displaying as `••••` instead of `1234`) |
| **Risk prevented** | Leakage via keyboard prediction dictionaries, system snapshots | Leakage via direct visual **shoulder surfing**, screen recording, screenshots |

The two tests complement each other — a field that is correctly configured via `inputType` to prevent caching **does not necessarily** automatically mask its visual display correctly in all UI frameworks (especially Jetpack Compose, discussed in §1.2), so both are worth testing separately.

### 1.2 Masking Mechanism Across Two UI Worlds: XML View vs Jetpack Compose

**In the traditional XML View system**, masking is fairly simple — the `android:inputType="textPassword"` attribute automatically displays characters as dots:

```xml
<EditText android:inputType="textPassword" />
```

**In Jetpack Compose**, the mechanism is more granular, via `SecureTextField` and the `TextObfuscationMode` parameter:

```kotlin
SecureTextField(
    textObfuscationMode = TextObfuscationMode.RevealLastTyped,  // default
    // or TextObfuscationMode.Hidden
)
```

There are **three** `TextObfuscationMode` values relevant for evaluation:

| Value | Behavior | Security Status |
|---|---|---|
| **`RevealLastTyped`** (default) | The last character typed is **briefly visible** before turning into a dot, previous characters are masked | Considered **sufficiently secure** by the official overview — this is the built-in default |
| **`Hidden`** | All characters are **always** masked, with no brief reveal at all | **Most secure** |
| **`Visible`** | All characters are shown **entirely without masking** | **Not secure** — this is the main FAIL condition for this test |

### 1.3 Why Two Weaknesses at Once (MASWE-0036 and MASWE-0040): Visual Masking ≠ Full Protection from Accessibility Services

This is the **most important conceptual finding** of this document, and explains why this test is mapped to **two** different weaknesses simultaneously — a pattern rarely found in other tests in this research series. Visual masking (showing dots instead of actual characters) **resolves** the MASWE-0036 risk (exposure via UI that is visible to the eye/screenshot/screen recording) — but **does not automatically resolve** the MASWE-0040 risk (leakage via an **Accessibility Service**).

An **Accessibility Service** is an official Android API designed to help users with disabilities (screen readers, etc.) by **programmatically reading screen content**, including the content of `EditText`/`TextField` nodes. Mobile security research extensively documents the **abuse** of this capability by real-world malware:

> *"Accessibility services can read the text content of any application displayed on screen — including banking apps... This enables credential harvesting without a network proxy or overlay: the malware simply reads credentials from the screen as the user types them."*

Real malware families that specifically leverage this technique have been widely documented in security research: **FluBot**, **RatHat**, and **Manic Trojan** — all of them use Accessibility Services as a **keylogger** that reads changes to an input field in real time, **regardless of how that field is displayed visually** to the user. This is the root of why MASWE-0040 is relevant here: **visual masking (dots) is a defense against the human eye and visual capture**, but **not a defense against an API that reads the UI's data structure programmatically** — two different threat layers requiring different mitigations (e.g., ensuring sensitive fields have the correct flag so that the actual value is not exposed to the accessibility tree, not merely relying on the dotted display alone).

### 1.4 The Most Crucial Official Warning: Secure Mode Can Be Changed Dynamically

The official overview includes a note that **explicitly** anticipates the failure of pure static analysis:

> *"Even if `SecureTextField` uses the default `TextObfuscationMode.RevealLastTyped` or is configured explicitly with `RevealLastTyped` or `Hidden`, **it can later be changed to `Visible` programmatically**."*

This means the **initial configuration that appears secure** at the component's declaration point **does not guarantee** that field will **remain** secure throughout its lifecycle — code elsewhere (e.g., a "show password" feature commonly found in login forms) could **change** `textObfuscationMode` to `Visible` dynamically based on a certain state (an eye-icon toggle, etc.). Static analysis that **only checks the component's initial declaration point** risks missing mode-changing logic that occurs elsewhere in the codebase — demanding a **thorough** search of all references to the `SecureTextField` instance/related `textObfuscationMode` state, not just its declaration point.

### 1.5 Explicitly Acknowledged Limitation: False Negatives on Custom UI

This is one of the few cases in this research series where **MASTG itself proactively acknowledges a limitation** of its methodology in a separate clause called **"Expected False Negatives"**:

> *"This test may produce false negatives if the app uses custom text input controls that do not rely on standard classes such as `TextField` or `SecureTextField` (for example in custom UI frameworks or game engines)."*

This is an honest acknowledgment that an application that builds **custom text input components from scratch** (commonly found in game-engine-based apps such as Unity, or custom UI rendering frameworks) **will not be caught at all** by standard detection methodology based on searching for the `TextField`/`SecureTextField`/`EditText` classes — because such components architecturally **do not** inherit/call those standard classes at all. A tester facing such an application needs to **explicitly document this limitation** in the report, rather than readily concluding PASS simply because a standard pattern search found nothing.

---

## 2. Tools Used for Testing

### 2.1 Required Tools (Core)

| Tool | Function |
|---|---|
| **jadx** | DEX → Java/Kotlin-like decompilation for finding `EditText`/`TextField`/`SecureTextField` patterns |
| **apktool** | Raw layout XML extraction for the `android:inputType` attribute |
| **grep / ripgrep** | API and `TextObfuscationMode` pattern search |
| **semgrep** | Running the official rule (with specific technical caveats, §3.2) |

### 2.2 Alternative & Supporting Tools

| Tool | Function |
|---|---|
| **CodeQL** | Traces **all** references to `SecureTextField` instances/`textObfuscationMode` variables, including value changes beyond the initial declaration point (§1.4) |
| **Accessibility Scanner (Google)** | Google's official tool for inspecting the accessibility tree — can help empirically verify whether a sensitive field's actual value is truly exposed to the accessibility tree (relevant for MASWE-0040, §1.3) |
| **Frida** | Hooking the `SecureTextField`/`TextObfuscationMode` setter to capture mode changes at runtime — complements static analysis for the case in §1.4 |

### 2.3 Environment Prerequisites

- **No device/root required** for core static analysis.
- **Device/emulator required** for verification with Accessibility Scanner or Frida.
- **Manual review (MASTG-TECH-0023) is absolutely required**, consistent with the `manual` tag on this test's type — the official "Further Validation Required" clause explicitly demands this.

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0013** to reverse engineer the application.
2. Use **MASTG-TECH-0014** to find relevant APIs.

### 3.2 Method A — Official Semgrep Rule *(interesting technical finding: designed for mangled Compose bytecode)*

```yaml
rules:
  - id: mastg-android-input-field-usage
    severity: WARNING
    languages: [java]
    metadata:
      summary: This rule looks for TextFields and SecureTextField.
    message: "[MASVS-PLATFORM] Detected TextFields and SecureTextField."
    pattern-either:
      - pattern: androidx.compose.material3.TextFieldKt
      - pattern-regex: SecureTextFieldKt.m\d+SecureTextField\w+\(.+TextObfuscationMode.Companion.m\d+getVisible\w+\(\).+\);
```

**An interesting technical note that is unique to this rule** compared to all other rules analyzed so far in this research series: the second pattern explicitly matches method names such as `m\d+SecureTextField\w+` and `m\d+getVisible\w+` — this naming pattern is an **artifact of the Jetpack Compose compilation process**, not Kotlin source code written by a developer. The Compose compiler plugin performs **method name transformation** (adding numeric suffixes like `$1`, `m1`, etc.) when compiling composable functions to JVM/DEX bytecode — a pattern that only appears after **decompiling the APK**, not in the original source code. This indicates this rule is **specifically designed to be run on decompiled APK output (blackbox)**, not on project source code (whitebox) — different from the common assumption a tester might make that all MASTG semgrep rules can be run uniformly on both kinds of targets.

```bash
jadx -d ./decompiled ./target-app.apk
semgrep --config https://raw.githubusercontent.com/OWASP/mastg/master/rules/mastg-android-input-field-usage.yml ./decompiled/sources/
```

**Practical implication**: if a tester runs this rule on the **original Kotlin source code** (whitebox, pre-compilation), the regex pattern `m\d+SecureTextField\w+` **will never match** because method names have not yet been mangled — this rule **must** be run on decompiled APK output to function as designed.

### 3.3 Method B — grep/ripgrep for XML View and Manual Verification

```bash
D=./decompiled/sources

# XML View — find inputType that is NOT textPassword on a field whose name relates to authentication
rg -n '<EditText' ./decompiled/resources/res/layout/ -A3 | grep -iE "password|pin|otp|cvv" -B3 | grep -v "textPassword"

# Compose — explicitly find TextObfuscationMode.Visible
rg -n 'TextObfuscationMode\.Visible' $D

# Find usage of TextField (not SecureTextField) in a context whose name relates to authentication
rg -n -B5 'TextField\(' $D | grep -iE "password|pin|otp" -B5
```

### 3.4 Method C — CodeQL to Trace Dynamic Mode Changes

```ql
import java

class SecureTextFieldUsage extends MethodAccess {
  SecureTextFieldUsage() {
    this.getMethod().hasName("SecureTextField")
  }
}

class ObfuscationModeChange extends MethodAccess {
  ObfuscationModeChange() {
    this.getMethod().hasName("setValue") and
    this.getAnArgument().toString().matches("%TextObfuscationMode.Visible%")
  }
}

from ObfuscationModeChange change
select change, "Found a dynamic change of textObfuscationMode to Visible — verify the context (legitimate 'show password' feature, or an unintended leak?)"
```

### 3.5 Method D — Accessibility Scanner for MASWE-0040 Verification

```bash
# Install Accessibility Scanner from Google Play on the test device
# Enable via Settings > Accessibility > Accessibility Scanner
```

Run the application on a sensitive field that is being filled in, trigger an Accessibility Scanner check, and verify whether the **actual value** of that field (not the dotted representation) is exposed to the node information captured by the scanner — this is direct empirical verification of the MASWE-0040 risk explained in §1.3.

### 3.6 Method Comparison: When to Use Which

| Method | Tool | Correct target | Detects dynamic changes? | When to Use |
|---|---|---|---|---|
| **A** | Official semgrep rule | **Decompiled APK, not source** | ❌ | Baseline, MUST run on decompiled output |
| **B** | grep | Both | ❌ | Supplementary, manual verification |
| **C** | CodeQL | Source code | ✅ | Catches the case in §1.4 |
| **D** | Accessibility Scanner | N/A (dynamic) | N/A | Empirically verifies MASWE-0040 |

**Minimum combination I recommend:** **A (on decompiled APK) + B → C (dynamic changes) → D (verify MASWE-0040)**, complemented by a manual MASTG-TECH-0023 review of every candidate per the mandatory official clause.

---

### 3.7 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rule:**

> **Evaluation:** *"The test case fails if any text input field used for access or verification codes is found to be unmasked. For example, due to the following: `TextField` is used; `SecureTextField` is used but configured with `TextObfuscationMode.Visible`."*

---

#### ❌ FAIL / ISSUE — The check is declared FAILED if:

| No | Condition |
|---|---|
| F1 | A password/PIN/OTP field uses a plain `TextField` (not `SecureTextField`) in Compose |
| F2 | `SecureTextField` is configured with `TextObfuscationMode.Visible` |
| F3 | The secure mode at initial declaration is detected to be **dynamically changed** to `Visible` without legitimate UX justification (§1.4) |
| F4 | An XML View field uses a plain `android:inputType="text"` for content that is clearly a password/PIN |

**Example evidence (illustrative — MASTG has not yet provided an official demo for this test):**

```kotlin
@Composable
fun PinEntryScreen() {
    var pin by remember { mutableStateOf("") }
    TextField(  // WRONG — should be SecureTextField
        value = pin,
        onValueChange = { pin = it },
        label = { Text("Enter PIN") }
    )
}
```

Interpretation: the field for PIN input uses a plain `TextField` that displays characters as-is with no masking whatsoever — **FAIL**.

---

#### ✅ PASS — The check is declared PASSED if:

| No | Condition |
|---|---|
| P1 | The password/PIN/OTP field uses `SecureTextField` with `RevealLastTyped` (default) or `Hidden` |
| P2 | CodeQL verification confirms there is no dynamic change to `Visible` without explicit and legitimate UX control (e.g., a "show" button controlled by the user themselves) |
| P3 | The XML View uses `android:inputType="textPassword"`/`numberPassword` as appropriate for the context |

---

#### ⚠️ Important Notes on Evaluation

1. **Run the official semgrep rule on the decompiled APK output, not the source code** — per the technical finding in §3.2, its regex pattern specifically targets method names that have been mangled by the Compose compiler.

2. **"Secure mode at declaration" does not guarantee security throughout the component's lifecycle** — always trace all related references for possible dynamic changes to `Visible` (§1.4).

3. **Visual masking does not automatically resolve Accessibility Service risk** — this is the most frequently missed point; consider additional verification with Accessibility Scanner for the completeness of the MASWE-0040 evaluation.

4. **Explicitly document the false negative limitation** for game-engine/custom UI based applications (§1.5) — do not conclude PASS purely from the absence of standard pattern search results.

5. **A user-controlled "show password" button is NOT automatically a FAIL** — this is a common legitimate UX pattern; focus on whether the change to `Visible` occurs **without** explicit user control (e.g., a bug that makes the field always visible without the user requesting it).

6. **Severity is modulated:**

   | Factor | Severity |
   |---|---|
   | PIN/password/OTP field not masked at all from the start | **High** |
   | Secure mode changed to Visible without clear user control | **High** |
   | Legitimate "show password" button with explicit user control | **Not a finding** |

7. **Document:** the field's location, the component type (`TextField`/`SecureTextField`/`EditText`), the configured obfuscation mode, the results of tracing dynamic changes, and the Accessibility Scanner verification results if performed.

---

## 4. Recommendations

### 4.1 Use `SecureTextField` with a Secure Mode

```kotlin
SecureTextField(
    state = pinState,
    textObfuscationMode = TextObfuscationMode.Hidden  // most secure for PIN/OTP
)
```

### 4.2 Control the "Show Password" Toggle Explicitly and Safely

```kotlin
var obfuscationMode by remember { mutableStateOf(TextObfuscationMode.Hidden) }
SecureTextField(
    state = passwordState,
    textObfuscationMode = obfuscationMode
)
IconButton(onClick = {
    obfuscationMode = if (obfuscationMode == TextObfuscationMode.Hidden)
        TextObfuscationMode.Visible else TextObfuscationMode.Hidden
}) { /* eye icon */ }
```

### 4.3 Remediation Checklist

- [ ] All password/PIN/OTP fields use the appropriate `SecureTextField`/`android:inputType="textPassword"`
- [ ] No dynamic change to `Visible` occurs without explicit user control
- [ ] Accessibility Scanner verification is performed for the most sensitive fields
- [ ] False negative limitations for custom UI/game engines are documented where relevant
- [ ] **Re-verify:** re-run MASTG-TEST-0316 on the latest release APK's decompiled output

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0316: App Exposing User Authentication Data in Text Input Fields](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0316/)
- [MASTG-TEST-0258: References to Keyboard Caching Attributes in UI Elements](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0258/)
- [MASWE-0036: Unnecessary Exposure of Sensitive Data via the User Interface](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0036/)
- [MASWE-0040: Sensitive Data Leaked via Accessibility Services](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0040/)
- [Official rule: mastg-android-input-field-usage.yml (GitHub)](https://github.com/OWASP/mastg/blob/master/rules/mastg-android-input-field-usage.yml)

### 5.2 Official Android Documentation

- [Android Developers — `SecureTextField` source (androidx)](https://cs.android.com/androidx/platform/frameworks/support/+/androidx-main:compose/material/material/src/commonMain/kotlin/androidx/compose/material/SecureTextField.kt)
- [Android Developers — Accessibility Scanner](https://play.google.com/store/apps/details?id=com.google.android.apps.accessibility.auditor)

### 5.3 Research and Real-World Cases

- [SRLabs — FluBot Abuses Accessibility Features to Steal Data](https://srlabs.de/blog/flubot-abuses-accessibility-features-to-steal-data)
- [Security Affairs — RatHat Turns Android Accessibility Into an Attack Weapon](https://securityaffairs.com/199317/malware/rathat-turns-android-accessibility-into-an-attack-weapon.html)
- [Kaspersky — Manic Trojan: Android Malware Steals Banking Credentials](https://me-en.kaspersky.com/blog/manic-android-trojan/26036/)
- [FAU CS1 — How Android's UI Security is Undermined by Accessibility](https://www.cs1.tf.fau.de/research/system-security-group/how-androids-ui-security-is-undermined-by-accessibility/)
- [CWE-549: Missing Password Field Masking](https://cwe.mitre.org/data/definitions/549.html)
- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)

### 5.4 Tool Documentation

- [Semgrep — Documentation](https://semgrep.dev/docs/)
- [CodeQL — Documentation](https://codeql.github.com/docs/)
- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [Frida — Dynamic instrumentation toolkit](https://frida.re/docs/javascript-api/)

---

*This document is compiled based on OWASP MASTG (current release as of September 2026), official Android/Jetpack Compose documentation, and mobile security research on the abuse of Accessibility Services by real-world malware (FluBot, RatHat, Manic Trojan). The two most important findings: (1) this test is mapped to **two weaknesses at once** (MASWE-0036 and MASWE-0040) because visual masking does not automatically protect against programmatic reading via Accessibility Services — two different threat layers that need different mitigations; and (2) the official semgrep rule is technically designed specifically to run on **decompiled APK bytecode** (method names mangled by the Compose compiler), not the original source code — an implementation detail easily missed if the tester does not carefully inspect the pattern's content.*
