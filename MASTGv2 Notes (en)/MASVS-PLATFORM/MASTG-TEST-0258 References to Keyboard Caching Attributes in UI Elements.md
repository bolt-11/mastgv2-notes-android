# MASTG-TEST-0258 References to Keyboard Caching Attributes in UI Elements

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0258 |
| **Platform** | Android |
| **MASVS Category** | MASVS-PLATFORM (per the official file location and MASWE-0036) |
| **Weakness** | MASWE-0036 — *Unnecessary Exposure of Sensitive Data via the User Interface* |
| **Test Type** | Static, Code |
| **Profile** | **L2 only** |
| **Knowledge** | MASTG-KNOW-0055 (Keyboard Cache) — **note: this knowledge document itself is categorized under `masvs_category: MASVS-STORAGE`**, and the official semgrep rule's message also labels it `[MASVS-STORAGE]` — a cross-category attribution pattern that is internally consistent between the KNOW doc and the rule, yet differs from the test's own official category (MASVS-PLATFORM) |
| **Best Practice** | MASTG-BEST-0019 (Use Non-Caching Input Types for Sensitive Fields) |
| **Related Techniques** | MASTG-TECH-0013, MASTG-TECH-0014, MASTG-TECH-0007 (Extract Layout Files) |
| **Related Demo** | — (none) |
| **Official Rule** | `mastg-android-keyboard-cache-input-types.yml` — only detects calls to `setInputType()`, **does not cover XML attributes nor Jetpack Compose** (see §3.2) |
| **Related CWE** | CWE-200 (Exposure of Sensitive Information), CWE-524 (Use of Cache Containing Sensitive Information) |

---

## 1. Explanation

### 1.1 Testing Objective

Quote from the official MASTG overview:

> *"This test verifies that the app appropriately configures text input fields to prevent the keyboard from caching sensitive information, such as passwords or personal data."*

This test targets an interaction layer that is **often forgotten** in mobile security audits: **the behavior of the software keyboard (IME — Input Method Editor)**, rather than the application's own code. Even if the app correctly encrypts data at rest (passing other MASVS-CRYPTO/STORAGE tests in this research series), sensitive data **typed by the user** can still leak through a mechanism entirely outside the app code's direct control: the keyboard's **prediction/auto-suggestion cache**.

### 1.2 Three Ways to Configure Input Type, One Goal

The official overview lays out three different technical paths to achieve the same goal — configuring a field's `inputType` so the keyboard does not cache it:

1. **XML Layout** — the `android:inputType` attribute on an `<EditText>` element.
2. **Programmatic code (traditional View System)** — calling `setInputType()` with `InputType.*` constants.
3. **Jetpack Compose** — the `keyboardType` and `autoCorrect` parameters on the `KeyboardOptions` constructor.

The crucial point from MASTG-KNOW-0055 that explains the relationship between the three: **Jetpack Compose internally still maps to the same `inputType`** — `KeyboardType.Password` is ultimately translated into `InputType.TYPE_CLASS_TEXT or EditorInfo.TYPE_TEXT_VARIATION_PASSWORD` at the implementation level. This means **all three paths are fundamentally the same mechanism** viewed from three different surface APIs — however, for the tester, this means **three distinct patterns that must be searched for separately**, because their textual representation in code/resources is very different from one another.

### 1.3 Official List of Non-Caching Input Types

MASTG-KNOW-0055 provides a definitive table of input types that **officially disable** keyboard suggestions and caching:

| `android:inputType` (XML) | `InputType` constant (code) | Minimum API level |
|---|---|---|
| `textNoSuggestions` | `TYPE_TEXT_FLAG_NO_SUGGESTIONS` | 3 |
| `textPassword` | `TYPE_TEXT_VARIATION_PASSWORD` | 3 |
| `textVisiblePassword` | `TYPE_TEXT_VARIATION_VISIBLE_PASSWORD` | 3 |
| `numberPassword` | `TYPE_NUMBER_VARIATION_PASSWORD` | 11 |
| `textWebPassword` | `TYPE_TEXT_VARIATION_WEB_PASSWORD` | 11 |

An important note about `minSdkVersion` from the official overview (consistent with the `minSdkVersion` nuance already discussed in depth in the MASTG-TEST-0245/0252 documents in this research series):

> *"In the MASTG tests we won't be checking the minimum required SDK version... because we are considering testing modern apps. If you are testing an older app, you should check it. For example, Android API level 11 is required for `textWebPassword`. Otherwise, the compiled app would not honor the used input type constants allowing keyboard caching."*

This is an explicit methodological exception from MASTG itself — unlike other tests in this research series that strictly require checking `minSdkVersion` (e.g., MASTG-TEST-0252), this test **by default assumes** a modern application (API ≥11 is not a practical concern in 2026). However, the overview still **explicitly warns** testers handling legacy applications to still verify `minSdkVersion` — especially for `numberPassword`/`textWebPassword`, which require API 11.

### 1.4 The Bitwise Nature of `inputType` — A Subtle Source of Misconfiguration

A technical point that often slips past a quick review: the `inputType` attribute is not a single enum value, but rather a **bitwise combination** of flags and classes:

> *"The `inputType` attribute is a bitwise combination of flags and classes... The flags are defined as `TYPE_TEXT_FLAG_*` and the classes are defined as `TYPE_CLASS_*`."*

The practical consequence: a field could appear "safe" because it includes the `TYPE_TEXT_FLAG_NO_SUGGESTIONS` flag, but if its **base class** is wrong or combined with another conflicting flag, the final behavior may not match expectations. Example of the correct pattern from MASTG-KNOW-0055 for a numeric PIN:

```kotlin
inputType = InputType.TYPE_CLASS_NUMBER or InputType.TYPE_NUMBER_VARIATION_PASSWORD
```

The tester needs to check the **full combination** of OR'd flags, not just search for one specific constant in isolation — an overly narrow search pattern (e.g., only looking for the string `"textPassword"`) risks missing a valid bitwise combination written in a different order/combination of constants.

### 1.5 Why Keyboard Caching Is Dangerous: Evidence from Real-World Incidents

Unlike most other tests in this series whose risk is theoretical/contextual, the risk of keyboard caching has very concrete **large-scale real-world incident precedent**:

- **The Ai.Type case (2017)**: this popular third-party keyboard app collected and stored **text typed by users** — including phone numbers, sensitive information, search terms, email addresses, and **passwords** — on a server that was **not password-protected at all**, resulting in a leak of **577GB of data** from approximately **31 million users**.
- **Citizen Lab research**: analyzed Pinyin keyboard apps (China market) and found that **8 of the 9** apps examined had vulnerabilities that allowed **full disclosure of keystroke content** to a passive network eavesdropper — due to weak homegrown encryption on keyboard data transmission.
- **Academic research on cross-app KeyEvent injection**: identified a vulnerability in Android's `KeyEvent` processing framework that allows an attacker to **harvest entries from the user's personal dictionary** — a personal prediction dictionary built from the user's typing habits — via an apparently harmless app with common permissions.
- **Even popular official keyboards** (Google Gboard, Microsoft SwiftKey) routinely send telemetry data about **every word typed**, including word length, precise input timing, and the context of the app in which typing occurred — while this serves a legitimate purpose (improving prediction), it underscores that **data typed in a field without appropriate `inputType` protection can potentially leave a trail outside the app's control**, regardless of the good or bad intentions of whichever keyboard is used.

These cases underscore why this test matters: **an app has no control over which software keyboard the user has installed** — Android users are free to install any third-party keyboard, including ones that behave like the Ai.Type case above. The only defense layer **fully within the app developer's control** is ensuring sensitive fields are configured with an `inputType` that explicitly tells the **system** (not a specific keyboard) to disable suggestions/caching at that level.

### 1.6 Additional Benefit: Protection from System Snapshots/Recordings

MASTG-BEST-0019 provides an additional note that broadens the reason this practice matters, beyond just the IME cache issue:

> *"Using non-caching input types helps protect sensitive data from being exposed in system-generated snapshots and recordings."*

This connects to the fact that the **word suggestion strip** (suggestion bar) displayed by most software keyboards is part of the **screen display** that can also be captured in automatic system screenshots (e.g., when the app goes to the background and Android takes a thumbnail for the App Switcher) or screen recording. Disabling suggestions via `textNoSuggestions`/`textPassword` indirectly also **removes potentially sensitive content that could appear in that suggestion strip** from the reach of system snapshot/recording mechanisms — complementing (not replacing) the `FLAG_SECURE` protection discussed in other MASVS-STORAGE screenshot-related tests in the MASTG series.

---

## 2. Tools Used for Testing

### 2.1 Required Tools (Core)

| Tool | Function |
|---|---|
| **apktool** | Extracting raw layout XML (MASTG-TECH-0007) — important because `android:inputType` in layouts is most accurately read from the original XML, not from decompiled Java output |
| **jadx** | Decompiles code for searching `setInputType()` and `KeyboardOptions` |
| **grep / ripgrep** | Searches for all three configuration path patterns (§1.2) |
| **semgrep** | Runs the official rule as a partial baseline |

### 2.2 Alternative & Supporting Tools

| Tool | Function |
|---|---|
| **CodeQL** | Programmatically traces bitwise `InputType` flag combinations (§1.4), and correlates input fields with variable names/hints indicating sensitivity (e.g., `password`, `pin`, `ssn`) |
| **MobSF** | Sometimes flags improperly configured password fields in its Manifest/Layout Analysis report |
| **Frida** | Hooks `EditText.setInputType()` at runtime to capture the value actually applied, including dynamically built ones |
| **Accessibility Scanner (Google)** | Google's official accessibility tool, which can **indirectly** help identify input fields and their properties via UI tree inspection — an additional blackbox approach outside MASTG's official scope |

### 2.3 Environment Prerequisites

- **No device/root required** for the core static analysis.
- **Identify fields handling sensitive data first** (password, PIN, card number, SSN/national ID, etc.) as priority targets — not every `<EditText>`/`TextField` needs to be checked with equal weight.
- **For Jetpack Compose applications**, ensure the decompilation tooling can handle Kotlin code well, since `KeyboardOptions` syntax differs quite a bit from the traditional `EditText` pattern.

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0013** to reverse engineer the application.
2. Use **MASTG-TECH-0014** to search for relevant APIs.
3. Use **MASTG-TECH-0007** to extract the layout files from the app package.

### 3.2 Method A — Official Semgrep Rule *(exists, but only covers 1 of 3 paths)*

```yaml
rules:
  - id: mastg-android-non-caching-input-types
    severity: WARNING
    languages: [java]
    metadata:
      summary: This rule scans all usages of setInputType().
    message: "[MASVS-STORAGE] Set input type detected ($OBJ) with $ARG"
    patterns:
      - pattern: $OBJ.setInputType($ARG)
```

```bash
semgrep --config https://raw.githubusercontent.com/OWASP/mastg/master/rules/mastg-android-keyboard-cache-input-types.yml ./decompiled/sources/
```

**A significant coverage gap**: this rule **only** covers the second of the three official paths (§1.2) — the programmatic `setInputType()` call. It **completely does not cover**:
1. **The XML attribute `android:inputType`** in layouts — which is actually the **most common** path developers use for static fields such as login forms.
2. **Jetpack Compose `KeyboardOptions`** — increasingly common in modern apps, and whose syntax is completely different from the `setInputType()` pattern.

This means the official rule can potentially miss the **majority** of real-world cases if a developer uses the XML or Compose pattern (which Google actually recommends as the modern approach) — Method B below must close both of these gaps.

### 3.3 Method B — grep/ripgrep for All Three Paths at Once

```bash
# Extract raw layout XML
apktool d -s -f -o ./apktool_out target-app.apk
jadx -d ./decompiled target-app.apk

# 1. XML Layout — android:inputType
rg -n 'android:inputType="[^"]*"' ./apktool_out/res/layout/

# 2. Programmatic code — setInputType() (same as the official rule, but grep is more flexible)
rg -n '\.setInputType\(' ./decompiled/sources/

# 3. Jetpack Compose — KeyboardOptions
rg -n 'KeyboardOptions\(' ./decompiled/sources/ -A5 | grep -i "keyboardType\|autoCorrect"

# Look for fields that are LIKELY sensitive but do NOT use a non-caching input type
rg -n -B3 '<EditText' ./apktool_out/res/layout/ | grep -i "password\|pin\|ssn\|card\|cvv" -A3 | grep -v "textPassword\|textNoSuggestions\|numberPassword\|textWebPassword\|textVisiblePassword"
```

### 3.4 Method C — CodeQL (Verifying the Bitwise Combination + Sensitivity Correlation)

```ql
import java

class SensitiveFieldDeclaration extends VarAccess {
  SensitiveFieldDeclaration() {
    this.getVariable().getName().toLowerCase().regexpMatch(".*(password|pin|cvv|ssn|nik|secret).*")
  }
}

class SetInputTypeCall extends MethodAccess {
  SetInputTypeCall() {
    this.getMethod().hasName("setInputType")
  }
}

from SensitiveFieldDeclaration field
where not exists(SetInputTypeCall call |
  call.getQualifier().toString() = field.toString())
select field, "Sensitively-named field found without an explicit setInputType call — check whether it is configured via XML/Compose"
```

This query is specifically useful for triggering cross-verification: if a sensitively-named field is **not** found via `setInputType()`, the tester must investigate further whether that field is configured via XML/Compose (rather than automatically concluding FAIL).

### 3.5 Method D — Frida (Runtime Confirmation)

```javascript
// hook-edittext-inputtype.js
Java.perform(function () {
    var EditText = Java.use("android.widget.EditText");
    EditText.setInputType.overload("int").implementation = function (type) {
        console.log("[*] EditText.setInputType(" + type + ") called");
        // Compare against known non-caching constants
        var NO_SUGGESTIONS = 0x80000; // TYPE_TEXT_FLAG_NO_SUGGESTIONS
        var VARIATION_PASSWORD = 0x80; // TYPE_TEXT_VARIATION_PASSWORD (part of the combination)
        if ((type & NO_SUGGESTIONS) === 0 && (type & VARIATION_PASSWORD) === 0) {
            console.log("    [!] Possibly NOT non-caching — manual verification required");
        }
        return this.setInputType(type);
    };
});
```

### 3.6 Method Comparison: Which One to Use When

| Method | Tool | Configuration path coverage | When to use |
|---|---|---|---|
| **A** | Official semgrep rule | Only `setInputType()` (1 of 3 paths) | Partial baseline only |
| **B** | Thorough grep | All three paths (XML, code, Compose) | **Mandatory primary baseline** |
| **C** | CodeQL | Field-name sensitivity correlation + bitwise verification | Large codebase, reduces manual review |
| **D** | Frida | Actual runtime value, including dynamic ones | Confirms conditionally-built cases |

**Minimum recommended combination:** **B (thorough, covering all three paths) → C (field-name sensitivity correlation)**, with Method A used only as an additional reference since its coverage is very limited relative to what this test actually requires.

---

### 3.7 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rule:**

> **Observation:** *"The output should include: All `android:inputType` XML attributes... All calls to the `setInputType` method and the input type values passed to it."*
>
> **Evaluation:** *"The test case fails if there are any fields handling sensitive data for which the app does not use non-caching input types."*

---

#### ❌ FAIL / ISSUE — The check is declared FAILED when:

| No | Condition |
|---|---|
| F1 | A field handling a password/PIN/other sensitive data uses an ordinary `android:inputType` (`text`, `textCapWords`, etc.) without a non-caching flag/variation |
| F2 | A sensitive field in Jetpack Compose uses the ordinary `KeyboardType.Text` with `autoCorrect = true` (default), instead of `KeyboardType.Password` |
| F3 | The bitwise `InputType` combination used **appears** to include a non-caching flag but actually has a wrong combination/base class, making it ineffective (confirmed via Method C/D) |
| F4 | A sensitive field has **no** explicit `inputType` setting at all (inheriting the ordinary `text` default) |

**Example evidence (illustrative — MASTG does not yet provide an official demo for this test):**

```xml
<!-- res/layout/activity_login.xml -->
<EditText
    android:id="@+id/password"
    android:hint="Password"
    android:inputType="text" />   <!-- WRONG: password field but ordinary inputType -->
```

```bash
$ rg -n 'android:inputType="[^"]*"' ./apktool_out/res/layout/activity_login.xml
android:inputType="text"
```

Interpretation: a field with `id="password"` and hint "Password" uses the ordinary `inputType="text"` — the keyboard will show word suggestions and can cache this input. **FAIL** — it should use `textPassword` instead.

---

#### ✅ PASS — The check is declared PASSED when:

| No | Condition |
|---|---|
| P1 | All sensitive fields use one of the five official non-caching input types (§1.3) |
| P2 | Sensitive Jetpack Compose fields use `KeyboardType.Password`/`NumberPassword` with `autoCorrect = false` |
| P3 | The bitwise combination is verified to be functionally correct (confirmed via Method C/D) |
| P4 | For apps with `minSdkVersion` below API 11 that use `numberPassword`/`textWebPassword`, it has been verified that this API remains honored at the declared `minSdkVersion` (§1.3) |

---

#### ⚠️ Important Notes on the Assessment

1. **The official rule only covers about a third of the real scope** — do not rely on an empty result from Method A as proof of PASS; always run a thorough search (Method B) covering XML and Jetpack Compose.

2. **Check the bitwise combination as a whole, not by searching for a substring** — per §1.4, a field could use a valid combination of constants written in a different order than a simple search pattern expects.

3. **Prioritize based on data sensitivity, not the number of fields.** A search field or public comment field using an ordinary `inputType` is not a finding; focus on passwords, PINs, payment cards, and identity data.

4. **Use the real-world incident precedent (§1.5) to communicate urgency to the development team** — this risk is not hypothetical; it has been proven real at a scale of millions of users (the Ai.Type case).

5. **Remember the dual benefit of non-caching input types** (§1.6) — besides preventing IME caching, it also reduces the risk of leakage via system snapshots/recordings, making this finding cross-relevant to other `FLAG_SECURE`/screenshot protection tests in the MASTG series.

6. **Severity is modulated as follows:**

   | Factor | Severity |
   |---|---|
   | The app's primary password/PIN field without a non-caching input type | **High** |
   | Secondary sensitive data field (e.g., security answer, address) without a non-caching input type | **Medium** |
   | Non-sensitive field without a non-caching input type | **Not a finding** |

7. **Document:** the field's location (layout XML/code/Compose), the `inputType`/`KeyboardType` value used, the data sensitivity classification of that field, and the result of the bitwise combination verification where relevant.

---

## 4. Recommendations

### 4.1 XML Layout

```xml
<EditText
    android:id="@+id/password"
    android:hint="Password"
    android:inputType="textPassword" />
```

### 4.2 Programmatic Code (View System)

```kotlin
val pinInput = EditText(context).apply {
    hint = "Enter PIN"
    inputType = InputType.TYPE_CLASS_NUMBER or InputType.TYPE_NUMBER_VARIATION_PASSWORD
}
```

### 4.3 Jetpack Compose

```kotlin
OutlinedTextField(
    value = password,
    onValueChange = { password = it },
    label = { Text("Password") },
    visualTransformation = PasswordVisualTransformation(),
    keyboardOptions = KeyboardOptions(
        keyboardType = KeyboardType.Password,
        autoCorrect = false
    )
)
```

### 4.4 Integrate into CI/CD

```bash
#!/bin/bash
# ci-check-keyboard-caching.sh
apktool d -s -f -o /tmp/layout_check "$1"
grep -rn 'password\|pin\|cvv' /tmp/layout_check/res/layout/ | grep -v 'inputType="text[NP]assword\|numberPassword\|textVisiblePassword\|textWebPassword\|textNoSuggestions'
```

### 4.5 Remediation Checklist

- [ ] All password/PIN/sensitive data fields have been identified across all three paths (XML, code, Compose)
- [ ] Every sensitive field uses one of the five official non-caching input types
- [ ] The bitwise combination has been verified to be functionally correct (not just textually correct)
- [ ] `minSdkVersion` has been verified for `numberPassword`/`textWebPassword` compatibility if handling a legacy application
- [ ] **Re-verify:** re-run MASTG-TEST-0258 whenever a new input form is added

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0258: References to Keyboard Caching Attributes in UI Elements](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0258/)
- [MASWE-0036: Unnecessary Exposure of Sensitive Data via the User Interface](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0036/)
- [MASTG-KNOW-0055: Keyboard Cache](https://mas.owasp.org/MASTG/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0055/)
- [MASTG-BEST-0019: Use Non-Caching Input Types for Sensitive Fields](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0019/)
- [MASTG-TECH-0007: Extract Layout Files](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0007/)
- [Official rule: mastg-android-keyboard-cache-input-types.yml (GitHub)](https://github.com/OWASP/mastg/blob/master/rules/mastg-android-keyboard-cache-input-types.yml)

### 5.2 Official Android Documentation

- [Android Developers — `TextView` `android:inputType` reference](https://developer.android.com/reference/android/widget/TextView#attr_android:inputType)
- [Android Developers — `InputType` class reference](https://developer.android.com/reference/android/text/InputType)
- [Android Developers — Jetpack Compose `KeyboardOptions`](https://developer.android.com/reference/kotlin/androidx/compose/foundation/text/KeyboardOptions)
- [Android Source — `InputType.java`](https://cs.android.com/android/platform/superproject/main/+/main:frameworks/base/core/java/android/text/InputType.java)

### 5.3 Research and Real-World Cases

- [Gearbrain — Android Keyboard App (Ai.Type) Spills Personal Data of 31M Users](https://www.gearbrain.com/aitype-android-keyboard-data-leak-2515327775.html)
- [Citizen Lab — The Not-So-Silent Type: Vulnerabilities Across Keyboard Apps](https://citizenlab.ca/research/vulnerabilities-across-keyboard-apps-reveal-keystrokes-to-network-eavesdroppers/)
- [ResearchGate — Keyboard or Keylogger? A Security Analysis of Third-Party Keyboards on Android](https://www.researchgate.net/publication/308820014_Keyboard_or_keylogger_A_security_analysis_of_third-party_keyboards_on_Android)
- [Kaspersky — Is It Possible to Spy on Keystrokes from an Android On-Screen Keyboard?](https://www.kaspersky.com/blog/prevent-android-keylogging-and-ime-spying/51281/)
- [Zeltser — Security of Third-Party Keyboard Apps on Mobile Devices](https://zeltser.com/third-party-keyboards-security)
- [IEEE S&P 2020 Poster — Android IME Privacy Leakage Analyzer](https://www.ieee-security.org/TC/SP2020/poster-abstracts/hotcrp_sp20posters-final12.pdf)
- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
- [CWE-524: Use of Cache Containing Sensitive Information](https://cwe.mitre.org/data/definitions/524.html)

### 5.4 Tool Documentation

- [apktool](https://apktool.org/)
- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [Semgrep — Documentation](https://semgrep.dev/docs/)
- [CodeQL — Documentation](https://codeql.github.com/docs/)
- [Frida — Dynamic instrumentation toolkit](https://frida.re/docs/javascript-api/)
- [Accessibility Scanner (Google Play)](https://play.google.com/store/apps/details?id=com.google.android.apps.accessibility.auditor)

---

*This document was prepared based on OWASP MASTG (current release as of September 2026), official Android Developers documentation, and real-world research and incidents (the Ai.Type case, Citizen Lab research) on the security risks of third-party keyboard applications. The most important nuance: the official semgrep rule only covers one of the three configuration paths (`setInputType()`), missing XML layouts and Jetpack Compose, which are actually the most common patterns used by developers — a thorough manual/grep check across all three paths is mandatory for a truly complete evaluation.*
