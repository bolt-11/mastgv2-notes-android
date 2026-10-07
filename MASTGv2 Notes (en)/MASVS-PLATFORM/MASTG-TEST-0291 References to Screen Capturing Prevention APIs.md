# MASTG-TEST-0291 References to Screen Capturing Prevention APIs

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0291 |
| **Platform** | Android |
| **MASVS Category** | MASVS-PLATFORM |
| **Weakness** | MASWE-0038 — *Insufficient Protection of Sensitive Data from Screenshots or Screen Recordings* (same as MASTG-TEST-0289) |
| **Highlighted APIs** | `Window.addFlags()`, `Window.setFlags()`, `Window.clearFlags()`, the `WindowManager.LayoutParams.FLAG_SECURE` constant |
| **Test Type** | Static, Code |
| **Knowledge** | MASTG-KNOW-0053 |
| **Best Practice** | MASTG-BEST-0014 (Preventing Screenshots and Screen Recording) |
| **Related Technique** | MASTG-TECH-0013, MASTG-TECH-0014 |
| **Related Tests** | **MASTG-TEST-0289** (Runtime Verification of Sensitive Content Exposure in Screenshots — the dynamic counterpart; that test proves the **real visual outcome**, this test maps the **code locations** that control `FLAG_SECURE`) |
| **Related Demo** | — (none) |
| **Official Rule** | `mastg-android-flag-secure-enable-flags.yml` (ID per content: `mastg-android-flag-secure-enable-flags`) — **only detects enabling the flag**, and does not cover `clearFlags()` at all, which is precisely half of the official FAIL definition (see §3.2) |
| **Related CWE** | CWE-200, CWE-311 |

---

## 1. Explanation

### 1.1 Testing Objective and Its Relationship to MASTG-TEST-0289

Excerpt from the official MASTG overview:

> *"This test verifies whether an app references Android screen capture prevention APIs... Developers typically apply the flag with `addFlags()` or `setFlags()`."*

This test is the **static counterpart** of **MASTG-TEST-0289**, which has already been discussed in depth in this research series. The entire core conceptual context — why Android automatically takes a screenshot when backgrounding, the `FLAG_SECURE` mechanism, and the **timing race condition gap** that makes static auditing alone insufficient — has already been fully explained in that document. This document focuses on the unique value of the static approach: **mapping the consistency of application** of `FLAG_SECURE` across the entire codebase, a question that is inherently easier to answer through comprehensive code analysis than through dynamic testing, which is limited to scenarios the tester actually triggers.

### 1.2 Two Failure Modes Explicitly Named by the Official Overview

This is the most important part of this test's overview — it explicitly names **two distinct failure patterns**, not just one:

> *"Common failure modes include **not setting** `FLAG_SECURE` on all sensitive screens **or clearing the flag** during transitions e.g., using `clearFlags()` or `setFlags()`."*

| Failure Mode | Description | Example |
|---|---|---|
| **1. Inconsistently applied** | `FLAG_SECURE` is applied to **some** sensitive screens, but missed on other screens of equivalent sensitivity | The "Payment Confirmation" screen is protected, but the "Transaction History" screen (displaying equally sensitive data) is not |
| **2. Deliberately removed mid-flow** | Code explicitly calls `clearFlags(FLAG_SECURE)` at some point in the same Activity's lifecycle, disabling protection that was previously active | A developer removes the flag temporarily to display a "Share" dialog that requires a screenshot, but forgets to re-enable it after the dialog is closed |

This second failure mode is particularly interesting because it is a **deliberate regression** — not an oversight of never adding protection in the first place, but rather **the removal of existing protection** for a specific functional need (e.g. enabling a "screenshot to share" feature on a particular part of the screen), which then **risks not being correctly restored** on every code path the user might subsequently take.

### 1.3 Evaluation Criteria That Demand Consistency Analysis, Not Mere Presence

This test's official Evaluation clause is carefully worded to capture both failure modes at once:

> *"The test case fails if the relevant APIs are **missing** or **inconsistently applied** on any UI component that displays sensitive data, or if code paths **clear the protection without an adequate justification**."*

The phrases **"inconsistently applied"** and **"clear the protection without an adequate justification"** confirm that this test demands a **holistic understanding of the entire codebase** — it is not enough for the tester to find one `FLAG_SECURE` call and conclude PASS; they must **map every sensitive screen** (the result of the `identify-sensitive-screens` prerequisite, as in MASTG-TEST-0289) and verify that **each one** has consistent protection throughout its lifecycle, including checking **whether there is adequate justification** for every `clearFlags()` call found.

The phrase "without an adequate justification" implicitly **acknowledges** that there are legitimate scenarios for temporarily removing `FLAG_SECURE` (e.g. a deliberate screenshot-sharing feature for content that is **at that point** no longer sensitive) — but this demands **manual contextual judgment** for every `clearFlags()` instance found, not a simple binary rule of "clearFlags() = always FAIL".

### 1.4 The Cross-Cutting Nature of `FLAG_SECURE`: Why Consistency Is Hard to Achieve in Practice

Unlike many other security controls that can be applied once centrally (e.g. a single network interceptor, one database encryption layer), `FLAG_SECURE` is **per-window/per-Activity** — it must be **explicitly applied everywhere relevant**, with no built-in Android mechanism to "apply globally across the entire app at once". This creates a classic **cross-cutting concern** in software engineering: a security concern that is **scattered** across many structurally unrelated code locations, making it **highly prone to inconsistency** as the application grows — a new developer adding a new Activity for a new financial feature can easily **forget** to copy the `FLAG_SECURE` pattern from a similar existing Activity, because there is no compiler/lint mechanism that automatically enforces it.

This is the **unique value of the static approach** compared to the dynamic approach (MASTG-TEST-0289): static analysis can **build a complete map** of every Activity/Fragment present in the application and identify which ones **should** have `FLAG_SECURE` (based on the content displayed) but **do not** — a systematic comparison that is far harder to achieve through dynamic testing, which depends on the tester manually visiting every screen one by one.

---

## 2. Tools Used for Testing

### 2.1 Required Tools (Core)

| Tool | Function |
|---|---|
| **jadx** | DEX → Java decompilation for searching `FLAG_SECURE` patterns |
| **grep / ripgrep** | Searching for API patterns and analyzing flag-removal context |
| **semgrep** | Running the official rule as a baseline (with the coverage gap noted, §3.2) |

### 2.2 Alternative & Supporting Tools

| Tool | Function |
|---|---|
| **CodeQL** | Builds a **complete map** of every `Activity`/`Fragment` in the application, correlates it with the presence of `FLAG_SECURE`, and detects `clearFlags()` not followed by an `addFlags()` restoration before the Activity's state changes — key to answering the "inconsistently applied" criterion (§1.3) |
| **jadx-gui "Find Usage"** | Traces every Activity present in the manifest to build a complete list of candidate "screens that should be protected" based on name/content (`PaymentActivity`, `PinEntryActivity`, etc.) |
| **MobSF** | Sometimes shows `FLAG_SECURE` usage status in the Code Analysis summary |
| **Frida** | Hooking `addFlags()`/`clearFlags()` for runtime confirmation of call order on a specific Activity, complementing static results with dynamic evidence (a bridge to MASTG-TEST-0289) |

### 2.3 Environment Prerequisites

- **No device/root needed** for the core static analysis.
- **Identify all sensitive screens first** (the `identify-sensitive-screens` prerequisite) as a complete reference list to be checked — not just passively searching for `FLAG_SECURE` patterns and stopping there.
- **Understand the application's navigation structure** (Activity/Fragment/Compose Navigation) to assess whether a found `clearFlags()` is actually restored on every possible return path.

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0013** to reverse engineer the application.
2. Use **MASTG-TECH-0014** to search for relevant APIs.

### 3.2 Method A — Official Semgrep Rule *(exists, but only covers half of the FAIL definition)*

```yaml
rules:
  - id: mastg-android-flag-secure-enable-flags
    severity: INFO
    languages: [java]
    metadata:
      summary: Window uses FLAG_SECURE to block screenshots.
    message: "[MASVS-PLATFORM] Make sure you use this flag for all screens with sensitive data"
    pattern-either:
      - patterns:
          - pattern: $W.addFlags($F)
          - metavariable-regex: { metavariable: $F, regex: ^(FLAG_SECURE|8192|0x2000)$ }
      - patterns:
          - pattern: $W.setFlags($FLAGS, $FLAGS)
          - metavariable-regex: { metavariable: $FLAGS, regex: ^(FLAG_SECURE|8192|0x2000)$ }
```

```bash
semgrep --config https://raw.githubusercontent.com/OWASP/mastg/master/rules/mastg-android-sensitive-data-in-screenshot.yml ./decompiled/sources/
```

**A significant coverage gap**: this rule explicitly **only detects enabling patterns** (`addFlags`/`setFlags` with `FLAG_SECURE`) — there is **no pattern at all** for `clearFlags()`. This means the official rule **only answers half** of the official FAIL definition (§1.2/§1.3) — it can help find failure mode #1 (a screen with no `FLAG_SECURE` at all, indirectly via an empty result for that file), but it **cannot detect at all** failure mode #2 (`clearFlags()` removing protection without justification). The rule's own `summary` message is honestly consistent with its coverage (*"Window uses FLAG_SECURE to block screenshots"* — it only claims to detect usage, not to assess consistency), unlike some other rules in this research series whose claims are misleading.

### 3.3 Method B — grep/ripgrep for Failure Mode #2 (clearFlags)

```bash
D=./decompiled/sources

# Find all clearFlags calls with FLAG_SECURE
rg -n 'clearFlags\(.*FLAG_SECURE|clearFlags\(8192\)|clearFlags\(0x2000\)' $D

# For each occurrence, check whether there is a restoration (addFlags) in the subsequent code path
rg -n -A20 'clearFlags\(.*FLAG_SECURE' $D | grep -A20 "clearFlags" | grep -c "addFlags.*FLAG_SECURE"
```

### 3.4 Method C — CodeQL for a Complete Activity Consistency Map

```ql
import java

class ActivityClass extends Class {
  ActivityClass() {
    this.getASupertype*().hasQualifiedName("android.app", "Activity")
  }
}

class FlagSecureAdd extends MethodAccess {
  FlagSecureAdd() {
    this.getMethod().hasName(["addFlags", "setFlags"]) and
    this.getAnArgument().toString().matches("%FLAG_SECURE%")
  }
}

class FlagSecureClear extends MethodAccess {
  FlagSecureClear() {
    this.getMethod().hasName("clearFlags") and
    this.getAnArgument().toString().matches("%FLAG_SECURE%")
  }
}

// Part 1: Activities whose name suggests sensitivity BUT have no FLAG_SECURE
from ActivityClass activity
where activity.getName().toLowerCase().regexpMatch(".*(payment|pin|password|card|wallet|otp).*")
  and not exists(FlagSecureAdd add | add.getEnclosingCallable().getDeclaringType() = activity)
select activity, "Activity with a name indicating sensitive data found WITHOUT FLAG_SECURE"
```

```ql
// Part 2: clearFlags without an addFlags restoration in the same method
from FlagSecureClear clear
where not exists(FlagSecureAdd add |
  add.getEnclosingCallable() = clear.getEnclosingCallable() and
  add.getControlFlowNode().getASuccessor*() = clear.getControlFlowNode())
select clear, "clearFlags(FLAG_SECURE) found without a clear addFlags restoration in the same method"
```

### 3.5 Method D — Frida for Runtime Order Confirmation (A Bridge to MASTG-TEST-0289)

```javascript
// hook-flag-secure-sequence.js
Java.perform(function () {
    var Window = Java.use("android.view.Window");
    var FLAG_SECURE = 0x00002000;

    Window.addFlags.overload("int").implementation = function (flags) {
        if ((flags & FLAG_SECURE) !== 0) console.log("[+] FLAG_SECURE added");
        return this.addFlags(flags);
    };
    Window.clearFlags.overload("int").implementation = function (flags) {
        if ((flags & FLAG_SECURE) !== 0) console.log("[-] FLAG_SECURE REMOVED");
        return this.clearFlags(flags);
    };
});
```

```bash
frida -U -f com.target.app -l hook-flag-secure-sequence.js --no-pause
```

### 3.6 Method Comparison: When to Use Which

| Method | Tool | Failure mode #1 (missing)? | Failure mode #2 (clearFlags)? | When to use |
|---|---|---|---|---|
| **A** | Official semgrep rule | Partially (indirect) | ❌ | Quick baseline, limited coverage |
| **B** | grep clearFlags | ❌ | ✅ | Closing the official rule's gap |
| **C** | CodeQL | ✅ (complete map) | ✅ | **Most valuable** — both failure modes at once |
| **D** | Frida | N/A (static→dynamic) | ✅ (actual order) | Runtime confirmation |

**Minimum recommended combination:** **C (CodeQL for a complete map of both failure modes) → B (quick grep supplement) → D (dynamic confirmation, correlated with MASTG-TEST-0289)**. The official rule (A) can be used as an initial reference but is not sufficient for a complete conclusion.

---

### 3.7 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rule:**

> **Evaluation:** *"The test case fails if the relevant APIs are missing or inconsistently applied on any UI component that displays sensitive data, or if code paths clear the protection without an adequate justification."*

---

#### ❌ FAIL / ISSUE — The check is declared FAILED if:

| No | Condition |
|---|---|
| F1 | A screen identified as sensitive (prerequisite) has **no** `FLAG_SECURE` call whatsoever |
| F2 | `FLAG_SECURE` is applied **inconsistently** — some sensitive screens are protected, other screens of equivalent sensitivity are not |
| F3 | A `clearFlags(FLAG_SECURE)` is found **without clear justification** and **without restoring** protection before sensitive content is displayed again |

**Example evidence (illustrative — MASTG has not yet provided an official demo for this test):**

```java
// PaymentConfirmationActivity.java — PROTECTED
protected void onCreate(Bundle savedInstanceState) {
    getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
    super.onCreate(savedInstanceState);
}
```

```java
// TransactionHistoryActivity.java — NO FLAG_SECURE whatsoever
protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    // Displays complete transaction history with amounts and descriptions
}
```

Interpretation: `PaymentConfirmationActivity` is protected, but `TransactionHistoryActivity` — which displays equally sensitive financial data — **has no protection whatsoever**. **FAIL** per the "inconsistently applied" criterion (§1.2 failure mode #1).

---

#### ✅ PASS — The check is declared PASSED if:

| No | Condition |
|---|---|
| P1 | **All** screens identified as sensitive have `FLAG_SECURE` applied consistently |
| P2 | Every `clearFlags(FLAG_SECURE)` instance found is accompanied by a clear justification (e.g. a transition to a non-sensitive screen) **and** is restored before sensitive content is displayed again |
| P3 | The CodeQL map (Method C) finds no Activity with an indication of sensitive content lacking protection |

---

#### ⚠️ Important Notes on Assessment

1. **Do not stop after finding one correct `FLAG_SECURE` example** — the "inconsistently applied" criterion demands mapping **all** sensitive screens, not a single sample. One Activity being well protected does not guarantee another Activity of equivalent sensitivity is also protected.

2. **The official rule only covers half of the FAIL definition** — it is mandatory to supplement it with a separate search for `clearFlags()` (Method B/C), because the official rule does not cover this failure mode at all.

3. **Assessing "adequate justification" on a `clearFlags()` requires manual contextual judgment** — not every `clearFlags()` automatically FAILs; check whether the content at that point is genuinely no longer sensitive and whether protection is correctly restored before sensitive content is shown again.

4. **Correlate with MASTG-TEST-0289 for definitive proof** — the static results here show candidate code locations, but real visual proof (an actual leaked screenshot) still requires dynamic testing, especially given the timing race condition gap discussed in depth in that document.

5. **Severity is modulated by:**

   | Factor | Severity |
   |---|---|
   | A financial/credential screen with no `FLAG_SECURE` at all | **High** |
   | `clearFlags()` with no restoration on a path that can return to sensitive content | **High** |
   | Inconsistency between screens of equivalent sensitivity | **Medium-High** |
   | `clearFlags()` with clear justification and correct restoration | **Not a finding** |

6. **Document:** the complete list of sensitive screens with each one's `FLAG_SECURE` status (consistency map), the location and context of every `clearFlags()` found, and the justification assessment for each.

---

## 4. Recommendations

Refer to **the MASTG-TEST-0289 document, §4**, for complete technical implementation recommendations (`FLAG_SECURE` from `onCreate()`, per-Activity granularity).

Additional recommendations specific to cross-codebase consistency:

### 4.1 Centralize Protection Logic Through a Base Activity/Fragment

```kotlin
abstract class SecureActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        super.onCreate(savedInstanceState)
    }
}

// Every sensitive Activity MUST extend SecureActivity, not Activity/AppCompatActivity directly
class PaymentConfirmationActivity : SecureActivity() { /* ... */ }
class TransactionHistoryActivity : SecureActivity() { /* ... */ }
```

This pattern turns the cross-cutting concern (§1.4) into a **structural obligation** — a new developer who forgets to choose the correct base class will be more easily caught during code review, and a custom lint rule can be added to force every Activity displaying certain content to inherit from `SecureActivity`.

### 4.2 Audit and Document Every `clearFlags()`

```kotlin
// ALWAYS include a comment explaining why it is safe to remove protection at this point
fun showShareableReceiptView() {
    window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)  // Safe: content is already redacted before this point
    // ...
    window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)  // MUST restore before this Activity displays other data
}
```

### 4.3 Integrate the Consistency Map into CI/CD

```bash
#!/bin/bash
# ci-check-flag-secure-consistency.sh
codeql database analyze ./cqldb ./flag-secure-consistency.ql --format=sarif-latest --output=result.sarif
if grep -q "FLAG_SECURE" result.sarif; then
    echo "[WARNING] FLAG_SECURE inconsistency found — review the CodeQL results"
fi
```

### 4.4 Remediation Checklist

- [ ] All sensitive screens from the prerequisite mapping have `FLAG_SECURE` applied consistently
- [ ] The centralization pattern (base Activity/Fragment) is applied to prevent future inconsistency
- [ ] Every `clearFlags(FLAG_SECURE)` is documented with a clear justification and correctly restored
- [ ] Custom CodeQL/lint is integrated into CI/CD to detect new Activities lacking protection
- [ ] Results are correlated with MASTG-TEST-0289 for dynamic proof
- [ ] **Re-verify:** rerun MASTG-TEST-0291 whenever a new Activity/screen is added

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0291: References to Screen Capturing Prevention APIs](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0291/)
- [MASTG-TEST-0289: Runtime Verification of Sensitive Content Exposure in Screenshots During App Backgrounding](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0289/)
- [MASWE-0038: Insufficient Protection of Sensitive Data from Screenshots or Screen Recordings](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0038/)
- [MASTG-BEST-0014: Preventing Screenshots and Screen Recording](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0014/)
- [Official rule: mastg-android-sensitive-data-in-screenshot.yml (GitHub)](https://github.com/OWASP/mastg/blob/master/rules/mastg-android-sensitive-data-in-screenshot.yml)

### 5.2 Official Android Documentation

- [Android Developers — Secure Sensitive Activities (Fraud Prevention)](https://developer.android.com/security/fraud-prevention/activities)
- [Android Developers — `Window#addFlags()`](https://developer.android.com/reference/android/view/Window#addFlags(int))
- [Android Developers — `Window#setFlags()`](https://developer.android.com/reference/android/view/Window#setFlags(int,int))
- [Android Developers — `Window#clearFlags()`](https://developer.android.com/reference/android/view/Window#clearFlags(int))

### 5.3 Tool Documentation

- [Semgrep — Documentation](https://semgrep.dev/docs/)
- [CodeQL — Documentation](https://codeql.github.com/docs/)
- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [Frida — Dynamic instrumentation toolkit](https://frida.re/docs/javascript-api/)
- [MobSF — Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)

### 5.4 CWE

- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
- [CWE-311: Missing Encryption of Sensitive Data](https://cwe.mitre.org/data/definitions/311.html)

---

*This document was compiled based on OWASP MASTG (latest release as of September 2026) and official Android Developers documentation. As the static counterpart of MASTG-TEST-0289, this test's unique value is its ability to build a **thorough consistency map** across every sensitive screen in the application — something difficult to achieve through dynamic testing alone. The official semgrep rule was found to cover only half of the two failure modes explicitly named in the official overview (missing vs. clearFlags without justification) — CodeQL with thorough structural analysis is the most valuable method for answering the "inconsistently applied" evaluation criterion, which demands a holistic understanding of the codebase rather than mere local pattern detection.*
