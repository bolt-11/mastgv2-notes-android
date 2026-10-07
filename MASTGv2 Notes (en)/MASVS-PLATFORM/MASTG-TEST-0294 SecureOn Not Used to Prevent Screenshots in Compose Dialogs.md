# MASTG-TEST-0294 `SecureOn` Not Used to Prevent Screenshots in Compose Dialogs

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0294 |
| **Platform** | Android |
| **MASVS Category** | MASVS-PLATFORM |
| **Weakness** | MASWE-0038 — *Insufficient Protection of Sensitive Data from Screenshots or Screen Recordings* (same as MASTG-TEST-0289/0291/0292/0293) |
| **API Highlighted** | `androidx.compose.ui.window.DialogProperties(securePolicy = ...)`, `SecureFlagPolicy` (`SecureOn`, `SecureOff`, `Inherit`) |
| **Test Type** | Static, Code |
| **Official MASTG Status** | **`placeholder`** — no complete Overview/Steps/Evaluation yet |
| **Official Note (the only content available)** | *"This test verifies whether an app prevents sensitive data from being captured in screenshots and screen recordings of Jetpack Compose dialogs."* |
| **Knowledge** | MASTG-KNOW-0053 |
| **Best Practice** | MASTG-BEST-0014, MASTG-BEST-0018 (Use `SecureFlagPolicy.SecureOn` to Prevent Screenshots in Compose Components — **also a placeholder**) |
| **Related Tests** | **MASTG-TEST-0289/0291/0292/0293** — the entire MASWE-0038 group; this test complements **MASTG-TEST-0293** (SurfaceView) as a second component-specific architectural gap, this time for the **Jetpack Compose** context |
| **Related Demo** | — (none) |
| **Official Rule** | — (none; placeholder test) |
| **Related CWE** | CWE-200, CWE-311 |

---

## 1. Explanation

### 1.1 Status of This Test

Just like MASTG-TEST-0292 and MASTG-TEST-0293, both this test and the best practice it references (**MASTG-BEST-0018**) are both in **`placeholder`** status. This document is compiled entirely from independent research into official Jetpack Compose documentation and the public issue history relevant to this topic.

### 1.2 Root Cause: Compose `Dialog` Creates an Entirely New Android Window

This is a direct conceptual continuation of the architectural gap discussed in the **MASTG-TEST-0293** document (`SurfaceView`), but with a **different technical mechanism**. Jetpack Compose's `Dialog` component is **not rendered inside the same Activity window** — it internally creates a **completely new `android.view.Window`** (via `android.app.Dialog` at the platform level), entirely separate from its parent Activity's window. This differs from the `SurfaceView` gap (which remains within the same window but on a separate compositor layer) — here, **the window itself is new**, making the question "does `FLAG_SECURE` propagate into this new window?" architecturally relevant.

### 1.3 Historical Evolution: From a Gap to a Fixed Default Behavior

This is the most interesting part of the research for this test — unlike `SurfaceView` (MASTG-TEST-0293), which **still, to this day**, does not automatically inherit `FLAG_SECURE`, a similar gap in Compose's `Dialog` **has already been fixed** into a safer default behavior, though its history is important to understand when assessing risk on older Compose versions:

- **Historical problem** (documented in public Google Issue Tracker reports #143778149 and #171682480): early Compose widget implementations **failed to automatically** apply `FLAG_SECURE` to the new Dialog window it created, **even though** the Activity window that launched it already had `FLAG_SECURE` active. The community's proposed fix rationale at the time explicitly stated: *"the ideal solution would be for `FLAG_SECURE` to be propagated: if `FLAG_SECURE` is set on an activity or fragment displaying a composable, then those composables should also set `FLAG_SECURE` on any windows they create."*
- **Current behavior** (modern Compose versions): `DialogProperties` provides a `securePolicy` parameter with a **default value of `SecureFlagPolicy.Inherit`** — meaning, **since this fix was applied**, Compose Dialogs **automatically inherit** the `FLAG_SECURE` status of their launching window, without the developer needing to do anything explicit.

### 1.4 The Three `SecureFlagPolicy` Values and Their Implications

```kotlin
enum class SecureFlagPolicy {
    Inherit,    // Default — automatically inherits the FLAG_SECURE status from the parent window
    SecureOn,   // Forces FLAG_SECURE ON for this Dialog, regardless of the parent window's status
    SecureOff   // Forces FLAG_SECURE OFF for this Dialog, regardless of the parent window's status
}
```

| Value | Behavior | When Relevant |
|---|---|---|
| **`Inherit`** (default) | The Dialog automatically "follows" its launching window's `FLAG_SECURE` status | The most common scenario — the developer does not need to do anything |
| **`SecureOn`** | The Dialog is **always** secure, even if the launching window does **not** have `FLAG_SECURE` | Dialogs that display sensitive content (PIN, OTP) **even when launched from a generally non-sensitive Activity** |
| **`SecureOff`** | The Dialog is **always** insecure, even if the launching window **has** `FLAG_SECURE` | **Dangerous** if applied without justification — explicitly removes protection that should have been inherited |

### 1.5 Why This Test Remains Relevant Even Though the Default Has Been Fixed

Unlike `SurfaceView` (where the risk is **always** relevant because there is no safe default behavior), this test has a more conditional nuance — but it remains important to check because of several real-world risk scenarios:

1. **Older Jetpack Compose versions** that have not yet applied the `SecureFlagPolicy.Inherit`-as-default fix — applications with outdated Compose dependencies still inherit this historical gap.
2. **`securePolicy = SecureFlagPolicy.SecureOff` applied explicitly** — whether due to a copy-paste code mistake, a leftover debugging need, or a developer's misunderstanding of this parameter.
3. **`Inherit` is only effective if the PARENT window actually already has `FLAG_SECURE`** — if the launching Activity does **not** have `FLAG_SECURE` (because it is indeed not a generally sensitive screen), yet the Dialog it raises **displays** sensitive content (e.g., a PIN confirmation dialog in the middle of a checkout flow that is mostly non-sensitive), **`Inherit` is not sufficient** — the developer **must** explicitly use `SecureFlagPolicy.SecureOn` for that specific Dialog.
4. **Compose's `Popup` component** (different from `Dialog`) has a separate history and configuration properties — it needs to be checked independently for whether its inheritance behavior is identical.

Point #3 above is the **most important evaluation nuance** — similar to the pattern in MASTG-TEST-0292 (`setRecentsScreenshotEnabled`), where a perfectly functioning `Inherit` **is not automatically sufficient** when the protection granularity needed differs from that of its parent window.

---

## 2. Tools Used for Testing

### 2.1 Required Tools (Core)

| Tool | Function |
|---|---|
| **jadx** | DEX → Java/Kotlin-like decompilation for finding `DialogProperties`/`securePolicy` patterns |
| **grep / ripgrep** | API pattern search |

### 2.2 Alternative & Supporting Tools

| Tool | Function |
|---|---|
| **CodeQL** | Traces all Compose `Dialog(...)` calls, checks the `properties`/`securePolicy` parameter passed, and correlates it with the parent Activity's `FLAG_SECURE` status |
| **Dependency version audit (`build.gradle`)** | Checks the `androidx.compose.ui` version used — relevant for assessing whether the `Inherit` default fix is in effect on that version |
| **MASTG-TEST-0289 (screenshot extraction methodology)** | Definitive dynamic verification |

### 2.3 Environment Prerequisites

- **No device/root required** for core static analysis.
- **Check the Jetpack Compose version** (`androidx.compose.ui:ui` in `build.gradle`) as required context.
- **Identify all Compose Dialogs** that display sensitive content (PIN confirmation, OTP, card details) as the primary audit target.

---

## 3. Testing Methodology

Since there are no official steps (placeholder status), the following methodology is compiled from independent research.

### 3.1 General Steps

1. Identify all Compose `Dialog(...)`/`AlertDialog(...)` calls within the codebase.
2. For each Dialog displaying sensitive content, check the `securePolicy` parameter provided (or its absence, which means the default `Inherit`).
3. For `Inherit` cases, verify whether the launching Activity/window actually has `FLAG_SECURE` — if not, `Inherit` provides no protection at all.

### 3.2 Method A — grep/ripgrep

```bash
D=./decompiled/sources

# Find all Compose Dialog calls with an explicit securePolicy
rg -n 'securePolicy\s*=\s*SecureFlagPolicy\.' $D

# Specifically find the DANGEROUS case: explicit SecureOff
rg -n 'SecureFlagPolicy\.SecureOff' $D

# Find Dialogs WITHOUT securePolicy at all (default Inherit) — needs manual verification of the parent window
rg -n -B10 'Dialog\(' $D | grep -v "securePolicy"
```

### 3.3 Method B — CodeQL for Correlation with the Parent Window

```ql
import java

class ComposeDialogCall extends MethodAccess {
  ComposeDialogCall() {
    this.getMethod().hasName("Dialog") and
    this.getMethod().getDeclaringType().getPackage().getName().matches("androidx.compose.ui.window%")
  }
}

from ComposeDialogCall dialog
where not exists(string s | s = dialog.toString() and s.matches("%securePolicy%"))
select dialog, "Compose Dialog found without an explicit securePolicy — manually verify whether the parent window has FLAG_SECURE (Inherit)"
```

### 3.4 Method C — Dependency Version Audit

```bash
grep -A2 "androidx.compose.ui:ui" app/build.gradle
```

Compare the version found against the official Jetpack Compose changelog to confirm whether the `SecureFlagPolicy.Inherit` default fix is in effect for that version.

### 3.5 Method D — Dynamic Verification

```bash
# Trigger a Dialog that displays sensitive content, then take a manual screenshot
adb shell input tap <dialog_trigger_button_coordinates>
adb shell screencap -p /sdcard/dialog_test.png
adb pull /sdcard/dialog_test.png
```

If the screenshot clearly shows the Dialog's content (not black/empty), this is definitive proof that protection is ineffective — whether due to explicit `SecureOff`, an old Compose version, or a parent window that lacks `FLAG_SECURE` while the Dialog relies on `Inherit`.

### 3.6 Method Comparison: When to Use Which

| Method | Tool | When to Use |
|---|---|---|
| **A** | grep | Fast baseline, identify explicit `SecureOff` (most critical) |
| **B** | CodeQL | Systematic correlation of Dialogs with parent window status |
| **C** | Version audit | Assessing the relevance of historical risk |
| **D** | Dynamic verification | Definitive proof |

**Minimum combination I recommend:** **A (look for explicit `SecureOff` first, most critical) → B (correlate Dialogs with Inherit) → D (dynamic confirmation)**.

---

### 3.7 Evaluation Criteria: Positive Case & Negative Case

Since there is no official Evaluation clause (placeholder status), the following criteria are compiled based on the brief official note and the architectural principles explained in §1.2–1.5.

---

#### ❌ FAIL / ISSUE — The check is declared FAILED if:

| No | Condition |
|---|---|
| F1 | A Compose Dialog displaying sensitive content explicitly uses `securePolicy = SecureFlagPolicy.SecureOff` |
| F2 | The Dialog relies on `Inherit` (default), but its launching Activity/window does **not** have `FLAG_SECURE` — so the Dialog displaying sensitive content remains unprotected |
| F3 | The application uses an old Jetpack Compose version that has not applied the `Inherit` default fix, and there is no explicit `securePolicy` configured as compensation |
| F4 | Dynamic verification confirms the sensitive Dialog content remains clearly visible in a screenshot |

---

#### ✅ PASS — The check is declared PASSED if:

| No | Condition |
|---|---|
| P1 | The Dialog displaying sensitive content explicitly uses `SecureFlagPolicy.SecureOn` — protection is guaranteed regardless of the parent window's status |
| P2 | The Dialog relies on `Inherit`, **and** its parent window is confirmed to actually have `FLAG_SECURE` active |
| P3 | The Jetpack Compose version used already applies the correct `Inherit` default, confirmed via version audit |

---

#### ⚠️ Important Notes on Evaluation

1. **`Inherit` is NOT absolute protection — its effectiveness depends entirely on the parent window's status.** This is the most likely evaluation mistake: concluding PASS just because `securePolicy` was not set explicitly (thus "using the safe default"), without verifying whether the parent window actually has `FLAG_SECURE`.

2. **Explicit `SecureFlagPolicy.SecureOff` is the highest-priority FAIL signal** — this is the clearest and most unambiguous pattern, similar to an unjustified `clearFlags()` in the MASTG-TEST-0291 document.

3. **For sensitive Dialogs that can be triggered from a non-sensitive Activity, explicit `SecureOn` is the only correct choice** — do not rely on `Inherit` for this case.

4. **Check the Compose version as mandatory context** — this risk is far more relevant for codebases with Compose dependencies that have not been updated in a long time.

5. **Severity is modulated:**

   | Factor | Severity |
   |---|---|
   | Explicit `SecureOff` on a PIN/OTP/card Dialog | **Critical** |
   | `Inherit` used on a sensitive Dialog triggered from a non-`FLAG_SECURE` Activity | **High** |
   | Old Compose version without explicit compensation | **Medium-High** |
   | Explicit `SecureOn` already correctly applied | **Not a finding** |

6. **Document:** the list of sensitive Dialogs along with each `securePolicy` value, the `FLAG_SECURE` status of the parent window for each `Inherit` case, and the Jetpack Compose version used.

---

## 4. Recommendations

### 4.1 Apply Explicit `SecureOn` for Sensitive Dialogs

```kotlin
@Composable
fun PinConfirmationDialog(onConfirm: (String) -> Unit) {
    Dialog(
        onDismissRequest = { /* ... */ },
        properties = DialogProperties(
            securePolicy = SecureFlagPolicy.SecureOn  // Always secure, regardless of the parent window
        )
    ) {
        // PIN input UI
    }
}
```

### 4.2 Update the Jetpack Compose Dependency

```gradle
dependencies {
    implementation "androidx.compose.ui:ui:1.7.0"  // Current version that already applies the Inherit default
}
```

### 4.3 Remediation Checklist

- [ ] All Compose Dialogs displaying sensitive content are inventoried
- [ ] Dialogs that can be triggered from a non-sensitive Activity use explicit `SecureOn`
- [ ] No `SecureOff` is applied without clear justification
- [ ] The Jetpack Compose version is updated to a release that supports the correct `Inherit` default
- [ ] **Re-verify:** re-run MASTG-TEST-0294 whenever a new Dialog is added

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0294: SecureOn Not Used to Prevent Screenshots in Compose Dialogs](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0294/)
- [MASTG-TEST-0293: setSecure Not Used to Prevent Screenshots in SurfaceViews](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0293/)
- [MASWE-0038: Insufficient Protection of Sensitive Data from Screenshots or Screen Recordings](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0038/)
- [MASTG-BEST-0018: Use SecureFlagPolicy.SecureOn to Prevent Screenshots in Compose Components](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0018/)

### 5.2 Official Android Documentation

- [Android Developers — `DialogProperties` (Jetpack Compose)](https://developer.android.com/reference/kotlin/androidx/compose/ui/window/DialogProperties)
- [Android Developers — Secure Sensitive Activities](https://developer.android.com/security/fraud-prevention/activities)

### 5.3 Community Research and History

- [CommonsWare — Securing Jetpack Compose](https://commonsware.com/blog/2019/12/10/securing-jetpack-compose.html)
- [Google Issue Tracker #143778149 — FLAG_SECURE propagation](https://issuetracker.google.com/issues/143778149?hl=ja)
- [Google Issue Tracker #171682480 — Status Update](https://issuetracker.google.com/issues/171682480?hl=ja)
- [ProAndroidDev — Android Security in the Age of Jetpack Compose](https://proandroiddev.com/android-security-in-the-age-of-jetpack-compose-from-task-hijacking-to-tapjacking-edbbc78be943)
- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)

### 5.4 Tool Documentation

- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [CodeQL — Documentation](https://codeql.github.com/docs/)

---

*This document is compiled entirely from independent research, because both MASTG-TEST-0294 and the MASTG-BEST-0018 it references are both in **placeholder** status. Unlike the `SurfaceView` gap (MASTG-TEST-0293), which has no safe default behavior, Jetpack Compose's `Dialog` component **has already been fixed** to automatically inherit `FLAG_SECURE` from its parent window (`SecureFlagPolicy.Inherit` as the default). However, this "Inherit" value is not absolute protection — its effectiveness depends entirely on the parent window's status, so sensitive Dialogs that can be triggered from a non-sensitive Activity still require explicit `SecureFlagPolicy.SecureOn` as the only correct guarantee of protection.*
