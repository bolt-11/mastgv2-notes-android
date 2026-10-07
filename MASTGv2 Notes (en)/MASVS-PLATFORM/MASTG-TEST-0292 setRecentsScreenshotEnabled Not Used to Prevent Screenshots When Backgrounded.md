# MASTG-TEST-0292 `setRecentsScreenshotEnabled` Not Used to Prevent Screenshots When Backgrounded

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0292 |
| **Platform** | Android |
| **MASVS Category** | MASVS-PLATFORM |
| **Weakness** | MASWE-0038 — *Insufficient Protection of Sensitive Data from Screenshots or Screen Recordings* (same as MASTG-TEST-0289/0291) |
| **Highlighted API** | `Activity.setRecentsScreenshotEnabled(boolean)` — API 33+ |
| **Test Type** | Static, Code |
| **Official MASTG Status** | **`placeholder`** — no complete Overview/Steps/Evaluation yet |
| **Official note (the only content currently available)** | *"This test verifies whether an app prevents sensitive data from being captured in the Recents screen when backgrounded."* |
| **Knowledge** | MASTG-KNOW-0053 |
| **Best Practice** | MASTG-BEST-0014 (Preventing Screenshots and Screen Recording), MASTG-BEST-0015 (Use `setRecentsScreenshotEnabled` to Prevent Screenshots When Backgrounded — **also a placeholder**) |
| **Related Tests** | **MASTG-TEST-0289** (dynamic visual proof), **MASTG-TEST-0291** (References to Screen Capturing Prevention APIs — targets `FLAG_SECURE`; this test targets a **different** API that complements, rather than replaces, `FLAG_SECURE`) |
| **Related Demo** | — (none) |
| **Official Rule** | — (none; placeholder test) |
| **Related CWE** | CWE-200, CWE-311 |

---

## 1. Explanation

### 1.1 The Status of This Test and Two Placeholders at Once

This is a **rare case** in this research series: **both this test and the best practice it references (MASTG-BEST-0015) are both in `placeholder` status**. This likely reflects that the `setRecentsScreenshotEnabled` API is still **relatively new** (introduced in Android 13/API 33, in 2022) compared to `FLAG_SECURE`, which has been standard since API 1 — the official MASTG documentation for this topic is likely still being written out more fully. This document is compiled entirely from **independent research** into official Android Developers documentation and community articles.

### 1.2 What `setRecentsScreenshotEnabled` Is and Why It Differs from `FLAG_SECURE`

This is an API that specifically **targets one specific scenario** — the thumbnail preview in the Recents/Overview screen — unlike `FLAG_SECURE` (discussed in depth in the MASTG-TEST-0289/0291 documents), which operates **far more broadly**:

```java
// Introduced in Activity since API 33 (Android 13)
setRecentsScreenshotEnabled(false);
```

Per official Android documentation:

> *"By default, this value is `true`... What this does: Hides your activity's thumbnail in Recents. What it does NOT do: Does not block normal screenshots; Does not stop screen recording."*

A summary of the coverage difference between the two APIs:

| Aspect | `FLAG_SECURE` | `setRecentsScreenshotEnabled(false)` |
|---|---|---|
| **Scope** | **Global** — blocks manual user screenshots, screen recording, display on insecure screens (casting), **and** the Recents thumbnail all at once | **Narrow** — **only** affects the thumbnail on the Recents/Overview screen |
| **Manual user screenshot** | Blocked (black screen) | **Still works normally** — the user can still take a manual screenshot as usual |
| **Screen recording** | Blocked | **Unaffected** |
| **Minimum API** | API 1 (available from the start) | **API 33** (Android 13) |
| **UX impact** | Significant — the user's entire screenshot/recording interaction is blocked in that window | Minimal — the user barely notices the difference unless trying to view the preview in Recents |

### 1.3 Why This API Has Value as a Complement, Not a Replacement, for `FLAG_SECURE`

The most important conceptual point explaining **when** this API is relevant to use: `FLAG_SECURE` is — per the term already quoted in the MASTG-TEST-0289 document — a *"blunt instrument"* that blocks **everything** at once, including legitimate screenshot needs a user might want (e.g. saving transaction proof, screenshotting order history for personal documentation). `setRecentsScreenshotEnabled(false)` offers a **different balance point**: it closes off the **passive automatic leakage path** (the Recents thumbnail that appears without any conscious user action) while **still allowing** the user to deliberately take a screenshot if they genuinely want to.

This is especially relevant for scenarios where:
- A developer wants to **avoid the UX friction** caused by `FLAG_SECURE` (users complaining they cannot screenshot a transaction receipt for personal needs), yet still wants to close the **automatic thumbnail** gap that appears entirely without the user's awareness.
- The application targets **API 33+ exclusively** and wants more granular control than the "all-or-nothing" approach of `FLAG_SECURE`.

### 1.4 An Important Limitation: The System Can Still Take Screenshots in Other Contexts

The official documentation gives an important note that must be understood as a limitation of this API:

> *"The system may still take screenshots of the activity in other contexts; for example, when the user takes a screenshot of the entire screen, or when the active `VoiceInteractionService` requests a screenshot."*

This confirms the API's **truly narrow scope** — `setRecentsScreenshotEnabled(false)` **purely** stops the automatic screenshot generation process specifically for Recents purposes, and **does not** provide any protection against other capture mechanisms (a manual user screenshot, a capture request from a voice assistant service/`VoiceInteractionService`, or an accessibility app with screen-capture permission). This is **not** a general solution for MASWE-0038 — it only closes **one specific gap** among the many possible visual leakage paths.

### 1.5 Combination Recommendation: When to Use Which

Based on a synthesis of understanding both APIs:

| Scenario | Recommendation |
|---|---|
| Screen displays highly sensitive credential/financial data (PIN, password, card number) | **`FLAG_SECURE`** — maximum protection is needed, UX friction is acceptable for the sake of security |
| Screen displays reasonably sensitive data, but the user might reasonably want to screenshot it for personal needs (e.g. order details, e-tickets, a completed payment receipt) | **`setRecentsScreenshotEnabled(false)`** — closes the passive thumbnail gap without sacrificing the user's ability to take a deliberate screenshot |
| App supports API below 33 and needs Recents protection | **`FLAG_SECURE` is mandatory** — `setRecentsScreenshotEnabled` is unavailable, and `FLAG_SECURE` itself **already** closes the Recents gap as part of its broader coverage (discussed in the MASTG-TEST-0289 document) |
| Combining both | For highly sensitive screens in an app with `minSdkVersion` < 33, still rely on `FLAG_SECURE` alone — both APIs are essentially **redundant** for this specific Recents case, since `FLAG_SECURE` already covers it |

---

## 2. Tools Used for Testing

### 2.1 Required Tools (Core)

| Tool | Function |
|---|---|
| **jadx** | DEX → Java decompilation for searching `setRecentsScreenshotEnabled` patterns |
| **grep / ripgrep** | API pattern searching |

### 2.2 Alternative & Supporting Tools

| Tool | Function |
|---|---|
| **CodeQL** | Same as the MASTG-TEST-0291 document, builds a map of sensitive Activities and correlates it with both APIs (`FLAG_SECURE` **and** `setRecentsScreenshotEnabled`) at once for a thorough protection overview |
| **aapt2 / apkanalyzer** | Extracting `targetSdkVersion`/`minSdkVersion` — relevant because this API only works on API 33+ |
| **MASTG-TEST-0289 (screenshot extraction methodology)** | Dynamic verification — compare Recents thumbnail results before/after applying this API |

### 2.3 Environment Prerequisites

- **No device/root needed** for the core static analysis.
- **For dynamic verification**, a device/emulator with **Android 13+** is needed — this API does not function on older versions.
- **Check `minSdkVersion`/`targetSdkVersion`** as mandatory context — just as with the recurring pattern in various tests in this research series (MASTG-TEST-0245, 0252), the presence/absence of this API must be assessed relative to the version range the app supports.

---

## 3. Testing Methodology

Because there are no official steps (placeholder status), the following methodology is compiled from independent research.

### 3.1 General Steps

1. Identify sensitive screens (the `identify-sensitive-screens` prerequisite, same as MASTG-TEST-0289/0291).
2. For each screen, check whether `FLAG_SECURE` **and/or** `setRecentsScreenshotEnabled(false)` is applied.
3. Assess the combination of both relative to the application's `minSdkVersion` (§1.5).

### 3.2 Method A — grep/ripgrep

```bash
D=./decompiled/sources

rg -n 'setRecentsScreenshotEnabled\(' $D
```

```bash
# Correlate with targetSdkVersion to assess relevance
grep -oP 'targetSdkVersion="\K[0-9]+' AndroidManifest.xml
```

### 3.3 Method B — CodeQL for a Dual-Protection Map

```ql
import java

class ActivityClass extends Class {
  ActivityClass() {
    this.getASupertype*().hasQualifiedName("android.app", "Activity")
  }
}

class FlagSecureCall extends MethodAccess {
  FlagSecureCall() {
    this.getMethod().hasName(["addFlags", "setFlags"]) and
    this.getAnArgument().toString().matches("%FLAG_SECURE%")
  }
}

class RecentsScreenshotCall extends MethodAccess {
  RecentsScreenshotCall() {
    this.getMethod().hasName("setRecentsScreenshotEnabled")
  }
}

from ActivityClass activity
where activity.getName().toLowerCase().regexpMatch(".*(payment|pin|password|card|wallet|otp).*")
  and not exists(FlagSecureCall f | f.getEnclosingCallable().getDeclaringType() = activity)
  and not exists(RecentsScreenshotCall r | r.getEnclosingCallable().getDeclaringType() = activity)
select activity, "Sensitive Activity WITHOUT either FLAG_SECURE or setRecentsScreenshotEnabled"
```

### 3.4 Method C — Dynamic Verification (Android 13+, Comparison with MASTG-TEST-0289)

```bash
# Extract a Recents snapshot before and after applying this API on an Android 13+ device
adb pull /data/system_ce/0/snapshots/ ./before/
# ... re-trigger after the code change ...
adb pull /data/system_ce/0/snapshots/ ./after/
diff -rq ./before/ ./after/
```

### 3.5 Method Comparison: When to Use Which

| Method | Tool | When to use |
|---|---|---|
| **A** | grep | Quick baseline |
| **B** | CodeQL | Dual-protection map (`FLAG_SECURE` + this API) across all sensitive Activities |
| **C** | Dynamic verification | Definitive confirmation on an Android 13+ device |

**Minimum recommended combination:** **B (thorough map, assessing BOTH APIs per Activity at once) → C (dynamic confirmation if an Android 13+ device is available)**.

---

### 3.6 Evaluation Criteria: Positive Case & Negative Case

Since there is no official Evaluation clause (placeholder status), the following criteria are compiled based on the brief official note and the basic principles of MASWE-0038.

---

#### ❌ FAIL / ISSUE — The check is declared FAILED if:

| No | Condition |
|---|---|
| F1 | The application targets API 33+ exclusively for a feature, and an identified sensitive screen has **neither** `FLAG_SECURE` **nor** `setRecentsScreenshotEnabled(false)` |
| F2 | Dynamic verification (Method C, Android 13+) confirms the Recents thumbnail still displays sensitive content even though this API **should** have been applied |

**Important note**: because `FLAG_SECURE` **already** closes the Recents gap as part of its coverage (discussed in MASTG-TEST-0289), the **absence** of `setRecentsScreenshotEnabled` is **not automatically a FAIL** if `FLAG_SECURE` has already been correctly applied to the same screen — both APIs are redundant for this scenario.

---

#### ✅ PASS — The check is declared PASSED if:

| No | Condition |
|---|---|
| P1 | The sensitive screen is protected by `FLAG_SECURE` (automatically covering the Recents gap) — `setRecentsScreenshotEnabled` becomes irrelevant/optional |
| P2 | A sensitive screen (deliberately not given `FLAG_SECURE` for UX reasons, per the scenario in §1.5) is given `setRecentsScreenshotEnabled(false)` as the appropriate compromise |
| P3 | Dynamic verification confirms the Recents thumbnail is empty/a placeholder for that screen |

---

#### ⚠️ Important Notes on Assessment

1. **Do not demand this API when `FLAG_SECURE` has already been correctly applied** — per §1.5, both are redundant for the Recents case. Focus the evaluation on **whether EITHER** of the two closes this gap, not on demanding both at once.

2. **This API's unique value actually emerges when `FLAG_SECURE` is DELIBERATELY not used** for UX reasons — in this scenario, the absence of `setRecentsScreenshotEnabled` becomes a genuine gap worth flagging.

3. **API 33 is a hard boundary** — do not demand use of this API on an app with `minSdkVersion`/`targetSdkVersion` below 33; for such cases, `FLAG_SECURE` remains the only valid path.

4. **Remember this API's limited scope** (§1.4) — do not let a report imply this API provides protection equivalent to `FLAG_SECURE`; it purely closes the Recents thumbnail gap alone.

5. **Document:** the status of both APIs per sensitive screen, the application's `minSdkVersion`/`targetSdkVersion`, and the justification if `FLAG_SECURE` is deliberately not used for UX reasons.

---

## 4. Recommendations

### 4.1 Apply as a Complement for UX-Sensitive Scenarios

```kotlin
class OrderDetailActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            setRecentsScreenshotEnabled(false)  // Allow manual screenshot, block Recents thumbnail
        }
        // Do NOT apply FLAG_SECURE here — users may manually screenshot the order receipt
    }
}
```

### 4.2 Remediation Checklist

- [ ] For each sensitive screen, determine the appropriate policy: full `FLAG_SECURE` vs `setRecentsScreenshotEnabled` alone vs a combination
- [ ] The `setRecentsScreenshotEnabled` API is wrapped in a `Build.VERSION.SDK_INT >= 33` check
- [ ] Dynamic verification is performed on an Android 13+ device to confirm effectiveness
- [ ] **Re-verify:** rerun MASTG-TEST-0292 whenever a new screen is added

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0292: setRecentsScreenshotEnabled Not Used to Prevent Screenshots When Backgrounded](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0292/)
- [MASTG-TEST-0289: Runtime Verification of Sensitive Content Exposure in Screenshots](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0289/)
- [MASTG-TEST-0291: References to Screen Capturing Prevention APIs](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0291/)
- [MASWE-0038: Insufficient Protection of Sensitive Data from Screenshots or Screen Recordings](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0038/)
- [MASTG-BEST-0015: Use setRecentsScreenshotEnabled to Prevent Screenshots When Backgrounded](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0015/)

### 5.2 Official Android Documentation

- [Android Developers — `Activity#setRecentsScreenshotEnabled()`](https://developer.android.com/reference/android/app/Activity#setRecentsScreenshotEnabled(boolean))
- [Android Developers — Secure Sensitive Activities](https://developer.android.com/security/fraud-prevention/activities)

### 5.3 Research and Community Articles

- [ProAndroidDev — Multitasking Intrusion and Preventing Screenshots in Android Apps](https://proandroiddev.com/multitasking-intrusion-and-preventing-screenshots-in-android-app-15bd8757c24d)
- [Worth Doing Badly — Accessing Screenshots from Android's Recent Apps Screen](https://worthdoingbadly.com/androidrecents/)
- [Jojonosaurus — Behind the Screen: Detecting and Preventing Screenshots in Android](https://jojonosaur.us/posts/flag-secure/)
- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)

### 5.4 Tool Documentation

- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [CodeQL — Documentation](https://codeql.github.com/docs/)

---

*This document was compiled entirely from independent research (official Android Developers documentation and community articles) because both MASTG-TEST-0292 and the MASTG-BEST-0015 it references are both in **placeholder** status. The most important nuance: `setRecentsScreenshotEnabled(false)` is not a replacement for `FLAG_SECURE`, but rather a tool with a far narrower scope — it only closes the Recents thumbnail gap without blocking manual screenshots or screen recording. Its value emerges specifically as a UX compromise when `FLAG_SECURE` is considered too restrictive for a given screen, not as an additional obligation on a screen already fully protected by `FLAG_SECURE`.*
