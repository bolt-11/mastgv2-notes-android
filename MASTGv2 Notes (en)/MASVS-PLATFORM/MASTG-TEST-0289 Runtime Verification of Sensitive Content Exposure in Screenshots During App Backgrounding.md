# MASTG-TEST-0289 Runtime Verification of Sensitive Content Exposure in Screenshots During App Backgrounding

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0289 |
| **Platform** | Android |
| **MASVS Category** | MASVS-PLATFORM |
| **Weakness** | MASWE-0038 — *Insufficient Protection of Sensitive Data from Screenshots or Screen Recordings* |
| **Test Type** | **Dynamic, Filesystem, Manual** |
| **Prerequisite** | `identify-sensitive-screens` |
| **Knowledge** | MASTG-KNOW-0053 |
| **Best Practice** | MASTG-BEST-0014 (Preventing Screenshots and Screen Recording) |
| **Related Techniques** | MASTG-TECH-0002 (Retrieving Files from Device Storage) |
| **Related Test** | This series is complemented by other MASWE-0038 tests targeting `FLAG_SECURE` from a static/runtime-hooking perspective (outside the scope of this document) |
| **Related Demo** | — (none) |
| **Official Rule** | — (not applicable; purely dynamic test, evidence is an image file) |
| **Related CWE** | CWE-200, CWE-311, CWE-1258 (Exposure of Sensitive System Information Due to Uncleared Debug Information — conceptual analog) |

---

## 1. Explanation

### 1.1 Testing Objective

Quote from the official MASTG overview:

> *"This test verifies that the app hides sensitive content from the screen when it moves to the background. This is important because Android captures a task screenshot of the app UI when it moves to the background. This screenshot is used for the Recents screen and transitions, and can expose sensitive content if the app does not protect it."*

This is one of the **most easily overlooked Android system behaviors** by developers because it is **automatic and not directly visible** — every time an app moves to the background (pressing the Home button, opening the Recents/Overview screen, receiving an incoming phone call, or even a system notification covering the screen), Android **automatically takes a screenshot** of the app's current display to show as a preview thumbnail on the Recents screen. This screenshot is **stored as an actual image file** in system storage — not merely a temporary display buffer in memory.

### 1.2 Storage Location and Its Significance

The official overview explicitly lists the system storage location where this screenshot is cached:

> *"The system stores the screenshots in their containers `/data/system_ce/0/snapshots` or `/data/system`."*

An important point: this location sits on the **system partition** (not the app's private directory `/data/data/<package>/`), meaning this screenshot is **potentially accessible** to entities with elevated access privileges (root, device forensics, or — on a rooted/compromised device — a malicious app with system-level access). This creates a **leakage path independent** of how well the app secures its own internal storage (refer to other MASVS-STORAGE documents in this research series) — even if all data in the app's database/SharedPreferences is perfectly encrypted, the **visual rendering** of that data can still be captured and stored as an ordinary image file readable by any gallery app/forensic file explorer.

### 1.3 Official Solution: `FLAG_SECURE`

MASTG-BEST-0014 provides the single officially recommended solution:

> *"Setting `FLAG_SECURE` on the window prevents screenshots (or appear black), blocks screen recording, and hides content on nonsecure displays and in the system task switcher."*

```kotlin
window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
```

When this flag is active on an `Activity`, the system will **display an empty black area** in place of the actual content — whether for the user's manual screenshots, screen recording, display on a non-secure screen (casting/mirroring), **and also** on the Recents screen thumbnail that this test focuses on.

### 1.4 The Most Significant Finding: A Timing Gap That Can Make `FLAG_SECURE` Fail Even When Applied

This is the **most important technical nuance** in this document, and explains why this test is explicitly designed as a **manual dynamic test** (examining actual screenshots) rather than simply verifying the presence of `FLAG_SECURE` code statically. Community research has uncovered a real **race-condition-based** vulnerability:

> *"The core of the issue is that the timing of the system capturing a screenshot for the Recents screen is not guaranteed to be synchronized with the Activity's lifecycle callbacks, specifically `onPause()`. When a user presses the Recents button, the system immediately captures the current screen to prepare for a smooth transition animation and preview. This capture process can occur **before** the app's `onPause()` method is called and completed."*

This means: **a developer who applies `FLAG_SECURE` conditionally inside `onPause()`** (a fairly common pattern — e.g., to show normal content while active but hide it only when about to move to the background) **risks a race condition** in which the system has already taken the screenshot **before** the flag had a chance to be applied. The consequence: **code that appears statically correct** (a call to `FLAG_SECURE` exists in a location that "makes sense") **can still genuinely fail** under certain runtime conditions — this is the fundamental reason why this test **must** be performed dynamically by examining the **actual result** of a stored screenshot, rather than merely a static code audit of the `FLAG_SECURE` call.

**Practical implication for remediation recommendations**: `FLAG_SECURE` should ideally be applied **from `onCreate()` onward** (a permanent state throughout the lifecycle of an Activity displaying sensitive data) rather than being enabled/disabled dynamically in `onPause()`/`onResume()` — an approach far more vulnerable to this timing gap.

### 1.5 Real-World Case: Password Manager Applications

Community research and reports have documented a real-world case that perfectly illustrates the consequence of this failure:

> *"Sensitive data such as the master password and generated passwords were visible in screenshots and in the Android recent apps view, exposing them to other apps with screen capture permissions in real-world password management apps that initially didn't implement `FLAG_SECURE` properly."*

This is a highly ironic and instructive example — **an app whose core purpose is to secure credentials** actually failed to protect the most fundamental layer: its own visual display. A similar case appears in a community-submitted `FLAG_SECURE` fix on an open-source password manager project (`lesspass/lesspass#906`) — demonstrating that this oversight is **not a rare or exotic case**, but rather a fairly common misconfiguration found even in applications with an explicit security purpose.

### 1.6 Content Categories at the Highest Risk

MASTG-BEST-0014 and additional context from industry research highlight the most critical display categories to protect:

- **Credentials**: passwords, PINs, passcodes, master passwords
- **Financial data**: account balances, transaction history, payment card numbers, bank statements
- **One-time authentication codes (OTP)**
- **Personally identifiable information (PII)**: national ID numbers, identity data, health data
- **Keystrokes on custom keyboards/keypads** — a point specifically highlighted by MASTG-BEST-0014: *"Protect on screen keyboards or custom keypad views as they may leak keystrokes from passcode fields"* — even **button-tap animations** on a custom PIN keypad captured at a particular moment can potentially leak a trace of the digit being entered.

### 1.7 A Trade-off Worth Understanding: `FLAG_SECURE` Is a Blunt Instrument

Industry research offers an important note on the limitations of this solution:

> *"It's a blunt instrument that blocks everything, including screenshots and screen recordings that your users might legitimately need."*

`FLAG_SECURE` operates at the level of the **entire Activity window** — there is no built-in mechanism to "hide only part of the display" (e.g., only the card number, leaving other UI elements screenshot-able). This means developers need to carefully consider **Activity granularity** — separating screens that genuinely display highly sensitive data into separate `Activity`/`Fragment` components given `FLAG_SECURE`, rather than applying it blanket-wide across the entire application (which would disrupt legitimate user experience, e.g., a user who wants to screenshot an order history for personal documentation).

---

## 2. Tools Used for Testing

### 2.1 Required Tools (Core)

| Tool | Function |
|---|---|
| **adb** | Extracting screenshot cache files from `/data/system_ce/0/snapshots` or `/data/system` (MASTG-TECH-0002) |
| **Manual visual review** | Mandatory — inspecting every image for the presence of sensitive data, per the `manual` tag on the test type |

### 2.2 Alternative & Supporting Tools

| Tool | Function |
|---|---|
| **scrcpy** | Records/observes screen transitions in real time as the app moves to the background, to visually confirm the moment of failure (the timing gap in §1.4) without needing to extract snapshot files |
| **OCR (Tesseract, etc.)** | For large-scale/automated audits — running OCR on a collection of extracted screenshots to semi-automatically detect patterns of sensitive text (e.g., card number formats, the keyword "password") before a final manual visual verification |
| **Frida** | Hooks `Window.setFlags()`/`Window.addFlags()` to confirm at runtime **exactly when** `FLAG_SECURE` is applied relative to the Activity lifecycle — useful for diagnosing cases where `FLAG_SECURE` is applied "too late" (§1.4) |

### 2.3 Environment Prerequisites

- **A device/emulator is required** — this is a purely dynamic test.
- **Root is required** to directly access the system directories `/data/system_ce/0/snapshots`/`/data/system` (outside the normal app sandbox).
- **Identify sensitive screens first** (the `identify-sensitive-screens` prerequisite) — mapping which app flows display credentials/financial data/PII before beginning systematic testing.
- **Test various background-trigger mechanisms**, not just the Home button — per the official steps: the Home button **and** opening the Recents screen then exiting again — both can trigger slightly different capture behavior depending on the system/vendor implementation.

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Navigate through the application until reaching each screen identified as sensitive. On each such screen, move the app to the background (e.g., pressing Home or opening the Recents screen then exiting), then proceed to the next screen.
2. Use **MASTG-TECH-0002** to copy the screenshots captured by the system to a laptop for further analysis.

### 3.2 Method A — Extraction and Manual Visual Review *(the primary official method)*

```bash
# Root is required to access the system directories
adb root
adb shell "ls /data/system_ce/0/snapshots/"
adb pull /data/system_ce/0/snapshots/ ./snapshots_extracted/

# Alternative location depending on Android version
adb shell "ls /data/system/"
adb pull /data/system/ ./system_extracted/ 2>/dev/null
```

```bash
# Review each image file visually
for img in ./snapshots_extracted/*; do
    echo "=== $img ==="
    # Open with an image viewer or run OCR (Method C)
done
```

For each identified sensitive screen (prerequisite), perform the cycle: open the screen → background via Home → note the time → background via Recents → note the time → extract and compare the corresponding snapshot results.

### 3.3 Method B — scrcpy for Real-Time Observation of the Timing Gap

```bash
scrcpy --record=recording.mp4
```

While recording, repeatedly trigger the transition to the background on a sensitive screen (ideally with varied interaction speed/timing) to visually observe whether there is a **transition frame** in which sensitive content is briefly visible before the `FLAG_SECURE` black area appears — direct visual evidence of the timing gap described in §1.4.

### 3.4 Method C — OCR for Automated Triage in Large-Scale Audits

```bash
for img in ./snapshots_extracted/*.png; do
    tesseract "$img" - | grep -iE "password|pin|card|balance|token|ssn" && echo "  -> found in: $img"
done
```

This is a **supplementary** method to speed up triage on apps with a very large number of screens — but it **does not replace** the full manual visual review required by the official "Further Validation Required" clause, since OCR cannot detect non-textual visual leaks (e.g., a photo of an ID card, a photo of a physical credit card, an avatar/name displayed as an image).

### 3.5 Method D — Frida for Diagnosing `FLAG_SECURE` Timing

```javascript
// hook-flag-secure-timing.js
Java.perform(function () {
    var Window = Java.use("android.view.Window");
    Window.setFlags.overload("int", "int").implementation = function (flags, mask) {
        var FLAG_SECURE = 0x00002000;
        if ((flags & FLAG_SECURE) !== 0) {
            console.log("[*] FLAG_SECURE applied at: " + new Date().toISOString());
            console.log("    Stack:\n" + Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
        }
        return this.setFlags(flags, mask);
    };

    var Activity = Java.use("android.app.Activity");
    Activity.onPause.implementation = function () {
        console.log("[*] onPause() called at: " + new Date().toISOString());
        return this.onPause();
    };
});
```

```bash
frida -U -f com.target.app -l hook-flag-secure-timing.js --no-pause
```

Compare the `FLAG_SECURE` timestamp against `onPause()` — if `FLAG_SECURE` is applied **inside** `onPause()` (rather than earlier, e.g., in `onCreate()`), this directly confirms the timing-gap risk described in §1.4.

### 3.6 Method Comparison: Which One to Use When

| Method | Tool | Advantage | When to use |
|---|---|---|---|
| **A** | adb pull + manual review | Definitive evidence per the official clause | **Mandatory**, primary method |
| **B** | scrcpy recording | Direct visual observation of the timing gap | Diagnosing "almost worked" `FLAG_SECURE` cases |
| **C** | Automated OCR | Fast triage across many screens | Supplementary, not a replacement for manual review |
| **D** | Frida timing hook | Diagnosing the technical root cause | Explaining WHY a screen FAILS |

**Minimum recommended combination:** **A (mandatory, per the official clause) → D (if a FAIL is found, to diagnose the timing root cause) → B (additional visual confirmation if needed)**.

---

### 3.7 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rule:**

> **Observation:** *"The output should include a collection of screenshots cached when the app entered the background state."*
>
> **Evaluation:** *"The test case fails if any screenshot displays sensitive data that should have been protected."*

With a mandatory **Further Validation Required** clause: *"Inspect each screenshot visually, looking for sensitive information such as passwords, tokens, personally identifiable information, or other sensitive content."*

---

#### ❌ FAIL / ISSUE — The check is declared FAILED when:

| No | Condition |
|---|---|
| F1 | An extracted screenshot cache clearly displays readable sensitive data (credentials, tokens, PII, financial data) |
| F2 | A screen with a custom PIN/password keypad/keyboard shows a visual trace of user input at the moment of capture |
| F3 | `FLAG_SECURE` is found applied in the code (supporting static analysis), yet still FAILS dynamically due to the timing gap (§1.4) — confirmed by Method D showing `FLAG_SECURE` applied after/concurrent with `onPause()`, not earlier |

**Example evidence (illustrative — MASTG does not yet provide an official demo for this test):**

```bash
$ adb pull /data/system_ce/0/snapshots/ ./snapshots_extracted/
$ ls ./snapshots_extracted/
com.example.target_task5.png

# Visual review: the image displays the "Payment Confirmation" screen
# with the full card number "4532 **** **** 1234" and the "Pay Rp 5,000,000" button clearly visible
```

Interpretation: a payment screen that should be sensitive was fully captured without protection — a **critical FAIL**.

---

#### ✅ PASS — The check is declared PASSED when:

| No | Condition |
|---|---|
| P1 | A screenshot for a sensitive screen shows an **empty black area** (indicating `FLAG_SECURE` is working correctly) |
| P2 | Method D confirmation shows `FLAG_SECURE` applied **from `onCreate()` onward** (a permanent state), not conditionally in `onPause()` — eliminating the timing-gap risk |
| P3 | Screenshots for non-sensitive screens (outside the prerequisite's scope) still display normally — confirming `FLAG_SECURE` is applied **precisely where needed** (not applied excessively across the entire app in a way that could disrupt legitimate UX, §1.7) |

---

#### ⚠️ Important Notes on the Assessment

1. **A static code audit of `FLAG_SECURE` alone is NOT SUFFICIENT** — this is the most important lesson of this document. Per §1.4, textually correct code can still fail at runtime due to a race-condition timing gap. Dynamic verification with actual screenshots is the only way to confirm the protection genuinely works.

2. **Test ALL background-trigger mechanisms**, not just one way — the Home button and the Recents screen can trigger different capture behavior depending on the Android version/vendor.

3. **Pay special attention to the capture moment for custom keypads/keyboards** (§1.6) — this is a risk category that is easily missed because an audit's focus is usually on "static" data displays (e.g., a transaction list), not an input interaction in progress.

4. **Root is required for direct access to the system snapshot directories** — if a rooted device is not available, consider an alternative approach of taking a manual screenshot at the moment of background transition (less precise than extracting the real system cache, but can still provide an initial indication).

5. **Do not recommend applying `FLAG_SECURE` blanket-wide across the entire app** (§1.7) — consider per-Activity/Fragment granularity to balance security against legitimate user experience.

6. **Severity is modulated as follows:**

   | Factor | Severity |
   |---|---|
   | Credentials/financial data/OTP clearly visible in a screenshot | **Critical** |
   | PII (name, address) visible without other highly sensitive data | **Medium** |
   | PIN keypad keystrokes partially captured | **High** |
   | A non-sensitive screen screenshotted normally (outside the prerequisite's scope) | **Not a finding** |

7. **Document:** the list of sensitive screens tested, the background-trigger mechanism used per screen, the visual result of each screenshot (redacted if needed for the report), and the result of timing diagnosis (Method D) if a FAIL was found.

---

## 4. Recommendations

### 4.1 Apply `FLAG_SECURE` from `onCreate()` Onward (Avoiding the Timing Gap)

```kotlin
class PaymentConfirmationActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )  // Applied BEFORE any content is rendered, not in onPause()
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_payment_confirmation)
    }
}
```

### 4.2 Separate Sensitive Screens into Distinct Activities/Fragments for Granularity

Avoid applying `FLAG_SECURE` globally at the `Application` level — apply it specifically only to the Activity that genuinely displays sensitive data, per the mapping results from the `identify-sensitive-screens` prerequisite.

### 4.3 Specifically Protect Custom Keypads/Keyboards

For custom PIN/password input components (not a standard `EditText`), ensure `FLAG_SECURE` is active from the start on the Activity/Dialog containing it, and consider disabling visual button-tap feedback animations that could leak a trace of the digit pressed.

### 4.4 Integrate Verification into Regression Testing

```bash
#!/bin/bash
# ci-check-flag-secure-screenshots.sh
adb shell am start -n com.target.app/.PaymentConfirmationActivity
sleep 2
adb shell input keyevent KEYCODE_HOME
sleep 1
adb root
adb pull /data/system_ce/0/snapshots/ ./ci_snapshots/
# Automated verification: the image file should be dominated by solid black (simple heuristic)
```

### 4.5 Remediation Checklist

- [ ] All sensitive screens from the prerequisite mapping have been tested with real screenshot extraction
- [ ] `FLAG_SECURE` is applied from `onCreate()` onward, not conditionally in `onPause()`
- [ ] Custom keypads/keyboards for PIN/password are explicitly protected
- [ ] Timing diagnosis (Frida) has been performed for every FAIL finding to confirm the root cause
- [ ] `FLAG_SECURE` is applied with appropriate granularity (per sensitive Activity, not globally)
- [ ] **Re-verify:** re-run MASTG-TEST-0289 whenever a new screen displaying sensitive data is added

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0289: Runtime Verification of Sensitive Content Exposure in Screenshots During App Backgrounding](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0289/)
- [MASWE-0038: Insufficient Protection of Sensitive Data from Screenshots or Screen Recordings](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0038/)
- [MASTG-BEST-0014: Preventing Screenshots and Screen Recording](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0014/)
- [MASTG-TECH-0002: Retrieving Files from Device Storage](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0002/)

### 5.2 Official Android Documentation

- [Android Developers — Secure Sensitive Activities (Fraud Prevention)](https://developer.android.com/security/fraud-prevention/activities)
- [Android Developers — `FLAG_SECURE` reference](https://developer.android.com/security/fraud-prevention/activities#flag_secure)
- [Android Developers — Recents Screen (Overview)](https://developer.android.com/guide/components/activities/recents)
- [Google Play Console Help — FLAG_SECURE and REQUIRE_SECURE_ENV](https://support.google.com/googleplay/android-developer/answer/14638385?hl=en)

### 5.3 Research and Real-World Cases

- [Medium — Handling the Recents Screen with FLAG_SECURE (the onPause timing gap)](https://kimmandoo.medium.com/handling-the-recents-screen-with-flag-secure-bd13f70ada0e)
- [GitHub lesspass/lesspass#906 — Fix: add FLAG_SECURE to prevent screenshots and recent apps exposure](https://github.com/lesspass/lesspass/pull/906)
- [Ostorlab — Understanding Android's FLAG_SECURE for Screen Security](https://blog.ostorlab.co/understanding-android-flag-secure-screen-security.html)
- [Medium — Stop Using FLAG_SECURE: A Better Way to Protect Sensitive Screens in Jetpack Compose](https://medium.com/pickme-engineering-blog/stop-using-flag-secure-heres-a-better-way-to-protect-sensitive-screens-in-jetpack-compose-bf03fc853674)
- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
- [CWE-311: Missing Encryption of Sensitive Data](https://cwe.mitre.org/data/definitions/311.html)

### 5.4 Tool Documentation

- [scrcpy — Display and control Android devices](https://github.com/Genymobile/scrcpy)
- [Tesseract OCR](https://github.com/tesseract-ocr/tesseract)
- [Frida — Dynamic instrumentation toolkit](https://frida.re/docs/javascript-api/)

---

*This document was prepared based on OWASP MASTG (current release as of September 2026), official Android Developers documentation, and community research and real-world cases (including a vulnerability in a password manager application) regarding data leakage via Recents screen screenshots. The most significant finding: `FLAG_SECURE` applied conditionally in `onPause()` is vulnerable to a **race-condition timing gap** — the system can take a screenshot before that flag has a chance to be applied, because the capture is not guaranteed to be synchronized with the Activity lifecycle. This is the fundamental reason why this test is designed as a dynamic test examining real visual evidence, rather than merely a static code audit of `FLAG_SECURE`'s presence.*
