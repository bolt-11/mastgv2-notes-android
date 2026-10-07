# MASTG-TEST-0315 Sensitive Data Exposed via Notifications

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0315 |
| **Platform** | Android |
| **MASVS Category** | MASVS-PLATFORM (MASVS-PLATFORM-3) |
| **Weakness** | MASWE-0037 — *Unnecessary Exposure of Sensitive Data via Notifications* |
| **API Highlighted** | `NotificationManager`, `Notification.Builder`/`NotificationCompat.Builder` (`setContentTitle`, `setContentText`) |
| **Test Type** | Static, Code |
| **Prerequisite** | `identify-sensitive-data` |
| **Best Practice** | MASTG-BEST-0027 (Preventing Sensitive Data Exposure in Notifications — placeholder status) |
| **Related Techniques** | MASTG-TECH-0013, MASTG-TECH-0014, MASTG-TECH-0117, MASTG-TECH-0150, MASTG-TECH-0126 |
| **Related Demo** | — (none) |
| **Official Rule** | `mastg-android-sensitive-data-in-notifications.yml` — only detects the presence of `setContentTitle`/`setContentText`, does not assess the content (a pattern consistent with several other inventory-style rules in this research series) |
| **Related CWE** | CWE-200, CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor) |

---

## 1. Explanation

### 1.1 Testing Objective

Official MASTG overview excerpt:

> *"This test verifies that the app correctly handles notifications, ensuring that sensitive information, such as personally identifiable information (PII), one-time passwords (OTPs), or other sensitive data, like health or financial details, is not exposed."*

Android notifications are a **unique** data leakage surface compared to most other vectors in this research series — they are **deliberately designed to be visible** to anyone near the device, **including when the device is locked** (lock screen). This creates a *"shoulder surfing"* risk explicitly named by the official overview: *"Notification usage should not expose sensitive information that could be disclosed accidentally, e.g., through shoulder surfing or when sharing the device with another person."*

### 1.2 Real-World Risk Context: OTP on the Lock Screen

This is a case **very commonly experienced** by real users and is the most iconic example of this test's risk — community user reports explicitly complain:

> *"OTP is received on the lock screen and is clearly visible to others, which violates security — the received OTP message tells users not to share the OTP, but in this case it could be seen by anyone who glances at the device."*

The irony of this case is quite sharp: the OTP message itself usually **explicitly warns** the user not to share that code with anyone — yet **the notification that displays the code in full on the lock screen** essentially **shares it** with anyone who glances at the device screen, without needing to unlock it or have any access to the app at all.

### 1.3 Current Platform Response: Android 16 Automatically Redacts OTPs

This is very relevant and current context — Google itself **acknowledges this problem is significant enough in scale** to have built a platform-level mitigation:

> *"Android 16 will automatically redact the contents of notifications containing one-time passwords (OTPs) from the lock screen in higher risk scenarios, such as when a user's device is not connected to Wi-Fi and has not been recently unlocked."*

The fact that Google felt the need to build **automatic heuristic-based detection** (detecting text patterns resembling an OTP and automatically masking them) as a platform feature — instead of fully relying on application developers to implement correct practices — is an **implicit acknowledgment** that this vulnerability class is **very common** across the Android application ecosystem broadly, significant enough to justify platform-level engineering investment. Nevertheless, this automatic mitigation **cannot be relied upon as the sole defense** — it is only active in certain "higher risk scenarios" (device not connected to Wi-Fi and not recently unlocked) and is only available starting with Android 16, so it **remains the developer's responsibility** not to display sensitive data in notifications in the first place, across all Android versions the app supports.

### 1.4 Additional Risk Vector: `NotificationListenerService` and OTP Theft by Malware

Beyond the physical *shoulder surfing* risk, there is a **digital** attack vector that is relevant as additional context: an Android app granted **notification access** (`NotificationListenerService`, a permission requested by the user via Settings, commonly used by legitimate apps like smartwatch companion apps) can **read all notifications** that appear on the device — including OTP notifications from other apps. This is a technique that is **actively exploited by malware** to automatically steal banking OTP codes without needing phishing or any user interaction at all. Although mitigation for this specific vector (restricting which apps are allowed to read notifications) is beyond the direct control of the application developer **sending** the notification, this remains relevant as context reinforcing **why** not displaying the full OTP in the notification in the first place is a far stronger defense than relying on the user to correctly manage third-party app permissions.

### 1.5 Crucial Nuance: Why the Evaluation Uses `minSdkVersion`, Not `targetSdkVersion`

This is the **most methodologically important** part of this test, and the official overview gives the **most explicit and clear** explanation among all tests in this research series that have discussed a similar nuance (compare with the more implicit discussion in the MASTG-TEST-0245/0252/0285 documents):

> *"Why `minSdkVersion` and not `targetSdkVersion`?: Using `minSdkVersion` ensures the test accounts for the **least secure environment** in which the app can operate, which is what determines the real exposure risk. `targetSdkVersion` only influences how the app behaves on newer Android versions and how the system enforces newer platform restrictions. It does not change the behavior of older Android versions. As a result, an app with a high `targetSdkVersion` but a low `minSdkVersion` must still be evaluated against the security guarantees, or lack thereof, of those older versions."*

Concrete context for this test: starting with **Android 13 (API 33)**, apps targeting that API are **required to request** the `POST_NOTIFICATIONS` runtime permission before they can send notifications at all — this permission gives users **explicit control** to refuse notifications from a specific app entirely. However, **below API 33**, notifications are **always allowed by default** without needing any explicit user consent at all. This means the **user population** running the app on devices with API below 33 **has no control** over whether notifications (including those containing sensitive data) will appear or not — the only remaining defense is for **developers not to place sensitive data in notifications in the first place**. This is why `minSdkVersion` — which determines the **worst-case device population** that can run the app — becomes the relevant parameter to evaluate, not `targetSdkVersion`, which only affects behavior on newer Android versions.

### 1.6 Precise FAIL Condition Formulation Based on `minSdkVersion`

The official Evaluation clause gives a precise condition formulation, combining the sensitive-data finding with two different `minSdkVersion` scenarios:

> *"The test case fails if the app exposes any sensitive data in any notifications **and** either:*
> - *`minSdkVersion` is `33` or higher and the `POST_NOTIFICATIONS` permission is declared in the manifest file, or*
> - *`minSdkVersion` is `32` or lower, regardless of whether the `POST_NOTIFICATIONS` permission is declared."*

Note the **logical asymmetry** between the two condition branches:

| `minSdkVersion` Scenario | Additional Condition Required for FAIL |
|---|---|
| **≥ 33** | A `POST_NOTIFICATIONS` declaration in the manifest **must** be present (if not declared, the app **cannot** send notifications at all on that device population — the point becomes moot) |
| **≤ 32** | It **does not matter** whether `POST_NOTIFICATIONS` is declared or not — notifications will still be sendable by default on that device population |

This asymmetry is **logically consistent** with §1.5 — on API 33+ devices, the presence of the runtime permission gives a **relevant signal** to check (without that permission, notifications cannot appear at all, making the risk of sensitive data in notifications practically moot on that population); on API 32-and-below devices, there is **no user control mechanism** at all, so the presence of a permission declaration is entirely irrelevant for evaluation — notifications will still appear regardless of what is declared in the manifest.

---

## 2. Tools Used for Testing

### 2.1 Required Tools (Core)

| Tool | Function |
|---|---|
| **jadx** | DEX → Java decompilation for finding `setContentTitle`/`setContentText` patterns |
| **grep / ripgrep** | API pattern search and verification of the content passed |
| **semgrep** | Running the official rule as a location baseline |
| **aapt2 / apkanalyzer** | Extraction of `minSdkVersion` and the `POST_NOTIFICATIONS` declaration status |

### 2.2 Alternative & Supporting Tools

| Tool | Function |
|---|---|
| **CodeQL** | Traces whether the variable passed to `setContentText`/`setContentTitle` originates from a known sensitive source (field named `otp`, `password`, financial API response results, etc.) |
| **Frida** | Hooking `Notification.Builder.setContentText()`/`setContentTitle()` to capture the **actual** value displayed at runtime, including cases where the text is built dynamically and is hard to analyze statically |
| **MobSF** | Sometimes shows `NotificationManager` usage in the Code Analysis report |

### 2.3 Environment Prerequisites

- **No device/root required** for core static analysis.
- **Extracting `minSdkVersion` and the `POST_NOTIFICATIONS` status is a required first step** (§1.6) — the FAIL/PASS evaluation cannot be determined without both pieces of information.
- **Identify sensitive data first** (the `identify-sensitive-data` prerequisite) to determine which types of notification content are relevant to check.

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0013** to reverse engineer the application.
2. Use **MASTG-TECH-0014** to find relevant APIs.
3. Use **MASTG-TECH-0117** to obtain `AndroidManifest.xml`.
4. Use **MASTG-TECH-0150** to obtain `minSdkVersion`.
5. Use **MASTG-TECH-0126** to obtain the relevant permissions (`POST_NOTIFICATIONS`).

### 3.2 Method A — Official Semgrep Rule + Manual Context Verification

```yaml
rules:
  - id: mastg-android-sensitive-data-in-notifications
    languages: [java]
    severity: WARNING
    message: "[MASVS-PLATFORM-3] Ensure that notifications do not contain sensitive information"
    pattern-either:
      - pattern: $X.setContentTitle(...)
      - pattern: $X.setContentText(...)
```

```bash
semgrep --config https://raw.githubusercontent.com/OWASP/mastg/master/rules/mastg-android-sensitive-data-in-notifications.yml ./decompiled/sources/
```

**Note about this rule**: consistent with the pattern consistently found in other "location-inventory" rules elsewhere in this research series, this rule **only detects the presence** of the call — it does not assess whether the content passed is actually sensitive. Content verification must still be done manually or via Method B/C.

```bash
jadx --no-src -d ./out target-app.apk
grep -oP 'minSdkVersion="\K[0-9]+' ./out/resources/AndroidManifest.xml
grep -i "POST_NOTIFICATIONS" ./out/resources/AndroidManifest.xml
```

### 3.3 Method B — grep/ripgrep with Content Verification

```bash
D=./decompiled/sources

rg -n -B5 'setContentText\(|setContentTitle\(' $D | grep -iE "otp|password|token|balance|account|ssn|pin" -B5
```

### 3.4 Method C — CodeQL for Sensitive Data Source Correlation

```ql
import java

class NotificationContentCall extends MethodAccess {
  NotificationContentCall() {
    this.getMethod().hasName(["setContentText", "setContentTitle"])
  }
}

from NotificationContentCall call, Variable v
where v.getName().toLowerCase().regexpMatch(".*(otp|password|token|pin|balance|account|ssn).*") and
      call.getAnArgument() = v.getAnAccess()
select call, "Notification content originates from a sensitively-named variable: " + v.getName()
```

### 3.5 Method D — Frida for Runtime Confirmation

```javascript
// hook-notification-content.js
Java.perform(function () {
    var Builder = Java.use("android.app.Notification$Builder");
    Builder.setContentText.overload("java.lang.CharSequence").implementation = function (text) {
        console.log("[*] setContentText: " + text);
        return this.setContentText(text);
    };
    Builder.setContentTitle.overload("java.lang.CharSequence").implementation = function (title) {
        console.log("[*] setContentTitle: " + title);
        return this.setContentTitle(title);
    };
});
```

### 3.6 Method Comparison: When to Use Which

| Method | Tool | Assesses content? | When to Use |
|---|---|---|---|
| **A** | Official semgrep rule + manifest extraction | ❌ (location only) | Required baseline |
| **B** | grep context | Manual | Quick verification |
| **C** | CodeQL | ✅ (variable-name heuristic) | Large codebases |
| **D** | Frida | ✅ (actual runtime value) | Definitive confirmation, including dynamic content |

**Minimum combination I recommend:** **A (mandatory minSdkVersion/POST_NOTIFICATIONS extraction) → C/D (content verification) → apply the evaluation formula in §1.6**.

---

### 3.7 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rule** (refer to §1.6 for a full explanation of the logic).

---

#### ❌ FAIL / ISSUE — The check is declared FAILED if:

| No | Condition |
|---|---|
| F1 | Sensitive data (OTP, PII, financial/health data) is found in `setContentText`/`setContentTitle`, **AND** (`minSdkVersion` ≥33 with `POST_NOTIFICATIONS` declared) **OR** (`minSdkVersion` ≤32, regardless of permission status) |

**Example evidence (illustrative — MASTG has not yet provided an official demo for this test):**

```java
notificationBuilder.setContentTitle("Your OTP Code")
    .setContentText("Verification code: " + otpCode);  // FULL OTP displayed in the notification
```

```bash
$ grep -oP 'minSdkVersion="\K[0-9]+' AndroidManifest.xml
23
```

Interpretation: `minSdkVersion=23` (≤32) — a notification containing the full OTP will always appear with no user control whatsoever on the entire device population the app supports. **FAIL**, exactly the pattern complained about by real users (§1.2).

---

#### ✅ PASS — The check is declared PASSED if:

| No | Condition |
|---|---|
| P1 | The notification does not display any sensitive data at all (e.g., "You have a new verification code" without including the code itself) |
| P2 | `minSdkVersion` ≥33 **and** `POST_NOTIFICATIONS` is **not** declared (notifications cannot possibly be sent to that device population) |
| P3 | The sensitive data displayed is masked (e.g., `setVisibility(VISIBILITY_PRIVATE)` combined with generic public content, hiding details only on the lock screen) |

---

#### ⚠️ Important Notes on Evaluation

1. **Apply the §1.6 formula precisely** — do not conclude FAIL/PASS without first extracting `minSdkVersion` and the `POST_NOTIFICATIONS` status; both condition branches have different logic.

2. **The official rule only finds the location, not the sensitivity assessment** — content verification is still absolutely required.

3. **Leverage `setVisibility(VISIBILITY_PRIVATE)` as a partial mitigation** — if sensitive data truly must be displayed in the notification body for UX needs, at least hide that detail from the lock screen while still showing a generic notification.

4. **Do not rely solely on Android 16's automatic mitigation** (§1.3) — this feature is new, limited to certain scenarios, and does not apply to older Android versions that may still make up a significant portion of the app's user base.

5. **Severity is modulated:**

   | Factor | Severity |
   |---|---|
   | Full OTP/credentials in notification, low `minSdkVersion` | **High** |
   | PII (name, partial number) in notification | **Medium** |
   | Generic notification without sensitive data | **Not a finding** |

6. **Document:** the code location where the notification is created, the content found, `minSdkVersion`, the `POST_NOTIFICATIONS` status, and the result of applying the §1.6 evaluation formula.

---

## 4. Recommendations

### 4.1 Avoid Displaying Sensitive Data Directly

```java
// BEFORE
.setContentText("Verification code: " + otpCode)

// AFTER
.setContentText("You have a new verification code. Open the app to view it.")
```

### 4.2 Use `setVisibility(VISIBILITY_PRIVATE)` as an Additional Layer

```java
Notification notification = new Notification.Builder(context, channelId)
    .setContentTitle("New Transaction")
    .setContentText("$500.00 has been transferred")
    .setVisibility(Notification.VISIBILITY_PRIVATE)  // Details hidden on the lock screen
    .setPublicVersion(genericNotification)  // Generic version displayed on the lock screen
    .build();
```

### 4.3 Remediation Checklist

- [ ] All notification creation is inventoried and its content checked
- [ ] Sensitive data (OTP, credentials, PII, financial data) is not displayed directly in `setContentText`/`setContentTitle`
- [ ] `setVisibility(VISIBILITY_PRIVATE)` is applied for notifications that still contain some sensitive info
- [ ] `minSdkVersion` and the `POST_NOTIFICATIONS` status are documented as evaluation context
- [ ] **Re-verify:** re-run MASTG-TEST-0315 whenever a new notification type is added

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0315: Sensitive Data Exposed via Notifications](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0315/)
- [MASWE-0037: Unnecessary Exposure of Sensitive Data via Notifications](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0037/)
- [MASTG-BEST-0027: Preventing Sensitive Data Exposure in Notifications](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0027/)
- [MASTG-TEST-0245: References to Platform Version APIs](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0245/) — related discussion of the minSdkVersion nuance

### 5.2 Official Android Documentation

- [Android Developers — `POST_NOTIFICATIONS` permission](https://developer.android.com/reference/android/Manifest.permission#POST_NOTIFICATIONS)
- [Android Developers — `Notification.Builder`](https://developer.android.com/reference/android/app/Notification.Builder)
- [Android Developers — `Notification.Builder#setVisibility()`](https://developer.android.com/reference/android/app/Notification.Builder#setVisibility(int))

### 5.3 Research and Real-World Cases

- [OnePlus Community — OTP is received on lock screen and is clearly visible to others](https://community.oneplus.com/threads/otp-is-received-on-lock-screen-and-is-clearly-visible-to-others-which-violates-security.1083459/)
- [Android Authority — Android 16 automatically hides some sensitive notifications from the lock screen](https://www.androidauthority.com/android-16-sensitive-notifications-lock-screen-3501564/)
- [Android Police — Android 16 makes a subtle change to keep your OTPs safe](https://www.androidpolice.com/android-16-subtle-change-keeps-otps-safe/)
- [Android Police — Android 15 could stop apps from spying on your most sensitive notifications](https://www.androidpolice.com/android-15-stop-malware-from-stealing-otps/)
- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
- [CWE-359: Exposure of Private Personal Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/359.html)

### 5.4 Tool Documentation

- [Semgrep — Documentation](https://semgrep.dev/docs/)
- [CodeQL — Documentation](https://codeql.github.com/docs/)
- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [Frida — Dynamic instrumentation toolkit](https://frida.re/docs/javascript-api/)

---

*This document is compiled based on OWASP MASTG (current release as of September 2026), official Android Developers documentation, and community research and media reports about OTP leakage via lock screen notifications — including Android 16's current platform response, which built automatic detection for this problem. The most important methodological nuance: this test gives the most explicit explanation among all tests in this research series for why `minSdkVersion` (not `targetSdkVersion`) is the correct evaluation parameter — because it reflects the "least secure device population" that can run the app, which determines the real exposure risk, whereas `targetSdkVersion` only affects behavior on newer Android versions.*
