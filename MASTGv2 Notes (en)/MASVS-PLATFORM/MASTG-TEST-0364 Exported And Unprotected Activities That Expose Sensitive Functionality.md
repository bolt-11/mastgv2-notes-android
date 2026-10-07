# MASTG-TEST-0364 Exported And Unprotected Activities That Expose Sensitive Functionality

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0364 |
| **Platform** | Android |
| **MASVS Category** | MASVS-PLATFORM |
| **Weakness** | MASWE-0018 |
| **Test Type** | Static, Config, Code, **Manual** |
| **Related Techniques** | MASTG-TECH-0013, MASTG-TECH-0117 (Obtain Manifest), MASTG-TECH-0160 (Enumerating Activities), MASTG-TECH-0014, MASTG-TECH-0023 |
| **Related Knowledge** | MASTG-KNOW-0132 (Android Activities), MASTG-KNOW-0017 (App Permissions), MASTG-KNOW-0020 (IPC Mechanisms) |
| **Related Best Practice** | MASTG-BEST-0052 (Restrict Access to Android App Components) |
| **Official rule** | — (no dedicated Semgrep rule; this test is purely manual, consistent with its contextual nature) |

---

## 1. Explanation

### 1.1 Testing Objective

Quote from the official MASTG overview:

> *"If an exported activity does not define `android:permission` with a proper protection level and performs or grants access to sensitive functionality, another third-party app outside the intended trust boundary can start it with an Intent and reach that functionality without going through the app's intended flow."*

The key phrase here is **"without going through the app's intended flow"** — this is the core of this entire vulnerability class. An Activity, as part of the Android IPC model (MASTG-KNOW-0020), can be **started directly** by another app component via `Intent`, **skipping** the entire normal navigation flow the developer designed (e.g. splash screen → login → PIN verification → dashboard). If `DashboardActivity` is exported without protection, an attacker doesn't need to go through the login step at all — simply calling `startActivity()` with the target component name directly is enough.

### 1.2 Access Control Mechanism and the Important Change in Android 12+

MASTG-KNOW-0132 explains three interacting layers of access control:

> *"`android:exported`: when true, components of other apps can start the activity... The default is false when an activity has no intent filters."*
>
> *"Historically, activities with intent filters and no explicit android:exported value could become reachable by other apps on older target SDK versions... apps targeting Android 12 (API level 31) or higher must set android:exported explicitly on activities with intent filters, or the app fails to install."*

This Android 12 change is important for historical context — before this rule was enforced, **many apps unintentionally exported an activity** simply because it had an `<intent-filter>`, without the developer realizing that this automatically made it exported on older target SDKs. A developer who tests their app only on an older/intermediate Android version might never notice this unwanted exported status until the app is audited specifically.

Another important point from MASTG-KNOW-0132: *"Intent filters are not an access-control mechanism; use android:exported and permissions to control which external callers can start an activity."* — this corrects a common developer misconception that adding validation inside the `<intent-filter>` (action/category/data) alone is sufficient as a security control; an intent filter only governs **routing**, not **authorization**.

### 1.3 Three "Sensitive" Criteria at the Core of the Evaluation

The official evaluation gives three concrete categories for assessing whether an activity "exposes sensitive functionality":

> *"Determine whether the activity displays or returns sensitive data (for example, account details, messages, or stored secrets). Determine whether the activity performs a security-relevant action (for example, changing settings or credentials). Determine whether starting the activity directly bypasses an authentication step, such as a login or PIN screen, that the app relies on elsewhere."*

The third category — **authentication bypass** — is the one most frequently seen in real-world cases (§1.5) and the easiest to verify dynamically: simply call the activity directly and observe whether the displayed screen is the post-login screen, or still asks for credentials.

### 1.4 Advanced Evaluation Nuance: The Question "Does It Really Need to Be Exported" Precedes "Is Its Permission Adequate"

The official further-validation structure has an important logical order:

> *"Determine whether the activity has a legitimate reason to be started by third-party apps. If it doesn't, it shouldn't be exported."*

Only after that:

> *"If external access is required, determine whether the activity is protected by an appropriate android:permission or an equivalent access control... Verify that the permission is effective for that trust boundary, for example by using a signature protection level or another control that is not broadly grantable to untrusted apps."*

MASTG-BEST-0052 reinforces a crucial point that aligns with a principle already discussed repeatedly in this research series (TEST-0326, TEST-0355): *"Do not treat the presence of android:permission as sufficient by itself: a broadly grantable protection level (normal or dangerous) may still allow untrusted apps to invoke sensitive components."* — this confirms that this test's evaluation **does not stop** at "does a permission attribute exist," but must trace through to the `protectionLevel` of the referenced permission (per the full risk table in MASTG-KNOW-0017).

### 1.5 Concrete Evidence: Two Classic Cases of Login Bypass via Exported Activity

Two cases from pentest community research illustrate the exact threat scenario of the third category in §1.3, concretely:

> *"Trustwave documented a messaging app built for internal company use where the app's manifest exported activities that allowed logging in directly to the messaging system without credentials, allowing access to all messages."*

And a classic case from a popular example app in the mobile pentest world:

> *"In Sieve.apk (a password manager), the FileSelectActivity had 'exported' set to 'true,' allowing outside access, and researchers were able to trigger the activity and successfully bypass the login screen without entering credentials."*

Both cases show the same pattern: a **post-login activity** (a message dashboard, an activity displaying password-manager files) that turned out to be reachable **without ever going through the login activity** at all, because that activity was exported independently and did not verify the user's own session status when opened directly. An exploitation note relevant to understanding severity:

> *"The simplest exploit is launching an exported Activity directly via ADB, and an attacker with physical access to a device or a malicious app installed on the same device could silently invoke this."*

The phrase *"silently invoke this"* is important — a malicious app installed on the same device **does not require any conspicuous user interaction** to trigger this bypass; simply calling `startActivity()` with an explicit `Intent` in the background is enough.

---

## 2. Tools Used for Testing

### 2.1 Required Tools (Core)

| Tool | Function |
|---|---|
| **aapt2 / xmlstarlet** | Enumeration of exported activities along with their permissions from the manifest (MASTG-TECH-0160) |
| **jadx** | Review of the activity's implementation code to assess the sensitivity of its functionality (MASTG-TECH-0014, MASTG-TECH-0023) |

### 2.2 Alternative & Supporting Tools

| Tool | Function |
|---|---|
| **ADB (`am start`)** | The most direct dynamic verification — explicitly calling the activity to observe whether the bypass actually occurs |
| **Drozer** | Automated enumeration of exported activities (`app.activity.info`) and launching with intent-crafting assistance (`app.activity.start`) |
| **`adb shell dumpsys package`** | Inspection of the activity resolver table on a device/emulator for runtime confirmation |

### 2.3 Environment Prerequisites

- Static manifest analysis does not require a device/root.
- Dynamic verification (ADB/Drozer) requires a device/emulator with the target application installed.

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0013** to reverse engineer the application.
2. Use **MASTG-TECH-0117** to obtain the `AndroidManifest.xml`.
3. Use **MASTG-TECH-0160** to list exported activities along with their `android:permission`.
4. Use **MASTG-TECH-0014** to examine the code of each exported activity.

### 3.2 Method A — Manifest Enumeration with xmlstarlet

```bash
xmlstarlet sel -t -m "//activity | //activity-alias" \
  -v "name()" -o " name=" -v "@android:name" \
  -o " exported=" -v "@android:exported" \
  -o " permission=" -v "@android:permission" \
  -o " intent_filters=" -v "count(intent-filter)" -n \
  AndroidManifest.xml
```

### 3.3 Method B — Enumeration with aapt2

```bash
aapt2 d xmltree app.apk --file AndroidManifest.xml | grep -A20 -E "E: activity|E: activity-alias"
```

### 3.4 Method C — Code Review to Assess Sensitivity (Mandatory, Per MASTG-TECH-0023)

For each exported activity without a permission identified from Method A/B:

1. Check `onCreate()` — is there any session/login status check before content is displayed?
2. Check whether the activity displays data from a source that requires authentication (local database, API results that require a session token) without re-validation.
3. Identify whether the activity performs an action that changes a security state (change PIN, account settings) directly from `onCreate()`/`onResume()` without prerequisites.

### 3.5 Method D — Dynamic Verification with ADB (Replicating the Real-World Scenario in §1.5)

```bash
# List activities from the resolver table
adb shell dumpsys package com.example.app | grep -A5 'Activity Resolver Table'

# Try calling the suspected post-login activity directly
adb shell am start -n com.example.app/.DashboardActivity
```

Observe: is the displayed screen the dashboard directly (bypass successful, FAIL), or does the application reject/redirect to login (PASS)?

### 3.6 Method E — Drozer for Automated Triage

```bash
dz> run app.activity.info -a com.example.app
dz> run app.activity.start --component com.example.app com.example.app.DashboardActivity
```

### 3.7 Method Comparison: When to Use Which

| Method | Tool | When to use |
|---|---|---|
| **A/B** | xmlstarlet/aapt2 | Mandatory baseline — complete enumeration of exported activities |
| **C** | Manual review | Core of the test — assessing the sensitivity of functionality |
| **D** | ADB `am start` | Most direct dynamic verification, replicates the real-world scenario |
| **E** | Drozer | Automated triage across many activities at once |

**Minimum recommended combination:** **A/B (enumeration) → C (mandatory, assess sensitivity) → D (dynamic confirmation)**.

---

### 3.8 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rule:**

> **Evaluation:** *"The test case fails if any exported activity is not protected by an appropriate android:permission that restricts which apps can start it and exposes or performs sensitive functionality."*

---

#### ❌ FAIL / ISSUE — The check is declared FAILED if:

| No | Condition |
|---|---|
| F1 | An activity with `exported="true"` lacks an adequate `android:permission`, **and** displays/performs a sensitive function (§1.3) |

**Example evidence (reflecting the real-world Trustwave/Sieve pattern in §1.5):**

```xml
<activity android:name=".DashboardActivity" android:exported="true" />
```

```bash
$ adb shell am start -n com.example.app/.DashboardActivity
Starting: Intent { cmp=com.example.app/.DashboardActivity }
# The dashboard opens directly, with no login prompt
```

**FAIL** — authentication bypass confirmed.

---

#### ✅ PASS — The check is declared PASSED if:

| No | Condition |
|---|---|
| P1 | The sensitive activity is set to `exported="false"` (no need for external access), **or** |
| P2 | The activity is exported **with** `android:permission` referencing a permission that uses `protectionLevel="signature"`, **or** |
| P3 | The activity independently verifies session/authentication status in `onCreate()` before displaying sensitive content, regardless of how it was invoked |

---

#### ⚠️ Important Notes on Assessment

1. **Ask "does it need to be exported at all" before assessing the permission's strength** — per §1.4, if there is no legitimate reason for a third party to call that activity, the simplest and strongest solution is `exported="false"`, not adding a permission.

2. **Intent filters are not access control** — do not be fooled into assuming that an activity with a "specific" `<intent-filter>` (a particular action/category/data) is automatically safe; per §1.2, the filter only governs routing, and anyone can still call it directly via an explicit `Intent`.

3. **Independent verification at the activity level is a strong second line of defense** — even if forced to be exported, an activity that re-checks session status in `onCreate()` (rather than relying on the assumption that it "must have come from the normal flow") remains safe even when invoked directly — this is consistent with the defense-in-depth principle recurring throughout this research series.

4. **Severity is modulated:**

   | Factor | Severity |
   |---|---|
   | Authentication bypass confirmed, exposing financial data/functions or credentials | **High** |
   | Displays non-financial sensitive data without a full authentication bypass | **Medium** |
   | Permission exists but `protectionLevel` is weak (`normal`/`dangerous`) | **Medium-High** |
   | Non-exported, or exported with `signature` + independent session verification | **Not a finding** |

5. **Document:** the activity name, exported status, permission attribute and its `protectionLevel`, the result of the code review (whether independent session verification exists), and the result of dynamic verification via `am start`.

---

## 4. Recommendations

### 4.1 Non-Exported If There Is No External Need (Per MASTG-BEST-0052)

```xml
<activity android:name=".DashboardActivity" android:exported="false" />
```

### 4.2 Signature Permission for External Access That Is Genuinely Needed

```xml
<activity
    android:name=".ShareResultActivity"
    android:exported="true"
    android:permission="com.example.app.permission.TRUSTED_PARTNER" />

<permission
    android:name="com.example.app.permission.TRUSTED_PARTNER"
    android:protectionLevel="signature" />
```

### 4.3 Independent Session Verification as a Second Line of Defense

```java
@Override
protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    if (!SessionManager.isAuthenticated()) {
        startActivity(new Intent(this, LoginActivity.class));
        finish();
        return;
    }
    setContentView(R.layout.activity_dashboard);
}
```

### 4.4 Remediation Checklist

- [ ] Every exported activity has been evaluated for whether external access is genuinely needed
- [ ] Activities that don't need to be exported are explicitly set to `exported="false"`
- [ ] Required exported activities are protected by a permission with `protectionLevel="signature"`
- [ ] Sensitive activities independently verify session/authentication status in `onCreate()`, not relying on an assumed navigation order
- [ ] Verified dynamically with `adb shell am start` for every post-login activity

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0364 (source, tests-beta)](https://github.com/OWASP/mastg/blob/master/tests-beta/android/MASVS-PLATFORM/MASTG-TEST-0364.md)
- [MASTG-KNOW-0132: Android Activities](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0132/)
- [MASTG-KNOW-0017: App Permissions](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0017/)
- [MASTG-BEST-0052: Restrict Access to Android App Components](https://github.com/OWASP/mastg/blob/master/best-practices/MASTG-BEST-0052.md)
- [MASTG-TECH-0160: Enumerating Activities](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0160/)

### 5.2 Research and Real-World Cases

- [RedFoxSec: How to Exploit Android Activities — Practical Attack Guide](https://www.redfoxsec.com/blog/how-to-exploit-android-activities)
- [Medium: Breaking In — Bypassing Sieve.apk's Authentication](https://medium.com/@r00t7h3ll/bypassing-login-screen-in-android-application-4277ec5b4c17)
- [Android Headlines: Any App Can Be Hit By This Authentication Bypass Vulnerability](https://www.androidheadlines.com/2020/06/app-authentication-bypass-vulnerability-android-manifests.html)
- [Oversecured: Android Deep Link Vulnerabilities — How Intent Filters Lead to Account Takeover](https://oversecured.com/blog/android-deep-link-vulnerabilities)

### 5.3 Tool Documentation

- [Drozer — Android Security Assessment Framework](https://github.com/WithSecureLabs/drozer)
- [aapt2 Documentation](https://developer.android.com/tools/aapt2)

---

*This document was compiled based on official OWASP MASTG content (`tests-beta/android/MASVS-PLATFORM/MASTG-TEST-0364.md`, `MASTG-KNOW-0132/0017/0020`, `MASTG-BEST-0052`), together with pentest community research documenting two classic cases of authentication bypass via exported activity (an internal messaging app documented by Trustwave, and `FileSelectActivity` in Sieve.apk). The most important methodological nuance: there is no official Semgrep rule for this test — it relies entirely on manifest enumeration and manual review, because determining "whether an activity exposes sensitive functionality" is a contextual question that requires understanding the application's business logic and cannot be reduced to syntactic pattern-matching. The correct order of evaluation always starts with "does this activity need to be exported at all" before assessing the strength of the permission protecting it.*
