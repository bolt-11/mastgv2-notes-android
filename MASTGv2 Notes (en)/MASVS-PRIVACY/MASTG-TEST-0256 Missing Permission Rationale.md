# MASTG-TEST-0256 Missing Permission Rationale

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0256 |
| **Platform** | Android |
| **MASVS Category** | MASVS-PRIVACY |
| **Weakness** | MASWE-0066 — *Inadequate Permission Management* (same as MASTG-TEST-0254/0255) |
| **Official MASTG Status** | **`placeholder`** — no complete Overview/Steps/Evaluation yet |
| **Official note (the only content currently available)** | *"This test checks if the app does not provide a rationale for requesting permissions."* — with two official Android Developers references |
| **Profile** | **P (Privacy) only** |
| **Knowledge** | MASTG-KNOW-0017 *(a problematic reference, consistent with the note in the MASTG-TEST-0254/0255 documents)* |
| **Related Tests** | **MASTG-TEST-0254** (whether the permission is proportional), **MASTG-TEST-0255** (whether the permission is the most minimal) — this test complements both with a third question: **is the user told WHY this permission is being requested?** |
| **Related Demo** | — (none) |
| **Official Rule** | — (none) |
| **Related CWE** | CWE-1021 (Improper Restriction of Rendered UI Layers or Frames) — not quite fitting; more relevant as a *usable security/transparency gap*, which does not always map cleanly to a technical CWE |

---

## 1. Explanation

### 1.1 This Test's Status and Its Position in the MASTG-TEST-0254/0255/0256 Trio

This test is in **`placeholder`** status, yet its official note references two very specific and actionable Android Developers documentation pages. Together with MASTG-TEST-0254 and MASTG-TEST-0255, all three form a **complete privacy permission evaluation sequence**:

| Test | Core Question |
|---|---|
| **MASTG-TEST-0254** | Is this permission **proportional** to the existing feature? |
| **MASTG-TEST-0255** | Is this the **most minimal** way to achieve that feature? |
| **MASTG-TEST-0256** *(this document)* | Is the user given a **clear explanation** of why this permission is needed, **before and after** the request is made? |

A permission could be **proportional** (passes 0254) and **already the most minimal** (passes 0255), yet still **FAIL** this test if the application never explains to the user why it is needed — the user is forced to face a generic system dialog ("Allow App X to access Location?") with no context at all about the **specific feature** that needs it.

### 1.2 Two Different, Complementary Rationale Mechanisms

The official note references **two** Android Developers pages that describe **two different rationale mechanisms**, operating at different points in the timeline of a user's interaction with a permission:

| Mechanism | When It Is Shown | Who Displays It |
|---|---|---|
| **In-app rationale** (`shouldShowRequestPermissionRationale`) | **Before** the system permission dialog appears (specifically after the first denial) | The application's own custom UI |
| **Privacy Dashboard rationale** (`VIEW_PERMISSION_USAGE`) | **After** the permission is granted — when the user reviews access history via the system's Privacy Dashboard (Android 12+) | A custom application Activity, displayed **inside** the system Privacy Dashboard UI |

Both address the need for transparency at **different phases** — one at the decision point (whether to grant permission or not), the other at the audit point (the user reviewing why an application previously accessed its sensitive data).

### 1.3 The First Mechanism: In-App Rationale with `shouldShowRequestPermissionRationale()`

Android provides a dedicated API for determining **when** educational/rationale UI should be shown:

```kotlin
ActivityCompat.shouldShowRequestPermissionRationale(
    this, Manifest.permission.REQUESTED_PERMISSION)
```

This API returns `true` **specifically** when the user has **previously denied** this permission request, but **has not yet** chosen "Don't ask again" — a signal that the user might be hesitant, and this is the **most appropriate moment** to explain the benefit before asking again. The official documentation provides a complete decision flow:

```kotlin
when {
    ContextCompat.checkSelfPermission(context, permission) == PackageManager.PERMISSION_GRANTED -> {
        // Permission already granted, use the related API directly
    }
    ActivityCompat.shouldShowRequestPermissionRationale(this, permission) -> {
        // SHOW educational UI: explain WHY this feature needs the permission,
        // what won't work if denied, include a "cancel"/"no, thanks" button
        showInContextUI(...)
    }
    else -> {
        // Request directly without additional rationale (first-time request)
        requestPermissionLauncher.launch(permission)
    }
}
```

Official best practices for this rationale UI's content:

1. **Explain specifically** why a particular feature needs this permission, and what won't work if denied.
2. **Provide an exit** — a "cancel"/"no, thanks" button so the user can keep using the application without granting permission.
3. **Proper context** — request permission **right when** the user tries to use the related feature, not upfront (e.g. at the application's first `onCreate`).
4. **Specific about the data** — explain what data is accessed and for what purpose.
5. **Do not assume from prior behavior** — always request the permission every time it is needed, do not assume status from a previous session.

### 1.4 The Second Mechanism: Privacy Dashboard Rationale (Android 12+)

This is a **less well-known** but significant mechanism for long-term transparency. Since Android 12, the system provides a **Privacy Dashboard** — a centralized screen showing a **history** of which applications have accessed location, camera, and microphone. Android allows developers to provide a **contextual explanation** that appears **directly inside** this system dashboard (not in the app's own UI), via the following mechanism:

```xml
<activity android:name=".DataAccessRationaleActivity"
          android:permission="android.permission.START_VIEW_PERMISSION_USAGE"
          android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.VIEW_PERMISSION_USAGE" />
        <action android:name="android.intent.action.VIEW_PERMISSION_USAGE_FOR_PERIOD" />
        <category android:name="android.intent.category.DEFAULT" />
    </intent-filter>
</activity>
```

Two different actions trigger different display contexts:

- **`VIEW_PERMISSION_USAGE`** — triggers an info icon on the application's permission page (applies to all runtime permissions), carrying the `EXTRA_PERMISSION_GROUP_NAME` extra.
- **`VIEW_PERMISSION_USAGE_FOR_PERIOD`** — triggers an info icon **directly in the Privacy Dashboard screen**, carrying additional extras `EXTRA_ATTRIBUTION_TAGS`, `EXTRA_START_TIME`, `EXTRA_END_TIME` — allowing the application to explain **a specific access during a given time period** (e.g. "The app accessed your location at 2:00-2:05 PM to update the order's estimated arrival time").

An important architectural point: this `Activity` **must** be `android:exported="true"` (because it is called by the system from a separate process — the Privacy Dashboard is a system component, not part of the application's process), yet it is protected by the system permission `START_VIEW_PERMISSION_USAGE`, which **can only be held by system components** — so even though it is `exported="true"`, it **cannot be triggered by any arbitrary third-party application**, only by the official Privacy Dashboard. This is an exported-but-safe pattern relevant to correlate with *exported components* testing in other MASVS-PLATFORM categories in this research series — do not immediately flag `exported="true"` here as a finding without first checking its permission protection.

### 1.5 Why Rationale Matters: Not Just a UX Formality

Official documentation states the fundamental reason directly:

> *"Research shows that users are much more comfortable with permission requests when they understand why the app needs them."*

This is not purely about UX comfort, but has a direct impact on the **quality of users' privacy decisions**. The default system dialog only states **which API** is being requested ("App X wants to access your device location") — with no context about the **specific feature** that needs it. Users who don't understand the context tend to make decisions based on **habit** (always tapping "Allow" without reading, or always denying out of suspicion) rather than **genuine understanding** — both patterns are equally undesirable from a healthy privacy perspective. Good rationale bridges this information gap, enabling **truly informed consent** (consent that is genuinely understood), not merely a click formality.

---

## 2. Tools Used for Testing

### 2.1 Required Tools (Core)

| Tool | Function |
|---|---|
| **jadx** | Decompilation to search for the `shouldShowRequestPermissionRationale` pattern and the `VIEW_PERMISSION_USAGE` Activity implementation |
| **grep / ripgrep** | Searching for rationale API patterns in code and manifest |
| **apktool/jadx (manifest)** | Extracting `AndroidManifest.xml` to check for the existence of the Privacy Dashboard rationale Activity |

### 2.2 Alternative & Supporting Tools

| Tool | Function |
|---|---|
| **Android 12+ device/emulator** | Mandatory for dynamic verification of the Privacy Dashboard mechanism (§1.4), since this feature does not exist on older versions |
| **UI Automator / Espresso** | Testing the UI flow automatically — triggering a first-time permission denial, then verifying whether educational UI appears before the second request |
| **MobSF** | Sometimes shows a list of permissions alongside the presence/absence of related explanation strings in app resources (a rough heuristic) |
| **Manual UX walkthrough** | Since this is fundamentally a quality evaluation of communication to the user, manually walking through the app's flow as a real user remains the most reliable method |

### 2.3 Environment Prerequisites

- **No device needed for basic static analysis** (API/manifest pattern searching).
- **A device/emulator is needed for complete dynamic verification** — especially to simulate the "deny then ask again" flow that triggers `shouldShowRequestPermissionRationale() = true`.
- **Ideally an Android 12+ device** to test the Privacy Dashboard mechanism (§1.4).

---

## 3. Testing Methodology

Because there are no official steps (placeholder status), the following methodology is compiled based on an elaboration of the two Android Developers pages directly referenced by the official note.

### 3.1 General Steps

1. Take the list of dangerous permissions from the results of **MASTG-TEST-0254**.
2. For each permission, trace the code around the calls to `requestPermissionLauncher.launch()`/`ActivityCompat.requestPermissions()`.
3. Check whether there is a `shouldShowRequestPermissionRationale()` call **followed by** educational UI display before the actual request.
4. Check the manifest for the existence of an Activity with the `VIEW_PERMISSION_USAGE`/`VIEW_PERMISSION_USAGE_FOR_PERIOD` intent-filter.
5. Dynamic verification: trigger the first-denial flow, observe whether educational UI actually appears before the second request.

### 3.2 Method A — grep/ripgrep for the In-App Rationale Mechanism

```bash
D=./decompiled/sources

# Find rationale API calls
rg -n 'shouldShowRequestPermissionRationale' $D

# For each occurrence, check whether it is followed by a dialog/educational UI display (not an immediate re-request)
rg -n -A15 'shouldShowRequestPermissionRationale' $D | grep -i "AlertDialog\|showInContextUI\|DialogFragment\|Snackbar"

# Find requestPermissions calls NOT preceded by any rationale check at all
rg -l 'requestPermissions\(|ActivityResultContracts\.RequestPermission' $D > files_requesting_permission.txt
for f in $(cat files_requesting_permission.txt); do
    if ! grep -q "shouldShowRequestPermissionRationale" "$f"; then
        echo "[!] $f requests permission WITHOUT any rationale check at all"
    fi
done
```

### 3.3 Method B — Manifest Check for Privacy Dashboard Rationale

```bash
jadx --no-src -d ./out target-app.apk
grep -A5 "VIEW_PERMISSION_USAGE" ./out/resources/AndroidManifest.xml
grep -B3 "START_VIEW_PERMISSION_USAGE" ./out/resources/AndroidManifest.xml
```

If found nowhere at all, the application **does not provide** contextual explanation in the system Privacy Dashboard — a candidate finding for the second mechanism (§1.4).

### 3.4 Method C — CodeQL (Correlating Permission Requests with Rationale Checks)

```ql
import java

class PermissionRequestCall extends MethodAccess {
  PermissionRequestCall() {
    this.getMethod().hasName(["requestPermissions", "launch"]) and
    exists(this.getAnArgument().getType().(RefType).getASupertype*() |
      it.hasQualifiedName("java.lang", "String"))
  }
}

class RationaleCheckCall extends MethodAccess {
  RationaleCheckCall() {
    this.getMethod().hasName("shouldShowRequestPermissionRationale")
  }
}

from PermissionRequestCall req
where not exists(RationaleCheckCall check | check.getEnclosingCallable() = req.getEnclosingCallable())
select req, "A permission request was found without a shouldShowRequestPermissionRationale check in the same method"
```

### 3.5 Method D — Dynamic Verification of the Deny-Then-Re-request Flow

```bash
# 1. Install the app, run it, trigger the feature that needs a dangerous permission, DENY the request
# (revoke/grant via adb pm is not relevant here -- perform the denial directly through the UI)

# 2. Trigger the same feature AGAIN
# Observe manually: does educational/rationale UI appear BEFORE the second system dialog appears,
# or does it immediately show the generic system dialog again with no additional context?
```

```bash
# Verify permission status via adb to confirm the denial state was recorded
adb shell dumpsys package com.target.app | grep -A3 "runtime permissions"
```

### 3.6 Method E — Testing the Privacy Dashboard Directly (Android 12+)

```bash
# After the app has been granted either location/camera/microphone
# Open the system Privacy Dashboard manually:
adb shell am start -a android.settings.PRIVACY_CONTROLS_SETTINGS
```

Navigate manually to the target application's access history, check whether an **info icon** appears that can be clicked to view an additional explanation from the application (an indication the §1.4 mechanism is active and functioning).

### 3.7 Method Comparison: When to Use Which

| Method | Tool | Mechanism Tested | When to use |
|---|---|---|---|
| **A** | grep | In-app rationale | Static baseline for the first mechanism |
| **B** | grep manifest | Privacy Dashboard rationale | Static baseline for the second mechanism |
| **C** | CodeQL | In-app rationale (precise correlation) | Large codebase |
| **D** | Manual dynamic verification | In-app rationale (real behavior) | Confirming actual UX |
| **E** | Direct Privacy Dashboard | Privacy Dashboard rationale (real behavior) | Confirming actual UX, Android 12+ device |

**Minimum recommended combination:** **A+B (static baseline of both mechanisms) → D+E (real dynamic confirmation)** — because this is fundamentally an evaluation of communication quality to the user, dynamic/manual confirmation is far more convincing than static conclusions alone.

---

### 3.8 Evaluation Criteria: Positive Case & Negative Case

Since there is no official Evaluation clause (placeholder status), the following criteria are derived from the two official guides referenced.

---

#### ❌ FAIL / ISSUE — The check is declared FAILED if:

| No | Condition |
|---|---|
| F1 | The application requests a dangerous permission **without** any `shouldShowRequestPermissionRationale()` call anywhere in its code flow |
| F2 | `shouldShowRequestPermissionRationale()` is called, but the result is **not followed** by any educational UI display — the code immediately re-requests without any additional explanation |
| F3 | Dynamic verification (Method D) confirms that after the first denial, the second request appears **without** any additional context from the application |
| F4 | No Activity is found with a `VIEW_PERMISSION_USAGE`/`VIEW_PERMISSION_USAGE_FOR_PERIOD` intent-filter, so the system Privacy Dashboard displays no contextual explanation at all for this application |

---

#### ✅ PASS — The check is declared PASSED if:

| No | Condition |
|---|---|
| P1 | The application implements the `shouldShowRequestPermissionRationale()` flow per the official pattern, with clear educational UI and a provided "cancel" option |
| P2 | The application provides a rationale Activity for the Privacy Dashboard (§1.4), giving additional context visible in the system |
| P3 | Dynamic verification (Method D/E) confirms both mechanisms genuinely function and display as designed |
| P4 | The application **has no** dangerous permission at all (rationale becomes irrelevant) |

---

#### ⚠️ Important Notes on Assessment

1. **This is a UX/transparency quality evaluation, not purely a technical vulnerability** — weigh the clarity and honesty of the rationale content (whether it genuinely explains specifically, rather than merely a generic "This app needs this permission to function properly" text).

2. **These two mechanisms are independent** — an application can implement one without the other. Evaluate and report both separately, do not assume one is sufficient to represent both.

3. **`android:exported="true"` on the Privacy Dashboard Activity is NOT a vulnerability** (§1.4) — do not mistakenly flag this as a dangerous exported component finding; it is protected by the system permission `START_VIEW_PERMISSION_USAGE`, which is held only by official system components.

4. **Correlate with MASTG-TEST-0254/0255** — a permission that is already proportional and minimal can still result in a poor user experience (and potentially reduced trust) if not explained properly.

5. **Severity is generally low-to-medium** — this is about privacy transparency/UX quality, not an active security vulnerability; however, it remains relevant for compliance with the *informed consent* principle that underpins many modern privacy regulations (GDPR, etc.).

6. **Document:** the list of dangerous permissions, implementation status of both rationale mechanisms per permission, the quality of the rationale text content (specific vs. generic), and the results of dynamic verification of the deny-then-re-request flow.

---

## 4. Recommendations

### 4.1 Implement In-App Rationale Per the Official Pattern

```kotlin
when {
    ContextCompat.checkSelfPermission(this, Manifest.permission.CAMERA) ==
            PackageManager.PERMISSION_GRANTED -> {
        openCameraFeature()
    }
    ActivityCompat.shouldShowRequestPermissionRationale(this, Manifest.permission.CAMERA) -> {
        AlertDialog.Builder(this)
            .setTitle("Camera Permission Needed")
            .setMessage("The QR code scanning feature needs camera access. " +
                    "Without this permission, you can still enter the code manually.")
            .setPositiveButton("Grant Permission") { _, _ ->
                requestPermissionLauncher.launch(Manifest.permission.CAMERA)
            }
            .setNegativeButton("No, Thanks") { dialog, _ -> dialog.dismiss() }
            .show()
    }
    else -> {
        requestPermissionLauncher.launch(Manifest.permission.CAMERA)
    }
}
```

### 4.2 Implement a Rationale Activity for the Privacy Dashboard

```xml
<activity android:name=".PermissionRationaleActivity"
          android:permission="android.permission.START_VIEW_PERMISSION_USAGE"
          android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.VIEW_PERMISSION_USAGE" />
        <action android:name="android.intent.action.VIEW_PERMISSION_USAGE_FOR_PERIOD" />
        <category android:name="android.intent.category.DEFAULT" />
    </intent-filter>
</activity>
```

```kotlin
class PermissionRationaleActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val permissionGroup = intent.getStringExtra(Intent.EXTRA_PERMISSION_GROUP_NAME)
        // Show a specific explanation based on permissionGroup
        setContentView(buildRationaleView(permissionGroup))
    }
}
```

### 4.3 Write Specific Rationale Content, Not Generic

```
BAD:   "This app needs location permission to function properly."
GOOD:  "We use your location to show nearby restaurants and
        estimate delivery time. Your location is not shared with
        third parties and is only accessed when you open the
        restaurant search feature."
```

### 4.4 Remediation Checklist

- [ ] Every dangerous permission has a `shouldShowRequestPermissionRationale()` flow with clear educational UI
- [ ] The educational UI provides a decline option without blocking app usage
- [ ] Rationale content is specific to the feature and data, not generic text
- [ ] A Privacy Dashboard rationale Activity is implemented for location/camera/microphone permissions
- [ ] Dynamic verification of the deny-then-re-request flow has been performed
- [ ] **Re-verify:** rerun MASTG-TEST-0256 after any change to the permission request flow

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0256: Missing Permission Rationale](https://mas.owasp.org/MASTG/tests/android/MASVS-PRIVACY/MASTG-TEST-0256/)
- [MASTG-TEST-0254: Dangerous App Permissions](https://mas.owasp.org/MASTG/tests/android/MASVS-PRIVACY/MASTG-TEST-0254/)
- [MASTG-TEST-0255: Permission Requests Not Minimized](https://mas.owasp.org/MASTG/tests/android/MASVS-PRIVACY/MASTG-TEST-0255/)
- [MASWE-0066: Inadequate Permission Management](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0066/)
- [OWASP Mobile Top 10 2024 — M6: Inadequate Privacy Controls](https://owasp.org/www-project-mobile-top-10/2023-risks/m6-inadequate-privacy-controls)

### 5.2 Official Android Documentation

- [Android Developers — Request App Permissions: Explain access to sensitive data](https://developer.android.com/training/permissions/requesting#explain)
- [Android Developers — Explain access to more sensitive information (Privacy Dashboard rationale)](https://developer.android.com/training/permissions/explaining-access#privacy-dashboard-show-rationale)
- [Android Developers — `shouldShowRequestPermissionRationale()` API reference](https://developer.android.com/reference/android/app/Activity#shouldShowRequestPermissionRationale(java.lang.String))
- [Android Developers — Privacy Dashboard](https://developer.android.com/about/versions/12/features/privacy-dashboard)

### 5.3 Tool Documentation

- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [CodeQL — Documentation](https://codeql.github.com/docs/)
- [UI Automator — Testing framework](https://developer.android.com/training/testing/other-components/ui-automator)
- [MobSF — Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)

---

*This document was compiled primarily from an elaboration of the two official Android Developers documentation pages directly referenced by the official MASTG-TEST-0256 note (placeholder status). This test completes the privacy permission evaluation trio alongside MASTG-TEST-0254 (proportionality) and MASTG-TEST-0255 (minimality) with a third dimension: transparency. The two different rationale mechanisms — in-app (`shouldShowRequestPermissionRationale`) and the system Privacy Dashboard (`VIEW_PERMISSION_USAGE`) — operate independently, and both need to be evaluated separately for a complete picture of the quality of an application's privacy communication to its users.*
