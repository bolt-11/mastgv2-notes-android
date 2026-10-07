# MASTG-TEST-0257 Not Resetting Unused Permissions

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0257 |
| **Platform** | Android |
| **MASVS Category** | MASVS-PRIVACY |
| **Weakness** | MASWE-0066 — *Inadequate Permission Management* (same as MASTG-TEST-0254/0255/0256) |
| **Official MASTG Status** | **`placeholder`** — no complete Overview/Steps/Evaluation yet |
| **Official note (the only content currently available)** | *"This test checks if the app does not remove unnecessary access to granted permissions."* — referencing https://developer.android.com/training/permissions/requesting#remove-access |
| **Profile** | **P (Privacy) only** |
| **Knowledge** | MASTG-KNOW-0017 *(a problematic reference, consistent with the note in the MASTG-TEST-0254/0255/0256 documents)* |
| **Related Tests** | Completes the MASTG-TEST-0254/0255/0256 trio with a fourth dimension: **does the application proactively release a permission once it is no longer needed?** |
| **Related Demo** | — (none) |
| **Official Rule** | — (none) |
| **Related CWE** | CWE-459 (Incomplete Cleanup), CWE-250 (Execution with Unnecessary Privileges) |

---

## 1. Explanation

### 1.1 This Test's Status and Its Position in the Four-Test Privacy Permission Sequence

This test is in **`placeholder`** status, completing the permission evaluation sequence already discussed in the three previous documents:

| Test | Core Question |
|---|---|
| MASTG-TEST-0254 | Is this permission **proportional**? |
| MASTG-TEST-0255 | Is this the **most minimal** way? |
| MASTG-TEST-0256 | Is the user given an **explanation** of why? |
| **MASTG-TEST-0257** *(this document)* | Once a permission is **no longer needed**, does the application **proactively release it**? |

This test highlights a **lifecycle** dimension of permissions that is often overlooked: a permission that was once proportional and needed (passing the three previous tests) can **become no longer relevant** over time — the user disables the related feature in the app's settings, the feature is removed in an update version, or the user's usage pattern changes. The question is: **does the application recognize and react to this change**, or does it keep holding that permission forever simply because there is no mechanism actively releasing it?

### 1.2 A Crucial Distinction: System Auto-Reset (Passive) vs. Application Self-Revocation (Proactive)

This is the most important conceptual distinction to understand before evaluating this test — there are **two entirely different mechanisms** that are easy to confuse:

| | **System Permission Auto-Reset** (Android 11+) | **Application Self-Revocation** (Android 13+, this test's focus) |
|---|---|---|
| **Who initiates it** | **The operating system**, automatically | **The application itself**, via explicit code |
| **When it happens** | After the application has **not been used for several months** (a system heuristic based on inactivity time) | **Any time** the application detects a permission is no longer relevant — can be immediately after the user disables the related feature |
| **Granularity** | All of the application's permissions at once (related to App Hibernation) | Per-permission or per-group, chosen specifically by the developer |
| **Can it be relied on as the only layer?** | **No** — this is a passive, months-scale safety net, not a rapid response to actual changes in need |

The system auto-reset feature (introduced in Android 11, extended to older versions via a Google Play services update in 2021) is a **passive, platform-level safety net** — it resets permissions for applications that have **not been opened at all** for several months, regardless of the app's own code behavior. This **always runs** in the background of the system and **cannot be tested or influenced** via application code — so this is **not** the object of MASTG-TEST-0257's evaluation.

**This test's focus** is the second mechanism: the **`revokeSelfPermissionOnKill()`/`revokeSelfPermissionsOnKill()`** API explicitly referenced by the "remove-access" page cited in the official note — the application's ability to **proactively and immediately** release a permission it knows is no longer needed, **without waiting** for the system's passive heuristic to react after several months.

### 1.3 The `revokeSelfPermissionOnKill()` Mechanism (Android 13+)

Per official Android Developers documentation:

```kotlin
// Releasing a single permission
context.revokeSelfPermissionOnKill(Manifest.permission.RECORD_AUDIO)

// Releasing a group of permissions at once
context.revokeSelfPermissionsOnKill(listOf(
    Manifest.permission.RECORD_AUDIO,
    Manifest.permission.CAMERA
))
```

Important characteristics of this mechanism:

1. **An asynchronous process** — permission revocation does not happen immediately when the API is called.
2. **The system waits for a safe time** — the application process is only actually killed (and the permission actually released) after the system determines the application has been running in the **background**, not in the **foreground**, for long enough — this design prevents a sudden disruption of the user's active session.
3. **Permission group granularity** — for the system to display the status "this app no longer accesses [data category]" in settings, the application must release **all** permissions within the related group, not just some of them.
4. **An obligation to communicate with the user** — official documentation explicitly recommends displaying a dialog the next time the app is opened, telling the user that the application **no longer needs** a particular permission — a transparency communication pattern that complements (not replaces) the rationale discussed in MASTG-TEST-0256.

### 1.4 Why This Matters: Building Trust and Reducing Long-Term Risk Surface

The value of this mechanism is twofold:

- **Security**: a permission held longer than needed is an **unnecessary risk surface** — if the application (or one of its dependencies) is compromised later, an attacker inherits access to every permission **still held**, including ones whose functionality has long gone unused.
- **User trust**: official documentation asserts the psychological value of this proactive transparency:

> *"You might want to consider displaying a dialogue to users that lists the permissions you have proactively removed... users can feel safe if you tell them that you have revoked certain permissions at your will due to non-use."*

This reverses the common developer habit pattern of **only requesting** permissions and rarely **voluntarily releasing them** — yet the act of releasing a no-longer-used permission is a strong trust signal for users, showing the application genuinely applies the *least privilege* principle continuously, not just at the point of initial installation.

### 1.5 Relevant Use-Case Scenarios

Several concrete patterns where this mechanism should be applied but is often neglected:

- **An optional feature disabled by the user**: the application has a "allow sharing location with friends" toggle that the user turns off — the `ACCESS_FINE_LOCATION` permission should be released at that moment, not held indefinitely while waiting for the toggle to be re-enabled (which may never happen).
- **A feature removed in an app update**: a new version of the application removes the voice memo recording feature, but the previously requested `RECORD_AUDIO` permission remains held without ever being explicitly released in the version migration code.
- **Incomplete onboarding**: a user grants camera permission during onboarding for a face-verification feature, but later chooses a different verification method (OTP) — the camera permission, now irrelevant to the chosen flow, remains held without being released.

---

## 2. Tools Used for Testing

### 2.1 Required Tools (Core)

| Tool | Function |
|---|---|
| **jadx** | Decompilation to search for `revokeSelfPermissionOnKill`/`revokeSelfPermissionsOnKill` call patterns |
| **grep / ripgrep** | Searching for API patterns and correlating with feature toggles/settings in code |
| **aapt/adb** | Extracting `targetSdkVersion` — relevant because this API is only available since API 33 |

### 2.2 Alternative & Supporting Tools

| Tool | Function |
|---|---|
| **CodeQL** | Tracing whether a toggle/setting that disables a feature (e.g. `SharedPreferences.putBoolean("location_sharing", false)`) correlates with a call to the revoke API in the same/nearby code location |
| **adb shell dumpsys** | Checking the application's runtime permission status over time to confirm status changes after certain interactions |
| **UI Automator/Espresso** | Testing dynamic scenarios: disable a feature via the UI, observe whether the permission is actually released after the application enters the background |

### 2.3 Environment Prerequisites

- **No device needed for basic static analysis.**
- **An Android 13+ device/emulator is needed for dynamic verification** — this API is unavailable on older versions.
- **The application's `targetSdkVersion` must be ≥33** for this API to even be callable; if `targetSdkVersion` is below that, the absence of this mechanism is not entirely an implementation fault, but rather a target-version limitation (though it remains worth noting as a recommendation to raise `targetSdkVersion`, consistent with the discussion in MASTG-TEST-0245).

---

## 3. Testing Methodology

Because there are no official steps (placeholder status), the following methodology is compiled based on an elaboration of the Android Developers page directly referenced by the official note.

### 3.1 General Steps

1. Take the list of dangerous permissions from the results of **MASTG-TEST-0254**.
2. Identify application features that **can be disabled** by the user (a settings toggle) or **are potentially removed** in a future update, related to those permissions.
3. Trace whether there is a `revokeSelfPermissionOnKill`/`revokeSelfPermissionsOnKill` call correlating with disabling that feature.
4. Dynamic verification: disable the related feature, observe the permission status after the application has been in the background for a sufficient duration.

### 3.2 Method A — grep/ripgrep for API Calls

```bash
D=./decompiled/sources

# Find self-revocation API calls
rg -n 'revokeSelfPermissionOnKill|revokeSelfPermissionsOnKill' $D

# Find toggles/settings related to a dangerous-permission feature
rg -n -B5 -A15 'putBoolean\("location_sharing"|putBoolean\(".*_enabled"|putBoolean\(".*_feature' $D | \
  grep -i "location\|camera\|contacts\|microphone\|record_audio"

# Check targetSdkVersion as a prerequisite for API availability
grep -oP 'targetSdkVersion="\K[0-9]+' AndroidManifest.xml
```

### 3.3 Method B — CodeQL (Correlating a Feature Toggle with Permission Release)

```ql
import java

class FeatureToggleOff extends MethodAccess {
  FeatureToggleOff() {
    this.getMethod().hasName("putBoolean") and
    this.getArgument(1).(BooleanLiteral).getBooleanValue() = false
  }
}

class SelfRevokeCall extends MethodAccess {
  SelfRevokeCall() {
    this.getMethod().hasName(["revokeSelfPermissionOnKill", "revokeSelfPermissionsOnKill"])
  }
}

from FeatureToggleOff toggle
where not exists(SelfRevokeCall revoke | revoke.getEnclosingCallable() = toggle.getEnclosingCallable())
select toggle, "A feature was disabled without explicitly releasing the related permission"
```

### 3.4 Method C — Dynamic Verification with a Background Time Simulation

```bash
# 1. Install, grant the permission, use the related feature
adb install target-app.apk
adb shell dumpsys package com.target.app | grep -A5 "RECORD_AUDIO"
# Observe: granted=true

# 2. Disable the related feature via the app's UI (e.g. the "record voice memo" toggle)

# 3. Force the application to the background and simulate idle time
adb shell am force-stop com.target.app  # or wait for natural idle
# 4. After a reasonable duration (a real implementation waits for the system's "safe kill window"),
#    check the permission status again
adb shell dumpsys package com.target.app | grep -A5 "RECORD_AUDIO"
```

If the permission status **remains** `granted=true` even though the related feature has long been disabled by the user and the application has been in the background for a while, this is a strong indication the self-revocation mechanism is **not implemented**.

### 3.5 Method D — Changelog/Release Audit for Removed Features

For whitebox testing, review the application's release history/changelog to identify features that **once existed** but were removed in later versions, then verify whether permissions related to that feature were also removed from the manifest or released via migration code:

```bash
git log --oneline --all -- AndroidManifest.xml | head -20
git diff <old_version> <new_version> -- AndroidManifest.xml
```

### 3.6 Method Comparison: When to Use Which

| Method | Tool | Advantage | When to use |
|---|---|---|---|
| **A** | grep | Fast, directly shows whether the API is called or not | Initial baseline |
| **B** | CodeQL | Precise correlation between feature toggles and permission release | Large codebase |
| **C** | Dynamic verification | Proof of real behavior | Final confirmation |
| **D** | Changelog audit | Catches cases of a feature removed in an update (whitebox) | Historical/regression audit |

**Minimum recommended combination:** **A (baseline for API existence) → B (correlation with feature toggles) → C (dynamic confirmation)** for a solid conclusion.

---

### 3.7 Evaluation Criteria: Positive Case & Negative Case

Since there is no official Evaluation clause (placeholder status), the following criteria are derived from the official guide referenced.

---

#### ❌ FAIL / ISSUE — The check is declared FAILED if:

| No | Condition |
|---|---|
| F1 | The application has a user-disableable feature (a settings toggle) related to a dangerous permission, **but there is no** `revokeSelfPermissionOnKill`/`revokeSelfPermissionsOnKill` call correlating with that disabling action |
| F2 | Dynamic verification (Method C) confirms the permission **remains granted** even though the related feature has long been disabled and the application has long been in the background |
| F3 | A feature requiring a dangerous permission is completely removed in an update version, but the related permission is **not also removed** from the manifest nor released via migration code |
| F4 | `targetSdkVersion` is already ≥33 (the API is available) yet the application makes no use of this mechanism at all for any permission that is clearly conditional/optional |

---

#### ✅ PASS — The check is declared PASSED if:

| No | Condition |
|---|---|
| P1 | Every disabling of an optional feature correlates with a `revokeSelfPermissionOnKill` call for the related permission |
| P2 | Dynamic verification confirms the permission is actually released (`granted=false`) after the feature is disabled and a reasonable background period has elapsed |
| P3 | The application displays a transparency dialog to the user when a permission is released (per the recommendation in §1.3 point 4) |
| P4 | `targetSdkVersion` is below 33 (the API is not yet available) — in this case, note it as a version-upgrade recommendation, not a pure implementation failure |
| P5 | The application has no conditional/optional permission at all — every dangerous permission is used consistently throughout the application's runtime |

---

#### ⚠️ Important Notes on Assessment

1. **Do not confuse this with system auto-reset** (§1.2) — this is the most fundamental mistake that can occur when evaluating this test. The existence of the Android 11+ auto-reset feature is **not** proof the application "passes" this test; auto-reset is a passive system safety net that runs independently of the application's code, on a monthly time scale that is far slower than the proactive response evaluated here.

2. **This API is only available since API 33** — the evaluation must take the application's `targetSdkVersion` into account. The absence of this implementation on an application with a low `targetSdkVersion` is a platform limitation, not purely a design oversight (though it remains worth recommending an upgrade).

3. **Focus on conditional/optional permissions** — not every permission needs this mechanism. A permission used **continuously** throughout the application's runtime (e.g. `INTERNET` for an always-online app) is not relevant to evaluate here; focus on permissions tied to **features that can be disabled/removed**.

4. **Dynamic verification (Method C) requires patience** — since the system itself determines the "safe time" to kill the process (§1.3), testing may need to simulate a sufficiently long background period or use additional debugging tooling to speed up this cycle in the test environment.

5. **Severity is generally low-to-medium** — this is about long-term permission lifecycle hygiene, not a directly active vulnerability; however, it contributes to cumulative risk surface and long-term user trust.

6. **Document:** the list of optional features tied to dangerous permissions, self-revocation implementation status for each, the application's `targetSdkVersion`, and the results of dynamic verification of permission status over time.

---

## 4. Recommendations

### 4.1 Implement Self-Revocation When a Feature Is Disabled

```kotlin
fun onLocationSharingToggled(enabled: Boolean) {
    sharedPreferences.edit().putBoolean("location_sharing_enabled", enabled).apply()
    if (!enabled) {
        // Feature disabled -> proactively release the related permission
        context.revokeSelfPermissionOnKill(Manifest.permission.ACCESS_FINE_LOCATION)
    }
}
```

### 4.2 Clean Up Permissions During Version Migration (Feature Removed)

```kotlin
// Migration code run when updating from an older version that still had the voice memo feature
fun migrateFromVersionWithVoiceMemoFeature() {
    if (permissionWasGrantedForRemovedFeature(Manifest.permission.RECORD_AUDIO)) {
        context.revokeSelfPermissionOnKill(Manifest.permission.RECORD_AUDIO)
    }
}
```

### 4.3 Inform the User Transparently

```kotlin
if (permissionsRevokedSinceLastLaunch.isNotEmpty()) {
    showDialog(
        title = "Permissions Updated",
        message = "We have removed access to ${permissionsRevokedSinceLastLaunch.joinToString()} " +
                "because the related feature is no longer in use. You can re-enable it anytime in Settings."
    )
}
```

### 4.4 Raise `targetSdkVersion` If Still Below 33

Refer to the complete discussion of the importance of an up-to-date `targetSdkVersion` in the MASTG-TEST-0245 document — this is an absolute technical prerequisite for this API to be usable at all.

### 4.5 Remediation Checklist

- [ ] All optional features that depend on a dangerous permission have been identified
- [ ] Every disabling of a related feature correlates with a `revokeSelfPermissionOnKill` call
- [ ] Version migration code cleans up permissions for removed features
- [ ] Users are informed transparently when a permission is released
- [ ] `targetSdkVersion` is already ≥33 to access this API
- [ ] Dynamic verification of permission status over time has been performed
- [ ] **Re-verify:** rerun MASTG-TEST-0257 whenever a new optional feature is added

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0257: Not Resetting Unused Permissions](https://mas.owasp.org/MASTG/tests/android/MASVS-PRIVACY/MASTG-TEST-0257/)
- [MASTG-TEST-0254: Dangerous App Permissions](https://mas.owasp.org/MASTG/tests/android/MASVS-PRIVACY/MASTG-TEST-0254/)
- [MASTG-TEST-0255: Permission Requests Not Minimized](https://mas.owasp.org/MASTG/tests/android/MASVS-PRIVACY/MASTG-TEST-0255/)
- [MASTG-TEST-0256: Missing Permission Rationale](https://mas.owasp.org/MASTG/tests/android/MASVS-PRIVACY/MASTG-TEST-0256/)
- [MASTG-TEST-0245: References to Platform Version APIs](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0245/)
- [MASWE-0066: Inadequate Permission Management](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0066/)

### 5.2 Official Android Documentation

- [Android Developers — Request App Permissions: Remove access to a permission](https://developer.android.com/training/permissions/requesting#remove-access)
- [Android Developers — `Context.revokeSelfPermissionOnKill()` API reference](https://developer.android.com/reference/android/content/Context#revokeSelfPermissionOnKill(java.lang.String))
- [Android Developers — Permissions Updates in Android 11 (Auto-Reset)](https://developer.android.com/about/versions/11/privacy/permissions)
- [Android Developers — App Hibernation](https://developer.android.com/topic/performance/app-hibernation)
- [Android Developers Blog — Making Permissions Auto-Reset Available to Billions More Devices](https://android-developers.googleblog.com/2021/09/making-permissions-auto-reset-available.html)
- [AOSP Source — App Hibernation](https://source.android.com/docs/core/perf/hiber)

### 5.3 Research and Community Articles

- [GeeksforGeeks — Understanding Self-Downgrading App Permissions in Android 13](https://www.geeksforgeeks.org/android/understanding-self-downgrading-app-permissions-in-android-13/)
- [CWE-459: Incomplete Cleanup](https://cwe.mitre.org/data/definitions/459.html)
- [CWE-250: Execution with Unnecessary Privileges](https://cwe.mitre.org/data/definitions/250.html)

### 5.4 Tool Documentation

- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [CodeQL — Documentation](https://codeql.github.com/docs/)
- [UI Automator — Testing framework](https://developer.android.com/training/testing/other-components/ui-automator)

---

*This document was compiled primarily from an elaboration of the official Android Developers documentation page "Remove access to a permission" directly referenced by the official MASTG-TEST-0257 note (placeholder status). The most important nuance: this test specifically evaluates an application's **proactive self-revocation** mechanism (`revokeSelfPermissionOnKill`, API 33+) — not the system-level passive auto-reset feature (Android 11+), which runs independently of application code and cannot be used as a reason an application "passes" without explicit implementation. This test completes the MASTG-TEST-0254/0255/0256 trio with a lifecycle dimension: a permission that was once proportional can become outdated over time, and a well-built application should actively recognize and respond to this change.*
