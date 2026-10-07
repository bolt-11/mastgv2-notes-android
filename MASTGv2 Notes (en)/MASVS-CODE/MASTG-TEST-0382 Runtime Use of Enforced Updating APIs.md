# MASTG-TEST-0382 Runtime Use of Enforced Updating APIs

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0382 |
| **Platform** | Android |
| **MASVS Category** | MASVS-CODE |
| **Weakness** | MASWE-0043 |
| **Test Type** | Dynamic, Network, Hooks, **Manual** |
| **Related Techniques** | MASTG-TECH-0005, MASTG-TECH-0010 (Capture App Traffic), MASTG-TECH-0043, MASTG-TECH-0023 |
| **Related Knowledge** | MASTG-KNOW-0023 (Enforced Updating) |
| **Official Rule** | — (none exists; purely dynamic and behavioral, with no static counterpart in the current catalog) |

---

## 1. Explanation

### 1.1 Testing Objective and Why Enforced Updating Matters for Security

Quote from the official MASTG overview:

> *"At runtime, Android apps implementing enforced updating typically either invoke the Google Play In-App Updates API... or perform a custom version check... If the app does not perform this check before access to protected functionality or backend services, or if the enforcement can be bypassed... the app fails to properly enforce the update."*

MASTG-KNOW-0023 explains **why** forcing updates matters from a security standpoint, rather than being just a regular product feature:

> *"Forcing a user to update the application can be necessary in multiple cases: A client-side vulnerability was discovered which needs to be fixed. Cryptographical key material that needs to be rotated (e.g. public key pinning). Migrating to a new API so that the old API can be decommissioned more quickly."*

This confirms that enforced updating is an **incident-response mechanism** — when a vulnerability is found in an app version already widely deployed, the only way to guarantee the **entire user base** is actually protected is to force them to migrate to the fixed version, rather than simply providing the update and hoping users install it voluntarily.

### 1.2 Important Note: Updating Does Not Fix Backend Problems

A nuance that is often overlooked but is explicitly stated:

> *"Keep in mind that updating the app does not resolve vulnerabilities residing on backend systems. A secure update mechanism should complement proper API and service lifecycle management."*

This is relevant to a broader evaluation context — enforced updating is **one component** of a broader API/version lifecycle security strategy, not a standalone solution. If the real vulnerability resides on the backend (not the client), forcing a client update will not resolve the root cause — the backend must still independently enforce its own API versioning and deprecation policy.

### 1.3 Two Different Mechanisms: Play In-App Updates API vs Backend-Gated Flow

| Mechanism | When Used | Core API |
|---|---|---|
| **Google Play In-App Updates API** | App distributed via Google Play, device supports it (API 21+) | `AppUpdateManager`, `getAppUpdateInfo()`, `startUpdateFlowForResult()` |
| **Backend-Gated Flow (custom)** | Distribution outside the Play Store, or stricter enforcement is required | `BuildConfig.VERSION_CODE`/`VERSION_NAME`, `PackageManager.getPackageInfo()`, compared against a `minVersion` from the backend |

MASTG-KNOW-0023 explicitly confirms the advantage of the official API over older, fragile approaches:

> *"This mechanism is far more reliable than legacy methods such as scraping Play Store pages or calling undocumented endpoints, which are unstable and unsupported."*

### 1.4 Two Play In-App Update Modes and Three Specific Enforcement Failure Scenarios

> *"Immediate updates, which use a full-screen flow requiring the user to update and restart the app before continuing... Flexible updates, which allow users to continue using the app while the update downloads in the background."*

For **immediate** updates (the mode relevant to critical vulnerabilities), the official overview identifies **three very specific enforcement failure scenarios** that must be tested one by one:

> *"Users can cancel or decline an immediate update, and an immediate update can become stalled if the app is closed or backgrounded before completion."*

1. **Direct dismissal** — the user closes the update dialog without proceeding.
2. **Cancellation mid-process** — the update flow has started but is canceled before completion.
3. **Backgrounding** — the app is minimized/closed before the update process completes, producing a `UpdateAvailability.DEVELOPER_TRIGGERED_UPDATE_IN_PROGRESS` status that **must** be handled:

> *"The app should... check update state when the app returns to the foreground, for example in `onResume`... If `UpdateAvailability.DEVELOPER_TRIGGERED_UPDATE_IN_PROGRESS` is reported, restart the immediate update flow."*

These three scenarios directly form the basis for the dynamic testing structure of this test (§3) — the tester **must** try each one separately, because an app could handle the first scenario correctly yet fail on the third (backgrounding), or vice versa.

### 1.5 Limitations of Play Console Recovery Tools: Not a Substitute for Real Enforcement

An important note relevant to evaluation — there is a **Play Console–level** mechanism that looks like enforcement but is actually much weaker:

> *"Google Play also provides Play Console recovery tools that can prompt users... This is configured in Play Console rather than implemented directly in app code, and it should not be treated as a substitute for app-side or server-side enforcement when strict blocking is required, because users can dismiss the prompt and will be shown it again after a cold restart."*

It is important to distinguish: the Play Console prompt is **not** true blocking — the user can still close the dialog and continue fully using the old version of the app, only to be reminded again after a cold restart. If an application **solely** relies on this mechanism and calls it an "enforced update," this is an architectural misunderstanding that should be flagged as a finding.

### 1.6 Good Backend-Gated Flow Practices, Including Integrity Considerations

MASTG-KNOW-0023 provides concrete guidance for backend-gated flows, including a security point that is often overlooked:

> *"Enforce the policy on backend services where possible by rejecting requests from unsupported app versions, especially for security-critical updates."*
>
> *"Consider integrity and tamper resistance. Avoid trusting only client-provided data, use platform integrity signals where appropriate, sign update policy responses if they are security-sensitive, and handle offline scenarios with a cached policy, a reasonable TTL, and a safe fallback."*

This first point is crucial — **truly robust enforcement** does not rely solely on UI blocking on the client (which is inherently bypassable through local manipulation), but also rejects **the API requests themselves** from unsupported versions on the server side. This aligns with the defense-in-depth principle that recurs throughout this research series — a client-side check alone, no matter how well designed, remains vulnerable to manipulation by an attacker who has full control over their own device (root, Frida, proxy interception).

---

## 2. Tools Used for Testing

### 2.1 Required Tools (Core)

| Tool | Function |
|---|---|
| **ADB** | Installing the app, controlling the app's lifecycle (background/foreground) to replicate the scenarios in §1.4 |
| **mitmproxy/Burp Suite** | Capturing traffic (MASTG-TECH-0010) and manipulating version values sent to the backend |
| **Frida** | Hooking `AppUpdateManager`/`getAppUpdateInfo()`/`startUpdateFlowForResult()` (MASTG-TECH-0043) |

### 2.2 Alternative & Supporting Tools

| Tool | Function |
|---|---|
| **Objection** | Quickly exploring update-related method calls without a custom script |
| **adb shell am** | Simulating forced backgrounding/cold restart to test the `DEVELOPER_TRIGGERED_UPDATE_IN_PROGRESS` scenario |

### 2.3 Environment Prerequisites

- Device/emulator with Google Play Services (for testing the Play In-App Updates API) OR traffic-interception capability (for backend-gated flow).
- Ability to install an **older** app version than the expected minimum version, to realistically trigger an "update required" condition.

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0005** to install the application.
2. Use **MASTG-TECH-0010** to capture application traffic.
3. Use **MASTG-TECH-0043** to hook the relevant APIs.
4. Exercise the application extensively to trigger as many flows as possible.

### 3.2 Method A — Hook the Play In-App Updates API

```javascript
Java.perform(function () {
    var AppUpdateManager = Java.use("com.google.android.play.core.appupdate.AppUpdateManagerFactory");
    // Hook getAppUpdateInfo and startUpdateFlowForResult to observe when/whether they are called
    var Mgr = Java.use("com.google.android.play.core.appupdate.AppUpdateManager");
    Mgr.getAppUpdateInfo.implementation = function () {
        console.log("[getAppUpdateInfo] called");
        return this.getAppUpdateInfo();
    };
});
```

### 3.3 Method B — Replicate the Three Enforcement Failure Scenarios (Mandatory, Per §1.4)

```
Manual procedure:
1. Trigger the immediate update flow → close the dialog directly without proceeding → observe whether access remains blocked
2. Trigger the immediate update flow → start the process → cancel it mid-way → observe the access status
3. Trigger the immediate update flow → background the app (Home button) before completion → return to the foreground via adb → observe whether the app detects DEVELOPER_TRIGGERED_UPDATE_IN_PROGRESS and blocks access
```

```bash
adb shell am start -n com.example.app/.MainActivity  # return to foreground after manual backgrounding
```

### 3.4 Method C — Version Manipulation for Backend-Gated Flow

```bash
mitmproxy --mode regular
```

```python
# mitmproxy addon script to lower the versionCode sent
def request(flow):
    if "versionCode" in flow.request.text:
        flow.request.text = flow.request.text.replace('"versionCode":100', '"versionCode":1')
```

Observe: does the backend respond with an "update required" policy, and does the app actually block access according to that response? Conversely, also try **artificially increasing** the versionCode to test whether the app can "trick itself" past enforcement.

### 3.5 Method Comparison: When to Use Which

| Method | Tool | When to Use |
|---|---|---|
| **A** | Frida | Baseline observation of Play In-App Updates API calls |
| **B** | Manual + ADB | **Required** — testing the three specific failure scenarios |
| **C** | mitmproxy | **Required** for backend-gated flow — testing direct version manipulation |

**Minimum recommended combination:** **A/C (depending on which mechanism the app uses) → B (mandatory for both mechanisms)**.

---

### 3.6 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rule:**

> **Evaluation:** *"The test case fails if the app does not perform a runtime update check, or if the update is not enforced at runtime."*

---

#### ❌ FAIL / ISSUE — The check is declared FAILED if:

| No | Condition |
|---|---|
| F1 | There is no update check at all at runtime |
| F2 | The user can bypass enforcement by closing the dialog/canceling the process/backgrounding the app |
| F3 | Lowering the versionCode sent to the backend does not trigger an enforced "update required" response |

**Evidence example:**

```
Scenario: Backgrounding during the immediate update flow
1. The update dialog appears, the download process starts
2. Press the Home button, wait 10 seconds
3. Bring the app back to the foreground via adb shell am start
4. RESULT: The dashboard opens directly without the DEVELOPER_TRIGGERED_UPDATE_IN_PROGRESS status being handled
```

**FAIL** — enforcement fails after backgrounding.

---

#### ✅ PASS — The check is declared PASSED if:

| No | Condition |
|---|---|
| P1 | The update check is performed before access to protected functionality, **and** |
| P2 | All three failure scenarios (dismiss, cancel, background) remain correctly blocked, **and** |
| P3 | *(for backend-gated)* Lowering the versionCode triggers real enforcement, **and** the backend also rejects requests from the old version (not just UI blocking on the client) |

---

#### ⚠️ Important Notes on Assessment

1. **Do not settle for one successful scenario** — per §1.4, test all three failure scenarios separately; an app that handles dismissal correctly might still fail the backgrounding scenario.

2. **Distinguish the Play Console recovery prompt from real enforcement** — per §1.5, do not mistake a prompt that can be dismissed and reappears after a cold restart for an effective blocking mechanism.

3. **For backend-gated flow, verify enforcement on BOTH sides** — client-side blocking alone is not sufficient; also check whether the backend independently rejects API requests from old versions (§1.6), since the client-side check can be bypassed by an attacker who has full control over the device.

4. **Severity is modulated as follows:**

   | Factor | Severity |
   |---|---|
   | No enforcement at all, update relates to a critical security vulnerability | **High** |
   | Enforcement exists but can be bypassed via any of the three failure scenarios | **Medium-High** |
   | Client-side enforcement is solid but the backend does not independently reject old versions | **Medium** |
   | All three PASS criteria are fully met | **Not a finding** |

5. **Document:** the mechanism used (Play In-App Updates/backend-gated), the result of each test scenario (dismiss/cancel/background), the result of the versionCode manipulation, and whether the backend enforces the policy independently.

---

## 4. Recommendations

### 4.1 Handle the DEVELOPER_TRIGGERED_UPDATE_IN_PROGRESS Status

```kotlin
override fun onResume() {
    super.onResume()
    appUpdateManager.appUpdateInfo.addOnSuccessListener { info ->
        if (info.updateAvailability() == UpdateAvailability.DEVELOPER_TRIGGERED_UPDATE_IN_PROGRESS) {
            appUpdateManager.startUpdateFlowForResult(info, AppUpdateType.IMMEDIATE, this, REQUEST_CODE)
        }
    }
}
```

### 4.2 Dual Enforcement: Client Blocking + Backend Rejection

```kotlin
if (versionCode < minRequiredVersion) {
    showBlockingUpdateDialog() // non-dismissible
    return
}
```

```
Backend: reject all API requests with X-App-Version < minVersion with HTTP 426 Upgrade Required
```

### 4.3 Remediation Checklist

- [ ] The `DEVELOPER_TRIGGERED_UPDATE_IN_PROGRESS` status is handled in `onResume`/another entry point
- [ ] The mandatory update dialog is non-dismissible, cannot be canceled
- [ ] The backend rejects requests from unsupported versions independently of the client
- [ ] The Play Console recovery prompt is not relied upon as the sole enforcement mechanism
- [ ] Re-tested against all three failure scenarios after every change

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0382 (source, tests-beta)](https://github.com/OWASP/mastg/blob/master/tests-beta/android/MASVS-CODE/MASTG-TEST-0382.md)
- [MASTG-KNOW-0023: Enforced Updating](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0023/)

### 5.2 Official Documentation

- [Android Developers: In-App Updates](https://developer.android.com/guide/playcore/in-app-updates)
- [Google Play: Prompt Users to Update to Your Latest App Version](https://support.google.com/googleplay/android-developer/answer/13812041)
- [Firebase Remote Config](https://firebase.google.com/docs/remote-config)

### 5.3 Tool Documentation

- [mitmproxy Documentation](https://docs.mitmproxy.org/stable/)
- [Frida — Dynamic Instrumentation Toolkit](https://frida.re/docs/home/)

---

*This document was prepared based on official OWASP MASTG content (`tests-beta/android/MASVS-CODE/MASTG-TEST-0382.md`, `MASTG-KNOW-0023`). This test has no corresponding Semgrep rule or static test counterpart in the current MASTG catalog — it is entirely dynamic and behavioral, because assessing "whether enforcement actually blocks access" requires observing actual runtime behavior, not merely the presence of API references in the code. The most important methodological nuance: the evaluation must cover the three specific failure scenarios explicitly named in the official overview (dismissing the dialog, canceling mid-process, backgrounding the app) separately — passing one scenario does not guarantee passing another. For backend-gated flow, truly robust enforcement requires independent rejection on the server side, not just UI blocking on the client, which is inherently manipulable by an attacker with full control over their own device.*
