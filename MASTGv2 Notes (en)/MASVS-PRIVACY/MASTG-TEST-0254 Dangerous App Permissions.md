# MASTG-TEST-0254 Dangerous App Permissions

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0254 |
| **Platform** | Android |
| **MASVS Category** | MASVS-PRIVACY |
| **Weakness** | MASWE-0066 — *Inadequate Permission Management* |
| **Test Type** | Static, Code |
| **Profile** | **P (Privacy) only** — not L1/L2, evaluated purely from the user privacy standpoint, not purely from a technical security standpoint |
| **Knowledge** | MASTG-KNOW-0017 *(problematic reference — not found under the MASVS-PRIVACY category as the numbering convention would suggest; a reference-inconsistency pattern similar to the one already noted in the MASTG-TEST-0247 document)* |
| **Related Techniques** | MASTG-TECH-0117 (Obtaining AndroidManifest), MASTG-TECH-0126 (Obtaining App Permissions) |
| **Related Tests** | This test is the pure manifest-only version; consider it alongside testing of *runtime permission requests* and code-level *permission usage* analysis (outside this test's specific scope) |
| **Related Demo** | — (none) |
| **Official Rule** | `mastg-android-dangerous-app-permissions.yaml` — a complete list of all AOSP dangerous permissions, matched as literal XML patterns (see §3.2) |
| **Related CWE** | CWE-250 (Execution with Unnecessary Privileges), CWE-732 (Incorrect Permission Assignment for Critical Resource) |

---

## 1. Explanation

### 1.1 Testing Objective

Official MASTG overview quote:

> *"In Android apps, permissions are acquired through different methods to access information and system functionalities, including the camera, location, or storage. The necessary permissions are specified in the `AndroidManifest.xml` file with `<uses-permission>` tags."*

This test is purely an **inventory and contextual evaluation** of permissions categorized as **"dangerous"** under the official Android taxonomy (as distinct from the "normal" category which is granted automatically, or "signature" which is only for apps signed with the same certificate). Dangerous permission is the category that **requires explicit user consent at runtime** (since Android 6.0/API 23) because it potentially accesses data or functions with a significant privacy impact — camera, location, contacts, microphone, SMS, etc.

### 1.2 Profile "P" — Purely About Privacy, Not Technical Security

A metadata point worth highlighting: this test **only applies to the P (Privacy) profile**, unlike most other tests in this research series, which generally fall under L1/L2 (security baseline) or R (resilience). This reflects the nature of this test's evaluation, which is **not** about whether the permission is "technically safe" (e.g., whether `CAMERA` is exploited through a vulnerability), but rather **whether the existence of the permission itself is proportionate** to the app's functional needs from the user privacy lens — an evaluation that is far more contextual/policy-based than a binary technical test (vulnerable/not vulnerable).

### 1.3 A Highly Context-Dependent Evaluation Criterion — Not Merely a Blocklist

This is the most important characteristic that sets this test apart from most other tests in this research series. The official Evaluation clause literally looks simple:

> *"The test case fails if there are any dangerous permissions in the app."*

But the official overview immediately qualifies it with a **"Context Consideration"** clause that fundamentally changes how the criterion above should be read:

> *"Context is essential when evaluating permissions. For example, an app that uses the camera to scan QR codes should have the `CAMERA` permission. However, if the app does not have a camera feature, the permission is unnecessary and should be removed."*

This means the FAIL criterion is **NOT** "the app has any dangerous permission at all" (which would fail nearly every functional app — camera apps, navigation apps, and messaging apps all legitimately need dangerous permissions). The real criterion is: **"the app has a dangerous permission that is NOT proportionate to/needed by a feature that actually exists."** The literal official clause must **always** be read alongside this Context Consideration section — a literal reading alone will produce systematically wrong conclusions.

### 1.4 Proactive Recommendation: Privacy-Preserving Alternatives

The official overview does not stop at "remove it if unnecessary" — it also encourages evaluating **whether there is a way to achieve the same function without a dangerous permission at all**:

> *"Also, consider if there are any privacy-preserving alternatives to the permissions used by the app. For example, instead of using the `CAMERA` permission, the app could use the device's built-in camera app to capture photos or videos by invoking the `ACTION_IMAGE_CAPTURE` or `ACTION_VIDEO_CAPTURE` intent actions."*

This is an important architectural pattern: instead of the app **directly accessing** the camera hardware (which requires the `CAMERA` permission and runs within the app's own process — a higher risk if a bug/exploitation occurs in the code), the app can **delegate** the photo/video capture task to the system's built-in camera app via an Intent (`ACTION_IMAGE_CAPTURE`/`ACTION_VIDEO_CAPTURE`), then only receive the **final result** (an image/video file) without ever touching the raw camera API at all. A similar pattern applies to many other dangerous permissions — e.g., using the `Storage Access Framework` instead of direct `READ_EXTERNAL_STORAGE`, or a `Contact Picker Intent` instead of the full `READ_CONTACTS`.

### 1.5 Real-World Case: Avast's Research on Flashlight Apps

This is a case that perfectly illustrates the **"dangerous permission without a feature to justify it"** scenario described in §1.3 — a classic case in mobile security research:

> Avast's research analyzed **937 flashlight apps** on Google Play and found that this category of app **requests an average of 25 permissions**, with some apps requesting as many as **77 permissions**. The ten worst apps (with a combined ~5.5 million downloads) requested between 68-77 permissions. Among the permissions that are **hard to justify** for a feature as simple as turning on a flashlight: **77 apps requested `RECORD_AUDIO`**, **180 apps requested `READ_CONTACTS`**, **21 apps requested `WRITE_CONTACTS`**, plus location, Bluetooth, phone call, and SMS permissions.

The flashlight function **only needs** basic camera access (even on modern implementations, it is enough to use `CameraManager.setTorchMode()` without the `CAMERA` permission at all for simple use cases) — so requesting `RECORD_AUDIO`, `READ_CONTACTS`, or location access is **completely disproportionate** to the feature offered. This research concluded that although only a small portion (7 of 937) were officially classified as malicious/malware, **almost all of them** had sufficient system privileges to steal user data, disable antivirus scanning, or install malicious software — this is exactly the privacy risk this test aims to prevent: not about proven malicious intent, but about an unnecessary **risk surface**.

---

## 2. Tools Used for Testing

### 2.1 Required Tools (Core)

| Tool | Role |
|---|---|
| **aapt / aapt2** | `aapt d permissions app.apk` — the fastest official way to see all declared permissions |
| **adb** | `adb shell dumpsys package <package>` — viewing permissions along with their **runtime status** (granted/denied), useful for correlating with the installed app's actual behavior |
| **jadx / apktool** | Extracting `AndroidManifest.xml` per MASTG-TECH-0117 |
| **semgrep** | Running the official rule for quick detection |

### 2.2 Alternative & Supporting Tools

| Tool | Role |
|---|---|
| **MobSF** | Automatically classifies and displays all permissions (normal/dangerous/signature) with risk descriptions for each, within the Manifest Analysis report — very efficient for initial triage |
| **Exodus Privacy** | An APK analysis platform focused specifically on privacy — displays permissions **alongside detected third-party trackers**, providing additional context on *why* a permission might be requested (e.g., an ad SDK that needs location) |
| **Google Play Console (App Content > Data Safety)** | For published apps, the official data safety declaration can be compared against the actual permissions to find mismatches |
| **androguard** | `androguard axml`/Python API for programmatic permission extraction, suited for large-scale audits/CI |
| **CodeQL** | Checks whether declared permissions are actually **used** in the code (correlated APIs, e.g. the `Camera2 API` for `CAMERA`) — distinguishes permissions that are genuinely used from those that are declared but never realized in functionality |

### 2.3 Environment Prerequisites

- **No device/root required** for the core static analysis — the APK is enough.
- **Understanding of the app's actual features** is a key prerequisite (§1.3) — the tester needs to use the app directly or read the Play Store description/documentation to assess what features actually exist, as a basis for assessing permission proportionality.
- **The list of Android dangerous permissions changes across API versions** — always refer to the latest official source (the AOSP `AndroidManifest.xml` or the `Manifest.permission` reference) rather than a static list that may be outdated.

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0117** to obtain `AndroidManifest.xml`.
2. Use **MASTG-TECH-0126** to obtain the list of declared permissions.

### 3.2 Method A — aapt/adb *(fastest official method)*

```bash
aapt d permissions target-app.apk
```

```bash
adb install target-app.apk
adb shell dumpsys package org.owasp.mastestapp | grep -A20 "requested permissions:"
```

### 3.3 Method B — Official Semgrep Rule (Complete List of AOSP Dangerous Permissions)

```yaml
rules:
  - id: detect-dangerous-android-permissions
    languages: [xml]
    message: "Dangerous Android permission found:"
    severity: WARNING
    pattern-either:
      - pattern: <uses-permission android:name="android.permission.CAMERA"/>
      - pattern: <uses-permission android:name="android.permission.RECORD_AUDIO"/>
      - pattern: <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION"/>
      - pattern: <uses-permission android:name="android.permission.READ_CONTACTS"/>
      # ... (see the full file: mastg-android-dangerous-app-permissions.yaml, covering 40+ permissions)
```

```bash
semgrep --config https://raw.githubusercontent.com/OWASP/mastg/master/rules/mastg-android-dangerous-app-permissions.yaml ./out/resources/AndroidManifest.xml
```

**Note on this rule**: this rule is one of the **most comprehensive** found in this research series' documents — covering more than 40 individual dangerous permissions per the official AOSP list (`frameworks/base/core/res/AndroidManifest.xml`), including relatively new permissions such as `NEARBY_WIFI_DEVICES`, `READ_MEDIA_VISUAL_USER_SELECTED`, `BODY_SENSORS_BACKGROUND`, and `POST_NOTIFICATIONS`. However, being a literal pattern-matching rule, it **only detects presence** and **cannot at all assess proportionality**, which is the core of this test's evaluation (§1.3) — manual contextual validation is still absolutely required after running this rule.

### 3.4 Method C — MobSF (Automatic Classification + Risk Context)

```bash
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest
```

MobSF's **Manifest Analysis** section automatically groups permissions into categories (`dangerous`, `normal`, `signature`) along with a brief risk description for each — speeding up initial triage before manual contextual analysis.

### 3.5 Method D — Exodus Privacy (Third-Party Tracker Context)

```bash
# Via the web (upload the APK) or the exodus-standalone CLI
pip install exodus-standalone
exodus-standalone target-app.apk
```

Exodus's results map detected **third-party tracker SDKs** alongside the permission list — very useful for cases where a dangerous permission turns out to be needed not by the app's core feature, but by a bundled ad/analytics SDK (e.g., `ACCESS_FINE_LOCATION` that turns out to be used by an ad targeting SDK, not the app's map feature).

### 3.6 Method E — CodeQL (Verifying Actual Code Usage)

```ql
import java

class CameraPermissionUsage extends MethodAccess {
  CameraPermissionUsage() {
    this.getMethod().getDeclaringType().getASupertype*().hasQualifiedName("android.hardware.camera2", "CameraManager") or
    this.getMethod().getDeclaringType().hasQualifiedName("android.hardware", "Camera")
  }
}

from CameraPermissionUsage usage
select usage, "Camera API usage found — correlate with the CAMERA permission declaration in the manifest"
```

If a permission is declared in the manifest **but no usage of its related API is found in the code** (empty query result), this is a strong indication that the permission is **unused** — a strong FAIL candidate per the Context Consideration clause (§1.3).

### 3.7 Method Comparison: Which to Use When

| Method | Tool | Detects presence? | Assesses proportionality/context? | When to use |
|---|---|---|---|---|
| **A** | aapt/adb | ✅ | ❌ | Fastest official baseline |
| **B** | Official semgrep rule | ✅ (most comprehensive) | ❌ | Automated baseline, CI/CD |
| **C** | MobSF | ✅ + categorization | Partial (generic risk descriptions) | Quick triage |
| **D** | Exodus Privacy | ✅ + tracker correlation | ✅ (reveals third-party SDK sources) | Answers "who is this permission for" |
| **E** | CodeQL | ✅ (indirect) | ✅ (verifies actual usage) | Answers "is it really used" |

**Minimum recommended combination:** **A/B (full inventory) → E (verify actual code usage) → D (identify third-party SDK sources for unexplained permissions) → manual contextual assessment** against the app's actual features (§1.3), ideally by trying the app directly or reading its official Play Store description.

---

### 3.8 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rule:**

> **Observation:** *"The output should contain the list of permissions declared by the app."*
>
> **Evaluation:** *"The test case fails if there are any dangerous permissions in the app"* — **to be read together with the Context Consideration clause**, which requires assessing proportionality against the app's features.

---

#### ❌ FAIL / ISSUE — The check is declared FAILED when:

| No | Condition |
|---|---|
| F1 | A dangerous permission is declared **without a feature justifying it** in the app (confirmed either through direct use or Method E CodeQL showing no usage of the related API) |
| F2 | A dangerous permission is used for a feature that **has a privacy-preserving alternative** that has not been adopted (e.g., full `CAMERA` used only to capture a single profile photo, when `ACTION_IMAGE_CAPTURE` would suffice) |
| F3 | A dangerous permission confirmed (Method D) to be used by a **third-party SDK** (ads/analytics) with no connection to the core feature the app claims, and not transparently disclosed to the user |
| F4 | A pattern matching the Avast research case (§1.5) — permissions whose quantity and type far exceed what is needed by the app's described core function |

**Example evidence (illustrative — MASTG does not yet provide an official demo for this test):**

```bash
$ aapt d permissions flashlight-app.apk
package: com.example.flashlightapp
uses-permission: name='android.permission.CAMERA'
uses-permission: name='android.permission.RECORD_AUDIO'
uses-permission: name='android.permission.READ_CONTACTS'
uses-permission: name='android.permission.ACCESS_FINE_LOCATION'
```

```bash
$ # App feature verification: only turns the flashlight on/off, no audio recording/contacts/location feature
$ # CodeQL: no usage found of the AudioRecord, ContactsContract, or FusedLocationProviderClient APIs in the code
```

Interpretation: `RECORD_AUDIO`, `READ_CONTACTS`, and `ACCESS_FINE_LOCATION` do not correlate with any observed feature of this flashlight app — **FAIL** with three disproportionate permissions, exactly the pattern revealed by the Avast research.

---

#### ✅ PASS — The check is declared PASSED when:

| No | Condition |
|---|---|
| P1 | **No** dangerous permissions are declared at all |
| P2 | Every declared dangerous permission **clearly correlates** with a feature that genuinely exists and is used in the app (confirmed by Method E) |
| P3 | For every dangerous permission used, it has been considered and documented why a privacy-preserving alternative (Intent delegation, etc.) is not suitable for that use case |
| P4 | Permissions used by third-party SDKs (confirmed by Method D) are transparently disclosed in the app's privacy policy/Data Safety |

---

#### ⚠️ Important Notes on Assessment

1. **Never conclude FAIL purely from the existence of a dangerous permission without contextual evaluation.** This is the most fatal error for this test — a literal reading of the Evaluation clause without considering the Context Consideration (§1.3) will produce massive false positives on nearly every functional app.

2. **Camera, navigation, and communication apps legitimately need dangerous permissions** — focus the evaluation on **proportionality and scope**, not binary presence. `CAMERA` on a professional camera app is clearly proportionate; `CAMERA` on a calculator app clearly is not.

3. **Always try to understand the app's actual features** before assessing — this is a test that **cannot** be done purely from code/manifest analysis without an understanding of the product's functionality. Ideally, use the app directly or read its official description.

4. **Use Exodus Privacy to reveal "who is actually using this permission"** — a permission that appears unrelated to the core feature often turns out to be used by a bundled third-party SDK rather than the app's own code.

5. **Pay attention to the granular permission trend since Android 13+** (e.g., `READ_MEDIA_IMAGES`/`READ_MEDIA_VIDEO`/`READ_MEDIA_AUDIO` replacing the broader-scoped `READ_EXTERNAL_STORAGE`) — an app that still requests the older, broader permission when it only needs a specific subset (e.g., only images) is a good finding candidate, since a narrower granularity is available but not utilized.

6. **Severity is modulated:**

   | Factor | Severity |
   |---|---|
   | A sensitive dangerous permission (location, microphone, contacts) with no justifying feature at all | **High** (from a privacy perspective) |
   | A dangerous permission used by a real feature but with a scope broader than needed (e.g., full `READ_EXTERNAL_STORAGE` when the Storage Access Framework would suffice) | **Medium** |
   | A proportionate dangerous permission matching a feature, with no clearly better privacy-preserving alternative | **Not a finding** |

7. **Document:** the full list of dangerous permissions, the app feature claiming to need each one (or its absence), the code usage verification result (Method E), the third-party SDK source where relevant (Method D), and the assessment of available privacy-preserving alternatives.

---

## 4. Recommendations

### 4.1 Remove Unused Permissions

```xml
<!-- BEFORE -->
<uses-permission android:name="android.permission.READ_CONTACTS"/>  <!-- not used by any feature -->

<!-- AFTER: removed entirely -->
```

### 4.2 Use Privacy-Preserving Alternatives (Per §1.4)

```kotlin
// BEFORE: direct camera access, requires the CAMERA permission
// AFTER: delegate to the system camera app
val takePictureIntent = Intent(MediaStore.ACTION_IMAGE_CAPTURE)
startActivityForResult(takePictureIntent, REQUEST_IMAGE_CAPTURE)
// No <uses-permission android:name="android.permission.CAMERA"/> needed at all
```

### 4.3 Use Modern Granular Permissions

```xml
<!-- BEFORE (Android 12 and below, broad scope) -->
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>

<!-- AFTER (Android 13+, granular to the need) -->
<uses-permission android:name="android.permission.READ_MEDIA_IMAGES"/>
```

### 4.4 Audit Third-Party SDKs Regularly

Run Exodus Privacy (Method D) as a routine part of evaluating new dependencies — permissions that "suddenly" appear in the final manifest often come from a newly added SDK, not the app's own code.

### 4.5 Integrate into CI/CD

```bash
#!/bin/bash
# ci-check-permission-proportionality.sh
APK=$1
aapt d permissions "$APK" > declared_permissions.txt
semgrep --config ./mastg-android-dangerous-app-permissions.yaml ./decompiled/resources/AndroidManifest.xml
# Compare against a whitelist of permissions the team has already approved for existing features
```

### 4.6 Remediation Checklist

- [ ] All dangerous permissions have been inventoried and correlated with real features (Method E)
- [ ] Unused/disproportionate permissions have been removed
- [ ] Privacy-preserving alternatives (Intent delegation) have been considered for every remaining dangerous permission
- [ ] Modern granular permissions (API 33+) have been adopted to replace older broad-scope permissions
- [ ] Third-party SDKs have been audited for their permission sources (Exodus Privacy)
- [ ] Remaining permissions are transparently disclosed in the privacy policy/Data Safety
- [ ] **Re-verify:** re-run MASTG-TEST-0254 for every new dependency/feature addition

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0254: Dangerous App Permissions](https://mas.owasp.org/MASTG/tests/android/MASVS-PRIVACY/MASTG-TEST-0254/)
- [MASWE-0066: Inadequate Permission Management](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0066/)
- [MASTG-TECH-0117: Obtaining Information from the AndroidManifest](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0117/)
- [MASTG-TECH-0126: Obtaining App Permissions](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0126/)
- [Official rule: mastg-android-dangerous-app-permissions.yaml (GitHub)](https://github.com/OWASP/mastg/blob/master/rules/mastg-android-dangerous-app-permissions.yaml)
- [OWASP Mobile Top 10 2024 — M6: Inadequate Privacy Controls](https://owasp.org/www-project-mobile-top-10/2023-risks/m6-inadequate-privacy-controls)

### 5.2 Official Android Documentation

- [Android Developers — `Manifest.permission` reference](https://developer.android.com/reference/android/Manifest.permission)
- [AOSP Source — Full List of Dangerous Permissions (AndroidManifest.xml)](https://android.googlesource.com/platform/frameworks/base/+/master/core/res/AndroidManifest.xml)
- [Android Developers — Minimize Permission Requests](https://developer.android.com/privacy-and-security/minimize-permission-requests)
- [Android Developers — Request App Permissions](https://developer.android.com/training/permissions/requesting)
- [Android Developers — Photo Picker (privacy-preserving alternative for storage)](https://developer.android.com/training/data-storage/shared/photopicker)

### 5.3 Research and Real-World Cases

- [Avast — Flashlight Apps on Google Play Request Up to 77 Permissions](https://blog.avast.com/flashlight-apps-on-google-play-request-up-to-77-permissions-avast-finds)
- [SecurityWeek — Android Flashlight Apps Request 77 Permissions](https://www.securityweek.com/android-flashlight-apps-request-77-permissions/)
- [Forbes — Google Play Warning: Harmless Flashlight Apps Secretly Access Data](https://www.forbes.com/sites/zakdoffman/2019/09/15/google-warning-as-harmless-apps-installed-by-millions-secretly-access-user-data-report/)
- [Exodus Privacy](https://exodus-privacy.eu.org/)
- [CWE-250: Execution with Unnecessary Privileges](https://cwe.mitre.org/data/definitions/250.html)
- [CWE-732: Incorrect Permission Assignment for Critical Resource](https://cwe.mitre.org/data/definitions/732.html)

### 5.4 Tool Documentation

- [aapt2 — Android Asset Packaging Tool](https://developer.android.com/tools/aapt2)
- [Semgrep — Documentation](https://semgrep.dev/docs/)
- [CodeQL — Documentation](https://codeql.github.com/docs/)
- [MobSF — Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)
- [Exodus Standalone (CLI)](https://github.com/Exodus-Privacy/exodus-standalone)
- [androguard](https://github.com/androguard/androguard)

---

*This document was compiled based on OWASP MASTG (latest release as of September 2026), official Android Developers and AOSP documentation, and Avast's research on flashlight apps as a real-world example of "dangerous permission without a justifying feature." The most important nuance of this test: the literal evaluation criterion ("fails if there is any dangerous permission") must **always** be read alongside the official Context Consideration clause — a literal reading without a feature-proportionality assessment will produce systematic false positives on nearly every functional app.*
