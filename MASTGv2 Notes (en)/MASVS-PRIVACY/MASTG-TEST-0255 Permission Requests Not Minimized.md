# MASTG-TEST-0255 Permission Requests Not Minimized

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0255 |
| **Platform** | Android |
| **MASVS Category** | MASVS-PRIVACY |
| **Weakness** | MASWE-0066 — *Inadequate Permission Management* (same as MASTG-TEST-0254) |
| **Official MASTG Status** | **`placeholder`** — no complete Overview/Steps/Evaluation yet |
| **Official Note (the only content available)** | *"This test checks if the app requests permissions that have privacy-preserving alternatives."* |
| **Profile** | **P (Privacy) only** |
| **Knowledge** | MASTG-KNOW-0017 *(problematic reference, as already noted in the MASTG-TEST-0254 document)* |
| **Related Tests** | **MASTG-TEST-0254** (Dangerous App Permissions — checks the **proportionality** of a permission relative to a feature; this test goes one step further: it checks **whether the feature itself can be achieved without a dangerous permission at all**) |
| **Related Demo** | — (none) |
| **Official Rule** | — (none) |
| **Related CWE** | CWE-250 (Execution with Unnecessary Privileges) |

---

## 1. Explanation

### 1.1 The Status of This Test and Its Relationship to MASTG-TEST-0254

This test has `placeholder` status — only a single official note sentence is available. However, that sentence was actually **already touched on** in the MASTG-TEST-0254 document (§1.4) as part of its "Context Consideration" clause:

> *"Also, consider if there are any privacy-preserving alternatives to the permissions used by the app."*

MASTG-TEST-0255 essentially **elevates this point into a standalone test** with a narrower, more specific focus:

| | MASTG-TEST-0254 | MASTG-TEST-0255 *(this document)* |
|---|---|---|
| **Core question** | Is this dangerous permission **proportional** to the feature that exists? | Can the same feature be achieved **without** this dangerous permission at all, via an alternative mechanism provided by the platform? |
| **FAIL condition** | The permission exists but the feature is absent/unclear | The permission exists, the feature **does genuinely and legitimately exist**, but the platform provides a way to achieve the same feature without that permission |

In other words: MASTG-TEST-0254 answers "does this permission make sense?", while MASTG-TEST-0255 answers "even though it makes sense, is this truly the **most minimal** way to achieve it?" — a question that remains relevant even for permissions that have **already passed** the MASTG-TEST-0254 evaluation.

### 1.2 A Complete Map of Privacy-Preserving Alternatives per Permission Category

Because there are no official Steps/Evaluation, this document refers to the **official Android Developers guidance** ("Minimize Permission Requests") which is explicitly cited in the MASTG-TEST-0254 overview as the primary source of the following patterns. This is the complete map of alternatives used as the evaluation reference for this test:

| Dangerous Permission | Privacy-Preserving Alternative | Mechanism |
|---|---|---|
| `CAMERA` | Delegate to the system camera app | `ACTION_IMAGE_CAPTURE` / `ACTION_VIDEO_CAPTURE` Intent |
| `CAMERA` (for barcode/QR scanning) | No need for raw camera access | Google Code Scanner API / ML Kit Barcode Scanning API |
| `CAMERA` (for payment card input) | No need for raw camera access | Debit and Credit Card Recognition library (Google Play services) |
| `READ_EXTERNAL_STORAGE` / `READ_MEDIA_*` (selecting photos/videos) | No runtime permission needed at all | **Photo Picker** (`ActivityResultContracts.PickVisualMedia`) |
| `READ_EXTERNAL_STORAGE` (accessing documents owned by other apps) | Access limited by design | Storage Access Framework (`ACTION_OPEN_DOCUMENT`) |
| `READ_CONTACTS` (selecting one/several contacts) | Access restricted to only the contact(s) the user selects | **Contact Picker** Intent (`ACTION_PICK`) |
| `ACCESS_FINE_LOCATION` (momentary need, "search nearby here") | No need for continuous location permission | Location Button / one-time location request |
| `ACCESS_FINE_LOCATION` (low-precision need) | Coarse location is sufficient | Use `ACCESS_COARSE_LOCATION` instead of `ACCESS_FINE_LOCATION` |
| `ACCESS_FINE_LOCATION`/`ACCESS_COARSE_LOCATION` (for Bluetooth device pairing) | No location/Bluetooth admin permission needed at all | **Companion Device Pairing API** |
| `READ_SMS` (OTP verification) | No need to read the entire SMS inbox | **SMS Retriever API** or SMS User Consent API |
| `READ_PHONE_STATE` (phone number verification) | No need for full phone state | Digital Credentials API / Phone Number Hint library |
| `READ_PHONE_STATE` (spam call filtering) | Sufficient via the official screening API | `CallScreeningService` |
| `READ_PHONE_STATE` (handling audio interruption on incoming calls) | No need for phone state at all | `AudioManager.OnAudioFocusChangeListener` |
| `CALL_PHONE` (placing a call) | Delegate to the system phone app | `ACTION_DIAL` Intent (not `ACTION_CALL`) |
| Device ID access (IMEI, etc.) | No need for a permanent device-level identifier | Instance ID library / per-app scoped `UUID.randomUUID()` |

### 1.3 Core Principle: Intent-Based Delegation and Scoped Picker APIs

All the patterns above share the **same architectural philosophy**, explicitly summarized by official Android documentation:

> *"Use intent-based approaches, pickers, and scoped APIs rather than declaring broad permissions."*

There are two categories of mechanism underlying almost all of these alternatives:

1. **Delegation via Intent to a system component** (`ACTION_IMAGE_CAPTURE`, `ACTION_DIAL`, `ACTION_PICK`): the app **never directly touches** sensitive data/hardware. The operating system (via the built-in camera/phone/contacts app) handles the sensitive interaction, and the app only receives the **final result** (a photo URI, a contact selection result) via an `ActivityResult` callback. Because the app never holds direct access to the sensitive hardware/database, it **needs no permission** for it at all.
2. **Scoped Picker API** (Photo Picker, Storage Access Framework): the user explicitly **selects the specific item(s)** the app is allowed to access (a single photo, a single document), and the system grants access **only to the selected item(s)** — not full access to the entire gallery/storage. This is the *least privilege* principle applied at the data-granularity level, not merely at the permission-category level.

### 1.4 Why This Test Is Significant Even When the Feature Is "Legitimate"

This is an important nuance that sets this test apart from a first impression one might have. A photo gallery app that requests `READ_EXTERNAL_STORAGE`/`READ_MEDIA_IMAGES` for the **feature of selecting a profile photo** will **pass** MASTG-TEST-0254 (the feature exists, the permission is proportional to that feature) — yet can still **FAIL** MASTG-TEST-0255, because the **Photo Picker** provides a way to achieve exactly the same feature (selecting a single photo) **without needing any runtime permission at all**. The difference in impact on the user is real: with the Photo Picker, the app **never** sees the user's full gallery — only the specific photo they selected; with full `READ_MEDIA_IMAGES`, the app **potentially** (technically, even if perhaps unintentionally) can read the user's entire photo collection.

### 1.5 Academic Foundation: The "Over-Privilege" Concept in Android Security Research

The concept behind this test is nothing new — it is rooted in Android security academic research that has matured over more than a decade. Two classic reference works in this field:

- **Stowaway** (Felt et al.) — a research tool that built a **permission-to-API map**: a list of which APIs require which permissions. By analyzing the reachability of an app's code against those APIs, Stowaway could automatically determine whether an app was **over-privileged** — holding a permission whose corresponding API is never actually invoked by the code.
- **PScout** — a similar approach that automates extraction of the permission-API map directly from the Android framework source code, producing a dataset that is more accurate and up to date compared to manual annotation.

Both pieces of research answer a **slightly different** question from MASTG-TEST-0255 (they focus on "permission not used at all," rather than "permission is used but there is a more minimal alternative") — but the **reachability analysis methodology** they developed remains highly relevant as the technical basis for automating this test's implementation (see §3.4).

---

## 2. Tools Used for Testing

### 2.1 Required Tools (Core)

| Tool | Function |
|---|---|
| **jadx** | Decompilation to trace the implementation of the feature behind each dangerous permission |
| **aapt/adb** | Extracting the permission list (same as MASTG-TEST-0254) |
| **grep / ripgrep** | Searching for alternative API patterns (Photo Picker, Intent delegation) vs. direct API |

### 2.2 Alternative & Supporting Tools

| Tool | Function |
|---|---|
| **APKPerm** | A modern (Python) tool for static analysis of permission references in a decompiled APK — can be used as the basis for building a permission-to-code-location mapping |
| **CodeQL** | Traces the **specific API** invoked in relation to each permission — key for distinguishing "using the camera API directly" vs. "calling the `ACTION_IMAGE_CAPTURE` Intent" |
| **MobSF** | Basic Manifest Analysis report as a starting point for identifying permissions that need further tracing |
| **Android Studio Lint** | Several built-in Android Studio lint checks (Correctness/Usability categories) can flag usage of older storage/contact APIs that have more modern alternatives |

### 2.3 Environment Prerequisites

- **No device/root needed** for the core static analysis.
- **Understanding of the app's features remains crucial** — just as with MASTG-TEST-0254, the tester needs to know **what** each dangerous permission is used for before being able to assess whether a more minimal alternative exists for that specific use case.
- **Use the alternatives map (§1.2) as a checklist** — run a systematic check for every dangerous permission found in MASTG-TEST-0254.

---

## 3. Testing Methodology

Because there are no official steps (placeholder status), the following methodology is constructed based on an elaboration of the official note and the Android Developers guidance cross-referenced from MASTG-TEST-0254.

### 3.1 General Steps

1. Take the list of dangerous permissions from the **MASTG-TEST-0254** results.
2. For each permission, trace the **code location** that uses it (MASTG-TECH-0014/0023).
3. Identify the **specific API** called at that location.
4. Compare it against the alternatives map (§1.2) — is a direct API used (requiring the permission), or a delegated/scoped API (not requiring the permission)?

### 3.2 Method A — grep/ripgrep for Direct API vs. Alternative Patterns

```bash
D=./decompiled/sources

# Camera: search for direct API usage vs. Intent delegation
echo "=== Direct Camera2 API usage (requires CAMERA permission) ==="
rg -l 'android\.hardware\.camera2\.CameraManager|Camera\.open\(' $D

echo "=== Delegation via Intent (does NOT require CAMERA permission) ==="
rg -l 'MediaStore\.ACTION_IMAGE_CAPTURE|MediaStore\.ACTION_VIDEO_CAPTURE' $D

# Storage: Photo Picker vs. direct access
echo "=== Direct storage access ==="
rg -l 'MediaStore\.Images\.Media\.query|ContentResolver.*EXTERNAL_CONTENT_URI' $D

echo "=== Photo Picker (does NOT require runtime permission) ==="
rg -l 'ActivityResultContracts\.PickVisualMedia|ACTION_PICK_IMAGES' $D

# Contacts: Contact Picker vs. direct query
echo "=== Direct ContactsContract query (requires READ_CONTACTS) ==="
rg -l 'ContactsContract\.Contacts\.CONTENT_URI' $D

echo "=== Contact Picker Intent (access limited to selected contact) ==="
rg -l 'Intent\.ACTION_PICK.*Contacts\.CONTENT_URI' $D

# Phone: ACTION_DIAL vs. ACTION_CALL
echo "=== Direct ACTION_CALL (requires CALL_PHONE) ==="
rg -l 'Intent\.ACTION_CALL' $D

echo "=== ACTION_DIAL (does NOT require CALL_PHONE) ==="
rg -l 'Intent\.ACTION_DIAL' $D
```

### 3.3 Method B — Permission-to-API Correlation with CodeQL

```ql
import java

class DirectCameraApiUsage extends MethodAccess {
  DirectCameraApiUsage() {
    this.getMethod().getDeclaringType().hasQualifiedName("android.hardware.camera2", "CameraManager") and
    this.getMethod().hasName("openCamera")
  }
}

class ImageCaptureIntentUsage extends FieldAccess {
  ImageCaptureIntentUsage() {
    this.getField().hasName("ACTION_IMAGE_CAPTURE")
  }
}

from DirectCameraApiUsage direct
select direct, "Direct usage of CameraManager.openCamera() found — consider ACTION_IMAGE_CAPTURE if the use case only needs to capture a single photo/video"
```

Similar queries can be built for every direct-API-vs-alternative-API pair in the table in §1.2, providing systematic, repeatable coverage for ongoing audits.

### 3.4 Method C — Reachability Analysis (Inspired by Stowaway/PScout)

Apply the classic academic approach: build a permission-to-API map, then check **whether the API corresponding to that permission category is actually invoked**, and **exactly which API** (direct vs. delegated):

```python
PERMISSION_API_MAP = {
    "android.permission.CAMERA": {
        "direct": ["android.hardware.camera2.CameraManager", "android.hardware.Camera"],
        "alternative": ["MediaStore.ACTION_IMAGE_CAPTURE", "MediaStore.ACTION_VIDEO_CAPTURE"]
    },
    "android.permission.READ_CONTACTS": {
        "direct": ["ContactsContract.Contacts.CONTENT_URI query"],
        "alternative": ["Intent.ACTION_PICK + Contacts.CONTENT_URI"]
    },
    "android.permission.CALL_PHONE": {
        "direct": ["Intent.ACTION_CALL"],
        "alternative": ["Intent.ACTION_DIAL"]
    },
    # ... complete according to the table in §1.2
}

def evaluate_minimization(declared_permissions, code_api_usage):
    findings = []
    for perm in declared_permissions:
        mapping = PERMISSION_API_MAP.get(perm)
        if not mapping:
            continue
        uses_direct = any(api in code_api_usage for api in mapping["direct"])
        uses_alternative = any(api in code_api_usage for api in mapping["alternative"])
        if uses_direct and not uses_alternative:
            findings.append(f"[FAIL CANDIDATE] {perm}: uses the direct API, an alternative is available but not used")
    return findings
```

### 3.5 Method D — Manual Verification Against the Specific Use Case

For every candidate finding from Methods A-C, manually verify whether the alternative **truly fits** the app's use case — not every case can use the alternative:

```
Verification questions:
1. Does the app only need to capture ONE photo momentarily? -> ACTION_IMAGE_CAPTURE fits
2. Does the app need a real-time camera preview/custom UI (e.g. AR, filters)? -> the direct CAMERA permission is still required, NOT a FAIL
3. Does the app only need to SELECT a contact occasionally? -> Contact Picker fits
4. Does the app need ONGOING contact SYNCHRONIZATION (e.g. a contact management app)? -> full READ_CONTACTS is still required, NOT a FAIL
```

This is a crucial step — Methods A-C only produce **candidates**, not final conclusions, because some use cases **legitimately** require full access that cannot be replaced by a scoped/delegated alternative.

### 3.6 Method Comparison: When to Use Which

| Method | Tool | Advantage | When to use |
|---|---|---|---|
| **A** | grep API patterns | Fast, directly shows textual evidence | Initial baseline |
| **B** | CodeQL | High precision, repeatable as a CI/CD gate | Large codebases |
| **C** | Reachability map (Python) | Systematic, covers all permission categories at once | Structured, comprehensive audits |
| **D** | Manual use-case verification | Filters out false positives from legitimate cases | **Mandatory** before a final conclusion |

**Minimum recommended combination:** **A/C (systematic candidate detection) → D (manual use-case verification) → correlation with MASTG-TEST-0254 results**.

---

### 3.7 Evaluation Criteria: Positive Case & Negative Case

Because there is no official Evaluation clause (placeholder status), the following criteria are derived from the official note and Android's permission minimization principles.

---

#### ❌ FAIL / ISSUE — The check is declared FAILED if:

| No | Condition |
|---|---|
| F1 | A dangerous permission is used via a **direct API**, even though the app's use case (confirmed manually, Method D) **fully fits** what can be achieved via a privacy-preserving alternative (§1.2) |
| F2 | The app requests full `READ_EXTERNAL_STORAGE`/`READ_MEDIA_IMAGES` solely for a feature that **selects one or a few media items**, even though the Photo Picker is available and sufficient |
| F3 | The app uses `Intent.ACTION_CALL` (requiring `CALL_PHONE`) even though the feature only **places a regular call** without any need for automation without user interaction |
| F4 | The app queries the full `ContactsContract` for a feature that **selects a single contact** (e.g. "share to contact"), even though the Contact Picker is sufficient |

**Example evidence (illustrative — MASTG does not yet provide an official demo for this test):**

```bash
$ rg -n 'Intent\.ACTION_CALL' ./decompiled/sources/com/example/target/ui/ContactDetailActivity.java
44:    val callIntent = Intent(Intent.ACTION_CALL, Uri.parse("tel:$phoneNumber"))
45:    startActivity(callIntent)
```

```xml
<uses-permission android:name="android.permission.CALL_PHONE"/>
```

Interpretation: the "call this contact" feature uses `ACTION_CALL`, which directly places a call without user confirmation in the phone app — even though this feature (calling a number from a contact detail screen) is a classic case that can be **fully** replaced by `ACTION_DIAL` (opening the phone app with the number already filled in, leaving the user to simply press the call button). **FAIL** — the `CALL_PHONE` permission is not minimal for this use case.

---

#### ✅ PASS — The check is declared PASSED if:

| No | Condition |
|---|---|
| P1 | Every declared dangerous permission uses a **direct** API because its use case **genuinely requires** full access (manually verified, not replaceable by an alternative) |
| P2 | The app already uses privacy-preserving alternatives (Photo Picker, Contact Picker, `ACTION_DIAL`, etc.) for every use case that fits |
| P3 | No dangerous permission is declared at all (any permission present, if any, is already minimal) |

---

#### ⚠️ Important Notes on Assessment

1. **This is not an absolute ban on using direct APIs** — as noted in §3.5, many use cases (real-time camera preview, full contact synchronization, automated calls from a VoIP system) legitimately require full access that cannot be replaced. The evaluation should focus on the **fit** between the use case and the alternative's capability, not a blanket prohibition on direct APIs.

2. **Manual verification (Method D) is a step that cannot be skipped** — automated detection (grep/CodeQL) only produces candidates; the final decision requires understanding the app's specific use case.

3. **The Photo Picker is the most common and easiest-to-verify case** — because it is relatively new (Android 13+) and entirely built into Jetpack/AndroidX, its absence in an app that clearly only needs "select one photo" is a strong and easily confirmed FAIL signal.

4. **Always correlate with MASTG-TEST-0254** — the two tests complement each other: 0254 answers "does this permission make sense," 0255 answers "is this the most minimal way to do it."

5. **Severity is generally lower compared to MASTG-TEST-0254** — this is about additional privacy *hardening* (reducing the access surface even though the permission itself is legitimate), not removing a permission that is entirely unneeded.

6. **Document:** the list of dangerous permissions along with the specific API used (direct vs. alternative), the manually verified use case, and migration recommendations to the specific alternative for each finding.

---

## 4. Recommendations

### 4.1 Migrate to the Photo Picker

```kotlin
val pickMedia = registerForActivityResult(ActivityResultContracts.PickVisualMedia()) { uri ->
    uri?.let { /* use the selected uri, WITHOUT needing READ_MEDIA_IMAGES */ }
}
pickMedia.launch(PickVisualMediaRequest(ActivityResultContracts.PickVisualMedia.ImageOnly))
```

### 4.2 Migrate to the Contact Picker

```kotlin
val pickContact = registerForActivityResult(ActivityResultContracts.PickContact()) { uri ->
    uri?.let { /* use the selected contact uri, WITHOUT needing full READ_CONTACTS */ }
}
pickContact.launch()
```

### 4.3 Replace `ACTION_CALL` with `ACTION_DIAL` Where Possible

```kotlin
// BEFORE: requires CALL_PHONE, calls immediately without confirmation
val callIntent = Intent(Intent.ACTION_CALL, Uri.parse("tel:$phoneNumber"))

// AFTER: no permission needed, user confirms via the phone app
val dialIntent = Intent(Intent.ACTION_DIAL, Uri.parse("tel:$phoneNumber"))
```

### 4.4 Remediation Checklist

- [ ] Every dangerous permission from the MASTG-TEST-0254 results has been mapped to the specific API that uses it
- [ ] Every direct API usage has been manually verified — does the use case genuinely need full access?
- [ ] Media selection features have transitioned to the Photo Picker
- [ ] Contact selection features have transitioned to the Contact Picker
- [ ] Call-placing features that don't need full automation have transitioned to `ACTION_DIAL`
- [ ] Successfully removed permissions have been confirmed to no longer be declared in the manifest
- [ ] **Re-verify:** rerun MASTG-TEST-0255 after every migration to an alternative

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0255: Permission Requests Not Minimized](https://mas.owasp.org/MASTG/tests/android/MASVS-PRIVACY/MASTG-TEST-0255/)
- [MASTG-TEST-0254: Dangerous App Permissions](https://mas.owasp.org/MASTG/tests/android/MASVS-PRIVACY/MASTG-TEST-0254/)
- [MASWE-0066: Inadequate Permission Management](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0066/)
- [OWASP Mobile Top 10 2024 — M6: Inadequate Privacy Controls](https://owasp.org/www-project-mobile-top-10/2023-risks/m6-inadequate-privacy-controls)

### 5.2 Official Android Documentation

- [Android Developers — Minimize Permission Requests](https://developer.android.com/privacy-and-security/minimize-permission-requests)
- [Android Developers — Photo Picker](https://developer.android.com/training/data-storage/shared/photopicker)
- [Android Developers — Storage Access Framework](https://developer.android.com/guide/topics/providers/document-provider)
- [Android Developers — Companion Device Pairing](https://developer.android.com/guide/topics/connectivity/companion-device-pairing)
- [Google — SMS Retriever API](https://developers.google.com/identity/sms-retriever/overview)
- [Google — Phone Number Hint](https://developers.google.com/identity/phone-number-hint/android)
- [Android Developers — `CallScreeningService`](https://developer.android.com/reference/android/telecom/CallScreeningService)
- [Google — Debit and Credit Card Recognition](https://developers.google.com/pay/payment-card-recognition/debit-credit-card-recognition)

### 5.3 Academic Research

- [Felt et al. — Android Permissions Demystified (Stowaway)](https://people.eecs.berkeley.edu/~dawnsong/papers/2011%20Android%20permissions%20demystified.pdf)
- [PScout — Analyzing the Android Permission Specification](https://arxiv.org/pdf/1311.4201)
- [CWE-250: Execution with Unnecessary Privileges](https://cwe.mitre.org/data/definitions/250.html)

### 5.4 Tool Documentation

- [APKPerm — Static permission reference analyzer](https://github.com/INCT-DD/APKPerm)
- [CodeQL — Documentation](https://codeql.github.com/docs/)
- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [MobSF — Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)

---

*This document is composed primarily from an elaboration of the brief official note for MASTG-TEST-0255 (placeholder status), supplemented extensively by the official Android Developers guidance "Minimize Permission Requests" and the classic academic research foundation (Stowaway, PScout) on over-privilege detection. The most important nuance: this test complements MASTG-TEST-0254 with a sharper question — not "does this permission make sense," but "is this the most minimal way to achieve the same feature" — and manual verification against the specific use case remains a step that cannot be fully replaced by automation.*
