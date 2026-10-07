# MASTG-TEST-0393 Use of Unverified App Links

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0393 |
| **Platform** | Android |
| **MASVS Category** | MASVS-PLATFORM |
| **Weakness** | MASWE-0029 |
| **Test Type** | Static, Config |
| **Related Techniques** | MASTG-TECH-0013, MASTG-TECH-0172 (Listing Deep Links), MASTG-TECH-0174 (Verifying App Link Website Association) |
| **Related Knowledge** | MASTG-KNOW-0019 (Deep Links) |
| **Related Best Practice** | MASTG-BEST-0070 (Verify Android App Links with autoVerify and Digital Asset Links) |
| **Official rule** | `mastg-android-deeplink-autoverify-missing.yml` — a relatively solid design, see §1.5 |

---

## 1. Explanation

### 1.1 Testing Objective

Quote from the official MASTG overview:

> *"Android App Links are http/https deep links that the OS verifies against a website's Digital Asset Links file before routing them to the app... When a deep link `<intent-filter>` declares an http/https `<data>` scheme... but is missing the `android:autoVerify="true"` attribute, Android cannot confirm the app's ownership of the declared domain. A malicious app can register the same intent filter and intercept the deep links, enabling phishing, credential theft, or hijacking of user actions."*

### 1.2 Two Types of Deep Link and Why Both Need to Be Distinguished

MASTG-KNOW-0019 fundamentally distinguishes two types of deep link:

| Type | Scheme | OS Verification | Main Risk |
|---|---|---|---|
| **Custom URL Scheme** | `myapp://` (arbitrary) | **Never** verified | Can be claimed by any app that registers the same scheme |
| **Android App Links** | `http://`/`https://` with `autoVerify` | **Verified** against the domain's Digital Asset Links | Safe **only if** verification succeeds |

This test specifically targets the second category when it **fails to be configured correctly** — a deep link using the `http`/`https` scheme (which **should be** verifiable) but where the developer **forgot or deliberately did not** enable `android:autoVerify="true"`, thereby losing the one security advantage that distinguishes it from the fragile custom URL scheme.

### 1.3 Deep Link Collision: The Underlying Attack Mechanism

> *"Using unverified deep links can cause a significant issue — any other apps installed on a user's device can declare and try to handle the same intent, which is known as deep link collision... In recent versions of Android this results in a so-called disambiguation dialog shown to the user that asks them to select the application that should handle the deep link. The user could make the mistake of choosing a malicious application instead of the legitimate one."*

This explains the attack mechanism technically — without verification, Android **has no way** to know which application "truly" has the right to a domain; the system can only show a selection dialog and **entrust the decision to the user**, who can be socially deceived (a fake app name that mimics the legitimate one, a similar icon) into choosing the malicious application.

### 1.4 Critical Historical Nuance: A Single Link's Failure Can Disable Verification for All Links (Pre-Android 12)

This is a very important architectural detail, repeatedly emphasized throughout the related documentation:

> *"Before Android 12 (API level 31), if the app has any non-verifiable links (e.g., missing autoVerify, an invalid Digital Asset Links file, or custom URL schemes), the system may skip verification for all Android App Links declared by that app — leaving even correctly configured App Links unprotected."*

This implication is very serious — in an application with a `minSdkVersion`/tested on a device with API < 31, **one** misconfigured `<intent-filter>` (or even an unrelated custom URL scheme) can **disable protection for the ENTIRE set of other App Links** that are already correctly configured in the same application. This means the audit must be **comprehensive** — finding one correct `<intent-filter>` does not guarantee the entire domain is protected if another, flawed `<intent-filter>` exists in the same application.

Android 12+ partially fixes this problem:

> *"Starting with Android 12, a generic web intent resolves to the user's default browser unless the target app is approved for the specific domain, reducing but not eliminating the attack surface."*

### 1.5 Analysis of the Official Rule: A Relatively Solid Design with Nested Pattern-Inside

Unlike many other rules in this research series that have significant coverage gaps, the `mastg-android-deeplink-autoverify-missing.yml` rule shows a fairly mature design — using **four layers of `pattern-inside`** to ensure the correct context:

```yaml
patterns:
  - pattern: <data ... android:scheme="$SCHEME" ... />
  - metavariable-regex: { metavariable: $SCHEME, regex: ^https?$ }
  - pattern-inside: <activity ...>...</activity>
  - pattern-inside: <intent-filter ...><action .../>...</intent-filter>  # must be VIEW
  - pattern-inside: <intent-filter ...><category .../>...</intent-filter>  # must be BROWSABLE
  - pattern-not-inside: <intent-filter ... android:autoVerify="true" ...>...</intent-filter>
```

This rule explicitly verifies **all three components** that MASTG-KNOW-0019 names as the requirements for a valid web deep link (action `VIEW`, category `BROWSABLE`, data scheme `http`/`https`) **before** flagging the absence of `autoVerify` — this reduces the risk of false positives against an `<intent-filter>` that is not actually a web deep link (for example, one that only handles an internal intent without the BROWSABLE category).

### 1.6 Important Limitation: Attribute Presence ≠ Successful Verification

An official note in the evaluation section confirms the limits of pure static analysis:

> *"Note that the presence of `android:autoVerify="true"` is necessary but not sufficient: the website association must also succeed. Use MASTG-TECH-0174 to confirm the declared domains are actually verified, since a misconfigured Digital Asset Links file leaves the App Links unverified even when the attribute is set."*

This means this test **only** identifies candidates based on the manifest attribute — **actual** verification (whether the `assetlinks.json` file is genuinely valid and accessible) requires an additional step with MASTG-TECH-0174, which checks the actual verification status on a device (`adb shell pm get-app-links`) or via an independent tool.

### 1.7 Concrete Evidence: Four HackerOne Reports Already Cited Directly by MASTG

This is a unique test because **the official documentation itself** already cites four real-world vulnerability pieces of evidence without needing additional external research:

> - *HackerOne #1372667 — Able to steal bearer token from deep link*
> - *HackerOne #401793 — Insecure deeplink leads to sensitive information disclosure*
> - *HackerOne #583987 — Android app deeplink leads to CSRF in follow action*
> - *HackerOne #341908 — XSS via Direct Message deeplinks*

These four cases cover a broad spectrum of impact — from direct authentication-token theft, sensitive information disclosure, CSRF (forcing an action on behalf of the user without consent — e.g. a forced "follow"), to XSS injected via a direct-message deep link parameter. This diversity of impact confirms that the risk of unverified deep links is **not a single category**, but an **entry vector** that can escalate into various other vulnerability classes depending on how the deep link parameter is subsequently processed by the application.

---

## 2. Tools Used for Testing

### 2.1 Required Tools (Core)

| Tool | Function |
|---|---|
| **aapt2 / xmlstarlet** | Manifest extraction for enumerating deep link `<intent-filter>` elements (MASTG-TECH-0172) |
| **Semgrep** + official rule | Detection of http/https `<data>` without `autoVerify` (relatively solid coverage) |

### 2.2 Alternative & Supporting Tools

| Tool | Function |
|---|---|
| **Android App Link Verification Tester** (`deeplink_analyser.py`) | Deep link enumeration and direct association-status verification from the APK (MASTG-TECH-0172, MASTG-TECH-0174) |
| **adb shell pm get-app-links** | Verification of the actual association status on the device (API 31+) — mandatory to close the gap in §1.6 |
| **adb shell dumpsys package** | Viewing all schemes registered by the application |

### 2.3 Environment Prerequisites

- Manifest analysis does not require a device/root.
- Verification of the actual association status (§1.6) requires a device/emulator with the application installed, or access to the relevant domain to independently check `assetlinks.json`.

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0013** to reverse engineer the application.
2. Use **MASTG-TECH-0172** to list deep links declared in the manifest.

### 3.2 Method A — Semgrep with the Official Rule

```bash
semgrep --config mastg-android-deeplink-autoverify-missing.yml ./AndroidManifest.xml
```

### 3.3 Method B — Android App Link Verification Tester

```bash
git clone https://github.com/inesmartins/Android-App-Link-Verification-Tester
python3 deeplink_analyser.py -op list-all -apk target.apk
python3 deeplink_analyser.py -op verify-applinks -apk target.apk
```

### 3.4 Method C — Verifying the Actual Association Status (Mandatory, Per §1.6)

```bash
adb shell pm get-app-links com.example.app
```

Check the output — the status must be `verified` for every domain; any other value (`legacy_failure`, a numeric error code) means the domain is **not** verified even though `autoVerify="true"` is already present in the manifest.

### 3.5 Method D — Manual Inspection of the Digital Asset Links File

```bash
curl -s https://www.example.com/.well-known/assetlinks.json
```

Verify: whether the file exists, is served over HTTPS without a redirect, is valid JSON, and lists the correct package name and signing-certificate fingerprint.

### 3.6 Method Comparison: When to Use Which

| Method | Tool | When to use |
|---|---|---|
| **A** | Semgrep + official rule | Mandatory baseline — quick detection of missing `autoVerify` |
| **B** | deeplink_analyser.py | An integrated alternative for enumeration + verification |
| **C** | `adb shell pm get-app-links` | **Mandatory** — confirmation of actual verification |
| **D** | Manual curl | Root-cause diagnosis when verification fails |

**Minimum recommended combination:** **A (triage) → C (mandatory, real confirmation)**, with **D** for diagnosis when C shows failure.

---

### 3.7 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rule:**

> **Evaluation:** *"The test case fails if you identify any deep link `<intent-filter>` element that declares an http/https `<data>` scheme without the `android:autoVerify="true"` attribute."*

---

#### ❌ FAIL / ISSUE — The check is declared FAILED if:

| No | Condition |
|---|---|
| F1 | An `<intent-filter>` with action `VIEW` + category `BROWSABLE` + `<data>` scheme `http`/`https` **without** `android:autoVerify="true"` |
| F2 | *(Further validation)* `autoVerify="true"` is present but domain verification fails when checked via `adb shell pm get-app-links` (§1.6) |

**Example evidence (reflecting the real-world HackerOne #1372667 pattern in §1.7):**

```xml
<activity android:name=".DeepLinkActivity" android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data android:scheme="https" android:host="app.example.com" android:path="/auth/callback" />
    </intent-filter>
</activity>
```

Interpretation: the deep link `https://app.example.com/auth/callback` (likely carrying a bearer token as a parameter) lacks `autoVerify` — a malicious application can register an identical intent filter and intercept the authentication token. **FAIL**.

---

#### ✅ PASS — The check is declared PASSED if:

| No | Condition |
|---|---|
| P1 | `android:autoVerify="true"` is present on all http/https `<intent-filter>` elements, **and** |
| P2 | Domain verification is confirmed as `verified` via `adb shell pm get-app-links`, **and** |
| P3 | *(Pre-Android 12)* No other non-verifiable `<intent-filter>` exists in the same application that could disable overall verification (§1.4) |

---

#### ⚠️ Important Notes on Assessment

1. **Do not stop after finding `autoVerify="true"`** — per §1.6, this is a necessary but not sufficient condition; always verify the actual status via Method C.

2. **Audit all `<intent-filter>` elements in the application, not just each in isolation** — per §1.4, on pre-Android 12 devices, a single flawed link can disable verification for all other App Links in the same application.

3. **Assess the deep link parameters for further risk** — per the diversity of impact in §1.7 (token theft, CSRF, XSS), also check how the deep link's parameters are subsequently processed, because App Links verification itself does not guarantee safe parameter handling.

4. **Severity is modulated:**

   | Factor | Severity |
   |---|---|
   | Deep link carries a token/credential/sensitive parameter without `autoVerify` | **High** |
   | Ordinary navigation deep link without sensitive data, without `autoVerify` | **Medium** |
   | `autoVerify` is present but domain verification fails | **High** (effectively equivalent to F1) |
   | All PASS criteria met, including actual verification | **Not a finding** |

5. **Document:** the full list of deep link `<intent-filter>` elements, `autoVerify` status, the result of `pm get-app-links` per domain, and any sensitive parameters carried by the deep link.

---

## 4. Recommendations

### 4.1 Enable autoVerify and Ensure the Digital Asset Links File Is Valid (Per MASTG-BEST-0070)

```xml
<intent-filter android:autoVerify="true">
    <action android:name="android.intent.action.VIEW" />
    <category android:name="android.intent.category.DEFAULT" />
    <category android:name="android.intent.category.BROWSABLE" />
    <data android:scheme="https" android:host="app.example.com" />
</intent-filter>
```

```json
// https://app.example.com/.well-known/assetlinks.json
[{
  "relation": ["delegate_permission/common.handle_all_urls"],
  "target": {
    "namespace": "android_app",
    "package_name": "com.example.app",
    "sha256_cert_fingerprints": ["AA:BB:CC:..."]
  }
}]
```

### 4.2 Avoid Custom URL Schemes for Sensitive Flows

Per MASTG-BEST-0070, do not use `myapp://` for a flow carrying a token/sensitive data — this scheme is **never** verified by the OS. Migrate all sensitive flows to verified App Links.

### 4.3 Remediation Checklist

- [ ] Every http/https `<intent-filter>` has `android:autoVerify="true"`
- [ ] The `assetlinks.json` file is valid, served over HTTPS without a redirect, and lists the correct package and fingerprint, for every domain/subdomain
- [ ] Verification is confirmed as `verified` via `adb shell pm get-app-links`
- [ ] No other non-verifiable `<intent-filter>` exists that could disable overall verification (pre-Android 12)
- [ ] Sensitive flows (token, auth callback) are migrated from custom URL scheme to verified App Links

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0393 (source, tests-beta)](https://github.com/OWASP/mastg/blob/master/tests-beta/android/MASVS-PLATFORM/MASTG-TEST-0393.md)
- [MASTG-KNOW-0019: Deep Links](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0019/)
- [MASTG-BEST-0070: Verify Android App Links with autoVerify and Digital Asset Links](https://github.com/OWASP/mastg/blob/master/best-practices/MASTG-BEST-0070.md)
- [MASTG-TECH-0172: Listing Deep Links](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0172/)
- [MASTG-TECH-0174: Verifying App Link Website Association](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0174/)

### 5.2 Real-World Cases (Cited Directly by MASTG)

- [HackerOne #1372667: Able to Steal Bearer Token from Deep Link](https://hackerone.com/reports/1372667)
- [HackerOne #401793: Insecure Deeplink Leads to Sensitive Information Disclosure](https://hackerone.com/reports/401793)
- [HackerOne #583987: Android App Deeplink Leads to CSRF in Follow Action](https://hackerone.com/reports/583987)
- [HackerOne #341908: XSS via Direct Message Deeplinks](https://hackerone.com/reports/341908)
- [People VT: Measuring the Insecurity of Mobile Deep Links of Android (Academic Research)](https://people.cs.vt.edu/gangwang/deep17.pdf)

### 5.3 Tool Documentation

- [Android App Link Verification Tester](https://github.com/inesmartins/Android-App-Link-Verification-Tester)
- [Semgrep Documentation](https://semgrep.dev/docs/)

---

*This document was compiled based on official OWASP MASTG content (`tests-beta/android/MASVS-PLATFORM/MASTG-TEST-0393.md`, `MASTG-KNOW-0019`, `MASTG-BEST-0070`), analysis of the `mastg-android-deeplink-autoverify-missing.yml` rule, which shows a relatively mature design with layered context verification, and four real HackerOne reports already cited directly by MASTG's own official documentation — covering bearer token theft, information disclosure, CSRF, and XSS via deep link parameters. The most important methodological nuance: the presence of `android:autoVerify="true"` is a **necessary but not sufficient** condition — actual domain verification (via `adb shell pm get-app-links` or a direct check of the `assetlinks.json` file) is a mandatory step that cannot be replaced by manifest analysis alone, and on pre-Android 12 devices, a single flawed `<intent-filter>` anywhere in the application can disable verification for all other, correctly configured App Links.*
