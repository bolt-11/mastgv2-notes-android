# MASTG-TEST-0399 SafeBrowsing Disabled

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0399 |
| **Platform** | Android |
| **MASVS Category** | MASVS-CODE |
| **Weakness** | MASWE-0035 |
| **Test Type** | Static, Config, Code |
| **Related APIs** | `WebView`, `WebSettings`, `EnableSafeBrowsing`, `setSafeBrowsingEnabled` |
| **Related Techniques** | MASTG-TECH-0013, MASTG-TECH-0117 (Obtain Manifest), MASTG-TECH-0150, MASTG-TECH-0014 |
| **Related Knowledge** | MASTG-KNOW-0018 (WebViews) |
| **Available Since** | API level 27 (Android 8.1) |
| **Related Tests** | **MASTG-TEST-0398** — related document in this research series; both cover WebView navigation control, but via different mechanisms (custom allowlist vs Google's reputation service) |
| **Official Rule** | `mastg-android-webview-safebrowsing.yml` — two clean patterns, see §1.4 |

---

## 1. Explanation

### 1.1 Testing Objective and the SafeBrowsing Mechanism

Quote from the official MASTG overview:

> *"Since Android 8.1 (API level 27), WebViews include SafeBrowsing by default, which warns users about URLs that Google has classified as known threats such as phishing or malware sites."*

SafeBrowsing is a **reputation-protection layer based on a Google-operated service** — fundamentally different from the mechanism covered in MASTG-TEST-0398 (a custom allowlist/denylist written by the developer). SafeBrowsing leverages a **continuously, globally updated threat database** maintained by Google, covering URLs classified as malicious across the entire web — something no custom application allowlist could ever replicate.

### 1.2 Technical Evolution: From Local Blocklist to Real-Time Checking

Additional technical context relevant to understanding the strength of this mechanism:

> *"For WebView versions prior to M126, Safe Browsing on WebView uses the 'Local Blocklist' or 'V4' protocol, with URLs checked for malware, phishing etc against an on-device blocklist that is periodically updated by Google's servers. From M126 onwards, WebView uses a 'Real-Time' or 'V5' protocol for Safe Browsing, with URLs checked in real-time against blocklists maintained by servers."*

This evolution matters — modern WebView versions no longer rely on a local database that is only periodically updated (with a time gap between a new threat appearing and the device receiving the update), but instead check **in real time** against Google's servers. This means that disabling SafeBrowsing on a modern WebView means losing protection that is **stronger** than what was available in the earlier versions of this feature.

### 1.3 Two Control Points with a Clear Priority Hierarchy

The overview describes two ways to disable SafeBrowsing, with an explicit hierarchy:

> *"Apps can also disable SafeBrowsing at runtime by calling `WebSettings.setSafeBrowsingEnabled(false)` on a WebView instance. This takes precedence over the manifest setting, so even if the manifest enables SafeBrowsing, it can still be disabled in code."*

| Control Point | Location | Priority |
|---|---|---|
| Manifest meta-data `EnableSafeBrowsing` | `AndroidManifest.xml` | Default/global for all of the application's WebViews |
| `WebSettings.setSafeBrowsingEnabled(false)` | Java/Kotlin code, per WebView instance | **Wins** over the manifest setting |

This hierarchy has an important implication for testing methodology (§3) — **checking the manifest alone is not enough**. An application can look safe in the manifest (no `false` meta-data, or even explicitly `true`), yet still be vulnerable if somewhere in the code, a single call to `setSafeBrowsingEnabled(false)` disables it for a particular WebView instance — this is consistent with the following official evaluation principle:

> **Evaluation:** *"A WebView is protected only when SafeBrowsing is neither disabled in the manifest nor in code."*

This evaluation logic is an **AND** of two negations — both control points must **both** not disable it, not just one of them.

### 1.4 Official Rule Analysis: Two Clean Patterns Without Excessive Complexity

Unlike several other rules in this research series that have significant coverage gaps, the `mastg-android-webview-safebrowsing.yml` rule for this test is quite simple and well-targeted — because the dangerous value is a **single literal** (`false`), there is no room for ambiguity like there is in rules dealing with combinations of flags:

```yaml
# Manifest pattern
pattern: <meta-data android:name="android.webkit.WebView.EnableSafeBrowsing" android:value="false" ... />

# Code pattern
pattern: $WEBSETTINGS.setSafeBrowsingEnabled(false)
```

These two patterns directly map to the two control points named in the overview (§1.3) with no obvious gap — this is one of the "cleanest" rules found throughout this research series, likely because the binary nature of the value being checked (`true`/`false`) leaves little room for the kind of complex expression variation seen in bitwise flag combinations in other tests.

### 1.5 Important Note: A Related but Differently Scoped Rule Found Alongside the TEST-0398 File

While researching the earlier MASTG-TEST-0398 document, a second rule, `mastg-android-webviewclient-safebrowsing-whitelist`, was found **bundled in TEST-0398's own YAML file**, targeting `setSafeBrowsingWhitelist()` and the `onSafeBrowsingHit()` override. That topic is **thematically closer** to this test (SafeBrowsing) than it is to TEST-0398 (custom URL handlers), yet it is **not mentioned** in either this test's or TEST-0398's `apis:` frontmatter. This indicates the existence of a **related third topic** (weakening/customizing SafeBrowsing via a whitelist or callback override) that does not yet have its own official MASTG test, but already has a Semgrep rule bundled in a file-organizationally inconsistent way. A tester wanting to audit SafeBrowsing comprehensively should **also** check for this pattern as a supplement, even though it is strictly outside the declarative scope of both tests (TEST-0398 and TEST-0399).

### 1.6 Real-World Evidence: An Official Android Lint Rule as Platform-Tooling-Level Recognition of the Risk

The significance of this risk is acknowledged not only by MASTG, but also by **Android's own official tooling** — Google provides a dedicated custom lint check for this exact pattern:

> *"Application has disabled safe browsing for all WebView objects is a warning"* — from the [Android Custom Lint Rules: DisabledAllSafeBrowsing](https://googlesamples.github.io/android-custom-lint-rules/checks/DisabledAllSafeBrowsing.md.html) documentation.

The existence of this official lint check confirms that Google itself considers the pattern of disabling SafeBrowsing entirely risky enough to warrant an automatic warning **at compile time**, before the app is even released — a strong signal about the seriousness of this finding from the platform vendor's own perspective, not just from the perspective of independent security testing like MASTG.

---

## 2. Tools Used for Testing

### 2.1 Required Tools (Core)

| Tool | Function |
|---|---|
| **aapt / Androguard** | Extracting the manifest to check the `EnableSafeBrowsing` meta-data (MASTG-TECH-0117, MASTG-TECH-0150) |
| **jadx** | Decompiling to search for `setSafeBrowsingEnabled` in code (MASTG-TECH-0013, MASTG-TECH-0014) |
| **Semgrep** + official rule | Automatically detecting both patterns |

### 2.2 Alternative & Supporting Tools

| Tool | Function |
|---|---|
| **Android Lint** | The built-in `DisabledAllSafeBrowsing` check — can be run directly against the project source (if available) as a complement to binary APK analysis |
| **grep/ripgrep** | Additional verification and searching for related patterns (whitelist/callback, §1.5) |

### 2.3 Environment Prerequisites

- No device/root needed — purely static configuration analysis.

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0013** to reverse engineer the application.
2. Use **MASTG-TECH-0117** to obtain `AndroidManifest.xml`.
3. Use **MASTG-TECH-0150** to inspect the relevant attribute.
4. Use **MASTG-TECH-0014** to search for the relevant API in the code.

### 3.2 Method A — Semgrep with the Official Rule (Full Coverage)

```bash
semgrep --config mastg-android-webview-safebrowsing.yml ./AndroidManifest.xml ./decompiled/sources
```

### 3.3 Method B — grep/ripgrep for Manual Verification

```bash
# Manifest
grep -A3 'EnableSafeBrowsing' AndroidManifest.xml

# Code
rg -n 'setSafeBrowsingEnabled\(' ./decompiled/sources
```

### 3.4 Method C — Searching for Related Patterns (Supplementary, Per §1.5)

```bash
rg -n 'setSafeBrowsingWhitelist\(|onSafeBrowsingHit\(' ./decompiled/sources
```

### 3.5 Method Comparison: When to Use Which

| Method | Tool | When to Use |
|---|---|---|
| **A** | Semgrep + official rule | Mandatory baseline — coverage is already adequate |
| **B** | grep/ripgrep manual | Additional verification/confirmation |
| **C** | grep manual | Optional supplement for the related whitelist/callback topic |

**Minimum recommended combination:** **A (already sufficient as a baseline)**, with **C** as a supplement if a comprehensive audit of all SafeBrowsing aspects is required.

---

### 3.6 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rule:**

> **Evaluation:** *"The test case fails if the `android.webkit.WebView.EnableSafeBrowsing` meta-data is present with `android:value='false'`, or if SafeBrowsing is disabled in code via `WebSettings.setSafeBrowsingEnabled(false)`."*

---

#### ❌ FAIL / ISSUE — The check is declared FAILED if any of the following:

| No | Condition |
|---|---|
| F1 | The `android.webkit.WebView.EnableSafeBrowsing` meta-data in the manifest is set to `false` |
| F2 | `WebSettings.setSafeBrowsingEnabled(false)` is called in code for any WebView instance |

**Evidence example:**

```xml
<meta-data android:name="android.webkit.WebView.EnableSafeBrowsing" android:value="false" />
```

**FAIL** — Google's reputation protection is disabled globally for all of the application's WebViews.

---

#### ✅ PASS — The check is declared PASSED if:

| No | Condition |
|---|---|
| P1 | There is no `EnableSafeBrowsing=false` meta-data in the manifest, **and** |
| P2 | There is no call to `setSafeBrowsingEnabled(false)` in code for any WebView |

---

#### ⚠️ Important Notes on Assessment

1. **Check BOTH control points, not just the manifest** — per §1.3, `setSafeBrowsingEnabled(false)` in code wins over the manifest setting; an app that looks safe in the manifest can still FAIL if this call exists in code for a particular WebView instance.

2. **Check each WebView instance separately** if the application has multiple WebViews — disabling in code is per-instance, so one WebView might be safe while another (e.g., for third-party ads) has SafeBrowsing disabled.

3. **There is generally no valid business reason to disable this** — unlike some other tests in this research series that have a nuance of "not always dangerous," findings in this test rarely have a legitimate justification; it is most likely an oversight or an unintentional legacy configuration.

4. **Severity is modulated as follows:**

   | Factor | Severity |
   |---|---|
   | SafeBrowsing disabled on a WebView loading content from external/third-party sources | **High** |
   | SafeBrowsing disabled on a WebView that only loads fully controlled first-party content | **Low-Medium** |
   | SafeBrowsing active at both control points | **Not a finding** |

5. **Document:** the manifest/code location, the value found, and whether any related pattern (whitelist/callback, §1.5) further weakens protection.

---

## 4. Recommendations

### 4.1 Make Sure SafeBrowsing Remains Active (Default, Do Not Change It)

```xml
<!-- Remove this meta-data entirely, or make sure value="true" if it truly needs to be declared explicitly -->
<!-- <meta-data android:name="android.webkit.WebView.EnableSafeBrowsing" android:value="false" /> -->
```

```java
// Avoid this call unless there is a strong, documented justification
// webSettings.setSafeBrowsingEnabled(false);
```

### 4.2 Remediation Checklist

- [ ] The `EnableSafeBrowsing` meta-data is not set to `false` in the manifest
- [ ] There is no call to `setSafeBrowsingEnabled(false)` in code for any WebView
- [ ] If a SafeBrowsing whitelist/callback is found (§1.5), it is audited separately to confirm it does not unintentionally weaken protection
- [ ] Android Lint (`DisabledAllSafeBrowsing`) is run as an additional check in the CI pipeline where access to the project source is available

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0399 (source, tests-beta)](https://github.com/OWASP/mastg/blob/master/tests-beta/android/MASVS-CODE/MASTG-TEST-0399.md)
- [MASTG-TEST-0398 (related document in this research series)](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0398/)
- [MASTG-KNOW-0018: WebViews](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0018/)

### 5.2 Official Documentation and Research

- [Chromium: Android WebView Safe Browsing (V4/V5 Protocol Technical Documentation)](https://chromium.googlesource.com/chromium/src.git/+/master/android_webview/browser/safe_browsing/README.md)
- [Android Developers: Manage WebView Objects](https://developer.android.com/develop/ui/views/layout/webapps/managing-webview)
- [Android Custom Lint Rules: DisabledAllSafeBrowsing](https://googlesamples.github.io/android-custom-lint-rules/checks/DisabledAllSafeBrowsing.md.html)

### 5.3 Tool Documentation

- [Semgrep Documentation](https://semgrep.dev/docs/)
- [Google Safe Browsing](https://developers.google.com/safe-browsing/)

---

*This document was prepared based on official OWASP MASTG content (`tests-beta/android/MASVS-CODE/MASTG-TEST-0399.md`, `MASTG-KNOW-0018`), analysis of the `mastg-android-webview-safebrowsing.yml` rule, which shows a clean design without significant gaps (thanks to the binary nature of the value being checked), and Chromium's technical documentation on the evolution of the SafeBrowsing protocol from a local blocklist (V4) to real-time checking (V5, since M126). The strongest real-world evidence for this test comes from Google's own acknowledgment via the official `DisabledAllSafeBrowsing` custom lint rule — confirming that even the platform vendor considers this pattern risky enough to warrant an automatic warning at compile time. The most important methodological nuance: the evaluation is an AND of two independent control points (manifest and code), with code always winning over the manifest — an audit that checks only one control point is inadequate.*
