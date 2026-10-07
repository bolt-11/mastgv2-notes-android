# MASTG-TEST-0285 Outdated Android Version Allowing Trust in User-Provided CAs

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0285 |
| **Platform** | Android |
| **MASVS Category** | MASVS-NETWORK (MASVS-NETWORK-2) |
| **Weakness** | MASWE-0027 — *Insecure Certificate Validation* |
| **Test Type** | Static, Code |
| **Special Field** | **`deprecated_since: 24`** — the same metadata pattern found in MASTG-TEST-0222 in this research series, marking that the risk tested here is **no longer relevant** for apps with `minSdkVersion` ≥ 24 |
| **Knowledge** | MASTG-KNOW-0014 (Android Network Security Configuration) |
| **Related Techniques** | MASTG-TECH-0013, MASTG-TECH-0117 (Obtaining AndroidManifest), MASTG-TECH-0150 (Analyzing AndroidManifest) |
| **Related Tests** | **MASTG-TEST-0234/0282/0283/0284** — the same MASWE-0027 group, but this test is **unique**: the only one in the group that is purely determined by **a single number in the manifest** (`minSdkVersion`), rather than by the quality of the code implementation |
| **Related Demo** | — (none) |
| **Official Rule** | — (not applicable; the evaluation is purely a manifest attribute value extraction, too simple to require a semgrep rule) |
| **Related CWE** | CWE-295, CWE-1104 (analogous: inheriting weaknesses from an outdated platform) |

---

## 1. Explanation

### 1.1 Testing Objective

Official MASTG overview excerpt:

> *"This test evaluates whether an Android app **implicitly** trusts user-added CA certificates by default, which is the case for apps that can be installed to devices running API level 23 or lower."*

This test targets the security consequences of a **low `minSdkVersion`** — it is not about a bug in the application code, but about **whether the app can even be installed** on older Android devices (Android 6.0/API 23 and below) that, as a **structural platform matter**, trust user-added CA certificates by default.

### 1.2 The Trust Anchor Policy Change in Android Nougat (API 24) — Historical Context

Per the research and official Android documentation:

> *"By default, secure connections from all apps trust the pre-installed system CAs, and apps targeting Android 6.0 (API level 23) and lower also trust the user-added CA store by default. Apps that target API Level 24 and above no longer trust user or admin-added CAs for secure connections, by default."*

This was a **deliberate security change** introduced in Android Nougat (2016) — the official announcement from the Android Developers Blog explicitly explains the motivation: reducing the MITM attack surface, since user-added CA certificates (whether intentionally added by the user or **silently injected by malware/a compromised corporate MDM**) were previously **automatically trusted** by every application on that device without exception.

### 1.3 The Most Important Nuance: Why This Test Checks `minSdkVersion`, Not `targetSdkVersion`

This is the **single most important conceptual finding** in this document, and at first glance it appears to contradict the pattern already discussed in several other documents in this research series (MASTG-TEST-0235, 0245, 0252) — where **`targetSdkVersion`**, not `minSdkVersion`, usually determines the **default behavior** of a given API/platform policy. Following that pattern, the first instinct would be: "shouldn't the default trust anchor be determined by `targetSdkVersion`, as explained in MASTG-KNOW-0014?" (Per the official table: `targetSdkVersion` ≤23 → trust user+system CA; `targetSdkVersion` 24-27/28+ → trust system CA only.)

**However, this test explicitly and correctly checks `minSdkVersion`, not `targetSdkVersion`** — and here is the deep technical reasoning for why this is in fact **correct**, not a mistake:

**Network Security Configuration (NSC) — the mechanism that lets developers configure/override the trust anchor policy — was itself only introduced in API 24.** On devices running **API 23 and below**, NSC **does not exist at all** as a platform feature — the operating system on such a device runs the **legacy built-in trust anchor logic**, which always trusts both system CAs **and** user CAs, **with no way whatsoever for the app to change that** — even if the developer declares an arbitrarily high `targetSdkVersion`, or ships a perfectly configured `network_security_config.xml` file.

This means: **a high `targetSdkVersion` provides NO protection whatsoever for a user running the app on an older Android device** — because the OS on that device **literally has no mechanism (NSC) to read/honor any trust anchor configuration the app declares**. The only factor that actually determines whether that user is **potentially exposed** to this risk is: **whether the app even allows itself to be installed on that device in the first place** — which is determined by **`minSdkVersion`**.

A summary table to clarify this fundamental distinction:

| Scenario | `targetSdkVersion` | `minSdkVersion` | Device running it | Result |
|---|---|---|---|---|
| A | 34 (high) | 21 (low) | Android 6.0 (API 23) | **Still trusts user CA** — NSC does not exist on this OS, `targetSdkVersion` is entirely irrelevant |
| B | 34 (high) | 24+ | Android 6.0 (API 23) | **Cannot happen** — the app can't be installed in the first place because `minSdkVersion` excludes this device |
| C | 23 (low) | 24+ | Android 7.0+ | Trusts system CA only — NSC exists on this OS, and the safe API 24+ default applies regardless of the low `targetSdkVersion` *(note: this scenario rarely occurs in practice, since `targetSdkVersion` is typically ≥ `minSdkVersion`)* |

Row **A** is the crux of why this test specifically targets `minSdkVersion` — it is the only control that actually effectively prevents this risk from manifesting in the real world, because it controls the **device population**, not the **software behavior** on a device that is already installed.

### 1.4 Practical Consequence: A Dual Impact on Security and the Pentest Workflow

This API 24 policy change has **two opposing sides of impact**, and both are relevant for a tester to understand:

- **The security side (relevant to this test)**: apps with `minSdkVersion` ≥24 are **structurally protected** from malicious CAs added by a user/malware/compromised MDM on any device that runs them — because every device eligible to install the app already has NSC, which by default rejects trusting user CAs.
- **The security-testing workflow side (a side effect testers should be aware of)**: this same change **complicates the work of pentesters/security researchers themselves** — certificates issued by interception tools such as **Burp Suite** or **mitmproxy** (which work by adding themselves as a user-trusted CA on the test device) are **no longer automatically trusted** by apps targeting API 24+ — unless the app's NSC is explicitly configured to trust user CAs (`<certificates src="user"/>`), something that is **rarely done** in production apps except for specific debug needs. This is the technical reason why modern mobile security testers often need to **patch the APK** (injecting a custom NSC via apktool) or use other bypass techniques to keep performing HTTPS interception on modern apps — a topic already touched on briefly regarding pinning bypass in several other documents in this MASVS-NETWORK research series.

### 1.5 Why `deprecated_since: 24`

The `deprecated_since: 24` field in this test's frontmatter — following the same pattern discussed in the **MASTG-TEST-0222** document in this research series — indicates that the risk this test checks for is **structurally impossible** for apps with `minSdkVersion` ≥24 from the outset, because the protection mechanism (a safe NSC default) has been an intrinsic part of the platform since that version. Unlike MASTG-TEST-0222 (PIE), whose relevance has declined because **nearly all modern devices** are already above that threshold, the relevance of this test carries a slightly different nuance: it remains **highly relevant to check** because `minSdkVersion` is a **conscious developer choice** that may still be set low for the sake of broader device reach — not something that automatically becomes "obsolete" over time without any developer decision being involved.

---

## 2. Tools Used for Testing

### 2.1 Required Tools (Core)

| Tool | Function |
|---|---|
| **jadx --no-src** | Extract `AndroidManifest.xml` to read the `<uses-sdk>` element |
| **aapt2 / apkanalyzer** | Official Android SDK way to read `minSdkVersion` without full decompilation |
| **grep** | Quick extraction of the attribute value |

### 2.2 Alternative & Supporting Tools

| Tool | Function |
|---|---|
| **androguard** | Programmatic extraction of `minSdkVersion` (Python), suited for large-scale/CI audits |
| **MobSF** | Displays `minSdkVersion`/`targetSdkVersion` in the Manifest Analysis summary |
| **Dynamic verification on an API 23 emulator** (optional, for empirical proof) | Running the app on an Android 6.0 emulator image and directly confirming that a manually added user CA is indeed trusted by the system for that app's HTTPS connections |

### 2.3 Environment Prerequisites

- **No device/root required** for the core static analysis — extracting the manifest from the APK is enough.
- **Optional**: an emulator with an Android 6.0 (API 23) image for empirical verification of trust anchor behavior directly, if definitive proof beyond simply reading the `minSdkVersion` value is needed.

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0013** to reverse engineer the application.
2. Use **MASTG-TECH-0117** to obtain `AndroidManifest.xml`.
3. Use **MASTG-TECH-0150** to read the `minSdkVersion` value from the `<uses-sdk>` element.

### 3.2 Method A — jadx + grep *(the main official method, the simplest in the entire research series)*

```bash
jadx --no-src -d ./out target-app.apk
grep -oP 'minSdkVersion="\K[0-9]+' ./out/resources/AndroidManifest.xml
```

**Important note based on MASTG-TECH-0117**: use **jadx**, not apktool, for this step — MASTG-TECH-0117 explicitly notes that the `<uses-sdk>` element (which holds `minSdkVersion`) is **missing** from apktool's decompiled output, whereas jadx includes it in full.

### 3.3 Method B — aapt2 (Official Android SDK Approach)

```bash
aapt2 dump badging target-app.apk | grep -i "sdkVersion"
```

or

```bash
apkanalyzer manifest print target-app.apk | grep -i "minSdkVersion"
```

### 3.4 Method C — androguard (Automation/CI)

```python
from androguard.core.apk import APK
apk = APK("target-app.apk")
min_sdk = apk.get_min_sdk_version()
print(f"minSdkVersion: {min_sdk}")
if int(min_sdk) < 24:
    print("[FAIL] The app can be installed on devices that trust user CAs by default")
```

### 3.5 Method D — Empirical Verification on an API 23 Emulator (Definitive Proof, Optional)

For testers who want direct proof beyond simply reading the manifest value:

```bash
# 1. Launch an Android 6.0 (API 23) emulator
emulator -avd api23-test &

# 2. Install a custom CA certificate as a "user CA" (not a system CA)
adb push malicious-ca.pem /sdcard/
# Then install via Settings > Security > Install from storage (requires manual interaction)

# 3. Run the target app and intercept via a proxy using that CA
mitmproxy --mode transparent

# 4. Observe: does the app's HTTPS connection SUCCEED through the proxy with the newly added USER CA?
```

If the connection succeeds without being rejected, this is direct empirical confirmation that the API 23 device does indeed trust the user CA for this app — complementing (not replacing) the result of the static `minSdkVersion` reading.

### 3.6 Method Comparison: When to Use Which

| Method | Tool | When to use |
|---|---|---|
| **A** | jadx + grep | **Mandatory official baseline** — fast and definitive |
| **B** | aapt2/apkanalyzer | Official Android SDK alternative, no decompilation |
| **C** | androguard | Automation/CI, large-scale audits |
| **D** | API 23 emulator + mitmproxy | Additional empirical proof, rarely needed since the static result is already definitive |

**Minimum recommended combination:** **A or B alone is already sufficient** for a solid conclusion — this test is one of the **simplest** in this entire research series, since the evaluation is purely reading a single integer value, with no ambiguity of interpretation. Method D is only relevant as an educational demonstration or for audits that demand explicit empirical proof, not a routine necessity.

---

### 3.7 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rule:**

> **Observation:** *"The output should contain the value of `minSdkVersion`."*
>
> **Evaluation:** *"The test case fails if `minSdkVersion` is less than 24."*

This is one of the **clearest and least ambiguous** evaluation criteria in this entire research series — a purely single numeric comparison.

---

#### ❌ FAIL / ISSUE — The check is declared FAILED if:

| No | Condition |
|---|---|
| F1 | `minSdkVersion` < 24 (Android 7.0/Nougat) |

**Example evidence (illustrative — MASTG does not yet provide an official demo for this test):**

```bash
$ grep -oP 'minSdkVersion="\K[0-9]+' AndroidManifest.xml
21
```

Interpretation: `minSdkVersion=21` (Android 5.0) — this app can be installed on a device that, as a **structural platform matter**, trusts user CAs with no way for the app to change that. **FAIL**, regardless of `targetSdkVersion` or any NSC configuration that may already be in place (§1.3).

---

#### ✅ PASS — The check is declared PASSED if:

| No | Condition |
|---|---|
| P1 | `minSdkVersion` ≥ 24 |

```bash
$ grep -oP 'minSdkVersion="\K[0-9]+' AndroidManifest.xml
28
```

---

#### ⚠️ Important Notes on Assessment

1. **Do not confuse this with `targetSdkVersion`** — this is the most likely mistake for a tester already accustomed to the "targetSdkVersion determines the default" pattern seen in other tests in this series (MASTG-TEST-0235). For this **specific** test, `minSdkVersion` is the correct and relevant attribute, for the deep reason explained in §1.3 — the NSC override mechanism does not exist at all on API<24.

2. **Any NSC configuration implemented by the app is IRRELEVANT for API<24 devices** — do not let the existence of a perfect `network_security_config.xml` (a passing result of MASTG-TEST-0235/0242) lead a tester to assume this risk is already handled; NSC only applies on an OS that actually supports the feature.

3. **This test is purely determined by the developer's business/compatibility decision**, not code quality — its remediation is a **product decision** (raising `minSdkVersion`, sacrificing reach to older devices) that may involve non-technical considerations (user-population analytics, device-support policy).

4. **Severity tends to be consistently high** when FAILed — because the impact is structural (no code-level mitigation can close this gap other than raising `minSdkVersion` itself), unlike most other tests whose severity varies depending on context of use.

5. **Document:** the exact `minSdkVersion` value, and optionally: the result of empirical verification on an API 23 emulator, if performed.

---

## 4. Recommendations

### 4.1 Raise `minSdkVersion` to at Least 24

```gradle
android {
    defaultConfig {
        minSdkVersion 24  // or higher, ideally per MASTG-BEST-0010 recommendations (see the MASTG-TEST-0245 document)
    }
}
```

### 4.2 If Raising `minSdkVersion` Is Not Feasible in the Short Term

If a business constraint prevents raising `minSdkVersion` immediately (e.g., a significant user base still on older devices), explicitly document this risk in the product's risk assessment, and consider additional application-level mitigations (e.g., manually implemented **certificate pinning** in code — not via NSC, which does not apply on that OS — as an additional defense layer independent of the system trust store, though its implementation must very carefully follow the safe practices discussed in the MASTG-TEST-0282/0283 documents in this research series).

### 4.3 Remediation Checklist

- [ ] `minSdkVersion` has been evaluated and ideally raised to ≥24 (or higher as needed for overall modernization, see MASTG-TEST-0245)
- [ ] If `minSdkVersion` <24 must be retained for business reasons, this risk is explicitly documented in the product risk assessment
- [ ] Consider manual certificate pinning in code as an additional mitigation independent of NSC for older devices
- [ ] **Re-verify:** re-run MASTG-TEST-0285 after every `minSdkVersion` change

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0285: Outdated Android Version Allowing Trust in User-Provided CAs](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0285/)
- [MASTG-TEST-0222: Position Independent Code (PIC) Not Enabled](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0222/) — similar `deprecated_since` pattern
- [MASTG-TEST-0245: References to Platform Version APIs](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0245/)
- [MASWE-0027: Insecure Certificate Validation](https://mas.owasp.org/MASWE/MASVS-NETWORK/MASWE-0027/)
- [MASTG-KNOW-0014: Android Network Security Configuration](https://mas.owasp.org/MASTG/knowledge/android/MASVS-NETWORK/MASTG-KNOW-0014/)
- [MASTG-TECH-0117: Obtaining Information from the AndroidManifest](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0117/)
- [MASTG-TECH-0150: Analyzing the AndroidManifest](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0150/)

### 5.2 Official Android Documentation

- [Android Developers — Network Security Configuration: Custom Trust](https://developer.android.com/privacy-and-security/security-config#CustomTrust)
- [Android Developers Blog — Changes to Trusted Certificate Authorities in Android Nougat](https://android-developers.googleblog.com/2016/07/changes-to-trusted-certificate.html)

### 5.3 Community Research and Articles

- [Hurricane Labs — Modifying Android Apps to Allow TLS Intercept with User CAs](https://hurricanelabs.com/blog/modifying-android-apps-to-allow-tls-intercept-with-user-cas/)
- [CWE-295: Improper Certificate Validation](https://cwe.mitre.org/data/definitions/295.html)

### 5.4 Tool Documentation

- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [aapt2 — Android Asset Packaging Tool](https://developer.android.com/tools/aapt2)
- [apkanalyzer](https://developer.android.com/tools/apkanalyzer)
- [androguard](https://github.com/androguard/androguard)
- [MobSF — Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)

---

*This document was prepared based on OWASP MASTG (latest release as of September 2026) and official Android Developers documentation regarding the trust anchor policy change in Android Nougat. The most important conceptual nuance: unlike other tests in this research series where `targetSdkVersion` determines the default behavior, this test correctly targets `minSdkVersion` because the Network Security Configuration — the mechanism that allows overriding trust anchor policy — does not exist at all as a platform feature on Android API 23 and below. This means no code/manifest configuration whatsoever can protect users on such older devices — the only effective control is preventing the app from being installed there in the first place, via `minSdkVersion`.*
