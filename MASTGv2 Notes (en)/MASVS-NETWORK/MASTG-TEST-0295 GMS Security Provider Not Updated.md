# MASTG-TEST-0295 GMS Security Provider Not Updated

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0295 |
| **Platform** | Android |
| **MASVS Category** | MASVS-NETWORK (MASVS-NETWORK-1) |
| **Weakness** | MASWE-0027 — *Insecure Certificate Validation* |
| **Highlighted APIs** | `ProviderInstaller.installIfNeeded()`, `ProviderInstaller.installIfNeededAsync()`, `ProviderInstaller.ProviderInstallListener` |
| **Test Type** | Static, Code |
| **Knowledge** | MASTG-KNOW-0011, MASTG-KNOW-0010 (Exception Handling) |
| **Best Practice** | MASTG-BEST-0020 (Update the GMS Security Provider) |
| **Related Technique** | MASTG-TECH-0013, MASTG-TECH-0014 |
| **Related Demo** | — (none) |
| **Official Rule** | — (**no dedicated semgrep rule** exists for this topic; a similarly named rule, `mastg-android-hardcoded-security-provider.yaml`, is found in the MASTG repository, but it targets a **completely different** topic — a hardcoded crypto provider in `Cipher.getInstance()`, not `ProviderInstaller` — see §3.2) |
| **Related CWE** | CWE-295, CWE-327 (Use of a Broken or Risky Cryptographic Algorithm) |

---

## 1. Explanation

### 1.1 Testing Objective

Excerpt from the official MASTG overview:

> *"This test checks whether the Android app ensures the Security Provider is updated to mitigate SSL/TLS vulnerabilities. The provider should be updated using Google Play Services APIs, and the implementation should handle exceptions properly."*

This test targets a mechanism that is **fairly unique** compared to most other MASVS-NETWORK tests in this research series — it is not about the application's own code configuration (such as NSC, `HostnameVerifier`, `TrustManager`), but about **whether the application leverages the independent update mechanism** provided by **Google Play Services** to patch the operating system's core cryptographic components — **without** needing to wait for an Android OS update itself.

### 1.2 Why This Mechanism Is Needed: Android Fragmentation and Slow OS Updates

MASTG-BEST-0020 explains the fundamental rationale behind this mechanism's existence:

> *"Android devices vary widely in OS version and update frequency. Relying solely on platform-level security can leave apps exposed to outdated SSL/TLS implementations and known vulnerabilities."*

This addresses the long-known problem of **Android fragmentation** — device manufacturers (OEMs) are often **slow or stop entirely** distributing OS security updates to devices already sold, leaving millions of users with outdated SSL/TLS implementations that are structurally vulnerable, **regardless** of how well the application's own code is written. The **GMS Security Provider** (delivered via Google Play Services) solves this problem elegantly:

> *"The GMS Security Provider addresses this by updating critical cryptographic components—such as `OpenSSL` and `TrustManager`—**independently of the Android OS**."*

This means core cryptographic components (the `OpenSSL`, `TrustManager` implementations) can be **updated via Google Play Services** — a distribution channel that is far faster and not dependent on the OEM — **without** needing to wait for a full Android OS update that may never arrive for that device.

### 1.3 A Real-World Case: CVE-2014-0224 (The Vulnerability Behind This Mechanism's Creation)

Official Android documentation explicitly cites the concrete vulnerability that was the historical motivation for creating this mechanism:

> *"CVE-2014-0224 in OpenSSL allowed on-path attackers to decrypt secure traffic. Google Play services version 5.0+ offers fixes."*

CVE-2014-0224 is the **ChangeCipherSpec Injection** vulnerability in OpenSSL — allowing an on-path (MITM) attacker to force both communicating parties to use a weak/predictable session key, effectively decrypting traffic that should have been TLS-encrypted. Because OpenSSL is a core component of the Android TLS stack, a vulnerability of this kind **cannot be fixed** through application code alone — it demands an update at the level of the system library itself, which then became the direct justification for the existence of `ProviderInstaller`.

### 1.4 A Critical Caveat That Is Often Missed: `SSLCertificateSocketFactory` Is NOT Updated

This is the **most important nuance** in this entire document, and it is explicitly warned about in the official documentation:

> *"Updating the `Provider` does **not** update the deprecated `android.net.SSLCertificateSocketFactory`, which remains vulnerable. Use high-level methods like `HttpsURLConnection` instead."*

This is consistent with a recurring theme already discussed in several other documents in this research series (MASTG-TEST-0234 regarding `SSLSocket`) — **manually built low-level APIs** tend to fall **outside the reach** of platform protection mechanisms that operate at a higher level. Applications that **still use** `SSLCertificateSocketFactory` (an API that is already **deprecated**, yet still possibly found in legacy codebases) **gain no benefit whatsoever** from the `ProviderInstaller` update, **even if** `installIfNeeded()` is called and executed successfully. This means the evaluation of this test is **incomplete** if it only checks for the presence of a `ProviderInstaller` call — the tester **must also** verify that the application does not use a legacy API path that this update does not touch at all.

### 1.5 Two Implementation Paths and Their Different Exception-Handling Needs

The official overview highlights two implementation approaches, each demanding a different error-handling pattern:

**`installIfNeeded()` (synchronous)** — used when the calling thread is allowed to block (e.g. a background worker):

```kotlin
try {
    ProviderInstaller.installIfNeeded(context)
} catch (e: GooglePlayServicesRepairableException) {
    // Google Play Services is outdated — show a repair notification to the user
    GoogleApiAvailability.getInstance().showErrorNotification(context, e.connectionStatusCode)
} catch (e: GooglePlayServicesNotAvailableException) {
    // Permanent error — the provider CANNOT be updated on this device
}
```

**`installIfNeededAsync()` (asynchronous)** — used on the UI thread, reports results via `ProviderInstallListener`:

```kotlin
override fun onProviderInstalled() {
    // Provider is now up to date — safe to proceed with network connections
}
override fun onProviderInstallFailed(errorCode: Int, recoveryIntent: Intent) {
    if (GoogleApiAvailability.getInstance().isUserResolvableError(errorCode)) {
        // Show a repair dialog
    } else {
        // Treat all HTTP communication as VULNERABLE
    }
}
```

Table of exceptions and their handling:

| Exception/Callback | Cause | Correct Handling |
|---|---|---|
| `GooglePlayServicesRepairableException` | Google Play Services outdated/disabled/unavailable | Show a dialog to the user to install/update/enable Play Services |
| `GooglePlayServicesNotAvailableException` | Permanent error, the provider **cannot** be updated | **Treat all HTTP communication as vulnerable** — take an appropriate fallback action |
| `onProviderInstallFailed()` with a non-user-recoverable error | Same as above, via the async path | Same — consider HTTP communication vulnerable |

### 1.6 A Critical Evaluation Point: Timing — Must Occur BEFORE Any Network Connection

The official Evaluation clause asserts a strict timing requirement:

> *"Check that these calls occur **before any network connections are made**."*

This is directly logical — if `ProviderInstaller.installIfNeeded()` is called **after** the application has already begun making network connections using the old/vulnerable cryptographic provider, those initial connections **will still use the un-updated implementation**, making the entire update effort ineffective for that time window. This call ideally should happen **as early as possible** in the application lifecycle — in `Application.onCreate()` or the earliest launcher activity, **before** the HTTP client (`OkHttpClient`, `Retrofit`, etc.) finishes being built and used.

### 1.7 A Special Scenario: Devices Without Google Play Services

MASTG-BEST-0020 provides an important note for the increasingly fragmented device ecosystem:

> *"If your app needs to support devices both with and without Google Play Services (such as Huawei devices, Amazon tablets, or AOSP-based ROMs), implement runtime checks to detect Play Services availability... On non-GMS devices, consider bundling a secure TLS library like Conscrypt."*

This is especially relevant for applications distributed outside the official Google Play Store or that target markets with alternative Android ecosystems (e.g. Huawei AppGallery/HMS, Amazon Fire devices) — **the entire `ProviderInstaller` mechanism becomes irrelevant** on devices without GMS, and the application needs a **separate mitigation strategy** (bundling a standalone TLS library such as **Conscrypt**) to ensure consistent cryptographic security across its entire user base.

---

## 2. Tools Used for Testing

### 2.1 Required Tools (Core)

| Tool | Function |
|---|---|
| **jadx** | DEX → Java decompilation for searching `ProviderInstaller` patterns |
| **grep / ripgrep** | Searching for API patterns and related exception handling |

### 2.2 Alternative & Supporting Tools

| Tool | Function |
|---|---|
| **CodeQL** | Traces whether the `ProviderInstaller.installIfNeeded()` call actually occurs **before** HTTP client initialization (`OkHttpClient.Builder().build()`, etc.) in the code execution order (§1.6) |
| **grep for `SSLCertificateSocketFactory`** | Mandatory supplemental verification per §1.4 — confirming the application does not use the legacy API that the provider update does not touch |
| **MobSF** | Sometimes shows Google Play Services API usage in the Code Analysis report |
| **Frida** | Hooking `ProviderInstaller.installIfNeeded()`/`installIfNeededAsync()` for runtime confirmation that the call actually occurs and does not throw an unhandled exception |

### 2.3 Environment Prerequisites

- **No device/root needed** for the core static analysis.
- **For dynamic verification**, ideally test on a device/emulator with Google Play Services deliberately set to outdated/disabled to confirm exception handling works as designed.
- **Check whether the app targets non-GMS devices** (§1.7) as an evaluation context — if so, the mere presence of `ProviderInstaller` is not enough; also check the fallback strategy for such devices.

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0013** to reverse engineer the application.
2. Use **MASTG-TECH-0014** to search for relevant APIs.

### 3.2 Method A — grep/ripgrep for Calls and Exception Handling

```bash
D=./decompiled/sources

# Find ProviderInstaller calls
rg -n 'ProviderInstaller\.installIfNeeded\(|ProviderInstaller\.installIfNeededAsync\(' $D

# Verify exception handling for the synchronous path
rg -n -A15 'ProviderInstaller\.installIfNeeded\(' $D | grep -A15 "installIfNeeded" | grep -c "GooglePlayServicesRepairableException\|GooglePlayServicesNotAvailableException"

# Verify ProviderInstallListener implementation for the asynchronous path
rg -n 'implements ProviderInstaller\.ProviderInstallListener|onProviderInstalled\(\)|onProviderInstallFailed\(' $D

# MANDATORY: search for legacy API usage NOT touched by the provider update (§1.4)
rg -n 'SSLCertificateSocketFactory' $D
```

**Note on the official rule**: there is no MASTG semgrep rule that specifically targets this `ProviderInstaller` topic. A similarly named rule (`mastg-android-hardcoded-security-provider.yaml`) available in the same repository **targets a completely different topic** — it detects calls to `Cipher.getInstance(algo, provider)` with an explicitly hardcoded cryptographic provider (relevant for auditing general cryptographic implementation quality, not for verifying provider updates via Google Play Services). Testers **must not** mistakenly associate that rule with this test.

### 3.3 Method B — CodeQL for Timing Verification

```ql
import java

class ProviderInstallerCall extends MethodAccess {
  ProviderInstallerCall() {
    this.getMethod().hasName(["installIfNeeded", "installIfNeededAsync"]) and
    this.getMethod().getDeclaringType().hasQualifiedName("com.google.android.gms.security", "ProviderInstaller")
  }
}

class HttpClientInit extends MethodAccess {
  HttpClientInit() {
    this.getMethod().hasName("build") and
    this.getMethod().getDeclaringType().hasQualifiedName("okhttp3", "OkHttpClient$Builder")
  }
}

from HttpClientInit httpInit
where not exists(ProviderInstallerCall call |
  call.getControlFlowNode().getASuccessor*() = httpInit.getControlFlowNode())
select httpInit, "HTTP client initialization found WITHOUT ProviderInstaller being called earlier in the execution order"
```

### 3.4 Method C — Frida for Runtime Confirmation

```javascript
// hook-provider-installer.js
Java.perform(function () {
    try {
        var ProviderInstaller = Java.use("com.google.android.gms.security.ProviderInstaller");
        ProviderInstaller.installIfNeeded.overload("android.content.Context").implementation = function (ctx) {
            console.log("[*] ProviderInstaller.installIfNeeded() called at: " + new Date().toISOString());
            try {
                return this.installIfNeeded(ctx);
            } catch (e) {
                console.log("    [!] Exception: " + e);
                throw e;
            }
        };
    } catch (e) { console.log("[x] ProviderInstaller not found/not used: " + e); }
});
```

### 3.5 Method Comparison: When to Use Which

| Method | Tool | When to use |
|---|---|---|
| **A** | grep | Baseline, including the `SSLCertificateSocketFactory` verification |
| **B** | CodeQL | Verifying timing relative to HTTP client initialization |
| **C** | Frida | Runtime confirmation of calls and exceptions |

**Minimum recommended combination:** **A (including the mandatory `SSLCertificateSocketFactory` check) → B (timing verification)**.

---

### 3.6 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rule:**

> **Evaluation:** *"The test case fails if the app does not update the provider, or it does not handle exceptions properly. Check that these calls occur before any network connections are made."*

---

#### ❌ FAIL / ISSUE — The check is declared FAILED if:

| No | Condition |
|---|---|
| F1 | The application **does not** call `ProviderInstaller.installIfNeeded()`/`installIfNeededAsync()` at all |
| F2 | It is called, but `GooglePlayServicesRepairableException`/`GooglePlayServicesNotAvailableException` is **not properly handled** (swallowed, or no fallback for the permanent case) |
| F3 | The `installIfNeeded()` call is found to occur **after** the first network connection is made (confirmed via Method B) |
| F4 | The application still uses `android.net.SSLCertificateSocketFactory` in any communication path — **not touched** by the provider update at all (§1.4) |

---

#### ✅ PASS — The check is declared PASSED if:

| No | Condition |
|---|---|
| P1 | `ProviderInstaller` is called as early as possible, before any HTTP client initialization |
| P2 | Both types of exception/callback are handled according to the official pattern (§1.5), including an explicit fallback for the unrecoverable case |
| P3 | The application **does not** use `SSLCertificateSocketFactory` in any path |
| P4 | For applications targeting non-GMS devices, there is an explicit fallback strategy (e.g. Conscrypt) |

---

#### ⚠️ Important Notes on Assessment

1. **DO NOT confuse this with the similarly named semgrep rule** — per §3.2, the `mastg-android-hardcoded-security-provider.yaml` rule targets a completely different topic.

2. **Verifying `SSLCertificateSocketFactory` is a mandatory step that is easy to overlook** — a perfectly implemented `ProviderInstaller` still provides no protection whatsoever for communication paths using this legacy API.

3. **Timing is an explicit official criterion, not merely a best practice** — verify the execution order, not just the presence of the call.

4. **Severity is modulated by:**

   | Factor | Severity |
   |---|---|
   | No `ProviderInstaller` at all, app handles sensitive data | **High** |
   | `ProviderInstaller` exists but exceptions are swallowed/unhandled | **Medium-High** |
   | Still uses `SSLCertificateSocketFactory` in any path | **High** — a direct bypass of this entire protection mechanism |

5. **Document:** the location of the `ProviderInstaller` call, exception-handling status, timing verification results, and the results of the `SSLCertificateSocketFactory` check.

---

## 4. Recommendations

### 4.1 Call as Early as Possible with Complete Exception Handling

```kotlin
class MyApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        try {
            ProviderInstaller.installIfNeeded(this)
        } catch (e: GooglePlayServicesRepairableException) {
            GoogleApiAvailability.getInstance().showErrorNotification(this, e.connectionStatusCode)
        } catch (e: GooglePlayServicesNotAvailableException) {
            // Mark HTTP communication as vulnerable; apply a fallback (e.g. disable sensitive features)
        }
    }
}
```

### 4.2 Avoid `SSLCertificateSocketFactory`

Migrate every path that still uses this deprecated API to `HttpsURLConnection`/OkHttp.

### 4.3 Remediation Checklist

- [ ] `ProviderInstaller` is called as early as possible, before any network connection
- [ ] Both exception types are handled with a clear fallback
- [ ] `SSLCertificateSocketFactory` is not used anywhere
- [ ] A fallback strategy for non-GMS devices has been considered (if relevant)
- [ ] **Re-verify:** rerun MASTG-TEST-0295 after changes to network initialization

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0295: GMS Security Provider Not Updated](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0295/)
- [MASWE-0027: Insecure Certificate Validation](https://mas.owasp.org/MASWE/MASVS-NETWORK/MASWE-0027/)
- [MASTG-BEST-0020: Update the GMS Security Provider](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0020/)

### 5.2 Official Android Documentation

- [Android Developers — Updating Your Security Provider to Protect Against SSL Exploits](https://developer.android.com/privacy-and-security/security-gms-provider)
- [Android Developers — `ProviderInstaller` API reference](https://developers.google.com/android/reference/com/google/android/gms/security/ProviderInstaller)
- [NVD — CVE-2014-0224 (OpenSSL ChangeCipherSpec Injection)](https://nvd.nist.gov/vuln/detail/CVE-2014-0224)
- [Conscrypt — TLS/crypto library for non-GMS devices](https://conscrypt.org)

### 5.3 CWE

- [CWE-295: Improper Certificate Validation](https://cwe.mitre.org/data/definitions/295.html)
- [CWE-327: Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)

### 5.4 Tool Documentation

- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [CodeQL — Documentation](https://codeql.github.com/docs/)
- [Frida — Dynamic instrumentation toolkit](https://frida.re/docs/javascript-api/)

---

*This document was compiled based on OWASP MASTG (latest release as of September 2026), official Android Developers documentation, and the CVE-2014-0224 reference as the real historical context underlying the existence of the `ProviderInstaller` mechanism. The most important nuance: provider updates via Google Play Services do **not** reach deprecated low-level APIs (`SSLCertificateSocketFactory`) — a complete evaluation demands dual verification: confirming `ProviderInstaller` is called correctly AND confirming no communication path escapes its protection via that legacy API. No official MASTG semgrep rule was found that specifically targets this topic.*
