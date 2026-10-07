# MASTG-TEST-0351 Runtime Use of Emulator Detection Techniques

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0351 |
| **Platform** | Android |
| **MASVS Category** | MASVS-RESILIENCE |
| **Weakness** | MASWE-0053 |
| **Test Type** | Dynamic, Hooks |
| **Related Techniques** | MASTG-TECH-0005 (Installing Apps), MASTG-TECH-0043 (Method Hooking), MASTG-TECH-0032 (Execution Tracing) |
| **Related Knowledge** | MASTG-KNOW-0031 (Emulator Detection) |
| **Related Best Practice** | MASTG-BEST-0046 (Hardening Against Emulation) |
| **Structural Note** | Unlike root detection (TEST-0324/0325), this test currently has **no static counterpart** in the MASTG catalog — it stands alone as a purely dynamic test |

---

## 1. Explanation

### 1.1 Testing Objective

Quote from the official MASTG overview:

> *"This test verifies whether an app implements runtime emulator detection by attempting to hook into common emulator detection mechanisms. These may include checks for build properties and artifacts typically associated with emulated devices, as well as calls to known emulator detection APIs."*

The purpose of emulator detection is conceptually similar to root detection (TEST-0324/0325) — both are **anti-reversing** controls that raise the cost of analysis rather than absolutely preventing attacks. MASTG-KNOW-0031 states this explicitly:

> *"In the context of anti-reversing, the goal of emulator detection is to increase the difficulty of running the app on an emulated device. This increased difficulty forces the reverse engineer to defeat the emulator checks or use a physical device, thereby limiting the access required for large-scale device analysis."*

The phrase *"limiting the access required for large-scale device analysis"* is key — emulator detection is highly relevant for preventing **large-scale automated analysis** (fuzzing, mass scanning), because running thousands of application instances on physical devices is far more expensive and difficult than running them on an emulator.

### 1.2 Six Categories of Emulator Indicators (Per MASTG-KNOW-0031)

| Category | Example Indicators |
|---|---|
| **Build characteristics** | `Build.FINGERPRINT` contains `generic`/`test-keys`; `Build.MODEL` such as `sdk`, `genymotion`, `nox` |
| **Telephony characteristics** | `getLine1Number()` returns `15555215554`–`15555215584` (the fixed QEMU range) |
| **Package name indicators** | Installed emulator packages: `com.bignox.`, `com.bluestacks`, `com.microvirt.`, etc. |
| **Available activities/services** | Launcher activity with the prefix `com.bluestacks.` |
| **File system artifacts** | `/dev/socket/qemud`, `/dev/goldfish_pipe`, `/dev/socket/genyd` |
| **OpenGL renderer** | GLES renderer string containing `Bluestacks` or `Translator` |

The richness of these categories is far more diverse than root detection — emulator detection exploits **architectural artifacts** (hardware virtualization cannot be fully hidden) beyond merely files/processes that can be renamed.

### 1.3 An Important Nuance: Package Visibility Restrictions Limit Package-Based Detection

One technical detail MASTG-KNOW-0031 specifically highlights, relevant for interpreting test results:

> *"On Android 11 (API level 30) and later, package visibility restrictions affect package-based emulator detection. If a package is installed but not visible to the app, getPackageInfo behaves the same as if the package were not installed... This can create false negatives for package-based emulator detection."*

This means that an application **targeting API 30+** that does not declare the appropriate `<queries>` element in its manifest **will be unable** to detect certain emulator packages at all, even though its checking code technically "exists." This is relevant for the evaluation in §3.7 — the absence of **positive results** from package-based detection may not be because the mechanism is absent, but because of architectural limitations in modern platforms that restrict package visibility.

### 1.4 Direct Comparison with Root Detection (TEST-0324/0325)

This test's structure is **nearly identical** to the root detection pair in this research series, though with a few nuanced differences worth noting:

| | Root Detection (TEST-0324/0325) | Emulator Detection (this test) |
|---|---|---|
| **Static counterpart** | Exists (TEST-0324) | **Does not exist** — this test stands alone |
| **Test device flexibility** | Rooted recommended, non-rooted partially still works | Emulator recommended, *"some checks may still surface on a physical device if the app runs them unconditionally"* |
| **Optional bypass** | Mentioned as an indirect inference technique | **Identically worded** pattern — *"successful bypassing of certain checks or failed detections may indicate the presence"* |
| **Expected False Negatives** | Present, cites anti-instrumentation as a confounding factor | Present, **identically worded** pattern |
| **Robustness/effectiveness scope** | Out of scope for robustness/effectiveness | Out of scope for robustness/effectiveness (identically worded pattern) |

This very high structural similarity indicates that MASTG applies a **consistent methodology template** for the entire family of resilience tests covering "detection of risky environments" (root, emulator, debugger, etc.) — something useful for testers to know, because experience testing one test in this family is highly transferable to other similar tests.

### 1.5 Why There Is No Static Counterpart: Possible Structural Reasons

Unlike root detection, which has an explicit static counterpart (TEST-0324), this emulator detection test **stands alone** as a dynamic test. This is consistent with the nature of most indicators in §1.2 — many of them (OpenGL renderer, telephony characteristics, file system artifacts) **can only be meaningfully verified at runtime** in a relevant environment, because the comparison values (`Build.MODEL`, etc.) are **simple string literals** that are easy to find statically yet **not informative** without execution context — meaning static candidates for a test like this likely would not provide significant additional investigative value compared to a direct dynamic approach.

### 1.6 Real-World Context: The Industrial Scale of Emulator-Farm-Based Fraud

Security anti-fraud industry research shows that the threat this test attempts to mitigate is **not merely a reversing concern**, but an actively occurring large-scale financial fraud vector:

> *"Mobile app fraud involves the abuse of Android and iOS applications using automation, fake devices, emulators, and manipulated runtime environments, with 2025 dominated by mobile bots, emulators, device farms, fake installs, and account takeover (ATO) attacks... Android emulators are heavily used by fraud rings running click farms and account farming operations."*

A documented real-world incident from the first quarter of 2025 shows a concrete attack pattern:

> *"During Q1-Q2 2025, Southeast Asia experienced an organized credit-card fraud incident where attackers exploited design weaknesses in top-up mechanisms, bypassed user-side verification, bound stolen credit cards to Sybil accounts for fraudulent top-ups, and completed cash-out through collusive merchants."*

An important note about the limitations of static-value-based detection, reinforcing the "cat-and-mouse" principle already affirmed by MASTG-KNOW-0031:

> *"Emulator system values can be modified to fool fingerprinting attempts, with emulators like Bliss OS, Waydroid, and LDPlayer 9 allowing extensive system value spoofing."*

This context matters — modern emulators used in large-scale fraud operations are **deliberately designed** to spoof `Build.*` values to appear like physical devices, reinforcing why relying on a single layer of detection alone is not sufficient (in line with the layered defense principle of MASTG-BEST-0046).

---

## 2. Tools Used for Testing

### 2.1 Required Tools (Core, Per MASTG-TECH)

| Tool | Function |
|---|---|
| **Frida** | Hooking emulator detection APIs (MASTG-TECH-0043) |
| **strace** | Tracing system calls to capture native-level checks (MASTG-TECH-0032) |
| **ADB** | App installation (MASTG-TECH-0005) |

### 2.2 Alternative & Supporting Tools

| Tool | Function |
|---|---|
| **Objection** | Quick hooking without custom scripts |
| **Several different emulator types (standard AVD, Genymotion, LDPlayer, Bliss OS)** | Testing detection coverage against various emulator types — one emulator may be detected while another is not, given the diversity of artifact characteristics (§1.2) |
| **Physical device** | Comparison verification — ensuring the mechanisms found do **not false-positive** flag a genuine physical device as an emulator |

### 2.3 Environment Prerequisites

- **An emulator is recommended** as the primary testing environment, though a physical device remains useful as a comparison (§2.2) and for catching checks that run unconditionally.
- Vary the emulator types used to assess detection coverage more representatively.

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0005** to install the application.
2. Use **MASTG-TECH-0043** to hook relevant APIs.
3. Use **MASTG-TECH-0032** to trace relevant system calls.
4. Exercise the application extensively to trigger as many flows as possible.

### 3.2 Method A — Frida: Passive Observation Hooks on Build Properties

```javascript
Java.perform(function () {
    var Build = Java.use("android.os.Build");
    ["FINGERPRINT", "MODEL", "MANUFACTURER", "HARDWARE", "PRODUCT"].forEach(function (field) {
        console.log("[Build." + field + "] " + Build.class.getField(field).get(null));
    });

    var PackageManager = Java.use("android.app.ApplicationPackageManager");
    PackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function (pkg, flags) {
        if (pkg.indexOf("bignox") !== -1 || pkg.indexOf("bluestacks") !== -1 || pkg.indexOf("microvirt") !== -1) {
            console.log("[getPackageInfo] emulator package check: " + pkg);
        }
        return this.getPackageInfo(pkg, flags);
    };
});
```

### 3.3 Method B — strace to Capture File System Artifact Checks

```bash
adb shell strace -f -e trace=access,openat,stat -p $(adb shell pidof com.example.targetapp) 2>&1 | grep -iE 'qemud|goldfish|genyd|qemu_pipe'
```

### 3.4 Method C — Objection for Quick Bypass and Behavior-Change Observation

```bash
objection -g com.example.targetapp explore
# inside the REPL, manually hook Build fields or use third-party emulator bypass modules
```

Observe whether forcing `Build.*` values to physical-device values changes the app's behavior (per the indirect inference technique mentioned in the official overview §1.1).

### 3.5 Method D — Cross-Emulator-Type Testing

```
Procedure:
1. Run the app on a standard AVD (goldfish/ranchu) — observe hook results
2. Repeat on Genymotion — observe hook results
3. Repeat on LDPlayer/Bliss OS (designed for spoofing, §1.6) — observe hook results
4. Compare detection coverage across emulator types
```

### 3.6 Method Comparison: When to Use Which

| Method | Tool | When to use |
|---|---|---|
| **A** | Frida | Mandatory baseline — passive observation of Build properties & package checks |
| **B** | strace | Capturing native-level file system artifact checks |
| **C** | Objection bypass | Indirect inference via behavior change |
| **D** | Cross-emulator | Assessing detection coverage against emulators deliberately designed to disguise themselves |

**Minimum recommended combination:** **A + B (mandatory)**, with **D** highly recommended for financial applications given the real scale of emulator-farm-based fraud (§1.6).

---

### 3.7 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rule:**

> **Evaluation:** *"The test case fails if no instances of emulator detection checks are observed. However, results from this test should be interpreted as evidence of the presence of emulator detection logic, not as an assessment of its robustness or effectiveness."*

---

#### ❌ FAIL / ISSUE — The check is declared FAILED if:

| No | Condition |
|---|---|
| F1 | Not a single API call/artifact check related to emulator detection is observed during extensive exercising |

**Caution note:** before concluding FAIL, consider whether the absence of results is caused by package visibility limitations (§1.3) or anti-instrumentation (per the Expected False Negatives pattern), rather than the genuine absence of a mechanism.

---

#### ✅ PASS — The check is declared PASSED if:

| No | Condition |
|---|---|
| P1 | At least one API call/artifact check matching a MASTG-KNOW-0031 category (§1.2) is observed |
| P2 | *(Optional, additional quality signal)* The mechanism consistently triggers across various emulator types (§3.5 Method D), not only one specific type |

---

#### ⚠️ Important Notes on Scoring

1. **A pure presence test, not an effectiveness test** — identical to the root detection principle (TEST-0325); a PASS does not guarantee resilience against modern emulators that deliberately spoof system values (§1.6).

2. **Vary the emulator types tested** — a mechanism tested only on one emulator type (e.g., standard AVD) may give an impression of broader coverage than it actually has; emulators like LDPlayer/Bliss OS, designed for spoofing, provide a more representative resilience test against the real-world threat.

3. **Consider the API 30+ package visibility limitation** before concluding FAIL for package-based detection (§1.3) — also check whether the manifest has the appropriate `<queries>` element.

4. **Severity is modulated as follows:**

   | Factor | Severity |
   |---|---|
   | No emulator detection at all on a financial app prone to emulator-farm fraud | **High** |
   | Detection exists but covers only one category (e.g., only Build properties, easily spoofed) | **Medium** |
   | Layered detection, consistent across various emulator types, combined with the Play Integrity API | **Not a finding** |

5. **Document:** the APIs/artifacts observed triggering, the emulator types used in testing, and the coverage comparison results across emulator types if performed.

---

## 4. Recommendations

### 4.1 Combine Layered Detection with Google Play Integrity API

```java
// A local signal alone is not sufficient — combine with server-side attestation
RiskSignal signal = RiskSignal.builder()
    .emulatorDetected(EmulatorDetector.checkBuildProperties() || EmulatorDetector.checkFileArtifacts())
    .playIntegrityVerdict(playIntegrityManager.requestIntegrityToken())
    .build();
riskEngine.evaluate(signal);
```

### 4.2 Declare `<queries>` for Package-Based Detection on API 30+

```xml
<queries>
    <package android:name="com.bignox.app" />
    <package android:name="com.bluestacks" />
</queries>
```

### 4.3 Remediation Checklist

- [ ] Emulator detection covers at least three different categories (build properties, file artifacts, package/activity)
- [ ] Tested against at least three different emulator types, including ones designed for spoofing
- [ ] Combined with the Google Play Integrity API for a server-side verdict
- [ ] `<queries>` element declared for package-based detection when targeting API 30+
- [ ] Risk signal results are combined with server-side decisions, not client-only

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0351 (source, tests-beta)](https://github.com/OWASP/mastg/blob/master/tests-beta/android/MASVS-RESILIENCE/MASTG-TEST-0351.md)
- [MASTG-KNOW-0031: Emulator Detection](https://mas.owasp.org/MASTG/knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0031/)
- [MASTG-BEST-0046: Hardening Against Emulation](https://github.com/OWASP/mastg/blob/master/best-practices/MASTG-BEST-0046.md)
- [MASTG-TEST-0324/0325: Root Detection (related document in this research series, similar methodology pattern)](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0324/)

### 5.2 Research and Real-World Cases

- [Veriff: Emerging Emulator and Injection Attacks — Protect Your Bank Cards in 2025](https://www.veriff.com/fraud/news/bank-card-fraud-2025)
- [Appdome: What Is Mobile App Fraud? 2026 Trends & Risks](https://www.appdome.com/dev-sec-blog/what-is-mobile-app-fraud/)
- [Cryptomathic: Protecting Mobile Banking in 2025 with Emulator Detection](https://www.cryptomathic.com/blog/securing-mobile-banking-apps-in-2025-stay-ahead-of-emulator-attacks)
- [Surepass: Emulator Detection — What It Is and Why Apps Need It](https://surepass.io/blog/what-is-emulator-detection/)

### 5.3 Tool Documentation

- [Frida — Dynamic Instrumentation Toolkit](https://frida.re/docs/home/)
- [Objection — Runtime Mobile Exploration](https://github.com/sensepost/objection)

---

*This document was prepared based on official OWASP MASTG content (`tests-beta/android/MASVS-RESILIENCE/MASTG-TEST-0351.md`, `MASTG-KNOW-0031`, `MASTG-BEST-0046`), as well as anti-fraud industry research on the real scale of emulator-farm-based fraud (banking bots, account farming, the Southeast Asia credit card incident Q1-Q2 2025). The most important methodological nuance: unlike root detection, which has an explicit static counterpart (TEST-0324), this test stands alone as a purely dynamic test — likely because the comparison values (Build properties, etc.) are uninformative without execution context. Its evaluation structure follows an almost identical template to root detection (presence-based, not effectiveness-based, with Expected False Negatives due to anti-instrumentation), but modern emulators used in large-scale fraud operations are deliberately designed to spoof system values — confirming that a PASS on this test does not guarantee resilience against device farms already optimized for evasion.*
