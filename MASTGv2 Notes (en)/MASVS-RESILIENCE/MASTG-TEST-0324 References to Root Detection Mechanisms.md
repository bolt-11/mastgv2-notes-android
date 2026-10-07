# MASTG-TEST-0324 References to Root Detection Mechanisms

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0324 |
| **Platform** | Android |
| **MASVS Category** | MASVS-RESILIENCE |
| **Weakness** | MASWE-0051 |
| **Test Type** | Static, Code |
| **Related Techniques** | MASTG-TECH-0013 (Reverse Engineering), MASTG-TECH-0014 (Static Analysis for Relevant APIs) |
| **Related Best Practices** | MASTG-BEST-0029 (Implementing Resilience and RASP Signals — `status: placeholder`), MASTG-BEST-0030 (Implementing Root Detection) |
| **Related Knowledge** | MASTG-KNOW-0027 (Root Detection) |
| **Related Test** | **MASTG-TEST-0325** — the **dynamic** counterpart that confirms the root detection mechanism is active at runtime (a two-way relationship, see §1.2) |
| **Official Rule** | `mastg-android-root-detection.yaml` — 5 rules combined (file checks, package check, test-keys, system properties, runtime exec), see §1.4 |

---

## 1. Explanation

### 1.1 Testing Objective

Official MASTG overview quote:

> *"This test checks whether the app implements root detection by statically analyzing the app binary for common root detection patterns. These may include checks for files and artifacts typically associated with rooted devices, as well as calls to known root detection APIs or libraries."*

It is important to note from the outset: this is a test about the **presence** of a root detection mechanism, **not** about its **effectiveness/strength**. MASTG explicitly limits this scope:

> *"Out of Scope: This test does not cover robustness or effectiveness of root detection mechanisms, which can be very difficult to assess through static analysis alone and may require manual reverse engineering and custom instrumentation."*

This scope limitation matters methodologically — finding root detection in the code **does not mean** the mechanism is hard to bypass. Evaluating the strength/robustness of root detection (whether it is easily patched, hooked, or avoided) is a **different** question, further discussed in MASTG-BEST-0030 (§1.5).

### 1.2 Two-Way Relationship with MASTG-TEST-0325 (Static ↔ Dynamic)

Unlike many other static/dynamic test pairs in this research series that follow a single direction (static first, then dynamic to confirm), this test's overview explicitly offers **two equally valid workflow orders**:

> *"This way, you can use static analysis to surface potential root detection logic and then focus your dynamic testing on those specific checks to confirm they are triggered at runtime. Alternatively, you can perform dynamic testing first to identify any root detection mechanisms that are active at runtime, and then use static analysis to further investigate their implementation and coverage."*

In other words:

- **Path A (Static → Dynamic):** Find candidate root detection patterns in the code via semgrep/grep, then use them as precise hooking targets in MASTG-TEST-0325.
- **Path B (Dynamic → Static):** Hook common APIs (`File.exists`, `Runtime.exec`, etc.) on a rooted device first to see which mechanisms are **actually active**, then trace back to the code to understand the full implementation and its coverage.

Which path to use depends on context — if the code is easy to decompile and read, Path A is more efficient; if the code is heavily obfuscated, Path B (observing runtime behavior first) often provides a faster starting point for investigation.

### 1.3 Why the Definition of "Root" Is Broadened for Android: Custom ROM

The MASTG-KNOW-0027 overview provides a definitional nuance that is often overlooked:

> *"For Android, we define 'root detection' a bit more broadly, including custom ROMs detection, i.e., determining whether the device is a stock Android build or a custom build."*

This means indicators such as **`Build.TAGS` containing `"test-keys"`** (signifying a non-stock image, signed with a test key rather than the official release key) fall within the scope of root detection even though the device may not technically have `su` access. This detection category is relevant because custom ROMs often (though not always) correlate with an environment that is easier to modify/instrument.

### 1.4 Analysis of the Official Rule: Five Separate Patterns, All Severity INFO

The official `mastg-android-root-detection.yaml` rule contains **five separate Semgrep rules**, each targeting one technique category from MASTG-KNOW-0027:

| Rule ID | Pattern Matched | Category from MASTG-KNOW-0027 |
|---|---|---|
| `mastg-android-root-detection-file-checks` | `new File($PATH).exists()` where `$PATH` contains `su`/`magisk`/`Superuser.apk` | File Existence Checks |
| `mastg-android-root-detection-package-check` | `$PM.getPackageInfo($PKG, ...)` | Checking Installed App Packages |
| `mastg-android-root-detection-test-keys` | `Build.TAGS.contains("test-keys")` (3 pattern variants, including the Kotlin compiled form `StringsKt.contains$default`) | Checking for Custom Android Builds |
| `mastg-android-root-detection-system-properties` | `Runtime.getRuntime().exec("getprop " + $PROP)` | — (checking system properties via shell) |
| `mastg-android-root-detection-runtime-exec` | `Runtime.getRuntime().exec($CMD)` **excluding** the `getprop` pattern above | Executing Privileged Commands |

Important analytical note: **all five rules have `INFO` severity**, not `WARNING` or `ERROR` — this is consistent with the nature of the test (detecting **presence** only, not assessing **effectiveness**), and also acknowledges that invoking these patterns (`Runtime.exec`, `getPackageInfo`) **does not automatically mean root detection** — they could be used for entirely unrelated, non-security purposes. The INFO severity signals that this result is purely informational and needs manual verification against the calling context.

The `-test-keys` rule also shows design maturity — handling **three different pattern variants** for the same case, including a compiled-Kotlin pattern (`StringsKt.contains$default`), demonstrating that the rule has been tuned for mixed Java/Kotlin source code rather than assuming a single language.

### 1.5 Real-World Impact: RootBeer as the Most Common Bypass Target

MASTG-KNOW-0027 explicitly references **RootBeer** (MASTG-TOOL-0146) as one of the commonly used root detection libraries. Security community research shows that precisely because of its popularity, RootBeer has become the **most common bypass target** in mobile application penetration testing:

> *"RootBeer is a widely used open-source root detection library that many apps rely on, making it a high-value target during assessments. RootBeer exposes an isRooted() method on the RootBeer class... Apps may call individual RootBeer check methods directly such as checkForSuBinary, checkForDangerousProps, checkForRWPaths, detectTestKeys, and checkSuExists."*

This provides real-world context for evaluating effectiveness (§1.1) — once a tester (or attacker) knows an app uses RootBeer (discovered via this test), publicly available Frida bypass scripts from Frida CodeShare can immediately be used to neutralize **all check methods** at once, without needing deep reverse engineering. This reinforces the point from MASTG-BEST-0030 (§1.6) that **relying on a single default library without customization** is a weak practice.

### 1.6 Design Principle from MASTG-BEST-0030: Root Detection as "Cost-Raising," Not an Absolute Barrier

A key quote that frames how to assess this test's findings:

> *"Root detection is an environment risk signal that helps identify devices with elevated privilege or common rooting artifacts. It is a cost raising measure and it is bypassable, so it should be used only when rooted device risk materially impacts the app."*

MASTG-BEST-0030 provides seven good practices relevant for assessment **alongside** this test's results (merely finding presence is not enough):

1. Layer defenses (combine with integrity checks, anti-debug, backend enforcement)
2. Distribute checks (spread across many points, not a single centralized gate)
3. Use multiple methods (combine filesystem, property, process, and native-level checks)
4. **Avoid well-known patterns only** — a point directly relevant to the RootBeer-default finding in §1.5
5. Proportional responses (don't go straight to total lockout when confidence is low)
6. Validate server-side
7. Rotate and randomize checks across sessions/releases

And a realistic note about limitations:

> *"Root detection can flag legitimate scenarios such as custom ROMs, enterprise test devices, and security research environments. Aggressive blocking can push users to modified app builds, and can increase support costs."*

This is relevant for remediation recommendations — overly aggressive root detection has real business side effects, not merely pure security considerations.

---

## 2. Tools Used for Testing

### 2.1 Required Tools (Core)

| Tool | Function |
|---|---|
| **jadx** | DEX → Java decompilation (MASTG-TECH-0013) |
| **Semgrep** + official rule `mastg-android-root-detection.yaml` | Matching the five root detection patterns (MASTG-TECH-0014) |

### 2.2 Alternative and Supporting Tools

| Tool | Function |
|---|---|
| **MobSF** | Automated report that already includes detection of common root-check patterns in its static pipeline |
| **mobsfscan** | Standalone CLI based on the MobSF + Semgrep rule set, suitable for CI integration without running full MobSF |
| **Androguard** | Python library for parsing DEX/APK/Manifest — the foundation of many other tools, useful for custom queries against strings/methods related to root detection |
| **Quark-Engine** | Scores application behavior based on a weighted rule set, customizable to flag combinations of root detection patterns as a single "behavior" |
| **grep/ripgrep** | Fast literal string search for paths like `su`, `magisk`, rooting package names (`com.topjohnwu.magisk`, etc.) outside the scope of the standard Semgrep patterns |

### 2.3 Environment Prerequisites

- No device/root required for static analysis.
- Prepare a reference list of strings/paths from MASTG-KNOW-0027 (§1.3) to supplement manual searches beyond the five official rules.

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0013** to reverse engineer the application.
2. Use **MASTG-TECH-0014** to search for relevant APIs.

### 3.2 Method A — Semgrep with the Official Rule

```bash
semgrep --config mastg-android-root-detection.yaml ./decompiled/sources
```

### 3.3 Method B — grep/ripgrep for Patterns Outside the Official Rule's Coverage

```bash
D=./decompiled/sources

# Root paths/binaries not covered by the official rule's regex (only su/magisk/Superuser.apk)
rg -n 'busybox|daemonsu|/system/xbin/|/system/app/Superuser' $D

# Rooting packages beyond those already covered
rg -n 'eu\.chainfire\.supersu|com\.noshufou\.android\.su|com\.koushikdutta\.superuser' $D

# Process checking (checkRunningProcesses pattern)
rg -n 'getRunningServices|getRunningAppProcesses' $D
```

### 3.4 Method C — mobsfscan for CI Integration

```bash
pip install mobsfscan
mobsfscan ./decompiled/sources --json -o root_detection_scan.json
```

Useful when a team wants to run root detection checks (and other security patterns) automatically in a CI/CD pipeline, not just during one-off manual audit sessions.

### 3.5 Method D — MobSF Automated Report

Upload the APK to a (self-hosted) MobSF instance — the automated static report will include a findings section related to root detection as part of the overall security summary, useful for initial triage before an in-depth manual audit.

### 3.6 Method Comparison: When to Use Which

| Method | Tool | When to Use |
|---|---|---|
| **A** | Semgrep + official rule | Mandatory baseline, covers 5 core patterns |
| **B** | Manual grep/ripgrep | Complements the official rule's limited coverage (only su/magisk/Superuser.apk for file checks) |
| **C** | mobsfscan | Continuous CI/CD integration |
| **D** | MobSF | Quick triage/comprehensive report |

**Minimum recommended combination:** **A (mandatory) + B (closing coverage gaps in the official rule)**, followed by **MASTG-TEST-0325** for runtime confirmation per the two-way relationship in §1.2.

---

### 3.7 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rule:**

> **Evaluation:** *"The test case fails if the app does not implement any root detection checks. However, note that static analysis may not detect all root detection mechanisms, especially if they are proprietary, obfuscated, or implemented in native code."*
>
> *"If root detection checks are found, this is a positive sign, but you should still evaluate their effectiveness."*

Important note: this test's FAIL logic runs in the **opposite direction** compared to most other tests in this research series — here, the **absence** of a mechanism is a FAIL, not the **presence** of a dangerous pattern.

---

#### ❌ FAIL / ISSUE — The check is declared FAILED if:

| No | Condition |
|---|---|
| F1 | **No** root detection pattern is found at all (neither from the official rule nor additional manual search) anywhere in the application's code |

**Example:** the Semgrep scan + manual grep results are empty, with no references to `su`, `magisk`, `getPackageInfo` for rooting packages, `test-keys`, or root-related `Runtime.exec` — indicating the application has no mechanism at all for detecting a rooted environment. **FAIL**.

---

#### ✅ PASS — The check is declared PASSED if:

| No | Condition |
|---|---|
| P1 | At least one valid root detection pattern is found (not a false positive — see the INFO-severity note in §1.4) |
| P2 | The mechanism found is **spread across multiple layers** (file check + package check + native, not just a single unmodified default library) — an additional quality signal beyond a binary pass/fail |

**Example evidence:**

```java
// Found in com/example/targetapp/security/RootChecker.java
if (new File("/system/xbin/su").exists() || Build.TAGS.contains("test-keys")) {
    disableSensitiveFeatures();
}
```

Interpretation: two different patterns (file check + test-keys check) are found and used together to disable sensitive features. **PASS**, with the note that further evaluation of robustness (§1.6) is still needed.

---

#### ⚠️ Important Notes on Assessment

1. **A PASS on this test does NOT mean the app is secure** — it purely indicates presence. Refer to MASTG-BEST-0030 to assess whether the implementation deserves to be called effective (layered, distributed, uses server-side validation, etc.) — do not stop at "a root check was found, done."

2. **A FAIL on this test may be a false negative caused by obfuscation or native code** — per the official note, proprietary/obfuscated/native mechanisms are not always detected via ordinary pattern matching. Consider Method D (MobSF, which also analyzes native libraries) and proceed to **MASTG-TEST-0325** (dynamic) before concluding there is no root detection at all.

3. **INFO severity on the official rule does not mean the finding is unimportant** — it acknowledges the ambiguity of automated interpretation (the pattern could be used for non-security purposes), not diminishing the importance of the final manual evaluation result.

4. **Reliance on a default library (RootBeer without customization) is a quality finding, not merely a PASS/FAIL** — per §1.5, this is the most common real-world bypass target; note it as a remediation recommendation even if the technical test result is PASS.

5. **Document:** the code location of each pattern found, the technique category (per the MASTG-KNOW-0027 taxonomy), whether a third-party library (RootBeer/RootBeer-like) or a custom implementation is used, and recommendations for further testing in MASTG-TEST-0325.

---

## 4. Recommendations

### 4.1 Do Not Rely Solely on a Default Library

```java
// WEAK — only calls the default isRooted() without customization
RootBeer rootBeer = new RootBeer(context);
if (rootBeer.isRooted()) { ... }

// BETTER — combine with additional custom checks
RootBeer rootBeer = new RootBeer(context);
boolean suspicious = rootBeer.isRooted()
    || customNativeCheck()
    || checkWritableSystemPartition();
```

### 4.2 Distribute Checks, Don't Use a Single Centralized Gate

Place checks at sensitive points (before a transaction, during session initialization) instead of only once in `onCreate()` — per the "Distribute checks" practice from MASTG-BEST-0030.

### 4.3 Server-Side Validation as the Final Layer

Do not make client-side root detection the sole line of defense for high-risk operations — correlate risk signals with a server-side policy that considers the user's context comprehensively.

### 4.4 Remediation Checklist

- [ ] Root detection is present and distributed across several layers (not just a single default library)
- [ ] Minimum combination: file check + package check + native-level check
- [ ] Proportional response (not an immediate total lockout) for low-confidence cases
- [ ] Additional server-side validation for sensitive operations
- [ ] Results confirmed via MASTG-TEST-0325 before being considered final

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0324 (source, tests-beta)](https://github.com/OWASP/mastg/blob/master/tests-beta/android/MASVS-RESILIENCE/MASTG-TEST-0324.md)
- [MASTG-TEST-0325: Runtime Use of Root Detection Techniques (source)](https://github.com/OWASP/mastg/blob/master/tests-beta/android/MASVS-RESILIENCE/MASTG-TEST-0325.md)
- [MASTG-KNOW-0027: Root Detection](https://mas.owasp.org/MASTG/knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0027/)
- [MASTG-BEST-0030: Implementing Root Detection](https://github.com/OWASP/mastg/blob/master/best-practices/MASTG-BEST-0030.md)
- [MASTG-BEST-0029: Implementing Resilience and RASP Signals](https://github.com/OWASP/mastg/blob/master/best-practices/MASTG-BEST-0029.md)

### 5.2 Research and Real-World Cases

- [Secarma: Bypassing Android's RootBeer Library (Part 2)](https://secarma.com/bypassing-androids-rootbeer-library-part-2)
- [RedFoxSec: Android Root Detection Bypass Using Frida: Full Guide](https://www.redfoxsec.com/blog/android-root-detection-bypass-using-frida)
- [GitHub: rootbeer-bypass — Frida script for bypassing the RootBeer sample](https://github.com/0x4ngK4n/rootbeer-bypass)
- [Talsec: Simple Root Detection: Implementation and Verification](https://docs.talsec.app/appsec-articles/articles/simple-root-detection-implementation-and-verification)
- [NetSPI: Android Root Detection Techniques](https://www.netspi.com/blog/technical-blog/mobile-application-penetration-testing/android-root-detection-techniques/)

### 5.3 Tool Documentation

- [MobSF — Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)
- [mobsfscan — Standalone Static Analysis CLI](https://github.com/MobSF/mobsfscan)
- [Androguard](https://github.com/androguard/androguard)
- [Quark-Engine](https://www.kali.org/tools/quark-engine/)
- [Frida CodeShare](https://codeshare.frida.re/)

---

*This document was prepared based on official OWASP MASTG content (`tests-beta/android/MASVS-RESILIENCE/MASTG-TEST-0324.md`, `MASTG-KNOW-0027`, `MASTG-BEST-0030`, rule `mastg-android-root-detection.yaml`), as well as security community research on RootBeer as the most common real-world bypass target. The most important methodological nuance: this test purely evaluates **presence**, not **effectiveness** — a PASS on this test is only the first step; evaluating the quality of the implementation (layering, distribution, server-side validation) per MASTG-BEST-0030 must still be done separately, and the relationship with MASTG-TEST-0325 is two-way (static→dynamic or dynamic→static), unlike most other test pairs which are one-directional.*
