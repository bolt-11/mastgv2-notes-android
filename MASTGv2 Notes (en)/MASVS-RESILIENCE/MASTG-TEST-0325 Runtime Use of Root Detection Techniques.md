# MASTG-TEST-0325 Runtime Use of Root Detection Techniques

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0325 |
| **Platform** | Android |
| **MASVS Category** | MASVS-RESILIENCE |
| **Weakness** | MASWE-0051 |
| **Test Type** | Dynamic, Hooks |
| **Related Techniques** | MASTG-TECH-0005 (Installing Apps), MASTG-TECH-0043 (Method Hooking), MASTG-TECH-0032 (Execution Tracing), MASTG-TECH-0144 (Bypassing Root Detection, optional) |
| **Related Best Practices** | MASTG-BEST-0029, MASTG-BEST-0030 (Implementing Root Detection) |
| **Related Knowledge** | MASTG-KNOW-0027 (Root Detection) |
| **Related Test** | **MASTG-TEST-0324** — the **static** counterpart, a two-way relationship (already discussed in the TEST-0324 document, §1.2) |

---

## 1. Explanation

### 1.1 Testing Objective

Official MASTG overview quote:

> *"This test verifies whether an app implements runtime root detection by attempting to hook into common root detection mechanisms."*

This test completes the **active confirmation** side of the findings from **MASTG-TEST-0324** — but unlike the "static candidate, then dynamic confirmation" pattern used in many other test pairs (e.g., TEST-0318/0319), the official overview here explicitly permits both directions of work (already discussed in detail in the TEST-0324 document, §1.2). What specifically distinguishes this test is its **focus on observing the API/system calls that are actually invoked while the app is running**, rather than merely finding references in the code.

### 1.2 Device Flexibility: Rooted Recommended, But Not Strictly Mandatory

An important nuance that distinguishes this test from most other dynamic tests that strictly require a rooted device:

> *"It is recommended to run this test using a rooted device or emulator to ensure that root detection mechanisms are triggered during testing. However, even on a non-rooted device, this test can still surface root detection logic if the app performs checks that do not require root access (for example, checking for the presence of root-related files or system properties)."*

This is technically logical — many root detection patterns (checking `File.exists()` against `su` paths, reading `Build.TAGS`) **do not require root access to execute**; the app only checks for the **absence** of these indicators. This means that even if hooking is performed on a non-rooted device, the method invocation itself will still occur (and the hook will detect it) — only the outcome of the check will always read as "clean"/not rooted. This is relevant for teams who do not have access to a rooted device in their testing environment.

### 1.3 An Optional Approach: Active Bypass as an Additional Signal, Not Merely Passive Observation

The overview offers a more aggressive option than simply hooking and logging:

> *"But, optionally, you can use MASTG-TECH-0144 to try to bypass root detection checks in the app and observe the results. For example, successful bypassing of certain checks or failed detections may indicate the presence of root detection mechanisms."*

This is a clever indirect inference technique: if a tester attempts to **bypass** a mechanism (forcing `File.exists()` to always return `false`) and **the app's behavior changes** (a feature that was previously blocked becomes accessible), that itself is **strong evidence** that a root detection mechanism indeed exists and is functional — even without needing to look at the source code at all. This is especially useful for cases involving **obfuscated native code** mechanisms, mentioned as a limitation in MASTG-TEST-0324, because bypass-and-observe-behavior does not depend on being able to read the internal logic.

### 1.4 Expected False Negatives: MASTG's Explicit Acknowledgment of Hooking Limitations

This section is unique in that MASTG explicitly provides a dedicated "Expected False Negatives" subsection (rarely found this complete in other tests in this research series):

> *"This test may produce false negatives if the app uses root detection techniques that are not covered by the hooks or traces used in this test, or if the root detection logic is implemented in a way that evades detection (for example, through obfuscation, dynamic code loading, or anti-instrumentation techniques). In such cases, the absence of findings does not guarantee the absence of root detection."*

The **anti-instrumentation techniques** point here is highly relevant in practice — many modern financial apps actually detect **the presence of Frida itself** as a separate risk signal (anti-Frida detection), which means the hooking process performed by a tester for this test might **trigger another defense mechanism** that alters the app's behavior (e.g., forced app termination) before the root check can be observed running normally. This creates a methodological paradox: to test root detection, a tester may first need to **bypass Frida detection**, which is itself a different resilience layer (outside this test's scope, but must be watched for as a confounding factor).

### 1.5 Real-World Context: An "Arms Race" Between Modern Root-Hiding and App Detection

Community research shows that the root detection bypass ecosystem has become far more mature than simply renaming the `su` binary. The modern stack widely used to fool real financial apps combines multiple layers:

> *"The full stack for hiding root includes Zygisk → DenyList → Play Integrity Fix → Shamiko → HideMyAppList. This stack has been tested with major banking apps including Chase, Bank of America, Wells Fargo, Capital One, and others."*

The **Shamiko** component is specifically designed to neutralize detection based on **Magisk's DenyList** itself:

> *"Shamiko is a Zygisk module that works in conjunction with Magisk's DenyList, making Magisk's presence virtually undetectable by specific apps and helping to pass SafetyNet/Play Integrity checks."*

This is important context for assessing findings: even if a target app PASSes this test (root detection confirmed active at runtime), real-world conditions show that **client-side mechanisms alone are no longer sufficient** against a device genuinely and seriously prepared to evade detection — this is the basis for MASTG-BEST-0030's recommendation for server-side validation as a mandatory, not optional, layer (already discussed in the TEST-0324 document, §1.6, §4.3).

### 1.6 Layered Risk: Frida as a Real Attack Vector Outside Legitimate Testing Contexts

It's important to note, in balance — the same technique used by authorized testers (with permission) to verify root detection is also used as a real attack vector when it falls into unauthorized hands:

> *"For mobile banking specifically, attackers can use Frida for: SSL pinning bypass through scripts that disable certificate validation in seconds, exposing all API traffic to interception; hooking network libraries to read request/response bodies, steal authentication tokens, modify transaction amounts, and replay requests."*

This reinforces that root detection is not a standalone control — it is one **signal** within a chain of layered defenses (anti-Frida, SSL pinning, server-side risk engine) that collectively raise the cost of attack, consistent with the "cost-raising measure" principle already stated by MASTG-BEST-0030.

---

## 2. Tools Used for Testing

### 2.1 Required Tools (Core, per MASTG-TECH)

| Tool | Function |
|---|---|
| **Frida** | Hooking root detection APIs (MASTG-TECH-0043), optionally also for active bypass (MASTG-TECH-0144) |
| **strace** | Kernel-level system call tracing (MASTG-TECH-0032), capturing native calls not visible from Java hooking |
| **ADB** | App installation (MASTG-TECH-0005) |
| **Objection** | Quick bypass via `android root disable` without writing a custom script |

### 2.2 Alternative and Supporting Tools

| Tool | Function |
|---|---|
| **Magisk + Zygisk + DenyList + Shamiko** | Simulates an advanced "root-hidden" device to test whether the app's mechanism still triggers even when root is aggressively concealed — a realistic test scenario per §1.5 |
| **LSPosed** | System-level Java/native hooking framework, a Frida alternative for a more persistent bypass (a module rather than a session script) |
| **frida-antiantijb** / community anti-anti-detection scripts | Countering anti-Frida mechanisms that may trigger before the root check can be observed (handling the confounding factor in §1.4) |
| **KernelSU** | Kernel-level (rather than user-space) root-hiding simulation for testing resilience against the most advanced scenarios |

### 2.3 Environment Prerequisites

- **A rooted device/emulator is recommended**, but a non-rooted device can still be used for limited cases (§1.2).
- Prepare handling for possible anti-Frida detection in the target app (§1.4) — consider Frida with a hidden configuration (custom frida-server rename, etc.) if needed.
- A list of sensitive scenarios/flows that need to be triggered during the exercise (per official step 4: "exercise the app extensively... enter sensitive data wherever you can").

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0005** to install the application.
2. Use **MASTG-TECH-0043** to hook the relevant APIs.
3. Use **MASTG-TECH-0032** to trace the relevant system calls.
4. Exercise the app extensively to trigger as many flows as possible.

### 3.2 Method A — Frida: Passive Observation Hook (Without Altering Results)

```javascript
Java.perform(function () {
    var File = Java.use("java.io.File");
    File.exists.overload().implementation = function () {
        var path = this.getAbsolutePath();
        var result = this.exists();
        console.log("[File.exists] " + path + " -> " + result);
        return result; // not altered, purely observational
    };

    var Runtime = Java.use("java.lang.Runtime");
    Runtime.exec.overload('java.lang.String').implementation = function (cmd) {
        console.log("[Runtime.exec] " + cmd);
        return this.exec(cmd);
    };

    var PackageManager = Java.use("android.app.ApplicationPackageManager");
    PackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function (pkg, flags) {
        console.log("[getPackageInfo] " + pkg);
        return this.getPackageInfo(pkg, flags);
    };
});
```

```bash
frida -U -f com.example.targetapp -l observe_root_checks.js --no-pause
```

### 3.3 Method B — strace to Capture Native-Level Checks

```bash
adb shell strace -f -e trace=stat,openat,access -p $(adb shell pidof com.example.targetapp) 2>&1 | grep -iE 'su|magisk|busybox'
```

Complements Method A — capturing file checks performed through **native code (JNI)**, which would not be visible from Java method hooking alone.

### 3.4 Method C — Objection for Quick Bypass and Observing Behavioral Change (Per §1.3)

```bash
objection -g com.example.targetapp explore
# inside the REPL:
android root disable
```

Run the app after the bypass, then compare its behavior to the non-bypassed state — a change in behavior (a previously blocked feature now becoming accessible) is indirect evidence of the mechanism's existence (§1.3).

### 3.5 Method D — Advanced Root-Hiding Stack to Test Real-World Resilience (Per §1.5)

```
Procedure:
1. Prepare a device with Magisk + Zygisk + DenyList + Shamiko active
2. Add the target app's package to the DenyList
3. Run the app, observe whether the root detection mechanism still triggers (via Method A hooking) even with root hidden at the system level
4. Compare the results with Method A on a rooted device without the hiding stack
```

This goes beyond the test's official scope (basic observation), but is relevant for assessing whether a PASS finding on this test is truly resilient against the realistic root-hiding scenarios used in the field.

### 3.6 Method Comparison: When to Use Which

| Method | Tool | When to Use |
|---|---|---|
| **A** | Frida passive observation | Mandatory baseline — records which APIs are invoked without altering results |
| **B** | strace | Captures native/JNI checks invisible to Java hooking |
| **C** | Objection bypass | Indirect inference via observing behavioral change (§1.3) |
| **D** | Root-hiding stack (Shamiko, etc.) | Assessing real-world resilience against field scenarios, beyond the official baseline scope |

**Minimum recommended combination:** **A (mandatory, passive observation) + B (closing the native gap)**. Method C is a useful complement when A/B give unclear results. Method D is only for in-depth resilience audits, not standard testing.

---

### 3.7 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rule:**

> **Evaluation:** *"The test case fails if no instances of root detection checks are observed. However, results from this test should be interpreted as evidence of the presence of root detection logic, not as an assessment of its robustness or effectiveness."*

As with TEST-0324, the direction of evaluation is **inverted** — the absence of an observation is a FAIL.

---

#### ❌ FAIL / ISSUE — The check is declared FAILED if:

| No | Condition |
|---|---|
| F1 | After extensive exercising with active hooking (Method A/B), **not a single** root-detection-related API/system call invocation is observed |

**Mandatory caution note:** before concluding a final FAIL, make sure this is not caused by **anti-instrumentation** preventing Frida from functioning normally (§1.4) — first verify that the app runs normally with Frida attached, and only then conclude a FAIL if there is truly no root-check activity at all.

---

#### ✅ PASS — The check is declared PASSED if:

| No | Condition |
|---|---|
| P1 | At least one API/system call invocation matching a root detection pattern from MASTG-KNOW-0027 is observed during the exercise |
| P2 | *(Optional, additional quality signal)* Active bypass (Method C) shows a real behavioral change — functional proof, not just an empty API call with no effect |

**Example evidence:**

```
[File.exists] /system/xbin/su -> false
[File.exists] /system/bin/su -> false
[getPackageInfo] com.topjohnwu.magisk
```

Interpretation: APIs are actively invoked at runtime against paths and packages relevant to root detection. **PASS**.

---

#### ⚠️ Important Notes on Assessment

1. **This too is purely a presence test, not an effectiveness test** — as with TEST-0324, a PASS result does not guarantee the mechanism is resilient against modern root-hiding stacks (§1.5); consider Method D for a deeper audit when business risk is high (e.g., financial apps).

2. **Beware of anti-instrumentation as a confounding factor** — if the app immediately crashes/exits when Frida is attached, this does **not** mean there is no root detection; it is actually a signal of an additional resilience layer (anti-Frida) that must first be bypassed separately before this test can be run validly.

3. **Passive observation (without altering return values) is preferred to avoid bias** — altering results early on (as in Method C) may hide other layered mechanisms that only trigger after the first check "passes"; run passive observation thoroughly first before attempting an active bypass.

4. **Correlate with MASTG-TEST-0324 results** — if the static test finds many candidates but the dynamic test observes none of them being invoked, the logic in question may be **dead code**, invoked only under conditions that were not triggered, or located in an untested path; further investigation is needed before concluding there is a discrepancy.

5. **Severity is modulated:**

   | Factor | Severity |
   |---|---|
   | No root detection observed at all, app handles sensitive data/transactions | **High** |
   | Root detection observed but easily neutralized with a basic bypass (only 1 layer, no server-side validation) | **Medium** |
   | Root detection observed, layered, and still triggers even with an advanced root-hiding stack enabled | **Not a finding**/positive information |

6. **Document:** the API/system calls observed being invoked along with their arguments, the observed behavioral change from an active bypass (if performed), and the interaction with any detected anti-instrumentation.

---

## 4. Recommendations

### 4.1 Combine Detection with a Proportional Response, Not Just a Hard Block

```java
// WEAK — only a single binary decision point
if (RootDetector.isRooted()) { finish(); }

// BETTER — risk signals are combined and sent to the server for a contextual decision
RiskSignal signal = RiskSignal.builder()
    .rootDetected(RootDetector.isRooted())
    .fridaDetected(AntiInstrumentation.isHooked())
    .build();
riskEngine.evaluate(signal); // final decision made on the server, not purely client-side
```

### 4.2 Periodically Test Resilience Against Modern Root-Hiding Stacks

Make testing with Magisk+Zygisk+DenyList+Shamiko (§3.5) part of the routine security audit cycle, given that this stack keeps evolving and the APK needs to be re-tested with every major release.

### 4.3 Remediation Checklist

- [ ] Root detection is observed actively running at runtime (not just present in code but never invoked)
- [ ] The mechanism withstands basic bypass (Objection `android root disable`, common Frida scripts)
- [ ] Also tested against an advanced root-hiding stack (Shamiko, etc.) for high-risk applications
- [ ] Risk signal results are combined with server-side validation, not a client-only decision
- [ ] Combined with anti-instrumentation (anti-Frida) as a separate layer

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0325 (source, tests-beta)](https://github.com/OWASP/mastg/blob/master/tests-beta/android/MASVS-RESILIENCE/MASTG-TEST-0325.md)
- [MASTG-TEST-0324: References to Root Detection Mechanisms](https://github.com/OWASP/mastg/blob/master/tests-beta/android/MASVS-RESILIENCE/MASTG-TEST-0324.md)
- [MASTG-TECH-0144: Bypassing Root Detection](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0144/)
- [MASTG-KNOW-0027: Root Detection](https://mas.owasp.org/MASTG/knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0027/)
- [MASTG-BEST-0030: Implementing Root Detection](https://github.com/OWASP/mastg/blob/master/best-practices/MASTG-BEST-0030.md)

### 5.2 Research and Real-World Cases

- [Approov: Frida Detection & Prevention](https://approov.io/knowledge/frida-detection-prevention)
- [Approov: What is Frida and How Can Apps Protect Against It?](https://approov.io/knowledge/what-is-frida-and-how-can-apps-protect-against-it)
- [GitHub: frida-antiantijb — Jailbreak Detection Bypasses Based on Frida](https://github.com/juliangrtz/frida-antiantijb)
- [Wikipedia: Magisk (software)](https://en.wikipedia.org/wiki/Magisk_(software))
- [XDA Forums: Hide Magisk Root (Bank Apps, SafetyNet, Play Integrity)](https://xdaforums.com/t/hide-magisk-root-bank-apps-safetynet-play-integrity.4729480/)

### 5.3 Tool Documentation

- [Frida — Dynamic Instrumentation Toolkit](https://frida.re/docs/home/)
- [Objection — Runtime Mobile Exploration](https://github.com/sensepost/objection)
- [LSPosed Framework](https://github.com/LSPosed/LSPosed)
- [KernelSU](https://github.com/tiann/KernelSU)

---

*This document was prepared based on official OWASP MASTG content (`tests-beta/android/MASVS-RESILIENCE/MASTG-TEST-0325.md`, `MASTG-TECH-0144`), as well as community research on the evolution of modern root-hiding stacks (Zygisk, DenyList, Shamiko, Play Integrity Fix) that have proven effective against real banking apps (Chase, Bank of America, Wells Fargo, etc.) as of 2026. The most important methodological nuance: MASTG's official "Expected False Negatives" subsection explicitly acknowledges that anti-instrumentation (Frida detection itself) can be a confounding factor that prevents this test from running validly — testers must verify that Frida functions normally on the target app before concluding there is no root detection, and a PASS result on this test still does not guarantee resilience against modern root-hiding stacks that have already proven effective in the field.*
