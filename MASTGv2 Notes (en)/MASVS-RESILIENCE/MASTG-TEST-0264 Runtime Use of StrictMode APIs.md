# MASTG-TEST-0264 Runtime Use of StrictMode APIs

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0264 |
| **Platform** | Android |
| **MASVS Category** | MASVS-RESILIENCE |
| **Weakness** | MASWE-0061 — *Debug Artifacts Not Removed* |
| **Highlighted API** | `StrictMode.setVmPolicy`, `StrictMode.VmPolicy.Builder.penaltyLog` |
| **Test Type** | **Dynamic, Hooks** |
| **Profile** | **R (Resilience) only** |
| **Related Techniques** | MASTG-TECH-0005 (Install App), MASTG-TECH-0043 (Method Hooking) |
| **Related Test** | **MASTG-TEST-0263** (Logging of StrictMode Violations) — a **different** approach to the same risk, see §1.2 |
| **Related Demo** | — (none) |
| **Official Rule** | — (not applicable; dynamic test based on hooking, not static code analysis) |
| **Related CWE** | CWE-215, CWE-489 |

---

## 1. Explanation

### 1.1 Testing Objective

Official MASTG overview quote:

> *"This test checks whether the app uses `StrictMode` by dynamically analyzing the app's behavior and placing relevant hooks to detect the use of `StrictMode` APIs, such as `StrictMode.setVmPolicy` and `StrictMode.VmPolicy.Builder.penaltyLog`."*

The entire in-depth conceptual context — why `StrictMode` active in production is dangerous, what specific information leaks through its violation stack traces (class names, methods, code lines), and how this provides a "free map" for reverse engineering efforts — **has already been discussed in full in the MASTG-TEST-0263 document**. This document focuses on the **methodological difference** between the two tests, which, despite sharing an identical weakness (MASWE-0061) and profile (R), actually **measure something subtly different**.

### 1.2 Fundamental Difference from MASTG-TEST-0263: Detecting Configuration vs. Detecting Violations

This is the most important methodological nuance distinguishing the two tests — although at first glance it looks like a "hooking version" of the previous logcat test, the two actually **measure different signals**:

| | MASTG-TEST-0263 (Logging of Violations) | MASTG-TEST-0264 *(this document)* |
|---|---|---|
| **What is detected** | **Evidence of a policy violation** that actually occurred and was logged to Logcat | **The existence of the `StrictMode` configuration** itself, regardless of whether a violation was actually triggered |
| **Method** | Passive Logcat monitoring (`adb logcat`) | Active hooking on the configuration API (`setVmPolicy`, `penaltyLog`) |
| **Prerequisite for FAIL** | At least **one policy violation** must actually occur during the session (e.g., disk I/O on the main thread) | **Merely** calling the `StrictMode` configuration API is enough — **no need** for a violation to actually occur |

The practical consequence: **MASTG-TEST-0264 is structurally more sensitive** than MASTG-TEST-0263 in certain cases. Imagine a scenario where an application enables `StrictMode` in a production build, but **during a particular test session**, by coincidence no operation violates the configured policy (e.g., all disk I/O has already been correctly moved to a background thread, so it never triggers a `StrictModeDiskReadViolation`). In this scenario:

- **MASTG-TEST-0263 will show a PASS result** (no violation log found) — even though technically this could be a **false negative**, because an active `StrictMode` is still a debug artifact that should not be present in production, regardless of whether a violation happened to be triggered during that particular test session.
- **MASTG-TEST-0264 will still show a FAIL result** — because the hook on `setVmPolicy()`/`penaltyLog()` will fire **as soon as that API is called during application initialization**, regardless of whether a real policy violation occurs afterward.

This is why **the two tests complement each other**, rather than being duplicates — MASTG-TEST-0264 closes a coverage gap that could potentially be missed by MASTG-TEST-0263's passive approach.

### 1.3 Why `penaltyLog()` Is Specifically Highlighted

The official overview specifically names `StrictMode.VmPolicy.Builder.penaltyLog` as a hooking target, not just `setVmPolicy()` in general. This matters because `StrictMode` supports various kinds of **penalties** (actions taken when a violation is detected) — `penaltyLog()` (logs to Logcat, which is the root cause of the information-leak risk in MASTG-TEST-0263), `penaltyDeath()` (forces the application to crash), `penaltyDropBox()` (logs to Android's internal DropBox system), and others. By specifically hooking `penaltyLog()`, a tester can **specifically confirm** that the configuration found truly leads to a logging risk (not merely `penaltyDeath()` alone, for example, which has a different risk profile — though still a debug artifact that should not be present in production).

---

## 2. Tools Used for Testing

### 2.1 Mandatory Tools (Core)

| Tool | Function |
|---|---|
| **Frida** | Core dynamic instrumentation — hooking the `StrictMode` configuration API |
| **frida-tools** (`frida-trace`) | Quick tracing without a custom script |
| **objection** | Ready-to-use Frida wrapper |

### 2.2 Alternative & Supporting Tools

| Tool | Function |
|---|---|
| **Xposed/LSPosed** | Persistent hooking alternative per MASTG-TECH-0043 |
| **adb logcat** | Complement for correlating with MASTG-TEST-0263 results |

### 2.3 Environment Prerequisites

- **A device/emulator with a Frida server is required** — this test is purely dynamic, based on hooking.
- **The test target must be the production/release build APK**, the same as MASTG-TEST-0263.
- **Thorough interaction** — although this test is more sensitive to the mere existence of the configuration (§1.2), `StrictMode` is typically configured once during application initialization (`Application.onCreate()`), so the hook should ideally be in place **before** the application finishes starting, in order to catch that initialization moment.

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0005** to install the application.
2. Use **MASTG-TECH-0043** to hook the relevant API calls.
3. Exercise the application thoroughly, entering sensitive data wherever possible.

### 3.2 Method A — Comprehensive Hooking of the `StrictMode` Configuration *(primary method)*

```javascript
// hook-strictmode-runtime.js
Java.perform(function () {
    function getBacktrace() {
        return Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());
    }

    // 1. setVmPolicy — VM/application-level configuration
    try {
        var StrictMode = Java.use("android.os.StrictMode");
        StrictMode.setVmPolicy.overload("android.os.StrictMode$VmPolicy").implementation = function (policy) {
            console.log("\n[!] StrictMode.setVmPolicy() called on this build!");
            console.log("    Policy: " + policy.toString());
            console.log("    Stack trace:\n" + getBacktrace());
            return this.setVmPolicy(policy);
        };
    } catch (e) { console.log("[x] setVmPolicy hook failed: " + e); }

    // 2. setThreadPolicy — thread-level configuration (complementary, not explicitly named but relevant)
    try {
        StrictMode.setThreadPolicy.overload("android.os.StrictMode$ThreadPolicy").implementation = function (policy) {
            console.log("\n[!] StrictMode.setThreadPolicy() called on this build!");
            console.log("    Stack trace:\n" + getBacktrace());
            return this.setThreadPolicy(policy);
        };
    } catch (e) { console.log("[x] setThreadPolicy hook failed: " + e); }

    // 3. penaltyLog() on VmPolicy.Builder — specifically highlighted by the official overview
    try {
        var VmPolicyBuilder = Java.use("android.os.StrictMode$VmPolicy$Builder");
        VmPolicyBuilder.penaltyLog.overload().implementation = function () {
            console.log("\n[!] StrictMode.VmPolicy.Builder.penaltyLog() called!");
            console.log("    Stack trace:\n" + getBacktrace());
            return this.penaltyLog();
        };
    } catch (e) { console.log("[x] penaltyLog (VmPolicy) hook failed: " + e); }

    // 4. penaltyLog() on ThreadPolicy.Builder
    try {
        var ThreadPolicyBuilder = Java.use("android.os.StrictMode$ThreadPolicy$Builder");
        ThreadPolicyBuilder.penaltyLog.overload().implementation = function () {
            console.log("\n[!] StrictMode.ThreadPolicy.Builder.penaltyLog() called!");
            console.log("    Stack trace:\n" + getBacktrace());
            return this.penaltyLog();
        };
    } catch (e) { console.log("[x] penaltyLog (ThreadPolicy) hook failed: " + e); }
});
```

```bash
frida -U -f com.target.app -l hook-strictmode-runtime.js --no-pause
```

**Important note**: the script **must** be run with `-f` (spawn, not attaching to an already-running process) and `--no-pause`, because `StrictMode` configuration almost always happens in `Application.onCreate()` — a very early moment in the application lifecycle. If the hook is installed **after** the application is already running (attaching to an existing process), the moment `setVmPolicy()` is called has very likely already passed and will never be caught.

### 3.3 Method B — objection (Without Writing a Custom Script)

```bash
objection -g com.target.app explore
android hooking watch class_method android.os.StrictMode.setVmPolicy --dump-args --dump-backtrace
android hooking watch class_method 'android.os.StrictMode$VmPolicy$Builder.penaltyLog' --dump-backtrace
```

### 3.4 Method C — frida-trace (Quick Tracing via Wildcard)

```bash
frida-trace -U -f com.target.app -m "android.os.StrictMode*!*"
```

### 3.5 Method D — Correlation with MASTG-TEST-0263 for a Complete Picture

Run both tests side by side to obtain the most complete picture:

```bash
# Terminal 1: configuration hooking (this test)
frida -U -f com.target.app -l hook-strictmode-runtime.js --no-pause

# Terminal 2: actual violation monitoring (MASTG-TEST-0263)
adb logcat | grep -i "StrictMode"
```

If Terminal 1 captures a call to `setVmPolicy()`/`penaltyLog()` **but** Terminal 2 never shows a real violation during the same session, this confirms exactly the scenario described in §1.2 — concrete proof that MASTG-TEST-0264 catches a FAIL condition that is **missed** by MASTG-TEST-0263 alone.

### 3.6 Method Comparison: When to Use Which

| Method | Tool | Advantage | When to use |
|---|---|---|---|
| **A** | Custom Frida script (spawn) | Covers all 4 APIs at once + backtrace | Primary baseline, `-f` is mandatory |
| **B** | objection | Fast, no scripting | Quick initial exploration |
| **C** | frida-trace | Automatic tracing via wildcard | Quick overview |
| **D** | Parallel correlation with MASTG-TEST-0263 | Proves this test's unique added value | Thorough comparative analysis |

**Minimum combination recommended:** **A (spawn hooking from the start, `-f` mandatory) → D (correlation with MASTG-TEST-0263)** for a report that shows both configuration status and evidence of actual violations, if any.

---

### 3.7 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rule:**

> **Observation:** *"The output should show the runtime usage of `StrictMode` APIs."*
>
> **Evaluation:** *"The test case fails if the output shows the runtime usage of `StrictMode` APIs."*

This criterion is **much simpler** than MASTG-TEST-0263 — there is no requirement that "a violation must have been logged"; merely **evidence that the API was called** already satisfies the FAIL condition.

---

#### ❌ FAIL / ISSUE — The check is declared FAILED if:

| No | Condition |
|---|---|
| F1 | The `setVmPolicy`/`setThreadPolicy` hook **fires at all** during the test session on a production build, regardless of whether a real policy violation occurs afterward |
| F2 | The `penaltyLog()` hook (VmPolicy or ThreadPolicy) fires — explicit confirmation that penalty logging is enabled |

**Example evidence (illustrative — MASTG does not yet provide an official demo for this test):**

```
[!] StrictMode.setVmPolicy() called on this build!
    Policy: VmPolicy{mask=13, mCtsLog=...}
    Stack trace:
        at com.target.app.MyApplication.onCreate(MyApplication.java:18)
        at android.app.Instrumentation.callApplicationOnCreate(Instrumentation.java:1270)

[!] StrictMode.VmPolicy.Builder.penaltyLog() called!
    Stack trace:
        at com.target.app.MyApplication.onCreate(MyApplication.java:17)
```

Interpretation: `StrictMode` is fully configured with `penaltyLog()` from `Application.onCreate()` onward on the build under test (which should be a production build) — **FAIL**, regardless of whether Logcat during this session happened to show a real violation or not.

---

#### ✅ PASS — The check is declared PASSED if:

| No | Condition |
|---|---|
| P1 | **No** `StrictMode` API hook fires at all during a thorough test session on a production build |

---

#### ⚠️ Important Assessment Notes

1. **This test is stricter than its counterpart (MASTG-TEST-0263) — use it to close false-negative gaps.** Per §1.2, an application could PASS MASTG-TEST-0263 (no violation logged during a particular session) yet still FAIL this test (configuration proven to exist). Always run **both**, not just one, for a truly solid conclusion.

2. **Make sure the hook is installed BEFORE the application starts (`-f`, not attach)** — this is the most common technical mistake causing a false negative on this test, since `StrictMode` configuration usually occurs very early in `Application.onCreate()`.

3. **Make sure to test the production/release build**, consistent with the same prerequisite as MASTG-TEST-0263.

4. **The hook result's backtrace gives a precise code location for remediation** — use it to point directly at the code line that needs to be wrapped in a `BuildConfig.DEBUG` guard, the same pattern as in the MASTG-TEST-0238/0249/0251 documents in this research series.

5. **Severity follows the same pattern as MASTG-TEST-0263** — although the FAIL criteria here do not require proof of an actual violation, the real impact (architectural leakage) is only truly realized when a real violation occurs and is logged; combine the results of both tests for the most accurate impact assessment.

6. **Document:** which `StrictMode` API fired (`setVmPolicy`/`setThreadPolicy`/`penaltyLog`), the backtrace of its configuration location, and the correlation result with MASTG-TEST-0263 (whether a real violation was also found during the same session).

---

## 4. Recommendations

The recommendations are identical to **the MASTG-TEST-0263 document §4** — wrap all `StrictMode` calls in a `BuildConfig.DEBUG` guard, verify via ProGuard/R8 dead-code elimination, and integrate testing into CI/CD.

Additional specifics from the hooking perspective:

### 4.1 Integrate Both Tests into Automated Regression Testing

```bash
#!/bin/bash
# ci-check-strictmode-hooks-and-logs.sh — combine both approaches
frida -U -f com.target.app -l hook-strictmode-runtime.js --no-pause > frida_output.log &
FRIDA_PID=$!
adb logcat -c
sleep 3
./run-ui-test-suite.sh
kill $FRIDA_PID

if grep -q "StrictMode.setVmPolicy() called" frida_output.log; then
    echo "[FAILED] StrictMode API detected active on this build (MASTG-TEST-0264)"
    exit 1
fi
```

### 4.2 Remediation Checklist

- [ ] Hooks cover `setVmPolicy`, `setThreadPolicy`, and `penaltyLog` on both builders
- [ ] Hooks are installed via spawn (`-f`), not attach, to catch early initialization
- [ ] Results are correlated with MASTG-TEST-0263 for a complete picture
- [ ] All `StrictMode` calls found are wrapped in a `BuildConfig.DEBUG` guard
- [ ] **Re-verification:** re-run MASTG-TEST-0264 on every new release build

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0264: Runtime Use of StrictMode APIs](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0264/)
- [MASTG-TEST-0263: Logging of StrictMode Violations](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0263/)
- [MASWE-0061: Debug Artifacts Not Removed](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0061/)
- [MASTG-TECH-0005: Installing Apps](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0005/)
- [MASTG-TECH-0043: Method Hooking](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0043/)

### 5.2 Official Android Documentation

- [Android Developers — `StrictMode` API reference](https://developer.android.com/reference/android/os/StrictMode)
- [Android Developers — `StrictMode.VmPolicy.Builder`](https://developer.android.com/reference/android/os/StrictMode.VmPolicy.Builder)
- [Android Developers — `StrictMode.ThreadPolicy.Builder`](https://developer.android.com/reference/android/os/StrictMode.ThreadPolicy.Builder)

### 5.3 Tool Documentation

- [Frida — Dynamic instrumentation toolkit](https://frida.re/docs/javascript-api/)
- [frida-trace — Documentation](https://frida.re/docs/frida-trace/)
- [Objection — Runtime Mobile Exploration toolkit](https://github.com/sensepost/objection)
- [LSPosed Framework](https://github.com/LSPosed/LSPosed)

---

*This document was compiled based on OWASP MASTG (latest release as of September 2026) and official Android Developers documentation. Despite sharing an identical weakness and profile with MASTG-TEST-0263, this test measures a fundamentally different signal: the **existence of the `StrictMode` configuration** via API hooking, rather than **evidence of a violation** via passive Logcat monitoring. This difference makes this test structurally more sensitive — able to detect a FAIL condition even in a test session where, by coincidence, no policy violation was actually triggered, a scenario that would be missed by MASTG-TEST-0263 alone. Both tests are recommended to be run side by side for the most complete evaluation coverage.*
