# MASTG-TEST-0353 Runtime Use of Debugging Detection APIs

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0353 |
| **Platform** | Android |
| **MASVS Category** | MASVS-RESILIENCE |
| **Weakness** | MASWE-0064 |
| **Test Type** | Dynamic, Hooks, **Manual** |
| **Related Techniques** | MASTG-TECH-0005, MASTG-TECH-0043, MASTG-TECH-0032 (Execution Tracing), MASTG-TECH-0023, MASTG-TECH-0031 (Debugging — attaching a JDWP/native debugger) |
| **Related Knowledge** | MASTG-KNOW-0007, MASTG-KNOW-0028 (Anti-Debugging) |
| **Related Best Practice** | MASTG-BEST-0007, MASTG-BEST-0029, MASTG-BEST-0047 (Continuous Anti-Debugging Checks) |
| **Related Tests** | **MASTG-TEST-0352** — the static counterpart, a bidirectional relationship (same pattern as TEST-0324/0325) |

---

## 1. Explanation

### 1.1 Testing Objective and Rationale for Its Existence

Quote from the official MASTG overview:

> *"Even if an app references debugging detection APIs, those checks may not execute in security-relevant code paths at runtime. For example, they may only run in debug build variants, fire only once at startup, or be dead code that's never reached. If the app doesn't invoke its debugging detection logic at the right moments, an attacker can attach a debugger without triggering any defensive response."*

This overview's opening directly justifies why this dynamic test **needs to exist separately** from MASTG-TEST-0352 — and specifically confirms three gap scenarios already anticipated in the TEST-0352 document §1.6 (incorrect build variant, a check that only fires once at startup, dead code). A static test can only find **code references**; it cannot prove whether those references are actually **executed** under real, relevant conditions.

### 1.2 Bidirectional Relationship with MASTG-TEST-0352

Just as with the root detection pair (TEST-0324/0325), this test's overview explicitly permits two working orders:

> *"Obtain a list of potential debugging detection mechanisms from static analysis and then focus your dynamic testing on those specific checks to confirm they are triggered at runtime. Alternatively, you can perform dynamic testing first to identify any debugging detection mechanisms that are active at runtime, and then use static analysis to further investigate their implementation and coverage."*

Given the significant coverage gap already discussed in the TEST-0352 document (the official rule never actually scans genuine native binaries), **Path B (dynamic first)** has higher strategic value for this test than for most similar pairs — runtime observation can **find** native mechanisms that static analysis fails to confirm via Semgrep, after which the tester traces back to disassembly to understand the full implementation.

### 1.3 Flexibility of Testing Conditions: Active Debugger vs. Debuggable Build vs. Neither

The overview gives three testing-condition options with varying levels of reliability:

> *"It is recommended to run this test while actively attempting to attach a debugger (or on a debuggable build), to ensure that debugging detection mechanisms are triggered during testing. However, even without attaching a debugger, this test can still surface debugging detection logic if the app runs those checks unconditionally."*

This matters practically — many detection mechanisms (`ApplicationInfo.FLAG_DEBUGGABLE`, timing checks) **run unconditionally** every time the app launches, regardless of whether a genuine debugger is attached. This means hooking can catch calls to this API even **without** the tester actually attempting to attach a debugger — but for mechanisms that are **conditionally** active only when a debugger is actually detected (e.g., a `TracerPid` check whose value is zero unless a process is genuinely performing ptrace), simulating real conditions (attaching a genuine debugger via MASTG-TECH-0031, or using a debuggable build) is necessary to fully trigger that code path.

### 1.4 Two Further Validations That Require Genuinely Simulating an Attack

This test's "Further Validation Required" section is unique in that it explicitly requires the tester to **genuinely perform** the action the app aims to detect (attaching a real debugger), not merely observe passively:

> *"Using the backtraces from the hook output, inspect the code locations... and additionally use MASTG-TECH-0031 to attach a JDWP or native debugger to verify the app's defensive response: Determine whether the checks are called in release builds and not only in debug configurations. Determine whether the app changes its behavior when a debugger is attached (for example, issues a warning, restricts access, or terminates)."*

This distinguishes this test from the usual passive-hooking pattern — full verification requires **two types of instrumentation running simultaneously**: Frida for observing API calls, and a genuine JDWP/native debugger (via MASTG-TECH-0031) to simulate the actual threat scenario the app tries to detect. Observing an API hook alone, without genuinely attempting to attach a debugger, only proves "the API was called," not "the API produces the correct result when a genuine debugger is present."

### 1.5 A Specific Risk: Enabling Debuggable Mode Can Interfere with Other Integrity Checks

MASTG-TECH-0031 gives a practical note relevant to test planning — the option to force an app into debuggable mode (to trigger the testing condition in §1.3) has a side effect:

> *"Hook Android framework checks so the app appears debuggable... This approach requires root and a hooking framework, and apps may detect it... Enable system-wide app debugging by changing system properties... This approach is noisy and easy for apps to detect."*

This creates a potential **confounding factor** similar to what was discussed in the earlier root/emulator detection documents in this research series — if the app also has detection mechanisms against `resetprop`/system modification, the attempt to force debuggable mode itself may trigger a defensive response **unrelated** to the anti-debugging logic being tested, creating ambiguity in interpreting the results.

### 1.6 Expected False Negatives: A Pattern Consistent with Other Resilience Test Families

> *"This test may produce false negatives if the app uses debugging detection techniques that are not covered by the hooks or traces used in this test, or if the debugging detection logic is implemented in a way that evades detection (for example, through obfuscation, dynamic code loading, or anti-instrumentation techniques)."*

This sentence pattern is **structurally identical** to the Expected False Negatives in TEST-0325 (root) and TEST-0351 (emulator) in this research series — reconfirming that the entire "runtime detection technique" test family in MASVS-RESILIENCE uses a consistent methodology template. Anti-instrumentation (detection of Frida itself) remains a relevant confounding factor here — an app that detects Frida before the anti-debugging hook has a chance to observe it running normally can create the mistaken impression of "no debugging detection."

---

## 2. Tools Used for Testing

### 2.1 Required Tools (Core, Per MASTG-TECH)

| Tool | Function |
|---|---|
| **Frida** | Hooking anti-debugging APIs (MASTG-TECH-0043) |
| **strace** | Tracing native-level `ptrace` system calls (MASTG-TECH-0032) |
| **jdb / Android Studio Debugger** | Attaching a genuine JDWP debugger for further verification (MASTG-TECH-0031) |
| **ADB** | App installation, `adb jdwp`/`adb forward` for debugging setup |

### 2.2 Alternative & Supporting Tools

| Tool | Function |
|---|---|
| **Objection** | Quick hooking without custom scripts |
| **lldb-server** | Attaching a native (ptrace-based) debugger to specifically simulate a native-layer debugging scenario |
| **Custom debuggable APK build** | An alternative to attaching a genuine debugger — modifying the manifest's `android:debuggable="true"` then re-signing, to trigger the testing condition without needing root (MASTG-TECH-0038) |

### 2.3 Environment Prerequisites

- A rooted device/emulator with `frida-server`.
- The ability to attach a genuine JDWP/native debugger (via Android Studio or `jdb`) to fulfill the further validation in §1.4 — not merely passive observation.

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0005** to install the application.
2. Use **MASTG-TECH-0043** to hook relevant APIs.
3. Use **MASTG-TECH-0032** to trace relevant system calls.
4. Exercise the app extensively to trigger as many flows as possible.

### 3.2 Method A — Frida: Passive Observation Hooks on Anti-Debugging APIs

```javascript
Java.perform(function () {
    var Debug = Java.use("android.os.Debug");
    Debug.isDebuggerConnected.implementation = function () {
        var result = this.isDebuggerConnected();
        console.log("[Debug.isDebuggerConnected] -> " + result);
        console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));
        return result;
    };

    var ApplicationInfo = Java.use("android.content.pm.ApplicationInfo");
    // Observe reads of the flags field to indirectly detect FLAG_DEBUGGABLE via access logging
});
```

```bash
frida -U -f com.example.targetapp -l hook_antidebug.js --no-pause
```

### 3.3 Method B — strace to Capture Native Checks (TracerPid/ptrace)

```bash
adb shell strace -f -e trace=openat,read -p $(adb shell pidof com.example.targetapp) 2>&1 | grep -i 'proc.*status'
```

### 3.4 Method C — Attaching a Genuine Debugger for Further Verification (Mandatory, Per §1.4)

```bash
# JDWP
adb jdwp
adb forward tcp:7777 jdwp:<pid>
jdb -attach localhost:7777

# Observe: does the app crash/show a warning/restrict a feature immediately after the attach succeeds?
```

```bash
# Native (ptrace-based) — alternative
adb shell
gdbserver :5039 --attach <pid>
```

### 3.5 Method Comparison: When to Use Which

| Method | Tool | When to use |
|---|---|---|
| **A** | Frida passive observation | Mandatory baseline — catching APIs called without altering the outcome |
| **B** | strace | Catching native-level checks not visible from a Java hook |
| **C** | Attaching a genuine debugger | **Mandatory** — the only way to verify a defensive response against a genuine threat condition (§1.4) |

**Minimum recommended combination:** **A + B (observation) → C (mandatory, verifying the genuine response)**.

---

### 3.6 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rule:**

> **Evaluation:** *"The test case fails if no debugging detection API calls are observed during app execution."*

---

#### ❌ FAIL / ISSUE — The check is declared FAILED if:

| No | Condition |
|---|---|
| F1 | Not a single anti-debugging-related API call/syscall trace is observed, **even after** attempting to attach a genuine debugger (§1.3-1.4) |

---

#### ✅ PASS — The check is declared PASSED if:

| No | Condition |
|---|---|
| P1 | At least one anti-debugging API call is observed during exercising/debugger attach |
| P2 | *(Mandatory further validation)* The app is proven to **change behavior** (warning/restriction/termination) when a genuine debugger is actually attached — not merely calling the API with no effect whatsoever |

---

#### ⚠️ Important Notes on Scoring

1. **Observing an API call alone is not sufficient for a full PASS** — per §1.4, mandatory validation requires proof that the app's behavior genuinely changes when a real debugger is attached, not merely that the API is called with no consequence.

2. **Be wary of the confounding factor from forcing debuggable mode** (§1.5) — if results don't match expectations, consider whether this is caused by a different detection mechanism (not anti-debugging) triggered by the `resetprop`/hooking technique used to simulate the debuggable condition.

3. **Correlate with MASTG-TEST-0352 results** — if static analysis finds many candidates but dynamic testing observes none actually called (even after attaching a genuine debugger), the code is likely dead code or locked behind the wrong build variant (exactly the scenario anticipated in overview §1.1).

4. **Severity is modulated as follows:**

   | Factor | Severity |
   |---|---|
   | No detection observed at all even after attaching a genuine debugger, on a sensitive-data application | **High** |
   | API is called but no real behavior change occurs when the debugger is attached (checks exist but are ineffective) | **Medium-High** (worse than simply "no effort at all" — it creates a false sense of security) |
   | API is called and behavior genuinely changes (termination/restriction) when verified | **Not a finding** |

5. **Document:** the API observed being called, the backtrace, the result of attaching a genuine debugger (JDWP and/or native), and the observed behavior change (or lack thereof).

---

## 4. Recommendations

The recommendations are the same as for its static counterpart (MASTG-TEST-0352) — see that document for full details. Additional points specific to dynamic verification results:

### 4.1 Ensure the Defensive Response Genuinely Triggers, Not Just Logging

```java
// WEAK — only logs, no genuine defensive action
if (Debug.isDebuggerConnected()) {
    Log.w(TAG, "Debugger detected");
    // no follow-up action!
}

// BETTER — a genuine defensive action
if (Debug.isDebuggerConnected()) {
    clearSensitiveDataFromMemory();
    finishAffinity();
    System.exit(0);
}
```

### Remediation Checklist

- [ ] Dynamic verification confirms a genuine behavior change, not just an API call with no effect
- [ ] The check is confirmed active in the release build by attaching a debugger directly to the production APK
- [ ] Results are correlated with MASTG-TEST-0352 for a complete picture of static vs. dynamic coverage

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0353 (source, tests-beta)](https://github.com/OWASP/mastg/blob/master/tests-beta/android/MASVS-RESILIENCE/MASTG-TEST-0353.md)
- [MASTG-TEST-0352: References to Debugging Detection APIs (the static counterpart document in this research series)](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0352/)
- [MASTG-KNOW-0028: Anti-Debugging](https://mas.owasp.org/MASTG/knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0028/)
- [MASTG-BEST-0047: Continuous Anti-Debugging Checks](https://github.com/OWASP/mastg/blob/master/best-practices/MASTG-BEST-0047.md)
- [MASTG-TECH-0031: Debugging](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0031/)

### 5.2 Tool Documentation

- [Frida — Dynamic Instrumentation Toolkit](https://frida.re/docs/home/)
- [Objection — Runtime Mobile Exploration](https://github.com/sensepost/objection)
- [Android Studio Debugger Documentation](https://developer.android.com/studio/debug)

---

*This document was prepared based on official OWASP MASTG content (`tests-beta/android/MASVS-RESILIENCE/MASTG-TEST-0353.md`, `MASTG-KNOW-0028`, `MASTG-TECH-0031`), supplemented with an in-depth cross-reference to the MASTG-TEST-0352 document (its static counterpart) in this research series, which already discussed the official rule's coverage gap regarding native code. The most important methodological nuance: this test's further validation explicitly requires the tester to genuinely attach a real debugger (JDWP/native) to verify the actual defensive response — merely observing an API being called via passive hooking is not enough for a full PASS, since an API that is called with no behavioral effect whatsoever actually creates a false sense of security that is more dangerous than having no mechanism at all.*
