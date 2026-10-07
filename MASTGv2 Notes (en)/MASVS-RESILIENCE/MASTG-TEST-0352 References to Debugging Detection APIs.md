# MASTG-TEST-0352 References to Debugging Detection APIs

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0352 |
| **Platform** | Android |
| **MASVS Category** | MASVS-RESILIENCE |
| **Weakness** | MASWE-0064 |
| **Test Type** | Static, Code, **Manual** |
| **Related Techniques** | MASTG-TECH-0013, MASTG-TECH-0014, MASTG-TECH-0157 (Extracting Bundled Native Libraries), MASTG-TECH-0018 (Disassembling Native Code), MASTG-TECH-0023 |
| **Related Knowledge** | MASTG-KNOW-0007 (Debuggable Apps), MASTG-KNOW-0028 (Anti-Debugging) |
| **Related Best Practice** | MASTG-BEST-0007, MASTG-BEST-0029, MASTG-BEST-0047 (Continuous Anti-Debugging Checks) |
| **Related Tests** | **MASTG-TEST-0353** — the dynamic counterpart that confirms the mechanism is active at runtime |
| **Official Rule** | Three rules: `mastg-android-debugger-checks.yml`, `mastg-android-native-debugger-checks.yml`, `mastg-android-debuggable-flag.yml` — a **significant coverage gap** regarding native code was found, see §1.4 |

---

## 1. Explanation

### 1.1 Testing Objective

Quote from the official MASTG overview:

> *"Apps can implement debugging detection at the Java/Kotlin level using APIs such as `Debug.isDebuggerConnected()`, or at the native level using mechanisms such as `ptrace` calls, `TracerPid` checks in `/proc/self/status`, or inlined syscalls. If these checks are absent or not applied in security-relevant code paths, an attacker can attach a debugger undetected and use it to inspect or modify runtime state, extract sensitive data, or bypass security controls."*

### 1.2 Two Debugging Protocols That Must Both Be Accounted For

MASTG-KNOW-0028 explains an important architectural distinction:

> *"We have to deal with two debugging protocols on Android: we can debug on the Java level with JDWP or on the native layer via a ptrace-based debugger. A good anti-debugging scheme should defend against both types of debugging."*

| Protocol | Target | Typical Detection Technique |
|---|---|---|
| **JDWP** (Java Debug Wire Protocol) | Java/Kotlin code, via a debug thread started when `android:debuggable="true"` | `ApplicationInfo.FLAG_DEBUGGABLE`, `Debug.isDebuggerConnected()`, timing check (`Debug.threadCpuTimeNanos()`) |
| **ptrace-based debugger** | Native code (C/C++) | Checking `TracerPid` in `/proc/self/status`, detecting `ptrace(PTRACE_ATTACH)` already used by another process (self-attach trick) |

A key principle asserted by MASTG-KNOW-0028: *"The 'more-is-better' rule applies: to maximize effectiveness, defenders combine multiple methods of prevention and detection that operate on different API layers."* — a mechanism that targets only one protocol (e.g., JDWP alone) leaves a large gap for an attacker who switches to pure native debugging.

### 1.3 The Timing Check Technique: An Unusual Approach Worth Knowing

One technique from MASTG-KNOW-0028, rarely discussed in other tests in this research series, deserves highlighting for its fairly unusual approach — rather than checking an API/flag, it **measures execution-time anomalies**:

> *"Debug.threadCpuTimeNanos indicates the amount of time that the current thread has been executing code. Because debugging slows down process execution, you can use the difference in execution time to guess whether a debugger is attached."*

This technique is relevant to include in the manual search (§3.3) because it is **not covered by any official rule** (§1.4) — searching for it requires recognizing a code pattern that measures the time difference before/after a simple loop, rather than just a single API name that's easy to search for.

### 1.4 Critical Analytical Finding: The Official Rule Is Java-Only and Never Actually Scans Native Binaries

This is the most significant finding from the rule analysis for this test. Note the `languages` metadata on a rule whose **name itself references "native"**:

```yaml
- id: mastg-android-native-debugger-checks
  languages: [java]  # <-- notice this
  metadata:
    summary: Detects Java references to native anti-debugging checks based on TracerPid and ptrace-related indicators.
  patterns:
    - pattern-either:
        - pattern: '"/proc/self/status"'
        - pattern: '"TracerPid:"'
        - pattern-regex: PTRACE_(ATTACH|SEIZE)
```

This rule is **Java-only** — it searches for the string literals `"/proc/self/status"`/`"TracerPid:"` or the regex pattern `PTRACE_ATTACH`/`PTRACE_SEIZE` **inside Java/Kotlin code**, not inside the native binary file (`.so`) itself. This means the rule will only catch cases where Java code **references that string directly** (e.g., calling `new File("/proc/self/status")` directly from Java) — but it will **completely fail to detect** an anti-debugging implementation written **purely in native C/C++ code** compiled into a `.so` and called via JNI without any string-level bridge on the Java side.

This gap is highly significant because **this test's own official steps** (§ Steps items 3-4) explicitly require:

> *"Use MASTG-TECH-0157 to extract the native libraries from the app package. Use MASTG-TECH-0018 to look for native debugging detection patterns in the extracted libraries, such as calls to ptrace, reads of /proc/self/status, or checks for the TracerPid field."*

In other words, **MASTG itself requires direct analysis of the native binary** (via a disassembler, not Semgrep against Java source), yet **provides no automated rule** for this task — there is no C/Assembly-language rule in the official catalog for scanning direct `ptrace()` calls in `.so` disassembly. This is consistent with a general limitation of Semgrep as a source-code pattern-matching tool — it is not designed to analyze compiled native ELF binaries. The tester **must** perform manual disassembly (via Ghidra/IDA/radare2) to genuinely fulfill official steps 3-4, since no automated shortcut is available.

### 1.5 Real-World Context: Bypass Techniques Already Highly Mature in the Community

Community research shows that the bypass ecosystem for this vulnerability class is already very mature, including techniques specifically targeting the two debugging protocols mentioned in §1.2:

> *"Frida spawn mode can bypass dual process (ptrace) detection, /proc status checks, and detection of special task names like 'gum-js-loop', 'gmain', 'gdbus', or 'pool-frida'."*
>
> *"Anti-debugging methods can be bypassed by using the LD_PRELOAD environment variable, which allows control over the loading path of a shared library."*

The **LD_PRELOAD** technique is particularly relevant here — it allows an attacker to inject a custom shared library that **intercepts low-level syscalls before they reach the original implementation**, effectively neutralizing `ptrace`/`TracerPid` checks without needing to modify the application's binary at all. This reinforces the defense-in-depth principle of MASTG-BEST-0047 — a single layer of checking, however sophisticated, can still be neutralized by system-level injection techniques that are already widely known in the reverse-engineering community.

### 1.6 Further Validation Structure: Two Key Questions That Distinguish Quality Findings

The "Further Validation Required" section demands two specific checks that **cannot be automated**:

> *"Determine whether the check is called in release builds and not only in debug configurations. Determine whether the app takes a security-relevant action when a debugger is detected (for example, process termination or feature restriction)."*

The first point is very important and easy to miss — developers sometimes write an anti-debugging check but **only enable it in certain build variants** (e.g., wrapped in an `if (BuildConfig.DEBUG)` with inverted/incorrect logic, or deliberately disabled in CI build configs to ease internal testing and forgotten to be re-enabled for production releases). The presence of anti-debugging code in the source **does not automatically mean that code is active in the APK released to users**.

---

## 2. Tools Used for Testing

### 2.1 Required Tools (Core)

| Tool | Function |
|---|---|
| **jadx** | Decompiling DEX → Java (MASTG-TECH-0013) |
| **Semgrep** + three official rules | Detecting Java-level patterns and native string references (limited coverage, §1.4) |
| **Ghidra / IDA Pro / radare2** | **Mandatory** for directly scanning `ptrace()` calls in `.so` binary disassembly (MASTG-TECH-0018) — the only way to adequately fulfill official steps 3-4 |

### 2.2 Alternative & Supporting Tools

| Tool | Function |
|---|---|
| **grep/ripgrep** | Searching for timing-check patterns (`threadCpuTimeNanos`) and string variations the official rule might miss |
| **unzip/apktool** | Extracting the `lib/` directory to obtain `.so` files (MASTG-TECH-0157) |
| **MobSF** | Automated reports that sometimes include basic anti-debugging detection |

### 2.3 Environment Prerequisites

- No device/root required for static analysis.
- **Basic ARM/x86 disassembly-reading ability is strongly recommended** given the limitations of automated rules against native code (§1.4).

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0013** to reverse engineer the application.
2. Use **MASTG-TECH-0014** to search for relevant Java/Kotlin APIs.
3. Use **MASTG-TECH-0157** to extract native libraries.
4. Use **MASTG-TECH-0018** to search for native debugging detection patterns in the extracted library.

### 3.2 Method A — Semgrep with the Three Official Rules (Limited Native Coverage)

```bash
semgrep --config mastg-android-debugger-checks.yml \
        --config mastg-android-native-debugger-checks.yml \
        --config mastg-android-debuggable-flag.yml \
        ./decompiled/sources ./AndroidManifest.xml
```

**Mandatory note:** the result from the second rule only catches string references in Java, **not** actual `ptrace` calls in the native binary (§1.4). Proceed to Method B to fully satisfy the official steps.

### 3.3 Method B — grep/ripgrep for Timing Checks and Additional Variations

```bash
D=./decompiled/sources
rg -n 'threadCpuTimeNanos' $D
rg -n 'FLAG_DEBUGGABLE|isDebuggerConnected' $D
```

### 3.4 Method C — Manual Disassembly of the Native Binary (Mandatory for Official Steps 3-4)

```bash
# Extract native libraries
unzip -o target.apk "lib/*" -d extracted_libs

# Search for related string literals in the binary (quick triage before full disassembly)
strings extracted_libs/lib/arm64-v8a/libnative-lib.so | grep -E 'TracerPid|proc/self/status'

# Disassemble to look for actual ptrace() calls
objdump -d extracted_libs/lib/arm64-v8a/libnative-lib.so | grep -A5 'bl.*ptrace'
```

Or use Ghidra/radare2 for deeper function analysis, tracing the call graph to the imported `ptrace` symbol.

### 3.5 Method Comparison: When to Use Which

| Method | Tool | When to use |
|---|---|---|
| **A** | Semgrep + 3 official rules | Initial triage for the Java side, native coverage very limited |
| **B** | grep/ripgrep | Closing the gap for timing checks and string variations |
| **C** | Manual disassembly (mandatory) | **The only way** to fulfill official steps 3-4 for genuine native code |

**Minimum recommended combination:** **A + B (Java side) → C (mandatory for native side)**, then proceed to **MASTG-TEST-0353** for runtime confirmation.

---

### 3.6 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rule:**

> **Evaluation:** *"The test case fails if the app contains no debugging detection patterns in either its Java/Kotlin code or its native libraries."*

---

#### ❌ FAIL / ISSUE — The check is declared FAILED if:

| No | Condition |
|---|---|
| F1 | **No** debugging detection pattern is found either on the Java/Kotlin side **or** after manual disassembly of native libraries |

---

#### ✅ PASS — The check is declared PASSED if:

| No | Condition |
|---|---|
| P1 | At least one detection pattern is found on the Java **or** native side, **and** |
| P2 | That check is confirmed active in the release build (not only in a debug config), **and** |
| P3 | There is a clear security action when a debugger is detected (termination, feature restriction) — per §1.6 |

---

#### ⚠️ Important Notes on Scoring

1. **Do not conclude FAIL based solely on Semgrep results** — per §1.4, the official rule never actually scans the native binary; a final FAIL is only valid after manual disassembly (Method C) also finds nothing.

2. **Verify the build variant** — the presence of code in the source does not guarantee it is active in the production release (§1.6); check the build configuration (ProGuard/R8 rules, flavor-specific source sets) to confirm the check is not stripped or disabled in the release build.

3. **Always combine with MASTG-TEST-0353** — this test is purely about presence at the code level; the actual effectiveness (including resilience against LD_PRELOAD/Frida spawn mode techniques in §1.5) can only be assessed through dynamic testing.

4. **Severity is modulated as follows:**

   | Factor | Severity |
   |---|---|
   | No debugging detection at all (confirmed for both Java and native via disassembly) on an app handling highly sensitive data | **High** |
   | Detection only targets one protocol (JDWP only, no native) | **Medium** |
   | Layered detection across both protocols, active in the release build, with a clear security action | **Not a finding** |

5. **Document:** the Java code location, native disassembly results (the function that calls `ptrace`, if any), the build variant verified, and a follow-up recommendation toward MASTG-TEST-0353.

---

## 4. Recommendations

### 4.1 Combine JDWP and Native Detection (Per MASTG-KNOW-0028)

```java
public static boolean isUnderAttack() {
    boolean jdwpFlag = (context.getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0;
    boolean jdwpConnected = Debug.isDebuggerConnected();
    boolean nativeDebug = nativeCheckTracerPid(); // JNI call to native implementation
    return jdwpFlag || jdwpConnected || nativeDebug;
}
```

### 4.2 Apply Repeated Checkpoints, Not Just Once at Startup (Per MASTG-BEST-0047)

```java
// Call again before every sensitive operation, not only onCreate()
fun approvePayment() {
    if (AntiDebug.isUnderAttack()) { terminateSession(); return }
    // proceed with the transaction
}
```

### 4.3 Remediation Checklist

- [ ] Detection covers both protocols: JDWP (Java) and ptrace-based (native)
- [ ] The check is confirmed active in the release build via verification of the production APK, not just source code
- [ ] The check is repeated at checkpoints before sensitive operations, not only once at startup
- [ ] A clear security action (termination/feature restriction) is in place when a debugger is detected
- [ ] Results are confirmed via MASTG-TEST-0353 to verify runtime effectiveness

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0352 (source, tests-beta)](https://github.com/OWASP/mastg/blob/master/tests-beta/android/MASVS-RESILIENCE/MASTG-TEST-0352.md)
- [MASTG-TEST-0353: Runtime Use of Debugging Detection Techniques](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0353/)
- [MASTG-KNOW-0028: Anti-Debugging](https://mas.owasp.org/MASTG/knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0028/)
- [MASTG-BEST-0047: Continuous Anti-Debugging Checks](https://github.com/OWASP/mastg/blob/master/best-practices/MASTG-BEST-0047.md)
- [MASTG-TECH-0018: Disassembling Native Code](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0018/)
- [MASTG-TECH-0157: Extracting Bundled Native Libraries](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0157/)

### 5.2 Technical Research and References

- [Guided Hacking: Tutorial Bypass Ptrace Anti-Debugger in Android](https://guidedhacking.com/threads/bypass-ptrace-anti-debugger-in-android.17099/)
- [Recursively: Android Anti-debugging Tricks — Part 1](https://recursively.review/2021/04/25/Android-Anti-debugging-Tricks-Part-1/)

### 5.3 Tool Documentation

- [Semgrep Documentation](https://semgrep.dev/docs/)
- [Ghidra — NSA Reverse Engineering Framework](https://ghidra-sre.org/)
- [radare2](https://rada.re/n/)

---

*This document was prepared based on official OWASP MASTG content (`tests-beta/android/MASVS-RESILIENCE/MASTG-TEST-0352.md`, `MASTG-KNOW-0028`), analysis of the three official rules, and community research on already-mature anti-debugging bypass techniques (Frida spawn mode, LD_PRELOAD injection). The most important methodological nuance: the rule `mastg-android-native-debugger-checks.yml`, despite its name referencing "native," is technically **Java-only** (`languages: [java]`) and never actually scans genuine `.so` binaries — while this test's own official steps (items 3-4) explicitly require extracting and analyzing the disassembly of native libraries. This means there is no automated shortcut to fully satisfy the official test steps; manual disassembly (Ghidra/radare2) of the native binary is mandatory, not optional, even though it is technically beyond the capability of source-code pattern-matching tools like Semgrep.*
