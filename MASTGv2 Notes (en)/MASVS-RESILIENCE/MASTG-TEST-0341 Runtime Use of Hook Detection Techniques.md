# MASTG-TEST-0341 Runtime Use of Hook Detection Techniques

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0341 |
| **Platform** | Android |
| **MASVS Category** | MASVS-RESILIENCE |
| **Weakness** | MASWE-0058 |
| **Test Type** | Dynamic, Hooks |
| **Related Techniques** | MASTG-TECH-0005 (Installing Apps), MASTG-TECH-0043 (Method Hooking) |
| **Related Knowledge** | MASTG-KNOW-0030 (Reverse Engineering Tool Detection), MASTG-KNOW-0032 (Runtime Integrity Verification), MASTG-KNOW-0118 |
| **Related Best Practice** | MASTG-BEST-0041 (Hardening Against Runtime Hooking) |
| **Related Tests** | MASTG-TEST-0324/0325 (root detection) — complementary preventive controls, though hooking can still succeed on non-rooted devices (§1.5) |
| **Official Rule** | — (none; a purely dynamic test, consistent with the nature of other tests that target runtime response rather than static code patterns) |

---

## 1. Explanation

### 1.1 Testing Objective

Quote from the official MASTG overview:

> *"This test verifies whether the app detects and responds to instrumentation and hooking attempts at runtime."*

This test is the heart of the MASVS-RESILIENCE category — it does not target one specific code vulnerability, but rather tests whether the application's **last line of defense** functions: when an attacker/tester succeeds in hooking a sensitive function (via Frida, Xposed, etc.), does the application **become aware** of it and **respond** defensively, or does it keep running normally as if nothing happened.

### 1.2 Seven Categories of Sensitive Functions Targeted by Hooks and Their Impact

The overview gives a concrete list of APIs that, if successfully hooked undetected, open the door to exfiltration of highly sensitive data:

| Hooked API | Exposed Data |
|---|---|
| `AccountManager.getPassword()` / `getAuthToken()` | OAuth tokens, session credentials, stored account passwords |
| `KeyStore.getKey()` / `getCertificate()` | Cryptographic keys and certificates |
| `Cipher.doFinal()` | Session/ephemeral keys currently being processed |
| `SQLiteDatabase.rawQuery()` / `query()` / `execSQL()` | Contents of the local database |
| `EncryptedSharedPreferences` APIs | Data that should be encrypted |
| `KeyGenParameterSpec.Builder.setUserAuthenticationRequired()` | Authentication bypass — directly connected to the risk discussed in TEST-0327 |

An important note the overview gives explicitly: *"This list is just indicative, and each app may have its own defensive response mechanisms."* — this list is not a closed list; any sensitive API specific to the target app's business logic deserves to be treated as an additional test point.

### 1.3 A Unique Evaluation Mechanism: The Test Result Is Measured by Hook Failure, Not Success

This is one of the tests with the most unusual evaluation logic in this entire research series — instead of the tester trying to **confirm** that something works, the tester here actively **tries to attack** the app, and **the failure of that attack** is the PASS signal:

> **Evaluation:** *"The test case fails if the hook executes successfully and returns the expected data, indicating the app lacks runtime integrity verification. The test case passes if the hooking attempt fails due to the app's defensive response (e.g., session terminates unexpectedly, hook callbacks never execute, or the process exits)."*

This flips the common intuition that "an error result = a bug" — in the context of this test, **a crash/exit deliberately triggered by the app's own defense mechanism is actually the desired outcome**. The tester needs to clearly distinguish between two kinds of "hook failure": (a) failure caused by **a bug in the tester's own Frida script**, versus (b) failure caused by **a defensive response deliberately triggered by the app**. The official Observation note helps distinguish these by requiring detailed logging of failure signals — specific error messages, the timing of occurrence relative to the hook call, and consistency of behavior across repeated attempts.

### 1.4 An Honest Admission: A PASS Today Is Not a Permanent Guarantee

The official closing note gives an important warning about interpreting a PASS result:

> *"Even if the test case passes, it might still be possible to bypass the app's defensive response."*

This is consistent with a principle reaffirmed repeatedly in MASTG-KNOW-0032:

> *"Runtime integrity verification is inherently a cat-and-mouse game. Detection methods and bypass defensive controls evolve continuously. Determined attackers with sufficient time and resources can typically circumvent these protections, especially on rooted devices."*

Practical implication: the report for this test's result **must not** state "the app is permanently resistant to hooking" — it can only state "the defense mechanism successfully defeated the specific hooking technique tested, on the given test date, with the given tool version."

### 1.5 Two Complementary Detection Categories, Not Mutually Substitutable

MASTG-KNOW-0030 and MASTG-KNOW-0032 explicitly distinguish two fundamentally different approaches:

> *"Some tools can be detected both by their artifacts and by the modifications they make to the runtime. [MASTG-KNOW-0030] focuses on identifying the presence of known tools, while MASTG-KNOW-0032 focuses on identifying unauthorized runtime modification."*

| Category | What Is Detected | Example Technique | Main Weakness |
|---|---|---|---|
| **Artifact-based** (KNOW-0030) | Presence of tools (process, file, port, string) | Checking `/proc/self/maps` for `frida-agent`, checking the APK signing certificate | Fragile — file/process names are easily renamed by an attacker |
| **Integrity-based** (KNOW-0032) | Modifications a tool causes to memory/code | Verification of PLT/GOT, vtable, ART method entry point | Stronger, but complex to implement and specific to the Android version |

MASTG-BEST-0041 asserts that **both must be combined**: *"Do not rely on only one approach, as each has blind spots the other covers."* This is directly relevant to test design: the tester should try **both types** of hooking techniques (direct via default Frida vs. via embedded/hidden Frida Gadget) to thoroughly assess the app's defense coverage, not just one scenario.

### 1.6 An Important Nuance: Hooking Does Not Require Root — The Threat Also Applies on Non-Rooted Devices

A crucial point from MASTG-BEST-0041 relevant to the overall threat context:

> *"Because hooking can also occur on non-rooted devices (e.g., by repackaging the app with an embedded frida-gadget), do not rely solely on preventive controls."*

This means **root detection (TEST-0324/0325) is not sufficient** as the sole line of defense against hooking — an attacker can extract the APK, inject `libfrida-gadget.so`, re-sign the APK, and then install it on any non-rooted device, completely bypassing the need for root. This is why MASTG-BEST-0041 groups controls into four categories (preventive, detective, deterrent, responsive) instead of relying solely on preventive controls (root detection) alone.

### 1.7 A Sophisticated Deterrent Technique: Inlining and Randomizing Check Placement

Two defensive techniques rarely discussed in other tests but covered in depth in MASTG-BEST-0041 deserve to be noted as a high-quality evaluation standard:

> *"A named function has a fixed entry point that hooking frameworks can intercept with a single hook. When detection logic is inlined directly into the surrounding application code, there is no entry point to target — the check becomes an inseparable part of the surrounding control flow."*

> *"Randomize check placement at build time forces attackers to do fresh analysis for every release, significantly increasing the cost of maintaining automated bypass tools."*

Both techniques explain why some applications remain resistant for a long time to generic bypasses published by the community — without a function entry point that can be hooked once for all cases, and with placement that changes with every release, a bypass script that works on version N no longer automatically works on version N+1.

---

## 2. Tools Used for Testing

### 2.1 Required Tools (Core)

| Tool | Function |
|---|---|
| **Frida** | Hooking the seven sensitive APIs (MASTG-TECH-0043) to trigger and observe the app's defensive response |
| **ADB** | App installation (MASTG-TECH-0005) |

### 2.2 Alternative & Supporting Tools

| Tool | Function |
|---|---|
| **Frida Gadget + apktool** | Replicating the **non-rooted** hooking scenario (§1.6) — injecting `libfrida-gadget.so` into the APK, re-signing it, installing on a regular device |
| **Objection** | Quick hooking without custom scripts for initial exploration of which APIs are protected |
| **Xposed/LSPosed** | Testing resistance against a hooking framework category different from Frida, complementing the coverage of instrumentation types tested |
| **strace** | Observing process behavior at the system level to confirm the type of defensive response (forced exit, SIGKILL, etc.) |

### 2.3 Environment Prerequisites

- A rooted device/emulator with `frida-server` for the standard hooking scenario.
- An additional non-rooted device for the embedded Frida Gadget scenario (§1.6) — providing the test coverage that MASTG-BEST-0041 explicitly emphasizes as important.

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0005** to install the application.
2. Use **MASTG-TECH-0043** to hook the relevant APIs.
3. Exercise the app extensively to trigger as many flows as possible, entering sensitive data wherever possible.

### 3.2 Method A — Frida: Hook the Seven Official API Categories

```javascript
Java.perform(function () {
    var AccountManager = Java.use("android.accounts.AccountManager");
    AccountManager.getPassword.implementation = function (account) {
        console.log("[HOOK TEST] AccountManager.getPassword() called, hook SUCCEEDED");
        return this.getPassword(account);
    };

    var KeyStore = Java.use("java.security.KeyStore");
    KeyStore.getKey.implementation = function (alias, password) {
        console.log("[HOOK TEST] KeyStore.getKey() called, hook SUCCEEDED");
        return this.getKey(alias, password);
    };

    var Cipher = Java.use("javax.crypto.Cipher");
    Cipher.doFinal.overload().implementation = function () {
        console.log("[HOOK TEST] Cipher.doFinal() called, hook SUCCEEDED");
        return this.doFinal();
    };
});
```

```bash
frida -U -f com.example.targetapp -l hook_test.js --no-pause
```

Observe: does the message "[HOOK TEST]... hook SUCCEEDED" appear in the console (indicating FAIL), or does the session stop/app exit before the hook has a chance to trigger (indicating PASS)?

### 3.3 Method B — Replicating the Non-Rooted Scenario with Frida Gadget

```bash
# Extract the APK, inject libfrida-gadget.so
apktool d target.apk -o target_decoded
cp libfrida-gadget-arm64.so target_decoded/lib/arm64-v8a/
# add System.loadLibrary("frida-gadget") at the smali entry point
apktool b target_decoded -o target_patched.apk
apksigner sign --ks debug.keystore target_patched.apk

# Install on a NON-ROOTED device
adb install target_patched.apk
```

Run the application and observe whether the defense mechanism still triggers even though the device is not rooted — in line with the emphasis in §1.6 that preventive controls (root detection) alone are not sufficient.

### 3.4 Method C — Objection for Quick Exploration

```bash
objection -g com.example.targetapp explore
# inside the REPL, try watching various sensitive methods
android hooking watch class_method android.accounts.AccountManager.getPassword --dump-args
```

### 3.5 Method D — strace to Confirm the Type of Defensive Response

```bash
adb shell strace -f -p $(adb shell pidof com.example.targetapp) 2>&1 | grep -E 'exit_group|SIGKILL'
```

Distinguishes whether the "hook failure" is truly caused by the app forcing an exit itself, or merely the tester's Frida script failing to connect (an important confounding factor, §1.3).

### 3.6 Method Comparison: When to Use Which

| Method | Tool | When to use |
|---|---|---|
| **A** | Standard Frida | Mandatory baseline — testing the seven official API categories on a rooted device |
| **B** | Embedded Frida Gadget | Mandatory for thorough coverage — testing the non-rooted scenario (§1.6) |
| **C** | Objection | Quick exploration before writing a custom script |
| **D** | strace | Confirming that the failure type is a genuine defensive response, not a tester script error |

**Minimum recommended combination:** **A (mandatory, rooted device) + B (mandatory, non-rooted device)** — testing only one of these two scenarios gives an incomplete picture, given MASTG-BEST-0041's explicit emphasis that both are distinct threats.

---

### 3.7 Evaluation Criteria: Positive Case & Negative Case

---

#### ❌ FAIL / ISSUE — The check is declared FAILED if:

| No | Condition |
|---|---|
| F1 | A hook on a sensitive API **executes successfully** and returns the expected data (callback data, arguments, return value) undisturbed |

**Example evidence:**

```
[HOOK TEST] AccountManager.getPassword() called, hook SUCCEEDED
Return value: "s3cr3tP@ssw0rd"
```

Interpretation: the hook on `getPassword()` runs perfectly, the account password is successfully extracted without any defensive response from the app whatsoever. **FAIL**.

---

#### ✅ PASS — The check is declared PASSED if:

| No | Condition |
|---|---|
| P1 | The app's session/process stops unexpectedly immediately after the hook is installed/triggered |
| P2 | The hook callback never executes at all |
| P3 | The app exits as a direct response to the hooking attempt |

**Example evidence:**

```
$ frida -U -f com.example.targetapp -l hook_test.js --no-pause
[*] Spawned `com.example.targetapp`
Process terminated
```

**PASS** — but **must** be given the caveat per §1.4 (not permanent, other techniques may still succeed).

---

#### ⚠️ Important Notes on Scoring

1. **Carefully distinguish between a genuine defensive response vs. an error in the tester's own script** — before concluding PASS, re-verify that the Frida script works normally against a control app (e.g., a sample app with no protection) to confirm that the failure genuinely originates from the target's defense mechanism, not a bug in the tester's own tooling.

2. **Always test both the rooted and non-rooted scenarios (§1.6)** — a PASS tested only on a rooted device (standard hooking) provides no information about resilience against the embedded Frida Gadget scenario, which requires no root at all.

3. **PASS is never permanent** — always include the test date, app version, Frida/tool version used, and an explicit statement that this result may change with more sophisticated bypass techniques in the future (§1.4).

4. **Also assess the quality of the response, not just its presence** — per MASTG-BEST-0041, a response that occurs **only** at a single centralized point is easier to bypass (found once, neutralized once) compared to a response spread across many points and repeated before every sensitive operation (§1.7); where possible, test whether bypassing one check instance is enough to get through the entire flow, or whether repeated checks at other points still block it.

5. **Severity is modulated as follows:**

   | Factor | Severity |
   |---|---|
   | A hook on a credential/cryptographic key API succeeds with no response whatsoever | **High** |
   | A defensive response exists but only at a single centralized point (easily bypassed once found) | **Medium** |
   | Defensive response is distributed, proven resilient in both rooted and non-rooted scenarios | **Not a finding** (with the caveat per §1.4) |

6. **Document:** the APIs tested, the result of each hooking attempt (success/failure with failure signal details), the device scenario (rooted/non-rooted), and the tool version used, for report reproducibility.

---

## 4. Recommendations

### 4.1 Implement Layered Detection (Artifact + Integrity-Based)

Do not rely on only one type of detection — combine artifact checks (`/proc/self/maps` for the string `frida`) with runtime integrity verification (PLT/GOT, ART entry point) per MASTG-BEST-0041.

### 4.2 Implement Detection Logic in Native Code, Inline, and with Randomized Position

```cpp
// Native C/C++, inlined at every call site, NOT a separate function that could be hooked once
__attribute__((always_inline)) static inline bool quickIntegrityCheck() {
    // lightweight PLT/GOT verification performed directly in place
}
```

### 4.3 Layered and Distributed Response

Repeat the check before every sensitive operation (fund transfer, premium feature unlock), not only once at startup — per the "Repeat Checks Before Sensitive Operations" principle in MASTG-BEST-0041.

### 4.4 Remediation Checklist

- [ ] All seven categories of sensitive APIs have a hooking-detection mechanism that is proven resilient
- [ ] Detection combines BOTH artifact-based AND integrity-based approaches
- [ ] Detection logic is implemented in native code, inline, not as a separate function
- [ ] Checks are repeated at many points before sensitive operations, not centralized in one place
- [ ] Proven resilient in BOTH ROOTED AND NON-ROOTED scenarios (embedded Frida Gadget)
- [ ] The response includes session termination, clearing of sensitive data from memory, and notification to the backend

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0341 (source, tests-beta)](https://github.com/OWASP/mastg/blob/master/tests-beta/android/MASVS-RESILIENCE/MASTG-TEST-0341.md)
- [MASTG-KNOW-0030: Reverse Engineering Tool Detection](https://mas.owasp.org/MASTG/knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0030/)
- [MASTG-KNOW-0032: Runtime Integrity Verification](https://mas.owasp.org/MASTG/knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0032/)
- [MASTG-BEST-0041: Hardening Against Runtime Hooking](https://github.com/OWASP/mastg/blob/master/best-practices/MASTG-BEST-0041.md)
- [MASTG-TEST-0324/0325: Root Detection (related document in this research series)](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0324/)

### 5.2 Technical Research and References

- [Bernhard Mueller: The Jiu-Jitsu of Detecting Frida](https://web.archive.org/web/20181227120751/http://www.vantagepoint.sg/blog/90-the-jiu-jitsu-of-detecting-frida)
- [Tan, 2016 — Black Hat: Attacking BYOD Enterprise Mobile Security Solutions](https://www.blackhat.com/docs/us-16/materials/us-16-Tan-Bad-For-Enterprise-Attacking-BYOD-Enterprise-Mobile-Security-Solutions-wp.pdf)
- [Clang Control Flow Integrity Documentation](https://clang.llvm.org/docs/ControlFlowIntegrity.html)

### 5.3 Tool Documentation

- [Frida — Dynamic Instrumentation Toolkit](https://frida.re/docs/home/)
- [Frida Gadget Documentation](https://www.frida.re/docs/gadget/)
- [Objection — Runtime Mobile Exploration](https://github.com/sensepost/objection)
- [xHook — Android PLT Hook Library](https://github.com/iqiyi/xHook)

---

*This document was prepared based on official OWASP MASTG content (`tests-beta/android/MASVS-RESILIENCE/MASTG-TEST-0341.md`, `MASTG-KNOW-0030`, `MASTG-KNOW-0032`, `MASTG-BEST-0041`), which provides one of the most in-depth technical discussions in this entire research series regarding runtime defense mechanisms (PLT/GOT hook detection, vtable hook detection, ART entry point verification). The most important methodological nuance: this is a test with inverted evaluation logic — the failure of the tester's own hooking attempt (not its success) is the PASS signal, and a PASS result must always be accompanied by the caveat that it is not a permanent guarantee (an ever-evolving cat-and-mouse game). Hooking also does not require root access (via embedded Frida Gadget), so testing conducted only on a rooted device provides incomplete coverage of the real threat.*
