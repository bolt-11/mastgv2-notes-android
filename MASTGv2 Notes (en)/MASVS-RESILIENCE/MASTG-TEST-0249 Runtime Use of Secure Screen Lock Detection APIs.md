# MASTG-TEST-0249 Runtime Use of Secure Screen Lock Detection APIs

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0249 |
| **Platform** | Android |
| **Official test location** | MASVS-RESILIENCE folder (same as MASTG-TEST-0247 — and inherits the same MASVS category ambiguity, see the MASTG-TEST-0247 document §1.1) |
| **Weakness** | MASWE-0017 — *Device Secure Lock Not Enforced* |
| **Highlighted APIs** | `KeyguardManager.isDeviceSecure()`, `BiometricManager#canAuthenticate()` |
| **Test Type** | **Dynamic, Hooks** |
| **Profile** | **L2 only** |
| **Knowledge** | MASTG-KNOW-0001 *(this reference is problematic — see the note in the MASTG-TEST-0247 document §1.6)* |
| **Related Techniques** | MASTG-TECH-0005 (Install App), MASTG-TECH-0043 (Method Hooking) |
| **Related Test** | **MASTG-TEST-0247** (References to APIs for Detecting Secure Screen Lock — the static counterpart; the official overview of this test explicitly states *"This test is the dynamic counterpart to MASTG-TEST-0247"*) |
| **Related Demo** | — (none) |
| **Official Rule** | — (not applicable; dynamic test based on hooking) |
| **Related CWE** | CWE-287 (Improper Authentication), CWE-862 (Missing Authorization) |

---

## 1. Explanation

### 1.1 Testing Objective and Its Relationship to MASTG-TEST-0247

The official MASTG overview for this test is very brief and states its position directly:

> *"This test is the dynamic counterpart to MASTG-TEST-0247. In this case, we'll look for uses of `KeyguardManager.isDeviceSecure` and `BiometricManager.canAuthenticate` APIs."*

The entire conceptual context — why detecting a secure lock screen matters (its connection to `KeyGenParameterSpec.setUserAuthenticationRequired(true)` on the Android Keystore), the limitation that an application cannot force the user to enable a lock screen at the system level, and the reason `BiometricManager#canAuthenticate()` becomes a fallback path when `KeyguardManager` is restricted on certain vendors — **has already been discussed in depth in the MASTG-TEST-0247 document** and fully applies to this test. This document will focus on **what is unique** from the dynamic perspective: the added value of runtime hooking compared to purely static analysis, and its implementation methodology.

### 1.2 The Unique Value of the Dynamic Approach: Confirming Real Execution and Catching What Static Analysis Misses

Consistent with the recurring pattern across all static-dynamic test pairs in this research series (MASTG-TEST-0200/0201, 0203/0231, etc.), the dynamic approach here provides two specific pieces of added value:

1. **Confirmation that the check actually executes**, not merely exists in the code but is never called (dead code, a conditional branch that is never satisfied).
2. **Catching cases missed by static analysis** — especially relevant for this test because of the specific gap already identified in the MASTG-TEST-0247 document §3.2: the official semgrep rule for its static version (`mastg-android-device-passcode-present.yml`) has narrow coverage (it relies on the literal string pattern `"keyguard"`, does not cover `isKeyguardSecure()`, and only targets the Java language). An API call constructed **dynamically** (via reflection, strings assembled at runtime, or code deliberately obfuscated to evade static pattern detection) will **always slip past** any static approach, yet will **still be captured** by runtime hooking, because the instrumentation attaches directly to the method call itself, regardless of how its arguments/callers are constructed in the code.

### 1.3 Why "Exercise the App Extensively" Is a Highly Relevant Instruction Here

The third official step emphasizes:

> *"Exercise the app extensively to trigger as many flows as possible and enter sensitive data wherever you can."*

This is a generic instruction that appears in many dynamic tests, but it carries special relevance for this test given the context in §1.3 of the MASTG-TEST-0247 document: a secure lock screen check is **most likely called right before a sensitive operation** — such as opening a crypto wallet, confirming a financial transaction, or accessing encrypted data whose key is protected by `setUserAuthenticationRequired`. If the tester merely opens the application and browses the main pages without actually **triggering those sensitive flows** (login, payment confirmation, access to a data vault), the installed hook **will never fire** — not because the application lacks this check, but because the code path containing it was never executed during the test session. This is an important reminder that **an empty result from this dynamic test carries the same ambiguity** that recurs throughout this document series (compare with the similar note in the MASTG-TEST-0238 document §1.3 regarding instrumentation coverage).

### 1.4 Instrumentation Completeness: Make Sure Both API Paths Are Covered

Per the MASTG-TEST-0247 document §1.5, there are two complementary (not duplicate) API paths — `KeyguardManager` and `BiometricManager` — because some device vendors restrict/modify the behavior of one or the other. The hooking instrumentation for this dynamic test **must cover both paths together with their method variants** (`isDeviceSecure()` **and** `isKeyguardSecure()`) so it does not inherit the same coverage gap present in the official static rule.

---

## 2. Tools Used for Testing

### 2.1 Mandatory Tools (Core)

| Tool | Function |
|---|---|
| **Frida** | Core dynamic instrumentation — hooking secure lock detection APIs and capturing stack traces |
| **frida-tools** (`frida-trace`) | A quick way to perform tracing without writing a custom script |
| **objection** | Ready-to-use Frida wrapper for quick hooking without scripting |

### 2.2 Alternative & Supporting Tools

| Tool | Function |
|---|---|
| **Xposed / LSPosed** | Alternative hooking based on system modules, per the example methodology in MASTG-TECH-0043 — suitable for scenarios requiring persistent hooks across sessions without needing repeated re-attachment |
| **adb logcat** | Simple baseline — some implementations log when a device security status check is performed (depending on the application's verbosity level) |
| **Emulator/device with varying lock screen conditions** | Running the application under device conditions **with** and **without** a secure lock to compare real behavior, complementing the hooking results alone |

### 2.3 Environment Prerequisites

- **A device/emulator with Frida server installed is required** — this test is purely dynamic.
- **Root or frida-gadget** for non-debuggable applications on non-rooted devices.
- **Prepare test scenarios that cover the application's sensitive flows** (login, access to encrypted data, transaction confirmation) per §1.3 — not just surface-level navigation.
- **Ideally, run two separate sessions**: one with the device having an active secure lock, one without — to observe whether the application's behavior actually differs according to the check result (answering the same question as Method D in the MASTG-TEST-0247 document, but now integrated as a core part of this dynamic test's methodology).

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0005** to install the application.
2. Use **MASTG-TECH-0043** to hook the relevant API calls.
3. Exercise the application thoroughly to trigger as many flows as possible, and enter sensitive data wherever possible.

### 3.2 Method A — A Frida Script Hooking Both API Paths at Once *(primary method)*

```javascript
// hook-secure-lock-detection.js
Java.perform(function () {
    function getBacktrace() {
        return Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());
    }

    // 1. KeyguardManager.isDeviceSecure()
    try {
        var KeyguardManager = Java.use("android.app.KeyguardManager");
        KeyguardManager.isDeviceSecure.overload().implementation = function () {
            var result = this.isDeviceSecure();
            console.log("\n[*] KeyguardManager.isDeviceSecure() called -> " + result);
            console.log("    Stack:\n" + getBacktrace());
            return result;
        };
    } catch (e) { console.log("[x] isDeviceSecure hook failed: " + e); }

    // 2. KeyguardManager.isKeyguardSecure() — the official static rule's coverage gap, DO NOT skip this
    try {
        var KeyguardManager2 = Java.use("android.app.KeyguardManager");
        KeyguardManager2.isKeyguardSecure.overload().implementation = function () {
            var result = this.isKeyguardSecure();
            console.log("\n[*] KeyguardManager.isKeyguardSecure() called -> " + result);
            console.log("    Stack:\n" + getBacktrace());
            return result;
        };
    } catch (e) { console.log("[x] isKeyguardSecure hook failed: " + e); }

    // 3. BiometricManager.canAuthenticate() — framework API
    try {
        var BiometricManager = Java.use("android.hardware.biometrics.BiometricManager");
        BiometricManager.canAuthenticate.overload("int").implementation = function (authenticators) {
            var result = this.canAuthenticate(authenticators);
            console.log("\n[*] BiometricManager.canAuthenticate(" + authenticators + ") called -> " + result);
            console.log("    Stack:\n" + getBacktrace());
            return result;
        };
    } catch (e) { console.log("[x] BiometricManager (framework) hook failed: " + e); }

    // 4. androidx.biometric.BiometricManager — Jetpack, more commonly used in modern applications
    try {
        var BiometricManagerX = Java.use("androidx.biometric.BiometricManager");
        BiometricManagerX.canAuthenticate.overload("int").implementation = function (authenticators) {
            var result = this.canAuthenticate(authenticators);
            console.log("\n[*] androidx.biometric.BiometricManager.canAuthenticate(" + authenticators + ") -> " + result);
            console.log("    Stack:\n" + getBacktrace());
            return result;
        };
    } catch (e) { console.log("[x] AndroidX BiometricManager hook failed: " + e); }
});
```

```bash
frida -U -f com.target.app -l hook-secure-lock-detection.js --no-pause
# Exercise the application thoroughly, especially login flows/sensitive data access/transaction confirmation
```

### 3.3 Method B — objection (Without Writing a Custom Script)

```bash
objection -g com.target.app explore
# Inside the objection console:
android hooking watch class_method android.app.KeyguardManager.isDeviceSecure --dump-backtrace
android hooking watch class_method android.app.KeyguardManager.isKeyguardSecure --dump-backtrace
android hooking watch class_method androidx.biometric.BiometricManager.canAuthenticate --dump-args --dump-backtrace
```

### 3.4 Method C — frida-trace (Quick Tracing)

```bash
frida-trace -U -f com.target.app -m "android.app.KeyguardManager!is*Secure*" -m "*BiometricManager!canAuthenticate"
```

`frida-trace` automatically generates a *stub* for every method matching the wildcard pattern, giving a quick overview without needing to write detailed hooks for each API variant.

### 3.5 Method D — Xposed/LSPosed (Persistent Hooking Alternative)

```java
// Example Xposed module per the MASTG-TECH-0043 pattern
XposedHelpers.findAndHookMethod(
    "android.app.KeyguardManager", lpparam.classLoader, "isDeviceSecure",
    new XC_MethodHook() {
        @Override
        protected void afterHookedMethod(MethodHookParam param) {
            XposedBridge.log("[*] isDeviceSecure() called, result: " + param.getResult());
        }
    }
);
```

Useful as an alternative approach when Frida is detected/blocked by anti-tampering mechanisms in the target application (see the Frida detection discussion in other MASVS-RESILIENCE documents in this series).

### 3.6 Method E — Device Condition Comparison Test (Complementing the Hooking Results)

```bash
# Session 1: device WITH an active secure lock
adb shell locksettings set-pin 1234
frida -U -f com.target.app -l hook-secure-lock-detection.js --no-pause
# Exercise sensitive flows, record hook results and application behavior

# Session 2: device WITHOUT a secure lock
adb shell locksettings clear --old 1234
frida -U -f com.target.app -l hook-secure-lock-detection.js --no-pause
# Exercise the same flows, compare: does the application react differently?
```

Comparing these two sessions answers a question of greater security value than merely "was the API called": **does the check result actually influence the application's behavior** under both conditions, in the same evaluative spirit as Method D in the MASTG-TEST-0247 document §3.4 (CodeQL for statically assessing correlation) — here confirmed empirically through real runtime behavior.

### 3.7 Method Comparison: When to Use Which

| Method | Tool | Advantage | When to use |
|---|---|---|---|
| **A** | Custom Frida script | Full control, covers all 4 API variants at once | Primary baseline |
| **B** | objection | Fast, no scripting | Quick initial exploration |
| **C** | frida-trace | Automatic tracing via wildcard | Quick overview before detailed hooking |
| **D** | Xposed/LSPosed | Resistant to certain Frida detection | Applications with active anti-Frida measures |
| **E** | Two-condition device comparison | Answers the real effect on application behavior | **Mandatory** for a meaningful conclusion, not just "the API was called" |

**Minimum combination recommended:** **A (comprehensive hooking of 4 API variants) → thorough interaction per §1.3 → E (two-condition device comparison test)** for a conclusion that truly answers the security value of the check found, rather than merely noting its existence.

---

### 3.8 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rule:**

> **Observation:** *"The output should contain a list of locations where relevant APIs are used."*
>
> **Evaluation:** *"The test case fails if an app doesn't use any API to verify the secure screen lock presence."*

---

#### ❌ FAIL / ISSUE — The check is declared FAILED if:

| No | Condition |
|---|---|
| F1 | None of the hooks (the four API variants, §3.2) **ever fire** during a thorough test session covering the application's sensitive flows |
| F2 | The hooks fire, but Method E shows **no difference in behavior** between the device-with-secure-lock and device-without-secure-lock conditions — indicating the check result is not actually used to make a security decision |
| F3 | Thorough interaction has been performed (including sensitive flows) yet the secure lock detection API is still never called, while the application is known to use a `setUserAuthenticationRequired` key (confirmed via the MASTG-TEST-0247 document or related cryptographic testing) |

---

#### ✅ PASS — The check is declared PASSED if:

| No | Condition |
|---|---|
| P1 | One or more of the four API variants fires during thorough interaction with the application |
| P2 | Method E confirms the application **reacts genuinely differently** between the device-with-secure-lock and device-without-secure-lock conditions (e.g., displaying a warning, restricting a feature) |
| P3 | The hook's stack trace shows the call occurring at a security-relevant location (e.g., before access to a financial feature/sensitive data), not in code that has no bearing on the security flow |

---

#### ⚠️ Important Assessment Notes

1. **An empty result can mean two different things — don't conclude hastily.** Per §1.3, a hook that never fires could mean (a) the application truly has no such check at all (a genuine FAIL), or (b) the code path containing it was never executed because the test interaction was insufficiently thorough (a methodological false negative). Always ensure the test scenario covers sensitive flows before concluding FAIL.

2. **Merely "the API was triggered" is not enough — prove it has a real effect (Method E).** This is the same lesson that repeats across various dynamic tests in this research series: the mere presence of an API call does not automatically mean its result is used to make a meaningful security decision. This test is explicitly more valuable when accompanied by comparative evidence of real behavior.

3. **Always correlate with MASTG-TEST-0247.** Both tests are ideally reported together — the static result provides a map of candidate code locations, the dynamic result confirms which ones actually execute and have a real effect.

4. **Leverage the coverage gap already identified in the static version.** Because the official semgrep rule for MASTG-TEST-0247 has gaps (`isKeyguardSecure()` not covered, dependency on a literal string), the dynamic approach here becomes a highly relevant **safety net** — make sure the hooking instrumentation truly covers all API variants (§1.4) so the same gap is not inherited into the dynamic test result.

5. **Severity follows the same pattern as the MASTG-TEST-0247 document** — modulated based on whether the application uses a cryptographic key dependent on lock screen status (`setUserAuthenticationRequired`), and how sensitive the affected data/feature is.

6. **Document:** which API fired (out of the 4 variants), the stack trace of its trigger location, the comparison results from Method E (behavior with vs. without secure lock), and the scope of application interaction performed (for transparency regarding the limitations of a "not found" result).

---

## 4. Recommendations

Because the root cause and the technical solution are identical to MASTG-TEST-0247 (the same weakness, MASWE-0017), refer to **the MASTG-TEST-0247 document §4** for the complete implementation recommendations (layered checks with fallback, denying sensitive features without a secure lock, correlation with `setUserAuthenticationRequired`).

Additional specifics from the dynamic perspective:

### 4.1 Integrate Hooking into Automated Regression Testing

```bash
#!/bin/bash
# ci-dynamic-secure-lock-check.sh — run as part of an automated smoke test
frida -U -f com.target.app -l hook-secure-lock-detection.js --no-pause &
FRIDA_PID=$!
sleep 5
./run-ui-test-suite.sh --scenario=login,payment,vault-access
kill $FRIDA_PID
```

### 4.2 Test Both Device Conditions as Part of Routine QA

Make Method E (comparing a device with/without a secure lock) a standard part of the QA cycle for any feature that uses an authentication-protected cryptographic key — not something done only once during a security audit.

### 4.3 Remediation Checklist

- [ ] Hooking instrumentation covers all four API variants (`isDeviceSecure`, `isKeyguardSecure`, framework and Jetpack `BiometricManager`)
- [ ] Test interaction has covered all of the application's sensitive flows (login, encrypted data access, transactions)
- [ ] A comparison of application behavior on a device with vs. without a secure lock has been performed and documented
- [ ] Results have been correlated with the MASTG-TEST-0247 (static) findings
- [ ] **Re-verification:** re-run MASTG-TEST-0249 after changes to authentication/cryptography flows

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0249: Runtime Use of Secure Screen Lock Detection APIs](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0249/)
- [MASTG-TEST-0247: References to APIs for Detecting Secure Screen Lock](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0247/)
- [MASWE-0017: Device Secure Lock Not Enforced](https://mas.owasp.org/MASWE/MASVS-CRYPTO/MASWE-0017/)
- [MASTG-TECH-0005: Installing Apps](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0005/)
- [MASTG-TECH-0043: Method Hooking](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0043/)

### 5.2 Official Android Documentation

- [Android Developers — `KeyguardManager` API reference](https://developer.android.com/reference/android/app/KeyguardManager)
- [Android Developers — `BiometricManager#canAuthenticate(int)`](https://developer.android.com/reference/android/hardware/biometrics/BiometricManager#canAuthenticate(int))
- [Android Developers — androidx.biometric library](https://developer.android.com/jetpack/androidx/releases/biometric)

### 5.3 Tool Documentation

- [Frida — Dynamic instrumentation toolkit](https://frida.re/docs/javascript-api/)
- [frida-trace — Documentation](https://frida.re/docs/frida-trace/)
- [Objection — Runtime Mobile Exploration toolkit](https://github.com/sensepost/objection)
- [LSPosed Framework](https://github.com/LSPosed/LSPosed)

---

*This document was compiled based on OWASP MASTG (latest release as of September 2026) and official Android Developers documentation. As the direct dynamic counterpart to MASTG-TEST-0247, the in-depth conceptual context (the connection to the Android Keystore's `setUserAuthenticationRequired`, the limitation that an application cannot force a system-level setting) is fully discussed in that document. This test's unique value lies in its ability to catch dynamically constructed/obfuscated API calls that slip past static analysis, as well as providing empirical proof — through comparing application behavior on devices with and without a secure lock — that the check found actually has a real effect on the application's security decisions, rather than being called without consequence.*
