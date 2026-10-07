# MASTG-TEST-0263 Logging of StrictMode Violations

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0263 |
| **Platform** | Android |
| **MASVS Category** | MASVS-RESILIENCE |
| **Weakness** | MASWE-0061 — *Debug Artifacts Not Removed* |
| **Highlighted API** | `StrictMode` |
| **Test Type** | **Dynamic, Logs** |
| **Profile** | **R (Resilience) only** |
| **Related Techniques** | MASTG-TECH-0005 (Install App), MASTG-TECH-0009 (Monitoring System Logs) |
| **Related Demo** | — (none) |
| **Official Rule** | `mastg-android-strictmode.yml` — only matches `StrictMode.setVmPolicy(...)`, does not cover `setThreadPolicy(...)` (see §3.2) |
| **Related CWE** | CWE-215 (Insertion of Sensitive Information Into Debugging Code), CWE-489 (Active Debug Code) |

---

## 1. Explanation

### 1.1 Testing Objective

Official MASTG overview quote:

> *"This test checks whether an app enables `StrictMode` in production. While useful for developers to log policy violations such as disk I/O or network operations in production apps, leaving `StrictMode` enabled can expose sensitive implementation details in the logs that could be exploited by attackers."*

`StrictMode` is a developer aid that, by design, is **intended for the development phase** — it monitors the main thread and the entire application VM to detect poor code patterns (disk I/O on the main thread causing ANRs, network connections without a `SocketTag`, resource leaks, etc.) and **logs the full details of such violations** to Logcat. This test purely checks **whether this debugging artifact is still active** in a production build — consistent with its categorization under **MASWE-0061 (Debug Artifacts Not Removed)**, part of a broader risk pattern around leftover development mechanisms that remain at release time (compare with MASTG-TEST-0226 regarding the `debuggable` flag elsewhere in this research series).

### 1.2 Why This Test Is Specific to the R (Resilience) Profile

This test **only applies to the R profile** — consistent with several other tests in this research series that target hardening against reverse engineering (e.g., MASTG-TEST-0222/0223 on PIE/stack canary, MASTG-TEST-0224/0225 on APK signature schemes). This reflects the nature of `StrictMode`'s risk: its impact is **not** direct user data leakage (like credentials or PII), but rather **leakage of internal implementation details** that make reverse engineering and code architecture mapping easier — particularly relevant for applications whose binary itself is the target (DRM, payment applications, anti-cheat), per the definition of the R profile in the MASTG standard.

### 1.3 What Actually Leaks Through `StrictMode` Logs

To understand this test's real impact, it is important to know the **concrete details** that `StrictMode` logs when a violation is detected. Based on the official `StrictMode` API documentation, two policy categories log fairly detailed information:

**`StrictMode.VmPolicy`** (VM/application level) detects:
- Disk write/read off the main thread
- Network operations on the main thread
- Socket creation without a tag
- Cleartext traffic
- Content provider access violations
- Unsafe class loading

**`StrictMode.ThreadPolicy`** (thread level) detects:
- Disk I/O operations (read/write) on the main thread
- Network access on the main thread
- Custom violations via `noteSlowCall()`

Every detected violation is logged to Logcat with **very detailed information**:

```
StrictMode policy violation: ...
    at android.os.StrictMode$AndroidBlockGuardPolicy.onNetwork()
    at java.net.Socket.<init>()
    at com.example.app.internal.PaymentGatewayClient.connectDirectly(PaymentGatewayClient.java:87)
    at com.example.app.internal.PaymentGatewayClient.processTransaction(PaymentGatewayClient.java:42)
```

Notice how much architectural information is revealed by this single log line alone: the **internal package name** (`com.example.app.internal`), the **class name revealing business function** (`PaymentGatewayClient`), the **method names** (`connectDirectly`, `processTransaction`), and the **exact source code line number**. This is exactly the class of information that obfuscation/code-shrinking mechanisms (ProGuard/R8, discussed in various other MASVS-RESILIENCE documents in this series) specifically **try to hide** — yet `StrictMode` active in production effectively **leaks the same navigation map** through a path entirely separate from and independent of any obfuscation effort, because the runtime stack trace still shows the real execution structure regardless of how symbol names were obfuscated at the static bytecode level.

### 1.4 Connection to Reverse Engineering: A "Free Map" Without Decompilation

An important synthesis point: an attacker wanting to understand an application's internal architecture typically has to go through a time-consuming decompilation and static analysis process (exactly the methodology discussed in many other documents in this research series). However, if `StrictMode` is active in a production build, an attacker **only needs to run the application while watching Logcat** — a technique far cheaper and faster than full static reverse engineering — to obtain:

- A map of real execution flow (not just static code structure, but the **actual call sequence** when a given feature is used)
- Code points performing sensitive I/O (disk/network), which often correlate with where important data is processed
- Real class/method names even if the application has been obfuscated (because the runtime stack trace is unaffected by symbol-name obfuscation at the source-map level that is not published — the name appearing in the stack trace is the name **after** obfuscation, but the class structure and call hierarchy are still functionally revealed)

This complements insights from general research on *log info disclosure* on Android:

> *"Log Info Disclosure is a type of vulnerability where apps print sensitive data into the device log. If attackers gain access to log files or Logcat, they may extract sensitive user details, which could include confidential paths, API keys, or database queries... Activating logging in a production environment can disclose internal application information, thereby aiding potential attackers in the reverse-engineering process."*

`StrictMode` is a special case of this risk category — the difference being that the logs produced are not the result of a `Log.d()` call deliberately written by a developer (as discussed in the MASTG-TEST-0203/0231 documents in this research series), but are **automatically generated by the system** whenever application code violates a configured policy — meaning a developer who forgets to disable it in a release build may **not even be aware** that such logs continue to be generated without having written each one explicitly.

---

## 2. Tools Used for Testing

### 2.1 Mandatory Tools (Core)

| Tool | Function |
|---|---|
| **adb logcat** | Monitors system log output while the application runs (MASTG-TECH-0009) — the official primary method |
| **jadx** | Decompilation for supporting static analysis (finding `StrictMode.setVmPolicy`/`setThreadPolicy` calls in the code) |
| **semgrep** | Runs the official rule as a supporting static baseline |

### 2.2 Alternative & Supporting Tools

| Tool | Function |
|---|---|
| **grep / ripgrep** | Fills the coverage gap left by the official rule, which does not cover `setThreadPolicy` (§3.2) |
| **pidcat / matlog** | A friendlier log filter than raw `adb logcat`, making it easier to isolate `StrictMode`-related lines among other log noise |
| **Frida** | Hooking `StrictMode.setVmPolicy`/`setThreadPolicy` to confirm at runtime which configuration is actually applied, including configurations built conditionally (e.g., wrapped in `if (BuildConfig.DEBUG)`) |
| **CodeQL** | Tracing whether `StrictMode` calls are truly wrapped consistently in a `BuildConfig.DEBUG` check, or left unguarded in certain code paths |

### 2.3 Environment Prerequisites

- **Requires a device/emulator** — this test is purely dynamic, requiring the application to actually run.
- **The test target must be the production/release build APK**, not a debug build — the official overview states this explicitly: *"The target of this test is the production build of the app."* Testing a debug build will produce a false positive, since `StrictMode` being active in a debug build is normal and expected.
- **Thorough interaction with the application** to trigger as many code paths as possible that could potentially violate `StrictMode` policies (disk I/O, network calls) — a pattern consistent with other dynamic tests in this research series.

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0005** to install the application.
2. Use **MASTG-TECH-0009** to display the system logs generated by `StrictMode`.
3. Open the application and let it run.

### 3.2 Method A — `adb logcat` *(the official primary method)*

```bash
adb install target-app-release.apk
adb logcat -c
adb shell am start -n com.target.app/.MainActivity

# Filter specifically for StrictMode
adb logcat | grep -i "StrictMode"
```

Example output indicating FAIL:

```
D/StrictMode: StrictMode policy violation; ~duration=42 ms: android.os.StrictMode$StrictModeDiskReadViolation
    at com.target.app.data.LocalCache.readFromDisk(LocalCache.java:55)
```

### 3.3 Method B — Official Semgrep Rule + Supplementary grep *(official rule exists, but has narrow coverage)*

```yaml
rules:
  - id: mastg-android-strictmode
    severity: WARNING
    languages: [java]
    message: "[MASVS-RESILIENCE] Detected usage of StrictMode"
    patterns:
      - pattern: StrictMode.setVmPolicy(...)
```

```bash
semgrep --config https://raw.githubusercontent.com/OWASP/mastg/master/rules/mastg-android-strictmode.yml ./decompiled/sources/
```

**Coverage gap**: this rule **only matches `setVmPolicy()`**, and does not cover `StrictMode.setThreadPolicy()` at all — even though both are two independent configuration APIs per §1.3, and an application could use only one of them. Complement with grep:

```bash
rg -n 'StrictMode\.setVmPolicy\(|StrictMode\.setThreadPolicy\(' ./decompiled/sources/

# Verify whether the call is wrapped in a BuildConfig.DEBUG guard
rg -n -B5 'StrictMode\.set(VmPolicy|ThreadPolicy)\(' ./decompiled/sources/ | grep -B5 "BuildConfig.DEBUG"
```

### 3.4 Method C — CodeQL (Verifying the `BuildConfig.DEBUG` Guard)

```ql
import java

class StrictModeCall extends MethodAccess {
  StrictModeCall() {
    this.getMethod().hasName(["setVmPolicy", "setThreadPolicy"]) and
    this.getMethod().getDeclaringType().hasQualifiedName("android.os", "StrictMode")
  }
}

from StrictModeCall call
where not exists(IfStmt guard |
  guard.getCondition().toString().matches("%BuildConfig.DEBUG%") and
  guard.getAChild*() = call.getEnclosingStmt())
select call, "StrictMode call found WITHOUT a clear BuildConfig.DEBUG guard"
```

### 3.5 Method D — Frida (Runtime Confirmation on the Production Build)

```javascript
// hook-strictmode-config.js
Java.perform(function () {
    var StrictMode = Java.use("android.os.StrictMode");
    StrictMode.setVmPolicy.overload("android.os.StrictMode$VmPolicy").implementation = function (policy) {
        console.log("[!] StrictMode.setVmPolicy() called on this build — policy: " + policy.toString());
        return this.setVmPolicy(policy);
    };
    StrictMode.setThreadPolicy.overload("android.os.StrictMode$ThreadPolicy").implementation = function (policy) {
        console.log("[!] StrictMode.setThreadPolicy() called on this build — policy: " + policy.toString());
        return this.setThreadPolicy(policy);
    };
});
```

```bash
frida -U -f com.target.app -l hook-strictmode-config.js --no-pause
```

### 3.6 Method Comparison: When to Use Which

| Method | Tool | Coverage | When to use |
|---|---|---|---|
| **A** | adb logcat | Direct evidence per the test's official definition | **Mandatory**, primary method |
| **B** | semgrep rule + grep | Static, only `setVmPolicy` (rule) + supplement (grep) | Supporting, identifying code locations |
| **C** | CodeQL | Verifies the `BuildConfig.DEBUG` guard | Large codebases, pattern-compliance audits |
| **D** | Frida | Confirms active configuration on a specific build | Complements Method A with configuration detail |

**Minimum combination recommended:** **A (mandatory official method, direct Logcat evidence) → B/C (code location identification if FAIL is found, for precise remediation)**.

---

### 3.7 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rule:**

> **Observation:** *"The output should contain a list of log statements related to `StrictMode`."*
>
> **Evaluation:** *"The test case fails if an app logs any `StrictMode` policy violations."*

---

#### ❌ FAIL / ISSUE — The check is declared FAILED if:

| No | Condition |
|---|---|
| F1 | Logcat on the **production/release** build shows **even one** `StrictMode` violation log line during normal application interaction |
| F2 | A `setVmPolicy`/`setThreadPolicy` call is found in the code **without** a consistent `BuildConfig.DEBUG` guard |

**Example evidence (illustrative — MASTG does not yet provide an official demo for this test):**

```bash
$ adb logcat | grep -i "StrictMode"
D/StrictMode: StrictMode policy violation; ~duration=120 ms
    at com.target.app.storage.SecureVaultManager.loadKeyFromDisk(SecureVaultManager.java:33)
```

Interpretation: this log appears on a release build, revealing the `SecureVaultManager` class name, which clearly handles cryptographic material, along with its method name and code line — **FAIL**, with a more significant impact because this architectural leak touches a security-critical component.

---

#### ✅ PASS — The check is declared PASSED if:

| No | Condition |
|---|---|
| P1 | Logcat on the production build **shows no** `StrictMode` violation logs at all during thorough interaction |
| P2 | Static analysis (Method B/C) confirms every `StrictMode` call is consistently wrapped in `if (BuildConfig.DEBUG)` |

**Example output indicating PASS:**

```bash
$ adb logcat | grep -i "StrictMode"
# (no results after thorough interaction)
```

---

#### ⚠️ Important Assessment Notes

1. **Make sure to test the production build, not the debug build** — this is an explicit official prerequisite. Mistakenly testing a debug build will always produce a FAIL, since `StrictMode` is naturally expected to be active there.

2. **Thorough interaction is important for a convincing negative result** — consistent with the recurring pattern across all dynamic tests in this series, `StrictMode` only logs violations for operations that **actually occur**; rarely used code paths (rare features, error flows) risk not triggering a violation even though the configuration remains active.

3. **Use static analysis to identify precise remediation locations** if the dynamic result is FAIL — Method B/C directly show which code lines need to be wrapped in a `BuildConfig.DEBUG` guard.

4. **The official rule only covers half the API (`setVmPolicy`)** — do not conclude PASS from an empty semgrep result without separately checking `setThreadPolicy`.

5. **Severity is modulated by the content of the exposed stack trace** — violations whose stack trace touches classes/methods related to security-critical functions (cryptography, authentication, payment processing) are more significant than those touching ordinary UI/rendering code.

6. **Document:** the complete excerpt of the violation log found, the class/method revealed by the stack trace, the location of the `StrictMode` call in the code (if found via static analysis), and the status of the `BuildConfig.DEBUG` guard.

---

## 4. Recommendations

### 4.1 Wrap All `StrictMode` Configuration in a Build Guard

```kotlin
class MyApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        if (BuildConfig.DEBUG) {
            StrictMode.setVmPolicy(
                StrictMode.VmPolicy.Builder()
                    .detectAll()
                    .penaltyLog()
                    .build()
            )
            StrictMode.setThreadPolicy(
                StrictMode.ThreadPolicy.Builder()
                    .detectAll()
                    .penaltyLog()
                    .build()
            )
        }
    }
}
```

### 4.2 Verify via ProGuard/R8 as a Second Layer

For additional certainty that `StrictMode` code truly does not make it into the release build, consider a shrinking configuration that removes that block entirely when `BuildConfig.DEBUG` is statically known to be `false` at build time (R8 is already capable of dead-code elimination for the `if (false)` pattern produced by `BuildConfig.DEBUG=false` on a release build).

### 4.3 Integrate into CI/CD

```bash
#!/bin/bash
# ci-check-strictmode-production.sh — run on the RELEASE APK
adb install -r "$1"
adb logcat -c
adb shell am start -n "$2"
sleep 10
VIOLATIONS=$(adb logcat -d | grep -c "StrictMode policy violation")
if [ "$VIOLATIONS" -gt "0" ]; then
    echo "[FAILED] Found $VIOLATIONS StrictMode violations on the release build!"
    exit 1
fi
```

### 4.4 Remediation Checklist

- [ ] All `StrictMode.setVmPolicy`/`setThreadPolicy` calls are wrapped in `if (BuildConfig.DEBUG)`
- [ ] Dynamic verification on the release APK shows no `StrictMode` violation logs
- [ ] CI/CD includes an automated gate to detect future regressions
- [ ] **Re-verification:** re-run MASTG-TEST-0263 on every new release build

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0263: Logging of StrictMode Violations](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0263/)
- [MASWE-0061: Debug Artifacts Not Removed](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0061/)
- [MASTG-TECH-0005: Installing Apps](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0005/)
- [MASTG-TECH-0009: Monitoring System Logs](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0009/)
- [MASTG Document 0x05i — Testing Code Quality and Build Settings](https://mas.owasp.org/MASTG/0x05i-Testing-Code-Quality-and-Build-Settings/)
- [Official rule: mastg-android-strictmode.yml (GitHub)](https://github.com/OWASP/mastg/blob/master/rules/mastg-android-strictmode.yml)

### 5.2 Official Android Documentation

- [Android Developers — `StrictMode` API reference](https://developer.android.com/reference/android/os/StrictMode)
- [Android Developers — Log Info Disclosure](https://developer.android.com/privacy-and-security/risks/log-info-disclosure)

### 5.3 Community Research and Articles

- [SecureFlag Knowledge Base — Sensitive Information Disclosure in Android](https://knowledge-base.secureflag.com/vulnerabilities/sensitive_information_exposure/sensitive_information_disclosure_android.html)
- [Oversecured Blog — Android Security Checklist: Theft of Arbitrary Files](https://blog.oversecured.com/Android-security-checklist-theft-of-arbitrary-files/)
- [CWE-215: Insertion of Sensitive Information Into Debugging Code](https://cwe.mitre.org/data/definitions/215.html)
- [CWE-489: Active Debug Code](https://cwe.mitre.org/data/definitions/489.html)

### 5.4 Tool Documentation

- [Semgrep — Documentation](https://semgrep.dev/docs/)
- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [CodeQL — Documentation](https://codeql.github.com/docs/)
- [Frida — Dynamic instrumentation toolkit](https://frida.re/docs/javascript-api/)
- [pidcat](https://github.com/JakeWharton/pidcat)

---

*This document was compiled based on OWASP MASTG (latest release as of September 2026), official Android Developers documentation, and general research on log information disclosure on Android. The most important nuance: `StrictMode` active in production leaks architectural details (class names, method names, code lines, real execution stack traces) that effectively provide a "free map" for reverse engineering efforts — far cheaper for an attacker than full static decompilation, and operating independently of any obfuscation/code-shrinking effort that may already have been applied at the bytecode level.*
