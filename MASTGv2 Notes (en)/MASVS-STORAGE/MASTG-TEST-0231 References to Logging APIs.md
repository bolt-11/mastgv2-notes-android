# MASTG-TEST-0231 References to Logging APIs

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0231 |
| **Platform** | Android |
| **MASVS Category** | MASVS-STORAGE (MASVS-STORAGE-2: The app prevents leakage of unnecessary sensitive data) |
| **Weakness** | MASWE-0005 — *Insertion of Sensitive Data into Logs* |
| **Test Type** | **Static**, Code |
| **Profile** | L1, L2, **P** (Privacy) |
| **Knowledge** | MASTG-KNOW-0049 (Logs) |
| **Best Practice** | MASTG-BEST-0002 (Remove Logging Code) |
| **Highlighted APIs** | `android.util.Log`, `Log`, `Logger`, `System.out.print`, `System.err.print`, `java.lang.Throwable#printStackTrace` |
| **Related Techniques** | MASTG-TECH-0013 (Reverse Engineering Android Apps), MASTG-TECH-0014 (Static Analysis on Android), MASTG-TECH-0023 (Reviewing Decompiled Java Code) |
| **Related Demo** | — (MASTG does not yet provide a demo for this test) |
| **Sibling Test** | **MASTG-TEST-0203** (Runtime Use of Logging APIs) — the dynamic counterpart, exact same weakness and APIs |
| **Supersedes** | MASTG-TEST-0003 (*Testing Logs for Sensitive Data* — now **deprecated**, `covered_by: [MASTG-TEST-0203, MASTG-TEST-0231]`) |
| **Related CWEs** | CWE-532 (Insertion of Sensitive Information into Log File), CWE-200 (Exposure of Sensitive Information), CWE-312 (Cleartext Storage of Sensitive Information), CWE-359 (Exposure of Private Personal Information) |

---

## 1. Explanation

### 1.1 Testing Objective

Direct quote from the MASTG overview:

> *"This test verifies if an app uses logging APIs like `android.util.Log`, `Log`, `Logger`, `System.out.print`, `System.err.print`, and `java.lang.Throwable#printStackTrace`."*

This test is the **exact static counterpart** of MASTG-TEST-0203, discussed previously. Both share the weakness (MASWE-0005), knowledge (MASTG-KNOW-0049), best practice (MASTG-BEST-0002), and an **identical list of APIs**. The difference is purely in approach:

| | MASTG-TEST-0203 | MASTG-TEST-0231 *(this document)* |
|---|---|---|
| **Approach** | Dynamic — hooking (Frida) or `adb logcat` | **Static** — reverse engineering + pattern matching |
| **Answers** | "What value is **actually** logged at runtime?" | "Where is a logging API **referenced** in the code?" |
| **Strength** | Sees the actual runtime value — the core of the evaluation criteria ("sensitive data *is logged*") | **Comprehensive coverage** of all existing code, including rarely-exercised paths (error handlers, premium features) |
| **Weakness** | Only catches flows the tester actually ran | Doesn't know the **value** logged — only knows **that** there is an API call at a given location |

Since the full detail on why logging is dangerous, leakage paths, and the API map has already been covered in depth in the MASTG-TEST-0203 document, this document will **refer back** to that section and focus on **what is unique** to the static analysis side: how to thoroughly find API references, and how its evaluation criteria subtly differ from its dynamic counterpart.

### 1.2 The Unique Value of the Static Approach: Coverage, Not Depth

The dynamic test (MASTG-TEST-0203) only sees what is **actually executed** during a testing session. This is a significant blind spot:

- **A log inside a `catch` block for a rarely-occurring exception** (e.g., a specific network failure, a race condition) will never trigger unless the tester manages to reproduce that condition.
- **A log in a feature gated by a flag** (premium account, A/B testing, a specific region) will not be visible if the tester doesn't have access to that condition.
- **A log in a rarely-used module** (an advanced settings page, a one-time-only onboarding flow) is easily missed during a time-limited manual testing session.

Static analysis **sees everything at once** — every line of code that calls a logging API will be found, regardless of whether that line was ever executed during testing. This is this test's unique value: it provides a **complete map** of the app's logging surface, which can then be used to direct dynamic testing more efficiently (see §1.4).

### 1.3 Why Its Evaluation Criteria Subtly Differ from MASTG-TEST-0203

This is an important nuance that's easy to miss because the two tests look very similar. Compare both official evaluation criteria:

> **MASTG-TEST-0203 (dynamic):** *"The test case fails if **you can find sensitive data being logged** using those APIs."*
>
> **MASTG-TEST-0231 (static, this document):** *"The test case fails if **an app logs sensitive information** from any of the listed locations."*

Textually both appear to state the same thing, but their practical implications differ because of **the nature of the data available to each approach**:

- In the **dynamic** test, the tester **sees the literal value** recorded at runtime — so "finding sensitive data" literally means seeing a canary string/credential in the log output.
- In the **static** test, the tester **does not see the runtime value** — they only see the *code* that calls the logging API, such as `Log.d(TAG, "token: " + accessToken)`. To conclude that this "logs sensitive information," the tester must **analyze the code** around that call: what variable is interpolated into the log string, where it came from, and whether it genuinely holds a sensitive value.

This is why MASTG consistently requires the **MASTG-TECH-0023** (*Reviewing Decompiled Java Code*) step as an inseparable part of evaluating this kind of static test — static logging analysis is **never complete** merely by finding API call locations; it must be followed by tracing the **variables** that go into them.

### 1.4 Recommended Workflow: Static as a Map, Dynamic as Confirmation

Since the two complement each other, the most efficient work order is:

```
TEST-0231 (static)  ──►  COMPLETE map of logging API call locations
        │                (including rarely-exercised ones)
        ▼
   Analyze the variables interpolated into each call
   (MASTG-TECH-0023) — flag candidates that MIGHT be sensitive
        │
        ▼
TEST-0203 (dynamic)  ──►  CONFIRM the actual runtime value
        │                 on the flagged candidates, plus a canary value
        ▼
   PASS / FAIL decision with actual runtime value evidence
```

This approach avoids two pitfalls at once: a **false positive** from pure static analysis (concluding sensitivity just from a suspicious-looking variable name, when the value is actually generic), and a **false negative** from pure dynamic analysis (missing a code path that was never exercised).

---

## 2. Tools Used for Testing

Since this test is purely static and shares its target APIs with MASTG-TEST-0203, most of the tooling here complements (rather than replaces) what has already been discussed for its dynamic counterpart.

### 2.1 Required Tools (Core)

| Tool | MASTG ID | Function |
|---|---|---|
| **jadx** | MASTG-TOOL-0018 | **DEX → Java decompilation** (MASTG-TECH-0013). Required for MASTG-TECH-0023 — tracing logged variables |
| **grep / ripgrep** | — | Logging API pattern search. **The primary method**, since MASTG does not provide an official semgrep rule for this test |
| **apktool** | MASTG-TOOL-0011 | An alternative for decompilation; smali analysis if needed |

### 2.2 Alternative and Supporting Tools

| Tool | Function |
|---|---|
| **semgrep** | No official MASTG rule exists — a custom rule (§3.3) is needed to cover all six APIs plus variants not explicitly named (Timber, etc.) |
| **CodeQL** | Taint analysis — can programmatically trace whether a logged variable genuinely originates from a sensitive source (a field named password/token, an API response parameter, etc.), reducing the manual review burden |
| **MobSF** | Automated analysis, flags logging API calls in the Code Analysis report |
| **jadx-gui** | Interactive navigation with a "Find Usage" feature — to trace where a logged variable's value comes from |
| **ProGuard mapping / R8 rules inspector** | Checks whether the `-assumenosideeffects` rule for `android.util.Log` has been applied to the release build (see MASTG-BEST-0002 and the detailed discussion in the MASTG-TEST-0203 document, §4.1) |

### 2.3 Environment Prerequisites

- **No device and no root needed** — just the APK file. Fully automatable in CI/CD.
- **Test the RELEASE build APK**, not the debug build — same important note as in MASTG-TEST-0203: excessive logging in a debug build is normal and not representative of production risk. However, for a **static** test, it's important to note: **the presence of a logging API reference in the release-build code does NOT automatically mean that API will be executed** — if ProGuard/R8 has already stripped `Log.*` calls per MASTG-BEST-0002, that reference may have already disappeared from the decompiled bytecode. This verification matters to avoid drawing a wrong conclusion (see §3.7 note 3).
- **Watch for obfuscation.** Framework API names (`Log`, `Logger`, `System.out`) are not obfuscated by ProGuard/R8 since they are system APIs, so detection remains effective even if the app's own class/method names are scrambled.
- **Watch for third-party logging libraries** not explicitly named in the official API list (Timber, SLF4J, etc.) — see MASTG-TEST-0203 §1.4 for the full map of Group B APIs that need additional checking.

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0013** (*Reverse Engineering Android Apps*) to reverse engineer the application.
2. Use **MASTG-TECH-0014** (*Static Analysis on Android*) to search for relevant APIs.

For evaluation, although not explicitly stated in this test's official steps, practice consistent with other static tests in MASTG requires **MASTG-TECH-0023** to review every finding location.

### 3.2 Method A — grep/ripgrep on Decompiled Code *(the primary method)*

```bash
jadx -d ./decompiled ./target-app.apk
D=./decompiled/sources

# --- The six APIs EXPLICITLY named by the MASTG overview ---
rg -n --no-heading "android\.util\.Log|Log\.(v|d|i|w|e|wtf|println)\(" $D
rg -n --no-heading "java\.util\.logging\.Logger|\.severe\(|\.warning\(|\.info\(|\.fine\(|\.config\(" $D
rg -n --no-heading "System\.out\.print" $D
rg -n --no-heading "System\.err\.print" $D
rg -n --no-heading "printStackTrace\(\)" $D

# --- Recap finding counts per file for initial triage ---
rg -c --no-heading "Log\.(v|d|i|w|e|wtf)\(" $D | sort -t: -k2 -rn | head -20
```

**The mandatory next step — trace the logged variables (MASTG-TECH-0023):**

```bash
# For every result, check the full context of that line
rg -n -B3 -A1 "Log\.(d|e|w|i)\(" $D | grep -B3 -A1 "token\|password\|secret\|key\|email\|credential" -i

# Search for string interpolation patterns carrying a variable into the log call
rg -n 'Log\.\w+\([^,]+,\s*"[^"]*"\s*\+' $D          # string + variable concatenation
rg -n 'Log\.\w+\([^,]+,\s*\w+\)' $D                  # a variable directly as the second argument
```

### 3.3 Method B — semgrep with a Custom Rule *(a CI/CD gate, covers all six APIs)*

MASTG provides no official rule for this test. Below is a rule covering all six explicitly-named APIs, plus variants that are often missed:

```yaml
rules:
  - id: custom-logging-api-android-log
    severity: WARNING
    languages: [java, kotlin]
    message: "[MASVS-STORAGE-2] An android.util.Log call was found — verify the logged variable"
    pattern-either:
      - pattern: android.util.Log.$METHOD(...)

  - id: custom-logging-api-logger
    severity: WARNING
    languages: [java, kotlin]
    message: "[MASVS-STORAGE-2] A java.util.logging.Logger call was found"
    pattern-either:
      - pattern: $LOGGER.severe(...)
      - pattern: $LOGGER.warning(...)
      - pattern: $LOGGER.info(...)
      - pattern: $LOGGER.fine(...)
      - pattern: $LOGGER.config(...)

  - id: custom-logging-api-system-print
    severity: WARNING
    languages: [java, kotlin]
    message: "[MASVS-STORAGE-2] System.out/err.print was found"
    pattern-either:
      - pattern: System.out.print(...)
      - pattern: System.out.println(...)
      - pattern: System.err.print(...)
      - pattern: System.err.println(...)

  - id: custom-logging-api-stacktrace
    severity: WARNING
    languages: [java, kotlin]
    message: "[MASVS-STORAGE-2] printStackTrace() was found — the exception message/stack trace could potentially contain sensitive data"
    pattern: $EX.printStackTrace(...)

  - id: custom-logging-api-thirdparty
    severity: INFO
    languages: [java, kotlin]
    message: "[MASVS-STORAGE-2] A third-party logging library was found — not covered by MASTG's official API list, still needs checking"
    pattern-either:
      - pattern: timber.log.Timber.$METHOD(...)
      - pattern: org.slf4j.Logger $X = ...
```

```bash
semgrep -c ./logging-rules.yml ./decompiled/sources/ --json -o findings.json
jq '.results | length' findings.json
```

### 3.4 Method C — CodeQL *(taint analysis — reduces the manual review burden)*

This is the method that best answers this static test's core challenge (§1.3): distinguishing a log call that carries sensitive data from one that doesn't, programmatically.

```ql
/**
 * @name Sensitive-looking variable flows into logging API
 * @kind path-problem
 * @problem.severity warning
 */
import java
import semmle.code.java.dataflow.TaintTracking

class SensitiveSource extends DataFlow::Node {
  SensitiveSource() {
    exists(Variable v |
      v.getName().toLowerCase().regexpMatch(".*(password|token|secret|apikey|credential|auth|session).*") and
      this.asExpr() = v.getAnAccess()
    )
  }
}

class LoggingSink extends DataFlow::Node {
  LoggingSink() {
    exists(MethodAccess ma |
      ma.getMethod().getDeclaringType().hasQualifiedName("android.util", "Log") or
      ma.getMethod().getDeclaringType().hasQualifiedName("java.util.logging", "Logger") or
      ma.getMethod().getDeclaringType().hasQualifiedName("java.io", "PrintStream") |
      this.asExpr() = ma.getAnArgument()
    )
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink
where TaintTracking::localFlow(source, sink)
select sink, source, sink, "A suspiciously-named variable flows into a logging API"
```

```bash
codeql database create ./cqldb --language=java --command="./gradlew assembleRelease"
codeql database analyze ./cqldb ./sensitive-logging-query.ql --format=sarif-latest --output=result.sarif
```

> Note: this **variable-name-based** approach is still heuristic — a variable named `data` or `result` that actually holds a token will not be caught, while a variable named `passwordHint` holding non-sensitive text could become a false positive. For more precise results, combine this with taint tracking from API sources known to be sensitive (e.g., the return value of an authentication function) — but this requires further customization tailored to the specific codebase under test.

### 3.5 Method D — MobSF

```bash
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest
```

Upload the APK → the **Code Analysis** section looks for findings related to *"Application logs information"* or similar, with a list of code locations. Like other automated scanners, MobSF's results **only show the location**, not an assessment of the logged value's sensitivity — manual verification (§1.3) is still mandatory.

### 3.6 Method E — Verifying the ProGuard/R8 Configuration *(complements pattern-matching results)*

This is a step that is often skipped but is important for accurately interpreting results (see §3.7 note 3): finding a logging API reference in the **source** code does not mean that API genuinely exists in the **final release bytecode**.

```bash
# Check whether a logging-strip rule already exists in the project configuration
find . -name "proguard-rules.pro" -exec grep -A10 "android.util.Log" {} \;

# On the release-build APK, verify whether Log calls STILL EXIST
# after shrinking/obfuscation — if the ProGuard configuration is correct,
# this result should be far lower than from decompiling the original source
jadx -d ./decompiled_release ./target-app-release.apk
rg -c "Log\.(v|d|i|w|e)\(" ./decompiled_release/sources/ | awk -F: '{sum+=$2} END {print sum}'
```

If the result on the final release APK shows **far fewer** (or zero) calls compared to the original source code, this is a strong indication that `-assumenosideeffects` has been correctly applied — although, per the MASTG-BEST-0002 note discussed in depth in the MASTG-TEST-0203 document, **a string dynamically built for a log parameter that has been stripped could still be left behind in the bytecode** even though the `Log.v()` call itself has disappeared.

### 3.7 Method Comparison: When to Use Which

| Method | Tool | Finds locations? | Assesses value sensitivity? | Suitable for CI/CD? | When to use |
|---|---|---|---|---|---|
| **A** | grep/ripgrep | ✅ | Manual (mandatory) | Moderate | **Primary baseline** — no official rule exists |
| **B** | Custom semgrep | ✅ | ❌ | ✅ | CI/CD gate; initial location filter |
| **C** | CodeQL | ✅ | Partial (variable-name heuristic) | ✅ | Reduces manual review burden on a large codebase |
| **D** | MobSF | ✅ | ❌ | Partial | Fast initial triage, report-ready output |
| **E** | ProGuard/R8 verification | — | — | ✅ | **Accurate result interpretation** — checking whether a source finding is relevant to the final release |

**Minimum recommended combination:** **A (grep) → E (ProGuard verification) → manual review (MASTG-TECH-0023)**.
A gives complete location coverage, E ensures you're assessing the relevant bytecode (not source already stripped in the final build), and manual review of each candidate answers this test's core question: is the logged value genuinely sensitive. Add **C (CodeQL)** for a large codebase to narrow down candidates needing manual review.

---

### 3.8 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rule:**

> **Observation:** *"The output should contain a list of locations where logging APIs are used."*
>
> **Evaluation:** *"The test case **fails** if an app logs sensitive information from any of the listed locations."*

As touched on in §1.3, this criterion requires **assessing content**, not merely the existence of an API call.

---

#### ❌ FAIL / ISSUE — The check is declared FAILED if:

| No | Condition | Example evidence |
|---|---|---|
| F1 | A `Log.*` call is found carrying a variable containing a **credential/token** into the log string | `Log.d(TAG, "token=" + accessToken)` |
| F2 | A call is found carrying **PII** (email, national ID, phone number) | `Logger.getLogger("X").info("user email: " + user.getEmail())` |
| F3 | A call is found carrying **cryptographic material** (key, IV, seed) | `Log.v(TAG, "key bytes: " + Arrays.toString(secretKey.getEncoded()))` |
| F4 | `printStackTrace()` is called on an exception whose **message or causal chain** is likely to contain sensitive data (e.g., a full URL with a token parameter, a failed API response's content) | `catch (Exception e) { e.printStackTrace(); }` in a block handling an HTTP response containing an authentication payload |
| F5 | `System.out.print`/`System.err.print` is used to print a sensitive value — a rare pattern, but still worth checking, especially in code ported from a non-Android CLI/library | `System.out.println("Session ID: " + sessionId)` |
| F6 | A log call is found with a variable whose **name clearly indicates sensitivity** (`password`, `token`, `secret`, `apiKey`) even if its literal value isn't directly visible in static code — a sufficiently strong indicator if it cannot be further confirmed dynamically | `Log.e(TAG, "auth failed for: " + password)` |
| F7 | A logging API reference is **still present in the final release APK's bytecode** (confirmed via Method E) when it should have been stripped, indicating ProGuard/R8 was not properly configured | The number of `Log.*` calls in the release APK does not decrease significantly from the original source |

**Example evidence (illustrative — MASTG does not yet provide an official demo for this test):**

```java
// Found in com/example/target/AuthManager.java (jadx decompilation result)
public class AuthManager {
    private static final String TAG = "AuthManager";

    public void login(String username, String password) {
        Log.d(TAG, "Attempting login for user=" + username + " pass=" + password);  // line 42
        // ...
        try {
            performLogin(username, password);
        } catch (IOException e) {
            e.printStackTrace();   // line 47 — check whether the exception carries a sensitive payload
        }
    }
}
```

```bash
$ rg -n "Log\.\w+\(" ./decompiled/sources/com/example/target/AuthManager.java
42:        Log.d(TAG, "Attempting login for user=" + username + " pass=" + password);
$ rg -n "printStackTrace" ./decompiled/sources/com/example/target/AuthManager.java
47:            e.printStackTrace();
```

Interpretation: line 42 explicitly concatenates the `password` variable into the log message — **FAIL** with strong evidence directly from the source code, without needing runtime confirmation since the variable is already clear from its name **and** its function's context (`login`).

---

#### ✅ PASS — The check is declared PASSED if:

| No | Condition | Example evidence |
|---|---|---|
| P1 | **No** logging API call is found at all in the code (after verifying ProGuard/R8 has stripped everything for the release build) | `rg` results on the final release APK are empty or already stripped |
| P2 | A logging API call is found, but the recorded variable **only contains non-sensitive operational data** | `Log.i(TAG, "Network request completed in " + elapsed + "ms")` |
| P3 | `printStackTrace()` is found, but only called on an exception **proven not to carry sensitive data** in its message/causal chain | A generic network timeout exception with no payload |
| P4 | The logging call is **wrapped** in a `BuildConfig.DEBUG` condition and proven to genuinely disappear in the release build (verified by Method E) | `if (BuildConfig.DEBUG) { Log.d(TAG, "token=" + token); }` **and** this reference is confirmed stripped in the final release APK |
| P5 | All logged values already go through a **redaction/masking** mechanism before being recorded | `Log.d(TAG, "user=" + user.toString())` where `toString()` is overridden to return `"User(email=XX)"` |

**Example output indicating PASS:**

```bash
$ rg -n "Log\.\w+\(|System\.(out|err)\.print|printStackTrace" ./decompiled_release/sources/
# (no result — everything already stripped in the release build, confirmed by Method E)
```

Or — a call is found, but it's clean of sensitive data:

```java
Log.i(TAG, "onCreate: activity started");
Log.e(TAG, "Network error", genericIOException);   // generic exception message, verified to carry no payload
```

---

#### ⚠️ Important Notes on Assessment

1. **This test demands context analysis — not merely the presence of an API.** As emphasized in §1.3, finding an API call's location is only the **first step**. The FAIL/PASS criterion depends entirely on what the variable carries into that call — this requires MASTG-TECH-0023 as an inseparable part of the evaluation, even though it is not stated as a separate formal step in this test's overview.

2. **A variable's name is a strong clue, but not absolute proof.** A variable named `password` being logged is almost certainly a legitimate finding. But a generically-named variable (`data`, `value`, `result`) that actually holds a token still needs to be checked by tracing data flow (MASTG-TECH-0023 or Method C's CodeQL) — don't filter solely based on a keyword search of variable names.

3. **The difference between source code and release bytecode strongly affects a finding's validity.** A static test is ideally run on the **final release APK**, not development source code. If you only have access to source code (white-box audit) without a built release APK, explicitly note in the report that this finding **could potentially be irrelevant** if the dev team has already applied `-assumenosideeffects` per MASTG-BEST-0002 — this verification matters so as not to overstate the risk.

4. **`printStackTrace()` is often overlooked because it doesn't obviously carry a "sensitive variable."** Yet the exception message and its causal chain can contain unexpected detail — a full URL with a query parameter containing a token, a fragment of a request/response payload that an HTTP library inserted into the error message. Don't underestimate a `printStackTrace()` finding just because its argument is empty (`e.printStackTrace()` with no explicit parameter).

5. **Supplement with MASTG-TEST-0203 for runtime value confirmation.** This static test excels at coverage but is weak on value certainty. For ambiguous static findings (unclear variable names, complex data flow), run MASTG-TEST-0203 with a canary value to get definitive runtime evidence — see the combined workflow in §1.4.

6. **Don't forget API variants not explicitly named in the overview (Timber, SLF4J, etc.).** As explained in depth in MASTG-TEST-0203 §1.4 Group B, the six officially-named MASTG APIs are not a complete list of a modern app's entire logging surface. The custom rule (§3.3) already covers Timber as an example, but adjust it to the libraries actually used by the target app (checked via the dependency manifest/build.gradle if available).

7. **Empty output does not always mean an unqualified PASS.** If the grep result is empty due to **heavy obfuscation**, code **loaded dynamically** (DexClassLoader), or **native code** calling `__android_log_print` directly (outside the scope of Java/Kotlin analysis), note it as an analysis limitation, not an unconditional PASS conclusion.

8. **Severity is modulated by data type and code execution context:**

   | Factor | Severity |
   |---|---|
   | Password/token/cryptographic key logged in code guaranteed to execute on the main flow (login, transaction) | **High** |
   | PII logged on the main flow | **High** (+ a privacy dimension, profile P) |
   | Sensitive data logged only in a `catch` block for a rarely-occurring error | **Medium** — still a FAIL, but with lower exploitation likelihood |
   | An API reference found in source but proven to be perfectly stripped in the release build (Method E) | **Not a finding for production risk** — note as a potential issue if `-assumenosideeffects` is ever removed in the future |
   | Only generic operational messages (lifecycle, timing) are logged | **Not a finding** |

9. **Document:** the code location (file + line) from the decompilation, **the quoted interpolated variable** along with the tracing of its origin, whether it was confirmed via MASTG-TEST-0203 (actual runtime value) or only via static inference (variable name/context), the status of the build tested (source/debug/release), and the ProGuard/R8 configuration verification result if relevant.

---

## 4. Recommendations

Since the root cause is identical to MASTG-TEST-0203 (the same MASWE-0005), all the in-depth recommendations — including ProGuard/R8 stripping strategy, a custom logging facility, redaction/masking techniques, and the important warning about strings left behind in the bytecode even after a `Log` call is stripped — **have already been covered in full in the MASTG-TEST-0203 document, §4**. Refer to that document for full implementation detail.

A summary of priorities specifically relevant to the **static** viewpoint:

**Priority 1 — Don't log sensitive data in the first place** (see MASTG-TEST-0203 §4.1 for the full list of categories to avoid).

**Priority 2 — Apply `-assumenosideeffects` in ProGuard/R8**, and **verify the result** with Method E above — don't just assume the configuration works because it's written in `proguard-rules.pro`. Compare the number of logging API references between the source code and the final release APK's bytecode.

**Priority 3 — For dynamically-built strings, use a custom logging facility** with simple arguments that can be fully stripped, per the detailed example in MASTG-TEST-0203 §4.1 (`SecureLog.v("prefix: ", key)` as a replacement for direct concatenation).

**Priority 4 — Integrate this static test into CI/CD** as a regression check, run on every **release** build (not just debug), to catch regressions introduced by dependency changes or new code before they reach production:

```bash
#!/bin/bash
# ci-check-logging-refs.sh — run on the built RELEASE APK
APK=$1
jadx -d /tmp/decompiled_check "$APK" 2>/dev/null
COUNT=$(rg -c "Log\.(v|d|i|w|e|wtf)\(|printStackTrace\(\)" /tmp/decompiled_check/sources/ 2>/dev/null | awk -F: '{sum+=$2} END {print sum+0}')
if [ "$COUNT" -gt "0" ]; then
    echo "[WARNING] Found $COUNT logging API references in the RELEASE APK — verify whether this complies with policy (non-sensitive operational logging) or needs further stripping"
fi
```

**Priority 5 — Audit third-party libraries** whose dependencies are bundled into the APK, since logging references from vendor SDKs are not always obviously recognizable as part of the app's own code when first reading the decompilation result.

### 4.2 Remediation Checklist

- [ ] All logging API references (`Log`, `Logger`, `System.out/err.print`, `printStackTrace`) in the code have been identified through thorough static analysis
- [ ] Every reference has been reviewed with MASTG-TECH-0023 to determine the interpolated variable and its origin
- [ ] References carrying sensitive data (credentials, PII, keys) have been removed or wrapped in a redaction mechanism
- [ ] The ProGuard/R8 `-assumenosideeffects` configuration for `android.util.Log` has been applied and **verified** on the final release APK's bytecode (not merely assumed from the configuration file)
- [ ] Dynamically-built strings for log parameters are confirmed not left behind in the bytecode after stripping (a custom logging facility applied where needed)
- [ ] `printStackTrace()` has been reviewed to ensure handled exceptions don't carry a sensitive payload in the message/causal chain
- [ ] Third-party libraries (Timber, SLF4J, etc.) have also been checked for additional logging references
- [ ] Static findings have been cross-checked with MASTG-TEST-0203 for runtime value confirmation on ambiguous cases
- [ ] This static test is integrated as a regression check in CI/CD, run on the release build
- [ ] **Re-verify:** rerun MASTG-TEST-0231 on the final release APK after every code/dependency change
- [ ] **Cross-verify:** run MASTG-TEST-0203 (dynamic) to ensure no sensitive value is actually logged at runtime

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0231: References to Logging APIs](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0231/)
- [MASTG-TEST-0203: Runtime Use of Logging APIs](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0203/)
- [MASTG-TEST-0003: Testing Logs for Sensitive Data](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0003/) *(deprecated — superseded by MASTG-TEST-0203 & 0231)*
- [MASWE-0005: Insertion of Sensitive Data into Logs](https://mas.owasp.org/MASWE/MASVS-STORAGE/MASWE-0005/)
- [MASTG-KNOW-0049: Logs](https://mas.owasp.org/MASTG/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0049/)
- [MASTG-BEST-0002: Remove Logging Code](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0002/)
- [MASTG-TECH-0013: Reverse Engineering Android Apps](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/)
- [MASTG-TECH-0014: Static Analysis on Android](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/)
- [MASTG-TECH-0023: Reviewing Decompiled Java Code](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0023/)
- [MASTG-TOOL-0022: ProGuard](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0022/)
- [MASVS-STORAGE: Storage](https://mas.owasp.org/MASVS/05-MASVS-STORAGE/)
- [OWASP MASTG Repository (GitHub)](https://github.com/OWASP/mastg)
- [OWASP Mobile Top 10 2024 — M9: Insecure Data Storage](https://owasp.org/www-project-mobile-top-10/2023-risks/m9-insecure-data-storage)
- [OWASP Mobile Top 10 2024 — M1: Improper Credential Usage](https://owasp.org/www-project-mobile-top-10/2023-risks/m1-improper-credential-usage.html)

### 5.2 Official Android / Google Documentation

- [Log Info Disclosure — Android Security Risks](https://developer.android.com/privacy-and-security/risks/log-info-disclosure)
- [`android.util.Log` — API reference](https://developer.android.com/reference/kotlin/android/util/Log)
- [`java.util.logging.Logger` — API reference](https://developer.android.com/reference/java/util/logging/Logger)
- [Shrink, obfuscate, and optimize your app (R8/ProGuard)](https://developer.android.com/build/shrink-code)
- [ProGuard manual — example of removing logging code (Guardsquare)](https://www.guardsquare.com/en/products/proguard/manual/examples#logging)
- [App security best practices](https://developer.android.com/privacy-and-security/security-best-practices)

### 5.3 Standards, Taxonomy, and Other Guidelines

- [CWE-532: Insertion of Sensitive Information into Log File](https://cwe.mitre.org/data/definitions/532.html)
- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
- [CWE-312: Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)
- [CWE-359: Exposure of Private Personal Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/359.html)
- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
- [NIST SP 800-163 Rev.1 — Vetting the Security of Mobile Applications](https://csrc.nist.gov/publications/detail/sp/800-163/rev-1/final)

### 5.4 Tool Documentation

- [Semgrep — Documentation](https://semgrep.dev/docs/)
- [CodeQL — Documentation](https://codeql.github.com/docs/)
- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [apktool — Reverse engineering Android APK files](https://apktool.org/)
- [MobSF — Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)
- [mobsfscan](https://github.com/MobSF/mobsfscan)
- [Timber — logging library (JakeWharton)](https://github.com/JakeWharton/timber)

---

*This document was prepared based on OWASP MASTG (current release as of September 2026), official Android Developers documentation. This test does not yet have an official demo (MASTG-DEMO) from MASTG, and is the static counterpart of MASTG-TEST-0203 — refer to that document for an in-depth discussion of the logging risk landscape, leakage paths, and the complete remediation strategy.*
