# MASTG-TEST-0227 Debugging Enabled for WebViews

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0227 |
| **Platform** | Android |
| **MASVS Category** | **MASVS-RESILIENCE** (Resilience Against Reverse Engineering and Tampering) |
| **Weakness** | **MASWE-0063** — *Debug Mechanisms Not Disabled* (same weakness as MASTG-TEST-0226) |
| **Test Type** | **Static**, Code |
| **Profile** | **R** (Resilience) |
| **Knowledge** | MASTG-KNOW-0028 (Anti-Debugging) |
| **Best Practice** | MASTG-BEST-0008 (Debugging Disabled for WebViews) |
| **Related Techniques** | MASTG-TECH-0013 (Reverse Engineering Android Apps), MASTG-TECH-0014 (Static Analysis on Android) |
| **Related Demo** | — (MASTG does not yet provide a demo for this test) |
| **Sibling Test** | **MASTG-TEST-0226** (Debuggable Flag Enabled) — same weakness, different object: manifest vs. WebView runtime API |
| **Key APIs** | `android.webkit.WebView.setWebContentsDebuggingEnabled(boolean)`, `android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE` |
| **Related CWE** | CWE-489 (Active Debug Code), CWE-215 (Insertion of Sensitive Information Into Debugging Code), CWE-1244 (Internal Asset Exposed to Unsafe Debug Access) |

---

## 1. Explanation

### 1.1 Testing Objective

Direct quote from the MASTG overview:

> *"The `WebView.setWebContentsDebuggingEnabled(true)` API enables debugging for **all** WebViews in the application. This feature can be useful during development, but introduces significant security risks if left enabled in production. When enabled, a connected PC can **debug, eavesdrop, or modify communication** within any WebView in the application."*
>
> *"Note that this flag works **independently** of the `debuggable` attribute (`ApplicationInfo.FLAG_DEBUGGABLE`) in the `AndroidManifest.xml` (see MASTG-TEST-0226). **Even if the app is not marked as debuggable, the WebViews can still be debugged** by calling this API."*

The second point is **the most important thing to understand** before moving forward — this is not merely a variant of MASTG-TEST-0226, but a **completely independent risk path**. An application can pass MASTG-TEST-0226 perfectly (`android:debuggable="false"` in the manifest) and **still FAIL** this test, because `setWebContentsDebuggingEnabled(true)` is a separate runtime API that does not depend at all on that manifest flag.

### 1.2 What an Attacker Can Actually Do

`setWebContentsDebuggingEnabled(true)` enables **Chrome DevTools remote debugging** for all WebView instances within the application (available since Android 4.4 KitKat). Once active, any debuggable WebView will appear on the `chrome://inspect` page of a computer connected to the device (via USB with ADB debugging enabled) — and from there, anyone who opens DevTools gets **full browser-level access** to that WebView's content:

| DevTools Protocol Capability | Security Impact |
|---|---|
| **DOM inspection & modification** | View/modify the structure of pages rendered by the WebView in real time |
| **Arbitrary JavaScript execution** within the WebView context | Call internal functions, manipulate the web app state running inside the WebView, trigger a JavaScript bridge (`addJavascriptInterface`) that might be exposed to native code |
| **WebView network traffic monitoring** | View requests/responses sent by the WebView, including headers and bodies — potentially including authentication tokens if the WebView is used for a login/OAuth flow |
| **Client-side storage access** | Cookies, `localStorage`, `sessionStorage`, IndexedDB used by the WebView — often containing session tokens |
| **JavaScript breakpoints** | Halt execution to analyze business logic implemented on the web side (relevant for WebViews running payment/verification modules) |

This is exactly the capability available to a legitimate developer debugging their own WebView during development — and **there is no difference** in capability between a legitimate developer and an attacker who has successfully connected to the target device, as long as this flag is enabled.

### 1.3 Realistic Attack Scenarios

MASTG-BEST-0008 is honest about the prerequisites an attacker needs, so the risk assessment remains proportionate:

> *"For an attacker to exploit WebView debugging, they must have **physical access** to the device (e.g., a stolen or test device) or **remote access through malware** or other malicious means. Additionally, the device must typically be **unlocked**, and the attacker would need to know the device PIN, password, or biometric authentication to gain full control and connect debugging tools like `adb` or Chrome DevTools."*

This context matters: exploiting this test is **not** a purely remote attack with no prerequisites — it requires one of the following:
- **Physical access to an unlocked device** with USB debugging enabled (a stolen device, a test device left unattended, a kiosk/POS device accessed without supervision), **or**
- **Malware or other remote access** that has already compromised the device and can forward the debugging port.

Nevertheless, this scenario is **highly relevant** for certain categories of applications:
- **Banking/payment applications** that use a WebView for third-party checkout pages (3D Secure, payment gateway) — this is where payment tokens and card data pass through.
- Applications with **WebView-based SSO/OAuth login** — access tokens can be stolen directly from the `localStorage`/cookies visible in DevTools.
- **Enterprise/BYOD applications** where the device can be lost/stolen and contains a WebView rendering sensitive internal documents.
- **"Evil maid" scenarios** — an attacker with brief physical access to an unlocked device (e.g., while the owner is distracted) can enable USB debugging if not already active, then directly inspect the WebView without needing root or any exploit.

### 1.4 Why This Is Separate from MASTG-TEST-0226

A comparison table to clarify the relationship between these two sibling tests:

| | MASTG-TEST-0226 | MASTG-TEST-0227 *(this document)* |
|---|---|---|
| **Object examined** | Static `android:debuggable` attribute in `AndroidManifest.xml` | Runtime API call `WebView.setWebContentsDebuggingEnabled()` within the code |
| **Impact scope** | **The entire application process** can be attached to by a Java debugger (JDWP) | **Only the WebView** can be inspected via the Chrome DevTools Protocol — a narrower surface, but still significant if the WebView handles sensitive data |
| **Dependency** | Standalone — manifest attribute value | **Independent of MASTG-TEST-0226** — this API works regardless of the `debuggable` status |
| **Detection method** | Read a single manifest attribute | Code analysis to find the **context of the call** (unconditional vs. conditional) |
| **Evaluation complexity** | Simple binary (`true`/`false`) | **Requires context analysis** — a `true` value alone is not enough for a verdict; it must be checked whether it is wrapped in a `FLAG_DEBUGGABLE` check |

The last point is the most significant methodological difference: MASTG-TEST-0226 purely reads an attribute value, while this test requires **understanding the code flow surrounding the API call** — approaching the testing style of earlier crypto tests (MASTG-TEST-0204/0205), which also required context verification rather than simple pattern matching.

### 1.5 Correct Code Pattern (Baseline for Assessing Context)

MASTG-BEST-0008 provides an explicit example of a pattern considered correct:

```kotlin
if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT) {
    if (0 != (getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE))
    { WebView.setWebContentsDebuggingEnabled(true); }
}
```

This pattern **wraps** the `setWebContentsDebuggingEnabled(true)` call with a check on `ApplicationInfo.FLAG_DEBUGGABLE` — so WebView debugging is only enabled **when the application itself is also debuggable** (i.e., on development builds, not release builds). On a standard release build (`debuggable=false`), this condition is never satisfied, so the `setWebContentsDebuggingEnabled(true)` line is never executed.

This is why the **MASTG overview explicitly mentions `ApplicationInfo.FLAG_DEBUGGABLE`** as part of the Observation step — the presence of this check around the API call is what distinguishes safe code from unsafe code.

### 1.6 Limits of the Mitigation — Explicitly Acknowledged by MASTG

Just as with the pattern in MASTG-TEST-0226, MASTG-BEST-0008 asserts that disabling WebView debugging is **not an absolute protection**:

> *"However, disabling WebView debugging **does not eliminate all attack vectors**. An attacker could:*
> 1. *Patch the app to add calls to these APIs, then repackage and re-sign it.*
> 2. *Use runtime method hooking (Frida) to enable WebView debugging dynamically at runtime.*
>
> *Disabling WebView debugging serves as **one layer of defense** to reduce risks but should be combined with other security measures."*

A sufficiently sophisticated attacker can:
- **Perform binary patching** on the APK to insert their own call to `setWebContentsDebuggingEnabled(true)`, then repackage and re-sign it with their own key (linked to MASTG-TEST-0224/0225 — a strong signature scheme does not prevent repackaging, it only detects that the result is not the genuine APK).
- **Use Frida** to call this API directly at runtime, bypassing the application code entirely — no matter how strict the `FLAG_DEBUGGABLE` check is in the original code, because Frida operates outside the code flow being examined.

This again reinforces the same theme as MASTG-TEST-0226: flag-based controls are a **first layer**, not a single solution, especially for R-profile applications that require higher resilience.

---

## 2. Tools Used for Testing

### 2.1 Mandatory Tools (Core)

| Tool | MASTG ID | Function |
|---|---|---|
| **jadx** | MASTG-TOOL-0018 | **Decompile DEX → Java** (MASTG-TECH-0013). Required to read the **context** of the API call — not just its presence |
| **grep / ripgrep** | — | Pattern search on decompiled code. **Primary method**, since MASTG does not provide an official semgrep rule for this test |
| **apktool** | MASTG-TOOL-0011 | Decompilation alternative; smali analysis when needed |

### 2.2 Alternative & Supporting Tools

| Tool | Function |
|---|---|
| **semgrep** | No official MASTG rule exists — a custom rule is needed (§3.3) to detect calls **without** a surrounding `FLAG_DEBUGGABLE` check |
| **CodeQL** | Taint/control-flow analysis — can programmatically verify whether the API call sits inside a conditional branch that checks `FLAG_DEBUGGABLE` |
| **MobSF** | Automated analysis, can flag `setWebContentsDebuggingEnabled(true)` calls as a finding in the APK report |
| **adb + Chrome DevTools (`chrome://inspect`)** | **The most convincing dynamic confirmation** — proves the WebView can actually be inspected externally on a running application (§3.5) |
| **Frida** | For testing the resilience of the mitigation (§1.6) — attempting to force-enable this flag via hooking even though the source code already wraps it correctly |

### 2.3 Environment Prerequisites

- **No device and no root required** for basic static checks — just the APK file is enough.
- **For dynamic confirmation** (§3.5), a device/emulator with USB debugging enabled is needed — root is not required.
- **Note that this API has been available since Android 4.4 (API 19/KitKat)** — code that checks `Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT` before calling this API is a normal pattern for backward compatibility, **not** an indication of a vulnerability in itself.
- **Test the final distributed APK**, consistent with the approach used for other sibling tests in MASVS-RESILIENCE.

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0013** (*Reverse Engineering Android Apps*) to reverse engineer the application.
2. Use **MASTG-TECH-0014** (*Static Analysis on Android*) to search for the relevant API.

### 3.2 Method A — grep/ripgrep on Decompiled Code *(primary method, no official rule)*

```bash
jadx -d ./decompiled ./target-app.apk
D=./decompiled/sources

# --- 1. Find ALL calls to setWebContentsDebuggingEnabled ---
rg -n --no-heading "setWebContentsDebuggingEnabled" $D

# --- 2. For each result, show the surrounding CONTEXT (10 lines before) ---
#     This is the crucial step: a true value ALONE is not enough for a verdict
rg -n -B10 "setWebContentsDebuggingEnabled\s*\(\s*true\s*\)" $D

# --- 3. Search for references to FLAG_DEBUGGABLE as a comparison ---
#     (explicitly mentioned as part of the Observation section in the MASTG overview)
rg -n --no-heading "FLAG_DEBUGGABLE" $D
```

**How to read the results of Step 2** — this is the core of this test's manual assessment:

```java
// ✅ SAFE PATTERN — a FLAG_DEBUGGABLE check wrapping the call was found
if ((getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0) {
    WebView.setWebContentsDebuggingEnabled(true);   // <-- only runs if the app is debuggable
}

// ❌ UNSAFE PATTERN — called UNCONDITIONALLY, with no check at all
WebView.setWebContentsDebuggingEnabled(true);        // <-- always active, including in release

// ❌ UNSAFE PATTERN — wrapped in a condition that is NOT RELEVANT to debuggability
if (BuildConfig.ENABLE_LOGGING) {                    // <-- this is a logging flag, NOT FLAG_DEBUGGABLE!
    WebView.setWebContentsDebuggingEnabled(true);
}
```

> Note the third pattern — this is a mistake that is often missed: a developer wraps the call with a condition that **looks safe** (e.g., `BuildConfig.DEBUG`, a custom internal flag) but is **not** the `ApplicationInfo.FLAG_DEBUGGABLE` that MASTG actually requires. It is worth checking further whether `BuildConfig.DEBUG` truly always aligns with debuggable status on the final release build — in practice this is **generally safe** because the Android Gradle Plugin synchronizes `BuildConfig.DEBUG` with the build type, but this is an assumption that needs to be verified, not simply accepted (see the assessment note in §3.7).

### 3.3 Method B — semgrep with a Custom Rule *(CI/CD gate, automated context control)*

```yaml
rules:
  - id: custom-webview-debugging-unconditional
    severity: ERROR
    languages: [java, kotlin]
    message: "[MASVS-RESILIENCE] setWebContentsDebuggingEnabled(true) called without a detectable FLAG_DEBUGGABLE check in this simple pattern — manual verification still required"
    patterns:
      - pattern: android.webkit.WebView.setWebContentsDebuggingEnabled(true)
      - pattern-not-inside: |
          if (...) {
            ...
            android.webkit.WebView.setWebContentsDebuggingEnabled(true);
            ...
          }

  - id: custom-webview-debugging-any-call
    severity: INFO
    languages: [java, kotlin]
    message: "[MASVS-RESILIENCE] A call to setWebContentsDebuggingEnabled was found — manually verify the FLAG_DEBUGGABLE check context"
    pattern: android.webkit.WebView.setWebContentsDebuggingEnabled(...)
```

```bash
semgrep -c ./webview-debug-rules.yml ./decompiled/sources/
```

> **Limitation of the semgrep pattern above:** the `custom-webview-debugging-unconditional` rule only detects the **structural absence of a surrounding `if` block** — it cannot verify that the **content** of that condition actually checks `FLAG_DEBUGGABLE` and is not some other, irrelevant condition (the third pattern in §3.2). Use the `custom-webview-debugging-any-call` rule (severity INFO) to catch all candidates, then **always perform manual verification** on every result before marking it FAIL/PASS — this is one of the tests where pure automation is not enough, and manual review (MASTG-TECH-0023-style) is truly mandatory.

### 3.4 Method C — CodeQL *(programmatically verifies the condition)*

This is the method closest to a genuinely reliable automated verification of conditional context, because CodeQL understands the *control flow graph*, not just a textual pattern.

```ql
/**
 * @name WebView debugging enabled without FLAG_DEBUGGABLE guard
 * @kind problem
 * @problem.severity warning
 */
import java

from MethodAccess ma, IfStmt ifStmt
where
  ma.getMethod().hasName("setWebContentsDebuggingEnabled") and
  ma.getAnArgument().(BooleanLiteral).getBooleanValue() = true and
  (
    // Not inside any if block
    not exists(IfStmt enclosing | ma.getEnclosingStmt().getEnclosingStmt*() = enclosing)
    or
    // Inside an if, but the condition does not reference FLAG_DEBUGGABLE
    (
      ma.getEnclosingStmt().getEnclosingStmt*() = ifStmt and
      not ifStmt.getCondition().toString().matches("%FLAG_DEBUGGABLE%")
    )
  )
select ma, "setWebContentsDebuggingEnabled(true) called without a clear FLAG_DEBUGGABLE guard"
```

```bash
codeql database create ./cqldb --language=java --command="./gradlew assembleDebug"
codeql database analyze ./cqldb ./webview-debug-query.ql --format=sarif-latest --output=result.sarif
```

### 3.5 Method D — Dynamic Confirmation with Chrome DevTools *(the most convincing proof of exploitability)*

This method elevates a static finding into **proof of real impact** — highly recommended for pentest reporting.

```bash
# 1. Install and run the target application
adb install -r YourApp.apk
adb shell am start -n com.example.target/.MainActivity

# 2. Open Chrome on a computer connected to the device via USB
#    Navigate to: chrome://inspect/#devices

# 3. If the application's WebView is debuggable, it will appear in the list
#    with an "inspect" option -> opens full DevTools connected to that WebView
```

**Verification from the command line** (without manually opening Chrome), by checking the open debug socket:

```bash
# The abstract socket webview_devtools_remote_<pid> indicates WebView debugging is active
adb shell cat /proc/net/unix | grep webview_devtools_remote

# Or via port forwarding and curling the DevTools Protocol JSON endpoint
adb forward tcp:9222 localabstract:webview_devtools_remote_<pid>
curl http://localhost:9222/json
# If WebView debugging is active, this returns a list of debuggable targets
```

> If the command above returns a JSON list containing WebView targets (not connection refused/empty), this is **definitive proof** that `setWebContentsDebuggingEnabled(true)` is active on the running instance of the application — complementing the static finding with runtime confirmation.

### 3.6 Method E — MobSF

```bash
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest
```

Upload the APK → the **Code Analysis** section looks for a pattern such as *"WebView debugging is enabled"* or similar if MobSF detects this API call in the code. Note that MobSF, like most automated scanners, **likely cannot reliably verify conditional context** — its results still need manual verification per §3.2.

### 3.7 Method Comparison: When to Use Which

| Method | Tool | Verifies conditional context? | Needs a device? | Proves real exploitability? | When to use |
|---|---|---|---|---|---|
| **A** | grep/ripgrep + manual review | Manual (mandatory) | No | ❌ | **Primary baseline** — no official rule exists, manual review is unavoidable |
| **B** | custom semgrep | Partial (structural, not semantic) | No | ❌ | CI/CD gate as an initial filter, not a final verdict |
| **C** | CodeQL | ✅ **(most reliably automated)** | No | ❌ | Programmatic verification of conditional context |
| **D** | Chrome DevTools / socket check | — | **Yes** | ✅ **(key)** | **The most convincing pentest evidence** |
| **E** | MobSF | ❌ | No | ❌ | Quick initial triage |

**Minimum combination recommended:** **A (grep + manual review) always**, because there is no fully reliable shortcut for automatically verifying conditional context with perfect accuracy. Use **C (CodeQL)** when source code is available, to reduce manual review burden on large applications. Add **D (DevTools/socket)** whenever a FAIL is found, to confirm impact and strengthen the pentest report with concrete evidence, not just a code quotation.

---

### 3.8 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rule:**

> **Observation:** *"The output should list: All locations where `WebView.setWebContentsDebuggingEnabled` is called with `true` at runtime. Any references to `ApplicationInfo.FLAG_DEBUGGABLE`."*
>
> **Evaluation:** *"The test case **fails** if `WebView.setWebContentsDebuggingEnabled(true)` is called **unconditionally** or in contexts where the `ApplicationInfo.FLAG_DEBUGGABLE` flag **is not checked**."*

Note that the FAIL criteria have **two conditions, either of which alone is sufficient** to cause a FAIL (not both at once):
1. Called **unconditionally**, **OR**
2. Called within a conditional context, but the condition **does not check** `FLAG_DEBUGGABLE`.

---

#### ❌ FAIL / ISSUE — The check is declared FAILED if:

| No | Condition | Example evidence |
|---|---|---|
| F1 | `setWebContentsDebuggingEnabled(true)` is called **without** any wrapping condition at all | `WebView.setWebContentsDebuggingEnabled(true);` standing alone, e.g., directly inside `onCreate()` |
| F2 | Called inside an `if` that references a flag/condition **other than** `FLAG_DEBUGGABLE` | Wrapped in `BuildConfig.ENABLE_WEBVIEW_DEBUG` (a custom flag) that is **not** synchronized with the application's debuggable status |
| F3 | Called inside an `if` that checks `FLAG_DEBUGGABLE`, but with **inverted logic** (enabling debugging precisely when `FLAG_DEBUGGABLE` is `false`) | A negation logic error — rare, but must be actually checked, not assumed correct just because the variable name looks right |
| F4 | Chrome DevTools / socket check (§3.5) confirms WebView debugging is active on the **final release APK** that was installed | `curl http://localhost:9222/json` returns a list of WebView targets on the production APK |
| F5 | A wrapping condition exists, but can be bypassed or is always `true` due to a build misconfiguration (e.g., `BuildConfig.DEBUG` mistakenly remaining `true` on a release build due to a pipeline error) | Found via final APK verification — linked to the note in MASTG-TEST-0226 about the importance of testing the final artifact |

**Example evidence (illustrative — MASTG does not yet provide an official demo for this test):**

```java
// Found in com/example/target/MainActivity.java, line 42 (jadx decompilation result)
public class MainActivity extends AppCompatActivity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        WebView.setWebContentsDebuggingEnabled(true);   // <-- UNCONDITIONAL, no check whatsoever
        WebView webView = findViewById(R.id.webview);
        webView.loadUrl("https://payment.example.com/checkout");
    }
}
```

```bash
$ rg -n -B10 "setWebContentsDebuggingEnabled\s*\(\s*true\s*\)" ./decompiled/sources/
com/example/target/MainActivity.java-40-    protected void onCreate(Bundle savedInstanceState) {
com/example/target/MainActivity.java-41-        super.onCreate(savedInstanceState);
com/example/target/MainActivity.java:42:        WebView.setWebContentsDebuggingEnabled(true);
```

Interpretation: the call sits **directly** in `onCreate()` with no wrapping condition at all, and the WebView being debugged loads a **payment checkout** page → **FAIL** with high severity, because payment tokens and sensitive transaction data could potentially be exposed via DevTools on an unlocked device with ADB enabled.

Verification of real impact:

```bash
$ adb install -r TargetApp-release.apk
$ adb shell am start -n com.example.target/.MainActivity
$ adb forward tcp:9222 localabstract:webview_devtools_remote_12345
$ curl http://localhost:9222/json
[
  {
    "description": "",
    "devtoolsFrontendUrl": "...",
    "title": "Checkout - Example Payment",
    "type": "page",
    "url": "https://payment.example.com/checkout",
    "webSocketDebuggerUrl": "ws://localhost:9222/devtools/page/..."
  }
]
```

Interpretation: the WebView containing the checkout page **can actually be debugged** on the installed release APK — concrete proof that the static finding has a real, exploitable impact.

---

#### ✅ PASS — The check is declared PASSED if:

| No | Condition | Example evidence |
|---|---|---|
| P1 | `setWebContentsDebuggingEnabled` is **never called** anywhere in the application code (no WebView debugging is enabled at all) | `rg "setWebContentsDebuggingEnabled"` → no results |
| P2 | Called with `true`, but **wrapped** in a correct `ApplicationInfo.FLAG_DEBUGGABLE` check whose logic has been verified | Matches the official MASTG-BEST-0008 pattern |
| P3 | Called with the explicit argument `false` (explicitly disabled, even though the default is already `false`) | `WebView.setWebContentsDebuggingEnabled(false);` |
| P4 | Chrome DevTools / socket check (§3.5) **confirms** the WebView cannot be inspected on the final release APK | `curl http://localhost:9222/json` → connection refused / no target |

**Example output indicating PASS:**

```bash
$ rg -n "setWebContentsDebuggingEnabled" ./decompiled/sources/
# (no results at all)
```

Or — called with the correct check:

```java
// com/example/target/MainActivity.java
if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT) {
    if (0 != (getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE)) {
        WebView.setWebContentsDebuggingEnabled(true);
    }
}
```

Dynamic verification on the final release APK:

```bash
$ adb forward tcp:9222 localabstract:webview_devtools_remote_12345
$ curl http://localhost:9222/json
curl: (7) Failed to connect to localhost port 9222: Connection refused
```

Interpretation: the `FLAG_DEBUGGABLE` condition is verified to exist in the code, **and** dynamically confirmed that no debug socket is open on the release APK → **PASS**, with double evidence (static + dynamic).

---

#### ⚠️ Important Assessment Notes

1. **This is a test that demands manual context verification — not just binary pattern matching.** Unlike MASTG-TEST-0226, which purely reads a single attribute value, here the **mere presence** of an API call with `true` **is not enough** for a FAIL verdict. It is mandatory to read the wrapping condition (if any) and verify that the condition truly refers to `ApplicationInfo.FLAG_DEBUGGABLE`, and not some other flag that looks similar by name but differs in function.

2. **Do not assume `BuildConfig.DEBUG` is always equivalent to `FLAG_DEBUGGABLE`.** Although in practice the standard Android Gradle Plugin synchronizes the two, the MASTG evaluation criteria specifically name `ApplicationInfo.FLAG_DEBUGGABLE` — if an application uses `BuildConfig.DEBUG` or another custom flag instead, note this as a **finding requiring additional verification** of build pipeline consistency, rather than automatically accepting it as an equivalent pattern.

3. **Independence from MASTG-TEST-0226 means both tests MUST be run separately, not assumed to be correlated.** Never conclude "MASTG-TEST-0226 already passed, so this test must also pass" — both test entirely different code paths and are not dependent on one another.

4. **Semgrep/other static tools can only catch structural patterns, not semantic ones.** The custom rule in §3.3 can detect "is there an `if` surrounding it or not," but **cannot read the meaning** of that condition. CodeQL (Method C) is somewhat better because it understands *control flow*, but a final manual verification is still recommended for full certainty.

5. **Prove impact with Chrome DevTools/socket checks when possible (within the permitted scope).** This is another test where MASTG directly acknowledges that the static finding is "not a direct vulnerability" without additional prerequisites (physical access + unlocked device, per MASTG-BEST-0008) — so proof of real impact significantly strengthens the credibility of the report, especially for WebViews that handle sensitive data (payment, SSO).

6. **Prioritize review of WebViews that handle sensitive data.** If an application has multiple WebViews for different purposes (non-sensitive help/FAQ vs. payment checkout), finding severity must be differentiated based on the **content and function** of the exposed WebView — not treated uniformly just because the same API was called.

7. **Severity is modulated by application context and WebView function:**

   | Factor | Severity |
   |---|---|
   | WebView handling payment/checkout/SSO with debugging enabled unconditionally | **High** |
   | Non-sensitive WebView (e.g., static help page) with debugging enabled unconditionally | **Medium** |
   | Confirmed dynamically (DevTools/socket) to be actually inspectable on a production APK | **Raise severity** — impact proven, not just potential |
   | Wrapped in an incorrect/irrelevant condition (F2) | **High** — false sense of security for developers |
   | Correctly wrapped in `FLAG_DEBUGGABLE`, or never called at all | **Not a finding** |

8. **Document:** the code location (file + line) from the decompilation result, **the complete conditional context quotation** (not just the API call line itself), the function/purpose of the affected WebView (payment/SSO/general content), dynamic verification results (DevTools/socket) if performed, and whether the APK tested was a final or internal build.

---

## 4. Recommendations

### 4.1 Core Principle (MASTG-BEST-0008)

**Priority 1 — Remove this API call entirely if not needed in production.** The simplest and most error-resistant solution:

```kotlin
// ✅ SAFEST — no call at all in the shipped code
// (remove this line entirely from production code if it was only used for development debugging)
```

**Priority 2 — If WebView debugging is still needed for development purposes, wrap it with a `FLAG_DEBUGGABLE` check per the official MASTG-BEST-0008 pattern:**

```kotlin
if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT) {
    if (0 != (applicationContext.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE)) {
        WebView.setWebContentsDebuggingEnabled(true)
    }
}
```

**Priority 3 — Verify that the flag mechanism used is truly synchronized with the production build type**, rather than a custom flag that risks slipping into a release build:

```kotlin
// ✅ BETTER — use BuildConfig.DEBUG which is automatically synchronized by AGP,
//    COMBINED with a FLAG_DEBUGGABLE check for a double layer
if (BuildConfig.DEBUG &&
    (0 != (applicationContext.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE))) {
    WebView.setWebContentsDebuggingEnabled(true)
}
```

**Priority 4 — Apply layered defenses for WebViews handling highly sensitive data** (payment, SSO), given the limitations of this mitigation against sophisticated attackers (§1.6):

- Implement **active debugger detection** (MASTG-TEST-0352/0353, MASWE-0064) as an additional layer that can detect attempts to force-enable debugging via hooking/patching.
- For the most critical functions (e.g., payment modules), consider **moving sensitive logic entirely out of the WebView** into native code that is harder to inspect via the DevTools Protocol.
- Implement **certificate pinning and content integrity validation** for content loaded by the WebView, so that even if DevTools is open, modifying content/traffic remains hard to exploit undetected.

**Priority 5 — Integrate this check into the release pipeline** as an automated gate:

```bash
#!/bin/bash
# ci-verify-webview-debug.sh
APK_SOURCES_DIR=$1
if grep -rq "setWebContentsDebuggingEnabled(true)" "$APK_SOURCES_DIR" 2>/dev/null; then
    echo "[WARNING] Found a call to setWebContentsDebuggingEnabled(true) — manual verification of the FLAG_DEBUGGABLE check context is needed before release"
    exit 1
fi
echo "[OK] No WebView debugging call found"
```

> Note that this automated gate is an **initial filter** (catching candidates), not a final decision — consistent with the automation limitations described in §3.7; positive results from this gate still need manual review to confirm they are not false positives from an already-correct pattern.

**Priority 6 — Verify on the final distributed APK**, consistent with the approach used for sibling tests in MASVS-RESILIENCE (MASTG-TEST-0224/0225/0226) — correct build configuration in the source code does not guarantee the final artifact is free of pipeline errors.

### 4.2 Remediation Checklist

- [ ] All calls to `WebView.setWebContentsDebuggingEnabled` in the code have been identified and their context reviewed
- [ ] Calls not needed in production have been removed entirely
- [ ] Remaining calls (for development purposes) are wrapped in a correct `ApplicationInfo.FLAG_DEBUGGABLE` check
- [ ] The wrapping condition's logic has been verified to not be inverted and to truly refer to `FLAG_DEBUGGABLE` (not an unsynchronized custom flag)
- [ ] Dynamic verification (Chrome DevTools / `webview_devtools_remote_*` socket) confirms no WebView can be debugged on the final release APK
- [ ] WebViews handling sensitive data (payment, SSO) are given priority review and additional layered defenses
- [ ] For R-profile applications: active debugger detection (MASWE-0064) is implemented as an additional layer against bypass via hooking/patching
- [ ] Static checks are integrated as a CI/CD gate, with the understanding that results still need manual verification
- [ ] The final distributed APK (not just a local build) is verified separately
- [ ] **Re-verification:** re-run MASTG-TEST-0227 after any code change touching WebView configuration

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0227: Debugging Enabled for WebViews](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0227/)
- [MASTG-TEST-0226: Debuggable Flag Enabled in the AndroidManifest](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0226/)
- [MASTG-TEST-0352: References to Debugging Detection APIs](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0352/)
- [MASTG-TEST-0353: Runtime Use of Debugging Detection APIs](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0353/)
- [MASWE-0063: Debug Mechanisms Not Disabled](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0063/)
- [MASWE-0064: Debugger Detection Not Implemented](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0064/)
- [MASTG-KNOW-0028: Anti-Debugging](https://mas.owasp.org/MASTG/knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0028/)
- [MASTG-BEST-0008: Debugging Disabled for WebViews](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0008/)
- [MASTG-TECH-0013: Reverse Engineering Android Apps](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/)
- [MASTG-TECH-0014: Static Analysis on Android](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/)
- [MASTG-TECH-0023: Reviewing Decompiled Java Code](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0023/)
- [MASTG-TECH-0038: Bypassing Debugger Detection (binary patching)](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0038/)
- [MASTG-TECH-0039: Repackaging (Reverse Engineering and Tampering)](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0039/)
- [MASTG-TECH-0043: Method Hooking](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0043/)
- [MASVS-RESILIENCE: Resilience Against Reverse Engineering and Tampering](https://mas.owasp.org/MASVS/11-MASVS-RESILIENCE/)
- [OWASP Mobile Top 10 2024 — M7: Insufficient Binary Protections](https://owasp.org/www-project-mobile-top-10/2023-risks/m7-insufficient-binary-protections.html)

### 5.2 Official Android / Chrome DevTools Documentation

- [Chrome DevTools — Remote debugging WebViews](https://developer.chrome.com/docs/devtools/remote-debugging/webviews/)
- [Chrome DevTools — Configure WebViews for debugging](https://developer.chrome.com/docs/devtools/remote-debugging/webviews/#configure_webviews_for_debugging)
- [Android — `WebView.setWebContentsDebuggingEnabled` API reference](https://developer.android.com/reference/android/webkit/WebView#setWebContentsDebuggingEnabled(boolean))
- [Android — `ApplicationInfo.FLAG_DEBUGGABLE` API reference](https://developer.android.com/reference/android/content/pm/ApplicationInfo#FLAG_DEBUGGABLE)
- [Chrome DevTools Protocol — official documentation](https://chromedevtools.github.io/devtools-protocol/)
- [Android — WebView overview](https://developer.android.com/reference/android/webkit/WebView)
- [Android — `addJavascriptInterface` security considerations](https://developer.android.com/reference/android/webkit/WebView#addJavascriptInterface(java.lang.Object,%20java.lang.String))

### 5.3 Standards & Taxonomies

- [CWE-489: Active Debug Code](https://cwe.mitre.org/data/definitions/489.html)
- [CWE-215: Insertion of Sensitive Information Into Debugging Code](https://cwe.mitre.org/data/definitions/215.html)
- [CWE-1244: Internal Asset Exposed to Unsafe Debug Access](https://cwe.mitre.org/data/definitions/1244.html)
- [NIST SP 800-163 Rev.1 — Vetting the Security of Mobile Applications](https://csrc.nist.gov/publications/detail/sp/800-163/rev-1/final)

### 5.4 Research & Technical Articles

- [HackTricks — Android WebView Attacks](https://book.hacktricks.wiki/en/mobile-pentesting/android-app-pentesting/webview-attacks.html)
- [PortSwigger — DOM-based vulnerabilities via WebView debugging (conceptual background)](https://portswigger.net/web-security/dom-based)
- [OWASP MASTG — Testing WebViews (chapter overview)](https://mas.owasp.org/MASTG/0x05h-Testing-Platform-Interaction/)

### 5.5 Tool Documentation

- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [apktool — Reverse engineering Android APK files](https://apktool.org/)
- [Semgrep — Documentation](https://semgrep.dev/docs/)
- [CodeQL — Documentation](https://codeql.github.com/docs/)
- [MobSF — Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)
- [Frida — Documentation Home](https://frida.re/docs/home/)
- [adb — Android Debug Bridge](https://developer.android.com/tools/adb)

---

*This document was compiled based on OWASP MASTG (latest release as of September 2026), official Android Developers documentation, and Chrome DevTools documentation on WebView remote debugging. This test does not yet have an official demo (MASTG-DEMO) from MASTG, and is the conceptual pair of MASTG-TEST-0226, testing an independent debugging path (WebView, rather than the entire application process).*
