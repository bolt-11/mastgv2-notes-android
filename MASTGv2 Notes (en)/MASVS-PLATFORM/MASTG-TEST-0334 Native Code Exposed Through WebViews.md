# MASTG-TEST-0334 Native Code Exposed Through WebViews

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0334 |
| **Platform** | Android |
| **MASVS Category** | MASVS-PLATFORM |
| **Weakness** | MASWE-0034 |
| **Test Type** | Static, Code, **Manual** |
| **Related Techniques** | MASTG-TECH-0013 (Reverse Engineering), MASTG-TECH-0014 (Static Analysis for Relevant APIs), MASTG-TECH-0023 (Reviewing Decompiled Java Code) |
| **Related Best Practice** | MASTG-BEST-0011, MASTG-BEST-0012, MASTG-BEST-0013, MASTG-BEST-0035 |
| **Related Knowledge** | MASTG-KNOW-0018 (WebViews) |
| **Prerequisite** | `identify-security-relevant-contexts` |
| **Official Rule** | `mastg-android-webview-bridges.yml` — 2 patterns, see §1.4 |

---

## 1. Explanation

### 1.1 Testing Objective

Official MASTG overview excerpt:

> *"This test verifies Android apps that use WebViews with legacy WebView-Native bridges do not expose native code to websites loaded inside the WebView."*

The mechanism being targeted:

> *"These bridges are created by registering a Java object with the WebView through `addJavascriptInterface`. Public methods of that object that are annotated with `@JavascriptInterface` become callable from JavaScript running inside the WebView, using the provided `name` as the global JavaScript object."*

And the prerequisite that makes this bridge accessible:

> *"For this mechanism to work, JavaScript execution must be enabled on the WebView by calling `WebSettings.setJavaScriptEnabled(true)` (default is `false`)."*

This is one of the few tests in this research series that is explicitly given a **"manual"** type alongside static/code — a signal that MASTG itself acknowledges that automated pattern-matching alone **is not sufficient** to reach a final finding; human contextual judgment is required.

### 1.2 The Triple-AND FAIL Criteria: Three Conditions Must All Be True

This test's evaluation structure has **three AND conditions**, more complex than most other tests in this research series:

> *"The test case fails if all the following are true:*
> - *`setJavaScriptEnabled` is explicitly set to `true`.*
> - *`addJavascriptInterface` is used at least once.*
> - *At least one method annotated with `@JavascriptInterface` handles sensitive data or actions and is reachable from untrusted content."*

The third condition is the **hardest to verify automatically** — it demands two qualitative judgments at once: (a) whether that method handles sensitive data/actions, and (b) whether that method is **truly reachable** from untrusted content. This is the root reason this test is labeled "manual."

### 1.3 Two Further Validation Questions That Must Be Answered by a Human

The "Further Validation Required" section gives an explicit framework for answering the third condition above:

> *"Inspect each reported code location using MASTG-TECH-0023 to determine whether the bridge is used in a security-relevant context:*
> - *Determine whether the exposed methods handle sensitive data or security-critical actions.*
> - *Determine whether the bridge is reachable from untrusted content, for example if the WebView can load arbitrary or weakly validated URLs, or if the app does not implement proper origin allowlisting."*

The second point here is very important — **"reachable from untrusted content"** is not simply about whether the bridge exists, but about the **path** by which malicious content can reach the WebView that holds that bridge. A bridge that is only exposed to a first-party page loaded from a local application asset (and where the WebView never navigates to any external URL) has a very different risk profile from a bridge exposed to a WebView that can load arbitrary URLs or that accepts URL parameters from an external deep link/intent.

### 1.4 Analysis of the Official Rule: Two Patterns That Require Manual Correlation

The `mastg-android-webview-bridges.yml` rule consists of two patterns that **each stand on their own** and are not automatically linked by Semgrep:

```yaml
# Pattern 1: detects the combination of setJavaScriptEnabled(true) + addJavascriptInterface
- id: mastg-android-webview-bridges-setup
  patterns:
    - pattern: $WEBVIEW.addJavascriptInterface($BRIDGE, $_)
    - pattern-inside: |
        $RET $METHOD(...) {
          ...
          $WEBVIEW.getSettings().setJavaScriptEnabled(true);
          ...
        }

# Pattern 2: detects a method exposed via @JavascriptInterface
- id: mastg-android-webview-bridges-javascriptinterface
  pattern: |
    @JavascriptInterface
    $TYPE $NAME(...) {
      ...
    }
```

Pattern 1 captures **conditions 1 and 2** of the FAIL criteria (§1.2) — it cleverly restricts the scope with `pattern-inside` to ensure `setJavaScriptEnabled(true)` and `addJavascriptInterface` occur within the **same method**, reducing the false-positive risk compared to simply searching for two separate patterns anywhere in a file. Pattern 2 captures the **location** of the exposed method, but **cannot automatically assess** whether that method "handles sensitive data" or is "reachable from untrusted content" — both of those assessments are purely manual, per §1.3. The tester must **manually correlate** the results of both patterns: confirm that the `$BRIDGE` in Pattern 1 is the same class where the methods from Pattern 2 reside, then assess the content of that method.

### 1.5 Three Common Challenges Explicitly Acknowledged by MASTG

The "Well-known Challenges" section gives a rare honest acknowledgment of methodological limitations:

> *"The app may use parametrized or indirect calls to these APIs, for example through utility methods or wrapper classes. Static analysis may not be able to resolve these calls..."*
>
> *"The app may use several WebViews with different configurations, and it may be difficult to determine which values are set for each WebView instance, especially if they are created dynamically, in different code paths or even across different files."*
>
> *"The app may use obfuscation, reflection, or dynamic code loading to hide the use of these APIs."*

The second challenge is specifically relevant for large applications with many WebView-based screens (e.g., an e-commerce app with separately configured WebViews for checkout, help, and promo pages) — the official rule will flag every matching combination, but the tester must manually map which WebView instance connects to which configuration, because a single application can have a mix of secure and insecure WebViews at once.

### 1.6 Real-World Evidence: From Classic RCE to Real Production Application Cases

The `addJavascriptInterface` class of vulnerability is not a theoretical risk — it is one of the most extensively documented Android vulnerability classes in mobile security research history. Classic research by WithSecure (formerly F-Secure), also referenced in MASTG-KNOW-0018, demonstrated a complete exploitation mechanism:

> *"JavaScript injected into a WebView that implements a native bridge using android.webkit.JavascriptInterface can result in execution of operating system commands via java.lang.Runtime through reflection techniques... A real-world example involved a method named getTime() that accepts a string parameter and directly passes it to Runtime.getRuntime().exec(), allowing command execution."*

This example perfectly illustrates the risk of the third condition in §1.2 — a method that **appears harmless** (named `getTime()`, seemingly just returning the time) turned out to be a full **remote code execution** vector because the string parameter it received was passed directly to `Runtime.exec()` without validation.

A real-world case on a production application is also documented — a vulnerability analysis report for the **ownCloud Mobile App** found:

> *"A vulnerability was found in SamlWebViewDialog.java where JavaScript was enabled in the WebView, exposing the application to potential attacks."*

This confirms that this vulnerability class continues to reappear in real production applications over time, not merely a scenario that was "resolved" since API level 21 (per the MASTG-BEST-0035 note that reflection-based RCE risk has been mitigated for `targetSdkVersion` 21+, which only exposes annotated methods) — the **business logic** risk of a method that is intentionally exposed but not properly validated remains fully relevant regardless of the target API level.

---

## 2. Tools Used for Testing

### 2.1 Required Tools (Core)

| Tool | Function |
|---|---|
| **jadx** | DEX → Java decompilation for manual review (MASTG-TECH-0013, MASTG-TECH-0023) |
| **Semgrep** + official rule `mastg-android-webview-bridges.yml` | Initial triage of candidate locations (MASTG-TECH-0014) |

### 2.2 Alternative & Supporting Tools

| Tool | Function |
|---|---|
| **grep/ripgrep** | Finding indirect patterns (wrapper methods, helper classes) missed by Semgrep per the challenges in §1.5 |
| **MobSF** | Automated reports that sometimes include `addJavascriptInterface` detection as part of the summary |
| **Frida** | Dynamic verification — hooking `@JavascriptInterface` methods to confirm they are genuinely callable from real WebView content at runtime, including dynamically created WebView cases (§1.5) |
| **objection** | Quick exploration of active WebViews on a test device, including checking the actual `WebSettings` configuration |

### 2.3 Environment Prerequisites

- No device/root required for initial static analysis, but **manual and dynamic verification is strongly recommended** given this test's type includes "manual."
- Prepare a clear definition of "sensitive data/action" (per the `identify-security-relevant-contexts` prerequisite) before assessing the third FAIL criterion condition.

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0013** to reverse engineer the application.
2. Use **MASTG-TECH-0014** to find relevant APIs.
3. **(Mandatory, not optional)** Use **MASTG-TECH-0023** to manually review every location found.

### 3.2 Method A — Semgrep with the Official Rule for Initial Triage

```bash
semgrep --config mastg-android-webview-bridges.yml ./decompiled/sources
```

### 3.3 Method B — grep/ripgrep for Indirect Patterns

```bash
D=./decompiled/sources

# Find all addJavascriptInterface calls, including via WebView object variables whose name is not explicit
rg -n 'addJavascriptInterface\(' $D

# Find all @JavascriptInterface-annotated methods
rg -n -A3 '@JavascriptInterface' $D

# Find indications of a wrapper/helper that may be hiding a setJavaScriptEnabled call
rg -n 'setJavaScriptEnabled' $D
```

### 3.4 Method C — Manual Review of Decompiled Code (Mandatory, Per MASTG-TECH-0023)

For each `@JavascriptInterface` method found by Method A/B:

1. Read the method's content fully — does it handle sensitive data (tokens, credentials) or trigger a sensitive action (transfers, security setting changes)?
2. Trace back the WebView object receiving that bridge — can that WebView load a URL controllable by the user/externally (deep link, intent extra), or only a fixed local asset?
3. Check whether there is an origin allowlisting mechanism (`shouldOverrideUrlLoading`, `shouldInterceptRequest`) that restricts that WebView's navigation.

### 3.5 Method D — Frida for Dynamic Reachability Verification

```javascript
Java.perform(function () {
    var targetBridge = Java.use("com.example.app.webview.NativeBridge");
    targetBridge.sensitiveMethod.implementation = function (param) {
        console.log("[NativeBridge.sensitiveMethod] called with: " + param);
        console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));
        return this.sensitiveMethod(param);
    };
});
```

Load a test web page (including one simulated as being from an untrusted source) in the application's WebView and observe whether the bridge method is actually invoked — the most conclusive evidence for the "reachable from untrusted content" condition.

### 3.6 Method Comparison: When to Use Which

| Method | Tool | When to Use |
|---|---|---|
| **A** | Semgrep + official rule | Fast initial triage — conditions 1 & 2 |
| **B** | grep/ripgrep manual | Closing the gap on indirect patterns (§1.5) |
| **C** | Manual review (mandatory) | Assessing condition 3 — sensitive data & reachability, CANNOT be fully automated |
| **D** | Frida | Conclusive dynamic proof of reachability |

**Minimum combination I recommend:** **A + B (triage) → C (mandatory, the core of this test's "manual" nature)**, with **D** as a supplement for dynamic proof when a stronger report is needed.

---

### 3.7 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rule (triple-AND criteria, §1.2):**

---

#### ❌ FAIL / ISSUE — The check is declared FAILED if **all three** of the following conditions are met:

| No | Condition |
|---|---|
| F1 | `setJavaScriptEnabled` is explicitly set to `true` |
| F2 | `addJavascriptInterface` is used at least once |
| F3 | At least one `@JavascriptInterface` method handles sensitive data/actions **and** is reachable from untrusted content |

**Example evidence (replicating the real-world WithSecure pattern in §1.6):**

```java
// Found in com/example/app/webview/SupportChatActivity.java
webView.getSettings().setJavaScriptEnabled(true);
webView.addJavascriptInterface(new NativeBridge(), "AndroidBridge");
webView.loadUrl(getIntent().getStringExtra("support_url")); // External URL, not validated!

// Found in com/example/app/webview/NativeBridge.java
public class NativeBridge {
    @JavascriptInterface
    public void executeCommand(String cmd) {
        Runtime.getRuntime().exec(cmd); // a method handling a very sensitive action
    }
}
```

Interpretation: all three conditions are met — JavaScript is active, the bridge is registered, and the `executeCommand` method handles a critical action **while** the WebView loads a URL that comes from an external `Intent` without validation. **FAIL** — full RCE risk.

---

#### ✅ PASS — The check is declared PASSED if **any one** of the following holds:

| No | Condition |
|---|---|
| P1 | JavaScript is not enabled at all |
| P2 | JavaScript is enabled but no `addJavascriptInterface` is used |
| P3 | A bridge exists, but every `@JavascriptInterface` method only handles non-sensitive data (e.g., `getAppVersion()`) |
| P4 | A sensitive method exists, but the WebView hosting it is **proven** to only load trusted first-party content (static local assets, with no navigation to any external URL) |

---

#### ⚠️ Important Notes on Evaluation

1. **Do not stop at raw Semgrep results** — per this test's "manual" nature, finding a combination of Pattern 1 + Pattern 2 statically **only identifies a candidate**; the third condition (§1.2, §1.3) must be verified by a human before a final FAIL is concluded.

2. **"Reachable from untrusted content" is an architectural question, not just a local code question** — trace every path by which a URL is loaded into that WebView: from an intent extra, deep link, QR code, or another external source that an attacker could control.

3. **Beware of the three official challenges (§1.5)** before concluding PASS from an absence of a match — indirect patterns, multiple WebView instances with varied configurations, and obfuscation/reflection can hide the real findings.

4. **Classic reflection-based RCE (API <21) has largely been mitigated**, but **business logic risk remains relevant at all target API levels** — a method intentionally exposed without proper input validation (like the `executeCommand`/`getTime()` example in §1.6) remains dangerous regardless of `targetSdkVersion`.

5. **Severity is modulated:**

   | Factor | Severity |
   |---|---|
   | Bridge handles command execution/filesystem/credential actions, reachable from an unvalidated external URL | **Critical** (full RCE/access) |
   | Bridge handles sensitive data but is only reachable from controlled first-party content | **Low** (residual risk if the first party is compromised) |
   | Bridge only handles non-sensitive data | **Not a finding** |

6. **Document:** the location of the WebView and bridge code, the full content of the exposed method, the path by which that WebView can be navigated to external content, and the dynamic verification results if performed.

---

## 4. Recommendations

### 4.1 Migrate to a Modern Bridge Mechanism Per MASTG-BEST-0035

```java
// BEFORE — legacy addJavascriptInterface, no origin control
webView.addJavascriptInterface(new NativeBridge(), "AndroidBridge");

// AFTER — addWebMessageListener with an explicit origin allowlist
WebViewCompat.addWebMessageListener(
    webView,
    "nativeBridge",
    Set.of("https://trusted.example.com"), // explicit allowedOriginRules
    (view, message, sourceOrigin, isMainFrame, replyProxy) -> {
        // validate sourceOrigin before processing the message
    }
);
```

### 4.2 Minimize Exposed Native Functionality (Per MASTG-BEST-0035)

Do not expose generic utility/command dispatchers — expose only the specific operations the page genuinely needs, with a clearly defined message format and strict input validation for every parameter.

### 4.3 Validate Origin Before Loading Content Into a Bridged WebView

```java
webView.setWebViewClient(new WebViewClient() {
    @Override
    public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
        String host = request.getUrl().getHost();
        if (!ALLOWED_HOSTS.contains(host)) {
            return true; // block navigation to an untrusted domain
        }
        return false;
    }
});
```

### 4.4 Remediation Checklist

- [ ] Legacy `addJavascriptInterface` bridges are migrated to `addWebMessageListener` with an origin allowlist
- [ ] Every exposed method has its scope minimized and its input strictly validated
- [ ] The WebView hosting a sensitive bridge cannot navigate to external URLs without validation
- [ ] Results are dynamically verified (Frida) to ensure the bridge is no longer reachable from untrusted content
- [ ] A manual review (MASTG-TECH-0023) is performed for every new bridge added in the future

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0334 (source, tests-beta)](https://github.com/OWASP/mastg/blob/master/tests-beta/android/MASVS-PLATFORM/MASTG-TEST-0334.md)
- [MASTG-KNOW-0018: WebViews](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0018/)
- [MASTG-BEST-0035: Prefer Origin Scoped Messaging Over Legacy JavaScript Bridges](https://github.com/OWASP/mastg/blob/master/best-practices/MASTG-BEST-0035.md)
- [MASTG-BEST-0012: Disable JavaScript in WebViews](https://github.com/OWASP/mastg/blob/master/best-practices/MASTG-BEST-0012.md)
- [MASTG-TECH-0023: Reviewing Decompiled Java Code](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0023/)

### 5.2 Research and Real-World Cases

- [WithSecure Labs: WebView addJavascriptInterface Remote Code Execution](https://labs.withsecure.com/publications/webview-addjavascriptinterface-remote-code-execution)
- [SecureLayer7: Android WebView Vulnerabilities — Risks and Hardening](https://blog.securelayer7.net/android-webview-vulnerabilities/)
- [Android Developers: Insecure WebView Native Bridges](https://developer.android.com/privacy-and-security/risks/insecure-webview-native-bridges)
- [HackerOne Report #87835: ownCloud WebView JavaScript Exposure](https://hackerone.com/reports/87835)

### 5.3 Tool Documentation

- [Semgrep Documentation](https://semgrep.dev/docs/)
- [Frida — Dynamic Instrumentation Toolkit](https://frida.re/docs/home/)
- [MobSF — Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)
- [Objection — Runtime Mobile Exploration](https://github.com/sensepost/objection)

---

*This document is compiled based on official OWASP MASTG content (`tests-beta/android/MASVS-PLATFORM/MASTG-TEST-0334.md`, `MASTG-KNOW-0018`, `MASTG-BEST-0011/0012/0013/0035`, `MASTG-TECH-0023`), an analysis of the `mastg-android-webview-bridges.yml` rule, as well as classic WithSecure research on reflection-based RCE via `addJavascriptInterface` and real-world vulnerability reports on production applications (ownCloud). The most important methodological nuance: this is one of the few tests explicitly given a "manual" type — the FAIL criteria are a triple-AND, and the third condition (sensitive data + reachability from untrusted content) structurally **cannot be fully validated through automated pattern-matching**; MASTG itself acknowledges three real challenges (indirect calls, multi-instance WebViews, obfuscation) that demand a combination of automated triage with deep manual review.*
