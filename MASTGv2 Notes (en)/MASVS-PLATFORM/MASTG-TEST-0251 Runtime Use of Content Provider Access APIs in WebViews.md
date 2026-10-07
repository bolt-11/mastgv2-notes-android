# MASTG-TEST-0251 Runtime Use of Content Provider Access APIs in WebViews

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0251 |
| **Platform** | Android |
| **MASVS Category** | MASVS-PLATFORM (MASVS-PLATFORM-2) |
| **Weakness** | MASWE-0034 — *WebViews Allow Access to Local Resources with Untrusted Content* |
| **Highlighted API** | `WebView`, `WebSettings`, `getSettings`, `ContentProvider`, `setAllowContentAccess`, `setAllowUniversalAccessFromFileURLs`, `setJavaScriptEnabled` |
| **Test Type** | **Dynamic, Hooks, Manual** |
| **Profile** | L1, L2 |
| **Knowledge** | MASTG-KNOW-0018 (WebViews) |
| **Best Practice** | MASTG-BEST-0011, MASTG-BEST-0012, MASTG-BEST-0013, MASTG-BEST-0049 |
| **Related Techniques** | MASTG-TECH-0005 (Install App), MASTG-TECH-0043 (Method Hooking), MASTG-TECH-0023 (Reviewing Decompiled Java Code — further validation required) |
| **Related Test** | **MASTG-TEST-0250** (References to Content Provider Access in WebViews — static counterpart; the official overview explicitly states *"This test is the dynamic counterpart to MASTG-TEST-0250"*) |
| **Related Demo** | — (none) |
| **Official Rule** | — (not applicable; dynamic test) |
| **Related CWE** | CWE-200, CWE-668 |

---

## 1. Explanation

### 1.1 Relationship to MASTG-TEST-0250

The entire deep conceptual context — why `setAllowContentAccess`, which always defaults to `true`, is dangerous, why an app's own content providers remain exposed even when `android:exported="false"`, why `setAllowUniversalAccessFromFileURLs` is the critical key of the exploitation chain, and why this finding is not a standalone vulnerability but rather an impact multiplier — **has already been covered in full in the MASTG-TEST-0250 document**. This document focuses on what is unique to the dynamic side.

### 1.2 Two Hooking Approaches Explicitly Offered

The official overview gives two methodological options that are explicitly presented as equivalent:

> *"You can take two approaches when hooking or tracing the relevant APIs: enumerate instances of `WebView` in the app and list their configuration values; or, explicitly hook the setters of the `WebView` settings."*

Both approaches have different trade-offs:

| Approach | Advantage | Disadvantage |
|---|---|---|
| **Enumerate WebView instances + read configuration** | Captures the **final state** of WebSettings at a given point in time, including values inherited from defaults with no explicit setter call detected | Requires access to the right WebView instance at the right time (e.g., after the WebView has finished initializing) |
| **Hook the setters** (`setJavaScriptEnabled`, etc.) | Captures the **moment and context of the call** (stack trace, when it was called in the lifecycle) — richer for "Further Validation Required" analysis | Does not capture the case where a developer **deliberately never calls** a particular setter and relies on the default value (especially relevant for `setAllowContentAccess`, see §1.3) |

Because each approach's weaknesses complement each other, combining **both** gives the most complete picture — hooking setters to capture the context of explicit calls, and enumerating instances to capture the final effective value (including ones derived from an uncalled default).

### 1.3 Important Nuance: The Different Meaning of "Not Called" Between Static and Dynamic Testing

This is a very subtle but important point to understand. In **MASTG-TEST-0250 (static)**, the FAIL condition for `setAllowContentAccess` covers two scenarios: *"is explicitly set to `true` OR not used at all"* — this distinction makes sense statically because the tester is looking at **source code**, where "no call present" is a condition that can genuinely be observed textually.

However, in **this dynamic test**, the official Evaluation clause is simplified to purely the actual value:

> *"The test case fails if all the following applies: `JavaScriptEnabled` is `true`. `AllowContentAccess` is `true`. `AllowUniversalAccessFromFileURLs` is `true`."*

There is no longer a clause for "or not used at all" — this is **not an oversight**, but rather a logical consequence of the nature of dynamic testing: when a tester **enumerates running WebView instances** and reads `settings.getAllowContentAccess()`, that API will **always return the actual boolean value** currently in effect — `true`, whether due to an explicit call or inheriting the default. The "explicit vs. default" distinction that is textually relevant in static analysis **collapses into one** at this point at runtime — the system does not care how the value got there, only what value is **currently in effect**. This is a methodological value-add unique to the dynamic approach: it **automatically resolves** the "explicit vs. default" ambiguity that must be handled manually in static analysis.

### 1.4 "Further Validation Required" Clause More Detailed Than the Static Version

Compared to MASTG-TEST-0250, this dynamic version has a further-validation clause that is **more detailed and layered**:

> *"Using the backtraces from the hook output, inspect the code locations using MASTG-TECH-0023: Determine whether the settings are explicitly used and configured to the identified values. Determine which WebView instance receives the configuration and whether it handles sensitive information or functionality. Determine whether the WebView loads content in a context where content provider data could be accessed via `content://` URLs."*

This requires the tester to perform three distinct layers of analysis on **every** hooking finding:

1. **Configuration layer**: is this value actually configured as the finding indicates (not a testing artifact/rare edge case)?
2. **WebView identity layer**: **which specific** WebView receives this configuration — is it a WebView that displays sensitive content (account portal, payment page) or an unimportant WebView (e.g., displaying a static help page)?
3. **Load context layer**: does that WebView load content in a context that **can actually** execute `content://` access — e.g., loading `file://` per the exploitation chain described in the MASTG-TEST-0250 document §1.4?

The stack trace from hooking is key to answering questions #2 and #3 — this is the main reason why hooking setters (not just enumerating final values) remains valuable even though §1.3 already explained that the final value can be obtained via enumeration alone.

---

## 2. Tools Used for Testing

### 2.1 Required Tools (Core)

| Tool | Function |
|---|---|
| **Frida** | Core dynamic instrumentation — hooking setters and/or enumerating WebView instances |
| **frida-tools** (`frida-trace`) | Quick tracing without detailed scripting |
| **objection** | Ready-to-use Frida wrapper, including built-in backtrace dump capability |

### 2.2 Alternative & Supporting Tools

| Tool | Function |
|---|---|
| **Xposed/LSPosed** | Alternative persistent hooking per MASTG-TECH-0043, useful if the app detects/blocks Frida |
| **adb logcat** | Monitors CORS block messages as additional diagnostic evidence (explained in the MASTG-TEST-0250 document §1.4) |
| **Burp Suite/mitmproxy** | Observes actual exfiltration requests if an exploit PoC is run alongside a hooking session |

### 2.3 Environment Prerequisites

- **Device/emulator with Frida server is required** — this is a purely dynamic test.
- **Thorough interaction with the application** (§1.4 step 3 official: *"exercise the app extensively... enter sensitive data wherever you can"*) — a WebView that is rarely loaded (e.g., only appearing when opening a specific document or a specific help flow) will never be recorded if it is never triggered.
- **Ideally run alongside the results of MASTG-TEST-0250** — the static list of locations gives a map of candidate WebViews that should be prioritized for triggering during the dynamic session.

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0005** to install the application.
2. Use **MASTG-TECH-0043** to hook the relevant API calls.
3. Explore the application thoroughly, entering sensitive data wherever possible.

### 3.2 Method A — Hooking Setters with Backtrace *(the first approach mentioned officially)*

```javascript
// hook-webview-settings-setters.js
Java.perform(function () {
    function getBacktrace() {
        return Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());
    }

    var WebSettings = Java.use("android.webkit.WebSettings");
    var relevantSetters = [
        "setJavaScriptEnabled",
        "setAllowContentAccess",
        "setAllowUniversalAccessFromFileURLs"
    ];

    relevantSetters.forEach(function (method) {
        try {
            WebSettings[method].overload("boolean").implementation = function (value) {
                console.log("\n[*] WebSettings." + method + "(" + value + ")");
                console.log("    Backtrace:\n" + getBacktrace());
                return this[method](value);
            };
        } catch (e) {
            console.log("[x] Hook failed for " + method + ": " + e);
        }
    });
});
```

```bash
frida -U -f com.target.app -l hook-webview-settings-setters.js --no-pause
```

### 3.3 Method B — Enumerating WebView Instances and Reading Effective Values *(the second approach mentioned officially)*

```javascript
// enumerate-webview-instances.js
Java.perform(function () {
    Java.choose("android.webkit.WebView", {
        onMatch: function (instance) {
            try {
                var settings = instance.getSettings();
                console.log("\n[*] WebView instance found:");
                console.log("    JavaScriptEnabled: " + settings.getJavaScriptEnabled());
                console.log("    AllowContentAccess: " + settings.getAllowContentAccess());
                console.log("    AllowUniversalAccessFromFileURLs: " + settings.getAllowUniversalAccessFromFileURLs());
                console.log("    Current URL: " + instance.getUrl());
            } catch (e) {
                console.log("[x] Failed to read instance settings: " + e);
            }
        },
        onComplete: function () {
            console.log("[*] WebView instance enumeration complete.");
        }
    });
});
```

```bash
frida -U -f com.target.app -l enumerate-webview-instances.js --no-pause
# Run after the application has finished loading a page that uses a WebView
```

**Implementation note**: `Java.choose()` captures instances that are **currently alive on the heap** at the moment the script runs — for WebViews created/destroyed dynamically (e.g., a temporary WebView dialog), the timing of this script's execution matters; consider running it repeatedly (`setInterval` within the Frida script) throughout the interaction session.

### 3.4 Method C — objection (Quick Combination of Both Approaches)

```bash
objection -g com.target.app explore
# Inside the objection console:
android hooking watch class_method android.webkit.WebSettings.setJavaScriptEnabled --dump-args --dump-backtrace
android hooking watch class_method android.webkit.WebSettings.setAllowContentAccess --dump-args --dump-backtrace
android hooking watch class_method android.webkit.WebSettings.setAllowUniversalAccessFromFileURLs --dump-args --dump-backtrace

# Instance enumeration (second approach)
android heap search instances android.webkit.WebView
```

### 3.5 Method D — Correlation with the WebView's Loaded Content (Answers the Context Layer in §1.4)

Extend the Method A/B hook to also capture the loaded URL, directly answering the official question *"whether the WebView loads content in a context where content provider data could be accessed"*:

```javascript
// hook-webview-loadurl-correlated.js
Java.perform(function () {
    var WebView = Java.use("android.webkit.WebView");
    WebView.loadUrl.overload("java.lang.String").implementation = function (url) {
        console.log("\n[*] WebView.loadUrl(" + url + ")");
        var settings = this.getSettings();
        console.log("    JavaScriptEnabled: " + settings.getJavaScriptEnabled());
        console.log("    AllowContentAccess: " + settings.getAllowContentAccess());
        console.log("    AllowUniversalAccessFromFileURLs: " + settings.getAllowUniversalAccessFromFileURLs());
        if (url.indexOf("file://") === 0 && settings.getAllowUniversalAccessFromFileURLs()) {
            console.log("    [!] RISKY CONDITION: file:// loaded with universal access enabled!");
        }
        return this.loadUrl(url);
    };
});
```

This approach unifies Method A and B at once into a single trigger point (`loadUrl`) that is directly relevant to the real exploitation scenario — giving the strongest evidence because it ties the WebSettings configuration to the **actual URL** loaded at the same moment.

### 3.6 Method Comparison: Which One to Use When

| Method | Tool | Captures call context? | Captures final effective value? | When to use |
|---|---|---|---|---|
| **A** | Hook setters | ✅ (stack trace) | No (only at the moment called) | Answers "when and from where" |
| **B** | Enumerate instances | ❌ | ✅ | Answers "what value is currently in effect" |
| **C** | objection | ✅ + ✅ (quick combination) | ✅ | Quick initial exploration without scripting |
| **D** | Correlated `loadUrl` hook | ✅ | ✅ | **Most valuable** — directly answers the context question (§1.4) |

**Minimum recommended combination:** **D as the primary method** (combining the strengths of A and B while being directly relevant to the exploitation scenario), supplemented by **B** periodically throughout the session to capture instances that may not re-trigger `loadUrl`.

---

### 3.7 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rule:**

> **Observation:** *"The output should contain a list of WebView setting calls, including the argument values and backtraces of each call."*
>
> **Evaluation:** *"The test case fails if all the following applies: `JavaScriptEnabled` is `true`. `AllowContentAccess` is `true`. `AllowUniversalAccessFromFileURLs` is `true`."*

---

#### ❌ FAIL / ISSUE — The check is declared FAILED when:

| No | Condition |
|---|---|
| F1 | Hooking/enumeration results show all three values (`JavaScriptEnabled`, `AllowContentAccess`, `AllowUniversalAccessFromFileURLs`) are `true` on the **same WebView instance** |
| F2 | The backtrace/`loadUrl` correlation (Method D) confirms that WebView loads `file://` content or content that is potentially untrusted |
| F3 | The affected WebView is confirmed (MASTG-TECH-0023) to handle sensitive information/functionality |
| F4 | The related content provider (traced from MASTG-TEST-0250) is confirmed to handle sensitive data |

**Example evidence (illustrative — MASTG does not yet provide an official demo for this test):**

```
[*] WebView.loadUrl(file:///android_asset/document_viewer.html)
    JavaScriptEnabled: true
    AllowContentAccess: true
    AllowUniversalAccessFromFileURLs: true
    [!] RISKY CONDITION: file:// loaded with universal access enabled!
    Stack trace:
        at com.example.target.ui.DocumentViewerActivity.setupWebView(DocumentViewerActivity.java:58)
        at com.example.target.ui.DocumentViewerActivity.onCreate(DocumentViewerActivity.java:32)
```

Interpretation: all three conditions are confirmed `true` at runtime on a WebView that loads `file://`, with a precise code location from the stack trace. Next step: verify with MASTG-TECH-0023 on `DocumentViewerActivity` whether it handles sensitive user documents, and check the app's content provider list (MASTG-TEST-0250) for potentially exposed data.

---

#### ✅ PASS — The check is declared PASSED when:

| No | Condition |
|---|---|
| P1 | No WebView instance shows all three values as `true` simultaneously during a thorough testing session |
| P2 | A risky combination was found, but it is confirmed (MASTG-TECH-0023) that WebView **never** loads `file://`/untrusted content, or does not handle sensitive data/functionality |
| P3 | Interaction coverage is adequate (the app was explored thoroughly, including sensitive flows) and no risky combination was found |

---

#### ⚠️ Important Notes on the Assessment

1. **An empty result requires validating interaction coverage first**, consistent with a recurring pattern throughout the dynamic tests in this series — a WebView that is rarely loaded (help feature, a rarely-used document viewer) risks never being triggered if the testing session is not thorough.

2. **Make use of Method D (correlation with `loadUrl`) as the primary method** — this is the most efficient way to answer all three layers of the official "Further Validation Required" clause in a single observation point.

3. **Do not stop at the boolean value level alone** — the official clause explicitly demands an assessment of **context** (which WebView, loading what, handling what data). A report that only states "found JavaScriptEnabled=true, AllowContentAccess=true, AllowUniversalAccessFromFileURLs=true" without this context has not met the official evaluation standard for this test.

4. **Always correlate with the MASTG-TEST-0250 results** — the two tests complement each other: the static test provides a complete map of candidate locations (including ones not executed during dynamic testing), the dynamic test provides confirmation of real effective values and precise execution context.

5. **Severity follows the same pattern as the MASTG-TEST-0250 document** — modulated by the sensitivity of the content provider's data and whether it is combined with an exported Activity that accepts an external URL without validation.

6. **Document:** the values of all three settings per WebView instance, the backtrace of the configuration location, the URL loaded at the moment of observation, the results of the MASTG-TECH-0023 analysis of that WebView's context and sensitivity, and the interaction coverage performed on the application.

---

## 4. Recommendations

Because the root cause and technical solution are identical to MASTG-TEST-0250 (the same weakness, MASWE-0034), refer to **the MASTG-TEST-0250 document §4** for full implementation recommendations (disable content access, disable universal access, migrate to `WebViewAssetLoader`, strengthen content provider configuration).

Additional recommendations specific to the dynamic perspective:

### 4.1 Integrate Hooking into Automated Regression Testing

```bash
#!/bin/bash
# ci-dynamic-webview-content-check.sh
frida -U -f com.target.app -l hook-webview-loadurl-correlated.js --no-pause &
FRIDA_PID=$!
sleep 5
./run-ui-test-suite.sh --scenario=document-viewer,help-center,payment-portal
kill $FRIDA_PID
```

### 4.2 Remediation Checklist

- [ ] Hooking covers both official approaches (setters + instance enumeration), ideally via Method D which unifies both
- [ ] Testing interaction has covered every WebView present in the application (including rarely-loaded ones)
- [ ] Every finding of a risky combination has been reviewed via MASTG-TECH-0023 for context and sensitivity
- [ ] Results are correlated with the MASTG-TEST-0250 (static) findings and the content provider list
- [ ] **Re-verify:** re-run MASTG-TEST-0251 after any change to the WebView implementation

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0251: Runtime Use of Content Provider Access APIs in WebViews](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0251/)
- [MASTG-TEST-0250: References to Content Provider Access in WebViews](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0250/)
- [MASWE-0034: WebViews Allow Access to Local Resources with Untrusted Content](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0034/)
- [MASTG-KNOW-0018: WebViews](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0018/)
- [MASTG-TECH-0005: Installing Apps](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0005/)
- [MASTG-TECH-0043: Method Hooking](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0043/)
- [MASTG-TECH-0023: Reviewing Decompiled Java Code](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0023/)

### 5.2 Official Android Documentation

- [Android Developers — `WebSettings` API reference](https://developer.android.com/reference/android/webkit/WebSettings)
- [Android Developers — `WebView` API reference](https://developer.android.com/reference/android/webkit/WebView)

### 5.3 Tool Documentation

- [Frida — Dynamic instrumentation toolkit](https://frida.re/docs/javascript-api/)
- [Frida — `Java.choose()` API reference](https://frida.re/docs/javascript-api/#java)
- [frida-trace — Documentation](https://frida.re/docs/frida-trace/)
- [Objection — Runtime Mobile Exploration toolkit](https://github.com/sensepost/objection)
- [LSPosed Framework](https://github.com/LSPosed/LSPosed)

---

*This document was prepared based on OWASP MASTG (current release as of September 2026) and official Android Developers documentation. As the direct dynamic counterpart of MASTG-TEST-0250, the deep conceptual context about the risks of `setAllowContentAccess`/`setAllowUniversalAccessFromFileURLs` is covered in full in that document. The unique value of this test: two complementary hooking approaches (setters vs. instance enumeration), the automatic resolution of the "explicit vs. default" ambiguity present in static analysis, and a three-layer further-validation clause (configuration, WebView identity, load context) that is more detailed than the static version's.*
