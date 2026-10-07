# MASTG-TEST-0253 Runtime Use of Local File Access APIs in WebViews

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0253 |
| **Platform** | Android |
| **MASVS Category** | MASVS-PLATFORM (MASVS-PLATFORM-2) |
| **Weakness** | MASWE-0034 — *WebViews Allow Access to Local Resources with Untrusted Content* |
| **Highlighted API** | `WebView`, `WebSettings`, `getSettings`, `setAllowFileAccess`, `setAllowFileAccessFromFileURLs`, `setAllowUniversalAccessFromFileURLs` |
| **Test Type** | **Dynamic, Hooks, Manual** |
| **Profile** | L1, L2 |
| **Knowledge** | MASTG-KNOW-0018 (WebViews) |
| **Best Practice** | MASTG-BEST-0010, MASTG-BEST-0011, MASTG-BEST-0012 |
| **Related Techniques** | MASTG-TECH-0005, MASTG-TECH-0043, MASTG-TECH-0023 |
| **Related Test** | **MASTG-TEST-0252** (static counterpart; the official overview explicitly states *"This test is the dynamic counterpart to MASTG-TEST-0252"*) |
| **Related Demo** | — (none) |
| **Official Rule** | — (not applicable; dynamic test) |
| **Related CWE** | CWE-200, CWE-668 |

---

## 1. Explanation

### 1.1 Relationship to MASTG-TEST-0252

The entire deep conceptual context — the `minSdkVersion`-based default differences for the three APIs, why an "absence of reference" is actually suspicious, the interaction between `setAllowFileAccessFromFileURLs`/`setAllowUniversalAccessFromFileURLs`, and the *blind exfiltration* nuance (data still gets sent even if reading the response is blocked by CORS) — **has already been covered in full in the MASTG-TEST-0252 document**. This document focuses on the unique value-add of the dynamic approach, as well as one important methodological limitation that is **specific to this test** and does not appear in the MASTG-TEST-0250/0251 pair.

### 1.2 Two Hooking Approaches Structurally Identical to MASTG-TEST-0251

The official overview offers two approaches that are structurally identical to MASTG-TEST-0251 (the dynamic counterpart of MASTG-TEST-0250): enumerating WebView instances, or directly hooking the setters. Refer to the MASTG-TEST-0251 document §1.2 for a discussion of the trade-offs between the two — the same analysis fully applies here, differing only in the specific APIs being hooked (`setAllowFileAccess`, `setAllowFileAccessFromFileURLs`, `setAllowUniversalAccessFromFileURLs` instead of `setAllowContentAccess`).

### 1.3 A Methodological Limitation Specific to This Test: The Test Device's OS Version ≠ the App's `minSdkVersion`

This is the **most important and unique** nuance of this dynamic test compared to MASTG-TEST-0251 — it arises precisely because this test's official Evaluation clause **still retains a reference to `minSdkVersion`** even though it has moved into the dynamic domain:

> *"`setAllowFileAccess` is explicitly set to `true` (or not used at all when `minSdkVersion` < 30, inheriting the default value, `true`)."*

Recall the nuance discussed in the MASTG-TEST-0251 document §1.3: in MASTG-TEST-0251's dynamic testing, the "explicit vs. default" ambiguity **fully collapses** because `getAllowContentAccess()` always returns a single effective value (`true`) on **every** Android version without exception. **The same does NOT fully apply here** — because the default of all three APIs in this test **depends on the actual OS version**, not a single constant like `setAllowContentAccess`.

As a consequence, the results of dynamic enumeration/hooking in this test **only reflect behavior on one specific OS version**, namely **the OS version of the device/emulator used for testing** — not the app's actual `minSdkVersion`, which is what the official clause really intends to evaluate. This creates a serious potential for misinterpretation:

| Scenario | Consequence |
|---|---|
| The app has `minSdkVersion=21`, but is tested on an Android 14 (API 34) emulator | The result of `getAllowFileAccess()` will show `false` (modern default) — **concealing** the fact that real users on Android 5-10 (API 21-29) devices will experience the insecure `true` default |
| The app has `minSdkVersion=30`, tested on an emulator of any API level ≥30 | The dynamic testing result **consistently and validly** represents the entire user population, because no real device exists below the safe-default threshold |

This means that **a PASS conclusion from dynamic testing alone, without accounting for the app's `minSdkVersion`, can be a significant false negative** when the test device runs an OS newer than the app's `minSdkVersion` (a very common scenario, since most modern test devices/emulators run the latest Android version by default).

### 1.4 Methodological Implication: Test Across Multiple Android Versions, Not Just One Device

The nuance in §1.3 carries a concrete methodological consequence: to reach a conclusion that is genuinely valid per the official clause, this test's dynamic testing **should ideally be run on more than one Android version** — specifically including **an emulator with an API level close to the app's `minSdkVersion`** (obtained from MASTG-TEST-0252's static results), not just whichever latest-version emulator/device happens to be available. If resource constraints make multi-version testing infeasible, the tester **must** explicitly document the OS version of the test device and separately confirm the static `minSdkVersion` result (MASTG-TEST-0252) to complement the conclusion — rather than relying on a single-device dynamic result as a standalone final answer.

### 1.5 "Further Validation Required" Clause — Specific Focus on the `file://` Context

This test's official further-validation clause has a specific emphasis compared to its content-provider counterpart (MASTG-TEST-0251):

> *"Determine whether that `WebView` loads local `file://` content, for example via `loadUrl("file://...")` or `loadDataWithBaseURL` with a `file://` base URL."*

This explicitly names **two** relevant content-loading mechanisms — not just `loadUrl()` as the common pattern, but also **`loadDataWithBaseURL`** with `file://` as the base URL, a pattern often used to load HTML that is **built dynamically in Java/Kotlin code** (rather than a static HTML file) but still given a `file://` origin context. This test's hooking instrumentation **must cover both loading APIs** so as not to miss either path.

---

## 2. Tools Used for Testing

### 2.1 Required Tools (Core)

| Tool | Function |
|---|---|
| **Frida** | Core dynamic instrumentation |
| **frida-tools** (`frida-trace`) | Quick tracing |
| **objection** | Ready-to-use Frida wrapper |
| **Emulator with several different API-level images** | **Mandatory** per §1.4 — at minimum covering an API level close to the app's `minSdkVersion` and a modern API level for comparison |

### 2.2 Alternative & Supporting Tools

| Tool | Function |
|---|---|
| **Android Virtual Device (AVD) Manager / Genymotion** | Provides various API-level images for multi-version testing (§1.4) |
| **Xposed/LSPosed** | Alternative persistent hooking |
| **adb logcat** | CORS block diagnostic evidence following the pattern discussed in the MASTG-TEST-0252 document §1.5 |
| **Burp Suite/mitmproxy** | Observes real exfiltration when a PoC is run |

### 2.3 Environment Prerequisites

- **Device/emulator with Frida server is required** — this is a purely dynamic test.
- **Ideally prepare at least two emulator images**: one close to the app's `minSdkVersion` (per MASTG-TEST-0252's result), one modern — to validate the consistency/difference in behavior per §1.3-§1.4.
- **Thorough interaction** covering every WebView, including those loaded via `loadDataWithBaseURL` (§1.5).

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0005** to install the application.
2. Use **MASTG-TECH-0043** to hook the relevant APIs.
3. Explore the application thoroughly, entering sensitive data wherever possible.

### 3.2 Method A — Hooking Setters + Content Loading at Once *(covers both mechanisms in §1.5)*

```javascript
// hook-local-file-access-webview.js
Java.perform(function () {
    function getBacktrace() {
        return Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());
    }

    var WebSettings = Java.use("android.webkit.WebSettings");
    ["setJavaScriptEnabled", "setAllowFileAccess", "setAllowFileAccessFromFileURLs", "setAllowUniversalAccessFromFileURLs"]
        .forEach(function (method) {
            try {
                WebSettings[method].overload("boolean").implementation = function (value) {
                    console.log("\n[*] WebSettings." + method + "(" + value + ")");
                    console.log("    Backtrace:\n" + getBacktrace());
                    return this[method](value);
                };
            } catch (e) { console.log("[x] Hook failed for " + method + ": " + e); }
        });

    // Coverage for mechanism #1: loadUrl
    var WebView = Java.use("android.webkit.WebView");
    WebView.loadUrl.overload("java.lang.String").implementation = function (url) {
        if (url.indexOf("file://") === 0) {
            var s = this.getSettings();
            console.log("\n[*] WebView.loadUrl(FILE) = " + url);
            console.log("    JavaScriptEnabled=" + s.getJavaScriptEnabled() +
                " AllowFileAccess=" + s.getAllowFileAccess() +
                " AllowFileAccessFromFileURLs(deprecated getter may be unavailable)" +
                " AllowUniversalAccessFromFileURLs=" + s.getAllowUniversalAccessFromFileURLs());
        }
        return this.loadUrl(url);
    };

    // Coverage for mechanism #2: loadDataWithBaseURL with a file:// base URL
    WebView.loadDataWithBaseURL.overload(
        "java.lang.String", "java.lang.String", "java.lang.String", "java.lang.String", "java.lang.String"
    ).implementation = function (baseUrl, data, mimeType, encoding, historyUrl) {
        if (baseUrl && baseUrl.indexOf("file://") === 0) {
            console.log("\n[*] WebView.loadDataWithBaseURL with a file:// base URL: " + baseUrl);
            console.log("    Backtrace:\n" + getBacktrace());
        }
        return this.loadDataWithBaseURL(baseUrl, data, mimeType, encoding, historyUrl);
    };
});
```

```bash
frida -U -f com.target.app -l hook-local-file-access-webview.js --no-pause
```

### 3.3 Method B — Enumerating WebView Instances

```javascript
// enumerate-webview-file-access.js
Java.perform(function () {
    Java.choose("android.webkit.WebView", {
        onMatch: function (instance) {
            var settings = instance.getSettings();
            console.log("\n[*] WebView instance:");
            console.log("    Current URL: " + instance.getUrl());
            console.log("    JavaScriptEnabled: " + settings.getJavaScriptEnabled());
            console.log("    AllowFileAccess: " + settings.getAllowFileAccess());
            console.log("    AllowUniversalAccessFromFileURLs: " + settings.getAllowUniversalAccessFromFileURLs());
        },
        onComplete: function () {}
    });
});
```

### 3.4 Method C — Multi-Version Android Testing *(addresses the §1.3-§1.4 limitation, MANDATORY)*

```bash
# 1. Identify minSdkVersion from the MASTG-TEST-0252 result
MINSDK=21  # example, from static extraction

# 2. Create/use an emulator with an API level EQUAL TO/CLOSE TO minSdkVersion
avdmanager create avd -n test-minsdk -k "system-images;android-${MINSDK};google_apis;x86_64"
emulator -avd test-minsdk &
frida -U -f com.target.app -l hook-local-file-access-webview.js --no-pause
# Explore thoroughly, record results

# 3. Compare against a modern-version emulator
avdmanager create avd -n test-modern -k "system-images;android-34;google_apis;x86_64"
emulator -avd test-modern &
frida -U -f com.target.app -l hook-local-file-access-webview.js --no-pause
# Explore thoroughly using the SAME scenarios, record results
```

Compare both results — if there is an **instance of a WebView without an explicit `setAllowFileAccess` call**, the result on the `minSdkVersion` emulator will show `AllowFileAccess: true` while the modern emulator shows `AllowFileAccess: false` — this difference **directly proves** the risk described in §1.3, and confirms that a PASS conclusion drawn from a modern device alone would be misleading.

### 3.5 Method D — objection

```bash
objection -g com.target.app explore
android hooking watch class_method android.webkit.WebSettings.setAllowFileAccess --dump-args --dump-backtrace
android hooking watch class_method android.webkit.WebView.loadDataWithBaseURL --dump-args --dump-backtrace
```

### 3.6 Method Comparison: Which One to Use When

| Method | Tool | Addresses the OS-version limitation? | When to use |
|---|---|---|---|
| **A** | Hook setters + loadUrl/loadDataWithBaseURL | ❌ (single device) | Primary baseline, single session |
| **B** | Enumerate instances | ❌ (single device) | Final effective value, single session |
| **C** | Multi-version emulator | ✅ | **Mandatory** for a conclusion that is genuinely valid per the official clause |
| **D** | objection | ❌ (single device) | Quick exploration |

**Minimum recommended combination:** **A (comprehensive hooking covering loadUrl + loadDataWithBaseURL) run on at least two different OS versions per Method C** — this is the only way this test's dynamic testing truly represents the official clause that explicitly names the `minSdkVersion` threshold.

---

### 3.7 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rule:** structurally identical to MASTG-TEST-0252 (see that document §1.4 for the full detail of the three-condition conditional logic), with an additional **Further Validation Required** clause that demands tracing `loadUrl("file://...")`/`loadDataWithBaseURL` and assessing whether attacker-controlled JavaScript can run in that context.

---

#### ❌ FAIL / ISSUE — The check is declared FAILED when:

| No | Condition |
|---|---|
| F1 | All three official conditions are satisfied **on the OS version relevant to the app's `minSdkVersion`** (not just whichever test device version happens to be used) |
| F2 | The `loadUrl`/`loadDataWithBaseURL` backtrace confirms the WebView loads content with a `file://` base |
| F3 | It is confirmed (MASTG-TECH-0023) that there is a path where untrusted JavaScript (HTML injection, manipulable content) can run within that `file://` context |
| F4 | The affected WebView handles sensitive information/functionality |

---

#### ✅ PASS — The check is declared PASSED when:

| No | Condition |
|---|---|
| P1 | Multi-version testing (Method C) confirms no FAIL condition combination exists on **any OS version** relevant to the app's `minSdkVersion` |
| P2 | A WebView loading `file://` is confirmed to load only fully trusted content (internal app assets, with no injection path) |
| P3 | All three APIs are explicitly set to `false` regardless of the OS version running them |

---

#### ⚠️ Important Notes on the Assessment

1. **This is the most important note in the entire document: testing on only one device/emulator is NOT SUFFICIENT for this test**, unlike most other dynamic tests in this research series. Per §1.3-§1.4, a PASS result from a modern device alone can be a **false negative** that conceals a real risk for the user population on older devices consistent with the app's `minSdkVersion`.

2. **Always cross-reference dynamic results with the `minSdkVersion` from MASTG-TEST-0252** — these two tests depend on each other more than the MASTG-TEST-0250/0251 pair does, because it is the static version that provides the `minSdkVersion` figure that determines which emulator must be used for valid dynamic testing.

3. **Instrumentation coverage must include `loadDataWithBaseURL`, not just `loadUrl`** — per §1.5, this is explicitly named in the official clause and is easily missed if one only mimics the hooking pattern from MASTG-TEST-0251.

4. **Explicitly document the OS version of each testing session** — a report that does not state the test device's Android version cannot have its validity assessed against the official clause, which depends on an API-level threshold.

5. **Severity follows the same pattern as the MASTG-TEST-0252 document** — modulated by the WebView's sensitivity and the real likelihood of injecting untrusted content into the `file://` context.

6. **Document:** the OS version of each testing session, results per version (for explicit comparison), the backtrace location of `loadUrl`/`loadDataWithBaseURL`, and the results of the MASTG-TECH-0023 analysis of potential content injection.

---

## 4. Recommendations

Refer to **the MASTG-TEST-0252 document §4** for identical full implementation recommendations (explicitly disable all three APIs, migrate to `WebViewAssetLoader`, raise `minSdkVersion`).

Additional recommendations specific to the dynamic perspective:

### 4.1 Integrate Multi-Version Testing into CI/CD

```bash
#!/bin/bash
# ci-multi-version-webview-check.sh
for AVD in "test-minsdk" "test-modern"; do
    emulator -avd "$AVD" &
    sleep 30
    frida -U -f com.target.app -l hook-local-file-access-webview.js --no-pause &
    FRIDA_PID=$!
    sleep 5
    ./run-ui-test-suite.sh
    kill $FRIDA_PID
    adb emu kill
done
```

### 4.2 Remediation Checklist

- [ ] Dynamic testing is run on at least two OS versions (close to `minSdkVersion` and a modern version)
- [ ] Hooking covers both `loadUrl` and `loadDataWithBaseURL`
- [ ] Results are correlated with the `minSdkVersion` from MASTG-TEST-0252
- [ ] Every finding has been reviewed via MASTG-TECH-0023 for potential untrusted content injection
- [ ] **Re-verify:** re-run MASTG-TEST-0253 on every relevant OS version after any change to the WebView implementation

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0253: Runtime Use of Local File Access APIs in WebViews](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0253/)
- [MASTG-TEST-0252: References to Local File Access in WebViews](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0252/)
- [MASTG-TEST-0251: Runtime Use of Content Provider Access APIs in WebViews](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0251/)
- [MASWE-0034: WebViews Allow Access to Local Resources with Untrusted Content](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0034/)
- [MASTG-KNOW-0018: WebViews](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0018/)
- [MASTG-TECH-0005, MASTG-TECH-0043, MASTG-TECH-0023](https://mas.owasp.org/MASTG/techniques/android/)

### 5.2 Official Android Documentation

- [Android Developers — `WebView#loadDataWithBaseURL`](https://developer.android.com/reference/android/webkit/WebView#loadDataWithBaseURL(java.lang.String,%20java.lang.String,%20java.lang.String,%20java.lang.String,%20java.lang.String))
- [Android Developers — `WebSettings` API reference](https://developer.android.com/reference/android/webkit/WebSettings)
- [Android Developers — Managing Virtual Devices (AVD)](https://developer.android.com/studio/run/managing-avds)

### 5.3 Tool Documentation

- [Frida — Dynamic instrumentation toolkit](https://frida.re/docs/javascript-api/)
- [Objection — Runtime Mobile Exploration toolkit](https://github.com/sensepost/objection)
- [Android SDK — `avdmanager` command-line tool](https://developer.android.com/tools/avdmanager)

---

*This document was prepared based on OWASP MASTG (current release as of September 2026) and official Android Developers documentation. As the dynamic counterpart of MASTG-TEST-0252, the deep conceptual context is covered in full in that document. The most important methodological finding of this document: unlike the MASTG-TEST-0250/0251 pair, this test requires testing on **more than one Android version** — because its evaluation clause still depends on a `minSdkVersion` threshold that cannot be represented by a single dynamic testing session on a single device/emulator, regardless of whichever OS version the tester happens to use.*
