# MASTG-TEST-0400 Runtime Use of WebViewClient URL Loading Handlers

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0400 |
| **Platform** | Android |
| **MASVS Category** | MASVS-CODE |
| **Weakness** | MASWE-0035 |
| **Test Type** | Dynamic, Hooks, **Manual** |
| **Related APIs** | `WebView`, `WebViewClient`, `shouldOverrideUrlLoading`, `shouldInterceptRequest`, `Uri`, `getHost`, `getScheme`, `getPath` |
| **Related Techniques** | MASTG-TECH-0005, MASTG-TECH-0043, MASTG-TECH-0023 |
| **Related Knowledge** | MASTG-KNOW-0018 (WebViews) |
| **Related Tests** | **MASTG-TEST-0398** — static counterpart already covered in depth in this research series; this test is a **direct runtime confirmation** |
| **Official Rule** | — (none exists; purely dynamic) |

---

## 1. Explanation

### 1.1 Testing Objective and the Added Value Compared to Static Analysis

Quote from the official MASTG overview:

> *"This test dynamically analyzes the runtime behavior of WebViewClient URL interception methods... By hooking relevant methods at runtime, you can observe: Which URLs are being loaded and intercepted. How the app validates or filters URLs. Whether the app implements allowlist or denylist patterns. What decisions the app makes when encountering different URL schemes or domains."*

This is the dynamic counterpart to **MASTG-TEST-0398**, already covered in depth in this research series. The dynamic added value here is very concrete and practical: instead of **reading** the validation logic in decompiled code and **manually inferring** whether it uses a substring check or correct host parsing (the approach used in TEST-0398), this test lets the tester **directly try** specially crafted malicious URLs and **observe the actual decision outcome** (the `true`/`false` returned by the method) empirically — eliminating any ambiguity from code interpretation that might be complex or obfuscated.

### 1.2 Requested Observations: URL, Decision, and Parsing Operations

The official Observation section specifically requests three types of data:

> *"A list of URLs that were intercepted... The return values of these methods (indicating whether the URL was allowed or blocked). Any URL parsing operations performed using Uri methods."*

This third point matters — observing **`Uri` parsing operations** (`getHost()`, `getScheme()`, `getPath()`) separately from just the URL and the final decision lets the tester see **how** validation was performed, not just **what** the result was. If the hook shows that `getHost()` was **never called at all** for a URL that was still allowed, this indicates that the validation used is likely based on a raw substring match against the URL string, rather than correct host parsing — exactly the CWE-346 weakness already covered in depth in the TEST-0398 document.

### 1.3 Evaluation Criteria: Focused on Actual Outcomes, Not Code Patterns

> **Evaluation:** *"The test case fails if the runtime analysis shows that a URL is loaded or a resource request is served without the app validating it against trusted content."*

An important difference from TEST-0398: evaluation here is based purely on **what actually happens** when a test URL is tried, not on an assessment of code patterns. This means that even if the code looks complex/obfuscated enough that static analysis struggles to conclude whether the validation is correct, the dynamic test can still provide a definitive answer: try a malicious URL, observe whether it is actually blocked or allowed.

### 1.4 Reaffirmation: Intercepting Itself Is Not the Problem, the Implementation Is What Gets Assessed

> *"Note that intercepting URL loading is not inherently insecure. The test fails only when the implementation does not properly restrict navigation to trusted content."*

This principle is identical to what was already established in the TEST-0398 document — whether assessed statically or dynamically, custom intervention in WebView navigation is not inherently problematic; what is assessed is the **effectiveness** of the restriction.

---

## 2. Tools Used for Testing

### 2.1 Required Tools (Core)

| Tool | Function |
|---|---|
| **Frida** | Hooking `shouldOverrideUrlLoading`/`shouldInterceptRequest`/`Uri` methods for runtime observation (MASTG-TECH-0043) |
| **ADB** | Installing the app, triggering WebView navigation with test deep links (MASTG-TECH-0005) |

### 2.2 Alternative & Supporting Tools

| Tool | Function |
|---|---|
| **Local/test HTTP server (mitmproxy acting as a web server)** | Hosting a test page containing links to various crafted URLs (including substring-bypass payloads) to be triggered naturally through WebView interaction |

### 2.3 Environment Prerequisites

- Rooted device/emulator with `frida-server`.
- A list of test URL payloads crafted to probe validation gaps (see §3.3), including variants that precisely replicate the CWE-346 pattern from the TEST-0398 document.

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0005** to install the application.
2. Use **MASTG-TECH-0043** to hook the relevant APIs.
3. Exercise the application extensively to trigger as many flows as possible and enter sensitive data.

### 3.2 Method A — Frida: Full Hook with Decision and Uri-Parsing Observation

```javascript
Java.perform(function () {
    var WebViewClient = Java.use("android.webkit.WebViewClient");

    WebViewClient.shouldOverrideUrlLoading.overload(
        'android.webkit.WebView', 'android.webkit.WebResourceRequest'
    ).implementation = function (view, request) {
        var url = request.getUrl().toString();
        var result = this.shouldOverrideUrlLoading(view, request);
        console.log("[shouldOverrideUrlLoading] url=" + url + " -> result(override)=" + result +
            " (false means the WebView STILL loads this URL)");
        return result;
    };

    var Uri = Java.use("android.net.Uri");
    Uri.getHost.implementation = function () {
        var host = this.getHost();
        console.log("[Uri.getHost] called -> " + host);
        return host;
    };
});
```

```bash
frida -U -f com.example.targetapp -l hook_webviewclient.js --no-pause
```

### 3.3 Method B — Active Testing with Crafted URL Payloads (Replicating CWE-346)

Prepare a test HTML page containing the following links, or trigger them directly via deep link if the WebView accepts navigation from outside:

```
https://trusted-domain.com.evil.com/phishing
https://evil.com/?redirect=trusted-domain.com
https://trusted-domain.com@evil.com/
```

Observe the Method A hook's output for each payload — does `shouldOverrideUrlLoading` return `false` (allowing navigation) for a URL that **should** be blocked?

### 3.4 Method C — Verifying the Methods' Limited Coverage (Per the TEST-0398 Nuance, §1.2)

```html
<!-- Test page loading an iframe to an untrusted domain -->
<iframe src="https://evil.com/malicious-content"></iframe>
```

Observe whether the `shouldOverrideUrlLoading`/`shouldInterceptRequest` hooks **are not triggered at all** for this iframe content — empirically confirming the coverage limitation already discussed in TEST-0398, and showing that strong validation on the main navigation path does not protect against this vector.

### 3.5 Method Comparison: When to Use Which

| Method | Tool | When to Use |
|---|---|---|
| **A** | Frida hooking | Mandatory baseline — passive observation |
| **B** | Crafted URL payloads | **Required** — conclusive evidence of a substring-bypass gap |
| **C** | iframe payload | Confirming the methods' limited coverage |

**Minimum recommended combination:** **A + B (mandatory)**, with **C** as a supplement for a comprehensive audit.

---

### 3.6 Evaluation Criteria: Positive Case & Negative Case

---

#### ❌ FAIL / ISSUE — The check is declared FAILED if:

| No | Condition |
|---|---|
| F1 | A malicious URL (crafted payload, §3.3) is observed to be allowed (`shouldOverrideUrlLoading` returns `false`/navigation still occurs) even though it should have been rejected |

**Evidence example (direct replication of CWE-346 from TEST-0398):**

```
[shouldOverrideUrlLoading] url=https://trusted-domain.com.evil.com/phishing -> result(override)=false (navigation ALLOWED)
[Uri.getHost] NEVER called for this request
```

Interpretation: the phishing URL successfully passed, and the absence of a `getHost()` call confirms that the validation is indeed based on a raw substring, not host parsing. **FAIL**.

---

#### ✅ PASS — The check is declared PASSED if:

| No | Condition |
|---|---|
| P1 | All malicious URL payloads (§3.3) are observed to be blocked (`shouldOverrideUrlLoading` returns `true`), **and** |
| P2 | `Uri.getHost()` is observed being called as part of the validation logic |

---

#### ⚠️ Important Notes on Assessment

1. **Use payloads that specifically probe the substring gap** — random payloads are not sufficient; per §3.3, payloads must be crafted to textually resemble a trusted domain while differing in actual host.

2. **Correlate with MASTG-TEST-0398's results** — if the static analysis found a substring-check pattern but the dynamic test did not yet try the relevant payload, the dynamic result is not yet conclusive; conversely, if the dynamic test has already proven the bypass succeeds, this is the strongest evidence to include in the report.

3. **Also test the iframe/XHR path (Method C)** — a hook failing to trigger here is not a Frida-script bug, but confirmation of the method's own architectural limitation.

4. **Severity is modulated** the same way as the TEST-0398 criteria: high if the bypass succeeds on a WebView loading sensitive content/credentials, with dynamic evidence giving a higher confidence level for the report than a static finding alone.

5. **Document:** the URL payloads tried, the decision outcome for each payload, whether `getHost()`/`getScheme()` was called, and the backtrace of the related code location.

---

## 4. Recommendations

The recommendations are identical to its static counterpart (MASTG-TEST-0398) — use host parsing with exact match, not a substring check. See that document for complete implementation details.

### Remediation Checklist

- [ ] All test URL payloads (§3.3) are confirmed to be blocked after the fix
- [ ] `Uri.getHost()` is confirmed to be called and used as the basis for the validation decision
- [ ] iframe/XHR payloads are tested separately to assess the need for additional controls (CSP) beyond `WebViewClient`
- [ ] Dynamic test results are documented as supporting evidence for the static findings of MASTG-TEST-0398

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0400 (source, tests-beta)](https://github.com/OWASP/mastg/blob/master/tests-beta/android/MASVS-CODE/MASTG-TEST-0400.md)
- [MASTG-TEST-0398 (static counterpart document in this research series)](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0398/)
- [MASTG-KNOW-0018: WebViews](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0018/)

### 5.2 Tool Documentation

- [Frida — Dynamic Instrumentation Toolkit](https://frida.re/docs/home/)

---

*This document was prepared based on official OWASP MASTG content (`tests-beta/android/MASVS-CODE/MASTG-TEST-0400.md`, `MASTG-KNOW-0018`), supplemented by an in-depth cross-reference with the MASTG-TEST-0398 document (its static counterpart) in this research series, which already discusses the CWE-346 weakness (substring validation) in depth. The most important methodological nuance: the added value of this dynamic test is the ability to **empirically prove** whether a substring-bypass gap can actually be exploited — by trying specially crafted URL payloads (`trusted-domain.com.evil.com`) and observing the actual decision outcome, rather than merely inferring from a reading of static code that might be ambiguous. Observing the call (or absence of a call) to `Uri.getHost()` provides additional evidence of the validation mechanism the application actually uses at runtime.*
