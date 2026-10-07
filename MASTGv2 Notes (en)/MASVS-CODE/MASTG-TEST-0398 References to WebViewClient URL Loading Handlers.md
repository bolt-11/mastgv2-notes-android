# MASTG-TEST-0398 References to WebViewClient URL Loading Handlers

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0398 |
| **Platform** | Android |
| **MASVS Category** | MASVS-CODE |
| **Weakness** | MASWE-0035 |
| **Test Type** | Static, Code, **Manual** |
| **Related APIs** | `WebView`, `WebViewClient`, `shouldOverrideUrlLoading`, `shouldInterceptRequest`, `setWebViewClient` |
| **Related Techniques** | MASTG-TECH-0013, MASTG-TECH-0014, MASTG-TECH-0023 |
| **Related Knowledge** | MASTG-KNOW-0018 (WebViews) |
| **Official Rule** | `mastg-android-webview-url-handlers.yml` — two rules, one presence-based and one bonus rule for a related topic, see §1.4 |

---

## 1. Explanation

### 1.1 Testing Objective and the "Safest Default" Baseline

Quote from the official MASTG overview:

> *"The default and safest behavior on Android is to let the default web browser open any link that the user clicks inside the WebView. However, this can be modified by configuring a WebViewClient with custom URL handling logic."*

This is an important starting point — **doing nothing** (not replacing the default `WebViewClient`) is already the safest configuration, because navigation is automatically forwarded to the user's external browser, which has its own security model separate from the application's context. The risk arises **precisely when a developer actively intervenes** in this default behavior — a case where "doing more" (adding custom control) can create new risk if done improperly, rather than reducing risk as intended.

### 1.2 Two Interception Methods with Different and Incomplete Coverage

The overview gives important technical detail about the **coverage limitations** of each method — this is not merely an API detail, but a hidden source of risk if the developer makes the wrong assumption:

> *"`shouldOverrideUrlLoading`... Note that this method is **not called** for POST requests, XmlHttpRequests, iFrames, 'src' attributes in HTML, or `<script>` tags."*

> *"`shouldInterceptRequest`... This callback is invoked for various URL schemes... but **not** for `javascript:` or `blob:` URLs, or for assets accessed via `file:///android_asset/` or `file:///android_res/`."*

This is a very important finding for security evaluation — a developer who implements `shouldOverrideUrlLoading` with a perfect domain allowlist can **still be bypassed** if the loaded page contains an `<iframe>` to another domain, an `XMLHttpRequest`/`fetch` request to a malicious endpoint, or a `<script src="...">` tag — none of these ever pass through that well-protected method at all. Validation that looks strong on one method can give a false **illusion of security** if the developer is unaware of other request types that are not filtered at all.

### 1.3 AND Logic in the FAIL Criteria: Implementation Must Exist, But Must Also Be Correct

> **Evaluation:** *"The test case fails if a WebViewClient URL interception method is implemented without properly restricting navigation to trusted content."*

This evaluation structure implicitly contains two conditions — the interception method **must exist** (not left as the empty default) **and** its implementation must effectively restrict navigation. But there is a third nuance that actually **reverses** the usual direction — the further-validation section introduces a unique finding category:

> *"**Missing client implementation:** a WebViewClient is assigned to a WebView via setWebViewClient without overriding any interception method, leaving the default (unrestricted) navigation behavior in place for an app that intended to restrict it."*

This is an interesting case — the developer **calls** `setWebViewClient()` (indicating the **intent** to control the WebView's behavior), but **forgets** to actually override `shouldOverrideUrlLoading`/`shouldInterceptRequest` within it. The result: navigation behavior remains **unrestricted** (just as if nothing had been done, per §1.1), **yet** the developer likely **believes** they have implemented a control — a gap between intent and actual implementation that can slip past a cursory review because `setWebViewClient()` does look like a security step that has "already been taken."

### 1.4 Official Rule Analysis: Purely Presence-Based, Plus a Bonus Rule for a Related Topic

The first rule (`mastg-android-webviewclient-url-handlers`) has **INFO severity**, consistent with this test's purely manual nature — the rule only flags the **presence** of the five API patterns named in the frontmatter (classes extending `WebViewClient` with overridden methods, calls to those methods, and `setWebViewClient`), **without** attempting to assess whether the implementation is secure. This is consistent with the "honest rule" pattern already found in several other tests in this research series (TEST-0394) — this limitation is **acknowledged by design**, not a hidden weakness.

The second rule (`mastg-android-webviewclient-safebrowsing-whitelist`) targets a topic that is **closely related but distinct** — Safe Browsing customization (`setSafeBrowsingWhitelist`, `onSafeBrowsingHit`), which is **not mentioned at all** in this test's `apis:` frontmatter. This is likely a "bonus rule" bundled into the same YAML file because the topic is related (both concern WebView navigation control), but it is strictly **outside the declarative scope** of the MASTG-TEST-0398 test — testers should treat findings from the second rule as useful supplementary information, not as part of this test's core evaluation.

### 1.5 Real-World Evidence: CWE-346 — A Substring-Validation Weakness Matching the Official Evaluation Exactly

The official evaluation explicitly names a very specific weakness pattern:

> *"Weak validation: the method performs validation that does not reliably prevent navigation to untrusted domains (for example, substring checks instead of validating the host)."*

Security research confirms that this pattern is already documented as a real CWE-346 (Origin Validation Error) class weakness found in production applications:

> *"The vulnerability involves Android applications that intercept URL loading within a WebView and use substring checks like `url.substring(0,14).equalsIgnoreCase('examplescheme:')` for validation, without properly checking the URL origin... Because the application does not check the source, a malicious website loaded within this WebView has the same access to the API as a trusted site."*

The documented remediation is also very specific and immediately actionable:

> *"A more secure approach is to use `Uri.parse(url).getHost().equals(URL)` to properly extract and validate the host portion of the URL, rather than relying on simple substring checks."*

Illustration of why a substring check fails: validation such as `url.contains("trusted-domain.com")` would **incorrectly pass** malicious URLs such as `https://evil.com/?redirect=trusted-domain.com` or `https://trusted-domain.com.evil.com/phishing` — both contain the string `"trusted-domain.com"`, yet the **actual host** is an attacker-owned domain. Only by properly parsing the URL and comparing the parsed **host** (not the raw URL string) does the validation become reliable.

---

## 2. Tools Used for Testing

### 2.1 Required Tools (Core)

| Tool | Function |
|---|---|
| **jadx** | Decompiles DEX → Java for manual review (MASTG-TECH-0013, MASTG-TECH-0023) |
| **Semgrep** + official rule | Quickly locating `WebViewClient` implementations (MASTG-TECH-0014) |

### 2.2 Alternative & Supporting Tools

| Tool | Function |
|---|---|
| **grep/ripgrep** | Searching for substring-validation patterns (`contains`, `startsWith`, `endsWith`) around URL-handler implementations for quick triage of the weakness in §1.5 |
| **Frida** | Dynamic verification — hooking `shouldOverrideUrlLoading` to observe the actual URLs processed and the decision outcome (allow/block) at runtime |

### 2.3 Environment Prerequisites

- No device/root needed for static analysis.
- Dynamic verification (optional) requires a device/emulator to load test pages with URLs crafted to test validation gaps.

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0013** to reverse engineer the application.
2. Use **MASTG-TECH-0014** to search for relevant APIs.

### 3.2 Method A — Semgrep with the Official Rule

```bash
semgrep --config mastg-android-webview-url-handlers.yml ./decompiled/sources
```

### 3.3 Method B — grep/ripgrep to Triage Weak Validation Patterns (Per §1.5)

```bash
D=./decompiled/sources

# Find shouldOverrideUrlLoading/shouldInterceptRequest implementations
rg -n -A15 'shouldOverrideUrlLoading\(|shouldInterceptRequest\(' $D

# Quick triage of substring-based validation patterns (weakness candidates)
rg -n -B5 -A5 'shouldOverrideUrlLoading' $D | grep -E '\.contains\(|\.startsWith\(|\.endsWith\('

# Compare against the correct pattern (host parsing)
rg -n 'Uri\.parse\(.*\)\.getHost\(\)' $D
```

### 3.4 Method C — Verifying Missing Client Implementation (Per §1.3)

```bash
# Find calls to setWebViewClient, then verify whether the class passed actually overrides any interception method
rg -n 'setWebViewClient\(' $D
```

For each result, trace the `WebViewClient` class passed — does it actually override `shouldOverrideUrlLoading`/`shouldInterceptRequest`, or is it just an empty/anonymous class with no overrides at all?

### 3.5 Method D — Complete Manual Review (Mandatory, Per MASTG-TECH-0023)

For each implementation found, verify:
1. Does the validation use correct host parsing, rather than raw substring matching?
2. Does the validation account for the methods' limited coverage (§1.2) — are there other paths (iframe, XHR, script src) that need protection via additional mechanisms?

### 3.6 Method Comparison: When to Use Which

| Method | Tool | When to Use |
|---|---|---|
| **A** | Semgrep + official rule | Baseline — locating implementations |
| **B** | grep/ripgrep manual | Quick triage of weak (substring) validation patterns |
| **C** | grep manual | Detecting "missing client implementation" (§1.3) |
| **D** | Manual review | **Required** — the core of this test, assessing the correctness of validation |

**Minimum recommended combination:** **A (location) → B + C (triage) → D (mandatory)**.

---

### 3.7 Evaluation Criteria: Positive Case & Negative Case

---

#### ❌ FAIL / ISSUE — The check is declared FAILED if:

| No | Condition |
|---|---|
| F1 | The interception method has no validation at all before allowing navigation |
| F2 | The validation uses a bypassable substring check (instead of correct host parsing) |
| F3 | `setWebViewClient` is called, but the class passed does not override any interception method |

**Evidence example (reflecting the real CWE-346 pattern, §1.5):**

```java
@Override
public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
    String url = request.getUrl().toString();
    if (url.contains("trusted-domain.com")) { // VULNERABLE — substring check
        return false; // allow navigation
    }
    return true;
}
```

Interpretation: a URL such as `https://trusted-domain.com.evil.com/phishing` would **incorrectly pass** the validation because it contains the searched-for substring. **FAIL**.

---

#### ✅ PASS — The check is declared PASSED if:

| No | Condition |
|---|---|
| P1 | The validation uses `Uri.parse(url).getHost()` and compares it with an **exact match** against an allowed-domain allowlist, **and** |
| P2 | Awareness of the methods' limited coverage (iframe/XHR/script) is addressed via additional mechanisms where relevant (CSP, sandboxing), **or** |
| P3 | `WebViewClient` is not replaced at all (safe default, §1.1) |

**Evidence example:**

```java
@Override
public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
    String host = request.getUrl().getHost();
    if (host != null && (host.equals("trusted-domain.com") || host.endsWith(".trusted-domain.com"))) {
        return false;
    }
    return true;
}
```

**PASS**.

---

#### ⚠️ Important Notes on Assessment

1. **Always check whether the validation uses host parsing rather than a raw substring** — this is the most common and most easily verified weakness per §1.5.

2. **Watch for the "missing client implementation" case** — a `setWebViewClient()` call that looks like a security step but has no override at all inside it still leaves navigation behavior unrestricted (§1.3); do not be fooled by the mere presence of the API call.

3. **Consider the limited coverage of both methods** — strong validation on `shouldOverrideUrlLoading` does not protect against content loaded via iframe/XHR/script tags; for comprehensive protection, consider additional controls at the page-content level itself (CSP) or disabling JavaScript when not required.

4. **Severity is modulated as follows:**

   | Factor | Severity |
   |---|---|
   | No validation at all, or an easily bypassable substring validation, in a WebView loading sensitive content/credentials | **High** |
   | Host validation is correct but does not account for limited coverage (iframe/XHR) | **Medium** |
   | Host-parsing validation is correct and complete, or the default WebViewClient is not replaced | **Not a finding** |

5. **Document:** the location of the `WebViewClient` class, the method(s) implemented (or not), the type of validation used (substring vs host parsing), and the test results with crafted test URLs designed to probe the gap (`trusted-domain.com.evil.com`, etc.).

---

## 4. Recommendations

### 4.1 Use Correct Host Parsing with Exact Match

```java
private static final Set<String> ALLOWED_HOSTS = Set.of("trusted-domain.com", "api.trusted-domain.com");

@Override
public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
    String host = request.getUrl().getHost();
    return host == null || !ALLOWED_HOSTS.contains(host); // true = block
}
```

### 4.2 Make Sure the Override Is Actually Applied When setWebViewClient Is Called

```java
// BEFORE — intent is there, implementation is empty
webView.setWebViewClient(new WebViewClient()); // no override at all

// AFTER — explicit override
webView.setWebViewClient(new WebViewClient() {
    @Override
    public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
        // validate host here
        return !isAllowedHost(request.getUrl().getHost());
    }
});
```

### 4.3 Remediation Checklist

- [ ] All URL validation uses host parsing (`Uri.getHost()`), with no substring checks
- [ ] Every call to `setWebViewClient` is paired with a genuinely active interception method override
- [ ] Awareness of the methods' limited coverage is accounted for (CSP/disable JavaScript where appropriate)
- [ ] Tested with URL payloads crafted to probe substring gaps (`trusted.com.evil.com`, `evil.com?trusted.com`)

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0398 (source, tests-beta)](https://github.com/OWASP/mastg/blob/master/tests-beta/android/MASVS-CODE/MASTG-TEST-0398.md)
- [MASTG-KNOW-0018: WebViews](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0018/)

### 5.2 Official Documentation

- [Android Developers: WebViewClient#shouldOverrideUrlLoading](https://developer.android.com/reference/android/webkit/WebViewClient#shouldOverrideUrlLoading(android.webkit.WebView,%20android.webkit.WebResourceRequest))
- [Android Developers: WebViewClient#shouldInterceptRequest](https://developer.android.com/reference/android/webkit/WebViewClient#shouldInterceptRequest(android.webkit.WebView,%20android.webkit.WebResourceRequest))

### 5.3 Research and Real-World Cases

- [CWE-346: Origin Validation Error](https://www.pentestreports.com/cwe/CWE-346)

### 5.4 Tool Documentation

- [Semgrep Documentation](https://semgrep.dev/docs/)
- [Frida — Dynamic Instrumentation Toolkit](https://frida.re/docs/home/)

---

*This document was prepared based on official OWASP MASTG content (`tests-beta/android/MASVS-CODE/MASTG-TEST-0398.md`, `MASTG-KNOW-0018`), analysis of the `mastg-android-webview-url-handlers.yml` rule, and CWE-346 research confirming the substring-validation weakness pattern that exactly matches what the official evaluation names explicitly. The most important methodological nuance: the two interception methods (`shouldOverrideUrlLoading`/`shouldInterceptRequest`) have **incomplete coverage** — each is not invoked for certain categories of requests (POST/XHR/iframe/script for the first; javascript:/blob: for the second) — creating an illusion of security if the developer is unaware of this gap. The evaluation also recognizes a unique finding category of "missing client implementation": a call to `setWebViewClient()` that looks like a security control but has no method override inside it at all, leaving navigation behavior unrestricted even though the developer believes a restriction has been applied.*
