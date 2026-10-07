# MASTG-TEST-0284 Incorrect SSL Error Handling in WebViews

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0284 |
| **Platform** | Android |
| **MASVS Category** | MASVS-NETWORK (MASVS-NETWORK-2) |
| **Weakness** | MASWE-0027 — *Insecure Certificate Validation* (the same group as MASTG-TEST-0234/0282/0283 in this research series) |
| **API in focus** | `WebViewClient#onReceivedSslError(...)`, `SslErrorHandler#proceed()`, `SslErrorHandler#cancel()` |
| **Test Type** | Static, Code, **Manual** |
| **Profile** | L1, L2 |
| **Knowledge** | MASTG-KNOW-0010 (Exception Handling, MASVS-CODE — same as referenced by MASTG-TEST-0282) |
| **Best Practice** | MASTG-BEST-0021 (Ensure Proper Error and Exception Handling) |
| **Related Techniques** | MASTG-TECH-0013, MASTG-TECH-0014, MASTG-TECH-0023 (mandatory further validation) |
| **Related Tests** | **MASTG-TEST-0234/0282/0283** — all four tests together form the complete "incorrectly implemented TLS validation" group on Android, each targeting a different API (`SSLSocket`, `X509TrustManager`, `HostnameVerifier`, and now `WebViewClient`) |
| **Related Demo** | — (none) |
| **Official Rule** | `mastg-android-network-onreceivedsslerror.yml` — **an identical claim-vs-implementation pattern** to the two other rules already discussed in MASTG-TEST-0282/0283 (see §3.2) |
| **Related CWE** | CWE-295, CWE-297 |

---

## 1. Explanation

### 1.1 Testing Objective and Its Position as the Fourth Member of the TLS Validation "Quartet"

Quote from the official MASTG overview:

> *"This test evaluates whether an Android app has WebViews that ignore SSL/TLS certificate errors by overriding the `onReceivedSslError(...)` method without proper validation."*

This test completes the **full quartet** of Android TLS validation weaknesses discussed in this research series — all four share the same weakness (MASWE-0027) but target **four different API surfaces**:

| Test | API Targeted | Connection Context |
|---|---|---|
| MASTG-TEST-0234 | `SSLSocket` without a `HostnameVerifier` | Low-level TLS socket |
| MASTG-TEST-0282 | Flawed `X509TrustManager.checkServerTrusted()` | Custom certificate chain validation |
| MASTG-TEST-0283 | Flawed `HostnameVerifier.verify()` | Custom hostname validation |
| **MASTG-TEST-0284** *(this document)* | Flawed `WebViewClient.onReceivedSslError()` | **Content loaded inside a WebView** |

This difference in context is important: the three preceding tests target an app's **native networking API traffic** (custom HTTP client), while this test specifically targets **traffic occurring inside a WebView component** — a different attack surface because it involves rendering web content, not merely pure API data exchange.

### 1.2 The `onReceivedSslError()` Mechanism: A Safe Default Design, Undermined by Override

`WebViewClient.onReceivedSslError()` is triggered when the WebView encounters an **SSL/TLS certificate error** while loading a page. The crucial point from the official overview:

> *"By default, the `WebView` cancels the request to protect users from insecure connections."*

This means **Android's default behavior is already safe** — without the developer doing anything, the WebView will **reject** a connection with a problematic certificate. This vulnerability arises **purely because the developer actively takes over (overrides)** this behavior and **incorrectly** calls `SslErrorHandler.proceed()` — the method that explicitly tells the WebView to **continue** the connection despite a detected certificate error:

```java
@Override
public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {
    handler.proceed();  // DANGEROUS — ignores any certificate error
}
```

This pattern is structurally similar to the "trust manager that does nothing" anti-pattern in MASTG-TEST-0282 — in both cases, the developer **deliberately disables** a built-in protective mechanism that was actually already working correctly without their intervention.

### 1.3 A Very Firm Official Guideline: Never `proceed()`, Never Ask the User

This is the most interesting part of this test — the official overview quotes a **very categorical official Android guideline**, without the contextual exceptions seen in other tests:

> *"According to official Android guidance, apps should never call `proceed()` in response to SSL errors. The correct behavior is to cancel the request to protect users from potentially insecure connections. **User prompts are also discouraged, as users cannot reliably evaluate SSL issues.**"*

This second point is especially important to understand — many developers **try to "do the right thing"** by displaying a confirmation dialog to the user before continuing a problematic connection ("This site's certificate is invalid. Continue?"), considering this a reasonable compromise between security and functionality. **Official Android guidance explicitly rejects this approach** — because ordinary users **lack the technical capacity** to assess whether an SSL certificate error is genuinely dangerous or not; handing this critical security decision to the user is essentially **transferring security responsibility without giving any real ability to make the correct decision** — similar to why modern browser MITM warnings (e.g., Chrome) are deliberately made difficult to bypass with a simple click.

### 1.4 Three Anti-Patterns from the "Further Validation Required" Clause

**1. Accepting an SSL error unconditionally** — the simplest and most extreme pattern, `proceed()` is called without any check on the received `SslError` object.

**2. Only relying on the primary error code** — a more subtle pattern that often escapes code review:

```java
@Override
public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {
    if (error.getPrimaryError() != SslError.SSL_UNTRUSTED) {
        handler.proceed();  // DANGER: ignores OTHER errors that may exist in the chain
    } else {
        handler.cancel();
    }
}
```

`SslError.getPrimaryError()` only returns **one** error code considered most significant by the system — however, the actual `SslError` object can carry **a combination of multiple error types** at once in a single certificate chain (e.g., an expired certificate **and** a hostname mismatch simultaneously). Code that only checks `getPrimaryError()` and assumes "as long as it's not `SSL_UNTRUSTED`, it's safe to continue" risks **missing** another error type that is equally dangerous but happens not to be the "primary" one in the system's evaluation.

**3. Silently swallowing exceptions** — a pattern that directly connects this test to **MASVS-CODE (Exception Handling)**, per the official reference to MASTG-KNOW-0010/MASTG-BEST-0021 (the same pattern already discussed in the MASTG-TEST-0282 document, §1.4):

```java
@Override
public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {
    try {
        validateCertificate(error);
    } catch (Exception e) {
        // SWALLOWED — no handler.cancel() called here!
        // The connection silently CONTINUES because no explicit action was taken
    }
}
```

This is the most dangerous hidden **"fail-open"** pattern — if `validateCertificate()` throws an exception (e.g., due to a bug/unexpected edge case) and that exception is **caught but not followed by an explicit `cancel()` call**, the WebView could **still proceed** with the loading process (depending on the default `SslErrorHandler` implementation if no explicit action is taken) — a silent failure far harder to detect than pattern #1, which explicitly calls `proceed()`.

---

## 2. Tools Used for Testing

### 2.1 Mandatory Tools (Core)

| Tool | Function |
|---|---|
| **jadx** | DEX → Java decompilation to find `onReceivedSslError()` overrides |
| **grep / ripgrep** | Searching for implementation patterns and verifying the `SslError` handling logic |
| **semgrep** | Running the official rule as a location baseline |

### 2.2 Alternative & Supporting Tools

| Tool | Function |
|---|---|
| **CodeQL** | Tracing the **content** of the `onReceivedSslError()` method — whether `proceed()` is called unconditionally, whether it only relies on `getPrimaryError()`, whether there is a `catch` path without `cancel()` |
| **MobSF** | Sometimes flags an `onReceivedSslError` pattern that calls `proceed()` in the Code Analysis report |
| **Frida** | Hooking `onReceivedSslError()` and `SslErrorHandler.proceed()`/`cancel()` for runtime confirmation — can trigger a genuine certificate error (via mitmproxy with an invalid certificate) to observe the WebView's real reaction |
| **mitmproxy with an invalid certificate** | A definitive dynamic test — present an expired/self-signed certificate to the target WebView and observe whether content still loads |

### 2.3 Environment Prerequisites

- **No device/root required** for core static analysis.
- **Requires a device + mitmproxy for dynamic confirmation** (optional but strongly reinforces evidence).
- **Manual review (MASTG-TECH-0023) is absolutely required**, consistent with the `manual` tag.

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0013** to reverse engineer the app.
2. Use **MASTG-TECH-0014** to search for the relevant API.

### 3.2 Method A — Official Semgrep Rule *(the same claim-vs-implementation pattern as MASTG-TEST-0282/0283)*

```yaml
rules:
  - id: mastg-android-network-onreceivedsslerror
    severity: WARNING
    languages: [java]
    metadata:
      summary: This rule looks for the use of onReceivedSslError and ensures it throws an exception instead of silently muting TLS errors.
    message: Improper use of onReceivedSslError handler
    match:
      any:
        - public void onReceivedSslError(...) {...}
```

```bash
semgrep --config https://raw.githubusercontent.com/OWASP/mastg/master/rules/mastg-android-network-onreceivedsslerror.yml ./decompiled/sources/
```

**This is the third identical pattern found in a row** within the TLS validation test group (MASTG-TEST-0282, 0283, and now 0284) — the rule's `summary` claims **"ensures it throws an exception instead of silently muting TLS errors,"** yet the pattern `{...}` that is actually executed is merely a **wildcard body match**, matching **every** override of `onReceivedSslError()` regardless of its content — whether it correctly calls `cancel()` or dangerously calls `proceed()` unconditionally. This confirms a pattern already identified as a systemic issue in the "unsafe implementation" rules of MASTG for this category of custom TLS validation — all three consistently function only as **location maps**, not security evaluators, even though their textual descriptions claim otherwise.

### 3.3 Method B — grep/ripgrep for All Three Anti-Patterns

```bash
D=./decompiled/sources

# Pattern #1: proceed() without any condition at all
rg -n -B10 'handler\.proceed\(\)|\.proceed\(\)' $D | grep -B10 "onReceivedSslError"

# Pattern #2: only relying on getPrimaryError()
rg -n -B5 -A10 'onReceivedSslError' $D | grep -B5 -A5 'getPrimaryError\(\)'

# Pattern #3: try-catch without an explicit cancel()
rg -n -B3 -A15 'onReceivedSslError' $D | grep -B3 -A15 'catch\s*(' | grep -v 'cancel()'
```

### 3.4 Method C — CodeQL for All Three Patterns at Once

```ql
import java

class OnReceivedSslErrorMethod extends Method {
  OnReceivedSslErrorMethod() {
    this.hasName("onReceivedSslError") and
    this.getDeclaringType().getASupertype*().hasQualifiedName("android.webkit", "WebViewClient")
  }
}

// Pattern #1: proceed() called without being guarded by any condition
from OnReceivedSslErrorMethod m, MethodAccess proceedCall
where proceedCall.getMethod().hasName("proceed") and
      proceedCall.getEnclosingCallable() = m and
      not exists(IfStmt guard | guard.getAChild*() = proceedCall)
select proceedCall, "proceed() called WITHOUT any condition — accepts all SSL errors"
```

```ql
// Pattern #3: try-catch within onReceivedSslError without a cancel() call
import java

from OnReceivedSslErrorMethod m, TryStmt t
where t.getEnclosingCallable() = m and
      not exists(MethodAccess cancelCall |
        cancelCall.getMethod().hasName("cancel") and
        cancelCall.getEnclosingCallable() = m)
select t, "A try-catch block found in onReceivedSslError WITHOUT any cancel() call at all"
```

### 3.5 Method D — Frida + mitmproxy (Definitive Dynamic Confirmation)

```javascript
// hook-onreceivedsslerror.js
Java.perform(function () {
    var WebViewClient = Java.use("android.webkit.WebViewClient");
    WebViewClient.onReceivedSslError.implementation = function (view, handler, error) {
        console.log("[!] onReceivedSslError called — primaryError: " + error.getPrimaryError());
        var result = this.onReceivedSslError(view, handler, error);
        console.log("    Method finished executing");
        return result;
    };

    var SslErrorHandler = Java.use("android.webkit.SslErrorHandler");
    SslErrorHandler.proceed.implementation = function () {
        console.log("[!!!] SslErrorHandler.proceed() CALLED — SSL error IGNORED!");
        return this.proceed();
    };
});
```

```bash
# Present an invalid certificate to the WebView via mitmproxy
mitmproxy --mode transparent --certs=*=invalid-cert.pem

frida -U -f com.target.app -l hook-onreceivedsslerror.js --no-pause
```

If the WebView's content **still loads** even though `proceed()` was invoked with a deliberately invalid certificate, this is definitive proof of a FAIL condition.

### 3.6 Method Comparison: When to Use Which

| Method | Tool | Detects existence? | Assesses content security? | When to use |
|---|---|---|---|---|
| **A** | Official semgrep rule | ✅ | ❌ (misleading claim) | Location inventory only |
| **B** | grep specific patterns | ✅ | Partial | Primary baseline |
| **C** | CodeQL | ✅ | ✅ (all three patterns at once) | Large codebases |
| **D** | Frida + mitmproxy | ✅ (runtime) | ✅ (definitive proof) | Final confirmation |

**Minimum recommended combination:** **A (DO NOT trust its security claim) → C (CodeQL for all three patterns) → D (dynamic confirmation with a genuinely invalid certificate)**, supplemented by manual review via MASTG-TECH-0023 on every candidate.

---

### 3.7 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rules:**

> **Evaluation:** *"The test case fails if `onReceivedSslError(...)` is overridden and certificate errors are ignored without proper validation or user involvement."*

Note: even **involving the user** (a confirmation dialog) **does not** rescue an implementation from being categorized as a FAIL, per the firm guideline in §1.3 — the only correct behavior is `cancel()`.

---

#### ❌ FAIL / ISSUE — The check is considered FAILED if any of the three patterns is found (§1.4):

| No | Pattern |
|---|---|
| F1 | `proceed()` is called without any check condition at all |
| F2 | The decision is based only on `getPrimaryError()`, ignoring the possibility of multiple errors in the chain |
| F3 | An exception is silenced without an explicit `cancel()` call |
| F4 | The implementation displays a confirmation dialog to the user and proceeds based on their choice — **still a FAIL** even though the user is involved, per §1.3 |

**Example evidence (illustrative — MASTG does not yet provide an official demo for this test):**

```java
@Override
public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {
    if (error.getPrimaryError() != SslError.SSL_UNTRUSTED) {
        handler.proceed();
    } else {
        handler.cancel();
    }
}
```

Interpretation: pattern #2 — only checking for `SSL_UNTRUSTED`, missing other error combinations such as `SSL_EXPIRED` or `SSL_IDMISMATCH` that may occur simultaneously. **FAIL**.

---

#### ✅ PASS — The check is considered PASSED if:

| No | Condition |
|---|---|
| P1 | **No** override of `onReceivedSslError()` is found at all — the WebView relies on its safe default behavior (§1.2) |
| P2 | An override is found, but it **always** calls `handler.cancel()` without any exception |

---

#### ⚠️ Important Notes on Assessment

1. **Do not rely on the semgrep rule to assess security** — the same claim-vs-implementation pattern has been found repeatedly across all three "unsafe implementation" rules for this TLS validation test group.

2. **The safest solution is to NOT override this method at all** — unlike some other tests where "no implementation" could mean negligence, here the **system default is already safe**, so the absence of an override is the best PASS condition.

3. **A user confirmation dialog is NOT a valid mitigation** — this is the nuance most commonly misunderstood by "well-intentioned" developers. Mark it as a FAIL even if the implementation involves user interaction.

4. **Correlate with MASTG-TEST-0234/0282/0283** for a complete picture of the app's entire custom TLS validation surface.

5. **Severity is modulated** by the sensitivity of the content loaded by the WebView — a WebView displaying a login/payment portal is far more critical than one displaying a static help page.

6. **Document:** the location of the override, the specific anti-pattern identified, and the results of dynamic confirmation if performed.

---

## 4. Recommendations

### 4.1 Best Solution: Do Not Override at All

If there is no explicit business need, let the default `WebViewClient` handle `onReceivedSslError()` — the built-in behavior is already safe.

### 4.2 If an Override Is Unavoidable (e.g., for Logging), Always `cancel()`

```java
@Override
public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {
    Log.w(TAG, "SSL error detected: " + error.toString());  // logging only, does NOT affect the decision
    handler.cancel();  // ALWAYS cancel, no exceptions
}
```

### 4.3 Remediation Checklist

- [ ] All `onReceivedSslError()` overrides are inventoried and their content reviewed
- [ ] No `proceed()` is called unconditionally
- [ ] No decision is based solely on `getPrimaryError()`
- [ ] No exception is silenced without an explicit `cancel()`
- [ ] No user confirmation dialog is used as the basis for deciding to continue the connection
- [ ] **Re-verify:** re-run MASTG-TEST-0284 on the final release APK after remediation

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0284: Incorrect SSL Error Handling in WebViews](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0284/)
- [MASTG-TEST-0234: Missing Implementation of Server Hostname Verification with SSLSockets](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0234/)
- [MASTG-TEST-0282: Unsafe Custom Trust Evaluation](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0282/)
- [MASTG-TEST-0283: Incorrect Implementation of Server Hostname Verification](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0283/)
- [MASWE-0027: Insecure Certificate Validation](https://mas.owasp.org/MASWE/MASVS-NETWORK/MASWE-0027/)
- [MASTG-KNOW-0010: Exception Handling](https://mas.owasp.org/MASTG/knowledge/android/MASVS-CODE/MASTG-KNOW-0010/)
- [MASTG-BEST-0021: Ensure Proper Error and Exception Handling](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0021/)
- [Official rule: mastg-android-network-onreceivedsslerror.yml (GitHub)](https://github.com/OWASP/mastg/blob/master/rules/mastg-android-network-onreceivedsslerror.yml)

### 5.2 Official Android Documentation

- [Android Developers — `WebViewClient#onReceivedSslError()`](https://developer.android.com/reference/android/webkit/WebViewClient#onReceivedSslError(android.webkit.WebView,%20android.webkit.SslErrorHandler,%20android.net.http.SslError))
- [Android Developers — `SslErrorHandler#proceed()`](https://developer.android.com/reference/android/webkit/SslErrorHandler#proceed())
- [Android Developers — `SslErrorHandler#cancel()`](https://developer.android.com/reference/android/webkit/SslErrorHandler#cancel())
- [Android Developers — `SslError#getPrimaryError()`](https://developer.android.com/reference/android/net/http/SslError#getPrimaryError())

### 5.3 Research and Third-Party Sources

- [Georgiev et al. — The Most Dangerous Code in the World](http://www.cs.umd.edu/class/fall2019/cmsc818O/papers/most-dangerous-code.pdf)
- [CWE-295: Improper Certificate Validation](https://cwe.mitre.org/data/definitions/295.html)
- [CWE-297: Improper Validation of Certificate with Host Mismatch](https://cwe.mitre.org/data/definitions/297.html)

### 5.4 Tool Documentation

- [Semgrep — Documentation](https://semgrep.dev/docs/)
- [CodeQL — Documentation](https://codeql.github.com/docs/)
- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [Frida — Dynamic instrumentation toolkit](https://frida.re/docs/javascript-api/)
- [mitmproxy](https://mitmproxy.org/)

---

*This document was prepared based on OWASP MASTG (latest release as of September 2026) and official Android Developers documentation. Completing the custom TLS validation test quartet (alongside MASTG-TEST-0234/0282/0283), the third recurring finding in this series: the official MASTG semgrep rule for the "unsafe implementation" category consistently claims a security-evaluation capability its pattern does not actually possess. The most important substantive nuance: official Android guidance is firm without exception — never `proceed()`, and never involve the user in this decision, because users lack the capacity to technically assess the validity of an SSL error.*
