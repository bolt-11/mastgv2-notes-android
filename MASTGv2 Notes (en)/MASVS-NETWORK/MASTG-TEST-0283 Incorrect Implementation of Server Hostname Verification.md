# MASTG-TEST-0283 Incorrect Implementation of Server Hostname Verification

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0283 |
| **Platform** | Android |
| **MASVS Category** | MASVS-NETWORK (MASVS-NETWORK-2) |
| **Weakness** | MASWE-0027 — *Insecure Certificate Validation* (same as MASTG-TEST-0234/0282) |
| **API in focus** | `HostnameVerifier`, `HostnameVerifier#verify(String, SSLSession)` |
| **Test Type** | Static, Code, **Manual** |
| **Profile** | L1, L2 |
| **Related Techniques** | MASTG-TECH-0013, MASTG-TECH-0014, MASTG-TECH-0023 (mandatory further validation) |
| **Related Tests** | **MASTG-TEST-0234** (Missing Implementation of Server Hostname Verification with SSLSockets — tests for the **absence** of a `HostnameVerifier` altogether; this test checks for the **presence** of a `HostnameVerifier` that is **incorrectly implemented**), **MASTG-TEST-0282** (Unsafe Custom Trust Evaluation — a parallel weakness on `X509TrustManager`) |
| **Related Demo** | — (none) |
| **Official Rule** | `mastg-android-network-hostname-verification.yml` — **the same rule** discussed in the MASTG-TEST-0234 document, but for this test the rule **is semantically on-target** (see §1.2) — though it still inherits the same gap: it only detects location, not content security |
| **Related CWE** | CWE-297 (Improper Validation of Certificate with Host Mismatch), CWE-295 |

---

## 1. Explanation

### 1.1 Testing Objective and Its Position as the Complementary Counterpart of MASTG-TEST-0234

Quote from the official MASTG overview:

> *"This test evaluates whether an Android app implements a `HostnameVerifier` that uses `verify(...)` in an unsafe manner, effectively turning off hostname validation for the affected connections."*

This test is a **mirror pair** of MASTG-TEST-0234, already discussed in depth in this research series — both target an identical consequence (server identity not verified despite a successful TLS handshake), but from **opposite starting conditions**:

| | MASTG-TEST-0234 | MASTG-TEST-0283 *(this document)* |
|---|---|---|
| **Condition checked** | A `HostnameVerifier` is **ABSENT** entirely when using `SSLSocket` | A `HostnameVerifier` is **PRESENT**, but implemented **incorrectly** |
| **Source of the problem** | Omission — the developer forgot/did not know verification needed to be called | Implementation error — the developer **tried** to verify but the logic is flawed |

MASTG-TEST-0234's own note explicitly states the correct testing order: *"If a `HostnameVerifier` is present, ensure it's not implemented in an unsafe manner. See MASTG-TEST-0283 for guidance"* — confirming that both tests **must be run sequentially**, not as alternatives to one another.

### 1.2 The Same Semgrep Rule, But Now On-Target

This is an interesting point that complements the analysis from the MASTG-TEST-0234 document: the official rule `mastg-android-network-hostname-verification.yml` (which in that document was identified as **mistargeted**, since it searches for the existence of `HostnameVerifier` when TEST-0234 actually tests for its **absence**) — for **this test**, the **exact same** rule is actually **semantically correct**:

```yaml
rules:
  - id: mastg-android-network-hostname-verification
    severity: WARNING
    languages: [java]
    message: Improper server hostname verification detected
    match:
      any:
        - new HostnameVerifier() {...}
```

Because MASTG-TEST-0283 does aim to find the **location of existing** custom `HostnameVerifier` implementations (to then assess their security), the pattern `new HostnameVerifier() {...}` **matches this test's purpose appropriately**. However, **the same gap discussed in the MASTG-TEST-0282 document** still applies here: `{...}` is a **wildcard body match** — this rule will trigger an identical warning both for a safe implementation and for one that is genuinely flawed (`return true` unconditionally). This rule is **only useful as a location map**, and cannot at all be used to distinguish safe/unsafe — manual review (MASTG-TECH-0023) remains absolutely necessary for every location found.

### 1.3 Four Implementation Error Patterns Checked

The official "Further Validation Required" clause provides **four specific patterns**:

**1. Always accepting any hostname** — the most extreme and most commonly found pattern in the field:

```java
HostnameVerifier allowAllHostnames = new HostnameVerifier() {
    @Override
    public boolean verify(String hostname, SSLSession session) {
        return true;  // ALWAYS true, regardless of hostname or any certificate
    }
};
```

This pattern often appears as a "quick fix" to address SSL errors during development/debugging against a server with a self-signed certificate, which is then **left behind** in production code.

**2. Matching rules that are too permissive** — unintentional wildcard logic that matches domains not actually intended:

```java
public boolean verify(String hostname, SSLSession session) {
    return hostname.endsWith("example.com");  // DANGER: this also matches "evil-example.com"!
}
```

A classic string-matching programming mistake — `endsWith("example.com")` will **also** evaluate to `true` for `"attacker-controlled-example.com"` or any domain that coincidentally ends with that string, not only legitimate subdomains of `example.com`.

**3. Incomplete verification coverage** — hostname verification **is not applied consistently** across all SSL/TLS channels used by the app, including those created via `SSLSocket` (the connection type **specifically** targeted by MASTG-TEST-0234) or during TLS **renegotiation** that occurs mid-session on an already-established connection.

**4. Missing manual verification** — not performing hostname verification at all when the low-level API in use (`SSLSocket`) **does not do so automatically** — this is a **direct overlap** with MASTG-TEST-0234, and this test's official overview explicitly lists it as one of the patterns to also check for here, reinforcing the close relationship between the two tests.

### 1.4 Why Pattern #2 (Overly Permissive Wildcard) Is the Hardest to Detect Automatically

Among the four patterns, **pattern #2** is the hardest to detect purely through static pattern-matching (semgrep/simple regex) — because there is no single "dangerous keyword" to search for; the problem lies in **string-matching logic** that can be written in many different ways (`endsWith`, `contains`, custom regex, a wrongly-directed `startsWith`). This explains why **CodeQL with data flow analysis** (§3.4) is far more valuable than simple grep for this error category — a flawed string-matching logic pattern demands understanding **code structure**, not just text matching.

---

## 2. Tools Used for Testing

### 2.1 Mandatory Tools (Core)

| Tool | Function |
|---|---|
| **jadx** | DEX → Java decompilation to find `HostnameVerifier` implementations |
| **grep / ripgrep** | Searching for implementation patterns and verifying the logic of `verify()` |
| **semgrep** | Running the official rule as a location baseline |

### 2.2 Alternative & Supporting Tools

| Tool | Function |
|---|---|
| **CodeQL** | Data flow analysis for pattern #2 (§1.4) — tracing which methods are called on the `hostname` parameter (`endsWith`/`contains`/`matches`) as an indication of potentially permissive matching logic |
| **MalloDroid / SMV-Hunter** (academic, same as referenced in the MASTG-TEST-0282 document) | Research tools specifically designed to detect flawed `HostnameVerifier` overrides at scale |
| **MobSF** | Sometimes flags a `HostnameVerifier` pattern that always `return true` |
| **Frida** | Hooking `HostnameVerifier.verify()` to confirm at runtime the actual return value and hostname argument received on a real connection |

### 2.3 Environment Prerequisites

- **No device/root required** for core static analysis.
- **Manual review (MASTG-TECH-0023) is absolutely required** — consistent with the `manual` tag on this test's test type, and per the official rule's gap (§1.2).
- **Check ALL SSL/TLS channels**, not only `HttpsURLConnection` — per pattern #3 (§1.3), including manual `SSLSocket` and renegotiation moments.

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0013** to reverse engineer the app.
2. Use **MASTG-TECH-0014** to search for the relevant API.

### 3.2 Method A — Official Semgrep Rule + grep for Content Verification

```bash
jadx -d ./decompiled ./target-app.apk
semgrep --config https://raw.githubusercontent.com/OWASP/mastg/master/rules/mastg-android-network-hostname-verification.yml ./decompiled/sources/
```

```bash
D=./decompiled/sources

# Pattern #1: always returns true unconditionally
rg -n -A8 'public boolean verify\(' $D | grep -B5 'return true;' | grep -B10 "^\s*}" | head -50

# Pattern #2: potentially permissive string-matching logic
rg -n -A5 'public boolean verify\(' $D | grep -E "endsWith|startsWith|contains|matches"
```

### 3.3 Method B — CodeQL for Patterns #1 and #2

```ql
import java

class HostnameVerifierImpl extends AnonymousClass {
  HostnameVerifierImpl() {
    this.getASupertype().hasQualifiedName("javax.net.ssl", "HostnameVerifier")
  }
}

// Pattern #1: verify() never returns false on any path
from HostnameVerifierImpl impl, Method verifyMethod
where verifyMethod = impl.getAMethod() and verifyMethod.hasName("verify")
  and not exists(ReturnStmt r | r.getEnclosingCallable() = verifyMethod and
    r.getResult().(BooleanLiteral).getBooleanValue() = false)
select verifyMethod, "verify() NEVER returns false — a strong candidate for 'always accept'"
```

```ql
// Pattern #2: use of String.endsWith/contains on the hostname parameter
import java

from Method verifyMethod, MethodAccess stringMatch
where verifyMethod.hasName("verify") and
      verifyMethod.getDeclaringType().getASupertype*().hasQualifiedName("javax.net.ssl", "HostnameVerifier") and
      stringMatch.getMethod().hasName(["endsWith", "contains", "startsWith"]) and
      stringMatch.getEnclosingCallable() = verifyMethod
select stringMatch, "Potentially permissive hostname matching logic — manually verify this string pattern"
```

### 3.4 Method C — Frida (Runtime Confirmation)

```javascript
// hook-hostnameverifier.js
Java.perform(function () {
    Java.enumerateLoadedClasses({
        onMatch: function (className) {
            if (className.indexOf("HostnameVerifier") !== -1 || className.match(/\$\d+$/)) {
                try {
                    var cls = Java.use(className);
                    if (cls.verify) {
                        cls.verify.implementation = function (hostname, session) {
                            var result = this.verify(hostname, session);
                            console.log("[*] " + className + ".verify(" + hostname + ") -> " + result);
                            return result;
                        };
                    }
                } catch (e) {}
            }
        },
        onComplete: function () {}
    });
});
```

```bash
frida -U -f com.target.app -l hook-hostnameverifier.js --no-pause
```

Interact with the app while observing the output — if `verify()` **always** returns `true` regardless of the `hostname` value varying across connections, this is a direct runtime confirmation of pattern #1.

### 3.5 Method Comparison: When to Use Which

| Method | Tool | Finds pattern #1 (always true)? | Finds pattern #2 (permissive wildcard)? | When to use |
|---|---|---|---|---|
| **A** | Semgrep rule + grep | Partial (manual grep) | Partial | Location baseline |
| **B** | CodeQL | ✅ | ✅ | **Most valuable** for both harder patterns |
| **C** | Frida | ✅ (empirical confirmation) | ✅ (visible from varying hostnames that still pass) | Confirming high-priority candidates |

**Minimum recommended combination:** **A (location inventory) → B (CodeQL for both harder patterns) → C (Frida for runtime confirmation)**, supplemented by mandatory manual review via MASTG-TECH-0023 on all findings.

---

### 3.6 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rules:**

> **Evaluation:** *"The test case fails if the app does **not** properly validate that the server's hostname matches the certificate."*

---

#### ❌ FAIL / ISSUE — The check is considered FAILED if any of the four patterns is found (§1.3):

| No | Pattern |
|---|---|
| F1 | `verify()` is overridden to always return `true` unconditionally |
| F2 | Hostname-matching logic is too permissive (e.g., `endsWith` without proper domain-structure validation) |
| F3 | Verification is not applied consistently across all channels (`SSLSocket`, renegotiation) |
| F4 | Manual verification is missing when using a low-level API that does not perform it automatically (overlap with MASTG-TEST-0234) |

**Example evidence (illustrative — MASTG does not yet provide an official demo for this test):**

```java
HostnameVerifier verifier = new HostnameVerifier() {
    @Override
    public boolean verify(String hostname, SSLSession session) {
        return hostname.contains("mycompany");  // Pattern #2 — "evil-mycompany-phishing.com" would PASS
    }
};
```

Interpretation: the logic `contains("mycompany")` will pass **any** domain containing that substring, including an attacker's domain deliberately crafted to include that keyword — **FAIL** per pattern #2.

---

#### ✅ PASS — The check is considered PASSED if:

| No | Condition |
|---|---|
| P1 | **No** custom `HostnameVerifier` implementation is found — the app relies on the system's default verification (`HttpsURLConnection`) |
| P2 | A custom implementation is found, but it delegates to `HttpsURLConnection.getDefaultHostnameVerifier()` or performs correct structural matching (exact match/full domain matching, not substring) |
| P3 | Verification is applied consistently across all channels, including `SSLSocket` |

---

#### ⚠️ Important Notes on Assessment

1. **Do not rely on the semgrep rule to assess content security** — as with the MASTG-TEST-0282 document, this rule is only a location inventory.

2. **Pattern #2 (permissive wildcard) demands extra attention** — this is the error most easily overlooked in code review because the code **looks** like it's performing a reasonable validation at a glance.

3. **Always run this test alongside MASTG-TEST-0234** — per §1.1, the two tests form a complete evaluation flow: 0234 ensures a verifier **exists**, 0283 ensures that verifier is **correct**.

4. **Severity is modulated** by the sensitivity of the data passing over the affected connection, consistent with the pattern in the MASTG-TEST-0234/0282 documents.

5. **Document:** the location of the `HostnameVerifier` implementation, the specific error pattern identified (from the four categories), and the results of runtime confirmation if performed.

---

## 4. Recommendations

### 4.1 Delegate to the System's Default Verifier

```java
HostnameVerifier verifier = HttpsURLConnection.getDefaultHostnameVerifier();
if (!verifier.verify(expectedHostname, sslSession)) {
    throw new SSLPeerUnverifiedException("Hostname mismatch: " + expectedHostname);
}
```

### 4.2 If Customization Is Needed, Use Exact Domain Matching

```java
// WRONG
return hostname.endsWith("example.com");

// CORRECT — full domain matching, not substring
return hostname.equals("api.example.com") || hostname.equals("example.com");
```

### 4.3 Remediation Checklist

- [ ] All custom `HostnameVerifier` implementations are inventoried and their content reviewed
- [ ] No `verify()` always returns `true`
- [ ] Hostname-matching logic uses exact matching, not a substring/permissive wildcard
- [ ] Verification is applied consistently across all channels (`HttpsURLConnection`, `SSLSocket`)
- [ ] **Re-verify:** re-run MASTG-TEST-0283 alongside MASTG-TEST-0234

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0283: Incorrect Implementation of Server Hostname Verification](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0283/)
- [MASTG-TEST-0234: Missing Implementation of Server Hostname Verification with SSLSockets](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0234/)
- [MASTG-TEST-0282: Unsafe Custom Trust Evaluation](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0282/)
- [MASWE-0027: Insecure Certificate Validation](https://mas.owasp.org/MASWE/MASVS-NETWORK/MASWE-0027/)
- [Official rule: mastg-android-network-hostname-verification.yml (GitHub)](https://github.com/OWASP/mastg/blob/master/rules/mastg-android-network-hostname-verification.yml)

### 5.2 Official Android Documentation

- [Android Developers — Unsafe HostnameVerifier](https://developer.android.com/privacy-and-security/risks/unsafe-hostname)
- [Android Developers — `HostnameVerifier` API reference](https://developer.android.com/reference/javax/net/ssl/HostnameVerifier)
- [Android Developers — `HttpsURLConnection.getDefaultHostnameVerifier()`](https://developer.android.com/reference/javax/net/ssl/HttpsURLConnection#getDefaultHostnameVerifier())

### 5.3 Research and Third-Party Sources

- [Georgiev et al. — The Most Dangerous Code in the World](http://www.cs.umd.edu/class/fall2019/cmsc818O/papers/most-dangerous-code.pdf)
- [CWE-297: Improper Validation of Certificate with Host Mismatch](https://cwe.mitre.org/data/definitions/297.html)

### 5.4 Tool Documentation

- [Semgrep — Documentation](https://semgrep.dev/docs/)
- [CodeQL — Documentation](https://codeql.github.com/docs/)
- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [Frida — Dynamic instrumentation toolkit](https://frida.re/docs/javascript-api/)

---

*This document was prepared based on OWASP MASTG (latest release as of September 2026) and official Android Developers documentation. As the mirror pair of MASTG-TEST-0234, this test completes the hostname verification evaluation: ensuring the implementation that **exists** is genuinely safe, not merely confirming its presence. The official semgrep rule discussed in the MASTG-TEST-0234 document (assessed there as mistargeted) is in fact **appropriately targeted** for this test — yet it still inherits the same fundamental limitation: it only detects location, never evaluates the security of the implementation's content.*
