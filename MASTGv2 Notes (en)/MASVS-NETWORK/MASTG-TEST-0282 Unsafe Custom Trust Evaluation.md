# MASTG-TEST-0282 Unsafe Custom Trust Evaluation

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0282 |
| **Platform** | Android |
| **MASVS Category** | MASVS-NETWORK (MASVS-NETWORK-2) |
| **Weakness** | MASWE-0027 — *Insecure Certificate Validation* (same as MASTG-TEST-0234/0283 in this research series) |
| **API in focus** | `X509TrustManager.checkServerTrusted(...)` |
| **Test Type** | Static, Code, **Manual** |
| **Profile** | L1, L2 |
| **Knowledge** | MASTG-KNOW-0010 (Exception Handling — MASVS-CODE) |
| **Best Practice** | MASTG-BEST-0021 (Ensure Proper Error and Exception Handling) |
| **Related Techniques** | MASTG-TECH-0013, MASTG-TECH-0014, MASTG-TECH-0023 (Reviewing Decompiled Java Code — mandatory further validation) |
| **Related Tests** | **MASTG-TEST-0234** (Missing Hostname Verification with SSLSockets), **MASTG-TEST-0283** (Incorrect Implementation of Server Hostname Verification) — all three target different gaps within the Android custom TLS validation ecosystem |
| **Related Demo** | — (none) |
| **Official Rule** | `mastg-android-network-checkservertrusted.yml` — **its coverage is very misleading**, it only detects the existence of the method, and the rule's description claim does not match its pattern implementation (see §3.2, the most significant finding in this document) |
| **Related CWE** | CWE-295 (Improper Certificate Validation), CWE-297 |

---

## 1. Explanation

### 1.1 Testing Objective

Quote from the official MASTG overview:

> *"This test evaluates whether an Android app uses `checkServerTrusted(...)` in an unsafe manner as part of a custom `TrustManager`, causing any connection configured to use that `TrustManager` to skip certificate validation."*

`checkServerTrusted()` is the core method of the `X509TrustManager` interface — called by the TLS system **every time** an HTTPS connection attempts to validate the certificate chain presented by the server. When a developer creates a **custom** implementation of this interface (replacing the system's built-in, well-tested `TrustManager`), **full responsibility for security validation** shifts entirely into the hands of that application code — and per the classic academic research *"The Most Dangerous Code in the World,"* which extensively documents this pattern across various non-browser platforms, **such custom implementations consistently become the most common source of TLS validation failures** across the entire software ecosystem, not just on Android.

### 1.2 Anti-Patterns Explicitly Warned About by MASTG

The official **"Further Validation Required"** clause of this test provides a list of **six concrete patterns** that testers must check for in every `checkServerTrusted()` implementation found — one of the most detailed anti-pattern lists found anywhere in this document series:

1. **Using `checkServerTrusted()` when the NSC would have been sufficient** — an architectural flag: the decision to use a custom TrustManager itself increases risk (refer to the in-depth discussion of this in the MASTG-TEST-0239 document in this research series, MASWE-0047 regarding the use of non-standard APIs for security-critical functions).
2. **A trust manager that does nothing** — overriding `checkServerTrusted()` to accept **all** certificates without any validation, the most extreme and most commonly found example in the field:
   ```java
   public void checkServerTrusted(X509Certificate[] chain, String authType) {
       // EMPTY — no validation at all, implicitly "passing" all certificates
   }
   ```
3. **Ignoring errors** — failing to throw the exception that should be thrown (`CertificateException`, `IllegalArgumentException`) when validation fails, or **catching and silencing** that exception (`catch (CertificateException e) { /* silence */ }`).
4. **Using `checkValidity()` as a substitute for full validation** — `checkValidity()` **only** checks whether a certificate has expired or is not yet valid (date range), but **does not at all** verify whether the certificate is **trusted** (issued by a legitimate CA) or **matches the hostname** of the destination — a very subtle conceptual error because the code **appears** to be performing validation, when the validation performed does not answer the actual security question.
5. **Explicitly relaxing trust** — disabling trust checks to accept self-signed/untrusted certificates for development/testing convenience, **which is then left behind** in production code.
6. **Misusing `getAcceptedIssuers()`** — returning `null` or an empty array without proper handling can effectively **disable issuer validation** entirely.

### 1.3 Crucial Point: `checkValidity()` Is Not a Substitute for Trust Validation (Anti-Pattern #4)

This is the most subtle and most worth highlighting of the six patterns above, because it is **the easiest to slip past a quick code review** — code that calls `checkValidity()` **looks** like it is doing correct validation work:

```java
public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
    chain[0].checkValidity();  // LOOKS like validation, but IS NOT ENOUGH
    // No trust chain verification to a root CA
    // No hostname verification
}
```

`checkValidity()` answers the question **"is this certificate still valid in terms of time?"** — a question that is **entirely different** from the actual security question: **"was this certificate genuinely issued by a trusted authority for the correct domain?"** An MITM attacker can easily create a self-signed certificate that is **still valid by date** (`checkValidity()` will pass), yet is **not issued by any trusted CA whatsoever** — an implementation relying solely on `checkValidity()` will **accept that fake certificate** without complaint.

### 1.4 Relationship with MASVS-CODE: Exception Handling as the Root Cause

Note that the knowledge and best practice referenced by this test (**MASTG-KNOW-0010 — Exception Handling**, **MASTG-BEST-0021**) come from the **MASVS-CODE** category, not MASVS-NETWORK — a **coherent cross-reference** (not a metadata inconsistency as seen in some other cases in this research series), because the root cause of **three of the six** anti-patterns above (ignoring errors, silencing exceptions) is actually a problem of **poor exception handling**, not purely a cryptography/networking issue. MASTG-BEST-0021 reinforces the directly relevant principle:

> *"Fail securely: Exceptions must not weaken security controls. Any failure in security checks should result in a **deny** outcome... Security mechanisms should default to denying access until explicitly granted, since **fail-open paths are a common attack vector**."*

A `checkServerTrusted()` that fails to throw an exception when validation fails is a textbook example of **"fail-open"** (CWE-636) — instead of rejecting the connection when a suspicious condition occurs, the code silently **continues as if everything is fine**.

### 1.5 Academic Context: The Scale of the Problem Across the Industry

The seminal research *"The Most Dangerous Code in the World: Validating SSL Certificates in Non-Browser Software"* (Georgiev et al.) documents that SSL/TLS certificate validation is **systematically broken** across various non-browser libraries and applications — not a phenomenon exclusive to Android, but a recurring failure pattern across the entire software ecosystem that implements its own TLS validation instead of using the platform's built-in path. Specifically for Android, two academic research tools were designed to detect this pattern at scale:

- **MalloDroid**: performs static analysis to detect various flaws related to SSL/TLS misuse, including accepting any certificate/hostname without validation.
- **SMV-Hunter**: specifically focuses on **custom validation code** — i.e., overrides of `X509TrustManager` and `HostnameVerifier` — precisely the target of this test.

---

## 2. Tools Used for Testing

### 2.1 Mandatory Tools (Core)

| Tool | Function |
|---|---|
| **jadx** | DEX → Java decompilation to find custom `X509TrustManager` implementations |
| **grep / ripgrep** | Searching for implementation patterns and verifying method content |
| **semgrep** | Running the official rule as a location baseline (with the significant caveat noted, §3.2) |

### 2.2 Alternative & Supporting Tools

| Tool | Function |
|---|---|
| **CodeQL** | Programmatically tracing the **content** of the `checkServerTrusted()` method — whether the method body is truly empty, whether it calls chain validation (`CertPathValidator`), whether there is a `throw` on the failure path |
| **MalloDroid** (academic) | A research tool specifically designed to detect SSL/TLS misuse patterns, including flawed custom TrustManagers |
| **SMV-Hunter** (academic) | A research tool specifically focused on `X509TrustManager`/`HostnameVerifier` overrides |
| **MobSF** | Sometimes flags `TrustManager` patterns that accept all certificates in the Code Analysis report |
| **Frida** | Hooking `checkServerTrusted()` to confirm at runtime that the method is actually called, and to see the content of the `X509Certificate[]` received during a real connection |

### 2.3 Environment Prerequisites

- **No device/root required** for core static analysis.
- **Manual review (MASTG-TECH-0023) is a mandatory part**, not optional — this is explicitly stated as the official "Further Validation Required" for this test, consistent with the `manual` tag on its test type.

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0013** to reverse engineer the app.
2. Use **MASTG-TECH-0014** to search for the relevant API.

With the mandatory **Further Validation Required** clause: *"Inspect each reported code location using MASTG-TECH-0023"* against the six anti-patterns (§1.2).

### 3.2 Method A — Official Semgrep Rule *(EXISTS, BUT THE MOST SIGNIFICANT FINDING: the rule's claim DOES NOT MATCH its implementation)*

Official rule:

```yaml
rules:
  - id: mastg-android-network-checkservertrusted
    severity: WARNING
    languages: [java]
    metadata:
      summary: This rule looks for the use of checkServerTrusted and ensures it throws an exception instead of silently muting invalid server certificates
    message: Improper Server Certificate verification detected.
    match:
        any:
        - public void checkServerTrusted (...) { ... }
```

```bash
semgrep --config https://raw.githubusercontent.com/OWASP/mastg/master/rules/mastg-android-network-checkservertrusted.yml ./decompiled/sources/
```

**This is the most significant finding in this document**: note the **claim in the `summary` field** of this rule:

> *"This rule looks for the use of checkServerTrusted and **ensures it throws an exception** instead of silently muting invalid server certificates"*

This claim explicitly states the rule will **verify exception-throwing behavior** — however, the pattern that is actually executed is only:

```
public void checkServerTrusted (...) { ... }
```

The `{ ... }` pattern in semgrep syntax is a **wildcard body match** — it matches **any method** with that signature, **regardless of its content**. This means this rule **will always trigger a warning for EVERY `checkServerTrusted()` implementation, whether safe or unsafe** — including implementations that correctly throw an exception when validation fails. **This rule does not in any way do** what its `summary` claims (verifying the existence of a `throw`) — it is purely a location-inventory rule disguised as a security-evaluation rule.

Practical consequences:
- **No false negatives from this rule for existence detection** — every custom `TrustManager` implementation will be caught.
- **But this rule cannot be used to distinguish safe/unsafe at all** — the same `WARNING` severity will appear both for a perfectly safe implementation and for one that is completely empty with no validation at all. This directly contradicts the textual claim of its `summary`, and is the clearest case of a **rule description vs. implementation mismatch** found throughout this document series.

### 3.3 Method B — grep/ripgrep with Manual Verification of Method Content

```bash
D=./decompiled/sources

# Find all implementations
rg -n -A20 'public void checkServerTrusted' $D > trustmanager_implementations.txt

# Automatically detect the most suspicious pattern: a very short method body (strong indication of "doing nothing")
rg -n -A5 'public void checkServerTrusted' $D | grep -B1 '^\s*}$' | grep -c "checkServerTrusted"

# Look for the checkValidity() pattern as a substitute for full validation (anti-pattern #4, §1.3)
rg -n -B3 -A10 'public void checkServerTrusted' $D | grep -B5 'checkValidity()'

# Look for catch blocks that silence exceptions (anti-pattern #3)
rg -n -B10 'catch\s*\(\s*CertificateException' $D | grep -B10 "^\s*}\s*$" | grep "checkServerTrusted"
```

### 3.4 Method C — CodeQL (Programmatic Analysis of Method Content)

```ql
import java

class CheckServerTrustedMethod extends Method {
  CheckServerTrustedMethod() {
    this.hasName("checkServerTrusted") and
    this.getDeclaringType().getASupertype*().hasQualifiedName("javax.net.ssl", "X509TrustManager")
  }
}

// Pattern 1: Empty method body or no exception thrown at all
from CheckServerTrustedMethod m
where not exists(ThrowStmt t | t.getEnclosingCallable() = m)
  and not exists(MethodAccess ma | ma.getEnclosingCallable() = m and
    ma.getMethod().getDeclaringType().hasQualifiedName("java.security.cert", "CertPathValidator"))
select m, "checkServerTrusted() does not throw an exception and does not call CertPathValidator — a strong candidate for unsafe validation"
```

```ql
// Pattern 2: Only calls checkValidity() without validating the trust chain (anti-pattern #4)
import java

from Method m, MethodAccess checkValidityCall
where m.hasName("checkServerTrusted") and
      checkValidityCall.getMethod().hasName("checkValidity") and
      checkValidityCall.getEnclosingCallable() = m and
      not exists(MethodAccess trustCall |
        trustCall.getEnclosingCallable() = m and
        trustCall.getMethod().getDeclaringType().hasQualifiedName("java.security.cert", "CertPathValidator"))
select m, "checkServerTrusted() ONLY calls checkValidity() without full trust chain validation"
```

### 3.5 Method D — Frida (Runtime Confirmation)

```javascript
// hook-checkservertrusted.js
Java.perform(function () {
    Java.enumerateLoadedClasses({
        onMatch: function (className) {
            // Look for a custom class implementing X509TrustManager
        },
        onComplete: function () {}
    });

    // Hook directly if the custom TrustManager class name is already known from static analysis
    try {
        var CustomTM = Java.use("com.target.app.net.PermissiveTrustManager");
        CustomTM.checkServerTrusted.implementation = function (chain, authType) {
            console.log("[!] checkServerTrusted called with " + chain.length + " certificates");
            var result = this.checkServerTrusted(chain, authType);
            console.log("    Method finished WITHOUT throwing an exception — check whether this should have failed");
            return result;
        };
    } catch (e) { console.log("[x] Custom TrustManager class not found/different name: " + e); }
});
```

### 3.6 Method Comparison: When to Use Which

| Method | Tool | Detects existence? | Assesses content security? | When to use |
|---|---|---|---|---|
| **A** | Official semgrep rule | ✅ | ❌ (despite claiming to, §3.2) | Location inventory only |
| **B** | grep + manual verification | ✅ | Manual (needs human eyes) | Primary baseline |
| **C** | CodeQL | ✅ | ✅ (programmatic, detects specific patterns) | **Most valuable** — large codebases |
| **D** | Frida | ✅ (runtime) | Partial (execution confirmation) | Confirming high-priority candidates |

**Minimum recommended combination:** **A (location inventory, DO NOT trust its security claim) → C (CodeQL to programmatically assess content) → manual review via MASTG-TECH-0023** on every remaining candidate, per the mandatory official clause.

---

### 3.7 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rules:**

> **Evaluation:** *"The test case fails if `checkServerTrusted(...)` is implemented in a custom `X509TrustManager` and does **not** properly validate server certificates."*

---

#### ❌ FAIL / ISSUE — The check is considered FAILED if any of the six patterns is found (§1.2):

| No | Pattern |
|---|---|
| F1 | Empty method body — accepts all certificates without any validation |
| F2 | Catches/silences a validation exception without re-throwing |
| F3 | Only calls `checkValidity()` without validating the trust chain (§1.3) |
| F4 | Trust checks are explicitly relaxed for self-signed/untrusted certificates |
| F5 | `getAcceptedIssuers()` returns `null`/an empty array without proper handling |
| F6 | Uses a custom `checkServerTrusted()` when the need could already be met by the NSC (an architectural finding, even if the implementation itself is correct) |

**Example evidence (illustrative — MASTG does not yet provide an official demo for this test):**

```java
// Found in com/example/target/net/DevTrustManager.java
public class DevTrustManager implements X509TrustManager {
    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) {
        // TODO: remove before production release — temporarily accept all for testing
    }
    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) {}
    @Override
    public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[]{}; }
}
```

Interpretation: the class name `DevTrustManager` and the `TODO` comment confirm this is testing code that was **left behind** in production — an empty method body (F1) and `getAcceptedIssuers()` returning an empty array (F5). **Critical FAIL** — exactly matching anti-patterns #2 and #6 of the official clause.

---

#### ✅ PASS — The check is considered PASSED if:

| No | Condition |
|---|---|
| P1 | **No** custom `X509TrustManager` implementation is found at all — the app fully relies on the system's built-in `TrustManager`/NSC |
| P2 | A custom implementation is found, but it **genuinely** calls `CertPathValidator`/delegates to the system `TrustManager`, throws the appropriate exception on failure, and does not misuse `getAcceptedIssuers()` |

---

#### ⚠️ Important Notes on Assessment

1. **NEVER trust the claim in the official semgrep rule's `summary` without verification.** This is the most important lesson from this document — this rule explicitly claims to verify the existence of a `throw`, when its pattern purely detects the existence of any method. Always read the technical content of the semgrep pattern, not just its description.

2. **Every Method A finding must be followed by a review of the method's content** — an empty result from this rule means PASS (no custom TrustManager at all), but a result with **findings** from this rule **provides no information whatsoever** about the security of its implementation.

3. **`checkValidity()` is the subtlest trap** (§1.3) — code that "looks like" it's doing validation but is actually answering the wrong question. Be especially wary of this pattern during manual review.

4. **Correlate with MASTG-TEST-0234/0283** — the Android custom TLS validation ecosystem has many interrelated points of failure (custom TrustManager, hostname verification, SSLSocket) — check all three together for a complete picture.

5. **Severity is modulated:**

   | Factor | Severity |
   |---|---|
   | Empty/always-accepting method body, used on sensitive data connections | **Critical** |
   | `checkValidity()` alone without trust chain, sensitive data | **High** |
   | Exception silenced but there is logging that detects it (even though it doesn't reject the connection) | **High** |
   | A custom implementation proven correct and complete | **Not a finding**, though still noted as F6 (consider the NSC) |

6. **Document:** the location of the custom TrustManager class, the full content of the `checkServerTrusted()` method, the specific anti-pattern identified (from the six categories in §1.2), and the results of runtime confirmation if performed.

---

## 4. Recommendations

### 4.1 Avoid Custom TrustManagers Entirely — Use the NSC (Per Anti-Pattern #1)

```xml
<network-security-config>
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system" />
        </trust-anchors>
    </base-config>
</network-security-config>
```

### 4.2 If a Custom TrustManager Is Still Needed, Delegate to a Standard Validator

```java
public class ProperCustomTrustManager implements X509TrustManager {
    private final X509TrustManager defaultTrustManager;

    public ProperCustomTrustManager() throws Exception {
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init((KeyStore) null);
        defaultTrustManager = (X509TrustManager) tmf.getTrustManagers()[0];
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        defaultTrustManager.checkServerTrusted(chain, authType);  // delegation, NOT a manual re-implementation
        // Add pinning here if needed, STILL throw an exception on failure
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return defaultTrustManager.getAcceptedIssuers();  // DO NOT return null/empty
    }
}
```

### 4.3 Remediation Checklist

- [ ] All custom `X509TrustManager` implementations have been inventoried and their full content reviewed
- [ ] The `checkServerTrusted()` method delegates to the default `TrustManagerFactory` or the NSC, rather than being manually reimplemented from scratch
- [ ] No empty method body accepts all certificates
- [ ] A validation exception is thrown correctly, not silenced
- [ ] `getAcceptedIssuers()` does not return `null`/an empty array without valid reason
- [ ] Testing/development code (e.g., `DevTrustManager`) is confirmed not to be included in production builds
- [ ] **Re-verify:** re-run MASTG-TEST-0282 on the final release APK after remediation

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0282: Unsafe Custom Trust Evaluation](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0282/)
- [MASTG-TEST-0234: Missing Implementation of Server Hostname Verification with SSLSockets](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0234/)
- [MASTG-TEST-0283: Incorrect Implementation of Server Hostname Verification](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0283/)
- [MASWE-0027: Insecure Certificate Validation](https://mas.owasp.org/MASWE/MASVS-NETWORK/MASWE-0027/)
- [MASTG-KNOW-0010: Exception Handling](https://mas.owasp.org/MASTG/knowledge/android/MASVS-CODE/MASTG-KNOW-0010/)
- [MASTG-BEST-0021: Ensure Proper Error and Exception Handling](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0021/)
- [Official rule: mastg-android-network-checkservertrusted.yml (GitHub)](https://github.com/OWASP/mastg/blob/master/rules/mastg-android-network-checkservertrusted.yml)

### 5.2 Official Android Documentation

- [Android Developers — Unsafe X509TrustManager](https://developer.android.com/privacy-and-security/risks/unsafe-trustmanager)
- [Android Developers — `X509TrustManager` API reference](https://developer.android.com/reference/javax/net/ssl/X509TrustManager)
- [Google — How to Fix Apps Containing an Unsafe Implementation of TrustManager](https://support.google.com/faqs/answer/6346016?hl=en)
- [Android Developers — `X509Certificate#checkValidity()`](https://developer.android.com/reference/java/security/cert/X509Certificate#checkValidity())

### 5.3 Academic Research and Third-Party Sources

- [Georgiev et al. — The Most Dangerous Code in the World: Validating SSL Certificates in Non-Browser Software](http://www.cs.umd.edu/class/fall2019/cmsc818O/papers/most-dangerous-code.pdf)
- [MalloDroid — Static Analysis Tool for SSL/TLS Misuse Detection](https://www.researchgate.net/publication/262173624_The_most_dangerous_code_in_the_world_validating_SSL_certificates_in_non-browser_software)
- [OWASP — Fail Securely](https://owasp.org/www-community/Fail_securely)
- [OWASP — Improper Error Handling](https://owasp.org/www-community/Improper_Error_Handling)
- [CWE-636: Not Failing Securely ('Failing Open')](https://cwe.mitre.org/data/definitions/636.html)
- [CWE-295: Improper Certificate Validation](https://cwe.mitre.org/data/definitions/295.html)

### 5.4 Tool Documentation

- [Semgrep — Documentation](https://semgrep.dev/docs/)
- [CodeQL — Documentation](https://codeql.github.com/docs/)
- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [Frida — Dynamic instrumentation toolkit](https://frida.re/docs/javascript-api/)
- [MobSF — Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)

---

*This document was prepared based on OWASP MASTG (latest release as of September 2026), official Android Developers documentation, and seminal academic research (Georgiev et al., MalloDroid, SMV-Hunter) on TLS certificate validation failures in non-browser software. The most significant finding in this research: the official MASTG semgrep rule for this test has an **explicit mismatch between its description claim (`summary`) and its actual pattern implementation** — the description claims the rule "ensures an exception is thrown," when the pattern purely detects the existence of any method without assessing its content at all. This is the clearest case of a rule-description mismatch found throughout this document series, confirming that manual verification (MASTG-TECH-0023) against the six official anti-patterns remains a genuinely irreplaceable step.*
