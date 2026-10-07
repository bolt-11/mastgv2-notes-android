# MASTG-TEST-0394 Missing Input Validation in Custom URL Scheme Handlers

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0394 |
| **Platform** | Android |
| **MASVS Category** | MASVS-PLATFORM |
| **Weakness** | MASWE-0029 |
| **Test Type** | Static, Code, **Manual** |
| **Related API** | `getData`, `getQueryParameter` |
| **Related Techniques** | MASTG-TECH-0013, MASTG-TECH-0014, MASTG-TECH-0023, MASTG-TECH-0173 (Monitoring Deep Link Handlers at Runtime with Frida) |
| **Related Knowledge** | MASTG-KNOW-0019 (Deep Links) |
| **Related Best Practice** | MASTG-BEST-0071 (Validate Input Parameters in Deep Link and Custom URL Scheme Handlers) |
| **Related Tests** | **MASTG-TEST-0393** — related document in this research series (verified App Links); this test targets **custom URL schemes**, which by design are **never** verified by the OS at all |
| **Official rule** | `mastg-android-deeplink-unvalidated-parameter.yml` — an "honest" rule that is purely observational, see §1.4 |

---

## 1. Explanation

### 1.1 Testing Objective and the Fundamental Difference from MASTG-TEST-0393

Quote from the official MASTG overview:

> *"Apps register custom URL schemes by declaring an `<intent-filter>`... with a `<data>` element whose `android:scheme` is a custom (non-http/https) value... Apps must validate and sanitize these URL parameters before using them in security-sensitive operations."*

The crucial difference from MASTG-TEST-0393, already discussed in this research series: App Links (`http`/`https`) **can** be verified through the `autoVerify` + Digital Asset Links mechanism. **Custom URL schemes have no equivalent verification mechanism at all** — this is not a matter of "forgetting to enable verification," but a **permanent architectural limitation**. As a consequence, this test does not target *whether the scheme is verified* (not relevant, since it simply cannot be), but rather targets **how the application handles the fact that anyone can call it** — namely, through adequate input validation.

### 1.2 Three Concrete Example Payloads Reflecting Three Different Vulnerability Classes

The overview gives three examples, each representing a classic web vulnerability class now translated into the context of deep link parameters:

| Payload | Vulnerability Class | Impact |
|---|---|---|
| `myapp://transfer?amount=-1` or `amount=9999999` | **Business logic bypass** | Bypasses a legitimate transaction value limit |
| `myapp://open?path=../../data/sensitive.txt` | **Path traversal** | Access to a file outside the intended directory |
| `myapp://search?q=<script>alert(1)</script>` | **Script injection (XSS)** | JavaScript execution if rendered in a WebView |

These three examples confirm that deep link parameters are **not merely a navigation risk**, but an **input entry point equivalent to an HTTP form** — every classic web vulnerability class normally tested in a web application has an equivalent in the context of mobile deep link parameters.

### 1.3 Fundamental Nuance: Android Has No Sender-Identification Mechanism

This is an architectural limitation that makes input validation the **only** available line of defense, not merely an additional good practice:

> *"Unlike iOS, Android provides no mechanism to identify which app sent the Intent. There is no equivalent to iOS's sourceApplication property, so the handler cannot verify the caller's identity, and every custom URL scheme handler is effectively reachable by any app on the device."*

This means there is no way for the handler to "trust" a particular sender based on identity — **every** request coming in through a custom URL scheme must be treated equally, as coming from an entirely untrusted source, regardless of how confident the developer is that the request "usually" comes from an internal application component or a trusted partner.

### 1.4 Analysis of the Official Rule: An "Honest," Purely Observational Design

The `mastg-android-deeplink-unvalidated-parameter.yml` rule has a characteristic that is **deliberately limited** and transparent about its own limitation:

```yaml
pattern-either:
  - pattern: $INTENT.getData()
  - pattern: $URI.getQueryParameter(...)
message: 'A deep link handler reads the incoming URI... Verify each value is validated... before it is used.'
```

This rule **does not try** to assess whether validation genuinely exists or not — it **only points to the location** where a parameter is read, and explicitly delegates the real assessment to a human via the word "Verify" in its own message. This is an **honest** design compared to some other rules in this research series that claim more evaluation capability than they actually deliver — this rule does not pretend to automatically detect "missing validation" (which is in fact impossible to do through pattern-matching alone, since validation can take many forms: type conversion, bounds checking, sanitization, allowlisting — four distinct forms explicitly named in §1.6). This is consistent with this test's `manual` type — the rule only functions as a **location map** to speed up human review, not as a substitute for the human judgment itself.

### 1.5 Important Exception: Not Every Parameter Needs Strict Validation

An official note gives an important exception nuance to avoid over-flagging:

> *"If the app intentionally accepts arbitrary parameter values (for example, a search scheme that passes user-typed text to a search UI), input validation may not be required and this test may not apply."*

This is relevant — the `q` parameter in a search scheme (`myapp://search?q=anything`) is, **by design**, intended to accept free-form text from the user; the "validation" needed here is not restricting the text content, but ensuring the **subsequent processing destination** (for example, rendering in a WebView) is safe against that free-form text — which leads back to the XSS question in §1.2, rather than merely "rejecting" the parameter.

### 1.6 Four Categories of Missing Validation (Diagnostic Framework)

The "Further Validation Required" section provides a concrete four-category framework of validation failures:

> *"Missing type conversion... Missing bounds or range checks... Missing sanitization... Missing allowlist checks: a parameter that selects a resource or action is not validated against an allowlist."*

The fourth category (allowlist) is often overlooked but important — if a parameter is used to **select** a resource/action from a limited set (for example, `myapp://action?type=share` vs. `type=delete`), the correct validation is not merely "filtering out dangerous characters," but **rejecting any value not present in a known-good allowlist** — an allowlist approach is inherently stronger than a denylist/character-sanitization approach, which always risks missing some case.

### 1.7 Concrete Evidence: CVE-2026-23866 in WhatsApp

This is very relevant real-world evidence — a recent vulnerability in **WhatsApp**, one of the applications with the largest user base in the world, precisely involving incomplete validation in the handling of a custom URL scheme:

> *"CVE-2026-23866 is a medium-severity input validation flaw affecting WhatsApp for iOS and Android, residing in the handling of AI rich response messages for Instagram Reels. Incomplete validation of these messages allowed a remote user to trigger processing of media content from an arbitrary URL on another user's device, with the flaw also permitting invocation of operating-system controlled custom URL scheme handlers."*

This shows that a **lack of validation** of the URL source embedded in a message can be exploited to trigger the application into processing/fetching content from a URL entirely controlled by the attacker, **while also** triggering the invocation of other custom URL scheme handlers on the system. Additional context on the general scale of similar impact:

> *"Custom URL scheme vulnerabilities in real-world attack scenarios may allow threat actors to redirect users to phishing sites and launch other apps and services on the device via URL schemes such as facetime:, tel:, itms-apps:, or custom app deep links."*

---

## 2. Tools Used for Testing

### 2.1 Required Tools (Core)

| Tool | Function |
|---|---|
| **jadx** | DEX → Java decompilation for manual handler review (MASTG-TECH-0013, MASTG-TECH-0023) |
| **Semgrep** + official rule | Quick location of `getData()`/`getQueryParameter()` calls (MASTG-TECH-0014) |

### 2.2 Alternative & Supporting Tools

| Tool | Function |
|---|---|
| **Frida + Android Deep Link Observer** | Dynamic verification — observing the handler method and the parameters genuinely processed at runtime (MASTG-TECH-0173) |
| **ADB (`am start -a VIEW -d`)** | Sending test payloads (negative amount, path traversal, script injection) directly to the handler |

### 2.3 Environment Prerequisites

- Static analysis does not require a device/root.
- Dynamic verification (Frida) requires a rooted device/emulator with the target application installed.

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0013** to reverse engineer the application.
2. Use **MASTG-TECH-0014** to search for the relevant APIs.

### 3.2 Method A — Semgrep with the Official Rule (Location, Not Evaluation)

```bash
semgrep --config mastg-android-deeplink-unvalidated-parameter.yml ./decompiled/sources
```

### 3.3 Method B — Manual Review Based on the Four Diagnostic Categories (Mandatory, Per §1.6)

For each location found by Method A:

```bash
D=./decompiled/sources
rg -n -A10 'getQueryParameter\(' $D
```

Verify each of the following:
1. **Type conversion** — is there a `toIntOrNull()`/`toLongOrNull()`/parsing with error handling?
2. **Bounds check** — is there a `<`/`>`/range comparison after conversion?
3. **Sanitization** — is the string value used directly in a file/SQL/WebView operation without escaping/parameterization?
4. **Allowlist** — if the parameter selects an action/resource, is it matched against a known list of valid values?

### 3.4 Method C — Dynamic Verification with Frida and Test Payloads (Per MASTG-TECH-0173)

```bash
frida -U -f com.example.app -l android_deep_link_observer.js --no-pause
```

```bash
# Test business logic bypass
adb shell am start -a android.intent.action.VIEW -d "myapp://transfer?amount=-1"

# Test path traversal
adb shell am start -a android.intent.action.VIEW -d "myapp://open?path=../../data/sensitive.txt"

# Test script injection
adb shell am start -a android.intent.action.VIEW -d "myapp://search?q=<script>alert(1)</script>"
```

Observe the hook's output to see which handler method is called and whether the malicious payload successfully affects the application's behavior.

### 3.5 Method Comparison: When to Use Which

| Method | Tool | When to use |
|---|---|---|
| **A** | Semgrep + official rule | Baseline — only shows the location, not the evaluation result |
| **B** | Manual review | **Mandatory** — the core of the test, assessing the four validation categories |
| **C** | Frida + test payloads | Conclusive dynamic verification with real payloads |

**Minimum recommended combination:** **A (location) → B (mandatory) → C (conclusive verification)**.

---

### 3.6 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rule:**

> **Evaluation:** *"The test case fails if a custom URL scheme handler uses URL parameter values without performing adequate validation before acting on them."*

---

#### ❌ FAIL / ISSUE — The check is declared FAILED if:

| No | Condition |
|---|---|
| F1 | A parameter from a custom URL scheme is used in a sensitive operation (financial, file, WebView, query) without any of the four relevant validation categories (§1.6) |

**Example evidence (reflecting the official scenario in §1.2):**

```kotlin
override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    val amount = intent.data?.getQueryParameter("amount") // raw String, not converted
    processTransfer(amount) // passed directly without type/bounds validation
}
```

**FAIL** — no type conversion or bounds check; `amount=-1` or `amount=9999999` can directly affect the transfer logic.

---

#### ✅ PASS — The check is declared PASSED if:

| No | Condition |
|---|---|
| P1 | A numeric parameter is converted with error handling (`toLongOrNull()`), **and** its value bounds are validated, **or** |
| P2 | A string parameter is sanitized according to its destination sink (path canonicalization, parameterized query, WebView escaping), **or** |
| P3 | An action/resource-selecting parameter is matched against an allowlist, **or** |
| P4 | The parameter is genuinely intended to accept free-form values (search text) **and** its destination sink is already safe against such free-form values (§1.5) |

---

#### ⚠️ Important Notes on Assessment

1. **Do not rely on the official rule as a FAIL/PASS indicator** — per §1.4, this rule by design only shows the location, not the evaluation result; every location **must** be manually reviewed against the four categories in §1.6.

2. **Distinguish "intentionally free-form parameters" from "parameters that should be restricted"** — per §1.5, do not flag a search/free-text scheme as a finding merely because it accepts any value; focus on whether the destination processing sink is safe.

3. **Test with real payloads, not just by reading code** — per Method C, dynamic verification with concrete test payloads provides the strongest evidence that validation (or its absence) genuinely impacts the application's behavior.

4. **Severity is modulated:**

   | Factor | Severity |
   |---|---|
   | Path traversal/script injection/business logic bypass on a financial operation confirmed dynamically | **High** |
   | Missing validation on a non-critical parameter | **Medium** |
   | Intentionally free-form parameter with a safe sink | **Not a finding** |

5. **Document:** the handler location, the parameter read, the validation category missing/present, and the result of the dynamic test payload (if performed).

---

## 4. Recommendations

### 4.1 Apply All Four Validation Categories According to Context (MASTG-BEST-0071)

```kotlin
// Type conversion + bounds check
val amount = uri.getQueryParameter("amount")?.toLongOrNull() ?: return
if (amount <= 0 || amount > 10_000) return

// Path traversal prevention
val requestedFile = File(baseDir, uri.getQueryParameter("path") ?: return)
if (!requestedFile.canonicalPath.startsWith(baseDir.canonicalPath)) return

// Allowlist for an action-selecting parameter
val action = uri.getQueryParameter("action")
if (action !in setOf("share", "view", "edit")) return
```

### 4.2 Remediation Checklist

- [ ] Numeric parameters are converted with error handling and their value bounds are validated
- [ ] Path/file parameters have their canonical path checked to remain within the allowed directory
- [ ] Parameters rendered in a WebView are sanitized/escaped according to context
- [ ] Action/resource-selecting parameters are matched against an allowlist
- [ ] Verified with dynamic test payloads (negative amount, `../`, `<script>`)
- [ ] Consideration given to migrating sensitive flows to verified App Links (MASTG-BEST-0070) instead of a custom URL scheme

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0394 (source, tests-beta)](https://github.com/OWASP/mastg/blob/master/tests-beta/android/MASVS-PLATFORM/MASTG-TEST-0394.md)
- [MASTG-TEST-0393 (related document in this research series)](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0393/)
- [MASTG-KNOW-0019: Deep Links](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0019/)
- [MASTG-BEST-0071: Validate Input Parameters in Deep Link and Custom URL Scheme Handlers](https://github.com/OWASP/mastg/blob/master/best-practices/MASTG-BEST-0071.md)
- [MASTG-TECH-0173: Monitoring Deep Link Handlers at Runtime with Frida](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0173/)

### 5.2 Research and Real-World Cases

- [SentinelOne: CVE-2026-23866 — WhatsApp Custom URL Scheme Input Validation Flaw](https://www.sentinelone.com/vulnerability-database/cve-2026-23866/)
- [Ines Martins: Exploiting Deep Links in Android — Part 1](https://inesmartins.github.io/exploiting-deep-links-in-android-part1/index.html)

### 5.3 Tool Documentation

- [Frida CodeShare: Android Deep Link Observer](https://codeshare.frida.re/@leolashkevych/android-deep-link-observer/)
- [Semgrep Documentation](https://semgrep.dev/docs/)

---

*This document was compiled based on official OWASP MASTG content (`tests-beta/android/MASVS-PLATFORM/MASTG-TEST-0394.md`, `MASTG-KNOW-0019`, `MASTG-BEST-0071`, `MASTG-TECH-0173`), analysis of the `mastg-android-deeplink-unvalidated-parameter.yml` rule, which is honestly designed to function only as a location map without claiming automated evaluation, and CVE-2026-23866 in WhatsApp as recent and highly relevant real-world evidence. The most important methodological nuance: unlike App Links (TEST-0393), which can be verified by the OS, a custom URL scheme **architecturally never** has a sender-verification mechanism — input validation at the handler level is the **only** available line of defense, not merely an additional good practice. The four validation categories (type conversion, bounds check, sanitization, allowlist) must be assessed individually and manually, since there is no automated way to verify the "adequacy" of validation from code pattern-matching alone.*
