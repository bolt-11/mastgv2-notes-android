# MASTG-TEST-0372 Implicit Intents Used for Internal App Communication

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0372 |
| **Platform** | Android |
| **MASVS Category** | MASVS-CODE |
| **Weakness** | MASWE-0032 |
| **Test Type** | Static, Code, **Manual** |
| **Related Techniques** | MASTG-TECH-0013, MASTG-TECH-0014, MASTG-TECH-0023 |
| **Related Knowledge** | MASTG-KNOW-0025 (Explicit vs Implicit Intents) |
| **Related Best Practice** | MASTG-BEST-0056 (Use Explicit Intents for Internal IPC) |
| **Related Tests** | Closely related to MASTG-TEST-0364/0365/0366 (exported component) — findings from this test are often the **source** that activates the risk in those tests from the sender's side |
| **Official Rule** | `mastg-android-implicit-intent-internal-communication.yml` — a **significant coverage gap** was found, see §1.5 |

---

## 1. Explanation

### 1.1 Testing Objective

Quote from the official MASTG overview:

> *"An implicit intent is an Intent that does not name a concrete target component. Instead, it declares an action, and optionally data or categories, and Android resolves it to an installed component with a matching `<intent-filter>`."*

It's important to note: an implicit intent is **not inherently dangerous**. The overview explicitly acknowledges its wide range of legitimate uses:

> *"Android apps commonly use implicit intents when they intentionally delegate an action to another app selected by the system or the user. Typical legitimate uses include opening a web page or map location with ACTION_VIEW, sharing content with ACTION_SEND, requesting a file or image with ACTION_GET_CONTENT."*

The problem arises specifically when a mechanism designed for **intentional cross-application delegation** is misused for **communication that should remain internal**.

### 1.2 Intent Hijacking Mechanism: Two Different Scenarios Depending on the Number of Matches

> *"If the system presents a chooser, the user may select the third-party app; if only one matching handler exists or a default handler has been set, the intent may be delivered without an explicit user decision."*

This reveals two exploitation paths with different levels of user involvement:

| Scenario | Mechanism | User's Role |
|---|---|---|
| **Multiple matches, no default** | The system displays a chooser dialog | The user **can** unknowingly select a malicious app (social engineering via a deceptive name/icon) |
| **Only one match (malicious app installed first/sole match), or a default handler is already set** | The system sends automatically **with no dialog** | **No user involvement at all** — the attacker only needs to install an app with a matching `<intent-filter>` |

The second scenario is far more dangerous because it **requires no user interaction/inattention at all** — interception happens entirely silently at the system level.

### 1.3 List of Relevant APIs: Broader Coverage Than Just startActivity

The overview explicitly lists many relevant APIs, beyond what people commonly think of:

> *"Relevant creation and dispatch patterns include `Intent(String)`, `Intent().setAction(...)`, `startActivity`, `startActivityForResult`, `ActivityResultLauncher.launch`, `startService`, `bindService`, `sendBroadcast`, and related APIs."*

This confirms that this risk **extends beyond Activity** — `startService`/`bindService` (linking to the Service risk in TEST-0365) and `sendBroadcast` (linking to TEST-0366) are equally relevant here, because **all three component types** can be the target of a misdirected implicit intent.

### 1.4 Modern Platform Protection: Android 14 Fully Prohibits Internal Implicit Intents

This is the most important piece of information for the context of severity and recommendations — MASTG-KNOW-0025 reveals a very significant platform change:

> *"If the application targets Android 14 (API level 34) or higher, implicit intents will never be sent to internal components. This feature forces developers to implement explicit intents for internal communication, as otherwise the application would not function correctly while testing."*

This means for applications that **already** target API 34+, this mistake **will be detected automatically during ordinary functional testing** (the application will fail to function, not merely be silently vulnerable) — a form of "fail-safe by design" from the platform. However, this also means **this test's findings are far more relevant for applications with a `targetSdkVersion` below 34**, which can still run this problematic code without ever becoming aware of it through normal functional testing.

### 1.5 Critical Analytical Finding: The Official Rule Only Covers One of the Six Dispatch APIs Named by the Overview

Look at the pattern of the `mastg-android-implicit-intent-internal-communication.yml` rule:

```yaml
patterns:
  - pattern: |
      $INTENT = new Intent(...);
      ...
      $INTENT.setAction($ACTION);
      ...
      $CONTEXT.startActivity($INTENT);
  # (pattern-not for setPackage/setComponent/explicit constructor)
languages: [java]
```

This rule **exclusively** matches patterns that end with `startActivity()`. However, the official overview (§1.3) explicitly lists **six** relevant dispatch APIs: `startActivity`, `startActivityForResult`, `ActivityResultLauncher.launch`, `startService`, `bindService`, `sendBroadcast`. The official rule **only covers one of the six** — implicit intents sent via `startService()`/`bindService()` (risk directly connected to TEST-0365) or `sendBroadcast()` (connected to TEST-0366) **will not be detected at all** by this rule, even though both are explicitly mentioned as relevant vectors in this test's own overview.

A second gap: this rule is **Java-only** (`languages: [java]`), while all the official code examples in MASTG-KNOW-0025 and MASTG-BEST-0056 are actually written in **Kotlin**. This means modern Kotlin codebases (which are the de facto standard for new Android development) will fully evade this rule regardless of the implicit intent pattern used.

### 1.6 Real-World Evidence: From Firewall Database Tampering to ICCID/IMSI Leaks in Major Vendor Apps

Security research documents several real CVEs that precisely illustrate this risk:

> *"An implicit intent hijacking vulnerability in Firewall application (CVE-2023-42552) allows 3rd party application to tamper the database of Firewall."*

> *"Implicit Intent hijacking vulnerability in AppLinker allows attackers to launch certain activities with privilege of AppLinker."*

Most concerning — a similar vulnerability was found in a **major vendor's** application, not just a niche app:

> *"Xiaomi's Phone Services app was vulnerable to implicit intent hijacking that exposed system values such as ICCID or IMSI of virtual SIMs."*

Documented common exploitation mechanisms technically explain how hijacking occurs through priority manipulation:

> *"When multiple services have the same intent-filter, the service with higher priority is chosen to process corresponding intents. A malicious app has a service X with the same intent-filter as that of the service Y in a benign app and with higher priority than Y... service X in the malicious app will be started."*

This adds an important nuance — the attacker does not only rely on "being the sole match," but can also actively **win the competition** against a legitimate internal component by setting a higher `android:priority` on its own `<intent-filter>`.

---

## 2. Tools Used for Testing

### 2.1 Required Tools (Core)

| Tool | Function |
|---|---|
| **jadx** | Decompile DEX → Java/Kotlin (MASTG-TECH-0013) |
| **Semgrep** + official rule | Basic detection of `startActivity` with an implicit intent (limited coverage, §1.5) |

### 2.2 Alternative & Supporting Tools

| Tool | Function |
|---|---|
| **grep/ripgrep** | **Mandatory** — closes the gap for the other five dispatch APIs (`startService`, `bindService`, `sendBroadcast`, `startActivityForResult`, `ActivityResultLauncher.launch`) and Kotlin code |
| **MobSF** | Automated report that sometimes includes basic intent detection |

### 2.3 Environment Prerequisites

- No device/root required — purely static analysis.
- Note the application's `targetSdkVersion` at the outset (§1.4) to calibrate severity.

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0013** to reverse engineer the application.
2. Use **MASTG-TECH-0014** to search for relevant APIs.

### 3.2 Method A — Semgrep with the Official Rule (Limited Coverage)

```bash
semgrep --config mastg-android-implicit-intent-internal-communication.yml ./decompiled/sources
```

### 3.3 Method B — grep/ripgrep to Close the Gap for the Other Five Dispatch APIs and Kotlin (Mandatory)

```bash
D=./decompiled/sources

# Implicit intent construction in both Kotlin and Java
rg -n 'Intent\("|setAction\(' $D

# The five dispatch APIs NOT covered by the official rule
rg -n '\.startService\(|\.bindService\(|\.sendBroadcast\(|\.startActivityForResult\(|ActivityResultLauncher.*\.launch\(' $D

# Verify whether setPackage/setComponent/setClass is present as a mitigation
rg -n -B10 'startService\(|sendBroadcast\(' $D | grep -E 'setPackage|setComponent|setClass'
```

### 3.4 Method C — Manual Review (Mandatory, Per MASTG-TECH-0023)

For each result from Method A/B, verify:

1. Whether the intent has `setPackage`/`setComponent`/an explicit constructor — if not, proceed.
2. Whether the action used is a **custom application** action (e.g., `com.example.app.INTERNAL_ACTION`) clearly intended to be internal, rather than a standard Android action (`ACTION_VIEW`, etc.) that is intentionally delegated to an external application.
3. For broadcasts, check whether there is a sender permission restricting the receiver.

### 3.5 Method Comparison: When to Use Which

| Method | Tool | When to use |
|---|---|---|
| **A** | Semgrep + official rule | Baseline, `startActivity` only + Java |
| **B** | Manual grep/ripgrep | **Mandatory** — full coverage of the other five APIs + Kotlin |
| **C** | Manual review | **Mandatory** — distinguishing internal action from legitimate external delegation |

**Minimum combination I recommend:** **B (the real baseline) → C (mandatory)**, with Method A only as a small supplement.

---

### 3.6 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rule:**

> **Evaluation:** *"The test case fails if an intent used for app-internal or trusted-component communication is implicit and another app can declare or register a matching component to receive it."*

---

#### ❌ FAIL / ISSUE — The check is declared FAILED if:

| No | Condition |
|---|---|
| F1 | An intent intended for internal/trusted-component communication is implicit (without `setPackage`/`setComponent`/an explicit constructor), **and** another application can register a matching `<intent-filter>` |

**Example evidence (reflecting the real CVE-2023-42552 pattern, §1.6):**

```kotlin
val intent = Intent("com.example.firewall.UPDATE_RULES").apply {
    putExtra("rule_data", sensitiveRuleConfig)
}
sendBroadcast(intent) // implicit, not covered by the official Semgrep rule (§1.5)
```

Interpretation: an internal broadcast for updating firewall configuration is sent implicitly — a malicious application could register a receiver with the same action to intercept/manipulate the configuration data. **FAIL**.

---

#### ✅ PASS — The check is declared PASSED if:

| No | Condition |
|---|---|
| P1 | The internal intent uses `setPackage`/`setComponent`/an explicit constructor `Intent(context, Class)`, **or** |
| P2 | The implicit intent is genuinely intended for delegation to an external application chosen by the user/system (ACTION_VIEW, ACTION_SEND, etc.) — not a finding category for this test |

---

#### ⚠️ Important Notes on Assessment

1. **Do not rely solely on the official rule** — per §1.5, five of the six dispatch APIs mentioned in the overview are not covered, and the rule is Java-only even though the official examples use Kotlin.

2. **Distinguish custom internal actions from standard system actions** — actions like `"com.example.app.*"` that clearly belong to the application itself are strong candidates, unlike standard `ACTION_VIEW`/`ACTION_SEND` which are indeed designed for external delegation.

3. **Consider `targetSdkVersion`** — findings on applications targeting API 34+ are likely already "self-correcting" since the platform prohibits sending implicit intents to internal components (§1.4); this finding is far more critical on applications targeting below that.

4. **Severity is modulated:**

   | Factor | Severity |
   |---|---|
   | Internal implicit intent carries sensitive data (credentials, security configuration) on `targetSdkVersion` < 34 | **High** |
   | Internal implicit intent without sensitive data | **Medium** |
   | `targetSdkVersion` ≥ 34 (platform already auto-mitigates) | **Low** (still recorded as a code smell) |

5. **Document:** code location, action used, dispatch API, presence/absence of `setPackage`/`setComponent`, data carried (extras), and the application's `targetSdkVersion`.

---

## 4. Recommendations

### 4.1 Use Explicit Intents for Internal Communication (Per MASTG-BEST-0056)

```kotlin
// BEFORE — implicit, vulnerable to hijacking
val intent = Intent("com.example.app.PROCESS_DATA").apply {
    putExtra("key", "value")
}
startActivity(intent)

// AFTER — explicit by component, the strictest option
val intent = Intent(context, TargetActivity::class.java).apply {
    putExtra("key", "value")
}
startActivity(intent)
```

### 4.2 Remediation Checklist

- [ ] All intents for internal communication use `setComponent`/an explicit constructor or at minimum `setPackage`
- [ ] Verification covers all five dispatch APIs (`startService`, `bindService`, `sendBroadcast`, `startActivityForResult`, `ActivityResultLauncher.launch`), not just `startActivity`
- [ ] No sensitive data (tokens, credentials) is carried via an implicit intent
- [ ] Internal broadcasts use a sender permission if they cannot be made explicit

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0372 (source, tests-beta)](https://github.com/OWASP/mastg/blob/master/tests-beta/android/MASVS-CODE/MASTG-TEST-0372.md)
- [MASTG-KNOW-0025: Explicit vs Implicit Intents](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0025/)
- [MASTG-BEST-0056: Use Explicit Intents for Internal IPC](https://github.com/OWASP/mastg/blob/master/best-practices/MASTG-BEST-0056.md)

### 5.2 Research and Real-World Cases

- [GitHub Advisory: CVE-2023-42552 — Implicit Intent Hijacking in Firewall Application](https://github.com/advisories/GHSA-qcqr-cxwj-882p)
- [Oversecured: Interception of Android Implicit Intents](https://blog.oversecured.com/Interception-of-Android-implicit-intents/)
- [Medium: Intent Hijacking in Android — What It Is and How to Prevent It](https://medium.com/@iam_azhar/intent-hijacking-in-android-what-it-is-and-how-to-prevent-it-ebb5a075f229)
- [CWE-927: Use of Implicit Intent for Sensitive Communication](https://exploit-intel.com/cwe/CWE-927)

### 5.3 Tool Documentation

- [Semgrep Documentation](https://semgrep.dev/docs/)
- [Android Developers: Safer Intents (Android 14 Behavior Changes)](https://developer.android.com/about/versions/14/behavior-changes-14#safer-intents)

---

*This document was prepared based on official OWASP MASTG content (`tests-beta/android/MASVS-CODE/MASTG-TEST-0372.md`, `MASTG-KNOW-0025`, `MASTG-BEST-0056`), analysis of the `mastg-android-implicit-intent-internal-communication.yml` rule, and security research documenting real CVEs (CVE-2023-42552 Firewall app database tampering, ICCID/IMSI leaks in Xiaomi Phone Services). The most important methodological nuance: the official rule only covers one of the six dispatch APIs explicitly named in this test's own overview (`startActivity` only, missing `startService`/`bindService`/`sendBroadcast`/`startActivityForResult`/`ActivityResultLauncher.launch`), and is Java-only even though all official MASTG code examples for this topic are written in Kotlin — manual searching covering the other five APIs and Kotlin syntax is a requirement, not an optional supplement. Android 14+ provides automatic platform mitigation for the internal-activity case, making this finding far more critical on applications targeting below that API level.*
