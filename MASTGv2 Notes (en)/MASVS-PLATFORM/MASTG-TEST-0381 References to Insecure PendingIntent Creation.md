# MASTG-TEST-0381 References to Insecure PendingIntent Creation

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0381 |
| **Platform** | Android |
| **MASVS Category** | MASVS-PLATFORM |
| **Weakness** | MASWE-0032 |
| **Test Type** | Static |
| **Related Techniques** | MASTG-TECH-0014 (Static Analysis for Relevant APIs) |
| **Related Knowledge** | MASTG-KNOW-0024 (Pending Intents) |
| **Related Best Practice** | MASTG-BEST-0063 (Use Immutable PendingIntents with Explicit Intents) |
| **Official rule** | `mastg-android-pendingintent-mutable.yml` — **two significant gaps** were found, see §1.4 |

---

## 1. Explanation

### 1.1 Testing Objective and Why PendingIntent Differs from an Ordinary Intent

Quote from the official MASTG overview:

> *"A PendingIntent wraps an Intent that will be executed later on behalf of the app's identity and permissions, making it critical to configure them securely."*

The fundamental difference that makes `PendingIntent` its own risk category (not merely a variation of the ordinary Intent in TEST-0372/0374/0375, already discussed in this research series):

> *"What makes a PendingIntent secure is that, unlike a normal Intent, it grants permission to a foreign application to use the Intent (the base intent) it contains, **as if it were being executed by your application's own process**."*

The phrase *"as if it were being executed by your application's own process"* is the core of the risk — `PendingIntent` is designed to grant **execution rights on behalf of the creating application's identity** to the party that receives it (a notification, a widget, a media browser service). This means a `PendingIntent` vulnerability is not merely "an intent that can be intercepted," but a **delegation of identity and permissions** that can be abused.

### 1.2 Two Independent Security Criteria That Must Both Be Satisfied

The overview explicitly splits the risk into two independent categories:

> *"Mutability: A mutable PendingIntent allows the receiving app to modify the base intent's unfilled fields (action, data, categories, extras, etc.)."*
>
> *"Implicit Intents: Using an implicit base intent... can allow malicious apps to intercept the PendingIntent and redirect its execution."*

These two criteria are **mutually independent** — a `PendingIntent` can be safe with respect to one aspect yet remain vulnerable with respect to the other. A combination table for clarity:

| Mutability | Base Intent | Result |
|---|---|---|
| `FLAG_IMMUTABLE` | Explicit | **Safe** |
| `FLAG_IMMUTABLE` | Implicit | Vulnerable to hijacking when the `PendingIntent` is sent to another party, even though its fields cannot be modified |
| `FLAG_MUTABLE` | Explicit | Vulnerable — fields (including action/extras/data) can be filled in by the recipient |
| `FLAG_MUTABLE` | Implicit | **Most vulnerable** — a combination of both risks |

### 1.3 Important Historical Nuance: The Android 12 Default Change

This is a crucial API-version detail for the evaluation criteria:

> *"Prior to Android 12 (API level 31), PendingIntent objects were mutable by default... since Android 12 (API level 31), the mutability of each PendingIntent object must be specified using either FLAG_MUTABLE or the FLAG_IMMUTABLE flag. If the mutability isn't specified, the system throws an IllegalArgumentException and the app will crash."*

This creates a dynamic similar to several other tests in this research series (TEST-0315, TEST-0285) — an application with a `minSdkVersion` below 31 **must explicitly** add `FLAG_IMMUTABLE` because the old default is unsafe; whereas an application that **only** targets API 31+ will automatically crash if it is forgotten — a "fail-safe by design" similar to the Android 14 finding for internal implicit intents in TEST-0372.

### 1.4 Critical Analytical Finding: The Official Rule Does Not Handle Combined Flag Expressions (Bitwise OR) and Entirely Ignores the Implicit-Intent Criterion

The `mastg-android-pendingintent-mutable.yml` rule uses a `metavariable-regex` that is fully anchored (`^...$`) against a single literal value:

```yaml
metavariable-regex:
  metavariable: $FLAGS
  regex: ^(0|134217728|33554432|0x08000000|0x02000000|PendingIntent\.FLAG_UPDATE_CURRENT|PendingIntent\.FLAG_MUTABLE)$
```

This has the **most significant gap** found so far concerning a very common idiomatic code pattern — the **most realistic pattern** most commonly used by developers for a notification `PendingIntent` is a **combination of two flags** via bitwise OR, for example:

```java
PendingIntent.getActivity(context, 0, intent,
    PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE) // SAFE, but NOT checked by the rule
```

or the dangerous version:

```java
PendingIntent.getActivity(context, 0, intent,
    PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_MUTABLE) // DANGEROUS, NOT detected by the rule
```

Because the regex is fully anchored against a **single token**, **any combined expression** (written textually by Semgrep as the string `"PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_MUTABLE"` when `$FLAGS` captures the entire expression) **will never match** any pattern in the list — neither the **safe** case (combined with `FLAG_IMMUTABLE`, which should not be flagged, and indeed is not — correct by coincidence) nor the **dangerous** case (combined with `FLAG_MUTABLE` without justification, which should be flagged but is **entirely missed**). This means the rule is only effective for a case that rarely occurs in real code — a single flag with no combination — while the most common pattern in production (a combination with `FLAG_UPDATE_CURRENT`/`FLAG_CANCEL_CURRENT`) entirely escapes detection, regardless of which direction the outcome goes.

A second gap: this rule **only targets the mutability criterion**, and contains **no pattern whatsoever** for the second criterion explicitly named in the overview — an implicit base intent (§1.2). Of the three official FAIL criteria (see §3.6), the rule touches only one criterion, and even for that one criterion its coverage is limited to a single, non-combined flag.

### 1.5 Concrete Evidence: From Major Vendor Firmware to System Privilege Escalation

Research and CVE databases show that this vulnerability class is very commonly found in major Android vendor firmware, with a wide range of impacts from file theft to provider access bypass:

> *"CVE-2023-44123 and CVE-2023-44125 involve implicit PendingIntents without FLAG_IMMUTABLE set or with FLAG_MUTABLE set in LG apps, leading to theft and/or overwrite of arbitrary files with system privilege."*

> *"CVE-2023-30700 is a PendingIntent hijacking vulnerability in SemWifiApTimeOutImpl that allows local attackers to access ContentProvider without proper permission."*

The scale of the problem at a single vendor alone is concerning:

> *"Samsung alone disclosed four PendingIntent hijacking CVEs between 2021 and 2023."*

Academic research from BlackHat EU 2021 ("PendingIntent Redirection: A Universal Privilege Escalation Method for Android Systems and Popular Apps") confirms that this vulnerability class is not a narrow issue limited to one or two applications, but a **universal attack pattern** applicable across many different systems and popular applications — consistent with the empirical finding that this mistake keeps recurring across many different vendors over time.

---

## 2. Tools Used for Testing

### 2.1 Required Tools (Core)

| Tool | Function |
|---|---|
| **jadx** | DEX → Java decompilation for manual analysis |
| **Semgrep** + official rule | Basic detection of a single, non-combined flag (very limited coverage, §1.4) |

### 2.2 Alternative & Supporting Tools

| Tool | Function |
|---|---|
| **grep/ripgrep** | **Mandatory** — closes the gap for combined flag expressions and the implicit-intent criterion not covered by the official rule |

### 2.3 Environment Prerequisites

- No device/root needed — purely static analysis.
- Note the application's `minSdkVersion` to calibrate the first FAIL criterion (§1.3).

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Run a static analysis tool to identify every call to the five `PendingIntent.get*()` variants.
2. For each call, check the flags parameter and whether the base intent is explicit/implicit.

### 3.2 Method A — Semgrep with the Official Rule (Limited Coverage)

```bash
semgrep --config mastg-android-pendingintent-mutable.yml ./decompiled/sources
```

### 3.3 Method B — grep/ripgrep to Close the Combined Flag Gap (Mandatory, §1.4)

```bash
D=./decompiled/sources

# Search for ALL calls to PendingIntent.get*, including those using combined flags
rg -n 'PendingIntent\.get(Activity|Activities|Service|ForegroundService|Broadcast)\(' $D -A1

# Manual verification: does FLAG_IMMUTABLE appear in the flag expression (single OR combined)?
rg -n 'PendingIntent\.FLAG_IMMUTABLE' $D
rg -n 'PendingIntent\.FLAG_MUTABLE' $D
```

### 3.4 Method C — Verify Explicit vs. Implicit Base Intent (Mandatory, a Criterion Not Covered by the Official Rule)

```bash
# Trace back the intent variable passed to PendingIntent.get*()
rg -n -B10 'PendingIntent\.get(Activity|Service|Broadcast)\(' $D | grep -E 'new Intent\(|setClass\(|setComponent\(|setClassName\('
```

For each base intent found, verify whether it was constructed with an explicit constructor (`Intent(context, Class)`) or paired with `setClass()`/`setComponent()`/`setClassName()` — if none of these are present, that intent is implicit.

### 3.5 Method Comparison: When to Use Which

| Method | Tool | When to use |
|---|---|---|
| **A** | Semgrep + official rule | Baseline, detects only a small fraction of cases (single flag) |
| **B** | Manual grep/ripgrep | **Mandatory** — the only way to close the combined-flag gap |
| **C** | Manual review | **Mandatory** — the only way to check the implicit-intent criterion |

**Minimum recommended combination:** **B + C (mandatory, the real baseline)**, with Method A only as a minor supplement.

---

### 3.6 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rule (three independent FAIL criteria):**

> **Evaluation:** *"The test case fails if any of the following conditions are met: (1) A PendingIntent is created without FLAG_IMMUTABLE when minSdkVersion is below 31, unless properly justified. (2) A PendingIntent is created with FLAG_MUTABLE without a valid use case. (3) The base intent is implicit."*

---

#### ❌ FAIL / ISSUE — The check is declared FAILED if any of the following holds:

| No | Condition |
|---|---|
| F1 | A `PendingIntent` is created without `FLAG_IMMUTABLE` on `minSdkVersion` < 31, without clear mutability justification |
| F2 | A `PendingIntent` is created with `FLAG_MUTABLE` without a valid use case (not an inline reply/app widget callback) |
| F3 | The base intent is implicit (no `setClass`/`setComponent`/`setClassName`/explicit constructor) |

**Example evidence (reflecting the real-world CVE-2023-44123/44125 pattern in §1.5):**

```java
Intent intent = new Intent(); // implicit — F3
intent.setAction("com.example.app.ACTION_SYNC");
PendingIntent pi = PendingIntent.getBroadcast(context, 0, intent,
    PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_MUTABLE); // F2, AND not detected by the rule (§1.4)
```

**FAIL** — doubly so: the base intent is implicit AND mutable without justification, both of which are missed by the automated rule.

---

#### ✅ PASS — The check is declared PASSED if:

| No | Condition |
|---|---|
| P1 | `FLAG_IMMUTABLE` is explicit (alone or combined via OR with other flags such as `FLAG_UPDATE_CURRENT`), **and** |
| P2 | The base intent is explicit (constructor `Intent(context, Class)` or `setClass`/`setComponent`/`setClassName`) |

---

#### ⚠️ Important Notes on Assessment

1. **Do not rely on the official rule as a baseline** — per §1.4, the most common code pattern in production (combined flags) entirely escapes the rule, regardless of direction; manual grep is the only adequate way to verify.

2. **Check all three FAIL criteria independently** — do not stop after finding that `FLAG_IMMUTABLE` is present; still check whether the base intent is explicit (criterion F3 is entirely separate from F1/F2).

3. **Consider `minSdkVersion` for criterion F1** — in an application that only targets API 31+, the absence of a mutability flag will cause a crash at build/runtime (a platform fail-safe), making F1 practically impossible to occur unnoticed; F1 is far more relevant for applications with a lower `minSdkVersion`.

4. **Severity is modulated:**

   | Factor | Severity |
   |---|---|
   | `PendingIntent` is mutable + implicit, related to a sensitive operation (authentication, transactions) | **High** |
   | Either one of the two criteria (mutable OR implicit) is satisfied, not both | **Medium-High** |
   | `FLAG_IMMUTABLE` + explicit intent fully verified | **Not a finding** |

5. **Document:** the code location, the complete flag expression (including OR combinations), the explicit/implicit status of the base intent, the application's `minSdkVersion`, and the justification if `FLAG_MUTABLE` is genuinely needed.

---

## 4. Recommendations

### 4.1 Always Use FLAG_IMMUTABLE + Explicit Intent (Per MASTG-BEST-0063)

```kotlin
// BEFORE — implicit + combined flags without IMMUTABLE
val intent = Intent("com.example.app.ACTION_SYNC")
val pendingIntent = PendingIntent.getBroadcast(context, 0, intent,
    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE)

// AFTER — explicit + IMMUTABLE
val intent = Intent(context, SyncReceiver::class.java).apply {
    setPackage(context.packageName)
}
val pendingIntent = PendingIntent.getBroadcast(context, 0, intent,
    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
```

### 4.2 Remediation Checklist

- [ ] Every call to `PendingIntent.get*()` uses `FLAG_IMMUTABLE`, whether alone or combined via OR
- [ ] `FLAG_MUTABLE` is only used for a justified use case (inline reply, app widget callback) with restricted fields
- [ ] Every base intent uses `setClass`/`setComponent`/`setClassName`/an explicit constructor
- [ ] Verification was performed manually (grep), not relying solely on the official Semgrep rule's results

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0381 (source, tests-beta)](https://github.com/OWASP/mastg/blob/master/tests-beta/android/MASVS-PLATFORM/MASTG-TEST-0381.md)
- [MASTG-KNOW-0024: Pending Intents](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0024/)
- [MASTG-BEST-0063: Use Immutable PendingIntents with Explicit Intents](https://github.com/OWASP/mastg/blob/master/best-practices/MASTG-BEST-0063.md)

### 5.2 Research and Real-World Cases

- [GitHub Advisory: CVE-2022-36829 — PendingIntent Hijacking in releaseAlarm](https://github.com/advisories/GHSA-pjg2-878f-mvhc)
- [Strix.ai: CVE-2023-30700 — PendingIntent Hijacking ContentProvider Access Bypass](https://www.strix.ai/cve/CVE-2023-30700)
- [arXiv: Exploiting PendingIntent Provenance Confusion to Spoof Android SDK Authentication](https://arxiv.org/pdf/2603.02539)
- [Android Developers: Pending Intents Risk](https://developer.android.com/privacy-and-security/risks/pending-intent)
- [SegmentFault: PendingIntent Redirection — A Universal Privilege Escalation Method (BlackHat EU 2021)](https://segmentfault.com/a/1190000041550819/en)

### 5.3 Tool Documentation

- [Semgrep Documentation](https://semgrep.dev/docs/)

---

*This document was compiled based on official OWASP MASTG content (`tests-beta/android/MASVS-PLATFORM/MASTG-TEST-0381.md`, `MASTG-KNOW-0024`, `MASTG-BEST-0063`), analysis of the `mastg-android-pendingintent-mutable.yml` rule, and real-world research and CVEs (CVE-2023-44123/44125 at LG, CVE-2023-30700 at Samsung, with a total of four PendingIntent hijacking CVEs from Samsung alone between 2021-2023, and academic research from BlackHat EU 2021 on PendingIntent Redirection as a universal privilege-escalation method). The most important and most significant methodological nuance: the official rule uses a fully anchored regex against a single flag token, so that **a combined flag expression via bitwise OR** — the most common code pattern used in real-world production (`FLAG_UPDATE_CURRENT | FLAG_IMMUTABLE`/`FLAG_MUTABLE`) — **entirely escapes automated detection regardless of direction**. The rule also entirely fails to cover the second criterion (implicit base intent) explicitly named in this test's own official evaluation. Manual verification of flag combinations and the explicit/implicit status of the base intent is mandatory, not an optional supplement.*
