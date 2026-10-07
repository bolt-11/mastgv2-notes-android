# MASTG-TEST-0368 Insufficient Obfuscation of Security-Relevant Java/Kotlin Code

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0368 |
| **Platform** | Android |
| **MASVS Category** | MASVS-RESILIENCE |
| **Weakness** | MASWE-0059 |
| **Test Type** | Static, Code, **Manual** |
| **Related Techniques** | MASTG-TECH-0013 (Reverse Engineering), MASTG-TECH-0023 (Reviewing Decompiled Java Code), MASTG-TECH-0016 (Smali, as fallback) |
| **Related Knowledge** | MASTG-KNOW-0033 (Obfuscation) |
| **Related Best Practice** | MASTG-BEST-0029 (Implementing Resilience and RASP Signals — `status: placeholder`) |
| **Official Rule** | — (none; this test is purely a qualitative human assessment, consistent with its nature) |

---

## 1. Explanation

### 1.1 Testing Objective

Quote from the official MASTG overview:

> *"If security-relevant Java or Kotlin code is not sufficiently obfuscated, decompilation of the app's DEX bytecode can expose business logic, device attestation and environment checks, integrity checks, and other implementation details that help an attacker understand the app and model attacks."*

This test is unique in this research series because **the question isn't "does it exist" but "is it sufficient"** — obfuscation is almost always *present* in some minimal form (default R8 minification in modern release builds), but the real question is whether that level of obfuscation is **strong enough** to prevent understanding of sensitive logic within a reasonable amount of time. This makes this test one of the most dependent on **qualitative human judgment** compared to automated pattern detection.

### 1.2 A Concrete Threat Scenario: Fintech Fraud Scoring Protected Only by Default R8

The overview gives a very specific step-by-step scenario:

> *"Suppose a fintech app implements its fraud-detection scoring in Java/Kotlin, relying solely on R8 identifier renaming to protect the logic. An attacker decompiles the APK and, despite the shortened class and method names, locates the fraud-scoring logic within minutes by following the plaintext string constants that remain in the code. The attacker reads the exact detection thresholds and decision criteria directly from the decompiled output. Armed with this knowledge, the attacker crafts transactions that stay just below the detection thresholds."*

This scenario contains an important methodological lesson: **an attacker doesn't need to understand class/method names to find sensitive logic** — they merely need to follow **string literals that remain in plaintext** (error message names, JSON field names, condition labels) as a "roadmap" toward the relevant logic, even when identifiers have been fully scrambled by R8. Industry research confirms that this attack pattern is not merely a hypothetical scenario:

> *"In fintech applications, reverse engineering can expose transaction limits, OTP flows, and risk scoring logic, allowing attackers to design highly targeted fraud strategies."*

### 1.3 Six Java/Kotlin Layer Obfuscation Techniques and Their Relative Strength

MASTG-KNOW-0033 lays out six categories of techniques, each targeting a different aspect of reverse engineering:

| Technique | What Is Disguised | Strength Notes |
|---|---|---|
| **Identifier Renaming** (R8/ProGuard) | Class/method/field names | **Layout obfuscation** — doesn't affect performance, but **does not hide string literals** (the main gap in §1.2) |
| **String Encryption** | String literals (URLs, API keys, error messages, root-detection artifacts) | Strings are only visible at runtime, not in static decompiled output |
| **Dynamic Code Loading/Packing** | The physical location of code (separated from the static DEX) | Uses `DexClassLoader`/`InMemoryDexClassLoader`; sensitive logic only "appears" after the loading process runs |
| **Reflection/Indirect Invocation** | Direct call sites in decompiled output | `Class.forName` + `getDeclaredMethod` reduces the number of explicit calls visible |
| **Control Flow Obfuscation** | The original logic flow structure | Opaque predicates, complex `GOTO` — complicates the decompiled control-flow graph |
| **Dead Code Injection** | The signal-to-noise ratio of the code | Adds static-analysis "noise" without changing actual behavior |

A key point testers must understand: **Identifier Renaming alone (the scenario in §1.2) is among the WEAKEST** of these six techniques — it only changes "labels," hiding neither the **content** (string literals) nor the **structure** (control flow) of the logic. This test's evaluation essentially assesses **how far** an application goes beyond this minimal baseline.

### 1.4 Three Diagnostic Questions to Assess Obfuscation Sufficiency

The "Further Validation Required" section gives a framework of three **mutually complementary** questions, not to be evaluated separately:

> *"Determine whether class names, method names, field names, or local variables have been renamed to meaningless identifiers. Determine whether string literals... remain in plaintext and can be used to locate security-relevant logic. Determine whether the control flow is structured in a way that still makes the original logic easy to follow."*

These three questions directly correspond to three of the six techniques in §1.3 (Identifier Renaming, String Encryption, Control Flow Obfuscation) — this is not a coincidence, but shows that the official evaluation implicitly expects testers to consider a **combination** of techniques, not just one. An application that only uses Identifier Renaming (like the fraud-scoring scenario in §1.2) **automatically fails** two of these three diagnostic criteria.

### 1.5 Methodological Fallback: Smali When Decompilation Fails

A practical note relevant for cases of applications with aggressive obfuscation/protection:

> *"If the decompiled output is incomplete or unreliable, use MASTG-TECH-0016 to inspect the corresponding Smali code."*

This matters because **very strong** obfuscation (especially combined with aggressive control flow obfuscation) can sometimes **cause the Java/Kotlin decompiler to fail** or produce syntactically invalid output — in this case, the tester must not conclude "cannot be analyzed, therefore FAIL/PASS by default," but rather descend to the Smali level (an assembly-like representation of Dalvik bytecode, closer to raw bytecode) which can usually still be extracted even when the Java decompiler fails entirely.

### 1.6 The Limitation of Dynamic Loading/Packing Detection

An important note from MASTG-KNOW-0033 relevant for report honesty:

> *"Use MASTG-TOOL-0009 with MASTG-TECH-0165 to identify known compilers, obfuscators, and packers in APKs. The absence of a known signature does not prove that dynamic loading or custom packing is not present."*

This is an important reminder — **the absence of a known obfuscation tool signature does not prove the absence of the mechanism itself**. A custom packer/loader built in-house by the development team (rather than a commercial tool with a known signature) will evade signature-based detection, yet remains functionally effective at hiding logic from ordinary static analysis.

---

## 2. Tools Used for Testing

### 2.1 Required Tools (Core)

| Tool | Function |
|---|---|
| **jadx** | Decompiling DEX → Java for qualitative assessment (MASTG-TECH-0013, MASTG-TECH-0023) |
| **baksmali/apktool** | Fallback to Smali when Java decompilation fails (MASTG-TECH-0016) |

### 2.2 Alternative & Supporting Tools

| Tool | Function |
|---|---|
| **MASTG-TOOL-0009 + MASTG-TECH-0165** | Detecting signatures of known obfuscation/packer tools (with the limitation noted in §1.6) |
| **strings** | Quickly checking how many meaningful string literals remain in the raw DEX, before full decompilation |
| **R8/ProGuard mapping file (if available from the developer for internal audit)** | Comparing original names vs. obfuscated names to assess the actual coverage of renaming applied |

### 2.3 Environment Prerequisites

- No device/root needed — this is purely static analysis.
- Prepare a list of "security-relevant" logic to serve as evaluation targets (fraud scoring, root/attestation checks, integrity verification) before starting, per the scope mentioned in the overview (§1.1).

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0013** to reverse engineer the application.

(A single step — confirming that this test's core is a **qualitative assessment** of decompiled output, not a series of staged pattern searches.)

### 3.2 Method A — Direct Decompilation and Visual Review

```bash
jadx -d ./decompiled target.apk
```

Open the decompiled output and directly assess: are class/method names like `a.b.c`/`a()`, or still descriptive (`FraudScoringEngine.calculateRiskScore()`)?

### 3.3 Method B — Checking Remaining String Literals (Per Diagnostic Criterion §1.4)

```bash
# Check raw strings in classes.dex without full decompilation
strings classes.dex | grep -iE 'threshold|fraud|risk_score|root|debugger|api_key|endpoint'
```

If many meaningful strings appear directly (condition variable names, debug log messages, endpoint names), this indicates **String Encryption has not been applied**, even if Identifier Renaming may be active.

### 3.4 Method C — Fallback to Smali When Decompilation Fails

```bash
apktool d target.apk -o target_smali
# Directly read the relevant .smali file if jadx produces invalid output
```

### 3.5 Method D — Detecting Known Obfuscation/Packer Tool Signatures

```bash
# Example general approach, adapt to the specific MASTG-TOOL-0009 tool
apkid target.apk
```

### 3.6 Method Comparison: When to Use Which

| Method | Tool | When to use |
|---|---|---|
| **A** | jadx | Mandatory baseline — direct visual assessment |
| **B** | strings/grep | Quickly verifying the second diagnostic criterion (string literals) |
| **C** | apktool/Smali | Fallback when decompilation via Method A fails/is unreliable |
| **D** | Signature detector | Identifying the obfuscation tool used (with the limitation in §1.6) |

**Minimum recommended combination:** **A + B (mandatory, the two main diagnostic criteria)**, with **C** as a conditional fallback.

---

### 3.7 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rule:**

> **Evaluation:** *"The test case fails if the Java or Kotlin layer allows an attacker to identify, correlate, and reverse engineer security-relevant logic with reasonable effort."*

Important note: this evaluation is **inherently qualitative** — "reasonable effort" has no official quantitative threshold, requiring experienced and transparently accountable tester judgment.

---

#### ❌ FAIL / ISSUE — The check is declared FAILED if:

| No | Condition |
|---|---|
| F1 | Security-relevant logic can be identified and understood within a reasonable amount of time (per the §1.2 scenario: "within minutes") through a combination of identifier names that remain informative **and/or** remaining plaintext string literals |

**Example evidence (reflecting the official scenario in §1.2):**

```java
// Decompiled output — only default R8 Identifier Renaming
public class a {
    public boolean a(double d) {
        if (d > 5000000.0) { // the threshold is CLEARLY VISIBLE despite obfuscated class/method names
            return true;
        }
        return false;
    }
}
```

Log strings found nearby: `"FRAUD_THRESHOLD_EXCEEDED"`, `"risk_score_calculated"`.

Interpretation: even though the class name `a` and method `a()` have been scrambled, **the threshold value (`5000000.0`) and the logic-marker string (`FRAUD_THRESHOLD_EXCEEDED`) remain in plaintext** — an attacker can directly understand the fraud-detection condition within minutes. **FAIL**.

---

#### ✅ PASS — The check is declared PASSED if:

| No | Condition |
|---|---|
| P1 | Identifiers have been thoroughly renamed, **and** |
| P2 | String literals related to sensitive logic have been encrypted (do not appear in plaintext during static analysis), **and** |
| P3 | The control flow of critical logic has been obfuscated such that the original flow is not easy to trace back |

---

#### ⚠️ Important Notes on Scoring

1. **Don't stop at "does obfuscation exist"** — almost every modern release build has default Identifier Renaming; the real question is whether all three diagnostic criteria (§1.4) are met **simultaneously**, not just one.

2. **String literals are the fastest "roadmap" for an attacker** — per §1.2, even with fully randomized class/method names, remaining string literals still allow rapid navigation to sensitive logic; this is often the single most decisive criterion in the final evaluation outcome.

3. **Consider the possibility of custom dynamic loading/packing** — per §1.6, a negative result from a signature detector **does not prove** the absence of a similar mechanism; if expected sensitive logic "disappears" from the static decompiled output with no clear explanation, consider additional dynamic investigation before concluding PASS.

4. **Document the basis for the "reasonable effort" judgment transparently** — because this evaluation is qualitative, explicitly state how much time the tester needed to find/understand the target logic, and which specific strings/patterns served as the guide, so the report can be re-verified by another party.

5. **Severity is modulated as follows:**

   | Factor | Severity |
   |---|---|
   | Financial fraud-detection/anti-tampering logic can be understood within minutes | **High** |
   | Sensitive logic requires significant effort (hours/days) to understand, even though eventually successful | **Medium** |
   | All three diagnostic criteria are met, sensitive logic is effectively hidden | **Not a finding** (with the caveat that this is still not a permanent guarantee, per the resilience cat-and-mouse principle) |

6. **Document:** the specific logic evaluated, results of checking the three diagnostic criteria, strings/patterns that served as a guide (if found), and the estimated time/effort needed to understand that logic.

---

## 4. Recommendations

### 4.1 Combine at Least Three Techniques, Not Just Identifier Renaming

```pro
# Identifier Renaming (baseline, R8/ProGuard)
-obfuscationdictionary dictionary.txt

# String Encryption (via DexGuard or similar)
-obfuscate-strings class com.example.fraud.ScoringEngine {
    private static double FRAUD_THRESHOLD;
}

# Control Flow Obfuscation for the most critical logic
-obfuscate-control-flow class com.example.fraud.** { *; }
```

### 4.2 Move Sensitive Thresholds/Constants Server-Side

Instead of storing fraud-detection threshold values hardcoded on the client (which will inevitably be found someday, no matter how strong the obfuscation), consider moving the final decision to the server — the client only sends raw features, and the server performs scoring with logic that **never exists in the APK at all**.

### 4.3 Remediation Checklist

- [ ] Identifier renaming is thoroughly applied to classes/methods/fields related to sensitive logic
- [ ] String literals related to sensitive logic (thresholds, condition names, endpoints) are encrypted
- [ ] The control flow of the most critical logic is obfuscated
- [ ] Consider moving the most sensitive decisions (final fraud scoring) server-side
- [ ] Obfuscation results are re-verified with direct decompilation attempts after every major release

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0368 (source, tests-beta)](https://github.com/OWASP/mastg/blob/master/tests-beta/android/MASVS-RESILIENCE/MASTG-TEST-0368.md)
- [MASTG-KNOW-0033: Obfuscation](https://mas.owasp.org/MASTG/knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0033/)
- [MASTG-TECH-0016: Using Smali](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0016/)
- [MASTG-TECH-0023: Reviewing Decompiled Java Code](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0023/)

### 5.2 Official Documentation and Research

- [Android Developers: Enable App Optimization (R8)](https://developer.android.com/topic/performance/app-optimization/enable-app-optimization)
- [Guardsquare ProGuard Manual](https://www.guardsquare.com/manual/configuration/usage)
- [O-MVLL: LLVM-based Obfuscator Documentation](https://obfuscator.re/omvll/)
- [Simpa Labs: Has Your Fintech App Been Reverse Engineered?](https://www.simpalabs.com/blog/how-to-tell-mobile-app-reverse-engineered)
- [Protectt.ai: What is Android App Reverse Engineering? Prevention and Impact on Businesses](https://protectt.ai/blog/what-is-android-app-reverse-engineering-and-how-to-prevent)

### 5.3 Tool Documentation

- [jadx — Dex to Java Decompiler](https://github.com/skylot/jadx)
- [APKiD — Android Application Identifier for Packers, Protectors, Obfuscators](https://github.com/rednaga/APKiD)

---

*This document was prepared based on official OWASP MASTG content (`tests-beta/android/MASVS-RESILIENCE/MASTG-TEST-0368.md`, `MASTG-KNOW-0033`), as well as industry research confirming that reverse engineering fraud-detection/risk-scoring logic in fintech applications is a real, active attack pattern, not a hypothetical scenario. The most important methodological nuance: this test is one of the most dependent on qualitative human judgment in this entire research series — there is no automated rule, and the "reasonable effort" criterion in the official evaluation requires the tester to transparently document the basis for their judgment. The official threat scenario specifically shows that Identifier Renaming alone (the weakest of the six Java/Kotlin layer obfuscation categories) is not sufficient — remaining plaintext string literals still serve as the fastest "roadmap" for an attacker toward sensitive logic, regardless of how randomized the class/method names surrounding it are.*
