# MASTG-TEST-0312 References to Explicit Security Provider in Cryptographic APIs

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0312 |
| **Platform** | Android |
| **MASVS Category** | MASVS-CRYPTO (MASVS-CRYPTO-1) |
| **Weakness** | MASWE-0007 — *Improper Encryption* |
| **Test Type** | Static, Code |
| **Knowledge** | MASTG-KNOW-0011 (Security Provider) |
| **Best Practice** | MASTG-BEST-0020 (Update the GMS Security Provider — discussed in depth in the MASTG-TEST-0295 document) |
| **Related Techniques** | MASTG-TECH-0013, MASTG-TECH-0014 |
| **Related Tests** | **MASTG-TEST-0295** (GMS Security Provider Not Updated) — a different test but sharing the "security provider" theme; **important clarification**: the official semgrep rule for this test (see §3.2) was previously **mis-associated** with MASTG-TEST-0295 in the preliminary research of this document series — that rule actually **belongs to this test** |
| **Related Demo** | — (none) |
| **Official Rule** | `mastg-android-hardcoded-security-provider.yaml` — **a rule correctly targeted at this test** |
| **Related CWE** | CWE-327 (Use of a Broken or Risky Cryptographic Algorithm), CWE-1104 (Use of Unmaintained Third Party Components) |

---

## 1. Explanation

### 1.1 Important Clarification: A Correction to the Earlier Analysis in the MASTG-TEST-0295 Document

Before discussing the substance of this test, an important methodological clarification should be noted: in the **MASTG-TEST-0295** document (GMS Security Provider Not Updated) in this research series, the semgrep rule `mastg-android-hardcoded-security-provider.yaml` was **found and correctly flagged as not relevant** to the `ProviderInstaller`/provider-update-via-Google-Play-Services topic that is the focus of that test. Further research for this test (MASTG-TEST-0312) **confirms** that the rule was in fact **not** mis-targeted overall — it is **genuinely relevant**, just **for a different test**, namely **this one**. This is a good example of how a single rule in the MASTG repository can serve a specific test ID, and of the importance of precisely verifying the rule-to-test association instead of assuming it from surface-level topic similarity ("security provider").

### 1.2 Testing Objective: When "Explicitly Specifying a Provider" Is Actually Risky

Quote from the official MASTG overview:

> *"Android cryptography APIs based on the Java Cryptography Architecture (JCA) allow developers to specify a security provider when calling `getInstance` methods. However, **explicitly specifying a provider can cause security issues and break compatibility** because several providers have been deprecated or removed in recent versions."*

This is a conceptually **interesting** test because it combines **two problem dimensions usually kept separate** in this research series: **security** (older providers carry cryptographic implementations that may be outdated/vulnerable) **and** **stability/compatibility** (a provider explicitly hardcoded risks making the app **crash** on newer Android versions). In JCA (Java Cryptography Architecture), the `getInstance()` method on various cryptographic classes (`Cipher`, `KeyStore`, `Signature`, etc.) accepts an **optional provider parameter** — a string name specifying **which specific implementation** must be used, instead of letting the system automatically choose the default provider based on the platform's pre-configured priority order.

### 1.3 The Deprecation Timeline That Is the Root of the Real Risk

The official overview gives a **concrete timeline** underlying why hardcoding a provider name is a dangerous practice on the continually evolving Android ecosystem:

| Provider | Status |
|---|---|
| **_Crypto_** | Deprecated in Android 7.0 (API 24), **completely removed** in Android 9 (API 28) |
| **_BouncyCastle_ (`BC`)** | Deprecated in Android 9 (API 28), **completely removed** in Android 12 (API 31) |
| **Any provider (in general)** | *"Apps targeting Android 9 (API level 28) or above fail when a provider is specified"* — a broader statement from the official overview, indicating that the risk of failure is not limited only to the two providers above |

This pattern **recurs historically** — Android has consistently removed/deprecated older providers in favor of consolidating around a more modern and maintained implementation (**Conscrypt**, discussed in §1.4). Developers who **write a provider name explicitly** in their code **lock** the app to that specific provider — once that provider is removed from the platform, calling `getInstance(algo, "ProviderName")` will **throw** a `NoSuchProviderException` at runtime, causing a **crash** that would have been entirely avoidable had the developer **not** specified a provider explicitly from the start (letting the system automatically choose the appropriate default provider).

### 1.4 Real-World Case: A Production Crash in the F-Droid App

Community research documents a concrete example of the real-world consequences of this pattern in the **F-Droid** app (a popular open-source app store) after updating to Android 12:

> Users experienced a **crash** when tapping the *"Nearby"* feature followed by *"Find people nearby"*, with the error: **`no such algorithm: SHA1WITHRSA for provider BC`**.

This case very clearly illustrates how the removal of the BouncyCastle implementation in Android 12 (which covered **all AES algorithms** and various other algorithms previously provided by the `BC` provider) directly caused a functional failure in a real production app that still encoded the assumption that the `BC` provider would always be available — not a hypothetical scenario, but an **incident genuinely experienced by users** of a widely used application.

### 1.5 The Recommended Provider: `AndroidOpenSSL` (Conscrypt)

The official overview states a clear solution:

> *"This test identifies cases where an app explicitly specifies a security provider... that is not the default provider, `AndroidOpenSSL` (Conscrypt), which is actively maintained and should generally be used."*

**Conscrypt** (internal provider name: `AndroidOpenSSL`) is a JCA provider based on OpenSSL/BoringSSL that is developed and **actively maintained by Google** as part of the Android platform itself. Unlike third-party providers such as BouncyCastle, whose integration cycle into Android depends on platform decisions that can change (and eventually be removed), Conscrypt **is the default provider** on modern Android and continues to receive security updates alongside platform releases — this is why the official overview concludes: the **safest approach** to avoiding this entire class of problems is to **not specify a provider at all**, letting the system automatically choose Conscrypt (or another appropriate default provider) without the developer needing to do anything explicitly.

### 1.6 An Explicitly Recognized Legitimate Exception: `AndroidKeyStore`

This is the most important evaluation nuance that distinguishes this test from an absolute prohibition against "never specify any provider." The official overview explicitly acknowledges **one legitimate exception**:

> *"It examines `getInstance` calls and flags any use of a named provider other than legitimate exceptions such as `KeyStore.getInstance("AndroidKeyStore")`."*

Calling `KeyStore.getInstance("AndroidKeyStore")` — along with related patterns such as `KeyPairGenerator.getInstance("RSA", "AndroidKeyStore")` discussed in MASTG-KNOW-0012 (refer to the MASTG-TEST-0307 document in this research series) — is **NOT** a mistake, because `AndroidKeyStore` is **not just any ordinary JCA provider**; it is a **special integration mechanism** with the Android hardware-backed keystore that **must** indeed be called explicitly by design (there is no other way to access keys stored in the Keystore besides calling this provider specifically). The official Evaluation clause confirms this exception precisely, by restricting the FAIL condition **specifically** to `KeyStore` operations:

> *"The test case fails if any `getInstance` call explicitly specifies a security provider other than `AndroidKeyStore` **for `KeyStore` operations**."*

Note this **specific wording** — the official clause literally restricts the FAIL condition to `KeyStore.getInstance()` calls that use a provider other than `AndroidKeyStore`, not to **all** JCA classes (`Cipher`, `Signature`, `MessageDigest`, etc.) in general — even though the substance and rationale of the overview (the deprecation timeline, crash risk) clearly applies broadly across all JCA APIs. This is a nuance in precise wording that testers **should pay attention to** when interpreting the literal scope of the evaluation versus the overall spirit of this test.

---

## 2. Tools Used for Testing

### 2.1 Required Tools (Core)

| Tool | Function |
|---|---|
| **jadx** | Decompiles DEX → Java for searching `getInstance()` patterns with a provider parameter |
| **grep / ripgrep** | Searching for API patterns and extracting the provider name used |
| **semgrep** | Runs the official rule |

### 2.2 Alternative & Supporting Tools

| Tool | Function |
|---|---|
| **CodeQL** | Traces all two-argument `getInstance()` calls across all relevant JCA classes (`Cipher`, `KeyGenerator`, `KeyPairGenerator`, `MessageDigest`, `Signature`, `Mac`, `SecretKeyFactory`, `KeyFactory`, `SecureRandom`, etc.), classifying the found provider name against the list of deprecated/removed providers |
| **MobSF** | Sometimes displays this pattern in the Code Analysis report's cryptography category |
| **Multi-version Android target (emulator)** | Dynamic verification — running the app on an Android 12+ emulator to empirically confirm whether the found provider call actually causes a `NoSuchProviderException`/`NoSuchAlgorithmException` crash |

### 2.3 Environment Prerequisites

- **No device/root required** for core static analysis.
- **For dynamic verification**, ideally an emulator with **several different API versions** should be available (especially API 28+ and API 31+) to empirically confirm the crash impact per the deprecation timeline (§1.3).

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0013** to reverse engineer the application.
2. Use **MASTG-TECH-0014** to search for the relevant APIs.

### 3.2 Method A — Official Semgrep Rule *(a correctly targeted rule, see §1.1)*

```yaml
rules:
  - id: mastg-android-hardcoded-security-provider
    languages: [java]
    severity: WARNING
    metadata:
      summary: This rule looks for explicitly specified security providers in getInstance calls.
    message: "[MASVS-CRYPTO-1] Explicitly specified security provider found. Do not hardcode a provider unless using AndroidKeyStore."
    patterns:
      - pattern-either:
          - pattern: $X.getInstance($ALGO, $PROVIDER)
          - pattern: $X.getInstance($ALGO, (String $PROVIDER))
          - pattern: $X.getInstance($ALGO, (java.security.Provider $PROVIDER))
      - pattern-not: KeyStore.getInstance("AndroidKeyStore")
      - metavariable-regex:
          metavariable: $X
          regex: (Cipher|KeyGenerator|KeyPairGenerator|MessageDigest|Signature|Mac|SecretKeyFactory|KeyFactory|SecureRandom|KeyAgreement|AlgorithmParameters|AlgorithmParameterGenerator|CertificateFactory|CertPathBuilder|CertPathValidator|CertStore|KeyStore)
```

```bash
semgrep --config https://raw.githubusercontent.com/OWASP/mastg/master/rules/mastg-android-hardcoded-security-provider.yaml ./decompiled/sources/
```

**Analysis of this rule's coverage**: this rule effectively covers **all relevant JCA classes** (see the full list in `metavariable-regex`) — much broader than the literal official Evaluation clause, which specifically mentions only `KeyStore` (§1.6). This rule already includes a `pattern-not` to explicitly exclude `KeyStore.getInstance("AndroidKeyStore")` as a legitimate exception — consistent with the official overview. **Unlike several other rules analyzed in this research series**, this rule is **reasonably comprehensive and functions as claimed** — it is worth using as the primary method with a higher degree of confidence, without much to note in terms of significant gaps.

### 3.3 Method B — grep/ripgrep as a Supplement for Manual Verification

```bash
D=./decompiled/sources

# Find all getInstance calls with 2 arguments (algorithm + provider)
rg -n '\.getInstance\([^,]+,\s*"[A-Za-z]+"\)' $D

# Specifically highlight providers KNOWN to already be deprecated/removed
rg -n '\.getInstance\([^,]+,\s*"(BC|Crypto)"\)' $D
```

### 3.4 Method C — CodeQL for Systematic Classification

```ql
import java

class ExplicitProviderCall extends MethodAccess {
  ExplicitProviderCall() {
    this.getMethod().hasName("getInstance") and
    this.getNumArgument() = 2 and
    this.getArgument(1).getType().hasName("String") and
    not (this.getQualifier().getType().hasName("KeyStore") and
         this.getArgument(1).(StringLiteral).getValue() = "AndroidKeyStore")
  }
}

from ExplicitProviderCall call
select call, call.getArgument(1).toString(), "Provider explicitly specified — verify whether this is AndroidOpenSSL/Conscrypt or a risky provider (BC/Crypto)"
```

### 3.5 Method D — Multi-Version Dynamic Verification (Confirming the Actual Crash Impact)

```bash
# Run on an Android 12+ (API 31+) emulator to confirm BouncyCastle has been removed
emulator -avd api31-test &
adb install target-app.apk
adb logcat | grep -i "NoSuchProviderException\|NoSuchAlgorithmException"
# Trigger the code path that uses the explicit provider, observe the crash
```

### 3.6 Method Comparison: When to Use Which

| Method | Tool | Coverage | When to use |
|---|---|---|---|
| **A** | Official semgrep rule | Broad, covers all relevant JCA classes | **Reliable primary baseline** |
| **B** | grep | Quick manual verification supplement | Quick cross-check |
| **C** | CodeQL | Structured classification for large codebases | Large-scale audits |
| **D** | Multi-version dynamic verification | Definitive proof of real crash impact | Final confirmation, especially for reporting to the development team |

**Recommended minimum combination:** **A (reliable baseline) → D (confirmation of real impact on the relevant Android version)** for the most persuasive report to the development team.

---

### 3.7 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rule:**

> **Evaluation:** *"The test case fails if any `getInstance` call explicitly specifies a security provider other than `AndroidKeyStore` for `KeyStore` operations."*

---

#### ❌ FAIL / ISSUE — The check is declared FAILED when:

| No | Condition |
|---|---|
| F1 | A call to `getInstance(algo, "BC")` or `getInstance(algo, "Crypto")` is found — providers **already confirmed** to be removed on the relevant Android version |
| F2 | A call to `getInstance()` with **any** explicit provider other than `AndroidOpenSSL`/the system default is found, on any JCA class other than `KeyStore` (following the broad spirit of the overview, §1.6) |
| F3 | Dynamic verification (Method D) confirms an actual `NoSuchProviderException`/`NoSuchAlgorithmException` crash on the target Android version |

**Example evidence (illustrative — MASTG does not yet provide an official demo for this test):**

```java
// Found in com/example/target/crypto/LegacyCryptoHelper.java
Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding", "BC");  // explicit BouncyCastle
```

```bash
$ emulator -avd api31-test &
$ adb logcat | grep NoSuchProviderException
E/AndroidRuntime: java.security.NoSuchProviderException: no such provider: BC
    at com.example.target.crypto.LegacyCryptoHelper.encrypt(LegacyCryptoHelper.java:22)
```

Interpretation: the `BC` provider is explicitly hardcoded, and dynamic verification on Android 12+ confirms an **actual crash** per the deprecation timeline (§1.3) — exactly the pattern experienced by the F-Droid app (§1.4). **Critical FAIL**, combining both the security and stability dimensions at once.

---

#### ✅ PASS — The check is declared PASSED when:

| No | Condition |
|---|---|
| P1 | All `getInstance()` calls **do not** specify a provider explicitly — letting the system automatically choose the default provider (Conscrypt/`AndroidOpenSSL`) |
| P2 | The only call with an explicit provider is `KeyStore.getInstance("AndroidKeyStore")` — a legitimate exception |
| P3 | Multi-version dynamic verification shows no provider-related crash on any Android version the app supports |

---

#### ⚠️ Important Notes on Assessment

1. **This is a rare test where "security fix" and "stability fix" are fully aligned** — communicate both benefits to the development team to increase remediation urgency, since the real crash impact (not just an abstract security risk) is often more effective at motivating a quick fix.

2. **Pay attention to the nuance of the literal Evaluation clause wording versus the overview's broader spirit** (§1.6) — even though the official clause literally mentions only `KeyStore`, the official rule and the overview's overall rationale clearly cover all JCA classes; report findings on other JCA classes as part of this test's spirit, rather than ignoring them because of the narrower literal wording.

3. **The official rule for this test is fairly reliable** — unlike several other rules analyzed in this research series that showed significant gaps, this rule is worth using as the primary method with higher confidence.

4. **Dynamic verification on the relevant Android version provides the most persuasive evidence** — an actual crash is far more convincing to a development team than a purely theoretical security-risk argument.

5. **Severity is modulated:**

   | Factor | Severity |
   |---|---|
   | A provider **already confirmed removed** (`BC` on API 31+, `Crypto` on API 28+) found in an active code path | **High** (real production crash risk) |
   | A provider that still exists but is hardcoded (locking the app to an implementation that may be removed in the future) | **Medium** |
   | `KeyStore.getInstance("AndroidKeyStore")` | **Not a finding** |

6. **Document:** the code location, the hardcoded provider name, that provider's deprecation/removal status per the timeline (§1.3), and the dynamic verification results, if performed.

---

## 4. Recommendations

### 4.1 Remove the Provider Parameter, Let the System Choose the Default

```java
// BEFORE — locked to a provider at risk of being removed
Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding", "BC");

// AFTER — the system automatically chooses the default provider (Conscrypt/AndroidOpenSSL)
Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
```

### 4.2 If Consistency Across Older Android Versions Must Be Guaranteed, Bundle Conscrypt Explicitly

```groovy
dependencies {
    implementation 'org.conscrypt:conscrypt-android:2.5.2'
}
```

```kotlin
Security.addProvider(Conscrypt.newProvider())
```

### 4.3 Remediation Checklist

- [ ] All `getInstance()` calls with an explicit provider are inventoried
- [ ] The provider parameter is removed except for `KeyStore.getInstance("AndroidKeyStore")`
- [ ] Dynamic verification on a multi-version emulator confirms no provider-related crash
- [ ] If cross-version consistency for older versions is needed, Conscrypt is bundled explicitly as a replacement for BouncyCastle
- [ ] **Re-verify:** rerun MASTG-TEST-0312 after every addition of new cryptographic code

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0312: References to Explicit Security Provider in Cryptographic APIs](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0312/)
- [MASTG-TEST-0295: GMS Security Provider Not Updated](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0295/)
- [MASWE-0007: Improper Encryption](https://mas.owasp.org/MASWE/MASVS-CRYPTO/MASWE-0007/)
- [MASTG-KNOW-0011: Security Provider](https://mas.owasp.org/MASTG/knowledge/android/MASVS-CRYPTO/MASTG-KNOW-0011/)
- [MASTG-BEST-0020: Update the GMS Security Provider](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0020/)
- [Official rule: mastg-android-hardcoded-security-provider.yaml (GitHub)](https://github.com/OWASP/mastg/blob/master/rules/mastg-android-hardcoded-security-provider.yaml)

### 5.2 Official Android Documentation

- [Android Developers Blog — Cryptography Changes in Android P](https://android-developers.googleblog.com/2018/03/cryptography-changes-in-android-p.html)
- [Android Developers — Android 9 Changes: Conscrypt Implementations](https://developer.android.com/about/versions/pie/android-9.0-changes-all#conscrypt_implementations_of_parameters_and_algorithms)
- [Android Developers — Android 12 Behavior Changes: Bouncy Castle](https://developer.android.com/about/versions/12/behavior-changes-all#bouncy-castle)
- [Conscrypt — A Java Security Provider for Android](https://github.com/google/conscrypt)

### 5.3 Research and Real-World Cases

- [GitLab F-Droid — Issue #2338 (crash due to BouncyCastle removal)](https://gitlab.com/fdroid/fdroidclient/-/issues/2338)
- [GitHub google/conscrypt#1119 — NoSuchProviderException: no such provider: BC on Android 7](https://github.com/google/conscrypt/issues/1119)
- [CWE-327: Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)
- [CWE-1104: Use of Unmaintained Third Party Components](https://cwe.mitre.org/data/definitions/1104.html)

### 5.4 Tool Documentation

- [Semgrep — Documentation](https://semgrep.dev/docs/)
- [CodeQL — Documentation](https://codeql.github.com/docs/)
- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)

---

*This document was compiled based on OWASP MASTG (latest release as of September 2026), official Android Developers documentation on security provider changes across versions, and the real-world case of F-Droid app breakage due to the BouncyCastle removal in Android 12. This test is unique because it combines the security and stability/compatibility dimensions in a fully aligned way — hardcoding a provider name not only locks the app to a cryptographic implementation that may be insecure, but also creates a real production crash risk as Android removes older providers. This document also corrects an earlier finding in the MASTG-TEST-0295 document — the semgrep rule flagged there as not relevant turns out to genuinely belong to this test (MASTG-TEST-0312), rather than being a rule entirely without a clear matching test.*
