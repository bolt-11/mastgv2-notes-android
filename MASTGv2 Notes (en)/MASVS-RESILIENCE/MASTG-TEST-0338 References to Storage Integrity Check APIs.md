# MASTG-TEST-0338 References to Storage Integrity Check APIs

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0338 |
| **Platform** | Android |
| **MASVS Category** | MASVS-RESILIENCE |
| **Weakness** | MASWE-0057 |
| **Test Type** | Static, Code, **Manual** |
| **Related APIs** | `javax.crypto.Mac`, `java.security.Signature`, `java.security.MessageDigest` |
| **Special Flag** | `false_negative_prone: true` — explicitly marked in the frontmatter |
| **Related Techniques** | MASTG-TECH-0013 (Reverse Engineering), MASTG-TECH-0014 (Static Analysis for Relevant APIs), MASTG-TECH-0008 (Accessing App Data Directories), MASTG-TECH-0023 (Reviewing Decompiled Java Code) |
| **Related Knowledge** | MASTG-KNOW-0036 (Shared Preferences) |
| **Related Best Practice** | MASTG-BEST-0066 (Implementing Storage Integrity Checks on Android) |
| **Official Rule** | `mastg-android-local-storage-input-validation.yml` — found to have a **significant design flaw**, see §1.4 |

---

## 1. Explanation

### 1.1 Testing Objective

Official MASTG overview quote:

> *"Android apps can protect the integrity and authenticity of data they store on the device (e.g., in SharedPreferences, files, or databases) by computing an HMAC or a digital signature over the data and verifying it before use. If the app does not implement such checks, an attacker who modifies the stored data can go undetected and the app may trust the tampered input in a security-relevant decision."*

An important nuance emphasized by the overview — this threat **does not depend on data leaking to another app**. Even data stored correctly in the app's private sandbox (`MODE_PRIVATE`, not normally readable by other apps) remains vulnerable to tampering by **the device owner themselves** or an attacker who has gained local privileged access:

> *"Even data stored in the app's private sandbox (such as SharedPreferences) normally cannot be modified by other apps, but it can still be tampered with in local attack scenarios, such as on rooted devices, during dynamic analysis, through backups, or by directly manipulating the app's data directory after obtaining privileged access."*

### 1.2 A Concrete Threat Scenario: Manipulating a Trial Counter / Premium Flag

The overview provides a very specific and easy-to-understand step-by-step scenario:

> *"Suppose an app stores a usage counter or entitlement flag in SharedPreferences and trusts it without verifying its integrity. 1. An attacker uses MASTG-TECH-0008 to locate the app's data directories on a rooted device. 2. The attacker modifies the stored value (for example, resets a trial counter or flips a 'premium' flag). 3. Because the app never verifies an HMAC or signature over the stored data, it loads the tampered value as authentic. 4. The attacker bypasses the intended restriction."*

This scenario is not a theoretical risk — it is a **complete business model** for popular tools that have been circulating in the Android ecosystem for a long time:

> *"Lucky Patcher's In-App Purchase Obstruction feature provides users with a way to bypass in-app purchases and access premium features without spending any money by modifying the app code and tricking the in-app purchase system into thinking that a legitimate purchase has been made... Lucky Patcher can bypass license verification for paid apps and unlock in-app purchases without payment."*

The existence of tools like this — which require root but are already highly mature and easily accessible to the public — confirms that the risk this test targets is **actively exploited in the field** against apps that do not implement integrity checks, not merely an academic scenario.

### 1.3 Three Core APIs and Their Respective Roles

| API | Mechanism | When It's Used |
|---|---|---|
| `javax.crypto.Mac` | HMAC — the same symmetric key is used to both generate and verify the tag | Most common, suitable when the app itself both writes and reads the data |
| `java.security.Signature` | Asymmetric digital signature (public/private key) | Suitable when verification needs to be performed by a party that does not hold the private key (e.g., a server verifying data signed by the app) |
| `java.security.MessageDigest` | Pure checksum/hash (no key) | **Does not provide authenticity** — only detects unintentional changes, not deliberate tampering (an attacker can recompute a new hash after modification) |

A critical point to underscore: the presence of `MessageDigest` **alone** (without HMAC/signature) **is not sufficient** to protect against deliberate tampering — a pure checksum without a secret key can be recomputed by anyone, including an attacker who has just modified the data. This is relevant to the evaluation in §3.7 — finding `MessageDigest` alone is not strong evidence of an effective integrity protection mechanism.

### 1.4 A Critical Analytical Finding: The Official Rule Contains a Demo-Specific, Non-Generic Pattern

This is the most significant finding from analyzing the rule for this test. The `mastg-android-local-storage-input-validation.yml` rule has the following structure:

```yaml
- patterns:
    - pattern-inside: |
        ...
        private final String loadPlain(...) {
          ...
        }
    - pattern-either:
        - pattern: prefs().getString(...)
        - ...
```

Note the `pattern-inside` which **requires** a match to occur inside a method **literally** named `loadPlain` or `loadProtected`. This is a serious design problem — **this rule will only function if the target app's code happens to have a method named exactly "loadPlain"/"loadProtected"**. This is extremely unlikely to occur by coincidence in any real production app outside of MASTG's own example/demo apps (such as Crackmes/MASTG-APP used to demonstrate techniques in the documentation). In other words, this rule was most likely **written as a template copied from MASTG's internal demo code** and has not yet been generalized into a pattern genuinely capable of detecting arbitrary code in any real-world app.

The second pattern (`mastg-android-hmac-validation-present`) is looser and more generic — it searches for the presence of `Mac.getInstance()`, `SecretKeySpec`, `$MAC.init()`, `$MAC.doFinal()` anywhere, with no method-name restriction. This pattern is **much more practically useful**, though it still does not cover `Signature`/`MessageDigest` mentioned in this test's `apis:` frontmatter. Also note a category-tag mismatch in this rule — the rule's message uses the tag `[MASVS-CODE-4]` rather than `[MASVS-RESILIENCE-...]` as this test's category would suggest — another indication that this rule was likely written/adapted from a different context without being fully adjusted to the MASVS-RESILIENCE category.

### 1.5 Why This Test Is Typed "Manual" and Flagged `false_negative_prone`

The "Further Validation Required" section explains why mere API presence is not sufficient:

> *"These APIs are commonly used for unrelated purposes (for example, networking, analytics, or generic checksums), so their mere presence does not confirm a storage integrity mechanism."*

`Mac`/`Signature`/`MessageDigest` are **generic** cryptographic APIs used everywhere — network API authentication (HMAC for request signing), license verification, even cache deduplication. Finding these APIs in the code **does not automatically mean** they are used to protect the specific `SharedPreferences`/file/database data relevant to this test — the tester must **manually trace** whether the resulting HMAC/signature is actually compared against a value read back from local storage.

The official "Expected False Negatives" section also acknowledges the opposite limitation:

> *"This test may produce false negatives if the integrity check relies on a third-party library, a custom implementation, or APIs not covered by the analysis."*

The `false_negative_prone: true` flag in the frontmatter is an explicit metadata acknowledgment from MASTG itself — rarely found this openly in other tests outside of prose notes.

### 1.6 An Additional Criterion: Not Just "Does It Exist," But "Is It Effective Against the Relevant Attacker Model"

The third validation question from "Further Validation Required" sets a higher bar than simply "HMAC found":

> *"Determine whether that validation is effective for the attacker model in scope."*

This connects directly to the warning note in MASTG-BEST-0066:

> *"Storage integrity checks are bypassable if the attacker can extract the HMAC key (for example, if it is hardcoded in the app or recoverable on a rooted device) or intercept the verification logic at runtime. Treat these as a defense-in-depth control rather than a standalone guarantee."*

This means even a PASS finding (HMAC found and used correctly) needs **further assessment** — where is that HMAC key stored? If the key is only hardcoded in the code (extractable via reverse engineering) or does not use the Android Keystore, that protection effectively **only raises the cost of attack**, rather than genuinely preventing it against a sufficiently motivated attacker (root + reverse engineering).

---

## 2. Tools Used for Testing

### 2.1 Required Tools (Core)

| Tool | Function |
|---|---|
| **jadx** | DEX → Java decompilation (MASTG-TECH-0013, MASTG-TECH-0023) |
| **Semgrep** + official rule `mastg-android-local-storage-input-validation.yml` | Initial triage — though with limited coverage (§1.4) |
| **objection** | Access to the app's data directory (MASTG-TECH-0008) for directly verifying the contents of `SharedPreferences`/file/database |

### 2.2 Alternative and Supporting Tools

| Tool | Function |
|---|---|
| **grep/ripgrep** | Searching for all `Mac`/`Signature`/`MessageDigest` calls without a method-name restriction, closing the official rule's gap (§1.4) |
| **Frida** | Dynamic verification — hooking the function that reads `SharedPreferences` and the HMAC/signature verification function to observe whether the two are genuinely connected at runtime |
| **Lucky Patcher (in a controlled test environment)** | Replicating a real-world attack scenario (§1.2) — attempting to directly modify `SharedPreferences` values and observing whether the app detects it |

### 2.3 Environment Prerequisites

- Initial static analysis does not require a device/root.
- **Dynamic verification is highly recommended** given this test's "manual" nature and `false_negative_prone` flag — a rooted device/emulator is needed to directly access and modify app data (MASTG-TECH-0008).

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0013** to reverse engineer the application.
2. Use **MASTG-TECH-0014** to search for relevant APIs.

### 3.2 Method A — Semgrep with the Official Rule (Limited Coverage)

```bash
semgrep --config mastg-android-local-storage-input-validation.yml ./decompiled/sources
```

**Mandatory note:** the `mastg-android-local-storage-input-validation` pattern only works if there is a method literally named `loadPlain`/`loadProtected` (§1.4) — it will most likely produce no matches on a real-world app. Rely instead on the second pattern (`mastg-android-hmac-validation-present`) as a more useful signal, though it still requires manual verification.

### 3.3 Method B — grep/ripgrep for Full Coverage of the Three APIs

```bash
D=./decompiled/sources

# Search for all HMAC calls without a method-name restriction
rg -n 'Mac\.getInstance\(|SecretKeySpec\(' $D

# Search for Signature calls (not covered by the official rule at all)
rg -n 'Signature\.getInstance\(' $D

# Search for MessageDigest calls (needs verification of whether paired with a secret key, §1.3)
rg -n 'MessageDigest\.getInstance\(' $D

# Search for SharedPreferences/file/database reads around the results above
rg -n -B5 -A5 'Mac\.getInstance|Signature\.getInstance' $D | grep -E 'SharedPreferences|getString\(|getInt\(|openFileInput|query\('
```

### 3.4 Method C — Manual Review (Mandatory, Per MASTG-TECH-0023)

For each location found via Method A/B:

1. Identify whether the value read from local storage influences a security decision (authentication, authorization, premium feature access, configuration flag).
2. Trace whether an HMAC/signature is computed **over the same data** and compared **before** that value is used.
3. Examine the app's reaction when verification fails — does it truly reject the value, or does it continue even though verification failed (silent failure)?
4. Trace the source of the HMAC key — is it hardcoded in the code, or stored in the Android Keystore (§1.6)?

### 3.5 Method D — Dynamic Verification by Replicating a Real-World Attack Scenario

```bash
# Via objection, access the app's data directory
objection -g com.example.app explore
# inside the REPL:
cd /data/data/com.example.app/shared_prefs
cat app_prefs.xml
```

```
Manual procedure:
1. Identify a value suspected to be an entitlement/counter (e.g., <boolean name="is_premium" value="false" />)
2. Directly modify that value via a text editor on a rooted device
3. Rerun the app, observe whether the change is accepted (FAIL) or rejected/detected (PASS)
```

This directly replicates the official threat scenario (§1.2) and the technique genuinely used by tools like Lucky Patcher.

### 3.6 Method Comparison: When to Use Which

| Method | Tool | When to Use |
|---|---|---|
| **A** | Semgrep + official rule | Initial triage, though the first pattern is almost useless (§1.4) |
| **B** | Manual grep/ripgrep | Far more adequate coverage for the three official APIs |
| **C** | Manual review (mandatory) | The core of testing — assessing security relevance and effectiveness |
| **D** | Dynamic verification | The most conclusive proof, directly replicating a real attack scenario |

**Minimum recommended combination:** **B (the real baseline) → C (mandatory) → D (final proof)**, with Method A serving only as a minor supplement given the significant limitations of its first pattern.

---

### 3.7 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rule:**

> **Evaluation:** *"The test case fails if the app uses data loaded from local storage in a security-relevant decision without verifying its integrity and authenticity beforehand."*

---

#### ❌ FAIL / ISSUE — The check is declared FAILED if:

| No | Condition |
|---|---|
| F1 | A value from `SharedPreferences`/file/database influences a security decision **and** no HMAC/signature is verified before that value is used |

**Example evidence (reflecting the official scenario in §1.2):**

```java
// Found in com/example/app/billing/PremiumChecker.java
SharedPreferences prefs = getSharedPreferences("billing", MODE_PRIVATE);
boolean isPremium = prefs.getBoolean("is_premium", false); // no integrity verification
if (isPremium) {
    unlockPremiumFeatures();
}
```

Interpretation: the premium flag is read directly without any HMAC/signature — it can be directly modified on a rooted device (via Lucky Patcher or manual editing) to unlock premium features for free. **FAIL**.

---

#### ✅ PASS — The check is declared PASSED if:

| No | Condition |
|---|---|
| P1 | A sensitive value is stored **together with** an HMAC/signature computed over it, and is verified **before** being used in a security decision, **and** |
| P2 | The app correctly reacts (rejects the value) when verification fails, **and** |
| P3 | The HMAC/signature key is stored in the Android Keystore (not hardcoded) — per MASTG-BEST-0066, for full effectiveness against a root-level attacker model (§1.6) |

**Example evidence:**

```java
boolean isPremium = prefs.getBoolean("is_premium", false);
byte[] expectedTag = Base64.decode(prefs.getString("is_premium_hmac", ""), Base64.DEFAULT);
byte[] actualTag = hmac(String.valueOf(isPremium).getBytes(), keystoreKey);
if (MessageDigest.isEqual(expectedTag, actualTag) && isPremium) {
    unlockPremiumFeatures();
} else {
    // reject, log as an indication of tampering
}
```

**PASS**.

---

#### ⚠️ Important Notes on Assessment

1. **Do not rely on the official rule's Pattern 1 as a meaningful signal** — it will most likely produce no match on any real-world app's code (§1.4); use manual grep as the real baseline.

2. **A pure `MessageDigest` is not evidence of effective integrity protection** — always verify whether the checksum is paired with a secret key (making it an HMAC) or is merely a plain hash that an attacker can recompute (§1.3).

3. **A technical PASS does not always mean fully secure** — always check where the HMAC/signature key is stored (§1.6); an HMAC with a hardcoded key only provides minimal "defense-in-depth" protection, not a real guarantee against an attacker with root access.

4. **The app's reaction to verification failure is just as important as the existence of verification itself** — an app that computes an HMAC but still continues even when verification fails (silent failure) is effectively equivalent to having no protection at all.

5. **Use dynamic verification for the strongest proof** — directly replicating the Lucky Patcher-style scenario (manually modifying a value on a rooted device) provides the most conclusive evidence and is easiest for non-technical stakeholders to understand.

6. **Severity is modulated:**

   | Factor | Severity |
   |---|---|
   | Entitlement/financial flag (premium, payment) with no integrity check at all | **High** |
   | Non-financial configuration flag with no integrity check | **Medium** |
   | An integrity check exists but the key is hardcoded/not in the Keystore | **Low-Medium** (weak defense-in-depth) |
   | An integrity check exists, the key is in the Keystore, and the failure reaction is correct | **Not a finding** |

7. **Document:** the code location, the type of data protected, the integrity check mechanism used (HMAC/signature/none), the key's storage location, and the result of dynamic verification (tampering replication).

---

## 4. Recommendations

### 4.1 Implement HMAC with a Key from the Android Keystore

```kotlin
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

fun hmac(data: ByteArray, key: ByteArray): ByteArray {
    val mac = Mac.getInstance("HmacSHA256")
    mac.init(SecretKeySpec(key, "HmacSHA256"))
    return mac.doFinal(data)
}

fun verify(data: ByteArray, tag: ByteArray, key: ByteArray): Boolean {
    return hmac(data, key).contentEquals(tag)
}
```

### 4.2 Ensure the Correct Reaction When Verification Fails

```java
if (!verify(storedValue, storedTag, keystoreKey)) {
    Log.w(TAG, "SharedPreferences data integrity verification failed — possible tampering");
    resetToSecureDefault(); // DO NOT proceed with an unverified value
    return;
}
```

### 4.3 Remediation Checklist

- [ ] All security-relevant data in local storage (entitlements, counters, configuration flags) is protected by an HMAC/signature
- [ ] The HMAC/signature key is stored in the Android Keystore, not hardcoded
- [ ] The app rejects and responds correctly when integrity verification fails
- [ ] Verified dynamically by attempting to directly modify values on a rooted device
- [ ] Understood as a defense-in-depth control, combined with server-side validation for critical business decisions (payment, licensing)

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0338 (source, tests-beta)](https://github.com/OWASP/mastg/blob/master/tests-beta/android/MASVS-RESILIENCE/MASTG-TEST-0338.md)
- [MASTG-KNOW-0036: Shared Preferences](https://mas.owasp.org/MASTG/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0036/)
- [MASTG-BEST-0066: Implementing Storage Integrity Checks on Android](https://github.com/OWASP/mastg/blob/master/best-practices/MASTG-BEST-0066.md)
- [MASTG-TECH-0008: Accessing App Data Directories](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0008/)

### 5.2 Research and Real-World Cases

- [Doverunner: How to Block Lucky Patcher Usage on Android Apps?](https://doverunner.com/blogs/how-to-block-lucky-patcher-usage-on-android-apps/)
- [OWASP Cheat Sheet: Encrypt-then-MAC Pattern](https://web.archive.org/web/20210804035343/https://cseweb.ucsd.edu/~mihir/papers/oem.html)

### 5.3 Tool Documentation

- [Semgrep Documentation](https://semgrep.dev/docs/)
- [Objection — Runtime Mobile Exploration](https://github.com/sensepost/objection)
- [Frida — Dynamic Instrumentation Toolkit](https://frida.re/docs/home/)

---

*This document was prepared based on official OWASP MASTG content (`tests-beta/android/MASVS-RESILIENCE/MASTG-TEST-0338.md`, `MASTG-KNOW-0036`, `MASTG-BEST-0066`), analysis of the `mastg-android-local-storage-input-validation.yml` rule, as well as real-world context on popular tools (Lucky Patcher) actively used to exploit storage integrity weaknesses in the Android ecosystem. The most important methodological nuance: the official rule's Pattern 1 (`mastg-android-local-storage-input-validation`) contains a dependency on a literal method name (`loadPlain`/`loadProtected`) that is most likely a leftover template from internal demo code and **will not match any real-world application code** — Pattern 2 (`mastg-android-hmac-validation-present`) is far more useful but also has an inconsistent category tag (`MASVS-CODE-4` on a test categorized under MASVS-RESILIENCE). This test is explicitly flagged `false_negative_prone` and typed manual — the mere presence of an API is never sufficient; assessing security relevance, correct pairing of verification, and reaction to verification failure all require human review.*
