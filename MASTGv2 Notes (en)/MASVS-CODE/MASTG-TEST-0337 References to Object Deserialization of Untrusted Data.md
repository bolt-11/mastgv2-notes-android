# MASTG-TEST-0337 References to Object Deserialization of Untrusted Data

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0337 |
| **Platform** | Android |
| **MASVS Category** | MASVS-CODE |
| **Weakness** | MASWE-0050 |
| **Test Type** | Static, Code |
| **Related Techniques** | MASTG-TECH-0013 (Reverse Engineering), MASTG-TECH-0014 (Static Analysis for Relevant APIs) |
| **Related Knowledge** | MASTG-KNOW-0021 (Object Serialization) |
| **Official Rule** | `mastg-android-object-deserialization.yml` — **very narrow scope**, see §1.4 |

---

## 1. Explanation

### 1.1 Testing Objective

Official MASTG overview quote:

> *"Android apps can reconstruct objects from serialized data received through platform mechanisms such as Intent extras, Bundle values, IPC payloads, files, or network responses. If the app deserializes data from these sources without restricting the allowed classes or validating the input before use, the deserialization logic can introduce unintended application behavior or unsafe state changes."*

An important point to underline from the start: the official overview explicitly names **five different data sources** (`Intent` extras, `Bundle`, IPC, files, network responses) as relevant vectors. This is far broader than a single API — and as will be discussed in §1.4, this is precisely where the biggest gap lies between the threat scope described in the overview and the scope of the available official rule.

### 1.2 Six Serialization Mechanisms on Android (Per MASTG-KNOW-0021)

MASTG-KNOW-0021 outlines the various ways Android can perform object serialization/deserialization, each with a different risk profile:

| Mechanism | Primary Deserialization Risk |
|---|---|
| **Java Serializable + `ObjectInputStream`** | The classic object-injection risk — the class being deserialized can be attacker-controlled if not filtered |
| **JSON (`JSONObject`, Gson, Jackson, Moshi)** | Inherently lower risk (field-based, not an arbitrary class type), but still vulnerable if using reflection without validation |
| **XML (`XmlPullParser`, SAX)** | The main risk is **XML External Entity (XXE)**, not direct object deserialization |
| **ORM (OrmLite, Realm, etc.)** | Depends on whether the underlying database is encrypted |
| **`Parcelable`** | Widely used for `Intent`/`Bundle` — vulnerable to a **parcel/unparcel mismatch** at the framework level (§1.5) |
| **Protocol Buffers** | Has a CVE history (`CVE-2015-5237`), provides no built-in encryption |

This diversity matters — this test is **not** solely about a single `ObjectInputStream.readObject()` API, but about a **risk pattern** that can appear across many different mechanisms, depending on how the target app actually builds its inter-component communication features.

### 1.3 FAIL Criterion: A Combination of an Untrusted Source + No Validation

> **Evaluation:** *"The test case fails if the app deserializes data received from untrusted sources (e.g., Intent extras from any other application) without proper validation or type filtering."*

An explicit example of an untrusted source cited — **`Intent` extras from any other application**. This is relevant because on Android, exported components (`Activity`, `Service`, `BroadcastReceiver` with `exported="true"`, or without an explicit declaration on older API levels) can receive an `Intent` from **any third-party app installed on the device**, not only from trusted apps or the system itself.

### 1.4 A Key Analytical Finding: The Official Rule Is Far Narrower Than the Documented Threat Scope

This is the most crucial part of the rule analysis — compared to the five sources and six mechanisms described in §1.1-1.2, the official rule `mastg-android-object-deserialization.yml` **only** targets one specific pattern:

```yaml
pattern: |-
  $VAR = new java.io.ObjectInputStream(...);
  ...
  $OBJ = $VAR.readObject();
```

This rule **completely does not cover**:

- `Intent.getSerializableExtra()` / `Intent.getParcelableExtra()` — even though this is **exactly the example** cited by the official Evaluation section (§1.3) itself as the primary untrusted source!
- `Bundle.getSerializable()` / `Bundle.getParcelable()`
- Custom `Parcelable.Creator` implementations vulnerable to a parcel/unparcel mismatch
- Deserialization via third-party libraries (Gson, Jackson) that use reflection without type validation

This is the **most extreme coverage gap** found so far in this research series — the rule is technically valid for detecting one pure `ObjectInputStream` pattern, but **cannot detect at all** the scenario used as the primary example in its own official evaluation (`Intent` extras). The tester **must** supplement Method A with far broader manual searching (§3.3) — relying on the official rule alone for this test will produce highly significant false negatives.

### 1.5 Real-World Context: A Long History of Deserialization CVEs at the Android Framework Level

Deserialization risk on Android is not merely theoretical — it has a long, ongoing CVE history, even at the level of the **Android framework itself**, not just third-party apps:

> *"CVE-2014-7911: A serious flaw where Android versions earlier than 5.0 didn't verify that received objects implement the Serializable interface, allowing arbitrary objects to be inserted into target apps or services."*

This is the classic case underlying object-injection concerns on Android — prior to Android 5.0, weak type verification allowed arbitrary objects to be inserted through the platform's serialization mechanism.

The **parcel/unparcel mismatch** vulnerability class continued to appear in recent years, in highly privileged framework components:

> *"CVE-2023-20963: A WorkSource Parcelable deserialization vulnerability allowing attackers to send arbitrary Intents as the system user... A parcel mismatch occurs when there is an inconsistency between how data is written to a Parcel object and how it is subsequently read from that object... leading to type confusion scenarios where the attacker's controlled data is interpreted as privileged objects."*

And **EvilParcel** (CVE-2017-13315) demonstrated a highly sophisticated exploitation technique leveraging the difference between the first deserialization and repeated deserialization:

> *"To launch an arbitrary activity with system privileges, you only need to create a Bundle with the Intent field hidden upon the first deserialization and appearing during the repeated deserialization."*

This context is important for testers to understand — even though the vulnerabilities above occurred at the **framework/OS level** (not the individual apps targeted by this MASTG test), they show that **this vulnerability class is real and continuously evolving**, and confirm why Google itself felt the need to publish a dedicated official guidance page about this risk.

### 1.6 Google's Official Mitigations: Two Different Approaches for Two Types of Risk

Official Android documentation provides two mitigation recommendations, each targeting a different mechanism:

**For `Parcelable` via `Intent`/`Bundle` (Android 13+):**

> *"Use type-safer methods... `parcel.readParcelable(ClassLoader, Class)` with an explicit type parameter that catches mismatches."*

**For `Serializable`/`ObjectInputStream` (the Look-Ahead/Allowlist pattern):**

> *"Implement the OWASP pattern to allowlist only expected classes during deserialization."*

Plus one additional, elegant defensive technique — blocking deserialization entirely on a class that must never be reconstructed from the outside:

```java
private final void readObject(ObjectInputStream in) throws IOException {
    throw new IOException("Cannot be deserialized");
}
```

---

## 2. Tools Used for Testing

### 2.1 Required (Core) Tools

| Tool | Function |
|---|---|
| **jadx** | DEX decompilation → Java (MASTG-TECH-0013) |
| **Semgrep** + official rule `mastg-android-object-deserialization.yml` | Detects the pure `ObjectInputStream.readObject()` pattern (limited scope, §1.4) |

### 2.2 Alternative & Supporting Tools (Required to Close the Official Rule's Gap)

| Tool | Function |
|---|---|
| **grep/ripgrep** | **Required** — searches for `getSerializableExtra`, `getParcelableExtra`, `Bundle.getSerializable/getParcelable`, and similar patterns completely uncovered by the official rule |
| **Androguard / jadx** | Manifest analysis to map `exported="true"` components as entry points for untrusted `Intent` data (connecting to §1.3) |
| **MobSF** | An automated report that sometimes includes detection of exported components and usage of `Serializable`/`Parcelable` |
| **Frida** | Dynamic verification — hook `readObject()`/`getSerializableExtra()` to observe the actual object type being deserialized at runtime, including from `Intent`s sent by external components |

### 2.3 Environment Prerequisites

- No device/root needed for static analysis.
- Prepare a list of `exported` components from the manifest as a map of entry points to cross-check against deserialization findings.

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0013** to reverse engineer the application.
2. Use **MASTG-TECH-0014** to search for relevant APIs.

### 3.2 Method A — Semgrep with the Official Rule (Limited Scope)

```bash
semgrep --config mastg-android-object-deserialization.yml ./decompiled/sources
```

**Mandatory note:** these results **only** capture the pure `ObjectInputStream` pattern. Proceed to Method B for coverage adequate to the actual threat scope described in the official overview (§1.4).

### 3.3 Method B — grep/ripgrep to Close the Coverage Gap (Required)

```bash
D=./decompiled/sources

# Intent/Bundle entry point - THE PRIMARY EXAMPLE from the official evaluation, NOT covered by rule A
rg -n 'getSerializableExtra\(|getParcelableExtra\(|getParcelableArrayListExtra\(' $D
rg -n '\.getBundle\(\).*\.(getSerializable|getParcelable)\(' $D

# Custom Parcelable.Creator implementations (potential parcel mismatch, §1.5)
rg -n 'Parcelable.Creator' $D

# Third-party libraries using reflection
rg -n 'new Gson\(\)\.fromJson|ObjectMapper\(\)\.readValue' $D
```

### 3.4 Method C — Mapping Exported Components as Untrusted Sources

```bash
# Extract exported components from the manifest
aapt dump xmltree app.apk AndroidManifest.xml | grep -B5 'exported.*true'
```

Correlate this result with Method B's findings — deserialization that occurs inside the `onReceive()`/`onCreate()` of a component registered as exported is the strongest FAIL candidate, per the official definition of "untrusted source."

### 3.5 Method D — Frida for Dynamic Verification of the Actual Object Type

```javascript
Java.perform(function () {
    var Intent = Java.use("android.content.Intent");
    Intent.getSerializableExtra.overload('java.lang.String').implementation = function (key) {
        var result = this.getSerializableExtra(key);
        console.log("[getSerializableExtra] key=" + key + " class=" + (result ? result.getClass().getName() : "null"));
        return result;
    };
});
```

### 3.6 Method Comparison: When to Use Which

| Method | Tool | When to use |
|---|---|---|
| **A** | Semgrep + official rule | Baseline, but its coverage is **very limited** (§1.4) |
| **B** | Manual grep/ripgrep | **Required** — closes the main coverage gap, covers the actual example from the official evaluation |
| **C** | Exported-component mapping | Identifies real untrusted sources per the official definition |
| **D** | Frida | Dynamic verification of the actual object type at runtime |

**Minimum recommended combination:** **B + C as the core of testing** (not A) — given the coverage gap in §1.4, the official rule is only a minor supplement, not an adequate baseline for this test.

---

### 3.7 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rule:**

> **Evaluation:** *"The test case fails if the app deserializes data received from untrusted sources (e.g., Intent extras from any other application) without proper validation or type filtering."*

---

#### ❌ FAIL / ISSUE — The check is declared FAILED when:

| No | Condition |
|---|---|
| F1 | The app deserializes data from an untrusted source (`Intent` extras from an exported component, IPC, a file accessible by other apps, a network response without schema validation) **without** type filtering or validation |

**Example evidence (reflecting the exact scenario cited by the official evaluation):**

```xml
<!-- AndroidManifest.xml -->
<receiver android:name=".SyncReceiver" android:exported="true" />
```

```java
// Found in com/example/app/SyncReceiver.java
public void onReceive(Context context, Intent intent) {
    SyncPayload payload = (SyncPayload) intent.getSerializableExtra("payload");
    payload.execute(); // no type/content validation before execution
}
```

Interpretation: an exported `BroadcastReceiver` receives a `Serializable` object from an `Intent` that any third-party app can send, with no type validation whatsoever before use. **FAIL** — exactly the scenario used as an example in the official evaluation.

---

#### ✅ PASS — The check is declared PASSED when:

| No | Condition |
|---|---|
| P1 | There is no deserialization from an untrusted source at all, **or** |
| P2 | Deserialization from an untrusted source is always accompanied by explicit type validation (e.g. an `instanceof` check, a class allowlist, or the Android 13+ type-safe API) |

**Example evidence:**

```java
public void onReceive(Context context, Intent intent) {
    Serializable raw = intent.getSerializableExtra("payload");
    if (raw instanceof SyncPayload) { // explicit type validation
        ((SyncPayload) raw).execute();
    } else {
        Log.w(TAG, "Unrecognized payload type, ignoring");
    }
}
```

**PASS**.

---

#### ⚠️ Important Notes on Evaluation

1. **Don't rely on the official rule as the main baseline** — per §1.4, that rule misses the primary threat example (`Intent`/`Bundle`) cited in its own official evaluation; Method B (manual grep) is the real core of testing for this test.

2. **Always correlate with the component's exported status** — deserialization occurring in a component that is **not exported** (accessible only from within the app itself) has a much lower risk profile than deserialization occurring in an exported component that accepts an `Intent` from any third-party app.

3. **An `instanceof` check alone is sometimes not enough** — for more complex cases (gadget chains, framework-level parcel mismatches as in §1.5), surface-level type validation can be bypassed by more sophisticated exploitation techniques; for high-risk apps, consider the Android 13+ type-safe API, which validates at the platform level, not just the application level.

4. **Severity is modulated as follows:**

   | Factor | Severity |
   |---|---|
   | Unvalidated deserialization in an exported component, with the resulting object directly executed/used for a sensitive decision | **High** |
   | Unvalidated deserialization but in a non-exported component (only risky if another vulnerability allows injection) | **Medium** |
   | Deserialization with explicit type validation | **Not a finding** |

5. **Document:** the code location, the data source (Intent/Bundle/file/network), the exported status of the related component, and whether type validation is present.

---

## 4. Recommendations

### 4.1 Use the Type-Safe API for Parcelable (Android 13+)

```java
// BEFORE — without type checking
UserParcelable user = intent.getParcelableExtra("user");

// AFTER — with an explicit type parameter
UserParcelable user = intent.getParcelableExtra("user", UserParcelable.class);
```

### 4.2 Implement an Allowlist for ObjectInputStream (OWASP Look-Ahead Pattern)

```java
ObjectInputStream ois = new ObjectInputStream(inputStream) {
    @Override
    protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
        if (!ALLOWED_CLASSES.contains(desc.getName())) {
            throw new InvalidClassException("Class not allowed: " + desc.getName());
        }
        return super.resolveClass(desc);
    }
};
```

### 4.3 Block Deserialization for Sensitive Classes That Should Never Be Reconstructed from the Outside

```java
private final void readObject(ObjectInputStream in) throws IOException {
    throw new IOException("This class must not be deserialized");
}
```

### 4.4 Remediation Checklist

- [ ] Every deserialization point from `Intent`/`Bundle` in an exported component uses explicit type validation or the Android 13+ type-safe API
- [ ] `ObjectInputStream` is protected by a class allowlist (OWASP Look-Ahead pattern)
- [ ] Sensitive classes that should never be reconstructed from the outside override `readObject()` to reject deserialization
- [ ] Components that don't need to be exposed to other apps are set to `exported="false"`
- [ ] Manual testing results (Method B) are documented as a mandatory supplement to the limited Semgrep results

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0337 (source, tests-beta)](https://github.com/OWASP/mastg/blob/master/tests-beta/android/MASVS-CODE/MASTG-TEST-0337.md)
- [MASTG-KNOW-0021: Object Serialization](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0021/)

### 5.2 Official Android Documentation

- [Android Developers: Unsafe Deserialization](https://developer.android.com/privacy-and-security/risks/unsafe-deserialization)
- [OWASP Deserialization Cheat Sheet — Harden Your Own java.io.ObjectInputStream](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html#harden-your-own-javaioobjectinputstream)

### 5.3 Research and Real-World Cases (CVE)

- [USENIX WOOT '15: One Class to Rule Them All — 0-Day Deserialization Vulnerabilities in Android](https://www.usenix.org/system/files/conference/woot15/woot15-paper-peles.pdf)
- [Habr: EvilParcel Vulnerabilities Analysis (CVE-2017-13315)](https://habr.com/en/companies/drweb/articles/457610/)
- [Google Project Zero: CVE-2023-20963 — Mismatching Parcel/Unparcel Logic for WorkSource](https://googleprojectzero.github.io/0days-in-the-wild/0day-RCAs/2023/CVE-2023-20963.html)
- [GitHub: TheLastBundleMismatch — Writeup CVE-2023-45777](https://github.com/michalbednarski/TheLastBundleMismatch)
- [GitHub: ReparcelBug2 — CVE-2021-0928 Writeup](https://github.com/michalbednarski/ReparcelBug2)
- [arXiv: Deserialization Gadget Chains in AOSP](https://arxiv.org/pdf/2502.08447)

### 5.4 Tool Documentation

- [Semgrep Documentation](https://semgrep.dev/docs/)
- [MobSF — Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)
- [Frida — Dynamic Instrumentation Toolkit](https://frida.re/docs/home/)

---

*This document was compiled based on official OWASP MASTG content (`tests-beta/android/MASVS-CODE/MASTG-TEST-0337.md`, `MASTG-KNOW-0021`), analysis of the `mastg-android-object-deserialization.yml` rule, official Android documentation on unsafe deserialization, and the long CVE history related to deserialization at the Android framework level (CVE-2014-7911, CVE-2017-13315/EvilParcel, CVE-2023-20963, CVE-2021-0928). The most important and most significant methodological nuance from this entire analysis: the official Semgrep rule for this test has the **most extreme coverage gap** found in this research series — the rule only targets the pure `ObjectInputStream.readObject()` pattern, while the primary threat example explicitly named in the test's own official Evaluation section (`Intent` extras) is **completely uncovered** by that rule. Relying on Semgrep results alone for this test will produce highly significant false negatives — manual searching for `getSerializableExtra`/`getParcelableExtra` and correlating it with component exported status is the real core of testing, not an optional supplement.*
