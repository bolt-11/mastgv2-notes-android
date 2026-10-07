# MASTG-TEST-0356 Runtime Verification of Unauthorized Database Access through Content Providers

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0356 |
| **Platform** | Android |
| **MASVS Category** | MASVS-PLATFORM |
| **Weakness** | MASWE-0018 |
| **Test Type** | Dynamic, Filesystem, **Manual** |
| **Related Techniques** | MASTG-TECH-0005 (Installing Apps), MASTG-TECH-0148 (Interacting with Android ContentProviders) |
| **Related Knowledge** | MASTG-KNOW-0020, MASTG-KNOW-0117 |
| **Related Best Practice** | MASTG-BEST-0049 |
| **Related Tests** | **MASTG-TEST-0355** — the static counterpart that examines manifest configuration; this test is a **direct runtime confirmation** (see §1.2 for its specific added value) |

---

## 1. Explanation

### 1.1 Testing Objective

Quote from the official MASTG overview:

> *"If an app exports a content provider without requiring permissions, any app on the device can directly query its underlying database using ContentResolver or using the adb shell content command. Even when a permission is declared, a misconfigured protection level (for example, android:protectionLevel="normal") allows any requesting app to obtain it automatically, effectively bypassing the restriction. This test verifies at runtime whether the app's exported content providers are accessible without the required permissions."*

### 1.2 Added Value Compared to Static Analysis: Direct Evidence, No Ambiguity in Manifest Interpretation

This is the dynamic counterpart to **MASTG-TEST-0355**, already discussed previously in this research series. The added value is clear and practical: static analysis (TEST-0355) requires the tester to **interpret** a complex combination of manifest attributes (`exported`, `readPermission`, `writePermission`, `permission`, and the `protectionLevel` of the referenced permission) — a process that, as already discussed in the TEST-0355 document §1.4, is prone to interpretation errors (e.g. the official rule cannot distinguish the case of read-protected-but-write-open).

This dynamic test **removes all of that ambiguity** — instead of inferring from the manifest configuration whether the provider is accessible, the tester **directly attempts to access it** from outside the application's own context (via `adb shell content`, which runs as the shell user, not as the target application) and observes the **actual result**. If a query successfully returns data, that is **definitive proof** that the provider is indeed accessible without adequate permission — regardless of how complex the combination of manifest attributes may be.

### 1.3 Coverage of Four Operations: Query, Insert, Update, Delete

MASTG-TECH-0148 provides the `adb shell content` command for all four CRUD operations, not just read:

```bash
adb shell content query --uri content://org.owasp.mastestapp.provider/students
adb shell content insert --uri content://org.owasp.mastestapp.provider/students --bind name:s:Eve
adb shell content update --uri content://org.owasp.mastestapp.provider/students --where "id=1" --bind name:s:"Alice Jr"
adb shell content delete --uri content://org.owasp.mastestapp.provider/students --where "id=3"
```

This directly bridges the methodological gap already identified in the TEST-0355 document §1.4 — there I recommended separate dynamic verification for read and write because the static rule cannot distinguish between the two. This test **officially provides a path for that**: try `query` to test read protection, then try `insert`/`update`/`delete` separately to test write protection — two results that can be very different on the same provider (exactly the real-world OEM mistake scenario already discussed in TEST-0355 §1.4: `readPermission` present, `writePermission` absent).

### 1.4 Important Technical Note from MASTG-TECH-0148: Execution Context as the Shell User

> *"The command executes in the context of the shell user, so access depends on whether the provider is exported and what permissions are enforced."*

This is relevant for interpreting results — `adb shell content` is **not** an ordinary third-party application; it runs with the shell UID (`com.android.shell`, which has certain privileges on some Android versions). Nevertheless, the testing principle remains valid: if the shell (which does not hold the target application's custom permission) successfully accesses the provider, this is a strong indication that **any third-party application** would also succeed in doing the same, since both lack the specific permission defined by the target application (unless that permission is a built-in system permission specifically granted to the shell).

### 1.5 Further Validation: Data Content, Not Just Query Success

> **Further Validation Required:** *"Inspect the content of each row returned by the query to determine whether the data is sensitive: Determine whether the records contain sensitive information (e.g., personal data, credentials, tokens, or health data). Determine whether the accessible data represents a security risk given the app's data classification."*

This is consistent with the contextual evaluation principle that recurs throughout this research series — the technical success of accessing the provider (a successful query that returns rows of data) **does not necessarily** mean a serious security finding if the exposed data is in fact not sensitive (for example, a public UI configuration table). The final value of a finding always depends on the **actual content of the data**, not merely the success/failure status of the access attempt.

---

## 2. Tools Used for Testing

### 2.1 Required Tools (Core)

| Tool | Function |
|---|---|
| **ADB** | App installation (MASTG-TECH-0005), execution of `content query/insert/update/delete` (MASTG-TECH-0148) |

### 2.2 Alternative & Supporting Tools

| Tool | Function |
|---|---|
| **Drozer** | Alternative with ready-made modules (`app.provider.query`, `scanner.provider.injection`), useful for automated triage across many providers at once |
| **Custom exploit app** | For simulating the most realistic scenario — an actually installed third-party application that calls `ContentResolver.query()` without any permission, complementing the results from `adb shell content`, which runs as the shell user (§1.4) |

### 2.3 Environment Prerequisites

- A device/emulator with `adb` connected and the target application installed.
- Root is not required for basic testing — `adb shell content` is sufficient to test most scenarios.

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0005** to install the application.
2. Exercise the application extensively to trigger as many flows as possible and populate sensitive data.
3. Use **MASTG-TECH-0148** to query the application's exported providers.

### 3.2 Method A — Direct Query via ADB Shell Content

```bash
# Identify the provider authority from the manifest (result of TEST-0355)
adb shell content query --uri content://com.example.app.provider/users
```

### 3.3 Method B — Test Write Operations Separately (Closing the TEST-0355 §1.4 Gap)

```bash
adb shell content insert --uri content://com.example.app.provider/users --bind name:s:"attacker_test"
adb shell content update --uri content://com.example.app.provider/users --where "id=1" --bind is_premium:i:1
adb shell content delete --uri content://com.example.app.provider/users --where "id=99"
```

Run **all four** operations separately and record each result — a provider that rejects `query` but accepts `insert` (or vice versa) is an important finding that confirms the need for granular, per-operation testing.

### 3.4 Method C — Drozer for Automated Triage of Many Providers

```bash
dz> run app.provider.finduri -a com.example.app
dz> run app.provider.query content://com.example.app.provider/users --vertical
dz> run app.provider.insert content://com.example.app.provider/users --string name "test"
```

### 3.5 Method D — Verification from a Genuine Third-Party Application

```java
// In a separate test application (not the shell), without any permission
Cursor cursor = getContentResolver().query(
    Uri.parse("content://com.example.app.provider/users"),
    null, null, null, null
);
```

Reinforces the Method A result by simulating a scenario more realistic than `adb shell` (§1.4).

### 3.6 Method Comparison: When to Use Which

| Method | Tool | When to use |
|---|---|---|
| **A** | adb shell content query | Mandatory baseline — test read |
| **B** | adb shell content insert/update/delete | **Mandatory** — test write separately, closing the TEST-0355 §1.4 gap |
| **C** | Drozer | Automated triage across many providers at once |
| **D** | Genuine third-party application | Most realistic verification, avoids ambiguity about the shell-user context |

**Minimum recommended combination:** **A + B (mandatory, all four operations)**, with **D** as corroborating evidence for the final report when maximum confidence is required.

---

### 3.7 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rule:**

> **Evaluation:** *"The test case fails if sensitive data can be accessed through content providers."*

---

#### ❌ FAIL / ISSUE — The check is declared FAILED if:

| No | Condition |
|---|---|
| F1 | A query/insert/update/delete successfully executes without any permission **and** the data/operation involved is sensitive |

**Example evidence:**

```
$ adb shell content query --uri content://com.example.app.provider/users
Row: 0 _id=1, username=budi_santoso, email=budi@example.com, auth_token=eyJhbGciOiJIUzI1NiJ9...
```

Interpretation: an authentication token and a user's email were successfully extracted without any permission from the shell. **FAIL**.

---

#### ✅ PASS — The check is declared PASSED if:

| No | Condition |
|---|---|
| P1 | All four operations (query/insert/update/delete) are rejected with a `SecurityException`/permission error, **or** |
| P2 | The operation succeeds but the exposed data is verified to be non-sensitive |

**Example evidence:**

```
$ adb shell content query --uri content://com.example.app.provider/users
java.lang.SecurityException: Permission Denial: opening provider ... requires com.example.app.permission.READ_USER_DATA
```

**PASS** (for the read operation; repeat the same verification for insert/update/delete).

---

#### ⚠️ Important Notes on Assessment

1. **Test all four operations separately, do not stop at query alone** — per §1.3, a PASS on `query` does not guarantee a PASS on `insert`/`update`/`delete`; the real-world OEM mistake pattern discussed in TEST-0355 occurs precisely in this asymmetry.

2. **A result from the shell user is a strong indicator, not absolute final proof** — for reports requiring maximum confidence, consider Method D (a genuine third-party application) to avoid ambiguity about the shell user's special privileges (§1.4).

3. **Always assess the content of the data, not merely the command's success/failure status** — per §1.5, a FAIL is only valid if the exposed data is genuinely sensitive according to the application's data classification.

4. **Correlate with the results of MASTG-TEST-0355** — this dynamic finding is definitive confirmation of the candidate found by static analysis; if the static analysis shows a configuration that looks safe but the dynamic test still succeeds in accessing it, this indicates a misinterpretation of the configuration (e.g. a `protectionLevel` weaker than it appears) that deserves further investigation.

5. **Severity is modulated:**

   | Factor | Severity |
   |---|---|
   | Highly sensitive data (credentials, tokens, personal data) accessed/modified without authorization | **High** |
   | Operation succeeds but the data is not sensitive | **Not a finding** |
   | Only one of the four operations fails to be blocked (read/write asymmetry) | **High** — still considered serious because it demonstrates a genuine access-control design failure |

6. **Document:** the provider URI tested, the result of all four operations (success/rejection along with error messages), examples of successfully extracted data (redacted if necessary), and the verification method used (shell vs. genuine application).

---

## 4. Recommendations

Recommendations are identical to its static counterpart (MASTG-TEST-0355) — see that document for full details (non-exported if not needed, separate read AND write permissions with `protectionLevel="signature"`). Additional points specific to the dynamic verification result:

### Remediation Checklist

- [ ] All four operations (query/insert/update/delete) are verified to be rejected without the appropriate permission
- [ ] Results are verified both from `adb shell content` and from a genuine third-party application
- [ ] After fixing the manifest (per the TEST-0355 recommendations), the dynamic test is repeated to confirm the fix is truly effective, not merely looking correct in the manifest

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0356 (source, tests-beta)](https://github.com/OWASP/mastg/blob/master/tests-beta/android/MASVS-PLATFORM/MASTG-TEST-0356.md)
- [MASTG-TEST-0355: References to Unauthorized Database Access through Content Providers (the static counterpart document in this research series)](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0355/)
- [MASTG-TECH-0148: Interacting with Android ContentProviders](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0148/)
- [MASTG-BEST-0049: Restrict and Validate Access to Exported Content Providers](https://github.com/OWASP/mastg/blob/master/best-practices/MASTG-BEST-0049.md)

### 5.2 Tool Documentation

- [Android Developers: ContentResolver](https://developer.android.com/reference/android/content/ContentResolver)
- [Drozer — Android Security Assessment Framework](https://github.com/WithSecureLabs/drozer)

---

*This document was compiled based on official OWASP MASTG content (`tests-beta/android/MASVS-PLATFORM/MASTG-TEST-0356.md`, `MASTG-TECH-0148`), supplemented with in-depth cross-referencing to the MASTG-TEST-0355 document (its static counterpart) within this research series. The most important methodological nuance: this test provides a concrete path (`adb shell content insert/update/delete`) to close the methodological gap already identified in TEST-0355 — namely the need to test read and write protection separately, because the official static-analysis rule cannot distinguish a provider that protects only one of the two operation types. A successful query/insert/update/delete from `adb shell content` (the shell-user context) is a strong indicator but not absolute final proof — verification from a genuine third-party application provides the highest level of confidence for reports requiring maximum precision.*
