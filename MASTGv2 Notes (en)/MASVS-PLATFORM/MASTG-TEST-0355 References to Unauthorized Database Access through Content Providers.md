# MASTG-TEST-0355 References to Unauthorized Database Access through Content Providers

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0355 |
| **Platform** | Android |
| **MASVS Category** | MASVS-PLATFORM |
| **Weakness** | MASWE-0018 |
| **Test Type** | Static, Config, **Manual** |
| **Related Technique** | MASTG-TECH-0013, MASTG-TECH-0117 (Obtain Manifest), MASTG-TECH-0150 (Identify Exported Components) |
| **Related Knowledge** | MASTG-KNOW-0020 (IPC Mechanisms), MASTG-KNOW-0117 (Android ContentProvider) |
| **Related Best Practice** | MASTG-BEST-0049 (Restrict and Validate Access to Exported Content Providers) |
| **Related Tests** | **MASTG-TEST-0339** (SQL Injection in Content Providers) — a related document in this research series; this test targets **unauthorized access**, TEST-0339 targets **injection after access has been obtained** — both frequently appear together on the same provider |
| **Official Rule** | A pair of rules — a **significant logic gap** was found, see §1.4 |

---

## 1. Explanation

### 1.1 Testing Objective

Excerpt from the official MASTG overview:

> *"This test checks whether the app exposes content providers that can be accessed by other apps without appropriate permission enforcement... If a content provider is exported (android:exported="true") without these permissions, any app on the device can query the underlying database to retrieve sensitive data such as user PII, account details, or internal app configurations."*

Unlike MASTG-TEST-0339, which targets **how** a query is constructed (vulnerable to injection or not), this test targets a more fundamental question: **who is at all allowed** to access that provider. A provider might use a perfectly parameterized query (passing TEST-0339) and yet still be a serious data leak if **anyone's** app on the device can call it without any permission whatsoever.

### 1.2 An Important Nuance: `protectionLevel="normal"` Is Not Real Protection

The second point from the overview that beginner testers often miss:

> *"The same applies when no protection level is configured and becomes automatically android:protectionLevel="normal", which is granting access automatically to any requesting app."*

This means that **merely declaring `android:readPermission`** does not automatically mean the provider is safe — if the **custom permission** being referenced does not explicitly set `protectionLevel="signature"` (or another, stronger level), that permission defaults to `normal`, meaning **the system automatically grants it** to any application that requests it via `<uses-permission>` — without user consent, without any certificate check. In effect, this is **nearly equivalent to no protection at all**, adding only one trivial administrative step (declaring `<uses-permission>`) for any malicious application.

### 1.3 The `protectionLevel` Hierarchy Relevant to This Evaluation

| `protectionLevel` | Who Gets the Permission | Strength |
|---|---|---|
| `normal` (default if not declared) | **Anyone** who requests it, granted automatically | Very weak — equivalent to no protection |
| `dangerous` | Requires explicit user consent at install/runtime | Weak — depends on the user not approving carelessly |
| `signature` | **Only** applications signed with the same developer certificate | Strong — a solid boundary that does not depend on a user decision |

MASTG-BEST-0049 states: *"A custom permission without an explicit protectionLevel defaults to normal. This means any app can request and typically receive it automatically, so it is a weak security boundary."*

### 1.4 A Critical Analytical Finding: The Official Rule Does Not Distinguish Read vs. Write — A Gap That Matches a Real OEM Mistake Exactly

Look at the logic of the second rule (`mastg-android-provider-exported-without-permissions`):

```yaml
patterns:
  - pattern: <provider ... android:exported="true" ... />
  - pattern-not: <provider ... android:permission="$PERM" ... />
  - pattern-not: <provider ... android:readPermission="$PERM" ... />
  - pattern-not: <provider ... android:writePermission="$PERM" ... />
```

This rule only triggers an alert if **all three are absent at once**. The consequence: **as soon as one** of `readPermission`/`writePermission`/`permission` is present — for instance, only `readPermission` — this rule **immediately stops flagging** that provider as a finding, even though **write operations (insert/update/delete) remain entirely open** with no protection whatsoever.

This is **not a theoretical concern** — industry security research explicitly documents this mistake pattern as a common real-world occurrence:

> *"A common OEM mistake is to export a ContentProvider with a readPermission but omit writePermission. When writePermission is null, any app can call insert/update/delete if those methods are implemented."*

This means testers **must not** stop simply because Semgrep did not flag a provider — the official rule is, by design, **unable to distinguish** the "both protected" case from the case where "only one of the two operations is protected, the other left wide open". Manual validation must check the **complete combination** of all three attributes, not merely "whether one of them is present".

### 1.5 Real-World Evidence: From Path Traversal to a Permission Bypass in a Chipset Vendor

Several real-world cases reinforce the urgency of this test at various levels of complexity:

> *"ESC Pocket Guidelines Application: The vulnerability... is a path traversal vulnerability that allows other applications on the device to request sensitive information. The openFile function was rewritten and no '../' filter was added, which allows read/write privileges for the files inside internal storage."*

This case shows that the risk of an exported provider without proper controls **is not only about database data** — it can extend to **full system file access** via path traversal in a custom `openFile()` implementation.

At a deeper level (chipset vendor firmware), **CVE-2023-20923** shows that even when permissions **have** been declared, a flawed implementation can create a bypass gap:

> *"In exported content providers of ShannonRcs, there is a possible way to get access to protected content providers due to a permissions bypass. This could lead to local information disclosure with no additional execution privileges needed."*

This reinforces the official "Further Validation Required" principle (§1.6) — a permission declared in the manifest **must** have its actual effectiveness verified, not merely its presence recorded.

### 1.6 Official Further Validation: Two Key Questions

> *"Determine whether the declared permission uses android:protectionLevel="normal" or android:protectionLevel="dangerous", which does not guarantee that only trusted apps can access the provider. Determine whether the data exposed through the provider is sensitive."*

This aligns with the contextual evaluation principle consistent across many other tests in this research series — the syntactic presence of a security attribute does not automatically mean **substantive** protection; a weak `protectionLevel` and non-sensitive data both influence the final severity conclusion.

---

## 2. Tools Used for Testing

### 2.1 Required Tools (Core)

| Tool | Function |
|---|---|
| **aapt / Androguard** | Extracting `AndroidManifest.xml` (MASTG-TECH-0117) |
| **Semgrep** + two official rules | Basic detection of exported providers without permission (limited coverage for the read/write nuance, §1.4) |

### 2.2 Alternative & Supporting Tools

| Tool | Function |
|---|---|
| **grep/ripgrep** | Manual verification of the complete combination of `readPermission`/`writePermission`/`permission` per provider, closing the gap in §1.4 |
| **Drozer** | Direct dynamic verification — attempting query/insert/update/delete against an exported provider from another application (without permission) |
| **adb shell content** | Quick verification without needing to write an exploit application |

### 2.3 Environment Prerequisites

- Static analysis does not need a device/root.
- Dynamic verification (Drozer/`adb shell content`) needs a device/emulator with the target app installed.

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0013** to reverse engineer the application.
2. Use **MASTG-TECH-0117** to obtain the `AndroidManifest.xml`.
3. Use **MASTG-TECH-0150** to identify exported providers and check their permission configuration.

### 3.2 Method A — Semgrep with the Official Rules

```bash
semgrep --config mastg-android-provider-exported-without-permissions.yml \
        --config mastg-android-provider-permission-protected.yml \
        ./AndroidManifest.xml
```

### 3.3 Method B — grep/ripgrep for Complete Read/Write Combination Verification (Mandatory, §1.4)

```bash
# Extract every <provider> element along with its complete attributes
aapt dump xmltree app.apk AndroidManifest.xml | grep -A15 '<provider'
```

For each provider with `exported="true"` found, explicitly verify manually:
- Is `readPermission` present? Is `writePermission` present?
- If **only one** is present, the unprotected operation (read or write) remains fully open.

### 3.4 Method C — Checking `protectionLevel` for a Custom Permission

```bash
aapt dump xmltree app.apk AndroidManifest.xml | grep -B2 -A5 '<permission'
```

Check whether the custom permission referenced by the provider uses `protectionLevel="signature"` (strong) or the default/`normal`/`dangerous` (weak, §1.3).

### 3.5 Method D — Dynamic Verification with Drozer

```bash
dz> run app.provider.info -a com.example.app
dz> run app.provider.query content://com.example.app.provider/users
dz> run app.provider.insert content://com.example.app.provider/users --string name "test"
```

Attempting read **and** write operations separately to empirically confirm whether each is actually protected, closing a gap that static analysis might miss (§1.4).

### 3.6 Method Comparison: When to Use Which

| Method | Tool | When to use |
|---|---|---|
| **A** | Semgrep + official rules | Baseline, only catches the case where there is no protection whatsoever |
| **B** | Manual grep/ripgrep | **Mandatory** — verifying the complete read/write combination per provider |
| **C** | protectionLevel check | Assessing the true strength of the declared permission |
| **D** | Drozer | The most conclusive empirical proof, covering read and write separately |

**Minimum recommended combination:** **B (mandatory, closes the main gap) + C → D (dynamic verification)**, with Method A serving only as an initial triage.

---

### 3.7 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rule:**

> **Evaluation:** *"The test case fails if one or more content providers are exported (android:exported="true") without declaring android:readPermission, android:writePermission, or android:permission."*

---

#### ❌ FAIL / ISSUE — The check is declared FAILED if:

| No | Condition |
|---|---|
| F1 | A provider with `exported="true"` has **none** of `readPermission`/`writePermission`/`permission` |
| F2 | *(Additional finding via manual validation, §1.4)* The provider has `readPermission` **but no** `writePermission` (or vice versa) — the uncovered operation remains open |
| F3 | The declared permission uses `protectionLevel="normal"` (default) — effectively providing no real protection |

**Example evidence (reflecting the real OEM mistake pattern in §1.4):**

```xml
<provider
    android:name=".UserDataProvider"
    android:authorities="com.example.app.userdata"
    android:exported="true"
    android:readPermission="com.example.app.permission.READ_USER_DATA" />
<!-- writePermission is NOT declared -->
```

Interpretation: the read operation is protected, but `insert()`/`update()`/`delete()` are entirely open to any application on the device. **FAIL** — even though it is not caught by the official Semgrep rule (§1.4).

---

#### ✅ PASS — The check is declared PASSED if:

| No | Condition |
|---|---|
| P1 | The provider is explicitly set to `exported="false"` (per the MASTG-BEST-0049 recommendation), **or** |
| P2 | The provider is exported **with** both `readPermission` **and** `writePermission` (or a `permission` covering both) declared with `protectionLevel="signature"` |

---

#### ⚠️ Important Notes on Assessment

1. **Do not stop at raw Semgrep results** — per §1.4, the official rule cannot distinguish a read-only-protected case from a fully-protected case; manual verification of the complete combination is mandatory.

2. **Always trace the `protectionLevel` of the referenced permission** — a custom permission that exists but is `normal` is effectively equivalent to no protection (§1.2-1.3).

3. **Also consider a custom `openFile()` implementation** — per the real ESC Pocket Guidelines case (§1.5), file-based providers are vulnerable to path traversal regardless of permission configuration; audit the implementation code, not just the manifest.

4. **Severity is modulated by:**

   | Factor | Severity |
   |---|---|
   | Exported without any permission, sensitive data (PII, credentials) | **High** |
   | One of read/write is protected, the other is open (§1.4) | **High** (unprotected write = data integrity risk + potential SQL injection, see TEST-0339) |
   | Permission exists but `protectionLevel="normal"` | **Medium-High** |
   | `protectionLevel="signature"` correctly applied, or non-exported | **Not a finding** |

5. **Document:** provider name, exported status, complete permission attributes (read/write/combination), the `protectionLevel` of the referenced permission, and the type of data exposed.

---

## 4. Recommendations

### 4.1 Make Non-Exported If Other Applications Don't Need Access (Per MASTG-BEST-0049)

```xml
<provider
    android:name=".UserDataProvider"
    android:authorities="com.example.app.userdata"
    android:exported="false" />
```

### 4.2 Protect Read AND Write Separately with a Strong Protection Level

```xml
<provider
    android:name=".UserDataProvider"
    android:authorities="com.example.app.userdata"
    android:exported="true"
    android:readPermission="com.example.app.permission.READ_USER_DATA"
    android:writePermission="com.example.app.permission.WRITE_USER_DATA" />

<permission
    android:name="com.example.app.permission.READ_USER_DATA"
    android:protectionLevel="signature" />
<permission
    android:name="com.example.app.permission.WRITE_USER_DATA"
    android:protectionLevel="signature" />
```

### 4.3 Use a Narrow-Scoped FileProvider for File Sharing

```xml
<provider
    android:name="androidx.core.content.FileProvider"
    android:authorities="com.example.app.fileprovider"
    android:exported="false"
    android:grantUriPermissions="true">
    <meta-data android:name="android.support.FILE_PROVIDER_PATHS" android:resource="@xml/file_paths" />
</provider>
```

### 4.4 Remediation Checklist

- [ ] Providers that do not need to be accessed by other applications are set to `exported="false"`
- [ ] Necessary exported providers protect **both read AND write** separately and completely
- [ ] The referenced custom permission uses `protectionLevel="signature"`, not the default `normal`
- [ ] A custom `openFile()` implementation (if any) is validated against path traversal
- [ ] Dynamically verified with Drozer for read and write operations separately

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0355 (source, tests-beta)](https://github.com/OWASP/mastg/blob/master/tests-beta/android/MASVS-PLATFORM/MASTG-TEST-0355.md)
- [MASTG-TEST-0339: SQL Injection in Content Providers (a related document in this research series)](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0339/)
- [MASTG-KNOW-0020: Inter-Process Communication (IPC) Mechanisms](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0020/)
- [MASTG-KNOW-0117: Android ContentProvider](https://mas.owasp.org/MASTG/knowledge/android/MASVS-CODE/MASTG-KNOW-0117/)
- [MASTG-BEST-0049: Restrict and Validate Access to Exported Content Providers](https://github.com/OWASP/mastg/blob/master/best-practices/MASTG-BEST-0049.md)

### 5.2 Research and Real-World Cases

- [Oversecured: Content Providers and the Potential Weak Spots They Can Have](https://oversecured.com/blog/content-providers-and-the-potential-weak-spots-they-can-have)
- [Trend Micro: ContentProvider Path Traversal Flaw on ESC App Reveals Info](https://www.trendmicro.com/en_us/research/20/j/contentprovider-path-traveral-flaw-on-esc-app-reveals-info.html)
- [NVD: CVE-2023-20923 — ShannonRcs Content Provider Permission Bypass](https://nvd.nist.gov/vuln/detail/CVE-2023-20923)
- [CWE-926: Improper Export of Android Application Components](https://cwe.mitre.org/data/definitions/926.html)
- [Guardsquare: Security Risks of Exposed Directories in Android FileProvider](https://www.guardsquare.com/blog/android-fileprovider-directories-security-risks)

### 5.3 Tool Documentation

- [Semgrep Documentation](https://semgrep.dev/docs/)
- [Drozer — Android Security Assessment Framework](https://github.com/WithSecureLabs/drozer)

---

*This document was compiled based on official OWASP MASTG content (`tests-beta/android/MASVS-PLATFORM/MASTG-TEST-0355.md`, `MASTG-KNOW-0020/0117`, `MASTG-BEST-0049`), an analysis of the two official rules, and industry research (Oversecured) documenting a real OEM mistake pattern, along with concrete CVE cases (the ESC Pocket Guidelines path traversal, CVE-2023-20923 ShannonRcs permission bypass). The most important methodological nuance: the official rule only flags providers that have **none at all** of the three permission attributes — it cannot detect a case where only `readPermission` is declared while `writePermission` is left empty, a mistake pattern that industry research shows is actually **common** in real-world Android OEM ecosystems. Manual validation of the complete read/write combination, along with checking the `protectionLevel` of every referenced permission, is a mandatory step that cannot be fully replaced by Semgrep results alone.*
