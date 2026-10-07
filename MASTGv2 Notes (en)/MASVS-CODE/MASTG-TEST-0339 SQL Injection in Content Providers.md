# MASTG-TEST-0339 SQL Injection in Content Providers

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0339 |
| **Platform** | Android |
| **MASVS Category** | MASVS-CODE |
| **Weakness** | MASWE-0050 |
| **Test Type** | Static, Code |
| **Related Techniques** | MASTG-TECH-0013 (Reverse Engineering), MASTG-TECH-0014 (Static Analysis for Relevant APIs) |
| **Related Knowledge** | MASTG-KNOW-0117 (Android ContentProvider) |
| **Related Best Practice** | MASTG-BEST-0039 (Prevent SQL Injection in ContentProviders) |
| **Related Demo** | MASTG-DEMO-0102 (referenced by MASTG-KNOW-0117 as a concrete example) |
| **Official Rule** | `mastg-android-sql-injection-contentprovider.yml` — one pattern, narrow coverage, see §1.4 |

---

## 1. Explanation

### 1.1 Testing Objective

Quote from the official MASTG overview:

> *"Android applications can share structured data via ContentProvider components. However, if these providers create SQL queries using untrusted input from URIs without adequate validation or parameterization, they risk becoming susceptible to SQL injection attacks."*

`ContentProvider` is Android's mechanism for **sharing structured data between applications** through a URI-based interface (`content://<authority>/<path>`). Because its backend is typically SQLite, the classic SQL injection risk commonly known from web applications turns out to be **equally relevant** in the Android context — but with a different entry vector: not an HTTP form, but the **URI path segment** and **query parameters** passed via `ContentResolver`.

### 1.2 Two Main Entry Points: Path Segment and Selection/SelectionArgs

MASTG-KNOW-0117 explains the relevant URI parsing mechanism:

> *"`Uri.getPathSegments()` returns a decoded list of path segments after the authority... These values are often user-controlled when the provider is exported."*

And the crucial distinction between two ways of building a `SELECT` query:

> *"`appendWhere(CharSequence)` appends a condition to the WHERE clause. The provided string is inserted verbatim into the SQL query and is not parameterized."*
>
> *"The query() method accepts a selection string and a selectionArgs array. Each `?` placeholder in selection is replaced with the corresponding value from selectionArgs, and those values are treated strictly as data... This prevents SQL injection because values are bound, not interpreted as SQL."*

A concise comparison table of both approaches:

| Approach | Security |
|---|---|
| `qb.appendWhere(userInput)` | **Unsafe** — the string is inserted verbatim into SQL, parsed as part of the statement |
| `qb.query(db, projection, "id = ?", new String[]{userInput}, ...)` | **Safe** — the value is bound as data, never interpreted as SQL |
| `selection = "id = '" + userInput + "'"` (manual string concatenation) | **Unsafe** — functionally identical to `appendWhere` without parameterization |

### 1.3 FAIL Criteria: Two Concrete Patterns

> **Evaluation:** *"The test case fails if: Untrusted user input (e.g., from getPathSegments()) is directly concatenated into SQL statements. The app uses appendWhere() or builds queries unsafely without sanitization or parameterization."*

### 1.4 Analysis of the Official Rule: Narrow Coverage That Misses the `selection` String Concatenation Case

The rule `mastg-android-sql-injection-contentprovider.yml` uses two pattern variants, both **focused exclusively on `appendWhere()`**:

```yaml
patterns:
  - pattern-either:
      - pattern: |
          $QB.appendWhere("..." + $VAR);
      - pattern: |
          $QB.appendWhere($VAR);
  - pattern-inside: |
      $VAR = $URI.getPathSegments().get(...);
      ...
```

An important analytical note here: the second variant (`$QB.appendWhere($VAR)`, without string concatenation) is a design that is **appropriate and clever** — this rule correctly recognizes that **passing a variable directly without any concatenation** remains dangerous, because `$VAR` originating from `getPathSegments()` may already contain a **complete malicious SQL string** (e.g., `"1 OR 1=1"`), which doesn't need to be combined with another string literal to become a valid exploit.

However, there is a significant coverage gap: this rule **does not cover at all** the second pattern from the official FAIL criteria (§1.3) — namely **manual concatenation into the `selection` parameter** before it is passed to `query()`, rather than through `appendWhere()`:

```java
// This pattern is NOT covered by the official rule, even though it is functionally just as dangerous
String id = uri.getPathSegments().get(1);
String selection = "id = '" + id + "'"; // manual concatenation into selection
Cursor c = db.query(table, projection, selection, null, null, null, null);
```

This is because the rule exclusively searches for calls to the `appendWhere` method — the pattern above uses `query()` directly with a `selection` string that is already tainted before the call, never touching `SQLiteQueryBuilder.appendWhere` at all. The tester must supplement automated search with manual patterns to close this gap.

### 1.5 Real-World Evidence: From the Android Framework Itself to Popular Production Applications

This class of vulnerability has an extensive and ongoing history, both at the Android framework level and in third-party applications:

**At the framework level (built-in AOSP components):**

> *"CVE-2020-0060: A local SQL injection vulnerability was found in a Content Provider provided by the 'com.android.providers.telephony' package (version 10), allowing injection and execution of arbitrary SQL statements within the context of the target package."*
>
> *"CVE-2018-9493: SQL injection in Android's DownloadProvider requires no permission if the provider is exported without permission protection."*

**At the level of real production applications (ownCloud Android app, not AOSP):**

> *"CVE-2023-24804, CVE-2023-23948: The ownCloud Android app's FileContentProvider has SQL injection vulnerabilities that allow malicious applications or users on the same device to obtain internal information of the app."*

The technical details of this ownCloud vulnerability are highly relevant as a concrete illustration:

> *"The FileContentProvider exported user-controlled parameters directly into SQL queries without parameterization. In the delete method, the where parameter was concatenated directly: 'AND ($where)' allowed injection when building deletion statements. Attackers leveraged the exported content provider through two techniques: direct injection to exfiltrate data from any table, and blind SQL injection in owncloud_database using conditional LIKE queries that measured response differences to extract information from restricted tables."*

The fact that **two separate vulnerabilities** were found in the same popular application (ownCloud) — one in the file list database, and another via **blind SQL injection**, which is much more sophisticated (extracting data through timing/response differences without a direct error message) — shows that this vulnerability class is not always as simple as "obvious direct injection," and the audit must also consider blind injection scenarios.

### 1.6 The Critical Role of `exported` Status as a Prerequisite for Exploitation

MASTG-KNOW-0117 emphasizes that this risk **entirely depends** on the access configuration:

> *"A ContentProvider's availability to other apps is governed by attributes in the Android manifest... Since Android 4.2, the default is false if no `<intent-filter>` is defined... Exported providers that process user-controlled input without validation are a common attack surface."*

This means the **logical order of investigation** is: first identify which providers are `exported="true"` (or have an `<intent-filter>` without explicit declaration on older API levels, which automatically makes them exported), **then** focus the SQL injection pattern analysis on those providers — providers that are not exported have a much smaller attack surface (accessible only from within the app itself or apps sharing the same UID).

---

## 2. Tools Used for Testing

### 2.1 Required Tools (Core)

| Tool | Function |
|---|---|
| **jadx** | Decompile DEX → Java (MASTG-TECH-0013) |
| **Semgrep** + official rule `mastg-android-sql-injection-contentprovider.yml` | Detects the `appendWhere()` pattern with input from `getPathSegments()` (MASTG-TECH-0014) |

### 2.2 Alternative & Supporting Tools

| Tool | Function |
|---|---|
| **grep/ripgrep** | Closes the official rule's coverage gap — searches for manual concatenation into the `selection` parameter (§1.4) |
| **aapt / Androguard** | Manifest extraction to map providers with `exported="true"` (investigation prerequisite, §1.6) |
| **adb shell content** | Direct dynamic verification — sends malicious queries to the provider via command line without needing to write an exploit app |
| **Drozer** | Android pentest framework specifically for exploring and exploiting IPC components including ContentProvider, providing ready-made modules for SQL injection testing |

### 2.3 Environment Prerequisites

- Static analysis does not require a device/root.
- For dynamic verification (Method D), a device/emulator with the target application installed and `adb` connected is required.

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0013** to reverse engineer the application.
2. Use **MASTG-TECH-0014** to search for relevant APIs.

### 3.2 Method A — Semgrep with the Official Rule

```bash
semgrep --config mastg-android-sql-injection-contentprovider.yml ./decompiled/sources
```

### 3.3 Method B — grep/ripgrep to Close the Selection Concatenation Gap

```bash
D=./decompiled/sources

# Search for all appendWhere calls (including variants the official rule might miss)
rg -n 'appendWhere\(' $D

# Search for manual concatenation into variables named 'selection'/'where' (NOT covered by the official rule)
rg -n 'selection\s*=\s*".*"\s*\+|where\s*=\s*".*"\s*\+' $D

# Trace variables originating from getPathSegments/getLastPathSegment
rg -n 'getPathSegments\(\)|getLastPathSegment\(\)' $D
```

### 3.4 Method C — Mapping Exported Providers (Mandatory Prerequisite, §1.6)

```bash
aapt dump xmltree app.apk AndroidManifest.xml | grep -B10 '<provider' | grep -E 'exported|authorities'
```

Focus the entire Method A/B analysis only on providers whose result is `exported="true"` (or without an explicit attribute but with an `<intent-filter>`).

### 3.5 Method D — Dynamic Verification via ADB Shell Content

```bash
# Test direct injection triggering against the identified exported provider
adb shell content query --uri "content://com.example.app.provider/students/1' OR '1'='1"

# Test blind SQL injection (replicating the ownCloud technique in §1.5)
adb shell content query --uri "content://com.example.app.provider/students/1' AND (SELECT 1 FROM restricted_table LIMIT 1)='1"
```

### 3.6 Method E — Drozer for Structured Exploration and Exploitation

```bash
dz> run app.provider.info -a com.example.app
dz> run app.provider.query content://com.example.app.provider/students --selection "1=1"
dz> run scanner.provider.injection -a com.example.app
```

Drozer's `scanner.provider.injection` module automatically tries various injection payloads against all detected exported providers — speeding up initial triage before deep manual verification.

### 3.7 Method Comparison: When to Use Which

| Method | Tool | When to use |
|---|---|---|
| **A** | Semgrep + official rule | Baseline, limited coverage of `appendWhere` only |
| **B** | Manual grep/ripgrep | Mandatory — closes the `selection` concatenation pattern gap |
| **C** | Exported mapping | Mandatory prerequisite to narrow the investigation focus |
| **D** | ADB shell content | Direct dynamic verification, replicating real blind injection scenarios |
| **E** | Drozer | Fast automated triage across all exported providers |

**Minimum combination I recommend:** **C (mandatory first) → A + B (static triage) → D/E (dynamic verification)**.

---

### 3.8 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rule (two FAIL patterns, §1.3):**

---

#### ❌ FAIL / ISSUE — The check is declared FAILED if:

| No | Condition |
|---|---|
| F1 | Untrusted input from `getPathSegments()`/other URI sources is concatenated directly into an SQL statement |
| F2 | `appendWhere()` is used with unsanitized/unparameterized input, **or** the query is built unsafely by other means (manual concatenation into `selection`) |

**Example evidence (reflecting the real ownCloud pattern in §1.5):**

```java
// Found in com/example/app/provider/FileContentProvider.java
@Override
public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs, String sortOrder) {
    String id = uri.getPathSegments().get(1); // from the URI, untrusted
    SQLiteQueryBuilder qb = new SQLiteQueryBuilder();
    qb.setTables("files");
    qb.appendWhere("_id = " + id); // direct concatenation, UNSAFE
    return qb.query(db, projection, selection, selectionArgs, null, null, sortOrder);
}
```

**AndroidManifest.xml:**
```xml
<provider android:name=".FileContentProvider" android:exported="true" />
```

Interpretation: the provider is exported, accepts untrusted URI segments, and concatenates them directly into `appendWhere()`. **FAIL** — exactly the ownCloud real-world vulnerability pattern.

---

#### ✅ PASS — The check is declared PASSED if:

| No | Condition |
|---|---|
| P1 | All queries use `selection`/`selectionArgs` with `?` placeholders, **or** |
| P2 | `appendWhereEscapeString()` is used in place of raw `appendWhere()` for cases that genuinely require it |

**Example evidence:**

```java
public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs, String sortOrder) {
    String id = uri.getPathSegments().get(1);
    SQLiteQueryBuilder qb = new SQLiteQueryBuilder();
    qb.setTables("files");
    return qb.query(db, projection, "_id = ?", new String[]{id}, null, null, sortOrder); // parameterized
}
```

**PASS**.

---

#### ⚠️ Important Notes on Assessment

1. **Always start by mapping exported providers** — per §1.6, providers that are not exported have a much smaller attack surface; prioritize in-depth auditing for exported providers first.

2. **Do not rely solely on the official rule** — its coverage is limited to `appendWhere()` only (§1.4); the manual concatenation pattern into `selection` is equally dangerous but is not covered by the rule.

3. **Consider blind SQL injection scenarios, not only error-based ones** — per the real ownCloud case (§1.5), an attacker can extract data from restricted tables via conditional query techniques without a visible error message; dynamic testing (Method D) should attempt both payload types.

4. **Also pay attention to operations other than `query()`** — per the ownCloud finding, the `delete()`/`update()`/`insert()` methods on a `ContentProvider` are equally vulnerable if they use similar concatenation patterns for the `where` parameter.

5. **Severity is modulated:**

   | Factor | Severity |
   |---|---|
   | Exported provider, confirmed SQL injection (static + dynamic), allowing access to data from tables that should be restricted | **High** |
   | Dangerous pattern found but the provider is not exported (risk limited to within the app itself/apps sharing the same UID) | **Low-Medium** |
   | All queries use correct parameterization | **No finding** |

6. **Document:** the code location, the exported status of the related provider, the vulnerable method (`query`/`delete`/`update`/`insert`), and the result of dynamic verification (successful payload, data successfully extracted).

---

## 4. Recommendations

### 4.1 Use Parameterized Queries Consistently (Per MASTG-BEST-0039)

```kotlin
// BEFORE — direct concatenation
qb.appendWhere("_id = " + idSegment)

// AFTER — parameterized, per MASTG-BEST-0039
val selection = "id = ?"
val selectionArgs = arrayOf(idSegment)
val cursor = qb.query(db, projection, selection, selectionArgs, null, null, sortOrder)
```

### 4.2 Apply the Same Pattern to delete/update/insert

```java
// BEFORE
db.execSQL("DELETE FROM files WHERE id = " + where);

// AFTER — prepared statement with argument binding
db.delete("files", "id = ?", new String[]{where});
```

### 4.3 Restrict `exported` Unless Truly Necessary

```xml
<provider
    android:name=".FileContentProvider"
    android:exported="false" />
```

If the provider is only used internally, fully disable `exported` to eliminate the attack surface from third-party applications altogether.

### 4.4 Remediation Checklist

- [ ] All `query`/`delete`/`update`/`insert` operations on the ContentProvider use parameterization, with no direct string concatenation
- [ ] `appendWhere()` is replaced with `selection`/`selectionArgs` or `appendWhereEscapeString()` where genuinely needed
- [ ] Providers that do not need to be accessed by other applications are set to `exported="false"`
- [ ] Dynamically verified with both direct and blind injection payloads (ADB/Drozer)
- [ ] Permissions (`readPermission`/`writePermission`) are applied for exported providers that genuinely require restricted access

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0339 (source, tests-beta)](https://github.com/OWASP/mastg/blob/master/tests-beta/android/MASVS-CODE/MASTG-TEST-0339.md)
- [MASTG-KNOW-0117: Android ContentProvider](https://mas.owasp.org/MASTG/knowledge/android/MASVS-CODE/MASTG-KNOW-0117/)
- [MASTG-BEST-0039: Prevent SQL Injection in ContentProviders](https://github.com/OWASP/mastg/blob/master/best-practices/MASTG-BEST-0039.md)

### 5.2 Official Android Documentation

- [Android Developers: Content Provider Basics — Protect Against Malicious Input](https://developer.android.com/guide/topics/providers/content-provider-basics#Injection)

### 5.3 Research and Real-World Cases (CVE)

- [GitHub Security Lab: GHSL-2022-059/060 — SQL Injection in ownCloud Android App (CVE-2023-24804, CVE-2023-23948)](https://securitylab.github.com/advisories/GHSL-2022-059_GHSL-2022-060_Owncloud_Android_app/)
- [Advania: Local SQL Injection in com.android.providers.telephony (CVE-2020-0060)](https://www.advania.co.uk/insights/blog/android-telephony-vulnerability/)
- [RedFox Security: Exploiting Content Providers in Android Applications](https://redfoxsecurity.medium.com/exploiting-content-providers-in-android-applications-a75cbda2a5c7)
- [arXiv: SecComp — Towards Practically Defending Against Component Hijacking in Android Applications](https://arxiv.org/pdf/1609.03322)

### 5.4 Tool Documentation

- [Semgrep Documentation](https://semgrep.dev/docs/)
- [Drozer — Android Security Assessment Framework](https://github.com/WithSecureLabs/drozer)
- [Androguard](https://github.com/androguard/androguard)

---

*This document was prepared based on official OWASP MASTG content (`tests-beta/android/MASVS-CODE/MASTG-TEST-0339.md`, `MASTG-KNOW-0117`, `MASTG-BEST-0039`), analysis of the `mastg-android-sql-injection-contentprovider.yml` rule, and real CVE history both at the Android framework level (`CVE-2020-0060` telephony, `CVE-2018-9493` DownloadProvider) and in popular production applications (`CVE-2023-24804`/`CVE-2023-23948` in the ownCloud Android App) covering both types of SQL injection: direct and blind. The most important methodological nuance: the official rule only covers the `appendWhere()` pattern, while the official FAIL criteria for this test also cover manual concatenation into the `selection` parameter, which is not covered by the rule at all — the tester must supplement with manual searches, and the investigation must always start with mapping the provider's `exported` status as a prerequisite for exploitation.*
