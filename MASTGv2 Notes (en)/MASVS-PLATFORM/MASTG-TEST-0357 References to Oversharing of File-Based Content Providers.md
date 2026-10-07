# MASTG-TEST-0357 References to Oversharing of File-Based Content Providers

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0357 |
| **Platform** | Android |
| **MASVS Category** | MASVS-PLATFORM |
| **Weakness** | MASWE-0018 |
| **Test Type** | Static, Config, Code, **Manual** |
| **Related Techniques** | MASTG-TECH-0013, MASTG-TECH-0159 (Verify Usage of File-Based Content Providers), MASTG-TECH-0014, MASTG-TECH-0023 |
| **Related Knowledge** | MASTG-KNOW-0020, MASTG-KNOW-0117 |
| **Related Best Practice** | MASTG-BEST-0049 (Restrict and Validate Access to Exported Content Providers) |
| **Related Tests** | MASTG-TEST-0355/0356 — related documents in this research series; those tests target **database-backed** providers, this test specifically targets **file-backed** providers (`FileProvider`) |
| **Official rule** | `mastg-android-fileprovider-broad-scope.yml` — 2 patterns, a **coverage gap** was found, see §1.4 |

---

## 1. Explanation

### 1.1 Testing Objective

Quote from the official MASTG overview:

> *"If the app exports an Android content provider without enforcing access restrictions, external callers may open private files through content:// URIs. This test checks whether exported providers expose sensitive stored data to callers that don't hold the required permissions."*

This test is the specific `FileProvider` complement to the series of content-provider tests in this research series. It was already discussed in the **MASTG-TEST-0355 §4.3** document that `FileProvider` is recommended as a **safer mechanism** for sharing files compared to a custom database provider — but its security **entirely depends** on how narrowly the path configuration is defined in `res/xml/file_paths.xml`. This test specifically targets misconfigurations of that kind.

### 1.2 Four Dangerous Configuration Patterns Explicitly Named by the Official Evaluation

> **Evaluation:** *"The test case fails if the app exports a FileProvider and if the provider's path configuration allows access outside the intended shared directory (for example, via `<root-path>`, `path="/"`, `path="."`, or `path=""`)."*

| Pattern | Impact |
|---|---|
| `<root-path>` | Maps the **entire filesystem root** (`/`) into the provider namespace |
| `path="/"` | Functionally equivalent to `<root-path>` on any path element |
| `path="."` | Maps the **entire base directory** (e.g. the whole `filesDir`) — including files added later such as authentication tokens, databases, or logs |
| `path=""` | Empty string — functionally equivalent to mapping the base directory itself without any subdirectory restriction |

MASTG-BEST-0049 gives the sharpest explanation of why `path="."` is dangerous even beyond what it appears to be at first glance:

> *"Setting path="." on any path element exposes the entire corresponding directory, including files added later such as authentication tokens, databases, or logs."*

The phrase *"files added later"* is crucial — the risk of this configuration is **not static**. Even if a developer verifies today that the mapped directory contains only non-sensitive files, **this risk remains latent** and will materialize automatically the moment another developer, in the future, stores any sensitive file into the same directory without realizing that the directory is already "connected" to an exported FileProvider.

### 1.3 Two Different Risk Vectors: Path Configuration vs. Attacker-Controlled Input

The overview and MASTG-TECH-0159 identify **two different kinds of analysis**, both of which need to be performed:

> *"Determine whether `FileProvider.getUriForFile()` is called with attacker-controlled input (for example, values derived from URI query parameters or user input)."*

This is a **second**, separate risk vector from the path-configuration problem (§1.2) — even if `file_paths.xml` is configured correctly and narrowly (e.g. only `files-path name="reports" path="reports/"`), the application **can still be vulnerable** if the `File` argument passed to `FileProvider.getUriForFile()` originates from **attacker-controllable input** — for example, a filename received from a deep-link URI parameter, then used directly without validation to construct a `File` path that might contain a `../` sequence to escape the intended subdirectory (although `FileProvider` natively rejects path traversal attempts that try to escape the declared subtree, a combination with other weaknesses nearby can still open a gap).

### 1.4 Analytical Finding: The Official Rule Does Not Explicitly Cover `path=""` and `path="/"`

Note the patterns covered by the `mastg-android-fileprovider-broad-scope.yml` rule:

```yaml
pattern-either:
  - pattern: <files-path ... path="." ... />
  - pattern: <cache-path ... path="." ... />
  - pattern: <external-path ... path="." ... />
  - pattern: <external-files-path ... path="." ... />
  - pattern: <external-cache-path ... path="." ... />
```

And a second rule only targets `<root-path>`. **Both rules explicitly match only the literal `path="."` and the `<root-path>` element** — **there is no pattern** targeting `path="/"` or `path=""` separately, even though **both are explicitly named** in this very test's own Evaluation section (§1.2) as equally dangerous patterns. This is a coverage gap consistent with a pattern repeatedly found throughout this research series — official rules often do not cover **every** variant mentioned in their own evaluation text.

Technically, `path=""` and `path="."` likely **behave the same way** (both map the base directory with no additional subdirectory), but `path="/"` may have a different interpretation depending on the Android parser — the tester should not assume the official rule covers this case without verification, and should add manual searches for both uncovered variants.

### 1.5 Concrete Evidence: Real CVEs and Findings in Giant Applications (Google, TikTok)

Industry research shows that this misconfiguration is not a theoretical risk, but a class of vulnerability that **continues to be found** in popular applications, even from major vendors:

> *"Oversecured has found examples of these vulnerabilities in Google, TikTok, and many other apps."*

The fact that this class of vulnerability has been found even in applications from **Google itself** (the maker of the Android platform) reinforces how easily `file_paths.xml` misconfiguration can occur, even among engineering teams with very deep platform understanding — this should be a strong signal to other teams that an explicit audit of this configuration **must never be assumed to be "surely already correct"** simply because the developers are experienced.

A specific, documented real-world CVE case:

> *"An issue in vicohome v.2.22.7 allows a remote attacker to execute arbitrary code via the xml/file_paths.xml component (CVE-2023-48984)."*

The impact of this CVE — **remote code execution**, not merely information disclosure — shows that FileProvider oversharing, when combined with other weaknesses (e.g. the exposed file could be a configuration/executable file that is later executed through another path), can escalate far beyond a simple data leak.

---

## 2. Tools Used for Testing

### 2.1 Required Tools (Core)

| Tool | Function |
|---|---|
| **aapt / Androguard** | Manifest extraction to identify exported `FileProvider` (MASTG-TECH-0159) |
| **jadx** | Decompilation for tracing `getUriForFile()` arguments (MASTG-TECH-0013, MASTG-TECH-0014) |
| **Semgrep** + official rule `mastg-android-fileprovider-broad-scope.yml` | Detection of `path="."` and `<root-path>` (limited coverage, §1.4) |

### 2.2 Alternative & Supporting Tools

| Tool | Function |
|---|---|
| **grep/ripgrep** | Closes the official rule's coverage gap — explicitly searching for `path=""`/`path="/"` (§1.4) |
| **Drozer / adb shell content** | Dynamic verification — attempting to open a `content://` URI with a suspected sensitive path to confirm actual access |

### 2.3 Environment Prerequisites

- Static analysis does not require a device/root.
- Dynamic verification requires a device/emulator with the target application installed.

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0013** to reverse engineer the application.
2. Use **MASTG-TECH-0159** to identify exported file-based providers and examine their path configuration.
3. Use **MASTG-TECH-0014** to search for the relevant APIs.

### 3.2 Method A — Semgrep with the Official Rule

```bash
semgrep --config mastg-android-fileprovider-broad-scope.yml ./res/xml
```

### 3.3 Method B — grep/ripgrep to Close the path="" and path="/" Gap

```bash
R=./res/xml

# Patterns covered by the official rule
rg -n 'path="\."' $R
rg -n '<root-path' $R

# Patterns NOT covered by the official rule, but explicitly named in the official evaluation (§1.2)
rg -n 'path=""' $R
rg -n 'path="/"' $R
```

### 3.4 Method C — Trace getUriForFile() Arguments for Attacker-Controlled Input (Per §1.3)

```bash
D=./decompiled/sources
rg -n 'FileProvider.getUriForFile\(' $D -A3
```

For each result, trace back the `File` variable passed in — whether it originates from `Intent` extras, a deep-link URI parameter, or other user input, per MASTG-TECH-0159.

### 3.5 Method D — Manual Review (Mandatory, Per MASTG-TECH-0023)

For each exported `FileProvider` found:

1. Check its `android:permission` and `protectionLevel` (following the principle already discussed in MASTG-TEST-0355).
2. Verify the physical directory mapped by the declared path — what it currently contains, and what it might contain in the future (§1.2, "files added later").

### 3.6 Method Comparison: When to Use Which

| Method | Tool | When to use |
|---|---|---|
| **A** | Semgrep + official rule | Baseline, covers `path="."` and `<root-path>` |
| **B** | Manual grep/ripgrep | **Mandatory** — closes the `path=""`/`path="/"` gap |
| **C** | Trace getUriForFile() | Catches the second vector: attacker-controlled input |
| **D** | Manual review | Assesses permission/protectionLevel and the latent risk of directory contents |

**Minimum recommended combination:** **A + B (mandatory) + C**, followed by **D** for final assessment.

---

### 3.7 Evaluation Criteria: Positive Case & Negative Case

---

#### ❌ FAIL / ISSUE — The check is declared FAILED if:

| No | Condition |
|---|---|
| F1 | An exported `FileProvider` has a path configuration of `<root-path>`, `path="/"`, `path="."`, or `path=""` |
| F2 | *(Additional vector, §1.3)* `getUriForFile()` is called with a `File` argument derived from attacker-controlled input without validation |

**Example evidence (reflecting the real-world pattern in §1.5):**

```xml
<!-- res/xml/file_paths.xml -->
<paths>
    <files-path name="all_files" path="." />
</paths>
```

```xml
<provider
    android:name="androidx.core.content.FileProvider"
    android:authorities="com.example.app.fileprovider"
    android:exported="false"
    android:grantUriPermissions="true">
    <meta-data android:name="android.support.FILE_PROVIDER_PATHS" android:resource="@xml/file_paths" />
</provider>
```

Interpretation: even though the provider is not exported, `path="."` maps the **entire** `filesDir` — if the application grants a URI to another application via an `Intent`, the recipient can access **any file** in `filesDir`, not only the file intended to be shared. **FAIL**.

---

#### ✅ PASS — The check is declared PASSED if:

| No | Condition |
|---|---|
| P1 | Every path element uses a specific, narrow subdirectory (`path="reports/"`, etc.), **and** |
| P2 | `getUriForFile()` is only called with a `File` argument originating from a trusted/validated source |

---

#### ⚠️ Important Notes on Assessment

1. **Do not rely on the official rule alone** — per §1.4, add manual searches for `path=""`/`path="/"`, which are explicitly named in the official evaluation but not covered by the Semgrep rule.

2. **Assess latent risk, not just current directory contents** — per §1.2, a broad path remains high-risk even if the directory it currently maps "happens to" contain only non-sensitive files; the evaluation must account for the future risk of new files being added to the same directory.

3. **Check the two vectors independently** — a narrow path configuration paired with attacker-controlled input in `getUriForFile()` (§1.3) remains at risk even if it passes the path check.

4. **Severity is modulated:**

   | Factor | Severity |
   |---|---|
   | `path="."`/`<root-path>` on an exported provider that grants URIs to other applications | **High** |
   | Narrow path but `getUriForFile()` accepts attacker-controlled input | **High** |
   | Narrow path, validated input, adequate permissions | **Not a finding** |

5. **Document:** the full `file_paths.xml` configuration, the provider's exported status, the result of tracing `getUriForFile()` arguments, and the physical directory contents mapped at the time of the audit.

---

## 4. Recommendations

### 4.1 Use Specific Subdirectories, Not the Full Base Directory

```xml
<!-- BEFORE -->
<files-path name="all_files" path="." />

<!-- AFTER -->
<files-path name="reports" path="reports/" />
```

### 4.2 Validate Input Before Passing It to getUriForFile()

```java
File file = new File(context.getFilesDir(), "reports/" + sanitizeFileName(userInput));
if (!file.getCanonicalPath().startsWith(reportsDir.getCanonicalPath())) {
    throw new SecurityException("Path traversal detected");
}
Uri uri = FileProvider.getUriForFile(context, AUTHORITY, file);
```

### 4.3 Remediation Checklist

- [ ] No `path="."`, `path=""`, `path="/"`, or `<root-path>` in `file_paths.xml`
- [ ] Every path element maps a specific, narrow subdirectory
- [ ] `getUriForFile()` does not accept a `File` argument from attacker-controlled input without validation
- [ ] The provider is set to `exported="false"` with `grantUriPermissions="true"` for controlled sharing (per MASTG-BEST-0049)

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0357 (source, tests-beta)](https://github.com/OWASP/mastg/blob/master/tests-beta/android/MASVS-PLATFORM/MASTG-TEST-0357.md)
- [MASTG-TEST-0355/0356 (related documents in this research series)](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0355/)
- [MASTG-TECH-0159: Verify Usage of File-Based Content Providers](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0159/)
- [MASTG-BEST-0049: Restrict and Validate Access to Exported Content Providers](https://github.com/OWASP/mastg/blob/master/best-practices/MASTG-BEST-0049.md)

### 5.2 Research and Real-World Cases

- [Android Developers: Improperly Exposed Directories to FileProvider](https://developer.android.com/privacy-and-security/risks/file-providers)
- [Guardsquare: Security Risks of Exposed Directories in Android FileProvider](https://www.guardsquare.com/blog/android-fileprovider-directories-security-risks)
- [Oversecured: Android Security Checklist — Theft of Arbitrary Files](https://blog.oversecured.com/Android-security-checklist-theft-of-arbitrary-files/)
- [GitHub: CVE-2023-48984 — vicohome FileProvider RCE](https://github.com/l00neyhacker/CVE-2023-48984)

### 5.3 Tool Documentation

- [Semgrep Documentation](https://semgrep.dev/docs/)
- [FileProvider API Reference](https://developer.android.com/reference/androidx/core/content/FileProvider)

---

*This document was compiled based on official OWASP MASTG content (`tests-beta/android/MASVS-PLATFORM/MASTG-TEST-0357.md`, `MASTG-TECH-0159`, `MASTG-BEST-0049`), analysis of the `mastg-android-fileprovider-broad-scope.yml` rule, and industry research (Oversecured, Guardsquare) documenting this vulnerability class in giant applications (Google, TikTok) and a concrete CVE (CVE-2023-48984, escalating to RCE). The most important methodological nuance: this test's official evaluation explicitly names four dangerous patterns (`<root-path>`, `path="/"`, `path="."`, `path=""`), yet the official Semgrep rule covers only two of those four patterns (`path="."` and `<root-path>`) — a manual search for `path=""`/`path="/"` is a mandatory step that cannot be replaced by automated results alone. The risk of a broad path configuration is also latent — it is dangerous not only because of the directory's current contents, but because any sensitive file added in the future to the same directory will be automatically exposed.*
