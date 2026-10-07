# MASTG-TEST-0375 Missing Validation of Data Returned from Implicit Intents

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0375 |
| **Platform** | Android |
| **MASVS Category** | MASVS-CODE |
| **Weakness** | MASWE-0050 |
| **Test Type** | Dynamic, Hooks, **Manual** |
| **Related Techniques** | MASTG-TECH-0005, MASTG-TECH-0043, MASTG-TECH-0023 |
| **Related Knowledge** | MASTG-KNOW-0025 (Explicit vs Implicit Intents), MASTG-KNOW-0138 (URI Schemes in Android Intent Results) |
| **Related Best Practice** | MASTG-BEST-0057 (Sanitize Data Coming from External Components) |
| **Related Tests** | MASTG-TEST-0372/0374 — related documents in this research series; all three cover implicit intents from different angles (see §1.1) |
| **Official Rule** | — (none exists; this test is purely dynamic with manual validation, consistent with the opposite direction of the previous two tests) |

---

## 1. Explanation

### 1.1 Reversed Risk Direction Compared to MASTG-TEST-0372/0374

Quote from the official MASTG overview:

> *"Apps commonly use implicit intents and activity result APIs to request data from another app, such as selecting a file, opening a document, or importing content. The selected responder controls the result returned to the caller... The issue appears when the app treats the returned data as trusted."*

This is the **opposite direction** from the two previous tests in this research series:

| | MASTG-TEST-0372/0374 | MASTG-TEST-0375 (this test) |
|---|---|---|
| **Data flow direction** | The app **sends** data out via an implicit intent | The app **receives** incoming data from an implicit intent's result |
| **Who is suspected** | A malicious app that **intercepts** the intent (intent hijacking) | A malicious app that **answers** the request (**malicious responder**) |
| **Main risk** | Sensitive data leaked to an untrusted party | The victim app **trusts** data controlled by the attacker |

This is a classic **"confused deputy"** pattern — the app requests a file/document via `ACTION_GET_CONTENT`/chooser, assuming that only a "good" app (Google Drive, File Manager, etc.) will respond, but **the system cannot guarantee that** — any malicious app that registers a matching `<intent-filter>` can also become the selected responder and return whatever data it wants.

### 1.2 Two URI Schemes and the Critical Difference in Their Access Control Models

MASTG-KNOW-0138 explains the fundamental difference that is at the core of this test's risk:

> *"`content://`: Routes through a ContentProvider. Access control: Governed by provider permissions, URI grants, and provider export state."*
>
> *"`file://`: Accesses the filesystem path directly. Access control: Governed by filesystem permissions for the calling process."*

This difference is crucial: a `content://` URI **still passes through the provider's access control layer**. A `file://` URI, however, is **truly direct** — it becomes a filesystem path opened **using the calling application's (the victim's) process identity**, not the responder's identity. This means:

> *"A responding app controls the URI value it returns in the result intent. If that value uses the `file://` scheme, the path is interpreted from the caller's process context. For example, `file:///data/data/com.example.app/shared_prefs/session.xml` denotes a filesystem path under the app-private data directory of `com.example.app`."*

This scenario is extremely dangerous — **a malicious responder can "trick" the victim into opening its own private file** (for example the victim's own `shared_prefs/session.xml`) simply by returning a `file://` URI pointing to that path, after which the victim (which blindly trusts the result) reads and processes "content the user selected" — when in reality it is the victim's own internal file, now exposed through a processing path it was never intended to go through.

### 1.3 Second Vector: Path Traversal via DISPLAY_NAME Metadata

The second vector, explained in detail with a concrete code example:

> *"When the responding app returns a content:// URI, the calling app can query `OpenableColumns.DISPLAY_NAME` to get a human-readable filename... The provider controls the value returned for that column. If the value contains path separators, constructing a path with `File(dir, name)` resolves it according to normal filesystem path rules."*

```kotlin
val name = getDisplayName(uri) ?: "download"
val target = File(context.filesDir, name) // resolves to ../lib-main/lib.so
```

This is **classic path traversal** — `DISPLAY_NAME`, which should only ever be a plain filename (`"document.pdf"`), could be returned by a malicious responder as `"../../../lib/malicious.so"`, and if the victim app naively builds the destination path with `File(dir, name)`, the final result could **write a file outside the intended directory** — even overwriting the application's own library file.

### 1.4 Highly Targeted Real-World Evidence: CVE-2026-38093 in the Flutter file_picker Plugin

This is real-world evidence that **precisely** replicates the `DISPLAY_NAME` path-traversal scenario described in MASTG-BEST-0057 (§1.3) — found in the popular `file_picker` plugin (widely used in the Flutter ecosystem, including for building Android apps):

> *"file_picker (aka flutter_file_picker) for Flutter, all versions through 10.3.10, is vulnerable to path traversal (CWE-22) in its Android implementation. The `openFileStream()` method uses the DISPLAY_NAME from `ContentResolver.query()` directly in file path construction without sanitization. A malicious Android app can supply a crafted ContentProvider that returns a filename containing '../' sequences, enabling the plugin to create files and directories outside the intended cache directory inside the victim app's internal storage."*

An important note on the limitations of impact in this specific case (relevant for realistic severity calibration, rather than overstating it):

> *"Existing files are not overwritten because an existence check is performed, but the flaw still allows placement of arbitrary files outside the allowed location... if the created files are later processed by the app, it could be used to modify data, elevate privileges, or facilitate other attacks."*

This shows an important nuance — the direct impact of a single path-traversal vulnerability **depends on subsequent context**: writing a new file in an unexpected location might "only" be information disclosure/clutter if no other logic automatically processes that file, but it **escalates significantly** if the app later loads/executes/trusts the file at that location without further verification.

### 1.5 Why This Test Is Dynamic, Not Static

Unlike TEST-0372/0374, which are purely static, this test is explicitly **dynamic** — the reasoning is logical: assessing "whether the returned data is validated before being used in a sensitive operation" requires **observing the actual data flow at runtime**, since the responder actually invoked, the value actually returned, and the code path actually executed afterward often cannot be determined with certainty just by reading static code (especially when there are many possible responders/conditional branches).

---

## 2. Tools Used for Testing

### 2.1 Required Tools (Core)

| Tool | Function |
|---|---|
| **Frida** | Hooking `onActivityResult`/`ActivityResultCallback`, `Intent.getData()`, `ContentResolver.query/openInputStream` (MASTG-TECH-0043) |
| **ADB** | Installing the app, installing a custom test responder app (MASTG-TECH-0005) |

### 2.2 Alternative & Supporting Tools

| Tool | Function |
|---|---|
| **Custom malicious responder app** | Registers an `<intent-filter>` matching the target app's request, then returns a `file://`/`content://` URI with a `DISPLAY_NAME` containing a path-traversal sequence — directly replicating the CVE-2026-38093 scenario (§1.4) |
| **jadx** | Reviewing code to trace result processing after the hook (MASTG-TECH-0023) |

### 2.3 Environment Prerequisites

- Rooted device/emulator with `frida-server`.
- **A custom test responder app** that can be configured to return different payloads (a `file://` URI to an internal victim path, a `DISPLAY_NAME` with `../`, etc.) — this is the most important testing component for this test.

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0005** to install the application.
2. Use **MASTG-TECH-0043** to hook the relevant APIs.
3. Exercise the application extensively to trigger flows that request data from another app via an implicit intent.

### 3.2 Method A — Frida: Hook the Full Request-Result-Processing Chain

```javascript
Java.perform(function () {
    var Intent = Java.use("android.content.Intent");
    Intent.getData.implementation = function () {
        var uri = this.getData();
        console.log("[Intent.getData] " + (uri ? uri.toString() : "null"));
        console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));
        return uri;
    };

    var ContentResolver = Java.use("android.content.ContentResolver");
    ContentResolver.openInputStream.overload('android.net.Uri').implementation = function (uri) {
        console.log("[ContentResolver.openInputStream] uri=" + uri.toString());
        return this.openInputStream(uri);
    };
});
```

### 3.3 Method B — Replicate the Path-Traversal Scenario with a Custom Responder (Mandatory, Per §1.4)

```xml
<!-- Test responder app manifest -->
<provider android:name=".MaliciousProvider" android:authorities="com.attacker.evil.provider" android:exported="true" />
```

```java
// MaliciousProvider.query() implementation — return a DISPLAY_NAME containing path traversal
cursor.addRow(new Object[]{"../../../../lib-main/libnative.so"});
```

Trigger the file-picker flow in the target app, select this test "responder" as the answering app, and observe whether a file is actually written outside the intended directory.

### 3.4 Method C — Manual Post-Hook Review (Mandatory, Per MASTG-TECH-0023)

For each piece of data captured by the hook:

1. Is the value used directly to build a file path (`File(dir, name)`) without sanitization?
2. Is the URI scheme (`file://` vs `content://`) checked before use?
3. Does the final result affect a sensitive operation (file writing, content parsing, authorization decisions)?

### 3.5 Method Comparison: When to Use Which

| Method | Tool | When to Use |
|---|---|---|
| **A** | Frida | Mandatory baseline — observing the intent result's data flow |
| **B** | Custom responder | **Required** — conclusive proof replicating a real-world attack |
| **C** | Manual review | **Required** — assessing actual validation |

**Minimum recommended combination:** **A + B (mandatory) → C (mandatory)**.

---

### 3.6 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rule:**

> **Evaluation:** *"The test case fails if data returned from an external intent result reaches a security-relevant operation without validation or sanitization."*

---

#### ❌ FAIL / ISSUE — The check is declared FAILED if:

| No | Condition |
|---|---|
| F1 | Data from an external intent result (`getData()`/`ClipData`/extras/provider metadata) reaches a sensitive operation without validation |

**Evidence example (reflecting the real pattern of CVE-2026-38093, §1.4):**

```java
override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
    val uri = data?.data ?: return
    val name = getDisplayName(uri) ?: "download" // from the responder, could be "../lib/evil.so"
    val target = File(context.filesDir, name) // NOT sanitized
    contentResolver.openInputStream(uri)?.copyTo(target.outputStream())
}
```

**FAIL** — a path-traversal vulnerability is open, allowing a file to be written outside the intended directory.

---

#### ✅ PASS — The check is declared PASSED if:

| No | Condition |
|---|---|
| P1 | The URI scheme is verified (`content://` is prioritized, `file://` is rejected/handled specially), **and** |
| P2 | `DISPLAY_NAME`/filename is sanitized with `File(name).name` before being used to build a path, **and** |
| P3 | The destination path is always anchored to a controlled directory (`filesDir`/`cacheDir`), rather than built directly from an external value |

---

#### ⚠️ Important Notes on Assessment

1. **Always test with a custom malicious responder** — relying on a "normal" responder (Google Files, etc.) will never trigger the dangerous condition; active replication (Method B) is the only way to conclusively verify this.

2. **Check both vectors separately** — the `file://` URI scheme (§1.2) and the `DISPLAY_NAME` metadata (§1.3) are two independent vectors; an app may be safe against one but vulnerable to the other.

3. **Assess downstream impact, not just whether the file write succeeded** — as the realistic note on CVE-2026-38093 (§1.4) shows, the full impact depends on whether a file written to an unexpected location is subsequently processed/executed by other logic.

4. **Severity is modulated as follows:**

   | Factor | Severity |
   |---|---|
   | Path traversal allows overwriting/writing a file that is subsequently executed/trusted (native lib, critical config) | **High** |
   | Path traversal writes a new file without clear further escalation | **Medium** |
   | URI scheme and filename are properly validated | **Not a finding** |

5. **Document:** the type of URI received, the `DISPLAY_NAME`/metadata values attempted, the resulting path, and whether the file was successfully written outside the intended directory.

---

## 4. Recommendations

### 4.1 Validate the URI Scheme and Sanitize the Filename (Per MASTG-BEST-0057)

```kotlin
fun sanitizeFileName(name: String): String = File(name).name // strip path traversal

override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
    val uri = data?.data ?: return
    if (uri.scheme != "content") return // reject file:// from an external responder

    val rawName = getDisplayName(uri) ?: "default.bin"
    val safeName = sanitizeFileName(rawName)
    val output = File(context.filesDir, safeName) // always anchor to a controlled directory
    contentResolver.openInputStream(uri)?.use { input ->
        output.outputStream().use { out -> input.copyTo(out) }
    }
}
```

### 4.2 Remediation Checklist

- [ ] The URI scheme of intent results is verified — `file://` from an external responder is rejected/handled specially
- [ ] `DISPLAY_NAME`/filename metadata is sanitized with `File(name).name` before use
- [ ] The destination path is always anchored to a controlled directory (`filesDir`/`cacheDir`)
- [ ] Verified with a custom malicious responder attempting path traversal and `file://` pointing to an internal path

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0375 (source, tests-beta)](https://github.com/OWASP/mastg/blob/master/tests-beta/android/MASVS-CODE/MASTG-TEST-0375.md)
- [MASTG-TEST-0372/0374 (related documents in this research series)](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0372/)
- [MASTG-KNOW-0138: URI Schemes in Android Intent Results](https://mas.owasp.org/MASTG/knowledge/android/MASVS-CODE/MASTG-KNOW-0138/)
- [MASTG-BEST-0057: Sanitize Data Coming from External Components](https://github.com/OWASP/mastg/blob/master/best-practices/MASTG-BEST-0057.md)

### 5.2 Research and Real-World Cases

- [GitHub Advisory: CVE-2026-38093 — file_picker (Flutter) Android Path Traversal via DISPLAY_NAME](https://github.com/advisories/ghsa-r2rg-pm28-j8gw)
- [SentinelOne: CVE-2025-48609 — Google Android Path Traversal Vulnerability](https://www.sentinelone.com/vulnerability-database/cve-2025-48609/)
- [Oversecured: Android Security Checklist — Theft of Arbitrary Files](https://blog.oversecured.com/Android-security-checklist-theft-of-arbitrary-files/)
- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)](https://cwe.mitre.org/data/definitions/22.html)

### 5.3 Tool Documentation

- [Frida — Dynamic Instrumentation Toolkit](https://frida.re/docs/home/)

---

*This document was prepared based on official OWASP MASTG content (`tests-beta/android/MASVS-CODE/MASTG-TEST-0375.md`, `MASTG-KNOW-0138`, `MASTG-BEST-0057`), along with highly targeted real-world evidence: CVE-2026-38093 in the popular Flutter `file_picker` plugin, which precisely replicates the `DISPLAY_NAME` path-traversal pattern described in official MASTG documentation. The most important methodological nuance: this test targets the **opposite** risk direction from MASTG-TEST-0372/0374 — not data leaking outward, but the application **blindly trusting** data controlled by an external implicit intent "responder" (the confused deputy pattern), with two independent vectors that must be checked separately: the `file://` URI scheme opened under the victim's process identity, and the `DISPLAY_NAME` metadata that can be compromised with a path-traversal sequence.*
