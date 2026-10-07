# MASTG-TEST-0287 Runtime Storage of Unencrypted Data via the SharedPreferences API

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0287 |
| **Platform** | Android |
| **MASVS Category** | MASVS-STORAGE (MASVS-STORAGE-1) |
| **Weakness** | MASWE-0001 — *Sensitive Data Stored Unencrypted in Private Storage* |
| **Highlighted APIs** | `SharedPreferences.Editor.putString(...)`, `putStringSet(...)`, and other `put*` methods; related cryptography APIs: `javax.crypto.Cipher`, `java.security.KeyStore`, `javax.crypto.KeyGenerator` |
| **Test Type** | **Dynamic, Hooks, Manual** |
| **Prerequisite** | `identify-sensitive-data` |
| **Knowledge** | MASTG-KNOW-0036 (Shared Preferences) |
| **Best Practice** | MASTG-BEST-0050 |
| **Related Techniques** | MASTG-TECH-0005 (Install App), MASTG-TECH-0043 (Method Hooking), MASTG-TECH-0008 (Retrieving Files/Data Directory), MASTG-TECH-0023 (Reviewing Decompiled Java Code) |
| **Related Tests** | **MASTG-TEST-0207** (Runtime Storage of Unencrypted Data in the App Sandbox) — a **generic filesystem diff** approach that captures any file regardless of which API writes it; this test is the **API-specific version** that targets `SharedPreferences` directly via hooking |
| **Related Demo** | — (none) |
| **Official Rule** | — (not applicable; dynamic, hooking-based test) |
| **Related CWE** | CWE-312 (Cleartext Storage of Sensitive Information), CWE-311 |

---

## 1. Explanation

### 1.1 Testing Objective and Its Relationship to MASTG-TEST-0207

Official MASTG overview quote:

> *"This test uses runtime instrumentation to detect when the app writes data via `SharedPreferences` and determines whether sensitive data is being stored unencrypted."*

This test is the **API-specific version** of the more generic approach found in **MASTG-TEST-0207** (already covered earlier in this research series, as part of the trio of external storage tests alongside MASTG-TEST-0200/0201/0202) — but with a different methodological philosophy:

| | MASTG-TEST-0207 | MASTG-TEST-0287 *(this document)* |
|---|---|---|
| **Approach** | **Filesystem diff** — snapshot the data directory before/after, look for changes | **Direct API hooking** — instrumentation on `SharedPreferences.Editor.put*()` |
| **Coverage** | Any file that changes, **regardless of the API that wrote it** | Specific to the `SharedPreferences` pathway only |
| **Unique value** | Captures leakage via **any** storage mechanism (custom files, databases, caches) | Provides a **precise stack trace** to the code location performing the write, and can correlate with `Cipher` calls surrounding that write |

Both tests are **complementary**, not duplicates: MASTG-TEST-0207 provides a broad safety net (catching leakage through any storage mechanism), while MASTG-TEST-0287 provides **diagnostic precision** specific to `SharedPreferences` — a storage API that statistically is one of the most common locations where credential leakage is found in Android applications, owing to how easy it is for developers to use.

### 1.2 Why `MODE_PRIVATE` Is Not a Security Guarantee

The most important conceptual point from the official overview, and one frequently misunderstood by developers as "already secure enough":

> *"While `MODE_PRIVATE` restricts file access to the app itself, it doesn't protect the data from being read by attackers who gain access to the device's file system (for example, through device compromise, backup extraction, or physical access to rooted/unlocked devices)."*

`MODE_PRIVATE` operates at the **standard Linux filesystem permission layer** — it prevents **other applications** (with a different Linux UID) from reading that file under normal conditions. However, this is **in no way equivalent** to encryption — for an attacker who already has **root access**, **physical access to an unlocked device**, or the ability to **extract a backup** (refer to the in-depth discussion of backup schemes in the MASTG-TEST-0216/0262 documents in this research series), the contents of `shared_prefs/*.xml` files remain **directly readable as plaintext** with no additional obstacle whatsoever. As the concrete example from MASTG-KNOW-0036 shows:

```xml
<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
  <string name="username">administrator</string>
  <string name="password">supersecret</string>
</map>
```

These credentials are stored **entirely in human-readable text** — `MODE_PRIVATE` provides no obfuscation or encryption layer whatsoever over the file's **content**, only controlling **who** is normally permitted to read it at the operating system level.

### 1.3 Important Warning: `EncryptedSharedPreferences` Is Deprecated

This is an important finding testers need to know when assessing mitigations an application may already have implemented. MASTG-KNOW-0036 gives an explicit warning:

> *"The Jetpack Security Crypto library, including the `EncryptedFile` and `EncryptedSharedPreferences` classes, has been deprecated. All APIs in the library were deprecated in stable version `1.1.0`, and Android states that there will be no subsequent releases."*

This creates a **transitional dilemma** for development teams: `EncryptedSharedPreferences` (which encrypts keys with `AES256_SIV` and values with `AES256_GCM`) has for years been the **primary recommended solution** for the problem this test examines — but its status is now deprecated with no direct replacement of equivalent convenience. The official guidance suggests:

> *"For existing apps that must continue using `SharedPreferences` for sensitive data, `EncryptedSharedPreferences` may still be a practical mitigation, but it should not be treated as a long term storage strategy... plan a migration to a supported encryption approach when available."*

For testers, this means: **finding `EncryptedSharedPreferences` used correctly should still be treated as a PASS for now** (since it still provides actual encryption), but it is worth noting as a **technical-debt observation** that the development team needs to monitor as Android's recommendations evolve — not as a permanent solution. The long-term migration direction recommended by Android is **DataStore** (Jetpack) combined with manual encryption via the **Android Keystore** directly.

### 1.4 Another Important Note from MASTG-KNOW-0036: Interaction with Auto Backup

An additional technical point cross-relevant to the MASTG-TEST-0262 document in this research series:

> *"When using `EncryptedSharedPreferences`, exclude the encrypted preference file from Auto Backup... restoring the file may fail because the key used to encrypt it might no longer be available."*

This is not about data leakage but about **functional failure** — if the `EncryptedSharedPreferences` file is included in a backup but the encryption key (stored in the Android Keystore, which is **not** backed up to the cloud) is no longer available upon restore on a new device, the application will fail to read that data. This is an additional reason why `EncryptedSharedPreferences` files **must** be included in the exclude list in `data_extraction_rules.xml`/`backup_rules.xml` — connecting directly to the MASTG-TEST-0262 evaluation already covered in depth earlier.

---

## 2. Tools Used for Testing

### 2.1 Required Tools (Core)

| Tool | Function |
|---|---|
| **Frida** | Core dynamic instrumentation — hooking `SharedPreferences.Editor.put*()` |
| **frida-tools** (`frida-trace`) | Quick tracing without custom scripts |
| **objection** | Ready-made Frida wrapper with a built-in module for monitoring `SharedPreferences` |

### 2.2 Alternative & Supporting Tools

| Tool | Function |
|---|---|
| **TruffleHog** (MASTG-TOOL-0144) | Secret pattern scanning (API keys, tokens, credentials) on hook output as well as extracted `shared_prefs/*.xml` files — combines entropy detection with a broad regex library covering 800+ credential types, with the ability to verify directly against the real service (AWS, GitHub, etc.) to reduce false positives |
| **adb** | Extracting `shared_prefs/*.xml` files (MASTG-TECH-0008) after the testing session |
| **apkleaks / gitleaks** | Alternative secret pattern scanning, as discussed in depth in the MASTG-TEST-0212 document in this research series |
| **CodeQL** | For whitebox testing — tracing whether the value passed to `putString()` originates from a variable that previously went through `Cipher.doFinal()` (indicating encryption) or directly from raw user input/API response |

### 2.3 Environment Prerequisites

- **A device/emulator with the Frida server is mandatory** — this is a purely dynamic test.
- **Root or `run-as`** is required to access `shared_prefs/*.xml` directly from the application's data directory (MASTG-TECH-0008).
- **Thorough interaction with the application**, including entering sensitive data — per the official instructions in step 3: *"exercise the app extensively... enter sensitive data wherever you can"*.
- **Identify sensitive data first** (prerequisite `identify-sensitive-data`) — understand what types of data are relevant (credentials, tokens, PII) before starting hooking.

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0005** to install the application.
2. Use **MASTG-TECH-0043** to hook the relevant API calls.
3. Explore the application thoroughly, entering sensitive data wherever possible.
4. Use **MASTG-TECH-0008** to retrieve the application's `SharedPreferences` XML files.

### 3.2 Method A — Hooking `SharedPreferences` with Correlation to Cryptographic Operations *(primary method)*

```javascript
// hook-sharedprefs-writes.js
Java.perform(function () {
    function getBacktrace() {
        return Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());
    }

    var Editor = Java.use("android.content.SharedPreferences$Editor");

    ["putString", "putStringSet"].forEach(function (method) {
        try {
            Editor[method].overloads.forEach(function (overload) {
                overload.implementation = function () {
                    var args = Array.prototype.slice.call(arguments);
                    console.log("\n[*] SharedPreferences.Editor." + method + "(" + args.join(", ") + ")");
                    console.log("    Backtrace:\n" + getBacktrace());
                    return this[method].apply(this, args);
                };
            });
        } catch (e) { console.log("[x] Hook failed for " + method + ": " + e); }
    });

    // Correlate with cryptographic operations — hook Cipher.doFinal() to see call order
    var Cipher = Java.use("javax.crypto.Cipher");
    Cipher.doFinal.overload().implementation = function () {
        console.log("\n[*] Cipher.doFinal() called (indicates possible encryption before storage)");
        console.log("    Backtrace:\n" + getBacktrace());
        return this.doFinal();
    };
});
```

```bash
frida -U -f com.target.app -l hook-sharedprefs-writes.js --no-pause
```

**Call-order analysis (per the official "High-level trace inspection" clause)**: compare the timestamp/order between the `Cipher.doFinal()` log and `putString()` — if `putString()` is called **without** a preceding `Cipher.doFinal()` in the same flow, this is strong evidence that the value is being written **unencrypted**.

### 3.3 Method B — objection (Built-in Module for SharedPreferences)

```bash
objection -g com.target.app explore
android hooking watch class_method android.content.SharedPreferences$Editor.putString --dump-args --dump-backtrace
```

### 3.4 Method C — Extraction and Scanning with TruffleHog

```bash
# Extract the shared_prefs files after the testing session
adb shell run-as com.target.app cat /data/data/com.target.app/shared_prefs/*.xml > shared_prefs_dump.txt

# Scan with TruffleHog for recognized secret patterns
trufflehog filesystem shared_prefs_dump.txt --only-verified
```

```bash
# Alternative: apkleaks/gitleaks for additional patterns
gitleaks detect --source shared_prefs_dump.txt --no-git
```

### 3.5 Method D — CodeQL for Whitebox Verification (Encryption Flow)

```ql
import java

class PutStringCall extends MethodAccess {
  PutStringCall() {
    this.getMethod().hasName(["putString", "putStringSet"]) and
    this.getMethod().getDeclaringType().hasQualifiedName("android.content", "SharedPreferences$Editor")
  }
}

class CipherDoFinalCall extends MethodAccess {
  CipherDoFinalCall() {
    this.getMethod().hasName("doFinal") and
    this.getMethod().getDeclaringType().hasQualifiedName("javax.crypto", "Cipher")
  }
}

from PutStringCall put
where not exists(CipherDoFinalCall cipher | cipher.getEnclosingCallable() = put.getEnclosingCallable())
select put, "putString() found WITHOUT a Cipher.doFinal() call in the same method — candidate for unencrypted storage"
```

### 3.6 Method E — Verifying Use of `EncryptedSharedPreferences` (Distinguishing Already-Implemented Mitigations)

```bash
rg -n 'EncryptedSharedPreferences\.create\(' ./decompiled/sources/
```

If found, verify that the `MasterKey`/encryption scheme configuration used matches the recommendation (AES256_SIV for keys, AES256_GCM for values) and **check whether the related file has already been excluded from backup** (§1.4, correlation with MASTG-TEST-0262).

### 3.7 Method Comparison: When to Use Which

| Method | Tool | Provides a stack trace? | Assesses encryption? | When to use |
|---|---|---|---|---|
| **A** | Frida hook + Cipher correlation | ✅ | ✅ (order heuristic) | **Primary baseline** |
| **B** | objection | ✅ | ❌ (needs additional manual work) | Quick exploration |
| **C** | TruffleHog/gitleaks on the XML file | ❌ | Indirectly (secret pattern detection) | Confirming the actual file contents |
| **D** | CodeQL | N/A (static) | ✅ (whitebox) | Large codebases, whitebox testing |
| **E** | Verify `EncryptedSharedPreferences` | N/A | ✅ (confirms mitigation exists) | Assessing the quality of an already-implemented mitigation |

**Recommended minimum combination:** **A (hooking with Cipher correlation) → C (scanning the actual file contents with TruffleHog)** for a solid conclusion, supplemented by **E** when encryption indications are found, to assess the implementation quality.

---

### 3.8 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rule:**

> **Evaluation:** *"The test case fails if sensitive data is written to `SharedPreferences` without being encrypted first."*

With three mandatory **Further Validation Required** steps: trace order inspection (whether Cipher precedes putString or not), secret detector pattern matching, and manual verification via MASTG-TECH-0023.

---

#### ❌ FAIL / ISSUE — The check is declared FAILED when:

| No | Condition |
|---|---|
| F1 | `putString()`/`putStringSet()` is called with a value containing sensitive data (credentials, tokens, PII), **without** being preceded by any `Cipher`/encryption operation |
| F2 | Scanning the extracted `shared_prefs/*.xml` file with TruffleHog/gitleaks **finds** a verified secret pattern |
| F3 | Encryption usage is found, but the implementation is **flawed** (e.g., a hardcoded key — refer to the MASTG-TEST-0212 document, or a weak algorithm — refer to MASTG-TEST-0221) |

**Example evidence (illustrative — MASTG does not yet provide an official demo for this test):**

```
[*] SharedPreferences.Editor.putString(auth_token, eyJhbGciOiJIUzI1NiIs...)
    Backtrace:
        at com.example.target.auth.SessionManager.saveToken(SessionManager.java:34)
```

```bash
$ adb shell run-as com.example.target cat /data/data/com.example.target/shared_prefs/auth_prefs.xml
<map>
  <string name="auth_token">eyJhbGciOiJIUzI1NiIs...</string>
</map>
```

Interpretation: an authentication token (JWT format visible from the `eyJ...` prefix) is written and found **in full plaintext form** in the XML file — no `Cipher.doFinal()` hook was triggered beforehand. **FAIL**.

---

#### ✅ PASS — The check is declared PASSED when:

| No | Condition |
|---|---|
| P1 | All sensitive values written via `SharedPreferences` are preceded by a verifiably correct encryption operation (confirmed via Method A+D) |
| P2 | The application uses `EncryptedSharedPreferences` with a configuration matching the recommendation, and the related file is excluded from backup (§1.4) |
| P3 | Scanning the extracted XML file with TruffleHog/gitleaks **finds no** secret patterns at all |
| P4 | The application does not store any sensitive data via `SharedPreferences` at all (using the Android Keystore directly or another more appropriate mechanism) |

---

#### ⚠️ Important Notes on Assessment

1. **`MODE_PRIVATE` is never a basis for a PASS** — per §1.2, this is filesystem access control, not encryption. Do not let this common misconception affect the conclusion.

2. **`EncryptedSharedPreferences` found to be used correctly is treated as a PASS for now**, but should be noted as a technical-debt observation given its deprecated status (§1.3) — recommend the development team monitor the evolution of Android guidance for a long-term migration.

3. **Cipher-putString order correlation is heuristic, not absolute proof** — the value could be encrypted elsewhere (e.g., before being passed to the function that performs the storage) with a call pattern that is not immediately adjacent; always supplement with manual verification per MASTG-TECH-0023 as per the official clause.

4. **Always check the `shared_prefs/*.xml` file directly**, not just rely on hooking results — a value that appears "encrypted" from the hook (e.g., base64) may turn out to be **merely encoding**, not actual encryption; the actual file contents are the definitive evidence.

5. **Correlate with MASTG-TEST-0207** to ensure no other storage mechanism (outside `SharedPreferences`) is also leaking the same data.

6. **Severity is modulated** by the type of data found in plaintext — authentication credentials/tokens are far more critical than non-sensitive UI preferences.

7. **Document:** the stack trace location of the write, the value written (redacted if necessary for reporting), the correlation result with Cipher operations, the contents of the extracted XML file, and the secret detector scan results.

---

## 4. Recommendations

### 4.1 Migrate to the Android Keystore Directly for Highly Sensitive Data

For critical credentials/cryptographic keys, avoid `SharedPreferences` entirely — store them directly in the Android Keystore (refer to the pattern in the MASTG-TEST-0212 document).

### 4.2 Use `EncryptedSharedPreferences` as a Medium-Term Mitigation

```kotlin
val masterKey = MasterKey.Builder(context)
    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
    .build()

val encryptedPrefs = EncryptedSharedPreferences.create(
    context,
    "secure_prefs",
    masterKey,
    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
)
encryptedPrefs.edit().putString("auth_token", token).apply()
```

**Note**: per §1.3, plan a long-term migration given this library's deprecated status.

### 4.3 Exclude Related Files from Backup

Refer to the complete implementation in the MASTG-TEST-0262 document §4 — ensure `data_extraction_rules.xml` excludes `EncryptedSharedPreferences` files from both `<cloud-backup>` and `<device-transfer>`.

### 4.4 Remediation Checklist

- [ ] All calls to `SharedPreferences.Editor.put*()` are inventoried and correlated with encryption operations
- [ ] `shared_prefs/*.xml` files are verified to contain no plaintext secrets (TruffleHog/gitleaks scan)
- [ ] Highly sensitive data is migrated directly to the Android Keystore
- [ ] `EncryptedSharedPreferences` (if used) is configured per recommendations and excluded from backup
- [ ] A long-term migration plan away from the Jetpack Security Crypto library has been considered
- [ ] **Re-verify:** rerun MASTG-TEST-0287 after every change to sensitive data storage

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0287: Runtime Storage of Unencrypted Data via the SharedPreferences API](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0287/)
- [MASTG-TEST-0207: Runtime Storage of Unencrypted Data in the App Sandbox](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0207/)
- [MASTG-TEST-0212: Use of Hardcoded Cryptographic Keys in Code](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0212/)
- [MASTG-TEST-0262: References to Backup Configurations Not Excluding Sensitive Data](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0262/)
- [MASWE-0001: Sensitive Data Stored Unencrypted in Private Storage](https://mas.owasp.org/MASWE/MASVS-STORAGE/MASWE-0001/)
- [MASTG-KNOW-0036: Shared Preferences](https://mas.owasp.org/MASTG/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0036/)
- [MASTG-TECH-0043: Method Hooking](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0043/)
- [MASTG-TECH-0008: Retrieving Files](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0008/)

### 5.2 Official Android Documentation

- [Android Developers — `SharedPreferences` API reference](https://developer.android.com/reference/android/content/SharedPreferences)
- [Android Developers — Use SharedPreferences in private mode](https://developer.android.com/privacy-and-security/security-best-practices#sharedpreferences)
- [Android Developers — `EncryptedSharedPreferences`](https://developer.android.com/reference/androidx/security/crypto/EncryptedSharedPreferences)
- [Android Developers — Cryptography (Jetpack Security Crypto deprecation notice)](https://developer.android.com/privacy-and-security/cryptography#jetpack_security_crypto_library)
- [Android Developers — DataStore](https://developer.android.com/topic/libraries/architecture/datastore)

### 5.3 Tool Documentation

- [TruffleHog — Documentation](https://docs.trufflesecurity.com/)
- [Frida — Dynamic instrumentation toolkit](https://frida.re/docs/javascript-api/)
- [Objection — Runtime Mobile Exploration toolkit](https://github.com/sensepost/objection)
- [CodeQL — Documentation](https://codeql.github.com/docs/)
- [gitleaks](https://github.com/gitleaks/gitleaks)

### 5.4 CWE

- [CWE-312: Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)
- [CWE-311: Missing Encryption of Sensitive Data](https://cwe.mitre.org/data/definitions/311.html)

---

*This document was compiled based on OWASP MASTG (latest release as of September 2026) and official Android Developers documentation. As the API-specific version of MASTG-TEST-0207, this test's unique value lies in the ability of hooking to provide a precise stack trace and direct correlation with surrounding cryptographic operations. An important finding testers should pay attention to: `EncryptedSharedPreferences` — the primary recommended solution for this problem for many years — is now **deprecated** with no direct replacement, creating a transition period in which an application that uses it correctly is still treated as a PASS but should be recommended to plan a long-term migration to a fully supported encryption approach.*
