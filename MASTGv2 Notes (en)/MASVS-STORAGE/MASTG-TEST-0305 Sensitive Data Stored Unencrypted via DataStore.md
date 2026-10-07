# MASTG-TEST-0305 Sensitive Data Stored Unencrypted via DataStore

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0305 |
| **Platform** | Android |
| **MASVS Category** | MASVS-STORAGE (MASVS-STORAGE-1) |
| **Weakness** | MASWE-0001 — *Sensitive Data Stored Unencrypted in Private Storage* |
| **Test Type** | **Static, Dynamic** |
| **Official MASTG Status** | **`placeholder`** — no complete Overview/Steps/Evaluation yet |
| **Official note (the only content available)** | *"This test checks if the app uses the modern Jetpack DataStore API (Preferences DataStore or Proto DataStore) to store sensitive data (e.g., tokens, PII) without encryption. It confirms the absence of secure serializers or mechanisms to protect data integrity and confidentiality."* |
| **Related Tests** | **MASTG-TEST-0287** (SharedPreferences) — DataStore is the **official replacement** Android recommends for SharedPreferences, yet it introduces a **different encryption gap** (see §1.2); **MASTG-TEST-0304** (Room Database) — a similar analysis pattern (two API pathways with different detection requirements) |
| **Related Demo** | — (none) |
| **Official Rule** | — (none) |
| **Related CWE** | CWE-312, CWE-311 |

---

## 1. Explanation

### 1.1 The Status of This Test and Its Position as the "Next Generation" of MASTG-TEST-0287

This test has a **`placeholder`** status, but its position within the chain of Android data storage evaluations is very clear: **Jetpack DataStore** is Google's officially recommended replacement for **`SharedPreferences`** (discussed in depth in the **MASTG-TEST-0287** document in this research series) — this fact is even explicitly noted in **MASTG-KNOW-0036**, which that document references: *"Android recommends `DataStore` as a modern replacement for `SharedPreferences`."* Following the industry-wide migration trend toward DataStore, this test exists as an **equivalent evaluation** for this new-generation storage mechanism.

### 1.2 The Most Critical Finding: DataStore Has No Equivalent to `EncryptedSharedPreferences` Whatsoever

This is the **most important nuance** in this document, and it creates a significant **migration paradox** for development teams. Community research explicitly states:

> *"DataStore has a lack of built-in encryption, which `EncryptedSharedPreferences` previously provided. By default, when persisting data to device storage the DataStore library does not encrypt it."*

This creates a situation that is **ironic** when placed alongside the nuance already discussed in depth in the MASTG-TEST-0287 document — there it was explained that `EncryptedSharedPreferences` is now **deprecated**, and official guidance suggests migrating to a more modern approach. However, **DataStore — the official migration target for `SharedPreferences` in general — provides no built-in encryption mechanism whatsoever**, for either the **Preferences DataStore** or **Proto DataStore** variant. A developer who **follows Android's official recommendation** to migrate from `SharedPreferences`/`EncryptedSharedPreferences` to DataStore, **without being aware of this gap**, risks **unintentionally lowering the security level** of their sensitive data storage — from "encrypted" (albeit through a now-deprecated library) to "entirely unencrypted" (a modern, recommended API, but plain with no encryption whatsoever by default).

### 1.3 Two DataStore Variants and Their Implications for Encryption Feasibility

Community research explains the fundamental difference between the two DataStore variants relevant to an encryption strategy:

> *"Preferences DataStore stores and accesses data using keys without a predefined schema and without type safety, while Proto DataStore stores data as instances of a custom data type and requires you to define a schema using protocol buffers but provides type safety."*

| Variant | Data Schema | Encryption Integration Feasibility |
|---|---|---|
| **Preferences DataStore** | Key-value without a fixed schema (similar to `SharedPreferences`) | **Limited** — its serializer API is not designed to flexibly inject custom encryption logic |
| **Proto DataStore** | Developer-defined Protocol Buffers schema, type-safe | **Feasible** — via a custom `Serializer<T>` into which encryption/decryption logic can be manually inserted |

This crucial point means: **the choice of DataStore variant a developer uses directly limits the available mitigation options**. An application already using Preferences DataStore for sensitive data has a far harder mitigation path than one using Proto DataStore — an architectural consideration that ideally should have been thought through **from the moment the variant was chosen**, rather than patched in afterward.

### 1.4 Mitigation Mechanism: Custom `Serializer` on Proto DataStore

For Proto DataStore, the encryption mechanism **must be manually implemented** by the developer via the `Serializer<T>` interface — Proto DataStore calls this serializer's `readFrom()`/`writeTo()` methods every time it reads/writes data to disk, allowing the developer to **insert an encryption/decryption step** at exactly that point:

```kotlin
object EncryptedUserPrefsSerializer : Serializer<UserPrefs> {
    override val defaultValue: UserPrefs = UserPrefs.getDefaultInstance()

    override suspend fun readFrom(input: InputStream): UserPrefs {
        val decryptedBytes = decryptWithKeystore(input.readBytes())  // Decrypt BEFORE parsing
        return UserPrefs.parseFrom(decryptedBytes)
    }

    override suspend fun writeTo(t: UserPrefs, output: OutputStream) {
        val encryptedBytes = encryptWithKeystore(t.toByteArray())  // Encrypt BEFORE writing to disk
        output.write(encryptedBytes)
    }
}
```

**No equivalent mechanism** is natively available for Preferences DataStore — which is why Proto DataStore becomes **the only realistic pathway** for securing sensitive data within the DataStore ecosystem.

### 1.5 Current Official Recommendation: Google Tink, Not Jetpack Security Crypto

Community research points to the latest relevant official mitigation direction, complementing the deprecation nuance already discussed in the MASTG-TEST-0287 document:

> *"Google deprecated Jetpack Security's cryptography APIs (`EncryptedSharedPreferences`/`EncryptedFile`) and now recommends moving to **Tink**, which offers a consistent, secure, and upgradeable cryptography layer that is independent from device-specific Android behavior."*

**Google Tink** is a multi-platform cryptography library (developed by Google's security team) that is now the **primary recommendation** for local data encryption needs on Android — used as the encryption layer inside a Proto DataStore custom `Serializer` following the pattern in §1.4. There is also an **official reference implementation** for migrating from the deprecated `EncryptedSharedPreferences` directly to a Tink-secured Proto DataStore — showing that the **correct migration path** has indeed been mapped out by Google, albeit requiring much more manual implementation work than a drop-in solution like `EncryptedSharedPreferences` used to be.

### 1.6 Why This Test Type Is Both Static AND Dynamic

Unlike many other tests that are purely static or purely dynamic, this test's frontmatter explicitly marks **both** types (`[static, dynamic]`). This makes sense given the nature of DataStore:

- **Static**: examining the code for the presence of a custom `Serializer` that implements encryption (or its absence) — similar to the analysis pattern in MASTG-TEST-0304.
- **Dynamic**: DataStore ultimately stores data in a file (Preferences DataStore as XML under `datastore/`, Proto DataStore as a binary protobuf) — verifying the **actual file contents** on the device remains necessary as definitive proof, just as in the MASTG-TEST-0287/0304 patterns, because code that "appears" to encrypt can still fail in its actual implementation.

---

## 2. Tools Used for Testing

### 2.1 Required Tools (Core)

| Tool | Function |
|---|---|
| **jadx** | DEX → Java/Kotlin-like decompilation for searching DataStore and custom `Serializer` patterns |
| **grep / ripgrep** | API pattern searches |
| **adb** | Extracting DataStore files from the device for direct verification |

### 2.2 Alternative & Supporting Tools

| Tool | Function |
|---|---|
| **CodeQL** | Tracing custom `Serializer<T>` implementations and verifying whether `readFrom()`/`writeTo()` actually calls cryptographic operations (`Cipher`, Tink `Aead`) |
| **protoc / Proto DataStore tooling** | For examining the `.proto` schema used and assessing whether sensitive fields can be identified from the schema's field names |
| **strings / hexdump** | Examining the raw DataStore file contents to detect directly readable plaintext strings |
| **TruffleHog/gitleaks** | Secret pattern scanning on the extracted DataStore file |

### 2.3 Environment Prerequisites

- **No device/root required** for the core static analysis.
- **Root/`run-as` required** for direct extraction of DataStore files from `/data/data/<package>/datastore/` or `/data/data/<package>/files/datastore/` (the location may vary depending on configuration).
- **Identifying the DataStore variant used** (Preferences vs. Proto) is a mandatory first step, as it determines the realistic mitigation pathway (§1.3).

---

## 3. Testing Methodology

Since there are no detailed official steps (placeholder status), the following methodology is composed from an elaboration of the official note and an understanding of DataStore's architecture.

### 3.1 General Steps

1. Identify all uses of DataStore (Preferences or Proto) within the codebase.
2. For Proto DataStore: check whether the custom `Serializer` used actually implements encryption.
3. For Preferences DataStore: flag it as **automatically high-risk** if it stores sensitive data, since no native mitigation pathway is available (§1.3).
4. Extract and verify the DataStore file directly from the device.

### 3.2 Method A — grep/ripgrep

```bash
D=./decompiled/sources

# Find uses of Preferences DataStore
rg -n 'preferencesDataStore\(|PreferenceDataStoreFactory' $D

# Find uses of Proto DataStore and custom Serializers
rg -n 'DataStoreFactory\.create\(|: Serializer<' $D

# Verify whether the custom Serializer calls cryptographic operations
rg -n -A15 'object \w+Serializer\s*:\s*Serializer<' $D | grep -c "Cipher\|Aead\|encrypt\|decrypt"
```

### 3.3 Method B — CodeQL to Verify the Serializer's Contents

```ql
import java

class CustomSerializer extends Class {
  CustomSerializer() {
    this.getAnInterface().hasQualifiedName("androidx.datastore.core", "Serializer")
  }
}

class CryptoOperation extends MethodAccess {
  CryptoOperation() {
    this.getMethod().getDeclaringType().hasQualifiedName("javax.crypto", "Cipher") or
    this.getMethod().getDeclaringType().getName().matches("%Aead%")  // Google Tink
  }
}

from CustomSerializer serializer
where not exists(CryptoOperation op | op.getEnclosingCallable().getDeclaringType() = serializer)
select serializer, "Custom DataStore Serializer found WITHOUT any cryptographic operation — data is likely unencrypted"
```

### 3.4 Method C — Direct Verification of the DataStore File (Definitive Evidence)

```bash
adb shell run-as com.target.app find /data/data/com.target.app -path "*datastore*"
adb shell run-as com.target.app cat /data/data/com.target.app/files/datastore/user_prefs.preferences_pb > ./dump.bin

# Check whether the contents can be read as plain text
strings ./dump.bin | grep -iE "token|password|email"
hexdump -C ./dump.bin | head -30
```

If `strings`/`hexdump` shows values that are **clearly readable as human text** (rather than random binary data consistent with encrypted output), this is strong evidence that the data is stored without encryption.

### 3.5 Method Comparison: When to Use Which

| Method | Tool | When to use |
|---|---|---|
| **A** | grep | Baseline, identifying the DataStore variant and the presence of a custom Serializer |
| **B** | CodeQL | Systematic verification of whether the Serializer actually performs encryption |
| **C** | Direct file verification | **Definitive evidence**, especially for cases where the implementation "looks" correct but fails in practice |

**Recommended minimum combination:** **A (identify the variant + Serializer) → B (verify the Serializer's contents) → C (definitive evidence from the raw file)**.

---

### 3.6 Evaluation Criteria: Positive Case & Negative Case

Since there is no official Evaluation clause (placeholder status), the following criteria are composed based on the official note and the fundamental principles of MASWE-0001.

---

#### ❌ FAIL / ISSUE — The check is declared FAILED when:

| No | Condition |
|---|---|
| F1 | The application uses **Preferences DataStore** to store sensitive data (credentials, tokens, PII) — automatically high-risk since no native mitigation pathway exists (§1.3) |
| F2 | The application uses **Proto DataStore** with a custom `Serializer` that does **not** implement any encryption |
| F3 | Direct verification of the DataStore file (Method C) confirms the data is stored as directly readable text |

---

#### ✅ PASS — The check is declared PASSED when:

| No | Condition |
|---|---|
| P1 | The application uses **Proto DataStore** with a custom `Serializer` verified to correctly implement encryption (Tink/Android Keystore) |
| P2 | Direct verification of the DataStore file confirms the data is stored as binary ciphertext, unreadable as text |
| P3 | The application does not store any sensitive data via DataStore at all |

---

#### ⚠️ Important Notes on Assessment

1. **Preferences DataStore storing sensitive data is by default a strong FAIL signal** — since there is no realistic native mitigation pathway, unlike Proto DataStore which at least **allows** mitigation via a custom `Serializer`.

2. **Do not conclude PASS merely because a custom `Serializer` is found** — many custom `Serializer`s are created solely for data format serialization (not for security); verify that the `readFrom()`/`writeTo()` methods actually call cryptographic operations (Method B/C).

3. **Correlate with the MASTG-TEST-0287 document** for full context — the irony of the SharedPreferences → DataStore migration (§1.2) is an important finding worth highlighting in audit reports if an organization is in the middle of, or has just completed, such a migration.

4. **Severity modulation:**

   | Factor | Severity |
   |---|---|
   | Preferences DataStore stores plaintext credentials/tokens | **Critical** |
   | Proto DataStore without encryption stores sensitive data | **High** |
   | Proto DataStore with verified correct encryption | **No finding** |

5. **Document:** the DataStore variant used, the implementation status of the `Serializer` (if Proto), the raw file verification results, and correlation with the MASTG-TEST-0287 audit results.

---

## 4. Recommendations

### 4.1 Migrate to Proto DataStore with Tink (If Still Using Preferences DataStore for Sensitive Data)

```kotlin
// build.gradle
implementation "com.google.crypto.tink:tink-android:1.13.0"
```

```kotlin
object EncryptedSerializer : Serializer<SensitiveData> {
    private val aead: Aead by lazy { /* initialize Tink Aead via Android Keystore */ }

    override val defaultValue: SensitiveData = SensitiveData.getDefaultInstance()

    override suspend fun readFrom(input: InputStream): SensitiveData {
        val ciphertext = input.readBytes()
        val plaintext = aead.decrypt(ciphertext, null)
        return SensitiveData.parseFrom(plaintext)
    }

    override suspend fun writeTo(t: SensitiveData, output: OutputStream) {
        val plaintext = t.toByteArray()
        val ciphertext = aead.encrypt(plaintext, null)
        output.write(ciphertext)
    }
}
```

### 4.2 Consider Still Using the Android Keystore Directly for Highly Sensitive Data

For the most critical credentials/cryptographic keys, consider not using DataStore at all — store them directly in the Android Keystore (refer to the pattern in the MASTG-TEST-0212/0287 documents).

### 4.3 Remediation Checklist

- [ ] The DataStore variant used by the application is identified (Preferences/Proto)
- [ ] Sensitive data stored via Preferences DataStore is migrated to Proto DataStore + Tink, or directly to the Android Keystore
- [ ] The custom `Serializer` is verified to actually perform encryption, not merely format serialization
- [ ] Direct verification of the DataStore file confirms no readable plaintext data exists
- [ ] **Re-verify:** rerun MASTG-TEST-0305 after every addition of new sensitive data storage via DataStore

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0305: Sensitive Data Stored Unencrypted via DataStore](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0305/)
- [MASTG-TEST-0287: Runtime Storage of Unencrypted Data via the SharedPreferences API](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0287/)
- [MASTG-TEST-0304: References to Sensitive Data Unencrypted via Android Room Database](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0304/)
- [MASWE-0001: Sensitive Data Stored Unencrypted in Private Storage](https://mas.owasp.org/MASWE/MASVS-STORAGE/MASWE-0001/)
- [MASTG-KNOW-0036: Shared Preferences](https://mas.owasp.org/MASTG/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0036/)

### 5.2 Official Android Documentation

- [Android Developers — DataStore](https://developer.android.com/topic/libraries/architecture/datastore)
- [Android Developers — DataStore Releases](https://developer.android.com/jetpack/androidx/releases/datastore)
- [Android Developers — Cryptography (Jetpack Security Crypto deprecation, Tink)](https://developer.android.com/privacy-and-security/cryptography)
- [Google Tink](https://developers.google.com/tink)

### 5.3 Research and Community Articles

- [Medium — Goodbye SharedPreferences: The Future of Android Data Storage with DataStore & Keystore](https://medium.com/@mahesh31.ambekar/the-modern-android-storage-stack-datastore-and-keystore-29f54572aa08)
- [DEV Community — Beyond Preferences](https://dev.to/tkuenneth/beyond-preferences-1fh2)
- [Styling Android — DataStore: Security](https://blog.stylingandroid.com/datastore-security/)
- [Medium ne-digital — Jetpack DataStore Evaluation: Journey to Find an Alternative Secure Storage](https://medium.com/ne-digital/jetpack-datastore-evaluation-aefb65260a30)
- [droidcon — Unpacking Android Security Part 2: Insecure Data Storage](https://www.droidcon.com/2022/06/15/unpacking-android-security-part-2-insecure-data-storage/)
- [CWE-312: Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)

### 5.4 Tool Documentation

- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [CodeQL — Documentation](https://codeql.github.com/docs/)
- [TruffleHog](https://docs.trufflesecurity.com/)

---

*This document was compiled entirely from independent research because MASTG-TEST-0305 has a **placeholder** status. The most significant finding: **Jetpack DataStore — Android's officially recommended replacement for `SharedPreferences` — provides no built-in encryption mechanism whatsoever**, creating a migration paradox where a developer following the official recommendation to move from `SharedPreferences`/`EncryptedSharedPreferences` (now deprecated) to DataStore risks unknowingly lowering the security level of their sensitive data storage. Mitigation is only realistically achievable via Proto DataStore (not Preferences DataStore) with a custom `Serializer` that integrates Google Tink — a path far more complex than the drop-in solution `EncryptedSharedPreferences` once provided.*
