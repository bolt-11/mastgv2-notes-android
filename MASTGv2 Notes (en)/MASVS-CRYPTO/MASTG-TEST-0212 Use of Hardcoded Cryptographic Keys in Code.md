# MASTG-TEST-0212 Use of Hardcoded Cryptographic Keys in Code

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0212 |
| **Platform** | Android |
| **MASVS Category** | **MASVS-CRYPTO** (MASVS-CRYPTO-1: The app uses up-to-date, correctly implemented cryptography) |
| **Weakness** | **MASWE-0003** — *Cryptographic Keys Stored Outside of Platform Keystore* |
| **Test Type** | **Static**, Code |
| **Profile** | L1, L2 |
| **Knowledge** | MASTG-KNOW-0012 (Key Generation) |
| **Related Techniques** | MASTG-TECH-0013 (Reverse Engineering Android Apps), MASTG-TECH-0014 (Static Analysis on Android), MASTG-TECH-0023 (Reviewing Decompiled Java Code) |
| **Related Demo** | MASTG-DEMO-0017 (Use of Hardcoded AES Key in SecretKeySpec with semgrep) |
| **Key API** | `javax.crypto.spec.SecretKeySpec` (creates a `SecretKey` from a byte array) |
| **Related CWE** | CWE-321 (Use of Hard-coded Cryptographic Key), CWE-798 (Use of Hard-coded Credentials), CWE-259 (Use of Hard-coded Password), CWE-547 (Use of Hard-coded, Security-relevant Constants), CWE-922 (Insecure Storage of Sensitive Information) |
| **Principle Violated** | **Kerckhoffs's principle** — the security of a system must not depend on the secrecy of its algorithm/implementation, only on the secrecy of the key |

---

## 1. Explanation

### 1.1 Testing Objective

This test looks for the **use of hardcoded cryptographic keys** within an Android application through static analysis.

Direct quote from the MASTG overview:

> *"In this test case, we will look for the use of hardcoded keys in Android applications. To do this, we need to focus on the cryptographic implementations of hardcoded keys. The Java Cryptography Architecture (JCA) provides the `SecretKeySpec` class, which allows you to create a `SecretKey` from a **byte array**."*

So the focal point is **`SecretKeySpec`** — the class that acts as a "bridge" between a plain byte array and a `SecretKey` object usable by `Cipher`. Any time a key originates from a literal byte array, that is where this weakness appears.

### 1.2 Why This Always Fails: A Key Inside the APK Is Not a Secret

Mobile applications are **distributed to the attacker**. This is a fundamental difference from server applications: everyone who installs the app has a complete copy of its code and can decompile it at any time, without time limits or detection.

Android documentation asserts that hardcoded cryptographic secrets **violate Kerckhoffs's principle** and break the entire security model:

> *"Developers commonly hardcode secrets as strings, byte arrays, or in asset files like `strings.xml`, making them **easily retrievable through reverse engineering**."*

According to Android documentation, the impact includes:
- **Attacker access** — reverse engineering tools can easily extract hardcoded secrets
- **Security breach** — unauthorized access to sensitive data
- **Compromised encryption** — **the entire cryptographic security model is broken**

Practical consequences worth understanding:

| Consequence | Explanation |
|---|---|
| **The key applies to ALL users** | One hardcoded key = one key for the entire user base. Extracting the key from a single device opens up every user's data |
| **Cannot be rotated without an app update** | If the key leaks, the only fix is to release a new version — and users who haven't updated remain vulnerable |
| **Historical data stays exposed** | Data already encrypted with that key does not become safe again after rotation |
| **Obfuscation doesn't help** | Hiding the key only adds one extra step; the key still has to sit in memory when used, so it can be dumped with Frida |
| **The backend is also exposed** | If the hardcoded key is a backend API key/secret, an attacker can abuse the paid service on the app's behalf |

**The scale of the problem in the real world:** research shows hardcoded secrets remain a very common finding. The *Leaky Apps* study (ACM CCS 2025) performed a large-scale analysis of API keys and cryptographic material in Android and iOS applications. Scanning 30,000 apps found **2,772 apps exposing at least one secret that could be directly correlated**. Hardcoded API keys are consistently cited as the **number one finding in mobile pentests**.

### 1.3 The Weakness Is Broader than the Test Title: MASWE-0003

This is an important nuance that is easy to miss. The test title is *"Use of Hardcoded Cryptographic Keys in **Code**"*, but the mapped weakness is **MASWE-0003: *Cryptographic Keys Stored Outside of Platform Keystore***.

This means the real problem is not merely "the key is written in code," but rather **"the key is not managed by the platform keystore."** This broadens what you need to check:

| Form | Included in MASWE-0003? |
|---|---|
| Key as a literal byte array in code | ✅ Yes — the main focus of this test |
| Key as a string literal (`"my secret".toByteArray()`) | ✅ Yes |
| Key in `strings.xml` / `res/raw/` / `assets/` | ✅ Yes |
| Key in `BuildConfig` (from `gradle.properties`) | ✅ Yes — still ends up in the APK |
| Key in native code (`.so`) | ✅ Yes |
| Key Base64/XOR/obfuscated inside the APK | ✅ Yes — obfuscation is not protection |
| Key stored in plaintext in `SharedPreferences`/sandbox file | ✅ Yes (also MASWE-0001 / MASTG-TEST-0207) |
| Key derived from a static value (IMEI, package name, timestamp) | ✅ Yes (also MASTG-TEST-0205) |
| Key generated with `SecureRandom` then stored unencrypted in a file | ✅ Yes — not hardcoded, but still outside the keystore |
| Key generated & stored in the **Android KeyStore** | ❌ No — this is the remediation target |

So the remediation direction is clear and singular: **move key management to the Android KeyStore** (or KeyChain for system credentials), not merely "hide the key better."

### 1.4 Where Hardcoded Keys Hide

Static analysis of Java code alone is not enough. Here is a map of the locations that need to be swept:

| Location | How to check |
|---|---|
| **Byte array / string literal in code** | MASTG semgrep rule (primary focus) |
| **`res/values/strings.xml`** | `grep` on the apktool output; long Base64/hex-style values |
| **`res/raw/`, `assets/`** | `.key`, `.pem`, `.jks`, `.bks`, `.p12`, `.properties`, `.json`, `.cfg` files |
| **`BuildConfig`** | Fields from `buildConfigField` — often populated from `gradle.properties` and **still end up in the APK as constants** |
| **`AndroidManifest.xml` `<meta-data>`** | API keys are often placed here (e.g., Maps API key) |
| **`google-services.json` / Firebase** | Firebase config; some values are indeed public, but check whether a server key is present |
| **Native code (`.so`)** | `strings` + Ghidra. **A total blind spot for Java rules.** Remember the MASTG-KNOW-0012 warning: hiding keys in the NDK is **ineffective** |
| **Split/obfuscated strings** | String concatenation, char arrays, runtime XOR, decoding in `<clinit>` |
| **Encoded strings** | Base64, hex, ROT13 — look for long strings then decode them |
| **Bundled keystore/certificates** | `.jks`/`.bks`/`.p12` along with their passwords, which are also often hardcoded |
| **Code loaded at runtime** | Downloaded DEX/JS bundles — require dynamic analysis |
| **Third-party libraries** | SDKs that ship with default/demo keys |

### 1.5 "Fake Encryption" Patterns That Are Commonly Found

Three patterns that look safe but are actually equivalent to a hardcoded key:

```kotlin
// ❌ 1. Hardcoded key that is "obfuscated" — still hardcoded
val part1 = "aX9k"; val part2 = "mQ2v"; val part3 = "T7pL"
val key = SecretKeySpec((part1 + part2 + part3).toByteArray(), "AES")

// ❌ 2. Hardcoded key that is XOR'd — the XOR key is also hardcoded
val enc = byteArrayOf(0x3A, 0x1F, 0x77, ...)
val key = SecretKeySpec(enc.map { (it.toInt() xor 0x5A).toByte() }.toByteArray(), "AES")

// ❌ 3. Key "derived" from a static value known to the attacker
val key = SecretKeySpec(
    MessageDigest.getInstance("SHA-256")
        .digest((context.packageName + Build.SERIAL).toByteArray()),
    "AES"
)
// Deterministic & reproducible -> equivalent to hardcoded (linked to MASTG-TEST-0205)
```

For the third pattern, the same principle applies as in MASTG-TEST-0205: **hashing does not add entropy**. `sha256(packageName + serial)` looks like a random 256-bit key, but an attacker only needs to reproduce the inputs.

---

## 2. Tools Used for Testing

### 2.1 Required Tools (Core)

| Tool | MASTG ID | Function in this test |
|---|---|---|
| **jadx** | MASTG-TOOL-0018 | **Decompiles DEX → Java** (MASTG-TECH-0013). Also required for MASTG-TECH-0023 — to determine whether the key is truly hardcoded and used in a sensitive context |
| **semgrep** | MASTG-TOOL-0110 | **Pattern matching**. MASTG provides the rule `mastg-android-hardcoded-crypto-keys-usage.yml` |
| **apktool** | MASTG-TOOL-0011 | **Important for this test** — decodes resources (`strings.xml`, `res/raw/`) that are not visible in jadx `--no-res` |
| **grep / ripgrep** | — | **Mandatory supplement** — the MASTG rule covers only `SecretKeySpec` |

### 2.2 Supporting Tools (Highly Relevant for This Test)

| Tool | Function |
|---|---|
| **apkleaks** | **MASTG-TOOL-0125.** Decompiles the APK with jadx then scans for hardcoded secrets, API keys, URIs, and endpoints using 50+ regex patterns (AWS access key, Google API key, JWT, Firebase URL, etc.). The most targeted tool for this test |
| **TruffleHog** | Secret detection via **entropy analysis** + active verification: if a string looks like a live key for some service, TruffleHog **calls that service's API** to verify whether the key is valid. This turns a finding from "suspected" into "proven live" |
| **gitleaks** | Regex + entropy-based alternative |
| **MobSF** | Comprehensive static analysis; flags hardcoded secrets in code and resources |
| **mobsfscan** | Semgrep-based mobile SAST; has a hardcoded key rule |
| **nuclei** (mobile/secret templates) | Scans for secret patterns in extracted files |
| **SonarQube** | Rule `java:S6418` — *Hard-coded secrets are security-sensitive*; `java:S2068` — hard-coded credentials |
| **CodeQL** | Taint analysis — tracks whether a constant actually flows into a crypto API (reduces false positives from the semgrep rule) |
| **jadx-gui** | "Find Usage" + global string search — for tracing split constants and strings |
| **Frida** | MASTG-TOOL-0001 — **the strongest dynamic confirmation** (see §3.5). Hook `SecretKeySpec.$init` and `Cipher.init` to dump the **actual** key at runtime, cutting through obfuscation, string-splitting, and native code |
| **Ghidra / `strings`** | Analysis of `.so` files — keys in native code |
| **`ent` / entropy analysis** | Filters candidates: high-entropy strings are more likely to be keys |
| **`keytool` / `openssl`** | Inspecting keystores & certificates bundled in the APK |
| **APKiD** | Packer/obfuscator detection to assess the reliability of the static analysis |

### 2.3 Environment Prerequisites

- **No device and no root required** for the static portion — the APK file is enough. Easy to automate in CI/CD.
- **The complete APK**, including all split APKs / dynamic feature modules.
- **Decode resources too, not just code.** Run `apktool d` (without `-s`) so that `strings.xml` and `res/raw/` are readable. This is often where keys hide and **will not be found** if you only scan `./decompiled/sources/`.
- **The rule is `languages: java` only** — scanning is performed on the decompiled code.
- **Be aware of how decompilation affects literals.** In Kotlin source, a byte array is written as `byteArrayOf(0x6C, 0x61, ...)` (hexadecimal); in the decompiled Java it becomes **decimal** `{108, 97, ...}`. The MASTG rule matches the structure `byte[] $KEY = {...}`, so it works on both forms — but when doing a manual `grep`, search for **both notations**.
- **Prepare Frida for confirmation.** For apps protected by an obfuscator/packer, static analysis will be incomplete; hooking is the most reliable path.
- **Satisfy context first.** The evaluation criteria require the key to be *"used in security-sensitive contexts"*, so you need to know what the app is protecting.

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0013** (*Reverse Engineering Android Apps*) to reverse engineer the application.
2. Use **MASTG-TECH-0014** (*Static Analysis on Android*) to search for the relevant APIs.

For evaluation: use **MASTG-TECH-0023** (*Reviewing Decompiled Java Code*) to review each location found.

### 3.2 Practical Implementation (MASTG-DEMO-0017)

**Step 1 — Decompile code AND resources**

```bash
# Code
jadx -d ./decompiled ./target-app.apk

# Resources (MANDATORY — strings.xml, res/raw, assets)
apktool d -f -o ./decoded ./target-app.apk

# Raw extraction for binary assets & .so files
unzip -o ./target-app.apk -d ./apk_x >/dev/null
```

**Step 2 — Run the official MASTG semgrep rule**

The `mastg-android-hardcoded-crypto-keys-usage.yml` rule:

```yaml
rules:
  - id: mastg-android-hardcoded-crypto-keys-usage
    severity: WARNING
    languages:
      - java
    metadata:
      summary: This rule looks for hardcoded keys in use.
    message: "[MASVS-CRYPTO-1] Hardcoded cryptographic keys found in use."
    pattern-either:
      - pattern: SecretKeySpec $_ = new SecretKeySpec($KEY, $ALGO);
      - pattern: |-
          byte[] $KEY = {...};
          ...
          new SecretKeySpec($KEY, $ALGO);
```

Running it (`run.sh` from the demo):

```bash
NO_COLOR=true semgrep -c ../../../../rules/mastg-android-hardcoded-crypto-keys-usage.yml \
  ./MastgTest_reversed.java > output.txt
```

For a real application:

```bash
NO_COLOR=true semgrep \
  -c ./mastg/rules/mastg-android-hardcoded-crypto-keys-usage.yml \
  ./decompiled/sources/ --json -o findings-hardcoded-keys.json
```

**Step 3 — Run dedicated secret scanners (a very useful supplement)**

```bash
# apkleaks (MASTG-TOOL-0125) — 50+ regex patterns for secrets & endpoints
apkleaks -f ./target-app.apk -o apkleaks-report.txt

# TruffleHog — entropy + ACTIVE verification against the service's API
trufflehog filesystem ./decompiled ./decoded --results=verified,unknown

# gitleaks
gitleaks detect --no-git -s ./decompiled -r gitleaks.json
```

**Step 4 — Review each finding (MASTG-TECH-0023)**

For each location, answer four questions:

1. **Is the value really hardcoded?** (a literal, or does it come from the KeyStore/PBKDF2/server?) — this is crucial because the MASTG rule produces many false positives (§3.4).
2. **What is this key used for?** Encrypting data at rest, HMAC, token signing, or just test/demo code?
3. **Is the context security-sensitive?** This is an explicit requirement in the evaluation criteria.
4. **Is there another key** in resources/native code that hasn't been caught yet?

### 3.3 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rule:**

> **Observation:** *"The output should contain a list of locations where hardcoded keys are used."*
>
> **Evaluation:** *"The test case **fails** if you find any hardcoded keys that are **used in security-sensitive contexts**."*

Note the qualification **"used in security-sensitive contexts"** — just as with MASTG-TEST-0204/0205. A hardcoded key in test/demo code, or a constant that is not a cryptographic key, is not a finding.

---

#### ❌ FAIL / ISSUE — The check is declared FAILED when:

| No | Condition | Example evidence |
|---|---|---|
| F1 | A **byte array literal** is used as a cryptographic key | `byte[] keyBytes = {108, 97, 107, ...}; new SecretKeySpec(keyBytes, "AES")` |
| F2 | A **string literal** is converted into a key | `SecretKeySpec("my secret here".toByteArray(), "AES")` |
| F3 | A hardcoded key is used for **encrypting sensitive data** | `cipher.init(ENCRYPT_MODE, hardcodedKey)` on user data |
| F4 | A hardcoded key is used for **HMAC / signing / token verification** | `Mac.getInstance("HmacSHA256").init(new SecretKeySpec("secret".getBytes(), "HmacSHA256"))` |
| F5 | A **hardcoded IV** together with a hardcoded key | `new IvParameterSpec("1234567890123456".getBytes())` — worsens F1/F2 |
| F6 | A key/secret in **`strings.xml`** or another resource | `<string name="api_secret">sk_live_...</string>` |
| F7 | A key in **`assets/` or `res/raw/`** | `assets/private.pem`, `res/raw/keystore.bks` + hardcoded password |
| F8 | A key in **`BuildConfig`** | `BuildConfig.API_SECRET` — from `gradle.properties`, still ends up in the APK as a constant |
| F9 | A key in **`AndroidManifest.xml` `<meta-data>`** | API key for a paid service |
| F10 | A hardcoded key in **native code** | `strings lib.so` → key-style string; confirmed with Ghidra. **A blind spot for the rule** |
| F11 | A hardcoded key that is **obfuscated / split / XOR'd / Base64-encoded** | String concatenation, char array, decoding in `<clinit>` — still hardcoded |
| F12 | A key **derived from a static value** known to the attacker | `sha256(packageName + Build.SERIAL)` — deterministic (linked to MASTG-TEST-0205) |
| F13 | A **hardcoded keystore password** | `keyStore.load(inputStream, "changeit".toCharArray())` |
| F14 | A **hardcoded PBKDF2 salt** that makes the derived key deterministic across users | `PBEKeySpec(pw, "fixedsalt".toByteArray(), 10000, 256)` |
| F15 | A key is correctly generated but **stored outside the KeyStore** without protection | `SecureRandom` → stored in plaintext in `SharedPreferences` (also MASWE-0001) |
| F16 | A hardcoded key is **logged or displayed in the UI** | `Log.d(TAG, Base64.encodeToString(key.encoded, ...))` — worsens the issue (linked to MASTG-TEST-0203) |
| F17 | Active verification (e.g., TruffleHog) proves **the secret is still valid/live** | A third-party service key confirmed active → **critical severity** |

**Example output signaling a FAIL — MASTG-DEMO-0017:**

Sample code (`MastgTest.kt`):

```kotlin
fun mastgTest(): String {

    // Bad: Use of a hardcoded key (from bytes) for encryption
    val keyBytes = byteArrayOf(0x6C, 0x61, 0x6B, 0x64, 0x73, 0x6C, 0x6A, 0x6B,
                               0x61, 0x6C, 0x6B, 0x6A, 0x6C, 0x6B, 0x6C, 0x73)
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    val secretKey = SecretKeySpec(keyBytes, "AES")
    cipher.init(Cipher.ENCRYPT_MODE, secretKey)

    // Bad: Hardcoded key directly in code (security risk)
    val badSecretKeySpec = SecretKeySpec("my secret here".toByteArray(), "AES")

    return "SUCCESS!!\n\n... Hardcoded AES Encryption Key: " +
           "${Base64.encodeToString(keyBytes, Base64.DEFAULT)}\n" +
           "Hardcoded Key from string: ${Base64.encodeToString(badSecretKeySpec.encoded, Base64.DEFAULT)}\n"
}
```

Decompiled code scanned by semgrep (`MastgTest_reversed.java`):

```java
public final String mastgTest() {
    byte[] keyBytes = {108, 97, 107, 100, 115, 108, 106, 107,
                       97, 108, 107, 106, 108, 107, 108, 115};      // <-- line 24
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");        // <-- line 25
    SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");   // <-- line 26
    cipher.init(1, secretKey);
    byte[] bytes = "my secret here".getBytes(Charsets.UTF_8);
    SecretKeySpec badSecretKeySpec = new SecretKeySpec(bytes, "AES"); // <-- line 30
    return "SUCCESS!!..." + Base64.encodeToString(keyBytes, 0) + ...;
}
```

Semgrep output (`output.txt`):

```
┌─────────────────┐
│ 3 Code Findings │
└─────────────────┘

    MastgTest_reversed.java
    ❯❱ rules.mastg-android-hardcoded-crypto-keys-usage
          [MASVS-CRYPTO-1] Hardcoded cryptographic keys found in use.

           24┆ byte[] keyBytes = {108, 97, 107, 100, 115, 108, 106, 107, 97, 108, 107, 106, 108, 107, 108,
               115};
           25┆ Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
           26┆ SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");
            ⋮┆----------------------------------------
           26┆ SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");
            ⋮┆----------------------------------------
           30┆ SecretKeySpec badSecretKeySpec = new SecretKeySpec(bytes, "AES");
```

MASTG evaluation:

> *"The test **fails** because hardcoded cryptographic keys are present in the code. Specifically:*
> - *On **line 24**, a byte array that represents a cryptographic key is directly hardcoded into the source code.*
> - *This hardcoded key is then used on **line 26** to create a `SecretKeySpec`.*
> - *Additionally, on **line 30**, another instance of hardcoded data is used to create a separate `SecretKeySpec`."*

**Six technical observations from this demo:**

1. **There are 3 findings, but only 2 keys.** Line 26 is reported **twice** — once by the second pattern (which spans lines 24–26 because it requires `byte[] $KEY = {...}` to precede it) and once by the first pattern (`SecretKeySpec $_ = new SecretKeySpec(...)`). **Don't double-count** when reporting the number of findings.

2. **A byte array that looks random turns out to be readable ASCII.** Decoding `{108, 97, 107, 100, 115, 108, 106, 107, 97, 108, 107, 106, 108, 107, 108, 115}` gives **`"lakdsljkalkjlkls"`**. This is a very common pattern in real applications: a developer typed something random on the keyboard, and the result *looks* like binary data in the decompiled code but is actually a low-entropy ASCII string. **Always decode found byte arrays to ASCII** — this strengthens the evidence in a report and sometimes reveals a meaningful word or phrase.

3. **The first key is 16 bytes long = AES-128** — so this sample **simultaneously fails MASTG-TEST-0208** (Insufficient Key Sizes, which judges AES-128 as inadequate). A good example that a single piece of code can trigger multiple MASVS-CRYPTO tests.

4. **The second key (`"my secret here"`) is 14 bytes long** — not 16/24/32, so it is **not a valid AES key length**. If `badSecretKeySpec` were actually used in `cipher.init()`, it would throw an `InvalidKeyException`. In this sample it is not used for encryption, only encoded to Base64 for display. This marks `badSecretKeySpec` as a **key that is formed but not used** — in a real application assessment, this condition needs to be checked: is the key truly used in a sensitive context, or is it just leftover code?

5. **The sample also leaks the key via the application's output** — `Base64.encodeToString(keyBytes, ...)` is returned to the UI. In real applications the same pattern (e.g., `Log.d` with `key.encoded`) is a direct key leak, and constitutes an additional finding (linked to MASTG-TEST-0203).

6. **The encryption mode is actually correct (AES/GCM/NoPadding)** — a reminder that the correct mode does not save a wrong key. All three dimensions (algorithm/mode, key size, key origin) must be correct simultaneously.

---

#### ✅ PASS — The check is declared PASSED when:

| No | Condition | Example evidence |
|---|---|---|
| P1 | **No findings** from semgrep, apkleaks, TruffleHog, or grep on resources/native code | `0 Code Findings`; a clean apkleaks report |
| P2 | All keys are **generated & managed by the Android KeyStore** | `KeyGenerator.getInstance(..., "AndroidKeyStore")` + `KeyGenParameterSpec`; no `SecretKeySpec` from a literal |
| P3 | The key is **derived from user input** with a correct KDF and a **random salt per user** | `PBEKeySpec(userPassword, randomSalt, 600_000, 256)` with a salt from `SecureRandom` |
| P4 | The key is **retrieved from a server** over an authenticated channel, not stored permanently | Key provisioning at login; key only in memory |
| P5 | `SecretKeySpec` is present, but **its input is not a literal** — it comes from the KeyStore, a KDF, or a server | Code review proves a non-literal source → **false positive from the rule** |
| P6 | The finding is located only in **test/demo code that is not included in the release build** | Confirmed: the class is not present in the release APK |
| P7 | The detected constant **is not a cryptographic key** | E.g., magic bytes for file format validation, protocol constants |
| P8 | `strings.xml`, `assets/`, `res/raw/`, `BuildConfig`, `AndroidManifest` are clean of secrets | grep + apkleaks clean |
| P9 | System credentials use **KeyChain** (not hardcoded) | `KeyChain.getPrivateKey(context, alias)` |

**Example output signaling a PASS:**

```bash
$ NO_COLOR=true semgrep -c mastg-android-hardcoded-crypto-keys-usage.yml ./decompiled/sources/
┌──────────────────┐
│ 0 Code Findings  │
└──────────────────┘

$ apkleaks -f ./target-app.apk -o report.txt && grep -cE "^\[" report.txt
0

$ trufflehog filesystem ./decompiled ./decoded --results=verified
# (no verified secrets)

$ grep -rnE "(secret|api[_-]?key|token|password|private[_-]?key)" ./decoded/res/values/strings.xml
# (no results)
```

Correct code:

```kotlin
// ✅ Key generated & stored in the Android KeyStore — the key material never
//    exists in code or in a file, and cannot be extracted from secure hardware
private const val KEYSTORE_PROVIDER = "AndroidKeyStore"
private const val KEY_ALIAS = "AES_KEY_DEMO"

private fun createAndStoreSecretKey() {
    val keySpec = KeyGenParameterSpec.Builder(
        KEY_ALIAS,
        KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
    )
        .setKeySize(256)
        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
        .setRandomizedEncryptionRequired(true)
        .build()

    val keyGen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE_PROVIDER)
    keyGen.init(keySpec)
    keyGen.generateKey()
}

private fun encryptWithKeyStore(plainText: String): ByteArray {
    val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
    val entry = keyStore.getEntry(KEY_ALIAS, null) as KeyStore.SecretKeyEntry
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    cipher.init(Cipher.ENCRYPT_MODE, entry.secretKey)
    // Store cipher.iv together with the ciphertext
    return cipher.doFinal(plainText.toByteArray())
}
```

---

#### ⚠️ Important Notes on Assessment

1. **The first pattern of the MASTG rule produces MANY false positives — this is its most significant weakness.** The pattern `SecretKeySpec $_ = new SecretKeySpec($KEY, $ALGO);` matches **every** `SecretKeySpec` creation assigned to a variable of type `SecretKeySpec`, **without checking whether `$KEY` is actually hardcoded**. Even fully correct code will trigger it:

   ```java
   // All of these are SAFE, yet still triggered by the first pattern:
   SecretKeySpec k1 = new SecretKeySpec(factory.generateSecret(pbeSpec).getEncoded(), "AES"); // from PBKDF2
   SecretKeySpec k2 = new SecretKeySpec(keyFromServer, "AES");                                // from server
   SecretKeySpec k3 = new SecretKeySpec(randomBytes, "AES");                                  // from SecureRandom
   ```

   **Consequence:** every finding **must** be verified with MASTG-TECH-0023 to determine the origin of `$KEY`. Reporting raw semgrep output as-is will produce many false positives and damage the credibility of the report. For more precise automation, use **CodeQL** (taint analysis) or the extended rules in §3.4.

2. **Don't double-count findings.** As seen in the demo: line 26 is reported twice because both patterns match. Report per **unique key**, not per match.

3. **Always decode found byte arrays to ASCII/hex.** Byte arrays that look binary are often low-entropy ASCII strings (demo: `"lakdsljkalkjlkls"`). This strengthens the evidence and sometimes reveals a meaningful word that indicates the key's origin.

4. **Empty output ≠ automatic PASS.** Causes of false passes:
   - **Key in a resource** (`strings.xml`, `assets/`, `res/raw/`) — not scanned if you only scan `sources/`
   - **Key in `BuildConfig`** or the manifest's `<meta-data>`
   - **Key in native code** (`.so`) — a total blind spot for the Java rule
   - **Split/obfuscated/XOR'd strings** — do not match the literal pattern
   - **Different declaration type**: `SecretKey key = new SecretKeySpec(...)` (declared as `SecretKey`, not `SecretKeySpec`) **does not match the first pattern**
   - **Other key APIs**: `PBEKeySpec`, `IvParameterSpec`, `KeyStore.load(is, password)`, `Mac.init()` — not covered
   - Heavy packing/obfuscation, reflection, code loaded at runtime, split APKs not analyzed
   
   **Mitigation:** run supplementary grep (§3.4), apkleaks, TruffleHog, and **dynamic confirmation with Frida** (§3.5), which cuts through all the obstacles above.

5. **Obfuscation is not mitigation — and finding it actually strengthens the finding.** If you find a key that has been split or XOR'd, that is evidence that the developer **was aware** the key was sensitive but chose the wrong solution. Recall the MASTG-KNOW-0012 warning that hiding crypto in the NDK is a widespread false belief — the key can still be dumped from memory.

6. **Verify whether the secret is still active.** For third-party service API keys, TruffleHog can verify validity by calling the service's API. A secret proven to be **live** escalates to critical severity and should be reported as an incident, not just a finding — because it means it can already be abused right now.
   > Only perform this verification within an authorized engagement scope, and consider that calling a third-party API with a found credential can trigger alerts or costs on the client's account. Confirm with the client first.

7. **A hardcoded key invalidates every other cryptographic control.** The demo sample uses AES/GCM/NoPadding — a correct mode — but is still insecure. When reporting, explain that this is not a "crypto configuration" issue but a **security model failure**: there is no secret left.

8. **Severity is modulated by several factors:**

   | Factor | Severity |
   |---|---|
   | Hardcoded key protects user data (encryption at rest, PII, financial, health) | **Critical** |
   | Backend API key/secret for a paid service, **confirmed active** | **Critical** — direct abuse |
   | Hardcoded key for HMAC/token signing (bypasses authentication/integrity) | **Critical** |
   | Hardcoded key + hardcoded IV | **Critical** — deterministic ciphertext |
   | Hardcoded keystore password | **High** |
   | Hardcoded PBKDF2 salt (same derived key across users) | **High** |
   | Key derived from a static value (packageName, serial, timestamp) | **High** |
   | Key correctly generated but stored in plaintext outside the KeyStore | **High** |
   | Hardcoded key for non-sensitive data (e.g., local config checksum) | Low |
   | Hardcoded key in test code not included in the release | **Not a finding** (note as hygiene) |
   | Constant that is not a cryptographic key | **Not a finding** (false positive) |

9. **Document complete evidence per finding:** path + line number, decompiled code snippet, **the key value** (partially redacted, include the decoded ASCII/hex form), key length in bytes/bits, the algorithm and mode that uses it, **the origin of `$KEY`** as traced (literal / KDF / server / KeyStore), the usage context and why it is security-sensitive, the result of active verification if performed, and the limitations of the analysis (obfuscation, native code not yet analyzed, resources not yet swept). Also state the number of **unique keys** versus the number of semgrep matches to avoid giving the impression of simply pasting raw tool output.

### 3.4 Gaps in the MASTG Rule and Supplementary Checks

| Gap | Example that slips through |
|---|---|
| Declaration typed as `SecretKey`, not `SecretKeySpec` | `SecretKey k = new SecretKeySpec(literal, "AES");` — the first pattern requires the `SecretKeySpec` type |
| `SecretKeySpec` without assignment | `cipher.init(1, new SecretKeySpec(literal, "AES"));` |
| Array literal as a **class-level field** | `private static final byte[] KEY = {...};` — the second pattern requires both to be in a single block |
| `char[]` / `String` literal for a keystore password | `keyStore.load(is, "changeit".toCharArray())` |
| **`PBEKeySpec`** with a hardcoded password/salt | `new PBEKeySpec("pw".toCharArray(), "salt".getBytes(), 1000, 256)` |
| **`IvParameterSpec`** / **`GCMParameterSpec`** with a hardcoded IV | `new IvParameterSpec("0123456789abcdef".getBytes())` |
| **`Mac.init()`** with a hardcoded key | HMAC secret |
| **`KeyFactory`/`X509EncodedKeySpec`** with a hardcoded public/private key | Pinning key, RSA private key in code |
| **Resources**: `strings.xml`, `res/raw/`, `assets/` | Not scanned if only `sources/` is scanned |
| **`BuildConfig`**, manifest `<meta-data>` | Not covered |
| **Native code** (`.so`) | A total blind spot |
| Strings split / XOR'd / Base64-encoded | Do not match the literal pattern |
| `languages: java` only | Kotlin source is not scanned |

**Supplementary check commands:**

```bash
D=./decompiled/sources
R=./decoded
X=./apk_x

# ===== 1. All APIs that accept key material (review the origin of their arguments) =====
grep -rnE "new SecretKeySpec\(|new PBEKeySpec\(|new IvParameterSpec\(|new GCMParameterSpec\(" $D
grep -rnE "Mac\.getInstance|\.init\(.*SecretKeySpec" $D
grep -rnE "X509EncodedKeySpec|PKCS8EncodedKeySpec|KeyFactory\.getInstance" $D

# ===== 2. Literals that directly become a key =====
grep -rnE "new SecretKeySpec\(\s*\"" $D                       # direct string literal
grep -rnE "new SecretKeySpec\([A-Za-z_]+\.getBytes" $D        # string -> bytes
grep -rnE "(static )?(final )?byte\[\] [A-Z_a-z]*(KEY|SECRET|IV)[A-Za-z_]* *= *\{" $D

# ===== 3. Literal byte arrays of length 16/24/32 (AES key candidates) =====
grep -rnoE "byte\[\] [A-Za-z_]+ = \{[0-9, -]{40,}\}" $D | head -40

# ===== 4. Hardcoded keystore password & PBKDF2 =====
grep -rnE "\.load\([^,]+, *\"" $D                             # keyStore.load(is, "password")
grep -rnE "toCharArray\(\)" $D | grep -iE "\"[^\"]{4,}\""
grep -rnE "new PBEKeySpec\(" $D -A1

# ===== 5. Hardcoded IV =====
grep -rnE "new (IvParameterSpec|GCMParameterSpec)\([^)]*\"" $D
grep -rnE "new (IvParameterSpec|GCMParameterSpec)\([^)]*\{" $D

# ===== 6. Keys "derived" from a static value (linked to MASTG-TEST-0205) =====
grep -rnE "getPackageName\(\)|Build\.SERIAL|ANDROID_ID|getDeviceId|getMacAddress" $D \
  | grep -iE "digest|sha|md5|key|secret"

# ===== 7. RESOURCES — often overlooked =====
grep -rniE "(secret|api[_-]?key|apikey|token|password|passwd|private[_-]?key|client[_-]?secret|aes[_-]?key)" \
  $R/res/values/*.xml
find $R/res/raw $R/assets -type f 2>/dev/null | head -50
grep -rnaiE "BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY" $R $X | head
grep -rniE "(secret|key|token|password)" $R/AndroidManifest.xml

# ===== 8. BuildConfig =====
grep -rnE "class BuildConfig" $D -A40 | grep -iE "SECRET|KEY|TOKEN|PASSWORD"

# ===== 9. High-entropy strings / Base64-hex style (key candidates) =====
grep -rnoE "\"[A-Za-z0-9+/]{32,}={0,2}\"" $D | head -40       # Base64 ≥ 32 chars
grep -rnoE "\"[0-9a-fA-F]{32,}\"" $D | head -40               # hex ≥ 32 chars

# ===== 10. Bundled keystore & certificates =====
find $X -iname "*.jks" -o -iname "*.bks" -o -iname "*.p12" -o -iname "*.keystore" \
        -o -iname "*.pem" -o -iname "*.key" -o -iname "*.der" -o -iname "*.crt"
for p in $(find $X -iname "*.pem" -o -iname "*.key"); do
  echo "--- $p"; head -2 "$p"
done

# ===== 11. Keys in native code =====
for so in $(find $X -name "*.so"); do
  echo "--- $so"
  strings -n 16 "$so" | grep -aE "^[A-Za-z0-9+/]{32,}={0,2}$|^[0-9a-fA-F]{32,}$" | head
  strings "$so" | grep -aiE "BEGIN .*PRIVATE KEY|secret|api_key|password" | head
done

# ===== 12. Dedicated secret scanners =====
apkleaks -f ./target-app.apk -o apkleaks.txt
trufflehog filesystem $D $R --results=verified,unknown
gitleaks detect --no-git -s $D -r gitleaks.json

# ===== 13. Protection detection =====
apkid ./target-app.apk
```

**Extended semgrep rule** — reduces false positives **and** closes gaps:

```yaml
rules:
  # --- High precision: literal that truly flows into SecretKeySpec ---
  - id: custom-hardcoded-key-literal-direct
    severity: ERROR
    languages: [java, kotlin]
    message: "[MASVS-CRYPTO-1] Hardcoded cryptographic key (literal directly into SecretKeySpec)"
    pattern-either:
      - pattern: new javax.crypto.spec.SecretKeySpec("...".getBytes(...), ...)
      - pattern: new javax.crypto.spec.SecretKeySpec("...".toByteArray(...), ...)
      - patterns:
          - pattern-inside: |
              byte[] $K = {...};
              ...
          - pattern: new javax.crypto.spec.SecretKeySpec($K, ...)
      - patterns:
          - pattern-inside: |
              static final byte[] $K = {...};
              ...
          - pattern: new javax.crypto.spec.SecretKeySpec($K, ...)

  # --- Hardcoded IV / nonce ---
  - id: custom-hardcoded-iv
    severity: ERROR
    languages: [java, kotlin]
    message: "[MASVS-CRYPTO-1] Hardcoded IV/nonce — ciphertext becomes deterministic"
    pattern-either:
      - pattern: new javax.crypto.spec.IvParameterSpec("...".getBytes(...))
      - pattern: new javax.crypto.spec.GCMParameterSpec($T, "...".getBytes(...))
      - patterns:
          - pattern-inside: |
              byte[] $IV = {...};
              ...
          - pattern: new javax.crypto.spec.IvParameterSpec($IV)

  # --- Hardcoded keystore password / PBKDF2 ---
  - id: custom-hardcoded-keystore-password
    severity: ERROR
    languages: [java, kotlin]
    message: "[MASVS-CRYPTO-1] Hardcoded keystore password or KDF parameter"
    pattern-either:
      - pattern: (java.security.KeyStore $KS).load($IS, "...".toCharArray())
      - pattern: new javax.crypto.spec.PBEKeySpec("...".toCharArray(), ...)
      - pattern: new javax.crypto.spec.PBEKeySpec($P, "...".getBytes(...), ...)

  # --- HMAC with a hardcoded key ---
  - id: custom-hardcoded-hmac-key
    severity: ERROR
    languages: [java, kotlin]
    message: "[MASVS-CRYPTO-1] Hardcoded HMAC key"
    patterns:
      - pattern: (javax.crypto.Mac $M).init(new javax.crypto.spec.SecretKeySpec("...".getBytes(...), ...))

  # --- Weak signal (needs manual review, INFO severity to avoid flooding) ---
  - id: custom-secretkeyspec-review-source
    severity: INFO
    languages: [java, kotlin]
    message: "[MASVS-CRYPTO-1] SecretKeySpec detected — verify the origin of the key material (KeyStore/KDF/server = OK)"
    pattern: new javax.crypto.spec.SecretKeySpec(...)
```

This approach separates **high-precision findings** (ERROR severity, proven literal) from **signals requiring review** (INFO severity) — so that CI output remains usable as a gate.

### 3.5 Dynamic Confirmation — The Most Reliable Approach

MASTG does not provide a dynamic test for this, but hooking is the **most powerful approach** for this test because it cuts through every static-analysis obstacle at once: obfuscation, string-splitting, runtime XOR, native code, reflection, and code loaded at runtime. The key **must** exist in plaintext form in memory when used — there is no way around it.

```javascript
// dump_keys.js — dumps the actual key material used by the app
function hex(bytes) {
    return Array.from(bytes, b => ('0' + (b & 0xff).toString(16)).slice(-2)).join('');
}
function ascii(bytes) {
    return Array.from(bytes, b => (b >= 32 && b < 127) ? String.fromCharCode(b) : '.').join('');
}
function bt(max = 12) {
    const E = Java.use("java.lang.Exception");
    const st = E.$new().getStackTrace();
    const out = [];
    for (let i = 0; i < Math.min(max, st.length); i++) {
        const f = st[i].toString();
        if (f.indexOf("javax.crypto") === 0) continue;
        out.push("    " + f);
    }
    return out.join("\n");
}

Java.perform(() => {
    // --- SecretKeySpec: the main entry point according to MASTG ---
    const SKS = Java.use("javax.crypto.spec.SecretKeySpec");
    SKS.$init.overload('[B', 'java.lang.String').implementation = function (k, algo) {
        const bytes = Java.array('byte', k);
        console.log(`\n[KEY] new SecretKeySpec(${bytes.length} B = ${bytes.length * 8} bit, "${algo}")`);
        console.log(`      hex   : ${hex(bytes)}`);
        console.log(`      ascii : ${ascii(bytes)}`);
        console.log(bt());
        return this.$init(k, algo);
    };

    // --- Cipher.init: shows the key & IV actually used ---
    const Cipher = Java.use("javax.crypto.Cipher");
    Cipher.init.overloads.forEach(ov => {
        ov.implementation = function (...a) {
            try {
                const algo = this.getAlgorithm();
                console.log(`\n[CIPHER] Cipher("${algo}").init(mode=${a[0]})`);
                if (a[1] && a[1].getEncoded) {
                    const enc = a[1].getEncoded();
                    if (enc) {
                        const b = Java.array('byte', enc);
                        console.log(`      key hex   : ${hex(b)}  (${b.length * 8} bit)`);
                        console.log(`      key ascii : ${ascii(b)}`);
                    } else {
                        console.log(`      key: <non-extractable — likely from AndroidKeyStore>`);
                    }
                }
                console.log(bt());
            } catch (e) { /* ignore */ }
            return ov.apply(this, a);
        };
    });

    // --- IV / nonce ---
    ['javax.crypto.spec.IvParameterSpec', 'javax.crypto.spec.GCMParameterSpec'].forEach(cls => {
        try {
            const C = Java.use(cls);
            C.$init.overloads.forEach(ov => {
                ov.implementation = function (...a) {
                    const arr = a.find(x => x && x.length !== undefined);
                    if (arr) {
                        const b = Java.array('byte', arr);
                        console.log(`\n[IV] ${cls}  ${b.length} B  hex=${hex(b)}  ascii=${ascii(b)}`);
                        console.log(bt());
                    }
                    return ov.apply(this, a);
                };
            });
        } catch (e) { /* ignore */ }
    });

    // --- Mac (HMAC) ---
    const Mac = Java.use("javax.crypto.Mac");
    Mac.init.overloads.forEach(ov => {
        ov.implementation = function (...a) {
            try {
                if (a[0] && a[0].getEncoded) {
                    const enc = a[0].getEncoded();
                    if (enc) {
                        const b = Java.array('byte', enc);
                        console.log(`\n[MAC] ${this.getAlgorithm()} key hex=${hex(b)} ascii=${ascii(b)}`);
                        console.log(bt());
                    }
                }
            } catch (e) { /* ignore */ }
            return ov.apply(this, a);
        };
    });

    // --- KeyStore.load: hardcoded keystore password ---
    const KS = Java.use("java.security.KeyStore");
    KS.load.overload('java.io.InputStream', '[C').implementation = function (is, pw) {
        if (pw !== null) {
            const s = Java.array('char', pw).map(c => String.fromCharCode(c)).join('');
            console.log(`\n[KS] KeyStore.load(password="${s}")`);
            console.log(bt());
        }
        return this.load(is, pw);
    };

    // --- PBEKeySpec: password, salt, iterations ---
    const PBE = Java.use("javax.crypto.spec.PBEKeySpec");
    PBE.$init.overload('[C', '[B', 'int', 'int').implementation = function (pw, salt, iter, len) {
        const p = Java.array('char', pw).map(c => String.fromCharCode(c)).join('');
        const s = Java.array('byte', salt);
        console.log(`\n[PBE] password="${p}" salt=${hex(s)} (${s.length}B) iter=${iter} keyLen=${len}`);
        console.log(bt());
        return this.$init(pw, salt, iter, len);
    };
});
```

Run it:

```bash
frida -U -f com.example.target -l dump_keys.js -o keys.log
# then exercise the features that use crypto (login, save data, local encryption)
```

**How to read the output** — this is a very useful diagnostic point:

| Output | Meaning |
|---|---|
| `key hex` and `key ascii` display a value | The key **can be extracted** → it is outside the KeyStore → **FAIL** |
| `key: <non-extractable>` | `getEncoded()` returns `null` — a hallmark of a key from the **AndroidKeyStore** that cannot be extracted → **PASS** |
| The key value is **identical** across different devices/installs | Proven to be hardcoded or deterministic across users → **FAIL** |
| The key value **differs** per install | Possibly generated per device — check how it is stored (can still be FAIL if outside the KeyStore) |
| `ascii` shows readable text | A low-entropy key derived from a string — strong evidence |
| `[PBE] salt=...` is the same on every device | Hardcoded salt → identical derived key across users → **FAIL** |

> **Testing on two devices/installations** is the most convincing way to distinguish a hardcoded key from a per-device key. If the hex values are identical, there is no room for debate.

---

### 3.6 Alternative Testing Methods (Multi-Tool)

This test has a particular character: the MASTG rule is **too loose** (it matches every `SecretKeySpec` without checking the origin of the key, §3.3 note 1) **while simultaneously being too narrow** (13 gaps, §3.4). The alternative methods below address both.

#### Method B — Dedicated secret scanners: apkleaks, TruffleHog, gitleaks *(most targeted)*

**This is the method I recommend as the primary supplement.** These tools are specifically designed to find secrets and cover a much wider surface than the MASTG rule — including resources, assets, and the manifest.

```bash
# --- apkleaks (MASTG-TOOL-0125) — 50+ regex patterns, directly from the APK ---
pip install apkleaks
apkleaks -f ./target-app.apk -o apkleaks-report.txt
#   Covers: AWS key, Google API key, JWT, Firebase URL, Slack token,
#           private key PEM, endpoints, and internal URIs

# With additional custom patterns
cat > custom-patterns.json <<'JSON'
{
  "AES Key Candidate (Base64 32B)": "\\b[A-Za-z0-9+/]{43}=\\b",
  "AES Key Candidate (hex 32B)": "\\b[0-9a-fA-F]{64}\\b",
  "Keystore Password": "(?i)(keystore|truststore)[_-]?(pass|password)\\s*[=:]\\s*\\S+"
}
JSON
apkleaks -f ./target-app.apk -p custom-patterns.json -o apkleaks-custom.txt

# --- TruffleHog — entropy + ACTIVE verification against the service's API ---
trufflehog filesystem ./decompiled ./decoded --results=verified,unknown --json > th.json
jq 'select(.Verified == true) | {detector: .DetectorName, raw: .Raw, file: .SourceMetadata.Data.Filesystem.file}' th.json
#   A secret with "Verified: true" = PROVEN STILL ACTIVE -> critical severity

# --- gitleaks — regex + entropy, fast ---
gitleaks detect --no-git -s ./decompiled -r gitleaks.json --redact
gitleaks detect --no-git -s ./decoded   -r gitleaks-res.json --redact
```

> **Operational warning for TruffleHog:** verification mode calls third-party service APIs with the found credentials. Do this **only** within an authorized engagement scope, and confirm with the client first — the call could trigger security alerts or costs on their account.

#### Method C — Structured ripgrep *(closes the rule's 13 gaps, high precision)*

See §3.4 for the full set of commands. The most important summary:

```bash
D=./decompiled/sources
R=./decoded

# Literals that DIRECTLY become a key (high precision — not just "a SecretKeySpec exists")
rg -n --no-heading 'new SecretKeySpec\(\s*"' $D
rg -n --no-heading 'new SecretKeySpec\([A-Za-z_]+\.getBytes' $D
rg -n --no-heading '(static )?(final )?byte\[\] [A-Za-z_]*(KEY|SECRET|IV)[A-Za-z_]* *= *\{' $D

# Other key APIs NOT covered by the MASTG rule
rg -n --no-heading 'new PBEKeySpec\(|new IvParameterSpec\(|new GCMParameterSpec\(' $D
rg -n --no-heading '\.load\([^,]+, *"' $D                    # keystore password
rg -n --no-heading 'X509EncodedKeySpec|PKCS8EncodedKeySpec' $D
rg -n --no-heading 'Mac\.getInstance' $D -A2

# RESOURCES — a surface that is often missed entirely
rg -ni --no-heading '(secret|api[_-]?key|token|password|private[_-]?key|client[_-]?secret)' $R/res/values/*.xml
rg -ni --no-heading '(secret|key|token|password)' $R/AndroidManifest.xml
rg -n --no-heading 'class BuildConfig' $D -A40 | rg -i 'SECRET|KEY|TOKEN|PASSWORD'

# High-entropy strings (key candidates)
rg -no --no-heading '"[A-Za-z0-9+/]{32,}={0,2}"' $D | head -40
rg -no --no-heading '"[0-9a-fA-F]{32,}"' $D | head -40
```

#### Method D — CodeQL *(automatically removes false positives from the MASTG rule)*

**This is the solution to the MASTG rule's biggest weakness.** Taint analysis can distinguish a `SecretKeySpec` that receives a literal from one that receives the output of PBKDF2/KeyStore/server — something pattern matching cannot do.

```bash
codeql database create ./cqldb --language=java --command="./gradlew assembleDebug"
codeql database analyze ./cqldb \
  codeql/java-queries:Security/CWE/CWE-798/HardcodedCredentialsApiCall.ql \
  codeql/java-queries:Security/CWE/CWE-798/HardcodedPasswordField.ql \
  codeql/java-queries:Security/CWE/CWE-321/HardcodedCryptoKey.ql \
  --format=sarif-latest --output=keys.sarif

jq '.runs[].results[] | {rule: .ruleId, msg: .message.text}' keys.sarif
```

```ql
/**
 * @name Hardcoded literal flows into cryptographic key material
 * @kind path-problem
 * @problem.severity error
 */
import java
import semmle.code.java.dataflow.TaintTracking

class LiteralSource extends DataFlow::Node {
  LiteralSource() {
    this.asExpr() instanceof StringLiteral or
    this.asExpr() instanceof ArrayInit or
    this.asExpr() instanceof CompileTimeConstantExpr
  }
}

class KeyMaterialSink extends DataFlow::Node {
  KeyMaterialSink() {
    exists(ClassInstanceExpr cie |
      cie.getConstructedType().hasQualifiedName("javax.crypto.spec",
        ["SecretKeySpec", "PBEKeySpec", "IvParameterSpec", "GCMParameterSpec"]) |
      this.asExpr() = cie.getAnArgument()
    )
    or
    exists(MethodAccess ma |
      ma.getMethod().hasName("load") and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.security", "KeyStore") |
      this.asExpr() = ma.getArgument(1)
    )
  }
}
```

Result: `new SecretKeySpec(factory.generateSecret(pbeSpec).getEncoded(), "AES")` is **not** reported (correctly), while `new SecretKeySpec("my secret".getBytes(), "AES")` is reported along with its data-flow path.

#### Method E — SonarQube / SonarLint

Relevant rules: **`java:S6418`** (*Hard-coded secrets are security-sensitive* — uses entropy analysis, not just regex), **`java:S2068`** (*Hard-coded credentials*), and **`java:S6437`** (*Credentials should not be hard-coded*). Advantage: entropy detection means it can find keys that don't match any naming pattern, and it surfaces directly in the IDE via SonarLint.

```bash
sonar-scanner -Dsonar.projectKey=android-app -Dsonar.sources=./app/src
```

#### Method F — MobSF *(ready-to-cite report + resource scanning)*

```bash
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest
```

| Report section | Contents |
|---|---|
| **Hardcoded Secrets** | List of strings suspected to be secrets, from scanning code **and** resources — the most relevant section |
| **Code Analysis** | *"Files may contain hardcoded sensitive information like usernames, passwords, keys"* |
| **Firebase / Third-party** | Detected Firebase configuration, endpoints, and API keys |

MobSF excels because it scans `strings.xml`, `assets/`, and `res/raw/` all at once — a surface the MASTG rule does not touch.

#### Method G — mobsfscan *(CLI for CI/CD)*

```bash
mobsfscan --json -o out.json ./decompiled/sources/ ./decoded/
jq '.results | to_entries[] | select(.key | test("hardcode|secret|key"))' out.json
mobsfscan --exit-warning ./decompiled/sources/
```

#### Method H — nuclei *(template-based scanning on extracted files)*

```bash
unzip -o ./target-app.apk -d ./apk_x >/dev/null

# Token/secret exposure templates from nuclei-templates
nuclei -t ~/nuclei-templates/file/keys/ -target ./apk_x -file
nuclei -t ~/nuclei-templates/file/android/ -target ./apk_x -file
```

Useful because nuclei-templates is community-maintained and its secret patterns are continually updated for new services.

#### Method I — APKHunt

```bash
go install github.com/Cyber-Buddy/APKHunt@latest
APKHunt -p ./target-app.apk -l
grep -iA3 "hardcode\|secret\|key" APKHunt_Report.txt
```

#### Method J — Native code analysis + string obfuscation

Java rules do not reach `.so` files, and split/XOR'd keys do not match the literal pattern.

```bash
# 1. Key-style strings in .so files
for so in $(find ./apk_x -name "*.so"); do
  echo "--- $so"
  strings -n 16 "$so" | grep -aE "^[A-Za-z0-9+/]{32,}={0,2}$|^[0-9a-fA-F]{32,}$" | head
  strings "$so" | grep -aiE "BEGIN .*PRIVATE KEY|secret|api_key|password" | head
done

# 2. XOR'd key — recover the key
xortool -c 00 ./apk_x/assets/blob.bin
xortool-xor -f ./apk_x/assets/blob.bin -s $'\x5a' | strings | head

# 3. Candidate encrypted/compressed blobs in assets
binwalk -e ./apk_x/assets/*
file ./apk_x/assets/* ./apk_x/res/raw/*

# 4. String concatenation / char array (simple obfuscation)
rg -n --no-heading 'new char\[\]\s*\{' ./decompiled/sources/ | head
rg -n --no-heading '"[A-Za-z0-9]{4}"\s*\+\s*"[A-Za-z0-9]{4}"' ./decompiled/sources/ | head
```

#### Method K — Multi-device verification *(definitive proof, no code reading required)*

This is the hardest method to dispute and requires no code analysis at all:

```bash
# Run the key-dump script (§3.5) on TWO different devices/emulators
frida -U -f com.example.target -l dump_keys.js -o keys_device_A.log   # device A
frida -U -f com.example.target -l dump_keys.js -o keys_device_B.log   # device B

# Compare the recorded key hex values
grep "hex" keys_device_A.log | sort > a.txt
grep "hex" keys_device_B.log | sort > b.txt
comm -12 a.txt b.txt
#   A key IDENTICAL on both devices  -> HARDCODED / deterministic  -> FAIL
#   A key that DIFFERS               -> per-device (check its storage)
#   getEncoded() = null              -> from AndroidKeyStore         -> PASS
```

Additionally: repeat after **uninstalling + reinstalling** on the same device. A key that stays the same after reinstalling means it is not generated per installation.

---

### 3.7 Method Comparison: When to Use Which

| Method | Tool | Needs a device? | Needs source? | Scans resources/assets? | Distinguishes literal vs. KDF? | When to use |
|---|---|---|---|---|---|---|
| **A** | semgrep (MASTG) | No | No | ❌ | ❌ **(high false positives)** | Official baseline; **must be manually verified** |
| **B** | apkleaks / TruffleHog / gitleaks | No | No | ✅ | Partially | **Primary supplement** — widest coverage; TruffleHog can verify active status |
| **C** | Structured ripgrep | No | No | ✅ | Manual | High-precision cross-verification |
| **D** | CodeQL | No | Yes (ideal) | ❌ | ✅ **automatic** | **Eliminates false positives from the MASTG rule** |
| **E** | SonarQube `java:S6418` | No | Yes | Partially | ✅ | Entropy-based detection; shift-left in the IDE |
| **F** | MobSF | No | No | ✅ | ❌ | Ready-to-cite report + resource scanning |
| **G** | mobsfscan | No | No | ✅ | ❌ | Lightweight CI/CD gate |
| **H** | nuclei | No | No | ✅ | ❌ | Continuously updated community secret patterns |
| **I** | APKHunt | No | No | Partially | ❌ | Additional automated pass |
| **J** | `strings`/Ghidra/xortool/binwalk | No | No | ✅ | Manual | Native code & obfuscated keys |
| **L** | Frida (§3.5) | **Yes** | No | — | ✅ (actual values) | **Cuts through all obfuscation** — the key must be plaintext in memory |
| **K** | Frida multi-device | **Yes** (2×) | No | — | ✅ | **Definitive proof** for reporting |

**Minimum recommended combination:** **B (apkleaks + TruffleHog) → L (Frida dump) → K (2-device verification)**.
B gives the widest coverage including resources and assets; L cuts through obfuscation because the key must be plaintext in memory when used; K provides undeniable evidence. Use **A (semgrep)** as a CI gate only, and **D (CodeQL)** when source is available to suppress its false positives. Add **J** if the APK contains `.so` files or binary assets.

---

## 4. Recommendations

### 4.1 Main Principles (in priority order)

**Priority 1 — Use the Android KeyStore. This is the definitive remediation for MASWE-0003.**

Android documentation positions this as the primary mitigation: the key is generated **inside** secure hardware and **never exists in plaintext form** — not in code, not in a file, and cannot be extracted even from a rooted device.

```kotlin
private const val KEYSTORE_PROVIDER = "AndroidKeyStore"
private const val KEY_ALIAS = "AES_KEY_DEMO"

// ✅ Create the key INSIDE the KeyStore — no key material in code
private fun createAndStoreSecretKey() {
    val keySpec = KeyGenParameterSpec.Builder(
        KEY_ALIAS,
        KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
    )
        .setKeySize(256)                                   // AES-256 (see MASTG-TEST-0208)
        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
        .setRandomizedEncryptionRequired(true)             // random IV guaranteed by the system
        .setUserAuthenticationRequired(true)               // for the most sensitive data
        .setIsStrongBoxBacked(true)                        // if the hardware supports it
        .build()

    val keyGen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE_PROVIDER)
    keyGen.init(keySpec)
    keyGen.generateKey()
}

// ✅ Use the key without ever touching its key material
private fun encryptWithKeyStore(plainText: String): Pair<ByteArray, ByteArray> {
    val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
    val entry = keyStore.getEntry(KEY_ALIAS, null) as KeyStore.SecretKeyEntry
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    cipher.init(Cipher.ENCRYPT_MODE, entry.secretKey)
    return cipher.doFinal(plainText.toByteArray()) to cipher.iv   // store the IV together with the ciphertext
}
```

For **system credentials shared across applications**, use **KeyChain**:

```kotlin
val privateKey = KeyChain.getPrivateKey(context, alias)
val chain = KeyChain.getCertificateChain(context, alias)
```

**Priority 2 — Derive the key from user input with a correct KDF.** If the key must depend on something the user knows (e.g., a vault with a master password):

```kotlin
// ✅ RANDOM salt per user (not hardcoded), high iteration count, modern PRF
val salt = ByteArray(16).also { SecureRandom().nextBytes(it) }   // store the salt, it's not a secret
val keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
val keySpec = PBEKeySpec(userPassword, salt, 600_000, 256)
val key = SecretKeySpec(keyFactory.generateSecret(keySpec).encoded, "AES")
```

Conditions for this not to be a finding:
- **Random salt per user** from `SecureRandom` — a hardcoded salt makes the key identical across users (F14)
- **High iteration count** — 600,000 for PBKDF2-HMAC-SHA256 (not 10,000 as in older examples); **Argon2id** is even better
- **Modern PRF** — `PBKDF2WithHmacSHA256`, not SHA1
- The password is **not** stored; only the salt and parameters are

> Note: `SecretKeySpec` is still used here, and **will still trigger the MASTG rule** — this is the false positive discussed in §3.3 note 1. What matters is that the origin of `$KEY` is not a literal.

**Priority 3 — Provision the key from a server (for critical keys).** Android documentation recommends, for the most critical keys:

- Store the master key in a **secure backend**, using an **HSM** where available
- Retrieve the key over an **authenticated channel** (TLS + user authentication)
- Enforce a **key rotation policy**
- **Do not** store provisioned keys permanently on the device; if you must, wrap them with a KeyStore key

This also solves the most fundamental problem of hardcoded keys: **rotation becomes possible without shipping a new app release**.

**Priority 4 — Move backend secrets out of the application entirely.** For third-party service API keys/secrets, there is no safe way to store them client-side. The solution is architectural:

- **Proxy through your own backend** — the app calls your backend, and your backend calls the third-party service using a secret stored server-side
- Use **short-lived tokens** issued by your backend, rather than long-lived API keys
- For keys that are **designed to be public** (e.g., a Firebase API key, a Maps API key), secure them with **server-side restrictions**: API restriction, package name + signing certificate restriction, quotas, and monitoring

**Priority 5 — Don't rely on obfuscation, the NDK, or white-box cryptography as a substitute.** MASTG-KNOW-0012 states that this is a widespread false belief:

> *"There is a widespread false belief that the NDK should be used to hide cryptographic operations and hardcoded keys. However, this mechanism is **ineffective**. Attackers can still use tools to identify the mechanism in use and **dump the key from memory**."*

The key **must** be in plaintext form in memory when used — Frida will find it (see §3.5). Obfuscation only slightly raises the cost of the attack, it does not prevent it. Use obfuscation as an **additional layer** (MASVS-RESILIENCE), **not** as a solution to MASWE-0003.

**Priority 6 — Clean up the entire APK surface, not just the code.**

```gradle
// ❌ WRONG — buildConfigField still ends up in the APK as a constant
buildConfigField "String", "API_SECRET", "\"${project.property('apiSecret')}\""

// ✅ Do not put secrets in BuildConfig at all.
//    For values that are genuinely meant to be public, use server-side restrictions.
```

- Remove secrets from `strings.xml`, `res/raw/`, `assets/`, manifest `<meta-data>`
- Remove unnecessary `.pem`, `.key`, `.jks`, `.p12` files from the APK
- Don't hardcode keystore passwords; if a keystore must be bundled, reconsider the design
- Enable **R8/ProGuard** — not as key protection, but to reduce the amount of exposed information

**Priority 7 — Treat an already-leaked key as an incident.** If this test finds a hardcoded key in an app that has **already been released**, fixing the code alone is not enough — that key must be treated as **already compromised**:

- **Rotate/revoke** that key and its credentials immediately
- **Audit the logs** of the related service for abuse that may have already occurred
- For data already encrypted with the leaked key: **re-encrypt** it with a new key
- Plan a migration path for users on older versions

**Priority 8 — Enforce this structurally.**
- **Secret scanning in CI/CD**: run apkleaks/TruffleHog/gitleaks on the APK artifact on every build, and fail the build on new findings outside an allowlist
- Add high-precision SAST rules (§3.4) as a gate; separate INFO-level signals so they don't flood the output
- Create **one centralized crypto utility** (e.g., `KeyProvider.getDataKey()`) that **only** retrieves keys from the KeyStore, then forbid direct calls to `SecretKeySpec` via custom lint or a code review checklist
- **Pre-commit hook** to prevent secrets from entering the repo in the first place
- Audit third-party libraries — also run scans on decompiled library code

### 4.2 Remediation Checklist

- [ ] Every semgrep finding has been verified with MASTG-TECH-0023 to confirm the **origin of the key material** (literal / KDF / server / KeyStore)
- [ ] The number of **unique keys** is reported, not the number of matches (avoid double counting)
- [ ] Byte arrays found have been decoded to ASCII/hex as evidence
- [ ] No byte array / string literal is used as a cryptographic key
- [ ] No hardcoded IV/nonce
- [ ] No hardcoded keystore password
- [ ] No hardcoded PBKDF2 salt; a random salt per user from `SecureRandom` is used
- [ ] No key derived from a static value (packageName, `Build.SERIAL`, ANDROID_ID, timestamp)
- [ ] All data-encryption keys are **generated & managed by the Android KeyStore**; `setUserAuthenticationRequired` & StrongBox are considered
- [ ] Shared system credentials use **KeyChain**
- [ ] Password-derived keys use `PBKDF2WithHmacSHA256` (or Argon2id), iterations ≥ 600,000, salt ≥ 16 random bytes
- [ ] Critical keys are provisioned from a server over an authenticated channel, with a rotation policy
- [ ] Backend secrets/third-party API keys are **moved to the server** (proxied), not stored client-side
- [ ] Keys that are genuinely meant to be public are restricted server-side (API restriction, package + signing cert, quotas, monitoring)
- [ ] `strings.xml`, `res/raw/`, `assets/`, `BuildConfig`, and manifest `<meta-data>` are clean of secrets
- [ ] Unnecessary `.pem`/`.key`/`.jks`/`.p12` files are removed from the APK
- [ ] Native code (`.so`) is clean of hardcoded keys; **no attempt to hide keys in the NDK**
- [ ] No key is logged or displayed in the app's UI/output
- [ ] Key sizes are adequate (AES-256, RSA ≥ 3072) — cross-verified with **MASTG-TEST-0208**
- [ ] Algorithm & mode are correct (AES-GCM, not ECB) — cross-verified with **MASTG-TEST-0221 / 0232**
- [ ] Third-party libraries are audited; all split APKs / dynamic feature modules are also analyzed
- [ ] **Keys already leaked in a release version have been rotated/revoked**, service logs have been audited, and affected data has been re-encrypted
- [ ] Secret scanning (apkleaks/TruffleHog/gitleaks) + SAST rules are integrated into CI/CD as a gate
- [ ] A centralized crypto utility has been created; direct calls to `SecretKeySpec` are forbidden
- [ ] **Static re-verification:** re-run the MASTG-TEST-0208-style scan + supplementary grep → clean
- [ ] **Dynamic re-verification:** run `dump_keys.js` → `getEncoded()` returns `null` (non-extractable key from the KeyStore), and the key value **differs** across devices

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0212: Use of Hardcoded Cryptographic Keys in Code](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0212/)
- [MASWE-0003: Cryptographic Keys Stored Outside of Platform Keystore](https://mas.owasp.org/MASWE/MASVS-CRYPTO/MASWE-0003/)
- [MASWE-0004: Sensitive Data Hardcoded in the App Package](https://mas.owasp.org/MASWE/MASVS-STORAGE/MASWE-0004/)
- [MASTG-DEMO-0017: Use of Hardcoded AES Key in SecretKeySpec with semgrep](https://mas.owasp.org/MASTG/demos/android/MASVS-CRYPTO/MASTG-DEMO-0017/MASTG-DEMO-0017/)
- [MASTG-KNOW-0012: Key Generation](https://mas.owasp.org/MASTG/knowledge/android/MASVS-CRYPTO/MASTG-KNOW-0012/)
- [MASTG-TEST-0208: Insufficient Key Sizes](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0208/)
- [MASTG-TEST-0221: Uses of Broken Symmetric Encryption Algorithms](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0221/)
- [MASTG-TEST-0232: Uses of Broken Encryption Modes](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0232/)
- [MASTG-TEST-0205: Non-random Sources Usage](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0205/)
- [MASTG-TEST-0207: Runtime Storage of Unencrypted Data in the App Sandbox](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0207/)
- [MASTG-TECH-0013: Reverse Engineering Android Apps](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/)
- [MASTG-TECH-0014: Static Analysis on Android](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/)
- [MASTG-TECH-0023: Reviewing Decompiled Java Code](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0023/)
- [MASTG-TOOL-0125: Apkleaks](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0125/)
- [MASTG-TOOL-0110: semgrep](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0110/)
- [MASTG-TOOL-0018: jadx](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0018/)
- [MASTG-TOOL-0011: apktool](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0011/)
- [MASTG Rules — `mastg-android-hardcoded-crypto-keys-usage.yml`](https://github.com/OWASP/mastg/blob/master/rules/mastg-android-hardcoded-crypto-keys-usage.yml)
- [MASTG — Testing Cryptography](https://mas.owasp.org/MASTG/0x05e-Testing-Cryptography/)
- [MASVS-CRYPTO: Cryptography](https://mas.owasp.org/MASVS/06-MASVS-CRYPTO/)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
- [OWASP Key Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html)
- [OWASP Mobile Top 10 2024 — M1: Improper Credential Usage](https://owasp.org/www-project-mobile-top-10/2023-risks/m1-improper-credential-usage.html)
- [OWASP Mobile Top 10 2024 — M10: Insufficient Cryptography](https://owasp.org/www-project-mobile-top-10/2023-risks/m10-insufficient-cryptography.html)

### 5.2 Official Android / Google / Java Documentation

- [Hardcoded Cryptographic Secrets — Android Security Risks](https://developer.android.com/privacy-and-security/risks/hardcoded-cryptographic-secrets)
- [`javax.crypto.spec.SecretKeySpec` — API reference](https://developer.android.com/reference/javax/crypto/spec/SecretKeySpec)
- [`javax.crypto.SecretKey` — API reference](https://developer.android.com/reference/javax/crypto/SecretKey)
- [Android Keystore system](https://developer.android.com/privacy-and-security/keystore)
- [`KeyStore` — API reference](https://developer.android.com/reference/java/security/KeyStore)
- [`KeyChain` — API reference](https://developer.android.com/reference/android/security/KeyChain)
- [`KeyGenParameterSpec` — API reference](https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec)
- [`PBEKeySpec` — API reference](https://developer.android.com/reference/javax/crypto/spec/PBEKeySpec)
- [`SecretKeyFactory` — API reference](https://developer.android.com/reference/javax/crypto/SecretKeyFactory)
- [Cryptography best practices](https://developer.android.com/privacy-and-security/cryptography)
- [Hardware-backed Keystore (AOSP)](https://source.android.com/docs/security/features/keystore)
- [StrongBox Keymaster (AOSP)](https://source.android.com/docs/security/best-practices/hardware)
- [Android Developers Blog — Android changes for NDK developers](https://android-developers.googleblog.com/2016/06/android-changes-for-ndk-developers.html)
- [Google Cloud — API key best practices & restrictions](https://cloud.google.com/docs/authentication/api-keys)
- [Firebase — Are API keys for Firebase safe to expose?](https://firebase.google.com/docs/projects/api-keys)
- [Google Tink — cryptographic library](https://developers.google.com/tink)

### 5.3 Standards & Weakness Taxonomy

- [CWE-321: Use of Hard-coded Cryptographic Key](https://cwe.mitre.org/data/definitions/321.html)
- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [CWE-259: Use of Hard-coded Password](https://cwe.mitre.org/data/definitions/259.html)
- [CWE-547: Use of Hard-coded, Security-relevant Constants](https://cwe.mitre.org/data/definitions/547.html)
- [CWE-922: Insecure Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/922.html)
- [CWE-1391: Use of Weak Credentials](https://cwe.mitre.org/data/definitions/1391.html)
- [Kerckhoffs's principle](https://en.wikipedia.org/wiki/Kerckhoffs%27s_principle)
- [NIST SP 800-57 Part 1 Rev. 5 — Recommendation for Key Management](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final)
- [NIST SP 800-132 — Recommendation for Password-Based Key Derivation](https://csrc.nist.gov/publications/detail/sp/800-132/final)
- [NIST SP 800-163 Rev.1 — Vetting the Security of Mobile Applications](https://csrc.nist.gov/publications/detail/sp/800-163/rev-1/final)
- [SonarQube Rule java:S6418 — Hard-coded secrets are security-sensitive](https://rules.sonarsource.com/java/RSPEC-6418/)
- [SonarQube Rule java:S2068 — Hard-coded credentials are security-sensitive](https://rules.sonarsource.com/java/RSPEC-2068/)
- [SEI CERT Oracle Coding Standard for Java — MSC03-J: Never hard code sensitive information](https://wiki.sei.cmu.edu/confluence/display/java/MSC03-J.+Never+hard+code+sensitive+information)
- [CodeQL — Java query help (hard-coded credentials)](https://codeql.github.com/codeql-query-help/java/)

### 5.4 Security Research & Technical Articles

- [ACM CCS 2025 — *Leaky Apps: Large-scale Analysis of Secrets Distributed in Android and iOS Apps*](https://dl.acm.org/doi/10.1145/3719027.3765033)
- [SBA Research — *Leaky Apps* (author's PDF version)](https://publications.sba-research.org/publications/Secrets_Distributed_in_Android_and_iOS_Apps-1_David%20Schmidt.pdf)
- [Empirical Software Engineering (Springer) — *How far are app secrets from being stolen? A case study on Android*](https://link.springer.com/article/10.1007/s10664-024-10607-9)
- [CEUR-WS — *Hardcoded credentials in Android apps: Service exposure analysis*](https://ceur-ws.org/Vol-3826/short8.pdf)
- [arXiv — *Automatically Detecting Checked-In Secrets in Android Apps: How Far Are We?*](https://arxiv.org/html/2412.10922)
- [arXiv — *A Longitudinal Study of Android Apps Signing Key Protection*](https://arxiv.org/pdf/2606.21487)
- [RedHunt Labs — *Scanning Android Apps for Secrets and More* (Project Resonance Wave 8)](https://redhuntlabs.com/blog/the-current-state-of-security-privacy-and-attack-surface-on-android-scanning-apps-for-secrets-and-more-wave-8-2/)
- [Cybernews — Android apps leak hard-coded secrets](https://cybernews.com/security/android-apps-leak-hardcoded-secrets/)
- [VAPT.PK — Hardcoded API Keys in Android Apps: 5-Minute Audit](https://vapt.pk/blog/hardcoded-api-keys-android/)
- [Undercode Testing — Exposing Hardcoded Secrets In Android Apps](https://undercodetesting.com/exposing-hardcoded-secrets-in-android-apps-a-cybersecurity-deep-dive/)
- [Jit — TruffleHog vs. Gitleaks: A Detailed Comparison of Secret Scanning Tools](https://www.jit.io/resources/appsec-tools/trufflehog-vs-gitleaks-a-detailed-comparison-of-secret-scanning-tools)
- [HackTricks — Android Applications Pentesting](https://book.hacktricks.wiki/en/mobile-pentesting/android-app-pentesting/index.html)

### 5.5 Tool Documentation

- [apkleaks — Scanning APK file for URIs, endpoints & secrets](https://github.com/dwisiswant0/apkleaks)
- [TruffleHog — secret scanning with active verification](https://github.com/trufflesecurity/trufflehog)
- [gitleaks — secret detection](https://github.com/gitleaks/gitleaks)
- [MobSF — Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)
- [mobsfscan — static analysis for Android/iOS](https://github.com/MobSF/mobsfscan)
- [Semgrep — Documentation](https://semgrep.dev/docs/)
- [Semgrep — Pattern syntax reference](https://semgrep.dev/docs/writing-rules/pattern-syntax/)
- [CodeQL — Documentation](https://codeql.github.com/docs/)
- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [apktool — Reverse engineering Android APK files](https://apktool.org/)
- [APKiD — Android Application Identifier](https://github.com/rednaga/APKiD)
- [Frida — Documentation Home](https://frida.re/docs/home/)
- [Frida — JavaScript API: `Java`](https://frida.re/docs/javascript-api/#java)
- [Ghidra — software reverse engineering framework](https://ghidra-sre.org/)
- [keytool — Java key and certificate management tool](https://docs.oracle.com/en/java/javase/17/docs/specs/man/keytool.html)
- [OpenSSL — command-line tools](https://www.openssl.org/docs/man3.0/man1/)

---

*This document was prepared based on the OWASP MASTG (latest release as of September 2026), official Android Developers documentation, CWE/NIST/SEI CERT standards, and third-party security research.*
