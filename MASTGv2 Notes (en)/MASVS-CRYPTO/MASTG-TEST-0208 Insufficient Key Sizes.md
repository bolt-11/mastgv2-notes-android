# MASTG-TEST-0208 Insufficient Key Sizes

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0208 |
| **Platform** | Android |
| **MASVS Category** | **MASVS-CRYPTO** (MASVS-CRYPTO-1: The app uses current and modern cryptography applied correctly) |
| **Weakness** | **MASWE-0013** — *Improper Cryptographic Key Generation* |
| **Test Type** | **Static**, Code |
| **Profile** | L1, L2 |
| **Knowledge** | MASTG-KNOW-0012 (Key Generation) |
| **Related Techniques** | MASTG-TECH-0013 (Reverse Engineering Android Apps), MASTG-TECH-0014 (Static Analysis on Android), MASTG-TECH-0023 (Reviewing Decompiled Java Code) |
| **Related Demo** | MASTG-DEMO-0012 (Cryptographic Key Generation With Insufficient Key Length) |
| **Key APIs** | `javax.crypto.KeyGenerator` (`init(int keysize)`), `java.security.KeyPairGenerator` (`initialize(int keysize)`) |
| **Related CWE** | CWE-326 (Inadequate Encryption Strength), CWE-310 (Cryptographic Issues), CWE-327 (Use of a Broken or Risky Cryptographic Algorithm), CWE-1240 (Use of a Cryptographic Primitive with a Risky Implementation) |
| **Reference Standards** | NIST SP 800-57 Part 1, NIST SP 800-131A Rev. 2, NIST IR 8547, CNSA 2.0, BSI TR-02102-1, ECRYPT-CSA |

---

## 1. Explanation

### 1.1 Testing Objective

This test looks for the **use of inadequate key sizes** in Android apps through static analysis.

Direct quote from the MASTG overview:

> *"In this test case, we will look for the use insufficient key sizes in Android apps. To do this, we need to focus on the cryptographic frameworks and libraries that are available in Android and the methods that are used to generate, inspect and manage cryptographic keys."*
>
> *"The Java Cryptography Architecture (JCA) provides foundational classes for key generation which are often used directly when portability or compatibility with older systems is a concern."*
>
> - *"**`KeyGenerator`**: ... used to generate symmetric keys including **AES, DES, ChaCha20 or Blowfish**, as well as various **HMAC** keys. The key size can be specified using the `init(int keysize)` method."*
> - *"**`KeyPairGenerator`**: ... used for generating key pairs for asymmetric encryption (e.g., **RSA, EC**). The key size can be specified using the `initialize(int keysize)` method."*

So there are **two main entry points** that must be checked, and each has a different method for determining key size:

| Class | For | Size-determining method |
|---|---|---|
| `javax.crypto.KeyGenerator` | **Symmetric** keys (AES, DES, ChaCha20, Blowfish) and **HMAC** | `init(int keysize)` |
| `java.security.KeyPairGenerator` | **Asymmetric** key pairs (RSA, EC/ECDSA, DSA) | `initialize(int keysize)` |

Also note the MASTG remark that JCA is often used directly *"when portability or compatibility with older systems is a concern"* — this is an important clue: code that uses plain JCA (without the Android KeyStore) is usually legacy or cross-platform code, and it is precisely there that legacy key sizes often linger.

### 1.2 Technical Foundation: Key Size vs. Security Bits

The most common misconception in this test is equating **key length** with **security level**. The two are only equal for symmetric algorithms; for asymmetric algorithms, the relationship is highly non-linear.

**Strength equivalence table (based on NIST SP 800-57 Part 1):**

| Bits of security | Symmetric (AES) | RSA (modulus) | ECC (curve) | Diffie-Hellman / DSA |
|---|---|---|---|---|
| 80 | — (SKIPJACK) | 1024 | 160–223 | 1024 |
| **112** | 3TDEA | **2048** | 224–255 | 2048 |
| **128** | **AES-128** | **3072** | **256–383** | 3072 |
| 192 | AES-192 | 7680 | 384–511 | 7680 |
| 256 | AES-256 | 15360 | 512+ | 15360 |

Practical implications:

- **RSA-1024 only provides ~80-bit security** — it has long been inadequate and has already been *disallowed* by NIST.
- **RSA-2048 provides 112-bit security** — still acceptable, but being **deprecated toward 2030**.
- **RSA-3072 provides 128-bit security** — this is what's equivalent to AES-128 and is recommended for new systems that need to remain secure past 2030.
- **ECC is far more efficient**: EC-256 (P-256) provides ~128-bit security, equivalent to RSA-3072. Therefore, don't assume "256" in EC is comparable to "256" in RSA.
- For **HMAC**, the key length should be at least as large as the hash output (e.g., ≥ 256 bits for HMAC-SHA256).

### 1.3 Recommended Key Lengths per Algorithm

| Algorithm | ❌ Insufficient | ⚠️ Deprecated / transitional | ✅ Recommended |
|---|---|---|---|
| **AES** | ≤ 64 bits; DES/3DES algorithms | **128** (see §1.4) | **256** |
| **RSA** (encryption/signature) | 512, 768, **1024** | **2048** (until ~2030) | **3072** or more; 4096 commonly used |
| **EC / ECDSA / ECDH** | < 224 (e.g., 160, 192) | 224 | **256** (P-256) or **384** (P-384) |
| **DSA / DH** | 1024 | 2048 | 3072+ |
| **ChaCha20** | — (fixed key size) | — | **256** (default) |
| **Blowfish** | < 128; **avoid entirely** (64-bit block → *Sweet32*) | — | Switch to AES |
| **DES** | **56** — broken | — | Switch to AES |
| **3DES / TDEA** | 2-key (112) | 3-key (168 → 112 effective) — NIST *disallowed* | Switch to AES |
| **HMAC** | < hash output size | — | ≥ 256 bits (HMAC-SHA256+) |
| **PBKDF2** (derived key length) | < 128 bits | 128 | **256 bits**, with high iteration count (see §1.6) |

### 1.4 Important Note: MASTG's Position on AES-128 Is Stricter Than NIST's

This needs to be understood precisely before reporting a finding, because it can potentially be contested by developers.

MASTG's evaluation criteria state:

> *"For example, a **1024-bit key size is considered insufficient for RSA** encryption and a **128-bit key size is considered insufficient for AES** encryption **considering quantum computing attacks**."*

The statement about RSA-1024 is not controversial — all standards bodies agree it is no longer adequate. But the statement about **AES-128 is a more conservative position, stricter than NIST's**, and it's important to understand the context:

**The argument behind MASTG's position (Grover's algorithm):** Grover's algorithm provides a *quadratic speed-up* over classical brute force — searching a symmetric key of `k` bits, which classically requires O(2^k) operations, drops to O(2^(k/2)). With this logic, AES-128 "drops" to the equivalent of ~64 bits against a quantum attacker, which is clearly inadequate. AES-256 still provides ~128-bit effective security — safe for the foreseeable future.

**However, the position of standards bodies differs:**

- **NIST still considers AES-128 secure** — it even uses it as the *benchmark* for measuring the security of post-quantum primitives (PQC Security Category 1). AES-128 is still *approved* under FIPS and SP 800-131A.
- **CNSA 2.0 (NSA) mandates AES-256** for National Security Systems. Interestingly, by accepting AES-256 at the 256-bit security level (rather than demanding a nonexistent "AES-512"), **CNSA 2.0 itself implicitly acknowledges that Grover's algorithm does not truly halve AES's strength** in practice.
- **Practical analysis** shows a Grover attack against AES-128 is unrealistic because of the enormous circuit-depth requirements and the difficulty of parallelization — Grover's algorithm does not parallelize well, so the theoretical speed-up is not realized at real-world scale.
- Conversely, **asymmetric cryptography (RSA/ECC) is genuinely threatened** by Shor's algorithm. NIST IR 8547 plans to **prohibit all quantum-vulnerable public-key cryptography — including RSA-3072, P-256, P-384 — by 2035**.

**How I recommend reporting this:**

| Finding | Proportional severity |
|---|---|
| RSA ≤ 1024, DES, 3DES, EC < 224 | **High** — consensus across all standards; real exploitability |
| RSA 2048 | **Low / hardening** — still approved, but plan migration before 2030 |
| **AES-128** | **Low / hardening** — report per MASTG criteria, but **state that NIST/FIPS still approves it**; recommend AES-256 as a best practice and alignment with CNSA 2.0 |
| Any asymmetric key without a PQC migration plan | Informational — relevant for the 2030–2035 roadmap |

Presenting it this way makes your finding **defensible**: you follow MASTG (so the check FAILs), but you don't overstate the risk, which keeps the report's credibility intact. Reporting AES-128 as a critical vulnerability will be immediately rebutted by a competent crypto team.

### 1.5 Android Context: KeyGenParameterSpec and the Android KeyStore

MASTG-KNOW-0012 explains that Android 6.0 (API 23) introduced `KeyGenParameterSpec` to ensure correct key usage. This is relevant to this test because **key size can be specified in several different places**, and not all of them are caught by the MASTG rule:

```kotlin
// Path A — plain JCA (what the MASTG rule looks for)
val keyGen = KeyGenerator.getInstance("AES")
keyGen.init(128)                                    // <-- key size here

val kpg = KeyPairGenerator.getInstance("RSA")
kpg.initialize(1024, SecureRandom())                // <-- key size here

// Path B — KeyGenParameterSpec + Android KeyStore (NOT caught by the MASTG rule)
val spec = KeyGenParameterSpec.Builder("alias", PURPOSE_ENCRYPT or PURPOSE_DECRYPT)
    .setKeySize(128)                                // <-- key size here
    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
    .build()
KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").init(spec)

// Path C — KeyPairGeneratorSpec (deprecated, but still present in legacy code)
val kpSpec = KeyPairGeneratorSpec.Builder(context)
    .setAlias(RSA_KEY_ALIAS)
    .setKeySize(4096)                               // <-- key size here
    .build()

// Path D — PBEKeySpec (derived key length)
val keySpec = PBEKeySpec(password, salt, iterationCount, 128)   // <-- keyLength here

// Path E — SecretKeySpec from a byte array (size determined by array length)
val key = SecretKeySpec(ByteArray(16), "AES")       // <-- 16 bytes = 128 bits
```

All five of these paths determine a key size, but **the MASTG semgrep rule only covers Path A** — and not even all of it (see §3.4).

Additional notes from MASTG-KNOW-0012 that are relevant here:

- Before Android 6.0 (API 23), **AES key generation was not supported** by the KeyStore. As a result, many implementations chose RSA and created a key pair, or used `SecureRandom` to create an AES key. This explains why legacy code often contains RSA with a legacy key size.
- The RSA example in KNOW-0012 uses **4096 bits** — good practice.
- **Since Android 11 (API 30), AndroidKeyStore does not support encryption/decryption with EC keys** — EC is only for signatures. So don't "fix" a weak RSA by switching to EC for KeyStore encryption.
- KNOW-0012 also gives an important warning: there is a **widespread false belief** that the NDK can be used to hide cryptographic operations and hardcoded keys. This mechanism **is not effective** — the key can still be dumped from memory with Frida, and since Android 7.0 (API 24), the use of private APIs is not allowed.

### 1.6 Other Parameters That Are Also "Insufficient" (Should Be Checked Together)

Although this test is formally about *key size*, in practice checking key generation (MASWE-0013) should also cover:

| Parameter | Inadequate threshold | Recommendation |
|---|---|---|
| **PBKDF2 iterations** | MASTG-KNOW-0012 exemplifies `iterationCount = 10000` — this number is **already outdated** | OWASP now recommends **600,000** iterations for PBKDF2-HMAC-SHA256; even better, use **Argon2id** or scrypt |
| **PBKDF2 PRF algorithm** | `PBKDF2WithHmacSHA1` | `PBKDF2withHmacSHA256` — KNOW-0012 itself recommends this for API levels above Android 8.0 (API 26) |
| **Salt length** | < 16 bytes | ≥ 16 bytes from `SecureRandom` |
| **GCM tag length** | < 128 bits | 128 bits (`GCMParameterSpec(128, iv)`) |
| **GCM nonce length** | ≠ 12 bytes (triggers internal re-derivation) | 12 bytes (96 bits) |
| **Key source** | `java.util.Random`, timestamp, hardcoded value | `SecureRandom` / KeyStore — see MASTG-TEST-0204 & 0205 |
| **RSA modulus size vs. padding** | RSA with PKCS#1 v1.5 | OAEP for encryption, PSS for signatures |

---

## 2. Tools Used for Testing

### 2.1 Required Tools (Core)

| Tool | MASTG ID | Function in this test |
|---|---|---|
| **jadx** | MASTG-TOOL-0018 | **Decompiles DEX → Java** (MASTG-TECH-0013). Also required for MASTG-TECH-0023 — verifying the context of key usage |
| **semgrep** | MASTG-TOOL-0110 | **Pattern matching**. MASTG provides the rule `mastg-android-key-generation-with-insufficient-key-length.yml` |
| **grep / ripgrep** | — | **Required complement** — the MASTG rule is very narrow (see §3.4) |
| **apktool** | MASTG-TOOL-0011 | Alternative decompilation; smali analysis when jadx fails |

### 2.2 Supporting Tools

| Tool | Function |
|---|---|
| **CodeQL** | Useful for cases where the key size comes from a **variable or constant** (e.g., `init(KEY_SIZE)`), which semgrep cannot resolve with literal patterns |
| **mobsfscan / MobSF** | Mobile SAST; has a built-in weak key size rule |
| **SonarQube** | Rule `java:S4426` — *Cryptographic keys should be robust* (detects RSA < 2048, EC < 224, etc.) |
| **semgrep-rules-android-security** (IMQ Minded Security) | Third-party rule collection; complement to the official MASTG rule |
| **jadx-gui** | Interactive navigation + "Find Usage" for tracing key size constants |
| **Frida** | MASTG-TOOL-0001 — **dynamic confirmation** of the key size actually used at runtime (see §3.5). Very useful when the key size is determined by a variable |
| **`keytool` / `openssl`** | Checks key sizes in certificates/keystores bundled in the APK (`res/raw/`, `assets/`) |
| **Ghidra / `strings`** | Analysis of `.so` files — cryptographic operations from native code are not reached by the Java rule |
| **APKiD** | Detects packers/obfuscators to assess the reliability of static analysis |

### 2.3 Environment Prerequisites

- **No device and no root required** — the APK file alone is sufficient. Easy to automate in CI/CD.
- **Complete APK**, including all split APKs / dynamic feature modules.
- **semgrep installed** with the MASTG rule available (`github.com/OWASP/mastg`, `rules/` directory).
- **The rule only covers `languages: java`** — scanning is performed on the decompiled code, not Kotlin source.
- **Note the effect of decompilation on constants.** This matters practically: in Kotlin source, the demo uses `KeyProperties.KEY_ALGORITHM_RSA`, but in the decompiled Java it becomes the **literal `"RSA"`**. The MASTG rule matches string literals, so it **only works on decompiled code** — not on the original source code that uses `KeyProperties.*` constants.
- **Be aware of obfuscation.** JCA API names (`KeyGenerator`, `KeyPairGenerator`, `init`, `initialize`) are not obfuscated by R8/ProGuard because they are system APIs, so detection remains effective. What's made harder is the context-review stage (application class names become single letters).
- **Have the key length reference table ready** (§1.3) as an assessment baseline, and agree with the client on which standard to apply (NIST, BSI, or CNSA 2.0) — this determines whether AES-128 and RSA-2048 count as findings.

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0013** (*Reverse Engineering Android Apps*) to reverse engineer the application.
2. Use **MASTG-TECH-0014** (*Static Analysis on Android*) to search for the relevant APIs.

For evaluation: use **MASTG-TECH-0023** (*Reviewing Decompiled Java Code*) to review each finding location.

### 3.2 Practical Implementation (MASTG-DEMO-0012)

**Step 1 — Decompile**

```bash
jadx -d ./decompiled ./target-app.apk

# If split APK / AAB, pull and decompile all parts
adb shell pm path com.example.target
```

**Step 2 — Run the official MASTG semgrep rule**

The `mastg-android-key-generation-with-insufficient-key-length.yml` rule:

```yaml
rules:
  - id: mastg-android-key-generation-with-insufficient-key-length
    severity: WARNING
    languages:
      - java
    metadata:
      summary: This rule looks for methods that create keys with insufficient length in encryption algorithms.
    message: "[MASVS-CRYPTO] Make sure that the key size is according to security best practices"
    pattern-either:
      - pattern: |
          $K = $G.getInstance("RSA");
          ...
          $K.initialize(1024, new SecureRandom());
      - pattern: |
          $K = $G.getInstance("RSA");
          ...
          $K.initialize(512, new SecureRandom());
      - pattern: |
          $K = $G.getInstance("AES");
          ...
          $K.init(128);
```

Running it (`run.sh` from the demo):

```bash
NO_COLOR=true semgrep -c ../../../../rules/mastg-android-key-generation-with-insufficient-key-length.yml \
  ./MastgTest_reversed.java > output.txt
```

For a real app:

```bash
NO_COLOR=true semgrep \
  -c ./mastg/rules/mastg-android-key-generation-with-insufficient-key-length.yml \
  ./decompiled/sources/ --json -o findings-keysize.json
```

**Step 3 — Review each finding (MASTG-TECH-0023)**

For each location, determine:

1. **Which algorithm** and **exactly what key size**?
2. **What is this key used for** — encrypting data at rest, signatures, key exchange, or only demo/test code?
3. **Is there another location** that sets the key size for the same key (e.g., `KeyGenParameterSpec.setKeySize`)?
4. **Is this code actually executed** (not dead code / an unused library)?

### 3.3 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rules:**

> **Observation:** *"The output should contain a list of locations where insufficient key lengths are used."*
>
> **Evaluation:** *"The test case **fails** if you can find the use of insufficient key sizes within the source code. For example, a **1024-bit key size is considered insufficient for RSA** encryption and a **128-bit key size is considered insufficient for AES** encryption considering quantum computing attacks."*

Unlike MASTG-TEST-0204/0205, **this test does not require proving a security-relevant context**. The criterion is direct: **an inadequate key size is found → FAIL**. This makes sense because, unlike `Random` (which has many legitimate uses), cryptographic key generation is **always** security-relevant by definition.

Still, use MASTG-TECH-0023 to confirm the code is actually active and to understand its impact.

---

#### ❌ FAIL / ISSUE — The check is declared FAILED if:

| No | Condition | Example evidence | Severity |
|---|---|---|---|
| F1 | **RSA 512 / 768 / 1024** is used | `generator.initialize(1024, new SecureRandom())` | **High** |
| F2 | **AES-128** is used (per MASTG criteria) | `keyGen1.init(128)` | Low/hardening — see §1.4 |
| F3 | **DES (56-bit)** or **3DES** is used | `KeyGenerator.getInstance("DES").init(56)` | **High** — also a broken algorithm (linked to MASTG-TEST-0221) |
| F4 | **Blowfish** with a short key, or Blowfish at all | `KeyGenerator.getInstance("Blowfish").init(64)` | **High** — 64-bit block vulnerable to *Sweet32* |
| F5 | **EC / ECDSA with a curve < 224 bits** | `kpg.initialize(160)`; curves `secp160r1`, `prime192v1` | **High** |
| F6 | **DSA / DH 1024-bit** | `KeyPairGenerator.getInstance("DSA").initialize(1024)` | **High** |
| F7 | `KeyGenParameterSpec.setKeySize()` with an inadequate value | `.setKeySize(128)` for AES; `.setKeySize(1024)` for RSA | Per algorithm — **not caught by the MASTG rule** |
| F8 | `KeyPairGeneratorSpec.setKeySize()` (deprecated) with an inadequate value | `.setKeySize(1024)` | **High** — **not caught by the MASTG rule** |
| F9 | `SecretKeySpec` from a byte array that is too short | `SecretKeySpec(ByteArray(8), "AES")` → 64 bits | **High** — **not caught by the MASTG rule** |
| F10 | `PBEKeySpec` with an inadequate `keyLength` | `PBEKeySpec(pw, salt, 10000, 128)` | Medium — **not caught by the MASTG rule** |
| F11 | Key size comes from a **variable/constant** with an inadequate value | `private static final int KEY_SIZE = 1024; ... kpg.initialize(KEY_SIZE)` | Per value — **not caught by the MASTG rule** |
| F12 | **RSA-2048** in an app with a long-term (> 2030) protection requirement | `initialize(2048)` | Low/hardening |
| F13 | Inadequate key size in **native code** | `strings lib.so` → `RSA_generate_key`, `EVP_PKEY_keygen` with small parameters | Per case — blind spot of the Java rule |
| F14 | A certificate / keystore **bundled in the APK** uses a weak key | `openssl x509 -in assets/pinned.crt -text \| grep "Public-Key"` → `1024 bit` | **High** |
| F15 | Other key-generation parameters are inadequate (low PBKDF2 iterations, short salt, GCM tag < 128) | `PBEKeySpec(..., 1000, 256)`; `GCMParameterSpec(96, iv)` | Medium — see §1.6 |

**Example output indicating FAIL — MASTG-DEMO-0012:**

Sample code (`MastgTest.kt`):

```kotlin
val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA)
generator.initialize(1024, SecureRandom())                    // <-- FAIL: RSA-1024
val keypair = generator.genKeyPair()

val keyGen1 = KeyGenerator.getInstance("AES")
keyGen1.init(128)                                             // <-- FAIL: AES-128
val secretKey1: SecretKey = keyGen1.generateKey()

val keyGen2 = KeyGenerator.getInstance("AES")
keyGen2.init(256)                                             // <-- PASS: AES-256
val secretKey2: SecretKey = keyGen2.generateKey()
```

Decompiled code scanned by semgrep (`MastgTest_reversed.java`):

```java
public final String mastgTest() {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");     // <-- line 27
    generator.initialize(1024, new SecureRandom());                      // <-- line 28
    KeyPair keypair = generator.genKeyPair();
    Log.d("Keypair generated RSA", Base64.encodeToString(keypair.getPublic().getEncoded(), 0));
    KeyGenerator keyGen1 = KeyGenerator.getInstance("AES");               // <-- line 31
    keyGen1.init(128);                                                   // <-- line 32
    SecretKey secretKey1 = keyGen1.generateKey();
    ...
    KeyGenerator keyGen2 = KeyGenerator.getInstance("AES");
    keyGen2.init(256);                                                   // not triggered
    ...
}
```

Semgrep output (`output.txt`):

```
┌─────────────────┐
│ 2 Code Findings │
└─────────────────┘

    MastgTest_reversed.java
    ❯❱ rules.mastg-android-key-generation-with-insufficient-key-length
          [MASVS-CRYPTO] Make sure that the key size is according to security best practices

           27┆ KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
           28┆ generator.initialize(1024, new SecureRandom());
            ⋮┆----------------------------------------
           31┆ KeyGenerator keyGen1 = KeyGenerator.getInstance("AES");
           32┆ keyGen1.init(128);
```

MASTG evaluation: *"The test **fails** because the key size of the RSA key is set to `1024` bits, and the size of the AES key is set to `128`, which is considered insufficient in both cases."*

**Four observations from this demo:**

1. **The rule displays TWO lines per finding** — the `getInstance(...)` line and the `init/initialize(...)` line. This is because the pattern is sequential (`$K = $G.getInstance("RSA"); ... ; $K.initialize(...)`), so the match spans a code range. This is useful because it immediately shows both the algorithm **and** its size.
2. **`keyGen2.init(256)` is not triggered** — proving the rule distinguishes between adequate and inadequate sizes.
3. **`KeyProperties.KEY_ALGORITHM_RSA` becomes the literal `"RSA"`** after decompilation. This is why the rule works on decompiled code but not on Kotlin source that uses the constant.
4. **This demo uses plain JCA without the Android KeyStore** — the generated key resides in the app's memory/heap, not in secure hardware. While not the focus of this test, that is an **additional finding** worth noting (linked to MASWE-0013 and key storage). Also note that the demo sample even **logs the public key** via `Log.d` (linked to MASTG-TEST-0203) — for a public key this is not sensitive, but the same pattern applied to `secretKey.encoded` would be a private-key leak.

---

#### ✅ PASS — The check is declared PASSED if:

| No | Condition | Example evidence |
|---|---|---|
| P1 | **No findings** from either semgrep or complementary grep | `0 Code Findings`; grep on `setKeySize`, `PBEKeySpec`, `SecretKeySpec` is clean |
| P2 | All symmetric keys are **AES-256** | `keyGen.init(256)` or `.setKeySize(256)` |
| P3 | All RSA ≥ **3072** (ideally 4096) | `initialize(4096)`; or `KeyPairGeneratorSpec.setKeySize(4096)` |
| P4 | All EC ≥ **256** (P-256/P-384) | `initialize(256)`; `ECGenParameterSpec("secp256r1")` |
| P5 | Key size **not explicitly specified** and the provider default is already adequate | `KeyPairGenerator.getInstance("RSA").generateKeyPair()` → defaults to 2048 on modern Android. **Should still be made explicit** — note as hardening |
| P6 | Key is generated and managed by the **Android KeyStore** with an adequate size | `KeyGenParameterSpec.Builder(...).setKeySize(256)` + provider `"AndroidKeyStore"` |
| P7 | No DES / 3DES / Blowfish / RC4 | grep clean |
| P8 | Supporting parameters are adequate: high PBKDF2 iterations + SHA256, salt ≥ 16 bytes, GCM tag 128 bits | `PBEKeySpec(pw, salt16, 600000, 256)`; `GCMParameterSpec(128, iv)` |
| P9 | A bundled certificate/keystore uses a key ≥ 2048 (RSA) or ≥ 256 (EC) | `openssl x509 ... \| grep Public-Key` → `4096 bit` |

**Example output indicating PASS:**

```bash
$ NO_COLOR=true semgrep -c mastg-android-key-generation-with-insufficient-key-length.yml ./decompiled/sources/
┌──────────────────┐
│ 0 Code Findings  │
└──────────────────┘

# Complementary grep for paths not covered by the rule
$ grep -rnE "setKeySize\(|initialize\(|\.init\(" ./decompiled/sources/ | grep -E "\((512|768|1024|128|160|192|56|64)[,)]"
# (no results)

$ grep -rniE "\"DES\"|DESede|Blowfish|RC4|RC2" ./decompiled/sources/
# (no results)
```

Correct code:

```kotlin
// ✅ AES-256 via Android KeyStore — the key never leaves secure hardware
val keyGen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
keyGen.init(
    KeyGenParameterSpec.Builder(
        "vault_key",
        KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
    )
        .setKeySize(256)                                      // AES-256
        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
        .setRandomizedEncryptionRequired(true)
        .build()
)
keyGen.generateKey()

// ✅ RSA-4096 via Android KeyStore, with OAEP
val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore")
kpg.initialize(
    KeyGenParameterSpec.Builder("rsa_key", KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
        .setKeySize(4096)                                     // RSA-4096
        .setDigests(KeyProperties.DIGEST_SHA256)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
        .build()
)
kpg.generateKeyPair()

// ✅ EC P-256 for signatures (remember: the KeyStore does not support EC encryption since API 30)
val ecKpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
ecKpg.initialize(
    KeyGenParameterSpec.Builder("sign_key", KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY)
        .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
        .setDigests(KeyProperties.DIGEST_SHA256)
        .build()
)
ecKpg.generateKeyPair()
```

---

#### ⚠️ Important Notes on Assessment

1. **The MASTG rule is very narrow — this is the most important characteristic of this test.** The rule only matches three very specific literal patterns. Many real-world cases **slip through entirely**. Don't conclude PASS just from an empty semgrep output; see §3.4 for the list of gaps and complementary grep commands.

2. **The AES-128 position needs to be stated carefully in the report.** See §1.4. Report it per the MASTG criteria (so the check FAILs), but classify it as **hardening / low severity** and mention that NIST/FIPS still approves AES-128. This makes your finding defensible under debate.

3. **Don't equate numbers across algorithms.** "256" in AES ≠ "256" in RSA. EC-256 is equivalent to RSA-3072, not RSA-256. Use the table in §1.2 when assessing and when explaining this to developers.

4. **Key size can be set in five different places** (§1.5) — and the MASTG rule only covers one. Check `KeyGenParameterSpec.setKeySize`, `KeyPairGeneratorSpec.setKeySize`, `PBEKeySpec`'s `keyLength`, and the byte array length in `SecretKeySpec`.

5. **Watch for key sizes that come from a variable.** Semgrep's literal pattern will not catch `initialize(KEY_SIZE)`. Use grep for small-valued constants, or CodeQL for constant-value resolution, or dynamic confirmation with Frida (§3.5).

6. **The absence of an `init()`/`initialize()` call is not automatically safe — but it's also not automatically a finding.** If the size is not made explicit, the provider uses its default (on modern Android: RSA 2048, AES 128 or 256 depending on provider/version). This is ambiguous and platform-dependent, so it is **best to still make it explicit** — note this as a hardening recommendation, not a hard finding.

7. **A correct key size does not save a wrong algorithm/mode.** AES-256 in **ECB** mode is still insecure. This test only assesses one dimension; complement it with MASTG-TEST-0221 (broken symmetric algorithms) and MASTG-TEST-0232 (broken encryption modes).

8. **A correct key size also does not save a key generated from a weak source.** An AES-256 key created from `java.util.Random` or from a timestamp only has as much entropy as its source. Complement with **MASTG-TEST-0204** and **MASTG-TEST-0205**.

9. **Empty output ≠ automatic PASS.** Causes of false pass: rule gaps (note 1), obfuscation/packing, reflection (`Class.forName("javax.crypto.KeyGenerator")`), native code, code loaded at runtime, unanalyzed split APKs, and third-party libraries not included in the scan.

10. **Also check bundled cryptographic assets.** Pinning certificates, JKS/BKS/PKCS#12 keystores in `assets/` or `res/raw/`, and hardcoded public keys all have a key size that can be weak — and will not be found by scanning code.

11. **Document complete evidence per finding:** rule ID (or grep method), path + line number, the decompiled code snippet, **the exact algorithm and key size**, **equivalent bits of security** (from the table in §1.2), the key's purpose, the reference standard used for assessment (NIST SP 800-57 / BSI / CNSA 2.0), the proposed severity with its justification, and the analysis limitations (obfuscation, native code, libraries not yet scanned).

### 3.4 MASTG Rule Gaps and Complementary Checks

The MASTG rule only covers **three literal patterns**. Here are its gaps:

| Gap | Example that slips through |
|---|---|
| `initialize(1024)` **without** the `new SecureRandom()` argument | `kpg.initialize(1024)` — does not match because the pattern requires two arguments |
| RSA 768 | `kpg.initialize(768, new SecureRandom())` — only 512 & 1024 are patterned |
| `init(128, ...)` with a second argument | `keyGen.init(128, new SecureRandom())` |
| AES with another weak size | `init(64)` |
| **DES, 3DES, Blowfish, RC2/RC4** | Not mentioned in the rule at all |
| **EC / ECDSA / DSA / DH** | Not mentioned in the rule at all |
| **HMAC** | Not mentioned |
| **`KeyGenParameterSpec.setKeySize()`** | Android KeyStore path — not covered |
| **`KeyPairGeneratorSpec.setKeySize()`** | Deprecated path — not covered |
| **`PBEKeySpec`'s `keyLength`** | Not covered |
| **`SecretKeySpec(ByteArray(n), ...)`** | Not covered |
| Size from a **variable/constant** | The literal pattern does not resolve the value |
| `getInstance()` and `init()` in **different functions** | The sequential pattern requires both in one block |
| `languages: java` only | Kotlin source is not scanned |
| **Native** code | A total blind spot |

**Complementary check commands:**

```bash
D=./decompiled/sources

# 1. All key-size-determining calls, then filter for small values
grep -rnE "\.(initialize|init)\(\s*(56|64|96|128|160|192|224|512|768|1024)\b" $D
grep -rnE "setKeySize\(\s*(56|64|96|128|160|192|224|512|768|1024|2048)\s*\)" $D

# 2. All key generation calls (review size manually)
grep -rnE "KeyGenerator\.getInstance|KeyPairGenerator\.getInstance|KeyGenParameterSpec|KeyPairGeneratorSpec" $D

# 3. Broken / weak algorithms (linked to MASTG-TEST-0221)
grep -rniE "\"DES\"|\"DESede\"|TripleDES|\"Blowfish\"|\"RC2\"|\"RC4\"|\"ARCFOUR\"|\"IDEA\"" $D

# 4. Weak EC curves
grep -rnE "ECGenParameterSpec\(|secp(160|192)|prime192|brainpoolP160" $D

# 5. SecretKeySpec with a short array (64/128-bit)
grep -rnE "new SecretKeySpec\(new byte\[(8|16)\]|ByteArray\((8|16)\)" $D

# 6. PBEKeySpec — keyLength & iterationCount
grep -rnE "new PBEKeySpec\(" $D -A2
grep -rnE "PBKDF2WithHmacSHA1" $D          # use SHA256 for API 26+

# 7. GCM parameters (tag length must be 128)
grep -rnE "new GCMParameterSpec\(" $D

# 8. Key size constants defined at the class level
grep -rnE "(static )?(final )?int [A-Z_]*KEY[_]?(SIZE|LEN|LENGTH)[A-Z_]* *= *[0-9]+" $D

# 9. Cryptographic assets bundled in the APK
unzip -o ./target-app.apk -d ./apk_x >/dev/null
find ./apk_x -iname "*.crt" -o -iname "*.pem" -o -iname "*.cer" -o -iname "*.der" \
     -o -iname "*.jks" -o -iname "*.bks" -o -iname "*.p12" -o -iname "*.keystore"
for c in $(find ./apk_x -iname "*.crt" -o -iname "*.pem" -o -iname "*.cer"); do
  echo "--- $c"
  openssl x509 -in "$c" -noout -text 2>/dev/null | grep -E "Public-Key|Signature Algorithm" | head -3
done
keytool -list -v -keystore ./apk_x/res/raw/mykeystore.bks -storetype BKS 2>/dev/null | grep -iE "algorithm|key size"

# 10. Cryptography from native code
for so in $(find ./apk_x -name "*.so"); do
  echo "--- $so"
  strings "$so" | grep -xE "RSA_generate_key|RSA_generate_key_ex|EVP_PKEY_keygen|DH_generate_parameters|EC_KEY_new_by_curve_name|DES_set_key|BF_set_key"
done

# 11. Detect protections that limit the reliability of analysis
apkid ./target-app.apk
```

**Extended semgrep rule** to close the main gaps:

```yaml
rules:
  - id: custom-insufficient-key-size-extended
    severity: ERROR
    languages: [java, kotlin]
    message: "[MASVS-CRYPTO-1] Insufficient key size or weak algorithm in key generation"
    pattern-either:
      # --- RSA / DSA / DH: all sizes < 2048 ---
      - pattern-regex: \.initialize\(\s*(512|768|1024)\b
      # --- Symmetric: small sizes ---
      - pattern-regex: \.init\(\s*(56|64|96)\b
      # --- KeyGenParameterSpec / KeyPairGeneratorSpec ---
      - pattern-regex: setKeySize\(\s*(56|64|96|128|512|768|1024)\s*\)
      # --- Broken algorithms (key size no longer relevant) ---
      - pattern: javax.crypto.KeyGenerator.getInstance("DES", ...)
      - pattern: javax.crypto.KeyGenerator.getInstance("DESede", ...)
      - pattern: javax.crypto.KeyGenerator.getInstance("Blowfish", ...)
      - pattern: javax.crypto.KeyGenerator.getInstance("RC4", ...)
      - pattern: javax.crypto.KeyGenerator.getInstance("ARCFOUR", ...)
      # --- Weak EC curves ---
      - pattern-regex: ECGenParameterSpec\(\s*"(secp160r1|secp160k1|secp192r1|prime192v1|brainpoolP160r1)"
      # --- SecretKeySpec from a short array ---
      - pattern-regex: new SecretKeySpec\(\s*new byte\[(8|16)\]

  - id: custom-aes-128-hardening
    severity: INFO
    languages: [java, kotlin]
    message: "[MASVS-CRYPTO-1] AES-128 detected. MASTG recommends AES-256; note that NIST/FIPS still approves AES-128 (severity: hardening)"
    pattern-either:
      - pattern-regex: \.init\(\s*128\b
      - pattern-regex: setKeySize\(\s*128\s*\)

  - id: custom-weak-kdf-params
    severity: WARNING
    languages: [java, kotlin]
    message: "[MASVS-CRYPTO-1] Inadequate KDF parameters (low iteration count / outdated PRF / small keyLength)"
    pattern-either:
      - pattern: javax.crypto.SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1", ...)
      - pattern-regex: new PBEKeySpec\([^,]+,[^,]+,\s*([0-9]{1,5})\s*,   # iterations < 100,000
```

### 3.5 Optional Dynamic Confirmation

MASTG does not provide a dynamic test for this, but hooking is useful in two situations: when the key size comes from a **variable** (so static analysis cannot resolve it), and when the code is **obfuscated** or loaded at runtime.

```javascript
Java.perform(() => {
    function bt(max = 10) {
        const E = Java.use("java.lang.Exception");
        const st = E.$new().getStackTrace();
        const out = [];
        for (let i = 0; i < Math.min(max, st.length); i++) out.push("    " + st[i]);
        return out.join("\n");
    }

    // Minimum thresholds per standard
    const MIN = { AES: 256, RSA: 3072, EC: 256, DSA: 3072, DH: 3072, ChaCha20: 256 };

    // --- KeyGenerator (symmetric + HMAC) ---
    const KG = Java.use("javax.crypto.KeyGenerator");
    KG.getInstance.overloads.forEach(ov => {
        ov.implementation = function (...a) {
            const inst = ov.apply(this, a);
            console.log(`\n[*] KeyGenerator.getInstance("${a[0]}")`);
            console.log(bt());
            return inst;
        };
    });
    KG.init.overloads.forEach(ov => {
        ov.implementation = function (...a) {
            if (typeof a[0] === 'number') {
                const algo = this.getAlgorithm();
                const min = MIN[algo] || 256;
                const flag = a[0] < min ? `  [!! INSUFFICIENT (min ${min}) !!]` : "  [ok]";
                console.log(`\n[*] KeyGenerator(${algo}).init(${a[0]})${flag}`);
                console.log(bt());
            }
            return ov.apply(this, a);
        };
    });

    // --- KeyPairGenerator (asymmetric) ---
    const KPG = Java.use("java.security.KeyPairGenerator");
    KPG.initialize.overloads.forEach(ov => {
        ov.implementation = function (...a) {
            if (typeof a[0] === 'number') {
                const algo = this.getAlgorithm();
                const min = MIN[algo] || 3072;
                const flag = a[0] < min ? `  [!! INSUFFICIENT (min ${min}) !!]` : "  [ok]";
                console.log(`\n[*] KeyPairGenerator(${algo}).initialize(${a[0]})${flag}`);
                console.log(bt());
            } else {
                console.log(`\n[*] KeyPairGenerator(${this.getAlgorithm()}).initialize(<spec>) -> ${a[0]}`);
                console.log(bt());
            }
            return ov.apply(this, a);
        };
    });

    // --- SecretKeySpec: size determined by array length ---
    const SKS = Java.use("javax.crypto.spec.SecretKeySpec");
    SKS.$init.overload('[B', 'java.lang.String').implementation = function (k, algo) {
        const bits = k.length * 8;
        const flag = bits < 256 ? `  [!! ${bits}-bit !!]` : `  [${bits}-bit]`;
        console.log(`\n[*] new SecretKeySpec(byte[${k.length}], "${algo}")${flag}`);
        console.log(bt());
        return this.$init(k, algo);
    };

    // --- PBEKeySpec: keyLength & iterationCount ---
    const PBE = Java.use("javax.crypto.spec.PBEKeySpec");
    PBE.$init.overload('[C', '[B', 'int', 'int').implementation = function (pw, salt, iter, len) {
        console.log(`\n[*] PBEKeySpec(salt=${salt.length}B, iterations=${iter}, keyLength=${len})`);
        if (iter < 100000) console.log("    [!! iteration count too low !!]");
        if (len < 256)     console.log("    [!! small keyLength !!]");
        if (salt.length < 16) console.log("    [!! salt < 16 bytes !!]");
        console.log(bt());
        return this.$init(pw, salt, iter, len);
    };
});
```

Run with:

```bash
frida -U -f com.example.target -l keysize_trace.js -o keysize.log
```

Advantage: **you see the key size value actually used**, including when it comes from a variable, remote configuration, or obfuscated code — plus a backtrace showing the calling location.

---

### 3.6 Alternative Testing Methods (Multi-Tool)

The MASTG rule only covers three literal patterns and leaves 16 gaps (§3.4). Below are alternative paths.

#### Method B — Structured ripgrep *(closes all five key-size-determining paths)*

See §3.4 for the full list of commands. The core idea: the MASTG rule only covers **Path A** (plain JCA), while key size can be set in **five places** (§1.5).

```bash
D=./decompiled/sources

# All key-size-determining paths at once, then filter for small values
rg -n --no-heading "\.(initialize|init)\(\s*(56|64|96|128|160|192|224|512|768|1024)\b" $D
rg -n --no-heading "setKeySize\(\s*(56|64|96|128|512|768|1024|2048)\s*\)" $D
rg -n --no-heading "new SecretKeySpec\(\s*new byte\[(8|16)\]|ByteArray\((8|16)\)" $D
rg -n --no-heading "new PBEKeySpec\(" $D -A1
rg -n --no-heading "ECGenParameterSpec\(|secp(160|192)|prime192|brainpoolP160" $D

# Broken algorithms — key size no longer relevant
rg -ni --no-heading '"DES"|"DESede"|TripleDES|"Blowfish"|"RC2"|"RC4"|"ARCFOUR"|"IDEA"' $D

# Class-level key size constants (literal pattern gap)
rg -n --no-heading "(static )?(final )?int [A-Z_]*KEY[_]?(SIZE|LEN|LENGTH)[A-Z_]* *= *[0-9]+" $D
```

#### Method C — SonarQube / SonarLint *(most targeted for this test)*

**Rule `java:S4426` — *Cryptographic keys should be robust*** is a far more complete implementation than the MASTG rule: it understands the algorithm's context and applies different thresholds for RSA, EC, DH, and symmetric keys — including when the size comes from a constant.

```bash
sonar-scanner -Dsonar.projectKey=android-app -Dsonar.sources=./app/src -Dsonar.java.binaries=./app/build
```

Related rules covered at the same time: `java:S5542` (encryption mode/padding), `java:S4790` (weak hashing), `java:S2278` (DES). A major advantage: it surfaces in the developer's IDE via **SonarLint** before a commit.

#### Method D — CodeQL *(resolves constant values across functions)*

Answers the MASTG rule's biggest gap: key sizes that come from a **variable or constant**.

```bash
codeql database create ./cqldb --language=java --command="./gradlew assembleDebug"
codeql database analyze ./cqldb \
  codeql/java-queries:Security/CWE/CWE-326/InsufficientKeySize.ql \
  --format=sarif-latest --output=keysize.sarif
```

```ql
/**
 * @name Insufficient key size (resolves constants)
 * @kind problem
 */
import java

from MethodAccess ma, int size, string algo
where
  (ma.getMethod().hasName("initialize") or ma.getMethod().hasName("init") or
   ma.getMethod().hasName("setKeySize")) and
  size = ma.getArgument(0).(CompileTimeConstantExpr).getIntValue() and
  algo = ma.getQualifier().(MethodAccess).getArgument(0).(StringLiteral).getValue() and
  (
    (algo = "RSA" and size < 3072) or
    (algo = "AES" and size < 256) or
    (algo = "EC"  and size < 256) or
    (algo = "DSA" and size < 3072)
  )
select ma, "Key size " + size + " is insufficient for " + algo
```

> The `getIntValue()` call on `CompileTimeConstantExpr` is the key here — CodeQL **resolves** `private static final int KEY_SIZE = 1024; ... initialize(KEY_SIZE)`, which semgrep's literal pattern can never catch.

#### Method E — MobSF *(citation-ready report)*

Look in **Code Analysis**: *"The App uses RSA Crypto with less than 2048 bit key length"*, *"The App uses a weak encryption algorithm"*. MobSF also checks `Cipher` mode/padding at the same time, giving a comprehensive crypto picture in a single pass.

#### Method F — mobsfscan *(CLI for CI/CD)*

```bash
mobsfscan --json -o out.json ./decompiled/sources/
jq '.results | to_entries[] | select(.key | test("key|rsa|crypto"))' out.json
mobsfscan --exit-warning ./decompiled/sources/     # CI gate
```

#### Method G — Checking bundled cryptographic assets *(blind spot of all code scanners)*

Pinning certificates, keystores, and public keys in `assets/`/`res/raw/` have their own key size — and **will not be found by scanning code**.

```bash
unzip -o ./target-app.apk -d ./apk_x >/dev/null

# Certificates
for c in $(find ./apk_x -iname "*.crt" -o -iname "*.pem" -o -iname "*.cer" -o -iname "*.der"); do
  echo "--- $c"
  openssl x509 -in "$c" -noout -text 2>/dev/null | grep -E "Public-Key|Signature Algorithm" | head -3
done

# Keystore (BKS/JKS/PKCS#12)
for k in $(find ./apk_x -iname "*.bks" -o -iname "*.jks" -o -iname "*.p12" -o -iname "*.keystore"); do
  echo "--- $k"
  keytool -list -v -keystore "$k" -storetype BKS -storepass "" 2>/dev/null | grep -iE "Algorithm|key size|Owner"
done

# Public key hardcoded as Base64 (e.g., for pinning)
rg -n --no-heading "MII[A-Za-z0-9+/]{40,}" ./decompiled/sources/ | head
```

#### Method H — Native code analysis

```bash
for so in $(find ./apk_x -name "*.so"); do
  echo "--- $so"
  strings "$so" | grep -xE "RSA_generate_key|RSA_generate_key_ex|EVP_PKEY_keygen|EVP_PKEY_CTX_set_rsa_keygen_bits|DH_generate_parameters|EC_KEY_new_by_curve_name|DES_set_key|BF_set_key"
done
```

#### Method I — APKHunt & semgrep registry

```bash
APKHunt -p ./target-app.apk -l
semgrep --config "p/java" --config "p/mobsfscan" ./decompiled/sources/
semgrep --config "r/java.lang.security.audit.crypto.weak-rsa.use-of-weak-rsa-key" ./decompiled/sources/
```

---

### 3.7 Method Comparison: When to Use Which

| Method | Tool | Needs device? | Needs source? | Resolves constants? | Covers all 5 paths (§1.5)? | When to use |
|---|---|---|---|---|---|---|
| **A** | semgrep (MASTG) | No | No | ❌ | ❌ (only Path A, partially) | Official baseline & CI gate |
| **B** | Structured ripgrep | No | No | Manual | ✅ | **Mandatory cross-verification** |
| **C** | SonarQube `java:S4426` | No | Yes | ✅ | ✅ | **Most targeted**; shift-left in the IDE |
| **D** | CodeQL | No | Yes (ideal) | ✅ **automatic** | ✅ | Best when size comes from a variable/constant |
| **E** | MobSF | No | No | Partial | Partial | Citation-ready report + comprehensive crypto audit |
| **F** | mobsfscan | No | No | Partial | Partial | Lightweight CI/CD gate |
| **G** | openssl / keytool | No | No | — | — | **Bundled cryptographic assets** — blind spot of code scanners |
| **H** | `strings` / Ghidra | No | No | Manual | ✅ (native) | APK with `.so` files |
| **I** | APKHunt / semgrep registry | No | No | ❌ | Partial | Additional automated pass |
| **J** | Frida (§3.5) | **Yes** | No | ✅ (runtime value) | ✅ | Size from a variable, remote configuration, obfuscated code |

**Minimum recommended combination:** **B (ripgrep) → A (semgrep) → G (bundled assets)**.
B closes all five key-size-determining paths, A provides a baseline aligned with MASTG, G checks the surface untouched by code scanners. If source is available, **C (SonarQube `java:S4426`)** is a better substitute for A because it genuinely understands algorithm context. Add **J (Frida)** when the key size cannot be determined statically.

---

## 4. Recommendations

### 4.1 Main Principle (in priority order)

**Priority 1 — Raise the key size to the recommended level.**

```kotlin
// ❌ WRONG
KeyPairGenerator.getInstance("RSA").initialize(1024, SecureRandom())
KeyGenerator.getInstance("AES").init(128)
KeyGenerator.getInstance("DES").init(56)
KeyPairGenerator.getInstance("EC").initialize(160)

// ✅ CORRECT
KeyPairGenerator.getInstance("RSA").initialize(4096, SecureRandom())   // ≥ 3072
KeyGenerator.getInstance("AES").init(256)
KeyPairGenerator.getInstance("EC").initialize(256)                      // P-256
```

Use the table in §1.3 as a reference. And **always make the key size explicit** — don't rely on the provider default, which can differ across Android versions and implementations.

**Priority 2 — Even better: use the Android KeyStore, not plain JCA.**

This is a stronger fix because it also solves the key-storage problem. The MASTG-DEMO-0012 sample uses plain JCA, so the key resides in the app's heap and can be dumped. With the KeyStore, **key material never leaves secure hardware**.

```kotlin
// ✅ AES-256 GCM via Android KeyStore
val keyGen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
keyGen.init(
    KeyGenParameterSpec.Builder(
        "vault_key",
        KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
    )
        .setKeySize(256)
        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
        .setRandomizedEncryptionRequired(true)
        .setUserAuthenticationRequired(true)       // for the most sensitive data
        .setIsStrongBoxBacked(true)                // if hardware supports it
        .build()
)
keyGen.generateKey()
```

> **Note two Android KeyStore limitations** relevant when fixing this:
> - **Since Android 11 (API 30), AndroidKeyStore does not support encryption/decryption with EC keys** — EC is only for signatures. So don't replace a weak RSA with EC for encryption.
> - Before Android 6.0 (API 23), AES key generation was not supported by the KeyStore. If `minSdkVersion` is still below 23, a fallback path is needed — but API 23 is already very old, so raising `minSdkVersion` is preferable.

**Priority 3 — Replace broken algorithms, not just enlarge their keys.**

| Replace | With | Reason |
|---|---|---|
| DES, 3DES | **AES-256-GCM** | DES broken (56-bit); 3DES *disallowed* by NIST, 64-bit block |
| Blowfish | **AES-256-GCM** or ChaCha20-Poly1305 | 64-bit block → vulnerable to *Sweet32* |
| RC4, RC2, IDEA | **AES-256-GCM** | Broken / outdated |
| RSA PKCS#1 v1.5 (encryption) | **RSA-OAEP** ≥ 3072, or better: **hybrid** (ECDH + AES-GCM) | Padding oracle |
| RSA PKCS#1 v1.5 (signature) | **RSA-PSS** ≥ 3072, or **ECDSA P-256** | Current practice |
| `PBKDF2WithHmacSHA1` | **`PBKDF2withHmacSHA256`** (or Argon2id) | SHA-1 outdated; KNOW-0012 itself recommends SHA256 for API 26+ |

**Priority 4 — Fix supporting key-generation parameters** (§1.6).

```kotlin
// ✅ KDF with adequate parameters
val salt = ByteArray(16).also { SecureRandom().nextBytes(it) }   // salt ≥ 16 bytes, from a CSPRNG
val spec = PBEKeySpec(password, salt, 600_000, 256)              // high iteration count, keyLength 256
val factory = SecretKeyFactory.getInstance("PBKDF2withHmacSHA256")
val key = SecretKeySpec(factory.generateSecret(spec).encoded, "AES")

// ✅ GCM with a 128-bit tag and a 12-byte nonce
val nonce = ByteArray(12).also { SecureRandom().nextBytes(it) }
cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, nonce))
```

> Note: MASTG-KNOW-0012 exemplifies `iterationCount = 10000` for PBKDF2. That number is **already outdated** — OWASP now recommends **600,000** iterations for PBKDF2-HMAC-SHA256. If possible, use **Argon2id**, which is resistant to GPU/ASIC-based attacks.

**Priority 5 — Make sure the key is generated from a proper entropy source.** An AES-256 key generated from `java.util.Random` or from a timestamp only has as much entropy as its source — the key size becomes meaningless. See **MASTG-TEST-0204** and **MASTG-TEST-0205**.

```kotlin
// ❌ Large key size, small entropy
val key = ByteArray(32); java.util.Random().nextBytes(key)

// ✅ Let the platform generate it, or use SecureRandom
KeyGenerator.getInstance("AES", "AndroidKeyStore").init(spec)     // best
// or
val key = ByteArray(32).also { SecureRandom().nextBytes(it) }
```

**Priority 6 — Don't rely on the NDK to "hide" cryptography.** MASTG-KNOW-0012 confirms this is a widespread false belief: moving crypto operations or hardcoded keys into native code **is not effective**. An attacker can still identify the mechanism and dump the key from memory with Frida, then analyze the control flow with radare2. And since Android 7.0 (API 24), the use of private APIs is not allowed, further reducing the effectiveness of hiding. **The solution is the Android KeyStore**, not obfuscation.

**Priority 7 — Update bundled cryptographic assets.** Pinning certificates, keystores, and hardcoded public keys in `assets/` or `res/raw/` must use RSA ≥ 2048 (ideally 4096) or EC ≥ 256. These are often forgotten because they are not part of the code.

**Priority 8 — Plan for crypto-agility and post-quantum migration.** This is what makes this test relevant for the long term:

- **RSA-2048 is being deprecated toward 2030.** If the app stores data that must remain protected past 2030, migrate to ≥ 3072 now.
- **NIST IR 8547 plans to prohibit all quantum-vulnerable public-key cryptography — including RSA-3072, P-256, P-384 — by 2035.**
- The **"harvest now, decrypt later"** threat: data encrypted today with RSA/ECC and captured by an attacker can be decrypted later once a relevant quantum computer becomes available. For data with a long sensitivity lifetime (medical records, identity data), this is a real risk **now**.
- **Design for crypto-agility**: create a cryptographic abstraction layer so algorithms and key sizes can be changed without altering business logic. Store an algorithm version marker alongside the ciphertext so migration can happen incrementally.
- Monitor PQC standards: **ML-KEM (Kyber)** for key encapsulation, **ML-DSA (Dilithium)** and **SLH-DSA (SPHINCS+)** for signatures. Consider **hybrid** modes (classical + PQC) as a transition step.
- **AES-256 is already quantum-resistant** for the foreseeable future — this is an additional strong reason to choose AES-256 over AES-128, regardless of the debate in §1.4.

**Priority 9 — Enforce this structurally.**
- Add SAST rules to CI/CD (the MASTG rule + the extended rules from §3.4) and fail the build if a key size below policy appears.
- Define an explicit **organizational cryptography policy** (minimum algorithms & key sizes), then enforce it via lint/SAST — not via manual code review.
- Create **one centralized cryptography utility** (e.g., `CryptoProvider.newAesKey()`, `CryptoProvider.newSigningKey()`) and prohibit direct calls to `KeyGenerator`/`KeyPairGenerator`.
- Audit third-party libraries — run the scan on decompiled library code as well.

### 4.2 Remediation Checklist

- [ ] Every finding from semgrep + complementary grep has been reviewed with MASTG-TECH-0023
- [ ] No RSA/DSA/DH < 2048; target ≥ **3072** (ideally 4096) for new systems
- [ ] No RSA-1024 / 768 / 512 in code or in bundled certificates
- [ ] All symmetric keys are **AES-256**
- [ ] No DES, 3DES, Blowfish, RC2, RC4, or IDEA
- [ ] All EC curves ≥ **256** (P-256/P-384); no secp160/192
- [ ] HMAC keys ≥ hash output size (≥ 256 bits for HMAC-SHA256)
- [ ] Key size is **always made explicit** — not relying on the provider default
- [ ] All key-size-determining paths have been checked: `init()`, `initialize()`, `KeyGenParameterSpec.setKeySize()`, `KeyPairGeneratorSpec.setKeySize()`, `PBEKeySpec`'s `keyLength`, `SecretKeySpec` array length
- [ ] Key sizes coming from a variable/constant have had their values verified
- [ ] Keys are generated and managed by the **Android KeyStore** (not plain JCA); `setUserAuthenticationRequired` & StrongBox are considered
- [ ] Mode & padding are correct: AES-GCM (not ECB/CBC-without-MAC), RSA-OAEP for encryption, RSA-PSS/ECDSA for signatures
- [ ] GCM tag is 128 bits, nonce is 12 bytes, nonce never repeats for the same key
- [ ] KDF: `PBKDF2withHmacSHA256` (not SHA1) with iterations ≥ 600,000, or Argon2id; salt ≥ 16 bytes from `SecureRandom`
- [ ] Keys are generated from **`SecureRandom`** or the KeyStore — not `java.util.Random`/timestamp (cross-verify MASTG-TEST-0204 & 0205)
- [ ] No hardcoded keys, and no attempt to "hide" cryptography in the NDK
- [ ] Certificates/keystores bundled in the APK use RSA ≥ 2048 (ideally 4096) or EC ≥ 256
- [ ] Cryptography from native code has been checked and meets the same policy
- [ ] Third-party libraries have been audited
- [ ] All split APKs / dynamic feature modules are included in the analysis
- [ ] **Crypto-agility**: a cryptographic abstraction layer exists, algorithm version is stored alongside the ciphertext
- [ ] Migration roadmap: RSA-2048 → ≥3072 before 2030; PQC plan (ML-KEM/ML-DSA) toward 2035
- [ ] Organizational cryptography policy is documented and enforced via SAST in CI/CD
- [ ] A centralized cryptography utility has been created; direct calls to `KeyGenerator`/`KeyPairGenerator` are prohibited
- [ ] **Re-verify:** re-run MASTG-TEST-0208 + complementary grep → no key size below policy
- [ ] **Cross-verify:** MASTG-TEST-0221 (broken algorithms), MASTG-TEST-0232 (broken modes), MASTG-TEST-0204/0205 (key entropy source)

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0208: Insufficient Key Sizes](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0208/)
- [MASWE-0013: Improper Cryptographic Key Generation](https://mas.owasp.org/MASWE/MASVS-CRYPTO/MASWE-0013/)
- [MASTG-DEMO-0012: Cryptographic Key Generation With Insufficient Key Length](https://mas.owasp.org/MASTG/demos/android/MASVS-CRYPTO/MASTG-DEMO-0012/MASTG-DEMO-0012/)
- [MASTG-KNOW-0012: Key Generation](https://mas.owasp.org/MASTG/knowledge/android/MASVS-CRYPTO/MASTG-KNOW-0012/)
- [MASTG-TEST-0221: Uses of Broken Symmetric Encryption Algorithms](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0221/)
- [MASTG-TEST-0232: Uses of Broken Encryption Modes](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0232/)
- [MASTG-TEST-0212: Use of Hardcoded AES Key in SecretKeySpec](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0212/)
- [MASTG-TEST-0204: Insecure Random API Usage](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0204/)
- [MASTG-TEST-0205: Non-random Sources Usage](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0205/)
- [MASTG-TECH-0013: Reverse Engineering Android Apps](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/)
- [MASTG-TECH-0014: Static Analysis on Android](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/)
- [MASTG-TECH-0023: Reviewing Decompiled Java Code](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0023/)
- [MASTG-TOOL-0110: semgrep](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0110/)
- [MASTG-TOOL-0018: jadx](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0018/)
- [MASTG Rules — `mastg-android-key-generation-with-insufficient-key-length.yml`](https://github.com/OWASP/mastg/blob/master/rules/mastg-android-key-generation-with-insufficient-key-length.yml)
- [MASTG — Testing Cryptography (Key Generation)](https://mas.owasp.org/MASTG/0x05e-Testing-Cryptography/)
- [MASVS-CRYPTO: Cryptography](https://mas.owasp.org/MASVS/06-MASVS-CRYPTO/)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [OWASP Password Storage Cheat Sheet (PBKDF2/Argon2 parameters)](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [OWASP Mobile Top 10 2024 — M10: Insufficient Cryptography](https://owasp.org/www-project-mobile-top-10/2023-risks/m10-insufficient-cryptography.html)

### 5.2 Cryptographic Standards & Key Length Recommendations

- [NIST SP 800-57 Part 1 Rev. 5 — Recommendation for Key Management](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final)
- [NIST SP 800-57 Part 3 Rev. 1 — Application-Specific Key Management Guidance](https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-57pt3r1.pdf)
- [NIST SP 800-131A Rev. 2 — Transitioning the Use of Cryptographic Algorithms and Key Lengths](https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final)
- [NIST IR 8547 — Transition to Post-Quantum Cryptography Standards](https://csrc.nist.gov/pubs/ir/8547/ipd)
- [NIST SP 800-132 — Recommendation for Password-Based Key Derivation (PBKDF2)](https://csrc.nist.gov/publications/detail/sp/800-132/final)
- [NIST SP 800-38D — Galois/Counter Mode (GCM)](https://csrc.nist.gov/publications/detail/sp/800-38d/final)
- [NIST FIPS 197 — Advanced Encryption Standard (AES)](https://csrc.nist.gov/publications/detail/fips/197/final)
- [NIST FIPS 186-5 — Digital Signature Standard (DSS)](https://csrc.nist.gov/publications/detail/fips/186/5/final)
- [NIST Post-Quantum Cryptography — FAQs](https://csrc.nist.gov/projects/post-quantum-cryptography/faqs)
- [NSA CNSA 2.0 — Commercial National Security Algorithm Suite](https://www.nsa.gov/Press-Room/News-Highlights/Article/Article/3148990/)
- [BSI TR-02102-1 — Cryptographic Mechanisms: Recommendations and Key Lengths](https://www.bsi.bund.de/EN/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/Technische-Richtlinien/TR-nach-Thema-sortiert/tr02102/tr02102_node.html)
- [ECRYPT-CSA — Algorithms, Key Size and Protocols Report](https://www.ecrypt.eu.org/csa/documents/D5.4-FinalAlgKeySizeProt.pdf)
- [Keylength.com — comparison of key length recommendations across standards bodies](https://www.keylength.com/)
- [RFC 8017 — PKCS #1 v2.2 (RSA, OAEP, PSS)](https://datatracker.ietf.org/doc/html/rfc8017)
- [RFC 7539 / 8439 — ChaCha20 and Poly1305](https://datatracker.ietf.org/doc/html/rfc8439)

### 5.3 Official Android / Google / Java Documentation

- [`javax.crypto.KeyGenerator` — API reference](https://developer.android.com/reference/javax/crypto/KeyGenerator)
- [`KeyGenerator.init(int keysize)` — API reference](https://developer.android.com/reference/javax/crypto/KeyGenerator#init(int))
- [`java.security.KeyPairGenerator` — API reference](https://developer.android.com/reference/java/security/KeyPairGenerator)
- [`KeyPairGenerator.initialize(int keysize)` — API reference](https://developer.android.com/reference/java/security/KeyPairGenerator#initialize(int))
- [`KeyGenParameterSpec` — API reference](https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec)
- [`KeyGenParameterSpec.Builder.setKeySize()` — API reference](https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder#setKeySize(int))
- [`KeyPairGeneratorSpec` (deprecated) — API reference](https://developer.android.com/reference/android/security/KeyPairGeneratorSpec)
- [`PBEKeySpec` — API reference](https://developer.android.com/reference/javax/crypto/spec/PBEKeySpec)
- [`SecretKeySpec` — API reference](https://developer.android.com/reference/javax/crypto/spec/SecretKeySpec)
- [`GCMParameterSpec` — API reference](https://developer.android.com/reference/javax/crypto/spec/GCMParameterSpec)
- [Android — Cryptography (supported algorithms & ciphers)](https://developer.android.com/guide/topics/security/cryptography)
- [Android — Supported Cipher suites & EC limitation on KeyStore](https://developer.android.com/guide/topics/security/cryptography#SupportedCipher)
- [Android Keystore system](https://developer.android.com/privacy-and-security/keystore)
- [Cryptography best practices](https://developer.android.com/privacy-and-security/cryptography)
- [Android Developers Blog — Android changes for NDK developers](https://android-developers.googleblog.com/2016/06/android-changes-for-ndk-developers.html)
- [Google Tink — cryptographic library](https://developers.google.com/tink)
- [Conscrypt — Java Security Provider](https://github.com/google/conscrypt)

### 5.4 Standards & Weakness Taxonomies

- [CWE-326: Inadequate Encryption Strength](https://cwe.mitre.org/data/definitions/326.html)
- [CWE-310: Cryptographic Issues](https://cwe.mitre.org/data/definitions/310.html)
- [CWE-327: Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)
- [CWE-1240: Use of a Cryptographic Primitive with a Risky Implementation](https://cwe.mitre.org/data/definitions/1240.html)
- [SonarQube Rule java:S4426 — Cryptographic keys should be robust](https://rules.sonarsource.com/java/RSPEC-4426/)
- [SEI CERT Oracle Coding Standard for Java — MSC61-J: Do not use insecure or weak cryptographic algorithms](https://wiki.sei.cmu.edu/confluence/display/java/MSC61-J.+Do+not+use+insecure+or+weak+cryptographic+algorithms)
- [NIST SP 800-163 Rev.1 — Vetting the Security of Mobile Applications](https://csrc.nist.gov/publications/detail/sp/800-163/rev-1/final)
- [CodeQL — Java query help (weak cryptography)](https://codeql.github.com/codeql-query-help/java/)

### 5.5 Research & Technical Articles

- [Filippo Valsorda — *Quantum Computers Are Not a Threat to 128-bit Symmetric Keys*](https://words.filippo.io/128-bits/)
- [PostQuantum.com — CNSA 2.0: Complete Guide to NSA's PQC Requirements](https://postquantum.com/cnsa-2-0/complete-guide/)
- [Encryption Consulting — NIST Post-Quantum Cryptography Security Levels (Categories 1–5)](https://www.encryptionconsulting.com/nist-post-quantum-cryptography-security-levels/)
- [ADHDecode — Key Size Guide: SP 800-57, ECRYPT, BSI](https://adhdecode.com/cryptography/reference-and-decision-guides/key-size-guide/)
- [AQtive Guard — Cryptographic keylengths reference](https://docs.aqtiveguard.com/kb-articles/cryptographic-keylengths/)
- [DEV Community — Why Can We Use "Shorter" Keys? Key Length vs Security Bits](https://dev.to/kanywst/why-can-we-use-shorter-keys-key-length-vs-security-bits-the-real-story-1gl3)
- [arXiv — *Post-Quantum Security: Origin, Fundamentals, and Adoption*](https://arxiv.org/pdf/2405.11885)
- [arXiv — *The Impact of Quantum Computing on Present Cryptography*](https://arxiv.org/pdf/1804.00200)
- [Sweet32 — Birthday attacks on 64-bit block ciphers](https://sweet32.info/)
- [HackTricks — Android Applications Pentesting](https://book.hacktricks.wiki/en/mobile-pentesting/android-app-pentesting/index.html)

### 5.6 Tool Documentation

- [Semgrep — Documentation](https://semgrep.dev/docs/)
- [Semgrep — Pattern syntax reference](https://semgrep.dev/docs/writing-rules/pattern-syntax/)
- [mindedsecurity/semgrep-rules-android-security](https://github.com/mindedsecurity/semgrep-rules-android-security)
- [mobsfscan — static analysis for Android/iOS](https://github.com/MobSF/mobsfscan)
- [MobSF — Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)
- [CodeQL — Documentation](https://codeql.github.com/docs/)
- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [apktool — Reverse engineering Android APK files](https://apktool.org/)
- [APKiD — Android Application Identifier](https://github.com/rednaga/APKiD)
- [Frida — Documentation Home](https://frida.re/docs/home/)
- [OpenSSL — `x509` command](https://www.openssl.org/docs/man3.0/man1/openssl-x509.html)
- [keytool — Java key and certificate management tool](https://docs.oracle.com/en/java/javase/17/docs/specs/man/keytool.html)

---

*This document was compiled based on OWASP MASTG (latest release as of September 2026), official Android Developers documentation, NIST/FIPS/BSI/ECRYPT/CNSA 2.0 standards, and third-party cryptographic research.*
