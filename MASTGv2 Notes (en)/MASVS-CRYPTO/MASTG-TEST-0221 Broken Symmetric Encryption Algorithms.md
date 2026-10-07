# MASTG-TEST-0221 Broken Symmetric Encryption Algorithms

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0221 |
| **Platform** | Android |
| **MASVS Category** | **MASVS-CRYPTO** (MASVS-CRYPTO-1: The app uses up-to-date, correctly implemented cryptography) |
| **Weakness** | **MASWE-0007** — *Use of a Broken or Risky Cryptographic Algorithm* |
| **Test Type** | **Static**, Code, Manual |
| **Profile** | L1, L2 |
| **Best Practice** | MASTG-BEST-0009 (Use Secure Encryption Algorithms) |
| **Related Techniques** | MASTG-TECH-0013 (Reverse Engineering Android Apps), MASTG-TECH-0014 (Static Analysis on Android), MASTG-TECH-0023 (Reviewing Decompiled Java Code) |
| **Related Demo** | MASTG-DEMO-0022 (Uses of Broken Symmetric Encryption Algorithms in Cipher with semgrep) |
| **Sibling Tests** | MASTG-TEST-0232 (Uses of Broken Encryption Modes — ECB/CBC-without-MAC), MASTG-TEST-0208 (Insufficient Key Sizes), MASTG-TEST-0212 (Hardcoded Keys) |
| **Key APIs** | `javax.crypto.Cipher.getInstance(String)`, `javax.crypto.SecretKeyFactory.getInstance(String)`, `javax.crypto.KeyGenerator.getInstance(String)` |
| **Related CWE** | CWE-327 (Use of a Broken or Risky Cryptographic Algorithm), CWE-326 (Inadequate Encryption Strength), CWE-328 (Use of Weak Hash — for derived algorithms), CWE-1240 (Use of a Cryptographic Primitive with a Risky Implementation) |

---

## 1. Explanation

### 1.1 Testing Objective

This test looks for the use of **symmetric encryption algorithms that have already been declared broken** within Android application code, through static analysis.

Direct quote from the MASTG overview:

> *"To test for the use of broken encryption algorithms in Android apps, we need to focus on methods from cryptographic frameworks and libraries that are used to perform encryption and decryption operations."*

Three explicitly named API entry points:

| API | Function |
|---|---|
| **`Cipher.getInstance(String)`** | Initializes a Cipher object for encryption/decryption. **The primary entry point** — the algorithm name is a string argument |
| **`SecretKeyFactory.getInstance(String)`** | Converts key material into a `SecretKey`. The algorithm name here indicates the **key scheme** being used (e.g., `"DES"`, `"DESede"`) |
| **`KeyGenerator.getInstance(String)`** | Generates a symmetric key. The algorithm name determines the type of key created |

**Fundamental difference from MASTG-TEST-0208** (Insufficient Key Sizes): that test evaluates the **size** of a key for an algorithm still considered valid (RSA-1024 vs. RSA-3072, AES-128 vs. AES-256). This test evaluates **the algorithm itself** — DES, 3DES, RC4, and Blowfish cannot be fixed by enlarging the key; they are structurally broken and must be **replaced entirely**.

### 1.2 The Four Algorithms Explicitly Named by MASTG

MASTG lists four broken algorithms along with their individual technical rationale — this is not opinion, but official status from standards bodies.

**DES (Data Encryption Standard):**
> *"56-bit key, breakable, [withdrawn by NIST in 2005](https://csrc.nist.gov/pubs/fips/46-3/final)."*

A 56-bit key space (2⁵⁶ possibilities) has been brute-forceable with specialized hardware since the late 1990s (the EFF "Deep Crack" project broke it in 56 hours in 1998). NIST withdrew FIPS 46-3 (the DES standard) in 2005 — meaning DES **has officially not been an approved cryptographic standard** by the US government for almost two decades.

**3DES / Triple DES (Triple Data Encryption Algorithm / TDEA):**
> *"64-bit block size, [vulnerable to Sweet32 birthday attacks](https://sweet32.info/), [withdrawn by NIST on January 1, 2024](https://csrc.nist.gov/pubs/sp/800/67/r2/final)."*

3DES solved DES's key-space problem (by applying DES three times), but **inherited the 64-bit block size**, which became a new problem: **Sweet32 (CVE-2016-2183)**. This is a *birthday attack* — after ~2³² blocks (~32 GB of data) encrypted with the same key in CBC mode, the probability of a **collision** between ciphertext blocks becomes significant. When two ciphertext blocks collide, XOR-ing them reveals the XOR of their plaintexts; if one plaintext is known (or guessable), the other plaintext can be recovered. For long-lived connections/encryption that process large amounts of data under a fixed key, this is a real risk — not merely theoretical. **NIST withdrew 3DES entirely effective January 1, 2024** (SP 800-67 Rev. 2).

**RC4:**
> *"Predictable key stream, allows plaintext recovery [RC4 Weakness](https://www.rc4nomore.com/), disapproved by [NIST](https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-52r1.pdf) in 2014 and prohibited by [IETF](https://datatracker.ietf.org/doc/html/rfc7465) in 2015."*

RC4 is a stream cipher with statistical bias in the first bytes of its keystream, enabling plaintext recovery without needing to know the key — especially when the same plaintext is encrypted repeatedly (a common scenario in HTTP, such as cookies). **IETF officially banned RC4 in TLS via RFC 7465 (2015)** — an internet-protocol-level prohibition, not merely a recommendation.

**Blowfish:**
> *"64-bit block size, [vulnerable to Sweet32 attacks](https://en.wikipedia.org/wiki/Birthday_attack), never FIPS-approved, and listed under 'Non-Approved algorithms' in FIPS."*

Blowfish was never a FIPS standard from the outset, and it inherits the same 64-bit block problem as 3DES — vulnerable to Sweet32. It frequently appears in applications because it is perceived as "fast and simple," without the developer realizing its structural block-size weakness.

**Summary table for quick reference:**

| Algorithm | Main problem | Official status | Named vulnerability |
|---|---|---|---|
| **DES** | 56-bit key — brute-forceable | Withdrawn by NIST (2005) | — |
| **3DES/DESede/TDEA** | 64-bit block | Withdrawn by NIST (Jan 1, 2024) | Sweet32 (CVE-2016-2183) |
| **RC4/ARCFOUR** | Keystream bias | Banned by IETF (RFC 7465, 2015); disapproved by NIST (2014) | RC4 biases (Royal Holloway attack, et al.) |
| **Blowfish** | 64-bit block | Never FIPS-approved | Sweet32 |

### 1.3 Other Algorithms That Also Count as Broken (Beyond the Four Named by MASTG)

The MASTG overview explicitly states "some broken symmetric encryption algorithms **include**" — not an exhaustive list. The Android documentation referenced by MASTG (*Broken or Risky Cryptographic Algorithm*) covers a broader scope including hash functions and signature schemes, and in real-world testing practice you should also look for:

| Algorithm | Category | Problem |
|---|---|---|
| **RC2** | Symmetric | Very weak, practically obsolete, similarly insecure to RC4 |
| **IDEA** | Symmetric | Rarely used, considered obsolete even though not as broken as DES |
| **SKIPJACK** | Symmetric | An old NSA algorithm (Clipper chip), 80-bit key, now obsolete |
| **XOR "encryption"** | Not real encryption | Often found as a custom implementation — falls under the *"non-approved algorithm"* category, not merely "weak" |
| **AES/ECB** | Mode, not an algorithm | AES itself is strong, but ECB mode is broken — this is covered by **MASTG-TEST-0232**, not this test |
| **MD5, SHA-1** (as part of an encryption/HMAC scheme) | Hash | Described by Android as *"vulnerable"*; relevant when used in a ciphertext-integrity context |

> **Scope boundary of this test:** MASTG-TEST-0221 focuses on **symmetric encryption algorithms**. Weak hash algorithms (MD5/SHA-1) and incorrect encryption modes (ECB) have separate tests/discussions — don't mix them up when reporting, even though the root cause is similar (obsolete cryptography).

### 1.4 Why "Broken" Differs from "Insufficient"

This is an important nuance that distinguishes this test from MASTG-TEST-0208:

- **AES-128** is considered by MASTG to be *insufficient* — it remains a mathematically solid algorithm, only its key size is debatable (see the discussion of Grover's algorithm in the MASTG-TEST-0208 document). The solution: **increase the key size**, keeping the same algorithm (AES-256).
- **DES/3DES/RC4/Blowfish** are considered *broken* — their flaw is **structural**: a key space that is too small (DES), a block size that is too small (3DES/Blowfish), or mathematical bias in the keystream (RC4). **There is no way to fix this** by enlarging any parameter. The only remediation is to **replace the algorithm entirely**.

This also means the default severity of this test is generally **higher** than MASTG-TEST-0208 — there is no "good enough for now, upgrade later"; broken is broken.

### 1.5 "Security-Relevant" Context Still Applies Here

Just as with MASTG-TEST-0204/0205/0212, the MASTG evaluation criteria require context validation:

> *"Inspect each reported code location using MASTG-TECH-0023 to determine whether the algorithm is used in a **security-relevant context** to protect sensitive data."*

However, the weight here differs from the PRNG test: using DES/RC4/Blowfish is **almost always** a finding worth reporting, because:

- These algorithms are **rarely** used for non-cryptographic purposes (checksums, etc.) — unlike `java.util.Random`, which is reasonably used for animation.
- Their presence in **modern** code almost always indicates one of: (a) legacy code not yet refactored, (b) compatibility with old external systems (e.g., integration with a mainframe/old bank API that still requires 3DES), or (c) a developer's incorrect algorithm choice.

Still perform the MASTG-TECH-0023 verification, but don't expect to find as many legitimate *false positives* as in the PRNG test — here the determination leans more toward **severity** (what data is being protected) than **relevance** (whether this is a vulnerability at all).

---

## 2. Tools Used for Testing

### 2.1 Required Tools (Core)

| Tool | MASTG ID | Function |
|---|---|---|
| **jadx** | MASTG-TOOL-0018 | **Decompiles DEX → Java** (MASTG-TECH-0013). Required for MASTG-TECH-0023 — to review what data is being encrypted |
| **semgrep** | MASTG-TOOL-0110 | **Pattern matching**. MASTG provides the rule `mastg-android-broken-encryption-algorithms.yaml` |
| **ripgrep/grep** | — | Mandatory supplement — the MASTG rule is fairly narrow (see §3.4) |
| **apktool** | MASTG-TOOL-0011 | Decompilation alternative; smali analysis |

### 2.2 Supporting Tools

| Tool | Function |
|---|---|
| **CodeQL** | Taint analysis — tracks whether the output of `Cipher.getInstance("DES")` actually encrypts sensitive data, rather than merely being called in dead code |
| **MobSF / mobsfscan** | Mobile SAST; has built-in rules for weak crypto algorithms |
| **SonarQube** | Rule `java:S5547` — *Cipher algorithms should be robust*; `java:S4790` — weak hashing |
| **Android Lint** | `TrustAllX509TrustManager`, and Android Studio's built-in crypto checks |
| **Frida** (MASTG-TOOL-0001) | Dynamic confirmation of which algorithm is actually used at runtime (§3.5) — important when the algorithm name comes from a variable/configuration |
| **Ghidra / `strings`** | Crypto configuration in native code — bundled OpenSSL/BoringSSL often uses constants like `EVP_des_cbc()`, `EVP_rc4()`, etc. |
| **APKiD** | Packer/obfuscator detection to assess the reliability of the static analysis |

### 2.3 Environment Prerequisites

- **No device and no root required** for static analysis — the APK is enough. Easy to automate in CI/CD.
- **The complete APK**, including all split APKs / dynamic feature modules.
- **The rule is `languages: java` only** — it works on decompiled code, not Kotlin source. Because this rule is based on `pattern-regex` (not an AST pattern), it is actually fairly tolerant of syntax variation — but it still needs a string literal of the algorithm name to trigger.
- **Know the accompanying `SecretKeySpec`.** The algorithm name in `Cipher.getInstance()` should be cross-checked against the key object used (`SecretKeySpec(bytes, "DES")`) — both should be consistent and serve as corroborating evidence together.
- **Watch out for string name obfuscation.** The algorithm name (`"DES"`, `"RC4"`) is an ordinary string literal, **not** a system API name — so it **can** be obfuscated (XOR'd, split, Base64-encoded) by a developer who is already aware of the risk and tries to hide it. This differs from framework class/method names, which are never obfuscated by ProGuard/R8.

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0013** (*Reverse Engineering Android Apps*) to reverse engineer the application.
2. Use **MASTG-TECH-0014** (*Static Analysis on Android*) to search for the relevant APIs.

For evaluation: use **MASTG-TECH-0023** to review each location found and determine its context.

### 3.2 Method A — semgrep with the official MASTG rule *(baseline)*

**Step 1 — Decompile:**

```bash
jadx -d ./decompiled ./target-app.apk
```

**Step 2 — Run the official MASTG rule:**

```yaml
rules:
  - id: mastg-android-broken-encryption-algorithms
    languages:
      - java
    severity: WARNING
    metadata:
      summary: This rule looks for broken encryption algorithms.
    message: "[MASVS-CRYPTO-1] Broken encryption algorithms found in use."
    pattern-regex: Cipher\.getInstance\("?(DES|DESede|RC4|Blowfish)(/[A-Za-z0-9]+(/[A-Za-z0-9]+)?)?"?\)
```

```bash
NO_COLOR=true semgrep -c ./rules/mastg-android-broken-encryption-algorithms.yaml \
  ./MastgTest_reversed.java > output.txt
```

For a real application:

```bash
NO_COLOR=true semgrep \
  -c ./mastg/rules/mastg-android-broken-encryption-algorithms.yaml \
  ./decompiled/sources/ --json -o findings-broken-crypto.json
```

**Step 3 — Review each finding (MASTG-TECH-0023).** For each location:
1. What data is being encrypted/decrypted there?
2. Is this flow actually executed (not dead code)?
3. Is there a legitimate reason related to external compatibility (legacy system integration), or is it purely a wrong choice?

### 3.3 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rule:**

> **Observation:** *"The output should contain a list of locations where insecure symmetric encryption algorithms are used."*
>
> **Evaluation:** *"The test case **fails** if you can find insecure or deprecated encryption algorithms being used."*
>
> **Further Validation Required:** *"Inspect each reported code location using MASTG-TECH-0023 to determine whether the algorithm is used in a security-relevant context to protect sensitive data."*

---

#### ❌ FAIL / ISSUE — The check is declared FAILED when:

| No | Condition | Example evidence |
|---|---|---|
| F1 | `Cipher.getInstance("DES"...)` is used to encrypt data | `Cipher.getInstance("DES")` followed by `cipher.doFinal(sensitiveData)` |
| F2 | `Cipher.getInstance("DESede"...)` (3DES) is used | Vulnerable to Sweet32 on high-volume data / long-lived connections |
| F3 | `Cipher.getInstance("RC4"...)` / `"ARCFOUR"` is used | Keystream bias enables plaintext recovery |
| F4 | `Cipher.getInstance("Blowfish"...)` is used | Vulnerable to Sweet32; never FIPS-approved |
| F5 | `SecretKeyFactory.getInstance("DES")` / `"DESede"` is used to build a key | Indicates a key scheme for a broken algorithm, even if `Cipher` is not visible on the same line |
| F6 | `KeyGenerator.getInstance("DES")` / `"DESede"` / `"RC4"` / `"Blowfish"` | The app actively creates keys for a broken algorithm |
| F7 | Other broken algorithms: RC2, IDEA, SKIPJACK, or custom XOR | Not covered by the MASTG rule — requires supplementary grep (§3.4) |
| F8 | A broken algorithm is used in **native code** | `strings lib.so` → `EVP_des_cbc`, `EVP_rc4`, `DES_encrypt` |
| F9 | The algorithm name is **obfuscated** (split/XOR'd/Base64-encoded) to evade string detection | `"D"+"E"+"S"` or `base64decode("UkM0")` (= "RC4") before `getInstance()` |
| F10 | A broken algorithm is confirmed to be **actually invoked** at runtime (Frida) | The backtrace points to a function that processes sensitive data |

**Example output signaling a FAIL — MASTG-DEMO-0022:**

Sample code (`MastgTest.kt`) — four functions, each using one broken algorithm:

```kotlin
// Broken: DES
fun vulnerableDesEncryption(data: String): String {
    val keyBytes = ByteArray(8)
    SecureRandom().nextBytes(keyBytes)
    val keySpec = DESKeySpec(keyBytes)
    val keyFactory = SecretKeyFactory.getInstance("DES")
    val secretKey: Key = keyFactory.generateSecret(keySpec)
    val cipher = Cipher.getInstance("DES")                 // <-- line 39 (in the decompiled Java)
    cipher.init(Cipher.ENCRYPT_MODE, secretKey)
    val encryptedData = cipher.doFinal(data.toByteArray())
    return Base64.encodeToString(encryptedData, Base64.DEFAULT)
}

// Broken: 3DES
fun vulnerable3DesEncryption(data: String): String {
    val keyBytes = ByteArray(24)
    val keySpec = DESedeKeySpec(keyBytes)
    val keyFactory = SecretKeyFactory.getInstance("DESede")
    val secretKey: Key = keyFactory.generateSecret(keySpec)
    val cipher = Cipher.getInstance("DESede")               // <-- line 62
    ...
}

// Broken: RC4
fun vulnerableRc4Encryption(data: String): String {
    val secretKey = SecretKeySpec(keyBytes, "RC4")
    val cipher = Cipher.getInstance("RC4")                  // <-- line 81
    ...
}

// Broken: Blowfish
fun vulnerableBlowfishEncryption(data: String): String {
    val secretKey: SecretKey = SecretKeySpec(keyBytes, "Blowfish")
    val cipher = Cipher.getInstance("Blowfish")             // <-- line 100
    ...
}
```

Semgrep output (`output.txt`):

```
┌─────────────────┐
│ 4 Code Findings │
└─────────────────┘

    MastgTest_reversed.java
    ❯❱ rules.mastg-android-broken-encryption-algorithms
          [MASVS-CRYPTO-1] Broken encryption algorithms found in use.

           39┆ Cipher cipher = Cipher.getInstance("DES");
            ⋮┆----------------------------------------
           62┆ Cipher cipher = Cipher.getInstance("DESede");
            ⋮┆----------------------------------------
           81┆ Cipher cipher = Cipher.getInstance("RC4");
            ⋮┆----------------------------------------
          100┆ Cipher cipher = Cipher.getInstance("Blowfish");
```

MASTG evaluation: *"The test **fails** due to the use of broken encryption algorithms, specifically DES, 3DES, RC4 and Blowfish."*

**Three observations from this demo:**

1. **The rule catches only `Cipher.getInstance()`, not `SecretKeyFactory`/`KeyGenerator`.** Note that `SecretKeyFactory.getInstance("DES")` and `SecretKeyFactory.getInstance("DESede")` **do not appear** in the output, even though both are clearly part of the same broken encryption flow. This rule is narrow by design — only four `Cipher.getInstance` lines are detected out of a total of eight broken-crypto API calls in the sample.
2. **This demo sample is structurally clean** — each function uses a single algorithm with a complete flow (create key → cipher → encrypt → encode), making attribution easy. Real applications are rarely this tidy; the algorithm and the key are often separated by many lines of code.
3. **The keys for DES/Blowfish are deliberately made short** (`ByteArray(8)` = 64-bit) in the sample — the code comment calls it *"insufficient key length"*. This shows that the same sample **also** violates both MASTG-TEST-0208 and MASTG-TEST-0221: the algorithm is broken **and** the key is also too short. In practice, don't stop at reporting only one dimension when both are problematic.

---

#### ✅ PASS — The check is declared PASSED when:

| No | Condition | Example evidence |
|---|---|---|
| P1 | **No findings** from semgrep or supplementary grep | `0 Code Findings`; grep on RC2/IDEA/XOR also clean |
| P2 | All symmetric encryption uses **AES** (128/256-bit, ideally 256) with **GCM** mode | `Cipher.getInstance("AES/GCM/NoPadding")` |
| P3 | The modern alternative **ChaCha20-Poly1305** is used | `Cipher.getInstance("ChaCha20-Poly1305")` |
| P4 | A reference to a broken algorithm is found, but it's proven to be **dead code** / never invoked | Confirmed via jadx call-graph **and** absent from the Frida runtime trace |
| P5 | A broken algorithm is used only for **interoperability with an external protocol that mandates it**, with data that is **not sensitive** | A rare case — still document it as *risk accepted*, not an automatic clean PASS |
| P6 | Encryption is performed via a **validated library** (Google Tink) that selects secure algorithms by default | `Aead aead = ...; aead.encrypt(plaintext, aad)` — Tink does not expose a choice of broken algorithms |

**Example output signaling a PASS:**

```bash
$ NO_COLOR=true semgrep -c mastg-android-broken-encryption-algorithms.yaml ./decompiled/sources/
┌──────────────────┐
│ 0 Code Findings  │
└──────────────────┘

$ rg -n --no-heading '"(DES|DESede|RC4|ARCFOUR|RC2|Blowfish|IDEA|SKIPJACK)"' ./decompiled/sources/
# (no results)
```

Correct code:

```kotlin
// ✅ AES-256-GCM — authenticated encryption, no broken mode/algorithm
val cipher = Cipher.getInstance("AES/GCM/NoPadding")
cipher.init(Cipher.ENCRYPT_MODE, secretKeyFromKeyStore)
val ciphertext = cipher.doFinal(plaintext)
val iv = cipher.iv

// ✅ Alternative: ChaCha20-Poly1305 (good for platforms without AES hardware acceleration)
val cipher2 = Cipher.getInstance("ChaCha20-Poly1305")
```

---

#### ⚠️ Important Notes on Assessment

1. **The MASTG rule catches only `Cipher.getInstance()` — not `SecretKeyFactory` or `KeyGenerator`.** This is a significant gap demonstrated directly by the official demo itself (see observation #1 above). You must use supplementary grep (§3.4) for full coverage matching what the MASTG overview itself describes.

2. **The security-relevant context still needs to be verified, but it rarely becomes a reason to PASS.** Unlike the PRNG test, the presence of DES/RC4/Blowfish in modern code almost always constitutes a legitimate finding — the MASTG-TECH-0023 review here is focused more on **determining severity** (what data is protected) than on filtering out false positives.

3. **Don't forget `SecretKeyFactory` and `KeyGenerator` as supporting evidence.** When `Cipher.getInstance("DES")` is found, trace backward: where did its `SecretKey` come from? If it's from `SecretKeyFactory.getInstance("DES")`, that strengthens the evidence that the entire flow was indeed designed for DES, not a coincidence.

4. **Algorithm strings can be obfuscated — unlike framework API names.** The class names `Cipher`/`SecretKeyFactory` are never obfuscated (system APIs), but the **string argument** `"DES"`/`"RC4"` is ordinary data that **can** be hidden via concatenation, XOR, or Base64 by a developer aware of the risk. This pattern actually raises suspicion further — a developer who deliberately hides a broken algorithm choice knows it is problematic.

5. **Watch out for algorithm name aliases that differ between providers.** `"RC4"` is also known as `"ARCFOUR"`; `"DESede"` also appears as `"TripleDES"` or `"3DES"` depending on the JCA provider. The MASTG regex rule only covers the canonical Java names (`DES`, `DESede`, `RC4`, `Blowfish`) — make sure supplementary grep covers their aliases too.

6. **Empty output ≠ automatic PASS.** Causes of false passes: API coverage gaps (note 3), string obfuscation (note 4), native code (a total blind spot for the Java rule), reflection (`Cipher.getInstance((String) Class.forName(...).getField("ALGO").get(null))`), and unanalyzed split APKs.

7. **Severity is modulated by the algorithm and the data context:**

   | Factor | Severity |
   |---|---|
   | RC4/DES used for financial, health, or credential data | **Critical** |
   | 3DES/Blowfish used on large data volumes or long-lived connections (susceptible to Sweet32) | **High** |
   | Broken algorithm for purely non-sensitive data (internal checksum, non-secret cache) | Low — still reported as a hygiene issue |
   | Broken algorithm in dead/unreachable code | Informational |
   | Broken algorithm for mandatory interoperability with a legacy external system, with data re-encrypted with AES afterward | Medium — layered mitigation reduces risk |
   | Algorithm name deliberately obfuscated | **Increase severity** — indicates awareness of the risk without proper remediation |

8. **Document complete evidence per finding:** the rule/method that found it, path + line number, the decompiled code snippet (both `Cipher.getInstance` **and** the related `SecretKeyFactory`/`KeyGenerator`), the specific algorithm, the data being protected, whether the code is actually executed, any aliases found, and migration recommendations. Also note whether a dual violation was found (e.g., a broken algorithm **and** a short key at the same time, as in the demo).

### 3.4 Gaps in the MASTG Rule and Supplementary Checks

| Gap | Example that slips through |
|---|---|
| Does not cover `SecretKeyFactory.getInstance()` | `SecretKeyFactory.getInstance("DESede")` without `Cipher` on the same line |
| Does not cover `KeyGenerator.getInstance()` | `KeyGenerator.getInstance("RC4")` |
| Does not cover **RC2, IDEA, SKIPJACK** | Not mentioned at all in the pattern |
| Does not cover aliases (`ARCFOUR`, `TripleDES`) | `Cipher.getInstance("ARCFOUR")` |
| Does not cover custom XOR (not a JCA API) | An implementation like `for (i) { out[i] = in[i] ^ key[i % key.length] }` |
| `languages: java` only | Kotlin source is not scanned |
| Split/obfuscated strings | `Cipher.getInstance("D" + "ES")` |
| Native code | A total blind spot |

**Supplementary check commands:**

```bash
D=./decompiled/sources

# 1. SecretKeyFactory & KeyGenerator — the biggest gap in the MASTG rule
rg -n --no-heading 'SecretKeyFactory\.getInstance\(\s*"(DES|DESede|RC4|ARCFOUR|Blowfish|RC2|IDEA)"' $D
rg -n --no-heading 'KeyGenerator\.getInstance\(\s*"(DES|DESede|RC4|ARCFOUR|Blowfish|RC2|IDEA)"' $D

# 2. Cipher.getInstance with an alias not covered by the rule
rg -n --no-heading 'Cipher\.getInstance\(\s*"(ARCFOUR|TripleDES|3DES|RC2|IDEA|SKIPJACK)"' $D

# 3. KeySpec that indicates a broken algorithm even if Cipher is not directly visible
rg -n --no-heading 'DESKeySpec|DESedeKeySpec|new SecretKeySpec\([^)]*,\s*"(DES|RC4|Blowfish|RC2)"' $D

# 4. Custom XOR implementation (not real encryption)
rg -n --no-heading '\^\s*key\[|xor.*[Ee]ncrypt|[Ee]ncrypt.*xor' $D

# 5. Algorithm string that might be obfuscated/split
rg -n --no-heading '"D"\s*\+\s*"ES"|"R"\s*\+\s*"C4"|Base64\.decode\("[A-Za-z0-9+/=]+"\).*getInstance' $D

# 6. Native code — a total blind spot
unzip -o ./target-app.apk -d ./apk_x >/dev/null
for so in $(find ./apk_x -name "*.so"); do
  echo "--- $so"
  strings "$so" | grep -aE "EVP_des|EVP_rc4|DES_encrypt|DES_set_key|BF_encrypt|BF_set_key|RC4\("
done

# 7. Protection detection that limits analysis reliability
apkid ./target-app.apk
```

**Extended semgrep rule** to close the main gaps:

```yaml
rules:
  - id: custom-broken-crypto-keyfactory-keygen
    severity: ERROR
    languages: [java, kotlin]
    message: "[MASVS-CRYPTO-1] SecretKeyFactory/KeyGenerator for a broken algorithm"
    pattern-either:
      - pattern: javax.crypto.SecretKeyFactory.getInstance("DES")
      - pattern: javax.crypto.SecretKeyFactory.getInstance("DESede")
      - pattern: javax.crypto.KeyGenerator.getInstance("DES")
      - pattern: javax.crypto.KeyGenerator.getInstance("DESede")
      - pattern: javax.crypto.KeyGenerator.getInstance("RC4")
      - pattern: javax.crypto.KeyGenerator.getInstance("Blowfish")

  - id: custom-broken-crypto-aliases
    severity: ERROR
    languages: [java, kotlin]
    message: "[MASVS-CRYPTO-1] Broken algorithm referenced by an alias name"
    pattern-regex: '(Cipher|KeyGenerator|SecretKeyFactory)\.getInstance\(\s*"(ARCFOUR|TripleDES|3DES|RC2|IDEA|SKIPJACK)"'

  - id: custom-broken-crypto-keyspec
    severity: WARNING
    languages: [java, kotlin]
    message: "[MASVS-CRYPTO-1] KeySpec for a broken algorithm detected"
    pattern-either:
      - pattern: new javax.crypto.spec.DESKeySpec(...)
      - pattern: new javax.crypto.spec.DESedeKeySpec(...)
```

### 3.5 Optional Dynamic Confirmation

MASTG does not provide a dynamic test for this, but hooking is useful when the algorithm name comes from a **variable/configuration** that cannot be resolved statically, or to cut through string obfuscation.

```javascript
// broken_cipher_trace.js
function bt(max = 10) {
    const E = Java.use("java.lang.Exception");
    const st = E.$new().getStackTrace();
    return Array.from({length: Math.min(max, st.length)}, (_, i) => "    " + st[i]).join("\n");
}

const BROKEN = /^(DES|DESede|RC4|ARCFOUR|Blowfish|RC2|IDEA|SKIPJACK)(\/|$)/i;

Java.perform(() => {
    const Cipher = Java.use("javax.crypto.Cipher");
    Cipher.getInstance.overloads.forEach(ov => {
        ov.implementation = function (...a) {
            const algo = a[0];
            const flag = BROKEN.test(algo) ? "  [!! BROKEN !!]" : "";
            console.log(`\n[Cipher] getInstance("${algo}")${flag}`);
            if (flag) console.log(bt());
            return ov.apply(this, a);
        };
    });

    ['SecretKeyFactory', 'KeyGenerator'].forEach(cls => {
        const K = Java.use(`javax.crypto.${cls}`);
        K.getInstance.overloads.forEach(ov => {
            ov.implementation = function (...a) {
                const algo = a[0];
                const flag = BROKEN.test(algo) ? "  [!! BROKEN !!]" : "";
                console.log(`\n[${cls}] getInstance("${algo}")${flag}`);
                if (flag) console.log(bt());
                return ov.apply(this, a);
            };
        });
    });
});
```

```bash
frida -U -f com.example.target -l broken_cipher_trace.js -o cipher.log
grep -B10 "BROKEN" cipher.log
```

Advantage: captures the **actual** `algo` value even if the string is constructed dynamically (concatenation, runtime decoding, from remote configuration) — something pure static pattern matching cannot resolve.

---

## 4. Recommendations

### 4.1 Main Principle (MASTG-BEST-0009)

MASTG-BEST-0009 states it concisely and firmly:

> *"Replace insecure encryption algorithms with secure ones such as **AES-256** (preferably in **GCM mode**) or **ChaCha20**."*

**Priority 1 — Replace the broken algorithm with AES-256-GCM.**

```kotlin
// ❌ WRONG — broken algorithm
val cipher = Cipher.getInstance("DES")
val cipher2 = Cipher.getInstance("DESede")
val cipher3 = Cipher.getInstance("RC4")
val cipher4 = Cipher.getInstance("Blowfish")

// ✅ CORRECT — AES-256-GCM (authenticated encryption)
val keyGen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
keyGen.init(
    KeyGenParameterSpec.Builder("vault_key", KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
        .setKeySize(256)
        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
        .setRandomizedEncryptionRequired(true)
        .build()
)
keyGen.generateKey()

val cipher = Cipher.getInstance("AES/GCM/NoPadding")
cipher.init(Cipher.ENCRYPT_MODE, keyFromKeyStore)
val ciphertext = cipher.doFinal(plaintext)
val iv = cipher.iv   // store together with the ciphertext
```

**Priority 2 — ChaCha20-Poly1305 as an alternative** (good for devices without AES hardware acceleration):

```kotlin
val cipher = Cipher.getInstance("ChaCha20-Poly1305")
```

**Priority 3 — Use a validated crypto library, not manual configuration.** The Android documentation referenced by MASTG-BEST-0009 recommends **Google Tink**:

```kotlin
// Tink — secure algorithm choice by default, reduces configuration mistakes
val aead = KeysetHandle.generateNew(KeyTemplates.get("AES256_GCM")).getPrimitive(Aead::class.java)
val ciphertext = aead.encrypt(plaintext, associatedData)
val decrypted = aead.decrypt(ciphertext, associatedData)
```

Advantage of Tink: its API **does not expose** any choice of broken algorithm at all — it is impossible by design to accidentally pick DES/RC4/Blowfish through this library.

**Priority 4 — Phased migration for systems that mandate legacy algorithms.** If DES/3DES is used for interoperability with an external system (e.g., an old bank HSM, a legacy protocol):

- **Isolate** the use of the legacy algorithm into a single, clearly documented adapter layer.
- **Re-encrypt** data with AES-256-GCM as soon as it leaves that interoperability layer — don't let data "rest" in a form protected by a broken algorithm.
- Still **report it as a finding** with severity calibrated to the real exposure, not automatically whitelisted.
- Plan a **long-term migration** together with the external system's owner — 3DES has already been withdrawn by NIST since 2024, and compliance pressure will only increase.

**Priority 5 — Re-audit the key and mode after replacing the algorithm.** Replacing the algorithm without checking the other dimensions is not enough:
- Make sure the key size is adequate (MASTG-TEST-0208).
- Make sure the encryption mode is correct — **avoid ECB**, use GCM (MASTG-TEST-0232).
- Make sure the key is not hardcoded (MASTG-TEST-0212) and comes from the Android KeyStore.
- Make sure the key source is correctly randomized (MASTG-TEST-0204/0205).

**Priority 6 — Enforce this structurally.**
- Add a SAST rule (semgrep + extensions from §3.4) to CI/CD, and fail the build when a new call to a broken algorithm is found.
- Create an **allowlist** of permitted algorithms as part of the organization's crypto policy: AES-256-GCM, ChaCha20-Poly1305, and explicitly ban DES/3DES/RC4/RC2/Blowfish/IDEA/SKIPJACK.
- Enable **SonarQube `java:S5547`** or Android Lint crypto checks as an additional IDE gate.
- Audit third-party libraries — also run scans on decompiled library code, as outdated SDKs sometimes still use DES/RC4 internally.

### 4.2 Remediation Checklist

- [ ] Every `Cipher.getInstance` finding for a broken algorithm has been reviewed with MASTG-TECH-0023
- [ ] `SecretKeyFactory.getInstance` and `KeyGenerator.getInstance` for broken algorithms have also been checked (the MASTG rule's gap)
- [ ] No use of DES, 3DES/DESede, RC4/ARCFOUR, or Blowfish
- [ ] No use of RC2, IDEA, SKIPJACK, or a custom XOR implementation as "encryption"
- [ ] All symmetric encryption uses **AES-256-GCM** or **ChaCha20-Poly1305**
- [ ] Consider migrating to **Google Tink** to eliminate the risk of choosing the wrong algorithm
- [ ] If a legacy algorithm is still used for external interoperability: it is isolated to a single layer, data is re-encrypted with AES afterward, and it is documented as an accepted risk
- [ ] Native code (`.so`) has been checked for `EVP_des_*`, `EVP_rc4`, `DES_*`, `BF_*`
- [ ] Obfuscated/split algorithm name strings have been traced and evaluated
- [ ] Key size, encryption mode, key source, and key storage are re-verified after the algorithm migration (cross-check with TEST-0208/0212/0204/0205/0232)
- [ ] Third-party libraries have been audited for internal use of broken algorithms
- [ ] All split APKs / dynamic feature modules have also been analyzed
- [ ] An allowlist of permitted algorithms is documented as the organization's crypto policy
- [ ] SAST scanning (semgrep + extensions, SonarQube) is integrated into CI/CD as a gate
- [ ] **Re-verification:** re-run MASTG-TEST-0221 + supplementary grep → no broken algorithms remain
- [ ] **Cross-verification:** MASTG-TEST-0232 (encryption mode), MASTG-TEST-0208 (key size), MASTG-TEST-0212 (hardcoded keys)

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0221: Broken Symmetric Encryption Algorithms](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0221/)
- [MASWE-0007: Use of a Broken or Risky Cryptographic Algorithm](https://mas.owasp.org/MASWE/MASVS-CRYPTO/MASWE-0007/)
- [MASTG-DEMO-0022: Uses of Broken Symmetric Encryption Algorithms in Cipher with semgrep](https://mas.owasp.org/MASTG/demos/android/MASVS-CRYPTO/MASTG-DEMO-0022/MASTG-DEMO-0022/)
- [MASTG-BEST-0009: Use Secure Encryption Algorithms](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0009/)
- [MASTG-TEST-0232: Uses of Broken Encryption Modes](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0232/)
- [MASTG-TEST-0208: Insufficient Key Sizes](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0208/)
- [MASTG-TEST-0212: Use of Hardcoded Cryptographic Keys in Code](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0212/)
- [MASTG-TECH-0013: Reverse Engineering Android Apps](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/)
- [MASTG-TECH-0014: Static Analysis on Android](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/)
- [MASTG-TECH-0023: Reviewing Decompiled Java Code](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0023/)
- [MASTG-TOOL-0110: semgrep](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0110/)
- [MASTG Rules — `mastg-android-broken-encryption-algorithms.yaml`](https://github.com/OWASP/mastg/blob/master/rules/mastg-android-broken-encryption-algorithms.yaml)
- [MASTG — Testing Cryptography (Identifying Insecure and/or Deprecated Cryptographic Algorithms)](https://mas.owasp.org/MASTG/0x04g-Testing-Cryptography/)
- [MASVS-CRYPTO: Cryptography](https://mas.owasp.org/MASVS/06-MASVS-CRYPTO/)
- [OWASP Mobile Top 10 2024 — M10: Insufficient Cryptography](https://owasp.org/www-project-mobile-top-10/2023-risks/m10-insufficient-cryptography.html)

### 5.2 Official Android / Google / Java Documentation

- [Broken or Risky Cryptographic Algorithm — Android Security Risks](https://developer.android.com/privacy-and-security/risks/broken-cryptographic-algorithm)
- [`javax.crypto.Cipher` — API reference](https://developer.android.com/reference/javax/crypto/Cipher)
- [`javax.crypto.Cipher.getInstance` — API reference](https://developer.android.com/reference/javax/crypto/Cipher#getInstance(java.lang.String))
- [`javax.crypto.SecretKeyFactory` — API reference](https://developer.android.com/reference/javax/crypto/SecretKeyFactory)
- [`javax.crypto.KeyGenerator` — API reference](https://developer.android.com/reference/javax/crypto/KeyGenerator)
- [Java Cryptography Architecture — Standard Algorithm Names](https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html)
- [Android Keystore system](https://developer.android.com/privacy-and-security/keystore)
- [Cryptography best practices](https://developer.android.com/privacy-and-security/cryptography)
- [Google Tink — what is Tink](https://developers.google.com/tink/what-is)
- [Android Security Lints (GitHub)](https://github.com/google/android-security-lints)

### 5.3 Cryptographic Standards & Deprecation History

- [NIST FIPS 46-3 (DES) — withdrawn 2005](https://csrc.nist.gov/pubs/fips/46-3/final)
- [NIST SP 800-67 Rev. 2 — 3DES withdrawn effective January 1, 2024](https://csrc.nist.gov/pubs/sp/800/67/r2/final)
- [NIST SP 800-52 Rev. 1 — RC4 disapproved](https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-52r1.pdf)
- [RFC 7465 — Prohibiting RC4 Cipher Suites (IETF, 2015)](https://datatracker.ietf.org/doc/html/rfc7465)
- [RC4 NOMORE — RC4 weakness research](https://www.rc4nomore.com/)
- [FIPS 140-2 Security Policy — Blowfish listed under Non-Approved algorithms](https://csrc.nist.gov/csrc/media/projects/cryptographic-module-validation-program/documents/security-policies/140sp2092.pdf)
- [CWE-327: Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)
- [CWE-326: Inadequate Encryption Strength](https://cwe.mitre.org/data/definitions/326.html)
- [CWE-328: Use of Weak Hash](https://cwe.mitre.org/data/definitions/328.html)
- [CWE-1240: Use of a Cryptographic Primitive with a Risky Implementation](https://cwe.mitre.org/data/definitions/1240.html)
- [SonarQube Rule java:S5547 — Cipher algorithms should be robust](https://rules.sonarsource.com/java/RSPEC-5547/)
- [NIST SP 800-163 Rev.1 — Vetting the Security of Mobile Applications](https://csrc.nist.gov/publications/detail/sp/800-163/rev-1/final)

### 5.4 Security Research & Technical Articles (Sweet32, RC4)

- [Sweet32.info — Birthday attacks on 64-bit block ciphers in TLS and OpenVPN (CVE-2016-2183)](https://sweet32.info/)
- [Rapid7 — TLS/SSL Birthday attacks on 64-bit block ciphers (SWEET32)](https://www.rapid7.com/db/vulnerabilities/ssl-cve-2016-2183-sweet32/)
- [Red Hat — SWEET32: Birthday attacks against TLS ciphers with 64-bit block size](https://access.redhat.com/articles/2548661)
- [SonicWall — SWEET32 vulnerability of 64-bit ciphers (3DES/Blowfish)](https://www.sonicwall.com/support/knowledge-base/sweet32-vulnerability-of-64-bit-ciphers-3des-blowfish-cve-2016-2183/170505312196945/)
- [Acunetix — TLS/SSL Sweet32 attack](https://www.acunetix.com/vulnerabilities/web/tls-ssl-sweet32-attack/)
- [Wikipedia — Birthday attack](https://en.wikipedia.org/wiki/Birthday_attack)
- [HackTricks — Android Applications Pentesting](https://book.hacktricks.wiki/en/mobile-pentesting/android-app-pentesting/index.html)

### 5.5 Tool Documentation

- [Semgrep — Documentation](https://semgrep.dev/docs/)
- [CodeQL — Documentation](https://codeql.github.com/docs/)
- [MobSF — Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)
- [mobsfscan](https://github.com/MobSF/mobsfscan)
- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [apktool — Reverse engineering Android APK files](https://apktool.org/)
- [Frida — Documentation Home](https://frida.re/docs/home/)
- [Ghidra — software reverse engineering framework](https://ghidra-sre.org/)
- [APKiD — Android Application Identifier](https://github.com/rednaga/APKiD)
- [Google Tink — cryptographic library](https://github.com/tink-crypto/tink)

---

*This document was prepared based on the OWASP MASTG (latest release as of September 2026), official Android Developers and Java documentation, NIST/IETF/CWE standards, and third-party security research on Sweet32 and RC4 weaknesses.*
