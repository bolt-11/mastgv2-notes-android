# MASTG-TEST-0204 Insecure Random API Usage

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0204 |
| **Platform** | Android |
| **MASVS Category** | **MASVS-CRYPTO** (MASVS-CRYPTO-1: The app uses current and correctly implemented cryptography) |
| **Weakness** | MASWE-0012 — *Insecure Random Number Generation* (use of a PRNG with inadequate entropy) |
| **Test Type** | **Static**, Code, Manual |
| **Profile** | L1, L2 |
| **Knowledge** | MASTG-KNOW-0013 (Random Number Generation) |
| **Best Practice** | MASTG-BEST-0001 (Use Secure Random Number Generator APIs) |
| **Prerequisites** | `identify-sensitive-data`, `identify-security-relevant-contexts` |
| **Related Technique** | MASTG-TECH-0013 (Reverse Engineering Android Apps), MASTG-TECH-0014 (Static Analysis on Android), MASTG-TECH-0023 (Reviewing Decompiled Java Code) |
| **Related Demo** | MASTG-DEMO-0007 (Common Uses of Insecure Random APIs) |
| **Sibling Test** | MASTG-TEST-0205 (Non-random Sources Usage — non-random sources such as timestamps) |
| **Related CWE** | CWE-338 (Use of Cryptographically Weak PRNG), CWE-330 (Use of Insufficiently Random Values), CWE-337 (Predictable Seed in PRNG), CWE-335 (Incorrect Usage of Seeds in PRNG), CWE-341 (Predictable from Observable State) |

---

## 1. Explanation

### 1.1 Testing Objective

This test uses **static analysis** to find the use of an **insecure pseudorandom number generator (PRNG)** within an Android app, then assesses whether the random values it produces are used in a **security-relevant context**.

Direct quote from the MASTG overview:

> *"Android apps sometimes use an insecure pseudorandom number generator (PRNG), such as `java.util.Random`, which is a **linear congruential generator** and produces a **predictable sequence for any given seed value**. As a result, `java.util.Random` and `Math.random()` (the latter simply calls `nextDouble()` on a static `java.util.Random` instance) generate **reproducible sequences across all Java implementations** whenever the same seed is used. This predictability makes them unsuitable for cryptographic or other security-sensitive contexts."*
>
> *"In general, **if a PRNG is not explicitly documented as being cryptographically secure, it should not be used where randomness must be unpredictable**."*

Three important points from that quote:

1. **`java.util.Random` is a Linear Congruential Generator (LCG)** — deterministic and predictable, not merely "less random."
2. **`Math.random()` is not a better alternative** — it merely calls `nextDouble()` on a static `java.util.Random` instance. So both are equally insecure.
3. **A safe default rule:** if a PRNG is not **explicitly documented** as being cryptographically secure, don't use it for anything that must be unpredictable. This is a useful principle whenever you encounter an unfamiliar PRNG library.

### 1.2 Why `java.util.Random` Is Predictable — The Technical Basis

This is not a theoretical weakness. `java.util.Random` can be broken with very minimal computational effort.

**Java's LCG parameters** (publicly documented in the Java specification, not a secret):

```
next_seed = (current_seed × 0x5DEECE66D + 0xB) mod 2^48
```

| Parameter | Value |
|---|---|
| Multiplier (A) | `0x5DEECE66D` |
| Addend (C) | `0xB` |
| Modulus (M) | `2^48` |
| Internal state size | **48 bits** |

**State-recovery attack:** `java.util.Random` **never outputs its full 48-bit state** — it outputs at most 32 bits on each call to `nextInt()`, because the seed is right-shifted by 16 bits. The consequences:

- With **two consecutive observations** of `nextInt()` output, an attacker can recover the seed with a very small amount of brute-forcing.
- The remaining 16 bits are small enough to brute-force entirely: **only 65,536 possibilities** — completed in milliseconds on any device.
- Once the seed is known, **all future (and past) values can be computed**.

For harder cases (e.g. only a few bits per sample are visible, or `nextInt(bound)` with a small bound), **lattice reduction (LLL)** techniques are available that recover the state from a larger number of small-valued samples. Ready-to-use public tools for this already exist.

**The practical implication:** if an app generates a session token, OTP, or password-reset token with `java.util.Random`, an attacker who obtains two of their own tokens can predict other users' tokens.

### 1.3 Real-World Case: Losses That Have Already Occurred

**The 2013 Android SecureRandom bug → Bitcoin theft.** This is the most instructive example because it involves a PRNG *that was supposed to be secure*:

- Android 4.1–4.3 (API 16–18) failed to properly initialize the PRNG. Google had replaced the broken Apache Harmony code in Android 4.2 with an implementation based on the system's OpenSSL PRNG, **but the OpenSSL PRNG was not correctly seeded**, making it actually more predictable.
- As a result, apps that used the Java Cryptography Architecture (JCA) for *key generation*, *signing*, or *random number generation* **did not receive cryptographically strong values**.
- ECDSA requires the nonce (`k`) used for signing to be **used only once**. If the same nonce is used twice, **the private key can be recovered** from the two signatures.
- Bitcoin wallets on Android sometimes generated the same nonce → **55.82 BTC was stolen** in August 2013. Affected wallets included Bitcoin Wallet, blockchain.info wallet, BitcoinSpinner, and Mycelium Wallet.
- Google responded with an article titled *"Some SecureRandom Thoughts"* on the Android Developers Blog, along with a patch for all versions.

This is why MASTG-KNOW-0013 gives a specific warning: if an app still supports Android below 4.4 (API 19), **extra care is needed to work around the PRNG bug in API 16–18**.

**Other CVEs caused by weak PRNGs** (referenced in Android documentation): CVE-2013-6386 (Drupal), CVE-2006-3419 (Tor), CVE-2008-4102 (Joomla — predictable seed).

### 1.4 Categories of Insecure PRNGs to Look For

**Group A — PRNGs that are insecure by design:**

| API | Issue |
|---|---|
| `java.util.Random` | 48-bit LCG. **Never** use for security |
| `Math.random()` | Calls `nextDouble()` on a static `java.util.Random` instance. **Explicitly prohibited** by Android documentation for any sensitive use |
| `java.util.concurrent.ThreadLocalRandom` | Also LCG-based, not cryptographic. **Not covered by the MASTG rule** — must be searched for manually |
| `kotlin.random.Random` (`Random.nextInt()`, `Random.Default`) | On JVM/Android, delegates to `java.util.Random`. **Very important for Kotlin apps** and **not covered by the MASTG rule** |
| `org.apache.commons.lang3.RandomStringUtils.random(...)` | Uses `Random` by default (the `...Secure` variant was added only later). Often used to generate tokens — exactly the dangerous context |
| `org.apache.commons.lang3.RandomUtils` | Same, based on `Random` |
| Custom PRNG implementations | No cryptographic guarantee of any kind |

**Group B — Secure PRNGs used incorrectly** (also falls under MASWE-0012, but CWE-337/335):

| Pattern | Issue |
|---|---|
| `SecureRandom(seedByteArray)` with a hardcoded seed | The output becomes deterministic. An attacker only needs to decompile the APK to predict all output |
| `secureRandom.setSeed(12345)` | Same. Android documentation **prohibits** this |
| `SecureRandom` with an old/custom provider | Documentation notes that `setSeed` behavior can differ on an *old security provider* — it may **replace** the seed instead of supplementing it |
| `new SecureRandom(...)` with a non-default constructor | MASTG-KNOW-0013: *"Other constructors are for more advanced uses and, if used incorrectly, can lead to decreased randomness and security"* |

> Note that `SecureRandom` with a hardcoded seed will **not be caught** by the official MASTG semgrep rule for this test. This must be searched for separately.

**Group C — Non-random sources** (this is the scope of **MASTG-TEST-0205**, not this test): `Date().getTime()`, `System.currentTimeMillis()`, `Calendar.MILLISECOND`, `nanoTime()`, UUIDs built from a timestamp, device IDs. Both fall under MASWE-0012 and BEST-0001, so in testing practice they should preferably be run together.

### 1.5 "Security-Relevant" Context

This is the core of this test — and this is why it has the **prerequisites** `identify-sensitive-data` and `identify-security-relevant-contexts`. Unlike other tests discussed previously, **finding `java.util.Random` alone is not a vulnerability**. What matters is **what the random value is used for**.

MASTG identifies the following contexts as security-relevant:

| Use | Why it's critical |
|---|---|
| **Cryptographic key** (symmetric key, key material) | A predictable key makes encryption meaningless |
| **Initialization Vector (IV)** | A predictable/repeated IV breaks CBC security and is **fatal for GCM** (nonce reuse in GCM leaks the authentication key) |
| **Nonce** | A repeated ECDSA nonce → the private key can be recovered (the 2013 Bitcoin case) |
| **Authentication token** | An attacker can predict other users' tokens |
| **Session identifier** | Session hijacking |
| **Password** (including app-generated passwords) | Can be computed by an attacker |
| **PIN** | The value space is already small; a weak PRNG makes it even easier |
| **Salt** | A predictable salt weakens protection against rainbow tables |
| **OTP / verification code / password-reset token** | Direct account takeover |
| **CSRF token / OAuth state** | Protection bypass |
| **Temporary filenames in a shared location** | Race condition / path prediction (linked to MASWE-0002) |

**Contexts that are NOT security-relevant** (where `java.util.Random` is acceptable):

- Shuffling a playlist, card order in a non-competitive game
- Jitter/backoff on network retries (unless used as anti-replay)
- Animation, visual effects, particle positions
- Sampling for A/B testing or analytics
- Random ad or content selection

> However, be careful with games that involve money or competitive rankings — there, a "shuffle" becomes security-relevant and requires a CSPRNG.

### 1.6 This Test's Position in the MASVS-CRYPTO Sequence

| Test | Focus | Approach |
|---|---|---|
| **MASTG-TEST-0204** *(this document)* | Use of **insecure PRNG APIs** (`Random`, `Math.random()`) | Static |
| **MASTG-TEST-0205** | Use of **non-random sources** (timestamp, `Calendar.MILLISECOND`) | Static |

Both share the weakness **MASWE-0012**, the knowledge item **MASTG-KNOW-0013**, and the best practice **MASTG-BEST-0001**. Both are also of static type with the same prerequisites. **Run them in pairs** — an app that uses `java.util.Random` for tokens often also uses a timestamp as a seed or as a token component.

Note: there is **no official dynamic counterpart** for this test in MASTG. This makes sense because detecting "this value originated from a weak PRNG" at runtime is far harder than reading the code. However, for confirmation, hooking can still be used (see §3.5).

---

## 2. Tools Used for Testing

### 2.1 Required Tools (Core)

| Tool | MASTG ID | Function in This Test |
|---|---|---|
| **jadx** | MASTG-TOOL-0018 | **Decompile DEX → Java** (MASTG-TECH-0013). Also required for MASTG-TECH-0023 — tracing *how* the random value is used (this is the hardest and most important part) |
| **semgrep** | MASTG-TOOL-0110 | **Pattern matching**. MASTG provides the rule `mastg-android-random-apis-insufficient-entropy.yml` |
| **grep / ripgrep** | — | A mandatory supplement to close the rule's gaps (see §3.4) |
| **apktool** | MASTG-TOOL-0011 | Alternative decompilation; useful for smali analysis if jadx fails |

### 2.2 Supporting Tools

| Tool | Function |
|---|---|
| **CodeQL** | **Strongly recommended for this test.** Semgrep only performs intra-file pattern matching; CodeQL performs **cross-function taint analysis** — exactly what's needed to answer "does this value from `Random` actually flow into token generation?" The `java/predictable-seed` query and related queries are available |
| **mobsfscan / MobSF** | Semgrep-based mobile SAST; has built-in weak-PRNG rules |
| **semgrep-rules-android-security** (IMQ Minded Security) | The **original source** of this MASTG rule (`mstg-crypto-6.yaml`) — useful for seeing more complete variants |
| **SonarQube** | Rule `java:S2245` — *Using pseudorandom number generators (PRNGs) is security-sensitive* |
| **Android Lint** | Some built-in checks related to `SecureRandom` |
| **jadx-gui** | Interactive navigation + "Find Usage" feature — key for tracing the usage of random values |
| **APKiD** | Detects packers/obfuscators to assess the reliability of static analysis results |
| **Frida** | MASTG-TOOL-0001. For optional dynamic confirmation (see §3.5) |
| **Ghidra / `strings`** | Analysis of `.so` files — PRNG from native code (`rand()`, `srand()`, `random()`) is unreachable by Java rules |
| **`java-prng-predict` / LLL scripts** | Public tools to **prove exploitability**: recovering a seed from two `nextInt()` outputs. Useful for PoC demonstrations in reports |

### 2.3 Environment Prerequisites

- **No device and no root needed** — the APK file alone suffices. Just like MASTG-TEST-0202, this makes it easy to automate in CI/CD.
- **A complete APK**, including all split APKs / dynamic feature modules if the app is distributed as an AAB.
- **semgrep installed** and the MASTG rules available (clone `github.com/OWASP/mastg`, `rules/` directory).
- **Satisfy the prerequisites first.** This test formally requires `identify-sensitive-data` and `identify-security-relevant-contexts`. In practice: before scanning, first understand **what the app's sensitive assets are** (what tokens are used? Is there local encryption? What is the authentication flow?). Without this, you cannot assess whether a given `Random` call is dangerous or not.
- **Note the rule only applies to `languages: java`.** This is why scanning is performed on **decompiled (Java) code**, not on Kotlin source. If you have access to Kotlin source code, this MASTG rule **will not work** — a separate Kotlin rule or grep is needed.
- **Be wary of obfuscation.** Framework class names (`java.util.Random`, `Math.random`) are not obfuscated by R8/ProGuard because they are system APIs, so **detection remains effective**. What becomes harder is the usage-review step (MASTG-TECH-0023) because the app's own class/method names become single letters.

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0013** (*Reverse Engineering Android Apps*) to reverse engineer the application.
2. Use **MASTG-TECH-0014** (*Static Analysis on Android*) to search for the relevant APIs.

Then for evaluation: use **MASTG-TECH-0023** (*Reviewing Decompiled Java Code*) on every reported code location.

### 3.2 Practical Implementation (MASTG-DEMO-0007)

**Step 1 — Decompilation**

```bash
jadx -d ./decompiled ./target-app.apk

# If split APK / AAB, pull and decompile all parts
adb shell pm path com.example.target
```

**Step 2 — Run the official MASTG semgrep rule**

Rule `mastg-android-random-apis-insufficient-entropy.yml`:

```yaml
rules:
  - id: mastg-android-random-apis-insufficient-entropy
    severity: WARNING
    languages:
      - java
    metadata:
      summary: This rule looks for common patterns including classes and methods.
      original_source: https://github.com/mindedsecurity/semgrep-rules-android-security/blob/main/rules/crypto/mstg-crypto-6.yaml
    message: "[MASVS-CRYPTO-1] The application makes use of random number generators with insufficient entropy."

    pattern-either:
        - patterns:
            - pattern-inside: $M(...){ ... }
            - pattern-either:
                - pattern: Math.random(...)
                - pattern: (java.util.Random $X).$Y(...)
```

Running it (`run.sh` from the demo):

```bash
NO_COLOR=true semgrep -c ../../../../rules/mastg-android-random-apis-insufficient-entropy.yml \
  ./MastgTest_reversed.java > output.txt
```

For a real-world app:

```bash
NO_COLOR=true semgrep \
  -c ./mastg/rules/mastg-android-random-apis-insufficient-entropy.yml \
  ./decompiled/sources/ --json -o findings-random.json
```

**Step 3 — Review each finding (MASTG-TECH-0023)** — **mandatory**

For every reported line, answer:

1. **What is this random value used for?** Trace the variable to its final point of use.
2. **Is that point of use security-relevant?** Compare against the table in §1.5.
3. **If the finding is inside a helper function** (e.g. `getRandom()`), **trace all its callers** — this is often what gets overlooked.

```bash
# Trace usage of the variable holding the Random result
grep -rn "random1\|random2\|random3" ./decompiled/sources/org/owasp/mastestapp/

# Find callers of a random helper function
grep -rn "getRandom\|get_random\|randomString\|generateToken\|generateNonce" ./decompiled/sources/

# In jadx-gui: right-click on the method → "Find Usage"
```

### 3.3 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rule:**

> **Observation:** *"The output should contain a list of locations where insecure random APIs are used."*
>
> **Evaluation:** *"The test case **fails** if you can find random numbers generated using those APIs that are **used in security-relevant contexts**, such as generating passwords or authentication tokens."*
>
> **Further Validation Required** — inspect each code location with MASTG-TECH-0023 to determine whether its use is security-relevant:
> - Determine whether the generated random value is used for a security-relevant purpose, such as the creation of a **cryptographic key, initialization vector (IV), nonce, authentication token, session identifier, password, or PIN**.

**Key point:** the clause *"used in security-relevant contexts"* is an **absolute requirement**. A finding of `java.util.Random` without a security-relevant context **is not a FAIL**. This differs from MASTG-TEST-0203 (logging), where simply "sensitive data present → FAIL" was sufficient.

---

#### ❌ FAIL / ISSUE — The check is declared FAILED if:

| No | Condition | Example evidence |
|---|---|---|
| F1 | `java.util.Random` / `Math.random()` is used to **create a password** | `password.append(characters[random.nextInt(characters.length)])` inside a password-generator function |
| F2 | Used for an **authentication token / session ID / OTP / reset token** | `String token = Long.toHexString(new Random().nextLong())` |
| F3 | Used for a **cryptographic key** | `byte[] key = new byte[32]; new Random().nextBytes(key); new SecretKeySpec(key, "AES")` |
| F4 | Used for an **IV or nonce** | `new Random().nextBytes(iv); new IvParameterSpec(iv)` → **critical on GCM**: nonce reuse leaks the authentication key |
| F5 | Used for a **salt** in password hashing / KDF | `new Random().nextBytes(salt)` before PBKDF2 |
| F6 | Used for a **PIN or verification code** | `int pin = 100000 + new Random().nextInt(900000)` |
| F7 | `SecureRandom` is used but **seeded with a hardcoded/deterministic value** | `SecureRandom r = new SecureRandom(); r.setSeed(12345);` or `new SecureRandom("mykey".getBytes())` → CWE-337. **Not caught by the MASTG rule** |
| F8 | `kotlin.random.Random` / `ThreadLocalRandom` used in a security-relevant context | `Random.nextInt(999999)` for an OTP → **not caught by the MASTG rule** |
| F9 | `RandomStringUtils.random(...)` (Apache Commons, non-secure variant) used for a token | Very common and very dangerous because it looks like a safe utility |
| F10 | A **custom PRNG** implementation is used for security | A hand-written function with XOR/shift, with no cryptographic guarantee |
| F11 | A finding is inside a **helper function**, and caller tracing proves security-relevant usage | `get_random()` called by `createSessionId()` |
| F12 | `minSdkVersion` ≤ 18 **and** there is no mitigation for the Android 4.1–4.3 PRNG bug | The app is vulnerable even when using `SecureRandom` — see §1.3 |
| F13 | A weak PRNG from **native code** is used for security | `strings lib.so` → `rand`, `srand` + review shows usage for a key/nonce |

**Example output indicating a FAIL — MASTG-DEMO-0007:**

Sample code (`MastgTest.kt`) — note the FAIL/PASS annotations provided by MASTG:

```kotlin
fun mastgTest(): String {

    // FAIL: [android-insecure-random-use] The app insecurely uses random numbers
    //       for generating authentication tokens.
    val random1 = Random().nextDouble()

    // FAIL: [android-insecure-random-use] The title of the function indicates that it
    //       generates a random number, but it is unclear how it is actually used in the
    //       rest of the app. Review any calls to this function to ensure that the random
    //       number is not used in a security-relevant context.
    val random2 = 1 + Math.random()

    val length = 16
    val characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    val random = Random()
    val password = StringBuilder(length)

    for (i in 0 until length) {
        // FAIL: [android-insecure-random-use] The app insecurely uses random numbers for
        //       generating passwords, which is a security-relevant context.
        password.append(characters[random.nextInt(characters.length)])
    }

    val random3 = password.toString()

    // PASS: [android-insecure-random-use] The app uses a secure random number generator.
    val random4 = SecureRandom().nextInt(21)

    return "Generated random numbers:\n$random1 \n$random2 \n$random3 \n$random4"
}
```

Decompiled code scanned by semgrep (`MastgTest_reversed.java`):

```java
public final String mastgTest() {
    double random1 = new Random().nextDouble();                                   // <-- line 22
    double random2 = 1 + Math.random();                                          // <-- line 23
    Random random = new Random();
    StringBuilder password = new StringBuilder(16);
    for (int i = 0; i < 16; i++) {
        password.append("ABCDEFGHIJ...0123456789".charAt(
            random.nextInt("ABCDEFGHIJ...0123456789".length())));                // <-- line 27
    }
    String random3 = password.toString();
    int random4 = new SecureRandom().nextInt(21);                                 // <-- PASS
    return "...";
}
```

Semgrep output (`output.txt`):

```
┌─────────────────┐
│ 3 Code Findings │
└─────────────────┘

    MastgTest_reversed.java
    ❯❱ rules.mastg-android-random-apis-insufficient-entropy
          [MASVS-CRYPTO-1] The application makes use of random number generators with insufficient entropy.

           22┆ double random1 = new Random().nextDouble();
            ⋮┆----------------------------------------
           23┆ double random2 = 1 + Math.random();
            ⋮┆----------------------------------------
           27┆ password.append("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".charAt(ran
               dom.nextInt("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".length())));
```

MASTG evaluation (referencing line numbers in the **Kotlin** file):

> - *"Line 12 seems to be used to generate random numbers for security purposes, in this case for generating **authentication tokens**."*
> - *"Line 17 is part of the function `get_random`. **Review any calls to this function** to ensure that the random number is not used in a security-relevant context."*
> - *"Line 27 is part of the **password generation** function which is a security-critical operation."*
> - *"Note that **line 37 did not trigger the rule** because the random number is generated using `SecureRandom` which is a secure random number generator."*

**Four important lessons from this demo:**

1. **One finding can represent many weak values.** Line 27 is reported **once**, even though it's inside a loop of 16 iterations — producing 16 password characters that are all predictable. Don't judge severity by the number of findings.
2. **The "finding needs further tracing" pattern is explicitly acknowledged by MASTG.** The case of line 17 (`Math.random()` inside a helper function) cannot be assessed without checking who calls it. This is a direct example of why the MASTG-TECH-0023 step is mandatory.
3. **`SecureRandom` does not trigger the rule** — proving the rule correctly distinguishes secure from insecure PRNGs.
4. **There are two inconsistencies in this demo artifact** that you should be aware of when replicating it:
   - The Observation section mentions *"identified **five** instances"*, while `output.txt` only shows **3 Code Findings**. The number "five" appears to be a leftover from an older version of the rule/sample.
   - The line numbers in the Evaluation (12, 17, 27, 37) refer to **`MastgTest.kt`**, while semgrep was run on **`MastgTest_reversed.java`** and reported lines 22, 23, 27. The evaluation text also mentions a function name, `get_random`, that doesn't exist in the published Kotlin sample.

   This doesn't change the substance of the lesson, but don't be confused when matching up the numbers.

---

#### ✅ PASS — The check is declared PASSED if:

| No | Condition | Example evidence |
|---|---|---|
| P1 | **Semgrep finds no findings** and the supplementary grep is also clean | `0 Code Findings`; no `kotlin.random.Random` / `ThreadLocalRandom` / `RandomStringUtils` |
| P2 | All security-relevant random needs use **`SecureRandom` with the default constructor** | `new SecureRandom().nextBytes(iv)`; no `setSeed()` nor a seed in the constructor |
| P3 | Uses `SecureRandom.getInstanceStrong()` | Per Android documentation's recommendation for modern Android |
| P4 | There are findings of `java.util.Random`/`Math.random()`, but review proves the usage is **not** security-relevant | `Math.random()` for animation jitter; `Random().nextInt()` to select a placeholder color |
| P5 | Keys/IV/nonce are generated by the **platform**, not by application code | `KeyGenerator.getInstance("AES").generateKey()`; `KeyGenParameterSpec` + Android KeyStore; `Cipher` generates its own IV, retrieved via `cipher.getIV()` |
| P6 | The random value comes from the **server** via a TLS channel (e.g. a session token created by the backend) | No token generation on the client side |
| P7 | `UUID.randomUUID()` is used — this is based on `SecureRandom` | Safe for identifiers, **though not a substitute for a cryptographic key** |
| P8 | `minSdkVersion` ≥ 19, so the Android 4.1–4.3 PRNG bug is not relevant | `aapt2 d badging` → `sdkVersion:'21'` |

**Example output indicating a PASS:**

```bash
$ NO_COLOR=true semgrep -c mastg-android-random-apis-insufficient-entropy.yml ./decompiled/sources/
┌──────────────────┐
│ 0 Code Findings  │
└──────────────────┘

# Supplementary grep for rule gaps
$ grep -rnE "kotlin\.random\.Random|ThreadLocalRandom|RandomStringUtils|RandomUtils" ./decompiled/sources/
# (no results)

$ grep -rnE "setSeed|new SecureRandom\([^)]" ./decompiled/sources/
# (no results — SecureRandom is only used with the default constructor)
```

Correct code:

```kotlin
// ✅ CSPRNG with the default constructor — self-seeding from system entropy
val secureRandom = SecureRandom()
val iv = ByteArray(12)
secureRandom.nextBytes(iv)

// ✅ Or, per Android documentation's recommendation for modern Android
val rand = SecureRandom.getInstanceStrong()
val randInt = rand.nextInt(1000)

// ✅ BEST for keys — let the platform generate it
val keyGen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
keyGen.init(
    KeyGenParameterSpec.Builder("myKey", KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
        .build()
)
keyGen.generateKey()

// ✅ BEST for IV — let Cipher generate it, then retrieve the result
val cipher = Cipher.getInstance("AES/GCM/NoPadding")
cipher.init(Cipher.ENCRYPT_MODE, key)
val iv = cipher.iv          // IV securely generated by the provider
```

---

#### ⚠️ Important Notes on Scoring

1. **A finding without context is not a vulnerability.** The clause *"used in security-relevant contexts"* is an absolute requirement in the evaluation criteria. Reporting every `java.util.Random` hit as a vulnerability is incorrect practice and will flood the report with false positives — normal apps have many legitimate uses of `Random` (animation, jitter, shuffling).

2. **Satisfy the prerequisites first.** This test formally requires `identify-sensitive-data` and `identify-security-relevant-contexts`. Without understanding the app's security assets and flows, you have no basis for assessing findings. This is a real prerequisite, not a formality.

3. **Trace helper functions to their callers.** The most commonly overlooked pattern: `Random` is used inside a generic utility (`RandomUtil.nextString()`), and that utility is called from various places — some safe, some not. MASTG explicitly raises this case in the demo. Use "Find Usage" in jadx-gui or, better yet, **CodeQL for taint analysis**.

4. **The MASTG rule has significant gaps.** You need to know these so you don't wrongly conclude PASS:

   | Gap | Impact |
   |---|---|
   | `pattern-inside: $M(...){ ... }` requires being **inside a method body** | **Class-level field initializers are not detected**, e.g. `private static final Random RNG = new Random();` |
   | `languages: java` only | **Kotlin source is not scanned.** Only works on decompiled code |
   | Does not cover `kotlin.random.Random` | A major gap for modern Kotlin apps |
   | Does not cover `ThreadLocalRandom` | Another weak PRNG that slips through |
   | Does not cover `RandomStringUtils` / `RandomUtils` (Apache Commons) | Precisely what's often used for tokens |
   | Does not cover `SecureRandom` with a hardcoded seed / `setSeed()` | CWE-337 slips through entirely |
   | Does not cover custom PRNGs or native PRNGs | Slips through |

   **Mitigation:** run the supplementary grep (§3.4) and consider CodeQL.

5. **An empty output ≠ automatic PASS.** Besides the rule gaps above: obfuscation/packing, reflection, runtime-loaded code, and unanalyzed split APKs can all hide findings. Run APKiD and analyze all modules.

6. **Don't be fooled by reassuring-sounding names.** `SecureRandom` that has `setSeed()` called with a constant is more dangerous than plain `java.util.Random`, because it gives a false sense of security. Likewise for `RandomStringUtils`, which looks like a ready-made, safe utility.

7. **GCM nonce cases need special attention.** In AES-GCM, **nonce reuse with the same key is catastrophic** — not only does it leak the plaintext, it also allows recovery of the *authentication key*, enabling an attacker to forge ciphertext. A weak PRNG used for a GCM nonce should be assessed as critical severity, higher than a weak IV for CBC.

8. **Severity is modulated by the usage context:**

   | Context | Severity |
   |---|---|
   | Cryptographic key, GCM/ECDSA nonce | **Critical** |
   | Authentication token, session ID, password-reset token, OTP | **High** |
   | CBC IV, salt | **Medium–High** |
   | PIN, verification code | **High** (value space is already small) |
   | Temporary filename in shared storage | Medium |
   | `SecureRandom` with a hardcoded seed | **High** — fully deterministic, easily exploited after decompilation |
   | `minSdkVersion` ≤ 18 without mitigation for the PRNG bug | Increases |
   | Non-security usage (animation, jitter, non-competitive shuffling) | **Not a finding** |

9. **Prove exploitability where possible.** Because `java.util.Random` can be broken with two output observations, you can build a very convincing PoC: collect two tokens from the app, recover the seed, then predict the next token. Public tools for this already exist. A PoC of this kind turns a finding from "bad practice" into "proven vulnerability."

10. **Document complete evidence per finding:** rule ID, file path + line number, the decompiled code snippet, **usage-tracing results** (from the PRNG to its final point of consumption), context classification (security-relevant or not) along with the rationale, `minSdkVersion`, and a prediction PoC if one was built. Also note the limits of the analysis (obfuscation, native code, rule gaps not yet closed).

### 3.4 Supplementary Checks (Closing the Rule's Gaps)

This is a section that must not be skipped.

```bash
D=./decompiled/sources

# 1. Weak PRNGs NOT covered by the MASTG rule
grep -rnE "kotlin\.random\.Random|Random\.Default|Random\.nextInt|Random\.nextBytes" $D
grep -rnE "java\.util\.concurrent\.ThreadLocalRandom|ThreadLocalRandom\.current" $D
grep -rnE "RandomStringUtils|org\.apache\.commons\.lang3?\.RandomUtils" $D
grep -rnE "SplittableRandom|XorShift|MersenneTwister" $D

# 2. Class-level field initializers (pattern-inside gap)
grep -rnE "(static )?(final )?Random [A-Za-z_]+ *= *new Random" $D

# 3. SecureRandom used INCORRECTLY (CWE-337/335) — not covered by the rule
grep -rnE "setSeed\(" $D
grep -rnE "new SecureRandom\([^)]+\)" $D              # constructor with a seed argument
grep -rnE "SecureRandom\.getInstance\(" $D            # check its algorithm & provider

# 4. Security-relevant consumption points — for correlation
grep -rnE "SecretKeySpec|IvParameterSpec|GCMParameterSpec|KeyGenerator|PBEKeySpec" $D
grep -rnE "generateToken|sessionId|session_id|nonce|otp|resetToken|csrf|salt" $D
grep -rniE "password|passcode|\bpin\b" $D | grep -iE "random|generate"

# 5. PRNG from native code (a total blind spot for the Java rule)
for so in $(find ./extracted -name "*.so"); do
  echo "--- $so"; strings "$so" | grep -xE "rand|srand|random|srandom|rand_r|drand48|lrand48"
done

# 6. minSdkVersion — to assess relevance of the Android 4.1-4.3 PRNG bug
aapt2 d badging ./target-app.apk | grep -E "sdkVersion|targetSdkVersion"

# 7. Detect protections that could limit the reliability of the analysis
apkid ./target-app.apk
```

**Additional semgrep rule** to close the main gaps:

```yaml
rules:
  - id: custom-insecure-random-extended
    severity: WARNING
    languages: [java, kotlin]
    message: "[MASVS-CRYPTO-1] Weak PRNG or deterministically-seeded SecureRandom"
    pattern-either:
      # Other weak PRNGs
      - pattern: new java.util.concurrent.ThreadLocalRandom(...)
      - pattern: java.util.concurrent.ThreadLocalRandom.current(...)
      - pattern: kotlin.random.Random.$M(...)
      - pattern: org.apache.commons.lang3.RandomStringUtils.random(...)
      - pattern: org.apache.commons.lang3.RandomUtils.$M(...)
      # Field initializer (without pattern-inside, so class-level is also caught)
      - pattern: new java.util.Random(...)
      # SecureRandom used incorrectly -> CWE-337 / CWE-335
      - pattern: (java.security.SecureRandom $S).setSeed(...)
      - pattern: new java.security.SecureRandom($SEED)
```

### 3.5 Optional Dynamic Confirmation

MASTG does not provide a dynamic test for this, but hooking is useful for **proving** that a value from a weak PRNG actually reaches a sensitive context — while also gathering samples for a prediction PoC.

```javascript
// Hook java.util.Random + SecureRandom.setSeed, print a backtrace
Java.perform(() => {
    function bt(max = 10) {
        const E = Java.use("java.lang.Exception");
        const st = E.$new().getStackTrace();
        let out = [];
        for (let i = 0; i < Math.min(max, st.length); i++) out.push("    " + st[i]);
        return out.join("\n");
    }

    const R = Java.use("java.util.Random");
    ['nextInt', 'nextLong', 'nextDouble', 'nextBytes', 'nextFloat'].forEach(m => {
        R[m].overloads.forEach(ov => {
            ov.implementation = function (...a) {
                const r = ov.apply(this, a);
                console.log(`\n[!] java.util.Random.${m}() -> ${r}`);
                console.log(bt());
                return r;
            };
        });
    });

    // Detect SecureRandom that has been manually seeded (CWE-337)
    const SR = Java.use("java.security.SecureRandom");
    SR.setSeed.overloads.forEach(ov => {
        ov.implementation = function (s) {
            console.log(`\n[!!] SecureRandom.setSeed(${s}) — MANUAL SEED, check whether deterministic`);
            console.log(bt());
            return ov.apply(this, [s]);
        };
    });
});
```

The backtrace will immediately reveal whether the caller is `TokenGenerator.create()` or merely `AnimationHelper.jitter()` — answering the context question with runtime evidence.

---

### 3.6 Alternative Testing Methods (Multi-Tool)

The MASTG semgrep rule only covers three patterns and leaves many gaps (§3.3, note 4). The following are alternative paths, each with different strengths.

#### Method B — Structured ripgrep/grep *(catches the entire weak-PRNG family)*

This is the most direct gap-closer: the MASTG rule does not cover `kotlin.random.Random`, `ThreadLocalRandom`, `RandomStringUtils`, or class-level field initializers.

```bash
jadx -d ./decompiled ./target-app.apk
D=./decompiled/sources

# --- 1. Weak PRNGs NOT covered by the MASTG rule ---
rg -n --no-heading "kotlin\.random\.Random|Random\.Default|RandomKt" $D
rg -n --no-heading "java\.util\.concurrent\.ThreadLocalRandom|ThreadLocalRandom\.current" $D
rg -n --no-heading "RandomStringUtils|org\.apache\.commons\.lang3?\.RandomUtils" $D
rg -n --no-heading "SplittableRandom|MersenneTwister|XorShift" $D

# --- 2. Class-level field initializers (pattern-inside gap) ---
rg -n --no-heading "(static )?(final )?Random [A-Za-z_]+ *= *new Random" $D

# --- 3. SecureRandom used INCORRECTLY (CWE-337) — slips through the MASTG rule entirely ---
rg -n --no-heading "setSeed\(" $D
rg -n --no-heading "new SecureRandom\([^)]" $D

# --- 4. Security-relevant consumption points (for context correlation) ---
rg -n --no-heading "SecretKeySpec|IvParameterSpec|GCMParameterSpec|KeyGenerator|PBEKeySpec" $D
rg -ni --no-heading "generateToken|sessionId|nonce|\botp\b|resetToken|csrf|\bsalt\b" $D

# --- 5. REVERSE-direction analysis: start from consumption, trace back to the source ---
#     More efficient because consumption points are far fewer than Random calls
rg -n --no-heading -B5 "new SecretKeySpec|new IvParameterSpec" $D | rg -i "random|nextInt|nextBytes"
```

#### Method C — MobSF *(ready-to-quote report)*

```bash
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest
```

Look in the **Code Analysis** section: a finding titled *"The App uses an insecure Random Number Generator"* mapped to CWE-330 with MASVS references. Its advantage: MobSF already detects `java.util.Random` **and** `Math.random()` at once, complete with severity that can be directly quoted.

#### Method D — mobsfscan *(CLI for CI/CD)*

```bash
pip install mobsfscan
mobsfscan --json -o out.json ./decompiled/sources/
jq '.results | to_entries[] | select(.key | test("random|prng"))' out.json

# CI gate
mobsfscan --exit-warning ./decompiled/sources/
```

#### Method E — CodeQL *(taint analysis — automatically answers the context question)*

**This is the most appropriate method for this test.** MASTG's evaluation criteria require the random value to be *"used in security-relevant contexts"* — a data-flow question that semgrep cannot answer, but CodeQL can answer automatically.

```bash
codeql database create ./cqldb --language=java --command="./gradlew assembleDebug"

# Relevant built-in queries
codeql database analyze ./cqldb \
  codeql/java-queries:Security/CWE/CWE-330/InsecureRandomness.ql \
  codeql/java-queries:Security/CWE/CWE-335/PredictableSeed.ql \
  --format=sarif-latest --output=random.sarif

jq '.runs[].results[] | {rule: .ruleId, msg: .message.text}' random.sarif
```

A custom query that precisely answers the MASTG criteria:

```ql
/**
 * @name Weak PRNG output flows into a cryptographic sink
 * @kind path-problem
 */
import java
import semmle.code.java.dataflow.TaintTracking

class WeakRandomSource extends DataFlow::Node {
  WeakRandomSource() {
    exists(MethodAccess ma |
      ma.getMethod().getDeclaringType().hasQualifiedName("java.util", "Random") or
      ma.getMethod().hasQualifiedName("java.lang", "Math", "random") |
      this.asExpr() = ma
    )
  }
}

class CryptoSink extends DataFlow::Node {
  CryptoSink() {
    exists(ClassInstanceExpr cie |
      cie.getConstructedType().hasQualifiedName("javax.crypto.spec",
        ["SecretKeySpec", "IvParameterSpec", "GCMParameterSpec", "PBEKeySpec"]) |
      this.asExpr() = cie.getAnArgument()
    )
  }
}
```

#### Method F — SonarQube / SonarLint *(IDE integration & quality gate)*

```bash
sonar-scanner \
  -Dsonar.projectKey=android-app \
  -Dsonar.sources=./app/src \
  -Dsonar.java.binaries=./app/build
```

The relevant rules: **`java:S2245`** — *Using pseudorandom number generators (PRNGs) is security-sensitive*, and **`java:S4347`** — *Secure random number generators should not output predictable values* (detects deterministic `setSeed`). Advantage: it appears directly in the developer's IDE via SonarLint, preventing the problem before commit.

#### Method G — semgrep registry & third-party rules *(broader rule coverage)*

```bash
# Semgrep Registry
semgrep --config "p/java" --config "p/mobsfscan" ./decompiled/sources/
semgrep --config "r/java.lang.security.audit.crypto.weak-random.weak-random" ./decompiled/sources/

# Android-specific rules (the original source of this MASTG rule)
git clone https://github.com/mindedsecurity/semgrep-rules-android-security
semgrep -c ./semgrep-rules-android-security/rules/crypto/ ./decompiled/sources/
```

#### Method H — APKHunt *(automated MASVS scanner)*

```bash
go install github.com/Cyber-Buddy/APKHunt@latest
APKHunt -p ./target-app.apk -l
grep -iA3 "random" APKHunt_Report.txt
```

#### Method I — Native code analysis *(a blind spot for Java rules)*

```bash
unzip -o ./target-app.apk -d ./apk_x >/dev/null
for so in $(find ./apk_x -name "*.so"); do
  echo "--- $so"
  strings "$so" | grep -xE "rand|srand|random|srandom|rand_r|drand48|lrand48|arc4random"
done
```

> `arc4random` and `getrandom`/`/dev/urandom` are **good** signs (CSPRNG). `rand`/`srand`/`drand48` are **bad** signs.

#### Method J — Proving exploitability *(seed-prediction PoC)*

This is what turns a finding from "bad practice" into "proven vulnerability" — and is only possible because `java.util.Random` can be broken from two observations.

```bash
# 1. Collect ≥2 consecutive outputs from the app (token, OTP, ID)
#    via the UI, API response, or a Frida hook (§3.5)

# 2. Recover the seed and predict the next value
git clone https://github.com/giuliocandre/java-prng-predict
cd java-prng-predict && python3 predict.py <output1> <output2>

# 3. Verify the prediction by requesting the next value from the app
```

An alternative using lattice reduction (for small-valued `nextInt(bound)`): the LLL script by Jorian Woltjer (see §5.4).

---

### 3.7 Method Comparison: When to Use Which

| Method | Tool | Needs a device? | Needs source code? | Catches non-JCA PRNGs? | Answers the context question? | When to Use |
|---|---|---|---|---|---|---|
| **A** | semgrep (MASTG) | No | No | ❌ | ❌ | Official baseline & CI gate |
| **B** | Structured ripgrep | No | No | ✅ | Manual | **Mandatory cross-verification** — closes the biggest gap |
| **C** | MobSF | No | No | Partial | ❌ | Ready-to-quote report |
| **D** | mobsfscan | No | No | Partial | ❌ | Lightweight CI/CD gate |
| **E** | CodeQL | No | **Yes** (ideal) | ✅ | ✅ **automatically** | **Best** when source is available — answers the "security-relevant context" criterion |
| **F** | SonarQube/SonarLint | No | Yes | Partial | ❌ | Developer-side prevention (shift-left) |
| **G** | semgrep registry / third-party rules | No | No | ✅ | ❌ | Broader rule coverage without writing your own |
| **H** | APKHunt | No | No | Partial | ❌ | Additional automated pass |
| **I** | `strings` / Ghidra | No | No | ✅ (native) | Manual | APKs with `.so` files |
| **K** | Frida (§3.5) | **Yes** | No | ✅ | ✅ (backtrace) | Variable-derived size/source, obfuscated code |
| **J** | java-prng-predict / LLL | Partial | No | — | — | **Proving exploitability** for the report |

**Minimum recommended combination:** **B (ripgrep) → A (semgrep) → K (Frida)**.
B closes the gaps in the PRNG family; A gives a baseline aligned with MASTG; K proves context via a runtime backtrace. If source code is available, **E (CodeQL) replaces most of the manual work**, since it automatically answers the context question. Add **J** if the finding needs extra weight in the report.

---

## 4. Recommendations

### 4.1 Main Principle (MASTG-BEST-0001)

MASTG-BEST-0001 states: *"Use a cryptographically secure pseudorandom number generator as provided by the platform or programming language you are using."*

**Priority 1 — Use `java.security.SecureRandom` with the default constructor.**

MASTG-BEST-0001 explains why: `SecureRandom` meets the random-number-generator statistical tests set out in **FIPS 140-2 section 4.9.1** and meets the cryptographic strength requirements in **RFC 4086** (*Randomness Requirements for Security*). It produces non-deterministic output and **automatically seeds itself from system entropy when the object is initialized**, so manual seeding is generally unnecessary and **can actually weaken** randomness if done incorrectly.

```kotlin
// ✅ CORRECT — default constructor, self-seeding from system entropy (/dev/urandom)
val secureRandom = SecureRandom()
val token = ByteArray(32)
secureRandom.nextBytes(token)

// ✅ Per Android documentation's recommendation for modern Android
val rand = SecureRandom.getInstanceStrong()
val randInt = rand.nextInt(1000)
```

```kotlin
// ❌ WRONG — all deterministic or weak
val r1 = Random().nextInt(1000)                          // LCG, predictable
val r2 = Math.random()                                    // same, via a static Random
val r3 = SecureRandom().apply { setSeed(12345) }           // CWE-337
val r4 = SecureRandom("hardcoded".toByteArray())           // CWE-337
val r5 = kotlin.random.Random.nextInt(999999)              // delegates to java.util.Random
val r6 = ThreadLocalRandom.current().nextInt()             // LCG-based
val r7 = RandomStringUtils.random(16)                      // Apache Commons, non-secure
```

**A special warning about seeding** from MASTG-BEST-0001: although the [documentation](https://developer.android.com/reference/java/security/SecureRandom) states that a supplied seed typically **supplements** the existing seed, **this behavior can differ when an old security provider is used** — meaning the seed may actually **replace** the system entropy. To avoid this trap, make sure the app targets a modern Android version with an updated provider, or explicitly configure a secure provider (**AndroidOpenSSL**, or **Conscrypt** on more recent releases).

**Priority 2 — Even better: don't generate it yourself; let the platform do it.**

This is a stronger recommendation than simply swapping `Random` → `SecureRandom`, because it eliminates an entire class of mistakes.

```kotlin
// ✅ Key: generate in the Android KeyStore — key material never leaves secure hardware
val keyGen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
keyGen.init(
    KeyGenParameterSpec.Builder(
        "myKeyAlias",
        KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
    )
        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
        .setRandomizedEncryptionRequired(true)   // forces a system-generated random IV
        .build()
)
keyGen.generateKey()

// ✅ IV/nonce: let Cipher generate it, then retrieve it
val cipher = Cipher.getInstance("AES/GCM/NoPadding")
cipher.init(Cipher.ENCRYPT_MODE, key)
val iv = cipher.iv                    // guaranteed random by the provider
// Store the iv together with the ciphertext (the IV is not secret, but must be unique)

// ✅ File/preferences encryption: use a high-level abstraction
//    (EncryptedFile / Google Tink) that handles keys & nonces correctly
```

**Priority 3 — Replace commonly wrong patterns.**

| Need | ❌ Don't | ✅ Do |
|---|---|---|
| Authentication token / session ID | `Random().nextLong()` | `SecureRandom().nextBytes(ByteArray(32))` then Base64-URL encode — **or even better, generated by the server** |
| Non-secret unique identifier | `Random().nextInt()` | `UUID.randomUUID()` (based on `SecureRandom`) |
| Symmetric key | `Random().nextBytes(key)` | `KeyGenerator` + Android KeyStore |
| IV / nonce | `Random().nextBytes(iv)` | `cipher.iv` or `SecureRandom().nextBytes(iv)` |
| Salt for KDF | `Random().nextBytes(salt)` | `SecureRandom().nextBytes(salt)` (≥ 16 bytes) |
| Password / passphrase | `Random().nextInt(chars.length)` | `SecureRandom().nextInt(chars.length)`, avoid modulo bias |
| OTP / PIN | `Random().nextInt(900000)` | `SecureRandom().nextInt(900000)` + rate limiting + short validity |
| Pseudorandom output that **needs to be reproducible** | `SecureRandom` with a fixed seed | **HMAC, HKDF, or SHAKE** — per Android documentation's recommendation |

> The last point is important and is often the reason developers use `setSeed()`: if you need random output that is **reproducible** (e.g. deterministic key derivation), **do not** use `SecureRandom` with a fixed seed. Use a derivation function designed for exactly that purpose: HMAC, HKDF, or SHAKE.

**Priority 4 — Handle legacy Android support.** If the app still supports Android below 4.4 (API 19), implement mitigations for the PRNG initialization bug in API 16–18 (see the patch from the *"Some SecureRandom Thoughts"* article). The cleanest solution: **raise `minSdkVersion` to 19 or higher** — API 16–18 is already far outside of security support.

**Priority 5 — Pay attention to other languages/frameworks.** MASTG-BEST-0001 gives a warning relevant to cross-platform apps: consult the standard library documentation to find the API that exposes the operating system's CSPRNG — this is generally the safest approach, **provided there is no known vulnerability in that random library's implementation**. MASTG cites the **CSPRNG issue in Flutter/Dart** as an example, as a reminder that some frameworks have known PRNG weaknesses. So for React Native, Flutter, or Unity apps, don't assume the built-in "random" API is safe.

**Priority 6 — Avoid modulo bias.** This is a mistake that slips past all static rules and still weakens randomness even when a CSPRNG is already used:

```kotlin
// ❌ Bias: the distribution is non-uniform if 256 doesn't divide the range evenly
val idx = secureRandom.nextInt() % chars.length

// ✅ nextInt(bound) already handles rejection sampling internally
val idx = secureRandom.nextInt(chars.length)
```

**Priority 7 — Enforce this structurally.**
- Add a **SAST rule in CI/CD** (MASTG semgrep + extension rules in §3.4) and fail the build when new findings appear.
- Create **one centralized utility** for all security-relevant random needs (e.g. `CryptoRandom.bytes(n)`, `CryptoRandom.token()`), then forbid direct use of `Random` via a custom lint rule.
- **Enable SonarQube rule `java:S2245`** or an equivalent Android Lint rule.
- Audit third-party libraries — run the scan on decompiled library code as well.

### 4.2 Remediation Checklist

- [ ] Every semgrep finding has been reviewed with MASTG-TECH-0023 and classified (security-relevant / not)
- [ ] For every finding in a helper function, **all its callers** have been traced
- [ ] No `java.util.Random` / `Math.random()` in a security-relevant context
- [ ] No `kotlin.random.Random`, `ThreadLocalRandom`, `RandomStringUtils`, or `RandomUtils` in a security-relevant context
- [ ] No custom PRNG implementation for security purposes
- [ ] No `SecureRandom` that has been manually seeded (`setSeed()` or a seed in the constructor)
- [ ] All security-relevant random needs use default `SecureRandom()` or `SecureRandom.getInstanceStrong()`
- [ ] Cryptographic keys are generated by `KeyGenerator`/`KeyPairGenerator` + Android KeyStore, not by the application's own PRNG
- [ ] IV/nonce is generated by `Cipher` or `SecureRandom`; **a GCM nonce is guaranteed to never repeat** for the same key
- [ ] KDF salt ≥ 16 bytes from `SecureRandom`
- [ ] No modulo bias (`nextInt() % n`); use `nextInt(n)`
- [ ] Pseudorandom output that needs to be reproducible uses HMAC/HKDF/SHAKE, not a fixed-seed `SecureRandom`
- [ ] A secure provider is configured (AndroidOpenSSL/Conscrypt), or a modern `targetSdkVersion` is used
- [ ] `minSdkVersion` ≥ 19, or there is explicit mitigation for the Android 4.1–4.3 PRNG bug
- [ ] PRNG from native code (`rand`/`srand`) is not used for security
- [ ] Cross-platform frameworks (Flutter/RN/Unity) have been checked — their random API is genuinely a CSPRNG
- [ ] A centralized random utility has been created, and direct use of `Random` is forbidden via lint
- [ ] Third-party libraries have been audited (semgrep run on library code too)
- [ ] All split APKs / dynamic feature modules have been analyzed as well
- [ ] SAST scanning is integrated into CI/CD as a gate
- [ ] **Re-verify:** re-run MASTG-TEST-0204 + supplementary grep → no findings in a security-relevant context
- [ ] **Cross-verify:** run MASTG-TEST-0205 (non-random sources such as timestamps)

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0204: Insecure Random API Usage](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0204/)
- [MASTG-TEST-0205: Non-random Sources Usage](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0205/)
- [MASWE-0012: Insecure Random Number Generation](https://mas.owasp.org/MASWE/MASVS-CRYPTO/MASWE-0012/)
- [MASTG-DEMO-0007: Common Uses of Insecure Random APIs](https://mas.owasp.org/MASTG/demos/android/MASVS-CRYPTO/MASTG-DEMO-0007/MASTG-DEMO-0007/)
- [MASTG-DEMO-0008: Uses of Non-random Sources](https://mas.owasp.org/MASTG/demos/android/MASVS-CRYPTO/MASTG-DEMO-0008/MASTG-DEMO-0008/)
- [MASTG-KNOW-0013: Random Number Generation](https://mas.owasp.org/MASTG/knowledge/android/MASVS-CRYPTO/MASTG-KNOW-0013/)
- [MASTG-BEST-0001: Use Secure Random Number Generator APIs](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0001/)
- [MASTG-TECH-0013: Reverse Engineering Android Apps](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/)
- [MASTG-TECH-0014: Static Analysis on Android](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/)
- [MASTG-TECH-0023: Reviewing Decompiled Java Code](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0023/)
- [MASTG-TOOL-0110: semgrep](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0110/)
- [MASTG-TOOL-0018: jadx](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0018/)
- [MASTG Rules — `mastg-android-random-apis-insufficient-entropy.yml`](https://github.com/OWASP/mastg/blob/master/rules/mastg-android-random-apis-insufficient-entropy.yml)
- [MASVS-CRYPTO: Cryptography](https://mas.owasp.org/MASVS/06-MASVS-CRYPTO/)
- [OWASP MASTG — Testing Cryptography (Random Number Generation)](https://mas.owasp.org/MASTG/0x05e-Testing-Cryptography/)
- [OWASP Cryptographic Storage Cheat Sheet — Secure Random Number Generation](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html#secure-random-number-generation)
- [OWASP Mobile Top 10 2024 — M10: Insufficient Cryptography](https://owasp.org/www-project-mobile-top-10/2023-risks/m10-insufficient-cryptography.html)

### 5.2 Official Android / Google / Java Documentation

- [Weak PRNG — Android Security Risks](https://developer.android.com/privacy-and-security/risks/weak-prng)
- [`java.security.SecureRandom` — API reference](https://developer.android.com/reference/java/security/SecureRandom)
- [`SecureRandom.setSeed(byte[])` — API reference](https://developer.android.com/reference/java/security/SecureRandom#setSeed(byte[]))
- [`java.util.Random` — API reference](https://developer.android.com/reference/java/util/Random)
- [`Math.random()` — API reference](https://developer.android.com/reference/java/lang/Math#random())
- [`KeyGenerator` — API reference](https://developer.android.com/reference/javax/crypto/KeyGenerator)
- [`KeyGenParameterSpec` — API reference](https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec)
- [Android Keystore system](https://developer.android.com/privacy-and-security/keystore)
- [Cryptography best practices](https://developer.android.com/privacy-and-security/cryptography)
- [Android Developers Blog — *Some SecureRandom Thoughts* (2013)](https://android-developers.googleblog.com/2013/08/some-securerandom-thoughts.html)
- [Android Developers Blog — *Security "Crypto" provider deprecated in Android N*](https://android-developers.googleblog.com/2016/06/security-crypto-provider-deprecated-in.html)
- [Conscrypt — Java Security Provider](https://github.com/google/conscrypt)
- [Google Tink — cryptographic library](https://developers.google.com/tink)

### 5.3 Other Standards, Taxonomies, and Guidelines

- [CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)](https://cwe.mitre.org/data/definitions/338.html)
- [CWE-330: Use of Insufficiently Random Values](https://cwe.mitre.org/data/definitions/330.html)
- [CWE-337: Predictable Seed in Pseudo-Random Number Generator (PRNG)](https://cwe.mitre.org/data/definitions/337.html)
- [CWE-335: Incorrect Usage of Seeds in Pseudo-Random Number Generator (PRNG)](https://cwe.mitre.org/data/definitions/335.html)
- [CWE-341: Predictable from Observable State](https://cwe.mitre.org/data/definitions/341.html)
- [FIPS 140-2 — Security Requirements for Cryptographic Modules (section 4.9.1)](http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.140-2.pdf)
- [RFC 4086 — Randomness Requirements for Security](https://tools.ietf.org/html/rfc4086)
- [NIST SP 800-90A Rev.1 — Recommendation for Random Number Generation Using Deterministic RBGs](https://csrc.nist.gov/publications/detail/sp/800-90a/rev-1/final)
- [NIST SP 800-90B — Entropy Sources Used for Random Bit Generation](https://csrc.nist.gov/publications/detail/sp/800-90b/final)
- [NIST SP 800-163 Rev.1 — Vetting the Security of Mobile Applications](https://csrc.nist.gov/publications/detail/sp/800-163/rev-1/final)
- [SonarQube Rule java:S2245 — Using pseudorandom number generators (PRNGs) is security-sensitive](https://rules.sonarsource.com/java/RSPEC-2245/)
- [CodeQL — Java query help (predictable seed & insecure randomness)](https://codeql.github.com/codeql-query-help/java/)
- [SEI CERT Oracle Coding Standard for Java — MSC02-J: Generate strong random numbers](https://wiki.sei.cmu.edu/confluence/display/java/MSC02-J.+Generate+strong+random+numbers)
- [NVD — CVE-2013-6386 (weak PRNG, Drupal)](https://nvd.nist.gov/vuln/detail/CVE-2013-6386)
- [NVD — CVE-2008-4102 (predictable seed, Joomla)](https://nvd.nist.gov/vuln/detail/CVE-2008-4102)
- [NVD — CVE-2006-3419 (weak PRNG, Tor)](https://nvd.nist.gov/vuln/detail/CVE-2006-3419)

### 5.4 Security Research & Technical Articles

- [Franklin Ta — *Predicting the next Math.random() in Java*](https://franklinta.com/2014/08/31/predicting-the-next-math-random-in-java/)
- [elttam — *Cracking the Odd Case of Randomness in Java*](https://www.elttam.com/blog/cracking-randomness-in-java)
- [James Roper (all that jazz) — *Cracking Random Number Generators, Part 1*](https://jazzy.id.au/2010/09/20/cracking_random_number_generators_part_1.html)
- [Jorian Woltjer — *Practical `java.util.Random` LCG attack using LLL reduction*](https://gist.github.com/JorianWoltjer/e10cf3235adfc47b1c6f6e90b8411fae)
- [Practical CTF — Pseudo-Random Number Generators (PRNG)](https://book.jorianwoltjer.com/cryptography/pseudo-random-number-generators-prng)
- [giuliocandre/java-prng-predict — Breaking Java LCG `Rand.nextInt()` with range](https://github.com/giuliocandre/java-prng-predict)
- [Ruptura InfoSecurity — *How Can Random Be Real When Random Isn't Real?*](https://ruptura-infosec.com/hack-of-the-month/how-can-random-be-real-when-random-isnt-real/)
- [Bitcoin.org — Android Security Vulnerability (2013 alert)](https://bitcoin.org/en/alert/2013-08-11-android)
- [The Register — *Android bug batters Bitcoin wallets*](https://www.theregister.com/2013/08/12/android_bug_batters_bitcoin_wallets/)
- [SiliconANGLE — *Android Crypto PRNG Flaw Aided Bitcoin Thieves*](https://siliconangle.com/2013/08/16/android-crypto-prng-flaw-aided-bitcoin-thieves-google-releases-patch/)
- [codepope — *Android SecureRandom: It gets worse*](https://codepope.dev/post/2013/08/android-securerandom-it-gets-worse/)
- [lxgr's blog — *Android's SecureRandom — not even nonce*](https://blog.lxgr.net/posts/2013/08/15/android-securerandom-not-even-nonce/)
- [Dr. Awesome Doge — *The 2013 Android Bitcoin Wallet Vulnerability: A Lesson in Randomness*](https://doge.tg/blog/2018/The-2013-Android-Bitcoin-Wallet-Vulnerability-A-Lesson-in-Randomness/)
- [Tangem — *Old Wallets, Weak Keys: How Poor Entropy Still Drains Millions in Crypto*](https://tangem.com/en/blog/post/randomness-importance/)
- [Zellic — *Proton, Dart/Flutter, and the CSPRNG that wasn't*](https://www.zellic.io/blog/proton-dart-flutter-csprng-prng/)
- [Terse Systems — *The Right Way to Use SecureRandom*](https://tersesystems.com/blog/2015/12/17/the-right-way-to-use-securerandom/)
- [Baeldung — *Java SecureRandom*](https://www.baeldung.com/java-secure-random)
- [GeeksforGeeks — *Random vs SecureRandom numbers in Java*](https://www.geeksforgeeks.org/random-vs-secure-random-numbers-java/)

### 5.5 Tool Documentation

- [Semgrep — Documentation](https://semgrep.dev/docs/)
- [Semgrep — Pattern syntax reference](https://semgrep.dev/docs/writing-rules/pattern-syntax/)
- [mindedsecurity/semgrep-rules-android-security — the original source of this MASTG rule](https://github.com/mindedsecurity/semgrep-rules-android-security)
- [IMQ Minded Security — Semgrep Rules for Android Application Security](https://blog.mindedsecurity.com/2023/10/semgrep-rules-for-android-application.html)
- [mobsfscan — static analysis for Android/iOS](https://github.com/MobSF/mobsfscan)
- [MobSF — Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)
- [CodeQL — Documentation](https://codeql.github.com/docs/)
- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [apktool — Reverse engineering Android APK files](https://apktool.org/)
- [APKiD — Android Application Identifier](https://github.com/rednaga/APKiD)
- [Frida — Documentation Home](https://frida.re/docs/home/)
- [Ghidra — software reverse engineering framework](https://ghidra-sre.org/)

---

*This document was compiled based on OWASP MASTG (latest release as of September 2026), official Android Developers documentation, CWE/FIPS/NIST/RFC standards, and third-party security research.*
