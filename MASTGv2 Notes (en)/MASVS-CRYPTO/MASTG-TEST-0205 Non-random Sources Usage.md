# MASTG-TEST-0205 Non-random Sources Usage

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0205 |
| **Platform** | Android |
| **MASVS Category** | **MASVS-CRYPTO** (MASVS-CRYPTO-1: The app uses current and modern cryptography applied correctly) |
| **Weakness** | MASWE-0012 — *Insecure Random Number Generation* |
| **Test Type** | **Static**, Code, Manual |
| **Profile** | L1, L2 |
| **Knowledge** | MASTG-KNOW-0013 (Random Number Generation) |
| **Best Practice** | MASTG-BEST-0001 (Use Secure Random Number Generator APIs) |
| **Prerequisites** | `identify-sensitive-data`, `identify-security-relevant-contexts` |
| **Related Techniques** | MASTG-TECH-0013 (Reverse Engineering Android Apps), MASTG-TECH-0014 (Static Analysis on Android), MASTG-TECH-0023 (Reviewing Decompiled Java Code) |
| **Related Demo** | MASTG-DEMO-0008 (Uses of Non-random Sources) |
| **Sibling Test** | MASTG-TEST-0204 (Insecure Random API Usage — weak PRNGs such as `java.util.Random`) |
| **Related CWE** | CWE-341 (Predictable from Observable State), CWE-330 (Use of Insufficiently Random Values), CWE-337 (Predictable Seed in PRNG), CWE-340 (Generation of Predictable Numbers or Identifiers), CWE-1241 (Use of Predictable Algorithm in Random Number Generator) |

---

## 1. Explanation

### 1.1 Testing Objective

This test uses **static analysis** to find the use of **non-random sources** in place of a random number generator, and then assesses whether the generated values are used in a security-relevant context.

Direct quote from the MASTG overview:

> *"Android applications sometimes use **non-random sources** to generate 'random' values, leading to potential security vulnerabilities. Common practices include relying on the **current time**, such as `Date().getTime()`, or accessing `Calendar.MILLISECOND` to produce values that are **easily guessable and reproducible**."*

Fundamental difference from MASTG-TEST-0204:

| | MASTG-TEST-0204 | MASTG-TEST-0205 *(this document)* |
|---|---|---|
| **Problem** | A **weak** PRNG is used (`java.util.Random`, `Math.random()`) | **Not a PRNG at all** — a deterministic value is used as "random" |
| Nature of the value | Pseudorandom, but its state can be recovered | **Not random at all** — predictable from knowledge of the time |
| Analogy | A lock whose combination can be computed | A lock whose "combination" is the current clock |

Conceptually, this test deals with a **more severe** problem than TEST-0204. `java.util.Random` at least produces a distribution that appears random and requires a state-recovery attack. A timestamp, on the other hand, **is not a random value at all** — the attacker doesn't need to break anything, only needs to know (or guess) when the value was generated.

Both tests share weakness **MASWE-0012**, knowledge **MASTG-KNOW-0013**, best practice **MASTG-BEST-0001**, and the same prerequisites. **Run them together** — these patterns often appear together in the same code.

### 1.2 Why a Timestamp Is Not a Random Source — Entropy Analysis

The core of the problem is **very low entropy**, and this can be computed.

**Case A — `Calendar.MILLISECOND`:** This field returns the millisecond component of the current time, i.e. a number from **0–999 only**.

```
Value space = 1,000 possibilities ≈ 9.97 bits of entropy
```

Compare this with a secure token (32 bytes from a CSPRNG), which has 256 bits of entropy. A 10-bit token can be brute-forced **instantly** — even by hand. If an app generates an authentication token from `Calendar.MILLISECOND`, the attacker only needs to try at most 1,000 values.

**Case B — `Date().getTime()` / `System.currentTimeMillis()`:** Returns the Unix epoch in milliseconds. Nominally this is a large number (~1.7 × 10¹²), but **its effective entropy is determined by how precisely the attacker can estimate the generation time**:

| Attacker's known time uncertainty | Search space | Effective entropy |
|---|---|---|
| ± 1 second | 2,000 values | ~11 bits |
| ± 1 minute | 120,000 values | ~17 bits |
| ± 1 hour | 7.2 million values | ~22.8 bits |
| ± 1 day | 172.8 million values | ~27.4 bits |

In real-world scenarios, the attacker usually **knows the time very precisely**: they trigger the action that generates the token themselves (e.g. pressing "Forgot Password"), then record the response time. The uncertainty drops to the level of a few hundred milliseconds → **the search space is only a few hundred values**.

Worse still, an `(int)` cast such as in the MASTG demo (`Date().time.toInt()`) **truncates the 64-bit value to 32 bits**, which can introduce additional easily-predictable patterns.

**Case C — timestamp as a PRNG seed.** This is the most dangerous and very common combination:

```kotlin
val r = Random(System.currentTimeMillis())   // ❌ the seed is guessable
```

The effect: the entire PRNG output sequence becomes computable. Note that `java.util.Random()` with no argument **already** seeds itself from the system time (combined with a unique value), so adding `System.currentTimeMillis()` as the seed **fixes nothing** — it actually makes it more predictable by removing that unique component. This falls under **CWE-337 (Predictable Seed)**.

### 1.3 Non-Random Sources to Look For

**Group A — Time sources (explicitly named by MASTG and covered by its rule):**

| Source | Note |
|---|---|
| `new Date()` / `Date().getTime()` / `Date().time` | Explicitly named in the MASTG overview |
| `System.currentTimeMillis()` | Scanned by the MASTG rule |
| `Calendar.getInstance().get(Calendar.MILLISECOND)` | Explicitly named in the MASTG overview. **Only 1,000 values** |
| Other `Calendar.get(...)` fields (`SECOND`, `MINUTE`, `HOUR`, `DAY_OF_YEAR`) | Entropy is even lower |
| `System.nanoTime()` | Finer granularity, but **still not a random source** — monotonic and correlated with boot time |
| `SystemClock.elapsedRealtime()` / `uptimeMillis()` / `currentThreadTimeMillis()` | **Not scanned by the MASTG rule.** Even worse: correlated with device boot time |
| `LocalDateTime.now()` / `Instant.now()` / `ZonedDateTime.now()` (java.time) | **Not scanned by the MASTG rule.** Modern API with the same problem |
| `java.sql.Timestamp` | Same |

**Group B — Other non-random sources not named by MASTG but that must be checked:**

| Source | Why it's dangerous |
|---|---|
| **Device identifiers**: `Settings.Secure.ANDROID_ID`, IMEI, serial number, MAC address | Static per device, and often readable by other apps → **not secret** |
| **Counter / auto-increment** | `userId + 1`, sequence numbers — fully predictable |
| **Hash of known data**: `md5(username)`, `sha1(email + timestamp)` | Hashing is deterministic. Hashing does not add entropy — it only obscures |
| **`UUID.nameUUIDFromBytes(...)`** (UUID version 3) | **Deterministic** from the input. Completely different from `UUID.randomUUID()`, which is based on `SecureRandom`. A very subtle trap |
| **UUID version 1** (time-based) | Contains a timestamp and MAC address — predictable |
| `Object.hashCode()` / `System.identityHashCode()` | Based on memory address, not random, and can repeat |
| `Thread.currentThread().getId()` | Small, sequential values |
| `Process.myPid()` | Limited value range |
| Hardcoded constants or values that "look random" | Static; found via decompilation |
| A combination of several of the above sources | Combining non-random sources **does not produce randomness** — the entropy remains low |

> **Principle to keep in mind:** entropy cannot be created by combining, hashing, or encoding predictable values. `sha256(timestamp + androidId)` looks like a random 256-bit value, but its real entropy is only as large as the uncertainty of its inputs — which can be below 20 bits. The attacker only needs to brute-force the **input**, not the output.

### 1.4 "Security-Relevant" Context

Just like MASTG-TEST-0204, this test has prerequisites `identify-sensitive-data` and `identify-security-relevant-contexts`. **Finding `System.currentTimeMillis()` alone is not a vulnerability** — what matters is what the value is used for.

MASTG names the following contexts as security-relevant:

| Usage | Impact if predictable |
|---|---|
| **Cryptographic key** | Encryption becomes meaningless — the attacker can derive the same key |
| **Initialization Vector (IV)** | A repeated IV breaks CBC; **fatal for GCM** (nonce reuse leaks the authentication key) |
| **Nonce** | A repeated ECDSA nonce → the private key can be recovered |
| **Authentication token** | The attacker predicts another user's token → account takeover |
| **Session identifier** | Session hijacking |
| **Password** (generated by the app) | Can be computed |
| **PIN** | The value space is already small; adding low entropy makes it trivial |
| **Password reset token / OTP / verification code** | Direct account takeover. **This is the most dangerous combination** because the attacker controls the trigger time |
| **Salt** for password hashing / KDF | A predictable salt weakens protection against precomputation |
| **CSRF token / OAuth `state` / PKCE `code_verifier`** | Protection bypass |
| **Temporary file names** in shared locations | Race condition / path prediction |

**Contexts that are NOT security-relevant** — here the use of a timestamp is actually **correct and expected**:

- Recording the time of an event (`createdAt`, `updatedAt`, log timestamp)
- Measuring duration/performance (`start = System.currentTimeMillis()` … `elapsed = now - start`)
- Cache expiry, TTL, scheduling, debouncing, throttling
- Displaying the date/time in the UI (`Calendar.get(Calendar.YEAR)` for date formatting)
- Timeout and retry-backoff calculations
- Timestamp-based file names for sorting purposes (non-secret)
- Analytics and telemetry

> **This is the most important distinguishing factor of this test.** Unlike `java.util.Random`, which is relatively rarely used, `System.currentTimeMillis()` and `new Date()` are **extremely common and legitimate** APIs in almost every app. A normal app can have dozens to hundreds of calls to them, all of which are legitimate. The testing implications of this are discussed in §3.4.

### 1.5 Concrete Attack Scenarios

So that findings can be assessed properly, here is how this weakness is exploited in practice:

**Scenario 1 — Predicting a password reset token.**
1. The attacker creates their own account and triggers "Forgot Password," recording the precise time and the token received.
2. From several samples, the attacker infers a pattern: `token = f(timestamp)`.
3. The attacker triggers a password reset for the victim's account, recording the request time.
4. The attacker generates all candidate tokens for that time window (typically a few hundred to a few thousand values) and tries them.
5. **Account takeover.** Without server-side rate limiting, this completes in a matter of seconds.

**Scenario 2 — Recovery of a local encryption key.** If a key is derived from the installation timestamp, an attacker who gains access to the device (or to a backup) can estimate the installation time from file metadata (`stat` on the app directory), then brute-force that time window to recover the key and decrypt all local data.

**Scenario 3 — Nonce collision.** If a GCM nonce is derived from `Calendar.MILLISECOND` (1,000 values), a nonce collision becomes **almost certain** after a few dozen encryption operations (birthday paradox: ~50% collision after ~37 operations). For AES-GCM, nonce reuse with the same key allows recovery of the *authentication key* → the attacker can forge ciphertext.

---

## 2. Tools Used for Testing

### 2.1 Required Tools (Core)

| Tool | MASTG ID | Function in this test |
|---|---|---|
| **jadx** | MASTG-TOOL-0018 | **Decompiles DEX → Java** (MASTG-TECH-0013). Also required for MASTG-TECH-0023 — tracing how the time value is used. The "Find Usage" feature is critical here |
| **semgrep** | MASTG-TOOL-0110 | **Pattern matching**. MASTG provides the rule `mastg-android-non-random-use.yml` |
| **grep / ripgrep** | — | Required complement to close the rule's gaps (see §3.5) |
| **apktool** | MASTG-TOOL-0011 | Alternative decompilation; smali analysis when jadx fails |

### 2.2 Supporting Tools

| Tool | Function |
|---|---|
| **CodeQL** | **Most important tool for this test.** Because the semgrep rule produces a very large number of false positives, **taint analysis** that tracks the flow from time sources to cryptographic consumption points is the most efficient way to separate real findings from noise |
| **mobsfscan / MobSF** | Mobile SAST; has rules related to weak PRNG and predictable values |
| **semgrep-rules-android-security** (IMQ Minded Security) | **Original source** of this MASTG rule (`mstg-crypto-6.yaml`) |
| **SonarQube** | Rule `java:S2245` (PRNG security-sensitive) and related predictable-seed rules |
| **jadx-gui** | Interactive navigation + "Find Usage" — key for tracing the flow of time values |
| **Frida** | MASTG-TOOL-0001. For dynamic confirmation (see §3.6) — very effective for this test because it can reveal the generated token value along with its backtrace |
| **Token analysis tools** (e.g. Burp Sequencer, `ent`) | Analyzes a collected set of tokens from the app to detect time-correlation patterns — **strong proof of exploitability** |
| **APKiD** | Detects packers/obfuscators to assess the reliability of static analysis |
| **Ghidra / `strings`** | Analysis of `.so` files — `time()`, `gettimeofday()`, `clock()` from native code |

### 2.3 Environment Prerequisites

- **No device and no root required** — the APK file alone is sufficient.
- **Complete APK**, including all split APKs / dynamic feature modules.
- **semgrep installed** with the MASTG rule available (clone `github.com/OWASP/mastg`, `rules/` directory).
- **Satisfy the prerequisites first.** For this test, the prerequisites are even more critical than for TEST-0204, because the noise ratio is far higher. You should already know: which tokens does the app use? Is there local encryption? What's the password-reset/OTP flow? Without this map, scanning for `System.currentTimeMillis()` will produce hundreds of undirected findings.
- **The rule only covers `languages: java`** — scanning is performed on the decompiled code, not Kotlin source.
- **Note the effect of decompilation on constants.** This matters practically: in the source code it reads `Calendar.MILLISECOND`, but in the **decompiled Java the constant becomes the numeric literal `14`** (see demo: `c.get(14)`). This means `grep "Calendar.MILLISECOND"` on decompiled code **will find nothing**. You need to search for `.get(` with numeric literals, or rely on the semgrep rule that matches `(Calendar $C).get(...)` generically.

**Useful `Calendar` constant table when reading decompiled code:**

| Literal | Constant | Value space |
|---|---|---|
| `1` | `YEAR` | — |
| `2` | `MONTH` | 0–11 |
| `5` | `DAY_OF_MONTH` | 1–31 |
| `6` | `DAY_OF_YEAR` | 1–366 |
| `11` | `HOUR_OF_DAY` | 0–23 |
| `12` | `MINUTE` | 0–59 |
| `13` | `SECOND` | 0–59 |
| **`14`** | **`MILLISECOND`** | **0–999** |

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0013** (*Reverse Engineering Android Apps*) to reverse engineer the application.
2. Use **MASTG-TECH-0014** (*Static Analysis on Android*) to search for the relevant APIs.

Then for evaluation: use **MASTG-TECH-0023** (*Reviewing Decompiled Java Code*) on each reported code location.

### 3.2 Practical Implementation (MASTG-DEMO-0008)

**Step 1 — Decompile**

```bash
jadx -d ./decompiled ./target-app.apk

# If split APK / AAB, pull and decompile all parts
adb shell pm path com.example.target
```

**Step 2 — Run the official MASTG semgrep rule**

The `mastg-android-non-random-use.yml` rule:

```yaml
rules:
  - id: mastg-android-non-random-use
    severity: WARNING
    languages:
      - java
    metadata:
      summary: This rule looks for common patterns including classes and methods that represent non-random sources e.g. via `Calendar.MILLISECOND` or `new Date()`.
      original_source: https://github.com/mindedsecurity/semgrep-rules-android-security/blob/main/rules/crypto/mstg-crypto-6.yaml
    message: "[MASVS-CRYPTO-1] The application makes use of non-random sources."
    pattern-either:
        - patterns:
            - pattern-inside: $M(...){ ... }
            - pattern-either:
                - pattern: new Date()
                - pattern: System.currentTimeMillis()
                - pattern: (Calendar $C).get(...)
```

Running it (`run.sh` from the demo):

```bash
NO_COLOR=true semgrep -c ../../../../rules/mastg-android-non-random-use.yml \
  ./MastgTest_reversed.java > output.txt
```

For a real app — **use JSON output** because the number of findings will be large:

```bash
NO_COLOR=true semgrep \
  -c ./mastg/rules/mastg-android-non-random-use.yml \
  ./decompiled/sources/ --json -o findings-nonrandom.json

# Check the scale of the findings first before starting review
jq '.results | length' findings-nonrandom.json
```

**Step 3 — Triage (mandatory, before review)**

Because this rule is very noisy, don't jump straight into reviewing each finding one by one. First narrow it down by searching for findings that are **close to a cryptographic/token context**:

```bash
# Get the list of files with findings
jq -r '.results[].path' findings-nonrandom.json | sort -u > files_with_findings.txt

# Narrow down: files that ALSO touch a security-relevant context
grep -lE "SecretKeySpec|IvParameterSpec|GCMParameterSpec|KeyGenerator|PBEKeySpec|MessageDigest|Mac\.getInstance" \
  $(cat files_with_findings.txt) 2>/dev/null > priority_files.txt

grep -liE "token|session|nonce|otp|passcode|reset|verify|csrf|salt|secret|credential" \
  $(cat files_with_findings.txt) 2>/dev/null >> priority_files.txt

sort -u priority_files.txt
```

**Step 4 — Review each priority finding (MASTG-TECH-0023)**

For each finding, answer three questions:

1. **What is this time value used for?** Trace the variable to its final consumption point.
2. **Is that point security-relevant?** Compare against the table in §1.4.
3. **If the finding is in a helper function, trace all of its callers.**

```bash
# Trace variables resulting from a time source
grep -rn "random1\|random2\|seed\|nonce" ./decompiled/sources/org/owasp/mastestapp/

# Find callers of the helper function
grep -rn "generateToken\|createSession\|getNonce\|newId\|generateOtp" ./decompiled/sources/
```

### 3.3 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rules:**

> **Observation:** *"The output should contain a list of locations where non-random sources are used."*
>
> **Evaluation:** *"The test case **fails** if you can find **security-relevant values, such as passwords or tokens, generated using non-random sources**."*
>
> **Further Validation Required** — inspect each code location with MASTG-TECH-0023 to determine whether the usage is security-relevant:
> - Determine whether the generated value is used for a security-relevant purpose, such as generating a **cryptographic key, initialization vector (IV), nonce, authentication token, session identifier, password, or PIN**.

The evaluation from MASTG-DEMO-0008 itself is very brief — only *"Review each of the reported instances."* Because of that, the evaluation framework below is needed to make consistent decisions.

**Key clause:** *"security-relevant values ... generated using non-random sources"*. A non-random source **must be proven to flow into a security-relevant value** to be declared FAIL.

---

#### ❌ FAIL / ISSUE — The check is declared FAILED if:

| No | Condition | Example evidence |
|---|---|---|
| F1 | A timestamp is used directly as an **authentication token / session ID** | `int random1 = (int) new Date().getTime();` then used as a token |
| F2 | `Calendar.MILLISECOND` (or another Calendar field) is used as a security-relevant "random" value | `int random2 = c.get(14);` → **only 1,000 possibilities** |
| F3 | A timestamp is used as a **PRNG seed** | `new Random(System.currentTimeMillis())` → CWE-337; the entire output sequence becomes computable |
| F4 | A timestamp is used to **derive a cryptographic key** | `SecretKeySpec(sha256(System.currentTimeMillis().toString()), "AES")` |
| F5 | A timestamp is used as an **IV or nonce** | `IvParameterSpec(longToBytes(System.currentTimeMillis()))` → **critical on GCM** |
| F6 | A timestamp is used for a **password reset token / OTP / verification code** | **Highest severity** — the attacker controls the trigger time |
| F7 | A timestamp is used as a **salt** | `PBEKeySpec(pass, timestampBytes, iter, len)` |
| F8 | A **device identifier** (`ANDROID_ID`, IMEI, MAC, serial) is used as a "random" source | Static per device and not secret |
| F9 | A **counter / sequential value** is used as a secret token or ID | `token = lastId + 1` |
| F10 | A **hash of known data** is used as a secret value | `md5(username + timestamp)` — hashing does not add entropy |
| F11 | `UUID.nameUUIDFromBytes(...)` (UUID v3, **deterministic**) is used for a value that must be unpredictable | A subtle trap — easily mistaken for `UUID.randomUUID()` |
| F12 | `System.nanoTime()` / `SystemClock.*` is used as a security-relevant random source | **Not caught by the MASTG rule** |
| F13 | A modern time API (`LocalDateTime.now()`, `Instant.now()`) is used as a random source | **Not caught by the MASTG rule** |
| F14 | A **combination of several non-random sources** is used, under the mistaken assumption that it produces randomness | `sha256(timestamp + androidId + pid)` — entropy remains low |
| F15 | A time source from **native code** is used for security | `strings lib.so` → `time`, `gettimeofday`, `clock` + review shows usage for key/nonce |

**Example output indicating FAIL — MASTG-DEMO-0008:**

Sample code (`MastgTest.kt`) — note the FAIL annotations provided by MASTG:

```kotlin
fun mastgTest(): String {
    // SUMMARY: This sample demonstrates different ways of creating non-random tokens in Java.

    // FAIL: [android-insecure-random-use] The app uses Date().time for generating authentication tokens.
    val random1 = Date().time.toInt()

    val c = Calendar.getInstance()
    // FAIL: [android-insecure-random-use] The app uses Calendar.getInstance().timeInMillis
    //       for generating authentication tokens.
    val random2 = c.get(Calendar.MILLISECOND)

    return "Generated random numbers:\n$random1 \n$random2"
}
```

Decompiled code scanned by semgrep (`MastgTest_reversed.java`):

```java
public final String mastgTest() {
    int random1 = (int) new Date().getTime();       // <-- line 22
    Calendar c = Calendar.getInstance();
    int random2 = c.get(14);                        // <-- line 24 (14 = Calendar.MILLISECOND)
    return "Generated random numbers:\n" + random1 + " \n" + random2;
}
```

Semgrep output (`output.txt`):

```
┌─────────────────┐
│ 2 Code Findings │
└─────────────────┘

    MastgTest_reversed.java
    ❯❱ rules.mastg-android-non-random-use
          [MASVS-CRYPTO-1] The application makes use of non-random sources.

           22┆ int random1 = (int) new Date().getTime();
            ⋮┆----------------------------------------
           24┆ int random2 = c.get(14);
```

**Five important lessons from this demo:**

1. **`Calendar.MILLISECOND` becomes the literal `14` after decompilation.** This is a very important practical consequence: `grep "Calendar.MILLISECOND"` on decompiled code **will find nothing**. The semgrep rule catches it because it matches `(Calendar $C).get(...)` generically — not because it recognizes the specific constant. Use the constant table in §2.3 when reading decompiled code.
2. **`random2` has only 1,000 possible values.** If used as an authentication token as the demo comment states, this can be brute-forced instantly.
3. **The `(int)` cast truncates the 64-bit value to 32 bits.** `Date().time.toInt()` loses information and can introduce additional patterns.
4. **The rule does not distinguish `new Date()` used for legitimate purposes.** It matches any `Date` object creation, anywhere. This is the main source of false positives in real apps.
5. **There are two small inconsistencies in the demo artifacts** worth noting when replicating:
   - The second FAIL comment mentions `Calendar.getInstance().timeInMillis`, while the actual code is `c.get(Calendar.MILLISECOND)`. Both are problematic, but their entropy differs greatly (full timestamp vs. 1,000 values).
   - The tag in the comment reads `[android-insecure-random-use]`, which is the tag from MASTG-DEMO-0007 (TEST-0204), not `mastg-android-non-random-use`, which is actually used here.

---

#### ✅ PASS — The check is declared PASSED if:

| No | Condition | Example evidence |
|---|---|---|
| P1 | **Semgrep finds no results** and complementary grep is also clean | `0 Code Findings`; no `nanoTime`, `SystemClock`, `Instant.now()` on the crypto path |
| P2 | There are many time-source findings, but review proves **all of them are for legitimate purposes** | `System.currentTimeMillis()` for duration measurement, cache TTL, `createdAt`, UI date formatting |
| P3 | All security-relevant values come from **`SecureRandom`**, not from a time source | `SecureRandom().nextBytes(tokenBytes)` |
| P4 | `SecureRandom` is used with the **default constructor**, without seeding from a timestamp | No `SecureRandom(timeBytes)` or `setSeed(System.currentTimeMillis())` |
| P5 | Key/IV/nonce is generated by the **platform**, not derived from time | `KeyGenerator` + Android KeyStore; `cipher.iv` |
| P6 | A timestamp is used **together with** a random value from a CSPRNG, where security rests on the random component | `token = base64(secureRandomBytes(32)) + ":" + timestamp` — the timestamp is only for expiry, not a source of entropy |
| P7 | `UUID.randomUUID()` is used (based on `SecureRandom`), **not** `UUID.nameUUIDFromBytes()` | Safe for identifiers |
| P8 | Security-relevant tokens are generated by the **server**, not the client | No token generation on the app side |

**Example output indicating PASS:**

```bash
$ NO_COLOR=true semgrep -c mastg-android-non-random-use.yml ./decompiled/sources/ --json -o f.json
$ jq '.results | length' f.json
47
# 47 findings — BUT after triage, all are in a non-security context:
```

```bash
# No findings in files touching a cryptographic/token context
$ grep -lE "SecretKeySpec|IvParameterSpec|GCMParameterSpec|PBEKeySpec" $(jq -r '.results[].path' f.json | sort -u)
# (no results)

# No timestamp used as a seed
$ grep -rnE "new Random\([^)]|setSeed\(|new SecureRandom\([^)]" ./decompiled/sources/
# (no results)

# Other non-random sources not covered by the rule are also clean on the crypto path
$ grep -rnE "nanoTime|SystemClock\.|Instant\.now|nameUUIDFromBytes|ANDROID_ID" ./decompiled/sources/
# (only in telemetry classes, not on the token/crypto path)
```

Correct code:

```kotlin
// ✅ Security-relevant value from a CSPRNG
val secureRandom = SecureRandom()
val tokenBytes = ByteArray(32)
secureRandom.nextBytes(tokenBytes)
val token = Base64.encodeToString(tokenBytes, Base64.URL_SAFE or Base64.NO_WRAP)

// ✅ Timestamp MAY be used for expiry — security rests on the random component
val expiresAt = System.currentTimeMillis() + 15 * 60 * 1000
val payload = "$token:$expiresAt"

// ✅ Key: let the platform generate it
val keyGen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
keyGen.init(
    KeyGenParameterSpec.Builder("myKey", KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
        .setRandomizedEncryptionRequired(true)
        .build()
)
keyGen.generateKey()

// ✅ IV: from the Cipher, not from the time
val cipher = Cipher.getInstance("AES/GCM/NoPadding")
cipher.init(Cipher.ENCRYPT_MODE, key)
val iv = cipher.iv

// ✅ A legitimate use of a timestamp — not a finding
val start = System.currentTimeMillis()
doWork()
Log.d(TAG, "took ${System.currentTimeMillis() - start}ms")
```

---

#### ⚠️ Important Notes on Assessment

1. **This rule is FAR noisier than the MASTG-TEST-0204 rule — this is the most important characteristic of this test.** `new Date()`, `System.currentTimeMillis()`, and `Calendar.get()` are truly common and legitimate APIs. A real app will produce dozens to hundreds of findings that are **almost all legitimate**. Reporting the semgrep output as-is is not only wrong, it will also damage the credibility of the report. **Perform triage (§3.2 Step 3) before review.**

2. **The pattern `(Calendar $C).get(...)` matches ALL `Calendar.get()` calls** — including `c.get(Calendar.YEAR)` for displaying a date in the UI. The rule does not distinguish which field is retrieved. Use the constant table in §2.3 to assess: `get(14)` (MILLISECOND) is highly suspicious; `get(1)` (YEAR) is almost certainly for date formatting.

3. **A more efficient direction of analysis: start from the consumption point, not the source.** Because the sources are too common, it is more productive to first search for **all token/key/nonce creation points**, then check backward whether their input comes from a non-random source. This is the reverse of the usual flow and much more time-efficient:

   ```bash
   # Start from the security-relevant consumption point
   grep -rnE "SecretKeySpec|IvParameterSpec|GCMParameterSpec|PBEKeySpec|new Random\(" ./decompiled/sources/
   grep -rniE "fun .*(generateToken|createSession|newNonce|generateOtp|resetToken)" ./decompiled/sources/
   # -> then check the input origin at each location
   ```

4. **`Calendar.MILLISECOND` cannot be found with grep in decompiled code** — it becomes the literal `14`. Don't conclude safety just because `grep "MILLISECOND"` is empty.

5. **Hashing/encoding does not add entropy.** `sha256(timestamp)` looks like a random 256-bit value, but its entropy is only as large as the uncertainty of the timestamp. Don't be fooled by the presence of `MessageDigest` on the code path — check **what is being hashed**.

6. **Timestamp together with a CSPRNG is fine.** The pattern `secureRandomBytes + timestamp` is a correct practice (timestamp for expiry, entropy from the CSPRNG). What's wrong is the timestamp being used **as** the entropy source. Distinguish these two carefully so as not to produce false positives.

7. **Empty output ≠ automatic PASS.** Rule gaps (see note 8), obfuscation, reflection, native code, and unanalyzed split APKs can all hide findings.

8. **MASTG rule gaps that need to be closed:**

   | Gap | Impact |
   |---|---|
   | `pattern-inside: $M(...){ ... }` requires being inside a method body | **Class-level field initializers slip through**, e.g. `private static final long SEED = System.currentTimeMillis();` |
   | `languages: java` only | Kotlin source is not scanned |
   | Does not cover `System.nanoTime()` | Slips through |
   | Does not cover `SystemClock.elapsedRealtime/uptimeMillis` | Slips through — even though it's Android-specific |
   | Does not cover `java.time` (`Instant.now()`, `LocalDateTime.now()`) | Slips through — modern API |
   | Does not cover `Date(long)`, `Date.from(...)`, `Calendar.getTimeInMillis()` | Only argument-less `new Date()` is matched |
   | Does not cover device identifiers, counters, deterministic hashes, `UUID.nameUUIDFromBytes` | All of Group B (§1.3) slips through |
   | Does not cover native time sources | Slips through |

9. **Severity is modulated by effective entropy and context:**

   | Factor | Severity |
   |---|---|
   | Timestamp/Calendar used for a crypto key or GCM/ECDSA nonce | **Critical** |
   | Used for a password reset token / OTP | **Critical** — the attacker controls the trigger time, making the search space very small |
   | Used for an authentication token / session ID | **High** |
   | `Calendar.MILLISECOND` as a source (1,000 values ≈ 10 bits) | **Raised** — entropy much lower than a full timestamp |
   | Used as a PRNG seed | **High** — the entire output sequence becomes computable |
   | Used for a CBC IV or salt | **Medium–High** |
   | Device identifier as a "random" source | **High** — static and not secret |
   | Rate limiting + short validity period on the server side | Slightly lowered — raises the cost of the attack, **but does not fix the root cause** |
   | Non-security usage (log timestamp, duration, TTL, date formatting) | **Not a finding** |

10. **Prove exploitability whenever possible.** This is a test whose PoC is relatively easy and very convincing: collect several tokens from the app along with their generation time, show the correlation (e.g. with Burp Sequencer or a simple plot), then demonstrate prediction of the next token. This turns the finding from "bad practice" into a "proven vulnerability."

11. **Document complete evidence per finding:** rule ID, path + line number, the decompiled code snippet (**include the meaning of the Calendar literal if applicable**, e.g. `get(14)` = `MILLISECOND`), the result of tracing the flow from source to consumption point, the context classification with its rationale, **estimated effective entropy**, and a PoC if created. Also include the total number of findings vs. the number that survived triage — this shows the quality of the analysis and prevents readers from thinking you simply pasted the tool output.

### 3.4 Complementary Checks (Closing the Rule's Gaps)

```bash
D=./decompiled/sources

# 1. Time sources NOT covered by the MASTG rule
grep -rnE "System\.nanoTime\(\)" $D
grep -rnE "SystemClock\.(elapsedRealtime|uptimeMillis|currentThreadTimeMillis)" $D
grep -rnE "Instant\.now|LocalDateTime\.now|LocalDate\.now|ZonedDateTime\.now|OffsetDateTime\.now" $D
grep -rnE "getTimeInMillis\(\)|new Date\([^)]|Date\.from\(" $D
grep -rnE "new Timestamp\(" $D

# 2. Class-level field initializers (pattern-inside gap)
grep -rnE "(static )?(final )?(long|int) [A-Za-z_]+ *= *System\.currentTimeMillis" $D

# 3. Timestamp as PRNG SEED — most dangerous pattern (CWE-337)
grep -rnE "new Random\(" $D                      # check its argument
grep -rnE "setSeed\(" $D
grep -rnE "new SecureRandom\([^)]" $D

# 4. Other non-random sources (Group B, not covered by the rule)
grep -rnE "ANDROID_ID|getDeviceId|getImei|getSerial|Build\.SERIAL|getMacAddress" $D
grep -rnE "nameUUIDFromBytes" $D                 # UUID v3 = DETERMINISTIC
grep -rnE "hashCode\(\)|identityHashCode" $D
grep -rnE "Thread\.currentThread\(\)\.getId|Process\.myPid" $D

# 5. Suspicious Calendar constant literals in decompiled code
grep -rnE "\.get\(1[1-4]\)|\.get\(13\)|\.get\(14\)" $D      # 11=HOUR,12=MIN,13=SEC,14=MILLISECOND

# 6. Security-relevant consumption points (for reverse-direction analysis — see note 3)
grep -rnE "SecretKeySpec|IvParameterSpec|GCMParameterSpec|KeyGenerator|PBEKeySpec|KeyPairGenerator" $D
grep -rniE "generateToken|sessionId|session_id|nonce|\botp\b|resetToken|csrf|\bsalt\b|verifyCode" $D

# 7. Time sources from native code
for so in $(find ./extracted -name "*.so"); do
  echo "--- $so"; strings "$so" | grep -xE "time|gettimeofday|clock|clock_gettime|times"
done

# 8. Detect protections that limit the reliability of analysis
apkid ./target-app.apk
```

**Extended semgrep rule** to close the main gaps:

```yaml
rules:
  - id: custom-non-random-sources-extended
    severity: WARNING
    languages: [java, kotlin]
    message: "[MASVS-CRYPTO-1] A non-random source is used; verify whether it flows into a security-relevant context"
    pattern-either:
      # Time sources that slip through the MASTG rule
      - pattern: System.nanoTime(...)
      - pattern: android.os.SystemClock.elapsedRealtime(...)
      - pattern: android.os.SystemClock.uptimeMillis(...)
      - pattern: java.time.Instant.now(...)
      - pattern: java.time.LocalDateTime.now(...)
      - pattern: (java.util.Calendar $C).getTimeInMillis(...)
      # Field initializer (without pattern-inside)
      - pattern: System.currentTimeMillis()
      # Deterministic UUID — often mistaken for safe
      - pattern: java.util.UUID.nameUUIDFromBytes(...)
      # Device identifier as a "random source"
      - pattern: android.os.Build.SERIAL

  - id: custom-predictable-seed
    severity: ERROR
    languages: [java, kotlin]
    message: "[MASVS-CRYPTO-1] PRNG seeded with a predictable value (CWE-337)"
    pattern-either:
      - pattern: new java.util.Random(System.currentTimeMillis())
      - pattern: new java.util.Random((new java.util.Date()).getTime())
      - pattern: (java.security.SecureRandom $S).setSeed(System.currentTimeMillis())
      - pattern: (java.util.Random $R).setSeed(System.currentTimeMillis())
```

### 3.5 Optional Dynamic Confirmation

MASTG does not provide a dynamic test for this, but hooking is very effective here — especially for **separating legitimate time usage from dangerous usage** based on the backtrace, while also collecting token samples for a PoC.

```javascript
Java.perform(() => {
    function bt(max = 12) {
        const E = Java.use("java.lang.Exception");
        const st = E.$new().getStackTrace();
        const out = [];
        for (let i = 0; i < Math.min(max, st.length); i++) {
            const f = st[i].toString();
            if (f.indexOf("java.lang.System") === 0) continue;
            out.push("    " + f);
        }
        return out.join("\n");
    }

    // Only flag when the backtrace touches a suspicious context
    const SUSPECT = /token|session|nonce|otp|crypto|cipher|key|secret|random|auth|reset|salt/i;

    const System_ = Java.use("java.lang.System");
    System_.currentTimeMillis.implementation = function () {
        const r = this.currentTimeMillis();
        const trace = bt();
        if (SUSPECT.test(trace)) {
            console.log(`\n[!] System.currentTimeMillis() -> ${r}  (suspicious context)`);
            console.log(trace);
        }
        return r;
    };

    const Cal = Java.use("java.util.Calendar");
    Cal.get.implementation = function (field) {
        const r = this.get(field);
        // 14 = MILLISECOND, 13 = SECOND
        if (field === 14 || field === 13) {
            console.log(`\n[!] Calendar.get(${field}${field === 14 ? " = MILLISECOND" : " = SECOND"}) -> ${r}`);
            console.log(bt());
        }
        return r;
    };

    // Detect a deterministically seeded PRNG (CWE-337)
    const R = Java.use("java.util.Random");
    R.$init.overload('long').implementation = function (seed) {
        console.log(`\n[!!] new Random(${seed}) — EXPLICIT SEED, check whether it comes from time`);
        console.log(bt());
        return this.$init(seed);
    };
    R.setSeed.overload('long').implementation = function (seed) {
        console.log(`\n[!!] Random.setSeed(${seed})`);
        console.log(bt());
        return this.setSeed(seed);
    };
});
```

> The `SUSPECT` filter on the backtrace is important here — without it, hooking `currentTimeMillis()` will produce thousands of lines because this API is called constantly by the framework.

**Token quality analysis** (proof of exploitability):

```bash
# Collect many tokens from the app, then check for time correlation
# Tokens derived from a timestamp will appear monotonic/sequential
sort tokens.txt | uniq -c | head
ent tokens_raw.bin        # low entropy => not from a CSPRNG
# Or use Burp Sequencer for automatic statistical analysis
```

---

### 3.6 Alternative Testing Methods (Multi-Tool)

This test has a particular challenge: the MASTG rule matches **very common and legitimate** APIs (`new Date()`, `System.currentTimeMillis()`), producing dozens to hundreds of findings that are almost all legitimate. The alternative methods below are chosen primarily to **suppress noise**, not just to expand coverage.

#### Method B — Reverse-direction analysis with ripgrep *(most efficient for this test)*

**This is the approach I recommend as the default.** Instead of scanning for time sources (too common), start from the **consumption points**, whose number is far smaller, then check backward.

```bash
jadx -d ./decompiled ./target-app.apk
D=./decompiled/sources

# --- STEP 1: Find ALL security-relevant consumption points (few in number) ---
rg -n --no-heading "SecretKeySpec|IvParameterSpec|GCMParameterSpec|PBEKeySpec|KeyGenerator|KeyPairGenerator" $D > sinks.txt
rg -ni --no-heading "generateToken|createSession|newNonce|generateOtp|resetToken|csrf|verifyCode|\bsalt\b" $D >> sinks.txt
wc -l sinks.txt        # usually dozens, not hundreds

# --- STEP 2: For each file appearing in sinks.txt, search for time sources WITHIN IT ---
for f in $(cut -d: -f1 sinks.txt | sort -u); do
  hit=$(rg -n "currentTimeMillis|new Date\(|nanoTime|Calendar|Instant\.now|SystemClock" "$f")
  [ -n "$hit" ] && { echo "=== $f"; echo "$hit"; }
done

# --- STEP 3: The most dangerous pattern — timestamp as a PRNG SEED (CWE-337) ---
rg -n --no-heading "new Random\(" $D            # check each argument individually
rg -n --no-heading "setSeed\(" $D
rg -n --no-heading "new SecureRandom\([^)]" $D

# --- STEP 4: Time sources NOT covered by the MASTG rule ---
rg -n --no-heading "System\.nanoTime\(\)" $D
rg -n --no-heading "SystemClock\.(elapsedRealtime|uptimeMillis|currentThreadTimeMillis)" $D
rg -n --no-heading "Instant\.now|LocalDateTime\.now|LocalDate\.now|ZonedDateTime\.now|OffsetDateTime\.now" $D
rg -n --no-heading "getTimeInMillis\(\)|new Timestamp\(" $D

# --- STEP 5: Group B — non-random sources other than time (slip through the MASTG rule) ---
rg -n --no-heading "ANDROID_ID|getDeviceId|getImei|getSerial|Build\.SERIAL|getMacAddress" $D
rg -n --no-heading "nameUUIDFromBytes" $D       # UUID v3 = DETERMINISTIC
rg -n --no-heading "hashCode\(\)|identityHashCode|Thread\.currentThread\(\)\.getId|Process\.myPid" $D

# --- STEP 6: Suspicious Calendar constant literals in decompiled code ---
#     Remember: Calendar.MILLISECOND becomes the literal 14 after decompilation
rg -n --no-heading "\.get\(1[1-4]\)" $D
```

#### Method C — CodeQL *(the only one that automatically suppresses noise)*

**This is the most appropriate method for this test.** Because the main problem is the noise ratio, taint analysis tracking the flow of `currentTimeMillis()` → cryptographic sink is the only way to get a list of truly relevant findings without manually reviewing hundreds of hits.

```bash
codeql database create ./cqldb --language=java --command="./gradlew assembleDebug"

codeql database analyze ./cqldb \
  codeql/java-queries:Security/CWE/CWE-335/PredictableSeed.ql \
  codeql/java-queries:Security/CWE/CWE-330/InsecureRandomness.ql \
  --format=sarif-latest --output=nonrandom.sarif
```

Custom query that precisely models this test's problem:

```ql
/**
 * @name Time-based value flows into a security-sensitive sink
 * @kind path-problem
 * @problem.severity error
 */
import java
import semmle.code.java.dataflow.TaintTracking

class TimeSource extends DataFlow::Node {
  TimeSource() {
    exists(MethodAccess ma |
      ma.getMethod().hasQualifiedName("java.lang", "System", ["currentTimeMillis", "nanoTime"]) or
      ma.getMethod().getDeclaringType().hasQualifiedName("java.util", "Date") or
      ma.getMethod().getDeclaringType().hasQualifiedName("java.util", "Calendar") or
      ma.getMethod().getDeclaringType().hasQualifiedName("android.os", "SystemClock") or
      ma.getMethod().getDeclaringType().hasQualifiedName("java.time", ["Instant", "LocalDateTime"]) |
      this.asExpr() = ma
    )
  }
}

class SecuritySink extends DataFlow::Node {
  SecuritySink() {
    // PRNG seed
    exists(ClassInstanceExpr cie |
      cie.getConstructedType().hasQualifiedName("java.util", "Random") |
      this.asExpr() = cie.getAnArgument())
    or
    // Key/IV/salt material
    exists(ClassInstanceExpr cie |
      cie.getConstructedType().hasQualifiedName("javax.crypto.spec",
        ["SecretKeySpec", "IvParameterSpec", "GCMParameterSpec", "PBEKeySpec"]) |
      this.asExpr() = cie.getAnArgument())
    or
    // setSeed
    exists(MethodAccess ma |
      ma.getMethod().hasName("setSeed") |
      this.asExpr() = ma.getAnArgument())
  }
}
```

With this query, an app with 200 calls to `System.currentTimeMillis()` for logging/TTL will produce **zero** findings, and only paths that actually flow into cryptography are reported.

#### Method D — MobSF *(citation-ready report)*

Look in **Code Analysis**: findings like *"The App may use weak PRNG"* and *"App uses time-based values for cryptographic purposes"* (if detected). Note that MobSF also tends to be noisy for this category — treat it as a list of candidates, not a list of vulnerabilities.

#### Method E — SonarQube / SonarLint

Relevant rules: **`java:S2245`** (PRNG security-sensitive) and **`java:S4347`** (*Secure random number generators should not output predictable values* — catches deterministic `setSeed`, including from a timestamp). Sonar excels here because it understands the context of the `new Random(seed)` constructor.

```bash
sonar-scanner -Dsonar.projectKey=android-app -Dsonar.sources=./app/src
```

#### Method F — semgrep registry & third-party rules

```bash
semgrep --config "r/java.lang.security.audit.crypto.weak-random.weak-random" ./decompiled/sources/
semgrep --config "p/java" ./decompiled/sources/

git clone https://github.com/mindedsecurity/semgrep-rules-android-security
semgrep -c ./semgrep-rules-android-security/rules/crypto/ ./decompiled/sources/
```

#### Method G — Statistical token quality analysis *(proof without code access)*

This is a unique path for this test: you can prove a token is derived from a timestamp **without reading any code at all**, using only its output.

```bash
# 1. Collect many tokens from the app (via UI/API, or Frida hook §3.5)
#    Record the TIME each token was obtained.

# 2. Test monotonicity — tokens derived from a timestamp will be sequentially increasing
sort -c tokens.txt && echo "[!] Tokens are MONOTONIC -> strong indication of time-based origin"

# 3. Test entropy — tokens from a CSPRNG approach 8 bits/byte
xxd -r -p tokens_hex.txt > tokens.bin
ent tokens.bin
#   Entropy < 6.0 bits/byte  => not from a CSPRNG

# 4. Test correlation between token delta vs. time delta
#    If delta_token ≈ delta_time(ms), then token = timestamp
paste time_ms.txt tokens_dec.txt | awk 'NR>1 {print $1-pw, $2-pt} {pw=$1; pt=$2}'

# 5. Burp Sequencer — automatic statistical analysis (FIPS test, per-bit entropy)
#    Intercept the request returning a token -> send it to Sequencer -> Start live capture
```

Burp Sequencer is very effective here: it runs a series of FIPS tests and reports an estimate of effective entropy per bit. A timestamp-based token will show very low entropy in the high-order bits.

#### Method H — Frida for collecting token samples *(complement to Method G)*

The script in §3.5 already hooks time sources. To collect the **generated tokens** (not the sources), hook the output point:

```javascript
Java.perform(() => {
    // Example: hook the method that returns a token
    const Klass = Java.use("com.example.app.TokenGenerator");
    Klass.generate.implementation = function () {
        const t = this.generate();
        console.log(`${Date.now()}\t${t}`);     // host timestamp \t token
        return t;
    };
});
```

```bash
frida -U -f com.example.target -l collect_tokens.js -o tokens.tsv
# Then run Method G steps 2–4 on tokens.tsv
```

#### Method I — Native code analysis

```bash
unzip -o ./target-app.apk -d ./apk_x >/dev/null
for so in $(find ./apk_x -name "*.so"); do
  echo "--- $so"
  strings "$so" | grep -xE "time|gettimeofday|clock|clock_gettime|times|mktime"
done
```

---

### 3.7 Method Comparison: When to Use Which

| Method | Tool | Needs device? | Needs source? | Noise ratio | Answers context? | When to use |
|---|---|---|---|---|---|---|
| **A** | semgrep (MASTG) | No | No | **Very high** | ❌ | Official baseline; **must be triaged** |
| **B** | Reverse-direction ripgrep | No | No | **Low** | Manual | **Default I recommend** — start from the sink |
| **C** | CodeQL | No | Yes (ideal) | **Very low** | ✅ **automatic** | **Best** when source is available |
| **D** | MobSF | No | No | High | ❌ | Citation-ready report |
| **E** | SonarQube/SonarLint | No | Yes | Medium | Partial | Shift-left on the developer side; strong for `new Random(seed)` |
| **F** | semgrep registry | No | No | High | ❌ | Broader rule coverage |
| **G** | Statistical token analysis / Burp Sequencer | Partial | **No** | — | — | **Proof without code access**; strongest evidence for a report |
| **H** | Frida (collect tokens) | **Yes** | No | — | ✅ (backtrace) | Complements G; obfuscated code |
| **I** | `strings` / Ghidra | No | No | Medium | Manual | APK with `.so` files |

**Minimum recommended combination:** **B (reverse-direction ripgrep) → G (token analysis)**.
B suppresses noise by starting from the consumption point; G provides empirical evidence that is hard to dispute. Add **C (CodeQL)** when source code is available — for this test its value is greater than for other tests, because the main problem is precisely the noise ratio. Avoid reporting raw output from **A** or **D** without triage.

---

## 4. Recommendations

### 4.1 Main Principle (MASTG-BEST-0001)

**Priority 1 — Do not use time (or any deterministic source) as a source of randomness. Use `SecureRandom`.**

MASTG-BEST-0001 states: *"Use a cryptographically secure pseudorandom number generator as provided by the platform or programming language you are using."* For Java/Kotlin: `java.security.SecureRandom`, which meets the **FIPS 140-2 section 4.9.1** statistical tests and the **RFC 4086** cryptographic strength requirements. It produces non-deterministic output and **seeds itself automatically from system entropy** on initialization.

```kotlin
// ❌ WRONG — all deterministic / very low entropy
val t1 = Date().time.toInt()                                  // timestamp as a token
val t2 = Calendar.getInstance().get(Calendar.MILLISECOND)      // only 1,000 values
val t3 = System.currentTimeMillis()                            // guessable
val t4 = System.nanoTime()                                     // monotonic, not random
val t5 = Random(System.currentTimeMillis())                     // CWE-337: guessable seed
val t6 = sha256("${System.currentTimeMillis()}$androidId")      // hashing does not add entropy
val t7 = UUID.nameUUIDFromBytes(email.toByteArray())            // UUID v3 = deterministic

// ✅ CORRECT — CSPRNG with the default constructor
val secureRandom = SecureRandom()
val tokenBytes = ByteArray(32)
secureRandom.nextBytes(tokenBytes)
val token = Base64.encodeToString(tokenBytes, Base64.URL_SAFE or Base64.NO_WRAP)

// ✅ Or, per the Android documentation's recommendation for modern Android
val rand = SecureRandom.getInstanceStrong()
val otp = 100000 + rand.nextInt(900000)
```

**Priority 2 — Even better: don't generate it yourself, let the platform do it.**

```kotlin
// ✅ Key: Android KeyStore — key material never leaves secure hardware
val keyGen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
keyGen.init(
    KeyGenParameterSpec.Builder("myKey", KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
        .setRandomizedEncryptionRequired(true)
        .build()
)
keyGen.generateKey()

// ✅ IV/nonce: generated by the Cipher, not derived from time
val cipher = Cipher.getInstance("AES/GCM/NoPadding")
cipher.init(Cipher.ENCRYPT_MODE, key)
val iv = cipher.iv

// ✅ Non-secret unique identifier
val id = UUID.randomUUID()          // based on SecureRandom — NOT nameUUIDFromBytes()
```

**Priority 3 — Move security-critical token generation to the server.** For password reset tokens, OTPs, and session identifiers, the client side is not the right place. The server has a better entropy source, can apply rate limiting, and cannot be inspected by an attacker via decompilation.

**Priority 4 — Use timestamps only for their proper purpose.** Timestamps **may and should** be used for expiry, TTL, duration measurement, and timekeeping. What is forbidden is using them **as an entropy source**.

```kotlin
// ✅ Correct pattern — entropy from CSPRNG, timestamp only for expiry
val random = ByteArray(32).also { SecureRandom().nextBytes(it) }
val token = Base64.encodeToString(random, Base64.URL_SAFE or Base64.NO_WRAP)
val expiresAt = System.currentTimeMillis() + 15 * 60 * 1000    // 15 minutes
storeToken(token, expiresAt)
```

**Priority 5 — If a deterministic value is genuinely needed, use a proper derivation function.** This addresses the most common reason developers use a timestamp/device ID as a seed: they need a value that is **reproducible**. The solution is not a deterministic seed, but a **keyed KDF**:

```kotlin
// ❌ WRONG — "reproducible" with a deterministic seed
val key = sha256(androidId + installTimestamp)

// ✅ CORRECT — HKDF with a master key from the KeyStore
//    Reproducible, but its security rests on the master key, not on the input
val mac = Mac.getInstance("HmacSHA256").apply { init(masterKeyFromKeyStore) }
val derived = mac.doFinal("purpose:local-db-encryption".toByteArray())
```

The Android documentation states: for pseudorandom output that needs to be reproducible, use **HMAC, HKDF, or SHAKE** — not `SecureRandom` with a fixed seed.

**Priority 6 — Do not use device identifiers as secrets.** `ANDROID_ID`, IMEI, serial, and MAC address are static, often readable by other apps/parties, and on modern Android their access is restricted. For "installation identity" needs, use a value from `SecureRandom` generated once at installation and then stored in internal storage or the KeyStore.

**Priority 7 — Apply defense in depth (mitigation, not a fix).** It must be emphasized: these measures **do not fix the root cause** and do not turn a finding into a PASS. They remain important, however:
- Strict **rate limiting** on token/OTP verification on the server side
- **Short validity period** (e.g. 15 minutes for a password reset token)
- **Single-use token** — invalidate after use
- **Adequate token length** — at least 128 bits of entropy (16 random bytes)
- **Monitoring** for repeated failed token attempts

**Priority 8 — Enforce this structurally.**
- Add SAST rules to CI/CD (MASTG semgrep + the extended rules from §3.4), with an **allowlist for legitimate timestamp usage** so the gate isn't always red.
- Create **one centralized utility** for all security-relevant random needs (`CryptoRandom.token()`, `CryptoRandom.bytes(n)`), then prohibit secret-value generation outside that utility via a code review checklist or custom lint.
- Consider **CodeQL taint analysis** in the pipeline to automatically track the flow from time sources → crypto points, since this is something semgrep cannot do.
- Check cross-platform frameworks (Flutter/React Native/Unity) — don't assume their built-in random or ID APIs are safe.

### 4.2 Remediation Checklist

- [ ] All semgrep findings have gone through triage, and priority ones have been reviewed with MASTG-TECH-0023
- [ ] For every finding in a helper function, **all of its callers** have been traced
- [ ] No timestamp (`Date().getTime()`, `System.currentTimeMillis()`, `nanoTime()`, `SystemClock.*`, `Instant.now()`) is used as an entropy source
- [ ] No `Calendar.get(...)` — especially `MILLISECOND` (literal `14`) — is used as a "random" value
- [ ] No PRNG is seeded from time (`new Random(System.currentTimeMillis())`, `setSeed(...)`)
- [ ] No device identifier (`ANDROID_ID`, IMEI, serial, MAC) is used as a random or secret source
- [ ] No counter/sequential value is used as a secret token
- [ ] No hash of known data (`md5(username+timestamp)`) is used as a secret value
- [ ] No `UUID.nameUUIDFromBytes()` (deterministic) is used in a context requiring unpredictability; use `UUID.randomUUID()`
- [ ] All security-relevant values come from the default `SecureRandom()` or `SecureRandom.getInstanceStrong()`
- [ ] Keys are generated by `KeyGenerator`/`KeyPairGenerator` + Android KeyStore
- [ ] IV/nonce is generated by `Cipher` or `SecureRandom`; **GCM nonce is guaranteed never to repeat** for the same key
- [ ] KDF salt is ≥ 16 bytes from `SecureRandom`
- [ ] Security-critical tokens (password reset, OTP, session) are generated on the **server**, not on the client
- [ ] Timestamps are used only for expiry/TTL/duration/logging — not as entropy
- [ ] Deterministic values that are genuinely needed are derived with **KeyStore-keyed HKDF/HMAC**, not from a deterministic seed
- [ ] Token length ≥ 128 bits of entropy, single-use, with a short validity period
- [ ] Rate limiting is applied server-side for token/OTP verification
- [ ] Time sources from native code (`time`, `gettimeofday`, `clock`) are not used for security
- [ ] Cross-platform frameworks have been checked — their built-in random/ID APIs are genuinely safe
- [ ] A centralized random utility has been created; secret-value generation outside that utility is prohibited
- [ ] All split APKs / dynamic feature modules are included in the analysis
- [ ] SAST scanning is integrated into CI/CD with an allowlist for legitimate timestamp usage
- [ ] **Re-verify:** re-run MASTG-TEST-0205 + complementary grep → no non-random source in a security-relevant context
- [ ] **Cross-verify:** run MASTG-TEST-0204 (weak PRNG such as `java.util.Random`)

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0205: Non-random Sources Usage](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0205/)
- [MASTG-TEST-0204: Insecure Random API Usage](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0204/)
- [MASWE-0012: Insecure Random Number Generation](https://mas.owasp.org/MASWE/MASVS-CRYPTO/MASWE-0012/)
- [MASTG-DEMO-0008: Uses of Non-random Sources](https://mas.owasp.org/MASTG/demos/android/MASVS-CRYPTO/MASTG-DEMO-0008/MASTG-DEMO-0008/)
- [MASTG-DEMO-0007: Common Uses of Insecure Random APIs](https://mas.owasp.org/MASTG/demos/android/MASVS-CRYPTO/MASTG-DEMO-0007/MASTG-DEMO-0007/)
- [MASTG-KNOW-0013: Random Number Generation](https://mas.owasp.org/MASTG/knowledge/android/MASVS-CRYPTO/MASTG-KNOW-0013/)
- [MASTG-BEST-0001: Use Secure Random Number Generator APIs](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0001/)
- [MASTG-TECH-0013: Reverse Engineering Android Apps](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/)
- [MASTG-TECH-0014: Static Analysis on Android](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/)
- [MASTG-TECH-0023: Reviewing Decompiled Java Code](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0023/)
- [MASTG-TOOL-0110: semgrep](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0110/)
- [MASTG-TOOL-0018: jadx](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0018/)
- [MASTG Rules — `mastg-android-non-random-use.yml`](https://github.com/OWASP/mastg/blob/master/rules/mastg-android-non-random-use.yml)
- [MASVS-CRYPTO: Cryptography](https://mas.owasp.org/MASVS/06-MASVS-CRYPTO/)
- [OWASP MASTG — Testing Cryptography (Random Number Generation)](https://mas.owasp.org/MASTG/0x05e-Testing-Cryptography/)
- [OWASP Cryptographic Storage Cheat Sheet — Secure Random Number Generation](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html#secure-random-number-generation)
- [OWASP Session Management Cheat Sheet — Session ID Entropy](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#session-id-entropy)
- [OWASP Forgot Password Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html)
- [OWASP Mobile Top 10 2024 — M10: Insufficient Cryptography](https://owasp.org/www-project-mobile-top-10/2023-risks/m10-insufficient-cryptography.html)

### 5.2 Official Android / Google / Java Documentation

- [Weak PRNG — Android Security Risks](https://developer.android.com/privacy-and-security/risks/weak-prng)
- [`java.security.SecureRandom` — API reference](https://developer.android.com/reference/java/security/SecureRandom)
- [`java.util.Calendar` — API reference (field constants)](https://developer.android.com/reference/java/util/Calendar)
- [`java.util.Date` — API reference](https://developer.android.com/reference/java/util/Date)
- [`System.currentTimeMillis()` — API reference](https://developer.android.com/reference/java/lang/System#currentTimeMillis())
- [`SystemClock` — API reference](https://developer.android.com/reference/android/os/SystemClock)
- [`UUID` — API reference (`randomUUID` vs `nameUUIDFromBytes`)](https://developer.android.com/reference/java/util/UUID)
- [`KeyGenerator` — API reference](https://developer.android.com/reference/javax/crypto/KeyGenerator)
- [`KeyGenParameterSpec` — API reference](https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec)
- [Android Keystore system](https://developer.android.com/privacy-and-security/keystore)
- [Cryptography best practices](https://developer.android.com/privacy-and-security/cryptography)
- [Best practices for unique identifiers](https://developer.android.com/training/articles/user-data-ids)
- [Android Developers Blog — *Some SecureRandom Thoughts* (2013)](https://android-developers.googleblog.com/2013/08/some-securerandom-thoughts.html)
- [Google Tink — cryptographic library](https://developers.google.com/tink)

### 5.3 Standards, Taxonomies, and Other Guidelines

- [CWE-341: Predictable from Observable State](https://cwe.mitre.org/data/definitions/341.html)
- [CWE-330: Use of Insufficiently Random Values](https://cwe.mitre.org/data/definitions/330.html)
- [CWE-337: Predictable Seed in Pseudo-Random Number Generator (PRNG)](https://cwe.mitre.org/data/definitions/337.html)
- [CWE-340: Generation of Predictable Numbers or Identifiers](https://cwe.mitre.org/data/definitions/340.html)
- [CWE-1241: Use of Predictable Algorithm in Random Number Generator](https://cwe.mitre.org/data/definitions/1241.html)
- [CWE-338: Use of Cryptographically Weak PRNG](https://cwe.mitre.org/data/definitions/338.html)
- [FIPS 140-2 — Security Requirements for Cryptographic Modules (section 4.9.1)](http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.140-2.pdf)
- [RFC 4086 — Randomness Requirements for Security](https://tools.ietf.org/html/rfc4086)
- [NIST SP 800-90A Rev.1 — Recommendation for Random Number Generation Using Deterministic RBGs](https://csrc.nist.gov/publications/detail/sp/800-90a/rev-1/final)
- [NIST SP 800-90B — Entropy Sources Used for Random Bit Generation](https://csrc.nist.gov/publications/detail/sp/800-90b/final)
- [NIST SP 800-108 Rev.1 — Recommendation for Key Derivation Using Pseudorandom Functions](https://csrc.nist.gov/publications/detail/sp/800-108/rev-1/final)
- [NIST SP 800-163 Rev.1 — Vetting the Security of Mobile Applications](https://csrc.nist.gov/publications/detail/sp/800-163/rev-1/final)
- [SEI CERT Oracle Coding Standard for Java — MSC02-J: Generate strong random numbers](https://wiki.sei.cmu.edu/confluence/display/java/MSC02-J.+Generate+strong+random+numbers)
- [SonarQube Rule java:S2245 — Using pseudorandom number generators (PRNGs) is security-sensitive](https://rules.sonarsource.com/java/RSPEC-2245/)
- [CodeQL — Java query help](https://codeql.github.com/codeql-query-help/java/)

### 5.4 Security Research & Technical Articles

- [turingpoint — CWE-330: Use of Insufficiently Random Values](https://turingpoint.de/en/vulnerability-database/CWE-330/)
- [CQR — Insecure Token Generation](https://cqr.company/web-vulnerabilities/insecure-token-generation-2/)
- [Offensive360 — Insecure Randomness](https://offensive360.com/knowledge-base/insecure-random/)
- [elttam — *Cracking the Odd Case of Randomness in Java*](https://www.elttam.com/blog/cracking-randomness-in-java)
- [Franklin Ta — *Predicting the next Math.random() in Java*](https://franklinta.com/2014/08/31/predicting-the-next-math-random-in-java/)
- [Practical CTF — Pseudo-Random Number Generators (PRNG)](https://book.jorianwoltjer.com/cryptography/pseudo-random-number-generators-prng)
- [Terse Systems — *The Right Way to Use SecureRandom*](https://tersesystems.com/blog/2015/12/17/the-right-way-to-use-securerandom/)
- [Baeldung — *Java SecureRandom*](https://www.baeldung.com/java-secure-random)
- [Bitcoin.org — Android Security Vulnerability (2013 alert)](https://bitcoin.org/en/alert/2013-08-11-android)
- [Zellic — *Proton, Dart/Flutter, and the CSPRNG that wasn't*](https://www.zellic.io/blog/proton-dart-flutter-csprng-prng/)
- [arXiv — *Measurements of the Most Significant Software Security Weaknesses*](https://arxiv.org/pdf/2104.05375)
- [HackTricks — Android Applications Pentesting](https://book.hacktricks.wiki/en/mobile-pentesting/android-app-pentesting/index.html)

### 5.5 Tool Documentation

- [Semgrep — Documentation](https://semgrep.dev/docs/)
- [Semgrep — Pattern syntax reference](https://semgrep.dev/docs/writing-rules/pattern-syntax/)
- [mindedsecurity/semgrep-rules-android-security — original source of this MASTG rule](https://github.com/mindedsecurity/semgrep-rules-android-security)
- [IMQ Minded Security — Semgrep Rules for Android Application Security](https://blog.mindedsecurity.com/2023/10/semgrep-rules-for-android-application.html)
- [mobsfscan — static analysis for Android/iOS](https://github.com/MobSF/mobsfscan)
- [MobSF — Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)
- [CodeQL — Documentation](https://codeql.github.com/docs/)
- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [apktool — Reverse engineering Android APK files](https://apktool.org/)
- [APKiD — Android Application Identifier](https://github.com/rednaga/APKiD)
- [Frida — Documentation Home](https://frida.re/docs/home/)
- [Burp Suite — Sequencer (token quality analysis)](https://portswigger.net/burp/documentation/desktop/tools/sequencer)
- [ent — Pseudorandom number sequence test (entropy)](https://www.fourmilab.ch/random/)

---

*This document was compiled based on OWASP MASTG (latest release as of September 2026), official Android Developers documentation, CWE/FIPS/NIST/RFC standards, and third-party security research.*
