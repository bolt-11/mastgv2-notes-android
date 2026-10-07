# MASTG-TEST-0310 Runtime Use of Reused Initialization Vectors in Symmetric Encryption

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0310 |
| **Platform** | Android |
| **MASVS Category** | MASVS-CRYPTO (MASVS-CRYPTO-1) |
| **Weakness** | MASWE-0007 — *Improper Encryption* |
| **Test Type** | **Dynamic, Hooks** |
| **Official MASTG Status** | **`placeholder`** — no complete Overview/Steps/Evaluation yet |
| **Official Note** | **Verbatim identical** to the MASTG-TEST-0309 note — refer to that document's §1 for the complete conceptual discussion (the CBC/NIST SP 800-38A vs. GCM/NIST SP 800-38D requirement difference, Joux's "forbidden attack," real-world cases) |
| **Related Tests** | **MASTG-TEST-0309** (References to Reused Initialization Vectors in Symmetric Encryption) — the static counterpart; both share the **exact same official note**, indicating an explicit static-dynamic pairing relationship even though it is not stated directly in a sentence as with other test pairs |
| **Related Demo** | — (none) |
| **Official Rule** | — (not relevant; a dynamic hooking-based test) |
| **Related CWE** | CWE-1204, CWE-323, CWE-329 |

---

## 1. Explanation

### 1.1 Relationship to MASTG-TEST-0309

This test's official note is **word-for-word identical** to MASTG-TEST-0309 — this fact alone is already a clear methodological signal: both tests target **exactly the same conceptual problem** (repetition of the key-IV/nonce pair in symmetric encryption), differing only in **the angle of testing**. The entire theoretical foundation — the difference between the *unpredictability* requirement (CBC, NIST SP 800-38A) vs. the *uniqueness* requirement (GCM/CTR, NIST SP 800-38D), the mechanics of Joux's "forbidden attack" that makes GCM nonce repetition catastrophic, and real-world cases (`InsecureBankv2`, CVE-2026-50210) — has **already been discussed fully in the MASTG-TEST-0309 document**. This document focuses purely on the **unique added value** of the dynamic, hooking-based approach.

### 1.2 Why a Dynamic Approach Is Needed Beyond What Static Analysis Can Achieve

Static analysis (MASTG-TEST-0309) is very effective at detecting the **most common and easiest** case: an IV/nonce built from a **literal byte array directly in the code** (`new byte[]{0,0,0,...}` or an uninitialized array). However, there are several scenarios where **only runtime observation** can give a definitive answer:

1. **IV/nonce sources that are complex in terms of control flow** — an IV built through several intermediate functions, the result of combining multiple data sources, or derived from native code (JNI) that is not fully visible from pure Java/Kotlin decompilation.
2. **A counter that fails to persist correctly across app lifecycles** — code that **looks statically correct** (e.g., using a counter incremented on every operation) but **fails to save the counter value** to permanent storage across app restarts — causing the counter to **reset to its initial value** (e.g., 0) every time the app is restarted, which effectively creates nonce repetition **across app sessions** that would never be detected simply by reading the source code in a single static-analysis session.
3. **Race conditions in concurrent scenarios** — an app that performs encryption operations from **multiple threads simultaneously** may encounter a race condition that causes two operations to **coincidentally obtain the same IV/nonce value** (e.g., due to a synchronization bug in the counter-generation mechanism), a failure that is **purely a runtime behavior** and impossible to confirm just by reading the code statically.
4. **Values that appear statically random but actually have low entropy** — e.g., an IV generated from `Random` (not `SecureRandom`) with a guessable seed (refer to the in-depth discussion of `Random` vs. `SecureRandom` in the MASTG-TEST-0204/0205 documents in this research series) — the code **appears** to use a "random" source, but the resulting value can still repeat in practice due to the limited period of the pseudo-random generator used.

### 1.3 Hooking Target: `Cipher.init()` as a Single Effective Observation Point

Unlike other tests that may need to hook several different APIs, this test can **efficiently** capture all relevant cases through **a single observation point**: the call to `Cipher.init()` with an `AlgorithmParameterSpec` parameter (which carries the `IvParameterSpec`/`GCMParameterSpec`). Because **every** symmetric encryption/decryption operation must ultimately pass through this initialization point, hooking here provides **comprehensive coverage** without needing to trace IV-generation points that may be scattered across various code locations.

---

## 2. Tools Used for Testing

### 2.1 Required Tools (Core)

| Tool | Function |
|---|---|
| **Frida** | Core dynamic instrumentation — hooking `Cipher.init()` to capture the actual IV/nonce |
| **frida-tools** (`frida-trace`) | Quick tracing |
| **objection** | Ready-to-use Frida wrapper |

### 2.2 Alternative & Supporting Tools

| Tool | Function |
|---|---|
| **Xposed/LSPosed** | An alternative persistent hooking approach |
| **adb** | Forcing repeated app restarts to test scenario #2 in §1.2 (a counter that fails to persist) |

### 2.3 Environment Prerequisites

- **A device/emulator with a Frida server is required.**
- **Thorough AND repeated interaction** — per §1.2, several failure scenarios (a counter not persisted, race conditions) **only surface** when the app is restarted several times or triggered concurrently, not merely during a single, uninterrupted linear interaction session.
- **Ideally test the app-restart scenario** as a mandatory part of the methodology — not just one long session without interruption.

---

## 3. Testing Methodology

Because there are no detailed official steps (placeholder status), the following methodology develops Method C, already introduced in the MASTG-TEST-0309 document, into the primary and more comprehensive approach.

### 3.1 General Steps

1. Install the app and attach a hook on `Cipher.init()`.
2. Explore the app thoroughly, triggering encryption operations repeatedly within a single session.
3. **Restart the app several times** and repeat the same encryption operations, to test counter/nonce persistence across sessions.
4. Compare all captured IV/nonce values — identify any repetition.

### 3.2 Method A — Comprehensive Frida Script with Cross-Session Log Persistence

```javascript
// hook-iv-nonce-runtime-comprehensive.js
Java.perform(function () {
    var seenPairs = {};  // (key alias + IV) combinations already observed

    function bytesToHex(byteArray) {
        return Array.from(Java.array('byte', byteArray))
            .map(b => (b & 0xff).toString(16).padStart(2, '0')).join('');
    }

    function getBacktrace() {
        return Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());
    }

    var Cipher = Java.use("javax.crypto.Cipher");
    Cipher.init.overload("int", "java.security.Key", "java.security.spec.AlgorithmParameterSpec").implementation = function (opmode, key, spec) {
        try {
            var specClassName = spec.getClass().getName();
            var ivBytes = null;

            if (specClassName.indexOf("IvParameterSpec") !== -1) {
                var ivSpec = Java.cast(spec, Java.use("javax.crypto.spec.IvParameterSpec"));
                ivBytes = ivSpec.getIV();
            } else if (specClassName.indexOf("GCMParameterSpec") !== -1) {
                var gcmSpec = Java.cast(spec, Java.use("javax.crypto.spec.GCMParameterSpec"));
                ivBytes = gcmSpec.getIV();
            }

            if (ivBytes !== null) {
                var ivHex = bytesToHex(ivBytes);
                var keyIdentifier = key.toString();  // key identity proxy
                var pairKey = keyIdentifier + ":" + ivHex;

                console.log("[*] Cipher.init(opmode=" + opmode + ") -> IV/nonce: " + ivHex + " (key: " + keyIdentifier + ")");

                if (seenPairs[pairKey]) {
                    console.log("\n[!!!] IV/NONCE REPETITION DETECTED!");
                    console.log("    This (key, IV) pair has ALREADY been used before.");
                    console.log("    Backtrace:\n" + getBacktrace());
                }
                seenPairs[pairKey] = (seenPairs[pairKey] || 0) + 1;
            }
        } catch (e) { console.log("[x] Error while processing spec: " + e); }

        return this.init(opmode, key, spec);
    };
});
```

```bash
# Session 1
frida -U -f com.target.app -l hook-iv-nonce-runtime-comprehensive.js --no-pause
# Explore, trigger encryption, record results

# FULLY restart the app (not just background-foreground)
adb shell am force-stop com.target.app

# Session 2 — repeat with the SAME script to test persistence across restarts
frida -U -f com.target.app -l hook-iv-nonce-runtime-comprehensive.js --no-pause
```

**Important note**: to effectively test the scenario in §1.2 point #2, manually compare the results of **Session 1** and **Session 2** — if an identical IV/nonce appears in both sessions for the same key, this confirms that the counter/nonce-generation mechanism **is not persisted** correctly across app restarts, even though a single session alone showed no repetition.

### 3.3 Method B — objection

```bash
objection -g com.target.app explore
android hooking watch class_method javax.crypto.Cipher.init --dump-args --dump-backtrace
```

With this approach, repetition detection is done **manually** from the dump output, unlike Method A, which automates detection via `seenPairs`.

### 3.4 Method Comparison: When to Use Which

| Method | Tool | Automatic detection? | Tests persistence across restarts? | When to use |
|---|---|---|---|---|
| **A** | Comprehensive Frida script | ✅ | ✅ (with a manual restart procedure) | **Primary baseline** |
| **B** | objection | ❌ (manual) | Manual | Quick initial exploration |

**Recommended minimum combination:** **A, run at least twice with a full app restart in between**, per §1.2 point #2, which is the most unique added value of the dynamic approach over the static one.

---

### 3.5 Evaluation Criteria: Positive Case & Negative Case

Because there is no official Evaluation clause (placeholder status) and its official note is identical to MASTG-TEST-0309, the following criteria adapt the same principles for a runtime observation context.

---

#### ❌ FAIL / ISSUE — The check is declared FAILED when:

| No | Condition |
|---|---|
| F1 | An **identical** (key, IV/nonce) pair is observed being used more than once during a single testing session |
| F2 | An identical (key, IV/nonce) pair is observed repeating **across app restart sessions** — confirming a failure in counter/nonce-generation mechanism persistence (§1.2 point #2) |
| F3 | GCM/CTR mode shows a repeated nonce — the most critical condition given the "forbidden attack" (refer to MASTG-TEST-0309 §1.4) |

**Example evidence (illustrative — MASTG does not yet provide an official demo for this test):**

```
=== Session 1 ===
[*] Cipher.init(opmode=1) -> IV/nonce: 000000000000000000000000 (key: SecretKey@a1b2)

=== After app restart ===
=== Session 2 ===
[*] Cipher.init(opmode=1) -> IV/nonce: 000000000000000000000000 (key: SecretKey@a1b2)

[!!!] IV/NONCE REPETITION DETECTED!
    This (key, IV) pair has ALREADY been used before (across app restart).
```

Interpretation: an identical nonce (`000000...`) appears both in the first session and after the app is fully restarted — indicating the nonce is generated from a counter that **always starts from zero** every time the app is relaunched, with no persistence of the previous counter value. **FAIL**, with a root cause that can only be confirmed through dynamic cross-session testing like this.

---

#### ✅ PASS — The check is declared PASSED when:

| No | Condition |
|---|---|
| P1 | All observed (key, IV/nonce) pairs are **unique**, both within a single session and across several app restart sessions |

---

#### ⚠️ Important Notes on Assessment

1. **Testing within a single session is not enough to capture the entire class of failures** — per §1.2, several scenarios (counter persistence, race conditions) **only surface** through cross-restart testing or concurrent scenarios. A report that only tests one long interaction session risks missing this class of failure.

2. **Always correlate with MASTG-TEST-0309** — the static results provide a map of candidate IV/nonce-generation locations that should be prioritized for triggering during the dynamic session; the dynamic results provide definitive confirmation/refutation of those candidates, while also uncovering failure classes that cannot possibly be seen statically (persistence, race conditions).

3. **Key identity (proxied via `key.toString()` or a similar approach) must have its reliability verified** — ensure the representation used is genuinely unique per distinct key, to avoid mistakenly grouping IVs from keys that are actually different as "the same pair."

4. **Severity follows the same pattern as MASTG-TEST-0309** — prioritize findings in GCM mode over CBC given the severity of the "forbidden attack."

5. **Document:** the IV/nonce values observed per session, the results of the cross-restart comparison, the backtrace of the call location, and the correlation with the static findings from MASTG-TEST-0309.

---

## 4. Recommendations

The technical recommendations are identical to **the MASTG-TEST-0309 document §4** (generate a fresh IV/nonce via `SecureRandom` for every operation). The following is specific to findings uniquely caught through dynamic testing:

### 4.1 Ensure the Nonce-Generator Counter/State Is Persisted Correctly

If the nonce-generation mechanism uses a counter (rather than pure `SecureRandom`), ensure the counter value is **stored persistently** (e.g., in `EncryptedSharedPreferences`/Keystore-backed storage) and **read back** when the app restarts — do not let the counter always start from zero on every new process.

### 4.2 Avoid Counter-Based Nonce Generation Altogether When Possible

To avoid the complexity of managing counter persistence, consider using `SecureRandom` with a sufficiently large value space (96 bits for GCM) — the risk of random collision in such a large value space is practically negligible without needing a bug-prone counter persistence mechanism.

### 4.3 Remediation Checklist

- [ ] `Cipher.init()` hooking is run across at least two sessions with a full app restart in between
- [ ] No (key, IV/nonce) pair is identified as repeating, either within a session or across sessions
- [ ] The nonce-generation mechanism is migrated to pure `SecureRandom`, or to a correctly persisted counter
- [ ] Results are correlated with MASTG-TEST-0309
- [ ] **Re-verify:** rerun MASTG-TEST-0310 after every change to the IV/nonce-generation mechanism

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0310: Runtime Use of Reused Initialization Vectors in Symmetric Encryption](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0310/)
- [MASTG-TEST-0309: References to Reused Initialization Vectors in Symmetric Encryption](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0309/)
- [MASTG-TEST-0204: Insecure Random API Usage](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0204/)
- [MASWE-0007: Improper Encryption](https://mas.owasp.org/MASWE/MASVS-CRYPTO/MASWE-0007/)

### 5.2 Official Standards

- [NIST SP 800-38A: Recommendation for Block Cipher Modes of Operation](https://csrc.nist.gov/pubs/sp/800/38/a/final)
- [NIST SP 800-38D: Recommendation for Block Cipher Modes of Operation — GCM and GMAC](https://csrc.nist.gov/pubs/sp/800/38/d/final)

### 5.3 Tool Documentation

- [Frida — Dynamic instrumentation toolkit](https://frida.re/docs/javascript-api/)
- [Objection — Runtime Mobile Exploration toolkit](https://github.com/sensepost/objection)

---

*This document was compiled based on OWASP MASTG (latest release as of September 2026) and the NIST standards referenced by its official note, which is identical to MASTG-TEST-0309. As the dynamic counterpart, this test's unique value lies in its ability to capture a class of failures that is **impossible to detect through pure static analysis** — specifically counter/nonce persistence failures across app restarts and race conditions in concurrent scenarios. The recommended methodology explicitly requires **cross-session** testing (with a full app restart in between), not just a single linear interaction session, to uncover the unique failure class that is the very reason this dynamic test exists.*
