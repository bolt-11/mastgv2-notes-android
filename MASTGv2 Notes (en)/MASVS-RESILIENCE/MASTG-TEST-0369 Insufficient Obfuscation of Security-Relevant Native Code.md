# MASTG-TEST-0369 Insufficient Obfuscation of Security-Relevant Native Code

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0369 |
| **Platform** | Android |
| **MASVS Category** | MASVS-RESILIENCE |
| **Weakness** | MASWE-0059 |
| **Test Type** | Static, Package, **Manual** |
| **Related Techniques** | MASTG-TECH-0157 (Extracting Bundled Native Libraries), MASTG-TECH-0018 (Disassembling Native Code), MASTG-TECH-0024 (Reviewing Disassembled Native Code) |
| **Related Knowledge** | MASTG-KNOW-0033 (Obfuscation) |
| **Related Best Practice** | MASTG-BEST-0029 |
| **Related Tests** | **MASTG-TEST-0368** — the Java/Kotlin layer counterpart in this research series; this test targets the **native layer** (`.so`), with parallel techniques and threat scenarios but different tooling |
| **Official Rule** | — (none; purely a qualitative human assessment, same as TEST-0368) |

---

## 1. Explanation

### 1.1 Testing Objective and the Common Misconception It Targets

Quote from the official MASTG overview:

> *"If native libraries that implement security-relevant logic are not obfuscated, reverse engineering of packaged native code can expose business logic, device attestation and environment checks, integrity checks, and other implementation details that help an attacker understand the app and model attacks."*

This test is the **native layer** counterpart of MASTG-TEST-0368 (Java/Kotlin layer), already discussed earlier in this research series. The official threat scenario explicitly targets a **common misconception** among developers that is often the primary motivation for moving logic into native code in the first place:

> *"Suppose a banking app moves its integrity and root checks into a native library, assuming native code is inherently harder to analyze, but does not apply any obfuscation."*

The assumption that *"native code is inherently harder to analyze"* **is not entirely wrong** (native disassembly genuinely requires different skills than reading decompiled Java/Kotlin), but **is very misleading if used as the sole reason** for not applying additional obfuscation — "harder" is not the same as "safe," and the official scenario shows just how quickly this flawed assumption can be exposed.

### 1.2 Three Attack Scenario Steps Showing How Fast Reverse Engineering Proceeds Without Obfuscation

> *"Plaintext strings in the .rodata section immediately reveal every file path and system property the library checks, requiring no further analysis to identify the protection's scope. The exported JNI function name and call structure fully expose the check's logic — the attacker understands it within minutes. The attacker hooks the function at runtime to return a benign result regardless of device state, bypasses the integrity check on a rooted device."*

Note that this scenario **requires no deep disassembly at all** for the first step — the `.rodata` section (the read-only data section, where string literals are stored in an ELF binary) can be examined with the most basic `strings` tool, without needing to open a disassembler at all. This is a direct parallel to the finding in TEST-0368 §1.2 that string literals are the fastest "roadmap" for an attacker — the same principle applies identically at the native layer.

### 1.3 Seven Native Layer Obfuscation Techniques (Per MASTG-KNOW-0033)

Unlike the six Java/Kotlin layer techniques already discussed in TEST-0368, MASTG-KNOW-0033 lays out **seven** techniques specific to the native layer (generally LLVM-based, exemplified by the open-source tool O-MVLL):

| Technique | What Is Disguised |
|---|---|
| **Symbol Stripping** | Function names and debug information — however, **JNI functions using the `Java_*` convention remain exposed** unless registered dynamically via `RegisterNatives` |
| **Control Flow Flattening** | The original branching structure — replaced by a loop+switch-based dispatcher |
| **Junk Code** | Adds duplicate basic blocks/redundant code paths to increase analysis noise |
| **Arithmetic Obfuscation** | Simple arithmetic/bitwise operations replaced with more complex equivalent expressions |
| **Strings Encoding** | String literals in `.rodata` — identical in purpose to String Encryption at the Java layer |
| **Opaque Constants** | Integer constants/magic numbers — reconstructed at runtime rather than written directly |
| **Obfuscated Function Calls** | The call graph — direct calls replaced with indirect calls |

### 1.4 An Important Technical Nuance: Symbol Stripping Does Not Automatically Hide JNI Functions

This is a very specific detail that's easy to miss, quoted directly from MASTG-KNOW-0033 (already noted in the TEST-0368 document but highly relevant to repeat here since this test directly targets the native layer):

> *"Native libraries that use name-based JNI resolution still expose descriptive exported `Java_*` symbols even after symbol stripping. Registering native methods dynamically through `JNI_OnLoad` and `RegisterNatives` can reduce that exposure, as the symbols of such functions can be stripped due to not needing to follow the `Java_*` convention."*

This explains exactly **why** the official threat scenario (§1.2) states that *"exported JNI function name... fully expose the check's logic"* — if a native function is called from Java using the **automatic naming convention** (`Java_com_example_app_SecurityChecker_isRooted`), that function name **must** remain descriptive in the symbol table so the JVM can find it automatically when loading the library — even after symbol stripping is applied to other functions. The only way to avoid this is to **register the function manually** via `RegisterNatives` inside `JNI_OnLoad`, which frees the function name from the obligation to follow the `Java_*` convention and allows that name to be stripped as well.

### 1.5 Three Diagnostic Criteria, Paralleling TEST-0368 but for Native Artifacts

> *"Determine whether native library strings or constants... are in plaintext. Determine whether the disassembled function structure and call edges still reveal the original security-relevant logic with recognizable patterns. Determine whether exported JNI symbols retain descriptive names that can be directly correlated with security-relevant functionality."*

The structure of these three criteria **deliberately parallels** TEST-0368 (strings, structure/control-flow, identifiers/symbols) — confirming that both tests use the same conceptual evaluation framework, only applied to different artifact formats (decompiled DEX bytecode vs. disassembled ELF binary).

### 1.6 Real-World Evidence: Widely Documented Bypass Techniques for Un-Obfuscated Native Root Detection

Community research confirms that the combination of native root detection without obfuscation is a very easy target to exploit with standard tools:

> *"Non-obfuscated native library implementations can be identified and analyzed during reverse engineering. Product names and versions can be retrieved from the strings section (.rodata section) of ELF files, while defined functions can be retrieved from the Symbol Table section."*

And a documented concrete bypass technique:

> *"Decompilers like Ghidra can be used to decompile root detection functions, and by patching the instruction to always return 0, the modified .so binary can be pushed back to the app directory to bypass root detection."*

This shows that the risk from this test is not limited to **understanding** the logic alone (as emphasized by the official scenario), but can directly proceed to **binary patching** — once the target function is easily identified via the symbol table and plaintext strings, direct modification of the assembly instructions (making the function always return a "safe" value) becomes a relatively simple follow-up step for an experienced attacker.

---

## 2. Tools Used for Testing

### 2.1 Required Tools (Core)

| Tool | Function |
|---|---|
| **unzip/apktool** | Extracting `.so` native libraries (MASTG-TECH-0157) |
| **Ghidra / IDA Pro / radare2** | Disassembly and review of native code (MASTG-TECH-0018, MASTG-TECH-0024) |

### 2.2 Alternative & Supporting Tools

| Tool | Function |
|---|---|
| **strings / objdump** | Quickly checking the `.rodata` section before full disassembly (replicating the first step of the threat scenario in §1.2) |
| **nm / readelf** | Checking the symbol table for JNI functions that remain exposed even after symbol stripping is applied (§1.4) |
| **APKiD** | Detecting known native obfuscator signatures (O-MVLL, etc.), with the same detection limitations discussed in TEST-0368 |

### 2.3 Environment Prerequisites

- No device/root needed — purely static analysis of the extracted `.so` file.
- Basic ARM/x86 disassembly-reading ability is strongly recommended.

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0157** to extract native libraries from the application package.

(Same as TEST-0368, the official steps are deliberately brief — confirming the test's core is a qualitative assessment of extraction/disassembly results, not a series of staged pattern searches.)

### 3.2 Method A — Quick Check of the .rodata Section (Replicating the First Step of the Official Scenario)

```bash
unzip -o target.apk "lib/*" -d extracted_libs
strings extracted_libs/lib/arm64-v8a/libsecuritycheck.so | grep -iE '/proc/|su|magisk|busybox|ro\.secure|TracerPid'
```

### 3.3 Method B — Checking the Symbol Table for JNI Functions (Per §1.4)

```bash
nm -D extracted_libs/lib/arm64-v8a/libsecuritycheck.so | grep 'Java_'
readelf -sW extracted_libs/lib/arm64-v8a/libsecuritycheck.so | grep FUNC
```

If many functions with descriptive names (`Java_com_example_app_SecurityChecker_isRooted`) appear, this indicates symbol stripping was **not applied effectively**, or that function uses the automatic JNI convention without `RegisterNatives`.

### 3.4 Method C — Full Disassembly to Assess Structure and Call Graph

```bash
# Via Ghidra (headless) or interactive radare2
r2 -A extracted_libs/lib/arm64-v8a/libsecuritycheck.so
[0x...]> afl  # list of functions
[0x...]> pdf @ sym.Java_com_example_app_SecurityChecker_isRooted
```

Assess: is the control flow easy to follow (simple linear branching), or has it already undergone significant flattening/junk code?

### 3.5 Method D — Verifying Known Obfuscator Signatures

```bash
apkid target.apk
```

### 3.6 Method Comparison: When to Use Which

| Method | Tool | When to use |
|---|---|---|
| **A** | strings | Mandatory baseline — replicating the first step of the threat scenario |
| **B** | nm/readelf | Verifying the third diagnostic criterion (JNI symbols) |
| **C** | Ghidra/radare2 | Verifying the second diagnostic criterion (structure/call graph) |
| **D** | APKiD | Identifying the obfuscation tool used (with limitations) |

**Minimum recommended combination:** **A + B (mandatory, quick) → C (mandatory for ambiguous cases)**.

---

### 3.7 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rule:**

> **Evaluation:** *"The test case fails if the app's native libraries allow an attacker to identify, correlate, and reverse engineer security-relevant logic with reasonable effort."*

---

#### ❌ FAIL / ISSUE — The check is declared FAILED if:

| No | Condition |
|---|---|
| F1 | Sensitive strings/constants are in plaintext in `.rodata`, **and/or** descriptive JNI symbols remain exposed, **and/or** the call graph structure is easy to follow without deep disassembly |

**Example evidence (reflecting the official scenario in §1.2):**

```bash
$ strings libsecuritycheck.so | grep -i proc
/proc/self/status
/system/bin/su

$ nm -D libsecuritycheck.so | grep Java_
0000000000001234 T Java_com_example_bank_SecurityChecker_isRooted
```

Interpretation: the file paths being checked (`/proc/self/status`, `/system/bin/su`) and the JNI function name (`isRooted`) directly reveal the scope and purpose of the protection without needing deep disassembly. **FAIL** — exactly the official scenario.

---

#### ✅ PASS — The check is declared PASSED if:

| No | Condition |
|---|---|
| P1 | Sensitive strings/constants are encrypted (not plaintext in `.rodata`), **and** |
| P2 | JNI functions are registered via `RegisterNatives` with effective symbol stripping (no descriptive names in the symbol table), **and** |
| P3 | The control flow of critical logic has been obfuscated (flattening/junk code/indirect calls) |

---

#### ⚠️ Important Notes on Scoring

1. **Always start with checking `.rodata` and the symbol table** — this is the easiest and fastest step, often already sufficient to conclude FAIL without needing deep disassembly, exactly replicating the shortcut a real attacker would use.

2. **Specifically check whether the function uses the automatic `Java_*` convention** — per §1.4, this is the most common reason symbol stripping "fails" to hide the most critical JNI function, even when other internal functions are successfully stripped.

3. **Do not conclude PASS merely because no known obfuscator signature is found** — same as TEST-0368 §1.6, custom in-house obfuscation may still exist even if undetected by signature-based tools.

4. **Severity is modulated as follows:**

   | Factor | Severity |
   |---|---|
   | A financial integrity/root check can be understood and patched within minutes | **High** |
   | Sensitive logic requires significant disassembly effort to understand | **Medium** |
   | All three diagnostic criteria are met, including proper handling of JNI symbols | **Not a finding** |

5. **Document:** the `.so` library name, the specific strings/symbols found in plaintext, the results of checking `RegisterNatives` vs. the automatic convention, and the estimated time/effort to understand the logic via disassembly.

---

## 4. Recommendations

### 4.1 Register JNI Functions Manually to Enable Full Symbol Stripping

```c
// BEFORE — automatic convention, the name MUST be descriptive so the JVM can find it
JNIEXPORT jboolean JNICALL
Java_com_example_bank_SecurityChecker_isRooted(JNIEnv *env, jobject thiz) { ... }

// AFTER — RegisterNatives, the internal function name is free to be stripped
static JNINativeMethod methods[] = {
    {"isRooted", "()Z", (void *)nativeCheck} // the Java name stays "isRooted", the C name is free
};

JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    JNIEnv *env;
    vm->GetEnv((void **)&env, JNI_VERSION_1_6);
    jclass clazz = env->FindClass("com/example/bank/SecurityChecker");
    env->RegisterNatives(clazz, methods, 1);
    return JNI_VERSION_1_6;
}
```

### 4.2 Encrypt Sensitive Strings and Obfuscate Control Flow

```python
# O-MVLL configuration for a specific integrity check function
def obfuscate_string(self, _, __, string: bytes):
    if string in [b"/proc/self/status", b"/system/bin/su"]:
        return omvll.StringEncOptLocal()
    return False

def flatten_cfg(self, mod, func):
    return func.name == "nativeCheck"
```

### 4.3 Remediation Checklist

- [ ] JNI functions handling sensitive logic are registered via `RegisterNatives`, not the automatic `Java_*` convention
- [ ] Sensitive strings/constants (paths, tokens, integrity comparison values) are encrypted
- [ ] The control flow of integrity/root check functions is obfuscated (flattening/indirect calls)
- [ ] Re-verified with `strings`/`nm` after the build to ensure no leaks slip through

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0369 (source, tests-beta)](https://github.com/OWASP/mastg/blob/master/tests-beta/android/MASVS-RESILIENCE/MASTG-TEST-0369.md)
- [MASTG-TEST-0368 (the Java/Kotlin layer counterpart document in this research series)](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0368/)
- [MASTG-KNOW-0033: Obfuscation](https://mas.owasp.org/MASTG/knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0033/)
- [MASTG-TECH-0024: Reviewing Disassembled Native Code](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0024/)

### 5.2 Research and Real-World Cases

- [8kSec: Frida Part 5 — Root Detection Bypass](https://www.8ksec.io/advanced-root-detection-bypass-techniques/)
- [arXiv: A Risk Estimation Study of Native Code Vulnerabilities in Android Applications](https://arxiv.org/pdf/2406.02011)
- [O-MVLL: LLVM-based Native Obfuscator](https://obfuscator.re/omvll/)

### 5.3 Tool Documentation

- [Ghidra — NSA Reverse Engineering Framework](https://ghidra-sre.org/)
- [radare2](https://rada.re/n/)
- [APKiD](https://github.com/rednaga/APKiD)

---

*This document was prepared based on official OWASP MASTG content (`tests-beta/android/MASVS-RESILIENCE/MASTG-TEST-0369.md`, `MASTG-KNOW-0033`), with an in-depth cross-reference to the MASTG-TEST-0368 document (the Java/Kotlin layer counterpart) in this research series, as well as community research on widely documented native root-detection bypass techniques. The most important and native-layer-specific methodological nuance: JNI functions using the automatic `Java_*` naming convention **still must** have a descriptive name in the symbol table so the JVM can find them, even after symbol stripping is applied to all other internal functions — the only way to avoid this is to register the function manually via `RegisterNatives` in `JNI_OnLoad`. This technically explains precisely why the official threat scenario cites the exported JNI function name as one of the most significant sources of information leakage.*
