# MASTG-TEST-0288 Debugging Symbols in Native Binaries

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0288 |
| **Platform** | Android |
| **MASVS Category** | MASVS-RESILIENCE |
| **Weakness** | MASWE-0061 — *Debug Artifacts Not Removed* (the same as the `StrictMode` test group — MASTG-TEST-0263/0264/0265 — in this research series, now applied to native binaries) |
| **Test Type** | Static, Code |
| **Related Techniques** | MASTG-TECH-0140 (Obtaining Debugging Information and Symbols) |
| **Related Demo** | — (none) |
| **Official Rule** | — (not applicable; this is ELF binary analysis, not Java/Kotlin code pattern matching) |
| **Related CWE** | CWE-215 (Insertion of Sensitive Information Into Debugging Code), CWE-540 (Inclusion of Sensitive Information in Source Code) |

---

## 1. Explanation

### 1.1 Testing Objective

Official MASTG overview quote:

> *"This test checks whether the app includes debugging symbols in its native binaries. Debugging symbols can provide valuable information during reverse engineering and vulnerability analysis by exposing sensitive implementation details such as function names, variable names, and source file references."*

This test targets **native binaries** (`.so`, ELF format) compiled from C/C++ code via the Android NDK — not DEX bytecode like most other tests in this research series. Debugging symbols (real function names, variable names, `.cpp` source file references/code lines) left behind in a release binary provide a **free map** for reverse engineering efforts — the same concept discussed in depth in the MASTG-TEST-0263 document (StrictMode) regarding how debug artifacts leak an application's internal structure, now applied to the native code context.

### 1.2 The Most Important Finding: The NDK Already Performs Stripping Automatically and Aggressively

This is the most crucial nuance distinguishing this test from most other "debug artifact" tests in this research series (e.g., MASTG-TEST-0226 debuggable flag, MASTG-TEST-0263-0265 StrictMode) — in those tests, **the developer must actively apply a guard** (`BuildConfig.DEBUG`) to prevent the leak from reaching production. For native debugging symbols, the situation is actually **reversed**: research from the NDK developer community found that the **Android NDK toolchain, by default, automatically strips debug symbols**, even described as:

> *"The Android SDK (NDK) will strip debugging symbols from native libraries going into an application automatically (in fact **it is very hard to disable**)."*

This means that, **unlike most other resilience tests in this series, a FAIL condition for this test is relatively rare on modern projects** that use a standard build toolchain (Gradle + CMake/ndk-build) without explicit configuration modifications. FAIL usually appears because of **deliberate changes to the default settings** or **specific build misconfigurations** — not passive negligence like most other tests. This changes how a tester should approach the investigation: instead of asking "did the developer forget to add a guard?", the more appropriate question is **"what specific build configuration caused this symbol to remain?"**

### 1.3 A Crucial Distinction: Debug Symbols vs. Dynamic Symbols — Why "Zero Symbols" Is Not a Realistic Expectation

This is a technical distinction that **must** be understood before evaluating binary inspection results, as it has the potential to cause significant misinterpretation:

| Symbol Type | What it contains | Can/should it be removed? |
|---|---|---|
| **Debug symbols** (`.symtab`, DWARF info) | Local variable names, line numbers, source `.cpp` file references, internal/static function names | **Yes, must be removed** — this is this test's evaluation target |
| **Dynamic symbols** (`.dynsym`) | Function names that **must remain visible** so they can be called from outside the binary — especially **JNI entry points** (`Java_com_example_MainActivity_stringFromJNI`) | **Cannot be removed** — removing them would break the application's functionality |

Community research explicitly confirms this technical limitation:

> *"Strip won't remove dynamic symbols, or it would make the library unusable... If your .so is a JNI library, you need to have the JNI entry point functions visible externally."*

**Important implication for evaluation**: a tester **must not** expect a result of "zero symbols whatsoever" as the PASS condition — a `.so` that is a JNI library **will always** show `Java_<package>_<class>_<method>` function names in the `.dynsym` table as an **unavoidable** part of how JNI itself works. These JNI function names do leak **a small amount of information** (the Java package/class/method name that calls them), but this is an **architectural limitation** that belongs to a different category than the leakage of internal implementation information (local variable names, internal logic of non-JNI functions, developer source file paths) that is this test's actual focus.

### 1.4 Real Security Consequences: Native Code as a Different Memory-Risk Surface

Native (C/C++) code has a fundamentally different risk profile from Java/Kotlin code, because it lacks automatic memory protection:

> *"Native code languages like C/C++ lack the memory safety features of Java/Kotlin, making them susceptible to vulnerabilities like buffer overflows, use-after-free errors, and other memory corruption issues."*

This explains why debugging symbol leakage in native binaries carries **more significant** risk weight than its Java/Kotlin counterpart: leaked function and variable names give vulnerability researchers (both defenders and attackers) a **direct map** to identify functions handling input parsing, buffer management, or raw memory operations — points that have historically been the most common locations for memory corruption vulnerabilities (buffer overflow, use-after-free) in C/C++ code. Academic research ("A Risk Estimation Study of Native Code Vulnerabilities in Android Applications") confirms that using native code via JNI does **indeed** expand an Android application's risk surface in a way that pure Java/Kotlin applications do not have.

### 1.5 Reverse Engineering Context: FLIRT and the Real Limits of Stripping

It is important to set realistic expectations: **stripping debug symbols is not an absolute guarantee** against reverse engineering, it only **raises the cost of the effort**. Professional reverse engineering tools such as IDA Pro have **FLIRT (Fast Library Identification and Recognition Technology)**, which can **re-identify** functions from standard/popular libraries even on a fully stripped binary, by matching instruction byte patterns against a known signature database. Other academic research (`punstrip`, ACSAC 2020) even explores machine learning techniques to **recover function names** from stripped binaries. This context matters for an audit report: stripping debug symbols remains **mandatory** as a basic hardening measure (and per §1.2, is already done automatically by modern toolchains), but it is **not a replacement** for other resilience controls like native code obfuscation, anti-tampering, or debugger detection — it is only one layer within a broader defense-in-depth strategy.

---

## 2. Tools Used for Testing

### 2.1 Mandatory Tools (Core, Per MASTG-TECH-0140)

| Tool | Function |
|---|---|
| **radare2** | `i~stripped,linenum,lsyms` — a quick way to check stripped/not-stripped status; `is`/`rabin2 -s` to view remaining symbols |
| **objdump** | `objdump --syms` — the standard Binutils way to check the ELF symbol table |
| **nm** | Extracting the symbol table; `nm -a` for local symbols, compared against plain `nm` to detect the presence of `.symtab` |

### 2.2 Alternative & Supporting Tools

| Tool | Function |
|---|---|
| **rabin2** (radare2 suite) | `rabin2 -s libnative-lib.so \| grep JNI` — a filter specifically for JNI symbols to separate them from other debug symbols |
| **readelf** | `readelf -S libnative-lib.so` — directly checks for the presence of `.debug_info`, `.debug_line` (DWARF) sections, a more precise complement than merely checking the symbol table |
| **file** (Unix) | `file libnative-lib.so` — the output explicitly lists `not stripped` or `stripped` as a very quick check |
| **strings** | Extracting literal strings from the binary — although not technically a debug symbol, leftover source file path strings (`/home/dev/project/src/native/...`) also leak similar project structure information |
| **IDA Pro / Ghidra with FLIRT/signature matching** | For realistically assessing how much information can **still be recovered** even after the binary has been stripped — provides context on the real level of protection beyond just a "stripped/not" binary check |

### 2.3 Environment Prerequisites

- **No device/root required** — this can be done entirely from the APK file, just by extracting `.so` files from the `lib/<abi>/` directory.
- **Test on the final RELEASE APK**, not a debug build — a debug build naturally includes full symbols for development debugging needs.
- **Check ALL bundled ABI architectures** (`armeabi-v7a`, `arm64-v8a`, `x86`, `x86_64`) — an inconsistent build configuration can produce different stripping statuses across architectures.

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0140** to obtain the debugging information present in the native binary.

### 3.2 Method A — radare2 *(the official primary method)*

```bash
unzip -o target-app.apk 'lib/*' -d ./native_libs
r2 -A ./native_libs/lib/arm64-v8a/libnative-lib.so
[0x0003e360]> i~stripped,linenum,lsyms
```

Example output indicating **FAIL**:

```
linenum  true
lsyms    true
stripped false
```

Example output indicating **PASS**:

```
linenum  false
lsyms    false
stripped true
```

To view remaining symbols (including distinguishing JNI vs. non-JNI per §1.3):

```bash
rabin2 -s ./native_libs/lib/arm64-v8a/libnative-lib.so | grep -v "JNI\|Java_"
```

If this filtered result (symbols **other than** JNI) shows many entries, this is a strong indication of a FAIL condition — because non-JNI symbols should not need to remain visible.

### 3.3 Method B — objdump / nm (Standard Binutils Alternative)

```bash
objdump --syms ./native_libs/lib/arm64-v8a/libnative-lib.so
```

```bash
# Compare regular symbols vs. ALL symbols (including local ones)
diff <(nm ./native_libs/lib/arm64-v8a/libnative-lib.so) \
     <(nm -a ./native_libs/lib/arm64-v8a/libnative-lib.so)
```

Per MASTG-TECH-0140: **an empty diff output** = debug symbols have been stripped (PASS); **additional entries** with function names/source file references = debug symbols are still present (FAIL).

### 3.4 Method C — readelf (Direct DWARF Section Verification)

```bash
readelf -S ./native_libs/lib/arm64-v8a/libnative-lib.so | grep -i debug
```

If sections like `.debug_info`, `.debug_line`, `.debug_str` appear, this is direct evidence of the presence of full DWARF debugging information — a very strong indication of FAIL, even more precise than merely checking the symbol table.

### 3.5 Method D — Quick Check with `file`

```bash
file ./native_libs/lib/*/*.so
```

```
libnative-lib.so: ELF 64-bit LSB shared object, ARM aarch64, ..., not stripped
```

The keyword **"not stripped"** immediately gives a quick signal without needing additional tools — useful for a quick initial check before deeper analysis with Methods A-C.

### 3.6 Method E — Build Configuration Audit (Whitebox, Identifying the Root Cause)

Per §1.2, since stripping is already the default, a FAIL finding usually originates from an incorrect explicit configuration. Check:

```gradle
// build.gradle or CMakeLists.txt — look for an override disabling the default stripping
externalNativeBuild {
    cmake {
        arguments "-DANDROID_STL=c++_shared"
        // Look for a line that explicitly disables strip, e.g., cppFlags "-g" without a subsequent strip step
    }
}
```

```bash
# Check whether packagingOptions/jniLibs explicitly exclude stripping
grep -n "doNotStrip\|debugSymbolLevel" app/build.gradle
```

The Gradle **`packagingOptions.doNotStrip`** flag is the most common cause of finding an unstripped binary in a production build — it is usually intentionally enabled for **symbolicated crash reporting** purposes (to make native crash stack traces more informative), but then **left** active in the final release build, rather than being limited to an internal build for the team's debugging purposes.

### 3.7 Method Comparison: When to Use Which

| Method | Tool | Precision | When to use |
|---|---|---|---|
| **A** | radare2 | High, distinguishes JNI vs. non-JNI | **Primary official baseline** |
| **B** | objdump/nm | High, standard Binutils | Alternative without radare2 |
| **C** | readelf | Very high (directly to the DWARF section) | Most precise verification |
| **D** | file | Low but very fast | Quick initial triage |
| **E** | Build config audit | N/A (root-cause identification) | **Mandatory** if FAIL is found, for precise remediation |

**Minimum combination recommended:** **D (quick triage) → A/C (precise confirmation, distinguishing JNI from genuine debug symbols) → E (identifying the configuration root cause if FAIL)**.

---

### 3.8 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rule:**

> **Observation:** *"The output should identify all instances of debugging information in the native binaries."*
>
> **Evaluation:** *"The test case fails if debugging information is present in any native binary, including if actual debugging symbols were successfully extracted."*

---

#### ❌ FAIL / ISSUE — The check is declared FAILED if:

| No | Condition |
|---|---|
| F1 | `radare2`/`objdump`/`nm` shows the binary is **not** stripped (`stripped: false`, or `nm -a` produces additional entries compared to plain `nm`) |
| F2 | `readelf -S` shows the presence of `.debug_info`/`.debug_line` (full DWARF) sections |
| F3 | The symbols found are **not** limited to JNI entry points (`Java_*`) — they include internal function names, variables, or `.cpp` source file references |
| F4 | An explicit build configuration (`doNotStrip`, `debugSymbolLevel=FULL`) is found that disables the default stripping on the release build |

**Example evidence (illustrative — MASTG does not yet provide an official demo for this test):**

```bash
$ file libnative-lib.so
libnative-lib.so: ELF 64-bit LSB shared object, ARM aarch64, ..., not stripped

$ readelf -S libnative-lib.so | grep -i debug
  [27] .debug_info       PROGBITS
  [28] .debug_line       PROGBITS

$ rabin2 -s libnative-lib.so | grep -v "Java_"
150 0x00003a20 GLOBAL FUNC 64 validateSessionToken
151 0x00003a80 GLOBAL FUNC 128 decryptPayloadInternal
```

Interpretation: full DWARF sections are found, plus internal function symbols (`validateSessionToken`, `decryptPayloadInternal`) that are clearly not JNI entry points and directly leak which functions handle session/decryption logic. **Critical FAIL**.

---

#### ✅ PASS — The check is declared PASSED if:

| No | Condition |
|---|---|
| P1 | Every `.so` binary across all ABI architectures shows a `stripped: true` status |
| P2 | `readelf -S` shows **no** DWARF sections at all |
| P3 | Any remaining symbols are **only** JNI entry points that must legitimately remain visible (§1.3) — not a violation, this is an unavoidable architectural limitation |

**Example output indicating PASS:**

```bash
$ file libnative-lib.so
libnative-lib.so: ELF 64-bit LSB shared object, ARM aarch64, ..., stripped

$ rabin2 -s libnative-lib.so
150 0x00003a20 GLOBAL FUNC 16 Java_com_example_target_MainActivity_stringFromJNI
# (only JNI entry points, no other internal symbols)
```

---

#### ⚠️ Important Assessment Notes

1. **Do not expect "zero symbols" as the PASS standard** — per §1.3, JNI entry points **must** remain visible in `.dynsym` for the application to function. Focus the evaluation on **debug symbols** (DWARF, local `.symtab` symbol table), not all symbols indiscriminately.

2. **Remember that this condition is relatively rare to FAIL on modern projects** (§1.2) because the NDK toolchain already performs automatic, aggressive stripping — if FAIL is found, this is a **strong signal** of an explicit configuration that needs investigating (Method E), not merely passive negligence like many other tests.

3. **Directly verifying the DWARF section (`readelf -S`) gives the highest certainty** — more precise than merely relying on radare2's `stripped` flag, because some partial-stripping scenarios might leave behind some debug information that is not always perfectly reflected in that summary flag.

4. **Investigate the root cause if FAIL is found** — most likely caused by `packagingOptions.doNotStrip` being deliberately enabled for symbolicated crash reporting but left active in the release. Remediation recommendations should direct the team toward the correct solution: **upload symbols separately to a crash reporting service** (e.g., Firebase Crashlytics, Play Console native symbol upload) instead of leaving symbols inside the binary distributed to users.

5. **Stripping is not an absolute protection** (§1.5) — do not let a PASS status on this test give the impression in an audit report that native code is fully protected from reverse engineering; it is only one basic layer, also consider native code obfuscation and other anti-tampering controls as part of a broader resilience strategy.

6. **Severity is modulated:**

   | Factor | Severity |
   |---|---|
   | Full DWARF section + cryptography/authentication function symbols exposed | **High** |
   | Non-sensitive function symbols (e.g., native UI rendering utilities) exposed | **Medium/Low** |
   | Only JNI entry points visible (expected condition) | **Not a finding** |

7. **Document:** stripped/not-stripped status per `.so` file per ABI architecture, the presence of DWARF sections, the list of non-JNI symbols found (if any), and the build configuration audit result identifying the root cause.

---

## 4. Recommendations

### 4.1 Ensure Build Configuration Does Not Disable Default Stripping

```gradle
android {
    packagingOptions {
        jniLibs {
            // DO NOT enable doNotStrip unless truly necessary,
            // and if necessary, limit it ONLY to debug/internal builds
        }
    }
    buildTypes {
        release {
            externalNativeBuild {
                cmake {
                    // Ensure there is no -g flag or -DANDROID_ARM_NEON without a subsequent strip step
                }
            }
        }
    }
}
```

### 4.2 Upload Debug Symbols Separately for Crash Reporting (the Correct Solution)

```bash
# Keep the unstripped symbols SEPARATE from the distributed APK
cp -r app/build/intermediates/merged_native_libs/release/out/lib ./symbols_backup/

# Upload to Play Console for automatic native crash deobfuscation
# (Play Console > App Bundle Explorer > Native Debug Symbols)
```

This is the correct pattern: symbols remain available for the **internal team** to analyze crash reports, but are **never distributed** to users inside the published APK/AAB.

### 4.3 Automated Verification in CI/CD

```bash
#!/bin/bash
# ci-check-native-symbols.sh
for so_file in $(find ./native_libs -name "*.so"); do
    if file "$so_file" | grep -q "not stripped"; then
        echo "[FAILED] $so_file is not stripped!"
        exit 1
    fi
done
echo "[OK] All native binaries are stripped."
```

### 4.4 Remediation Checklist

- [ ] Every `.so` binary across all ABI architectures is verified as stripped
- [ ] No DWARF section (`.debug_info`, `.debug_line`) is found
- [ ] The `packagingOptions.doNotStrip` configuration (if any) is limited to debug/internal builds only
- [ ] Debug symbols are uploaded separately to a crash reporting service, rather than left in the production APK
- [ ] CI/CD includes an automated gate to detect stripping regressions
- [ ] **Re-verification:** re-run MASTG-TEST-0288 on the final release APK for every release

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0288: Debugging Symbols in Native Binaries](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0288/)
- [MASTG-TEST-0263: Logging of StrictMode Violations](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0263/) — a fellow member of the MASWE-0061 group
- [MASWE-0061: Debug Artifacts Not Removed](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0061/)
- [MASTG-TECH-0140: Obtaining Debugging Information and Symbols](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0140/)

### 5.2 Official Android Documentation

- [Android Developers — Include Native Symbols in Your Release Build](https://developer.android.com/build/include-native-symbols)
- [Android Developers — Use of Native Code (Security Risks)](https://developer.android.com/privacy-and-security/risks/use-of-native-code)

### 5.3 Research and Community Discussions

- [Google Groups android-ndk — debug builds and strip --strip-unneeded](https://groups.google.com/g/android-ndk/c/pewNn32pDeE)
- [arXiv — A Risk Estimation Study of Native Code Vulnerabilities in Android Applications](https://arxiv.org/html/2406.02011v1)
- [Hex-Rays — Igor's Tip of the Week #55: Using Debug Symbols](https://hex-rays.com/blog/igors-tip-of-the-week-55-using-debug-symbols)
- [ACSAC 2020 — Punstrip: Function Name Recovery in Stripped Binaries](https://s2lab.cs.ucl.ac.uk/downloads/acsac20-punstrip.pdf)
- [Wikipedia — Strip (Unix)](https://en.wikipedia.org/wiki/Strip_(Unix))
- [CWE-215: Insertion of Sensitive Information Into Debugging Code](https://cwe.mitre.org/data/definitions/215.html)
- [CWE-540: Inclusion of Sensitive Information in Source Code](https://cwe.mitre.org/data/definitions/540.html)

### 5.4 Tool Documentation

- [radare2](https://github.com/radareorg/radare2)
- [rabin2 documentation](https://book.rada.re/tools/rabin2/symbols.html)
- [Binutils — objdump, nm, readelf](https://www.gnu.org/software/binutils/)
- [Ghidra](https://ghidra-sre.org/)
- [IDA Pro / FLIRT](https://hex-rays.com/ida-pro)

---

*This document was compiled based on OWASP MASTG (latest release as of September 2026), official Android Developers documentation, and academic research and NDK community discussions on symbol stripping and native binary reverse engineering. The most important nuance: unlike most other debug artifact tests in this research series, the Android NDK toolchain already performs automatic and aggressive debug symbol stripping by default — a FAIL condition usually originates from an explicit build configuration (`doNotStrip`) deliberately enabled for crash reporting needs but then left in the release, rather than passive negligence. A tester must also distinguish debug symbols (this test's evaluation target) from JNI dynamic symbols that must architecturally remain visible for the application's functionality.*
