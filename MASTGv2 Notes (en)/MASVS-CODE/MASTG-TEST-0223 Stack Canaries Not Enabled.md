# MASTG-TEST-0223 Stack Canaries Not Enabled

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0223 |
| **Platform** | Android |
| **MASVS Category** | **MASVS-CODE** (MASVS-CODE-4: The app validates build configuration and compile quality) |
| **Weakness** | **MASWE-0045** — *Compiler-Provided Security Features Not Used* |
| **Test Type** | **Static**, Code |
| **Profile** | **L2 only** |
| **Knowledge** | MASTG-KNOW-0006 (Binary Protection Mechanisms) |
| **Related Techniques** | MASTG-TECH-0157 (Extracting Bundled Native Libraries), MASTG-TECH-0115 (Obtaining Compiler-Provided Security Features) |
| **Related Demo** | — (MASTG does not yet provide a demo for this test) |
| **Sibling Test** | **MASTG-TEST-0222** (Position Independent Code Not Enabled) — same MASWE-0045, identical testing steps |
| **Related CWE** | CWE-121 (Stack-based Buffer Overflow), CWE-787 (Out-of-bounds Write), CWE-693 (Protection Mechanism Failure) |
| **Object Under Test** | `.so` files (NDK native libraries) inside `lib/<abi>/` in the APK — **not** Java/Kotlin code |

---

## 1. Explanation

### 1.1 Testing Objective

Direct quote from the MASTG overview:

> *"This test case checks if the native libraries of the app are compiled without common binary protection mechanisms, such as **stack smashing protection**, a mitigation technique against buffer overflow attacks."*
>
> *"NDK libraries should have stack canaries enabled since **the compiler does it by default**."*
>
> *"Other custom C/C++ libraries might not have stack canaries enabled because they **lack the necessary compiler flags** (`-fstack-protector-strong`, or `-fstack-protector-all`) or the canaries **were optimized out** by the compiler."*

This test is a **direct counterpart to MASTG-TEST-0222** — both test native `.so` binaries, using exactly identical tools and testing steps (MASTG-TECH-0157 + MASTG-TECH-0115), and sharing the MASWE-0045 weakness. The only difference is **which security feature is being checked**: PIC/PIE in TEST-0222, stack canaries here.

### 1.2 A Crucial Difference from MASTG-TEST-0222: No System Enforcement

This is the single most important point distinguishing these two sibling tests, and it explains why this test is **far more likely to produce real findings**.

| | MASTG-TEST-0222 (PIC/PIE) | MASTG-TEST-0223 (Stack Canary) *(this document)* |
|---|---|---|
| Enforced by the linker/OS? | **Yes** — since API 21, non-PIE `.so` files fail to load | **No** — the linker never refuses to load a `.so` lacking a canary |
| MASTG frontmatter status | `deprecated_since: 21` | No deprecated marker |
| Realistic likelihood of being found in 2026 | Very low (except for outdated SDKs) | **Significantly higher** — depends entirely on the developer's compile flags |
| Source of failure | Very outdated toolchain, deliberate override | Forgetting to set the flag; custom C/C++ code; compiler optimization |

The consequence: **stack canaries depend entirely on the developer's build-system discipline**, not on any platform-level guarantee. There is no Android mechanism that "rejects" a `.so` without a canary — the binary will still load and run normally, just without that layer of defense against stack buffer overflows. This is why this test has historically been more productive for mobile security testing than the PIC test.

### 1.3 Technical Foundation: How Stack Canaries Work

**Stack smashing protection** (also known as *StackGuard* — the name of the original implementation) is a mitigation against **stack-based buffer overflow** (CWE-121), one of the oldest and most widely exploited classes of memory-corruption vulnerability in software security history.

**How it works:**

1. **Function prologue** (start of function): the compiler inserts code that copies a secret value — called the **canary** — from a global/TLS variable into the stack frame, just **before** the return address and other important variables.
2. **Function epilogue** (end of function, before `return`): the compiler inserts code that **compares** the canary value on the stack with the original stored value.
3. **If both match** → the function returns control normally.
4. **If there is a mismatch** → this means something has **overwritten the memory between** the canary's location and the location of the variable that overflowed — a strong indication a buffer overflow attack is underway. The compiler calls **`__stack_chk_fail()`**, which forcibly terminates the process (usually via `abort()`) **before** the attacker-manipulated return address can be used.

**Why this effectively stops classic exploitation:** a conventional buffer overflow attack sequentially overwrites stack data to eventually overwrite the *return address* and redirect execution flow to attacker-controlled code (shellcode/ROP gadgets). Because the canary is placed **between** the vulnerable buffer and the *return address*, the attacker **must** overwrite the canary first to reach the return address. A change to the canary is detected in the epilogue before `return` executes — the attack fails before reaching its goal.

**Where the original canary value is stored:** the canary value (`__stack_chk_guard`) is typically stored in **Thread-Local Storage (TLS)** — on x86-64 Linux/Android architectures, it's accessed via the `fs` segment register at a specific offset (`fs:0x28`). Storing it in TLS (rather than as a regular global variable) makes the value harder for an attacker to guess/read, and safe to use across threads without race conditions.

### 1.4 Three Levels of Compile-Flag Coverage — This Determines Real-World Effectiveness

This is a technical nuance that often gets overlooked, even though it's crucial for assessing the quality of the mitigation, not merely its presence:

| Flag | Functions protected | Overhead | Coverage |
|---|---|---|---|
| **`-fstack-protector`** | Only functions declaring a character array ≥ 8 bytes on their stack | Very low (barely measurable) | **Very narrow** — only a small fraction of functions in a typical codebase |
| **`-fstack-protector-strong`** *(recommended by MASTG)* | All of the above **plus** functions with local arrays of any type/size (including within structs/unions), and functions that use the address of a local variable as an argument or on the right-hand side of an assignment | Low-to-moderate | **Broad** — research shows coverage increases dramatically (from ~2.8% of functions with the basic flag to ~20.5% of functions with `-strong` in a Linux kernel study) |
| **`-fstack-protector-all`** | **All functions without exception**, regardless of whether they're vulnerable | Significant — a real impact on performance & binary size | Maximum, but rarely used due to its performance cost |

MASTG explicitly names **`-fstack-protector-strong`** and **`-fstack-protector-all`** as the flags whose presence needs to be verified:

> *"Developers need to ensure that the flags `-fstack-protector-strong`, or `-fstack-protector-all` are set in the compiler flags for all native libraries."*

This means plain **`-fstack-protector`** (without `-strong`/`-all`) **technically enables canaries**, but its coverage is so narrow that MASTG does not consider it adequate as a recommended baseline.

### 1.5 False Positives Explicitly Acknowledged by MASTG — The Most Important Section of This Document

Unlike most other tests, MASTG gives a **very specific and explicit** warning for this test:

> *"When evaluating this please note that there are potential **expected false positives** for which the test case should be considered as passed. To be certain for these cases, they require **manual review of the original source code and the compilation flags used**."*

This is one of the few MASTG tests that explicitly instructs the tester **not** to report FAIL even when the tool shows `canary: false` — under certain conditions. Three documented categories of false positive:

**Category 1 — Use of a Memory-Safe Language (Flutter):**

> *"The Flutter framework does not use stack canaries because of the way [Dart mitigates buffer overflows]."*

Dart (the language behind Flutter) has memory management different from C/C++ and mitigates the class of buffer-overflow vulnerabilities through its own language design, rather than through a C-compiler-level stack canary. `libapp.so`, produced by Dart AOT compilation, **by design** does not use this mechanism — this is not an oversight, but an architectural property of that framework.

**Category 2 — Compiler Optimization Removes the Canary Even When the Flag Is Correct (React Native):**

> *"Sometimes, due to the size of the library and the optimizations applied by the compiler, it might be possible that the library was originally compiled with stack canaries but they were optimized out."*

MASTG gives a real-world example from the React Native ecosystem, with two sub-cases:

- **`.so` files that are effectively empty in the release build** — examples: `libruntimeexecutor.so`, `libreact_render_debug.so`. Even though built with `-fstack-protector-all`, no `stack_chk_fail` string appears because **there are no method calls at all** inside them in the release build.
- **Files containing code but no stack-buffer calls** — examples: `libreact_utils.so`, `libreact_config.so`, `libreact_debug.so`. These files are not empty and contain method calls, but those methods **don't contain a stack buffer call** that triggers the compiler to insert a canary — so no `stack_chk_fail` string appears in them, even though the `-fstack-protector-strong` flag is active for the entire project.

React Native developers have explicitly stated they will **not** add `-fstack-protector-all` for this case, arguing it would add a **performance cost with no effective security benefit** — because these functions genuinely have no buffer-overflow-prone code pattern to protect.

**Important methodological implication:** the absence of the `__stack_chk_fail` string in a binary **does not automatically prove** that the compile flag was not enabled. It could also mean "the flag is active, but there's no code requiring that protection to be inserted." **Static tools (rabin2/checksec) cannot distinguish between these two scenarios** — only manual review of the source code and build configuration can confirm which is the case.

### 1.6 Scope of the Object Under Test

Identical to MASTG-TEST-0222 (§1.5 in that document): focus on **native libraries (`.so`)**, since Java/Kotlin code runs on ART, which is already memory-safe for this class of vulnerability. Check **every ABI** (`arm64-v8a`, `armeabi-v7a`, `x86_64`, `x86`) and distinguish the app's own `.so` files from those bundled as third-party dependencies (React Native core libraries, the Flutter engine, SQLCipher, image-processing libraries, etc.).

---

## 2. Tools Used for Testing

Since this test uses MASTG-TECH-0157 and MASTG-TECH-0115, which are **exactly identical** to MASTG-TEST-0222, all the tools below are the same — the only difference is which output column (`canary` instead of `pic`) is being checked.

### 2.1 Required (Core) Tools

| Tool | MASTG ID | Function |
|---|---|---|
| **rabin2** (radare2) | MASTG-TOOL-0129 | **MASTG's official tool** for reading compiler-provided security features, including stack canaries |
| **unzip / apktool** | MASTG-TOOL-0011 | Extracting `.so` files from the APK (MASTG-TECH-0157) |

### 2.2 Alternative & Supporting Tools

| Tool | Function |
|---|---|
| **checksec / checksec.py** | Detects canaries via the `__stack_chk_fail` signature — concise output covering PIE+canary+RELRO+NX at once |
| **readelf / nm / strings** | Manually search for the `__stack_chk_fail`/`__stack_chk_guard` strings in the symbol table — useful for cross-verification |
| **objdump** | Disassembly to verify **with certainty** whether canary-read/compare instructions are genuinely present in a given function's prologue/epilogue (§1.5 Category 2) |
| **LIEF** | Python scripting for bulk audits, can programmatically check for the presence of the `__stack_chk_fail` symbol |
| **MobSF** | Automated `.so` analysis, reports stack canary status in the APK report |
| **Ghidra / IDA Pro** | **Required for Category 2 false-positive cases** — visually verifying whether a function genuinely has a stack buffer requiring protection, or is simply not relevant |
| **APKiD** | Framework identification (Flutter/React Native/Xamarin) — the first step in determining whether Category 1/2 false positives are relevant |

### 2.3 Environment Prerequisites

- **No device and no root needed** — just the APK is enough. Fully automatable in CI/CD.
- **Identify the framework in use first.** This is the first step that determines the entire analysis flow: whether the app uses Flutter (`libapp.so`, `libflutter.so`), React Native (`libreactnativejni.so`, `libhermes.so`), Xamarin/.NET MAUI, or pure native (Java/Kotlin + custom NDK). Use APKiD or check for the `assets/flutter_assets/`, `assets/index.android.bundle` structure as markers.
- **Have access to source code where possible** (for first-party/white-box testing) — this is the only way to definitively confirm Category 2 false positives, per MASTG's own instruction to *"require manual review of the original source code and the compilation flags used."*
- **Extract every ABI** present in `lib/`.

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0157** (*Extracting Bundled Native Libraries*) to extract native libraries from the application package.
2. Use **MASTG-TECH-0115** (*Obtaining Compiler-Provided Security Features*) on each native library to obtain the compiler-provided security features.

### 3.2 Method A — rabin2 *(official MASTG method)*

```bash
# Step 1: extract (identical to MASTG-TEST-0222)
unzip -o YourApp.apk "lib/*" -d YourApp
find YourApp/lib -name "*.so"

# Step 2: check the canary feature
rabin2 -I YourApp/lib/arm64-v8a/libnative-lib.so | grep -E "canary|pic"
```

Example **UNSAFE** output (matching the official MASTG-TECH-0115 example):

```
canary   false
```

Example **SAFE** output:

```
canary   true
```

**To check ALL `.so` files and ALL ABIs at once:**

```bash
for so in $(find YourApp/lib -name "*.so"); do
  echo "=== $so ==="
  rabin2 -I "$so" | grep -E "^canary"
done
```

### 3.3 Method B — Manual verification via symbol table *(required to validate false positives)*

This method **directly addresses** the false-positive warning from MASTG in §1.5.

```bash
# Explicitly look for the __stack_chk_fail / __stack_chk_guard symbol
nm -D YourApp/lib/arm64-v8a/libnative-lib.so 2>/dev/null | grep stack_chk
readelf --dyn-syms YourApp/lib/arm64-v8a/libnative-lib.so | grep stack_chk

# Look for canary-related strings in the binary (works even if stripped)
strings YourApp/lib/arm64-v8a/libnative-lib.so | grep -i stack_chk

# CRUCIAL STEP: check whether the .so is empty / contains very few symbols
# (relevant to the React Native case — "empty" files don't need a canary)
nm -D YourApp/lib/arm64-v8a/libreact_utils.so 2>/dev/null | wc -l
readelf -S YourApp/lib/arm64-v8a/libreact_utils.so | grep -E "\.text|\.symtab"

# Check the .text section size — a very small .so likely has minimal/no vulnerable functions
readelf -S YourApp/lib/arm64-v8a/libreact_utils.so | grep "\.text"
```

> **How to interpret the results:** if `strings` **and** `nm`/`readelf` both fail to find `stack_chk_fail`, **AND** the file turns out to be empty/has minimal `.text` (Category 2 in §1.5), this is a strong indicator of a false positive — not a configuration failure. If the file is substantial in size with many complex C/C++ functions yet still has no `stack_chk_fail` whatsoever, this **is a legitimate finding**.

### 3.4 Method C — checksec.py *(a single command for canary + PIE + RELRO + NX)*

```bash
pip install checksec.py
checksec --file=YourApp/lib/arm64-v8a/libnative-lib.so
```

```
RELRO           STACK CANARY       NX            PIE             FILE
Full RELRO      No canary found    NX enabled    PIE enabled     libnative-lib.so
```

For bulk audits:

```bash
checksec --dir=YourApp/lib --output=json > checksec-report.json
jq '.[] | select(.["binary-type"] == "ELF") | {file: .file, canary: .["stack-canary"]}' checksec-report.json
```

### 3.5 Method D — Framework identification with APKiD *(mandatory triage step before judging FAIL)*

```bash
apkid YourApp.apk
```

```
[!] YourApp.apk!classes.dex
    compiler : dexlib 2.x
[+] YourApp.apk!lib/arm64-v8a/libflutter.so
    manipulator : Flutter engine detected
```

If the app is identified as **Flutter** or **React Native**, proceed to §3.6/§3.7 before concluding FAIL on that framework's `.so` files.

### 3.6 Method E — Validating the Flutter false positive

```bash
# Identify .so files belonging to the Flutter engine
find YourApp/lib -iname "libapp.so" -o -iname "libflutter.so"

# This DELIBERATELY does not use stack canaries — Dart mitigates
# buffer overflows via its own mechanism, not via the C compiler
rabin2 -I YourApp/lib/arm64-v8a/libapp.so | grep canary
# canary   false   <-- THIS IS NOT AUTOMATICALLY A FINDING, see §1.5 Category 1
```

Official reference: [Flutter — Security false positives](https://docs.flutter.dev/reference/security-false-positives#shared-objects-should-use-stack-canary-values) explicitly states this is *expected behavior*, not a vulnerability.

### 3.7 Method F — Validating the React Native false positive (deep analysis with Ghidra)

```bash
# 1. Identify .so files belonging to the React Native core
find YourApp/lib -iname "libreact*.so" -o -iname "libruntimeexecutor.so" -o -iname "libhermes.so"

# 2. Check whether the file is "empty" (Category 2a)
for so in $(find YourApp/lib -iname "libreact*.so"); do
  size=$(stat -c%s "$so" 2>/dev/null || stat -f%z "$so")
  funcs=$(nm -D "$so" 2>/dev/null | grep " T " | wc -l)
  echo "$so: ${size} bytes, ${funcs} exported functions"
done

# 3. For files that are NOT empty but still lack stack_chk_fail (Category 2b),
#    verify with Ghidra whether their functions genuinely lack a
#    risky local stack buffer
ghidra_headless ./project ./YourApp/lib/arm64-v8a/libreact_utils.so \
  -import -analyze -postScript CheckStackCanaryUsage.java
```

If the Ghidra results show that the functions indeed do not declare any risky local array/buffer, this is consistent with the React Native team's official explanation in [GitHub issue #36870](https://github.com/react/react-native/issues/36870#issuecomment-1714007068) — **PASS with a note**, not FAIL.

### 3.8 Method G — LIEF *(programmatic bulk audit, distinguishing empty files from non-empty ones)*

```python
# check_canary.py
import lief
import glob

for so_path in glob.glob("YourApp/lib/**/*.so", recursive=True):
    binary = lief.parse(so_path)
    if binary is None:
        continue
    symbols = [s.name for s in binary.dynamic_symbols]
    has_canary = "__stack_chk_fail" in symbols
    text_section = next((s for s in binary.sections if s.name == ".text"), None)
    text_size = text_section.size if text_section else 0

    flag = ""
    if not has_canary and text_size < 200:
        flag = "  [LIKELY FALSE POSITIVE - .text is very small]"
    elif not has_canary:
        flag = "  [!! NEEDS MANUAL REVIEW !!]"

    print(f"{so_path}: canary={has_canary}, .text={text_size}B{flag}")
```

```bash
pip install lief
python3 check_canary.py
```

### 3.9 Method H — MobSF

```bash
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest
```

Upload the APK → the **Binary Analysis** / **Shared Object Analysis** section shows the `STACK CANARY` status per `.so`. Note that MobSF does **not** automatically apply the Flutter/React Native false-positive exceptions — the raw results still need manual review per §1.5.

### 3.10 Method Comparison: When to Use Which

| Method | Tool | Detects canary? | Distinguishes false positives? | Suitable for CI/CD? | When to use |
|---|---|---|---|---|---|
| **A** | rabin2 (MASTG) | ✅ | ❌ | Moderate | **Official baseline** — quick detection |
| **B** | nm/readelf/strings manual | ✅ (more detail) | Partial (via `.text` size) | Low | Initial indicator verification of false positives |
| **C** | checksec.py | ✅ | ❌ | ✅ | Quick summary + covers TEST-0222 at once |
| **D** | APKiD | — (framework identification) | ✅ **(mandatory step)** | ✅ | **First triage** before judging FAIL |
| **E** | Flutter validation | ✅ | ✅ **(definitive for Flutter)** | Moderate | `.so` identified as the Flutter engine |
| **F** | Ghidra (React Native) | ✅ | ✅ **(most definitive)** | Low | React Native `.so` without a canary, significant size |
| **G** | LIEF | ✅ | Partial (size heuristic) | ✅ **(best for gating)** | Automated bulk audit with initial false-positive flagging |
| **H** | MobSF | ✅ | ❌ | Moderate | Comprehensive, ready-to-cite report |

**Minimum recommended combination:** **D (APKiD) → A/C (rabin2/checksec) → B (manual verification for every FAIL)**.
D determines whether the app uses a framework with known false positives; A/C gives quick results; every remaining `canary: false` **must** be verified with Method B before being reported as a finding — this is how to carry out MASTG's explicit instruction for "manual review of source code and compilation flags." Use **F (Ghidra)** for ambiguous React Native cases, and **G (LIEF)** as a CI gate with initial heuristics.

---

### 3.11 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rule:**

> **Observation:** *"The output should show all the security features enabled for each native library, including stack canaries."*
>
> **Evaluation:** *"The test case **fails** if stack canaries are disabled."*
>
> *"When evaluating this please note that there are potential **expected false positives** for which the test case should be considered as **passed**."*

Unlike MASTG-TEST-0222, the criteria here are **explicitly not as simple as they look** — the false-positive clause is an integral part of the evaluation, not an optional addendum.

---

#### ❌ FAIL / ISSUE — The check is declared FAILED when:

| No | Condition | Example evidence |
|---|---|---|
| F1 | A `.so` **not** belonging to Flutter/React Native (or another memory-safe framework) shows `canary: false` | `rabin2 -I libcustom_crypto.so` → `canary false`, and the file has many complex C/C++ functions |
| F2 | A custom C/C++ library owned by the app is compiled without `-fstack-protector-strong`/`-all` | Verification of the build script/`CMakeLists.txt` confirms the flag's absence |
| F3 | A React Native `.so` that is **substantial in size** and has stack buffer calls, but has no `stack_chk_fail` | Confirmed via Ghidra (§3.7) — not a case of being "empty" or "without local buffers" |
| F4 | A third-party `.so` (a non-Flutter/RN SDK) compiled with an old toolchain without hardening | An outdated SDK, not part of a framework with an official exception |
| F5 | Only some ABIs lack a canary while others have it | Build script inconsistent across architectures |
| F6 | Only plain `-fstack-protector` (without `-strong`/`-all`) is used for code handling sensitive data | Protection coverage too narrow (§1.4) — even though the tool technically reports `canary: true`, a MASTG-TECH-0023-style review shows critical functions are not covered |

> Note that F6 requires deeper analysis than a simple binary `canary: true`/`false` reading — tools like `rabin2` generally only report the **presence** of the canary mechanism in the binary, not the **coverage** of which flag was used. To distinguish plain `-fstack-protector` from `-strong`/`-all`, the build configuration must be reviewed directly.

**Example evidence (illustrative — MASTG does not yet provide an official demo for this test):**

```bash
$ apkid YourApp.apk | grep -A2 "libcustom_crypto"
[+] lib/arm64-v8a/libcustom_crypto.so
    (not identified as part of a known framework)

$ rabin2 -I YourApp/lib/arm64-v8a/libcustom_crypto.so | grep canary
canary   false

$ nm -D YourApp/lib/arm64-v8a/libcustom_crypto.so | grep stack_chk
# (no results - genuinely absent)

$ readelf -S YourApp/lib/arm64-v8a/libcustom_crypto.so | grep "\.text"
  [13] .text  PROGBITS  0000000000012000  00012000  0000000000045000  ...
# .text is 0x45000 (~280KB) in size - a SUBSTANTIAL library with many functions
```

Interpretation: a custom crypto library (not part of Flutter/RN), of significant size, with no trace of `stack_chk_fail` at all → a legitimate **FAIL**, not a false positive.

---

#### ✅ PASS — The check is declared PASSED when:

| No | Condition | Example evidence |
|---|---|---|
| P1 | All non-framework `.so` files show `canary: true` with `-strong`/`-all` coverage confirmed | `canary true` + build script shows `-fstack-protector-strong` |
| P2 | A `.so` identified as the **Flutter engine** (`libapp.so`, `libflutter.so`) lacks a canary | **PASS by design** — Dart mitigates buffer overflow via a language-level mechanism |
| P3 | A React Native `.so` that is **empty/minimal** in the release build lacks a canary | `libruntimeexecutor.so` with `.text` close to zero, no method calls |
| P4 | A React Native `.so` containing code but **without a stack-buffer call** | Confirmed via Ghidra: functions don't declare any risky local array/buffer, consistent with the React Native team's official explanation |
| P5 | The library is compiled via a standard NDK toolchain without flag modifications that remove protection | Clean build config, no `-fno-stack-protector` |

**Example output indicating PASS (Flutter case — not a false alarm):**

```bash
$ apkid YourApp.apk
[+] lib/arm64-v8a/libapp.so
    manipulator : Dart AOT snapshot (Flutter)

$ rabin2 -I YourApp/lib/arm64-v8a/libapp.so | grep canary
canary   false

# THIS IS NOT A FINDING — per https://docs.flutter.dev/reference/security-false-positives
# Dart mitigates buffer overflow through language-level memory safety, not a C stack canary.
```

**Example output indicating PASS (React Native "empty" case — not a false alarm):**

```bash
$ python3 check_canary.py
YourApp/lib/arm64-v8a/libreact_render_debug.so: canary=False, .text=48B  [LIKELY FALSE POSITIVE - .text is very small]
YourApp/lib/arm64-v8a/libnative-lib.so: canary=True, .text=182340B
```

Further verification of `libreact_render_debug.so` confirms the file genuinely has no method calls in the release build — consistent with §1.5 Category 2a. **PASS with documentation note.**

---

#### ⚠️ Important Notes on Evaluation

1. **This is a test where "tool output = FAIL" is most often WRONG without further verification.** Unlike most other static tests, MASTG explicitly warns that raw tool output (`canary: false`) **must not** be directly reported as a finding without manual review of the source code and compilation flags. Reporting the raw rabin2 output as-is carries a high risk of producing a false positive that developers can easily (and legitimately) refute using official Flutter/React Native documentation.

2. **Always identify the framework FIRST (Method D) before judging anything.** The correct order of work is: (1) identify whether the `.so` originates from Flutter/React Native/another framework with known exceptions, (2) only then run the canary check, (3) for non-framework `.so` files that FAIL, verify further with Method B/F.

3. **`.text` size and symbol count are useful initial signals, but not definitive proof.** A very small file (`.text` < ~200 bytes) or one with no exported functions is likely a Category 2a false positive. However, for certainty, follow MASTG's instructions: review the source code or use Ghidra to directly verify the function structure.

4. **The list of false-positive examples in the MASTG overview (`libruntimeexecutor.so`, `libreact_render_debug.so`, etc.) can change between React Native versions.** Don't blindly blacklist file names as "always PASS" — the name and behavior of `.so` files can change between framework releases. Re-verify the actual conditions (size, symbols) every time you test a new app version.

5. **Distinguish flag levels, not just their presence (§1.4).** `rabin2`/`checksec` generally report a binary fact: canary present or not. They **do not distinguish** plain `-fstack-protector` (narrow coverage) from `-fstack-protector-strong`/`-all` (broad coverage). For white-box testing with source-code access, check `CMakeLists.txt`/`Android.mk`/`build.gradle` directly to confirm the flag used matches MASTG's recommendation.

6. **Frameworks other than Flutter/React Native may also have legitimate reasons not to use canaries** — for example, a library written purely in Rust (which has its own memory-safety guarantees) but linked as a `.so` inside an Android APK. Apply the same principle: identify the source language/toolchain before concluding FAIL.

7. **Empty output (no `.so` files at all) means a purely Java/Kotlin app — this test is automatically PASS/Not Applicable**, since there is no object under test. This is not a testing failure, but a scope that simply doesn't apply to that app.

8. **Severity is modulated as follows:**

   | Factor | Severity |
   |---|---|
   | A non-framework `.so` processing sensitive data/parsing external input without a canary | **High** — the CWE-121/CWE-787 vulnerability class is easier to exploit |
   | A non-critical non-framework `.so` without a canary | **Medium** |
   | Only plain `-fstack-protector` is used (not `-strong`) on code handling external data parsing | **Medium** — protection coverage inadequate for risky functions |
   | "Empty" Flutter/React Native `.so` without a canary | **Not a finding** (documented false positive) |
   | All non-framework `.so` files have canaries with `-strong`/`-all` coverage | **Not a finding** |

9. **Explicitly document the false-positive status.** For every `.so` showing `canary: false` but judged PASS, record the **specific reason** (Flutter by design / RN empty file / RN without stack-buffer call / another memory-safe language) along with supporting evidence (`.text` size, Ghidra results, or a reference to the framework's official documentation). This is important so audit results can be reproduced and don't appear to readers as "passed without justification."

---

## 4. Recommendations

### 4.1 Main Principles

**Priority 1 — Ensure adequate stack-protector flags for custom C/C++ code.**

```cmake
# CMakeLists.txt
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fstack-protector-strong")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fstack-protector-strong")
```

```makefile
# Android.mk (if still using ndk-build)
LOCAL_CFLAGS += -fstack-protector-strong
LOCAL_CPPFLAGS += -fstack-protector-strong
```

Use **`-fstack-protector-strong`** as the baseline (not plain `-fstack-protector`) — MASTG and most modern hardening guides (including the Linux kernel) recommend this level as the best balance between security coverage and performance cost.

**Priority 2 — Don't manually disable this protection.**

```cmake
# ❌ WRONG — never add this without a strong justification
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-stack-protector")
```

**Priority 3 — Use a current NDK toolchain.** Modern Clang-based NDKs usually already enable `-fstack-protector-strong` by default for release builds — problems generally come from very old toolchains or explicit overrides.

**Priority 4 — For framework developers (Flutter/React Native), explicitly document exceptions in internal security policy.** If your team builds/maintains native libraries for such frameworks, follow the pattern already validated by the React Native team: don't add protection that provides no real security benefit purely to "pass a scanner," but **document** the technical reason openly so external auditors (and internal security teams) can verify the claim without ambiguity — as Flutter and React Native do in their public documentation.

**Priority 5 — Audit third-party non-framework SDKs.** If a third-party crypto/parsing/image-processing library (not part of Flutter/RN) is found without a canary, this is purely that vendor's responsibility — request a rebuild with the appropriate flags, or evaluate a replacement.

**Priority 6 — Re-verify at every release, with awareness of false positives.** Integrate Method G (LIEF) into CI/CD, but **do not** make it fail automatically for `.so` files already known and documented as false positives — use an explicit allowlist for those files (with linked justification) so the gate doesn't produce repeated noise.

```python
# Example CI allowlist
KNOWN_FALSE_POSITIVES = {
    "libapp.so": "Flutter Dart AOT - memory safety by language design",
    "libflutter.so": "Flutter engine - same as above",
    "libruntimeexecutor.so": "React Native - empty in release build",
    "libreact_render_debug.so": "React Native - empty in release build",
}
```

**Priority 7 — Apply comprehensive hardening, not just canaries.** In line with MASTG-TEST-0222 and MASTG-KNOW-0006, canaries are most effective combined with PIE, RELRO, NX, and `_FORTIFY_SOURCE`:

```cmake
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fstack-protector-strong -D_FORTIFY_SOURCE=2")
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,-z,relro,-z,now -Wl,-z,noexecstack")
```

### 4.2 Remediation Checklist

- [ ] The framework used by the app has been identified (Flutter/React Native/pure native/other) as the first step
- [ ] Every `.so` with `canary: false` has been verified: documented false positive, or legitimate finding
- [ ] For legitimate findings: custom C/C++ code is compiled with `-fstack-protector-strong` (not just plain `-fstack-protector`)
- [ ] No `-fno-stack-protector` present in the build configuration
- [ ] The NDK toolchain used is a current version
- [ ] Every false-positive exception is explicitly documented with evidence (`.text` size, Ghidra results, or an official framework reference)
- [ ] Third-party non-framework libraries lacking a canary have been confirmed with the vendor or replaced
- [ ] All ABIs (`arm64-v8a`, `armeabi-v7a`, `x86_64`, `x86`) verified as consistent
- [ ] A documented false-positive allowlist is integrated into the CI/CD gate to avoid repeated noise
- [ ] Comprehensive hardening is applied (canary + PIE + RELRO + NX + FORTIFY_SOURCE)
- [ ] **Re-verify:** re-run MASTG-TEST-0223 after every change to native dependencies
- [ ] **Cross-verify:** run MASTG-TEST-0222 (PIC/PIE) — identical tool and steps, report as a separate finding

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0223: Stack Canaries Not Enabled](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0223/)
- [MASTG-TEST-0222: Position Independent Code (PIC) Not Enabled](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0222/)
- [MASWE-0045: Compiler-Provided Security Features Not Used](https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-0045/)
- [MASTG-KNOW-0006: Binary Protection Mechanisms](https://mas.owasp.org/MASTG/knowledge/android/MASVS-CODE/MASTG-KNOW-0006/)
- [MASTG-TECH-0157: Extracting Bundled Native Libraries](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0157/)
- [MASTG-TECH-0115: Obtaining Compiler-Provided Security Features](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0115/)
- [MASTG — Testing Code Quality (Binary Protection Mechanisms, Stack Smashing Protection)](https://mas.owasp.org/MASTG/0x04h-Testing-Code-Quality/)
- [MASTG-TOOL-0129: radare2 (rabin2)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0129/)
- [MASVS-CODE: Code Quality](https://mas.owasp.org/MASVS/08-MASVS-CODE/)
- [OWASP Mobile Top 10 2024 — M7: Insufficient Binary Protections](https://owasp.org/www-project-mobile-top-10/2023-risks/m7-insufficient-binary-protections.html)

### 5.2 Framework Documentation (Official False-Positive Source)

- [Flutter — Security false positives (Shared objects should use stack canary values)](https://docs.flutter.dev/reference/security-false-positives#shared-objects-should-use-stack-canary-values)
- [React Native GitHub Issue #36870 — Stack canary discussion](https://github.com/react/react-native/issues/36870#issuecomment-1714007068)
- [OWASP MASTG PR #3049 — React Native stack protector discussion](https://github.com/OWASP/mastg/pull/3049#pullrequestreview-2420837259)

### 5.3 Official Android / Google / AOSP Documentation

- [NDK Build System Maintainers Guide — Additional Required Arguments](https://android.googlesource.com/platform/ndk/+/master/docs/BuildSystemMaintainers.md#additional-required-arguments)
- [Android — Use of native code (security risks)](https://developer.android.com/privacy-and-security/risks/use-of-native-code)
- [Android NDK — Application Binary Interfaces (ABI)](https://developer.android.com/ndk/guides/abis)

### 5.4 Technical Research on Stack Canaries

- [Red Hat — Security Technologies: Stack Smashing Protection (StackGuard)](https://www.redhat.com/en/blog/security-technologies-stack-smashing-protection-stackguard)
- [Red Hat Developer — Use compiler flags for stack protection in GCC and Clang](https://developers.redhat.com/articles/2022/06/02/use-compiler-flags-stack-protection-gcc-and-clang)
- [LWN.net — "Strong" stack protection for GCC](https://lwn.net/Articles/584225/)
- [outflux.net — -fstack-protector-strong explained (Kees Cook)](https://outflux.net/blog/archives/2014/01/27/fstack-protector-strong/)
- [ARM Developer — -fstack-protector, -fstack-protector-all, -fstack-protector-strong, -fno-stack-protector](https://developer.arm.com/documentation/dui0774/latest/Compiler-Command-line-Options/-fstack-protector---fstack-protector-all---fstack-protector-strong---fno-stack-protector)
- [HackTricks — Stack Canaries](https://hacktricks.wiki/en/binary-exploitation/common-binary-protections-and-bypasses/stack-canaries/index.html)
- [CTF Wiki EN — Canary](https://ctf-wiki.mahaloz.re/pwn/linux/mitigation/canary/)
- [Phrack #67 — StackGuard internals](http://phrack.org/archives/issues/67/13.txt)
- [Zatoichi Engineer — Stack Smashing Protection and Its Performance Impact](https://zatoichi-engineer.github.io/2017/10/04/stack-smashing-protection.html)
- [arXiv — Is the Canary Dead? On the Effectiveness of Stack Canaries](https://cactilab.github.io/assets/pdf/canary2024xi.pdf)

### 5.5 Standards & Taxonomies

- [CWE-121: Stack-based Buffer Overflow](https://cwe.mitre.org/data/definitions/121.html)
- [CWE-787: Out-of-bounds Write](https://cwe.mitre.org/data/definitions/787.html)
- [CWE-693: Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html)
- [NIST SP 800-163 Rev.1 — Vetting the Security of Mobile Applications](https://csrc.nist.gov/publications/detail/sp/800-163/rev-1/final)

### 5.6 Tool Documentation

- [radare2 — rabin2 documentation](https://book.rada.re/tools/rabin2/headers.html)
- [checksec.py — PyPI](https://pypi.org/project/checksec.py/)
- [LIEF — Library to Instrument Executable Formats](https://github.com/lief-project/LIEF)
- [MobSF — Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)
- [APKiD — Android Application Identifier](https://github.com/rednaga/APKiD)
- [Ghidra — software reverse engineering framework](https://ghidra-sre.org/)
- [GNU Binutils — nm / readelf / objdump](https://www.gnu.org/software/binutils/)

---

*This document was compiled based on OWASP MASTG (latest release as of September 2026), official Flutter and React Native documentation (the primary source of false positives), AOSP/NDK documentation, and technical research on stack smashing protection mechanisms. This test does not yet have an official demo (MASTG-DEMO) from MASTG.*
