# MASTG-TEST-0222 Position Independent Code (PIC) Not Enabled

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0222 |
| **Platform** | Android |
| **MASVS Category** | **MASVS-CODE** (MASVS-CODE-4: The app validates build configuration and compile quality) |
| **Weakness** | **MASWE-0045** — *Compiler-Provided Security Features Not Used* |
| **Test Type** | **Static**, Code |
| **Profile** | **L2 only** |
| **⚠️ Special Status** | **`deprecated_since: 21`** — see §1.2, this changes how this test should be read |
| **Knowledge** | MASTG-KNOW-0006 (Binary Protection Mechanisms) |
| **Related Techniques** | MASTG-TECH-0157 (Extracting Bundled Native Libraries), MASTG-TECH-0115 (Obtaining Compiler-Provided Security Features) |
| **Related Demo** | — (MASTG does not yet provide a demo for this test) |
| **Sibling Test** | MASTG-TEST-0223 (Stack Canaries Not Enabled) — same MASWE-0045, identical steps |
| **Related CWE** | CWE-1259 (Improper Restriction of Security Token Assignment), CWE-121 (Stack-based Buffer Overflow), CWE-787 (Out-of-bounds Write), CWE-1173 (Improper Use of Validation Framework) — more precisely mapped via **CWE-119** (memory buffer boundary) as the exploitation context PIE mitigates |
| **Object Under Test** | `.so` files (NDK native libraries) inside `lib/<abi>/` in the APK — **not** Java/Kotlin code |

---

## 1. Explanation

### 1.1 Testing Objective

Direct quote from the MASTG overview:

> *"This test case checks if the native libraries of the app are compiled without enabling **Position Independent Code (PIC)**, a common mitigation technique against memory corruption attacks."*
>
> *"Since Android 5.0 (API level 21), Android **requires all dynamically linked executables to support PIE**."*
>
> *"Android requires Position-independent executables beginning with API 21. **Clang builds PIE executables by default.** If invoking the linker directly or not using Clang, use `-pie` when linking."*

This test is purely about **native binaries** — `.so` files compiled from C/C++ code via the Android NDK, or third-party libraries bundled in pre-compiled form. This is **not** about Java/Kotlin code (which runs on ART/Dalvik and is already safe from this class of vulnerability by design).

### 1.2 Critical Note: The `deprecated_since: 21` Frontmatter

This is the first thing you need to understand before running this test, and it is **not explicitly explained** in the overview text — it only appears in the metadata frontmatter of the MASTG source file.

The value `deprecated_since: 21` indicates that this test is **effectively obsolete since API level 21**, because:

> *"With Android 5.0 (API level 21), support for **non-PIE enabled native libraries was dropped**, and since then, **PIE is enforced by the linker**."* — MASTG-KNOW-0006

The practical consequences are very important for how you should read the results of this test:

- **Since API 21, the Android dynamic linker (`linker`/`linker64`) refuses to load `.so` files that aren't PIE.** This isn't merely a compiler recommendation — it is **enforcement at the operating system level**. The source code lives in `bionic/linker/linker_main.cpp` (referenced by MASTG-KNOW-0006).
- **Nearly all Android apps released today target `minSdkVersion` ≥ 21** (Google Play itself requires a much higher `targetSdkVersion`). This means a non-PIE native library **will never successfully load** on modern devices — the app will crash at startup rather than silently running with weakened mitigations.
- **Clang (the NDK's default compiler) has produced PIE binaries by default for a long time.** To produce a non-PIE `.so` today, a developer must **actively and deliberately** add the `-no-pie` flag or use a very outdated toolchain — something that almost never happens accidentally.

**How this changes the way findings should be assessed:**

| Scenario | Realistic likelihood | Implication |
|---|---|---|
| Modern app with `minSdkVersion` ≥ 21 using a standard NDK toolchain | **Almost certainly PASS** without needing deep investigation | This test becomes a quick *sanity check*, not a primary investigation area |
| App with `minSdkVersion` < 21 (very rare in 2026) | Potentially FAIL if it genuinely targets old devices | Check whether the developer truly supports Android < 5.0 |
| Bundled third-party `.so` (closed-source SDK, legacy library) | Low but **non-zero** likelihood — an old SDK recompiled without updating the toolchain | **The most realistic investigation target** for this test |
| Binary manually loaded via `dlopen()` outside the system linker (rare) | Could be non-PIE without triggering linker enforcement | A rare edge case seldom found in consumer apps |

**Practical conclusion:** don't expect to find many non-PIE native libraries in modern apps. In 2026 the value of this test lies more in **compliance/hygiene auditing** and as a **safety net for outdated third-party libraries**, rather than as a statistically frequent source of findings in new apps. Still report results honestly — but calibrate your team's expectations and allocated effort to this reality.

### 1.3 Technical Foundation: What PIC/PIE Is and Why It Matters

**Position Independent Code (PIC)** is machine code that can execute correctly **at any memory address**, without needing modification (it doesn't use hardcoded absolute addresses, but relative references instead). A **Position Independent Executable (PIE)** is an executable (or shared library) whose entirety is compiled as PIC, so that **the whole binary image** — not just certain parts — can be loaded at any address.

Its relationship to **ASLR (Address Space Layout Randomization)** is the key point:

- **ASLR** is an OS-level mitigation that randomizes the memory locations of the stack, heap, and shared libraries each time a process runs.
- **Without PIE, the base address of the executable binary itself remains fixed**, even when ASLR is active for other components. This opens a real gap: an attacker exploiting a memory corruption vulnerability (buffer overflow, etc.) can **reliably compute gadget addresses** from the binary's non-randomized `.text`, `.plt`, and `.got` segments — enabling **Return-Oriented Programming (ROP)** attacks and **ret2plt** techniques to fully bypass ASLR.
- **With PIE, the entire binary (including its dependencies) loads at a random address on every execution** — complementing ASLR so attackers no longer have a fixed address "anchor" to reliably build a ROP chain.

Academic research confirms this directly: binaries compiled without the PIE option **remain vulnerable even with ASLR fully active**, because an attacker can leverage the `.text`/`.plt`/`.got` segments within the executable itself. Adding PIE causes such exploitation to fail, because every execution loads the binary and all its dependencies at a randomized virtual memory location.

**Mitigation summary:**

| Without PIE | With PIE |
|---|---|
| Binary base address **remains fixed** even with ASLR active | Binary base address **is also randomized** |
| ROP gadgets can be computed from a fixed address | Gadget addresses change on every execution — ROP is far harder to build reliably |
| ret2plt/ret2libc attacks against `.plt`/`.got` are feasible | The same attacks become impractical without an additional address leak (info leak) |

### 1.4 Position Within the Set of Binary Protection Mechanisms

MASTG-KNOW-0006 lists several binary protection mechanisms for Android native libraries, and PIC/PIE is just one of them:

| Mechanism | Related MASTG Test | Status on Android |
|---|---|---|
| **PIC/PIE** | **MASTG-TEST-0222** *(this document)* | Enforced by the linker since API 21 |
| **Stack Smashing Protection (canary)** | MASTG-TEST-0223 (identical steps, same tool) | **Not** enforced by the system — depends on compile flags (`-fstack-protector-strong`) |
| **Memory management** | — (no specific static test; relevant for manual C/C++ code review) | Manual — developer is fully responsible, no garbage collection in native code |

Note the important asymmetry: **PIE is enforced by the operating system**, while **stack canaries are not**. This is why MASTG-TEST-0223 (a direct sibling test, with identical testing steps) is much more likely to produce real findings — the linker never refuses to load a `.so` lacking a canary, only the absence of PIE is strictly enforced. Run both tests together, since they use exactly the same tools and workflow (MASTG-TECH-0157 + MASTG-TECH-0115).

### 1.5 Scope of the Object Under Test

MASTG-KNOW-0006 explains why the focus is only on native libraries:

> *"In general all binaries should be tested... However, on Android we will focus on **native libraries** since the **main executables are considered safe**."*

This is because:
- Java/Kotlin application code compiles to Dalvik bytecode and executes via ART — considered **memory-safe** for the class of buffer-overflow vulnerabilities that PIE/canary mitigate.
- What needs testing is the **`.so` files inside `lib/<abi>/`** — both those compiled in-house via the NDK, and those **bundled as third-party dependencies** (analytics SDKs, image processing, native crypto, game engines, etc.).

**Architectures (ABIs) typically present in a single APK:**

| ABI | Target |
|---|---|
| `arm64-v8a` | Modern 64-bit ARM devices (the majority of current devices) |
| `armeabi-v7a` | Older 32-bit ARM devices |
| `x86_64` | 64-bit x86 emulators/devices |
| `x86` | Older 32-bit x86 emulators/devices |

**Important:** check **every ABI**, not just one. Sometimes only a single architecture slips through without hardening (e.g. a custom build script that differs for an older `armeabi-v7a` build), while `arm64-v8a` is already correct.

---

## 2. Tools Used for Testing

### 2.1 Required (Core) Tools

| Tool | MASTG ID | Function |
|---|---|---|
| **rabin2** (part of radare2) | MASTG-TOOL-0129 | **MASTG's official tool** for reading ELF headers and binary security properties, including PIC/PIE |
| **unzip / apktool** | MASTG-TOOL-0011 | Extracting `.so` files from the APK (MASTG-TECH-0157) |

### 2.2 Alternative & Supporting Tools

| Tool | Function |
|---|---|
| **readelf** (binutils) | Standard Linux alternative — reads the `e_type` ELF header (`DYN` = PIE/shared, `EXEC` = non-PIE) |
| **checksec / checksec.py** | Ready-made summary: PIE, RELRO, NX, Canary, Fortify in a single command |
| **file** | Quick ELF file-type detection, including `pie executable` vs `LSB executable` in some versions |
| **objdump** | Additional header & disassembly analysis when deeper investigation is needed |
| **Ghidra / IDA Pro** | Deep analysis when needing to visually verify the relocation structure (`.rela.dyn`) |
| **MobSF** | Automatically analyzes `.so` files and reports binary protection status in the APK report |
| **APKiD** | Detects the compiler/toolchain used — helps explain *why* a given `.so` is non-PIE (outdated toolchain?) |
| **LIEF** (Library to Instrument Executable Formats) | Python scripting for bulk auditing of many `.so` files at once, suitable for CI/CD |

### 2.3 Environment Prerequisites

- **No device and no root needed** — just the APK file is enough. Fully automatable in CI/CD.
- **Extract every ABI** present in `lib/` — don't test only one architecture.
- **Know the app's `minSdkVersion`** (§1.2) — important context for interpreting results, though it doesn't change the binary PASS/FAIL evaluation criteria itself.
- **Distinguish app-owned `.so` files from third-party ones.** Check file names and symbols to identify the library's origin (e.g. `libcrashlytics.so`, `libflutter.so`, `libreactnativejni.so`) — this determines who is responsible for remediation.

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0157** (*Extracting Bundled Native Libraries*) to extract native libraries from the application package.
2. Use **MASTG-TECH-0115** (*Obtaining Compiler-Provided Security Features*) on each native library to obtain the compiler-provided security features.

### 3.2 Method A — rabin2 *(official MASTG method)*

**Step 1 — Extract native libraries (MASTG-TECH-0157):**

```bash
# Option 1: unzip directly
unzip -o YourApp.apk "lib/*" -d YourApp
find YourApp/lib -name "*.so"
# YourApp/lib/arm64-v8a/libnative-lib.so
# YourApp/lib/armeabi-v7a/libnative-lib.so
# ...

# Option 2: apktool (preserves directory structure)
apktool d YourApp.apk -o YourApp
ls -1 YourApp/lib/arm64-v8a/
```

**Step 2 — Check compiler-provided security features (MASTG-TECH-0115):**

```bash
rabin2 -I YourApp/lib/arm64-v8a/libnative-lib.so | grep -E "canary|pic"
```

Example **SAFE** output (PIC enabled):

```
canary   true
pic      true
```

Example **UNSAFE** output (PIC disabled — matching the official MASTG-TECH-0115 example):

```
pic      false
```

**To view all security information at once:**

```bash
rabin2 -I YourApp/lib/arm64-v8a/libnative-lib.so
```

```
arch     arm
baddr    0x0
binsz    123456
bintype  elf
bits     64
canary   true
nx       true
pic      true
relocs   true
relro    full
sanitiz  false
static   false
stripped true
...
```

**To check ALL `.so` files and ALL ABIs at once:**

```bash
for so in $(find YourApp/lib -name "*.so"); do
  echo "=== $so ==="
  rabin2 -I "$so" | grep -E "^pic|^canary|^arch"
done
```

### 3.3 Method B — readelf *(standard POSIX/binutils, no radare2 needed)*

```bash
# e_type = DYN means shared object OR position-independent executable (PIE)
# e_type = EXEC means a NON-PIE executable (problematic)
readelf -h YourApp/lib/arm64-v8a/libnative-lib.so | grep "Type:"

# Example PIE output (safe):
#   Type: DYN (Shared object file)

# Example NON-PIE output (problematic, for a main executable):
#   Type: EXEC (Executable file)
```

> **Important note:** for `.so` files (shared libraries), `e_type` is **always** `DYN` by ELF design — this doesn't directly prove PIE in the sense of "fully position-independent." A more accurate check for `.so` files is to look for the presence of the **`DT_FLAGS_1` dynamic tag with the `DF_1_PIE` bit**, or more practically: rely on `rabin2`/`checksec`, which already handle this nuance correctly.

```bash
# Check dynamic tags related to PIE
readelf -d YourApp/lib/arm64-v8a/libnative-lib.so | grep -i "flags"

# Check relocations — a PIE binary has many R_*_RELATIVE entries
readelf -r YourApp/lib/arm64-v8a/libnative-lib.so | grep -c "RELATIVE"
```

### 3.4 Method C — checksec.py *(ready-made summary, covering PIC + other features at once)*

This has a big efficiency advantage: a single command covers PIE, RELRO, NX, Canary, and Fortify — covering **both this test and MASTG-TEST-0223** in one step.

```bash
pip install checksec.py
checksec --file=YourApp/lib/arm64-v8a/libnative-lib.so
```

Example output:

```
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols      FORTIFY  Fortified  Fortifiable  FILE
Full RELRO      Canary found      NX enabled    PIE enabled     No RPATH   No RUNPATH   No Symbols   Yes      12         15           libnative-lib.so
```

To check many files at once and export as JSON (suitable for CI):

```bash
checksec --dir=YourApp/lib --output=json > checksec-report.json
jq '.[] | select(.["binary-type"] == "ELF") | {file: .file, pie: .pie}' checksec-report.json
```

### 3.5 Method D — LIEF *(Python scripting, bulk audit for CI/CD)*

```python
# check_pie.py
import lief
import glob
import sys

failed = []
for so_path in glob.glob("YourApp/lib/**/*.so", recursive=True):
    binary = lief.parse(so_path)
    if binary is None:
        continue
    is_pie = binary.is_pie
    print(f"{so_path}: PIE={is_pie}")
    if not is_pie:
        failed.append(so_path)

if failed:
    print(f"\n[!] {len(failed)} libraries are NOT PIE:")
    for f in failed:
        print(f"    {f}")
    sys.exit(1)
else:
    print("\n[+] All native libraries are PIE-enabled.")
```

```bash
pip install lief
python3 check_pie.py
```

Advantage: can be directly integrated as a *build gate* in a CI/CD pipeline (non-zero exit code on findings), and easier to maintain than parsing `rabin2`/`readelf` text output with `grep`.

### 3.6 Method E — MobSF *(automated, ready-to-cite report)*

```bash
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest
```

Upload the APK → look for the **Binary Analysis** / **Shared Object Analysis** section in the report. MobSF displays the `NX`, `STACK CANARY`, `RELRO`, and `PIE` status for every `.so` found, usually based on `checksec` under the hood. Advantage: a single report covers all aspects of APK security (not just binary protection), making it easier to present to non-technical stakeholders.

### 3.7 Method F — file / objdump *(quick supplementary check)*

```bash
# Quick file-type identification
file YourApp/lib/arm64-v8a/libnative-lib.so
# ELF 64-bit LSB shared object, ARM aarch64, ... dynamically linked

# objdump to view program headers and segments
objdump -p YourApp/lib/arm64-v8a/libnative-lib.so | head -30
```

### 3.8 Method Comparison: When to Use Which

| Method | Tool | PIE only? | Also covers canary/RELRO/NX? | Suitable for CI/CD batch? | When to use |
|---|---|---|---|---|---|
| **A** | rabin2 (MASTG) | ✅ + more | ✅ | Moderate (needs grep scripting) | **Official baseline** |
| **B** | readelf | ✅ (with nuance) | Partial | Moderate | Cross-verification without radare2; deep ELF structure investigation |
| **C** | checksec.py | ✅ + more | ✅ **(single command)** | ✅ (JSON output) | **Most practical** — answers TEST-0222 & TEST-0223 at once |
| **D** | LIEF (Python) | ✅ | ✅ (full API) | ✅ **(best for CI gating)** | Bulk audits, automated pipeline integration |
| **E** | MobSF | ✅ | ✅ | Partial | Comprehensive, ready-to-cite report |
| **F** | file / objdump | Partial (indicative) | ❌ | Low | Quick triage / sanity check |

**Minimum recommended combination:** **C (checksec.py) → A (rabin2 for cross-verification)**.
checksec.py gives the fastest answer and covers MASTG-TEST-0223 at the same time in the same output; rabin2 serves as verification since it's the tool explicitly referenced by MASTG. For routine/CI audits, use **D (LIEF)** as an automated gate.

---

### 3.9 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rule:**

> **Observation:** *"The output should show all the security features enabled for each native library, including PIC."*
>
> **Evaluation:** *"The test case **fails** if PIC is disabled."*

This criterion is quite literally simple — there is no additional context clause like you'd find on crypto tests. **A single `.so` with PIC/PIE disabled is already enough to FAIL** that library.

---

#### ❌ FAIL / ISSUE — The check is declared FAILED when:

| No | Condition | Example evidence |
|---|---|---|
| F1 | `rabin2 -I` shows `pic false` for any `.so` | `pic      false` |
| F2 | `checksec` shows `No PIE` / `PIE disabled` | `PIE             No PIE` |
| F3 | `readelf -h` shows `e_type: EXEC` on a binary that should be PIE | Rarely occurs for pure `.so` files; more relevant for bundled executable binaries |
| F4 | A bundled third-party library (closed-source SDK) is non-PIE | An old SDK not yet recompiled with a modern toolchain |
| F5 | Only some ABIs are non-PIE (e.g. `armeabi-v7a` non-PIE, `arm64-v8a` PIE) | Custom build script inconsistent across architectures |
| F6 | `minSdkVersion` < 21 **and** the app genuinely supports such devices with a non-PIE `.so` | A combination that allows a non-PIE binary to actually load on an old device |

**Example evidence (illustrative — MASTG does not yet provide an official demo for this test):**

```bash
$ rabin2 -I lib/armeabi-v7a/libvendor_legacy.so | grep -E "canary|pic"
canary   false
pic      false
```

```bash
$ checksec --file=lib/armeabi-v7a/libvendor_legacy.so
RELRO         STACK CANARY    NX          PIE          RPATH      RUNPATH      FILE
No RELRO      No canary found NX enabled  No PIE       No RPATH   No RUNPATH   libvendor_legacy.so
```

> Note: MASTG-TECH-0115 itself gives a `pic false` output example purely to illustrate command format — not from a real application scenario. The file name `libvendor_legacy.so` above is constructed to illustrate the most realistic scenario (§1.2): an outdated third-party SDK/library.

---

#### ✅ PASS — The check is declared PASSED when:

| No | Condition | Example evidence |
|---|---|---|
| P1 | **All** `.so` files across **all ABIs** show `pic true` / `PIE enabled` | `rabin2 -I` → `pic      true` for every file |
| P2 | The app is compiled with a standard NDK/Clang toolchain without linker flag modification | No `-no-pie` in `Android.mk`/`CMakeLists.txt`/`build.gradle` |
| P3 | Bundled third-party libraries are also PIE (modern SDKs, recompiled with a current toolchain) | Verified per-file, not assumed |

**Example output indicating PASS:**

```bash
$ for so in $(find YourApp/lib -name "*.so"); do
    echo -n "$so: "; rabin2 -I "$so" | grep "^pic"
  done

YourApp/lib/arm64-v8a/libnative-lib.so: pic      true
YourApp/lib/armeabi-v7a/libnative-lib.so: pic      true
YourApp/lib/x86_64/libnative-lib.so: pic      true
YourApp/lib/x86/libnative-lib.so: pic      true
```

```bash
$ python3 check_pie.py
YourApp/lib/arm64-v8a/libnative-lib.so: PIE=True
YourApp/lib/armeabi-v7a/libnative-lib.so: PIE=True

[+] All native libraries are PIE-enabled.
```

---

#### ⚠️ Important Notes on Evaluation

1. **Expect PASS on the majority of modern apps (§1.2).** This isn't a reason to skip the test, but it's context that should be communicated to stakeholders: a FAIL finding on this test in 2026 is a **strong signal** that something unusual is going on (a very outdated toolchain, or a deliberately low `minSdkVersion`) — not the result of an oversight in standard build configuration.

2. **Different `.so` files within the same APK can have different statuses.** Don't stop after checking one file — check **all** `.so` files across **all** ABI directories. Third-party libraries bundled by developers often slip through without the same consistent hardening applied to the app's own code.

3. **`e_type: DYN` in `readelf` does not automatically prove PIE for a `.so`.** All shared objects by ELF design have `e_type: DYN` — whether they are PIE or not in the stricter sense. Rely on `rabin2`/`checksec`, which handle the nuance of PIE detection correctly through a combination of headers and dynamic tags, rather than `readelf -h` alone.

4. **Distinguish remediation responsibility.** If the failing `.so` is code owned by the development team, the fix is in their hands (§4). If it's a closed-source third-party SDK, options are limited to: reporting to the vendor, finding an alternative SDK, or accepting the risk with explicit documentation.

5. **Check whether `minSdkVersion` genuinely requires compatibility with API < 21.** If a FAIL is found on an app with `minSdkVersion` ≥ 21, this is an anomaly worth investigating further — likely a misconfigured build pipeline rather than a deliberate design decision.

6. **Don't conflate this with MASTG-TEST-0223.** Although the steps are identical and often checked with the same command (`checksec`/`rabin2`), these are two nominally separate weaknesses under MASWE-0045 reporting — report PIE status and canary status as separate finding rows, even though they come from a single test command.

7. **Severity is modulated as follows:**

   | Factor | Severity |
   |---|---|
   | Core app `.so` (processing sensitive data/crypto) is non-PIE | **High** — amplifies the impact of memory-corruption exploitation if present |
   | Non-critical third-party `.so` (e.g. a UI/animation library) is non-PIE | **Medium** |
   | All `.so` files are PIE-enabled | **Not a finding** |
   | Finding only on a deliberately low `minSdkVersion` < 21 intended to support old devices | **Informational** — document the legacy-support vs. security trade-off |

8. **Document:** the full path of every `.so` tested along with its ABI, raw tool output (`rabin2`/`checksec`), per-file PIE status, whether the file belongs to the app or a third party (based on name/symbols), the app's `minSdkVersion`, and — when a FAIL is found — a concrete recommendation (rebuild in-house vs. contact the vendor).

---

## 4. Recommendations

### 4.1 Main Principles

**Priority 1 — Do not manually disable PIE.** This is the simplest remediation: Clang (the NDK's default compiler) already produces PIE by default. Problems usually arise from an **explicit override**, not a wrong default.

```gradle
// ❌ WRONG — never add this flag manually
externalNativeBuild {
    cmake {
        cppFlags "-no-pie"     // <-- REMOVE this line if present
    }
}
```

```cmake
# ❌ WRONG in CMakeLists.txt
set(CMAKE_POSITION_INDEPENDENT_CODE OFF)   # <-- do not turn this off

# ✅ CORRECT — leave the NDK default in place (implicitly ON for shared libraries)
# No need to write anything; or be explicit for clarity:
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
```

**Priority 2 — Use a current NDK toolchain.** Don't use `ndk-build` with a very old configuration (`Android.mk` from the `gcc` era) without updating. Modern Clang-based NDKs guarantee PIE by default for `minSdkVersion` ≥ 21.

```gradle
android {
    ndkVersion "27.0.12077973"   // use a current NDK version supported by AGP
}
```

**Priority 3 — Audit and push vendors on non-PIE third-party libraries.** If the problematic `.so` comes from a closed-source SDK:
- Update to the latest SDK version — actively maintained vendors have usually fixed this.
- If the SDK is no longer maintained, evaluate replacing it with a more modern alternative.
- If there's no other option in the short term, document it as an **accepted risk** with business justification and a long-term mitigation/replacement plan.

**Priority 4 — Raise `minSdkVersion` where possible.** Supporting Android < 5.0 (API 21) in 2026 has a very small user base in most markets, while retaining it opens the door to compatibility with non-PIE binaries and the loss of various other platform security protections (see also MASTG-TEST-0223 and `targetSdkVersion` considerations in other MASVS-CODE tests).

**Priority 5 — Verify hardening at every release, not just once.** Add automated checks (Method D — LIEF, or checksec) as part of the CI/CD pipeline, so that build-script changes or new dependencies that accidentally disable PIE are caught immediately before release.

```bash
# Example simple CI gate
python3 check_pie.py || { echo "Build failed: found non-PIE .so"; exit 1; }
```

**Priority 6 — Apply full hardening, not just PIE.** In line with MASTG-TEST-0223 and MASTG-KNOW-0006, make sure the following compiler flags are active for all custom native code (outside the strict scope of this test, but part of the same hardening policy):

```cmake
# CMakeLists.txt — comprehensive hardening
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fstack-protector-strong -D_FORTIFY_SOURCE=2 -Wformat -Wformat-security")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fstack-protector-strong -D_FORTIFY_SOURCE=2 -Wformat -Wformat-security")
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,-z,relro,-z,now -Wl,-z,noexecstack")
```

### 4.2 Remediation Checklist

- [ ] All `.so` files across **all ABIs** (`arm64-v8a`, `armeabi-v7a`, `x86_64`, `x86`) verified as PIE-enabled
- [ ] No `-no-pie` flag or `CMAKE_POSITION_INDEPENDENT_CODE OFF` in the build configuration
- [ ] The NDK toolchain used is a current version supported by the Android Gradle Plugin
- [ ] Third-party libraries (closed-source SDKs) verified as PIE — not assumed safe
- [ ] Vendor SDKs proven to be non-PIE have been updated, replaced, or documented as an accepted risk
- [ ] `minSdkVersion` reviewed — is support for Android < 5.0 still required for the business
- [ ] Full hardening flags applied to custom native code (`-fstack-protector-strong`, `-D_FORTIFY_SOURCE=2`, `RELRO`, `NX`)
- [ ] PIE checks integrated into the CI/CD pipeline as an automated gate (e.g. with LIEF/checksec)
- [ ] **Re-verify:** re-run MASTG-TEST-0222 after every change to native dependencies
- [ ] **Cross-verify:** run MASTG-TEST-0223 (Stack Canaries) — identical steps and tools, report as a separate finding

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0222: Position Independent Code (PIC) Not Enabled](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0222/)
- [MASTG-TEST-0223: Stack Canaries Not Enabled](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0223/)
- [MASWE-0045: Compiler-Provided Security Features Not Used](https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-0045/)
- [MASTG-KNOW-0006: Binary Protection Mechanisms](https://mas.owasp.org/MASTG/knowledge/android/MASVS-CODE/MASTG-KNOW-0006/)
- [MASTG-TECH-0157: Extracting Bundled Native Libraries](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0157/)
- [MASTG-TECH-0115: Obtaining Compiler-Provided Security Features](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0115/)
- [MASTG-TECH-0007: Obtaining Information from the App Package](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0007/)
- [MASTG — Testing Code Quality (Binary Protection Mechanisms, Position Independent Code)](https://mas.owasp.org/MASTG/0x04h-Testing-Code-Quality/)
- [MASTG-TOOL-0129: radare2 (rabin2)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0129/)
- [MASTG-TOOL-0011: apktool](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0011/)
- [MASVS-CODE: Code Quality](https://mas.owasp.org/MASVS/08-MASVS-CODE/)
- [OWASP Mobile Top 10 2024 — M7: Insufficient Binary Protections](https://owasp.org/www-project-mobile-top-10/2023-risks/m7-insufficient-binary-protections.html)

### 5.2 Official Android / Google / AOSP Documentation

- [Android Security Enhancements — Android 5.0 (PIE enforcement)](https://source.android.com/docs/security/enhancements/enhancements50)
- [Android Security Enhancements — Android 5 overview](https://source.android.com/docs/security/enhancements/#android-5)
- [NDK Build System Maintainers Guide — Additional Required Arguments (PIE)](https://android.googlesource.com/platform/ndk/+/master/docs/BuildSystemMaintainers.md#additional-required-arguments)
- [Bionic linker source — PIE enforcement (`linker_main.cpp`)](https://cs.android.com/android/platform/superproject/+/master:bionic/linker/linker_main.cpp)
- [Android linker changes for NDK developers](https://android.googlesource.com/platform/bionic/+/master/android-changes-for-ndk-developers.md)
- [Android NDK — Application Binary Interfaces (ABI)](https://developer.android.com/ndk/guides/abis)
- [Android — Use of native code (security risks)](https://developer.android.com/privacy-and-security/risks/use-of-native-code)
- [Android Runtime (ART) overview](https://source.android.com/devices/tech/dalvik/configure)
- [Flutter — Security false positives (stack canary, shared objects)](https://docs.flutter.dev/reference/security-false-positives#shared-objects-should-use-stack-canary-values)

### 5.3 ELF Format & Technical Research

- [ELF Format Specification (Linux Foundation)](https://refspecs.linuxfoundation.org/elf/gabi4+/contents.html)
- [LIEF — Android executable formats tutorial](https://lief-project.github.io/doc/latest/tutorials/10_android_formats.html)
- [ResearchGate — ASLR and ROP Attack Mitigations for ARM-Based Android Devices](https://www.researchgate.net/publication/320952677_ASLR_and_ROP_Attack_Mitigations_for_ARM-Based_Android_Devices)
- [FortiGuard Labs — Tutorial of ARM Stack Overflow Exploit: Defeating ASLR with ret2plt](https://www.fortinet.com/blog/threat-research/tutorial-of-arm-stack-overflow-exploit-defeating-aslr-with-ret2plt)
- [arXiv — Security Mitigations for Return-Oriented Programming Attacks](https://arxiv.org/pdf/1008.4099)
- [0x00sec — Exploit Mitigation Techniques: ASLR](https://archive.0x00sec.org/t/exploit-mitigation-techniques-address-space-layout-randomization-aslr/5452)
- [Opensource.com — Identify security properties on Linux using checksec](https://opensource.com/article/21/6/linux-checksec)
- [Siphos blog — High level explanation on some binary executable security](https://blog.siphos.be/2011/07/high-level-explanation-on-some-binary-executable-security/)

### 5.4 Standards & Taxonomies

- [CWE-1259: Improper Restriction of Security Token Assignment](https://cwe.mitre.org/data/definitions/1259.html)
- [CWE-121: Stack-based Buffer Overflow](https://cwe.mitre.org/data/definitions/121.html)
- [CWE-787: Out-of-bounds Write](https://cwe.mitre.org/data/definitions/787.html)
- [NIST SP 800-163 Rev.1 — Vetting the Security of Mobile Applications](https://csrc.nist.gov/publications/detail/sp/800-163/rev-1/final)

### 5.5 Tool Documentation

- [radare2 — rabin2 documentation (The Official Radare2 Book)](https://book.rada.re/tools/rabin2/headers.html)
- [checksec.py — PyPI](https://pypi.org/project/checksec.py/)
- [LIEF — Library to Instrument Executable Formats](https://github.com/lief-project/LIEF)
- [MobSF — Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)
- [APKiD — Android Application Identifier](https://github.com/rednaga/APKiD)
- [Ghidra — software reverse engineering framework](https://ghidra-sre.org/)
- [GNU Binutils — readelf / objdump](https://www.gnu.org/software/binutils/)

---

*This document was compiled based on OWASP MASTG (latest release as of September 2026), official Android Open Source Project (AOSP) documentation, the ELF specification, and third-party technical research on ASLR/PIE/ROP. This test does not yet have an official demo (MASTG-DEMO) from MASTG, and its source frontmatter marks this test `deprecated_since: 21` — see §1.2 for an explanation of the impact on interpreting results.*
