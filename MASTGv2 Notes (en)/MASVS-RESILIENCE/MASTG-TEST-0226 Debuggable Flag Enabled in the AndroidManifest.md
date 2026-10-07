# MASTG-TEST-0226 Debuggable Flag Enabled in the AndroidManifest

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0226 |
| **Platform** | Android |
| **MASVS Category** | **MASVS-RESILIENCE** (Resilience Against Reverse Engineering and Tampering) |
| **Weakness** | **MASWE-0063** — *Debug Mechanisms Not Disabled* |
| **Test Type** | **Static**, Code |
| **Profile** | **R** (Resilience) |
| **Knowledge** | MASTG-KNOW-0007 (Debuggable Apps) |
| **Best Practice** | MASTG-BEST-0007 (Debuggable Flag Disabled in the AndroidManifest) |
| **Related Techniques** | MASTG-TECH-0117 (Obtaining Information from the AndroidManifest), MASTG-TECH-0150 (Analyzing the AndroidManifest) |
| **Related Demo** | — (MASTG does not yet provide a demo for this test) |
| **Closely Related Weakness** | **MASWE-0064** — *Debugger Detection Not Implemented* (see MASTG-TEST-0352/0353) — the next layer of defense after this flag |
| **Sibling Test** | MASTG-TEST-0227 (Debugging Enabled for WebViews) — a different object (WebView, not the native app) but a similar theme |
| **Related CVEs** | CVE-2024-31317 (Zygote JDWP flag injection), CVE-2024-0044 (`run-as` sandbox bypass) — see §1.4 |
| **Related CWEs** | CWE-489 (Active Debug Code), CWE-215 (Insertion of Sensitive Information Into Debugging Code), CWE-1244 (Internal Asset Exposed to Unsafe Debug Access) |

---

## 1. Explanation

### 1.1 Testing Objective

Direct quote from the MASTG overview:

> *"This test case checks if the app has the `debuggable` flag (`android:debuggable`) set to `true` in the `AndroidManifest.xml`. When this flag is enabled, it allows the app to be debugged enabling attackers to inspect the app's internals, bypass security controls, or manipulate runtime behavior."*
>
> *"Although having the `debuggable` flag set to `true` **is not considered a direct vulnerability**, it **significantly increases the attack surface** by providing unauthorized access to app data and resources, particularly in production environments."*

Note the important nuance that MASTG itself explicitly acknowledges, directly citing Android's own documentation: this flag is **not a direct vulnerability** (no automatic exploitation occurs merely because the flag is `true`), but rather an **attack surface amplifier** — it opens the door to a range of advanced techniques that require physical/ADB access first. This affects how severity is assessed (§3.9).

### 1.2 What Actually Happens When `debuggable="true"`

MASTG-KNOW-0007 briefly explains the technical mechanism:

> *"Every debugger-enabled process runs an **extra thread for handling JDWP protocol packets**. This thread is started only for apps that have the `android:debuggable="true"` attribute in the `Application` element within the Android Manifest."*

**JDWP (Java Debug Wire Protocol)** is the protocol used by IDEs (Android Studio) to communicate with a running Dalvik/ART process on a device — setting breakpoints, inspecting variables, modifying values at runtime, and controlling execution flow. When `android:debuggable="true"`:

- The system runs an **extra thread** dedicated to handling JDWP protocol packets for that application's process.
- The application process becomes **attachable** by any debugger that can connect to its JDWP socket — whether through legitimate Android Studio, or a command-line tool such as `jdb` run by an attacker via `adb`.
- **This attribute applies at the whole-application level** and **cannot be overridden per component** — once `true`, the entire application process (all Activities, Services, etc.) becomes an equally debuggable target.

**Concrete impacts described by the Android documentation** referenced by MASTG:

| Impact | Explanation |
|---|---|
| **Unauthorized Access** | Attackers can debug the app to access sensitive functionality that should otherwise be hidden |
| **Resource Exploitation** | Unauthorized access to app resources and data |
| **Administrative Functions Exposed** | Debugging interfaces meant only for developers become accessible to attackers |
| **Information Disclosure** | Facilitates reverse engineering and extraction of sensitive data |

### 1.3 Practical Consequences: What an Attacker Can Do

This is a part that is often insufficiently concrete in official documentation, but is important for understanding the real *severity* of this finding. With a debuggable app and `adb` access (physical device or emulator, no root required), an attacker can:

**1. Access the app sandbox via `run-as` — without root:**

```bash
adb shell run-as com.example.target ls -la /data/data/com.example.target/
```

The `run-as` command **only works for debuggable applications** on non-rooted devices. This is directly equivalent to `root`-level access to that application's sandbox — opening up all of `shared_prefs/`, `databases/`, `files/` that should otherwise be isolated (directly linked to MASTG-TEST-0207).

**2. Directly attach a debugger and manipulate runtime execution:**

```bash
# Find processes that are debuggable
adb jdwp
# Forward the JDWP port
adb forward tcp:8700 jdwp:<pid>
# Attach with jdb
jdb -attach localhost:8700
```

From here an attacker can set breakpoints on license/payment validation functions, read runtime variable values (including keys that may briefly reside in memory in plaintext), invoke methods arbitrarily, and **modify return values** to bypass security checks (e.g., changing the result of an `isLicensed()` function from `false` to `true`).

**3. Facilitates further instrumentation (Frida, etc.).** Although Frida does not *absolutely require* `debuggable="true"` (frida-gadget can be injected via repackaging), an app that is already debuggable makes the entire attack chain — from initial exploration to full instrumentation — much faster and requires no APK modification at all.

### 1.4 The 2024 Context: Why This Control Remains Relevant Even When the Flag Is `false`

This is an important nuance that goes beyond what is written in the MASTG overview, and explains why MASWE-0064 (*Debugger Detection Not Implemented*) exists as an additional layer after this baseline control.

**CVE-2024-31317 (fixed in the June 2024 Android Security Bulletin):** Research showed that **even apps NOT shipped with `android:debuggable="true"`** can still be forced to run with the runtime flag `DEBUG_ENABLE_JDWP` by exploiting how Zygote parses command-line arguments. An attacker who can reach `system_server` (for example, via `adb shell` holding the `WRITE_SECURE_SETTINGS` permission) can inject additional parameters when the application process is spawned. Once a process is spawned with this flag, the JDWP socket opens and **all standard dynamic-debug techniques** (method replacement, variable patching, direct Frida injection) become possible **without modifying either the APK or the boot image**. The impact includes full read/write access to any app's private data directory (including privileged apps such as `com.android.settings`), token theft, MDM bypass, and potential privilege escalation via exposed IPC endpoints.

**CVE-2024-0044 (fixed in the March 2024 Android Security Bulletin):** A critical vulnerability in the `run-as` command itself on Android 12/13/14 — allowing an attacker to **hijack the `run-as` mechanism** to make the system *believe* a target application is debuggable when it is not, through a flaw in the `check_directory()` function that incorrectly bypassed UID validation for the `/data/user/0` path. This effectively hijacks the Android Application Sandbox **without needing root** for any application on the device, not only those that are actually debuggable.

**Meta Red Team X** has also documented a technique to bypass the `run-as` debuggability check via *newline injection*, demonstrating that the assumption "only debuggable apps are vulnerable via `run-as`" does not fully hold against a sufficiently motivated attacker.

**Implications for testing:** a `debuggable="true"` finding remains a direct and definitive finding (requiring no additional platform vulnerability to be exploitable). But the context above explains why MASTG-BEST-0007 explicitly states that disabling this flag **"is an important first step but does not fully protect the app from advanced attacks"** — because a sufficiently sophisticated attacker has alternative paths to equivalent debugging capability, either via platform vulnerabilities (such as the two CVEs above) or via **binary patching** to forcibly re-enable this flag on a repackaged copy of the APK.

### 1.5 Position Within a Layered Defense Chain

MASTG-BEST-0007 explicitly positions this test as a **first layer**, not a single solution:

> *"Disabling debugging via the `debuggable` flag is an important first step but does not fully protect the app from advanced attacks. Skilled attackers can enable debugging through various means, such as **binary patching** to allow attachment of a debugger or the use of **binary instrumentation tools like Frida** to achieve similar capabilities. For apps requiring a higher level of security, consider implementing **anti-debugging techniques** as an additional layer of defense."*

| Layer | MASTG Test | What It Checks |
|---|---|---|
| **1. Baseline configuration** | **MASTG-TEST-0226** *(this document)* | Whether the `debuggable` flag is disabled in the manifest — passive defense, requires no additional code |
| **2. Active detection (static)** | MASTG-TEST-0352 (*References to Debugging Detection APIs*) | Whether the code contains references to debugger-detection APIs (`Debug.isDebuggerConnected()`, etc.) |
| **3. Active detection (dynamic)** | MASTG-TEST-0353 (*Runtime Use of Debugging Detection APIs*) | Whether that detection actually works and is difficult to bypass at runtime |

For R-profile applications requiring high resilience (financial, DRM, anti-cheat), passing MASTG-TEST-0226 alone is **not sufficient** — ideally all three layers are tested as a single chain.

### 1.6 Category Mismatch: KNOW-0007 vs. Test Placement

A small technical note worth knowing: the source file **MASTG-KNOW-0007** (Debuggable Apps) has metadata `masvs_category: MASVS-CODE`, while **the test that uses it (MASTG-TEST-0226) sits under MASVS-RESILIENCE**. This is likely a remnant of the MASTG V2 taxonomy reorganization that hasn't yet been made fully consistent across cross-references — it does not affect testing methodology or evaluation criteria, but is good to know so it doesn't cause confusion when browsing MASTG source documents directly.

---

## 2. Tools Used for Testing

### 2.1 Required Tools (Core)

| Tool | MASTG ID | Function |
|---|---|---|
| **jadx / apktool** | MASTG-TOOL-0018 / 0011 | Extract `AndroidManifest.xml` (MASTG-TECH-0117) |
| **aapt2** | MASTG-TOOL-0124 | The **fastest** way to read this flag's status — directly supported by MASTG-TECH-0150 |
| **grep** | — | Simple pattern search on the extracted manifest |

### 2.2 Alternative and Supporting Tools

| Tool | Function |
|---|---|
| **adb** | Verify the debuggable status of an app that is **already installed** on a device (not just a static APK file) — via `dumpsys package` |
| **apkanalyzer** | Android SDK GUI/CLI alternative for manifest inspection |
| **Python `androguard` / `pyaxmlparser`** | Scripting for bulk auditing of many APKs at once |
| **MobSF** | Automated analysis, flags the debuggable flag as a finding in the APK report |
| **`adb jdwp` + `jdb`** | **Proof of exploitability** — confirms the application can actually be attached by a debugger, not merely that the manifest value reads a certain way |

### 2.3 Environment Prerequisites

- **No device and no root required** for the basic static check — a plain APK file suffices.
- **For exploitability verification** (§3.5), a device/emulator with USB debugging enabled is needed — no root required.
- **As with the signing tests (0224/0225): test the final distributed APK**, not just a local build. This is **especially critical** for this test: Gradle configuration mistakes (e.g., `applicationVariants.all` targeting the wrong variant, or mixed-up build flavors) can cause `debuggable="true"` to **unintentionally end up in the release build** — something that can only be confirmed by inspecting the final artifact, not by assuming the source `build.gradle` configuration is correctly applied.
- **Note that this flag may also differ between internal development APKs (e.g., for QA) and the APK actually released on the Play Store** — make sure the testing target is clear.

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0117** (*Obtaining Information from the AndroidManifest*) to obtain `AndroidManifest.xml`.
2. Use **MASTG-TECH-0150** (*Analyzing the AndroidManifest*) to obtain the `debuggable` flag.

### 3.2 Method A — aapt2 *(fastest, no decompilation needed — directly exemplified by MASTG-TECH-0150)*

This is the method explicitly demonstrated in MASTG-TECH-0150 as the primary approach:

```bash
aapt2 d badging YourApp.apk | grep -i debuggable
```

Example output when the flag is **enabled** (per the official MASTG-TECH-0150 example):

```
application-debuggable
```

**If the flag does not appear in the output at all** → the flag value is `false` (the default for a release build).

### 3.3 Method B — grep on the decompiled manifest *(apktool/jadx)*

```bash
# Extraction with apktool
apktool d -f -o out_dir YourApp.apk
grep -i "android:debuggable" out_dir/AndroidManifest.xml

# Example output when enabled:
#   android:debuggable="true"

# Extraction with jadx
jadx --no-src -d out_dir YourApp.apk
grep -i "android:debuggable" out_dir/resources/AndroidManifest.xml
```

> Per the official MASTG-TECH-0150 note: *"If the attribute is absent, the flag **defaults to `false`** for release builds."* — the absence of this line in the `grep` output (with no error) means **PASS**, not an incomplete result.

### 3.4 Method C — adb dumpsys *(verification on an app that is ALREADY INSTALLED on a device)*

This is an important complement: verifying the actual *runtime* status on an installed app, not merely reading a static APK file — useful for confirming that the APK actually running on a user's device is consistent with the APK being audited.

```bash
adb shell dumpsys package com.example.target | grep -i debuggable

# Example output:
#   flags=[ DEBUGGABLE HAS_CODE ALLOW_CLEAR_USER_DATA ... ]
```

The presence of the `DEBUGGABLE` flag in the `flags=[...]` list confirms the actual status on that installation.

### 3.5 Method D — Exploitability verification with `run-as` and JDWP *(concrete proof, not merely a manifest value)*

This is the method that elevates a finding from a "configuration value" to "proof of real impact" — highly recommended for pentest reports, not just compliance audits.

```bash
PKG=com.example.target

# 1. Prove sandbox access via run-as WITHOUT ROOT
adb shell run-as $PKG ls -la /data/data/$PKG/
# Successfully shows the private directory's contents -> CONCRETE PROOF of real impact

adb shell run-as $PKG cat /data/data/$PKG/shared_prefs/*.xml

# 2. Prove the process can be attached by a debugger via JDWP
adb jdwp
# Shows a list of PIDs for processes with an open JDWP socket

PID=$(adb shell pidof -s $PKG)
adb forward tcp:8700 jdwp:$PID
jdb -attach localhost:8700
# > attach succeeds -> breakpoints, variable inspection, return value manipulation are possible
```

> **Ethics/scope note:** only run these steps against a target application that is within the authorized scope of testing (your own app, or with explicit authorization from a pentest client).

### 3.6 Method E — androguard *(scripting for bulk auditing)*

```python
# check_debuggable.py
from androguard.core.apk import APK
import glob

for apk_path in glob.glob("./apks/*.apk"):
    a = APK(apk_path)
    is_debuggable = a.get_element("application", "debuggable")
    verdict = "FAIL" if is_debuggable == "true" else "PASS"
    print(f"{apk_path}: debuggable={is_debuggable} -> {verdict}")
```

```bash
pip install androguard
python3 check_debuggable.py
```

### 3.7 Method F — MobSF

```bash
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest
```

Upload the APK → the **Manifest Analysis** section displays an explicit finding *"Debug Enabled For App"* with `high` severity when `android:debuggable="true"` is detected, complete with CWE reference.

### 3.8 Method Comparison: When to Use Which

| Method | Tool | Device needed? | Data source | Proves real exploitability? | When to use |
|---|---|---|---|---|---|
| **A** | aapt2 (MASTG) | No | APK file | ❌ | **Official baseline — fastest** |
| **B** | Manual grep (apktool/jadx) | No | APK file | ❌ | Cross-verification; when `aapt2` is unavailable |
| **C** | adb dumpsys | Yes | Installed device | ❌ | Verifying actual *runtime* status, APK-vs-installation consistency |
| **D** | `run-as` + JDWP/jdb | Yes | Installed device | ✅ **(key)** | **Pentest reports** — turns a finding into concrete proof |
| **E** | androguard | No | APK file | ❌ | Bulk auditing of many APKs, CI integration |
| **F** | MobSF | No | APK file | ❌ | Report-ready output with CWE references |

**Minimum recommended combination:** **A (aapt2) always**, plus **D (run-as/JDWP)** whenever this test results in a FAIL in a pentest context (not merely a compliance audit) — proof of exploitability is far more convincing to stakeholders than merely citing a manifest attribute value. Add **C** to verify that the APK circulating on user devices is consistent with what is being audited.

---

### 3.9 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rule:**

> **Observation:** *"The output should explicitly show whether the `debuggable` flag is set (`true` or `false`). If the flag is **not specified**, it is treated as **`false` by default** for release builds."*
>
> **Evaluation:** *"The test case **fails** if the `debuggable` flag is **explicitly set to `true`**. This indicates that the app is configured to allow debugging, which is inappropriate for production environments."*

The criterion is very straightforward — **a single binary condition**, without the contextual nuance seen in cryptography tests.

---

#### ❌ FAIL / ISSUE — The check is declared FAILED if:

| No | Condition | Example evidence |
|---|---|---|
| F1 | `android:debuggable="true"` is explicitly listed in the release APK's manifest | `aapt2 d badging` → `application-debuggable` |
| F2 | The flag is `true` on the **final distributed APK** (not just an internal development build) | Verified via the Play Store/bundletool APK, not just a local build |
| F3 | `adb shell dumpsys package` shows the `DEBUGGABLE` flag on an app installed on a production device | `flags=[ DEBUGGABLE ... ]` |
| F4 | `run-as` successfully grants access to the app sandbox without root, confirming real impact | `adb shell run-as <pkg> ls` successfully lists the contents of `/data/data/<pkg>/` |
| F5 | The app process can be attached via JDWP (`jdb`) and allows manipulation of variables/return values | A breakpoint is successfully set on a critical validation function |

**Example evidence (illustrative — MASTG does not yet provide an official demo for this test):**

```bash
$ aapt2 d badging LegacyBuild.apk | grep -i debuggable
application-debuggable

$ adb install -r LegacyBuild.apk
$ adb shell run-as com.example.legacyapp ls -la /data/data/com.example.legacyapp/shared_prefs/
-rw-rw---- 1 u0_a123 u0_a123  842 2026-09-01 10:15 auth_prefs.xml
-rw-rw---- 1 u0_a123 u0_a123  156 2026-09-01 10:15 user_settings.xml
```

Interpretation: `debuggable="true"` is confirmed statically **and** its impact is proven real — `run-as` grants direct access to `shared_prefs/` that should otherwise be sandbox-isolated → **FAIL** with concrete proof of exploitability.

---

#### ✅ PASS — The check is declared PASSED if:

| No | Condition | Example evidence |
|---|---|---|
| P1 | The `android:debuggable` attribute **does not appear at all** in the manifest (defaults to `false` for release) | `aapt2 d badging` does not show `application-debuggable` |
| P2 | The attribute is explicitly set to `android:debuggable="false"` | `grep` shows the value `"false"` explicitly |
| P3 | `run-as` fails (`run-as: package not debuggable`) on an installed app | Confirms the sandbox is properly protected |
| P4 | `adb jdwp` shows no PID for the target application's process | No open JDWP socket — the process cannot be attached |

**Example output indicating PASS:**

```bash
$ aapt2 d badging ProductionApp.apk | grep -i debuggable
# (no output)

$ adb install -r ProductionApp.apk
$ adb shell run-as com.example.productionapp ls
run-as: Package 'com.example.productionapp' is not debuggable
```

Interpretation: no `application-debuggable` in the badging output, **and** `run-as` explicitly refuses access with a message confirming non-debuggable status → **PASS**.

---

#### ⚠️ Important Notes on Assessment

1. **Test the final APK, not a development build.** This is the single most important note specific to this test. It is very common for teams to have an "internal"/"staging" build with `debuggable=true` for QA purposes — make sure the object under test is truly the APK released to end users (via the Play Store or another official distribution channel), not an internal artifact deliberately configured differently.

2. **Absence of the attribute = PASS, not an ambiguous result.** MASTG explicitly states that without a declaration, the default value is `false` for a standard Android Gradle Plugin release build. Do not flag this as "needs further verification" — this is a definitive PASS condition based on the platform's default behavior.

3. **Always try to prove real impact (`run-as`/JDWP) when a FAIL is found in a pentest context.** The manifest attribute value alone is proof of configuration; a successful `run-as` is proof of **impact**. This distinction matters for report credibility — especially since MASTG itself states this flag *"is not considered a direct vulnerability,"* so demonstrating concrete impact strengthens the justification for the assigned severity.

4. **`debuggable="false"` is not a complete solution (§1.4, §1.5).** Even when this test PASSes, for R-profile applications requiring high resilience, still check **MASTG-TEST-0352/0353** (active debugger detection) as an additional defense layer — given that CVE-2024-31317 and CVE-2024-0044 prove that sophisticated attackers have paths to debugging capability that do not fully depend on this manifest flag.

5. **Also check for consistency between the APK file and the actual installation on a device (Method C).** In rare but possible cases (distribution pipeline errors, sideloading the wrong APK, etc.), the status on a production device can differ from what is seen in the APK file being audited separately.

6. **This is not as prone to false positives as crypto tests** — there is no legitimate "flag is `true` but it's actually fine" scenario for a production build. Unlike MASTG-TEST-0223 (stack canary), which has legitimate exceptions (Flutter/React Native), **there is no valid reason** for a production APK to have `debuggable="true"`. If found, this is purely a build configuration mistake, not a defensible design decision.

7. **Severity is modulated by application context (profile R):**

   | Factor | Severity |
   |---|---|
   | Financial/payment/DRM app with `debuggable="true"` on a production APK | **High** — directly facilitates bypassing critical business logic |
   | General-purpose app with `debuggable="true"` on a production APK | **Medium-High** — still significant due to full sandbox access via `run-as` |
   | `run-as` proven to successfully grant access to credentials/tokens in the sandbox | **High** — confirmed impact, not merely potential |
   | `debuggable="true"` only on an internal/QA build that is never distributed to users | **Not a finding** for production assessment (still document the build separation policy) |
   | `debuggable="false"` or not declared | **Not a finding** |

8. **Document:** manifest check results (aapt2/grep), status on the installed device (dumpsys), and — where permitted within scope — concrete evidence from `run-as`/JDWP as supporting attachments for the impact level. Also include whether the APK tested is the final distributed build or an internal build.

---

## 4. Recommendations

### 4.1 Core Principle (MASTG-BEST-0007)

MASTG-BEST-0007 states:

> *"Ensure the debuggable flag in the AndroidManifest.xml is set to `false` for all release builds."*

**Priority 1 — Ensure the Gradle build type configuration handles this automatically; do not rely on manually setting it in the manifest.**

```kotlin
// build.gradle.kts
android {
    buildTypes {
        release {
            isDebuggable = false   // explicit, even though this is already the AGP default for release
            isMinifyEnabled = true
            // ...
        }
        debug {
            isDebuggable = true    // only for development builds
        }
    }
}
```

```groovy
// build.gradle (Groovy)
android {
    buildTypes {
        release {
            debuggable false
        }
        debug {
            debuggable true
        }
    }
}
```

**Do not** set `android:debuggable` directly in `AndroidManifest.xml` — let the Android Gradle Plugin manage it based on build type, since manually setting it in the manifest risks **overriding** the build type's behavior unintentionally (e.g., a developer adds `android:debuggable="true"` to the manifest for local debugging, then forgets to remove it before committing).

**Priority 2 — Verify as part of the release pipeline, not merely by assuming the source configuration is correct.** Per the note in §2.3 — correct `build.gradle` configuration does not guarantee the final artifact is free of mistakes (e.g., mixed-up build flavors). Add an automated gate:

```bash
#!/bin/bash
# ci-verify-debuggable.sh
APK=$1
if aapt2 d badging "$APK" | grep -q "application-debuggable"; then
    echo "[FAILED] Release APK detected as debuggable=true"
    exit 1
fi
echo "[OK] APK is not debuggable"
```

**Priority 3 — For R-profile apps (financial/DRM/anti-cheat), implement active debugger detection as an additional layer** (MASWE-0064, MASTG-TEST-0352/0353), given that MASTG-BEST-0007 itself states that the flag alone "does not fully protect the app from advanced attacks":

```kotlin
// Example of basic detection (bypassable by sophisticated attackers — not a replacement for debuggable=false)
if (Debug.isDebuggerConnected() || Debug.waitingForDebugger()) {
    // Responsive action: exit, log, or degrade sensitive functionality
}
```

> It should be emphasized: such detection techniques **can be bypassed** by attackers using Frida or binary patching — this is additional defense (defense in depth), not an absolute guarantee. Do not rely on it as the sole control for critical security logic.

**Priority 4 — Apply the principle of least privilege to ADB infrastructure in production environments.** Given that CVE-2024-31317 exploits `adb shell` access with the `WRITE_SECURE_SETTINGS` permission, ensure production devices (e.g., dedicated POS, kiosk, or corporate MDM devices) restrict USB debugging access and do not grant unnecessary elevated permissions to the shell.

**Priority 5 — Ensure the latest Android security patch level is applied** on organization-managed devices (MDM), specifically covering the **March 2024** (CVE-2024-0044) and **June 2024** (CVE-2024-31317) Android Security Bulletins or later, to close debug exploitation paths that do not depend on the application's own manifest flag.

**Priority 6 — Routine auditing as part of code review and pre-release checks.** Make checking `android:debuggable` a mandatory pre-release checklist item, not relied upon solely through automated CI — since this mistake often stems from human error (forgetting to remove a debug configuration line) rather than tooling failure.

### 4.2 Remediation Checklist

- [ ] `android:debuggable` is **not** manually set in `AndroidManifest.xml`
- [ ] The `debuggable` configuration is fully managed through Gradle `buildTypes` (`release { debuggable false }`)
- [ ] The final distributed APK/AAB (not just a local build) is verified with `aapt2 d badging`
- [ ] Additional verification is performed on the app as installed on a production device (`adb shell dumpsys package`)
- [ ] `run-as` and `adb jdwp` are confirmed to **fail/not apply** on the production APK
- [ ] The debuggable flag check is integrated as an automated gate in the release CI/CD pipeline
- [ ] For R-profile apps: active debugger detection (MASWE-0064) is implemented as an additional layer
- [ ] Organization-managed production/kiosk/POS devices restrict ADB access and privileged shell permissions
- [ ] The Android security patch level on managed devices covers the March 2024 and June 2024 bulletins or later
- [ ] The manual pre-release checklist includes verifying debuggable status as a mandatory item
- [ ] **Re-verify:** rerun MASTG-TEST-0226 after every build/signing configuration change

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0226: Debuggable Flag Enabled in the AndroidManifest](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0226/)
- [MASTG-TEST-0227: Debugging Enabled for WebViews](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0227/)
- [MASTG-TEST-0352: References to Debugging Detection APIs](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0352/)
- [MASTG-TEST-0353: Runtime Use of Debugging Detection APIs](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0353/)
- [MASWE-0063: Debug Mechanisms Not Disabled](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0063/)
- [MASWE-0064: Debugger Detection Not Implemented](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0064/)
- [MASTG-KNOW-0007: Debuggable Apps](https://mas.owasp.org/MASTG/knowledge/android/MASVS-CODE/MASTG-KNOW-0007/)
- [MASTG-BEST-0007: Debuggable Flag Disabled in the AndroidManifest](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0007/)
- [MASTG-TECH-0117: Obtaining Information from the AndroidManifest](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0117/)
- [MASTG-TECH-0150: Analyzing the AndroidManifest](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0150/)
- [MASTG-TECH-0038: Bypassing Debugger Detection (binary patching)](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0038/)
- [MASTG-TEST-0207: Runtime Storage of Unencrypted Data in the App Sandbox](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0207/)
- [MASVS-RESILIENCE: Resilience Against Reverse Engineering and Tampering](https://mas.owasp.org/MASVS/11-MASVS-RESILIENCE/)
- [OWASP Mobile Top 10 2024 — M7: Insufficient Binary Protections](https://owasp.org/www-project-mobile-top-10/2023-risks/m7-insufficient-binary-protections.html)

### 5.2 Official Android / Google Documentation

- [android:debuggable — Android Security Risks](https://developer.android.com/privacy-and-security/risks/android-debuggable)
- [`<application>` element — `android:debuggable` attribute](https://developer.android.com/guide/topics/manifest/application-element#debug)
- [Android Security Bulletin — March 2024 (CVE-2024-0044)](https://source.android.com/docs/security/bulletin/2024-03-01)
- [Android Security Bulletin — June 2024 (CVE-2024-31317)](https://source.android.com/docs/security/bulletin/2024-06-01)
- [Android — Debug your app](https://developer.android.com/studio/debug)
- [Android — Java Debug Wire Protocol (JDWP) overview](https://docs.oracle.com/javase/8/docs/technotes/guides/jpda/jdwp-spec.html)
- [Android — run-as command](https://developer.android.com/studio/command-line/adb)

### 5.3 Vulnerability Research & Technical Articles

- [NVD — CVE-2024-31317](https://nvd.nist.gov/vuln/detail/CVE-2024-31317)
- [NVD — CVE-2024-0044](https://nvd.nist.gov/vuln/detail/CVE-2024-0044)
- [Meta Red Team X — Bypassing the "run-as" debuggability check on Android via newline injection](https://rtx.meta.security/exploitation/2024/03/04/Android-run-as-forgery.html)
- [Talsec — Breaking the Android Sandbox and How to Defend Against It](https://docs.talsec.app/appsec-articles/articles/breaking-the-android-sandbox-and-how-to-defend-against-it)
- [HackTricks — Exploiting a debuggable application](https://book.hacktricks.wiki/en/mobile-pentesting/android-app-pentesting/exploiting-a-debuggeable-applciation.html)
- [Infosec Institute — Exploiting debuggable Android applications](https://www.infosecinstitute.com/resources/application-security/android-hacking-security-part-6-exploiting-debuggable-android-applications/)
- [Manifest Security — Android Application Security Part 21: Exploiting Debuggable Applications](https://manifestsecurity.com/android-application-security-part-21/)

### 5.4 Standards & Taxonomy

- [CWE-489: Active Debug Code](https://cwe.mitre.org/data/definitions/489.html)
- [CWE-215: Insertion of Sensitive Information Into Debugging Code](https://cwe.mitre.org/data/definitions/215.html)
- [CWE-1244: Internal Asset Exposed to Unsafe Debug Access](https://cwe.mitre.org/data/definitions/1244.html)
- [NIST SP 800-163 Rev.1 — Vetting the Security of Mobile Applications](https://csrc.nist.gov/publications/detail/sp/800-163/rev-1/final)

### 5.5 Tool Documentation

- [aapt2 — Android Asset Packaging Tool](https://developer.android.com/tools/aapt2)
- [apktool — Reverse engineering Android APK files](https://apktool.org/)
- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [Androguard — Android APK/DEX analysis library](https://github.com/androguard/androguard)
- [MobSF — Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)
- [jdb — The Java Debugger (Oracle documentation)](https://docs.oracle.com/javase/8/docs/technotes/tools/windows/jdb.html)
- [AndBug — Android debugging toolkit](https://github.com/swdunlop/AndBug)

---

*This document was prepared based on OWASP MASTG (current release as of September 2026), official Android Developers documentation, the 2024 Android Security Bulletin, and third-party vulnerability research (Meta Red Team X, GuardSquare-style analysis). This test does not yet have an official demo (MASTG-DEMO) from MASTG.*
