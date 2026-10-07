# MASTG-TEST-0201 Runtime Use of APIs to Access External Storage

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0201 |
| **Platform** | Android |
| **MASVS Category** | MASVS-STORAGE (MASVS-STORAGE-1: The app securely stores sensitive data) |
| **Weakness** | MASWE-0002 — *Sensitive Data Stored Unencrypted Outside of Private Storage* |
| **Test Type** | Dynamic, **Hooks**, Manual |
| **Profile** | L1, L2 |
| **Knowledge** | MASTG-KNOW-0042 (External Storage) |
| **Highlighted APIs** | `Environment#getExternalStorageDirectory`, `Environment#getExternalStoragePublicDirectory`, `Environment#getExternalFilesDir`, `Environment#getExternalCacheDir`, `FileOutputStream` |
| **Related Techniques** | MASTG-TECH-0005 (Installing Apps), MASTG-TECH-0043 (Method Hooking), MASTG-TECH-0023 (Reviewing Decompiled Java Code) |
| **Related Demo** | MASTG-DEMO-0002 (External Storage APIs Tracing with Frida) |
| **Related CWEs** | CWE-312 (Cleartext Storage of Sensitive Information), CWE-921 (Storage of Sensitive Data in a Mechanism without Access Control), CWE-200 (Exposure of Sensitive Information) |

---

## 1. Explanation

### 1.1 Testing Objective

This test aims to **identify which APIs the application actually invokes at runtime to access/write to external storage**, along with **what files result**, **who the caller is** (backtrace/stack trace), and **at which line of code** the write occurs.

Direct quote from the MASTG overview:

> *"Android apps use a variety of APIs to access the external storage. Collecting a comprehensive list of these APIs can be challenging, especially if an app uses a third-party framework, loads code at runtime, or includes native code."*
>
> *"The most effective approach to testing applications that write to device storage is usually dynamic analysis, and specifically method hooking. You can use it to hook into the relevant APIs such as `getExternalStorageDirectory`, `getExternalStoragePublicDirectory`, `getExternalFilesDir` or `FileOutputStream`. You could also use `open` as a catch-all for file interactions. However, this won't catch all file interactions, such as those that use the `MediaStore` API and should be done with additional filtering as it can generate a lot of noise."*

So, there are three key points from this overview that must be understood before testing:

1. **A complete list of APIs cannot possibly be gathered statically.** Third-party frameworks (React Native, Flutter, Unity, Cordova), code loaded at runtime (DexClassLoader, dynamic feature modules), and native code (JNI/NDK) always leave blind spots in static analysis. The approach therefore must be **dynamic**.
2. **libc's `open()` is used as a *catch-all*.** Almost all Java/Kotlin file I/O APIs (`FileOutputStream`, `FileWriter`, `RandomAccessFile`, `Files.write`) eventually descend to the `open()` syscall in libc — including native code. By hooking at this single point, we capture file operations from any layer.
3. **`open()` has a major blind spot: MediaStore.** And `open()` also generates **a great deal of noise**, so it must be filtered based on the external storage path prefix.

### 1.2 This Test's Position Within the MASVS-STORAGE Series

These three sibling tests complement each other and should ideally be run together:

| Test | Approach | Question Answered | Strength | Weakness |
|---|---|---|---|---|
| **MASTG-TEST-0200** | Dynamic — *filesystem diffing* (before/after snapshot) | "What files **actually appear** on disk?" | Real, fully API-agnostic evidence; cannot be fooled | Doesn't know **who** wrote them or **at which line of code**; doesn't catch files that are immediately deleted |
| **MASTG-TEST-0201** *(this document)* | Dynamic — **method hooking/instrumentation** | "**Which API** is called, by **which code**?" | Precise attribution to code line & library; catches temporary files (write→delete); catches native code | Needs Frida/root; can be blocked by anti-instrumentation; only catches exercised flows |
| **MASTG-TEST-0202** | Static — manifest & API reference reverse engineering | "Which API & permission is **referenced**?" | 100% coverage of existing code, without running the app | Many false positives (dead code, unused library); blind to dynamic/native/obfuscated code |

**TEST-0201's unique value** compared to TEST-0200: TEST-0200 only gives a list of paths. TEST-0201 gives a **backtrace** — so you can distinguish whether a file was written by the app's own code or by a **third-party SDK** (analytics, crash reporter, image loader), and can point directly to the line of code the developer needs to fix. This is what makes this test's findings highly *actionable*.

In addition, TEST-0201 catches cases that **slip past** TEST-0200:
- Files that are written and then **immediately deleted** (temp files) — they don't appear in the filesystem diff, but still briefly exposed data to other apps during that time window.
- Files written to a path not reachable by `find /sdcard/` (secondary storage, unusual paths).
- **Read** operations from external storage — relevant for Man-in-the-Disk risk, where the application loads untrusted data/code.

### 1.3 Map of External Storage APIs That Need to Be Hooked

Understanding the API layers is essential so hooking doesn't leak coverage.

**Layer A — Path resolution APIs (telling you *where* the app will write):**

| API | Path Returned | Security Note |
|---|---|---|
| `Context.getExternalFilesDir(String type)` | `/sdcard/Android/data/<pkg>/files/...` | App-specific external. Protected by scoped storage (API 29+), **not** before that. Removed on uninstall. |
| `Context.getExternalCacheDir()` | `/sdcard/Android/data/<pkg>/cache/` | Same as above. |
| `Context.getExternalMediaDirs()` | `/sdcard/Android/media/<pkg>/` | Visible in MediaStore → accessible by other apps with media permission. |
| `Environment.getExternalStorageDirectory()` | `/sdcard/` | **Deprecated (API 29)**. Shared storage — the riskiest. A legacy code indicator. |
| `Environment.getExternalStoragePublicDirectory(String type)` | `/sdcard/Download/`, `/sdcard/Documents/`, `/sdcard/DCIM/` | **Deprecated (API 29)**. Shared, accessible by other apps, **persists post-uninstall**. |
| `Context.getExternalFilesDirs()` / `ContextCompat.getExternalFilesDirs()` | Includes secondary SD card | A physical SD card can be removed and read on another device. |

> **Important:** merely calling a path resolution API does **not** necessarily mean a write occurred. Hooking at this layer is useful for mapping *intent*, but evidence of an actual write must come from Layer B/C. Don't jump straight to a FAIL conclusion just because `getExternalFilesDir` was called.

**Layer B — Java/Kotlin write APIs (performing the actual I/O):**

- `java.io.FileOutputStream` (constructor), `java.io.FileWriter`, `java.io.RandomAccessFile`
- `java.io.File.createNewFile()`, `File.mkdirs()`, `File.delete()`
- `java.nio.file.Files.write()` / `newOutputStream()` / `copy()`
- Kotlin: `File.writeText()`, `File.writeBytes()`, `File.appendText()` (all wrappers over `FileOutputStream`)
- `android.content.ContentResolver.openOutputStream()` / `openFileDescriptor()`
- High-level serialization: `ObjectOutputStream`, `Properties.store()`, `Bitmap.compress()`, `ZipOutputStream`
- `android.app.DownloadManager.enqueue()` — downloads directly to shared storage

**Layer C — Native/libc layer (catch-all):**

- `open()`, `openat()`, `creat()` — the convergence point for all file I/O, including from NDK code
- `fopen()`, `rename()`, `unlink()`, `mkdir()`
- Hooking here catches **everything** that slips past Layer B, including third-party native libraries

**Layer D — MediaStore / ContentResolver (the `open()` blind spot):**

Official MASTG-DEMO-0002 note:

> *"When apps write files using the `ContentResolver.insert()` method, the files are managed by Android's MediaStore and are identified by `content://` URIs, not direct file system paths. This design abstracts the actual file locations, making them inaccessible through standard file system operations like the `open` function in libc. Consequently, when using Frida to hook into file operations, intercepting calls to `open` won't reveal these files."*

This means: **hooking `open()` alone is NOT ENOUGH.** You must also hook:
- `ContentResolver.insert(Uri, ContentValues)` — to capture MediaStore entry creation
- `ContentResolver.openOutputStream(Uri)` — to capture file content writes
- `MediaStore.createWriteRequest()` (API 30+), `MediaSessionManager`

The final path must be **reconstructed** from `ContentValues`: the combination of `relative_path` + `_display_name`. Example from the demo: `relative_path: Download` + `_display_name: secretFile55.txt` → `/storage/emulated/0/Download/secretFile55.txt`.

**Layer E — Storage Access Framework and others:**
- `Intent.ACTION_CREATE_DOCUMENT` / `ACTION_OPEN_DOCUMENT` → `ContentResolver.openOutputStream()`
- `DocumentFile.createFile()` (androidx.documentfile)
- `MANAGE_EXTERNAL_STORAGE` + direct `File` API access to arbitrary paths

### 1.4 Risks Confirmed by This Test

This test validates the same exposure as MASTG-TEST-0200 (see that document for details), but from a code-attribution angle:

1. **Cross-app information disclosure** — plaintext files on external storage read by other apps (especially targeting API ≤ 29 or `requestLegacyExternalStorage="true"`).
2. **Man-in-the-Disk** (Check Point, DEF CON 2018) — an attacker overwrites data written/read by the app on external storage; potentially leads to DoS, crashes, or even **code injection within the privileged context of the target app**. This test is very effective at detecting this risk because hooking `open()` also catches **read** operations, so you can observe the app loading a file from `/sdcard` and trace it to the code line processing it.
3. **Leakage via third-party SDKs** — this is a distinctive advantage of this test. The backtrace will show packages like `com.google.firebase.crashlytics.*`, `com.squareup.picasso.*`, or `io.branch.*` as the caller, which developers often aren't aware of.
4. **Post-uninstall persistence** — files written via MediaStore to `Download/`, `Documents/` are not deleted when the app is uninstalled.
5. **Leakage from native code** — libc hooks catch writes from `.so` files that are invisible in DEX analysis.

---

## 2. Tools Used for Testing

### 2.1 Required Tools (Core)

| Tool | MASTG ID | Function in This Test |
|---|---|---|
| **Frida** | MASTG-TOOL-0001 | **The primary tool.** Dynamic instrumentation: hook `libc!open`, `ContentResolver.insert`, `FileOutputStream`, print backtraces. `frida` CLI for spawn + script injection. |
| **frida-server** | — | A daemon that must run on the device (requires root) — or use **frida-gadget** injected into the APK for non-root devices. |
| **adb** | MASTG-TOOL-0004 | APK installation, pushing frida-server, port forwarding, verifying found files. |
| **Android device / emulator (rooted)** | MASTG-TOOL-0003 | Target. An AVD emulator with a *Google APIs* image (not Google Play) is recommended for easy rooting via `adb root`. |
| **jadx** | MASTG-TOOL-0018 | **Required for the evaluation step.** MASTG-TECH-0023 directs us to review code locations from the backtrace to determine whether the code path is security-relevant. |

### 2.2 Alternative and Supporting Tools

| Tool | Function |
|---|---|
| **frida-trace** | A quick alternative without writing a script. `-i "open"` for native functions, `-j '<Class>!<method>'` for Java methods (supports the `/isu` modifiers: `s`=include signature, `i`=case-insensitive, `u`=user-defined classes only). Excellent for hooking thousands of functions at once with wildcards `*`. |
| **Objection** | MASTG-TOOL-0038. A ready-to-use Frida wrapper: `android hooking watch class_method java.io.FileOutputStream.$init --dump-args --dump-backtrace`, plus `filesystem download` to pull found files. Suitable for quick testing. |
| **jnitrace** | Tracing JNI API calls — important when the app writes files from native code via JNI. |
| **frida-gadget** | For **non-rooted** devices: inject the gadget into the APK (repackaging with objection/apktool + apksigner), then instrument without root. |
| **Xposed / LSPosed** | An alternative method-hooking framework (MASTG-TECH-0043). More persistent but less flexible for ad-hoc tracing than Frida. |
| **strace** | OS-level syscall tracing (`strace -f -e trace=openat,write -p <pid>`). Useful as an independent comparison when the app has anti-Frida. |
| **apktool** | MASTG-TOOL-0011. Decode the binary manifest to check `targetSdkVersion`, `requestLegacyExternalStorage`, storage permissions. |
| **`file`, `strings`, `xxd`, `ent`, `sqlite3`** | Inspect found file contents — including entropy analysis to distinguish genuine encryption from mere encoding. |
| **MASTestApp** | MASTG's reference app for validating scripts/tooling before applying them to the target. |

### 2.3 Environment Prerequisites

- **Root or frida-gadget.** This is a hard prerequisite; without one of these, method hooking is impossible. This is the main distinguishing factor compared to MASTG-TEST-0200, which can run without root.
- **The frida-server version must match the host's frida CLI version** (version mismatch is the most common error cause). The architecture must also be correct (`arm64`, `x86_64`).
- The application installed (`adb install -g` so all runtime permissions are granted and every flow is reachable).
- A **unique canary value** for each input (e.g., `MASTG_Pa55w0rd_UNIQ`) — makes it easier to grep file contents and correlate with trace output.
- **Anticipate anti-instrumentation.** Many production apps (especially financial ones) detect Frida/root and will exit. If this happens, bypass the detection first (refer to MASVS-RESILIENCE / MASTG-TECH-0043) — and **document it as a separate finding**, not as an excuse to skip this test. Alternatively, rely on MASTG-TEST-0200, which does not require instrumentation.
- A clean device/emulator snapshot to minimize baseline noise.

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0005** (*Installing Apps*) to install the application.
2. Use **MASTG-TECH-0043** (*Method Hooking*) to hook the relevant API calls.
3. **Exercise the app extensively** to trigger as many flows as possible, entering sensitive data wherever possible.

Then for evaluation, use **MASTG-TECH-0023** (*Reviewing Decompiled Java Code*) to inspect the code location from the backtrace, to determine the exact code path that produced the file and whether that code path is security-relevant.

### 3.2 Practical Implementation (MASTG-DEMO-0002)

**Step 0 — Set Up Frida**

```bash
# Check the frida version on the host
frida --version

# Download frida-server matching the device's version & architecture
adb shell getprop ro.product.cpu.abi      # -> e.g. x86_64 / arm64-v8a

# Push and run frida-server on the device
adb push frida-server-<version>-android-<arch> /data/local/tmp/frida-server
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "su -c /data/local/tmp/frida-server &"

# Verify the connection
frida-ps -U | head

# Install the target application with all permissions granted
adb install -g ./target-app.apk
```

**Step 1 — Hooking Script (`script.js`)**

This is the official script from MASTG-DEMO-0002:

```javascript
function printBacktrace(maxLines = 8) {
    Java.perform(() => {
        let Exception = Java.use("java.lang.Exception");
        let stackTrace = Exception.$new().getStackTrace().toString().split(",");
        console.log("\nBacktrace:");
        for (let i = 0; i < Math.min(maxLines, stackTrace.length); i++) {
            console.log(stackTrace[i]);
        }
    });
};

// Intercept libc's open to make sure we cover all Java I/O APIs
Interceptor.attach(
    Process.getModuleByName('libc.so').getExportByName('open'),
    {
        onEnter: function(args) {
            const external_paths = ['/sdcard', '/storage/emulated'];
            const path = args[0].readCString();
            external_paths.forEach(external_path => {
                if (path.indexOf(external_path) === 0) {
                    console.log(`\n[*] open called to open a file from external storage at: ${path}`);
                    printBacktrace(15);
                }
            });
        }
    }
);

// Hook ContentResolver.insert to log ContentValues (including keys like
// _display_name, mime_type, and relative_path) and returned URI
Java.perform(() => {
    let ContentResolver = Java.use("android.content.ContentResolver");
    ContentResolver.insert.overload('android.net.Uri', 'android.content.ContentValues')
      .implementation = function(uri, values) {
        console.log(`\n[*] ContentResolver.insert called with ContentValues:`);
        console.log(`\t_display_name: ${values.get("_display_name").toString()}`);
        console.log(`\tmime_type: ${values.get("mime_type").toString()}`);
        console.log(`\trelative_path: ${values.get("relative_path").toString()}`);

        let result = this.insert(uri, values);
        console.log(`\n[*] ContentResolver.insert returned URI: ${result.toString()}`);
        printBacktrace();
        return result;
    };
});
```

Note two important design choices in this script:
- **Path filtering** (`['/sdcard', '/storage/emulated']`) is applied directly in `onEnter` — this is the "additional filtering" MASTG requires to deal with noise from `open()`.
- **`ContentResolver.insert` is hooked separately** — because MediaStore is invisible to the `open()` hook.

**Step 2 — Run (`run.sh`)**

```bash
#!/bin/bash

# SUMMARY: This script uses frida to trace files that an app has opened since it spawned.
# The script filters the output of frida-trace to print only the paths belonging to external
# storage but the predefined list of external storage paths might not be complete.
# A sample output is shown in "output.txt". If the output is empty, it indicates that no
# external storage is used.

frida \
    -U \
    -f org.owasp.mastestapp \
    -l script.js \
    -o output.txt
```

**Step 3 — Exercise the App**

Open the app and run as many flows as possible systematically, with a canary value at every input:

- Registration, login, logout, re-login, "remember me", biometrics/2FA, password reset, OTP
- Complete the profile (name, national ID, address, phone, upload ID documents/photos)
- Add a payment method, make a transaction, download an invoice/e-statement
- Upload & download attachments, export data, share, print
- Camera, gallery, document scanner, voice notes
- Chat/messaging, search history, drafts
- Offline mode (turn off network → trigger local caching), then back online
- Repeated background/foreground, screen rotation, force-stop then reopen
- Trigger errors/crashes if possible (triggering a crash dump to disk)
- Enable all toggles in Settings, including debug/developer options if present

**Step 4 — Stop and Analyze**

Press `Ctrl+C` to end, then analyze `output.txt`.

### 3.3 Recommended Script Extensions

The MASTG demo script is intentionally minimal for educational purposes. For real-world testing, the script has several practical limitations that should be addressed:

1. **`values.get("...")` can return `null`** if the key does not exist, and `.toString()` will then crash, failing the hook. A null check is needed.
2. **Only `open` is hooked**, not `openat` — yet modern Android/bionic widely uses `openat`.
3. **The path filter does not yet cover** secondary/removable storage (`/storage/XXXX-XXXX`) and `/mnt/media_rw`.
4. **`ContentResolver.openOutputStream` is not hooked**, even though that is the point where MediaStore file content is written.
5. **Read operations are not distinguished from write operations** — yet for Man-in-the-Disk, read operations are actually the important ones.

An extended version:

```javascript
function printBacktrace(maxLines = 12) {
    Java.perform(() => {
        const Exception = Java.use("java.lang.Exception");
        const stackTrace = Exception.$new().getStackTrace();
        console.log("\nBacktrace:");
        for (let i = 0; i < Math.min(maxLines, stackTrace.length); i++) {
            console.log("  " + stackTrace[i].toString());
        }
    });
}

const EXTERNAL_PREFIXES = [
    '/sdcard',
    '/storage/emulated',
    '/storage/self/primary',
    '/mnt/sdcard',
    '/mnt/media_rw',
    '/storage/'            // captures removable storage /storage/XXXX-XXXX
];

function isExternal(path) {
    if (!path) return false;
    return EXTERNAL_PREFIXES.some(p => path.indexOf(p) === 0);
}

// Decode O_WRONLY/O_RDWR/O_CREAT flags so read can be distinguished from write
function decodeFlags(flags) {
    const acc = flags & 3;                       // O_ACCMODE
    let s = (acc === 0) ? "O_RDONLY" : (acc === 1) ? "O_WRONLY" : "O_RDWR";
    if (flags & 0x40)  s += "|O_CREAT";
    if (flags & 0x400) s += "|O_APPEND";
    if (flags & 0x200) s += "|O_TRUNC";
    return s;
}

// --- Layer C: native catch-all (open AND openat) ---
['open', 'openat'].forEach(fn => {
    const addr = Process.getModuleByName('libc.so').findExportByName(fn);
    if (!addr) return;
    Interceptor.attach(addr, {
        onEnter(args) {
            // open(path, flags) | openat(dirfd, path, flags)
            const pathArg  = (fn === 'open') ? args[0] : args[1];
            const flagsArg = (fn === 'open') ? args[1] : args[2];
            const path = pathArg.readCString();
            if (isExternal(path)) {
                console.log(`\n[*] ${fn}() on external storage: ${path}` +
                            `  [${decodeFlags(flagsArg.toInt32())}]`);
                printBacktrace(15);
            }
        }
    });
});

// --- Layer D: MediaStore / ContentResolver ---
Java.perform(() => {
    const ContentResolver = Java.use("android.content.ContentResolver");

    // Safely (null-safe) retrieve a ContentValues value
    function safeGet(values, key) {
        try {
            const v = values.get(key);
            return (v === null) ? "<null>" : v.toString();
        } catch (e) { return "<n/a>"; }
    }

    ContentResolver.insert.overload('android.net.Uri', 'android.content.ContentValues')
      .implementation = function (uri, values) {
        const name = safeGet(values, "_display_name");
        const mime = safeGet(values, "mime_type");
        const rel  = safeGet(values, "relative_path");
        console.log(`\n[*] ContentResolver.insert()`);
        console.log(`\ttarget uri     : ${uri}`);
        console.log(`\t_display_name  : ${name}`);
        console.log(`\tmime_type      : ${mime}`);
        console.log(`\trelative_path  : ${rel}`);
        // Reconstruct the estimated path
        console.log(`\t=> inferred path: /storage/emulated/0/${rel}/${name}`);
        const result = this.insert(uri, values);
        console.log(`\treturned URI   : ${result}`);
        printBacktrace();
        return result;
      };

    // The point where MediaStore / SAF file content is written
    ContentResolver.openOutputStream.overload('android.net.Uri')
      .implementation = function (uri) {
        console.log(`\n[*] ContentResolver.openOutputStream(): ${uri}`);
        printBacktrace();
        return this.openOutputStream(uri);
      };
});

// --- Layer A: path resolution APIs (mapping "intent") ---
Java.perform(() => {
    const Ctx = Java.use("android.content.ContextWrapper");
    Ctx.getExternalFilesDir.implementation = function (type) {
        const r = this.getExternalFilesDir(type);
        console.log(`\n[*] getExternalFilesDir("${type}") -> ${r}`);
        printBacktrace(10);
        return r;
    };
    Ctx.getExternalCacheDir.implementation = function () {
        const r = this.getExternalCacheDir();
        console.log(`\n[*] getExternalCacheDir() -> ${r}`);
        printBacktrace(10);
        return r;
    };

    const Env = Java.use("android.os.Environment");
    Env.getExternalStorageDirectory.implementation = function () {
        const r = this.getExternalStorageDirectory();
        console.log(`\n[!] DEPRECATED getExternalStorageDirectory() -> ${r}`);
        printBacktrace(10);
        return r;
    };
    Env.getExternalStoragePublicDirectory.implementation = function (type) {
        const r = this.getExternalStoragePublicDirectory(type);
        console.log(`\n[!] DEPRECATED getExternalStoragePublicDirectory("${type}") -> ${r}`);
        printBacktrace(10);
        return r;
    };
});

// --- Bonus: peek at written content to detect plaintext directly ---
Java.perform(() => {
    const FOS = Java.use("java.io.FileOutputStream");
    FOS.write.overload('[B', 'int', 'int').implementation = function (b, off, len) {
        try {
            const preview = Java.use("java.lang.String").$new(b, off, Math.min(len, 200));
            console.log(`\n[*] FileOutputStream.write() ${len} bytes, preview: ${preview}`);
        } catch (e) { /* binary data, ignore */ }
        return this.write(b, off, len);
    };
});
```

> The `FileOutputStream.write()` hook above is very helpful: it shows the **content** being written directly, so you can detect plaintext without having to pull the file from the device. But it is also a major source of noise — enable it only when needed.

### 3.4 Quick Alternatives with frida-trace and Objection

**frida-trace** (without writing a script):

```bash
# Trace the native open function (catch-all, high noise)
frida-trace -U -f org.owasp.mastestapp -i "open" -i "openat" -o trace.txt

# Trace Java methods related to storage; modifier /isu:
#   i = case-insensitive, s = include signature, u = user-defined classes only
frida-trace -U -f org.owasp.mastestapp --runtime=v8 \
  -j 'java.io.FileOutputStream!*' \
  -j 'android.content.ContentResolver!insert*' \
  -j '*!*ExternalStorage*/isu' \
  -j '*!*ExternalFilesDir*/isu' \
  -o trace.txt
```

**Objection** (fastest for exploratory testing):

```bash
objection -g org.owasp.mastestapp explore

# Inside the objection shell:
android hooking watch class_method java.io.FileOutputStream.$init --dump-args --dump-backtrace
android hooking watch class_method android.content.ContentResolver.insert --dump-args --dump-backtrace
android hooking watch class_method android.os.Environment.getExternalStorageDirectory --dump-backtrace

# Pull the found file directly
ls /sdcard/Android/data/org.owasp.mastestapp/files
filesystem download /sdcard/Android/data/org.owasp.mastestapp/files/secret.txt
```

**strace** as an independent comparison (useful when anti-Frida is present):

```bash
adb shell "su -c 'strace -f -e trace=openat,write -p $(pidof org.owasp.mastestapp)'" \
  | grep -E "/sdcard|/storage/emulated"
```

### 3.5 Mandatory Confirmation Step (Further Evaluation)

MASTG explicitly requires this step — do not stop at the trace output.

```bash
# 1. Pull the identified file from the trace, then inspect its contents
adb pull /storage/emulated/0/Android/data/org.owasp.mastestapp/files/secret.txt
adb pull /storage/emulated/0/Download/secretFile55.txt

file secret.txt secretFile55.txt
cat secret.txt

# 2. Search for the canary value & sensitive patterns
grep -riE "MASTG_Pa55w0rd_UNIQ|password|passwd|secret|token|api[_-]?key|bearer|authorization|BEGIN (RSA|EC|OPENSSH|PRIVATE) KEY|[0-9]{16}" .

# 3. Test whether the data is actually encrypted (not merely encoded)
ent secret.txt                 # entropy ~7.9+ bits/byte => likely encrypted
strings -n 6 secret.txt
base64 -d secret.txt 2>/dev/null | head   # check if it's just Base64

# 4. Verify the MediaStore path reconstructed from ContentValues
adb shell content query --uri content://media/external/downloads \
  --projection _id:_display_name:relative_path:owner_package_name:_data

# 5. MASTG-TECH-0023 — trace the code location from the backtrace
#    Open the APK in jadx, navigate to the class & line named in the backtrace
jadx -d ./decompiled ./target-app.apk
grep -rn "getExternalFilesDir\|MediaStore\|getExternalStoragePublicDirectory" ./decompiled/sources/

# 6. Check scoped storage configuration to determine severity
grep -E "targetSdkVersion|requestLegacyExternalStorage|preserveLegacyExternalStorage" \
  ./decoded/AndroidManifest.xml
adb shell dumpsys package org.owasp.mastestapp | grep -iE "targetSdk|EXTERNAL_STORAGE|READ_MEDIA"

# 7. Test exploitability: read from another app's context
adb shell run-as <another_test_package> cat \
  /sdcard/Android/data/org.owasp.mastestapp/files/secret.txt
```

### 3.6 Additional Alternative Testing Methods (Multi-Tool)

§3.4 already covers frida-trace, Objection, and strace. Below are additional paths for harder situations — especially **non-root devices**, **anti-instrumentation**, and **native code**.

#### Method E — frida-gadget *(instrumentation without root)*

This is the most important path if you don't have a rooted device. `frida-gadget` is injected into the APK so that the app "carries" its own Frida.

```bash
# The easiest way: objection does automatic repackaging
pip install objection
objection patchapk --source ./target-app.apk
#   -> produces target-app.objection.apk with the gadget embedded

adb install ./target-app.objection.apk
# The app will PAUSE at startup waiting for a connection:
frida -U Gadget -l script.js

# Manual method (more control):
apktool d -f -o ./app ./target-app.apk
cp frida-gadget-<ver>-android-arm64.so ./app/lib/arm64-v8a/libgadget.so
#   then add System.loadLibrary("gadget") in the Application class's <clinit> (smali)
apktool b -o repacked.apk ./app
apksigner sign --ks debug.keystore repacked.apk
```

> **Note as a separate finding:** if repackaging + installation succeeds, that means the app has no integrity/signature check — an MASVS-RESILIENCE weakness (MASTG-TEST-0224 and related).

#### Method F — Xposed / LSPosed module *(an alternative hooking method that's harder to detect)*

MASTG-TECH-0043 names Xposed as a legitimate hooking method. LSPosed (a modern implementation based on Zygisk/Riru) often escapes detection targeted specifically at Frida.

```java
// ExternalStorageMonitor.java — LSPosed module
public class ExternalStorageMonitor implements IXposedHookLoadPackage {
    @Override
    public void handleLoadPackage(final LoadPackageParam lpparam) throws Throwable {
        if (!lpparam.packageName.equals("com.example.target")) return;

        // Hook getExternalFilesDir
        findAndHookMethod("android.content.ContextWrapper", lpparam.classLoader,
            "getExternalFilesDir", String.class, new XC_MethodHook() {
                @Override protected void afterHookedMethod(MethodHookParam param) {
                    XposedBridge.log("[ExtStorage] getExternalFilesDir -> " + param.getResult());
                    XposedBridge.log(android.util.Log.getStackTraceString(new Throwable()));
                }
            });

        // Hook FileOutputStream constructor
        findAndHookConstructor("java.io.FileOutputStream", lpparam.classLoader,
            java.io.File.class, new XC_MethodHook() {
                @Override protected void beforeHookedMethod(MethodHookParam param) {
                    String p = param.args[0].toString();
                    if (p.startsWith("/sdcard") || p.startsWith("/storage/emulated")) {
                        XposedBridge.log("[ExtStorage] write -> " + p);
                        XposedBridge.log(android.util.Log.getStackTraceString(new Throwable()));
                    }
                }
            });
    }
}
```

```bash
# Module output appears in logcat with the LSPosed tag
adb logcat -s LSPosed:V | grep ExtStorage
```

Advantage: persistent across app restarts, and no `frida-server` process is running to be detected. Weakness: requires compiling a module APK and rebooting to activate.

#### Method G — jnitrace *(file writes from native code via JNI)*

If the app calls Java APIs from native code, a plain Java hook will see the call but its backtrace will be uninformative. `jnitrace` shows the entire JNI interaction.

```bash
pip install jnitrace
jnitrace -m libnative.so com.example.target | tee jnitrace.log

# Filter relevant calls
grep -A5 -iE "getExternalFilesDir|FileOutputStream|MediaStore" jnitrace.log
```

#### Method H — r2frida *(native analysis + hooking in a single session)*

```bash
r2 frida://usb//com.example.target

# Inside r2:
\i                                   # process info
\il                                  # list loaded modules
\iE libnative.so                     # exports from a native library
\dt libc.so!openat                   # trace openat
\dtf libc.so!openat "^z i"           # trace with arguments (string, int)
\is~open                             # search for symbols containing "open"
```

Useful when a file write originates from a `.so` and you need to analyze its native function at the same time.

#### Method I — fsmon / inotifywait *(monitoring without instrumenting the app)*

This path **completely avoids anti-instrumentation** because it does not touch the application at all.

```bash
# fsmon (NowSecure) — kernel-level monitoring
adb push fsmon-arm64 /data/local/tmp/fsmon && adb shell "chmod 755 /data/local/tmp/fsmon"
adb shell "su -c '/data/local/tmp/fsmon -P com.example.target /sdcard'" | tee fsmon.log

# inotifywait (if available on the ROM/BusyBox)
adb shell "su -c 'inotifywait -m -r -e create,modify,delete,moved_to /sdcard'"
```

Limitation: provides no backtrace, so it cannot attribute a write to a line of code. Use it as **independent confirmation** that a write did in fact occur.

#### Method J — MobSF Dynamic Analyzer *(automated, report-ready)*

```bash
docker run -it --rm -p 8000:8000 -p 1337:1337 \
  opensecurity/mobile-security-framework-mobsf:latest
```

MobSF runs Frida behind the scenes and provides a **Runtime Dependency Check** section and an **API Monitor** that records sensitive API calls — including file I/O. Advantage: no script-writing needed, and the results come directly in a report format. Limitation: its automated exercise is shallow and its hooks are generic, so this is an initial pass — not a replacement for a custom script.

#### Method K — Correlation with Static Analysis *(determining test coverage)*

This is not a new tool, but a methodological step that is often skipped and that determines the validity of a PASS conclusion.

```bash
# 1. Get the COMPLETE list of API references from static analysis (MASTG-TEST-0202)
jadx -d ./decompiled ./target-app.apk
rg -n --no-heading "getExternalFilesDir|getExternalStorageDirectory|getExternalCacheDir|MediaStore" \
  ./decompiled/sources/ | awk -F: '{print $1}' | sort -u > static_refs.txt

# 2. Get the list of APIs ACTUALLY called from the runtime trace
grep -oE "org\.owasp\.[A-Za-z0-9.$]+" output.txt | sort -u > runtime_hits.txt

# 3. The difference = code paths NOT YET exercised
#    -> status INCONCLUSIVE for these paths, not PASS
comm -23 static_refs.txt runtime_hits.txt
```

If the difference is not empty, you have not exercised the full surface — and must not conclude PASS. This is a concrete way to carry out assessment note #1 in §3.8.

---

### 3.7 Method Comparison: When to Use Which

| Method | Tool | Needs root? | Gives backtrace? | Catches native code? | Resistant to anti-Frida? | When to use |
|---|---|---|---|---|---|---|
| **A** | Custom Frida script (§3.2/§3.3) | Yes/gadget | ✅ | ✅ (libc hook) | ❌ | **Official baseline** — full control |
| **B** | frida-trace (§3.4) | Yes/gadget | Partial | ✅ | ❌ | Fast, no script writing |
| **C** | Objection (§3.4) | No¹ | ✅ | ❌ | ❌ | Fast exploratory testing; `filesystem download` |
| **D** | strace (§3.4) | Yes | ❌ | ✅ | ✅ | Independent comparison when anti-Frida is present |
| **E** | frida-gadget | **No** | ✅ | ✅ | ❌ | **Non-root device**; successful repackaging = MASVS-RESILIENCE finding |
| **F** | Xposed / LSPosed | Yes | ✅ | ❌ | ✅ (harder to detect) | Active anti-Frida; needs persistence |
| **G** | jnitrace | Yes | ✅ (JNI) | ✅ **(specialized)** | ❌ | File writes from `.so` via JNI |
| **H** | r2frida | Yes | Partial | ✅ **(specialized)** | ❌ | Native analysis + hooking at once |
| **I** | fsmon / inotifywait | Yes | ❌ | ✅ | ✅ **(doesn't touch the app)** | Independent confirmation; strong anti-instrumentation |
| **J** | MobSF Dynamic | No | Partial | ❌ | ❌ | Initial pass + report-ready output |
| **K** | Static–dynamic correlation | No | — | — | — | **Determines whether a PASS is valid** — mandatory |

¹ Objection uses Frida; without root it needs frida-gadget (Method E) or a device with frida-server.

**Minimum recommended combination:** **A (custom Frida) → K (static-dynamic correlation)**.
A gives the backtrace and runtime values that are the core of this test; K ensures your conclusion is valid by proving the entire surface was exercised. Add **E (frida-gadget)** when there's no root, **D or I** when the app has anti-instrumentation, and **G/H** when the APK bundles a `.so` that writes files.

> **If all instrumentation paths are blocked:** do not report PASS. The status is **Inconclusive**, and resolve the assessment via **MASTG-TEST-0200** (filesystem diffing, no instrumentation needed) and **MASTG-TEST-0202** (static).

---

### 3.8 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rule:**

> **Observation:** *"The output should contain a list of files that the app wrote to the external storage during execution and the APIs used to write them including function names and backtraces."*
>
> **Evaluation:** *"The test case **fails** if the files found above are not encrypted and leak sensitive data."*
>
> **Further Validation Required** — inspect the content of every reported file:
> - Determine whether the file contains sensitive information (e.g., personal data, credentials, or tokens).
> - Determine whether the data is stored without encryption.
>
> Use MASTG-TECH-0023 to inspect the code location from the backtrace if you want to determine the exact code path that produced the file and whether that code path is security-relevant.

Both conditions are an **AND**: sensitive file **AND** not encrypted → FAIL.

---

#### ❌ FAIL / ISSUE — The check is declared FAILED if:

| No | Condition | Example evidence from trace output |
|---|---|---|
| F1 | The trace shows a write to external storage, and the resulting file contains **sensitive plaintext data** | `[*] open called ... /storage/emulated/0/Android/data/<pkg>/files/secret.txt` + backtrace `FileOutputStream.<init>` → file content = `secr3tPa$$W0rd` |
| F2 | The `ContentResolver.insert` trace shows a sensitive file write to **shared storage** | `_display_name: secretFile55.txt`, `relative_path: Download` → `/storage/emulated/0/Download/secretFile55.txt` contains `MAS_API_KEY=8767086b9f6f976g-a8df76` |
| F3 | The `FileOutputStream.write()` hook shows a **canary value/credential** directly in the written buffer | `preview: {"user":"tester","password":"MASTG_Pa55w0rd_UNIQ"}` |
| F4 | The backtrace points to **the app's own code** writing sensitive data without encryption | `org.owasp.mastestapp.MastgTest.mastgTestApi(MastgTest.kt:26)` |
| F5 | The backtrace points to **a third-party SDK** writing sensitive/PII data to external storage | Backtrace contains `com.<vendor>.crashlytics.*` / `com.<vendor>.analytics.*` writing `/sdcard/.../crash_<ts>.log` containing a token |
| F6 | A call to a **high-risk deprecated API** is detected followed by a sensitive data write | `[!] DEPRECATED getExternalStoragePublicDirectory("Documents")` + backtrace + plaintext file |
| F7 | The "encryption" observed is merely **encoding/obfuscation** (Base64, hex, hardcoded XOR key) | `base64 -d` directly yields plaintext; `ent` → entropy < 6.0 bits/byte |
| F8 | The file is encrypted but **the key is also written** to external storage, or is hardcoded (visible from trace/decompile) | Trace shows a `key.bin` write in the same directory; or jadx shows `SecretKeySpec("hardcodedkey".getBytes(), "AES")` |
| F9 | The trace shows the app **reading** a file from external storage and then loading it as executable code/configuration without an integrity check | `openat() ... /sdcard/MyApp/plugin.dex [O_RDONLY]` + backtrace `DexClassLoader.<init>` → **Man-in-the-Disk / code injection** |
| F10 | The trace shows a write of a **temporary file** containing sensitive data to external storage (even if later deleted) | `open() ... /sdcard/tmp_upload_ktp.jpg [O_WRONLY\|O_CREAT]` — slips past TEST-0200 but still FAILs |
| F11 | The sensitive data write occurs on an app that has **opted out of scoped storage** (`requestLegacyExternalStorage="true"` with target ≤ API 29) | Manifest + finding F1/F2 → severity raised |

**Example output indicating FAIL** (official MASTG-DEMO-0002 result, `output.txt`):

```
[*] open called to open a file from external storage at: /storage/emulated/0/Android/data/org.owasp.mastestapp/files/secret.txt

Backtrace:
libcore.io.Linux.open(Native Method)
libcore.io.ForwardingOs.open(ForwardingOs.java:563)
libcore.io.BlockGuardOs.open(BlockGuardOs.java:274)
libcore.io.ForwardingOs.open(ForwardingOs.java:563)
android.app.ActivityThread$AndroidOs.open(ActivityThread.java:8063)
libcore.io.IoBridge.open(IoBridge.java:560)
java.io.FileOutputStream.<init>(FileOutputStream.java:236)
java.io.FileOutputStream.<init>(FileOutputStream.java:186)
org.owasp.mastestapp.MastgTest.mastgTestApi(MastgTest.kt:26)
org.owasp.mastestapp.MastgTest.mastgTest(MastgTest.kt:16)
org.owasp.mastestapp.MainActivityKt.MainScreen$lambda$9$lambda$8(MainActivity.kt:53)
...
java.lang.Thread.run(Thread.java:1012)

[*] ContentResolver.insert called with ContentValues:
        _display_name: secretFile59.txt
        mime_type: text/plain
        relative_path: Download

[*] ContentResolver.insert returned URI: content://media/external/downloads/1000000143

Backtrace:
android.content.ContentResolver.insert(Native Method)
org.owasp.mastestapp.MastgTest.mastgTestMediaStore(MastgTest.kt:44)
org.owasp.mastestapp.MastgTest.mastgTest(MastgTest.kt:17)
org.owasp.mastestapp.MainActivityKt.MainScreen$lambda$9$lambda$8(MainActivity.kt:53)
...
java.lang.Thread.run(Thread.java:1012)
```

**How to read the output above** — this is the heart of this test's value:

| Finding | Path | API Used | Code Location (from backtrace) |
|---|---|---|---|
| 1 | `/storage/emulated/0/Android/data/org.owasp.mastestapp/files/secret.txt` | `java.io.FileOutputStream` | `MastgTest.mastgTestApi(MastgTest.kt:26)` |
| 2 | `secretFile59.txt` → URI `content://media/external/downloads/1000000143`, **estimated path** `/storage/emulated/0/Download/secretFile59.txt` | `android.content.ContentResolver.insert` | `MastgTest.mastgTestMediaStore(MastgTest.kt:44)` |

Note the diagnostic pattern in the first backtrace: the chain `Linux.open → BlockGuardOs.open → IoBridge.open → FileOutputStream.<init>` is a **distinctive fingerprint** of a file write via Java I/O. The last frame before entering the framework (`MastgTest.kt:26`) is the **code location that needs to be fixed**.

Also note that the second finding **did not appear in the `open()` hook** — it was only caught by the `ContentResolver.insert` hook. This is concrete proof of the MediaStore blind spot that MASTG mentions.

The responsible code (demo sample, same as MASTG-DEMO-0001):

```kotlin
fun mastgTestApi() {
    val externalStorageDir = context.getExternalFilesDir(null)
    val fileName = File(externalStorageDir, "secret.txt")
    val fileContent = "secr3tPa\$\$W0rd\n"
    FileOutputStream(fileName).use { output ->          // <-- MastgTest.kt:26
        output.write(fileContent.toByteArray())
    }
}

fun mastgTestMediaStore() {
    val resolver = context.contentResolver
    val contentValues = ContentValues().apply {
        put(MediaStore.MediaColumns.DISPLAY_NAME, "secretFile59.txt")
        put(MediaStore.MediaColumns.MIME_TYPE, "text/plain")
        put(MediaStore.MediaColumns.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS)
    }
    val textUri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, contentValues)  // <-- :44
    textUri?.let {
        resolver.openOutputStream(it)?.use { os ->
            os.write("MAS_API_KEY=8767086b9f6f976g-a8df76\n".toByteArray())
        }
    }
}
```

MASTG's evaluation for this demo: *"This test **fails** because the files are not encrypted and contain sensitive data (such as a password and an API key). This can be further confirmed by reverse-engineering the app to inspect its code and retrieving the files from the device."*

---

#### ✅ PASS — The check is declared PASSED if:

| No | Condition | Example evidence |
|---|---|---|
| P1 | **The trace output is empty** after the app has been exercised extensively — no external storage API was called at all | `wc -c output.txt` → `0`. Per the official `run.sh` note: *"If the output is empty, it indicates that no external storage is used."* |
| P2 | There is an external storage API call, but **only for non-sensitive data** | `open() ... /sdcard/Android/data/<pkg>/cache/map_tile_1842.png [O_WRONLY\|O_CREAT]` — a public map tile, no PII |
| P3 | There is a sensitive data write, but the trace + decompile prove the data is **correctly encrypted** (AES-256-GCM) and **the key resides in the Android KeyStore** | The backtrace shows an `androidx.security.crypto.EncryptedFile` / `javax.crypto.CipherOutputStream` frame; the resulting file → `file` = `data`, `ent` ≈ 7.99 bits/byte, `strings` is clean of the canary |
| P4 | The `FileOutputStream.write()` hook shows only **ciphertext**, no canary value | `preview:` shows random/unreadable bytes, not plaintext |
| P5 | The write only occurs as the result of an **explicit user action** on data genuinely meant to be shared, without credentials/tokens | Backtrace triggered from the "Export PDF" button handler; PDF content = an invoice without a token. *(Still note it as informational.)* |
| P6 | All sensitive-data-write traces point to **internal storage**, not external | All paths in the trace are `/data/user/0/<pkg>/...`, so filtered out by `isExternal()` |
| P7 | The trace proves every **read** from external storage passes through **integrity verification** before the data is used | The backtrace shows a `Mac.doFinal` / `MessageDigest.digest` frame right after the file read, and `DexClassLoader` never appears |

**Example output indicating PASS:**

```bash
$ frida -U -f com.example.secureapp -l script.js -o output.txt
# ... exercise the app extensively ...
$ wc -c output.txt
0 output.txt
# => No external storage API was called
```

or — a write occurs, but is proven correctly encrypted:

```
[*] getExternalFilesDir("null") -> /storage/emulated/0/Android/data/com.example.secureapp/files

Backtrace:
  com.example.secureapp.storage.SecureVault.write(SecureVault.kt:41)
  ...

[*] open() on external storage: /storage/emulated/0/Android/data/com.example.secureapp/files/vault.bin  [O_WRONLY|O_CREAT|O_TRUNC]

Backtrace:
  libcore.io.Linux.open(Native Method)
  ...
  java.io.FileOutputStream.<init>(FileOutputStream.java:236)
  com.google.crypto.tink.subtle.StreamingAeadEncryptingStream.<init>(...)
  androidx.security.crypto.EncryptedFile.openFileOutput(EncryptedFile.java:212)
  com.example.secureapp.storage.SecureVault.write(SecureVault.kt:43)
  ...
```

```bash
$ adb pull /sdcard/Android/data/com.example.secureapp/files/vault.bin
$ file vault.bin
vault.bin: data
$ grep -aiE "MASTG_Pa55w0rd_UNIQ|password|token|api_key" vault.bin
# (no result)
$ ent vault.bin
Entropy = 7.998211 bits per byte.
```

Confirmed via jadx (MASTG-TECH-0023) that the key comes from the Android KeyStore:

```kotlin
val masterKey = MasterKey.Builder(context)
    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
    .build()

val encryptedFile = EncryptedFile.Builder(
    context,
    File(context.getExternalFilesDir(null), "vault.bin"),
    masterKey,
    EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB
).build()

encryptedFile.openFileOutput().use { it.write(sensitiveBytes) }
```

---

#### ⚠️ Important Notes on Assessment

1. **An empty trace output ≠ automatic PASS.** This is the biggest trap in this test. The trace only records flows you actually ran. Causes of a false pass:
   - The triggering flow was not exercised (e.g., the export feature is only active for premium accounts).
   - The app detects Frida and **silently disables** the feature.
   - The hook failed to attach (frida version mismatch, different export name, the app uses `openat` instead of `open`).
   - The write happens in a **separate process** (`:remote` service) that was not attached.

   **Mitigation:** first validate your script against an app known to fail (MASTestApp) to prove the hook works, then correlate the results with **MASTG-TEST-0200** (filesystem diffing) and **MASTG-TEST-0202** (static analysis). If TEST-0202 finds a reference to `getExternalFilesDir` but the trace is empty, that is **inconclusive — not PASS**; it means the triggering flow has not been touched.

2. **Hooking `open()` alone is not enough — MediaStore is invisible.** This is explicitly stressed by MASTG. Without hooking `ContentResolver.insert`, you will miss the entire category of writes to shared storage that is actually the riskiest (persists post-uninstall).

3. **The MediaStore path is *inferred*, not directly observed.** The reconstruction of `relative_path` + `_display_name` is an estimate. Always verify with `adb shell content query --uri content://media/external/downloads` or `adb shell ls`, since Android can add a suffix if the filename clashes (`secretFile55(1).txt`).

4. **A path-resolution API call ≠ proof of a write.** `getExternalFilesDir()` being called does not mean a sensitive file was written — it could be just a storage availability check. It must be correlated with `open(..., O_WRONLY|O_CREAT)` or `FileOutputStream`. Reporting this as a FAIL without correlation is a false positive.

5. **Beware of fake encryption.** Always test with `strings`, `base64 -d`, and entropy analysis. A backtrace showing a `javax.crypto.*` frame is also not a guarantee — check the cipher mode (reject ECB) and **the key's origin** via jadx.

6. **Pay attention to the caller's origin.** Clearly distinguish between:
   - The app's own code → the developer can fix it directly.
   - A third-party SDK → needs an SDK update, reconfiguration, or vendor replacement. **Still the application developer's responsibility** and still reported as a finding.
   - The Android framework itself (e.g., WebView cache) → evaluate whether it was indeed configured to external storage by the app.

7. **Severity is modulated by location & API level, but this does not eliminate the finding:**
   - Plaintext sensitive data in **shared storage** (Download/Documents/DCIM/MediaStore) → highest severity: readable by other apps **and** persists after uninstall.
   - Plaintext sensitive data in an **app-specific external directory** with target API ≥ 30 → lower severity (protected by scoped storage from other apps), but **still FAIL** because it remains readable via MTP/USB by the user, on a rooted device, by third-party backup, and by apps with `MANAGE_EXTERNAL_STORAGE`.
   - The presence of `requestLegacyExternalStorage="true"` or `MANAGE_EXTERNAL_STORAGE` → raises severity.
   - Loading code from external storage (F9) → critical severity, regardless of data sensitivity.

8. **Anti-instrumentation is a separate finding, not a reason to skip.** If the app refuses to run under Frida, note it as a functioning MASVS-RESILIENCE control, then **still complete the storage assessment** via MASTG-TEST-0200 (no instrumentation needed) and MASTG-TEST-0202 (static). Do not report this test as PASS merely because it could not be run — the status is **Inconclusive / Not Applicable**, along with the reason.

9. **Document complete evidence per finding:** the file path (and URI for MediaStore), API used, **full backtrace**, the code location from MASTG-TECH-0023 (`File.kt:line`), file content (redacted if necessary), device API level, `targetSdkVersion`, granted permissions, reproduction steps, and the cross-app read test result.

---

## 4. Recommendations

The root cause of this test is identical to MASTG-TEST-0200 (MASWE-0002), so the remediation is the same. The difference: this test's findings come **with their exact code locations**, so fixes can be directly targeted.

### 4.1 Core Principles (in priority order)

**Priority 1 — Eliminate external storage API calls for sensitive data.** Use the backtrace from the trace as a concrete worklist: each frame `<Class>.<method>(File.kt:N)` is one point that needs fixing.

```kotlin
// ❌ WRONG — detected as FileOutputStream.<init> + path /sdcard in the trace
val file = File(context.getExternalFilesDir(null), "secret.txt")
FileOutputStream(file).use { it.write(password.toByteArray()) }

// ❌ WRONG — detected as ContentResolver.insert to relative_path: Download
val uri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, contentValues)
resolver.openOutputStream(uri!!)?.use { it.write(apiKey.toByteArray()) }

// ✅ CORRECT — internal storage, will not appear in the external storage trace
context.openFileOutput("secret.txt", Context.MODE_PRIVATE).use { it.write(data) }
// or
File(context.filesDir, "secret.txt").writeBytes(data)
```

Never use `MODE_WORLD_READABLE` / `MODE_WORLD_WRITEABLE` (deprecated since API 17, throws a `SecurityException` since API 24).

**Priority 2 — Replace deprecated APIs detected in the trace.**

| API detected in trace | Correct replacement |
|---|---|
| `Environment.getExternalStorageDirectory()` | `context.filesDir` (sensitive) or `context.getExternalFilesDir()` (large non-sensitive) |
| `Environment.getExternalStoragePublicDirectory()` | MediaStore API / Storage Access Framework, **only for non-sensitive data** |
| `WRITE_EXTERNAL_STORAGE` + direct `File` API | MediaStore (media) / SAF (documents) / internal storage (sensitive) |
| Putting a file in `/sdcard` to share it with another app | **FileProvider** + `content://` URI with a temporary permission grant |
| Requesting `READ_EXTERNAL_STORAGE` to pick a photo | **Photo Picker** (no permission at all) |

**Priority 3 — Use the appropriate storage mechanism per data type.**

| Data Type | Correct Mechanism |
|---|---|
| Cryptographic keys | **Android KeyStore** (with `setUserAuthenticationRequired`, StrongBox if available) — the key never leaves secure hardware |
| Password, token, API key | Avoid storage where possible (a session token can stay in memory). If needed: encrypt with a KeyStore key, store in internal storage |
| Sensitive key-value preferences | Internal storage + encryption. Note that Jetpack Security `androidx.security:security-crypto` is now **deprecated** — consider your own AES-GCM with a KeyStore key, or **Google Tink** |
| Structured data | Room + **SQLCipher**, in internal storage |
| Large app-owned files | Internal storage; if size forces external, encryption is mandatory (Priority 4) |
| Files genuinely meant to be shared | MediaStore / SAF — **non-sensitive data only**, ideally following an explicit user action |

**Priority 4 — If external storage is unavoidable: encrypt with a key from the KeyStore.**

```kotlin
val masterKey = MasterKey.Builder(context)
    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
    .build()

val encryptedFile = EncryptedFile.Builder(
    context,
    File(context.getExternalFilesDir(null), "data.enc"),
    masterKey,
    EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB
).build()

encryptedFile.openFileOutput().use { it.write(sensitiveBytes) }
```

Requirements to be considered adequate:
- **AES-256-GCM** or ChaCha20-Poly1305 (authenticated encryption). Reject ECB, DES/3DES/RC4, and CBC without a MAC.
- Random IV/nonce per operation, never repeated.
- The key is **generated & stored in the Android KeyStore** — not hardcoded, not derived from a static value (IMEI, package name, constant), not written to external storage.
- If the key is derived from a user password: a strong KDF (high-iteration PBKDF2 / **Argon2id** / scrypt) with a random salt.

> **Verify remediation through this test itself:** after fixing, rerun MASTG-TEST-0201. A correct backtrace will show an `EncryptedFile.openFileOutput` / `CipherOutputStream` frame between the app code and `FileOutputStream.<init>`. The absence of a crypto frame on the write path is a strong indicator that the data is still plaintext.

**Priority 5 — Enable and maintain scoped storage.**

```xml
<application
    android:requestLegacyExternalStorage="false"
    ... >
```

- Target **Android 11 (API 30) and above** — scoped storage is forced active by the OS.
- **Remove** `requestLegacyExternalStorage="true"` and `preserveLegacyExternalStorage`.
- Avoid `MANAGE_EXTERNAL_STORAGE` unless truly required (file manager, antivirus, backup app) — restricted by Google Play policy.
- Declare storage permissions as minimally as possible; use granular `READ_MEDIA_IMAGES`/`VIDEO`/`AUDIO` (API 33+), or the Photo Picker, which needs no permission.

**Priority 6 — Validate input & integrity for all data READ from external storage** (Man-in-the-Disk mitigation; relevant to finding F9). Treat every file from external storage as **untrusted input**.

- **Never** load executable code (DEX, SO, APK, JS bundle, script) from external storage. If the trace shows `DexClassLoader` / `System.load()` on an `/sdcard` path, this must be removed entirely.
- Strict validation: size, MIME type, magic bytes, schema structure, value bounds. Do not deserialize Java/Kotlin objects from an external storage file.
- Prevent path traversal & symlink attacks: canonicalize the path (`File.canonicalPath`) and ensure it stays within the permitted directory.
- Verify integrity with a **keyed HMAC-SHA256** from the KeyStore or AEAD (AES-GCM), not a bare hash:

```kotlin
// Keyed integrity verification — resistant to an active attacker
fun verify(file: File, expectedTag: ByteArray, keyAlias: String): Boolean {
    val key = (KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        .getEntry(keyAlias, null) as KeyStore.SecretKeyEntry).secretKey
    val mac = Mac.getInstance("HmacSHA256").apply { init(key) }
    file.inputStream().buffered().use { input ->
        val buf = ByteArray(8192)
        var n: Int
        while (input.read(buf).also { n = it } != -1) mac.update(buf, 0, n)
    }
    return MessageDigest.isEqual(mac.doFinal(), expectedTag)   // constant-time
}
```

> A bare SHA-256 hash **is inadequate** if the hash is stored next to the file — an attacker can simply overwrite both. Store the tag in internal storage, and preferably use a keyed HMAC as shown above.

### 4.2 Additional Practice Improvements

- **Audit third-party SDKs specifically.** This is this test's unique value: the backtrace points to the responsible vendor. For every SDK detected writing to external storage — disable its feature, reconfigure it to internal storage if supported, update to the latest version, or replace the vendor.
- **Data minimization.** Don't store what isn't necessary. Session tokens should preferably stay in memory only; use short-lived refresh tokens.
- **Delete temporary files immediately** after use, and don't put temp files in `/sdcard` in the first place (use `context.cacheDir`). This closes finding F10.
- **Disable verbose logging in release builds** (`BuildConfig.DEBUG`); ensure the crash handler does not write a dump containing PII/credentials to external storage.
- **Exclude sensitive files from backup** (`android:allowBackup="false"` or `dataExtractionRules`/`fullBackupContent`) — see MASWE-0006.
- **Integrate into CI/CD.** This Frida script can be run on an emulator in a pipeline alongside UI tests (Espresso/Appium) as a regression test: fail the build if an external storage API call appears that is not in an allowlist. This prevents regressions when SDKs are updated.
- **Explicit threat model.** Document every deliberate write to external storage along with its justification, so reviewers can distinguish a design decision from an unintentional leak.

### 4.3 Remediation Checklist

- [ ] Every code location from the finding's backtrace has been reviewed and fixed
- [ ] No sensitive data (credentials, tokens, PII, financial data) is written to external storage
- [ ] `Environment.getExternalStorageDirectory()` and `getExternalStoragePublicDirectory()` (deprecated) have been removed from the code
- [ ] Sensitive data is stored in internal storage (`context.filesDir`, `openFileOutput(..., MODE_PRIVATE)`)
- [ ] No use of `MODE_WORLD_READABLE` / `MODE_WORLD_WRITEABLE`
- [ ] If external storage is still used: data is encrypted with AES-256-GCM using a key from the Android KeyStore
- [ ] No hardcoded key/secret, and none is also stored on external storage
- [ ] Writes via `ContentResolver.insert` / MediaStore are only for non-sensitive data
- [ ] `targetSdkVersion` ≥ 30 and `requestLegacyExternalStorage` is not set to `true`
- [ ] `MANAGE_EXTERNAL_STORAGE` is not declared (unless with strong justification and Play approval)
- [ ] Minimal storage permissions; use Photo Picker / SAF / granular `READ_MEDIA_*`
- [ ] No executable code (DEX/SO/APK/JS) is loaded from external storage
- [ ] All data read from external storage is validated and integrity-verified (HMAC/AEAD with a KeyStore key)
- [ ] Temporary files are no longer written to external storage; cache is directed to `context.cacheDir`
- [ ] Verbose logging & crash dumps to external storage are disabled in release builds
- [ ] Detected third-party SDKs writing to external storage have been audited and addressed
- [ ] Sensitive files are excluded from backup
- [ ] **Re-verify:** rerun MASTG-TEST-0201 → clean trace output, or the backtrace shows an encryption frame on every write path
- [ ] **Cross-verify:** run MASTG-TEST-0200 (filesystem diff) and MASTG-TEST-0202 (static) to make sure no path was missed

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0201: Runtime Use of APIs to Access External Storage](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0201/)
- [MASTG-TEST-0200: Files Written to External Storage](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0200/)
- [MASTG-TEST-0202: References to APIs and Permissions for Accessing External Storage](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0202/)
- [MASTG-TEST-0001: Testing Local Storage for Sensitive Data](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0001/)
- [MASWE-0002: Sensitive Data Stored Unencrypted Outside of Private Storage](https://mas.owasp.org/MASWE/MASVS-STORAGE/MASWE-0002/)
- [MASTG-DEMO-0002: External Storage APIs Tracing with Frida](https://mas.owasp.org/MASTG/demos/android/MASVS-STORAGE/MASTG-DEMO-0002/MASTG-DEMO-0002/)
- [MASTG-DEMO-0001: File System Snapshots from External Storage](https://mas.owasp.org/MASTG/demos/android/MASVS-STORAGE/MASTG-DEMO-0001/MASTG-DEMO-0001/)
- [MASTG-DEMO-0003: App Writing to External Storage without Scoped Storage Restrictions](https://mas.owasp.org/MASTG/demos/android/MASVS-STORAGE/MASTG-DEMO-0003/MASTG-DEMO-0003/)
- [MASTG-DEMO-0004: App Writing to External Storage with Scoped Storage Restrictions](https://mas.owasp.org/MASTG/demos/android/MASVS-STORAGE/MASTG-DEMO-0004/MASTG-DEMO-0004/)
- [MASTG-DEMO-0005: App Writing to External Storage via the MediaStore API](https://mas.owasp.org/MASTG/demos/android/MASVS-STORAGE/MASTG-DEMO-0005/MASTG-DEMO-0005/)
- [MASTG-KNOW-0042: External Storage](https://mas.owasp.org/MASTG/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0042/)
- [MASTG-TECH-0043: Method Hooking](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0043/)
- [MASTG-TECH-0023: Reviewing Decompiled Java Code](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0023/)
- [MASTG-TECH-0005: Installing Apps](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0005/)
- [MASTG-TECH-0002: Host-Device Data Transfer](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0002/)
- [MASTG-TOOL-0001: Frida](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0001/)
- [MASTG-TOOL-0038: Objection](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0038/)
- [MASTG-TOOL-0018: jadx](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0018/)
- [MASVS-STORAGE: Storage](https://mas.owasp.org/MASVS/05-MASVS-STORAGE/)
- [OWASP MASTG Repository (GitHub)](https://github.com/OWASP/mastg)
- [OWASP Mobile Top 10 2024 — M9: Insecure Data Storage](https://owasp.org/www-project-mobile-top-10/2023-risks/m9-insecure-data-storage)

### 5.2 Frida Documentation & Instrumentation Tooling

- [Frida — Documentation Home](https://frida.re/docs/home/)
- [Frida — `frida-trace` CLI reference](https://frida.re/docs/frida-trace/)
- [Frida — JavaScript API: `Interceptor`](https://frida.re/docs/javascript-api/#interceptor)
- [Frida — JavaScript API: `Java` (Android runtime)](https://frida.re/docs/javascript-api/#java)
- [Frida — Android instrumentation guide](https://frida.re/docs/android/)
- [Frida — `frida-gadget` (instrumentation without root)](https://frida.re/docs/gadget/)
- [Frida Handbook — Hooks and the Interceptor API](https://learnfrida.info/basic_usage/)
- [Frida CodeShare — a collection of community scripts](https://codeshare.frida.re/)
- [SensePost — Using & improving frida-trace (2025)](https://sensepost.com/blog/2025/using-improving-frida-trace/)
- [iddoeldor/frida-snippets — hand-crafted Frida examples](https://github.com/iddoeldor/frida-snippets)
- [FrenchYeti/frida-trick — collection of Frida scripts & tricks](https://github.com/FrenchYeti/frida-trick)
- [jnitrace — tracing JNI API usage in Android apps](https://github.com/chame1eon/jnitrace)
- [Objection — runtime mobile exploration](https://github.com/sensepost/objection)
- [Frida cheat sheet (awakened1712)](https://awakened1712.github.io/hacking/hacking-frida/)
- [awesome-frida — a curated list of Frida resources](https://github.com/DevenLu/awesome-frida)
- [rovo89/XposedTools — building & installing Xposed modules](https://github.com/rovo89/XposedTools)
- [LSPosed — a modern Xposed implementation (Zygisk/Riru)](https://github.com/LSPosed/LSPosed)

### 5.3 Official Android / Google Documentation

- [Sensitive Data Stored in External Storage — Android Security Risks](https://developer.android.com/privacy-and-security/risks/sensitive-data-external-storage)
- [Data and file storage overview](https://developer.android.com/training/data-storage)
- [Access app-specific files](https://developer.android.com/training/data-storage/app-specific)
- [Scoped storage](https://developer.android.com/training/data-storage#scoped-storage)
- [Storage use cases and best practices](https://developer.android.com/training/data-storage/use-cases)
- [Access media files from shared storage (MediaStore)](https://developer.android.com/training/data-storage/shared/media)
- [Access documents and other files (Storage Access Framework)](https://developer.android.com/training/data-storage/shared/documents-files)
- [Manage all files on a storage device (`MANAGE_EXTERNAL_STORAGE`)](https://developer.android.com/training/data-storage/manage-all-files)
- [`ContentResolver` — API reference](https://developer.android.com/reference/android/content/ContentResolver)
- [`Environment` — API reference](https://developer.android.com/reference/android/os/Environment)
- [`MediaStore.MediaColumns` — API reference](https://developer.android.com/reference/android/provider/MediaStore.MediaColumns)
- [`EncryptedFile` (Jetpack Security)](https://developer.android.com/reference/androidx/security/crypto/EncryptedFile)
- [Android Keystore system](https://developer.android.com/privacy-and-security/keystore)
- [Cryptography best practices](https://developer.android.com/privacy-and-security/cryptography)
- [App security best practices — Store data safely](https://developer.android.com/privacy-and-security/security-best-practices#external-storage)
- [Security tips — Using external storage](https://developer.android.com/privacy-and-security/security-tips#external-storage)
- [FileProvider](https://developer.android.com/reference/androidx/core/content/FileProvider)
- [Photo picker](https://developer.android.com/training/data-storage/shared/photopicker)
- [Google Play — Use of the All files access permission](https://support.google.com/googleplay/android-developer/answer/10467955)
- [Google Tink — cryptographic library](https://developers.google.com/tink)

### 5.4 Standards, Taxonomy, and Other Guidelines

- [CWE-312: Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)
- [CWE-921: Storage of Sensitive Data in a Mechanism without Access Control](https://cwe.mitre.org/data/definitions/921.html)
- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
- [SEI CERT Android — DRD00: Do not store sensitive information on external storage (SD card) unless encrypted first](https://wiki.sei.cmu.edu/confluence/display/android/DRD00.+Do+not+store+sensitive+information+on+external+storage+%28SD+card%29+unless+encrypted+first)
- [NIST SP 800-163 Rev.1 — Vetting the Security of Mobile Applications](https://csrc.nist.gov/publications/detail/sp/800-163/rev-1/final)
- [NIST SP 800-124 Rev.2 — Guidelines for Managing the Security of Mobile Devices](https://csrc.nist.gov/publications/detail/sp/800-124/rev-2/final)
- [SonarQube Rule java:S5324 — Accessing Android external storage is security-sensitive](https://rules.sonarsource.com/java/RSPEC-5324/)
- [CodeQL — Cleartext storage of sensitive information in the Android filesystem](https://codeql.github.com/codeql-query-help/java/java-android-cleartext-storage-filesystem/)
- [MITRE ATT&CK Mobile — T1533: Data from Local System](https://attack.mitre.org/techniques/T1533/)
- [MITRE ATT&CK Mobile — T1409: Stored Application Data](https://attack.mitre.org/techniques/T1409/)

### 5.5 Security Research & Technical Articles

- [Check Point Research — Man-in-the-Disk: Android Apps Exposed via External Storage](https://research.checkpoint.com/2018/androids-man-in-the-disk/)
- [Check Point Blog — Man-in-the-Disk: A New Attack Surface for Android Apps](https://blog.checkpoint.com/security/man-in-the-disk-a-new-attack-surface-for-android-apps/)
- [Threatpost — DEF CON 2018: 'Man in the Disk' Attack Surface Affects All Android Phones](https://threatpost.com/def-con-2018-man-in-the-disk-attack-surface-affects-all-android-phones/134993/)
- [The Hacker News — New Man-in-the-Disk attack leaves millions of Android phones vulnerable](https://thehackernews.com/2018/08/man-in-the-disk-android-hack.html)
- [NDSS 2025 — ScopeVerif: Analyzing the Security of Android's Scoped Storage via Differential Analysis](https://www.ndss-symposium.org/wp-content/uploads/2025-340-paper.pdf)
- [PolyScope: Multi-Policy Access Control Analysis to Triage Android Scoped Storage (arXiv)](https://arxiv.org/pdf/2302.13506)
- [Security Smells in Android (arXiv)](https://arxiv.org/pdf/2006.01181)
- [HackTricks — Android Applications Pentesting](https://book.hacktricks.wiki/en/mobile-pentesting/android-app-pentesting/index.html)
- [Linux `open(2)` man page — flags O_WRONLY/O_CREAT/O_APPEND](https://man7.org/linux/man-pages/man2/open.2.html)

---

*This document was prepared based on OWASP MASTG (current release as of September 2026), official Frida and Android Developers documentation, CWE/SEI CERT/NIST standards, and third-party security research.*
