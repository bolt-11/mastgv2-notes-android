# MASTG-TEST-0203 Runtime Use of Logging APIs

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0203 |
| **Platform** | Android |
| **MASVS Category** | MASVS-STORAGE (MASVS-STORAGE-2: The app prevents leakage of unnecessary sensitive data) |
| **Weakness** | MASWE-0005 — *Insertion of Sensitive Data into Logs* |
| **Test Type** | Dynamic, **Hooks** |
| **Profile** | L1, L2, **P** (Privacy) |
| **Knowledge** | MASTG-KNOW-0049 (Logs) |
| **Best Practice** | MASTG-BEST-0002 (Remove Logging Code) |
| **Highlighted APIs** | `Log`, `Logger`, `System.out.print`, `System.err.print`, `java.lang.Throwable#printStackTrace` |
| **Related Techniques** | MASTG-TECH-0005 (Installing Apps), MASTG-TECH-0043 (Method Hooking) |
| **Related Demo** | MASTG-DEMO-0006 (Tracing Common Logging APIs Looking for Secrets) |
| **Sibling Test** | MASTG-TEST-0231 (References to Logging APIs — the static approach) |
| **Supersedes** | MASTG-TEST-0003 (*Testing Logs for Sensitive Data* — now **deprecated**, superseded by MASTG-TEST-0203 + MASTG-TEST-0231) |
| **Related CWEs** | CWE-532 (Insertion of Sensitive Information into Log File), CWE-200 (Exposure of Sensitive Information), CWE-312 (Cleartext Storage of Sensitive Information), CWE-359 (Exposure of Private Personal Information) |

---

## 1. Explanation

### 1.1 Testing Objective

This test aims to **identify logging API calls at runtime and check whether sensitive data gets recorded into the log**.

Direct quote from the MASTG overview:

> *"On Android platforms, logging APIs like `Log`, `Logger`, `System.out.print`, `System.err.print`, and `java.lang.Throwable#printStackTrace` can inadvertently lead to the leakage of sensitive information. Log messages are recorded in logcat, a shared memory buffer, accessible since Android 4.1 (API level 16) only to privileged system applications that declare the `READ_LOGS` permission. Nonetheless, the vast ecosystem of Android devices includes pre-loaded apps with the `READ_LOGS` privilege, increasing the risk of sensitive data exposure. Therefore, direct logging to logcat is generally advised against due to its susceptibility to data leaks."*

There are four important technical facts in that paragraph:

1. **logcat is a *shared memory buffer*** — not the application's private storage. All apps on the device write to the same buffer.
2. **Since Android 4.1 (API 16)**, read access to logcat is restricted to *privileged* system apps that declare `READ_LOGS`. Before API 16, **any ordinary app** could read the entire device log simply by requesting that permission.
3. **That restriction is not as complete as it seems.** The Android ecosystem is highly diverse, and many **pre-installed apps** from vendors/carriers hold the `READ_LOGS` privilege — automatically granted without user consent. So the assumption "logcat is safe because it needs a system permission" doesn't hold in the real world.
4. Therefore, **logging directly to logcat is generally not recommended**.

### 1.2 Why Logging Is Dangerous: Real Leakage Paths

MASTG-KNOW-0049 acknowledges that there are many legitimate reasons to create logs on a mobile device — tracking crashes, errors, and usage statistics. Logs can be stored locally offline and then sent to an endpoint when online. **However**, logging sensitive data can expose that data to an attacker or malicious app, and **can potentially violate user confidentiality**.

It's important to understand that `READ_LOGS` is **not the only** path to access logs. This is why this test's findings remain relevant even if an ordinary malicious app cannot read logcat:

| Access Path | Condition | Note |
|---|---|---|
| **Pre-installed app with `READ_LOGS`** | Vendor/carrier, without user consent | The path MASTG explicitly mentions. Research has found pre-installed apps that write Android logs to external storage when triggered via an Intent — so **any app with `READ_EXTERNAL_STORAGE` can read it** |
| **`adb logcat` via USB debugging** | Developer options active | **No root needed.** A brief physical access to an unlocked device is enough to harvest logs |
| **A rooted device / malware with privilege** | Root/exploit | Full access to the logcat buffer |
| **Bug report / `adb bugreport`** | Triggered by the user or the system | Contains a full logcat dump; often sent by users to support, uploaded to tickets, or shared on public forums |
| **Crash reporting SDK** | Third-party SDK | Many SDKs attach a logcat excerpt to crash reports and then **send it to a third-party server** — sensitive data leaves the device |
| **The app reading its own log** | No permission needed | A process can read its own log output; if the app then writes it to a file on external storage, the leak spreads (linked to MASTG-TEST-0200) |
| **Log written to a local file then sent** | App design | Research has found apps that *post* raw logs to the internet |
| **Android < 4.1 (API 16)** | Old device/target SDK | Any ordinary app with `READ_LOGS` can read all logs |

Data categories proven to leak via logs in research and real-world findings: account names, password information, location data, as well as device data such as MAC addresses and IMEI. An example at the OS level: **CVE-2023-21387** in Android's User Backup Manager component, where a sensitive backup token was written to the system log in plaintext, allowing authentication token leakage.

**The privacy dimension.** Note that this test carries a **P (Privacy)** profile — not just L1/L2. This means logging PII is assessed as a privacy issue in its own right, regardless of whether an attacker exploits it. Logging email, phone number, location, or device ID can violate regulatory obligations (GDPR, Indonesia's PDP Law) even without a proven leak.

### 1.3 This Test's Position Within the Logging Series

Just like the external storage series (TEST-0200/0201/0202), logging testing is also split into dynamic and static approaches:

| Test | Approach | Answers | Strength | Weakness |
|---|---|---|---|---|
| **MASTG-TEST-0203** *(this document)* | **Dynamic** — method hooking | "What logging API is **actually called**, and **what value** is recorded?" | **Sees the actual runtime value** — this is its main advantage; catches dynamically-built data; catches logging from libraries | Only exercised flows; needs Frida; can be blocked by anti-instrumentation |
| **MASTG-TEST-0231** | **Static** — reverse engineering + pattern matching | "Where is a logging API **referenced** in the code?" | Comprehensive coverage of the entire code base, fast, CI-friendly, no device needed | Doesn't know the runtime value; many false positives; blind to native/dynamic code |
| **MASTG-TEST-0003** | — | *(deprecated)* | Superseded by the two tests above | — |

> **Version note:** MASTG-TEST-0003 (*Testing Logs for Sensitive Data*) is now **deprecated** with `covered_by: [MASTG-TEST-0203, MASTG-TEST-0231]`. If you reference old documentation or reports that mention MSTG-STORAGE-3 / MASTG-TEST-0003, its equivalent in MASTG V2 is these two tests.

**TEST-0203's unique value** compared to TEST-0231: static analysis can only see that there is a `Log.d(TAG, "token: $token")` call — it doesn't know what `$token` actually contains at runtime, and doesn't know whether that variable holds sensitive data or a dummy value. This dynamic test **sees the value actually recorded**, directly answering the evaluation question: is there sensitive data in the log?

Conversely, TEST-0231 catches what slips past TEST-0203: logging calls on code paths that were never triggered during testing (e.g., a rarely-occurring error handler, a premium feature).

### 1.4 Map of Logging APIs That Need to Be Checked

**Group A — APIs explicitly named by MASTG:**

| API | Description |
|---|---|
| `android.util.Log` — `v()`, `d()`, `i()`, `w()`, `e()`, `wtf()`, `println()` | Android's primary logging API. All of these write to logcat |
| `java.util.logging.Logger` — `severe()`, `warning()`, `info()`, `config()`, `fine()`, `finer()`, `finest()`, `log()` | The standard Java logger; on Android it is routed to logcat |
| `System.out.print` / `System.out.println` | On Android, routed to logcat with the `System.out` tag |
| `System.err.print` / `System.err.println` | Routed to logcat with the `System.err` tag |
| `java.lang.Throwable#printStackTrace()` | **Often forgotten.** Prints a stack trace to `System.err` → logcat. Exception messages often contain sensitive data (e.g., a full URL with a token, API response content) |

**Group B — Additional surface not named by MASTG but that must be checked in real-world testing:**

| API / Component | Reason for checking |
|---|---|
| **Timber** (`Timber.d/e/i/v/w/wtf`) | The most popular logging library on Android. Will not be caught if you only hook `android.util.Log` — unless Timber is configured with a `DebugTree` that delegates to `Log` |
| **SLF4J / Logback-android / log4j** | Common in enterprise apps |
| `android.util.Slog` | System logging (only for platform apps) |
| **Native logging** — `__android_log_print`, `__android_log_write` (liblog) | Logs from NDK code/`.so`. **Invisible** to Java hooks |
| **OkHttp `HttpLoggingInterceptor`** | If set to `Level.BODY`, logs **all request/response headers and bodies** — including `Authorization: Bearer ...`. One of the biggest causes of log leakage in practice |
| **Retrofit / Volley / Firebase / analytics SDK** | Often have their own debug logging flag |
| **WebView console** (`ConsoleMessage` via `WebChromeClient.onConsoleMessage`) | JavaScript `console.log()` output goes into logcat |
| **Crash reporter** (Crashlytics `log()`, Sentry breadcrumbs) | Adds log context that is **sent to a third-party server** |
| **Custom logger wrapper** in the app itself | E.g., `AppLogger.debug()` which internally calls `Log.d` — a hook on `Log` will catch it, but the backtrace will point to the wrapper, not the original caller |

> Rule of thumb: hooking `android.util.Log` catches **most** leakage because many libraries eventually delegate to it. But don't assume this — verify by checking the app's dependencies (`grep -r "timber\|slf4j\|HttpLoggingInterceptor"` on the decompiled code).

### 1.5 Myths That Need Correcting

Several common misconceptions that often cause incorrect assessments:

1. **"`Log.v` and `Log.d` are automatically removed in release builds."** **Wrong.** Android does not automatically remove any logging call. Removal only happens if you explicitly configure ProGuard/R8 with `-assumenosideeffects`. The MASTG demo itself shows `Log.v` and `Log.d` appearing normally in logcat.
2. **"Low log levels (verbose/debug) don't appear in production."** **Wrong.** All levels appear in logcat unless filtered during reading. `Log.isLoggable()` is only useful if the developer actually uses it as a gate.
3. **"logcat is safe because it needs `READ_LOGS`, which only system apps have."** **Misleading** — see the table in §1.2. Pre-installed apps, `adb logcat`, bug reports, and crash reporters are all real-world paths.
4. **"Just add a ProGuard rule and the problem is solved."** **Not sufficient.** MASTG-BEST-0002 explains that `-assumenosideeffects` only guarantees that the `Log` method *call* is removed. If the logged string is built dynamically, **the string-building code can remain in the bytecode** (see §4.1).

---

## 2. Tools Used for Testing

### 2.1 Required Tools (Core)

| Tool | MASTG ID | Function in This Test |
|---|---|---|
| **Frida / frida-trace** | MASTG-TOOL-0001 | **The primary tool.** `frida-trace -j` to hook all methods of a logging class at once and record their arguments |
| **frida-server** | — | A daemon on the device (requires root) — or **frida-gadget** for non-root devices |
| **adb** | MASTG-TOOL-0004 | APK installation (`adb install -g`), and **`adb logcat`** as an independent comparison for the trace result |
| **Android device / emulator (rooted)** | MASTG-TOOL-0003 | The test target |
| **jadx** | MASTG-TOOL-0018 | Tracing the code location of the log caller to determine the context and data source |

### 2.2 Supporting Tools

| Tool | Function |
|---|---|
| **`adb logcat` with filtering** | A mandatory comparison: `adb logcat --pid=$(adb shell pidof -s <pkg>)`. **No root needed** — USB debugging is enough. This also demonstrates one of the exploitation paths |
| **pidcat** | A logcat wrapper that filters per-package and colorizes output — far more readable |
| **Objection** | MASTG-TOOL-0038. A quick alternative: `android hooking watch class android.util.Log --dump-args --dump-backtrace` |
| **semgrep** | MASTG-TOOL-0110. For MASTG-TEST-0231 (static) — complements this test's coverage |
| **ProGuard / R8** | MASTG-TOOL-0022. Not a testing tool, but its configuration (`proguard-rules.pro`) must be **verified** as part of the evaluation |
| **`strings` / Ghidra** | Checking `.so` files for `__android_log_print` calls — a Java hook blind spot |
| **grep / ripgrep** | Filtering trace output for canary values and secret patterns |
| **TruffleHog / gitleaks** | Scanning collected log output for secret patterns (tokens, API keys, private keys) |
| **Android Studio Logcat** | An integrated logcat view; the MASTG demo uses this as a reference comparison |

### 2.3 Environment Prerequisites

- **Root or frida-gadget** for method hooking. Note, however: the **comparison** part (`adb logcat`) can run without root — and that in itself demonstrates exploitability.
- **The frida-server version must match** the host's frida CLI; the architecture must also be correct.
- **`--runtime=v8`** is needed for `frida-trace -j` (tracing Java methods), as in the MASTG demo's `run.sh`.
- The app installed with `adb install -g` so all flows are reachable.
- **A unique, easily-grepped canary value.** This is very important for this test and is **explicitly recommended by MASTG**: *"You could refine the test to input a known secret and then search for it in the logs."* Use a pattern like `MASTG_CANARY_PWD_7f3a`, `canary+mastg@example.com`.
- **Test the RELEASE build, not just debug.** This is crucial: many apps have excessive logging in the debug build that is actually removed/disabled in release. Testing a debug build will produce massive false positives. If only a debug build is available, **state that as a testing limitation** in the report.
- **Anticipate anti-instrumentation** on production apps (especially financial ones). If blocked, `adb logcat` can still be used as an alternative testing path.

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0005** (*Installing Apps*) to install the application.
2. Use **MASTG-TECH-0043** (*Method Hooking*) to hook the relevant API calls.
3. **Exercise the app extensively** to trigger as many flows as possible, entering sensitive data wherever possible.

### 3.2 Practical Implementation (MASTG-DEMO-0006)

**Step 0 — Setup**

```bash
# Check version & architecture
frida --version
adb shell getprop ro.product.cpu.abi

# Run frida-server on the device
adb push frida-server-<version>-android-<arch> /data/local/tmp/frida-server
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "su -c /data/local/tmp/frida-server &"
frida-ps -U | head

# Install the app (ideally a RELEASE build)
adb install -g ./target-app.apk

# Clear the logcat buffer for a clean baseline
adb logcat -c
```

**Step 1 — Run frida-trace (official `run.sh` from MASTG-DEMO-0006)**

```bash
#!/bin/bash

# SUMMARY: This script uses frida-trace to trace logging statements in the specified Android app
# and filters the output to exclude certain log methods.
# The raw output is saved to "output_raw.txt" and then filtered to remove unwanted log entries.
# The final result saved to "output.txt".

frida-trace \
    -U \
    -f org.owasp.mastestapp \
    --runtime=v8 \
    -j 'android.util.Log!*' \
    -j 'java.util.logging.Logger!severe' \
    -o output_raw.txt \
    && cat output_raw.txt | grep -E "(Log|Logger)" | grep -vE "Log\.println|Log\.isLoggable" > output.txt
```

How to read this command:

| Part | Meaning |
|---|---|
| `-U` | Connect to the device via USB |
| `-f org.owasp.mastestapp` | **Spawn** the app (not attach) — important so logs during startup are captured too |
| `--runtime=v8` | Required for tracing Java methods with `-j` |
| `-j 'android.util.Log!*'` | Hook **all** methods of the `android.util.Log` class (`v`, `d`, `i`, `w`, `e`, `wtf`, `println`, `isLoggable`, ...) |
| `-j 'java.util.logging.Logger!severe'` | Hook the `severe` method of `Logger` |
| `-o output_raw.txt` | Save the raw output |
| `grep -vE "Log\.println\|Log\.isLoggable"` | **Reduce noise/duplication**: `Log.v/d/i/w/e` internally calls `Log.println`, so each log would otherwise appear twice. `isLoggable` is just a level check, not a data-logging call |

> Note that the `grep` filter in the demo is an important design element, not cosmetic. Without it, every log call appears duplicated and the output becomes hard to read.

**Step 2 — Exercise the App with a Canary Value**

Run as many flows as possible, and at **every** input insert a unique canary value:

- Registration & login (username, password, OTP) — use the canary password `MASTG_CANARY_PWD_7f3a`
- Failed login, wrong password, locked account → triggers error paths that often carry verbose logging
- Password reset, email/SMS verification, 2FA/biometric setup
- Complete the profile: name, national ID, address, phone, date of birth, document upload
- Add a payment method (canary card number), make a transaction, download an invoice
- Search feature, chat, comments
- **Turn off the network mid-operation** → triggers an exception & `printStackTrace`
- **Trigger a server error** (invalid input, large payload) → triggers logging of the API response
- Background/foreground, screen rotation, force-stop, reopen
- Enable all toggles in Settings, especially "debug"/"developer" options if present
- Deep link / external intent

**Step 3 — Stop and Analyze**

```bash
# Press Ctrl+C to end frida-trace, then:

# Search for the canary value in the trace output
grep -iE "MASTG_CANARY_PWD_7f3a|canary\+mastg" output.txt

# Search for common secret patterns
grep -inE "password|passwd|pwd|token|bearer|authorization|api[_-]?key|secret|credential|session|cookie|jwt|eyJ[A-Za-z0-9_-]{10,}|BEGIN (RSA|EC|OPENSSH|PRIVATE) KEY" output.txt

# Search for PII
grep -inE "[0-9]{16}|[0-9]{3}-[0-9]{2}-[0-9]{4}|[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-z]{2,}|\+?62[0-9]{9,}|imei|mac[_ ]?address|latitude|longitude" output.txt

# Search for cryptographic material (IV, key) — as in the demo sample
grep -inE "\biv\b|initialization.?vector|secret_?key|aes|cipher" output.txt
```

**Step 4 — Compare with logcat**

The MASTG demo includes `logcat_output.txt` as a **comparison reference**. This is an important verification step: it proves that the data captured by the hook actually **reaches the logcat buffer** and is therefore accessible to other parties.

```bash
# Read logcat only for the target app's process — DOES NOT NEED ROOT
adb logcat --pid=$(adb shell pidof -s org.owasp.mastestapp)

# Save and search for the canary value
adb logcat -d > logcat_dump.txt
grep -iE "MASTG_CANARY_PWD_7f3a|password|token" logcat_dump.txt

# A more readable alternative
pidcat org.owasp.mastestapp
```

> That the command above runs **without root**, with only USB debugging, is practical proof of exploitability worth including in the report.

### 3.3 Recommended Extensions

The MASTG demo script is intentionally minimal for educational purposes and only covers `android.util.Log` and `Logger.severe`. For real-world testing, there are several gaps that need to be closed:

**Gap 1 — `Logger` is only hooked on `severe`.** Other methods (`warning`, `info`, `fine`, `log`) are missed.
**Gap 2 — `System.out` / `System.err` are not hooked**, even though they are explicitly named in this test's API list.
**Gap 3 — `printStackTrace()` is not hooked**, even though it is also explicitly named in the API list.
**Gap 4 — Third-party logging libraries** (Timber, OkHttp interceptor) are not covered.
**Gap 5 — No backtrace is printed**, making it hard to determine the caller's code location.

**An extended frida-trace command:**

```bash
frida-trace \
    -U \
    -f com.example.target \
    --runtime=v8 \
    -j 'android.util.Log!*' \
    -j 'java.util.logging.Logger!*' \
    -j 'java.io.PrintStream!print*' \
    -j 'java.lang.Throwable!printStackTrace*' \
    -j 'timber.log.Timber!*' \
    -j '*!*HttpLoggingInterceptor*/isu' \
    -o output_raw.txt
```

> Note: `-j 'java.io.PrintStream!print*'` will catch `System.out.print*` and `System.err.print*` (both are `PrintStream`), but is also very **noisy** since all stream writes get caught. Filter the result.

**A custom Frida script with backtrace and automatic canary detection:**

```javascript
// Patterns considered sensitive — adjust to your test's canary value
const SENSITIVE = [
    /MASTG_CANARY_PWD_7f3a/i,
    /canary\+mastg@example\.com/i,
    /password|passwd|pwd/i,
    /token|bearer|authorization/i,
    /api[_-]?key|secret|credential/i,
    /eyJ[A-Za-z0-9_-]{10,}/,                 // JWT
    /BEGIN (RSA|EC|OPENSSH)? ?PRIVATE KEY/,
    /\b\d{16}\b/,                            // card number
    /\biv\b|secret_?key/i
];

function isSensitive(s) {
    return s && SENSITIVE.some(re => re.test(s));
}

function backtrace(max = 10) {
    const Exception = Java.use("java.lang.Exception");
    const st = Exception.$new().getStackTrace();
    const lines = [];
    for (let i = 0; i < Math.min(max, st.length); i++) {
        const f = st[i].toString();
        // Skip logging framework frames so the original caller is visible
        if (f.indexOf("android.util.Log") === 0) continue;
        if (f.indexOf("java.util.logging") === 0) continue;
        lines.push("    " + f);
    }
    return lines.join("\n");
}

function report(api, tag, msg, thr) {
    const flag = isSensitive(msg) || isSensitive(tag) ? "  [!! SENSITIVE !!]" : "";
    console.log(`\n[*] ${api}${flag}`);
    if (tag !== null) console.log(`    tag : ${tag}`);
    console.log(`    msg : ${msg}`);
    if (thr) console.log(`    thr : ${thr}`);
    console.log("  Caller:");
    console.log(backtrace());
}

Java.perform(() => {
    // --- android.util.Log ---
    const Log = Java.use("android.util.Log");
    ['v', 'd', 'i', 'w', 'e', 'wtf'].forEach(m => {
        Log[m].overloads.forEach(ov => {
            ov.implementation = function (...args) {
                // Common overloads: (String tag, String msg) or (String tag, String msg, Throwable tr)
                const tag = (args.length > 0 && args[0]) ? args[0].toString() : null;
                const msg = (args.length > 1 && args[1]) ? args[1].toString() : null;
                const thr = (args.length > 2 && args[2]) ? args[2].toString() : null;
                report(`Log.${m}()`, tag, msg, thr);
                return ov.apply(this, args);
            };
        });
    });

    // --- java.util.logging.Logger (all levels, not just severe) ---
    const Logger = Java.use("java.util.logging.Logger");
    ['severe', 'warning', 'info', 'config', 'fine', 'finer', 'finest'].forEach(m => {
        try {
            Logger[m].overload('java.lang.String').implementation = function (msg) {
                report(`Logger.${m}()`, null, msg, null);
                return this[m](msg);
            };
        } catch (e) { /* method not available */ }
    });

    // --- System.out / System.err (both PrintStream) ---
    const PrintStream = Java.use("java.io.PrintStream");
    ['println', 'print'].forEach(m => {
        try {
            PrintStream[m].overload('java.lang.String').implementation = function (s) {
                report(`PrintStream.${m}()`, null, s, null);
                return this[m](s);
            };
        } catch (e) { /* ignore */ }
    });

    // --- Throwable.printStackTrace() — API named by MASTG but absent from the demo ---
    const Throwable = Java.use("java.lang.Throwable");
    Throwable.printStackTrace.overload().implementation = function () {
        const msg = this.getMessage() ? this.getMessage().toString() : "<no message>";
        report("Throwable.printStackTrace()", this.$className, msg, null);
        return this.printStackTrace();
    };

    // --- Timber (if used by the app) ---
    try {
        const Timber = Java.use("timber.log.Timber");
        ['v', 'd', 'i', 'w', 'e', 'wtf'].forEach(m => {
            Timber[m].overload('java.lang.String', '[Ljava.lang.Object;')
              .implementation = function (msg, args) {
                report(`Timber.${m}()`, null, msg, null);
                return this[m](msg, args);
            };
        });
    } catch (e) { console.log("[i] Timber not found — skipped"); }
});
```

Run it with:

```bash
frida -U -f com.example.target -l log_trace.js -o output.txt
```

This script's advantage over `frida-trace`: it automatically flags lines containing a sensitive pattern (`[!! SENSITIVE !!]`), and prints a **backtrace with logging-framework frames filtered out** — so the original caller is immediately visible (useful when the app uses a custom logger wrapper).

### 3.4 Supplementary Checks

```bash
# 1. The Java hook blind spot: logging from native code
for so in $(find ./extracted -name "*.so"); do
  echo "--- $so"
  strings "$so" | grep -E "__android_log_print|__android_log_write"
done

# 2. Check whether the app writes a log to a FILE (linked to MASTG-TEST-0200)
adb shell "find /sdcard/ -iname '*.log' -o -iname '*log*.txt'"
adb shell "run-as com.example.target ls -la /data/data/com.example.target/files/"

# 3. Verify the ProGuard/R8 configuration (part of the remediation evaluation)
apktool d -s -f -o out ./target-app.apk
grep -rn "assumenosideeffects" ./proguard-rules.pro 2>/dev/null
# If only the APK is available: check whether a Log call still exists in the bytecode
jadx -d ./decompiled ./target-app.apk
grep -rcE "Log\.(v|d|i|w|e|wtf)\(" ./decompiled/sources/ | grep -v ":0$" | head

# 4. Check the OkHttp logging interceptor — the biggest cause of log leakage in practice
grep -rn "HttpLoggingInterceptor\|Level.BODY\|Level.HEADERS" ./decompiled/sources/

# 5. Check WebView console logging
grep -rn "onConsoleMessage\|ConsoleMessage" ./decompiled/sources/

# 6. Check whether a crash reporter attaches log context
grep -rn "Crashlytics.log\|FirebaseCrashlytics\|Sentry.captureMessage\|addBreadcrumb" ./decompiled/sources/

# 7. Bug report — a frequently-overlooked leakage path
adb bugreport ./bugreport.zip
unzip -p ./bugreport.zip | grep -iE "MASTG_CANARY_PWD_7f3a|password|token" | head
```

### 3.5 Alternative Testing Methods (Multi-Tool)

This test has a huge advantage over other dynamic tests: **it has many alternative paths, and some need no root at all**, because logcat can be read via plain `adb`.

#### Method B — Pure `adb logcat` *(no root, no Frida — and also proof of exploitability)*

**This is the method I recommend as a starting point**, not just a comparison. It needs no root, no instrumentation, cannot be blocked by anti-Frida — and its success **simultaneously demonstrates a real attack path**.

```bash
PKG=com.example.target
adb logcat -c                                     # clear the buffer

# Option 1: filter per app PID (cleanest)
adb logcat --pid=$(adb shell pidof -s $PKG) | tee app.log

# Option 2: capture ALL buffers (main, system, crash, events, radio)
adb logcat -b all -v threadtime | tee all.log

# Option 3: dump then analyze offline
adb logcat -d -b all > dump.log

# Search for the canary & secret patterns
grep -inE "MASTG_CANARY_PWD_7f3a|password|token|bearer|authorization|api[_-]?key|eyJ[A-Za-z0-9_-]{10,}" all.log

# Filter by level (W/E only — what should remain in production)
adb logcat --pid=$(adb shell pidof -s $PKG) *:W
```

> **Important point for the report:** the command above runs **without root**, with only USB debugging enabled. This means brief physical access to an unlocked device is enough to harvest logs. Include this as proof of exploitability, not merely as a testing method.

#### Method C — pidcat *(a much more readable logcat)*

```bash
pip install pidcat        # or: brew install pidcat
pidcat com.example.target

# Filter minimum level
pidcat -l W com.example.target

# Only specific tags
pidcat --tag Auth --tag Network com.example.target
```

Output is color-coded per level and automatically follows the app's PID even if the app restarts — very helpful during a long manual exercise session.

#### Method D — Objection *(quick hooking without writing a script)*

```bash
objection -g com.example.target explore

# Monitor the entire Log class
android hooking watch class android.util.Log
android hooking watch class_method android.util.Log.d --dump-args --dump-backtrace
android hooking watch class_method android.util.Log.e --dump-args --dump-backtrace
android hooking watch class_method java.util.logging.Logger.severe --dump-args --dump-backtrace

# Throwable.printStackTrace — an API named by MASTG but absent from the demo
android hooking watch class_method java.lang.Throwable.printStackTrace --dump-backtrace
```

Advantage: `--dump-args` directly shows the recorded value, and `--dump-backtrace` gives the caller — the two things the evaluation criteria need — without writing a single line of JavaScript.

#### Method E — MASTG-TEST-0231: Static Analysis *(the official counterpart)*

MASTG provides a separate static test for logging. Run it alongside this test.

```bash
jadx -d ./decompiled ./target-app.apk
D=./decompiled/sources

# --- Logging APIs named by MASTG ---
rg -n --no-heading "android\.util\.Log|Log\.(v|d|i|w|e|wtf|println)\(" $D
rg -n --no-heading "java\.util\.logging\.Logger|\.severe\(|\.warning\(|\.info\(|\.fine\(" $D
rg -n --no-heading "System\.out\.print|System\.err\.print" $D
rg -n --no-heading "printStackTrace\(\)" $D

# --- Third-party logging libraries (NOT named by MASTG) ---
rg -n --no-heading "timber\.log\.Timber|Timber\.(v|d|i|w|e|wtf)\(" $D
rg -n --no-heading "org\.slf4j|LoggerFactory\.getLogger|logback" $D
rg -n --no-heading "HttpLoggingInterceptor|Level\.BODY|Level\.HEADERS" $D   # the biggest cause
rg -n --no-heading "Crashlytics\.log|FirebaseCrashlytics|Sentry\.|addBreadcrumb" $D
rg -n --no-heading "onConsoleMessage|ConsoleMessage" $D                     # WebView

# --- Verify whether Log has been STRIPPED by R8/ProGuard in release ---
rg -c --no-heading "Log\.(v|d|i|w|e|wtf)\(" $D | grep -v ":0$" | head
#   On a correct release build, the count SHOULD be 0 or very small
rg -n "assumenosideeffects" ./proguard-rules.pro 2>/dev/null

# --- Logging from native code ---
unzip -o ./target-app.apk -d ./apk_x >/dev/null
for so in $(find ./apk_x -name "*.so"); do
  echo "--- $so"; strings "$so" | grep -E "__android_log_print|__android_log_write"
done
```

#### Method F — MobSF *(static + dynamic in one tool)*

```bash
docker run -it --rm -p 8000:8000 -p 1337:1337 \
  opensecurity/mobile-security-framework-mobsf:latest
```

| Section | Content |
|---|---|
| **Code Analysis** (static) | *"The App logs information. Sensitive information should never be logged."* — with a list of code locations |
| **Logcat** (Dynamic Analysis) | A full logcat capture during the dynamic session, ready to grep |
| **API Monitor** | Sensitive API calls including logging |

A major advantage for this test: MobSF combines the static side (TEST-0231) and the dynamic side (TEST-0203) into a single report.

#### Method G — mobsfscan / semgrep *(CI/CD gate)*

```bash
mobsfscan --json -o out.json ./decompiled/sources/
jq '.results | to_entries[] | select(.key | test("log"))' out.json

# Semgrep registry
semgrep --config "r/java.android.security.android-logging.android-logging" ./decompiled/sources/
semgrep --config "p/mobsfscan" ./decompiled/sources/

# Custom rule for the most dangerous pattern: a variable going into Log
cat > log-rules.yml <<'YAML'
rules:
  - id: log-with-variable-interpolation
    severity: WARNING
    languages: [java, kotlin]
    message: "[MASVS-STORAGE-2] A variable value is logged — check its sensitivity"
    pattern-either:
      - pattern: android.util.Log.$M($TAG, $X + $Y)
      - pattern: android.util.Log.$M($TAG, String.format(...))
      - pattern: android.util.Log.$M($TAG, new StringBuilder(...).append(...).toString())
  - id: okhttp-body-logging
    severity: ERROR
    languages: [java, kotlin]
    message: "[MASVS-STORAGE-2] HttpLoggingInterceptor logs the body/headers — token leakage"
    pattern-either:
      - pattern-regex: 'Level\.BODY'
      - pattern-regex: 'Level\.HEADERS'
YAML
semgrep -c log-rules.yml ./decompiled/sources/
```

> The `log-with-variable-interpolation` rule targets the pattern that most often leaks data: `Log.d(TAG, "token: $token")`. A pure constant (`Log.d(TAG, "onCreate")`) doesn't trigger it.

#### Method H — Verifying Secondary Leakage Paths *(often completely overlooked)*

Logs don't just end up in logcat. These three paths need to be checked separately.

```bash
PKG=com.example.target

# --- 1. Bug report — contains a full logcat dump, often sent by users to support ---
adb bugreport ./bugreport.zip
unzip -o ./bugreport.zip -d ./br >/dev/null
grep -rinE "MASTG_CANARY_PWD_7f3a|password|token" ./br/ | head

# --- 2. Logs written to a FILE (linked to MASTG-TEST-0200 & 0207) ---
adb shell "find /sdcard/ -iname '*.log' -o -iname '*log*.txt' -o -iname '*.txt'" | head -30
adb shell "su -c 'find /data/data/$PKG -iname \"*.log\" -o -iname \"*crash*\"'"
adb shell "su -c 'ls -la /data/anr/ /data/tombstones/'"      # ANR trace & tombstone

# --- 3. Crash reporter — log sent to a THIRD-PARTY SERVER ---
rg -n --no-heading "Crashlytics\.log|setCustomKey|Sentry\.captureMessage|addBreadcrumb" \
  ./decompiled/sources/
#   Verify its content via MASTG-TEST-0206 (network capture)
```

This matters for severity: a log **sent to a third-party server** means data leaves the device, not merely stored locally.

#### Method I — Testing RELEASE vs. DEBUG *(a methodological step that determines validity)*

This is not a new tool, but a procedure that determines whether your finding carries production weight.

```bash
# Compare both builds under equivalent sessions
for APK in app-debug.apk app-release.apk; do
  echo "=== $APK"
  adb uninstall $PKG 2>/dev/null
  adb install -g "./$APK"
  adb logcat -c
  echo "--> exercise the app now, then press Enter"; read
  adb logcat -d -b all | grep -icE "MASTG_CANARY_PWD_7f3a|password|token"
done

# Verify whether Log has been stripped in release
jadx -d ./rel ./app-release.apk
rg -c --no-heading "Log\.(v|d|i)\(" ./rel/sources/ | grep -v ":0$" | wc -l
#   A result of 0 = ProGuard/R8 has removed the Log calls
```

If the release build is clean while the debug build is flooded with findings, that means **the control is working** — report it as a PASS with a hygiene note, not as a vulnerability.

---

### 3.6 Method Comparison: When to Use Which

| Method | Tool | Needs root? | Gives a runtime value? | Gives a backtrace? | Third-party library coverage | When to use |
|---|---|---|---|---|---|---|
| **A** | frida-trace / Frida (§3.2–3.3) | Yes/gadget | ✅ | ✅ | ✅ (if hooked) | **Official baseline** — full control |
| **B** | `adb logcat` | **No** | ✅ | ❌ | ✅ **(all, automatically)** | **The best starting point** + proof of exploitability |
| **C** | pidcat | **No** | ✅ | ❌ | ✅ | Same as B, far more readable |
| **D** | Objection | No¹ | ✅ | ✅ | Partial | Quick hooking without writing a script |
| **E** | Static analysis (TEST-0231) | No | ❌ | — | ✅ | **Comprehensive coverage** — code paths not yet exercised |
| **F** | MobSF | No | ✅ | Partial | ✅ | Static + dynamic in a single report |
| **G** | mobsfscan / semgrep | No | ❌ | — | ✅ | CI/CD gate; custom rule for variable interpolation |
| **H** | bugreport / log file / crash reporter | Partial | ✅ | ❌ | ✅ | **Secondary leakage paths** — often completely overlooked |
| **I** | Release vs. debug comparison | No | ✅ | — | ✅ | **Determines the finding's production weight** |

¹ Objection uses Frida; without root it needs frida-gadget.

**Minimum recommended combination:** **B (adb logcat) → E (static) → I (release vs. debug)**.
B is the fastest and most representative method — no root, no risk of being blocked by anti-instrumentation, and the result is direct evidence. E gives coverage over code paths not yet exercised. I ensures your finding is relevant to production. Add **A (Frida)** when you need a backtrace to attribute leakage to a third-party SDK, and **H** always — bug reports and log-to-file are the paths most often missed.

> **Note an important difference from other dynamic tests:** because logcat can be read without root or instrumentation, **anti-Frida does not make this test Inconclusive**. There is always a Method B path available.

---

### 3.7 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rule:**

> **Observation:** *"The output should contain a list of locations where logging APIs are used in the app for the current execution."*
>
> **Evaluation:** *"The test case **fails** if you can find sensitive data being logged using those APIs."*

This test's evaluation is **simpler** than TEST-0200/0201/0202: there is no "and not encrypted" clause. Simply **sensitive data in the log → FAIL**. This makes sense because the purpose of a log is readability; sensitive data that gets logged is in practice always plaintext.

Review guidance from MASTG-DEMO-0006:

> *"Review each of the reported instances by using keywords and known secrets (e.g. passwords or usernames or values you keyed into the app)."*
>
> *"Note: You could refine the test to input a known secret and then search for it in the logs."*

---

#### ❌ FAIL / ISSUE — The check is declared FAILED if:

| No | Condition | Example evidence |
|---|---|---|
| F1 | The trace shows a **password / PIN** being recorded via a logging API | `Log.i("MASTG", "key: MAS-Sensitive-Password")` |
| F2 | The trace shows a **token / API key / session ID / JWT** being recorded | `Log.d("Auth", "Bearer eyJhbGciOiJIUzI1NiIs...")` |
| F3 | The trace shows **cryptographic material** (key, IV, salt, seed phrase) being recorded | `Log.w("MASTG", "test: MAS-Sensitive-Value-IV")`; `Logger.severe("MAS-Sensitive-Key")` |
| F4 | The trace shows **PII** being recorded (name, email, national ID, phone, address, date of birth, location, IMEI, MAC address) | `Log.d("Profile", "user=budi@example.com, nik=3201...")` → also a profile **P (Privacy)** violation |
| F5 | The trace shows **financial/health data** being recorded | `Log.i("Payment", "card=4111111111111111, cvv=123")` |
| F6 | The **canary value** you entered into the app appears in the trace output or in logcat | `grep MASTG_CANARY_PWD_7f3a output.txt` → a match found |
| F7 | `printStackTrace()` / exception logging carries sensitive data in the message or stack trace | `Throwable.printStackTrace()` with the message `HTTP 401 for https://api/login?token=abc123` |
| F8 | **Full HTTP request/response** is logged (OkHttp `HttpLoggingInterceptor` at `Level.BODY`) | The log contains the `Authorization` header and a body with credentials |
| F9 | Sensitive data is logged on a **RELEASE build** (not just debug) | Confirmed by testing the release APK; ProGuard is not configured to strip logs |
| F10 | Sensitive-data logs are **written to a file** and/or sent to a server | Linked to MASTG-TEST-0200; or `Crashlytics.log()` sends sensitive context to a third party |
| F11 | Logs leak **internal details** that facilitate further attacks | Staging endpoint, feature flag, SSL pinning status, internal class names, library version, full SQL query |
| F12 | Logs from **native code** carry sensitive data | `strings lib.so` → `__android_log_print` + review shows credential logging |

**Example output indicating FAIL** (official MASTG-DEMO-0006 result):

Sample code (`MastgTest.kt`):

```kotlin
class MastgTest (private val context: Context){

    fun mastgTest(): String {
        val variable = "MAS-Sensitive-Value"
        val password = "MAS-Sensitive-Password"
        val secret_key = "MAS-Sensitive-Key"
        val IV = "MAS-Sensitive-Value-IV"
        val iv = "MAS-Sensitive-Value-IV-2"

        Log.v("MASTG", "key: $variable")
        Log.i("MASTG", "key: $password")
        Log.w("MASTG", "test: $IV")
        Log.d("MASTG", "test: $iv")
        Log.e("MASTG", "test: $variable")
        Log.wtf("MASTG", "test: $variable")

        val x = Logger.getLogger("myLogger")
        x.severe(secret_key)

        return "Done"
    }
}
```

`frida-trace` output (`output.txt`):

```
Log.v("MASTG", "key: MAS-Sensitive-Value")
Log.i("MASTG", "key: MAS-Sensitive-Password")
Log.w("MASTG", "test: MAS-Sensitive-Value-IV")
Log.d("MASTG", "test: MAS-Sensitive-Value-IV-2")
Log.e("MASTG", "test: MAS-Sensitive-Value")
Log.wtf("MASTG", "test: MAS-Sensitive-Value")
Log.wtf(0, "MASTG", "test: MAS-Sensitive-Value", null, false, false)
Logger.severe("MAS-Sensitive-Key")
```

Comparison logcat (`logcat_output.txt`) — proving the data actually reaches the shared buffer:

```
2024-05-14 10:30:06.864  6966-6966  MASTG   org.owasp.mastestapp  V  key: MAS-Sensitive-Value
2024-05-14 10:30:06.866  6966-6966  MASTG   org.owasp.mastestapp  I  key: MAS-Sensitive-Password
2024-05-14 10:30:06.867  6966-6966  MASTG   org.owasp.mastestapp  W  test: MAS-Sensitive-Value-IV
2024-05-14 10:30:06.867  6966-6966  MASTG   org.owasp.mastestapp  D  test: MAS-Sensitive-Value-IV-2
2024-05-14 10:30:06.867  6966-6966  MASTG   org.owasp.mastestapp  E  test: MAS-Sensitive-Value
2024-05-14 10:30:06.869  6966-6966  MASTG   org.owasp.mastestapp  E  test: MAS-Sensitive-Value
2024-05-14 10:30:06.881  6966-6966  myLogger org.owasp.mastestapp  E  MAS-Sensitive-Key
```

MASTG's evaluation: *"Review each of the reported instances by using keywords and known secrets."* → **FAIL**, because the password, secret key, and IV are all logged.

**Four important technical observations from this demo's output:**

1. **All levels appear, including `Log.v` and `Log.d`.** This is direct proof that verbose/debug logging is **not automatically removed** — explicit ProGuard configuration is needed.
2. **`Log.wtf` appears twice** — once as `Log.wtf("MASTG", ...)` (the public overload) and once as `Log.wtf(0, "MASTG", "...", null, false, false)` (the internal overload called within it). This is normal, not two separate logging events. Don't double-count it when reporting findings.
3. **`Log.wtf` appears in logcat as level `E`**, not a special level.
4. **`Logger.severe()` appears with the tag `myLogger`** (the logger's name) and level `E` — showing that `java.util.logging.Logger` on Android is routed to logcat.

---

#### ✅ PASS — The check is declared PASSED if:

| No | Condition | Example evidence |
|---|---|---|
| P1 | **The trace output is empty** — no logging API was called at all while the app was exercised | `wc -l output.txt` → `0`. Consistent with MASTG-BEST-0002: *"Ideally, a release build shouldn't use any logging functions"* |
| P2 | There is a logging call, but it **only records non-sensitive operational messages** | `Log.e("Net", "Request timeout")`, `Log.i("App", "Cold start completed in 412ms")` — without any sensitive variable values |
| P3 | **The canary value is not found** in either the trace output or logcat after all flows are exercised | `grep -i "MASTG_CANARY_PWD_7f3a" output.txt logcat_dump.txt` → no result |
| P4 | Sensitive data is logged in **redacted/masked** form | `Log.d("Profile", "email=XX, card=XXXX-XXXX-XXXX-1313")`; or `toString()` is overridden to return `Credential XX` |
| P5 | Logging is **gated by `BuildConfig.DEBUG`** and the release APK is proven to log nothing | The trace on the release build is empty; a jadx review shows `if (BuildConfig.DEBUG) Log.d(...)` |
| P6 | `Log` calls are **already stripped by R8/ProGuard** in the release build | `grep -rcE "Log\.(v\|d\|i)\(" ./decompiled/sources/` → 0; `proguard-rules.pro` contains `-assumenosideeffects class android.util.Log` |
| P7 | Log levels are restricted: only `w`/`e` in production, with generic content | Per Android's recommendation: *"Keep only Warning and Error logs in production"* |
| P8 | `HttpLoggingInterceptor` **is not installed** in release, or is set to `Level.NONE` | `grep "Level.BODY\|Level.HEADERS"` → no result in the release build |

**Example output indicating PASS:**

```bash
$ frida-trace -U -f com.example.secureapp --runtime=v8 \
    -j 'android.util.Log!*' -j 'java.util.logging.Logger!*' -o output_raw.txt
# ... exercise the app extensively with a canary value ...
$ cat output_raw.txt | grep -E "(Log|Logger)" | grep -vE "Log\.println|Log\.isLoggable" > output.txt
$ wc -l output.txt
0 output.txt
# => No logging API call on the release build
```

or — there is logging, but it's clean:

```
Log.i("Lifecycle", "onCreate")
Log.e("Network", "Request failed: timeout")
Log.w("Cache", "Cache miss, refetching")
```

```bash
$ grep -iE "MASTG_CANARY_PWD_7f3a|password|token|bearer|api_key|[0-9]{16}" output.txt
# (no result)

$ adb logcat -d | grep -i "MASTG_CANARY_PWD_7f3a"
# (no result)
```

Reinforced by verifying the build configuration:

```proguard
# proguard-rules.pro — Log calls stripped in release
-assumenosideeffects class android.util.Log {
    public static boolean isLoggable(java.lang.String, int);
    public static int v(...);
    public static int d(...);
    public static int i(...);
    public static int w(...);
    public static int e(...);
    public static int wtf(...);
}
```

---

#### ⚠️ Important Notes on Assessment

1. **Test the RELEASE build — this is the most common mistake.** Testing a debug build will flood you with findings that don't reflect the real risk, since debug logging is naturally present in development builds and is usually already stripped in release. If you only have a debug build, **state that as a testing limitation** and don't report the findings at production severity.

2. **An empty trace output ≠ automatic PASS.** Causes of a false pass:
   - The triggering flow was not exercised (sensitive logs often appear in **error handlers**, not the happy path — which is why it's important to deliberately trigger errors).
   - The app uses **Timber or another logger** that was not hooked.
   - Logging from **native code** (`__android_log_print`) — invisible to a Java hook.
   - The app detects Frida and changes its behavior.
   - The hook failed to attach (frida version mismatch, forgot `--runtime=v8`).

   **Mitigation:** validate the script against an app known to fail (MASTestApp) to prove the hook works; correlate with **MASTG-TEST-0231** (static) — if TEST-0231 finds many `Log.d` references but the trace is empty, the status is **inconclusive, not PASS**; and compare with `adb logcat` as an independent path.

3. **Always compare with `adb logcat`.** The MASTG demo includes `logcat_output.txt` specifically for this. The hook proves the API was called; logcat proves the data **reaches the shared buffer** and is therefore accessible to other parties. Both are needed.

4. **Use a canary value — this is the most effective technique for this test.** MASTG recommends it explicitly. Without a canary, it would be hard to distinguish whether the string `"user123"` in the log is real user data or a placeholder.

5. **Don't double-count internal overloads.** Like `Log.wtf` in the demo, which appears twice. The same applies to `Log.v/d/i/w/e`, which internally calls `Log.println` — this is why the `grep -vE "Log\.println"` filter exists in the demo script.

6. **Pay attention to context, not just keywords.** Grepping for the pattern `password` would trigger on `Log.d("Auth", "password field validated")` — which leaks **nothing**. Conversely, `Log.d("X", "u=$a p=$b")` looks harmless yet leaks credentials. Always review the actual value, and use the backtrace to understand the code's context.

7. **Distinguish the log's origin.** Use the backtrace to determine whether the caller is the app's own code, a custom logger wrapper, or a **third-party SDK**. A finding in an SDK is still the app developer's responsibility, but the remediation differs (configuration/update/replace the SDK, or turn off its debug flag).

8. **Severity is modulated by several factors:**

   | Factor | Effect on Severity |
   |---|---|
   | Password / token / private key logged in a release build | **Highest** |
   | Log sent to a third-party server (crash reporter) | Raised — data leaves the device |
   | Log written to a file on external storage | Raised — linked to MASWE-0002, readable by other apps |
   | PII logged (email, national ID, location, IMEI) | Raised on the **privacy/regulatory** dimension, even though it's not a credential |
   | Only occurs in a debug build, release is already stripped | Significantly lowered — note as informational/hygiene |
   | Only non-sensitive internal details (class names, timing) | Low — minor information disclosure |
   | Targeting an old device (< API 16) in `minSdkVersion` | Raised — even an ordinary app can read the log |

9. **Document complete evidence per finding:** the API called along with the level, the tag, the message content (partially redacted if needed but enough to prove the point), the backtrace/code location, **the type of build tested (debug/release)**, the matching logcat excerpt, reproduction steps including the canary value used, and the ProGuard/R8 configuration status. Also note limitations (e.g., native logging not yet analyzed).

---

## 4. Recommendations

### 4.1 Core Principles (in priority order)

**Priority 1 — Don't log sensitive data in the first place.** This is the only remediation that eliminates the root cause. All other techniques (stripping, redaction) are additional defense layers.

Based on Android guidance and MASTG-BEST-0022, **avoid logging**:
- Full request/response headers and bodies
- Authentication tokens, cookies, session identifiers, API keys
- Username, email address, or other personal data unless truly necessary and protected
- Full error objects, diagnostic context, metadata, nested causes, and stack traces
- Backend hostname, staging endpoint, feature flags, internal module/class names
- Certificate validation behavior, SSL pinning status, retry logic, or other network security details

```kotlin
// ❌ WRONG
Log.d(TAG, "login: user=$username pass=$password")
Log.i(TAG, "token=$accessToken")
Log.e(TAG, "API error: $response")            // response could contain PII
e.printStackTrace()                            // the message could contain a URL+token

// ✅ CORRECT — only an operational event, no sensitive value
Log.e(TAG, "Authentication failed")            // generic, no detail
Log.w(TAG, "Network timeout on endpoint #3")
```

**Priority 2 — Remove logging code from the release build (MASTG-BEST-0002).**

MASTG-BEST-0002 states: *"Ideally, a release build shouldn't use any logging functions, making it easier to assess sensitive data exposure."*

Configure ProGuard/R8 (`proguard-rules.pro`) to remove **all** `Log` calls:

```proguard
-assumenosideeffects class android.util.Log
{
  public static boolean isLoggable(java.lang.String, int);
  public static int v(...);
  public static int i(...);
  public static int w(...);
  public static int d(...);
  public static int e(...);
  public static int wtf(...);
}
```

Or a variant that **keeps only warning & error** (per Android's recommendation to *"Keep only Warning and Error logs in production"*) — simply remove the `w(...)` and `e(...)` lines from the block above.

Also make sure shrinking is actually enabled:

```gradle
android {
    buildTypes {
        release {
            minifyEnabled true
            proguardFiles getDefaultProguardFile('proguard-android-optimize.txt'),
                          'proguard-rules.pro'
        }
    }
}
```

> ⚠️ **IMPORTANT WARNING — don't stop here.** MASTG-BEST-0002 gives a critical note: the configuration above only guarantees that the `Log` class method *call* is removed. **If the logged string is built dynamically, the string-building code can remain in the bytecode.**
>
> Example:
> ```kotlin
> Log.v("Private key tag", "Private key [byte format]: $key")
> ```
> The compiled bytecode is equivalent to:
> ```kotlin
> Log.v("Private key tag", StringBuilder("Private key [byte format]: ").append(key).toString())
> ```
> ProGuard guarantees the `Log.v` call is removed. Whether the remainder (`StringBuilder ...`) is also removed **depends on the code's complexity and the ProGuard version**.
>
> **This is a real security risk:** the (now unused) string leaks plaintext data **into memory**, which can be accessed via a debugger or a memory dump.
>
> MASTG states there is no *silver bullet* for this problem, but the recommended solution is to **create a custom logging facility that accepts simple arguments and builds the string internally**:
> ```java
> SecureLog.v("Private key [byte format]: ", key);
> ```
> then configure ProGuard to strip calls to `SecureLog`.

**Priority 3 — Gate logging with a build flag / custom logging facility.**

```kotlin
// A custom logger that is entirely dead in release
object AppLog {
    private const val ENABLED = BuildConfig.DEBUG

    // Simple arguments; the string is built INTERNALLY — preventing a leftover StringBuilder
    fun d(tag: String, prefix: String, value: Any?) {
        if (ENABLED) Log.d(tag, prefix + value)
    }

    fun e(tag: String, msg: String) {
        if (ENABLED) Log.e(tag, msg)
    }
}
```

Then also strip this class in release:

```proguard
-assumenosideeffects class com.example.AppLog { *; }
```

For Timber, use the official pattern: install the `DebugTree` **only** in the debug build.

```kotlin
// Application.onCreate()
if (BuildConfig.DEBUG) {
    Timber.plant(Timber.DebugTree())
}
// In release: no Tree is planted → Timber.d() produces no output
```

**Priority 4 — Redact/mask sensitive data if logging is still needed.**

Techniques recommended by Android:

| Technique | How It Works | Note |
|---|---|---|
| **Tokenization** | Store sensitive data in a vault; log only its token | The strongest option if correlation is still needed |
| **Data masking** | One-way process, part of the data left visible: `1234-5678-9012-3456` → `XXXX-XXXX-XXXX-1313` | ⚠️ **Do not use for passwords or very critical data** |
| **Redaction** | Hide the entire field content: `1234-5678-9012-3456` → `XXXX-XXXX-XXXX-XXXX` | The safest |
| **Filtering** | Apply a string format in the logging library; modify non-constant values before logging | Can be enforced systematically |

Implementation via **overriding `toString()`** so sensitive data never leaks even if the object gets logged accidentally:

```kotlin
data class Credential<T>(val data: String) {
    /** Returns a redacted value to avoid accidental inclusion in logs. */
    override fun toString() = "Credential XX"
}
```

Or a more general sanitizer component:

```kotlin
data class ToMask<T>(private val data: T) {
    // Prevents accidental logging when an error occurs
    override fun toString() = "XX"

    // Makes access to sensitive data explicit & hard to do accidentally
    fun getDataToMask(): T = data
}

data class Person(
    val email: ToMask<String>,
    val username: String
)

fun main() {
    val person = Person(ToMask("name@gmail.com"), "myname")
    println(person)                         // Person(email=XX, username=myname)
    println(person.email.getDataToMask())   // "name@gmail.com"
}
```

This pattern is effective because it protects against the most common leakage path: someone logging an **entire object** (`Log.d(TAG, "$user")`) without realizing its content.

**Priority 5 — Enforce structurally, don't rely on manual discipline.**

- Use **ErrorProne** with the `@CompileTimeConstant` annotation so only compile-time constants are allowed into log parameters — this prevents runtime variables from being logged, enforced by the compiler.
- Avoid unpredictable log content.
- Configure the `logcat` backend **only for developer builds**.
- Apply the *principle of least privilege* to data entering the log.
- Use **automatic stripping with R8** instead of manual removal.

**Priority 6 — Close secondary leakage paths.**

```kotlin
// ❌ OkHttp: never use Level.BODY / Level.HEADERS in release
val logging = HttpLoggingInterceptor().apply {
    level = if (BuildConfig.DEBUG) HttpLoggingInterceptor.Level.BASIC
            else HttpLoggingInterceptor.Level.NONE
}
```

- **Don't use `printStackTrace()`.** Replace it with controlled logging that only records the exception type, without the message or stack trace: `Log.e(TAG, "Op failed: ${e.javaClass.simpleName}")`.
- **Don't write logs to external storage.** If a local log is genuinely needed (e.g., to be sent to an endpoint when online, as in the legitimate scenario in MASTG-KNOW-0049), store it in **internal storage** and **encrypt it** — see MASTG-TEST-0200 and MASWE-0002.
- **Audit the crash reporter.** Ensure `Crashlytics.log()` / Sentry breadcrumbs don't carry PII or credentials, since that data is sent to a third-party server.
- **WebView:** don't forward `ConsoleMessage` to `Log` in the release build.
- **Native code:** remove `__android_log_print` from the release build (e.g., with an `#ifndef NDEBUG` macro).

**Priority 7 — Prepare an incident response mechanism.** If production logging must be kept, prepare a **conditional flag to turn off logging during an incident**. Prioritize: deployment security, deployment speed & ease, completeness of log redaction, memory usage, then the performance cost of scanning log messages.

### 4.2 Remediation Checklist

- [ ] Every logging instance from the trace output has been reviewed and classified (sensitive / not)
- [ ] No password, PIN, token, API key, session ID, or JWT is logged
- [ ] No cryptographic material (key, IV, salt, seed phrase) is logged
- [ ] No PII (name, email, national ID, phone, address, location, IMEI, MAC) is logged
- [ ] No financial/health data is logged
- [ ] No full HTTP request/response is logged; `HttpLoggingInterceptor` = `Level.NONE` in release
- [ ] `printStackTrace()` has been removed/replaced with controlled logging
- [ ] No sensitive internal details (staging endpoint, feature flag, SSL pinning status) are in the log
- [ ] `proguard-rules.pro` contains `-assumenosideeffects class android.util.Log` and `minifyEnabled true` is active in release
- [ ] **Verified that dynamic strings are not left behind in the bytecode** after stripping (risk of leakage into memory)
- [ ] A custom logging facility is used with simple arguments (string built internally), and its calls are stripped in release
- [ ] Timber's `DebugTree` is installed only when `BuildConfig.DEBUG`
- [ ] Unavoidable sensitive logging has been redacted/masked; `toString()` is overridden for sensitive objects
- [ ] `@CompileTimeConstant` (ErrorProne) is applied to logging parameters, where possible
- [ ] Production log levels are restricted to `w`/`e` with generic content
- [ ] Logs are not written to external storage; if a local log is needed, it is written to internal storage and encrypted
- [ ] The crash reporter (Crashlytics/Sentry) is audited — does not send PII/credentials to a third party
- [ ] Logging from native code (`__android_log_print`) is removed in the release build
- [ ] WebView `onConsoleMessage` does not forward to `Log` in release
- [ ] A conditional flag is available to turn off logging during an incident
- [ ] **Re-verify on the RELEASE APK:** rerun MASTG-TEST-0203 → trace output is empty or clean of sensitive data
- [ ] **Cross-verify:** run MASTG-TEST-0231 (static) to find logging calls on code paths not yet exercised
- [ ] **Verify logcat:** `adb logcat` + grep canary value → no result

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0203: Runtime Use of Logging APIs](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0203/)
- [MASTG-TEST-0231: References to Logging APIs](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0231/)
- [MASTG-TEST-0003: Testing Logs for Sensitive Data](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0003/) *(deprecated — superseded by MASTG-TEST-0203 & 0231)*
- [MASWE-0005: Insertion of Sensitive Data into Logs](https://mas.owasp.org/MASWE/MASVS-STORAGE/MASWE-0005/)
- [MASTG-DEMO-0006: Tracing Common Logging APIs Looking for Secrets](https://mas.owasp.org/MASTG/demos/android/MASVS-STORAGE/MASTG-DEMO-0006/MASTG-DEMO-0006/)
- [MASTG-KNOW-0049: Logs](https://mas.owasp.org/MASTG/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0049/)
- [MASTG-BEST-0002: Remove Logging Code](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0002/)
- [MASTG-BEST-0022: Disable Verbose and Debug Logging in Production Builds](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0022/) *(iOS platform — the principle applies generally)*
- [MASTG-TECH-0043: Method Hooking](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0043/)
- [MASTG-TECH-0005: Installing Apps](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0005/)
- [MASTG-TECH-0013: Reverse Engineering Android Apps](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/)
- [MASTG-TECH-0014: Static Analysis on Android](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/)
- [MASTG-TOOL-0001: Frida](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0001/)
- [MASTG-TOOL-0022: ProGuard](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0022/)
- [MASVS-STORAGE: Storage](https://mas.owasp.org/MASVS/05-MASVS-STORAGE/)
- [OWASP MASTG Repository (GitHub)](https://github.com/OWASP/mastg)
- [OWASP Mobile Top 10 2024 — M9: Insecure Data Storage](https://owasp.org/www-project-mobile-top-10/2023-risks/m9-insecure-data-storage)
- [OWASP Mobile Top 10 2024 — M1: Improper Credential Usage](https://owasp.org/www-project-mobile-top-10/2023-risks/m1-improper-credential-usage.html)

### 5.2 Official Android / Google Documentation

- [Log Info Disclosure — Android Security Risks](https://developer.android.com/privacy-and-security/risks/log-info-disclosure)
- [`android.util.Log` — API reference](https://developer.android.com/reference/kotlin/android/util/Log)
- [`java.util.logging.Logger` — API reference](https://developer.android.com/reference/java/util/logging/Logger)
- [`READ_LOGS` permission — API reference](https://developer.android.com/reference/android/Manifest.permission#READ_LOGS)
- [Logcat command-line tool](https://developer.android.com/tools/logcat)
- [View logs with Logcat (Android Studio)](https://developer.android.com/studio/debug/logcat)
- [Shrink, obfuscate, and optimize your app (R8/ProGuard)](https://developer.android.com/build/shrink-code)
- [Enable shrinking, obfuscation, and optimization](https://developer.android.com/studio/build/shrink-code#enable)
- [Capture and read bug reports](https://developer.android.com/studio/debug/bug-report)
- [App security best practices](https://developer.android.com/privacy-and-security/security-best-practices)
- [Android Keystore system](https://developer.android.com/privacy-and-security/keystore)
- [ProGuard manual — example of removing logging code (Guardsquare)](https://www.guardsquare.com/en/products/proguard/manual/examples#logging)
- [ErrorProne — `@CompileTimeConstant` bug pattern](https://errorprone.info/bugpattern/CompileTimeConstant)
- [Timber — logging library (JakeWharton)](https://github.com/JakeWharton/timber)
- [OkHttp `HttpLoggingInterceptor`](https://square.github.io/okhttp/features/interceptors/)

### 5.3 Standards, Taxonomy, and Other Guidelines

- [CWE-532: Insertion of Sensitive Information into Log File](https://cwe.mitre.org/data/definitions/532.html)
- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
- [CWE-312: Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)
- [CWE-359: Exposure of Private Personal Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/359.html)
- [CWE-117: Improper Output Neutralization for Logs](https://cwe.mitre.org/data/definitions/117.html)
- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
- [OWASP ASVS V7 — Error Handling and Logging](https://owasp.org/www-project-application-security-verification-standard/)
- [NVD — CVE-2023-21387 (Android User Backup Manager log info disclosure)](https://nvd.nist.gov/vuln/detail/CVE-2023-21387)
- [NVD — CVE-2018-6599](https://nvd.nist.gov/vuln/detail/CVE-2018-6599)
- [NIST SP 800-163 Rev.1 — Vetting the Security of Mobile Applications](https://csrc.nist.gov/publications/detail/sp/800-163/rev-1/final)
- [CISA — Principle of Least Privilege](https://www.cisa.gov/uscert/bsi/articles/knowledge/principles/least-privilege)
- [MITRE ATT&CK Mobile — T1409: Stored Application Data](https://attack.mitre.org/techniques/T1409/)
- [MITRE ATT&CK Mobile — T1636: Protected User Data](https://attack.mitre.org/techniques/T1636/)

### 5.4 Security Research & Technical Articles

- [USENIX Security 2023 — *Log: It's Big, It's Heavy, It's Filled with Personal Data!*](https://www.usenix.org/system/files/sec23fall-prepub-89-lyons.pdf)
- [Thore Göbel — *Please Don't Write Passwords to Android Logs*](https://thore.io/posts/2023/05/please-dont-write-passwords-to-android-logs/)
- [TechRadar — Android devices are leaking contact tracing data all over the place](https://www.techradar.com/news/android-devices-are-leaking-contact-tracing-data-all-over-the-place)
- [arXiv — Dissecting contact tracing apps in the Android platform](https://arxiv.org/pdf/2008.00214)
- [Valency Networks — Sensitive Information Exposure via System Logs (Logcat Leakage)](https://www.valencynetworks.com/kb/sensitive-information-exposure-via-system-logs.html)
- [Medium — Android Logcat: The Hidden Goldmine of Sensitive Data for Pentesters](https://medium.com/@gowthami09027/android-logcat-the-hidden-goldmine-of-sensitive-data-for-pentesters-66a11109781a)
- [PTKD Journal — Insecure logging: sensitive data in your app's logs](https://ptkd.com/journal/insecure-logging-sensitive-data-app-logs)
- [Haxoris Wiki — Tokens Leaked In Logs](https://haxoris.com/haxoris-wiki/mobile-owasp-top-10/m1-improper-credential-usage/tokens-in-logs)
- [Securium Solutions — Sensitive information using logs cause leak of user details, password, token](https://securiumsolutions.com/sensitive-information-using-logs-cause-leak-of-users-personal-details-password-token/)
- [HackTricks — Android Applications Pentesting](https://book.hacktricks.wiki/en/mobile-pentesting/android-app-pentesting/index.html)

### 5.5 Tool Documentation

- [Frida — Documentation Home](https://frida.re/docs/home/)
- [Frida — `frida-trace` CLI reference](https://frida.re/docs/frida-trace/)
- [Frida — JavaScript API: `Java`](https://frida.re/docs/javascript-api/#java)
- [Frida — Android instrumentation guide](https://frida.re/docs/android/)
- [Objection — runtime mobile exploration](https://github.com/sensepost/objection)
- [pidcat — colored logcat per package](https://github.com/JakeWharton/pidcat)
- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [Semgrep — Documentation](https://semgrep.dev/docs/)
- [mobsfscan — static analysis for Android/iOS](https://github.com/MobSF/mobsfscan)
- [TruffleHog — secret scanning](https://github.com/trufflesecurity/trufflehog)

---

*This document was prepared based on OWASP MASTG (current release as of September 2026), official Frida and Android Developers documentation, CWE/NIST/OWASP standards, and third-party security research.*
