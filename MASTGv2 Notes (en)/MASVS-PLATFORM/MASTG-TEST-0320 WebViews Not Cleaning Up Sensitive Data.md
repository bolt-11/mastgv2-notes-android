# MASTG-TEST-0320 WebViews Not Cleaning Up Sensitive Data

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0320 |
| **Platform** | Android |
| **MASVS Category** | MASVS-PLATFORM |
| **Weakness** | MASWE-0001 |
| **Test Type** | Dynamic, Hooks |
| **Related Techniques** | MASTG-TECH-0005 (Installing Apps), MASTG-TECH-0043 (Method Hooking), MASTG-TECH-0002 (Host-Device Data Transfer), MASTG-TECH-0143 (Monitor File System Operations in WebViews) |
| **Related Best Practice** | MASTG-BEST-0028 (WebViews Cache Cleanup) |
| **Related Knowledge** | MASTG-KNOW-0018 (WebViews) |
| **Prerequisite** | `identify-sensitive-data` |
| **Official Rule** | — (none; the four existing WebView rules — `mastg-android-webview-allow-local-access.yml`, `mastg-android-webview-bridges.yml`, `mastg-android-webview-safebrowsing.yml`, `mastg-android-webview-url-handlers.yml` — target other WebView topics, not storage cleanup, consistent with this test's dynamic nature) |

---

## 1. Explanation

### 1.1 Testing Objective

Official MASTG overview excerpt:

> *"This test verifies whether the app cleans up sensitive data used by WebViews. Apps can enable several specific storage areas in their WebViews and not clean them up properly, leading to sensitive data being stored on the device longer than necessary."*

This test targets the risk of **excessive data retention** — it is not about whether the WebView *stores* data (that is normal, necessary behavior for performance), but rather whether the application **cleans up** that data once it is no longer needed (e.g., after logout, or after the WebView is closed). Unlike many other tests in this research series that are static-first-dynamic-second, this test is **purely dynamic from the start** — there is no official semgrep rule for this test, and logically it is indeed difficult to build one statically because it requires observing the **actual filesystem contents** after a series of application interactions.

### 1.2 The Four Enablement and Cleanup API Pairs That Must Be Matched

The official overview provides an explicit list of "enable" vs "cleanup" API pairs — this is the core framework for evaluating this test:

| Storage Area | API That Enables It | Expected Cleanup API |
|---|---|---|
| **HTTP Cache** | `WebSettings.setAppCacheEnabled()` *(deprecated/removed API 33)* or `setCacheMode()` ≠ `LOAD_NO_CACHE` | `WebView.clearCache(includeDiskFiles = true)` |
| **DOM Storage** (localStorage/sessionStorage) | `WebSettings.setDomStorageEnabled(true)` | `WebStorage.deleteAllData()` |
| **WebSQL Database** *(deprecated API 35)* | `WebSettings.setDatabaseEnabled(true)` | `WebStorage.deleteAllData()` |
| **Cookies** | `CookieManager.setAcceptCookie()` — **default `true`**, must be set to `false` explicitly to disable | `CookieManager.removeAllCookies(callback)` |

Important note: for Cookies, **the application default is to accept cookies** — meaning that if the developer never touches this setting at all, the default behavior still enables cookie storage, making explicit cleanup a hidden obligation, not optional.

### 1.3 Critical Nuance: A WebView Can Create Files Even If the Developer Never Calls the API Directly

This is the most important methodological point in this entire test:

> *"Regardless of whether the app uses these APIs directly, WebViews may use them internally when rendering content (e.g., JavaScript code using localStorage). So tracing calls to APIs such as open, openat, opendir, unlinkat, etc., can help identify file operations in the WebView storage directory."*

This means a **developer may never explicitly call `setDomStorageEnabled()`** at all, yet if the web page loaded in the WebView has JavaScript that calls `localStorage.setItem(...)`, data is still persisted to disk — because DOM storage is **enabled by default** on all supported WebView versions (confirmed by MASTG-KNOW-0018: *"DOM storage is enabled by default on all supported WebView versions"*). This means code auditing alone (grepping for specific API calls) **is not enough** — testers must trace low-level filesystem operations (`open`, `openat`, `unlinkat`) to capture activity triggered by third-party JavaScript inside the loaded page, not just the application's Kotlin/Java code.

### 1.4 Why There Is No Official "Delete Everything at Once" API

MASTG-KNOW-0018 confirms an architectural fact highly relevant to evaluation expectations:

> *"Android does not provide a dedicated API to delete the Chromium profile under app_webview. Apps must not attempt to delete this directory directly."*

Developers **cannot** simply call a single "clean up all WebView storage" API — they must call a **combination of several different APIs** (`clearCache`, `deleteAllData`, `removeAllCookies`) manually, and some modern storage types **cannot be cleaned up at all** via a public API:

> *"IndexedDB and OPFS are managed internally by Chromium and are not covered by the WebStorage API. They cannot be deleted with Java file APIs... Clearing requires deleting the entire WebView profile."*
>
> *"SQLite Wasm databases live inside OPFS... Clearing requires deleting the entire WebView profile."*

This is a **permanent architectural gap** — if an application loads a web page using IndexedDB or SQLite Wasm (OPFS) to store sensitive data, **there is no granular way** to clean it up without deleting the *entire* WebView profile (`ActivityManager.clearApplicationUserData()`), which would also delete non-sensitive data from other sources that might be worth retaining. Developers are faced with a real trade-off between privacy (delete everything) and user experience (retain data).

### 1.5 Real Risk: No Guarantee That the Cleanup Method Is Always Called

MASTG-BEST-0028's official note reveals a fundamental weakness of the "call clear on onDestroy" approach:

> *"The lack of a guarantee that the clear method will always be called, particularly if the app process is killed abruptly. In this case, evaluation of prior cache clearing and active clearing would be required, such as at the next app start."*

On Android, an application process can be force-killed by the system (low memory killer) without fully invoking lifecycle callbacks (`onDestroy`) — if cleanup logic is only placed in `onDestroy()`, this scenario will **always** leave residual data. This explains why good recommendations (§4) always include **proactive cleanup at the next app start** as a second line of defense, not relying solely on reactive cleanup on exit.

### 1.6 Real-World Case: Session Cookie Stored Raw in WebView SQLite (Apache Cordova)

A real case documented in the official **Apache Cordova** tracker (CB-9641) shows exactly the risk this test targets:

> *"A Cordova application using a Java web service with session cookie authentication discovered through security audit that the cookie's value was stored within the SQLite database at `/data/data/com.my.app/app_webview/Cookies`, which was easily viewable via SQLiteManager on a rooted phone."*

This case proves two things at once: (1) the authentication session cookie was indeed **stored in plaintext**, readable directly through an ordinary SQLite manager on a rooted device — no sophisticated exploit required; (2) independent research (Securing.pl) confirms that even when `setAllowFileAccess(false)` is enabled — which a developer might mistakenly assume is sufficient to secure the WebView — the **`app_webview` directory remains accessible to the WebView itself** for storing LocalStorage, because that setting only controls the WebView's access to external `file://` URLs, not its own internal storage.

---

## 2. Tools Used for Testing

### 2.1 Required Tools (Core, Per MASTG-TECH)

| Tool | Function |
|---|---|
| **Frida** | Hooking WebView enable/cleanup APIs (MASTG-TECH-0043) |
| **ADB** | Installing the app, pulling the `app_webview` directory (MASTG-TECH-0002/0005) |

### 2.2 Alternative & Supporting Tools for Filesystem Tracing

| Tool | Function |
|---|---|
| **strace** | Monitors kernel-level system calls (`open`, `openat`, `unlinkat`) directly against the process (MASTG-TECH-0032) |
| **lsof** | Shows files currently open by a process (`lsof -p <pid> | grep app_webview`, MASTG-TECH-0027) |
| **fsmon** (NowSecure) | A lightweight cross-platform (Linux/Android/iOS/macOS) filesystem monitoring tool — a lighter alternative to strace for tracing I/O events specific to a directory |
| **Android `FileObserver` / inotify** | Kernel-level mechanism for monitoring filesystem events (read/write/move/delete) — the basis of many of the monitoring tools above |
| **Objection** | Exploring and downloading the `app_webview` directory without needing full root / a debuggable app |
| **SQLiteManager / DB Browser for SQLite** | Directly opening the `Cookies`/WebSQL file found in `app_webview` to verify the content of sensitive data (per the real-world Cordova CB-9641 case) |

### 2.3 Environment Prerequisites

- **Rooted device / emulator** for full access to `/data/data/<app_package>/app_webview/`.
- **An agreed-upon definition of sensitive data** at the start (the `identify-sensitive-data` prerequisite), and **a log of the data entered during testing** so it can be matched against at the end.
- Understand that some storage types (IndexedDB, OPFS, SQLite Wasm) do not appear as ordinary files that are easy to read — they need special handling during pull and inspection.

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0005** to install the application.
2. Use **MASTG-TECH-0043** to hook the relevant APIs.
3. Exercise the application extensively, entering sensitive data wherever possible.
4. Close the application.
5. Use **MASTG-TECH-0002** to pull the `/data/data/<app_package>/app_webview/` directory, or search directly for sensitive data within it.

### 3.2 Method A — Frida: Hook the Enable & Cleanup APIs Together

```javascript
Java.perform(function () {
    var WebSettings = Java.use("android.webkit.WebSettings");
    WebSettings.setDomStorageEnabled.implementation = function (flag) {
        console.log("[setDomStorageEnabled] " + flag);
        return this.setDomStorageEnabled(flag);
    };
    WebSettings.setCacheMode.implementation = function (mode) {
        console.log("[setCacheMode] " + mode);
        return this.setCacheMode(mode);
    };

    var WebView = Java.use("android.webkit.WebView");
    WebView.clearCache.implementation = function (includeDiskFiles) {
        console.log("[clearCache] includeDiskFiles=" + includeDiskFiles);
        return this.clearCache(includeDiskFiles);
    };

    var WebStorage = Java.use("android.webkit.WebStorage");
    WebStorage.deleteAllData.implementation = function () {
        console.log("[WebStorage.deleteAllData] called");
        return this.deleteAllData();
    };

    var CookieManager = Java.use("android.webkit.CookieManager");
    CookieManager.removeAllCookies.implementation = function (callback) {
        console.log("[CookieManager.removeAllCookies] called");
        return this.removeAllCookies(callback);
    };
});
```

### 3.3 Method B — strace: Tracing Filesystem Operations Directly (Per MASTG-TECH-0143)

```bash
# Get the target application's process PID
adb shell pidof com.example.targetapp

# Trace file-operation system calls specific to the app_webview directory
adb shell strace -f -e trace=open,openat,opendir,unlinkat -p <PID> 2>&1 | grep app_webview
```

This approach captures file operations **triggered internally by the WebView** (including by JavaScript's `localStorage`), not just explicit Java API calls — closing the gap described in §1.3.

### 3.4 Method C — fsmon as a Lighter Alternative to strace

```bash
adb push fsmon /data/local/tmp/
adb shell /data/local/tmp/fsmon -p <PID> /data/data/com.example.targetapp/app_webview
```

`fsmon` (developed by NowSecure) gives more readable filesystem event output compared to raw `strace`, useful for long monitoring sessions during an app exercise.

### 3.5 Method D — lsof for a Snapshot of Open Files

```bash
adb shell "lsof -p $(adb shell pidof com.example.targetapp) | grep app_webview"
```

Useful as a quick check at a specific point in time (e.g., right before closing the app) to see which files are still actively open by the WebView process.

### 3.6 Method E — Pull and Manual Inspection with Objection/SQLite Browser

```bash
objection -g com.example.targetapp explore
# inside the REPL:
filesystem download app_webview webview_dump --folder
```

```bash
sqlite3 webview_dump/Default/Cookies "SELECT host_key, name, value FROM cookies;"
sqlite3 webview_dump/Default/Local\ Storage/leveldb "..." # inspect LevelDB localStorage content
```

Matching this finding directly against the real-world CB-9641 case (§1.6) — a plaintext-stored session cookie can be read directly via an ordinary SQL query.

### 3.7 Method Comparison: When to Use Which

| Method | Tool | When to Use |
|---|---|---|
| **A** | Frida hooking | Confirming which API is (or is not) actually called by the application's code |
| **B** | strace | Capturing file operations triggered internally by the WebView/JavaScript, including ones invisible to Java hooking |
| **C** | fsmon | Long-term monitoring that is more readable than raw strace |
| **D** | lsof | A quick snapshot of currently-open files |
| **E** | Objection + SQLite browser | Verifying the actual content of sensitive data in the files found |

**Minimum combination I recommend:** **A (API hooking) + B/C (filesystem tracing, closing the gap in §1.3) → E (content verification)**, following the order of the official steps (install → hook → exercise → close → pull & search).

---

### 3.8 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rule:**

> **Evaluation:** *"The test case fails if the app still has sensitive data on the `/data/data/<app_package>/app_webview/` directory after the app is closed. This could be due to the app not calling the relevant cleanup APIs after using the WebView."*

---

#### ❌ FAIL / ISSUE — The check is declared FAILED if:

| No | Condition |
|---|---|
| F1 | Sensitive data entered during the exercise (§1.3, per the definition from the `identify-sensitive-data` prerequisite) is **still found** inside `/data/data/<app_package>/app_webview/` after the application is closed |
| F2 | The storage-enabling API is called/active by default, but **no** paired cleanup API call is detected via hooking (Method A) |

**Example evidence (illustrative, based on the pattern of the real-world CB-9641 case):**

```
$ sqlite3 webview_dump/Default/Cookies "SELECT host_key, name, value FROM cookies;"
api.example.com|session_token|eyJhbGciOiJIUzI1NiJ9.eyJ1c2VySWQiOiI0MjIxIn0...
```

Interpretation: the user's authentication session token (after they had already logged out before the app was closed) **remains stored in plaintext** in the WebView's cookie database. **FAIL**.

---

#### ✅ PASS — The check is declared PASSED if:

| No | Condition |
|---|---|
| P1 | After an extensive exercise and closing the app, **no** sensitive data is found anywhere in the `app_webview` directory |
| P2 | The paired cleanup APIs (`clearCache`, `deleteAllData`, `removeAllCookies`) are proven to be called (via hooking) at the right point (logout, `onDestroy`, or before the next app start as a second line of defense per §1.5) |
| P3 | For storage that cannot be cleaned up granularly (IndexedDB/OPFS/SQLite Wasm), the application **does not store any sensitive data** in that storage at all (architectural mitigation, not cleanup) |

---

#### ⚠️ Important Notes on Evaluation

1. **This test is explicitly acknowledged by MASTG itself as difficult to evaluate with certainty** — the official note states: *"It can be challenging to determine whether the right cleanup APIs were called for the enabled storage areas."* Testers must be transparent about their level of confidence in findings, not claim absolute certainty.

2. **"No sensitive data found" could be a false negative if the exercise was not thorough** — if not all flows were successfully triggered during the testing session (e.g., a logout scenario was never tested), a PASS conclusion must be noted as limited to the flows actually tested.

3. **IndexedDB/OPFS/SQLite Wasm is an architectural gap, not a developer mistake** — the absence of a granular cleanup API for this storage (§1.4) means the **only real mitigation** is to not put sensitive data there in the first place; findings of sensitive data in this type of storage should be recorded as a **design risk**, not merely "forgot to call the cleanup API."

4. **A force-killed process is a test scenario that is often overlooked** — consider adding a **force-stop** test scenario (`adb shell am force-stop <package>`) in addition to normal exit, to verify whether cleanup still occurs under abnormal conditions (§1.5).

5. **Severity is modulated:**

   | Factor | Severity |
   |---|---|
   | Authentication credentials/tokens stored in plaintext and extractable via ordinary filesystem access (rooted device) | **High** |
   | Non-credential sensitive data (e.g., search history) stored without cleanup | **Medium** |
   | Residual data only appears under an abnormal force-kill scenario, not in a normal flow | **Medium-Low**, but still noted because this condition commonly occurs on real devices (low memory killer) |

6. **Document:** the active enablement APIs, the cleanup APIs called (or not), the results of searching for sensitive data in `app_webview` with specific file paths, and which exercise scenarios succeeded/failed to trigger.

---

## 4. Recommendations

### 4.1 Pair Every Enablement API with Its Corresponding Cleanup

```kotlin
override fun onDestroy() {
    webView.clearCache(true)
    WebStorage.getInstance().deleteAllData()
    CookieManager.getInstance().removeAllCookies(null)
    CookieManager.getInstance().flush()
    super.onDestroy()
}
```

### 4.2 Second Line of Defense: Proactive Cleanup on Startup

Given that `onDestroy()` is not guaranteed to always be called (§1.5), add a check/cleanup at the next app start as a safety net for the case of a force-killed process.

### 4.3 Prefer Server-Side Cache Prevention (Per MASTG-BEST-0028)

```http
Cache-Control: no-store, no-cache
```

Sending this header from API/endpoints that feed sensitive data to the WebView prevents caching from the start, avoiding the need to manually clean the cache later.

### 4.4 Avoid Placing Sensitive Data in IndexedDB/OPFS If It Cannot Be Cleaned Granularly

For storage without a granular cleanup API, evaluate whether sensitive data truly needs to be stored there — if it must, consider `ActivityManager.clearApplicationUserData()` on logout even though it deletes the entire WebView profile.

### 4.5 Consider WebView Alternatives

Per MASTG-KNOW-0018, **Trusted Web Activities** and **Custom Tabs** move JavaScript execution and storage into the user's browser context (following the browser's security model and update cycle), freeing the application from the obligation of WebView storage cleanup entirely — relevant to consider if the application does not strictly need an embedded WebView.

### 4.6 Remediation Checklist

- [ ] Every enabled storage area (cache, DOM storage, WebSQL, cookies) has a corresponding cleanup
- [ ] Cleanup is called at logout AND as a second line of defense at app start
- [ ] Server-side `Cache-Control` headers are used for sensitive content, not relying solely on client-side cleanup
- [ ] No sensitive data is stored in IndexedDB/OPFS/SQLite Wasm without mitigation
- [ ] Re-tested with a force-stop scenario, not just a normal exit

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0320 (source, tests-beta)](https://github.com/OWASP/mastg/blob/master/tests-beta/android/MASVS-PLATFORM/MASTG-TEST-0320.md)
- [MASTG-KNOW-0018: WebViews](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0018/)
- [MASTG-BEST-0028: WebViews Cache Cleanup](https://github.com/OWASP/mastg/blob/master/best-practices/MASTG-BEST-0028.md)
- [MASTG-TECH-0143: Monitor File System Operations in WebViews](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0143/)
- [MASTG-TECH-0002: Host-Device Data Transfer](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0002/)

### 5.2 Real-World Cases and Research

- [Apache Cordova JIRA CB-9641: Android WebView Writing Session Cookies to SQLite Database](https://issues.apache.org/jira/browse/CB-9641)
- [Securing.pl: WebView Security Issues in Android Applications](https://www.securing.pl/en/webview-security-issues-in-android-applications/)
- [SecureLayer7: Android WebView Vulnerabilities: Risks and Hardening](https://blog.securelayer7.net/android-webview-vulnerabilities/)
- [NIST Mobile Threat Catalogue — APP-8](https://pages.nist.gov/mobile-threat-catalogue/application-threats/APP-8.html)
- [CMU SEI — DRD22: Do Not Cache Sensitive Information](https://wiki.sei.cmu.edu/confluence/spaces/android/pages/87150623/DRD22.+Do+not+cache+sensitive+information)

### 5.3 Tool Documentation

- [fsmon — Filesystem Monitor Tool (NowSecure)](https://github.com/nowsecure/fsmon)
- [Android FileObserver Documentation](https://developer.android.com/reference/android/os/FileObserver)
- [Objection — Runtime Mobile Exploration](https://github.com/sensepost/objection)
- [strace man page](https://man7.org/linux/man-pages/man1/strace.1.html)

---

*This document is compiled based on official OWASP MASTG content (`tests-beta/android/MASVS-PLATFORM/MASTG-TEST-0320.md`, `MASTG-KNOW-0018`, `MASTG-BEST-0028`), a real-world session cookie leak case from the official Apache Cordova tracker (CB-9641), and industry research (Securing.pl, SecureLayer7) on the common developer misconception that `setAllowFileAccess(false)` is sufficient to secure the `app_webview` directory — when in fact that setting does not prevent the WebView from storing its own LocalStorage/cookies. The most important methodological nuance: the architectural gap in IndexedDB/OPFS/SQLite Wasm (no granular cleanup API) makes some FAIL findings from this test a design risk that can only be mitigated at the architectural decision level, not merely "the developer forgot to call the cleanup API."*
