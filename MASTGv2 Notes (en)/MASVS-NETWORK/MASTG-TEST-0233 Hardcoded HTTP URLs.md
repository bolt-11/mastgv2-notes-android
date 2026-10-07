# MASTG-TEST-0233 Hardcoded HTTP URLs

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0233 |
| **Platform** | Android |
| **MASVS Category** | MASVS-NETWORK (MASVS-NETWORK-1: All network traffic is encrypted using TLS) |
| **Weakness** | MASWE-0026 — *Network Traffic Not Encrypted* |
| **Test Type** | Static, Code |
| **Profile** | L1, L2 |
| **Related Techniques** | MASTG-TECH-0013 (Reverse Engineering), MASTG-TECH-0019 (Retrieving Strings) |
| **Related Tests** | **MASTG-TEST-0235** (Cleartext Traffic Config — the configuration that determines whether HTTP can actually run), **MASTG-TEST-0236** (Cleartext Traffic in Network Traffic Capture — dynamic evidence), **MASTG-TEST-0238** (Runtime Use of Networking APIs) |
| **Related Demo** | — (MASTG does not yet provide an official demo for this test) |
| **Official Rule** | — (no official semgrep rule exists; literal URL detection is simple enough for ordinary grep/regex) |
| **Related CWE** | CWE-295, CWE-296, CWE-297 (related to certificate validation — relevant because HTTP removes TLS entirely rather than merely weakening validation) |

---

## 1. Explanation

### 1.1 Testing Objective

Quote from the official MASTG overview:

> *"An Android app may have hardcoded HTTP URLs embedded in the app binary, library binaries, or other resources within the APK. These URLs may indicate potential locations where the app communicates with servers over an unencrypted connection."*

This test is purely **static**: it searches for the literal string `http://` (not `https://`) wherever it may appear inside the APK — application code, bundled third-party libraries, resource files (XML, JSON, config), and even native libraries (`.so`).

### 1.2 A Very Important Official Warning: Presence ≠ Usage

MASTG explicitly includes a **Limitations** block in its official overview — a crucial piece that distinguishes this test from most other static tests:

> *"The presence of HTTP URLs alone does not necessarily mean they are actively used for communication. Their usage may depend on runtime conditions, such as how the URLs are invoked and whether cleartext traffic is allowed in the app's configuration. For example, HTTP requests may fail if cleartext traffic is disabled in the AndroidManifest.xml or restricted by the Network Security Configuration."*

This is a nuance that beginner testers very easily misunderstand. There are **three possible scenarios** when the string `http://` is found in the code:

| Scenario | Is the URL actually used to make a request? | Will the request succeed? |
|---|---|---|
| **A** | The URL is just a constant that is never used (dead code, legacy code, comments, documentation placeholders) | Not relevant — never executed |
| **B** | The URL is actively used to make an HTTP request (`HttpURLConnection`, `OkHttp`, etc.) | **Depends on the cleartext configuration** — since Android 9 (API 28), cleartext HTTP is **blocked by default** by the system's built-in Network Security Configuration (NSC) |
| **C** | The URL is actively used, and cleartext is **explicitly allowed** (`usesCleartextTraffic="true"` or `cleartextTrafficPermitted="true"` in the NSC) | The request will **actually succeed** in plaintext — this is the genuine FAIL condition |

Since **Android 9 (API level 28)**, the operating system blocks cleartext HTTP by default via the built-in Network Security Configuration. This means that an `http://` string found in the code of a modern application **does not necessarily mean data can actually be sent** — the request could fail silently (`CleartextNotPermittedException`) unless the developer has explicitly allowed cleartext. This is why MASTG separates this test (finding the **location** of the URL) from MASTG-TEST-0235 (verifying **whether the configuration allows** cleartext) as two complementary tests that must be read together.

### 1.3 Why It Still Matters Despite the Default OS Protection

Even though the Android 9+ default protection reduces the risk, this test remains relevant because:

- **Applications with a low `minSdkVersion`**, or that explicitly lower their `targetSdkVersion`, may not be protected by this mechanism under all conditions.
- **Developers often add domain exceptions** to the Network Security Configuration for development/staging needs that get forgotten and left in when shipping to production (`<domain-config cleartextTrafficPermitted="true">` for internal domains).
- **Third-party libraries (ad SDKs, analytics, crash reporters)** bundled into the APK may carry hardcoded HTTP endpoints from legacy code that was never migrated to HTTPS — this is outside the direct control of the app development team.
- **WebView** can load HTTP URLs that are not always subject to the NSC in the same way as native networking APIs, depending on WebView version and configuration.
- **Redirect chains**: the initial URL may be `https://` but redirect to `http://` at some point in the flow, with a hardcoded intermediate/secondary API URL in that chain actually being HTTP.

### 1.4 Relationship to the MASVS-NETWORK Test Trio

This test is part of a series of four complementary tests that together answer the question "does the application send data over cleartext":

```
TEST-0233 (static)  ──► Find ALL locations of http:// strings in the APK
        │
        ▼
TEST-0235 (static)  ──► Check whether the CONFIGURATION (manifest/NSC) allows cleartext
        │                (if NOT allowed → http:// requests will fail at runtime)
        ▼
TEST-0238 (dynamic)  ──► Hook networking APIs at runtime to see WHICH URLs
        │                 the application actually calls
        ▼
TEST-0236 (dynamic)  ──► Capture ACTUAL network traffic — definitive proof
                          of whether plaintext HTTP packets are truly sent on the wire
```

This document (**TEST-0233**) only answers the **first step** — inventorying locations. A solid FAIL/PASS conclusion requires correlation with the other three tests.

---

## 2. Tools Used for Testing

### 2.1 Required Tools (Core)

| Tool | MASTG ID | Function |
|---|---|---|
| **jadx** | MASTG-TOOL-0018 | Decompiles DEX → Java for string searches in application code |
| **apktool** | MASTG-TOOL-0011 | Extracts resources (XML, assets) for string searches outside the code |
| **grep / ripgrep** | — | Pattern matching for `http://` — the primary method since no official rule exists |
| **strings (Unix)** / **rabin2** | MASTG-TOOL-0129 | Extracts strings from native binaries (`.so`) per MASTG-TECH-0019 |

### 2.2 Alternative & Supporting Tools

| Tool | Function |
|---|---|
| **semgrep** | No official rule exists — a simple custom rule (§3.3) for detecting URL patterns in Java/Kotlin code with API call context |
| **MobSF** | Automated analysis; usually flags a "Hardcoded HTTP connection" or "Insecure connection" category in its report |
| **apkleaks** | Designed for extracting secrets/endpoints from APKs, including URLs — can be combined with filters for `http://` patterns |
| **jadx-gui "Find Usage"** | Interactively traces whether a URL constant is actually called by a networking function (answers the §1.2 scenario A vs B question) |
| **CodeQL** | Taint/reachability analysis — tracks whether a literal URL string actually flows into a function parameter such as `HttpURLConnection`, `OkHttpClient.newCall()`, `Retrofit.Builder().baseUrl()` |
| **Frida** | Runtime hooking of `URL.openConnection()`, `OkHttpClient`, etc. (MASTG-TEST-0238) to confirm actual execution |
| **Burp Suite / mitmproxy / Wireshark** | Definitive evidence at the network layer (MASTG-TEST-0236) |

### 2.3 Environment Prerequisites

- **No device/root required** for this static test — the APK file alone is sufficient.
- The correlation phase (§1.4) requires a device for MASTG-TEST-0235/0236/0238.
- Examine **the entire contents of the APK**, not just `classes.dex` — including `assets/`, `res/raw/`, bundled JSON/XML configuration files, and native `.so` libraries.

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0013** to reverse engineer the application.
2. Use **MASTG-TECH-0019** to search for `http://` URLs.

### 3.2 Method A — Comprehensive grep/ripgrep across the entire APK contents *(primary method)*

```bash
# Fully extract the APK (not just decompile the code)
mkdir -p ./apk_extracted && cd ./apk_extracted && unzip -o ../target-app.apk >/dev/null
jadx -d ../decompiled ../target-app.apk

# 1. Search the decompiled code (Java/Kotlin)
rg -n 'http://[a-zA-Z0-9./_-]+' ../decompiled/sources/ | grep -v 'http://schemas\.\|http://www\.w3\.org\|http://xml\.'

# 2. Search XML resources (strings.xml, network_security_config.xml, etc.)
rg -n 'http://' ./res/ 2>/dev/null

# 3. Search assets and bundled configuration files (JSON, properties)
rg -n 'http://' ./assets/ 2>/dev/null

# 4. Search DEX strings directly (catches strings that may be missed by jadx decompilation)
for dex in $(find . -name "*.dex"); do
  strings "$dex" | grep -oE 'http://[a-zA-Z0-9./?=&_-]+'
done | sort -u

# 5. Search native libraries (.so) per MASTG-TECH-0019
find . -name "*.so" -exec sh -c 'echo "=== $1 ==="; rabin2 -zz "$1" | grep -oE "http://[a-zA-Z0-9./?=&_-]+"' _ {} \;
```

**Common noise filters** — many `http://` matches are not application communication endpoints at all, but rather:
- XML namespaces (`http://schemas.android.com/apk/res/android`, `http://www.w3.org/...`)
- License/comment text in open-source library code (`http://www.apache.org/licenses/LICENSE-2.0`)
- Leftover Javadoc documentation in metadata

Always apply this filter early, before manual triage, to avoid wasting time reviewing structural false positives.

### 3.3 Method B — Custom Semgrep with API Call Context *(answers the §1.2 scenario A vs B question)*

Since the core question of this test is not "does the string `http://` exist" but "is that string **actually used to make a request**," the following rule targets patterns where the HTTP literal becomes a direct argument of a networking API:

```yaml
rules:
  - id: custom-hardcoded-http-url-active-use
    languages: [java, kotlin]
    severity: WARNING
    message: "[MASVS-NETWORK-1] Hardcoded HTTP URL used DIRECTLY as an argument to a networking API — strong candidate for active cleartext communication"
    pattern-either:
      - pattern: new URL("http://...")
      - pattern: new java.net.URL("http://...")
      - pattern: $CLIENT.newCall(new Request.Builder().url("http://...").build())
      - pattern: Retrofit.Builder().baseUrl("http://...")
      - pattern: Uri.parse("http://...")

  - id: custom-hardcoded-http-url-constant
    languages: [java, kotlin]
    severity: INFO
    message: "[MASVS-NETWORK-1] HTTP URL constant found — investigate whether it is actually used (see the active-use pattern)"
    pattern-regex: '(public|private|internal)?\s*(static\s+)?final\s+String\s+\w+\s*=\s*"http://[^"]+"'
```

```bash
semgrep -c ./http-url-rules.yml ./decompiled/sources/ --json -o findings.json
jq '[.results[] | select(.check_id | contains("active-use"))] | length' findings.json
```

The `active-use` rule carries a much higher priority signal than the `constant` rule — in line with the official warning in §1.2, a string that is merely declared as a constant without being used directly in an API call is a weak candidate for FAIL.

### 3.4 Method C — CodeQL (reachability: constant → networking API)

For cases where the URL is stored as a separate constant and then passed through several variables before reaching a networking function (not caught by Method B's direct pattern):

```ql
import java
import semmle.code.java.dataflow.DataFlow

class HttpUrlLiteral extends DataFlow::Node {
  HttpUrlLiteral() {
    exists(StringLiteral s | s.getValue().matches("http://%") | this.asExpr() = s)
  }
}

class NetworkingApiSink extends DataFlow::Node {
  NetworkingApiSink() {
    exists(MethodAccess ma |
      ma.getMethod().hasName(["openConnection", "newCall", "baseUrl", "url"]) |
      this.asExpr() = ma.getAnArgument()
    )
    or
    exists(ClassInstanceExpr c |
      c.getConstructedType().hasQualifiedName("java.net", "URL") |
      this.asExpr() = c.getAnArgument()
    )
  }
}

from DataFlow::Node source, DataFlow::Node sink
where DataFlow::localFlow(source, sink)
select source, "This HTTP URL literal flows into a networking API at " + sink.getLocation()
```

```bash
codeql database create ./cqldb --language=java --command="./gradlew assembleRelease"
codeql database analyze ./cqldb ./http-url-reachability.ql --format=sarif-latest --output=result.sarif
```

### 3.5 Method D — MobSF

```bash
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest
```

MobSF's report typically lists findings in the *"App can read/write to External Storage"* category for unrelated matters, but for the networking category look for *"Insecure Connection"*, *"Files/Folders/URLs found"*, or the **Domain Malware Check / URLs** section, which lists every URL string found along with its scheme (`http`/`https`).

### 3.6 Method E — apkleaks

```bash
apkleaks -f target-app.apk -o apkleaks-results.txt
grep "http://" apkleaks-results.txt
```

`apkleaks` is designed to find endpoints and secrets leaked from an APK, so it naturally also catches HTTP URLs among its findings — useful as a secondary cross-check against the results of manual grep.

### 3.7 Method F — Frida (confirming actual execution, complementing MASTG-TEST-0238)

```javascript
// hook-url-connections.js
Java.perform(function () {
    var URL = Java.use("java.net.URL");
    URL.openConnection.overload().implementation = function () {
        var urlStr = this.toString();
        if (urlStr.indexOf("http://") === 0) {
            console.log("[!] Cleartext HTTP connection opened: " + urlStr);
        }
        return this.openConnection();
    };

    try {
        var OkHttpClient = Java.use("okhttp3.OkHttpClient");
        var Request = Java.use("okhttp3.Request");
        // Hook at the Call/Request level for clients using OkHttp
    } catch (e) { /* OkHttp may not be used / may be obfuscated */ }
});
```

```bash
frida -U -f com.target.app -l hook-url-connections.js --no-pause
```

This is the most direct way to answer the core question in §1.2 — if this hook is **never triggered** during a thorough test session, it is a strong indication (though not 100% conclusive without perfect test coverage) that the HTTP URL found statically is **not actively used**.

### 3.8 Method Comparison: When to Use Which

| Method | Tool | Finds the location? | Distinguishes constant vs. actively used? | When to use |
|---|---|---|---|---|
| **A** | Comprehensive grep/ripgrep | ✅ | ❌ | **Mandatory baseline** — full coverage of the entire APK contents |
| **B** | Custom semgrep | ✅ | ✅ (direct pattern) | Early prioritization of which findings deserve investigation first |
| **C** | CodeQL | ✅ | ✅ (reachability through intermediate variables) | Large codebases with many networking abstraction layers |
| **D** | MobSF | ✅ | Partial | Quick triage, report-ready output |
| **E** | apkleaks | ✅ | ❌ | Secondary cross-check, especially for hidden API endpoints |
| **F** | Frida | Only what is executed | ✅ (definitive for what is captured) | Runtime confirmation — a definitive answer for the high-priority candidates from B/C |

**Minimum recommended combination:** **A (comprehensive grep) → B/C (active-use prioritization) → MASTG-TEST-0235 (check cleartext configuration) → F/MASTG-TEST-0238 (runtime confirmation) → MASTG-TEST-0236 (definitive network evidence)**. Do not stop at step A alone — in line with the official warning in §1.2, a solid FAIL conclusion requires correlation at least through MASTG-TEST-0235.

---

### 3.9 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rule:**

> **Observation:** *"The output should contain a list of URLs and their locations within the app."*
>
> **Evaluation:** *"The test case fails if any HTTP URLs are confirmed to be used for communication."*

The key phrase here is **"confirmed to be used"** — not merely found.

---

#### ❌ FAIL / ISSUE — The check is considered FAILED when:

| No | Condition | Basis for confirmation |
|---|---|---|
| F1 | An `http://` URL is found **directly as an argument** of a networking API (`new URL("http://...")`, `Retrofit.Builder().baseUrl("http://...")`) | Method A/B — direct call pattern |
| F2 | An `http://` URL (constant) is proven to **flow** into a networking API via reachability analysis | Method C (CodeQL) |
| F3 | Runtime hooking (Frida/MASTG-TEST-0238) captures an **actual call** to a connection with an `http://` scheme | Method F |
| F4 | Network traffic capture (MASTG-TEST-0236) shows **plaintext HTTP packets actually being sent** to the server while the app is in use | Definitive network-layer evidence |
| F5 | The configuration allows cleartext (MASTG-TEST-0235 FAILs) **and** an actively used HTTP URL is found — this combination confirms the request will genuinely succeed in plaintext | Correlation of F1/F2 with TEST-0235 |

**Example evidence (illustrative — MASTG does not yet provide an official demo for this test):**

```java
// Found in com/example/target/api/LegacyApiClient.java (jadx decompilation output)
public class LegacyApiClient {
    private static final String LEGACY_ENDPOINT = "http://api-legacy.example.com/v1/sync";  // line 12

    public void syncData(String payload) throws IOException {
        URL url = new URL(LEGACY_ENDPOINT);   // line 22 — USED DIRECTLY to open a connection
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        // ... sends payload
    }
}
```

```bash
$ rg -n 'http://' ./decompiled/sources/com/example/target/api/LegacyApiClient.java
12:    private static final String LEGACY_ENDPOINT = "http://api-legacy.example.com/v1/sync";
$ semgrep -c ./http-url-rules.yml ./decompiled/sources/com/example/target/api/LegacyApiClient.java
custom-hardcoded-http-url-active-use: line 22 — new URL(LEGACY_ENDPOINT) [reachability from the line-12 constant]
```

Interpretation: the constant at line 12 flows directly into `new URL()` at line 22, which is used for `openConnection()` — a **strong FAIL candidate**. Final confirmation still requires MASTG-TEST-0235 (whether cleartext is allowed) and ideally MASTG-TEST-0236/0238 (whether it actually executes).

---

#### ✅ PASS — The check is considered PASSED when:

| No | Condition | Example evidence |
|---|---|---|
| P1 | **No** relevant `http://` strings are found (after filtering out XML namespace/license noise) anywhere in the APK | Comprehensive grep results are empty after filtering |
| P2 | An `http://` URL is found, but **only as a constant that is never used** (dead code, refactoring leftovers) — confirmed via jadx-gui "Find Usage" or CodeQL reachability showing no flow to any networking API | An `OLD_ENDPOINT` constant that is declared but never referenced elsewhere |
| P3 | The `http://` URL is actively used, **but** MASTG-TEST-0235 confirms cleartext is **blocked** by configuration (no `usesCleartextTraffic="true"`, no NSC that allows it) — the request will fail at runtime, **and** MASTG-TEST-0236/0238 confirms no actual HTTP traffic is sent | A `CleartextNotPermittedException` is thrown when an attempt is made |
| P4 | The `http://` string appears only inside **code comments**, Javadoc documentation, or sample error messages (not an actual value used as a request URL) | `// Deprecated: used to use http://old-api.example.com, already migrated` |
| P5 | All of the application's communication endpoints (confirmed via comprehensive MASTG-TEST-0236 capture) use `https://` — any `http://` string present belongs only to a third-party library proven not to be actively called by the target application | Traffic capture across a full test session shows only TLS connections |

**Example output indicating PASS (dead code scenario):**

```bash
$ rg -n 'http://' ./decompiled/sources/ | grep -v 'schemas\.\|w3\.org'
com/example/target/legacy/OldSyncManager.java:8:    private static final String OLD_URL = "http://deprecated.example.com";

$ jadx-gui  # "Find Usage" on OLD_URL → 0 references found outside its own declaration
```

---

#### ⚠️ Important Notes on Evaluation

1. **This is the most explicit rule in MASTG about "do not conclude FAIL from the presence of a static pattern alone."** The official overview specifically includes a "Limitations" block — a strong signal that MASTG itself anticipates a high false-positive rate for this test when performed superficially. A report that only states "found N http:// strings" without further analysis **does not meet the official evaluation standard**.

2. **The correct order of investigation is: location → active usage → cleartext configuration → runtime evidence.** Do not jump straight to a FAIL conclusion from Method A grep results alone — follow the flow described in §1.4.

3. **Prioritize triage based on endpoint context**, not the number of occurrences. One HTTP URL actively used to send credentials is far more significant than ten HTTP URLs found inside a third-party license file.

4. **Watch out for third-party libraries carrying legacy HTTP endpoints.** Remediation responsibility differs — if the problem originates from a third-party vendor SDK, a realistic mitigation step is to update the SDK version or contact the vendor, rather than editing vendor code directly.

5. **A server-side HTTP→HTTPS redirect does not fully eliminate the risk.** Even if the server returns a `301/302` redirect from HTTP to HTTPS, **the initial request** is still sent in cleartext before the redirect occurs — enough to leak headers (including cookies/tokens, if attached to the initial request) to a MITM attacker. Do not treat this as an automatic PASS just because "it gets redirected to HTTPS anyway."

6. **Severity is modulated by the type of data potentially sent through that endpoint:**

   | Factor | Severity |
   |---|---|
   | HTTP URL actively used to send credentials/tokens/PII, and cleartext is allowed by configuration | **Critical** |
   | HTTP URL actively used for a non-sensitive endpoint (e.g., app version check, public health check) | **Medium/Low** |
   | HTTP URL found as a dead-code constant, never called | **Informational** |
   | HTTP URL actively used but cleartext is blocked by configuration (confirmed via TEST-0235 & TEST-0236) | **Low** — still note as a code smell/technical debt, not an active vulnerability |

7. **Document:** the code location (file + line) where the URL is declared **and** where it is used (if different), the results of reachability analysis, correlation status with MASTG-TEST-0235 (whether cleartext is allowed), correlation status with MASTG-TEST-0236/0238 (whether it is actually executed and sent), and the classification of data potentially sent through that endpoint.

---

## 4. Recommendations

### 4.1 Migrate All Endpoints to HTTPS

The most direct solution — ensure all of the application's network communication, including bundled third-party endpoints, uses `https://`:

```java
// BEFORE
private static final String API_ENDPOINT = "http://api.example.com/v1/sync";

// AFTER
private static final String API_ENDPOINT = "https://api.example.com/v1/sync";
```

### 4.2 Apply a Strict Network Security Configuration as a Second Layer of Defense

Even after the code migration is complete, set an explicit **Network Security Configuration** to ensure the system forcibly rejects cleartext, so that any future hardcoded-HTTP mistakes (including from new third-party SDKs) will never actually be sent:

```xml
<!-- res/xml/network_security_config.xml -->
<network-security-config>
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system" />
        </trust-anchors>
    </base-config>
</network-security-config>
```

```xml
<!-- AndroidManifest.xml -->
<application
    android:networkSecurityConfig="@xml/network_security_config"
    android:usesCleartextTraffic="false"
    ... >
```

This directly closes the gap warned about in §1.2 — even if a hardcoded HTTP URL slips past code review in the future, the system will still block its request.

### 4.3 Avoid Leaving Development Cleartext Domain Exceptions in Production Releases

If a cleartext exception is needed for an internal/staging domain, **separate the build variants** for development and production using different NSC files, and verify via CI/CD that the production build variant **never** includes that exception:

```gradle
android {
    buildTypes {
        debug {
            manifestPlaceholders = [networkSecurityConfig: "@xml/network_security_config_debug"]
        }
        release {
            manifestPlaceholders = [networkSecurityConfig: "@xml/network_security_config_release"]
        }
    }
}
```

### 4.4 Regularly Audit Third-Party Dependencies

Run the Method A/E checks (comprehensive grep + apkleaks) as part of the **dependency audit** process every time a new SDK/library is added, not only ahead of release — legacy HTTP endpoints from vendor SDKs tend to go unnoticed because they lie outside code written by the team itself.

### 4.5 Integrate into CI/CD

```bash
#!/bin/bash
# ci-check-hardcoded-http.sh
APK=$1
mkdir -p /tmp/apk_check && cd /tmp/apk_check && unzip -o "$APK" >/dev/null
jadx -d /tmp/decompiled_check "$APK" 2>/dev/null

FOUND=$(rg -c 'http://' /tmp/decompiled_check/sources/ 2>/dev/null | grep -v 'schemas\.\|w3\.org' | awk -F: '{sum+=$2} END {print sum+0}')
if [ "$FOUND" -gt "0" ]; then
    echo "[WARNING] Found $FOUND http:// references — verify whether they are actively used (see the semgrep active-use rule)"
fi
```

### 4.6 Remediation Checklist

- [ ] All `http://` strings in the code, resources, assets, and native libraries have been inventoried (comprehensive Method A)
- [ ] Each finding has been categorized: dead code / unused constant vs. actively used for a request (Method B/C)
- [ ] Actively used endpoints have been migrated to `https://`
- [ ] An explicit Network Security Configuration with `cleartextTrafficPermitted="false"` has been applied in `<base-config>`
- [ ] No cleartext domain exceptions from development builds are left in the production variant
- [ ] Third-party dependencies have been audited for legacy HTTP endpoints
- [ ] Correlation with MASTG-TEST-0235 (configuration), MASTG-TEST-0236 (network capture), and MASTG-TEST-0238 (runtime API) has been performed before concluding the final status
- [ ] **Re-verification:** re-run MASTG-TEST-0233 on the final release APK after remediation

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0233: Hardcoded HTTP URLs](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0233/)
- [MASTG-TEST-0235: Android App Configurations Allowing Cleartext Traffic](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0235/)
- [MASTG-TEST-0236: Cleartext Traffic in Network Traffic Capture](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0236/)
- [MASTG-TEST-0238: Runtime Use of Networking APIs](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0238/)
- [MASWE-0026: Network Traffic Not Encrypted](https://mas.owasp.org/MASWE/MASVS-NETWORK/MASWE-0026/)
- [MASTG-TECH-0013: Reverse Engineering Android Apps](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/)
- [MASTG-TECH-0019: Retrieving Strings](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0019/)
- [MASTG Document 0x05g — Testing Network Communication](https://mas.owasp.org/MASTG/0x05g-Testing-Network-Communication/)
- [OWASP Mobile Top 10 2024 — M5: Insecure Communication](https://owasp.org/www-project-mobile-top-10/2023-risks/m5-insecure-communication)

### 5.2 Official Android Documentation

- [Android Developers — Network Security Configuration](https://developer.android.com/privacy-and-security/security-config)
- [Android Developers — `usesCleartextTraffic` attribute reference](https://developer.android.com/guide/topics/manifest/application-element#usesCleartextTraffic)
- [Android Developers — Changes in network security in Android 9 (Behavior changes: apps targeting API 28+)](https://developer.android.com/about/versions/pie/android-9.0-changes-28#device-security)
- [Android Developers — App security best practices](https://developer.android.com/privacy-and-security/security-best-practices)

### 5.3 Other Standards and Research

- [CWE-295: Improper Certificate Validation](https://cwe.mitre.org/data/definitions/295.html)
- [CWE-296: Improper Following of a Certificate's Chain of Trust](https://cwe.mitre.org/data/definitions/296.html)
- [CWE-297: Improper Validation of Certificate with Host Mismatch](https://cwe.mitre.org/data/definitions/297.html)
- [OWASP Transport Layer Protection Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)

### 5.4 Tool Documentation

- [Semgrep — Documentation](https://semgrep.dev/docs/)
- [CodeQL — Documentation](https://codeql.github.com/docs/)
- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [apktool](https://apktool.org/)
- [apkleaks](https://github.com/dwisiswant0/apkleaks)
- [MobSF — Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)
- [radare2 / rabin2](https://github.com/radareorg/radare2)
- [Frida — Dynamic instrumentation toolkit](https://frida.re/docs/javascript-api/)

---

*This document was prepared based on OWASP MASTG (current as of September 2026) and the official Android Developers documentation. This test does not yet have an official demo (MASTG-DEMO) or an official semgrep rule. The official MASTG overview explicitly warns that the presence of an HTTP URL alone is not sufficient to conclude FAIL — this document emphasizes correlation with MASTG-TEST-0235/0236/0238 as an inseparable part of a valid evaluation.*
