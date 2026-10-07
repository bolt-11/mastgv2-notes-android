# MASTG-TEST-0217 Insecure TLS Protocols Explicitly Allowed in Code

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0217 |
| **Platform** | Android |
| **MASVS Category** | **MASVS-NETWORK** (MASVS-NETWORK-1: The app secures all network traffic according to current best practices) |
| **Weakness** | **MASWE-0026** — *Network Traffic Not Encrypted* |
| **Test Type** | **Static**, Code |
| **Profile** | L1, L2 |
| **Related Techniques** | MASTG-TECH-0013 (Reverse Engineering Android Apps), MASTG-TECH-0014 (Static Analysis on Android), MASTG-TECH-0023 (Reviewing Decompiled Java Code) |
| **Related Demo** | — (MASTG does not yet provide a demo for this test) |
| **Key APIs** | `javax.net.ssl.SSLContext.getInstance(String)`, `javax.net.ssl.SSLSocket.setEnabledProtocols(String[])`, `okhttp3.ConnectionSpec` (`COMPATIBLE_TLS`, `tlsVersions(...)`, `connectionSpecs(...)`) |
| **Related CWE** | CWE-326 (Inadequate Encryption Strength), CWE-327 (Use of a Broken or Risky Cryptographic Algorithm), CWE-757 (Selection of Less-Secure Algorithm During Negotiation / 'Algorithm Downgrade'), CWE-319 (Cleartext Transmission of Sensitive Information) |
| **Reference Standards** | RFC 8996 (deprecating TLS 1.0/1.1), RFC 8446 (TLS 1.3), NIST SP 800-52 Rev. 2, PCI DSS 4.0 |

---

## 1. Explanation

### 1.1 Testing Objective

This test looks, through static analysis, for **the use of insecure TLS versions that are explicitly enabled within the code** of an Android application.

Direct quote from the MASTG overview:

> *"The Android Network Security Configuration does not provide direct control over specific TLS versions (unlike iOS), and starting with Android 10, TLS v1.3 is enabled by default for all TLS connections."*
>
> *"There are still several ways to enable insecure versions of TLS..."*

The first point is critical to understanding why this test is **static and code-based** — rather than configuration-based like most other MASVS-NETWORK tests:

- On **iOS**, the minimum TLS version is set declaratively via `NSExceptionMinimumTLSVersion` in `Info.plist`.
- On **Android, there is no equivalent declarative mechanism**. The Android Network Security Configuration (`network_security_config.xml`) controls trust anchors, cleartext, and pinning — **but not the TLS version**.

The consequence: the only way an Android app can downgrade the TLS version is **through code**, using the JCA APIs or third-party libraries. That's why the only way to detect it is by **reading the code**.

### 1.2 The Good News: Android's Default Is Already Secure

Before diving into detection, it's important to understand the baseline so the assessment stays proportionate:

- **Since Android 10 (API 29), TLS 1.3 is enabled by default** for all TLS connections.
- Modern Android **has already disabled** SSLv3, and TLS 1.0/1.1 have been progressively removed from the platform.
- Apps that **do not touch TLS configuration at all** are generally already secure — the system selects the best version both parties support.

This means: **this test looks for deviations from an already-secure default.** The weakness arises when a developer **deliberately** forces an older version — usually for compatibility with a legacy server, legacy code, or a copy-paste from Stack Overflow. This differs from other crypto tests where the issue is "forgot to configure"; here the issue is "configured incorrectly."

### 1.3 Why TLS 1.0/1.1 Are Dangerous

TLS 1.0 and 1.1 were officially **deprecated by the IETF in March 2021 via RFC 8996** and moved to *Historic* status. The reasons:

| Vulnerability | Attacks | Impact |
|---|---|---|
| **BEAST** (CVE-2011-3389) | TLS 1.0 — predictable CBC IV | Plaintext recovery such as session cookies |
| **POODLE** | SSL 3.0, also TLS 1.0/1.1 (padding) | Decryption of data via padding oracle |
| **Lucky 13, Sweet32** | CBC ciphers & 64-bit blocks common in older TLS | Plaintext recovery |
| **Downgrade attack** (CWE-757) | Version negotiation | MitM attacker forces negotiation down to the weakest version allowed |

RFC 8996 emphasizes that the problem isn't just known vulnerabilities: TLS 1.0/1.1 **don't support current cryptographic algorithms**, and future bugs in old versions may never be patched. Removing support for old versions **reduces the attack surface** and closes off opportunities for misconfiguration.

Various industry profiles also mandate its removal: **PCI DSS** (since June 30, 2018 for TLS 1.0), **NIST SP 800-52 Rev. 2** (mandates TLS 1.2 as the minimum, TLS 1.3 recommended), and all major browsers ended support for TLS 1.0/1.1 in 2020.

**TLS version classification** (assessment reference):

| Version | RFC | Status | Verdict |
|---|---|---|---|
| SSLv1 / SSLv2 / SSLv3 | RFC 6176 / 6101 | Broken | ❌ Not allowed |
| **TLS 1.0** | RFC 2246 | **Deprecated (RFC 8996)** | ❌ Insecure |
| **TLS 1.1** | RFC 4346 | **Deprecated (RFC 8996)** | ❌ Insecure |
| **TLS 1.2** | RFC 5246 | Active | ✅ Best practice |
| **TLS 1.3** | RFC 8446 | Active | ✅ Best practice (default on Android 10+) |

### 1.4 Why It Maps to MASWE-0026 ("Network Traffic Not Encrypted")

This is a nuance worth understanding to avoid confusion. The weakness's title is *"Network Traffic Not Encrypted"* — which sounds like it's about cleartext (HTTP), not weak TLS. The mapping makes sense when read from an effective-security perspective: **TLS 1.0/1.1, which can be broken (BEAST/POODLE) or downgraded by a MitM, is effectively equivalent to being unencrypted** — an attacker can read the data. So "traffic not encrypted" covers both cleartext and encryption that no longer provides a confidentiality guarantee.

For reporting purposes, still describe the finding as **"an insecure TLS version explicitly enabled"** and cite MASWE-0026 as the weakness.

### 1.5 API Map to Inspect

The MASTG overview mentions three paths. Here is the complete map:

**Path A — Java Sockets / JCA (direct):**

| API | Dangerous pattern | Notes |
|---|---|---|
| `SSLContext.getInstance(String)` | `getInstance("TLSv1")`, `getInstance("TLSv1.1")`, `getInstance("SSL")`, `getInstance("SSLv3")` | Creates a context with an old protocol. `getInstance("TLS")` alone is **neutral** (uses the platform default) |
| `SSLSocket.setEnabledProtocols(String[])` | `setEnabledProtocols(new String[]{"TLSv1", "TLSv1.1"})` or one that includes an old version | **The most explicit API** — the developer deliberately lists versions |
| `SSLEngine.setEnabledProtocols(String[])` | Same | For non-blocking connections |
| `SSLParameters.setProtocols(String[])` | Same | Used together with `SSLSocket.setSSLParameters()` |

**Path B — OkHttp / Retrofit (most common in modern apps):**

| API | Dangerous pattern | Notes |
|---|---|---|
| `ConnectionSpec.COMPATIBLE_TLS` | `connectionSpecs(Arrays.asList(ConnectionSpec.COMPATIBLE_TLS))` | **Explicitly called out as a FAIL in the MASTG evaluation criteria.** A fallback that included old versions in some OkHttp versions |
| `ConnectionSpec.Builder.tlsVersions(...)` | `.tlsVersions(TlsVersion.TLS_1_0, TlsVersion.TLS_1_1)` | Explicitly sets old versions |
| `ConnectionSpec.Builder.connectionSpecs(...)` | Includes a spec that contains old versions | — |
| Retrofit uses OkHttp underneath | Same as OkHttp | Retrofit inherits the `OkHttpClient` configuration |

> **Important OkHttp context:** OkHttp's default is **`MODERN_TLS`** (secure). `RESTRICTED_TLS` is even stricter. `COMPATIBLE_TLS` is a fallback that historically included TLS 1.0/1.1. The configuration of each spec **changes across OkHttp versions** — older versions of `COMPATIBLE_TLS` were more permissive. That's why MASTG refers to the *"OkHttp configuration history."*

**Path C — Apache HttpClient & other libraries:**

| Library | Dangerous pattern |
|---|---|
| Apache HttpClient (`SSLConnectionSocketFactory`) | Constructor with a protocol array that includes old versions |
| Volley (`HurlStack` with a custom `SSLSocketFactory`) | An old `SSLContext` is passed in |
| Conscrypt / custom provider | `SSLContext.getInstance("TLSv1.1", provider)` |
| gRPC / Netty (`SslContextBuilder.protocols(...)`) | Old versions are registered |

**Path D — Indirect consequence of a custom `TrustManager`/`SSLSocketFactory`:**
Apps that replace the `SSLSocketFactory` often **forget to restrict versions**, so the socket uses all protocols supported by the platform. This overlaps with MASTG-TEST-0282 (TrustManager not validating) — check both together.

---

## 2. Tools Used for Testing

### 2.1 Required Tools (Core)

| Tool | MASTG ID | Function |
|---|---|---|
| **jadx** | MASTG-TOOL-0018 | **Decompiles DEX → Java** (MASTG-TECH-0013). Also required for MASTG-TECH-0023 — reviewing the calling context |
| **grep / ripgrep** | — | Searching for TLS API patterns. **The primary method**, since MASTG does not provide an official semgrep rule for this test |
| **apktool** | MASTG-TOOL-0011 | Decompilation alternative; smali analysis |

### 2.2 Supporting Tools

| Tool | Function |
|---|---|
| **semgrep** (MASTG-TOOL-0110) | **No official MASTG rule**, but the Semgrep registry has weak-TLS rules (`java.lang.security.audit.crypto.ssl.*`). A custom rule is needed (§3.3) |
| **CodeQL** | Built-in `java/insecure-tls` / `java/android/insecure-tls-version` queries — traces protocol configuration across functions |
| **MobSF / mobsfscan** | Flags `SSLContext.getInstance` with old versions and risky TLS configurations |
| **SonarQube** | Rule `java:S4423` — *Weak SSL/TLS protocols should not be used* |
| **QARK** | Older Android scanner with a TLS version check |
| **jadx-gui** | "Find Usage" to trace protocol array variables and constants |
| **Ghidra / `strings`** | TLS configuration in native code (`SSL_CTX_set_min_proto_version`, the string `TLSv1`) |
| **testssl.sh / sslscan / nmap `ssl-enum-ciphers`** | **Server-side verification** — complements client-side analysis (see §3.6) |
| **Frida** (MASTG-TOOL-0001) | **Dynamic confirmation** of the TLS version actually negotiated at runtime (§3.5) |
| **mitmproxy / Wireshark** | Observing the actual TLS version in the handshake (§3.6) |

### 2.3 Environmental Prerequisites

- **No device needed** for the static portion — the APK alone is sufficient. Easy to automate in CI/CD.
- **Complete APK**, including all split APKs / dynamic feature modules.
- **Know which OkHttp version is bundled.** The behavior of `COMPATIBLE_TLS` depends on the version — check `META-INF/` or `okhttp3/internal/Version` inside the APK. This determines whether `COMPATIBLE_TLS` actually includes TLS 1.0/1.1.
- **Know the `minSdkVersion`.** Apps targeting older APIs may deliberately enable old TLS because TLS 1.2 only became default starting API 20/21 and TLS 1.3 since API 29. This explains *why* (but does not justify) a finding.
- **Be aware of obfuscation.** JCA API names (`SSLContext`, `setEnabledProtocols`) are not obfuscated because they are system APIs, so detection remains effective. TLS version strings (`"TLSv1.1"`) are also literal and easy to search for — unless strings are encrypted.
- **Static analysis alone is not conclusive for the final version.** The TLS version that is **actually used** is the result of client-server negotiation; confirm with §3.5/§3.6 when possible.

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0013** (*Reverse Engineering Android Apps*) to reverse engineer the application.
2. Use **MASTG-TECH-0014** (*Static Analysis on Android*) to search for the relevant APIs.

For evaluation: use **MASTG-TECH-0023** to review each finding location.

### 3.2 Method A — Structured grep/ripgrep *(primary method)*

Because MASTG does not provide an official semgrep rule for this test, pattern searching is the baseline.

```bash
jadx -d ./decompiled ./target-app.apk
D=./decompiled/sources

# --- Path A: JCA / Java Sockets ---
# SSLContext with an old protocol (getInstance("TLS") is neutral, not counted)
rg -n --no-heading 'SSLContext\.getInstance\(\s*"(SSL|SSLv3|TLSv1|TLSv1\.1)"' $D

# setEnabledProtocols — inspect the contents (THIS IS THE MOST EXPLICIT API)
rg -n --no-heading 'setEnabledProtocols' $D -A2

# SSLParameters.setProtocols
rg -n --no-heading 'setProtocols\(' $D -A2

# Old versions as string literals anywhere
rg -n --no-heading '"(SSLv3|TLSv1|TLSv1\.1)"' $D

# --- Path B: OkHttp / Retrofit ---
# COMPATIBLE_TLS — FAIL per MASTG evaluation criteria
rg -n --no-heading 'ConnectionSpec\.COMPATIBLE_TLS|COMPATIBLE_TLS' $D
# tlsVersions with old versions
rg -n --no-heading 'tlsVersions\(' $D -A2
rg -n --no-heading 'TlsVersion\.(TLS_1_0|TLS_1_1|SSL_3_0)' $D
# connectionSpecs
rg -n --no-heading 'connectionSpecs\(' $D -A2

# --- Path C: Apache HttpClient / Volley / gRPC ---
rg -n --no-heading 'SSLConnectionSocketFactory|SSLSocketFactory' $D -A2
rg -n --no-heading 'SslContextBuilder|\.protocols\(' $D -A2

# --- Check the bundled OkHttp version (determines COMPATIBLE_TLS behavior) ---
unzip -o ./target-app.apk -d ./apk_x >/dev/null
rg -n --no-heading 'okhttp' ./apk_x/META-INF/*.version 2>/dev/null
strings ./apk_x/**/*.dex 2>/dev/null | grep -oE "okhttp/[0-9.]+" | sort -u

# --- GOOD indicators (for assessing PASS) ---
rg -n --no-heading 'TlsVersion\.(TLS_1_2|TLS_1_3)|RESTRICTED_TLS|"TLSv1\.2"|"TLSv1\.3"' $D
```

### 3.3 Method B — Semgrep with a custom rule *(CI/CD gate)*

MASTG has no official rule, so this is a custom-built rule covering all three paths:

```yaml
rules:
  - id: android-insecure-tls-sslcontext
    severity: ERROR
    languages: [java, kotlin]
    message: "[MASVS-NETWORK-1] SSLContext created with an insecure TLS/SSL version"
    pattern-either:
      - pattern: javax.net.ssl.SSLContext.getInstance("SSL")
      - pattern: javax.net.ssl.SSLContext.getInstance("SSLv3")
      - pattern: javax.net.ssl.SSLContext.getInstance("TLSv1")
      - pattern: javax.net.ssl.SSLContext.getInstance("TLSv1.1")
      - pattern: javax.net.ssl.SSLContext.getInstance("SSL", ...)
      - pattern: javax.net.ssl.SSLContext.getInstance("TLSv1", ...)

  - id: android-insecure-tls-setenabledprotocols
    severity: ERROR
    languages: [java, kotlin]
    message: "[MASVS-NETWORK-1] setEnabledProtocols/setProtocols includes an old version — check the array"
    pattern-either:
      - pattern-regex: 'setEnabledProtocols\s*\([^)]*"(SSLv3|TLSv1|TLSv1\.1)"'
      - pattern-regex: 'setProtocols\s*\([^)]*"(SSLv3|TLSv1|TLSv1\.1)"'

  - id: android-insecure-tls-okhttp
    severity: WARNING
    languages: [java, kotlin]
    message: "[MASVS-NETWORK-1] OkHttp COMPATIBLE_TLS or tlsVersions with an old version"
    pattern-either:
      - pattern: okhttp3.ConnectionSpec.COMPATIBLE_TLS
      - pattern: $B.tlsVersions(..., okhttp3.TlsVersion.TLS_1_0, ...)
      - pattern: $B.tlsVersions(..., okhttp3.TlsVersion.TLS_1_1, ...)
      - pattern: $B.tlsVersions(..., okhttp3.TlsVersion.SSL_3_0, ...)
```

```bash
semgrep -c ./tls-rules.yml ./decompiled/sources/
# Plus the registry rule
semgrep --config "r/java.lang.security.audit.crypto.ssl.no-null-cipher" ./decompiled/sources/
```

> **Important note on `getInstance("TLS")`:** the Semgrep registry flags `SSLContext.getInstance("TLS")` as *medium severity*, but this is **controversial and often a false positive** — `"TLS"` uses the platform default, which on modern Android **is already TLS 1.3**. Don't automatically report `getInstance("TLS")` as a FAIL; it's only an issue when **combined** with `setEnabledProtocols` that forces an old version down. (This issue is documented in Semgrep issue #10452.)

### 3.4 Method C — MobSF, mobsfscan, SonarQube, CodeQL

**MobSF** — look under Code Analysis for: *"The App uses an insecure/weak SSL/TLS version"*.

```bash
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest
```

**mobsfscan** (CI/CD):

```bash
mobsfscan --json -o out.json ./decompiled/sources/
jq '.results | to_entries[] | select(.key | test("tls|ssl"))' out.json
```

**SonarQube** — rule `java:S4423` (*Weak SSL/TLS protocols should not be used*) understands the context of `SSLContext`, `setEnabledProtocols`, and OkHttp. It surfaces in the IDE via SonarLint.

```bash
sonar-scanner -Dsonar.projectKey=android-app -Dsonar.sources=./app/src
```

**CodeQL** — to resolve protocol arrays that originate from variables:

```bash
codeql database create ./cqldb --language=java --command="./gradlew assembleDebug"
codeql database analyze ./cqldb \
  codeql/java-queries:Security/CWE/CWE-327/InsecureTrustManager.ql \
  codeql/java-queries:Security/CWE/CWE-757/InsecureTLSVersion.ql \
  --format=sarif-latest --output=tls.sarif
```

### 3.5 Method D — Dynamic confirmation with Frida *(the version actually negotiated)*

Static analysis shows the version that is **enabled**; hooking shows the version that is **actually used** — including when the protocol array comes from a variable or a remote configuration.

```javascript
// tls_version_trace.js
function bt() {
    const E = Java.use("java.lang.Exception");
    return E.$new().getStackTrace().slice(0, 10).map(f => "    " + f).join("\n");
}

Java.perform(() => {
    // --- SSLContext.getInstance ---
    const Ctx = Java.use("javax.net.ssl.SSLContext");
    Ctx.getInstance.overload('java.lang.String').implementation = function (p) {
        console.log(`\n[SSLContext] getInstance("${p}")` +
            (/^(SSL|SSLv3|TLSv1|TLSv1\.1)$/.test(p) ? "  [!! INSECURE !!]" : ""));
        console.log(bt());
        return this.getInstance(p);
    };

    // --- setEnabledProtocols: the array that is ACTUALLY set ---
    const Sock = Java.use("javax.net.ssl.SSLSocket");
    Sock.setEnabledProtocols.implementation = function (arr) {
        const list = arr ? Java.array('java.lang.String', arr).join(", ") : "null";
        const bad = /SSLv3|TLSv1(?!\.[23])|TLSv1\.1/.test(list);
        console.log(`\n[SSLSocket] setEnabledProtocols([${list}])` + (bad ? "  [!! INSECURE !!]" : ""));
        console.log(bt());
        return this.setEnabledProtocols(arr);
    };

    // --- The NEGOTIATED version (the final truth) ---
    const Session = Java.use("com.android.org.conscrypt.ActiveSession");
    try {
        Session.getProtocol.implementation = function () {
            const v = this.getProtocol();
            console.log(`\n[Negotiated] TLS version = ${v}`);
            return v;
        };
    } catch (e) { /* class name differs across Android versions */ }
});
```

```bash
frida -U -f com.example.target -l tls_version_trace.js -o tls.log
# Exercise the features that trigger network connections
```

### 3.6 Method E — Network-side verification *(actual handshake + server side)*

Client-side analysis is incomplete without knowing what the server actually accepts. Two sides:

**E1 — Observe the actual handshake version (client):**

```bash
# Wireshark/tshark — TLS version in the ClientHello & ServerHello
tcpdump -i any -w tls.pcap    # on the device (root) or via emulator
tshark -r tls.pcap -Y "tls.handshake.type==1" -T fields \
  -e tls.handshake.version -e tls.handshake.extensions.supported_version

# mitmproxy shows the TLS version per flow
mitmdump --set flow_detail=3 | grep -i "tls"
```

**E2 — Audit the TLS version accepted by the SERVER** (complementary: a server that only accepts TLS 1.2/1.3 forces the client down to a safe default):

```bash
# testssl.sh — comprehensive protocol & cipher audit
testssl.sh --protocols api.example.com:443

# sslscan
sslscan api.example.com

# nmap
nmap --script ssl-enum-ciphers -p 443 api.example.com
```

> If the **server** only accepts TLS 1.2/1.3, then even though the app enables TLS 1.0 in its code, the real connection remains secure (the server rejects the old version). This lowers the **exploitability** of the finding — but code that enables an old version is **still a FAIL** under MASTG's criteria, because it remains vulnerable to a malicious MitM server. Document both.

### 3.7 Method Comparison: When to Use Which

| Method | Tool | Needs a device? | Resolves arrays from variables? | Shows the actual version? | When to use |
|---|---|---|---|---|---|
| **A** | Structured ripgrep | No | Manual | ❌ | **Baseline** (no official MASTG rule exists) |
| **B** | Custom semgrep rule | No | ❌ | ❌ | CI/CD gate |
| **C1** | MobSF / mobsfscan | No | ❌ | ❌ | Report-ready output + CI |
| **C2** | SonarQube `java:S4423` | No | ✅ | ❌ | Shift-left in the IDE |
| **C3** | CodeQL | No | ✅ **automatically** | ❌ | Protocol arrays sourced from variables |
| **D** | Frida | **Yes** | ✅ (runtime value) | ✅ (negotiation) | Configuration from variables/remote, obfuscated |
| **E1** | Wireshark / mitmproxy | **Yes** | — | ✅ **(handshake)** | The TLS version actually used |
| **E2** | testssl.sh / sslscan / nmap | No¹ | — | ✅ **(server side)** | Calibrating exploitability |
| **F** | `strings` / Ghidra | No | Manual | ❌ | TLS configuration in native code |

¹ E2 needs network access to the server, not a device.

**Recommended minimum combination:** **A (ripgrep) → C2 or C3 (Sonar/CodeQL) → D (Frida)**.
A gives fast initial coverage, Sonar/CodeQL resolves arrays sourced from variables (a gap in grep), and Frida proves the version actually negotiated. Add **E2 (testssl.sh)** to calibrate how real the risk is, and **F** if the APK bundles a `.so` with its own TLS stack (e.g., an app bundling BoringSSL/OpenSSL).

### 3.8 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rule:**

> **Observation:** *"The output should contain a list of all enabled TLS versions in the above mentioned API calls."*
>
> **Evaluation:** *"The test case **fails** if any insecure TLS version is directly enabled, or if the app enabled any settings allowing the use of outdated TLS versions, such as `okhttp3.ConnectionSpec.COMPATIBLE_TLS`."*

The criteria are straightforward: **an insecure TLS version explicitly enabled → FAIL.** This includes **indirect** enabling via `COMPATIBLE_TLS`.

---

#### ❌ FAIL / ISSUE — The check is declared FAILED if:

| No. | Condition | Example evidence |
|---|---|---|
| F1 | `SSLContext.getInstance()` with an old protocol | `SSLContext.getInstance("TLSv1.1")`, `getInstance("SSL")`, `getInstance("SSLv3")` |
| F2 | `setEnabledProtocols` / `setProtocols` includes an old version | `socket.setEnabledProtocols(new String[]{"TLSv1", "TLSv1.1"})` |
| F3 | OkHttp `ConnectionSpec.COMPATIBLE_TLS` is used | `connectionSpecs(Arrays.asList(ConnectionSpec.COMPATIBLE_TLS))` — **explicitly called out by MASTG as a FAIL** |
| F4 | OkHttp `tlsVersions(...)` includes an old version | `.tlsVersions(TlsVersion.TLS_1_0, TlsVersion.TLS_1_2)` |
| F5 | Apache HttpClient / Volley / gRPC configured with an old version | `new SSLConnectionSocketFactory(ctx, new String[]{"TLSv1"}, ...)` |
| F6 | Custom `SSLSocketFactory` that enables an old version | The returned socket includes TLSv1/1.1 in its enabled protocols |
| F7 | An old version is enabled in **native code** | `strings lib.so` → `TLSv1`, or `SSL_CTX_set_min_proto_version(ctx, TLS1_VERSION)` |
| F8 | Frida confirms an old version is actually negotiated | `[Negotiated] TLS version = TLSv1.1` |

**Example code that FAILS:**

```java
// F1 — SSLContext with an old protocol
SSLContext ctx = SSLContext.getInstance("TLSv1.1");

// F2 — setEnabledProtocols includes an old version
SSLSocket socket = (SSLSocket) factory.createSocket(host, 443);
socket.setEnabledProtocols(new String[]{"TLSv1", "TLSv1.1", "TLSv1.2"});

// F3 — OkHttp COMPATIBLE_TLS
OkHttpClient client = new OkHttpClient.Builder()
    .connectionSpecs(Arrays.asList(ConnectionSpec.COMPATIBLE_TLS))
    .build();

// F4 — OkHttp tlsVersions with an old version
ConnectionSpec spec = new ConnectionSpec.Builder(ConnectionSpec.MODERN_TLS)
    .tlsVersions(TlsVersion.TLS_1_0, TlsVersion.TLS_1_1, TlsVersion.TLS_1_2)
    .build();
```

> **Note:** MASTG does not yet provide a demo (MASTG-DEMO) for this test, so there is no official tool output to cite. The examples above were composed from the API descriptions in the MASTG overview and the OkHttp documentation.

---

#### ✅ PASS — The check is declared PASSED if:

| No. | Condition | Example evidence |
|---|---|---|
| P1 | The app **does not touch TLS configuration** at all | No `SSLContext.getInstance` with a version, no `setEnabledProtocols`, no custom `ConnectionSpec` → uses the platform default (TLS 1.3 on Android 10+) |
| P2 | `SSLContext.getInstance("TLS")` / `getInstance("TLSv1.2")` / `getInstance("TLSv1.3")` | Uses the secure default or an explicit modern version |
| P3 | `setEnabledProtocols` with **only** modern versions | `setEnabledProtocols(new String[]{"TLSv1.2", "TLSv1.3"})` |
| P4 | OkHttp uses `MODERN_TLS` (default) or `RESTRICTED_TLS` | No custom `connectionSpecs`, or explicitly `MODERN_TLS`/`RESTRICTED_TLS` |
| P5 | OkHttp `tlsVersions(...)` with **only** modern versions | `.tlsVersions(TlsVersion.TLS_1_3, TlsVersion.TLS_1_2)` |
| P6 | Frida confirms negotiation of TLS 1.2/1.3 | `[Negotiated] TLS version = TLSv1.3` |

**Example output indicating PASS:**

```bash
$ rg -n 'SSLContext\.getInstance\("(SSL|SSLv3|TLSv1|TLSv1\.1)"|setEnabledProtocols|COMPATIBLE_TLS|TlsVersion\.(TLS_1_0|TLS_1_1|SSL_3_0)' ./decompiled/sources/
# (no results)
```

Correct code:

```kotlin
// ✅ Simplest and safest: DON'T touch the TLS configuration — let the platform default apply
val client = OkHttpClient()      // MODERN_TLS default

// ✅ If an explicit strict setting is needed:
val spec = ConnectionSpec.Builder(ConnectionSpec.RESTRICTED_TLS)
    .tlsVersions(TlsVersion.TLS_1_3, TlsVersion.TLS_1_2)
    .build()
val client2 = OkHttpClient.Builder()
    .connectionSpecs(listOf(spec))
    .build()

// ✅ Explicit modern JCA
val ctx = SSLContext.getInstance("TLSv1.3")
```

---

#### ⚠️ Important Notes on Assessment

1. **There is no official MASTG rule and no demo.** This test relies entirely on grep plus manual review. Don't expect an "official" tool output to cite; build the evidence from decompiled code snippets and, ideally, Frida confirmation.

2. **`SSLContext.getInstance("TLS")` is not automatically a FAIL.** `"TLS"` is the platform default, which on modern Android is already TLS 1.3. It only becomes a problem when combined with `setEnabledProtocols` that downgrades the version. The Semgrep registry often produces false positives here (issue #10452) — verify manually.

3. **`COMPATIBLE_TLS` is a FAIL under MASTG regardless of the OkHttp version.** Even though newer OkHttp versions may no longer include TLS 1.0/1.1 in `COMPATIBLE_TLS`, the MASTG evaluation criteria explicitly call it out. Report it as a FAIL, but include the OkHttp version and the behavior of `COMPATIBLE_TLS` for that version to calibrate severity.

4. **Check arrays that originate from variables.** `setEnabledProtocols(protocolArray)` where `protocolArray` is defined elsewhere is not caught by simple grep. Use CodeQL (§3.4) or Frida (§3.5).

5. **Static analysis shows what is ENABLED, not what is USED.** The final version is the result of negotiation. For accurate severity, confirm with Frida (negotiated version) and testssl.sh (what the server accepts). Code that enables TLS 1.0 is still a FAIL even if the server rejects it — because a malicious MitM server could accept it (downgrade).

6. **Native code blind spot.** Apps that bundle their own TLS stack (BoringSSL/OpenSSL via NDK, Flutter, React Native, Xamarin) configure TLS outside of JCA. Check `.so` files with `strings`/Ghidra (`SSL_CTX_set_min_proto_version`, `TLS1_VERSION`).

7. **Cross-platform frameworks.** Flutter (`dart:io SecurityContext`), React Native (networking via OkHttp — covered under Path B), Xamarin/.NET (`ServicePointManager.SecurityProtocol`) have their own TLS APIs. Check according to the stack in use.

8. **`minSdkVersion` context explains but does not justify.** Apps with a very low `minSdk` may enable old TLS for compatibility with older devices. It's still a FAIL, but the fix can be paired with raising `minSdk` or using the Conscrypt provider (§4).

9. **Severity modulation:**

   | Factor | Severity |
   |---|---|
   | SSLv3 / TLS 1.0 enabled on a connection carrying sensitive data | **High** |
   | `COMPATIBLE_TLS` on an older OkHttp version that genuinely includes TLS 1.0/1.1 | **High** |
   | TLS 1.1 enabled | **Medium–High** |
   | An old version enabled in code but the server is proven to accept only TLS 1.2/1.3 | **Medium** — exploitability lowered, but still vulnerable to downgrade via MitM |
   | `getInstance("TLS")` without a version downgrade | **Not a finding** (secure default) |
   | Only TLS 1.2/1.3 enabled | **Not a finding** |

10. **Document:** the code location + decompiled snippet, the TLS version(s) enabled, the path (JCA/OkHttp/native), the OkHttp version where relevant, the Frida confirmation result (negotiated version), the testssl.sh result (version accepted by the server), `minSdkVersion`, and the severity along with its justification.

---

## 4. Recommendations

### 4.1 Core Principles (in priority order)

**Priority 1 — Don't touch TLS configuration; let the platform default apply.** This is the simplest and safest remediation. Since Android 10, the default is already TLS 1.3. Remove every `SSLContext.getInstance("TLSv1...")`, `setEnabledProtocols`, and custom `ConnectionSpec` that downgrades the version.

```kotlin
// ✅ This is enough — the system selects the best version
val client = OkHttpClient()
```

**Priority 2 — If you must be explicit, use only TLS 1.2 + 1.3.**

```kotlin
// OkHttp
val spec = ConnectionSpec.Builder(ConnectionSpec.RESTRICTED_TLS)
    .tlsVersions(TlsVersion.TLS_1_3, TlsVersion.TLS_1_2)
    .build()
val client = OkHttpClient.Builder().connectionSpecs(listOf(spec)).build()

// JCA
val ctx = SSLContext.getInstance("TLSv1.2")   // or "TLSv1.3"
socket.enabledProtocols = arrayOf("TLSv1.3", "TLSv1.2")
```

- Replace `COMPATIBLE_TLS` → `MODERN_TLS` (default) or `RESTRICTED_TLS` (strictest).
- Remove all `TlsVersion.TLS_1_0` / `TLS_1_1` / `SSL_3_0` from `tlsVersions(...)`.

**Priority 3 — Update the networking library.** The behavior of `COMPATIBLE_TLS` and the default ciphers improve across OkHttp versions. Use the latest version and monitor the [OkHttp TLS configuration history](https://square.github.io/okhttp/security/tls_configuration_history/).

**Priority 4 — For older device compatibility, use Conscrypt — not version downgrades.** Apps with a low `minSdk` often downgrade TLS so they can run on older Android versions. The correct solution: embed **Conscrypt** as a security provider, which brings TLS 1.3 to Android 5.0+.

```kotlin
// build.gradle: implementation("org.conscrypt:conscrypt-android:2.5.2")
Security.insertProviderAt(Conscrypt.newProvider(), 1)
// TLS 1.3 is now available even on older Android, without needing to enable obsolete versions
```

**Priority 5 — Harden the server side.** Configure the server to accept **only** TLS 1.2/1.3 (audit with testssl.sh). This closes the downgrade gap on the side you control — but it is not a substitute for fixing the client.

**Priority 6 — Check native & cross-platform stacks.** For `.so` files using OpenSSL/BoringSSL, set `SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION)`. For Flutter/RN/Xamarin, configure the minimum TLS version through each framework's own API.

**Priority 7 — Enforce it in CI/CD.** Add the semgrep rule (§3.3) / SonarQube `java:S4423` as a gate; fail the build if an old TLS version appears. Also monitor the networking library version via dependency scanning.

### 4.2 Remediation Checklist

- [ ] No `SSLContext.getInstance()` with `"SSL"`, `"SSLv3"`, `"TLSv1"`, or `"TLSv1.1"`
- [ ] No `setEnabledProtocols` / `setProtocols` that includes an old version
- [ ] No OkHttp `ConnectionSpec.COMPATIBLE_TLS`
- [ ] No `tlsVersions(...)` with `TLS_1_0` / `TLS_1_1` / `SSL_3_0`
- [ ] Custom `SSLSocketFactory` / `SSLConnectionSocketFactory` does not enable an old version
- [ ] Ideally: TLS configuration is not touched at all (platform default)
- [ ] If explicit: only TLS 1.2 + 1.3
- [ ] OkHttp uses `MODERN_TLS` or `RESTRICTED_TLS`
- [ ] The networking library (OkHttp/Retrofit) is updated to the latest version
- [ ] Older device compatibility is handled with **Conscrypt**, not version downgrades
- [ ] The native TLS stack (`.so`) uses `TLS1_2_VERSION` as the minimum
- [ ] Cross-platform frameworks are configured with TLS 1.2 as the minimum
- [ ] The server accepts only TLS 1.2/1.3 (audited with testssl.sh)
- [ ] Frida confirms negotiation of TLS 1.2/1.3 on real connections
- [ ] A TLS SAST rule is integrated into CI/CD as a gate
- [ ] **Re-verification:** re-run MASTG-TEST-0217 → no old version is enabled
- [ ] **Cross-verification:** MASTG-TEST-0282 (TrustManager), MASTG-TEST-0283 (HostnameVerifier), MASTG-TEST-0286 (Network Security Config) — TLS weaknesses often come in pairs

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0217: Insecure TLS Protocols Explicitly Allowed in Code](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0217/)
- [MASWE-0026: Network Traffic Not Encrypted](https://mas.owasp.org/MASWE/MASVS-NETWORK/MASWE-0026/)
- [MASTG — Testing Network Communication (Recommended TLS Settings)](https://mas.owasp.org/MASTG/0x04f-Testing-Network-Communication/)
- [MASTG-TEST-0282: Use of a TrustManager that Does Not Validate Certificate Chains](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0282/)
- [MASTG-TEST-0283: Use of the HostnameVerifier that Allows Any Hostname](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0283/)
- [MASTG-TEST-0284: WebView Ignoring TLS Errors in onReceivedSslError](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0284/)
- [MASTG-TEST-0286: Network Security Configuration Allows User-Added Certificates](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0286/)
- [MASTG-TECH-0013: Reverse Engineering Android Apps](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/)
- [MASTG-TECH-0014: Static Analysis on Android](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/)
- [MASTG-TECH-0023: Reviewing Decompiled Java Code](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0023/)
- [MASVS-NETWORK: Network Communication](https://mas.owasp.org/MASVS/06-MASVS-NETWORK/)
- [OWASP Mobile Top 10 2024 — M5: Insecure Communication](https://owasp.org/www-project-mobile-top-10/2023-risks/m5-insecure-communication.html)
- [OWASP Transport Layer Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)

### 5.2 Official Android / Google / Java Documentation

- [Android — SSL/Security (Updates to SSL, TLS 1.3 default)](https://developer.android.com/privacy-and-security/security-ssl)
- [Android 10 behavior changes — TLS 1.3 enabled by default](https://developer.android.com/about/versions/10/behavior-changes-all#tls-1.3)
- [`javax.net.ssl.SSLContext` — API reference](https://developer.android.com/reference/javax/net/ssl/SSLContext)
- [`javax.net.ssl.SSLSocket.setEnabledProtocols` — API reference](https://developer.android.com/reference/javax/net/ssl/SSLSocket#setEnabledProtocols(java.lang.String[]))
- [`SSLParameters.setProtocols` — API reference](https://developer.android.com/reference/javax/net/ssl/SSLParameters)
- [Android — Network Security Configuration](https://developer.android.com/privacy-and-security/security-config)
- [Conscrypt — modern TLS provider (TLS 1.3 on older Android)](https://github.com/google/conscrypt)
- [Android GMS ProviderInstaller — update security provider](https://developer.android.com/privacy-and-security/security-gms-provider)

### 5.3 OkHttp / Library Documentation

- [OkHttp — HTTPS & ConnectionSpec](https://square.github.io/okhttp/features/https/)
- [OkHttp — TLS Configuration History](https://square.github.io/okhttp/security/tls_configuration_history/)
- [OkHttp `ConnectionSpec` — API reference](https://square.github.io/okhttp/3.x/okhttp/okhttp3/ConnectionSpec.html)
- [OkHttp `TlsVersion` — API reference](https://square.github.io/okhttp/4.x/okhttp/okhttp3/-tls-version/)
- [Retrofit — documentation (uses OkHttp)](https://square.github.io/retrofit/)
- [Apache HttpClient — SSL/TLS customization](https://hc.apache.org/httpcomponents-client-5.2.x/current/httpclient5/apidocs/org/apache/hc/client5/http/ssl/SSLConnectionSocketFactory.html)

### 5.4 Cryptographic Standards & Taxonomy

- [RFC 8996 — Deprecating TLS 1.0 and TLS 1.1](https://www.rfc-editor.org/rfc/rfc8996.html)
- [RFC 8446 — TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446)
- [RFC 5246 — TLS 1.2](https://tools.ietf.org/html/rfc5246)
- [RFC 7525 / BCP 195 — Recommendations for Secure Use of TLS and DTLS](https://datatracker.ietf.org/doc/bcp195/)
- [NIST SP 800-52 Rev. 2 — Guidelines for TLS Implementations](https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final)
- [CWE-326: Inadequate Encryption Strength](https://cwe.mitre.org/data/definitions/326.html)
- [CWE-327: Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)
- [CWE-757: Selection of Less-Secure Algorithm During Negotiation ('Algorithm Downgrade')](https://cwe.mitre.org/data/definitions/757.html)
- [CWE-319: Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)
- [SonarQube Rule java:S4423 — Weak SSL/TLS protocols should not be used](https://rules.sonarsource.com/java/RSPEC-4423/)
- [PCI DSS — Migrating from SSL and early TLS](https://www.pcisecuritystandards.org/documents/Migrating-from-SSL-Early-TLS-Info-Supp-v1_1.pdf)

### 5.5 Security Research & Technical Articles

- [RFC Editor — RFC 8996 (PDF)](https://www.rfc-editor.org/rfc/rfc8996.pdf)
- [Feisty Duck — IETF Formally Deprecates TLS 1.0 and 1.1](https://www.feistyduck.com/newsletter/issue_75_ietf_formally_deprecates_tls_1_0_and_1_1)
- [KeyCDN — Deprecating TLS 1.0 and 1.1](https://www.keycdn.com/blog/deprecating-tls-1-0-and-1-1)
- [Invicti/Acunetix — Examples of TLS/SSL Vulnerabilities (BEAST, POODLE, Lucky 13)](https://www.acunetix.com/blog/articles/tls-vulnerabilities-attacks-final-part/)
- [PortSwigger Daily Swig — Browser-makers ditch support for TLS 1.0/1.1](https://portswigger.net/daily-swig/the-end-is-nigh-browser-makers-ditch-support-for-aging-tls-1-0-1-1-protocols)
- [PacketMania — Please Stop Using TLS 1.0 and TLS 1.1 Now!](https://www.packetmania.net/en/2022/11/10/Stop-TLS1-0-TLS1-1/)
- [Semgrep issue #10452 — SAST advice for minimum TLS versions in Java](https://github.com/semgrep/semgrep/issues/10452)
- [GitHub Gist — TLS 1.3 with OkHttp and Conscrypt on all Android versions](https://gist.github.com/Karewan/4b0270755e7053b471fdca4419467216)
- [Qualys SSL Labs — SSL and TLS Deployment Best Practices](https://github.com/ssllabs/research/wiki/SSL-and-TLS-Deployment-Best-Practices)
- [HackTricks — Android Applications Pentesting](https://book.hacktricks.wiki/en/mobile-pentesting/android-app-pentesting/index.html)

### 5.6 Tool Documentation

- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [apktool — Reverse engineering Android APK files](https://apktool.org/)
- [Semgrep — Documentation](https://semgrep.dev/docs/)
- [CodeQL — Documentation](https://codeql.github.com/docs/)
- [MobSF — Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)
- [mobsfscan](https://github.com/MobSF/mobsfscan)
- [Frida — Documentation Home](https://frida.re/docs/home/)
- [testssl.sh — Testing TLS/SSL encryption](https://testssl.sh/)
- [sslscan](https://github.com/rbsec/sslscan)
- [nmap — ssl-enum-ciphers script](https://nmap.org/nsedoc/scripts/ssl-enum-ciphers.html)
- [Wireshark — User's Guide](https://www.wireshark.org/docs/wsug_html_chunked/)
- [mitmproxy — Documentation](https://docs.mitmproxy.org/stable/)

---

*This document was compiled based on OWASP MASTG (latest release as of September 2026), official Android Developers and OkHttp documentation, RFC/NIST/PCI DSS standards, and third-party security research. This test does not yet have an official demo (MASTG-DEMO), so the FAIL/PASS code examples were composed from the API descriptions in the MASTG overview and vendor documentation.*
