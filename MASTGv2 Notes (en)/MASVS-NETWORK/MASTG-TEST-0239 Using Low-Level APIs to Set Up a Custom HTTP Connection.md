# MASTG-TEST-0239 Using Low-Level APIs (e.g. Socket) to Set Up a Custom HTTP Connection

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0239 |
| **Platform** | Android |
| **MASVS Category** | MASVS-NETWORK (MASVS-NETWORK-1: All network traffic is encrypted using TLS) |
| **Weakness** | MASWE-0026 — *Network Traffic Not Encrypted* (with the official note that **MASWE-0047** — *Using Non-Standard APIs for Security-Critical Functionality* — is also relevant, see §1.2) |
| **Test Type** | Static, Code |
| **Profile** | L1, L2 |
| **Official MASTG Status** | **`placeholder`** — no complete Overview/Steps/Observation/Evaluation from MASTG yet |
| **Official Note (the only content currently available)** | *"This test could also be for MASWE-0047 but we'd need to support multiple weaknesses."* |
| **Related Tests** | **MASTG-TEST-0234** (Missing Hostname Verification with SSLSockets — a specific case of the more general problem examined here), **MASTG-TEST-0233/0235/0238** (other cleartext test series) |
| **Related Demo** | — (none) |
| **Official Rule** | — (none) |
| **Related CWE** | CWE-319 (Cleartext Transmission of Sensitive Information), CWE-296 (Improper Following of a Certificate's Chain of Trust) |

---

## 1. Explanation

### 1.1 Status of This Test and Its Scope

Like MASTG-TEST-0237 and MASTG-TEST-0238, this test has the status **`status: placeholder`**. Its official title, *"Using low-level APIs (e.g. Socket) to set up a custom HTTP connection,"* indicates the focus of this test: detecting cases where developers **bypass** Android's standard HTTP client APIs (`HttpURLConnection`, `OkHttp`, `Volley`) and instead **manually rebuild the HTTP protocol** on top of a raw `java.net.Socket` or `SSLSocket` — writing HTTP request lines (`GET / HTTP/1.1\r\nHost: ...`) and parsing responses directly through the socket stream.

### 1.2 Key Insight from the Official Note: Two Weaknesses at Once

The official MASTG note for this test is very brief, yet it contains an important architectural insight:

> *"This test could also be for MASWE-0047 but we'd need to support multiple weaknesses."*

**MASWE-0047 (Using Non-Standard APIs for Security-Critical Functionality)** is a weakness under the **MASVS-CODE** category, distinct from MASWE-0026 (MASVS-NETWORK), which is currently the official weakness for this test. This note explicitly acknowledges that the issue of "using a raw `Socket` for HTTP" is actually **two independent, stacked problems**:

1. **From the MASVS-NETWORK (MASWE-0026) perspective**: the risk is that **traffic may end up as cleartext** — because a manual reimplementation of the HTTP protocol on top of a plain `Socket` (not `SSLSocket`) will never have any TLS encryption at all, unless the developer explicitly wraps it themselves.
2. **From the MASVS-CODE (MASWE-0047) perspective**: the risk is the **use of non-standard APIs for security-critical functionality** itself — **regardless of whether the end result is cleartext or successfully encrypted** — the decision to manually reimplement the HTTP/TLS stack instead of using a well-tested, maintained standard API (which automatically handles certificate validation, hostname verification, enforcement of the Network Security Configuration, and secure cipher suite handling) is an **architectural anti-pattern** that increases the overall risk surface.

This means that **even a custom Socket implementation that "successfully" adds TLS manually (`SSLSocket`) remains risky** from the MASWE-0047 perspective — because every security detail normally handled automatically by `HttpsURLConnection`/OkHttp (hostname verification — see MASTG-TEST-0234, NSC enforcement, certificate chain validation, support for modern cipher suites) now becomes the developer's **manual responsibility**, which is prone to implementation errors.

### 1.3 Why This Is Problematic: NSC and Platform Protections Do Not Apply

The most important technical point, consistent with the theme already discussed in MASTG-TEST-0234 (§1.3 of that document) — **the Network Security Configuration only applies at the Android networking framework layer** (`HttpsURLConnection`, `OkHttp`, `WebView`, and libraries built on top of them). Independent research explicitly confirms this:

> *"NSC operates at the Android framework level during standard network connections. When developers circumvent recommended libraries (HttpsURLConnection, OkHttp) and implement custom socket handling, they escape NSC's protective mechanisms entirely."*

As a consequence, an app can have a **perfect** `network_security_config.xml` — `cleartextTrafficPermitted="false"` across all domains, correct pinning, strict trust anchors — and still be fully vulnerable if even one code path builds its own connection via a raw `Socket`. **MASTG-TEST-0235 (which examines the NSC) will never detect this gap**, because it occurs precisely at a point that lies outside the NSC's reach.

### 1.4 The Scale of the Problem in the Real World: USENIX Academic Research

The academic research *"Revisiting TLS (In)Security in Android Applications"* (USENIX Security, cited in the research for this document) provides real-world scale data on how common it is for developers to deviate from Android's standard TLS implementation:

> Out of more than 1.3 million free Android apps analyzed on Google Play, **99,212 apps** included custom NSC settings — and of that number, **more than 88.87%** actually **weakened security** by downgrading the secure default settings.

Although this research specifically addresses NSC customization (not just raw Sockets), it illustrates the same behavioral pattern: developers often treat "customizing it themselves" at the network layer as a practical solution to compatibility/integration-convenience problems, without realizing that such customization almost always **degrades**, rather than improves, the security posture compared to using the platform defaults.

### 1.5 Common Reasons Developers Use Raw Sockets (Context for Triage)

Understanding the motivations behind this pattern helps testers assess risk proportionally:

- **Non-HTTP protocols** that need full byte-level control (custom binary protocols, game networking, IoT pairing) — a legitimate case where `Socket`/`SSLSocket` is indeed the right API, but it must still be implemented with complete security verification (see MASTG-TEST-0234).
- **Claimed performance optimization** (avoiding the overhead of full HTTP parsing) — often premature and not worth the security risk it introduces.
- **Code migrated from another platform** (Java desktop/server, or ported from iOS/cross-platform native code) that carries over the same Socket API patterns without adaptation for the mobile security context.
- **Avoiding NSC restrictions considered inconvenient** — the most dangerous pattern, where the developer **knowingly** chooses a raw Socket specifically to **bypass** the cleartext restrictions enforced by the NSC at the standard networking layer.

---

## 2. Tools Used for Testing

### 2.1 Required Tools (Core)

| Tool | Function |
|---|---|
| **jadx** | Decompiles DEX → Java for searching `Socket`/`SSLSocket` patterns and manual HTTP protocol construction |
| **grep / ripgrep** | Searches for low-level API patterns and manual HTTP request literal strings (`"GET "`, `"HTTP/1.1"`, `"Host: "`) |
| **semgrep** | Custom rules for manual HTTP request-building patterns on top of a socket stream |

### 2.2 Alternative & Supporting Tools

| Tool | Function |
|---|---|
| **CodeQL** | Traces whether `OutputStream`/`InputStream` from a `Socket` object is followed by a string-writing pattern resembling an HTTP request line — detects protocol reimplementation without relying on explicit string literals |
| **MobSF** | Sometimes flags `Socket`/`ServerSocket` usage in the Code Analysis report, though generally less precise for this specific case |
| **Frida** | Hooking `Socket.getOutputStream().write()` and `Socket.getInputStream().read()` to confirm at runtime whether the data written/read truly resembles a raw HTTP payload, while also confirming cleartext vs. encrypted |
| **Wireshark / PCAPdroid** | Definitive confirmation — if this connection truly is cleartext, the network capture will display a readable raw HTTP payload directly |

### 2.3 Environment Prerequisites

- **No device/root required** for core static analysis.
- **Focus the search on code that explicitly imports `java.net.Socket`, `java.net.ServerSocket`, or `javax.net.ssl.SSLSocket`** — this is the most direct marker of the pattern this test examines.
- **Distinguish from legitimate patterns**: not every use of `Socket` is a problem — non-HTTP protocols that genuinely require low-level control are not automatically a MASWE-0026/0047 violation. Focus triage on cases where `Socket` is used **to reimplement HTTP** (which should instead use `HttpURLConnection`/OkHttp) or where its use **results in cleartext transmission of sensitive data**.

---

## 3. Testing Methodology

Since there are no official steps (placeholder status), this section is compiled from independent research and patterns relevant to the test's definition as implied by its title.

### 3.1 General Steps

1. Identify all usages of `java.net.Socket`/`SSLSocket` in the codebase (Method A).
2. For each location, determine whether the socket is used to **reimplement the HTTP protocol** (rather than a legitimate binary/custom protocol).
3. If so, determine whether **TLS is applied** (`SSLSocket` with full verification per MASTG-TEST-0234) or **not** (plain `Socket` — automatically cleartext).
4. Confirm via network capture (§3.4) for definitive evidence.

### 3.2 Method A — grep/ripgrep for Manual HTTP Reimplementation Patterns *(primary method)*

```bash
jadx -d ./decompiled ./target-app.apk
D=./decompiled/sources

# 1. Find all Socket/SSLSocket instantiations
rg -n 'new Socket\(|new SSLSocket\(|\(SSLSocket\)|SocketFactory.*createSocket' $D

# 2. Look for manual HTTP request-writing patterns — a strong indicator of protocol reimplementation
rg -n '"GET \+|"POST \+|"HTTP/1\.[01]"|"Host: "|write.*"GET\|POST' $D
rg -n 'getOutputStream\(\).*write' $D -A3 | grep -i "http\|get \|post "

# 3. Look for manual response parsing (additional indicator)
rg -n 'BufferedReader.*getInputStream\(\)|readLine\(\).*[Hh][Tt][Tt][Pp]' $D
```

### 3.3 Method B — Custom Semgrep

```yaml
rules:
  - id: custom-raw-socket-http-reimplementation
    languages: [java, kotlin]
    severity: WARNING
    message: "[MASVS-NETWORK-1 / MASWE-0047] Possible manual reimplementation of the HTTP protocol on top of a Socket — consider using HttpURLConnection/OkHttp"
    patterns:
      - pattern-either:
          - pattern: |
              $SOCKET = new Socket($HOST, $PORT);
              ...
              $SOCKET.getOutputStream().write(...)
          - pattern: |
              $SOCKET = $FACTORY.createSocket($HOST, $PORT);
              ...
              $SOCKET.getOutputStream().write(...)

  - id: custom-plain-socket-no-tls
    languages: [java, kotlin]
    severity: ERROR
    message: "[MASVS-NETWORK-1] A plain Socket (NOT SSLSocket) is used for network communication — this traffic is automatically CLEARTEXT"
    pattern: new Socket($HOST, $PORT)
```

```bash
semgrep -c ./raw-socket-http-rules.yml ./decompiled/sources/
```

The second rule (`custom-plain-socket-no-tls`) gives the highest-priority signal — unlike `SSLSocket`, which at least **attempts** to apply TLS (even though that implementation could still be wrong, see MASTG-TEST-0234), the use of a plain `Socket` for network communication **is always cleartext by definition**, requiring no further analysis to establish a FAIL condition from the MASWE-0026 perspective.

### 3.4 Method C — CodeQL (structural pattern-based detection, not string literals)

```ql
import java

class SocketOutputWrite extends MethodAccess {
  SocketOutputWrite() {
    exists(MethodAccess getOutputCall |
      getOutputCall.getMethod().hasName("getOutputStream") and
      getOutputCall.getQualifier().getType().(RefType).hasQualifiedName("java.net", "Socket") |
      this.getQualifier() = getOutputCall
    ) and
    this.getMethod().hasName(["write", "print", "println"])
  }
}

from SocketOutputWrite write
select write, "Data written directly to a Socket's OutputStream — check whether this is a manual reimplementation of the HTTP protocol"
```

### 3.5 Method D — Frida (Runtime Confirmation)

```javascript
// hook-socket-write.js
Java.perform(function () {
    var SocketOutputStream = Java.use("java.net.SocketOutputStream");
    SocketOutputStream.write.overload("[B", "int", "int").implementation = function (buf, offset, len) {
        var bytes = Java.array('byte', buf);
        var str = "";
        for (var i = offset; i < offset + Math.min(len, 200); i++) {
            str += String.fromCharCode(bytes[i] & 0xff);
        }
        if (str.indexOf("HTTP/") !== -1 || str.match(/^(GET|POST|PUT|DELETE) /)) {
            console.log("[!] Manual HTTP reimplementation detected via raw Socket:");
            console.log(str);
            console.log("Stack:\n" + Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
        }
        return this.write(buf, offset, len);
    };
});
```

```bash
frida -U -f com.target.app -l hook-socket-write.js --no-pause
```

### 3.6 Method E — Network Capture (Definitive Cleartext Evidence)

```bash
# PCAPdroid or Wireshark on the same network
# Filter for packets containing the string "HTTP/1." on non-standard ports (not 80/443)
# which indicates a manual HTTP protocol reimplementation on top of a custom socket
```

If the raw payload can be read directly as HTTP text (`GET /api/data HTTP/1.1`) without any decryption process, this is definitive proof that the communication is cleartext.

### 3.7 Method Comparison: When to Use Which

| Method | Tool | Finds HTTP reimplementation? | Finds cleartext (specifically)? | When to use |
|---|---|---|---|---|
| **A** | grep/ripgrep | ✅ | Partial (via Socket vs SSLSocket) | Primary baseline |
| **B** | custom semgrep | ✅ | ✅ (rule `plain-socket-no-tls`) | CI/CD gate |
| **C** | CodeQL | ✅ (structural, robust against string obfuscation) | ❌ | Large/complex codebases |
| **D** | Frida | ✅ (confirms actual execution) | ✅ (payload directly visible) | Runtime confirmation |
| **E** | Network capture | N/A | ✅ (definitive proof) | Final confirmation |

**Minimum recommended combination:** **A/B (static baseline) → D (Frida for runtime confirmation) → E (network capture)**. For every finding involving `Socket` (not `SSLSocket`) used to build an HTTP request, also cross-reference with MASTG-TEST-0234 if `SSLSocket` turns out to be used instead (to assess whether its TLS is correctly implemented).

---

### 3.8 Evaluation Criteria: Positive Case & Negative Case

Since there is no official Evaluation clause (placeholder status), the following criteria are derived from MASWE-0026 and MASWE-0047.

---

#### ❌ FAIL / ISSUE — The check is declared FAILED if:

| No | Condition | Related Weakness |
|---|---|---|
| F1 | A plain `java.net.Socket` (not `SSLSocket`) is used to build a manual HTTP request to an external server | MASWE-0026 (automatically cleartext) |
| F2 | Runtime confirmation/network capture (Method D/E) shows a raw HTTP payload that can be read directly | MASWE-0026 |
| F3 | `SSLSocket` is used to manually reimplement HTTP **without** correct hostname verification (the FAIL condition of MASTG-TEST-0234) | MASWE-0026 + MASWE-0047 |
| F4 | Manual HTTP reimplementation is found **regardless of its encryption status** — a standard API (`HttpURLConnection`/OkHttp) is available and should be used, but the developer chose to manually rebuild the protocol stack for security-critical functionality (e.g. authentication, credential transmission) | MASWE-0047 (pure, independent of the MASWE-0026 outcome) |

**Example evidence (illustrative — MASTG does not yet provide an official demo for this test):**

```java
// Found in com/example/target/net/LegacyHttpClient.java (jadx decompilation result)
public class LegacyHttpClient {
    public String sendRequest(String host, int port, String path, String authToken) throws IOException {
        Socket socket = new Socket(host, port);   // line 15 — PLAIN Socket, not SSLSocket
        PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
        out.println("GET " + path + " HTTP/1.1");
        out.println("Host: " + host);
        out.println("Authorization: Bearer " + authToken);   // line 19 — token sent CLEARTEXT
        out.println();
        // ... read response
    }
}
```

```bash
$ rg -n 'new Socket\(' ./decompiled/sources/com/example/target/net/LegacyHttpClient.java
15:        Socket socket = new Socket(host, port);
$ semgrep -c ./raw-socket-http-rules.yml ./decompiled/sources/com/example/target/net/LegacyHttpClient.java
custom-plain-socket-no-tls: line 15
```

Interpretation: a plain `Socket` is used to build a manual HTTP request that carries an `Authorization: Bearer` token on line 19 — a **critical, dual FAIL**: MASWE-0026 (guaranteed cleartext) and MASWE-0047 (manual HTTP reimplementation for security-critical functionality).

---

#### ✅ PASS — The check is declared PASSED if:

| No | Condition |
|---|---|
| P1 | **No** use of `Socket`/`SSLSocket` to reimplement HTTP is found in the codebase — all communication uses `HttpURLConnection`/OkHttp/a standard library |
| P2 | `Socket`/`SSLSocket` is found, but is used for a **legitimate non-HTTP protocol** (e.g. a custom binary protocol that genuinely requires byte-level control), not an HTTP reimplementation |
| P3 | `SSLSocket` is used for manual HTTP, **and** hostname verification is correctly implemented per MASTG-TEST-0234 (reducing the MASWE-0026 risk, though MASWE-0047 remains relevant as a code-quality note) |
| P4 | Network capture (Method E) confirms no raw HTTP payload is detected on any custom socket connection |

---

#### ⚠️ Important Notes on Assessment

1. **This is a test with two weaknesses that must be considered separately** (§1.2) — a finding can PASS for MASWE-0026 (because TLS is correctly applied via `SSLSocket`) yet still be worth noting as a code-quality concern under MASWE-0047 (because it remains a manual reimplementation of functionality that should have been left to a tested standard API).

2. **Do not flag every use of `Socket` as an automatic finding.** Legitimate non-HTTP protocols (proprietary chat, game networking) are a valid use case — focus triage on evidence that the socket is used **specifically to reimplement HTTP** (request-line pattern, headers, HTTP method) that should instead use a standard API.

3. **A plain `Socket` = automatically cleartext, requiring no further analysis to reach the MASWE-0026 conclusion.** This differs from `SSLSocket` (which needs hostname verification per MASTG-TEST-0234) — don't spend excessive analysis time on cases that are already structurally guaranteed to FAIL.

4. **Prioritize findings based on the data they carry**, consistent with the pattern throughout the previous MASVS-NETWORK documents — credentials/tokens sent through this implementation are far more critical than non-sensitive data.

5. **Correlate with the industry-wide scale of the problem** (§1.4) for reporting context — if an organization has many apps with a similar pattern, this indicates an architectural/team-policy problem, not merely an isolated bug.

6. **Severity is modulated as follows:**

   | Factor | Severity |
   |---|---|
   | Plain `Socket` carries credentials/tokens/financial data | **Critical** |
   | `SSLSocket` for manual HTTP without hostname verification (F3) | **High** (equivalent to a MASTG-TEST-0234 FAIL) |
   | Manual HTTP reimplementation with TLS + correct verification, but without a clear technical justification | **Low/Informational** — note as MASWE-0047 code quality, not an active vulnerability |
   | `Socket` used for a legitimate non-HTTP protocol | **Not a finding** |

7. **Document:** the code location, the type of socket (`Socket` vs `SSLSocket`), evidence that it is an HTTP reimplementation (rather than another protocol), the data it carries, and the results of network capture confirmation if performed.

---

## 4. Recommendations

### 4.1 Migrate to a Standard HTTP API

```java
// BEFORE — manual reimplementation on top of Socket
Socket socket = new Socket(host, port);
PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
out.println("GET " + path + " HTTP/1.1");
// ...

// AFTER — using OkHttp, which automatically handles TLS, NSC, and hostname verification
OkHttpClient client = new OkHttpClient();
Request request = new Request.Builder()
    .url("https://" + host + path)
    .addHeader("Authorization", "Bearer " + authToken)
    .build();
Response response = client.newCall(request).execute();
```

### 4.2 If Low-Level Sockets Are Genuinely Necessary (Non-HTTP Protocols)

Implement all the security practices normally automatic in standard APIs manually and completely:

```java
SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
SSLSocket socket = (SSLSocket) factory.createSocket(host, port);
socket.startHandshake();
if (!HttpsURLConnection.getDefaultHostnameVerifier().verify(host, socket.getSession())) {
    socket.close();
    throw new SSLPeerUnverifiedException("Hostname verification failed");
}
// Only use the socket after verification succeeds
```

### 4.3 Document the Technical Justification for Every Low-Level Socket Usage

In keeping with the spirit of MASWE-0047, every decision to use a non-standard API for security-critical functionality should be documented with a clear technical rationale (e.g. a specific binary protocol requirement) in a code review/ADR (Architecture Decision Record), so it can be easily re-audited in the future and is not mistaken for an oversight.

### 4.4 Integrate into CI/CD

```bash
#!/bin/bash
# ci-check-raw-socket-http.sh
APK=$1
jadx -d /tmp/decompiled_check "$APK" 2>/dev/null
semgrep -c ./raw-socket-http-rules.yml /tmp/decompiled_check/sources/ --json | jq '.results | length'
```

### 4.5 Remediation Checklist

- [ ] All uses of `Socket`/`SSLSocket` in the codebase have been inventoried and classified (HTTP reimplementation vs. other legitimate protocols)
- [ ] Manual HTTP reimplementations have been migrated to `HttpURLConnection`/OkHttp
- [ ] If low-level Sockets are still needed, hostname verification and full TLS validation have been implemented (refer to MASTG-TEST-0234)
- [ ] The technical justification for each use of a non-standard API has been documented
- [ ] Network capture has confirmed no raw HTTP payload on any custom socket connection
- [ ] **Re-verification:** re-run MASTG-TEST-0239 on the final release APK after remediation

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0239: Using low-level APIs (e.g. Socket) to set up a custom HTTP connection](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0239/)
- [MASTG-TEST-0234: Missing Implementation of Server Hostname Verification with SSLSockets](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0234/)
- [MASTG-TEST-0235: Android App Configurations Allowing Cleartext Traffic](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0235/)
- [MASWE-0026: Network Traffic Not Encrypted](https://mas.owasp.org/MASWE/MASVS-NETWORK/MASWE-0026/)
- [MASWE-0047: Using Non-Standard APIs for Security-Critical Functionality](https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-0047/)
- [OWASP Mobile Top 10 2024 — M5: Insecure Communication](https://owasp.org/www-project-mobile-top-10/2023-risks/m5-insecure-communication)

### 5.2 Academic and Industry Research

- [USENIX Security — Revisiting TLS (In)Security in Android Applications (Oltrogge et al.)](https://www.usenix.org/system/files/sec21summer_oltrogge.pdf)
- [carloxavier.github.io — Caveats of Network Security Configuration in Android](https://carloxavier.github.io/android/security/network/2024/06/16/Caveats-of-Network-Security-Configuration-in-Android.html)
- [Securing.pl — How to force Android devices to communicate securely?](https://www.securing.pl/en/how-to-force-android-devices-to-communicate-securely/)
- [arXiv — Ghera: A Repository of Android App Vulnerability Benchmarks](https://arxiv.org/pdf/1708.02380)
- [CWE-319: Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)
- [CWE-296: Improper Following of a Certificate's Chain of Trust](https://cwe.mitre.org/data/definitions/296.html)

### 5.3 Tool Documentation

- [Semgrep — Documentation](https://semgrep.dev/docs/)
- [CodeQL — Documentation](https://codeql.github.com/docs/)
- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [Frida — Dynamic instrumentation toolkit](https://frida.re/docs/javascript-api/)
- [PCAPdroid](https://github.com/emanuele-f/PCAPdroid)
- [OkHttp — Documentation](https://square.github.io/okhttp/)

---

*This document was compiled primarily from independent research (USENIX academic research, community security articles) because MASTG-TEST-0239 currently has **placeholder** status and provides only a brief official note. That note reveals an important insight: this test actually combines two separate weaknesses (MASWE-0026 for cleartext risk, MASWE-0047 for the architectural risk of using non-standard APIs for security-critical functionality) that must be evaluated independently — a finding can pass one weakness yet remain relevant to the other.*
