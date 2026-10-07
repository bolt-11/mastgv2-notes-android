# MASTG-TEST-0234 Missing Implementation of Server Hostname Verification with SSLSockets

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0234 |
| **Platform** | Android |
| **MASVS Category** | MASVS-NETWORK (MASVS-NETWORK-2: The app verifies the identity of the server endpoint before establishing an encrypted connection) |
| **Weakness** | MASWE-0027 — *Insecure Certificate Validation* |
| **Test Type** | Static, Code |
| **Profile** | L1, L2 |
| **Related Techniques** | MASTG-TECH-0013 (Reverse Engineering), MASTG-TECH-0014 (Static Analysis), MASTG-TECH-0023 (Reviewing Decompiled Java Code) |
| **Related Tests** | **MASTG-TEST-0283** (Incorrect Implementation of Server Hostname Verification) — the counterpart that tests **whether an EXISTING `HostnameVerifier` is implemented correctly**; TEST-0234 tests whether a `HostnameVerifier` **exists at all** when `SSLSocket` is used |
| **Related Demo** | — (MASTG does not yet provide an official demo for this test) |
| **Official Rule** | `mastg-android-network-hostname-verification.yml` (exists, but **structurally does not test what this test's title claims** — see §3.2) |
| **Related CWE** | CWE-297 (Improper Validation of Certificate with Host Mismatch), CWE-295 (Improper Certificate Validation) |

---

## 1. Explanation

### 1.1 Testing Objective

Quote from the official MASTG overview:

> *"This test checks whether an Android app uses `SSLSocket` without a `HostnameVerifier`, allowing connections to servers presenting certificates with wrong or invalid hostnames."*

This test targets the low-level `javax.net.ssl.SSLSocket` API — one of the two main paths Android offers for establishing a TLS connection (the other being `HttpsURLConnection`/OkHttp, which **automatically** performs hostname verification). `SSLSocket` does **not** perform hostname validation automatically:

> *"By default, `SSLSocket` does not perform hostname verification. To enforce it, the app must explicitly invoke `HostnameVerifier.verify()` and implement proper checks."*

This is a **deliberate API design, not a bug** — `SSLSocket` operates at the pure TLS transport layer without any knowledge of the HTTP/URL context, so it has no way of knowing which hostname "should" be validated against the certificate. This responsibility is **entirely delegated to the application developer** who uses this API directly.

### 1.2 Why This Is Dangerous: TLS Succeeds, but Server Identity Is Never Checked

Without a `HostnameVerifier`, the TLS handshake will **still succeed** — encryption remains in place, and the certificate's trust chain is still validated up to the root CA — but **no step ensures that certificate actually belongs to the intended server**. This means:

- A **Man-in-the-Middle (MITM)** attacker who holds a valid certificate for **any** domain issued by a trusted CA (even a domain they own themselves) can present that certificate, and the app will accept it without complaint, because the hostname listed on the certificate is never matched against the actual destination hostname.
- This is fundamentally different from a certificate chain validation failure (e.g., a skipped `checkServerTrusted`) — here **the trust chain is valid**, but **the endpoint identity is unverified**. This combination of "TLS active but identity unverified" is what makes this flaw easy to miss in a cursory code review — the connection still looks "secure" (there's an `SSLSocket`, there's encryption), even though its security guarantee is empty.

### 1.3 Critical Point: Network Security Configuration Does NOT Protect `SSLSocket`

This is the most important official note in this test and a frequent source of misconception:

> *"Note: The connection succeeds even if the app has a fully secure Network Security Configuration (NSC) in place because `SSLSocket` is not affected by it."*

Many development teams feel secure because they have implemented a strict NSC (`cleartextTrafficPermitted="false"`, pinning via `<pin-set>`, etc. — see MASTG-TEST-0235 and MASTG-TEST-0242) and assume that is sufficient for the entire network layer of the application. **This is mistaken for code that uses `SSLSocket` directly** — the NSC operates on Android's standard HTTP/URL API layer (`HttpsURLConnection`, WebView, most popular HTTP libraries), **not** on a raw TLS socket built manually via `SSLSocketFactory`. This means a network security audit that **only** checks the NSC/manifest configuration (like a review focused on MASTG-TEST-0235) **will miss** this vulnerability entirely if the application has a custom communication path that uses `SSLSocket` — something commonly found in:

- **Custom non-HTTP protocol** implementations over TLS (e.g., proprietary chat/messaging protocols, IoT/device pairing protocols)
- **Legacy third-party SDKs** written before `HttpsURLConnection`/OkHttp became the de facto standard
- Code **ported from Java desktop/server applications** (which share the exact same socket API) without adjustment for the mobile context

### 1.4 The Correct Fix According to Official Android Documentation

Android Developers explicitly provides guidance (referenced in the official overview) on the correct way to use `HostnameVerifier` with `SSLSocket`:

```java
SSLSocketFactory sslSocketFactory = ...;
SSLSocket sslSocket = (SSLSocket) sslSocketFactory.createSocket(host, port);

// Mandatory: manually verify the hostname after the handshake
SSLSession session = sslSocket.getSession();
if (!HttpsURLConnection.getDefaultHostnameVerifier().verify(host, session)) {
    throw new SSLHandshakeException("Hostname does not match certificate: " + host);
}
```

A crucial point from the Android documentation (`getDefaultHostnameVerifier()`): **`HostnameVerifier.verify()` does not throw an exception when validation fails — it returns a boolean that the calling code MUST explicitly check.** This is an error-prone (*footgun*) API pattern — a developer who calls `verify()` but forgets to check its return value (or mistakenly assumes an exception will be thrown automatically) remains vulnerable even though the code at a glance "looks like" it already performs verification.

### 1.5 Relationship to MASTG-TEST-0283

These two tests examine **opposite but complementary** conditions:

| | MASTG-TEST-0234 *(this document)* | MASTG-TEST-0283 |
|---|---|---|
| **Focus** | `HostnameVerifier` is **ABSENT** when using `SSLSocket` | `HostnameVerifier` is **PRESENT**, but implemented **insecurely** |
| **Example finding** | `SSLSocket` is created, `getSession()` is called, but there is no `verify()` call at all | `verify()` is overridden to always `return true`, or has overly permissive wildcard logic |
| **Weakness** | MASWE-0027 (identical) | MASWE-0027 (identical) |

The correct testing flow: first run TEST-0234 to determine whether a `HostnameVerifier` exists at all; if it **does** exist, proceed to TEST-0283 to assess whether its implementation is secure. TEST-0234's own official note confirms this:

> *"If a `HostnameVerifier` is present, ensure it's not implemented in an unsafe manner. See MASTG-TEST-0283 for guidance."*

---

## 2. Tools Used for Testing

### 2.1 Required Tools (Core)

| Tool | MASTG ID | Function |
|---|---|---|
| **jadx** | MASTG-TOOL-0018 | Decompiles DEX → Java for finding `SSLSocket`/`HostnameVerifier` patterns |
| **grep / ripgrep** | — | API pattern search — the primary method, since the official rule has significant gaps (§3.2) |
| **semgrep** | — | Runs the official rule as a baseline, supplemented with a custom rule |

### 2.2 Alternative & Supporting Tools

| Tool | Function |
|---|---|
| **CodeQL** | Traces whether a created `SSLSocket` object truly **never** has a `verify()` call anywhere in any subsequent execution path — this "absence" question is easier to answer through control/data flow analysis than through simple regex |
| **MobSF** | Automated analysis; sometimes flags `SSLSocket` patterns in the Code Analysis report's Network Security category |
| **jadx-gui "Find Usage"** | Interactively traces whether a found `SSLSocket` instance is followed by `getSession()` + `verify()` calls in the same/nearby code block |
| **Frida** | Hooks `SSLSocketFactory.createSocket()` and `HostnameVerifier.verify()` at runtime to confirm whether verification is actually called, and what boolean result it produces |
| **grahamedgecombe/android-ssl** (public research tool) | A detection tool for Android SSL certificate validation vulnerabilities — a bytecode-level approach that can complement decompilation-based analysis |
| **Wireshark / mitmproxy with a deliberately wrong-domain certificate** | Definitive dynamic test — present a certificate that is valid for a CA but for a **different** domain than the actual target server, then observe whether the `SSLSocket` connection still succeeds (see §3.5) |

### 2.3 Environment Prerequisites

- **Static analysis requires no device/root** — the APK alone is sufficient.
- **Dynamic testing (§3.5) requires a device/emulator + a MITM proxy** that can present a certificate with a Common Name/SAN **deliberately mismatched** against the target hostname, yet still signed by a CA trusted by the system (e.g., via a custom CA installed into the test device's trust store) — this scenario is **different** from an ordinary pinning-bypass test that uses a self-signed certificate.
- Focus the search on code using the **low-level API**: `javax.net.ssl.SSLSocket`, `SSLSocketFactory`, `SSLContext.getSocketFactory()` — not `HttpsURLConnection`/OkHttp, which already handle hostname verification automatically behind the scenes.

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0013** to reverse engineer the application.
2. Use **MASTG-TECH-0014** to search for the relevant API.

### 3.2 Method A — Official Semgrep Rule *(exists, but its coverage must be critically examined)*

MASTG's official rule for this test:

```yaml
rules:
  - id: mastg-android-network-hostname-verification
    severity: WARNING
    languages:
      - java
    metadata:
      summary: This rule looks for the use of HostnameVerifier in the app
    message: Improper server hostname verification detected
    match:
      any:
        - new HostnameVerifier() {...}
```

```bash
semgrep -c https://raw.githubusercontent.com/OWASP/mastg/master/rules/mastg-android-network-hostname-verification.yml ./decompiled/sources/
```

**Significant issues testers should understand before relying on this rule:**

1. **This rule detects the presence of a custom `HostnameVerifier` implementation** (`new HostnameVerifier() {...}`) — this is actually the **opposite** of what TEST-0234 is testing for. This test examines the **absence** of a `HostnameVerifier` when `SSLSocket` is used, but the rule instead looks for when a `HostnameVerifier` **is present** (and even then, without assessing whether that implementation is secure or not — which would actually fit the TEST-0283 scenario, not TEST-0234).
2. **This rule does not search for `SSLSocket` at all.** Without detecting the presence of `SSLSocket` as a precondition, the rule cannot determine this test's actual FAIL condition: "SSLSocket used WITHOUT a HostnameVerifier."
3. **A contradictory semantic: an application that is genuinely vulnerable** (using plain `SSLSocket` with no `HostnameVerifier` whatsoever) will actually **produce no findings at all** from this rule, since there is no `new HostnameVerifier()` pattern to match — this is the **most significant false negative** found so far among the official MASTG rules examined in this research series.

Because of this structural weakness, **the official rule should not be relied upon as the primary method** for this test — Method B below is the approach that is actually relevant to the official FAIL definition.

### 3.3 Method B — grep/ripgrep + a Semantically Correct Custom Semgrep Rule *(the effective primary method)*

```bash
jadx -d ./decompiled ./target-app.apk
D=./decompiled/sources

# 1. Find all locations where an SSLSocket is created
rg -n -B2 -A15 '\(SSLSocket\)|SSLSocketFactory.*createSocket|SSLContext.*getSocketFactory' $D > sslsocket_locations.txt

# 2. For each location, manually check whether there is a nearby verify() call
rg -n -A20 '\(SSLSocket\)\s*\w+\s*=' $D | grep -c "HostnameVerifier\|\.verify("
```

A custom semgrep rule that genuinely targets the official FAIL pattern — `SSLSocket` created without a subsequent `verify()` call:

```yaml
rules:
  - id: custom-sslsocket-without-hostname-verification
    languages: [java, kotlin]
    severity: WARNING
    message: "[MASVS-NETWORK-2] SSLSocket created without a detected explicit HostnameVerifier.verify() call"
    patterns:
      - pattern-either:
          - pattern: $FACTORY.createSocket($HOST, $PORT)
          - pattern: (SSLSocket) $SOCKET
      - pattern-not-inside: |
          $SESSION = $SOCKET.getSession();
          ...
          $VERIFIER.verify($HOST, $SESSION);
```

> Technical note: the `pattern-not-inside` pattern with a flexible statement gap (`...`) in semgrep has limitations when it comes to detecting verification performed in a **separate function** (rather than the same code block). For such cases, use Method C (CodeQL), which is able to trace across functions.

### 3.4 Method C — CodeQL (answering the cross-function "absence" question)

```ql
import java

class SSLSocketCreation extends Expr {
  SSLSocketCreation() {
    exists(MethodAccess ma |
      ma.getMethod().hasName("createSocket") and
      ma.getMethod().getDeclaringType().hasQualifiedName("javax.net.ssl", "SSLSocketFactory") |
      this = ma
    )
  }
}

from SSLSocketCreation creation, Method enclosing
where
  enclosing = creation.getEnclosingCallable() and
  not exists(MethodAccess verifyCall |
    verifyCall.getMethod().hasName("verify") and
    verifyCall.getMethod().getDeclaringType().hasQualifiedName("javax.net.ssl", "HostnameVerifier") and
    verifyCall.getEnclosingCallable() = enclosing
  )
select creation, "SSLSocket created in " + enclosing.getName() + " without a HostnameVerifier.verify() call in the same method"
```

> This query remains heuristic — verification performed through a separate wrapper function call (e.g., `validateConnection(socket)`, which internally calls `verify()`) requires more complex interprocedural data flow analysis. Use this result as an initial candidate list for manual review (MASTG-TECH-0023), not as a final automated conclusion.

### 3.5 Method D — Dynamic Testing with a Mismatched-Domain Certificate *(definitive confirmation)*

This method directly proves the vulnerability at the real network layer — unlike an ordinary pinning bypass, here the certificate is **valid and signed by a trusted CA**, just for the **wrong domain**:

```bash
# 1. Create a valid certificate (signed by a custom CA that will be trusted by the test device)
#    for a domain DIFFERENT from the app's actual target server
openssl req -x509 -newkey rsa:2048 -keyout wrong-domain-key.pem -out wrong-domain-cert.pem \
    -days 365 -nodes -subj "/CN=attacker-controlled-domain.com"

# 2. Install the custom CA into the test device's trust store (root/emulator)
adb push custom-ca.pem /system/etc/security/cacerts/
adb shell chmod 644 /system/etc/security/cacerts/custom-ca.pem

# 3. Run mitmproxy/socat with that "wrong domain" certificate, and redirect the SSLSocket traffic to it
socat OPENSSL-LISTEN:443,cert=wrong-domain-cert.pem,key=wrong-domain-key.pem,verify=0,fork TCP:target-real-server:443

# 4. Observe: does the app's SSLSocket connection still SUCCEED even though the certificate is for a different domain?
```

If the connection **succeeds** even though the certificate is clearly issued for `attacker-controlled-domain.com` rather than the domain the app actually intends to reach — this is **definitive proof** of missing hostname verification.

### 3.6 Method E — Frida (runtime confirmation without needing a custom certificate setup)

```javascript
// hook-sslsocket-verify.js
Java.perform(function () {
    var SSLSocketFactory = Java.use("javax.net.ssl.SSLSocketFactory");
    SSLSocketFactory.createSocket.overload("java.lang.String", "int").implementation = function (host, port) {
        console.log("[SSLSocket] createSocket called for host=" + host + " port=" + port);
        console.log("  Stack:\n" + Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));
        return this.createSocket(host, port);
    };

    try {
        var HostnameVerifier = Java.use("javax.net.ssl.HostnameVerifier");
        // Hook the custom implementation if one exists — to determine whether verify() is EVER called at all
    } catch (e) {}

    var DefaultHV = Java.use("javax.net.ssl.HttpsURLConnection");
    // Flag if getDefaultHostnameVerifier().verify() never appears in the log following createSocket
});
```

```bash
frida -U -f com.target.app -l hook-sslsocket-verify.js --no-pause
```

If the log shows `createSocket` being called repeatedly but there is **never** a corresponding `verify()` call logged, this is a strong indication of the FAIL condition — and far cheaper to execute than setting up a custom certificate as in Method D.

### 3.7 Method Comparison: When to Use Which

| Method | Tool | Relevant to the official FAIL definition? | Answers cross-function absence? | When to use |
|---|---|---|---|---|
| **A** | Official semgrep rule | ❌ **No** — wrong target (see §3.2) | ❌ | Do not rely on alone; still run it as a reference, but never conclude PASS from an empty result |
| **B** | grep + custom rule | ✅ | Limited (same code block) | Primary baseline |
| **C** | CodeQL | ✅ | ✅ (within one method; partial cross-function) | Large/complex codebases |
| **D** | Wrong-domain certificate + socat/mitmproxy | ✅ (definitive proof) | N/A (tests actual behavior) | Final confirmation before reporting a FAIL |
| **E** | Frida | ✅ (strongly indicative) | N/A | Quick confirmation without a custom certificate setup |

**Minimum recommended combination:** **B (grep+custom rule) → C (CodeQL for large codebases) → E (Frida) or D (certificate test) for final confirmation**. **Never conclude PASS solely from an empty result on the official rule (Method A)** — as explained in §3.2, that rule is structurally incapable of detecting this test's genuine FAIL condition.

---

### 3.8 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rule:**

> **Observation:** *"The output should contain a list of locations where `SSLSocket` and `HostnameVerifier` are used."*
>
> **Evaluation:** *"The test case fails if the app uses `SSLSocket` without a `HostnameVerifier`."*
>
> **Note:** *"If a `HostnameVerifier` is present, ensure it's not implemented in an unsafe manner. See MASTG-TEST-0283 for guidance."*

---

#### ❌ FAIL / ISSUE — The check is considered FAILED when:

| No | Condition | Basis for confirmation |
|---|---|---|
| F1 | An `SSLSocket` is created via `SSLSocketFactory.createSocket()` and **there is no** `HostnameVerifier.verify()` call anywhere on the subsequent execution path | Method B/C |
| F2 | `getSession()` is called on the `SSLSocket`, but the resulting `SSLSession` is **never passed** to any `verify()` call | Method B/C — a "half-done" pattern that looks like verification but is incomplete |
| F3 | The code calls `verify()` but **ignores its return value** (the boolean result of `verify()` is never checked with an `if`, and the socket continues to be used regardless of the outcome) | Manual review per MASTG-TECH-0023 — in line with the §1.4 warning about this API's boolean-based nature |
| F4 | Dynamic confirmation (Method D/E) shows the connection **succeeds** even when the presented certificate is valid but for the wrong domain | Definitive runtime evidence |

**Example evidence (illustrative — MASTG does not yet provide an official demo for this test):**

```java
// Found in com/example/target/net/CustomProtocolClient.java (jadx decompilation output)
public class CustomProtocolClient {
    public void connect(String host, int port) throws IOException {
        SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
        SSLSocket socket = (SSLSocket) factory.createSocket(host, port);   // line 34
        socket.startHandshake();
        // NO call to getSession() or verify() here
        sendData(socket, buildPayload());   // line 37 — used immediately to send data
    }
}
```

```bash
$ rg -n -A10 '\(SSLSocket\)\s*factory\.createSocket' ./decompiled/sources/com/example/target/net/CustomProtocolClient.java
34:        SSLSocket socket = (SSLSocket) factory.createSocket(host, port);
35:        socket.startHandshake();
36:
37:        sendData(socket, buildPayload());
# No "verify(" or "HostnameVerifier" found in the next 10 lines
```

Interpretation: `SSLSocket` is used to send data (`sendData`) immediately after the handshake, with no hostname verification step whatsoever — **FAIL**, with direct evidence from the code structure. Further confirmation with Method D/E would reinforce this finding.

---

#### ✅ PASS — The check is considered PASSED when:

| No | Condition | Example evidence |
|---|---|---|
| P1 | **No** use of `SSLSocket`/`SSLSocketFactory` is found anywhere in the codebase — the application uses `HttpsURLConnection`/OkHttp exclusively, which handle hostname verification automatically | grep results for `SSLSocket` are empty |
| P2 | `SSLSocket` is used, **and** is followed by a `getSession()` + `HostnameVerifier.verify()` call whose boolean result is **explicitly checked**, with an exception/connection rejection when verification fails | Code matches the recommended pattern in §1.4 |
| P3 | `SSLSocket` is used for a **non-network-sensitive** purpose confirmed to carry no risk (e.g., a loopback connection to the same local process, not communication with an external server) | Manual review confirms the endpoint is `localhost`/`127.0.0.1` for internal IPC |
| P4 | Dynamic confirmation (Method D) shows the connection is **rejected/fails** when presented with a certificate valid for the wrong domain | `SSLHandshakeException: Hostname mismatch` thrown as expected |

**Example output indicating PASS:**

```java
SSLSocket socket = (SSLSocket) factory.createSocket(host, port);
socket.startHandshake();
SSLSession session = socket.getSession();
if (!HttpsURLConnection.getDefaultHostnameVerifier().verify(host, session)) {
    socket.close();
    throw new SSLHandshakeException("Hostname verification failed for: " + host);
}
sendData(socket, buildPayload());  // only executed if verification succeeds
```

---

#### ⚠️ Important Notes on Evaluation

1. **Do not rely on an empty result from the official semgrep rule as PASS evidence.** This is the most important note in this entire document — as explained in depth in §3.2, the official rule `mastg-android-network-hostname-verification.yml` structurally searches for a pattern that is the **opposite** of this test's FAIL condition. Code that is genuinely vulnerable (no `HostnameVerifier` at all) will actually **not** trigger that rule.

2. **A strict NSC provides no guarantee whatsoever for `SSLSocket` code.** Per §1.3, do not let a PASS result from MASTG-TEST-0235 (cleartext config) lead a tester to assume other networking aspects are also secure — they test entirely different layers.

3. **The presence of a `verify()` call does NOT automatically mean PASS** — also check whether its boolean return value is actually examined (F3). This implementation mistake is very easy to overlook on a cursory read, because the code "looks like" it already calls the right API.

4. **Prioritize searching custom communication/proprietary protocol code**, not code that obviously uses standard HTTP — per §1.3, `SSLSocket` usually appears in non-HTTP communication paths (chat, IoT pairing, custom binary protocols), which are audited less often than ordinary REST API code.

5. **Correlate with MASTG-TEST-0283 whenever a `HostnameVerifier` is found to EXIST.** Finding a `HostnameVerifier` present does not automatically mean PASS for the overall hostname verification aspect — follow the official reference to TEST-0283 to assess the correctness of its implementation.

6. **Severity is modulated by the sensitivity of the protocol running over that `SSLSocket`:**

   | Factor | Severity |
   |---|---|
   | `SSLSocket` used for a protocol carrying credentials/financial data/private messages, with no verification at all | **Critical** |
   | `SSLSocket` used for non-sensitive telemetry/analytics with no verification | **Medium** |
   | `SSLSocket` used only for local IPC (`localhost`), with no real-world network MITM risk | **Low/Informational** |
   | Verification exists but the return value is never checked (F3) | **High** — effectively just as severe as having no verification at all |

7. **Document:** the code location where the `SSLSocket` is created, the presence/absence of a `verify()` call and its distance from the point of socket creation (same block/cross-function), the status of the boolean return-value check, and dynamic confirmation evidence (Method D/E) if performed.

---

## 4. Recommendations

### 4.1 Implement Explicit Hostname Verification Every Time `SSLSocket` Is Used

```java
SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
SSLSocket socket = (SSLSocket) factory.createSocket(host, port);
socket.startHandshake();

SSLSession session = socket.getSession();
HostnameVerifier verifier = HttpsURLConnection.getDefaultHostnameVerifier();
if (!verifier.verify(host, session)) {
    socket.close();
    throw new SSLPeerUnverifiedException("Hostname verification failed: " + host
        + " does not match the certificate presented by the server");
}
// The connection is only considered safe to use AFTER this point
```

**Always explicitly check the return value of `verify()`** — do not assume an exception will be thrown automatically (see the warning in §1.4).

### 4.2 Migrate to a Higher-Level API Where Possible

If business requirements do not strictly require low-level socket control, migrating to `HttpsURLConnection` or OkHttp is considerably safer, since hostname verification is already handled automatically by the framework, reducing the surface area for manual implementation mistakes:

```java
// An alternative that handles hostname verification automatically
OkHttpClient client = new OkHttpClient.Builder().build();
Request request = new Request.Builder().url("https://" + host + path).build();
Response response = client.newCall(request).execute();
```

### 4.3 Centralize Custom TLS Connection Logic

If `SSLSocket` is still required (e.g., for a non-HTTP protocol), create a **single centralized wrapper** that always includes the verification step, rather than letting each part of the code create `SSLSocket` instances independently — this reduces the risk of forgetting to add verification at any one of many socket-creation points:

```java
public final class SecureSocketFactory {
    public static SSLSocket createVerifiedSocket(String host, int port) throws IOException {
        SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
        SSLSocket socket = (SSLSocket) factory.createSocket(host, port);
        socket.startHandshake();
        if (!HttpsURLConnection.getDefaultHostnameVerifier().verify(host, socket.getSession())) {
            socket.close();
            throw new SSLPeerUnverifiedException("Hostname verification failed: " + host);
        }
        return socket;
    }
}
```

### 4.4 Integrate into CI/CD with a Semantically Correct Rule

```bash
#!/bin/bash
# ci-check-sslsocket-hostname.sh — USE the custom rule (§3.3), NOT the official MASTG rule, which targets the wrong pattern
APK=$1
jadx -d /tmp/decompiled_check "$APK" 2>/dev/null
semgrep -c ./custom-sslsocket-hostname-rule.yml /tmp/decompiled_check/sources/ --json | jq '.results | length'
```

### 4.5 Remediation Checklist

- [ ] All uses of `SSLSocket`/`SSLSocketFactory` in the codebase have been inventoried (Method B/C, **not** just the official rule)
- [ ] Every `SSLSocket` creation is followed by a `getSession()` + `HostnameVerifier.verify()` call before the socket is used to send/receive data
- [ ] The boolean return value of `verify()` is explicitly checked, with failure handling that rejects the connection
- [ ] Where possible, migration to `HttpsURLConnection`/OkHttp (which handles verification automatically) has been performed
- [ ] Custom TLS connection logic is centralized through a single factory/wrapper for consistency
- [ ] For every `HostnameVerifier` found to EXIST, follow-up testing with MASTG-TEST-0283 has been performed to assess the security of its implementation
- [ ] Dynamic confirmation (Method D or E) has been performed on communication paths that use `SSLSocket`
- [ ] **Re-verification:** re-run MASTG-TEST-0234 on the final release APK after remediation

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0234: Missing Implementation of Server Hostname Verification with SSLSockets](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0234/)
- [MASTG-TEST-0283: Incorrect Implementation of Server Hostname Verification](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0283/)
- [MASWE-0027: Insecure Certificate Validation](https://mas.owasp.org/MASWE/MASVS-NETWORK/MASWE-0027/)
- [MASTG-TECH-0013: Reverse Engineering Android Apps](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/)
- [MASTG-TECH-0014: Static Analysis on Android](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/)
- [MASTG-TECH-0023: Reviewing Decompiled Java Code](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0023/)
- [MASTG Document 0x04f — Testing Network Communication](https://mas.owasp.org/MASTG/0x04f-Testing-Network-Communication/)
- [Official rule: mastg-android-network-hostname-verification.yml (GitHub)](https://github.com/OWASP/mastg/blob/master/rules/mastg-android-network-hostname-verification.yml)
- [OWASP Mobile Top 10 2024 — M5: Insecure Communication](https://owasp.org/www-project-mobile-top-10/2023-risks/m5-insecure-communication)

### 5.2 Official Android Documentation

- [Android Developers — Security with network protocols (SSLSocket warnings)](https://developer.android.com/privacy-and-security/security-ssl#WarningsSslSocket)
- [Android Developers — `SSLSocket` API reference](https://developer.android.com/reference/javax/net/ssl/SSLSocket)
- [Android Developers — `HostnameVerifier` API reference](https://developer.android.com/reference/javax/net/ssl/HostnameVerifier)
- [Android Developers — `HostnameVerifier.verify()` method reference](https://developer.android.com/reference/javax/net/ssl/HostnameVerifier#verify(java.lang.String,%20javax.net.ssl.SSLSession))
- [Android Developers — Unsafe HostnameVerifier (risks documentation)](https://developer.android.com/privacy-and-security/risks/unsafe-hostname)
- [Android Developers — Security with network protocols](https://developer.android.com/training/articles/security-ssl)

### 5.3 Research and Third-Party Sources

- [op-co.de — Java/Android SSLSocket Vulnerable to MitM Attacks](https://op-co.de/blog/posts/java_sslsocket_mitm/)
- [Google — How to resolve Insecure HostnameVerifier (Play Console FAQ)](https://support.google.com/faqs/answer/7188426?hl=en)
- [grahamedgecombe/android-ssl — SSL certificate validation vulnerability detection tools](https://github.com/grahamedgecombe/android-ssl)
- [arXiv — An Application Package Configuration Approach to Mitigating Android SSL Vulnerabilities](https://arxiv.org/pdf/1410.7745)
- [arXiv — Ghera: A Repository of Android App Vulnerability Benchmarks](https://arxiv.org/pdf/1708.02380)
- [arXiv — Are Free Android App Security Analysis Tools Effective in Detecting Known Vulnerabilities?](https://arxiv.org/pdf/1806.09059)
- [NowSecure — Fully validate SSL/TLS (Secure Mobile Development Best Practices)](https://books.nowsecure.com/secure-mobile-development/en/sensitive-data/fully-validate-ssl-tls.html)
- [CWE-297: Improper Validation of Certificate with Host Mismatch](https://cwe.mitre.org/data/definitions/297.html)
- [CWE-295: Improper Certificate Validation](https://cwe.mitre.org/data/definitions/295.html)

### 5.4 Tool Documentation

- [Semgrep — Documentation](https://semgrep.dev/docs/)
- [CodeQL — Documentation](https://codeql.github.com/docs/)
- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [Frida — Dynamic instrumentation toolkit](https://frida.re/docs/javascript-api/)
- [socat — Multipurpose relay (used to simulate a wrong-domain TLS server)](http://www.dest-unreach.org/socat/)
- [mitmproxy](https://mitmproxy.org/)

---

*This document was prepared based on OWASP MASTG (current as of September 2026), the official Android Developers documentation, and academic and community security research on Android SSL validation vulnerabilities. This test does not yet have an official demo (MASTG-DEMO), and its official semgrep rule has been identified as having a significant structural gap (§3.2) — this document provides a custom rule and alternative methods that genuinely and semantically test the FAIL condition defined by the official overview.*
