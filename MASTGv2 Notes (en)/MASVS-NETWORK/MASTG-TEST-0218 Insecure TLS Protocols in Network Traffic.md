# MASTG-TEST-0218 Insecure TLS Protocols in Network Traffic

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0218 |
| **Platform** | Android |
| **MASVS Category** | **MASVS-NETWORK** (MASVS-NETWORK-1: The app secures all network traffic according to current best practices) |
| **Weakness** | **MASWE-0026** — *Network Traffic Not Encrypted* |
| **Test Type** | **Dynamic**, Network |
| **Profile** | L1, L2 |
| **Related Techniques** | MASTG-TECH-0005 (Installing Apps), MASTG-TECH-0010 (Basic Network Monitoring/Sniffing) |
| **Related Demo** | — (MASTG does not yet provide a demo for this test) |
| **Static Counterpart** | **MASTG-TEST-0217** (Insecure TLS Protocols Explicitly Allowed in Code) |
| **Related CWE** | CWE-326 (Inadequate Encryption Strength), CWE-327 (Use of a Broken or Risky Cryptographic Algorithm), CWE-757 (Algorithm Downgrade), CWE-319 (Cleartext Transmission of Sensitive Information) |
| **Reference Standards** | RFC 8996 (deprecating TLS 1.0/1.1), RFC 8446 (TLS 1.3), NIST SP 800-52 Rev. 2, PCI DSS 4.0 |

---

## 1. Explanation

### 1.1 Testing Objective

Direct quote from the MASTG overview:

> *"While static analysis can identify configurations that allow insecure TLS versions, it may not accurately reflect the actual protocol used during live communications. This is because **TLS version negotiation occurs between the client (app) and the server at runtime**, where they agree on the most secure, mutually supported version."*
>
> *"By capturing and analyzing real network traffic, you can observe the **TLS version actually negotiated and in use**. This approach provides an accurate view of the protocol's security, accounting for the server's configuration, which may enforce or limit specific TLS versions."*
>
> *"In cases where static analysis is either incomplete or infeasible, examining network traffic can reveal instances where insecure TLS versions (e.g., TLS 1.0 or TLS 1.1) are actively in use."*

This test is the **official dynamic counterpart to MASTG-TEST-0217**. Both share the same weakness (MASWE-0026) and substantially identical evaluation criteria ("an insecure TLS version is in use"), but they answer different questions:

| | MASTG-TEST-0217 (static) | MASTG-TEST-0218 (dynamic) |
|---|---|---|
| Answers | "Which version is **enabled** in the code?" | "Which version is **actually negotiated**?" |
| Source of truth | Application code | The real TLS handshake |
| Weakness | Doesn't know what the server accepts; doesn't reach dynamic/native/obfuscated code | Only captures flows that were exercised; gives no code location |

### 1.2 Why Static Analysis Alone Is Not Enough

This is the reason this test exists. The final TLS version is the result of a **negotiation between two parties** — the client proposes the range of versions it supports (`ClientHello`), and the server picks one (`ServerHello`). Code analysis only sees the client side, and can be wrong in two directions:

**Direction 1 — Static says FAIL, but reality is secure.** The code enables TLS 1.1 (e.g., for legacy compatibility), but the **server** actually contacted only accepts TLS 1.2/1.3. The real connection never falls back to TLS 1.1. The real-world severity is lower — though the code still needs to be fixed, since it remains vulnerable to a malicious MitM server willing to accept the downgrade (CWE-757).

**Direction 2 — Static says PASS, but reality is insecure.** This is more dangerous and is in fact the primary reason this test matters:

- **Dynamic/remote configuration.** The `enabledProtocols` array can be built from values fetched from a remote configuration server, a feature flag, or an external file at runtime — never appearing as a static literal.
- **Obfuscated or runtime-loaded code** (DexClassLoader, plugins, a JS bundle in React Native) — ordinary static analysis cannot reach it.
- **Third-party libraries / closed-source SDKs** bundled as `.aar`/`.jar` — sometimes not fully decompiled, or using reflection to configure the socket.
- **Non-default TLS providers** (a custom `Provider`, an old Conscrypt version, or a native `.so` TLS stack) whose actual behavior is invisible from Java-level API signatures.
- **Network-induced downgrade** — a corporate proxy, public WiFi, or a transparent MitM device that forces a fallback to an old version without the app's or the static analysis's knowledge.

The MASTG quote makes this explicit: *"In cases where **static analysis is either incomplete or infeasible**, examining network traffic can reveal instances where insecure TLS versions are actively in use."*

### 1.3 Key Insight: The TLS Version Is Visible Without Decrypting Traffic

This is the most important technical point distinguishing this test from other network tests such as **MASTG-TEST-0206** (which requires full TLS decryption via MitM to see payload contents).

**The TLS handshake — `ClientHello` and `ServerHello` — is sent as *cleartext* by design**, because the two parties have not yet agreed on a session key at that point. The protocol version field sits right in this handshake:

| Message | Contains | Version field |
|---|---|---|
| `ClientHello` | The range of versions **proposed by the client** | `legacy_version` (record layer) + the `supported_versions` extension (for TLS 1.3) |
| `ServerHello` | The version **selected by the server** — this is the final version used | Same field, but containing a single final value |

The practical consequence, which is very favorable for testing:

- **No need to install a proxy CA certificate.**
- **No need to bypass certificate pinning.**
- **No need to decrypt anything at all.**
- Simply **capture raw packets** (`tcpdump`/Wireshark) and read the first two handshake messages.

This makes this test much easier to execute than MASTG-TEST-0206 — even against an app with the strictest pinning, you can still see the TLS version in use without ever having to defeat its pinning.

> **TLS 1.3 nuance:** in TLS 1.3, the `legacy_version` field at the record layer, and in `ClientHello`/`ServerHello`, **always** shows `0x0303` (TLS 1.2) for backward compatibility with legacy middleboxes. The actual negotiated TLS 1.3 version instead appears in the **`supported_versions` extension** of the `ServerHello`. Misreading this field is the most common mistake when analyzing a capture — see §3.2.

### 1.4 TLS Version Classification (Assessment Reference)

Identical to MASTG-TEST-0217 — both are assessed against the same standard:

| Version | Hex value (handshake) | Status | Verdict |
|---|---|---|---|
| SSLv3 | `0x0300` | Broken (POODLE) | ❌ Not allowed |
| **TLS 1.0** | `0x0301` | **Deprecated (RFC 8996)** | ❌ Insecure |
| **TLS 1.1** | `0x0302` | **Deprecated (RFC 8996)** | ❌ Insecure |
| **TLS 1.2** | `0x0303` | Active | ✅ Best practice |
| **TLS 1.3** | `0x0304` (via the `supported_versions` extension) | Active | ✅ Best practice (default on Android 10+) |

Refer to **MASTG-TEST-0217 §1.3** for details on the BEAST/POODLE/downgrade-attack vulnerabilities affecting TLS 1.0/1.1 — the rationale is identical.

### 1.5 Scope to Test: All Connections, Not Just the Main API

Modern apps open many TLS connections that are independent of one another, and each one may have a different configuration/version:

| Connection type | Example | Notes |
|---|---|---|
| Main backend API | `api.example.com` | Usually the most controlled and secure |
| Analytics/ads SDK | `app-measurement.com`, `graph.facebook.com` | Controlled by a third-party vendor — may have a different TLS configuration |
| CDN / static asset | `cdn.example.com` | Often on separate infrastructure with its own TLS policy |
| WebView (if present) | A loaded web page | Uses the WebView's system TLS stack, not the app's OkHttp |
| Push notifications | FCM/GCM (see MASTG-TECH-0010) | Separate XMPP/HTTP protocol, different ports (5228-5230, 5235-5236) |
| Update/OTA check | A remote config/update server | Sometimes skipped during audits as "not sensitive data" |
| Native/NDK connections | A socket from a `.so` library | Doesn't go through the Java stack at all |

**Don't test only the happy-path login flow.** Secondary endpoints (analytics, CDN, push) are often overlooked by developers during TLS hardening, precisely because they're not considered critical — yet they all still carry downgrade-attack risk.

---

## 2. Tools Used for Testing

### 2.1 Required Tools (Core)

| Tool | MASTG ID | Function |
|---|---|---|
| **tcpdump** (Android) | MASTG-TOOL-0080 | Captures packets on the device — recommended by MASTG-TECH-0010. Requires root |
| **Wireshark** | MASTG-TOOL-0081 | Analyzes the capture, filtering on `tls.handshake.version` / `supported_versions` |
| **adb** | MASTG-TOOL-0004 | App installation, port forwarding for remote sniffing |
| **netcat (nc)** | — | Pipes `tcpdump` from the device to Wireshark on the host (MASTG-TECH-0010) |

### 2.2 Supporting Tools

| Tool | Function |
|---|---|
| **tshark** | Wireshark's CLI — automated parsing for reports/CI, much faster than the GUI for many flows |
| **mitmproxy / Burp / ZAP** | Alternative capture — shows the TLS version per flow without manually reading raw handshake bytes |
| **testssl.sh / sslscan / nmap** | Audits the TLS version from the **server side** — complements client-side evidence |
| **Frida / Objection** | Confirms the TLS version directly from the runtime session object (§3.4) — a complement when packet capture is difficult |
| **PCAPdroid** | Packet capture **without root**, directly from the Android app (VpnService) |
| **Android Studio Network Profiler** | Views the app's network connections during debugging, including basic TLS metadata |

### 2.3 Environmental Prerequisites

- **Root is required for `tcpdump` on the device** (MASTG-TECH-0010) — or use **PCAPdroid** as a rootless alternative (§3.3).
- **No need to install a CA certificate** and **no need to bypass certificate pinning** — this is a unique advantage of this test (§1.3). If you already have a MitM setup from MASTG-TEST-0206, it can still be used, but it is not required.
- **Exercise the app extensively**, covering **all connection types** (§1.5) — not just the main login/API flow.
- **A time canary/marker** is not needed here (unlike PII tests) — just make sure every network-facing feature is triggered at least once.
- **Prepare a server baseline** — where possible, also test the endpoint with `testssl.sh` to know what version **could** be negotiated, as a comparison against what the app **actually** negotiates.

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0005** (*Installing Apps*) to install the application.
2. Use **MASTG-TECH-0010** (*Basic Network Monitoring/Sniffing*) to capture the app's traffic.
3. **Exercise the app extensively** to trigger as many flows as possible, entering sensitive data wherever feasible.

### 3.2 Method A — tcpdump on device + Wireshark *(official, MASTG-TECH-0010)*

**Step 1 — Install tcpdump on the device (requires root):**

```bash
adb root
adb remount
adb push ./tcpdump /system/xbin/tcpdump

# If "adbd cannot run as root in production builds":
adb push ./tcpdump /data/local/tmp/tcpdump
adb shell
su
mount -o rw,remount /system    # or: mount -o rw,remount /  if /system isn't mounted
cp /data/local/tmp/tcpdump /system/xbin/
chmod 755 /system/xbin/tcpdump
```

**Step 2 — Remote sniffing to Wireshark on the host:**

```bash
# On the device (via adb shell):
tcpdump -i wlan0 -s0 -w - | nc -l -p 11111

# On the host:
adb forward tcp:11111 tcp:11111
nc localhost 11111 | wireshark -k -S -i -
```

**Step 3 — Exercise the app**, covering all connection types (§1.5), then stop the capture.

**Step 4 — Analyze in Wireshark:**

```
Display filters:
  tls.handshake.type == 1                     # all ClientHello messages
  tls.handshake.type == 2                     # all ServerHello messages
  tls.handshake.version < 0x0303              # <-- INSECURE VERSION (TLS < 1.2)
```

**Analysis with tshark (faster, scriptable):**

```bash
# Extract the handshake version from ALL ServerHello messages (the version finally chosen by the server)
tshark -r capture.pcap -Y "tls.handshake.type==2" -T fields \
  -e ip.dst -e tcp.dstport -e tls.handshake.version

# IMPORTANT: also check the supported_versions extension for TLS 1.3
# (handshake.version will still read 0x0303 even when it's actually TLS 1.3)
tshark -r capture.pcap -Y "tls.handshake.type==2 && tls.handshake.extensions_supported_version" \
  -T fields -e ip.dst -e tls.handshake.extensions_supported_version

# Summary per destination host — check ALL endpoints, not just the main API
tshark -r capture.pcap -Y "tls.handshake.type==2" -T fields \
  -e ip.dst -e tls.handshake.version -e tls.handshake.extensions_supported_version \
  | sort -u

# Filter directly for insecure versions (SSLv3/TLS1.0/1.1) — hex < 0x0303
tshark -r capture.pcap -Y "tls.handshake.type==2 && tls.handshake.version < 0x0303" \
  -T fields -e ip.dst -e tls.handshake.version
```

> **How to read the results correctly (avoiding the most common mistake):** if `tls.handshake.version == 0x0303` **and** the `supported_versions` extension is **empty/absent**, that means **genuine TLS 1.2**. If `tls.handshake.version == 0x0303` **but** the `supported_versions` extension contains `0x0304`, that means **TLS 1.3** (the main field is deliberately kept at `0x0303` for middlebox compatibility). Misreading this can cause you to mistakenly report TLS 1.3 as TLS 1.2.

### 3.3 Method B — PCAPdroid *(no root, directly from the device)*

An alternative when root is unavailable — PCAPdroid uses Android's `VpnService` to capture traffic from all apps (or filtered per app) without requiring root access or system modifications.

```
1. Install PCAPdroid from F-Droid/Play Store
2. Select the target: filter by the app under test
3. Start capture -> exercise the app -> Stop
4. Export as .pcap
5. Pull the file and open it in Wireshark/tshark as in Method A
```

```bash
adb pull /sdcard/Download/PCAPdroid/capture.pcap
tshark -r capture.pcap -Y "tls.handshake.type==2" -T fields -e ip.dst -e tls.handshake.version
```

Advantages: no root needed, much faster setup. Limitations: capture performance on some devices may affect app latency during testing.

### 3.4 Method C — mitmproxy / Burp / ZAP *(if a MitM setup from TEST-0206 already exists)*

If you've already set up an interception proxy for MASTG-TEST-0206, it can also be used here — **although it is not required** (§1.3). Its advantage: the TLS version is shown directly in the UI without needing to read raw handshake fields.

```bash
# mitmproxy — show the TLS version per flow
mitmdump --set flow_detail=3 -s show_tls.py
```

```python
# show_tls.py
from mitmproxy import tls

def tls_established_client(data: tls.TlsData):
    print(f"[{data.context.client.peername}] TLS version: {data.context.client.tls_version}")
```

```bash
mitmdump -s show_tls.py
```

In **Burp Suite**: Proxy > HTTP history > click a request > the **TLS** tab shows the version and cipher suite used per connection.

In **ZAP**: History > click a request > **Alerts**/**TLS handshake detail** tab (via an add-on).

> Note: this method **requires** bypassing pinning if the app validates certificates (because the proxy injects its own certificate) — a drawback that Methods A/B do not have. Use it only if you already have this setup in place for another purpose.

### 3.5 Method D — Frida: confirming the version from the runtime session object

A complement when packet capture is difficult (e.g., a corporate network with restrictions), or to correlate the TLS version directly with the hostname and the calling stack trace in the same log.

```javascript
// tls_version_negotiated.js
Java.perform(() => {
    function bt(max = 8) {
        const E = Java.use("java.lang.Exception");
        const st = E.$new().getStackTrace();
        return Array.from({length: Math.min(max, st.length)}, (_, i) => "    " + st[i]).join("\n");
    }

    // Conscrypt (modern Android's default TLS provider)
    try {
        const Session = Java.use("com.android.org.conscrypt.ActiveSession");
        Session.getProtocol.implementation = function () {
            const v = this.getProtocol();
            const bad = /SSLv3|TLSv1(?!\.[23])|TLSv1\.1/.test(v);
            console.log(`\n[Negotiated] ${v}${bad ? "  [!! INSECURE !!]" : ""}`);
            console.log(bt());
            return v;
        };
    } catch (e) {}

    // Generic hook via SSLSession (works across providers)
    try {
        const SSLSocketImpl = Java.use("javax.net.ssl.SSLSession");
        // SSLSession is an interface; hook via the concrete instance once the connection is established
    } catch (e) {}

    // OkHttp Handshake.tlsVersion() — very useful since OkHttp is the most commonly used library
    try {
        const Handshake = Java.use("okhttp3.Handshake");
        Handshake.tlsVersion.implementation = function () {
            const v = this.tlsVersion();
            console.log(`\n[OkHttp Negotiated] ${v}`);
            console.log(bt());
            return v;
        };
    } catch (e) {}
});
```

```bash
frida -U -f com.example.target -l tls_version_negotiated.js -o negotiated.log
# Exercise the app, then:
grep -B1 "INSECURE" negotiated.log
```

### 3.6 Method E — Server-side audit *(complementary, confirming negotiation capacity)*

This complements client-side evidence by establishing **what could possibly** be negotiated with that endpoint.

```bash
testssl.sh --protocols api.example.com:443
sslscan api.example.com
nmap --script ssl-enum-ciphers -p 443 api.example.com
```

If the server **only** supports TLS 1.2/1.3, then the app's traffic **cannot possibly** fall back to a lower version — giving extra confidence in the capture results. Conversely, if the server still supports TLS 1.0/1.1 as a fallback, this flags a downgrade risk even if the current capture shows TLS 1.2/1.3 (the server picks the most secure option available — but that doesn't guarantee the client would refuse a lower version if proposed by a malicious MitM).

### 3.7 Method Comparison: When to Use Which

| Method | Tool | Needs root? | Needs pinning bypass? | Gives code location? | When to use |
|---|---|---|---|---|---|
| **A** | tcpdump + Wireshark/tshark (MASTG) | **Yes** | **No** | ❌ | **Official baseline** — most accurate, reads the handshake directly |
| **B** | PCAPdroid | **No** | No | ❌ | Non-root devices |
| **C** | mitmproxy / Burp / ZAP | Partial | **Yes** (if pinning is active) | ❌ | If MitM infrastructure already exists from another test |
| **D** | Frida (session object) | Yes/gadget | No | Partial (backtrace) | Packet capture is difficult; want to correlate host + calling code |
| **E** | testssl.sh / sslscan / nmap | No¹ | — | — | Calibrating server-side negotiation capacity |

¹ Method E needs network access to the server, not to the device.

**Recommended minimum combination:** **A or B (packet capture) → E (server audit)**.
Packet capture is the source of truth for the version actually used (and requires no bypass of any kind); the server audit provides context on whether a real downgrade risk exists. Add **D (Frida)** when you need to correlate the TLS version directly with the calling code's stack trace for remediation purposes.

---

### 3.8 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rule:**

> **Observation:** *"The output should contain the app traffic."*
>
> **Evaluation:** *"The test case **fails** if any insecure TLS version is used."*

The criteria are very straightforward — in the same spirit as MASTG-TEST-0217, but the source of truth here is the **real negotiation**, not the code configuration.

---

#### ❌ FAIL / ISSUE — The check is declared FAILED if:

| No. | Condition | Example evidence |
|---|---|---|
| F1 | The `ServerHello` shows `handshake.version` **< `0x0303`** for any connection | `tls.handshake.version == 0x0302` (TLS 1.1) to `api.example.com` |
| F2 | The handshake uses SSLv3 | `tls.handshake.version == 0x0300` |
| F3 | A connection to a **secondary endpoint** (analytics, CDN, push) uses an insecure version | TLS 1.1 to `app-measurement.com`, even though the main API is already TLS 1.3 |
| F4 | Frida confirms `Handshake.tlsVersion()` returns `TLS_1_0`/`TLS_1_1` | `[OkHttp Negotiated] TLS_1_1  [!! INSECURE !!]` |
| F5 | Cleartext traffic (no TLS at all) is found on a connection that should be encrypted | No TLS handshake; data flows as plaintext HTTP — a more severe violation of MASWE-0026 |
| F6 | A downgrade can be reproduced: blocking TLS 1.2/1.3 on the test network forces the app down to TLS 1.1 without rejection | The app does not enforce its own minimum version — fully dependent on the server |

**Example evidence (illustrative — MASTG does not yet provide an official demo):**

```bash
$ tshark -r capture.pcap -Y "tls.handshake.type==2" -T fields \
    -e ip.dst -e tls.handshake.version -e tls.handshake.extensions_supported_version

192.0.2.10    0x0303
192.0.2.11    0x0302
198.51.100.5  0x0303    0x0304
```

Interpretation: the first row is TLS 1.2 (secure), the second row `0x0302` = **TLS 1.1 — FAIL**, the third row is TLS 1.3 (secure, visible from the `supported_versions` extension).

> Because MASTG has not yet published a MASTG-DEMO for this test, the example above was composed based on the official `tshark` output structure and standard TLS fields (RFC 8446), not quoted from an MASTG artifact.

---

#### ✅ PASS — The check is declared PASSED if:

| No. | Condition | Example evidence |
|---|---|---|
| P1 | **All** connections (including secondary endpoints) negotiate TLS 1.2 or TLS 1.3 | Every `tshark` row shows `0x0303` with no old `supported_versions`, or `0x0304` |
| P2 | No cleartext traffic is found on a connection that should be encrypted | All traffic is wrapped in TLS |
| P3 | Frida confirms `tlsVersion()` is always `TLS_1_2`/`TLS_1_3` throughout the exercised session | No `INSECURE` flag in the log |
| P4 | A downgrade cannot be reproduced — the app refuses the connection when no secure version is available | The app fails to connect (not a silent fallback) when TLS 1.2/1.3 is blocked on the test network |

**Example output indicating PASS:**

```bash
$ tshark -r capture.pcap -Y "tls.handshake.type==2 && tls.handshake.version < 0x0303" \
    -T fields -e ip.dst -e tls.handshake.version
# (no results -> no ServerHello with a version < TLS 1.2)
```

---

#### ⚠️ Important Notes on Assessment

1. **Read the `supported_versions` extension, don't rely only on the main `handshake.version` field.** This is the most common mistake (§3.2). TLS 1.3 deliberately shows `0x0303` in the main field for middlebox compatibility — the real version is in the extension. Misreading this can cause TLS 1.3 to be reported as "only TLS 1.2" (not a FAIL, but inaccurate), or conversely cause a real downgrade occurring in another extension to be missed.

2. **Cover all endpoints, not just the main API (§1.5).** Analytics/CDN/push endpoints are often overlooked during hardening precisely because they're considered "less important" — yet they carry the same risk.

3. **Empty output can mean two things: PASS, or the flow was never exercised.** If a feature (e.g., document upload, chat) is never triggered during the capture, its connection simply won't appear in the pcap at all — this is not proof of security, but rather **not tested yet**. Always compare the host list in the capture against the app's feature inventory.

4. **A static FAIL (TEST-0217) plus a dynamic PASS (TEST-0218) do not cancel each other out.** If the code enables TLS 1.1 but the server rejects it, so the capture consistently shows TLS 1.2, **TEST-0217 remains a FAIL** (the code is vulnerable to a malicious MitM server) while **TEST-0218 PASSES for that test session**. Report both separately with an explanation of the causal relationship — don't let a dynamic PASS obscure the static finding.

5. **Conversely, a static PASS plus a dynamic FAIL is a serious signal.** This means there is a downgrade source **invisible from the code** — remote configuration, a third-party SDK, or a network-induced downgrade. Further investigation is mandatory: check third-party dependencies and retest on a different network to rule out the possibility that the test network itself was the source of interference.

6. **Test on more than one network** when possible (home WiFi, cellular data, public WiFi). A downgrade triggered by a corporate proxy or captive portal won't be visible if you only test on a single "clean" network.

7. **Actively attempt to reproduce a downgrade** (F6/P4) to assess resilience, rather than relying only on passive observation. Block TLS 1.2/1.3 on the test firewall (e.g., using `iptables` to reject specific cipher suites, or a MitM proxy that only offers TLS 1.1) and observe whether the app refuses the connection (good) or silently proceeds with the weak version (FAIL — strong evidence that the app does not enforce a minimum version on the client side).

8. **Severity modulation:**

   | Factor | Severity |
   |---|---|
   | TLS 1.0/1.1 negotiated on a connection carrying sensitive data (login, payment) | **High** |
   | TLS 1.1 only on a secondary, non-sensitive endpoint (e.g., anonymous analytics) | **Medium** |
   | Cleartext traffic found (not merely weak TLS) | **Critical** |
   | A downgrade can be actively reproduced (the app does not enforce a minimum version) | **High** — indicates an exploitable MitM vulnerability |
   | All connections consistently use TLS 1.2/1.3 across different test networks | **Not a finding** |

9. **Document:** the capture file (`.pcap`) as raw evidence, a list of hosts along with the negotiated TLS version (a table from tshark), the test network used, the server-side audit results (testssl.sh) as a comparison, and — if performed — the results of the active downgrade test. Cross-reference with the findings of MASTG-TEST-0217 for a complete narrative.

---

## 4. Recommendations

Since the root cause is the same as MASTG-TEST-0217 (MASWE-0026), the following recommendations complement — rather than replace — the recommendations in that document, with emphasis on the aspects specifically revealed through network testing.

### 4.1 Core Principles

**Priority 1 — Fix the code per MASTG-TEST-0217.** If the FAIL in this test originates from an explicit configuration (`setEnabledProtocols`, `COMPATIBLE_TLS`, etc.), refer to the full recommendations in that document.

**Priority 2 — Enforce the minimum version on the CLIENT SIDE, don't rely solely on the server.** This is the point emphasized in assessment note #7 above: an app that silently accepts a downgrade is clear evidence it does not enforce its own policy.

```kotlin
// ✅ Force the client to REJECT when only weak versions are available
val spec = ConnectionSpec.Builder(ConnectionSpec.RESTRICTED_TLS)
    .tlsVersions(TlsVersion.TLS_1_3, TlsVersion.TLS_1_2)   // NO fallback to old versions
    .build()
val client = OkHttpClient.Builder()
    .connectionSpecs(listOf(spec))   // without CLEARTEXT/COMPATIBLE_TLS as a fallback
    .build()
```

**Priority 3 — Fix the TLS configuration on ALL endpoints, not just the main API.** Audit the analytics SDK, CDN, push notifications, and WebView connections separately — each may have its own TLS configuration path outside the direct control of the app's own code (e.g., an outdated vendor SDK version).

**Priority 4 — Update third-party SDKs/libraries.** If the downgrade source is a vendor SDK (not your own code), update to the latest version or contact the vendor. This is a case where a dynamic FAIL is not caught by static analysis of your own code (see assessment note 5).

**Priority 5 — Harden the server configuration.** Disable TLS 1.0/1.1 entirely on the server side (not just the client side) so there is no negotiation path to an old version at all, regardless of what the client proposes. Audit with `testssl.sh` after the change.

**Priority 6 — Retest under various network conditions** as part of regression testing, since a network-induced downgrade (corporate proxy, captive portal) can appear and disappear depending on the environment.

**Priority 7 — Integrate this test into the QA/release pipeline.** Run automated captures (e.g., via scripted PCAPdroid or a Frida script per §3.5) during release smoke tests, and fail the release if an old version negotiation is found on any endpoint.

### 4.2 Remediation Checklist

- [ ] All connections (main API, analytics, CDN, push, WebView) are audited — not just the login flow
- [ ] No `ServerHello` with `handshake.version < 0x0303` on any capture
- [ ] The `supported_versions` extension is checked to ensure TLS 1.3 is correctly detected
- [ ] The client enforces its own minimum version (`tlsVersions` with no fallback to an old version) — not relying solely on the server's rejection
- [ ] An active downgrade test is performed: the app rejects the connection (not a silent fallback) when only a weak version is available
- [ ] Third-party SDKs are updated if they are the source of a downgrade not visible in the app's own code
- [ ] The server is configured to fully reject TLS 1.0/1.1 (verified with testssl.sh)
- [ ] Testing is performed on more than one network (home WiFi, cellular, public WiFi)
- [ ] Findings are cross-referenced with MASTG-TEST-0217 for a complete root-cause narrative
- [ ] Network testing is integrated into the QA/release pipeline as a regression check
- [ ] **Re-verification:** re-run MASTG-TEST-0218 after remediation → all endpoints consistently use TLS 1.2/1.3

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0218: Insecure TLS Protocols in Network Traffic](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0218/)
- [MASTG-TEST-0217: Insecure TLS Protocols Explicitly Allowed in Code](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0217/)
- [MASWE-0026: Network Traffic Not Encrypted](https://mas.owasp.org/MASWE/MASVS-NETWORK/MASWE-0026/)
- [MASTG — Testing Network Communication (Recommended TLS Settings)](https://mas.owasp.org/MASTG/0x04f-Testing-Network-Communication/)
- [MASTG-TECH-0005: Installing Apps](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0005/)
- [MASTG-TECH-0010: Basic Network Monitoring/Sniffing](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0010/)
- [MASTG-TOOL-0080: tcpdump](https://mas.owasp.org/MASTG/tools/network/MASTG-TOOL-0080/)
- [MASTG-TOOL-0081: Wireshark](https://mas.owasp.org/MASTG/tools/network/MASTG-TOOL-0081/)
- [MASVS-NETWORK: Network Communication](https://mas.owasp.org/MASVS/06-MASVS-NETWORK/)
- [OWASP Mobile Top 10 2024 — M5: Insecure Communication](https://owasp.org/www-project-mobile-top-10/2023-risks/m5-insecure-communication.html)

### 5.2 Wireshark Documentation & Packet Analysis

- [Wireshark — TLS dissector documentation](https://www.wireshark.org/docs/dfref/t/tls.html)
- [Ask Wireshark — Where can I find the TLS version in ClientHello?](https://ask.wireshark.org/question/5250/where-can-i-find-the-tls-version-that-is-being-sent-from-the-client-through-the-clienthello-to-the-server/)
- [AnalysisMan — Why TLS version differs in Record Layer and Handshake Protocol](https://www.analysisman.com/2021/06/wireshark-tls1.2.html)
- [F5 — Wireshark may provide misleading TLS version info](https://my.f5.com/manage/s/article/K90932505)
- [tshark — man page](https://www.wireshark.org/docs/man-pages/tshark.html)
- [Android remote sniffing using tcpdump, nc, and Wireshark](https://blog.dornea.nu/2015/02/20/android-remote-sniffing-using-tcpdump-nc-and-wireshark/)
- [androidtcpdump.com — tcpdump binary for Android](https://www.androidtcpdump.com/)

### 5.3 Cryptographic Standards & Taxonomy

- [RFC 8996 — Deprecating TLS 1.0 and TLS 1.1](https://www.rfc-editor.org/rfc/rfc8996.html)
- [RFC 8446 — TLS 1.3 (including `legacy_version` & `supported_versions` semantics)](https://www.rfc-editor.org/rfc/rfc8446)
- [RFC 5246 — TLS 1.2](https://tools.ietf.org/html/rfc5246)
- [RFC 7525 / BCP 195 — Recommendations for Secure Use of TLS and DTLS](https://datatracker.ietf.org/doc/bcp195/)
- [NIST SP 800-52 Rev. 2 — Guidelines for TLS Implementations](https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final)
- [CWE-326: Inadequate Encryption Strength](https://cwe.mitre.org/data/definitions/326.html)
- [CWE-757: Selection of Less-Secure Algorithm During Negotiation](https://cwe.mitre.org/data/definitions/757.html)
- [CWE-319: Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)
- [PCI DSS — Migrating from SSL and early TLS](https://www.pcisecuritystandards.org/documents/Migrating-from-SSL-Early-TLS-Info-Supp-v1_1.pdf)

### 5.4 Android & Related Documentation

- [Android — SSL/Security (TLS 1.3 default since Android 10)](https://developer.android.com/privacy-and-security/security-ssl)
- [Android 10 behavior changes — TLS 1.3 enabled by default](https://developer.android.com/about/versions/10/behavior-changes-all#tls-1.3)
- [OkHttp — TLS Configuration History](https://square.github.io/okhttp/security/tls_configuration_history/)
- [OkHttp `Handshake.tlsVersion()` — API reference](https://square.github.io/okhttp/4.x/okhttp/okhttp3/-handshake/tls-version/)
- [Firebase — Cloud Messaging server reference (XMPP/HTTP ports)](https://firebase.google.com/docs/cloud-messaging/server)

### 5.5 Tool Documentation

- [PCAPdroid — packet capture without root](https://github.com/emanuele-f/PCAPdroid)
- [testssl.sh — Testing TLS/SSL encryption](https://testssl.sh/)
- [sslscan](https://github.com/rbsec/sslscan)
- [nmap — ssl-enum-ciphers script](https://nmap.org/nsedoc/scripts/ssl-enum-ciphers.html)
- [mitmproxy — Documentation](https://docs.mitmproxy.org/stable/)
- [mitmproxy — TLS/SSL addon API](https://docs.mitmproxy.org/stable/api/mitmproxy/tls.html)
- [Burp Suite — TLS inspection](https://portswigger.net/burp/documentation/desktop)
- [OWASP ZAP — Documentation](https://www.zaproxy.org/docs/)
- [Frida — Documentation Home](https://frida.re/docs/home/)
- [Objection — runtime mobile exploration](https://github.com/sensepost/objection)

---

*This document was compiled based on OWASP MASTG (latest release as of September 2026), official Wireshark/tshark documentation, RFC 8446/8996, NIST/PCI DSS standards, and third-party technical research. This test does not yet have an official demo (MASTG-DEMO) from MASTG; the tshark output examples in this document were composed based on standard TLS field structures for illustrative purposes.*
