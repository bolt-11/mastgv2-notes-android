# MASTG-TEST-0236 Cleartext Traffic Observed on the Network

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0236 |
| **Platform** | Network (cross-platform — Android and iOS techniques are equally referenced) |
| **MASVS Category** | MASVS-NETWORK |
| **Weakness** | MASWE-0026 — *Network Traffic Not Encrypted* |
| **Test Type** | Dynamic, Network |
| **Related Techniques** | MASTG-TECH-0010 (Basic Network Monitoring/Sniffing), MASTG-TECH-0011 (Setting Up an Interception Proxy), MASTG-TECH-0012 (Disable Pinning, Android); MASTG-TECH-0062/0063/0064 (iOS equivalents) |
| **Related Tests** | **MASTG-TEST-0235** (native cleartext configuration — static), **MASTG-TEST-0237** (cross-platform framework configuration), **MASTG-TEST-0238** (Frida hooking — resolves the attribution limitations of this test) |
| **Official Rule** | — (none; this test is purely network capture, not relevant to Semgrep) |

---

## 1. Explanation

### 1.1 Testing Objective and Its Position Within the Cleartext Traffic Trio/Quartet

Quote from the official MASTG overview:

> *"This test intercepts the app's incoming and outgoing network traffic, and checks for any cleartext communication. Whilst the static checks can only show potential cleartext traffic, this dynamic test shows all communication the application definitely makes."*

This is the third test in the sequence of cleartext traffic tests already covered in this research series (alongside TEST-0235, 0237, 0238) — and it is philosophically the **most different** of the four, because it **does not look at the application code at all**. TEST-0235/0237 inspect **configuration** (whether the OS/framework *permits* cleartext), whereas this test inspects **the reality on the wire** — what actually traverses the network, regardless of what the configuration or code claims. This provides, in theory, the **most conclusive evidence**: if cleartext is found in a network capture, cleartext **actually occurred**, not merely "might have occurred" as a conclusion drawn from static audit alone.

### 1.2 Two Methodological Limitations Acknowledged Explicitly and Honestly

The official warning section transparently acknowledges two significant precision gaps — these have already been discussed in depth in the MASTG-TEST-0238 document as a problem that test **solves**, but they must be reiterated here as essential context:

> *"Intercepting traffic on a network level will show all traffic the device performs, not only the single app. Linking the traffic back to a specific app can be difficult, especially when more apps are installed on the device."*
>
> *"Linking the intercepted traffic back to specific locations in the app can be difficult and requires manual analysis of the code."*

These two limitations — **app attribution** and **code-location attribution** — are the main reasons MASTG-TEST-0238 (the Frida-hooking-based approach) exists as a **complement** to, not a replacement for, this test. This test (network-level capture) and TEST-0238 (process-level instrumentation) **complement each other**: this test provides a **comprehensive** picture of what happens on the network (including traffic from components that might be missed by hooking, such as a native library calling a syscall directly), while TEST-0238 provides **attribution precision** that this test lacks.

### 1.3 Third Limitation: Dynamic Testing That Is Never Truly Exhaustive

> *"Dynamic analysis works best when you interact extensively with the app. But even then there could be corner cases which are difficult or impossible to execute on every device. The results from this test therefore are likely not exhaustive."*

This is a general principle of dynamic testing that has already proven relevant repeatedly throughout this research series — a **PASS** result from this test (no cleartext found) is **never** proof of the absolute absence of cleartext, only proof that cleartext was not observed **during the testing session and the flows that were successfully triggered**. Flows that were not executed (particular error scenarios, rarely used features, specific network conditions) can still hide cleartext calls that escaped observation.

### 1.4 Two Capture Approaches and the Limitation on Non-HTTP Protocols

The overview offers two capture technique options with different characteristics:

| Technique | Coverage | Limitation |
|---|---|---|
| **Basic Network Sniffing** (tcpdump, Wireshark — MASTG-TECH-0010) | All packet-level traffic, all protocols | Does not automatically decode HTTP(S)/application payload content; requires further manual analysis |
| **Interception Proxy** (Burp, mitmproxy — MASTG-TECH-0011) | HTTP(S) automatically decoded, easy to read | **Only** HTTP(S) — other protocols (XMPP, custom TCP/UDP) are not captured directly |

The official note explicitly acknowledges this gap and offers a solution:

> *"Interception proxies will show HTTP(S) traffic only. You can, however, use some tool-specific plugins such as Burp-non-HTTP-Extension or other tools like Wireshark to decode and visualize communication via XMPP and other protocols."*

This is relevant because modern applications often use **more than HTTP** for real-time communication (WebSocket, custom chat protocols, gRPC over HTTP/2 which standard proxies sometimes do not parse perfectly) — relying on an interception proxy alone risks missing cleartext that occurs over these non-HTTP protocol paths.

### 1.5 Practical Challenge: Certificate Pinning as an Observation Barrier

> *"Some apps may not function correctly with proxies like Burp and mitmproxy because of certificate pinning. In such a scenario, you can still use basic network sniffing to detect cleartext traffic. Otherwise, you can try to disable pinning."*

This offers an important practical nuance — if the target application employs strong certificate pinning, **MITM-based interception proxies (Method A) will not function** for HTTPS traffic (the connection will fail/be rejected by the app). However, the crucial point is: **precisely because this test specifically looks for CLEARTEXT (not HTTPS)**, certificate pinning is **irrelevant** for traffic that is not encrypted at all in the first place — basic network sniffing (tcpdump/Wireshark) can still capture plain HTTP cleartext packets without needing to pass through any TLS/pinning mechanism at all, because pinning only applies to connections that **attempt** to use TLS.

### 1.6 Real-World Evidence: WebDAV Credentials and Map Tiles Sent via HTTP Cleartext

Research and real bug reports confirm that the scenario this test targets — finding cleartext traffic that **actually carries credentials** — is not merely a theoretical risk:

> *"An app permits cleartext HTTP traffic globally, and Nextcloud/Owncloud integrations accept user-supplied http:// server URLs — in which case login credentials are sent via HTTP Basic Auth in cleartext."*

> *"Cleartext HTTP traffic permitted; http:// map tiles and WebDAV credentials"* — from a public bug report that specifically flagged this finding as a `[MEDIUM]` security issue.

These cases demonstrate a pattern that fits exactly with this test's methodology — findings like this **can only be confirmed through observation of actual network traffic**, because the root cause is often not the application's own logic, but rather the **server URL configured by the user** (for example, the user typing `http://` instead of `https://` when setting up a WebDAV integration) — something that **cannot possibly be detected through static code audit**, because the URL value is determined at runtime by user input, not hardcoded in the code.

---

## 2. Tools Used for Testing

### 2.1 Required Tools (Core)

| Tool | Function |
|---|---|
| **tcpdump** (Android) | Packet-level traffic capture directly on the device (MASTG-TECH-0010) |
| **Wireshark** | Analysis and decoding of capture results, including non-HTTP protocols (MASTG-TECH-0010, §1.4) |
| **Burp Suite / mitmproxy** | Interception proxy for automatically decoded HTTP(S) (MASTG-TECH-0011) |

### 2.2 Alternative and Supporting Tools

| Tool | Function |
|---|---|
| **Burp-non-HTTP-Extension** | Decoding non-HTTP protocols such as XMPP within Burp (§1.4) |
| **Frida (for pinning bypass)** | Disables certificate pinning so HTTPS traffic can be inspected by an MITM proxy (MASTG-TECH-0012) — but **not required** for pure cleartext traffic (§1.5) |

### 2.3 Environment Prerequisites

- A device/emulator with root capability (for tcpdump) or proxy configuration (for an interception proxy).
- **Isolation of the test environment** — ideally the test device should run only the target application, or use filtering based on the app's IP/port to reduce noise from other system apps (mitigating the attribution limitation in §1.2).

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

Use one of two approaches:
- **MASTG-TECH-0010** (basic network sniffing) to capture all traffic.
- **MASTG-TECH-0011** (interception proxy) to capture automatically decoded HTTP(S).

### 3.2 Method A — tcpdump + Wireshark for Comprehensive Capture

```bash
adb shell tcpdump -i wlan0 -w /sdcard/capture.pcap
# ... run the application, exercise all features ...
adb pull /sdcard/capture.pcap
wireshark capture.pcap
```

Wireshark filter for HTTP cleartext:
```
http and ip.addr == <IP_device>
```

### 3.3 Method B — Interception Proxy for Decoded HTTP(S)

```bash
mitmproxy --mode transparent
```

Configure the proxy on the device/emulator (MASTG-TECH-0011), then inspect the request tab for entries using the `http://` scheme (not `https://`).

### 3.4 Method C — Bypass Pinning When Needed for Related HTTPS Analysis

```bash
frida -U -f com.example.app -l universal-ssl-pinning-bypass.js --no-pause
```

Note: this step is **only relevant** when the goal also includes inspecting HTTPS traffic content for other test purposes; for this pure cleartext test, Method A is sufficient and is not hindered by pinning at all (§1.5).

### 3.5 Method D — Decoding Non-HTTP Protocols

```bash
# Via Burp with a non-HTTP extension, or manual payload analysis in Wireshark
# Filter for a specific protocol, e.g. XMPP:
xmpp
```

### 3.6 Method Comparison: When to Use Which

| Method | Tool | When to Use |
|---|---|---|
| **A** | tcpdump + Wireshark | The most comprehensive baseline — captures all protocols |
| **B** | Interception proxy | Easier to read for HTTP(S) traffic |
| **C** | Frida pinning bypass | Only needed to inspect HTTPS content, not relevant for pure cleartext |
| **D** | Burp non-HTTP / Wireshark decoder | Specific protocols (XMPP, custom) |

**Minimum recommended combination:** **A (comprehensive) + B (ease of reading HTTP)**, with **D** as a complement when the application is known to use non-HTTP protocols.

---

### 3.7 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rule:**

> **Evaluation:** *"The test case fails if any clear text traffic originates from the target app."*

With a realistic caveat:

> *"This can be challenging to determine because traffic can potentially come from any app on the device."*

---

#### ❌ FAIL / ISSUE — The check is declared FAILED when:

| No | Condition |
|---|---|
| F1 | Cleartext traffic (HTTP without TLS, or another unencrypted protocol) is found that is **confirmed** to originate from the target application |

**Example evidence (reflecting the real WebDAV pattern from §1.6):**

```
GET /webdav/files/document.pdf HTTP/1.1
Host: nas.local
Authorization: Basic YWRtaW46cGFzc3dvcmQxMjM=
```

Interpretation: WebDAV credentials (Basic Auth, merely Base64 — not encryption) are sent over pure HTTP cleartext. The payload can be read directly by anyone sniffing the network. **FAIL**.

---

#### ✅ PASS — The check is declared PASSED when:

| No | Condition |
|---|---|
| P1 | All observed traffic from the target application uses TLS/encryption, after sufficiently thorough exercise |

---

#### ⚠️ Important Notes on Assessment

1. **Always verify the attribution of the traffic source** — per §1.2, cleartext captured at the network level does not automatically originate from the target application; correlate it with the timing of application activity, destination IP/port known to be associated with the application's backend, or proceed to MASTG-TEST-0238 for definitive attribution confirmation via stack trace.

2. **PASS is never absolute** — per §1.3, always record which flows were/were not successfully triggered during the testing session; cleartext that only appears in certain scenarios (error handling, connection fallback) is easily missed.

3. **Do not forget non-HTTP protocols** — per §1.4, a standard interception proxy only captures HTTP(S); use basic network sniffing for comprehensive coverage of WebSocket/custom protocols.

4. **Pinning is not a barrier for this test specifically** — per §1.5, pure cleartext traffic remains visible via basic network sniffing regardless of pinning; do not waste time bypassing pinning if the goal is only to find cleartext.

5. **Severity is modulated:**

   | Factor | Severity |
   |---|---|
   | Cleartext carries credentials/tokens/sensitive data, confirmed to originate from the target app | **High** |
   | Cleartext carries non-sensitive data (public metadata) | **Medium** |
   | No cleartext found after a thorough exercise | **Not a finding** (with a caveat regarding coverage limitations) |

6. **Document:** the protocol and endpoint carrying cleartext, the payload found (redact credentials in public reports), evidence of attribution to the target app, and the flow triggered to reproduce the finding.

---

## 4. Recommendations

### 4.1 Enforce HTTPS Across All User-Configured Endpoints

For cases such as WebDAV/custom server integration (§1.6) where the user manually types in a server URL, validate and **reject** the `http://` scheme, or automatically upgrade to `https://` before making the connection.

### 4.2 Perform a Comprehensive Audit Across the Cleartext Trio/Quartet

Correlate the findings of this test with MASTG-TEST-0235 (NSC/manifest configuration) and MASTG-TEST-0238 (precise attribution via Frida) to close the methodological gaps of each individual approach.

### 4.3 Remediation Checklist

- [ ] No cleartext traffic is confirmed to originate from the target application after a thorough exercise
- [ ] Validation of server URL input (if user-configured) rejects/upgrades the HTTP scheme
- [ ] Non-HTTP protocols (WebSocket, custom) are checked separately for cleartext
- [ ] Results are correlated with MASTG-TEST-0235/0238 for a complete picture

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0236 (source, tests-beta)](https://github.com/OWASP/mastg/blob/master/tests-beta/network/MASVS-NETWORK/MASTG-TEST-0236.md)
- [MASTG-TEST-0235: Android App Configurations Allowing Cleartext Traffic (related document in this research series)](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0235/)
- [MASTG-TEST-0238: Runtime Use of Network APIs Transmitting Cleartext Traffic (related document in this research series)](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0238/)
- [MASTG-TECH-0010: Basic Network Monitoring/Sniffing](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0010/)
- [MASTG-TECH-0011: Setting Up an Interception Proxy](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0011/)

### 5.2 Research and Real-World Cases

- [GitHub Issue andashi/home#8: Cleartext HTTP Traffic Permitted — http:// Map Tiles and WebDAV Credentials](https://github.com/andashi/home/issues/8)
- [GitHub Issue corona-warn-app/cwa-app-android#2: usesCleartextTraffic Set to True, Allowing HTTP Traffic](https://github.com/corona-warn-app/cwa-app-android/issues/2)
- [ValencyNetworks: Vulnerability Fixation — Cleartext Traffic Enabled in App](https://valencynetworks.com/kb/cleartext-traffic-enabled-iandroidmanifest-xml-security-risks-and-fixes.html)

### 5.3 Tool Documentation

- [tcpdump for Android](https://www.androidtcpdump.com/)
- [Wireshark](https://www.wireshark.org/)
- [Burp-non-HTTP-Extension](https://github.com/summitt/Burp-Non-HTTP-Extension)

---

*This document was compiled based on official OWASP MASTG content (`tests-beta/network/MASVS-NETWORK/MASTG-TEST-0236.md`), supplemented with in-depth cross-references to the MASTG-TEST-0235 and MASTG-TEST-0238 documents in this research series, as well as real public bug reports regarding WebDAV credentials sent over HTTP cleartext. The most important methodological nuance: this test provides, in principle, the most conclusive evidence (what is actually on the wire) but with two attribution limitations honestly acknowledged by MASTG itself — resolved by the complementary approach of MASTG-TEST-0238. Real findings such as leaked WebDAV credentials actually originate from **user input** (a manually typed server URL), a class of vulnerability that is structurally **impossible to detect** through static code audit alone, underscoring the unique added value of direct network traffic observation.*
