# MASTG-TEST-0206 Undeclared PII in Network Traffic Capture

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0206 |
| **Platform** | Android |
| **MASVS Category** | **MASVS-PRIVACY** (MASVS-PRIVACY-3: The app is transparent about the collection and use of data) |
| **Weakness** | MASWE-0073 — *Inadequate Data Collection Declarations* |
| **Test Type** | **Dynamic**, **Network** |
| **Profile** | **P** (Privacy) — *not* L1/L2 |
| **Prerequisites** | `identify-sensitive-data`, **`privacy-policy`**, **`app-store-privacy-declarations`** |
| **Related Techniques** | MASTG-TECH-0005 (Installing Apps), MASTG-TECH-0100 (Logging Sensitive Data from Network Traffic) |
| **Referenced Tools** | MASTG-TOOL-0097 (mitmproxy), MASTG-TOOL-0077 (Burp Suite), MASTG-TOOL-0079 (ZAP), MASTG-TOOL-0081 (Wireshark) |
| **Related Demo** | MASTG-DEMO-0009 (Detecting Undeclared PII in Network Traffic) |
| **Complementary Tests** | MASTG-TEST-0318 (References to SDK APIs Known to Handle Sensitive User Data — static), MASTG-TEST-0319 (Runtime Use of SDK APIs... — dynamic/hooks) |
| **Related CWE** | CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor), CWE-200 (Exposure of Sensitive Information), CWE-201 (Insertion of Sensitive Information Into Sent Data), CWE-497 (Exposure of Sensitive System Information) |
| **Related Regulations** | GDPR Art. 5 & 13 (transparency & information to data subjects), Indonesia's PDP Law, CCPA §1798.100, Google Play Data safety policy |

---

## 1. Explanation

### 1.1 Testing Objective

This test aims to verify that **sensitive data — specifically PII (Personally Identifiable Information) — is not sent over the network without being declared**, by capturing and decrypting the app's network traffic.

Direct quote from the MASTG overview:

> *"Attackers may capture network traffic from Android devices using an intercepting proxy, such as mitmproxy, Burp Suite, or ZAP, to analyze the data being transmitted by the app. **This works even if the app uses HTTPS**, as the attacker can install a custom root certificate on the Android device to decrypt the traffic. Inspecting traffic that is not encrypted with HTTPS is even easier and can be done without installing a custom root certificate for example by using Wireshark."*
>
> *"The goal of this test is to verify that sensitive data, specifically PII, is not being sent over the network, **even if the traffic is encrypted**. This test is especially important for apps that handle sensitive data, such as financial or health data, and **should be performed in conjunction with a review of the app's privacy policy and the app's marketplace privacy declarations** (e.g., Data Safety section in Google Play)."*

### 1.2 Paradigm Shift: This Is a Privacy Test, Not a Security Test

This is the **most important conceptual distinction** to understand before working on this test, and the one that sets it apart from all the previous tests we have covered.

Note three clues from the metadata and documentation:

1. **The profile is only `P` (Privacy)** — not L1/L2. This test does not fall under the standard security verification profiles.
2. **The key phrase in the overview:** *"even if the traffic is encrypted"*.
3. **The explicit note in MASTG-DEMO-0009:**

   > *"Note that **both the request and the response are encrypted using TLS, so they can be considered secure**. However, this **might represent a privacy issue** depending on the relevant privacy regulations and the app's privacy policy. You should now check the privacy policy and the App Store Privacy declarations to see if the app is allowed to send this data to a third-party."*

In other words: **an app that implements TLS correctly, with strong certificate pinning and flawless network security controls overall, can still FAIL this test.** What is being tested is not whether the data is protected from an attacker, but whether the data collection is **honestly declared to the user**.

Compare with the previous tests:

| Test | What is assessed | Control being checked |
|---|---|---|
| MASTG-TEST-0200/0201/0202 | Whether sensitive data is exposed to unauthorized parties | Encryption, sandboxing, permissions |
| MASTG-TEST-0203 | Whether sensitive data leaks into logs | Log removal/redaction |
| MASTG-TEST-0204/0205 | Whether random values are predictable | CSPRNG |
| **MASTG-TEST-0206** | **Whether data collection is honestly declared** | **Transparency & consent** |

The practical consequence: **you cannot complete this test just by capturing traffic.** You must have reference documents to compare against — which is exactly why this test has `privacy-policy` and `app-store-privacy-declarations` as prerequisites. Without them, the best you can produce is a **data inventory** (a list of PII transmitted), not a PASS/FAIL verdict.

### 1.3 Why This Matters: The Scale of the Problem

Mismatches between declarations and an app's actual behavior are not rare edge cases — they are a systemic problem:

- A study of **7,770 popular mobile games** found mismatches between the privacy policy and the Data safety declaration in **nearly 53% of cases**; the figure rose to **61%** among 1,711 widely used generic apps.
- Static code analysis showed that privacy policies disclosed only **66.8%** of potential access to sensitive data (location, financial), while Data safety declarations disclosed only **36.4%** for mobile games.
- **A network traffic analysis of 500 apps found that more than a quarter of them sent tracking data that was not declared** in their Data safety label. This is precisely this test's methodology.

**Consequences for developers:** a mismatch between what the code collects and what is declared on the form is grounds for **policy strikes and app removal** from Google Play, as well as a breach of disclosure obligations under **GDPR Art. 13** and **CCPA §1798.100**. Google states that if it becomes aware of a discrepancy between an app's behavior and its declarations, it may take enforcement action.

### 1.4 Foundation: What Counts as PII and Sensitive Data

For this test, the most practical reference is the **Google Play Data safety section's list of data types**, because that is the document you will be comparing against. The categories are:

| Category | Example data types |
|---|---|
| **Location** | Approximate location, **Precise location** |
| **Personal info** | Name, email address, **User IDs**, address, phone number, race & ethnicity, political/religious beliefs, sexual orientation, other personal info |
| **Financial info** | User payment info, purchase history, credit history, credit score, other financial info |
| **Health and fitness** | **Health info**, fitness info |
| **Messages** | Emails, SMS/MMS, other in-app messages |
| **Photos and videos** | Photos, videos |
| **Audio files** | Voice/sound recordings, music files, other audio files |
| **Files and docs** | Files & documents |
| **Calendar** | Calendar events |
| **Contacts** | Contacts |
| **App activity** | App interactions, in-app search history, installed apps, user-generated content, other actions |
| **Web browsing** | Web browsing history |
| **App info and performance** | Crash logs, diagnostics, other performance data |
| **Device or other IDs** | **Device or other IDs** (Advertising ID, Android ID, etc.) |

For each data type, the declaration must cover whether it is **collected**, whether it is **shared** with third parties, whether it is **encrypted in transit**, whether it is optional, and its **purpose** of use. A mismatch can occur along any of these dimensions — for example, data may be declared as "collected" only, while in reality it is also "shared" with a third party.

In addition, also consider the **special categories** under GDPR Art. 9 (health, biometric, genetic data, religious/political beliefs, sexual orientation, union membership) and the sensitive data categories under Indonesia's PDP Law — this data demands a stronger legal basis, not merely a declaration.

### 1.5 This Test's Position within the MASWE-0073 Series

MASTG has three tests under the MASWE-0073 weakness, which complement each other:

| Test | Approach | Answers | Strength | Weakness |
|---|---|---|---|---|
| **MASTG-TEST-0206** *(this document)* | **Dynamic — network interception** | "**What data** actually **leaves the device**, to **which host**?" | The most direct and convincing evidence; captures all traffic including from third-party SDKs without needing to know the API | **Does not give code locations**; blocked by certificate pinning; only covers exercised flows; blind to payloads encrypted at the application layer |
| **MASTG-TEST-0318** | Static — pattern matching | "**Which SDK APIs** are referenced?" | Thorough coverage, fast, CI-friendly | Only detects **potential**, not confirmation; requires prior knowledge of each SDK's entry points |
| **MASTG-TEST-0319** | Dynamic — method hooking | "**What value** is sent to the SDK, from **which line of code**?" | Provides a **backtrace + argument values**; captures data before it is encrypted/encoded | Requires knowledge of the SDK API; can be blocked by anti-instrumentation |

MASTG states this relationship explicitly in the Evaluation section:

> *"Note that this test does not provide any code locations where the sensitive data is being sent over the network. In order to identify the code locations you can use MASTG-TECH-0014 or MASTG-TECH-0015. Consult MASTG-TEST-0318 and MASTG-TEST-0319, respectively, for more details."*

**Recommended strategy:**

```
TEST-0206 (network capture)  ──►  PII inventory + list of destination hosts
        │                              (STRONG evidence, without code location)
        │
        ├── compare against ──►  Privacy Policy + Data safety section
        │                                    │
        │                                    ▼
        │                          PASS / FAIL decision
        │
        └── for remediation ──►  TEST-0318 (static) / TEST-0319 (hooks)
                                      to find the CODE LOCATION
```

And note: **TEST-0319 catches what TEST-0206 misses.** If an app implements certificate pinning that cannot be bypassed, or encrypts the payload at the application layer before sending (so the body content remains unreadable even after TLS is decrypted), hooking the SDK API can still reveal the data before it is processed. The two tests close each other's blind spots.

---

## 2. Tools Used for Testing

### 2.1 Required Tools (Core)

| Tool | MASTG ID | Role in this test |
|---|---|---|
| **mitmproxy / mitmdump** | MASTG-TOOL-0097 | **Primary tool** — used by MASTG-TECH-0100 and MASTG-DEMO-0009. Its strength: scriptable in Python, making automatic PII filtering and structured logging easy |
| **Burp Suite** | MASTG-TOOL-0077 | Alternative intercepting proxy. Excels at manual exploration, match-and-replace, and extensions (e.g., searching for PII via Bambdas/BApp) |
| **ZAP (Zed Attack Proxy)** | MASTG-TOOL-0079 | Open-source alternative |
| **Wireshark** | MASTG-TOOL-0081 | For **non-HTTPS** traffic — **no need to install a root certificate**. Also essential for mapping non-HTTP protocols (MQTT, DNS, QUIC) and detecting cleartext traffic |
| **adb** | MASTG-TOOL-0004 | App installation (MASTG-TECH-0005), proxy configuration, certificate management |
| **Android emulator with `-writable-system`** | MASTG-TOOL-0003 | Required to install the proxy certificate as a **system CA** — see §2.3 |

### 2.2 Supporting Tools (Very Much Needed in Practice)

| Tool | Role |
|---|---|
| **Frida** | MASTG-TOOL-0001. **Almost always required** — to bypass certificate pinning so traffic can be decrypted. Also used for MASTG-TEST-0319 |
| **Objection** | MASTG-TOOL-0038. `android sslpinning disable` — quick pinning bypass without writing a script |
| **frida-script "Universal Android SSL Pinning Bypass"** | Ready-to-use community script covering various pinning implementations (OkHttp, TrustManager, Conscrypt, Netty, WebView) |
| **apktool + apksigner** | Patch `network_security_config.xml` to trust the user CA and remove `<pin-set>`, then repackage. Alternative when Frida is blocked |
| **objection patchapk / frida-gadget** | For non-rooted devices |
| **jadx** | MASTG-TOOL-0018. Tracing code locations after findings (together with TEST-0318) |
| **`mitmproxy2swagger` / `mitmdump -w`** | Saving flows for re-analysis (offline) — important so you don't have to repeat the whole exercise session |
| **`jq`, `protoc --decode_raw`, `gzip -d`, `base64 -d`** | **Crucial.** For normalizing payloads so PII is readable: JSON, Protobuf, gzip, Base64 |
| **PolarProxy / SSLsplit** | Interception for non-HTTP, TLS-based protocols |
| **Burp Sequencer / custom grep-and-match** | PII scanning across a collection of flows |
| **Google Play Console / the app's Play Store page** | **Not a technical tool, but mandatory** — the source of the Data safety declaration for comparison |

### 2.3 Environment Prerequisites — The Hardest Part of This Test

Setting up a working interception is the part that consumes the most time. There are three layered obstacles:

**Obstacle 1 — Apps targeting Android 7 (API 24) and above do not trust the user CA by default.**

Since API 24, apps only trust the system CA unless stated otherwise in `network_security_config.xml`. Installing the mitmproxy certificate via *Settings → Security → Install certificate* **is not enough**. The options are:

```bash
# Option A (used by MASTG-DEMO-0009): emulator with a writable system,
#         then install the certificate as a SYSTEM CA
emulator -avd Pixel_3a_API_33_arm64-v8a -writable-system

adb root
adb shell "mount -o rw,remount /"          # on API 29+: mount /apex/... as needed
# Compute the mitmproxy certificate's subject hash
openssl x509 -inform PEM -subject_hash_old -in ~/.mitmproxy/mitmproxy-ca-cert.pem | head -1
# -> e.g. c8750f0d
cp ~/.mitmproxy/mitmproxy-ca-cert.pem c8750f0d.0
adb push c8750f0d.0 /system/etc/security/cacerts/
adb shell "chmod 644 /system/etc/security/cacerts/c8750f0d.0"
adb reboot
```

```xml
<!-- Option B: patch network_security_config.xml then repackage
     (useful when system modification is not possible) -->
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />   <!-- trust the proxy certificate -->
        </trust-anchors>
    </base-config>
    <!-- remove any <pin-set> blocks, if present -->
</network-security-config>
```

```bash
# Option C: Frida — no need to modify the system or the APK
objection -g com.example.target explore
# then: android sslpinning disable
```

**Obstacle 2 — Certificate pinning.** If the app implements pinning (common in financial and health apps — precisely the ones that most need testing), the connection will fail even after the proxy certificate is installed as a system CA. A bypass via Frida/Objection or removing `<pin-set>` via repackaging is required.

> **Record this as a positive finding in its own right**, not as a testing failure. Working certificate pinning is a good MASVS-NETWORK control. But do not then report TEST-0206 as PASS — the status is **Inconclusive** until you manage to view the traffic content, or until you supplement it with MASTG-TEST-0319 (hooking, which views data **before** it enters the TLS layer).

**Obstacle 3 — Protocols and encodings that an HTTP proxy cannot read.**

| Challenge | Handling |
|---|---|
| **QUIC / HTTP/3** | Many proxies do not fully handle this. Force a fallback to HTTP/2 by blocking UDP/443 in the firewall/emulator, or disable QUIC via app configuration if possible |
| **gRPC / Protobuf** | Binary payload. Use `protoc --decode_raw` or a mitmproxy addon for protobuf |
| **WebSocket** | mitmproxy supports this, but make sure WS flows are also processed (the `websocket_message` event) |
| **MQTT / custom TCP protocols** | Requires SSLsplit/PolarProxy, or analysis with Wireshark + TLS session keys |
| **Application-layer encryption** | Payload is already encrypted by the app before TLS. **A total blind spot for this test** → must be supplemented with MASTG-TEST-0319 |
| **Compression (gzip/brotli)** | Normalize before PII searching — see §3.4 |

**Non-technical prerequisites (and these are decisive):**

- **The app's privacy policy** — download and save its version along with the access date.
- **Data safety declaration** from the app's Google Play page — screenshot/copy the entire table.
- **A list of canary PII** values that are unique and easy to search for. This is the key technique of this test: use values that cannot plausibly appear by coincidence.

```
Name         : Mastg Canarytest
Email        : mastg.canary.7f3a@example.com
Phone        : +6281234567890
Address      : Jl. Canary Mastg No. 7F3A, Jakarta
Card         : 4111 1111 1111 1111   (test number, not a real card)
Location     : 37.7749 / -122.4194
Date of birth: 1990-07-03
National ID  : 3201077F3A000001      (test format, not a real national ID)
```

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0005** (*Installing Apps*) to install the app.
2. Use **MASTG-TECH-0100** (*Logging Sensitive Data from Network Traffic*) to capture and log the app's network traffic.
3. **Run and use the app through various workflows** while entering sensitive data at every possible location — **especially places you know will trigger network traffic**.

### 3.2 Practical Implementation (MASTG-DEMO-0009)

**Step 0 — Prepare the reference documents (do this BEFORE capturing traffic)**

```bash
mkdir -p ./evidence
# Save the privacy policy
curl -s "https://example.com/privacy" -o ./evidence/privacy-policy-$(date +%F).html
# Record the Data safety declaration from the Play Store page (manual/screenshot)
#   -> ./evidence/data-safety-$(date +%F).md
```

Build a declaration table that will serve as the baseline for comparison:

| Data type | Collected? | Shared? | Encrypted in transit? | Purpose (per declaration) |
|---|---|---|---|---|
| Precise location | ? | ? | ? | ? |
| Email address | ? | ? | ? | ? |
| Phone number | ? | ? | ? | ? |
| Payment info | ? | ? | ? | ? |
| Health info | ? | ? | ? | ? |
| Device or other IDs | ? | ? | ? | ? |

**Step 1 — Run the emulator with a writable system**

```bash
emulator -avd Pixel_3a_API_33_arm64-v8a -writable-system
```

**Step 2 — Install the certificate, configure the proxy, install the app**

```bash
# Install the mitmproxy certificate as a system CA (see §2.3 Option A)

# Route device traffic to the proxy
adb shell settings put global http_proxy 10.0.2.2:8080
# (or run the emulator with -http-proxy http://127.0.0.1:8080)

adb install -g ./target-app.apk
```

**Step 3 — Run mitmproxy with the PII-logging script**

The official MASTG script (`mitm_sensitive_logger.py`):

```python
from mitmproxy import http

# This data would come from another file and should be defined after identifying the data
# that is considered sensitive for this application.
# For example by using the Google Play Store Data Safety section.
SENSITIVE_DATA = {
    "precise_location_latitude": "37.7749",
    "precise_location_longitude": "-122.4194",
    "name": "John Doe",
    "email_address": "john.doe@example.com",
    "phone_number": "+11234567890",
    "credit_card_number": "1234 5678 9012 3456"
}

SENSITIVE_STRINGS = SENSITIVE_DATA.values()

def contains_sensitive_data(string):
    return any(sensitive in string for sensitive in SENSITIVE_STRINGS)

def process_flow(flow):
    url = flow.request.pretty_url
    request_headers = flow.request.headers
    request_body = flow.request.text
    response_headers = flow.response.headers if flow.response else "No response"
    response_body = flow.response.text if flow.response else "No response"

    if (contains_sensitive_data(url) or
        contains_sensitive_data(request_body) or
        contains_sensitive_data(response_body)):
        with open("sensitive_data.log", "a") as file:
            if flow.response:
                file.write(f"RESPONSE URL: {url}\n")
                file.write(f"Response Headers: {response_headers}\n")
                file.write(f"Response Body: {response_body}\n\n")
            else:
                file.write(f"REQUEST URL: {url}\n")
                file.write(f"Request Headers: {request_headers}\n")
                file.write(f"Request Body: {request_body}\n\n")

def request(flow: http.HTTPFlow):
    process_flow(flow)

def response(flow: http.HTTPFlow):
    process_flow(flow)
```

Run it (`run.sh` from the demo):

```bash
mitmdump -s mitm_sensitive_logger.py
```

> **Important note from MASTG** about the `SENSITIVE_DATA` list: *"the script is preconfigured with data that's already considered sensitive for this application. When running this test in a real-world scenario, you should determine what is considered sensitive data based on the app's privacy policy and relevant privacy regulations. One recommended way to do this is by checking the app's privacy policy and the App Store Privacy declarations."*

**Step 4 — Exercise the app extensively**

Focus on flows that trigger network traffic, and enter canary values at every input:

- **Onboarding & first launch** — often sends device fingerprint & Advertising ID before the user has agreed to anything
- Registration, login, logout, re-login, social login
- Complete the profile: name, email, phone, address, date of birth, upload photo/identity documents
- **Grant the location permission**, then move the location in the emulator (Extended controls → Location)
- Grant the contacts, calendar, camera, microphone, storage permissions
- Add a payment method, make a transaction, download an invoice
- Search feature (search history also falls under the App activity data type)
- Chat/messaging, comments, user-generated content
- Health/fitness features if present (Health info = a special category)
- **Trigger a crash** (crash logs are a data type that must be declared)
- Repeatedly background/foreground the app, let it idle for a few minutes (periodic analytics beacons)
- Navigate through every screen — some SDKs send a screen-view event per screen
- **Open the app's Settings**, turn off all "analytics"/"personalization" toggles, then repeat the flows — check whether the collection actually stops
- Uninstall and reinstall (checking whether a persistent ID is sent again)

**Step 5 — Analyze the results**

### 3.3 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rule:**

> **Observation:** *"The output should contain a network traffic log that includes the decrypted HTTPS traffic."*
>
> **Evaluation:** *"The test case **fails** if you can find the PII you entered in the app that is **not declared** in the app's marketplace privacy declarations (e.g., Data Safety section in Google Play) **and/or** in its privacy policy."*

Note the structure of the evaluation sentence. What causes a FAIL is a **combination of two conditions**:

1. The PII you entered is **found** in the network traffic, **AND**
2. That PII is **not declared** in the Data safety section and/or the privacy policy.

This means: **PII that is sent but already correctly declared → PASS** (from this test's perspective). And conversely, **PII that is declared but is actually sent to an undisclosed party/destination → FAIL.**

---

#### ❌ FAIL / ISSUE — The check is declared FAILED when:

| No | Condition | Example evidence |
|---|---|---|
| F1 | A data type that is **not declared at all** is found in the traffic | The request body contains `precise_location_latitude=37.7749` even though Data safety does not list "Precise location" |
| F2 | Data is declared as **"collected" only**, but in reality it is **"shared"** with a third-party domain | The canary email is sent to `api.thirdparty-analytics.com`, not only to the app's backend |
| F3 | PII is sent to an **undisclosed third-party host** not mentioned in the privacy policy | Canary name & phone appear in a request to an attribution/ads SDK |
| F4 | A **special data category** (health, biometric, religion, sexual orientation, children's data) is sent without declaration & adequate legal basis | `blood_type=O` sent to an analytics endpoint |
| F5 | PII is sent **before the user has given consent** or before a privacy screen is shown | Advertising ID + device fingerprint sent on the very first request at *first launch* |
| F6 | Collection **continues after the user has declined/disabled** the analytics/personalization option | The "Analytics" toggle is OFF, but events are still being sent |
| F7 | **Device/other IDs** (Advertising ID, Android ID, IMEI, MAC) are sent without being declared | Request contains `adid=...`, `android_id=...` |
| F8 | PII appears in the **URL / query string** (also a security issue: logged on server & proxy logs, stored in history) | `GET /api/user?email=mastg.canary.7f3a@example.com` |
| F9 | PII is sent over **HTTP cleartext** (visible in Wireshark without a certificate) | **Raise severity** — this is also a MASVS-NETWORK finding |
| F10 | PII appears in a **header** where it should not (e.g., `User-Agent`, `Referer`, custom header) | `X-User-Email: mastg.canary.7f3a@example.com` |
| F11 | Data is collected **more broadly than the declared purpose** (violation of the data minimization principle) | The declaration states "approximate location for local content", but in reality high-precision coordinates are sent periodically |
| F12 | The declaration states data is **"encrypted in transit"**, but in reality it is not | Visible as cleartext in Wireshark |
| F13 | PII is sent to an **endpoint in a jurisdiction** that is not disclosed, even though it is regulatorily relevant | EU residents' data is sent to a server without a valid transfer mechanism |

**Example output indicating FAIL — MASTG-DEMO-0009:**

Sample code (`MastgTest.kt`) — sends PII via `HttpURLConnection` to `https://httpbin.org/post`:

```kotlin
val SENSITIVE_DATA = mapOf(
    "precise_location_latitude" to "37.7749",
    "precise_location_longitude" to "-122.4194",
    "name" to "John Doe",
    "email_address" to "john.doe@example.com",
    "phone_number" to "+11234567890",
    "credit_card_number" to "1234 5678 9012 3456"
)

val url = URL("https://httpbin.org/post")
val httpURLConnection = url.openConnection() as HttpURLConnection
httpURLConnection.requestMethod = "POST"
httpURLConnection.doOutput = true
httpURLConnection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded")

val postData = SENSITIVE_DATA.map { (key, value) ->
    "${URLEncoder.encode(key, "UTF-8")}=${URLEncoder.encode(value, "UTF-8")}"
}.joinToString("&")
// ... sent via BufferedWriter
```

Output of `sensitive_data.log`:

```
REQUEST URL: https://httpbin.org/post
Request Headers: Headers[(b'Content-Type', b'application/x-www-form-urlencoded'), (b'User-Agent', b'Dalvik/2.1.0 (Linux; U; Android 13; sdk_gphone64_arm64 Build/TE1A.220922.021)'), (b'Host', b'httpbin.org'), ...]
Request Body: precise_location_latitude=37.7749&precise_location_longitude=-122.4194&name=John+Doe&email_address=john.doe%40example.com&phone_number=%2B11234567890&credit_card_number=1234+5678+9012+3456

RESPONSE URL: https://httpbin.org/post
Response Headers: Headers[(b'Date', b'Fri, 19 Jan 2024 10:17:44 GMT'), (b'Content-Type', b'application/json'), ...]
Response Body: {
  "form": {
    "credit_card_number": "1234 5678 9012 3456",
    "email_address": "john.doe@example.com",
    "name": "John Doe",
    "phone_number": "+11234567890",
    "precise_location_latitude": "37.7749",
    "precise_location_longitude": "-122.4194"
  },
  ...
  "origin": "148.141.65.87",
  "url": "https://httpbin.org/post"
}
```

MASTG identifies two instances: the POST request that carries PII in the body, and the response that carries PII in the body (because `httpbin.org` echoes back the data it received).

MASTG's evaluation: *"After reviewing the captured network traffic, we can conclude that the test **fails** because the sensitive data is sent over the network. ... in a real-world scenario, you should identify which reported instances are relevant to privacy and require remediation **because they are not included in the app's privacy policy or the App Store privacy declaration**."*

**And a key note that reinforces the nature of this test:**

> *"Note that **both the request and the response are encrypted using TLS, so they can be considered secure**. However, this might represent a **privacy issue**..."*

---

**⚠️ Important finding: the official MASTG script misses 4 out of 6 PII values in the request body.**

This is a real limitation you need to know before using that script as-is. The `contains_sensitive_data()` function performs an **exact substring match**, while the request body is already **URL-encoded**. Let's compare the searched values with what is actually present in the body:

| Value in `SENSITIVE_STRINGS` | Form in the request body (URL-encoded) | Match? |
|---|---|---|
| `37.7749` | `37.7749` | ✅ |
| `-122.4194` | `-122.4194` | ✅ |
| `John Doe` | `John+Doe` (space → `+`) | ❌ |
| `john.doe@example.com` | `john.doe%40example.com` (`@` → `%40`) | ❌ |
| `+11234567890` | `%2B11234567890` (`+` → `%2B`) | ❌ |
| `1234 5678 9012 3456` | `1234+5678+9012+3456` | ❌ |

So this flow was only logged **because the location coordinates happened to remain unchanged** when encoded. Had the app only sent the name, email, phone, and card number — **the script would have reported zero findings** and you might have wrongly concluded PASS.

In this demo, the leakage of the four other values is still visible, but that's **coincidental**: `httpbin.org` returns data as JSON that is not URL-encoded, so the original values appear in the response body. On a real app there is no such echo endpoint — you would only have the request, and those four values would slip through.

**Practical conclusion:** do not use the demo script as-is for real-world testing. Use a version that normalizes the payload (§3.4).

---

#### ✅ PASS — The check is declared PASSED when:

| No | Condition | Example evidence |
|---|---|---|
| P1 | **No canary PII** is found in any of the captured traffic, after the app has been extensively exercised and the payloads normalized | `sensitive_data.log` is empty; a search of the entire flow dump is also clean |
| P2 | PII **is found**, but **every data type is accurately declared** in the Data safety section **and** the privacy policy — covering collected/shared, purpose, and transit encryption | The comparison table (§3.5) shows full alignment |
| P3 | PII is only sent to the **app's own backend**, and this aligns with the declaration (no undisclosed "shared" status) | Every destination host receiving PII is on the declared list |
| P4 | Collection only occurs **after explicit consent**, and **stops** when the user declines/disables it | Before consent: no PII in traffic. After toggling OFF: collection stops |
| P5 | Data sent has been **minimized/pseudonymized** as per the declaration | Location is sent as `city=Jakarta` (approximate) matching the "Approximate location" declaration, not precise coordinates |
| P6 | No PII appears in the **URL/query string or headers**; everything is in the request body over HTTPS | Correct practice |
| P7 | No **cleartext** traffic carries PII | Wireshark finds no PII on port 80 or in TLS-less protocols |

**Example output indicating PASS:**

```bash
$ mitmdump -s mitm_sensitive_logger_improved.py
# ... extensively exercise the app with canary values ...
^C
$ wc -l sensitive_data.log
0 sensitive_data.log

# Cross-check against the full flow dump (not only matched flows)
$ mitmdump -nr flows.mitm --set flow_detail=3 | \
    grep -iE "mastg.canary.7f3a|Mastg[ +]Canarytest|6281234567890|4111" 
# (no results)

# Cleartext verification
$ tshark -r capture.pcap -Y 'http' -T fields -e http.file_data | \
    grep -iE "mastg.canary|4111"
# (no results)
```

Or — PII is found, but fully declared:

| Data type found | Destination host | Declared (Data safety)? | Declared (Privacy policy)? | Verdict |
|---|---|---|---|---|
| Email address | `api.myapp.com` | ✅ Collected, not shared, encrypted | ✅ Mentioned, purpose: authentication | ✅ |
| Phone number | `api.myapp.com` | ✅ Collected, not shared, encrypted | ✅ Mentioned, purpose: 2FA verification | ✅ |
| Device or other IDs | `api.myapp.com` | ✅ Collected, not shared | ✅ Mentioned, purpose: anti-fraud | ✅ |
| Crash logs | `crashlytics.googleapis.com` | ✅ Collected, **shared** | ✅ Mentions Firebase Crashlytics | ✅ |

→ **PASS** for TEST-0206.

---

#### ⚠️ Important Notes on Assessment

1. **Without a reference document, this test CANNOT be completed.** This is a direct consequence of the `privacy-policy` and `app-store-privacy-declarations` prerequisites. Without them, all you can produce is a **data inventory** — a list of PII sent and to which hosts. That is useful, but report it as *inventory/informational*, not as a FAIL. Declaring FAIL without comparing against the declarations is a methodological error.

2. **Correct TLS does not save this test.** This bears repeating because it is the most commonly misunderstood point: MASTG-DEMO-0009 explicitly states that the traffic "can be considered secure" yet still FAILS. Do not close a finding with the reasoning "but it's already HTTPS."

3. **Certificate pinning that blocks interception ≠ PASS.** The status is **Inconclusive**. Note the pinning as a good MASVS-NETWORK control, then complete the privacy assessment via **MASTG-TEST-0319** (hooking the SDK API — viewing data before it enters the TLS layer) and **MASTG-TEST-0318** (static).

4. **Empty output ≠ automatic PASS.** The causes of false passes on this test are numerous and specific:
   - **Substring matching fails** due to encoding (see the finding in §3.3 — the official script misses 4 out of 6 values)
   - Payload is **compressed** (gzip/brotli), **encoded** (Base64), or **binary** (Protobuf/gRPC)
   - The app **encrypts the payload at the application layer** before TLS
   - PII is sent as a **hash** (`sha256(email)`) — won't match the canary, **but it is still data collection** and is often still re-identifiable
   - Protocols not captured by the proxy (**QUIC/HTTP3**, MQTT, custom TCP)
   - **Trigger flows were not exercised** — many analytics beacons are periodic or only fire under certain conditions
   - The app **detects the proxy** and alters its behavior
   
   **Mitigation:** always save **all flows** (not just matched ones) with `mitmdump -w flows.mitm`, then manually review the list of destination hosts and sample payloads. Combine with Wireshark to map protocols that don't pass through the proxy.

5. **Watch for PII in hashed or derived form.** `sha256("mastg.canary.7f3a@example.com")` won't match the plain canary, but sending a hashed email **is still data collection** that must be declared (a common practice in ad SDKs for *matching*). Add hashes of every canary to the search list — see §3.4.

6. **Pay attention to the destination host, not just the payload content.** Often the most important finding isn't "PII was sent," but "**PII was sent to an undisclosed third party**." Build a complete domain inventory and map each one to its SDK/vendor. Traffic to `graph.facebook.com`, `app-measurement.com`, `*.adjust.com`, `*.appsflyer.com`, or `*.branch.io` carrying PII almost always implies a "shared" category that must be declared.

7. **Check the timing against consent.** Data collection **before** the user has agreed to anything is a more serious violation than undeclared collection. Record the chronological order: which requests occur before the consent screen is shown?

8. **Also test the "opt-out" path.** Turn off every privacy/analytics toggle in the app, repeat the flows, and check whether collection actually stops. A declaration that states data is "optional" but is still collected when disabled is a FAIL.

9. **Severity is modulated by several factors:**

   | Factor | Severity |
   |---|---|
   | Special data category (health, biometric, religion, sexual orientation) without declaration | **Critical** — the most serious regulatory implications (GDPR Art. 9) |
   | Children's data / app targeting children | **Critical** — COPPA / Play Families policy |
   | PII sent to a third party without "shared" declaration | **High** — grounds for a Google Play policy strike |
   | Collection before consent | **High** |
   | Collection continuing after opt-out | **High** |
   | Financial data (card number, account) without declaration | **High** |
   | PII sent in cleartext (HTTP) | **Elevated** — also a MASVS-NETWORK finding |
   | PII in URL/query string | Elevated — logged on server/proxy logs |
   | Device/other IDs without declaration | Medium |
   | Data is declared but the purpose description is inaccurate/too vague | Low–Medium |
   | PII is sent **and** fully and accurately declared | **Not a finding** (for this test) |

10. **Document complete evidence per finding:** data type (use Google Play Data safety terminology for direct comparability), the canary value found (partially redacted), **the full URL/destination host**, HTTP method, location within the message (URL/header/body), timestamp relative to consent, **a quote from the relevant declaration (or a statement that no declaration exists)**, the privacy policy version and its access date, reproduction steps, and testing limitations (e.g., pinning not yet bypassed for a certain host, QUIC traffic not captured).

11. **Include a comparison table in the report.** This is the most useful deliverable of this test — see the format in §3.5. This table is what the legal/privacy team and the product team will use to fix the declarations.

### 3.4 Improved Script (Closing the Encoding Gap)

The following script addresses the limitations found in §3.3: normalizing URL-encoding, Base64, gzip, JSON escaping, case-insensitive matching, detecting hashed PII, pattern-based detection (not just exact canary matches), and a **full host inventory** — not just matched flows.

```python
# mitm_sensitive_logger_improved.py
import base64, gzip, hashlib, json, re, urllib.parse, zlib
from collections import defaultdict
from mitmproxy import http, ctx

# ---- 1. Canary values: determine from the privacy policy + Data safety section ----
SENSITIVE_DATA = {
    "name":              "Mastg Canarytest",
    "email_address":     "mastg.canary.7f3a@example.com",
    "phone_number":      "+6281234567890",
    "street_address":    "Jl. Canary Mastg No. 7F3A",
    "credit_card":       "4111 1111 1111 1111",
    "precise_lat":       "37.7749",
    "precise_lon":       "-122.4194",
    "date_of_birth":     "1990-07-03",
    "national_id":       "3201077F3A000001",
}

# ---- 2. Variants of each canary: plain, no spaces, hashed (ad SDKs often send hashes) ----
def variants(value: str):
    out = {value, value.lower(), value.replace(" ", ""), value.replace(" ", "").lower()}
    for v in list(out):
        out.add(hashlib.md5(v.encode()).hexdigest())
        out.add(hashlib.sha1(v.encode()).hexdigest())
        out.add(hashlib.sha256(v.encode()).hexdigest())
    return {v for v in out if len(v) >= 5}

NEEDLES = {}
for label, val in SENSITIVE_DATA.items():
    for v in variants(val):
        NEEDLES[v.lower()] = label

# ---- 3. Generic patterns: catch PII that is NOT a canary (e.g. real device IDs) ----
PATTERNS = {
    "email":            re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    "credit_card":      re.compile(r"\b(?:\d[ -]?){13,19}\b"),
    "coordinates":      re.compile(r"\b-?\d{1,3}\.\d{4,}\b"),
    "advertising_id":   re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"),
    "imei":             re.compile(r"\b\d{15}\b"),
    "android_id":       re.compile(r"\b[0-9a-f]{16}\b"),
    "jwt":              re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
}

# ---- 4. Normalize the payload so PII is readable ----
def normalize(raw: bytes | str) -> str:
    if raw is None:
        return ""
    data = raw.encode("utf-8", "ignore") if isinstance(raw, str) else raw
    layers = [data]

    # Decompression
    for fn in (gzip.decompress, zlib.decompress):
        try:
            layers.append(fn(data))
        except Exception:
            pass

    texts = []
    for b in layers:
        t = b.decode("utf-8", "ignore")
        texts.append(t)
        texts.append(urllib.parse.unquote_plus(t))          # URL-decode (%40 -> @, + -> space)
        texts.append(t.encode().decode("unicode_escape", "ignore"))  # JSON escape
        # Base64 embedded in the payload
        for m in re.findall(r"[A-Za-z0-9+/=]{16,}", t):
            try:
                texts.append(base64.b64decode(m + "==", validate=False).decode("utf-8", "ignore"))
            except Exception:
                pass
    return "\n".join(texts).lower()

def find_hits(text_norm: str):
    hits = set()
    for needle, label in NEEDLES.items():
        if needle in text_norm:
            hits.add(("canary", label))
    for label, rx in PATTERNS.items():
        if rx.search(text_norm):
            hits.add(("pattern", label))
    return hits

# ---- 5. Host inventory: ALWAYS logged, even when there is no hit ----
HOSTS = defaultdict(lambda: {"count": 0, "hits": set()})

def process(flow: http.HTTPFlow):
    if not flow.response:
        return
    host = flow.request.pretty_host
    parts = {
        "url":      flow.request.pretty_url,
        "req_hdr":  str(flow.request.headers),
        "req_body": flow.request.get_content(strict=False),
        "res_hdr":  str(flow.response.headers),
        "res_body": flow.response.get_content(strict=False),
    }
    all_hits = {}
    for where, raw in parts.items():
        h = find_hits(normalize(raw))
        if h:
            all_hits[where] = h

    HOSTS[host]["count"] += 1
    for h in all_hits.values():
        HOSTS[host]["hits"] |= h

    if all_hits:
        with open("sensitive_data.log", "a", encoding="utf-8") as f:
            f.write("=" * 78 + "\n")
            f.write(f"HOST   : {host}\n")
            f.write(f"URL    : {flow.request.pretty_url}\n")
            f.write(f"METHOD : {flow.request.method}\n")
            for where, h in all_hits.items():
                f.write(f"HITS@{where}: {sorted(h)}\n")
            f.write(f"REQ HEADERS:\n{parts['req_hdr']}\n")
            f.write(f"REQ BODY:\n{flow.request.get_text(strict=False)}\n")
            f.write(f"RES BODY:\n{(flow.response.get_text(strict=False) or '')[:4000]}\n\n")

def response(flow: http.HTTPFlow):
    process(flow)

def websocket_message(flow):
    # WebSocket is often missed — check it too
    for msg in flow.websocket.messages[-1:]:
        h = find_hits(normalize(msg.content))
        if h:
            with open("sensitive_data.log", "a", encoding="utf-8") as f:
                f.write(f"[WS] {flow.request.pretty_url} HITS: {sorted(h)}\n")
                f.write(f"{msg.content[:2000]}\n\n")

def done():
    # Full inventory: important for finding third-party hosts
    with open("host_inventory.log", "w", encoding="utf-8") as f:
        for host, info in sorted(HOSTS.items(), key=lambda x: -x[1]["count"]):
            flag = "  <== PII" if info["hits"] else ""
            f.write(f"{info['count']:5d}  {host}{flag}\n")
            if info["hits"]:
                f.write(f"        {sorted(info['hits'])}\n")
    ctx.log.info(f"[*] {len(HOSTS)} hosts recorded -> host_inventory.log")
```

Run with full flow persistence so you can re-analyze without repeating the session:

```bash
mitmdump -s mitm_sensitive_logger_improved.py -w flows.mitm

# Re-analyze offline (no device needed)
mitmdump -nr flows.mitm -s mitm_sensitive_logger_improved.py

# Host inventory — often where the most important finding is
cat host_inventory.log
```

**Supplementary checks:**

```bash
# 1. Cleartext traffic (no certificate needed) — direct evidence
tshark -i any -Y 'http.request or http.response' -T fields -e http.host -e http.file_data \
  | grep -iE "mastg.canary|4111|6281234567890"

# 2. Protocols that do NOT pass through the HTTP proxy (QUIC, MQTT, DNS-over-X)
tshark -r capture.pcap -Y 'quic or mqtt' -T fields -e ip.dst -e udp.dstport | sort -u

# 3. DNS resolution — mapping which third-party SDKs are contacted
tshark -r capture.pcap -Y 'dns.flags.response == 0' -T fields -e dns.qry.name | sort -u

# 4. Check whether the app performs pinning (before you start)
grep -rn "pin-set\|certificatePinner\|CertificatePinner\|checkServerTrusted" ./decompiled/sources/
grep -n "pin-set" ./out/res/xml/network_security_config.xml
```

### 3.5 Comparison Table Format (Main Deliverable)

This is the output that makes this test valuable. Build this for every data type found:

| # | Data type (Play terminology) | Value found | Destination host | Location | Before consent? | Data safety: collected | Data safety: shared | Privacy policy | **Verdict** |
|---|---|---|---|---|---|---|---|---|---|
| 1 | Precise location | `37.7749 / -122.4194` | `api.myapp.com` | req body | No | ❌ not declared | ❌ | ❌ not mentioned | **FAIL (F1)** |
| 2 | Email address | `mastg.canary…@example.com` | `api.myapp.com` | req body | No | ✅ | ❌ not shared | ✅ | PASS |
| 3 | Email address (SHA-256) | `a3f1…` | `graph.facebook.com` | req body | No | ✅ collected | ❌ **not shared** | ❌ Meta not mentioned | **FAIL (F2/F3)** |
| 4 | Device or other IDs | `AdID 8f2c-…` | `app-measurement.com` | query | **Yes** | ❌ | ❌ | ❌ | **FAIL (F5/F7)** |
| 5 | Payment info | `4111 1111 1111 1111` | `api.myapp.com` | req body | No | ✅ | ❌ | ✅ | PASS |

Also attach a complete **host inventory** (from `host_inventory.log`), mapped to its SDK/vendor:

| Host | Request count | SDK/Vendor | Contains PII? | Mentioned in privacy policy? |
|---|---|---|---|---|
| `api.myapp.com` | 142 | Own backend | Yes | ✅ |
| `app-measurement.com` | 38 | Firebase/Google Analytics | Yes | ❌ |
| `graph.facebook.com` | 11 | Meta SDK | Yes (hash) | ❌ |
| `crashlytics.googleapis.com` | 6 | Firebase Crashlytics | Crash log | ✅ |

---

### 3.6 Alternative Testing Methods (Multi-Tool)

MASTG uses mitmproxy, but any intercepting proxy can be used — and some challenges (pinning, non-HTTP protocols) call for different tools. Below are the alternative paths.

#### Method B — Burp Suite *(interception + semi-automatic PII detection)*

Burp excels at manual exploration and has an extension ecosystem for automated PII detection.

```
1. Proxy > Options > add a listener on 0.0.0.0:8080 (all interfaces)
2. Route the device proxy:  adb shell settings put global http_proxy <host-IP>:8080
3. Install the Burp CA as a system CA (see §2.3 for API 24+)
4. Exercise the app with canary values
5. Proxy > HTTP history  ->  filter & search for PII
```

**Automated PII detection with Bambda** (Burp 2023.10+, *Proxy > HTTP history > Bambda* tab):

```java
// Highlight requests/responses that contain canary values or PII patterns
var body = requestResponse.request().bodyToString()
         + requestResponse.response().bodyToString();
var url  = requestResponse.request().url();
var patterns = java.util.List.of(
    "MASTG_CANARY_PWD_7f3a", "mastg.canary.7f3a@example.com", "6281234567890",
    "4111111111111111", "37.7749");
return patterns.stream().anyMatch(p -> body.contains(p) || url.contains(p));
```

Helpful extensions (BApp Store): **Reflected Parameters**, **Piper** (external tool integration), **Logger++** (advanced filtering & export with PII regex). For automatic decoding of encoded payloads, combine with the **Hackvertor** extension.

#### Method C — OWASP ZAP *(open-source, passive scripting)*

```bash
# Run ZAP in daemon mode with a proxy
zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.disablekey=true
```

Passive scan script (ZAP > Scripts > Passive Rules) to flag PII:

```javascript
// pii-detector.js — ZAP passive script
function scan(ps, msg, src) {
    var body = msg.getRequestBody().toString() + msg.getResponseBody().toString();
    var needles = ["MASTG_CANARY_PWD_7f3a", "mastg.canary.7f3a@example.com", "4111111111111111"];
    needles.forEach(function(n) {
        if (body.indexOf(n) !== -1) {
            ps.raiseAlert(3, 1, "PII in traffic", "Found: " + n,
                msg.getRequestHeader().getURI().toString(),
                "", "", "", "", "", 0, 0, msg);
        }
    });
}
```

ZAP's advantages: free, can be fully automated via API/CLI for CI, and supports HAR export for further analysis.

#### Method D — HTTP Toolkit *(fastest setup, especially for emulators)*

```bash
# HTTP Toolkit has a one-click ADB integration that handles proxy + CA automatically
# For emulators/rooted devices: system certificate injection is done automatically
```

Flow: open HTTP Toolkit → **Android device via ADB** → select the device → the app is immediately intercepted. Advantage: eliminates the entire manual CA setup complexity (§2.3 Obstacle 1) for supported devices, and has a good search/filter UI plus built-in rewrite rules. Saves significant time during what is usually the longest setup phase.

#### Method E — Frida for bypassing pinning + capture *(when the proxy is blocked)*

If certificate pinning is blocking you (Obstacle 2 in §2.3), this is the most reliable path.

```bash
# 1. Universal pinning bypass (handles OkHttp, TrustManager, Conscrypt, etc.)
frida -U -f com.example.target \
  -l https://codeshare.frida.re/@pcipolloni/universal-android-ssl-pinning-bypass-with-frida/

# or via objection (one command):
objection -g com.example.target explore
android sslpinning disable

# 2. Once pinning is disabled, traffic flows to the proxy (Burp/mitmproxy/ZAP) as usual
```

Alternative: **hook directly at the encryption/decryption point**, so you see the plaintext **before** TLS — this bypasses pinning **and** application-layer encryption at once:

```javascript
// View data before it enters SSL/TLS
Java.perform(() => {
    const SSLOut = Java.use("com.android.org.conscrypt.ConscryptFileDescriptorSocket$SSLOutputStream");
    // or hook OkHttp Interceptor, HttpURLConnection.getOutputStream, etc.
});
```

This connects directly to **MASTG-TEST-0319** (hooking the SDK API), which sees data even before it reaches the network layer.

#### Method F — PolarProxy / mitmproxy transparent mode *(non-HTTP, TLS-based protocols)*

For MQTT, gRPC, XMPP, or custom TCP protocols that do not go through an HTTP proxy.

```bash
# PolarProxy — TLS interception that saves decrypted traffic to PCAP
PolarProxy -p 10443,80,443 -x ./ca.cer -f ./decrypted.pcap
#   -> open decrypted.pcap in Wireshark to inspect any protocol

# mitmproxy transparent mode (captures more than HTTP)
mitmdump --mode transparent --showhost -s pii_logger.py
```

#### Method G — tcpdump + Wireshark *(cleartext + protocol mapping, no proxy)*

This method **requires no CA at all** and captures **everything**, including traffic that avoids the proxy.

```bash
# Capture on-device (requires root) or via emulator
adb shell "su -c 'tcpdump -i any -s0 -w /sdcard/capture.pcap'"
adb pull /sdcard/capture.pcap

# --- Analysis with tshark ---
# 1. Cleartext traffic carrying PII (direct evidence, no decryption needed)
tshark -r capture.pcap -Y 'http.request or http.response' \
  -T fields -e http.host -e http.file_data | grep -iE "MASTG_CANARY|4111|6281234567890"

# 2. Map ALL destination hosts (including those using non-HTTP protocols)
tshark -r capture.pcap -Y 'dns.flags.response==0' -T fields -e dns.qry.name | sort -u

# 3. Detect QUIC/HTTP3 that escapes the proxy
tshark -r capture.pcap -Y 'quic' -T fields -e ip.dst -e udp.dstport | sort -u

# 4. To decrypt TLS: set SSLKEYLOGFILE then load it into Wireshark
#    (Edit > Preferences > TLS > (Pre)-Master-Secret log filename)
```

Advantage: `tcpdump` captures traffic the app sends via a channel that **deliberately avoids the proxy** (e.g., hardcoded proxy bypass, or a non-HTTP protocol) — something that wouldn't be visible in Burp/mitmproxy.

#### Method H — MobSF Dynamic Analyzer *(automated + captured traffic)*

```bash
docker run -it --rm -p 8000:8000 -p 1337:1337 \
  opensecurity/mobile-security-framework-mobsf:latest
```

MobSF runs the app with a proxy + CA automatically installed, then provides an **HTTP(S) Traffic** section that can be searched. It also flags known third-party domains and trackers. Advantage: a quick first pass that also produces a list of destination hosts. Limitation: shallow exercising, cannot log in — a complement, not a replacement, for manual exercising.

#### Method I — Static SDK Analysis: MASTG-TEST-0318 *(finding the code location)*

Network capture does not give a code location. For that, run its static counterpart.

```bash
jadx -d ./decompiled ./target-app.apk
D=./decompiled/sources

# SDK APIs known to handle sensitive data
rg -n --no-heading "FirebaseAnalytics|logEvent|setUserId|setUserProperty" $D
rg -n --no-heading "AppsFlyerLib|Adjust\.|Branch\.|Amplitude|mixpanel|Segment" $D
rg -n --no-heading "getSystemService.*LOCATION|getLastKnownLocation|requestLocationUpdates" $D
rg -n --no-heading "getDeviceId|getImei|ANDROID_ID|AdvertisingIdClient" $D

# Semgrep registry for trackers
semgrep --config "p/trailofbits" ./decompiled/sources/
```

#### Method J — Exodus Privacy / trackers analysis *(tracker SDK inventory)*

```bash
# Exodus — detects known trackers from the APK
# Via https://reports.exodus-privacy.eu.org/ (upload the APK) or CLI:
pip install exodus-core
exodus-core analyze ./target-app.apk

# ClassyShark / classyshark3xodus for a library inventory
```

Useful for **knowing which tracker SDKs are present** before capturing traffic — it gives you the list of hosts to watch for in §3.5 (host inventory).

---

### 3.7 Method Comparison: Which to Use When

| Method | Tool | Needs CA/root? | Bypasses pinning? | Non-HTTP protocols? | Gives code location? | When to use |
|---|---|---|---|---|---|---|
| **A** | mitmproxy (MASTG) | CA + (root for API24+) | ❌ (needs separate bypass) | Partial | ❌ | **Official baseline** — scriptable |
| **B** | Burp Suite | CA + root | ❌ | ❌ | ❌ | Manual exploration + Bambda/PII extensions |
| **C** | OWASP ZAP | CA + root | ❌ | ❌ | ❌ | Open-source; CI automation via API |
| **D** | HTTP Toolkit | Automatic (supported) | ❌ | ❌ | ❌ | **Fastest setup** — avoids CA complexity |
| **E** | Frida (bypass pinning) | — | ✅ **(key)** | — | Partial (backtrace) | **When pinning blocks you** |
| **F** | PolarProxy / mitm transparent | CA + root | ❌ | ✅ **(key)** | ❌ | MQTT/gRPC/custom TCP |
| **G** | tcpdump + Wireshark | root (not CA) | — (sees cleartext) | ✅ **(all)** | ❌ | **Cleartext + traffic avoiding the proxy**; QUIC |
| **H** | MobSF Dynamic | Automatic | ❌ | Partial | ❌ | Quick first pass + host inventory |
| **I** | Static analysis (TEST-0318) | No | — | — | ✅ **(key)** | Finding the CODE LOCATION of data collection |
| **J** | Exodus / trackers | No | — | — | ❌ | **Tracker SDK inventory** before capture |

**Minimum recommended combination:** **J (Exodus) → A/B/D (your proxy of choice) → E (if pinning) → I (static)**.
J maps out the tracker SDKs to watch for; any proxy (A/B/D — pick whichever is most comfortable) captures the traffic; E unlocks pinning when it blocks you; I locates the code for remediation. Always add **G (tcpdump)** for high-privacy apps — it catches paths that deliberately avoid the proxy and the cleartext traffic that is actually the most dangerous.

> **Remember the nature of this test (§1.2):** all the methods above only produce an **inventory of outgoing data**. The PASS/FAIL decision still requires comparison against the privacy policy + Data safety declaration — no tool can substitute for that step.

---

## 4. Recommendations

Because this is a privacy test, remediation has **two equally valid paths**: reduce data collection, **or** fix the declaration. Both are legitimate — but the first is almost always better.

### 4.1 Core Principles (in priority order)

**Priority 1 — Data minimization: don't send what isn't needed.** This is the strongest fix because it eliminates the risk rather than merely disclosing it. For every data type in the inventory, ask: *can this feature really not work without it?*

- Remove PII fields sent "temporarily" or left over from an old version.
- Replace **precise location** with **approximate location** when the feature only needs the city/region.
- Send **derived** data instead of raw data: age range instead of date of birth, age group instead of national ID, `city` instead of coordinates.
- **Aggregate on-device** before sending — send statistics, not per-user events.
- Remove PII from **crash logs** and diagnostic payloads.

**Priority 2 — Never put PII in the URL, query string, or headers.**

```kotlin
// ❌ WRONG — logged in server logs, proxy logs, browser history, referrer
val url = URL("https://api.myapp.com/user?email=$email&phone=$phone")

// ✅ CORRECT — in the request body, over HTTPS
val body = JSONObject().apply { put("email", email) }.toString()
// POST with Content-Type: application/json
```

**Priority 3 — Audit and control third-party SDKs.** In practice, **this is the single largest source of findings** on this test — and it is often beyond the developer's own awareness.

- Build an SDK inventory along with the data each one sends (use `host_inventory.log` as a starting point).
- Disable unneeded automatic collection:

```xml
<!-- AndroidManifest.xml — turn off automatic Firebase Analytics collection -->
<meta-data android:name="firebase_analytics_collection_enabled" android:value="false" />
<meta-data android:name="google_analytics_default_allow_ad_personalization_signals"
           android:value="false" />
<meta-data android:name="firebase_crashlytics_collection_enabled" android:value="false" />
```

```kotlin
// Enable only after consent
FirebaseAnalytics.getInstance(context).setAnalyticsCollectionEnabled(consentGiven)
FirebaseCrashlytics.getInstance().isCrashlyticsCollectionEnabled = consentGiven
```

- **Never send PII as an event/user property parameter.** This violates Google Analytics policy while also creating a privacy finding:

```kotlin
// ❌ WRONG — PII sent to analytics (this is what MASTG-TEST-0319 detects)
analytics.setUserProperty("email", userEmail)
analytics.logEvent("profile_saved", bundleOf("blood_type" to bloodType))

// ✅ CORRECT — pseudonymous identifier, no PII, no special-category data
analytics.setUserId(pseudonymousId)      // internal random ID, not email/phone
analytics.logEvent("profile_saved", bundleOf("has_health_data" to true))
```

- Use the **Advertising ID** in line with policy, and respect *Limit Ad Tracking*/`isLimitAdTrackingEnabled`.
- If the SDK cannot be controlled, consider replacing it or proxying its data through your own backend so you control what goes out.

**Priority 4 — Implement proper consent (and respect it).**

- **Do not collect anything before consent** — including at *first launch*. Initialize analytics/ads SDKs **after** the user has decided.
- Consent must be **granular** (per purpose), **specific**, and **easily revocable**.
- When the user withdraws consent or disables a toggle, **collection must actually stop** — re-verify with this test.
- For the EU market, consider Google **Consent Mode** and TCF compliance when using ad SDKs.
- Keep a record of consent (time, policy version, choice) for audit purposes.

**Priority 5 — Align the declaration with actual behavior.** This is the second remediation path: if the data collection is genuinely needed and legitimate, **declare it accurately**.

- Update the **Google Play Data safety section**: for every data type, correctly fill in *collected*, *shared*, *processed ephemerally*, *required or optional*, *encrypted in transit*, and its **purpose**.
- Update the **privacy policy**: state the data types, purpose, **named third-party recipients**, legal basis, retention period, cross-border transfers, and data subject rights.
- Ensure both are **consistent with each other** — studies show mismatches between the privacy policy and the Data safety declaration occur in ~53% of games and ~61% of generic apps, and this itself is a finding.
- Do not use vague language ("we may collect certain information"). MASWE-0073 lists *"Vague or unclear language about data collection scope"* as one of this weakness's introduction modes.
- **Update it every time behavior changes** — including when an SDK is updated. Adding a new SDK almost always changes the data collection profile.

**Priority 6 — Strengthen technical protections (complementary, not a substitute for declaration).**

- TLS 1.2+ for all connections; `cleartextTrafficPermitted="false"`.
- Certificate pinning for endpoints that handle PII.
- Application-layer payload encryption for the most sensitive data (health, financial) as a defense-in-depth measure.
- Pseudonymize/tokenize PII before sending it to third parties where possible.
- Never log PII that originated from a URL on the server (a consequence of Priority 2).

> It should be emphasized: these steps **do not make this test PASS**. This test assesses transparency, not protection — perfectly protected data that is undeclared still FAILS.

**Priority 7 — Enforce this continuously.**

- Make this test part of a **regression suite**: run mitmproxy + the PII script on an emulator in a pipeline alongside UI tests, and fail the build when a **new destination host** or **new PII** outside the allowlist appears. This prevents regressions when SDKs are updated — the most common cause of declarations becoming outdated.
- Maintain a **data inventory (data map)** as a living artifact: data type → purpose → recipient → legal basis → retention.
- Conduct a **privacy review** every time a new SDK or feature is added.
- Supplement with **MASTG-TEST-0318** in CI (static, fast, no device required) to detect the addition of SDK APIs that handle sensitive data.

### 4.2 Remediation Checklist

- [ ] A complete inventory of data types sent + destination hosts has been built and reviewed
- [ ] Every data type is mapped to Google Play Data safety section terminology
- [ ] Every destination host is mapped to an SDK/vendor and its necessity verified
- [ ] The comparison table (traffic vs Data safety vs privacy policy) is complete with no gaps
- [ ] Data not needed by the feature has been **removed** from the payload (minimization)
- [ ] Precise location is replaced with approximate location where the feature doesn't require precision
- [ ] PII is sent as a derivative/aggregate where possible (age range, city)
- [ ] No PII appears in the URL, query string, or headers
- [ ] No PII (including special-category data) is sent to analytics/ads SDKs as an event parameter or user property
- [ ] `setUserId` uses a pseudonymous identifier, not email/phone/national ID
- [ ] Automatic SDK collection is disabled by default (`firebase_analytics_collection_enabled=false`, etc.)
- [ ] **No data is collected before consent whatsoever** — re-verified with this test
- [ ] Consent is granular per purpose, and **withdrawing consent actually stops collection** (verified)
- [ ] Limit Ad Tracking / Advertising ID reset is respected
- [ ] PII is removed from crash logs and diagnostic payloads
- [ ] The Google Play **Data safety section** is updated: collected/shared/purpose/transit encryption/required-optional accurate for every data type
- [ ] The **privacy policy** is updated: data types, purpose, **named third-party recipients**, legal basis, retention, cross-border transfer, data subject rights
- [ ] The privacy policy and Data safety section are **consistent with each other**
- [ ] Declaration language is specific, not vague
- [ ] Special data categories (health, biometric, religion, sexual orientation, children's data) have an adequate legal basis & additional protections
- [ ] TLS 1.2+ for all connections; `cleartextTrafficPermitted="false"`; pinning for PII-handling endpoints
- [ ] A mandatory privacy review process exists for every SDK/feature addition
- [ ] The data inventory (data map) is maintained as a living artifact
- [ ] This test is integrated into CI/CD with a host & data type allowlist
- [ ] **Re-verify:** re-run MASTG-TEST-0206 → no undeclared PII, no new hosts
- [ ] **Cross-verify:** run MASTG-TEST-0318 (static) and MASTG-TEST-0319 (hooks) to find code locations and close blind spots (pinning / application-layer encryption)

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0206: Undeclared PII in Network Traffic Capture](https://mas.owasp.org/MASTG/tests/android/MASVS-PRIVACY/MASTG-TEST-0206/)
- [MASTG-TEST-0318: References to SDK APIs Known to Handle Sensitive User Data](https://mas.owasp.org/MASTG/tests/android/MASVS-PRIVACY/MASTG-TEST-0318/)
- [MASTG-TEST-0319: Runtime Use of SDK APIs Known to Handle Sensitive User Data](https://mas.owasp.org/MASTG/tests/android/MASVS-PRIVACY/MASTG-TEST-0319/)
- [MASWE-0073: Inadequate Data Collection Declarations](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0073/)
- [MASTG-DEMO-0009: Detecting Undeclared PII in Network Traffic](https://mas.owasp.org/MASTG/demos/android/MASVS-PRIVACY/MASTG-DEMO-0009/MASTG-DEMO-0009/)
- [MASTG-DEMO-0081: Sensitive User Data Sent to Firebase Analytics with Frida](https://mas.owasp.org/MASTG/demos/android/MASVS-PRIVACY/MASTG-DEMO-0081/MASTG-DEMO-0081/)
- [MASTG-TECH-0100: Logging Sensitive Data from Network Traffic](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0100/)
- [MASTG-TECH-0005: Installing Apps](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0005/)
- [MASTG-TECH-0014: Static Analysis on Android](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/)
- [MASTG-TECH-0043: Method Hooking](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0043/)
- [MASTG-TOOL-0097: mitmproxy](https://mas.owasp.org/MASTG/tools/network/MASTG-TOOL-0097/)
- [MASTG-TOOL-0077: Burp Suite](https://mas.owasp.org/MASTG/tools/network/MASTG-TOOL-0077/)
- [MASTG-TOOL-0079: ZAP (Zed Attack Proxy)](https://mas.owasp.org/MASTG/tools/network/MASTG-TOOL-0079/)
- [MASTG-TOOL-0081: Wireshark](https://mas.owasp.org/MASTG/tools/network/MASTG-TOOL-0081/)
- [MASTG-TOOL-0001: Frida](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0001/)
- [MASTG-TOOL-0038: Objection](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0038/)
- [MASVS-PRIVACY: Privacy](https://mas.owasp.org/MASVS/07-MASVS-PRIVACY/)
- [OWASP MASTG — Identifying Sensitive Data](https://mas.owasp.org/MASTG/0x04b-Mobile-App-Security-Testing/#identifying-sensitive-data)
- [OWASP MASTG Repository (GitHub)](https://github.com/OWASP/mastg)
- [OWASP Mobile Top 10 2024 — M6: Inadequate Privacy Controls](https://owasp.org/www-project-mobile-top-10/2023-risks/m6-inadequate-privacy-controls.html)
- [OWASP Mobile Top 10 2024 — M5: Insecure Communication](https://owasp.org/www-project-mobile-top-10/2023-risks/m5-insecure-communication.html)

### 5.2 Platform Policies & Privacy Declarations

- [Provide information for Google Play's Data safety section — Play Console Help](https://support.google.com/googleplay/android-developer/answer/10787469?hl=en)
- [Google Play Data safety — list of data types](https://support.google.com/googleplay/android-developer/answer/10787469?hl=en#types)
- [Google Play — User Data policy](https://support.google.com/googleplay/android-developer/answer/10144311)
- [Google Play — Permissions and APIs that Access Sensitive Information](https://support.google.com/googleplay/android-developer/answer/9888170)
- [Google Play — Families policy requirements](https://support.google.com/googleplay/android-developer/answer/9893335)
- [Google Play — Advertising ID policy](https://support.google.com/googleplay/android-developer/answer/6048248)
- [Google — Consent Mode (EU user consent policy)](https://support.google.com/analytics/answer/9976101)
- [Apple — App Privacy Details (as a cross-platform comparison)](https://developer.apple.com/app-store/app-privacy-details/)

### 5.3 Official Android / Google Documentation

- [Android — Privacy best practices](https://developer.android.com/privacy-and-security/best-practices)
- [Android — Data and privacy](https://developer.android.com/privacy)
- [Android — Best practices for unique identifiers](https://developer.android.com/training/articles/user-data-ids)
- [Android — Network security configuration](https://developer.android.com/privacy-and-security/security-config)
- [Android — Security with HTTPS and SSL](https://developer.android.com/privacy-and-security/security-ssl)
- [Android — Advertising ID](https://developer.android.com/training/articles/ad-id)
- [Android — App permissions best practices](https://developer.android.com/training/permissions/usage-notes)
- [Android — Data access auditing](https://developer.android.com/guide/topics/data/audit-access)
- [Android 12+ — Privacy Dashboard](https://developer.android.com/about/versions/12/behavior-changes-12#privacy-dashboard)
- [Firebase Analytics — `setUserId`, `setUserProperty`, `logEvent`](https://firebase.google.com/docs/reference/android/com/google/firebase/analytics/FirebaseAnalytics)
- [Firebase — Configure Analytics data collection and usage](https://firebase.google.com/docs/analytics/configure-data-collection)
- [Firebase Crashlytics — Enable/disable collection](https://firebase.google.com/docs/crashlytics/customize-crash-reports)

### 5.4 Regulations & Standards

- [GDPR Art. 5 — Principles relating to processing of personal data](https://gdpr-info.eu/art-5-gdpr/)
- [GDPR Art. 9 — Processing of special categories of personal data](https://gdpr-info.eu/art-9-gdpr/)
- [GDPR Art. 13 — Information to be provided where personal data are collected](https://gdpr-info.eu/art-13-gdpr/)
- [CCPA §1798.100 — General duties of businesses that collect personal information](https://leginfo.legislature.ca.gov/faces/codes_displaySection.xhtml?sectionNum=1798.100&lawCode=CIV)
- [Law No. 27 of 2022 on Personal Data Protection (UU PDP) — JDIH](https://peraturan.bpk.go.id/Details/229798/uu-no-27-tahun-2022)
- [CWE-359: Exposure of Private Personal Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/359.html)
- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
- [CWE-201: Insertion of Sensitive Information Into Sent Data](https://cwe.mitre.org/data/definitions/201.html)
- [CWE-497: Exposure of Sensitive System Information to an Unauthorized Control Sphere](https://cwe.mitre.org/data/definitions/497.html)
- [NIST Privacy Framework](https://www.nist.gov/privacy-framework)
- [NIST SP 800-122 — Guide to Protecting the Confidentiality of PII](https://csrc.nist.gov/publications/detail/sp/800-122/final)
- [ISO/IEC 27701 — Privacy Information Management](https://www.iso.org/standard/71670.html)
- [OWASP Privacy Risks (Top 10)](https://owasp.org/www-project-top-10-privacy-risks/)

### 5.5 Security Research & Technical Articles

- [Zenodo — Study on privacy policy vs. data safety declaration mismatches](https://zenodo.org/records/7088557)
- [AuditBuffet — Google Data Safety form accuracy (pattern catalog)](https://auditbuffet.com/patterns/ab-000465)
- [NasrTech — Google Play Data Safety Section Explained](https://www.nasrtech.dev/blog/google-play-data-safety-explained/)
- [Respectlytics — Google Play Data Safety Section: Step-by-Step Guide](https://respectlytics.com/blog/google-play-data-safety-guide/)
- [Approov — Bypassing Certificate Pinning: Techniques and MitM Attack Prevention](https://approov.io/blog/bypassing-certificate-pinning)
- [Approov — Certificate Pinning Bypassing: Setup with Frida, mitmproxy and Android Emulator (gist)](https://gist.github.com/approovm/e550374428065ff1ecafca6a0488d384)
- [Oguzhan Oztaskin — SSL Pinning Bypass: Network Security Config](https://oguzhanstech.com/2025/08/25/ssl-pinning-bypass-network-security-config.html)
- [v0x.nl — Bypassing SSL certificate pinning on Android for MITM attacks](https://v0x.nl/articles/bypass-ssl-pinning-android/)
- [UPM SSE — Bypassing certificate pinning in Android applications](https://blogs.upm.es/sse/2020/08/03/bypassing-certificate-pinning-in-android-applications)
- [arXiv — Dissecting contact tracing apps in the Android platform](https://arxiv.org/pdf/2008.00214)
- [HackTricks — Android Applications Pentesting](https://book.hacktricks.wiki/en/mobile-pentesting/android-app-pentesting/index.html)

### 5.6 Tool Documentation

- [mitmproxy — Documentation](https://docs.mitmproxy.org/stable/)
- [mitmproxy — Addons & scripting API](https://docs.mitmproxy.org/stable/addons-overview/)
- [mitmproxy — Android setup (certificate installation)](https://docs.mitmproxy.org/stable/howto-install-system-trusted-ca-android/)
- [Burp Suite — Mobile testing (Android) documentation](https://portswigger.net/burp/documentation/desktop/mobile/config-android-device)
- [ZAP — Documentation](https://www.zaproxy.org/docs/)
- [Wireshark — User's Guide](https://www.wireshark.org/docs/wsug_html_chunked/)
- [tshark — man page](https://www.wireshark.org/docs/man-pages/tshark.html)
- [Frida — Documentation Home](https://frida.re/docs/home/)
- [Objection — runtime mobile exploration](https://github.com/sensepost/objection)
- [Frida CodeShare — Universal Android SSL Pinning Bypass](https://codeshare.frida.re/@pcipolloni/universal-android-ssl-pinning-bypass-with-frida/)
- [apktool — Reverse engineering Android APK files](https://apktool.org/)
- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)

---

*This document was compiled based on OWASP MASTG (latest release as of September 2026), Google Play policy, official Android and mitmproxy documentation, GDPR/CCPA/UU PDP regulations, and third-party security and privacy research.*
