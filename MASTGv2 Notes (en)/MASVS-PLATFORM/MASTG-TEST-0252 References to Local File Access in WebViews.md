# MASTG-TEST-0252 References to Local File Access in WebViews

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0252 |
| **Platform** | Android |
| **MASVS Category** | MASVS-PLATFORM (MASVS-PLATFORM-2) |
| **Weakness** | MASWE-0034 — *WebViews Allow Access to Local Resources with Untrusted Content* |
| **Highlighted API** | `WebView`, `WebSettings`, `getSettings`, `setAllowFileAccess`, `setAllowFileAccessFromFileURLs`, `setAllowUniversalAccessFromFileURLs` |
| **Test Type** | Static, Code |
| **Profile** | L1, L2 |
| **Knowledge** | MASTG-KNOW-0018 (WebViews) |
| **Best Practice** | MASTG-BEST-0010 (Use Up-to-Date minSdkVersion), MASTG-BEST-0011 (Securely Load File Content in WebView), MASTG-BEST-0012 (Disable JavaScript in WebViews) |
| **Related Techniques** | MASTG-TECH-0013, MASTG-TECH-0014, MASTG-TECH-0117, MASTG-TECH-0150 |
| **Related Test** | **MASTG-TEST-0250** (sibling — content provider access, not local file access; shares the `setAllowUniversalAccessFromFileURLs` API) |
| **Related Demo** | — (none) |
| **Official Rule** | `mastg-android-webview-allow-local-access.yml` — the same rule used by MASTG-TEST-0250, covering all six APIs at once (see the MASTG-TEST-0250 document §3.2 for a full analysis of this rule's gaps) |
| **Related CWE** | CWE-200, CWE-668 |

---

## 1. Explanation

### 1.1 Testing Objective and the Difference from MASTG-TEST-0250

This test is the **conceptual sibling** of MASTG-TEST-0250 — both target dangerous combinations of `WebSettings` and share the `setAllowUniversalAccessFromFileURLs` API, but **the exposed object differs**:

| | MASTG-TEST-0250 | MASTG-TEST-0252 *(this document)* |
|---|---|---|
| **Exposed object** | **Content provider** (`content://` scheme) | **Local file system** (`file://` scheme) — internal storage, external storage |
| **Key distinguishing API** | `setAllowContentAccess` | `setAllowFileAccess`, `setAllowFileAccessFromFileURLs` |
| **`minSdkVersion` dependency** | None — `setAllowContentAccess` always defaults to `true` on every version | **Heavily dependent** — the default changes based on API level (see §1.2) |

### 1.2 Crucial Difference: Defaults Dependent on `minSdkVersion` (Unlike MASTG-TEST-0250)

Unlike `setAllowContentAccess` discussed in the MASTG-TEST-0250 document (always defaulting to `true` without exception), the three APIs in this test have defaults that **change as the Android platform evolves**, per the official table in MASTG-KNOW-0018:

| API | Default `True` | Default `False` |
|---|---|---|
| `setAllowFileAccess` | ≤ API 29 (Android 10 and below) | ≥ API 30 (Android 11+) |
| `setAllowFileAccessFromFileURLs` | ≤ API 15 (Android 4.0.3 and below) | ≥ API 16 (Android 4.1+) |
| `setAllowUniversalAccessFromFileURLs` | ≤ API 15 | ≥ API 16 |

All three are also **deprecated as of Android 10/11**, but the official overview emphasizes why this remains relevant to test:

> *"Even though these methods have secure defaults and are deprecated in Android 10 (API level 29) and later, they can still be explicitly set to `true` or their insecure defaults may be used in apps that run on older versions of Android (due to their `minSdkVersion`)."*

This is a direct consequence of the **`minSdkVersion` vs. the device's actual OS** nuance already discussed in depth in the **MASTG-TEST-0245** document — an application with a modern `targetSdkVersion` can still run on an older Android device (below API 30/16) if its `minSdkVersion` is set low, and on that device, the insecure default value of these APIs **still applies** regardless of the declared `targetSdkVersion`. This is why **MASTG-TECH-0150 is explicitly used to extract `minSdkVersion`** as a mandatory official step (§3.1, step 4) — evaluating the FAIL condition of this test **cannot be done without first knowing this value**.

### 1.3 Why "Absence of a Reference" Is Actually Interesting — The Opposite of Common Intuition

This is the most important and unique methodological point of this test compared to most other static tests in this research series. The official observation states explicitly:

> *"Note that in this case, **the lack of references to the `setAllow*` methods is especially interesting** and must be captured, because it could mean that the app is using the default values, which in some scenarios are insecure."*

In most other tests in this series, "no API call found" is usually interpreted as an indication that **there is no issue** (no risky feature is in use). But for this test, the absence of a reference **can actually be a FAIL condition** — because, combined with a low `minSdkVersion` (§1.2), the WebView will **silently inherit an insecure default** without any code trace that can be directly "pointed to" as the cause. This is why MASTG explicitly recommends: *"it's highly recommended to try to identify **every** WebView instance in the app"* — a passive approach of "look for suspicious API calls" is not enough; the tester must **inventory every WebView instance** first, and only then check (for each instance) whether the related settings are explicitly called OR left at their default.

### 1.4 Three FAIL Conditions Dependent on `minSdkVersion` (More Complex Than MASTG-TEST-0250)

This test's official Evaluation clause is structurally more complex than MASTG-TEST-0250's because each condition has a **conditional branch** based on `minSdkVersion`:

> *"The test case fails if all of the following applies: `setJavaScriptEnabled` is explicitly set to `true`. `setAllowFileAccess` is explicitly set to `true` (**or not used at all when `minSdkVersion` < 30**, inheriting the default value, `true`). Either `setAllowFileAccessFromFileURLs` or `setAllowUniversalAccessFromFileURLs` is explicitly set to `true` (**or not used at all when `minSdkVersion` < 16**, inheriting the default value, `true`)."*

This means **identical code-level findings** (e.g., no call to `setAllowFileAccess` at all) can lead to **different PASS or FAIL conclusions**, purely depending on the app's `minSdkVersion` value:

| `minSdkVersion` | `setAllowFileAccess` not called at all → |
|---|---|
| < 30 (below Android 11) | Default `true` applies → **contributes to a FAIL condition** |
| ≥ 30 (Android 11+) | Default `false` applies → **this condition is satisfied for a PASS** |

### 1.5 The Third (and Most Important) Nuance: Data Leakage Can Occur Even If Reading Is Blocked by CORS ("Blind Exfiltration")

This is the most technical and most commonly misunderstood part. The official overview gives an explicit warning about `setAllowUniversalAccessFromFileURLs`:

> *"The JavaScript **can always send data to any origin** (e.g., via `POST`), regardless of this setting; this setting only affects **reading** data (e.g., the code wouldn't get a response to a `POST` request, but the data would still be sent)."*

This is a critical nuance: the same-origin policy (which this setting relaxes) fundamentally restricts JavaScript's ability to **read the response** from another origin — but it **never** restricts the ability to send data. The consequence is that an attacker **does not need** the ability to read a response in order to successfully exfiltrate data — it is enough to read a local file (via `XMLHttpRequest`/`fetch` to `file://`) and send its contents (via an ordinary `POST`) to an attacker-controlled server, **regardless of whether the response from that server can be read back or not**.

The official overview provides concrete diagnostic evidence confirming this phenomenon — a scenario where **both** settings (`setAllowFileAccessFromFileURLs` and `setAllowUniversalAccessFromFileURLs`) are set to `false` (which should ideally be completely safe):

```bash
[INFO:CONSOLE(0)] "Access to XMLHttpRequest at 'file:///data/data/org.owasp.mastestapp/files/api-key.txt' from origin 'null' has been blocked by CORS policy..."
[INFO:CONSOLE(31)] "File content sent successfully.", source: file:/// (31)
```

Notice that **both log lines appear together** — the first line shows CORS **blocking the read** of the file (`XMLHttpRequest` fails), yet the second line (printed by the attacker's JavaScript code) shows **"sent successfully."** However, the official overview also confirms that in this particular scenario (both flags `false`), the actual payload **was not successfully read** to be sent (because the `XMLHttpRequest` to read the file failed first):

```bash
[*] Received POST data from 127.0.0.1:
Error reading file: 0
```

This actually confirms that **both flags being `false` is sufficient to prevent the file read from being forwarded** — but the "File content sent successfully" line in the JS log remains an **important reminder**: an attack scheme that **succeeds** in reading the file (with at least one of the two flags `true`) would produce a similar log pattern **without** the CORS block line, and **the data would actually be sent**, even though the application could never confirm success by reading the response. The tester must understand that **"failed to read response" is not a safety indicator** — the only reliable indicator is **whether the source file read succeeded in the first place**.

### 1.6 Interaction Between `setAllowFileAccessFromFileURLs` and `setAllowUniversalAccessFromFileURLs`

The official overview provides an important note about the hierarchy between these two flags:

> **Note 2:** *"As indicated in the Android docs, the value of `setAllowFileAccessFromFileURLs` is ignored if `allowUniversalAccessFromFileURLs=true`."*

`setAllowUniversalAccessFromFileURLs` **fully subsumes** the scope of `setAllowFileAccessFromFileURLs` (allowing cross-origin access to *anywhere*, not just between `file://` origins) — so if the former is `true`, the value of the latter becomes irrelevant to check further. This is consistent with why the official Evaluation clause joins the two with the word **"Either... or"** (§1.4) — it is enough for **either** of the two to be `true` to satisfy the third condition.

---

## 2. Tools Used for Testing

### 2.1 Required Tools (Core)

| Tool | Function |
|---|---|
| **jadx** | Decompiles DEX → Java for searching `WebSettings` patterns |
| **grep / ripgrep** | Searches for API patterns and verifies argument values |
| **semgrep** | Runs the official rule (same as MASTG-TEST-0250) as a baseline |
| **aapt2 / jadx --no-src** | Extracts `minSdkVersion` — **mandatory**, since the evaluation fully depends on it (§1.4) |

### 2.2 Alternative & Supporting Tools

| Tool | Function |
|---|---|
| **CodeQL** | Traces the FAIL condition combination on the same WebView instance, while also correlating with the project's `minSdkVersion` |
| **jadx-gui "Find Usage"** | Inventories **every** WebView instance in the app (§1.3) — including ones that never call `setAllow*` at all, per MASTG's explicit recommendation to identify every instance |
| **MobSF** | Sometimes flags risky WebView setting combinations |
| **Frida** | Hooking to confirm the effective runtime value (including ones derived from a default — see the MASTG-TEST-0251 document §1.3 for why the explicit-vs-default ambiguity collapses at runtime) |

### 2.3 Environment Prerequisites

- **No device/root required** for the core static analysis.
- **Extracting `minSdkVersion` is the mandatory first step**, not optional — without this value, the FAIL/PASS condition for the second and third APIs cannot be evaluated at all.
- **Thorough inventory of every WebView instance** per the official explicit recommendation (§1.3) — do not just passively search for `setAllow*` calls.

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0013** to reverse engineer the application.
2. Use **MASTG-TECH-0014** to search for relevant APIs.
3. Use **MASTG-TECH-0117** to obtain the `AndroidManifest.xml`.
4. Use **MASTG-TECH-0150** to obtain the `minSdkVersion` from the manifest.

### 3.2 Method A — Thorough WebView Instance Inventory + `minSdkVersion` Extraction *(primary method)*

```bash
jadx -d ./decompiled ./target-app.apk
jadx --no-src -d ./out ./target-app.apk

# 1. MANDATORY first: extract minSdkVersion
MINSDK=$(grep -oP 'minSdkVersion="\K[0-9]+' ./out/resources/AndroidManifest.xml)
echo "minSdkVersion: $MINSDK"

# 2. Inventory EVERY WebView instance (not just ones calling setAllow*)
rg -l 'new WebView\(|findViewById.*WebView\)|extends WebView' ./decompiled/sources/ > webview_instances.txt
cat webview_instances.txt

# 3. For EVERY file containing a WebView instance, check all three settings
for f in $(cat webview_instances.txt); do
    echo "=== $f ==="
    grep -n "setJavaScriptEnabled\|setAllowFileAccess\b\|setAllowFileAccessFromFileURLs\|setAllowUniversalAccessFromFileURLs" "$f" || echo "  [!] NO setAllow* reference found -> check the default based on minSdkVersion=$MINSDK"
done
```

### 3.3 Method B — Automated Evaluation Script That Accounts for `minSdkVersion`

```python
def evaluate_test_0252(min_sdk, js_enabled, file_access, file_access_from_file_urls, universal_access):
    """
    Programmatically implements MASTG-TEST-0252's official Evaluation clause.
    Each parameter: True / False / None (None = never called at all in the code)
    """
    # Condition 1: JavaScript
    cond1 = (js_enabled is True)

    # Condition 2: setAllowFileAccess
    if file_access is True:
        cond2 = True
    elif file_access is None and min_sdk < 30:
        cond2 = True  # inherits default true
    else:
        cond2 = False

    # Condition 3: either setAllowFileAccessFromFileURLs or setAllowUniversalAccessFromFileURLs
    def resolve(value, threshold):
        if value is True:
            return True
        if value is None and min_sdk < threshold:
            return True
        return False

    cond3 = resolve(file_access_from_file_urls, 16) or resolve(universal_access, 16)

    fail = cond1 and cond2 and cond3
    return {"FAIL": fail, "cond1_js": cond1, "cond2_file_access": cond2, "cond3_from_file_urls": cond3}

# Example usage after manual extraction from the code:
result = evaluate_test_0252(
    min_sdk=24,
    js_enabled=True,
    file_access=None,               # not called -> defaults to true because minSdk < 30
    file_access_from_file_urls=None,# not called -> defaults to true because minSdk < 16? CHECK
    universal_access=None
)
print(result)
```

This script helps avoid manual mistakes in applying the fairly complex conditional logic in §1.4 — especially for large-scale audits with many WebView instances.

### 3.4 Method C — Semgrep (Official Rule, Same as MASTG-TEST-0250)

```bash
semgrep --config https://raw.githubusercontent.com/OWASP/mastg/master/rules/mastg-android-webview-allow-local-access.yml ./decompiled/sources/
```

The same gap noted and discussed in depth in the MASTG-TEST-0250 document §3.2 applies — this rule purely inventories locations without evaluating the FAIL condition combination or the `minSdkVersion` dependency.

### 3.5 Method D — CodeQL (Correlation with `minSdkVersion`)

```ql
import java

class WebSettingsFileAccessCall extends MethodAccess {
  WebSettingsFileAccessCall() {
    this.getMethod().hasName(["setAllowFileAccess", "setAllowFileAccessFromFileURLs", "setAllowUniversalAccessFromFileURLs", "setJavaScriptEnabled"]) and
    this.getMethod().getDeclaringType().hasQualifiedName("android.webkit", "WebSettings")
  }
}

from MethodAccess call
select call, call.getMethod().getName(), call.getArgument(0)
```

The results of this query are then matched manually/scripted against the project's `minSdkVersion` value to apply Method B's logic programmatically across the entire codebase.

### 3.6 Method Comparison: Which One to Use When

| Method | Tool | Handles `minSdkVersion` logic? | When to use |
|---|---|---|---|
| **A** | Manual inventory + grep | Manual | Mandatory baseline, especially to catch "absence of reference" (§1.3) |
| **B** | Python evaluation script | ✅ Automatic | Avoids manual conditional-logic mistakes, large scale |
| **C** | Official semgrep rule | ❌ | Quick location baseline |
| **D** | CodeQL | Needs additional manual correlation | Large codebase, structured data extraction |

**Minimum recommended combination:** **A (thorough inventory, including instances that do NOT call setAllow*) → B (automated evaluation with correct minSdkVersion logic)**. The official rule (C) can be used as a quick supplement, but should not be the primary method since it does not handle the `minSdkVersion` dependency that is the core of this test's evaluation.

---

### 3.7 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rule:**

> **Evaluation:** *"The test case fails if all of the following applies: `setJavaScriptEnabled` is explicitly set to `true`. `setAllowFileAccess` is explicitly set to `true` (or not used at all when `minSdkVersion` < 30). Either `setAllowFileAccessFromFileURLs` or `setAllowUniversalAccessFromFileURLs` is explicitly set to `true` (or not used at all when `minSdkVersion` < 16)."*

---

#### ❌ FAIL / ISSUE — The check is declared FAILED when:

| No | Condition |
|---|---|
| F1 | `setJavaScriptEnabled(true)` **and** the `setAllowFileAccess` condition is satisfied (explicit `true` or default `true` because `minSdkVersion` < 30) **and** the condition of either `setAllowFileAccessFromFileURLs`/`setAllowUniversalAccessFromFileURLs` is satisfied (explicit `true` or default `true` because `minSdkVersion` < 16) |
| F2 | A WebView instance is found with **not a single** `setAllow*` call, and the app's `minSdkVersion` < 30 — the "silent" combination that MASTG explicitly warns must be captured (§1.3) |
| F3 | Dynamic verification confirms a `file://` read **succeeds** (not merely "was sent" — see the §1.5 nuance on blind exfiltration) |

**Example evidence (illustrative — MASTG does not yet provide an official demo for this test):**

```bash
$ grep -oP 'minSdkVersion="\K[0-9]+' AndroidManifest.xml
21    # Android 5.0 — below both the 30 AND 16 thresholds

$ rg -n "setJavaScriptEnabled|setAllowFileAccess" ./decompiled/sources/com/example/target/ui/HelpViewerActivity.java
42:    settings.setJavaScriptEnabled(true);
# No call to setAllowFileAccess/setAllowFileAccessFromFileURLs/setAllowUniversalAccessFromFileURLs AT ALL
```

Interpretation: `minSdkVersion=21` means all three APIs inherit the default `true` for every device running this app (because 21 < 30 and... note: 21 is not less than 16, so check the table carefully — a device with API 21 is already above the threshold of 16, so the default for `setAllowFileAccessFromFileURLs`/`setAllowUniversalAccessFromFileURLs` is already `false`. However `setAllowFileAccess` still defaults to `true` because 21 < 30). Combined with JavaScript enabled — **FAIL**, because conditions 1 and 2 are satisfied, while condition 3 depends on whether either of the last two APIs is explicitly set to `true` in the code (needs further verification, it is not automatically FAIL purely from `minSdkVersion=21` alone).

*(Note: this example deliberately illustrates the complexity of calculating the two different per-API thresholds — this is why Method B / the automated script is strongly recommended to avoid manual errors.)*

---

#### ✅ PASS — The check is declared PASSED when:

| No | Condition |
|---|---|
| P1 | `minSdkVersion` ≥ 30 **and** there is no explicit `true` call on any of the three APIs — all inherit the modern safe default |
| P2 | `setJavaScriptEnabled` is set to `false`/not used on a WebView loading `file://` |
| P3 | All three APIs are explicitly set to `false` regardless of `minSdkVersion` |
| P4 | The app uses `WebViewAssetLoader` (MASTG-BEST-0011), fully avoiding `file://` |

---

#### ⚠️ Important Notes on the Assessment

1. **Extracting `minSdkVersion` is not a supplementary step — it is an absolute prerequisite.** Without this value, it is impossible to determine whether the absence of an API call means PASS (modern safe default) or FAIL (older insecure default).

2. **Do not ignore WebView instances that are "clean" of `setAllow*` calls** — per §1.3, these are precisely the ones that need the most careful scrutiny, the opposite of the common intuition that "no risky API call = safe."

3. **Understand the difference between "failed to read" and "failed to send"** (§1.5) — a log showing a CORS block on reading does not automatically mean data did not leak; always check whether **reading the source file** succeeded first, since that is the true deciding factor, not the sending status.

4. **Note that the API threshold differs for each condition** (30 for `setAllowFileAccess`, 16 for the other two APIs) — do not generalize the calculation; use the automated script (Method B) to avoid manual errors in large-scale audits.

5. **`setAllowFileAccessFromFileURLs` is ignored if `setAllowUniversalAccessFromFileURLs=true`** (§1.6) — check the latter first as the primary determinant.

6. **Severity is modulated as follows:**

   | Factor | Severity |
   |---|---|
   | Full FAIL combination, very low `minSdkVersion`, WebView loads content from a source that can be compromised (external download, deep link) | **Critical** |
   | Full FAIL combination but the WebView only loads fully trusted internal assets (no path for injecting malicious HTML) | **Medium** — lower risk due to a lack of a practical exploitation path |
   | `minSdkVersion` is already high (30+), with no explicit override to an insecure value | **Not a finding** |

7. **Document:** the app's `minSdkVersion`, the full list of WebView instances (including ones that never call `setAllow*`), the effective value of all three APIs per instance (the result of the default-vs-explicit calculation), and the results of dynamic verification, if performed.

---

## 4. Recommendations

### 4.1 Raise `minSdkVersion` (Refer to MASTG-BEST-0010 and the MASTG-TEST-0245 Document)

Raising `minSdkVersion` to ≥30 structurally changes the `setAllowFileAccess` default to a safe one without needing additional code — consistent with the cross-document recommendation in this research series about the importance of an up-to-date `minSdkVersion`.

### 4.2 Explicitly Disable Regardless of `minSdkVersion`

```kotlin
webView.settings.apply {
    allowFileAccess = false
    allowFileAccessFromFileURLs = false          // still set explicitly even though deprecated, for clarity of intent
    allowUniversalAccessFromFileURLs = false
}
```

Per MASTG-BEST-0011: *"For apps with a `minSdkVersion` that has secure defaults... ensure that these methods are not used and the default values are preserved. Alternatively, explicitly set them to `false`"* — an explicit setting is safer to audit in the future than relying on a `minSdkVersion`-dependent default.

### 4.3 Migrate to `WebViewAssetLoader`

Refer to the full implementation in the MASTG-TEST-0250 document §4.3 — the same solution applies here, fully avoiding `file://`.

### 4.4 Remediation Checklist

- [ ] `minSdkVersion` has been evaluated and raised where possible
- [ ] All WebView instances have been inventoried, including ones that never call `setAllow*` at all
- [ ] All three APIs are explicitly set to `false` on every instance loading `file://` content
- [ ] Migration to `WebViewAssetLoader` has been considered
- [ ] Dynamic verification has been performed to distinguish "failed to read" vs "failed to send" (§1.5)
- [ ] **Re-verify:** re-run MASTG-TEST-0252 after any change to `minSdkVersion` or the WebView implementation

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0252: References to Local File Access in WebViews](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0252/)
- [MASTG-TEST-0250: References to Content Provider Access in WebViews](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0250/)
- [MASTG-TEST-0245: References to Platform Version APIs](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0245/)
- [MASWE-0034: WebViews Allow Access to Local Resources with Untrusted Content](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0034/)
- [MASTG-KNOW-0018: WebViews](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0018/)
- [MASTG-BEST-0010: Use Up-to-Date minSdkVersion](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0010/)
- [MASTG-BEST-0011: Securely Load File Content in a WebView](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0011/)
- [MASTG-BEST-0012: Disable JavaScript in WebViews](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0012/)
- [MASTG Document 0x05h — Testing Platform Interaction (WebView Local File Access Settings)](https://mas.owasp.org/MASTG/0x05h-Testing-Platform-Interaction/)

### 5.2 Official Android Documentation

- [Android Developers — `WebSettings#setAllowFileAccess`](https://developer.android.com/reference/android/webkit/WebSettings#setAllowFileAccess(boolean))
- [Android Developers — `WebSettings#setAllowFileAccessFromFileURLs`](https://developer.android.com/reference/android/webkit/WebSettings#setAllowFileAccessFromFileURLs(boolean))
- [Android Developers — `WebSettings#setAllowUniversalAccessFromFileURLs`](https://developer.android.com/reference/android/webkit/WebSettings#setAllowUniversalAccessFromFileURLs(boolean))
- [Chromium — CORS and WebView API Documentation](https://chromium.googlesource.com/chromium/src/+/HEAD/android_webview/docs/cors-and-webview-api.md)

### 5.3 Research and Real-World Cases

- [Medium — Exploiting Insecure Android WebView with setAllowUniversalAccessFromFileURLs](https://medium.com/@youssefhussein212103168/exploiting-insecure-android-webview-with-setallowuniversalaccessfromfileurls-c7f4f7a8db9c)
- [INTEGRITY Labs — Reviewing Android WebViews fileAccess Attack Vectors](https://labs.integrity.pt/articles/review-android-webviews-fileaccess-attack-vectors/index.html)
- [arXiv — Cross Site Request Forgery on Android WebView](https://arxiv.org/pdf/1411.3124)
- [Google Issue Tracker — WebView doesn't allow to read the body of a POST request](https://issuetracker.google.com/issues/119844519)
- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
- [CWE-668: Exposure of Resource to Wrong Sphere](https://cwe.mitre.org/data/definitions/668.html)

### 5.4 Tool Documentation

- [Semgrep — Documentation](https://semgrep.dev/docs/)
- [CodeQL — Documentation](https://codeql.github.com/docs/)
- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [Frida — Dynamic instrumentation toolkit](https://frida.re/docs/javascript-api/)
- [MobSF — Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)

---

*This document was prepared based on OWASP MASTG (current release as of September 2026), official Android/Chromium documentation, and community security research on WebView exploitation. The three most important nuances of this test: (1) the evaluation fully depends on `minSdkVersion` with different thresholds per API (30 vs. 16), (2) the absence of a `setAllow*` reference is actually a signal that must be taken seriously — not ignored, and (3) a failure to read the response (CORS block) does not mean data was not leaked, because JavaScript can always send data regardless of its ability to read the reply ("blind exfiltration").*
