# MASTG-TEST-0293 `setSecure` Not Used to Prevent Screenshots in SurfaceViews

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0293 |
| **Platform** | Android |
| **MASVS Category** | MASVS-PLATFORM |
| **Weakness** | MASWE-0038 — *Insufficient Protection of Sensitive Data from Screenshots or Screen Recordings* (same as MASTG-TEST-0289/0291/0292) |
| **API Highlighted** | `SurfaceView.setSecure(boolean)` |
| **Test Type** | Static, Code |
| **Official MASTG Status** | **`placeholder`** — no complete Overview/Steps/Evaluation yet |
| **Official Note (the only content available)** | *"This test verifies whether an app prevents sensitive data from being captured in screenshots and screen recordings of `SurfaceView` components."* |
| **Knowledge** | MASTG-KNOW-0053 |
| **Best Practice** | MASTG-BEST-0014, MASTG-BEST-0017 (Use `setSecure` to Prevent Screenshots in SurfaceViews — **also a placeholder**) |
| **Related Tests** | **MASTG-TEST-0289/0291/0292** — the entire MASWE-0038 group; this test targets a **specific architectural gap** that `FLAG_SECURE` does not cover at all (see §1.2) |
| **Related Demo** | — (none) |
| **Official Rule** | — (none; placeholder test) |
| **Related CWE** | CWE-200, CWE-311 |

---

## 1. Explanation

### 1.1 Status of This Test

Just like MASTG-TEST-0292, both this test and the best practice it references (**MASTG-BEST-0017**) are both in **`placeholder`** status. This document is compiled entirely from independent research into official Android documentation and an understanding of Android's rendering architecture.

### 1.2 The Most Important Finding: `SurfaceView` Operates Outside the Reach of `FLAG_SECURE` — An Architectural Gap, Not Just an Alternative API

This is the **most critical nuance** in this document, and it is fundamentally different from the `setRecentsScreenshotEnabled` vs `FLAG_SECURE` relationship discussed in the MASTG-TEST-0292 document (where the two are **redundant** for the Recents scenario). For `SurfaceView`, the situation is actually the **reverse**: `FLAG_SECURE` applied to an Activity's window does **not automatically protect** content rendered through a `SurfaceView` that exists inside that window.

The technical reason is rooted in Android's **rendering architecture**, which is unique to `SurfaceView`:

> *"Unlike regular Views that render into the Activity window's surface, `SurfaceView` creates its own dedicated rendering surface that is composited by the system compositor (SurfaceFlinger)... `SurfaceView` surfaces can be promoted to hardware overlays on devices that support them, meaning they may bypass the standard window buffer entirely."*

Unlike regular `View`s (`TextView`, `ImageView`, `EditText`, etc.) which are all drawn **into the same window buffer** — so that `FLAG_SECURE` on that window automatically protects **all** of its content — `SurfaceView` works differently: it creates a **"hole punch"** in the Activity window and displays content from a **separate surface** managed directly by the system compositor (**SurfaceFlinger**), potentially even directly by the device's **hardware overlay**. Because this surface is architecturally **independent** of the main window buffer, `FLAG_SECURE` applied to the window **has no reach** to protect it — which is why Android provides a **separate** API, `SurfaceView.setSecure(boolean)`, that must be applied **explicitly** to the `SurfaceView` object itself.

### 1.3 Why This Gap Is Extremely Easy for Developers to Miss

This is a very common **mental model trap** for developers already familiar with `FLAG_SECURE`: the reasonable (but **mistaken**) assumption that *"I've already applied `FLAG_SECURE` to this Activity, so all its content must be protected."* This assumption is **correct** for standard UI components, but **fails completely** once that Activity includes a `SurfaceView` — a component that is **very commonly** used for:

- **Camera preview** (`Camera2`/`CameraX` — usually via `TextureView` or `SurfaceView` as the backing surface)
- **Video playback** (`VideoView`, `ExoPlayer`/Media3 which use `SurfaceView` as the rendering output)
- **Interactive maps** (Google Maps SDK, which has historically used `SurfaceView` for high-performance map rendering)
- **Game engines and custom graphics rendering** (OpenGL ES via `GLSurfaceView`, a direct descendant of `SurfaceView`)

This combination of contexts creates a highly relevant real-world risk scenario: **video identity verification apps (video KYC)**, **video calling apps** that display the user's face/identity documents, or **document scanning apps** that use camera preview to capture ID cards/passports — all of these **commonly use `SurfaceView`** to display the camera/video feed in real time. A developer who applies `FLAG_SECURE` to that Activity (following standard practice that is already correct for other UI components) **may still leave a real gap** in the `SurfaceView` content itself — screenshots or screen recordings can still capture that sensitive camera/video feed, even though `FLAG_SECURE` has been "applied" at the Activity level.

### 1.4 Strict Timing Requirement: Must Be Called Before the Surface Is Attached

The official documentation gives a precise technical requirement that resembles the timing nuance already discussed in the MASTG-TEST-0289 document (the `FLAG_SECURE` vs `onPause()` gap), but here the requirement is more explicit and stringent:

> *"This must be set before the surface view's containing window is attached to the window manager."*

This means `setSecure(true)` **must** be called on the `SurfaceView` **before** the window attachment process occurs — usually meaning **as soon as possible** after the `SurfaceView` object is instantiated, ideally in `onCreate()` before `setContentView()` finishes inflating the layout, or immediately after `findViewById()` obtains its reference. A **late** call (e.g., in `onResume()` after the surface has already attached and started rendering content) may be **ineffective** — a timing gap conceptually similar to the `FLAG_SECURE` vs `onPause()` vulnerability discussed in MASTG-TEST-0289, except that here the requirement is explicitly documented officially, not merely a community research finding.

### 1.5 Historical Context: Originally Designed for DRM, Not Purely for Application Security

An interesting historical point that is important context for an audit report — research found that:

> *"The `FLAG_SECURE` flag is not primarily used for security but rather relates to copyrighted content in the context of DRM and displays—secure content would be something like a DVD, and a secure display would be an HDTV."*

This explains **why** `SurfaceView.setSecure()` has existed as a separate API from the start — its original need was **copyright content protection (DRM)** during premium video playback (e.g., streaming services that need to ensure video output cannot be re-recorded by screen-recording devices/HDMI capture), not primarily designed as a user data privacy control. Nevertheless, the **exact same technical mechanism** — preventing a given surface from appearing in screenshots/recordings — is **also effectively used** for the purpose of protecting sensitive user content privacy (KYC camera feeds, identity document previews), remaining fully relevant to MASWE-0038 security evaluation even though its original design purpose was different.

---

## 2. Tools Used for Testing

### 2.1 Required Tools (Core)

| Tool | Function |
|---|---|
| **jadx** | DEX → Java decompilation for finding `SurfaceView`/`setSecure` patterns |
| **grep / ripgrep** | API pattern search and identification of `SurfaceView`/its subclasses instantiation |

### 2.2 Alternative & Supporting Tools

| Tool | Function |
|---|---|
| **CodeQL** | Traces all classes that **extend** `SurfaceView` (including `GLSurfaceView`, and `SurfaceView` that is the backing view of `CameraX`/ExoPlayer components) and verifies the timing of `setSecure()` calls relative to the lifecycle |
| **jadx-gui "Find Usage"** | Traces all usages of `SurfaceView`/`TextureView` in XML layouts and code, including those wrapped by third-party libraries (camera, video player) |
| **MASTG-TEST-0289 (screenshot extraction methodology)** | Dynamic verification — definitive confirmation of whether `SurfaceView` content actually leaks into screenshots/Recents |

### 2.3 Environment Prerequisites

- **No device/root required** for core static analysis.
- **Identifying all `SurfaceView` usage** (direct or indirect via third-party camera/video libraries) is a required first step — many developers are unaware that the camera/video SDK they use internally uses `SurfaceView`.
- **For dynamic verification**, prepare a device/emulator and trigger a scenario that displays a camera/video feed, then try manual screenshotting and Recents capture simultaneously.

---

## 3. Testing Methodology

Since there are no official steps (placeholder status), the following methodology is compiled from independent research.

### 3.1 General Steps

1. Identify all Activities/Fragments that use `SurfaceView`/its subclasses (directly or via third-party SDKs).
2. For each usage, check whether `setSecure(true)` is called, and **when** relative to window attachment.
3. Assess whether the content displayed by that `SurfaceView` is classified as sensitive (KYC camera feed, video call, identity document preview).

### 3.2 Method A — grep/ripgrep

```bash
D=./decompiled/sources

# Find all classes that extend SurfaceView (directly)
rg -n 'extends SurfaceView|extends GLSurfaceView' $D

# Find setSecure calls
rg -n '\.setSecure\(true\)|\.setSecure\(false\)' $D

# Find SurfaceView instantiation in layout XML
rg -n '<SurfaceView\|<android\.opengl\.GLSurfaceView' ./decompiled/resources/res/layout/
```

### 3.3 Method B — CodeQL for Timing and Coverage Verification

```ql
import java

class SurfaceViewSubclass extends Class {
  SurfaceViewSubclass() {
    this.getASupertype*().hasQualifiedName("android.view", "SurfaceView")
  }
}

class SetSecureCall extends MethodAccess {
  SetSecureCall() {
    this.getMethod().hasName("setSecure")
  }
}

// Find SurfaceView (direct/subclass) that NEVER calls setSecure(true) anywhere
from SurfaceViewSubclass sv
where not exists(SetSecureCall call |
  call.getQualifier().getType() = sv and
  call.getArgument(0).(BooleanLiteral).getBooleanValue() = true)
select sv, "SurfaceView subclass found WITHOUT a setSecure(true) call anywhere in the codebase"
```

### 3.4 Method C — Third-Party SDK Audit (Camera/Video)

```bash
# Check dependencies known to use SurfaceView internally
grep -E "camerax|exoplayer|media3|google-maps|mapbox" app/build.gradle
```

For third-party SDKs, check their respective documentation to see whether they provide configuration to enable a "secure surface" mode (e.g., some versions of CameraX/ExoPlayer provide related options) — the responsibility for this configuration may **rest with the application**, not be handled automatically by the library.

### 3.5 Method D — Dynamic Verification (Definitive Evidence)

```bash
# 1. Trigger a screen that displays a sensitive camera/video feed
adb shell am start -n com.target.app/.VideoKycActivity

# 2. Try a manual screenshot WHILE the camera feed is active
adb shell screencap -p /sdcard/test_surfaceview.png
adb pull /sdcard/test_surfaceview.png

# 3. Inspect the image: does the SurfaceView area show a real camera feed, or is it black/empty?
```

If the screenshot result shows a **genuinely visible camera/video feed** (not a black area), this is definitive proof that `setSecure(true)` was **not** effectively applied to that `SurfaceView` — regardless of whether `FLAG_SECURE` has been applied to its Activity (the area outside the `SurfaceView` may still be blanked out, but the `SurfaceView` area itself remains leaked).

### 3.6 Method Comparison: When to Use Which

| Method | Tool | When to Use |
|---|---|---|
| **A** | grep | Fast baseline identification of `SurfaceView` |
| **B** | CodeQL | Thorough coverage verification (all SurfaceView subclasses) |
| **C** | Third-party SDK audit | Identifying hidden SurfaceViews from external libraries |
| **D** | Dynamic verification | **Definitive proof**, highly recommended given how easily this gap slips past the "FLAG_SECURE is enough" assumption |

**Minimum combination I recommend:** **A+C (identify all SurfaceViews, including from third-party SDKs) → B (verify setSecure coverage) → D (definitive dynamic proof)** — Method D is very important for this test given how easily this gap slips past a developer's mistaken assumption.

---

### 3.7 Evaluation Criteria: Positive Case & Negative Case

Since there is no official Evaluation clause (placeholder status), the following criteria are compiled based on the brief official note and the fundamental architectural principles explained in §1.2.

---

#### ❌ FAIL / ISSUE — The check is declared FAILED if:

| No | Condition |
|---|---|
| F1 | `SurfaceView`/its subclasses is used to display sensitive content (KYC camera feed, video call, identity document preview) **without** calling `setSecure(true)` at all |
| F2 | `setSecure(true)` is called, but **too late** — after the surface has already attached to the window manager (confirmed via Method B/D) |
| F3 | Dynamic verification (Method D) confirms the `SurfaceView` content remains clearly visible in a manual screenshot even though `FLAG_SECURE` has been applied to its Activity — definitive proof of the architectural gap (§1.2) |
| F4 | A developer **mistakenly assumes** that `FLAG_SECURE` on the Activity is enough to protect the `SurfaceView` inside it, without explicit verification |

**Example evidence (illustrative — MASTG has not yet provided an official demo for this test):**

```java
// VideoKycActivity.java
protected void onCreate(Bundle savedInstanceState) {
    getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);  // Applied to the Activity
    super.onCreate(savedInstanceState);
    setContentView(R.layout.activity_video_kyc);
    SurfaceView cameraPreview = findViewById(R.id.camera_preview_surface);
    // NO cameraPreview.setSecure(true) call here!
    startCameraPreview(cameraPreview);
}
```

Interpretation: `FLAG_SECURE` is applied to the Activity, but the `SurfaceView` displaying the camera feed for identity verification is **not** given `setSecure(true)` — per §1.2, this is a real gap: the camera feed (potentially showing the user's face and identity documents) can still be screenshotted/recorded even though `FLAG_SECURE` has "been applied." **Critical FAIL**.

---

#### ✅ PASS — The check is declared PASSED if:

| No | Condition |
|---|---|
| P1 | All `SurfaceView`s that display sensitive content have `setSecure(true)` applied **before** window attachment (timing confirmed via Method B) |
| P2 | Dynamic verification (Method D) confirms the `SurfaceView` area is genuinely black/empty in a manual screenshot while sensitive content is being displayed |
| P3 | The application does not use `SurfaceView` to display any sensitive content at all (e.g., only used for non-sensitive UI elements such as background animations) |

---

#### ⚠️ Important Notes on Evaluation

1. **This is the single most important note in this entire document: DO NOT conclude PASS just because `FLAG_SECURE` is found applied to the Activity.** Per §1.2, this is a very common mistaken assumption — the window's `FLAG_SECURE` does **not** reach `SurfaceView` content at all. Always check `SurfaceView` separately and independently from the `FLAG_SECURE` audit results (MASTG-TEST-0291).

2. **Third-party SDK auditing is a step that is often skipped** — many developers are unaware that the camera/video/map library they use internally uses `SurfaceView`. Check dependencies explicitly (Method C).

3. **Pay strict attention to call timing** — unlike most other tests where "the API call already exists" is enough to be a PASS candidate, here **when** the API is called matters just as much as **whether** it is called.

4. **Dynamic verification is strongly recommended for this test** — given the non-intuitive nature of this architectural gap, definitive visual evidence (Method D) provides far more conviction than conclusions drawn from static analysis alone.

5. **Severity is modulated:**

   | Factor | Severity |
   |---|---|
   | `SurfaceView` displays a sensitive KYC camera feed/identity document/video call without `setSecure` | **Critical** |
   | `SurfaceView` displays non-sensitive video/media without `setSecure` | **Not a finding** (unless DRM-licensed content, relevant for license compliance not user privacy) |
   | `setSecure(true)` called but too late (timing gap) | **High** — effectiveness not guaranteed |

6. **Document:** the complete list of `SurfaceView`s/its subclasses (direct and from third-party SDKs), the status and timing of each `setSecure()` call, the sensitivity classification of the displayed content, and the dynamic verification results.

---

## 4. Recommendations

### 4.1 Apply `setSecure(true)` As Soon As Possible After Instantiation

```java
public class VideoKycActivity extends AppCompatActivity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_video_kyc);

        SurfaceView cameraPreview = findViewById(R.id.camera_preview_surface);
        cameraPreview.setSecure(true);  // BEFORE the surface holder callback/attachment occurs

        SurfaceHolder holder = cameraPreview.getHolder();
        holder.addCallback(surfaceCallback);
    }
}
```

### 4.2 Apply Both: `FLAG_SECURE` for General UI, `setSecure` for SurfaceView

```java
protected void onCreate(Bundle savedInstanceState) {
    getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);  // Protect general UI elements
    super.onCreate(savedInstanceState);
    setContentView(R.layout.activity_video_kyc);
    findViewById(R.id.camera_preview_surface).setSecure(true);  // Protect SurfaceView separately
}
```

### 4.3 Audit Third-Party Camera/Video SDK Configuration

Check the CameraX/ExoPlayer/Media3 documentation for secure `SurfaceView` configuration options that may be provided, and apply them explicitly where available — do not assume the SDK handles this automatically.

### 4.4 Remediation Checklist

- [ ] All `SurfaceView`s/its subclasses (direct and from third-party SDKs) are inventoried
- [ ] `setSecure(true)` is applied to all `SurfaceView`s that display sensitive content, before window attachment
- [ ] Dynamic verification confirms the `SurfaceView` area is genuinely protected in a manual screenshot
- [ ] The development team is educated that `FLAG_SECURE` does NOT automatically protect `SurfaceView`
- [ ] **Re-verify:** re-run MASTG-TEST-0293 whenever a new camera/video component is added

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0293: setSecure Not Used to Prevent Screenshots in SurfaceViews](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0293/)
- [MASTG-TEST-0289: Runtime Verification of Sensitive Content Exposure in Screenshots](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0289/)
- [MASTG-TEST-0291: References to Screen Capturing Prevention APIs](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0291/)
- [MASTG-TEST-0292: setRecentsScreenshotEnabled Not Used to Prevent Screenshots When Backgrounded](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0292/)
- [MASWE-0038: Insufficient Protection of Sensitive Data from Screenshots or Screen Recordings](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0038/)
- [MASTG-BEST-0017: Use setSecure to Prevent Screenshots in SurfaceViews](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0017/)

### 5.2 Official Android Documentation

- [Android Developers — `SurfaceView#setSecure()`](https://developer.android.com/reference/android/view/SurfaceView#setSecure(boolean))
- [Android Developers — `SurfaceView` class overview](https://developer.android.com/reference/android/view/SurfaceView)
- [Android Developers — Secure Sensitive Activities](https://developer.android.com/security/fraud-prevention/activities)
- [Android Developers — Surface Types (Media3)](https://developer.android.com/media/media3/ui/surface)

### 5.3 Community Research and Articles

- [Nightwatch Cybersecurity — Research: Securing Android Applications from Screen Capture (FLAG_SECURE)](https://wwws.nightwatchcybersecurity.com/2016/04/13/research-securing-android-applications-from-screen-capture/)
- [Google CameraX Developers Group — setSecure on PreviewView's underlying SurfaceView](https://groups.google.com/a/android.com/g/camerax-developers/c/z9THRAPo6Wo)
- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)

### 5.4 Tool Documentation

- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [CodeQL — Documentation](https://codeql.github.com/docs/)

---

*This document is compiled entirely from independent research (official Android Developers documentation and an understanding of rendering architecture), because both MASTG-TEST-0293 and the MASTG-BEST-0017 it references are both in **placeholder** status. The most significant finding: `SurfaceView` operates on a compositor surface that is architecturally separate from the main window buffer (potentially even a hardware overlay), so `FLAG_SECURE` on the Activity does **not** automatically protect its content — a gap that is very easy to miss because it contradicts the developer's reasonable assumption that "FLAG_SECURE on the Activity protects everything." This is most relevant for applications that use `SurfaceView` for KYC camera feeds, video calls, or identity document previews — a very common context whose separate screenshot-protection gap is rarely noticed.*
