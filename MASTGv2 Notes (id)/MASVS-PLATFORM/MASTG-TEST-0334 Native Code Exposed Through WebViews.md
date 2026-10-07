# MASTG-TEST-0334 Native Code Exposed Through WebViews

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0334 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-PLATFORM |
| **Weakness** | MASWE-0034 |
| **Tipe Pengujian** | Static, Code, **Manual** |
| **Teknik terkait** | MASTG-TECH-0013 (Reverse Engineering), MASTG-TECH-0014 (Static Analysis for Relevant APIs), MASTG-TECH-0023 (Reviewing Decompiled Java Code) |
| **Best Practice terkait** | MASTG-BEST-0011, MASTG-BEST-0012, MASTG-BEST-0013, MASTG-BEST-0035 |
| **Knowledge terkait** | MASTG-KNOW-0018 (WebViews) |
| **Prasyarat** | `identify-security-relevant-contexts` |
| **Rule resmi** | `mastg-android-webview-bridges.yml` — 2 pola, lihat §1.4 |

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian

Kutipan overview resmi MASTG:

> *"This test verifies Android apps that use WebViews with legacy WebView-Native bridges do not expose native code to websites loaded inside the WebView."*

Mekanisme yang disasar:

> *"These bridges are created by registering a Java object with the WebView through `addJavascriptInterface`. Public methods of that object that are annotated with `@JavascriptInterface` become callable from JavaScript running inside the WebView, using the provided `name` as the global JavaScript object."*

Dan prasyarat yang membuat jembatan ini bisa diakses:

> *"For this mechanism to work, JavaScript execution must be enabled on the WebView by calling `WebSettings.setJavaScriptEnabled(true)` (default is `false`)."*

Ini adalah salah satu dari sedikit test dalam seri riset ini yang secara eksplisit diberi tipe **"manual"** di samping static/code — menandakan MASTG sendiri mengakui bahwa pattern-matching otomatis **tidak cukup** untuk menyimpulkan temuan final; diperlukan penilaian kontekstual manusia.

### 1.2 Kriteria FAIL Triple-AND: Tiga Kondisi Harus Sama-sama Benar

Struktur evaluasi test ini memiliki **tiga kondisi AND**, lebih kompleks dibanding kebanyakan test lain dalam seri riset ini:

> *"The test case fails if all the following are true:*
> - *`setJavaScriptEnabled` is explicitly set to `true`.*
> - *`addJavascriptInterface` is used at least once.*
> - *At least one method annotated with `@JavascriptInterface` handles sensitive data or actions and is reachable from untrusted content."*

Kondisi ketiga adalah yang **paling sulit diverifikasi secara otomatis** — ia menuntut dua penilaian kualitatif sekaligus: (a) apakah method tersebut menangani data/aksi sensitif, dan (b) apakah method tersebut **benar-benar dapat dijangkau** dari konten yang tidak terpercaya. Inilah akar mengapa test ini diberi label "manual".

### 1.3 Dua Pertanyaan Validasi Lanjutan yang Wajib Dijawab Manusia

Bagian "Further Validation Required" memberi kerangka eksplisit untuk menjawab kondisi ketiga di atas:

> *"Inspect each reported code location using MASTG-TECH-0023 to determine whether the bridge is used in a security-relevant context:*
> - *Determine whether the exposed methods handle sensitive data or security-critical actions.*
> - *Determine whether the bridge is reachable from untrusted content, for example if the WebView can load arbitrary or weakly validated URLs, or if the app does not implement proper origin allowlisting."*

Poin kedua ini sangat penting — **"reachable from untrusted content"** bukan semata soal apakah bridge itu ada, tapi soal **jalur** bagaimana konten berbahaya bisa mencapai WebView yang memiliki bridge tersebut. Sebuah bridge yang hanya diekspos ke halaman first-party yang dimuat dari aset lokal aplikasi (dan WebView tidak pernah menavigasi ke URL eksternal apa pun) memiliki profil risiko yang jauh berbeda dari bridge yang diekspos ke WebView yang dapat memuat URL arbitrer atau menerima parameter URL dari deep link/intent eksternal.

### 1.4 Analisis Rule Resmi: Dua Pola yang Memerlukan Korelasi Manual

Rule `mastg-android-webview-bridges.yml` terdiri dari dua pola yang **masing-masing berdiri sendiri** dan tidak saling terhubung secara otomatis oleh Semgrep:

```yaml
# Pola 1: deteksi kombinasi setJavaScriptEnabled(true) + addJavascriptInterface
- id: mastg-android-webview-bridges-setup
  patterns:
    - pattern: $WEBVIEW.addJavascriptInterface($BRIDGE, $_)
    - pattern-inside: |
        $RET $METHOD(...) {
          ...
          $WEBVIEW.getSettings().setJavaScriptEnabled(true);
          ...
        }

# Pola 2: deteksi method yang diekspos via @JavascriptInterface
- id: mastg-android-webview-bridges-javascriptinterface
  pattern: |
    @JavascriptInterface
    $TYPE $NAME(...) {
      ...
    }
```

Pola 1 menangkap **kondisi 1 dan 2** dari kriteria FAIL (§1.2) — ia secara pintar membatasi scope dengan `pattern-inside` untuk memastikan `setJavaScriptEnabled(true)` dan `addJavascriptInterface` berada di **method yang sama**, mengurangi risiko false positive dibanding sekadar mencari dua pola terpisah di file manapun. Pola 2 menangkap **lokasi** method yang diekspos, namun **tidak dapat secara otomatis menilai** apakah method tersebut "menangani data sensitif" atau "reachable dari untrusted content" — kedua penilaian itu murni manual, sesuai §1.3. Penguji harus **mengkorelasikan hasil kedua pola secara manual**: pastikan `$BRIDGE` dari Pola 1 adalah kelas yang sama tempat method-method dari Pola 2 berada, lalu baru menilai isi method tersebut.

### 1.5 Tiga Tantangan Umum yang Diakui Secara Eksplisit oleh MASTG

Bagian "Well-known Challenges" memberikan pengakuan jujur tentang keterbatasan metodologi, jarang ditemukan selengkap ini:

> *"The app may use parametrized or indirect calls to these APIs, for example through utility methods or wrapper classes. Static analysis may not be able to resolve these calls..."*
>
> *"The app may use several WebViews with different configurations, and it may be difficult to determine which values are set for each WebView instance, especially if they are created dynamically, in different code paths or even across different files."*
>
> *"The app may use obfuscation, reflection, or dynamic code loading to hide the use of these APIs."*

Tantangan kedua secara khusus relevan untuk aplikasi besar dengan banyak layar berbasis WebView (mis. aplikasi e-commerce dengan WebView untuk halaman checkout, bantuan, dan promosi yang masing-masing dikonfigurasi terpisah) — rule resmi akan menandai setiap kombinasi yang cocok, namun penguji harus memetakan **secara manual** instance WebView mana yang terhubung ke konfigurasi mana, karena satu aplikasi bisa memiliki campuran WebView yang aman dan tidak aman sekaligus.

### 1.6 Bukti Nyata: Dari RCE Klasik hingga Kasus Aplikasi Produksi Nyata

Kerentanan class `addJavascriptInterface` bukan risiko teoretis — ini adalah salah satu kelas kerentanan Android paling terdokumentasi dalam sejarah riset keamanan mobile. Riset klasik WithSecure (sebelumnya F-Secure) yang dirujuk juga dalam MASTG-KNOW-0018 mendemonstrasikan mekanisme eksploitasi penuh:

> *"JavaScript injected into a WebView that implements a native bridge using android.webkit.JavascriptInterface can result in execution of operating system commands via java.lang.Runtime through reflection techniques... A real-world example involved a method named getTime() that accepts a string parameter and directly passes it to Runtime.getRuntime().exec(), allowing command execution."*

Contoh ini secara sempurna mengilustrasikan risiko kondisi ketiga di §1.2 — sebuah method yang **kelihatannya tidak berbahaya** (bernama `getTime()`, seolah hanya mengembalikan waktu) ternyata menjadi vektor **remote code execution** penuh karena parameter string yang diterimanya diteruskan langsung ke `Runtime.exec()` tanpa validasi.

Kasus nyata pada aplikasi produksi juga terdokumentasi — laporan analisis kerentanan **ownCloud Mobile App** menemukan:

> *"A vulnerability was found in SamlWebViewDialog.java where JavaScript was enabled in the WebView, exposing the application to potential attacks."*

Ini menegaskan bahwa kelas kerentanan ini terus muncul kembali pada aplikasi produksi nyata dari waktu ke waktu, bukan sekadar skenario yang sudah "diselesaikan" sejak API level 21 (sesuai catatan MASTG-BEST-0035 bahwa risiko reflection-based RCE sudah dimitigasi untuk `targetSdkVersion` 21+ yang hanya mengekspos method beranotasi) — risiko **logika bisnis** dari method yang memang sengaja diekspos namun tidak divalidasi dengan benar tetap sepenuhnya relevan terlepas dari target API level.

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | Fungsi |
|---|---|
| **jadx** | Dekompilasi DEX → Java untuk review manual (MASTG-TECH-0013, MASTG-TECH-0023) |
| **Semgrep** + rule resmi `mastg-android-webview-bridges.yml` | Triase awal lokasi kandidat (MASTG-TECH-0014) |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **grep/ripgrep** | Mencari pola tidak langsung (wrapper method, helper class) yang terlewat Semgrep sesuai tantangan §1.5 |
| **MobSF** | Laporan otomatis yang kadang menyertakan deteksi `addJavascriptInterface` sebagai bagian ringkasan |
| **Frida** | Verifikasi dinamis — hook method `@JavascriptInterface` untuk mengonfirmasi benar-benar dapat dipanggil dari konten WebView sungguhan saat runtime, termasuk kasus WebView yang dibuat dinamis (§1.5) |
| **objection** | Eksplorasi cepat WebView aktif di device uji, termasuk memeriksa konfigurasi `WebSettings` aktual |

### 2.3 Prasyarat Lingkungan

- Tidak butuh device/root untuk analisis statis awal, namun **verifikasi manual dan dinamis sangat direkomendasikan** mengingat tipe test ini mencakup "manual".
- Siapkan definisi "data/aksi sensitif" yang jelas (sesuai prasyarat `identify-security-relevant-contexts`) sebelum menilai kondisi ketiga kriteria FAIL.

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0013** untuk reverse engineer aplikasi.
2. Gunakan **MASTG-TECH-0014** untuk mencari API yang relevan.
3. **(Wajib, bukan opsional)** Gunakan **MASTG-TECH-0023** untuk meninjau setiap lokasi yang ditemukan secara manual.

### 3.2 Metode A — Semgrep dengan Rule Resmi untuk Triase Awal

```bash
semgrep --config mastg-android-webview-bridges.yml ./decompiled/sources
```

### 3.3 Metode B — grep/ripgrep untuk Pola Tidak Langsung

```bash
D=./decompiled/sources

# Cari seluruh pemanggilan addJavascriptInterface, termasuk via variabel objek WebView yang tidak eksplisit namanya
rg -n 'addJavascriptInterface\(' $D

# Cari seluruh method beranotasi @JavascriptInterface
rg -n -A3 '@JavascriptInterface' $D

# Cari indikasi wrapper/helper yang mungkin menyembunyikan pemanggilan setJavaScriptEnabled
rg -n 'setJavaScriptEnabled' $D
```

### 3.4 Metode C — Review Manual Decompiled Code (Wajib, Sesuai MASTG-TECH-0023)

Untuk setiap method `@JavascriptInterface` yang ditemukan Metode A/B:

1. Baca isi method secara lengkap — apakah menangani data sensitif (token, kredensial) atau memicu aksi sensitif (transfer, perubahan setting keamanan)?
2. Lacak balik objek WebView yang menerima bridge tersebut — apakah WebView tersebut memuat URL yang bisa dikontrol pengguna/eksternal (deep link, intent extra), atau hanya aset lokal tetap?
3. Periksa apakah ada mekanisme allowlisting origin (`shouldOverrideUrlLoading`, `shouldInterceptRequest`) yang membatasi navigasi WebView tersebut.

### 3.5 Metode D — Frida untuk Verifikasi Dinamis Reachability

```javascript
Java.perform(function () {
    var targetBridge = Java.use("com.example.app.webview.NativeBridge");
    targetBridge.sensitiveMethod.implementation = function (param) {
        console.log("[NativeBridge.sensitiveMethod] dipanggil dengan: " + param);
        console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));
        return this.sensitiveMethod(param);
    };
});
```

Muat halaman web uji (termasuk dari sumber yang disimulasikan sebagai tidak terpercaya) di WebView aplikasi dan amati apakah method bridge benar-benar terpanggil — bukti paling konklusif untuk kondisi "reachable from untrusted content".

### 3.6 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Kapan dipakai |
|---|---|---|
| **A** | Semgrep + rule resmi | Triase awal cepat — kondisi 1 & 2 |
| **B** | grep/ripgrep manual | Menutup celah pola tidak langsung (§1.5) |
| **C** | Review manual (wajib) | Menilai kondisi 3 — data sensitif & reachability, TIDAK BISA diotomasi penuh |
| **D** | Frida | Bukti dinamis konklusif untuk reachability |

**Kombinasi minimum yang aku rekomendasikan:** **A + B (triase) → C (wajib, inti dari sifat "manual" test ini)**, dengan **D** sebagai pelengkap bukti dinamis bila diperlukan laporan yang lebih kuat.

---

### 3.7 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG (kriteria AND rangkap tiga, §1.2):**

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila **ketiga** kondisi berikut terpenuhi:

| No | Kondisi |
|---|---|
| F1 | `setJavaScriptEnabled` diset eksplisit ke `true` |
| F2 | `addJavascriptInterface` dipakai minimal sekali |
| F3 | Minimal satu method `@JavascriptInterface` menangani data/aksi sensitif **dan** reachable dari konten tidak terpercaya |

**Contoh bukti (mereplikasi pola nyata WithSecure di §1.6):**

```java
// Ditemukan di com/example/app/webview/SupportChatActivity.java
webView.getSettings().setJavaScriptEnabled(true);
webView.addJavascriptInterface(new NativeBridge(), "AndroidBridge");
webView.loadUrl(getIntent().getStringExtra("support_url")); // URL dari luar, tidak divalidasi!

// Ditemukan di com/example/app/webview/NativeBridge.java
public class NativeBridge {
    @JavascriptInterface
    public void executeCommand(String cmd) {
        Runtime.getRuntime().exec(cmd); // method menangani aksi sangat sensitif
    }
}
```

Interpretasi: ketiga kondisi terpenuhi — JavaScript aktif, bridge terdaftar, dan method `executeCommand` menangani aksi kritis **sekaligus** WebView memuat URL yang berasal dari `Intent` eksternal tanpa validasi. **FAIL** — risiko RCE penuh.

---

#### ✅ PASS — Check dinyatakan LULUS apabila **salah satu** dari berikut:

| No | Kondisi |
|---|---|
| P1 | JavaScript tidak diaktifkan sama sekali |
| P2 | JavaScript aktif namun tidak ada `addJavascriptInterface` dipakai |
| P3 | Bridge ada, namun seluruh method `@JavascriptInterface` hanya menangani data non-sensitif (mis. `getAppVersion()`) |
| P4 | Method sensitif ada, namun WebView yang menghostnya **terbukti** hanya memuat konten first-party terpercaya (aset lokal statis, tanpa navigasi ke URL eksternal apa pun) |

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Jangan berhenti di hasil Semgrep mentah** — sesuai sifat "manual" test ini, menemukan kombinasi Pola 1 + Pola 2 secara statis **hanya mengidentifikasi kandidat**; kondisi ketiga (§1.2, §1.3) wajib diverifikasi manusia sebelum menyimpulkan FAIL final.

2. **"Reachable from untrusted content" adalah pertanyaan arsitektural, bukan sekadar pertanyaan kode lokal** — lacak seluruh jalur bagaimana URL dimuat ke WebView tersebut: dari intent extra, deep link, QR code, atau sumber eksternal lain yang bisa dikontrol penyerang.

3. **Waspadai tiga tantangan resmi (§1.5)** sebelum menyimpulkan PASS dari ketidakhadiran match — pola tidak langsung, banyak instance WebView dengan konfigurasi beragam, dan obfuskasi/reflection dapat menyembunyikan temuan sesungguhnya.

4. **Reflection-based RCE klasik (API <21) sudah banyak termitigasi** namun **risiko logika bisnis tetap relevan di semua target API level** — method yang sengaja diekspos namun tanpa validasi input yang benar (seperti contoh `executeCommand`/`getTime()` di §1.6) tetap berbahaya terlepas dari `targetSdkVersion`.

5. **Severity dimodulasi:**

   | Faktor | Severity |
   |---|---|
   | Bridge menangani aksi command execution/filesystem/kredensial, reachable dari URL eksternal tidak tervalidasi | **Kritis** (RCE/akses penuh) |
   | Bridge menangani data sensitif namun hanya reachable dari konten first-party terkontrol | **Rendah** (risiko residual bila first-party ter-compromise) |
   | Bridge hanya menangani data non-sensitif | **Bukan temuan** |

6. **Dokumentasikan:** lokasi kode WebView dan bridge, isi lengkap method yang diekspos, jalur bagaimana WebView tersebut dapat dinavigasi ke konten eksternal, dan hasil verifikasi dinamis bila dilakukan.

---

## 4. Rekomendasi Perbaikan

### 4.1 Migrasi ke Mekanisme Bridge Modern Sesuai MASTG-BEST-0035

```java
// SEBELUM — legacy addJavascriptInterface, tanpa origin control
webView.addJavascriptInterface(new NativeBridge(), "AndroidBridge");

// SESUDAH — addWebMessageListener dengan allowlist origin eksplisit
WebViewCompat.addWebMessageListener(
    webView,
    "nativeBridge",
    Set.of("https://trusted.example.com"), // allowedOriginRules eksplisit
    (view, message, sourceOrigin, isMainFrame, replyProxy) -> {
        // validasi sourceOrigin sebelum memproses pesan
    }
);
```

### 4.2 Minimalkan Fungsi Native yang Diekspos (Sesuai MASTG-BEST-0035)

Jangan ekspos utility/command dispatcher generik — ekspos hanya operasi spesifik yang benar-benar dibutuhkan halaman, dengan format pesan yang terdefinisi jelas dan validasi input yang ketat terhadap setiap parameter.

### 4.3 Validasi Origin Sebelum Memuat Konten ke WebView Berbridge

```java
webView.setWebViewClient(new WebViewClient() {
    @Override
    public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
        String host = request.getUrl().getHost();
        if (!ALLOWED_HOSTS.contains(host)) {
            return true; // blokir navigasi ke domain tidak terpercaya
        }
        return false;
    }
});
```

### 4.4 Checklist Remediasi

- [ ] Bridge legacy `addJavascriptInterface` dimigrasi ke `addWebMessageListener` dengan allowlist origin
- [ ] Setiap method yang diekspos diminimalkan scope-nya dan divalidasi inputnya secara ketat
- [ ] WebView yang menghost bridge sensitif tidak dapat menavigasi ke URL eksternal tanpa validasi
- [ ] Hasil diverifikasi secara dinamis (Frida) untuk memastikan bridge tidak lagi reachable dari konten tidak terpercaya
- [ ] Review manual (MASTG-TECH-0023) dilakukan untuk setiap bridge baru yang ditambahkan di masa depan

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0334 (source, tests-beta)](https://github.com/OWASP/mastg/blob/master/tests-beta/android/MASVS-PLATFORM/MASTG-TEST-0334.md)
- [MASTG-KNOW-0018: WebViews](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0018/)
- [MASTG-BEST-0035: Prefer Origin Scoped Messaging Over Legacy JavaScript Bridges](https://github.com/OWASP/mastg/blob/master/best-practices/MASTG-BEST-0035.md)
- [MASTG-BEST-0012: Disable JavaScript in WebViews](https://github.com/OWASP/mastg/blob/master/best-practices/MASTG-BEST-0012.md)
- [MASTG-TECH-0023: Reviewing Decompiled Java Code](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0023/)

### 5.2 Riset dan Kasus Nyata

- [WithSecure Labs: WebView addJavascriptInterface Remote Code Execution](https://labs.withsecure.com/publications/webview-addjavascriptinterface-remote-code-execution)
- [SecureLayer7: Android WebView Vulnerabilities — Risks and Hardening](https://blog.securelayer7.net/android-webview-vulnerabilities/)
- [Android Developers: Insecure WebView Native Bridges](https://developer.android.com/privacy-and-security/risks/insecure-webview-native-bridges)
- [HackerOne Report #87835: ownCloud WebView JavaScript Exposure](https://hackerone.com/reports/87835)

### 5.3 Dokumentasi Tools

- [Semgrep Documentation](https://semgrep.dev/docs/)
- [Frida — Dynamic Instrumentation Toolkit](https://frida.re/docs/home/)
- [MobSF — Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)
- [Objection — Runtime Mobile Exploration](https://github.com/sensepost/objection)

---

*Dokumen ini disusun berdasarkan konten resmi OWASP MASTG (`tests-beta/android/MASVS-PLATFORM/MASTG-TEST-0334.md`, `MASTG-KNOW-0018`, `MASTG-BEST-0011/0012/0013/0035`, `MASTG-TECH-0023`), analisis rule `mastg-android-webview-bridges.yml`, serta riset klasik WithSecure tentang reflection-based RCE melalui `addJavascriptInterface` dan laporan kerentanan nyata pada aplikasi produksi (ownCloud). Nuansa metodologis terpenting: ini salah satu dari sedikit test yang secara eksplisit diberi tipe "manual" — kriteria FAIL bersifat AND rangkap tiga, dan kondisi ketiga (data sensitif + reachability dari konten tidak terpercaya) secara struktural **tidak dapat divalidasi penuh lewat pattern-matching otomatis**; MASTG sendiri mengakui tiga tantangan nyata (pemanggilan tidak langsung, multi-instance WebView, obfuskasi) yang menuntut kombinasi triase otomatis dengan review manual mendalam.*
