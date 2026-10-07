# MASTG-TEST-0251 Runtime Use of Content Provider Access APIs in WebViews

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0251 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-PLATFORM (MASVS-PLATFORM-2) |
| **Weakness** | MASWE-0034 — *WebViews Allow Access to Local Resources with Untrusted Content* |
| **API yang disorot** | `WebView`, `WebSettings`, `getSettings`, `ContentProvider`, `setAllowContentAccess`, `setAllowUniversalAccessFromFileURLs`, `setJavaScriptEnabled` |
| **Tipe Pengujian** | **Dynamic, Hooks, Manual** |
| **Profile** | L1, L2 |
| **Knowledge** | MASTG-KNOW-0018 (WebViews) |
| **Best Practice** | MASTG-BEST-0011, MASTG-BEST-0012, MASTG-BEST-0013, MASTG-BEST-0049 |
| **Teknik terkait** | MASTG-TECH-0005 (Install App), MASTG-TECH-0043 (Method Hooking), MASTG-TECH-0023 (Reviewing Decompiled Java Code — validasi lanjutan wajib) |
| **Test terkait** | **MASTG-TEST-0250** (References to Content Provider Access in WebViews — counterpart statis; overview resmi menyatakan eksplisit *"This test is the dynamic counterpart to MASTG-TEST-0250"*) |
| **Demo terkait** | — (tidak ada) |
| **Rule resmi** | — (tidak relevan; test dinamis) |
| **CWE terkait** | CWE-200, CWE-668 |

---

## 1. Penjelasan

### 1.1 Hubungan dengan MASTG-TEST-0250

Seluruh konteks konseptual mendalam — mengapa `setAllowContentAccess` yang defaultnya selalu `true` berbahaya, mengapa content provider aplikasi sendiri tetap terekspos meski `android:exported="false"`, mengapa `setAllowUniversalAccessFromFileURLs` menjadi kunci kritis rantai eksploitasi, dan mengapa temuan ini bukan kerentanan berdiri sendiri melainkan pengganda dampak — **sudah dibahas lengkap di dokumen MASTG-TEST-0250**. Dokumen ini fokus pada apa yang unik dari sisi dinamis.

### 1.2 Dua Pendekatan Hooking yang Ditawarkan Secara Eksplisit

Overview resmi memberi dua opsi metodologi yang secara eksplisit disebutkan setara:

> *"You can take two approaches when hooking or tracing the relevant APIs: enumerate instances of `WebView` in the app and list their configuration values; or, explicitly hook the setters of the `WebView` settings."*

Kedua pendekatan ini punya trade-off yang berbeda:

| Pendekatan | Kelebihan | Kekurangan |
|---|---|---|
| **Enumerasi instance WebView + baca konfigurasi** | Menangkap **status akhir** WebSettings di titik waktu tertentu, termasuk nilai yang diwarisi dari default tanpa perlu pemanggilan setter eksplisit terdeteksi | Perlu akses ke instance WebView yang tepat pada waktu yang tepat (mis. setelah WebView selesai diinisialisasi) |
| **Hooking setter (`setJavaScriptEnabled`, dst.)** | Menangkap **momen dan konteks pemanggilan** (stack trace, kapan dalam siklus hidup dipanggil) — lebih kaya untuk analisis "Further Validation Required" | Tidak menangkap kasus di mana developer **sengaja tidak memanggil** setter tertentu dan mengandalkan nilai default (khususnya relevan untuk `setAllowContentAccess`, lihat §1.3) |

Karena kelemahan masing-masing saling melengkapi, kombinasi **keduanya** memberi gambaran paling lengkap — hooking setter untuk menangkap konteks pemanggilan eksplisit, dan enumerasi instance untuk menangkap nilai efektif akhir (termasuk yang berasal dari default tak-dipanggil).

### 1.3 Nuansa Penting: Perbedaan Makna "Tidak Dipanggil" antara Statis dan Dinamis

Ini titik yang sangat halus namun penting dipahami. Pada **MASTG-TEST-0250 (statis)**, kondisi FAIL untuk `setAllowContentAccess` mencakup dua skenario: *"is explicitly set to `true` OR not used at all"* — perbedaan ini masuk akal secara statis karena penguji melihat **kode sumber**, di mana "tidak ada pemanggilan" adalah kondisi yang benar-benar bisa diamati secara tekstual.

Namun pada **test dinamis ini**, klausul Evaluation resmi disederhanakan menjadi murni nilai aktual:

> *"The test case fails if all the following applies: `JavaScriptEnabled` is `true`. `AllowContentAccess` is `true`. `AllowUniversalAccessFromFileURLs` is `true`."*

Tidak ada lagi klausul "atau tidak dipakai sama sekali" — ini **bukan kelalaian penulisan**, melainkan konsekuensi logis dari sifat pengujian dinamis: ketika penguji **meng-enumerasi instance WebView yang sedang berjalan** dan membaca `settings.getAllowContentAccess()`, API tersebut akan **selalu mengembalikan nilai boolean aktual** yang sedang berlaku — `true`, entah itu karena dipanggil eksplisit atau karena mewarisi default. Perbedaan "eksplisit vs default" yang relevan secara tekstual di analisis statis **melebur menjadi satu** di titik ini pada saat runtime — sistem tidak peduli bagaimana nilai tersebut sampai di sana, hanya peduli nilai apa yang **sedang berlaku**. Ini nilai tambah metodologis tersendiri dari pendekatan dinamis: ia **secara otomatis menyelesaikan** ambiguitas "eksplisit vs default" yang harus ditangani secara manual pada analisis statis.

### 1.4 Klausul "Further Validation Required" yang Lebih Rinci dari Versi Statisnya

Dibanding MASTG-TEST-0250, versi dinamis ini memiliki klausul validasi lanjutan yang **lebih rinci dan berlapis**:

> *"Using the backtraces from the hook output, inspect the code locations using MASTG-TECH-0023: Determine whether the settings are explicitly used and configured to the identified values. Determine which WebView instance receives the configuration and whether it handles sensitive information or functionality. Determine whether the WebView loads content in a context where content provider data could be accessed via `content://` URLs."*

Ini menuntut penguji melakukan tiga lapis analisis berbeda pada **setiap** temuan hook:

1. **Lapis konfigurasi**: apakah nilai ini benar-benar dikonfigurasi sesuai temuan (bukan artefak pengujian/kondisi tepi yang jarang terjadi)?
2. **Lapis identitas WebView**: WebView **spesifik mana** yang menerima konfigurasi ini — apakah WebView yang menampilkan konten sensitif (portal akun, halaman pembayaran) atau WebView tidak penting (mis. menampilkan halaman bantuan statis)?
3. **Lapis konteks muatan**: apakah WebView tersebut memuat konten dalam konteks yang **benar-benar bisa** mengeksekusi akses `content://` — mis. memuat `file://` sesuai rantai eksploitasi yang dijelaskan di dokumen MASTG-TEST-0250 §1.4?

Stack trace dari hooking menjadi kunci untuk menjawab pertanyaan #2 dan #3 — ini alasan utama mengapa hooking setter (bukan hanya enumerasi nilai akhir) tetap bernilai meski §1.3 sudah menjelaskan bahwa nilai akhir bisa didapat lewat enumerasi semata.

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | Fungsi |
|---|---|
| **Frida** | Instrumentasi dinamis inti — hooking setter dan/atau enumerasi instance WebView |
| **frida-tools** (`frida-trace`) | Tracing cepat tanpa scripting detail |
| **objection** | Wrapper Frida siap pakai, termasuk kemampuan dump backtrace built-in |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **Xposed/LSPosed** | Alternatif hooking persisten sesuai MASTG-TECH-0043, berguna bila aplikasi mendeteksi/memblokir Frida |
| **adb logcat** | Memantau pesan CORS block sebagai bukti diagnostik tambahan (dijelaskan di dokumen MASTG-TEST-0250 §1.4) |
| **Burp Suite/mitmproxy** | Mengamati request eksfiltrasi nyata bila PoC eksploitasi dijalankan bersamaan dengan sesi hooking |

### 2.3 Prasyarat Lingkungan

- **Wajib device/emulator dengan Frida server** — test murni dinamis.
- **Interaksi menyeluruh dengan aplikasi** (§1.4 langkah 3 resmi: *"exercise the app extensively... enter sensitive data wherever you can"*) — WebView yang jarang dimuat (mis. hanya muncul saat membuka dokumen tertentu atau alur bantuan spesifik) tidak akan pernah terekam bila tidak dipicu.
- **Idealnya jalankan berdampingan dengan hasil MASTG-TEST-0250** — daftar lokasi statis memberi peta kandidat WebView mana yang perlu diprioritaskan untuk dipicu saat sesi dinamis.

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0005** untuk menginstal aplikasi.
2. Gunakan **MASTG-TECH-0043** untuk melakukan hooking pada pemanggilan API yang relevan.
3. Jelajahi aplikasi secara menyeluruh, masukkan data sensitif di mana pun memungkinkan.

### 3.2 Metode A — Hooking Setter dengan Backtrace *(pendekatan pertama yang disebut resmi)*

```javascript
// hook-webview-settings-setters.js
Java.perform(function () {
    function getBacktrace() {
        return Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());
    }

    var WebSettings = Java.use("android.webkit.WebSettings");
    var relevantSetters = [
        "setJavaScriptEnabled",
        "setAllowContentAccess",
        "setAllowUniversalAccessFromFileURLs"
    ];

    relevantSetters.forEach(function (method) {
        try {
            WebSettings[method].overload("boolean").implementation = function (value) {
                console.log("\n[*] WebSettings." + method + "(" + value + ")");
                console.log("    Backtrace:\n" + getBacktrace());
                return this[method](value);
            };
        } catch (e) {
            console.log("[x] Hook gagal untuk " + method + ": " + e);
        }
    });
});
```

```bash
frida -U -f com.target.app -l hook-webview-settings-setters.js --no-pause
```

### 3.3 Metode B — Enumerasi Instance WebView dan Baca Nilai Efektif *(pendekatan kedua yang disebut resmi)*

```javascript
// enumerate-webview-instances.js
Java.perform(function () {
    Java.choose("android.webkit.WebView", {
        onMatch: function (instance) {
            try {
                var settings = instance.getSettings();
                console.log("\n[*] Instance WebView ditemukan:");
                console.log("    JavaScriptEnabled: " + settings.getJavaScriptEnabled());
                console.log("    AllowContentAccess: " + settings.getAllowContentAccess());
                console.log("    AllowUniversalAccessFromFileURLs: " + settings.getAllowUniversalAccessFromFileURLs());
                console.log("    Current URL: " + instance.getUrl());
            } catch (e) {
                console.log("[x] Gagal membaca settings instance: " + e);
            }
        },
        onComplete: function () {
            console.log("[*] Enumerasi instance WebView selesai.");
        }
    });
});
```

```bash
frida -U -f com.target.app -l enumerate-webview-instances.js --no-pause
# Jalankan setelah aplikasi selesai memuat halaman yang memakai WebView
```

**Catatan implementasi**: `Java.choose()` menangkap instance yang **sedang hidup di heap** pada saat skrip dijalankan — untuk WebView yang dibuat/dihancurkan secara dinamis (mis. dialog WebView sementara), timing eksekusi skrip ini penting; pertimbangkan menjalankannya berulang (`setInterval` dalam skrip Frida) selama sesi interaksi berlangsung.

### 3.4 Metode C — objection (Kombinasi Cepat Kedua Pendekatan)

```bash
objection -g com.target.app explore
# Di dalam console objection:
android hooking watch class_method android.webkit.WebSettings.setJavaScriptEnabled --dump-args --dump-backtrace
android hooking watch class_method android.webkit.WebSettings.setAllowContentAccess --dump-args --dump-backtrace
android hooking watch class_method android.webkit.WebSettings.setAllowUniversalAccessFromFileURLs --dump-args --dump-backtrace

# Enumerasi instance (pendekatan kedua)
android heap search instances android.webkit.WebView
```

### 3.5 Metode D — Korelasi dengan Muatan WebView (Menjawab Lapis Konteks §1.4)

Perluas hook Metode A/B untuk turut menangkap URL yang dimuat, langsung menjawab pertanyaan resmi *"apakah WebView memuat konten dalam konteks yang bisa mengakses `content://`"*:

```javascript
// hook-webview-loadurl-correlated.js
Java.perform(function () {
    var WebView = Java.use("android.webkit.WebView");
    WebView.loadUrl.overload("java.lang.String").implementation = function (url) {
        console.log("\n[*] WebView.loadUrl(" + url + ")");
        var settings = this.getSettings();
        console.log("    JavaScriptEnabled: " + settings.getJavaScriptEnabled());
        console.log("    AllowContentAccess: " + settings.getAllowContentAccess());
        console.log("    AllowUniversalAccessFromFileURLs: " + settings.getAllowUniversalAccessFromFileURLs());
        if (url.indexOf("file://") === 0 && settings.getAllowUniversalAccessFromFileURLs()) {
            console.log("    [!] KONDISI BERISIKO: file:// dimuat dengan universal access aktif!");
        }
        return this.loadUrl(url);
    };
});
```

Pendekatan ini menyatukan Metode A dan B sekaligus dalam satu titik pemicu (`loadUrl`) yang secara langsung relevan dengan skenario eksploitasi nyata — memberi bukti terkuat karena mengaitkan konfigurasi WebSettings dengan **URL aktual** yang dimuat pada momen yang sama.

### 3.6 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Menangkap konteks pemanggilan? | Menangkap nilai efektif akhir? | Kapan dipakai |
|---|---|---|---|---|
| **A** | Hook setter | ✅ (stack trace) | Tidak (hanya saat dipanggil) | Menjawab "kapan dan dari mana" |
| **B** | Enumerasi instance | ❌ | ✅ | Menjawab "apa nilai yang sedang berlaku sekarang" |
| **C** | objection | ✅ + ✅ (gabungan cepat) | ✅ | Eksplorasi awal cepat tanpa scripting |
| **D** | Hook `loadUrl` terkorelasi | ✅ | ✅ | **Paling bernilai** — langsung menjawab pertanyaan konteks (§1.4) |

**Kombinasi minimum yang aku rekomendasikan:** **D sebagai metode utama** (menyatukan kekuatan A dan B sekaligus relevan langsung dengan skenario eksploitasi), dilengkapi **B** secara berkala selama sesi untuk menangkap instance yang mungkin tidak memicu `loadUrl` ulang.

---

### 3.7 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG:**

> **Observation:** *"The output should contain a list of WebView setting calls, including the argument values and backtraces of each call."*
>
> **Evaluation:** *"The test case fails if all the following applies: `JavaScriptEnabled` is `true`. `AllowContentAccess` is `true`. `AllowUniversalAccessFromFileURLs` is `true`."*

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi |
|---|---|
| F1 | Hasil hooking/enumerasi menunjukkan ketiga nilai (`JavaScriptEnabled`, `AllowContentAccess`, `AllowUniversalAccessFromFileURLs`) sama-sama `true` pada **instance WebView yang sama** |
| F2 | Backtrace/korelasi `loadUrl` (Metode D) mengonfirmasi WebView tersebut memuat konten `file://` atau konten yang berpotensi tidak tepercaya |
| F3 | WebView yang terpengaruh terkonfirmasi (MASTG-TECH-0023) menangani informasi/fungsionalitas sensitif |
| F4 | Content provider terkait (silsilah dari MASTG-TEST-0250) terbukti menangani data sensitif |

**Contoh bukti (ilustratif — MASTG belum menyediakan demo resmi untuk test ini):**

```
[*] WebView.loadUrl(file:///android_asset/document_viewer.html)
    JavaScriptEnabled: true
    AllowContentAccess: true
    AllowUniversalAccessFromFileURLs: true
    [!] KONDISI BERISIKO: file:// dimuat dengan universal access aktif!
    Stack trace:
        at com.example.target.ui.DocumentViewerActivity.setupWebView(DocumentViewerActivity.java:58)
        at com.example.target.ui.DocumentViewerActivity.onCreate(DocumentViewerActivity.java:32)
```

Interpretasi: ketiga kondisi terkonfirmasi `true` secara runtime pada WebView yang memuat `file://`, dengan lokasi kode presisi dari stack trace. Langkah berikutnya: verifikasi MASTG-TECH-0023 pada `DocumentViewerActivity` untuk menilai apakah ia menangani dokumen sensitif pengguna, dan periksa daftar content provider aplikasi (MASTG-TEST-0250) untuk data yang berpotensi terekspos.

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi |
|---|---|
| P1 | Tidak ada instance WebView yang menunjukkan ketiga nilai `true` secara bersamaan selama sesi pengujian menyeluruh |
| P2 | Ditemukan kombinasi berisiko, tapi terkonfirmasi (MASTG-TECH-0023) WebView tersebut **tidak pernah** memuat konten `file://`/tidak tepercaya, atau tidak menangani fungsi/data sensitif |
| P3 | Validasi cakupan interaksi memadai (aplikasi dijelajahi menyeluruh termasuk alur sensitif) dan tetap tidak ditemukan kombinasi berisiko |

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Hasil kosong menuntut validasi cakupan interaksi terlebih dahulu**, sesuai pola berulang di seluruh test dinamis dalam seri ini — WebView yang jarang dimuat (fitur bantuan, viewer dokumen yang jarang dipakai) berisiko tidak terpicu bila sesi pengujian tidak menyeluruh.

2. **Manfaatkan Metode D (korelasi dengan `loadUrl`) sebagai metode utama** — ini yang paling efisien menjawab ketiga lapis klausul "Further Validation Required" resmi sekaligus dalam satu titik pengamatan.

3. **Jangan berhenti di level nilai boolean saja** — klausul resmi eksplisit menuntut penilaian **konteks** (WebView mana, memuat apa, menangani data apa). Laporan yang hanya mencantumkan "ditemukan JavaScriptEnabled=true, AllowContentAccess=true, AllowUniversalAccessFromFileURLs=true" tanpa konteks ini belum memenuhi standar evaluasi resmi test ini.

4. **Korelasikan selalu dengan hasil MASTG-TEST-0250** — kedua test saling melengkapi: statis memberi peta kandidat lokasi lengkap (termasuk yang tidak tereksekusi saat pengujian dinamis), dinamis memberi konfirmasi nilai efektif nyata dan konteks eksekusi presisi.

5. **Severity mengikuti pola yang sama seperti dokumen MASTG-TEST-0250** — dimodulasi oleh sensitivitas data content provider dan apakah dikombinasikan dengan exported Activity yang menerima URL eksternal tanpa validasi.

6. **Dokumentasikan:** nilai ketiga pengaturan per instance WebView, backtrace lokasi konfigurasi, URL yang dimuat pada momen pengamatan, hasil analisis MASTG-TECH-0023 terhadap konteks dan sensitivitas WebView tersebut, dan cakupan interaksi aplikasi yang sudah dilakukan.

---

## 4. Rekomendasi Perbaikan

Karena akar masalah dan solusi teknisnya identik dengan MASTG-TEST-0250 (weakness yang sama, MASWE-0034), rujuk **dokumen MASTG-TEST-0250 §4** untuk rekomendasi implementasi lengkap (nonaktifkan content access, nonaktifkan universal access, migrasi ke `WebViewAssetLoader`, perkuat konfigurasi content provider).

Tambahan spesifik dari sudut pandang dinamis:

### 4.1 Integrasikan Hooking ke Regression Test Otomatis

```bash
#!/bin/bash
# ci-dynamic-webview-content-check.sh
frida -U -f com.target.app -l hook-webview-loadurl-correlated.js --no-pause &
FRIDA_PID=$!
sleep 5
./run-ui-test-suite.sh --scenario=document-viewer,help-center,payment-portal
kill $FRIDA_PID
```

### 4.2 Checklist Remediasi

- [ ] Hooking mencakup kedua pendekatan resmi (setter + enumerasi instance), idealnya via Metode D yang menyatukan keduanya
- [ ] Interaksi pengujian sudah mencakup seluruh WebView yang ada di aplikasi (termasuk yang jarang dimuat)
- [ ] Setiap temuan kombinasi berisiko sudah ditinjau MASTG-TECH-0023 untuk konteks dan sensitivitas
- [ ] Hasil dikorelasikan dengan temuan MASTG-TEST-0250 (statis) dan daftar content provider
- [ ] **Verifikasi ulang:** jalankan kembali MASTG-TEST-0251 setelah perubahan pada implementasi WebView

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0251: Runtime Use of Content Provider Access APIs in WebViews](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0251/)
- [MASTG-TEST-0250: References to Content Provider Access in WebViews](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0250/)
- [MASWE-0034: WebViews Allow Access to Local Resources with Untrusted Content](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0034/)
- [MASTG-KNOW-0018: WebViews](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0018/)
- [MASTG-TECH-0005: Installing Apps](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0005/)
- [MASTG-TECH-0043: Method Hooking](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0043/)
- [MASTG-TECH-0023: Reviewing Decompiled Java Code](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0023/)

### 5.2 Dokumentasi Resmi Android

- [Android Developers — `WebSettings` API reference](https://developer.android.com/reference/android/webkit/WebSettings)
- [Android Developers — `WebView` API reference](https://developer.android.com/reference/android/webkit/WebView)

### 5.3 Dokumentasi Tools

- [Frida — Dynamic instrumentation toolkit](https://frida.re/docs/javascript-api/)
- [Frida — `Java.choose()` API reference](https://frida.re/docs/javascript-api/#java)
- [frida-trace — Documentation](https://frida.re/docs/frida-trace/)
- [Objection — Runtime Mobile Exploration toolkit](https://github.com/sensepost/objection)
- [LSPosed Framework](https://github.com/LSPosed/LSPosed)

---

*Dokumen ini disusun berdasarkan OWASP MASTG (rilis terkini per September 2026) dan dokumentasi resmi Android Developers. Sebagai counterpart dinamis langsung dari MASTG-TEST-0250, konteks konseptual mendalam tentang risiko `setAllowContentAccess`/`setAllowUniversalAccessFromFileURLs` dibahas lengkap di dokumen tersebut. Nilai unik test ini: dua pendekatan hooking yang saling melengkapi (setter vs enumerasi instance), penyederhanaan otomatis ambiguitas "eksplisit vs default" yang ada pada analisis statis, dan klausul validasi lanjutan tiga lapis (konfigurasi, identitas WebView, konteks muatan) yang lebih rinci dibanding versi statisnya.*
