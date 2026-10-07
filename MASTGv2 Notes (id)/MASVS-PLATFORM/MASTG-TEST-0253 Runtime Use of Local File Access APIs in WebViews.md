# MASTG-TEST-0253 Runtime Use of Local File Access APIs in WebViews

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0253 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-PLATFORM (MASVS-PLATFORM-2) |
| **Weakness** | MASWE-0034 — *WebViews Allow Access to Local Resources with Untrusted Content* |
| **API yang disorot** | `WebView`, `WebSettings`, `getSettings`, `setAllowFileAccess`, `setAllowFileAccessFromFileURLs`, `setAllowUniversalAccessFromFileURLs` |
| **Tipe Pengujian** | **Dynamic, Hooks, Manual** |
| **Profile** | L1, L2 |
| **Knowledge** | MASTG-KNOW-0018 (WebViews) |
| **Best Practice** | MASTG-BEST-0010, MASTG-BEST-0011, MASTG-BEST-0012 |
| **Teknik terkait** | MASTG-TECH-0005, MASTG-TECH-0043, MASTG-TECH-0023 |
| **Test terkait** | **MASTG-TEST-0252** (counterpart statis; overview resmi menyatakan eksplisit *"This test is the dynamic counterpart to MASTG-TEST-0252"*) |
| **Demo terkait** | — (tidak ada) |
| **Rule resmi** | — (tidak relevan; test dinamis) |
| **CWE terkait** | CWE-200, CWE-668 |

---

## 1. Penjelasan

### 1.1 Hubungan dengan MASTG-TEST-0252

Seluruh konteks konseptual mendalam — perbedaan default berbasis `minSdkVersion` untuk ketiga API, mengapa "ketiadaan referensi" justru mencurigakan, interaksi antara `setAllowFileAccessFromFileURLs`/`setAllowUniversalAccessFromFileURLs`, dan nuansa *blind exfiltration* (data tetap terkirim meski pembacaan respons diblokir CORS) — **sudah dibahas lengkap di dokumen MASTG-TEST-0252**. Dokumen ini fokus pada nilai tambah unik pendekatan dinamis, sekaligus satu keterbatasan metodologis penting yang **khas untuk test ini** dan tidak muncul pada pasangan MASTG-TEST-0250/0251.

### 1.2 Dua Pendekatan Hooking yang Identik Strukturnya dengan MASTG-TEST-0251

Overview resmi menawarkan dua pendekatan yang sama persis strukturnya dengan MASTG-TEST-0251 (dynamic counterpart MASTG-TEST-0250): enumerasi instance WebView, atau hooking setter langsung. Rujuk dokumen MASTG-TEST-0251 §1.2 untuk pembahasan trade-off keduanya — analisis yang sama berlaku penuh di sini, hanya berbeda pada API spesifik yang di-hook (`setAllowFileAccess`, `setAllowFileAccessFromFileURLs`, `setAllowUniversalAccessFromFileURLs` alih-alih `setAllowContentAccess`).

### 1.3 Keterbatasan Metodologis Khas Test Ini: Versi OS Device Uji ≠ `minSdkVersion` Aplikasi

Ini adalah nuansa **paling penting dan unik** dari test dinamis ini dibanding MASTG-TEST-0251 — muncul justru karena klausul Evaluation resmi test ini **tetap mempertahankan referensi ke `minSdkVersion`** meski sudah berpindah ke ranah dinamis:

> *"`setAllowFileAccess` is explicitly set to `true` (or not used at all when `minSdkVersion` < 30, inheriting the default value, `true`)."*

Ingat kembali nuansa yang dibahas di dokumen MASTG-TEST-0251 §1.3: pada pengujian dinamis MASTG-TEST-0251, ambiguitas "eksplisit vs default" **melebur sepenuhnya** karena `getAllowContentAccess()` selalu mengembalikan nilai efektif tunggal (`true`) di **semua** versi Android tanpa pengecualian. **Hal serupa TIDAK sepenuhnya berlaku di sini** — karena default ketiga API pada test ini **bergantung pada versi OS aktual**, bukan konstanta tunggal seperti `setAllowContentAccess`.

Konsekuensinya, hasil enumerasi/hooking dinamis pada test ini **hanya mencerminkan perilaku pada satu versi OS spesifik**, yaitu **versi OS device/emulator yang dipakai untuk pengujian** — bukan `minSdkVersion` aplikasi yang sesungguhnya ingin dievaluasi klausul resmi. Ini menciptakan potensi kesalahan interpretasi yang serius:

| Skenario | Konsekuensi |
|---|---|
| Aplikasi memiliki `minSdkVersion=21`, tapi diuji pada emulator Android 14 (API 34) | Hasil `getAllowFileAccess()` akan menunjukkan `false` (default modern) — **menyembunyikan** fakta bahwa pengguna nyata dengan device Android 5-10 (API 21-29) akan mengalami default `true` yang insecure |
| Aplikasi memiliki `minSdkVersion=30`, diuji pada emulator API level berapa pun ≥30 | Hasil pengujian dinamis **konsisten dan valid** merepresentasikan seluruh populasi pengguna, karena tidak ada device nyata di bawah ambang default aman |

Ini artinya **kesimpulan PASS dari pengujian dinamis semata, tanpa memperhitungkan `minSdkVersion` aplikasi, bisa menjadi false negative yang signifikan** bila device uji memakai OS lebih baru dari `minSdkVersion` aplikasi (skenario yang sangat umum, karena kebanyakan device uji/emulator modern menjalankan Android versi terbaru secara default).

### 1.4 Implikasi Metodologis: Uji Multi-Versi Android, Bukan Cukup Satu Device

Nuansa §1.3 membawa konsekuensi metodologis konkret: untuk mendapat kesimpulan yang benar-benar valid sesuai klausul resmi, pengujian dinamis test ini **idealnya dijalankan di lebih dari satu versi Android** — khususnya menyertakan **emulator dengan API level mendekati `minSdkVersion` aplikasi** (diperoleh dari hasil statis MASTG-TEST-0252), bukan hanya emulator/device versi terbaru yang kebetulan tersedia. Bila keterbatasan sumber daya membuat pengujian multi-versi tidak memungkinkan, penguji **wajib** mendokumentasikan versi OS device uji secara eksplisit dan secara terpisah mengonfirmasi hasil statis `minSdkVersion` (MASTG-TEST-0252) sebagai pelengkap kesimpulan — bukan mengandalkan hasil dinamis single-device sebagai jawaban final yang berdiri sendiri.

### 1.5 Klausul "Further Validation Required" — Fokus pada Konteks `file://` Secara Spesifik

Klausul validasi lanjutan resmi test ini punya penekanan spesifik dibanding versi content-provider-nya (MASTG-TEST-0251):

> *"Determine whether that `WebView` loads local `file://` content, for example via `loadUrl("file://...")` or `loadDataWithBaseURL` with a `file://` base URL."*

Ini secara eksplisit menyebut **dua** mekanisme pemuatan konten yang relevan — bukan hanya `loadUrl()` seperti pola umum, tapi juga **`loadDataWithBaseURL`** dengan `file://` sebagai base URL, sebuah pola yang sering dipakai untuk memuat HTML yang **dibangun secara dinamis di kode Java/Kotlin** (bukan file HTML statis) namun tetap diberi konteks origin `file://`. Instrumentasi hooking test ini **wajib mencakup kedua API pemuatan** ini agar tidak melewatkan salah satu jalur.

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | Fungsi |
|---|---|
| **Frida** | Instrumentasi dinamis inti |
| **frida-tools** (`frida-trace`) | Tracing cepat |
| **objection** | Wrapper Frida siap pakai |
| **Emulator dengan beberapa image API level berbeda** | **Wajib** sesuai §1.4 — minimal mencakup API level mendekati `minSdkVersion` aplikasi dan API level modern untuk perbandingan |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **Android Virtual Device (AVD) Manager / Genymotion** | Menyediakan berbagai image API level untuk pengujian multi-versi (§1.4) |
| **Xposed/LSPosed** | Alternatif hooking persisten |
| **adb logcat** | Bukti diagnostik CORS block sesuai pola yang dibahas di dokumen MASTG-TEST-0252 §1.5 |
| **Burp Suite/mitmproxy** | Mengamati eksfiltrasi nyata saat PoC dijalankan |

### 2.3 Prasyarat Lingkungan

- **Wajib device/emulator dengan Frida server** — test murni dinamis.
- **Idealnya siapkan minimal dua image emulator**: satu mendekati `minSdkVersion` aplikasi (hasil MASTG-TEST-0252), satu versi modern — untuk memvalidasi konsistensi/perbedaan perilaku sesuai §1.3-§1.4.
- **Interaksi menyeluruh** mencakup seluruh WebView, termasuk yang dimuat lewat `loadDataWithBaseURL` (§1.5).

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0005** untuk menginstal aplikasi.
2. Gunakan **MASTG-TECH-0043** untuk hooking API yang relevan.
3. Jelajahi aplikasi secara menyeluruh, masukkan data sensitif di mana pun memungkinkan.

### 3.2 Metode A — Hooking Setter + Pemuatan Konten Sekaligus *(mencakup kedua mekanisme §1.5)*

```javascript
// hook-local-file-access-webview.js
Java.perform(function () {
    function getBacktrace() {
        return Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());
    }

    var WebSettings = Java.use("android.webkit.WebSettings");
    ["setJavaScriptEnabled", "setAllowFileAccess", "setAllowFileAccessFromFileURLs", "setAllowUniversalAccessFromFileURLs"]
        .forEach(function (method) {
            try {
                WebSettings[method].overload("boolean").implementation = function (value) {
                    console.log("\n[*] WebSettings." + method + "(" + value + ")");
                    console.log("    Backtrace:\n" + getBacktrace());
                    return this[method](value);
                };
            } catch (e) { console.log("[x] Hook gagal untuk " + method + ": " + e); }
        });

    // Cakupan mekanisme #1: loadUrl
    var WebView = Java.use("android.webkit.WebView");
    WebView.loadUrl.overload("java.lang.String").implementation = function (url) {
        if (url.indexOf("file://") === 0) {
            var s = this.getSettings();
            console.log("\n[*] WebView.loadUrl(FILE) = " + url);
            console.log("    JavaScriptEnabled=" + s.getJavaScriptEnabled() +
                " AllowFileAccess=" + s.getAllowFileAccess() +
                " AllowFileAccessFromFileURLs(deprecated getter mungkin tak tersedia)" +
                " AllowUniversalAccessFromFileURLs=" + s.getAllowUniversalAccessFromFileURLs());
        }
        return this.loadUrl(url);
    };

    // Cakupan mekanisme #2: loadDataWithBaseURL dengan base URL file://
    WebView.loadDataWithBaseURL.overload(
        "java.lang.String", "java.lang.String", "java.lang.String", "java.lang.String", "java.lang.String"
    ).implementation = function (baseUrl, data, mimeType, encoding, historyUrl) {
        if (baseUrl && baseUrl.indexOf("file://") === 0) {
            console.log("\n[*] WebView.loadDataWithBaseURL dengan file:// base URL: " + baseUrl);
            console.log("    Backtrace:\n" + getBacktrace());
        }
        return this.loadDataWithBaseURL(baseUrl, data, mimeType, encoding, historyUrl);
    };
});
```

```bash
frida -U -f com.target.app -l hook-local-file-access-webview.js --no-pause
```

### 3.3 Metode B — Enumerasi Instance WebView

```javascript
// enumerate-webview-file-access.js
Java.perform(function () {
    Java.choose("android.webkit.WebView", {
        onMatch: function (instance) {
            var settings = instance.getSettings();
            console.log("\n[*] Instance WebView:");
            console.log("    URL saat ini: " + instance.getUrl());
            console.log("    JavaScriptEnabled: " + settings.getJavaScriptEnabled());
            console.log("    AllowFileAccess: " + settings.getAllowFileAccess());
            console.log("    AllowUniversalAccessFromFileURLs: " + settings.getAllowUniversalAccessFromFileURLs());
        },
        onComplete: function () {}
    });
});
```

### 3.4 Metode C — Pengujian Multi-Versi Android *(menjawab keterbatasan §1.3-§1.4, WAJIB)*

```bash
# 1. Identifikasi minSdkVersion dari hasil MASTG-TEST-0252
MINSDK=21  # contoh, hasil ekstraksi statis

# 2. Buat/gunakan emulator dengan API level SETARA/MENDEKATI minSdkVersion
avdmanager create avd -n test-minsdk -k "system-images;android-${MINSDK};google_apis;x86_64"
emulator -avd test-minsdk &
frida -U -f com.target.app -l hook-local-file-access-webview.js --no-pause
# Jelajahi menyeluruh, catat hasil

# 3. Bandingkan dengan emulator versi modern
avdmanager create avd -n test-modern -k "system-images;android-34;google_apis;x86_64"
emulator -avd test-modern &
frida -U -f com.target.app -l hook-local-file-access-webview.js --no-pause
# Jelajahi menyeluruh dengan skenario SAMA, catat hasil
```

Bandingkan kedua hasil — bila terdapat **instance WebView tanpa pemanggilan eksplisit `setAllowFileAccess`**, hasil pada emulator `minSdkVersion` akan menunjukkan `AllowFileAccess: true` sementara pada emulator modern menunjukkan `AllowFileAccess: false` — perbedaan ini **membuktikan langsung** risiko yang dijelaskan §1.3, dan mengonfirmasi bahwa kesimpulan PASS dari device modern semata akan menyesatkan.

### 3.5 Metode D — objection

```bash
objection -g com.target.app explore
android hooking watch class_method android.webkit.WebSettings.setAllowFileAccess --dump-args --dump-backtrace
android hooking watch class_method android.webkit.WebView.loadDataWithBaseURL --dump-args --dump-backtrace
```

### 3.6 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Menjawab keterbatasan versi OS? | Kapan dipakai |
|---|---|---|---|
| **A** | Hook setter + loadUrl/loadDataWithBaseURL | ❌ (single device) | Baseline utama, satu sesi |
| **B** | Enumerasi instance | ❌ (single device) | Nilai efektif akhir, satu sesi |
| **C** | Multi-versi emulator | ✅ | **Wajib** untuk kesimpulan yang benar-benar valid sesuai klausul resmi |
| **D** | objection | ❌ (single device) | Eksplorasi cepat |

**Kombinasi minimum yang aku rekomendasikan:** **A (hooking komprehensif mencakup loadUrl + loadDataWithBaseURL) dijalankan pada minimal dua versi OS berbeda sesuai Metode C** — ini satu-satunya cara pengujian dinamis test ini benar-benar merepresentasikan klausul resmi yang eksplisit menyebut ambang `minSdkVersion`.

---

### 3.7 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG:** identik strukturnya dengan MASTG-TEST-0252 (lihat dokumen tersebut §1.4 untuk rincian penuh logika bersyarat tiga kondisi), dengan klausul **Further Validation Required** tambahan yang menuntut penelusuran `loadUrl("file://...")`/`loadDataWithBaseURL` dan penilaian apakah JavaScript yang dikendalikan penyerang dapat berjalan dalam konteks tersebut.

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi |
|---|---|
| F1 | Ketiga kondisi resmi terpenuhi **pada versi OS yang relevan dengan `minSdkVersion` aplikasi** (bukan hanya versi device uji yang kebetulan dipakai) |
| F2 | Backtrace `loadUrl`/`loadDataWithBaseURL` mengonfirmasi WebView memuat konten dengan basis `file://` |
| F3 | Terkonfirmasi (MASTG-TECH-0023) ada jalur di mana JavaScript yang tidak tepercaya (HTML injection, konten yang dapat dimanipulasi) dapat berjalan dalam konteks `file://` tersebut |
| F4 | WebView yang terpengaruh menangani informasi/fungsi sensitif |

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi |
|---|---|
| P1 | Pengujian multi-versi (Metode C) mengonfirmasi tidak ada kombinasi kondisi FAIL pada **versi OS manapun** yang relevan dengan `minSdkVersion` aplikasi |
| P2 | WebView yang memuat `file://` terkonfirmasi hanya memuat konten tepercaya penuh (aset internal aplikasi, tanpa jalur injeksi) |
| P3 | Ketiga API diset eksplisit `false` terlepas dari versi OS yang menjalankannya |

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Ini catatan terpenting di seluruh dokumen ini: pengujian pada satu device/emulator saja TIDAK CUKUP untuk test ini**, berbeda dari kebanyakan test dinamis lain dalam seri riset ini. Sesuai §1.3-§1.4, hasil PASS dari device modern semata bisa jadi **false negative** yang menyembunyikan risiko nyata pada populasi pengguna dengan device lawas sesuai `minSdkVersion` aplikasi.

2. **Selalu sandingkan hasil dinamis dengan `minSdkVersion` dari MASTG-TEST-0252** — dua test ini lebih saling bergantung dibanding pasangan MASTG-TEST-0250/0251, karena versi statis-lah yang memberi angka `minSdkVersion` yang menentukan emulator mana yang wajib dipakai untuk pengujian dinamis yang valid.

3. **Cakupan instrumentasi harus mencakup `loadDataWithBaseURL`, bukan hanya `loadUrl`** — sesuai §1.5, ini disebut eksplisit di klausul resmi dan mudah terlewat bila hanya meniru pola hooking dari MASTG-TEST-0251.

4. **Dokumentasikan versi OS setiap sesi pengujian secara eksplisit** — laporan yang tidak mencantumkan versi Android device uji tidak dapat dinilai validitasnya terhadap klausul resmi yang bergantung pada ambang API level.

5. **Severity mengikuti pola yang sama seperti dokumen MASTG-TEST-0252** — dimodulasi oleh sensitivitas WebView dan kemungkinan nyata injeksi konten tidak tepercaya ke dalam konteks `file://`.

6. **Dokumentasikan:** versi OS setiap sesi pengujian, hasil per versi (untuk perbandingan eksplisit), backtrace lokasi `loadUrl`/`loadDataWithBaseURL`, dan hasil analisis MASTG-TECH-0023 terhadap potensi injeksi konten.

---

## 4. Rekomendasi Perbaikan

Rujuk **dokumen MASTG-TEST-0252 §4** untuk rekomendasi implementasi lengkap yang identik (nonaktifkan eksplisit ketiga API, migrasi ke `WebViewAssetLoader`, naikkan `minSdkVersion`).

Tambahan khusus dari sudut pandang dinamis:

### 4.1 Integrasikan Pengujian Multi-Versi ke CI/CD

```bash
#!/bin/bash
# ci-multi-version-webview-check.sh
for AVD in "test-minsdk" "test-modern"; do
    emulator -avd "$AVD" &
    sleep 30
    frida -U -f com.target.app -l hook-local-file-access-webview.js --no-pause &
    FRIDA_PID=$!
    sleep 5
    ./run-ui-test-suite.sh
    kill $FRIDA_PID
    adb emu kill
done
```

### 4.2 Checklist Remediasi

- [ ] Pengujian dinamis dijalankan pada minimal dua versi OS (mendekati `minSdkVersion` dan versi modern)
- [ ] Hooking mencakup `loadUrl` dan `loadDataWithBaseURL` sekaligus
- [ ] Hasil dikorelasikan dengan `minSdkVersion` dari MASTG-TEST-0252
- [ ] Setiap temuan sudah ditinjau MASTG-TECH-0023 untuk potensi injeksi konten tidak tepercaya
- [ ] **Verifikasi ulang:** jalankan kembali MASTG-TEST-0253 pada setiap versi OS relevan setelah perubahan implementasi WebView

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0253: Runtime Use of Local File Access APIs in WebViews](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0253/)
- [MASTG-TEST-0252: References to Local File Access in WebViews](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0252/)
- [MASTG-TEST-0251: Runtime Use of Content Provider Access APIs in WebViews](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0251/)
- [MASWE-0034: WebViews Allow Access to Local Resources with Untrusted Content](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0034/)
- [MASTG-KNOW-0018: WebViews](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0018/)
- [MASTG-TECH-0005, MASTG-TECH-0043, MASTG-TECH-0023](https://mas.owasp.org/MASTG/techniques/android/)

### 5.2 Dokumentasi Resmi Android

- [Android Developers — `WebView#loadDataWithBaseURL`](https://developer.android.com/reference/android/webkit/WebView#loadDataWithBaseURL(java.lang.String,%20java.lang.String,%20java.lang.String,%20java.lang.String,%20java.lang.String))
- [Android Developers — `WebSettings` API reference](https://developer.android.com/reference/android/webkit/WebSettings)
- [Android Developers — Managing Virtual Devices (AVD)](https://developer.android.com/studio/run/managing-avds)

### 5.3 Dokumentasi Tools

- [Frida — Dynamic instrumentation toolkit](https://frida.re/docs/javascript-api/)
- [Objection — Runtime Mobile Exploration toolkit](https://github.com/sensepost/objection)
- [Android SDK — `avdmanager` command-line tool](https://developer.android.com/tools/avdmanager)

---

*Dokumen ini disusun berdasarkan OWASP MASTG (rilis terkini per September 2026) dan dokumentasi resmi Android Developers. Sebagai counterpart dinamis dari MASTG-TEST-0252, konteks konseptual mendalam dibahas lengkap di dokumen tersebut. Temuan metodologis terpenting dokumen ini: berbeda dari pasangan MASTG-TEST-0250/0251, test ini menuntut pengujian pada **lebih dari satu versi Android** — karena klausul evaluasinya tetap bergantung pada ambang `minSdkVersion` yang tidak dapat direpresentasikan hanya lewat satu sesi pengujian dinamis pada device/emulator tunggal, apa pun versi OS yang kebetulan dipakai penguji.*
