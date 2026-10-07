# MASTG-TEST-0400 Runtime Use of WebViewClient URL Loading Handlers

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0400 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-CODE |
| **Weakness** | MASWE-0035 |
| **Tipe Pengujian** | Dynamic, Hooks, **Manual** |
| **API terkait** | `WebView`, `WebViewClient`, `shouldOverrideUrlLoading`, `shouldInterceptRequest`, `Uri`, `getHost`, `getScheme`, `getPath` |
| **Teknik terkait** | MASTG-TECH-0005, MASTG-TECH-0043, MASTG-TECH-0023 |
| **Knowledge terkait** | MASTG-KNOW-0018 (WebViews) |
| **Test terkait** | **MASTG-TEST-0398** — counterpart statis yang sudah dibahas mendalam dalam seri riset ini; test ini adalah **konfirmasi runtime langsung** |
| **Rule resmi** | — (tidak ada; murni dinamis) |

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian dan Nilai Tambah Dibanding Analisis Statis

Kutipan overview resmi MASTG:

> *"This test dynamically analyzes the runtime behavior of WebViewClient URL interception methods... By hooking relevant methods at runtime, you can observe: Which URLs are being loaded and intercepted. How the app validates or filters URLs. Whether the app implements allowlist or denylist patterns. What decisions the app makes when encountering different URL schemes or domains."*

Ini adalah pasangan dinamis dari **MASTG-TEST-0398** yang sudah dibahas mendalam dalam seri riset ini. Nilai tambah dinamis di sini sangat konkret dan praktis: alih-alih **membaca** logika validasi di kode terdekompilasi dan **menyimpulkan** secara manual apakah ia memakai substring check atau host parsing yang benar (seperti pendekatan di TEST-0398), test ini memungkinkan penguji **langsung mencoba** URL berbahaya yang dirancang khusus dan **mengamati hasil keputusan sesungguhnya** (`true`/`false` yang dikembalikan method) secara empiris — menghilangkan ambiguitas interpretasi kode yang mungkin rumit atau terobfuskasi.

### 1.2 Observasi yang Diminta: URL, Keputusan, dan Operasi Parsing

Bagian Observation resmi secara spesifik meminta tiga jenis data:

> *"A list of URLs that were intercepted... The return values of these methods (indicating whether the URL was allowed or blocked). Any URL parsing operations performed using Uri methods."*

Poin ketiga ini penting — mengamati **operasi parsing `Uri`** (`getHost()`, `getScheme()`, `getPath()`) secara terpisah dari sekadar URL dan keputusan akhir memungkinkan penguji melihat **bagaimana** validasi dilakukan, bukan hanya **apa** hasilnya. Bila hook menunjukkan bahwa `getHost()` **tidak pernah dipanggil** sama sekali untuk suatu URL yang tetap diizinkan, ini mengindikasikan validasi yang dipakai kemungkinan memang berbasis substring mentah terhadap string URL, bukan parsing host yang benar — persis kelemahan CWE-346 yang sudah dibahas mendalam di dokumen TEST-0398.

### 1.3 Kriteria Evaluasi: Berfokus pada Hasil Nyata, Bukan Pola Kode

> **Evaluation:** *"The test case fails if the runtime analysis shows that a URL is loaded or a resource request is served without the app validating it against trusted content."*

Perbedaan penting dengan TEST-0398: evaluasi di sini murni berdasarkan **apa yang benar-benar terjadi** saat URL uji dicoba, bukan penilaian terhadap pola kode. Ini berarti bahkan bila kode tampak rumit/terobfuskasi sehingga analisis statis sulit menyimpulkan apakah validasinya benar, test dinamis tetap bisa memberi jawaban definitif: coba URL berbahaya, amati apakah benar-benar diblokir atau diizinkan.

### 1.4 Penegasan Ulang: Intercepting Bukan Masalah, Implementasinya yang Dinilai

> *"Note that intercepting URL loading is not inherently insecure. The test fails only when the implementation does not properly restrict navigation to trusted content."*

Prinsip ini identik dengan yang sudah ditegaskan di dokumen TEST-0398 — baik secara statis maupun dinamis, intervensi kustom terhadap navigasi WebView bukan masalah intrinsik; yang dinilai adalah **efektivitas** pembatasannya.

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | Fungsi |
|---|---|
| **Frida** | Hooking `shouldOverrideUrlLoading`/`shouldInterceptRequest`/method `Uri` untuk observasi runtime (MASTG-TECH-0043) |
| **ADB** | Instalasi app, memicu navigasi WebView dengan deep link uji (MASTG-TECH-0005) |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **Server HTTP lokal/uji (mitmproxy sebagai web server)** | Menghosting halaman uji yang berisi link ke berbagai URL rancangan (termasuk payload bypass substring) untuk dipicu secara alami lewat interaksi WebView |

### 2.3 Prasyarat Lingkungan

- Device rooted/emulator dengan `frida-server`.
- Daftar payload URL uji yang dirancang untuk menguji celah validasi (lihat §3.3), termasuk variasi yang persis mereplikasi pola CWE-346 dari dokumen TEST-0398.

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0005** untuk instalasi aplikasi.
2. Gunakan **MASTG-TECH-0043** untuk hook API yang relevan.
3. Exercise aplikasi secara ekstensif untuk memicu sebanyak mungkin alur dan masukkan data sensitif.

### 3.2 Metode A — Frida: Hook Lengkap dengan Observasi Keputusan dan Parsing Uri

```javascript
Java.perform(function () {
    var WebViewClient = Java.use("android.webkit.WebViewClient");

    WebViewClient.shouldOverrideUrlLoading.overload(
        'android.webkit.WebView', 'android.webkit.WebResourceRequest'
    ).implementation = function (view, request) {
        var url = request.getUrl().toString();
        var result = this.shouldOverrideUrlLoading(view, request);
        console.log("[shouldOverrideUrlLoading] url=" + url + " -> result(override)=" + result +
            " (false berarti WebView TETAP memuat URL ini)");
        return result;
    };

    var Uri = Java.use("android.net.Uri");
    Uri.getHost.implementation = function () {
        var host = this.getHost();
        console.log("[Uri.getHost] dipanggil -> " + host);
        return host;
    };
});
```

```bash
frida -U -f com.example.targetapp -l hook_webviewclient.js --no-pause
```

### 3.3 Metode B — Pengujian Aktif dengan Payload URL Rancangan (Replikasi CWE-346)

Siapkan halaman HTML uji yang memuat link-link berikut, atau picu langsung via deep link bila WebView menerima navigasi dari luar:

```
https://trusted-domain.com.evil.com/phishing
https://evil.com/?redirect=trusted-domain.com
https://trusted-domain.com@evil.com/
```

Amati hasil hook Metode A untuk tiap payload — apakah `shouldOverrideUrlLoading` mengembalikan `false` (mengizinkan navigasi) untuk URL yang **seharusnya** diblokir?

### 3.4 Metode C — Verifikasi Jangkauan Terbatas Method (Sesuai Nuansa TEST-0398 §1.2)

```html
<!-- Halaman uji yang memuat iframe ke domain tidak tepercaya -->
<iframe src="https://evil.com/malicious-content"></iframe>
```

Amati apakah hook `shouldOverrideUrlLoading`/`shouldInterceptRequest` **sama sekali tidak terpicu** untuk konten iframe ini — mengonfirmasi secara empiris keterbatasan jangkauan yang sudah dibahas di TEST-0398, dan menunjukkan bahwa validasi yang kuat pada navigasi utama tidak melindungi dari jalur ini.

### 3.5 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Kapan dipakai |
|---|---|---|
| **A** | Frida hooking | Baseline wajib — observasi pasif |
| **B** | Payload URL rancangan | **Wajib** — bukti konklusif celah substring bypass |
| **C** | Payload iframe | Konfirmasi keterbatasan jangkauan method |

**Kombinasi minimum yang aku rekomendasikan:** **A + B (wajib)**, dengan **C** sebagai pelengkap untuk audit menyeluruh.

---

### 3.6 Kriteria Evaluasi: Positive Case & Negative Case

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi |
|---|---|
| F1 | URL berbahaya (payload rancangan §3.3) diamati diizinkan (`shouldOverrideUrlLoading` mengembalikan `false`/navigasi tetap terjadi) meski seharusnya ditolak |

**Contoh bukti (replikasi langsung CWE-346 dari TEST-0398):**

```
[shouldOverrideUrlLoading] url=https://trusted-domain.com.evil.com/phishing -> result(override)=false (navigasi DIIZINKAN)
[Uri.getHost] TIDAK PERNAH dipanggil untuk request ini
```

Interpretasi: URL phishing berhasil lolos, dan ketidakhadiran pemanggilan `getHost()` mengonfirmasi validasi memang berbasis substring mentah, bukan parsing host. **FAIL**.

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi |
|---|---|
| P1 | Seluruh payload URL berbahaya (§3.3) diamati diblokir (`shouldOverrideUrlLoading` mengembalikan `true`), **dan** |
| P2 | `Uri.getHost()` teramati dipanggil sebagai bagian dari logika validasi |

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Gunakan payload yang secara spesifik menguji celah substring** — payload acak tidak cukup; sesuai §3.3, payload harus dirancang menyerupai domain tepercaya secara tekstual namun berbeda host sesungguhnya.

2. **Korelasikan dengan hasil MASTG-TEST-0398** — bila statis menemukan pola substring check namun dinamis tidak sempat menguji payload yang relevan, hasil dinamis belum konklusif; sebaliknya bila dinamis sudah membuktikan bypass berhasil, ini bukti paling kuat yang bisa disertakan dalam laporan.

3. **Uji juga jalur iframe/XHR (Metode C)** — kegagalan hook terpicu di sini bukan bug script Frida, melainkan konfirmasi keterbatasan arsitektural method itu sendiri.

4. **Severity dimodulasi:** sama dengan kriteria TEST-0398 — tinggi bila bypass berhasil pada WebView yang memuat konten sensitif/kredensial, dengan bukti dinamis memberi tingkat keyakinan yang lebih tinggi untuk laporan dibanding temuan statis semata.

5. **Dokumentasikan:** payload URL yang dicoba, hasil keputusan tiap payload, apakah `getHost()`/`getScheme()` terpanggil, dan backtrace lokasi kode terkait.

---

## 4. Rekomendasi Perbaikan

Rekomendasi identik dengan pasangan statisnya (MASTG-TEST-0398) — gunakan host parsing dengan exact match, bukan substring check. Lihat dokumen tersebut untuk detail implementasi lengkap.

### Checklist Remediasi

- [ ] Seluruh payload uji URL (§3.3) terkonfirmasi diblokir setelah perbaikan
- [ ] `Uri.getHost()` terkonfirmasi dipanggil dan dipakai sebagai basis keputusan validasi
- [ ] Payload iframe/XHR diuji terpisah untuk menilai kebutuhan kontrol tambahan (CSP) di luar `WebViewClient`
- [ ] Hasil pengujian dinamis didokumentasikan sebagai bukti pendukung temuan statis MASTG-TEST-0398

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0400 (source, tests-beta)](https://github.com/OWASP/mastg/blob/master/tests-beta/android/MASVS-CODE/MASTG-TEST-0400.md)
- [MASTG-TEST-0398 (dokumen pasangan statis dalam seri riset ini)](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0398/)
- [MASTG-KNOW-0018: WebViews](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0018/)

### 5.2 Dokumentasi Tools

- [Frida — Dynamic Instrumentation Toolkit](https://frida.re/docs/home/)

---

*Dokumen ini disusun berdasarkan konten resmi OWASP MASTG (`tests-beta/android/MASVS-CODE/MASTG-TEST-0400.md`, `MASTG-KNOW-0018`), dilengkapi cross-reference mendalam dengan dokumen MASTG-TEST-0398 (pasangan statisnya) dalam seri riset ini yang sudah membahas kelemahan CWE-346 (validasi substring) secara mendalam. Nuansa metodologis terpenting: nilai tambah test dinamis ini adalah kemampuan **membuktikan secara empiris** apakah celah bypass substring benar-benar bisa dieksploitasi — dengan mencoba payload URL yang dirancang khusus (`trusted-domain.com.evil.com`) dan mengamati hasil keputusan sesungguhnya, alih-alih hanya menyimpulkan dari pembacaan kode statis yang mungkin ambigu. Mengamati pemanggilan (atau ketidakhadiran pemanggilan) `Uri.getHost()` memberi bukti tambahan tentang mekanisme validasi yang sesungguhnya dipakai aplikasi saat runtime.*
