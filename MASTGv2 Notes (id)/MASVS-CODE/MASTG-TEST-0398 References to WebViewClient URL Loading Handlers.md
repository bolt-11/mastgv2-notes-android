# MASTG-TEST-0398 References to WebViewClient URL Loading Handlers

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0398 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-CODE |
| **Weakness** | MASWE-0035 |
| **Tipe Pengujian** | Static, Code, **Manual** |
| **API terkait** | `WebView`, `WebViewClient`, `shouldOverrideUrlLoading`, `shouldInterceptRequest`, `setWebViewClient` |
| **Teknik terkait** | MASTG-TECH-0013, MASTG-TECH-0014, MASTG-TECH-0023 |
| **Knowledge terkait** | MASTG-KNOW-0018 (WebViews) |
| **Rule resmi** | `mastg-android-webview-url-handlers.yml` — dua rule, satu presence-based dan satu bonus untuk topik terkait, lihat §1.4 |

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian dan Baseline "Default Teraman"

Kutipan overview resmi MASTG:

> *"The default and safest behavior on Android is to let the default web browser open any link that the user clicks inside the WebView. However, this can be modified by configuring a WebViewClient with custom URL handling logic."*

Ini adalah poin awal yang penting — **tidak melakukan apa pun** (tidak mengganti `WebViewClient` default) sudah merupakan konfigurasi paling aman, karena navigasi otomatis diteruskan ke browser eksternal pengguna yang memiliki model keamanannya sendiri terpisah dari konteks aplikasi. Risiko muncul **justru ketika developer secara aktif mengintervensi** perilaku default ini — sebuah kasus di mana "melakukan lebih" (menambah kontrol kustom) bisa menciptakan risiko baru bila dilakukan tidak tepat, alih-alih mengurangi risiko seperti yang dimaksudkan.

### 1.2 Dua Method Interception dengan Jangkauan yang Berbeda dan Tidak Lengkap

Overview memberi detail teknis penting tentang **keterbatasan jangkauan** masing-masing method — ini bukan sekadar detail API, melainkan sumber risiko tersembunyi bila developer salah asumsi:

> *"`shouldOverrideUrlLoading`... Note that this method is **not called** for POST requests, XmlHttpRequests, iFrames, 'src' attributes in HTML, or `<script>` tags."*

> *"`shouldInterceptRequest`... This callback is invoked for various URL schemes... but **not** for `javascript:` or `blob:` URLs, or for assets accessed via `file:///android_asset/` or `file:///android_res/`."*

Ini adalah temuan yang sangat penting untuk evaluasi keamanan — seorang developer yang mengimplementasikan `shouldOverrideUrlLoading` dengan allowlist domain yang sempurna **masih bisa terlewat** bila halaman yang dimuat berisi `<iframe>` ke domain lain, request `XMLHttpRequest`/`fetch` ke endpoint berbahaya, atau tag `<script src="...">` — semua ini **tidak pernah melewati** method yang sudah dilindungi dengan baik tersebut. Validasi yang terlihat kuat pada satu method bisa memberi **ilusi keamanan** yang salah bila developer tidak menyadari jenis request lain yang sama sekali tidak tersaring.

### 1.3 Logika AND dalam Kriteria FAIL: Implementasi Harus Ada, Namun Juga Harus Benar

> **Evaluation:** *"The test case fails if a WebViewClient URL interception method is implemented without properly restricting navigation to trusted content."*

Struktur evaluasi ini secara implisit mengandung dua kondisi — method interception **harus ada** (bukan default kosong) **dan** implementasinya harus benar-benar membatasi navigasi secara efektif. Namun ada nuansa ketiga yang justru **membalik arah** biasa — bagian validasi lanjutan memperkenalkan kategori temuan yang unik:

> *"**Missing client implementation:** a WebViewClient is assigned to a WebView via setWebViewClient without overriding any interception method, leaving the default (unrestricted) navigation behavior in place for an app that intended to restrict it."*

Ini adalah kasus menarik — developer **memanggil** `setWebViewClient()` (menandakan **niat** untuk mengontrol perilaku WebView), namun **lupa** benar-benar mengoverride `shouldOverrideUrlLoading`/`shouldInterceptRequest` di dalamnya. Hasilnya: perilaku navigasi tetap **tidak terbatas** (sama seperti tidak melakukan apa-apa sesuai §1.1), **namun** developer kemungkinan **percaya** bahwa mereka sudah menerapkan kontrol — sebuah kesenjangan antara niat dan implementasi aktual yang bisa lolos review sekilas karena `setWebViewClient()` memang terlihat seperti langkah keamanan yang "sudah dilakukan".

### 1.4 Analisis Rule Resmi: Presence-Based Murni, Plus Rule Bonus untuk Topik Terkait

Rule pertama (`mastg-android-webviewclient-url-handlers`) bersifat **severity INFO**, konsisten dengan sifat test ini yang murni manual — rule hanya menandai **keberadaan** kelima pola API yang disebut di frontmatter (kelas yang extends `WebViewClient` dengan override method, pemanggilan method tersebut, dan `setWebViewClient`), **tanpa** mencoba menilai apakah implementasinya aman. Ini konsisten dengan pola "rule jujur" yang sudah ditemukan di beberapa test lain dalam seri riset ini (TEST-0394) — keterbatasan ini **diakui secara desain**, bukan kelemahan tersembunyi.

Rule kedua (`mastg-android-webviewclient-safebrowsing-whitelist`) menyasar topik yang **berdekatan namun berbeda** — penyesuaian Safe Browsing (`setSafeBrowsingWhitelist`, `onSafeBrowsingHit`) yang **tidak disebut sama sekali** di frontmatter `apis:` test ini. Ini kemungkinan adalah "rule bonus" yang dibundel dalam file YAML yang sama karena topiknya related (keduanya tentang kontrol navigasi WebView), namun secara ketat berada **di luar scope deklaratif** test MASTG-TEST-0398 — penguji sebaiknya memperlakukan temuan dari rule kedua sebagai informasi tambahan yang berguna, bukan sebagai bagian inti evaluasi test ini.

### 1.5 Bukti Nyata: CWE-346 — Kelemahan Validasi Substring yang Persis Disebut Evaluasi Resmi

Evaluasi resmi secara eksplisit menyebut pola kelemahan yang sangat spesifik:

> *"Weak validation: the method performs validation that does not reliably prevent navigation to untrusted domains (for example, substring checks instead of validating the host)."*

Riset keamanan mengonfirmasi bahwa pola ini sudah terdokumentasi sebagai kelemahan class CWE-346 (Origin Validation Error) yang nyata ditemukan pada aplikasi produksi:

> *"The vulnerability involves Android applications that intercept URL loading within a WebView and use substring checks like `url.substring(0,14).equalsIgnoreCase('examplescheme:')` for validation, without properly checking the URL origin... Because the application does not check the source, a malicious website loaded within this WebView has the same access to the API as a trusted site."*

Rekomendasi perbaikan yang terdokumentasi juga sangat spesifik dan langsung actionable:

> *"A more secure approach is to use `Uri.parse(url).getHost().equals(URL)` to properly extract and validate the host portion of the URL, rather than relying on simple substring checks."*

Ilustrasi mengapa substring check gagal: validasi seperti `url.contains("trusted-domain.com")` akan **salah meluluskan** URL berbahaya seperti `https://evil.com/?redirect=trusted-domain.com` atau `https://trusted-domain.com.evil.com/phishing` — keduanya mengandung string `"trusted-domain.com"` namun **host sesungguhnya** adalah domain milik penyerang. Hanya dengan mem-parse URL secara benar dan membandingkan **host** hasil parsing (bukan string mentah URL) validasi menjadi reliable.

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | Fungsi |
|---|---|
| **jadx** | Dekompilasi DEX → Java untuk review manual (MASTG-TECH-0013, MASTG-TECH-0023) |
| **Semgrep** + rule resmi | Lokasi cepat implementasi `WebViewClient` (MASTG-TECH-0014) |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **grep/ripgrep** | Mencari pola validasi substring (`contains`, `startsWith`, `endsWith`) di sekitar implementasi URL handler untuk triase cepat kelemahan §1.5 |
| **Frida** | Verifikasi dinamis — hook `shouldOverrideUrlLoading` untuk mengamati URL sesungguhnya yang diproses dan hasil keputusan (allow/block) saat runtime |

### 2.3 Prasyarat Lingkungan

- Tidak butuh device/root untuk analisis statis.
- Verifikasi dinamis (opsional) butuh device/emulator untuk memuat halaman uji dengan URL yang dirancang menguji celah validasi.

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0013** untuk reverse engineer aplikasi.
2. Gunakan **MASTG-TECH-0014** untuk mencari API yang relevan.

### 3.2 Metode A — Semgrep dengan Rule Resmi

```bash
semgrep --config mastg-android-webview-url-handlers.yml ./decompiled/sources
```

### 3.3 Metode B — grep/ripgrep untuk Triase Pola Validasi Lemah (Sesuai §1.5)

```bash
D=./decompiled/sources

# Cari implementasi shouldOverrideUrlLoading/shouldInterceptRequest
rg -n -A15 'shouldOverrideUrlLoading\(|shouldInterceptRequest\(' $D

# Triase cepat pola validasi berbasis substring (kandidat kelemahan)
rg -n -B5 -A5 'shouldOverrideUrlLoading' $D | grep -E '\.contains\(|\.startsWith\(|\.endsWith\('

# Bandingkan dengan pola yang benar (parsing host)
rg -n 'Uri\.parse\(.*\)\.getHost\(\)' $D
```

### 3.4 Metode C — Verifikasi Missing Client Implementation (Sesuai §1.3)

```bash
# Cari pemanggilan setWebViewClient, lalu verifikasi apakah class yang diteruskan benar-benar mengoverride method interception
rg -n 'setWebViewClient\(' $D
```

Untuk setiap hasil, lacak kelas `WebViewClient` yang diteruskan — apakah benar-benar mengoverride `shouldOverrideUrlLoading`/`shouldInterceptRequest`, atau hanya kelas kosong/anonymous tanpa override apa pun?

### 3.5 Metode D — Review Manual Lengkap (Wajib, Sesuai MASTG-TECH-0023)

Untuk setiap implementasi yang ditemukan, verifikasi:
1. Apakah validasi memakai host parsing yang benar, bukan substring mentah?
2. Apakah validasi mencakup kesadaran terhadap jangkauan method yang terbatas (§1.2) — apakah ada jalur lain (iframe, XHR, script src) yang perlu dilindungi dengan mekanisme tambahan?

### 3.6 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Kapan dipakai |
|---|---|---|
| **A** | Semgrep + rule resmi | Baseline — lokasi implementasi |
| **B** | grep/ripgrep manual | Triase cepat pola validasi lemah (substring) |
| **C** | grep manual | Deteksi "missing client implementation" (§1.3) |
| **D** | Review manual | **Wajib** — inti pengujian, menilai kebenaran validasi |

**Kombinasi minimum yang aku rekomendasikan:** **A (lokasi) → B + C (triase) → D (wajib)**.

---

### 3.7 Kriteria Evaluasi: Positive Case & Negative Case

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi |
|---|---|
| F1 | Method interception tidak ada validasi apa pun sebelum mengizinkan navigasi |
| F2 | Validasi memakai substring check yang bisa dilewati (bukan host parsing yang benar) |
| F3 | `setWebViewClient` dipanggil namun kelas yang diteruskan tidak mengoverride method interception apa pun |

**Contoh bukti (merefleksikan pola nyata CWE-346 §1.5):**

```java
@Override
public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
    String url = request.getUrl().toString();
    if (url.contains("trusted-domain.com")) { // VULNERABLE — substring check
        return false; // izinkan navigasi
    }
    return true;
}
```

Interpretasi: URL seperti `https://trusted-domain.com.evil.com/phishing` akan **salah lolos** validasi karena mengandung substring yang dicari. **FAIL**.

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi |
|---|---|
| P1 | Validasi memakai `Uri.parse(url).getHost()` dan membandingkan dengan **exact match** terhadap domain yang diizinkan (allowlist), **dan** |
| P2 | Kesadaran terhadap jangkauan terbatas method (iframe/XHR/script) ditangani lewat mekanisme tambahan bila relevan (CSP, sandboxing), **atau** |
| P3 | `WebViewClient` tidak diganti sama sekali (default aman, §1.1) |

**Contoh bukti:**

```java
@Override
public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
    String host = request.getUrl().getHost();
    if (host != null && (host.equals("trusted-domain.com") || host.endsWith(".trusted-domain.com"))) {
        return false;
    }
    return true;
}
```

**PASS**.

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Selalu periksa apakah validasi memakai host parsing, bukan substring mentah** — ini adalah kelemahan paling umum dan paling mudah diverifikasi sesuai §1.5.

2. **Waspadai kasus "missing client implementation"** — `setWebViewClient()` yang terlihat seperti langkah keamanan namun tanpa override apa pun di dalamnya tetap meninggalkan perilaku navigasi tidak terbatas (§1.3); jangan tertipu oleh keberadaan pemanggilan API semata.

3. **Pertimbangkan jangkauan terbatas kedua method** — validasi yang kuat pada `shouldOverrideUrlLoading` tidak melindungi dari konten yang dimuat lewat iframe/XHR/script tag; untuk perlindungan menyeluruh, pertimbangkan kontrol tambahan di level konten halaman itu sendiri (CSP) atau nonaktifkan JavaScript bila tidak diperlukan.

4. **Severity dimodulasi:**

   | Faktor | Severity |
   |---|---|
   | Tidak ada validasi sama sekali, atau validasi substring yang mudah dilewati, pada WebView yang memuat konten sensitif/kredensial | **Tinggi** |
   | Validasi host benar namun tidak mempertimbangkan jangkauan terbatas (iframe/XHR) | **Sedang** |
   | Validasi host parsing benar dan lengkap, atau WebViewClient default tidak diganti | **Bukan temuan** |

5. **Dokumentasikan:** lokasi kelas `WebViewClient`, method yang diimplementasikan (atau tidak), jenis validasi yang dipakai (substring vs host parsing), dan hasil pengujian dengan URL uji yang dirancang menguji celah (`trusted-domain.com.evil.com`, dsb.).

---

## 4. Rekomendasi Perbaikan

### 4.1 Gunakan Host Parsing yang Benar dengan Exact Match

```java
private static final Set<String> ALLOWED_HOSTS = Set.of("trusted-domain.com", "api.trusted-domain.com");

@Override
public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
    String host = request.getUrl().getHost();
    return host == null || !ALLOWED_HOSTS.contains(host); // true = blokir
}
```

### 4.2 Pastikan Override Benar-Benar Diterapkan Saat setWebViewClient Dipanggil

```java
// SEBELUM — niat ada, implementasi kosong
webView.setWebViewClient(new WebViewClient()); // tidak ada override apa pun

// SESUDAH — override eksplisit
webView.setWebViewClient(new WebViewClient() {
    @Override
    public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
        // validasi host di sini
        return !isAllowedHost(request.getUrl().getHost());
    }
});
```

### 4.3 Checklist Remediasi

- [ ] Seluruh validasi URL memakai host parsing (`Uri.getHost()`), tidak ada substring check
- [ ] Setiap pemanggilan `setWebViewClient` dipasangkan dengan override method interception yang benar-benar aktif
- [ ] Kesadaran terhadap jangkauan terbatas method dipertimbangkan (CSP/disable JavaScript bila sesuai)
- [ ] Diuji dengan payload URL yang dirancang menguji celah substring (`trusted.com.evil.com`, `evil.com?trusted.com`)

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0398 (source, tests-beta)](https://github.com/OWASP/mastg/blob/master/tests-beta/android/MASVS-CODE/MASTG-TEST-0398.md)
- [MASTG-KNOW-0018: WebViews](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0018/)

### 5.2 Dokumentasi Resmi

- [Android Developers: WebViewClient#shouldOverrideUrlLoading](https://developer.android.com/reference/android/webkit/WebViewClient#shouldOverrideUrlLoading(android.webkit.WebView,%20android.webkit.WebResourceRequest))
- [Android Developers: WebViewClient#shouldInterceptRequest](https://developer.android.com/reference/android/webkit/WebViewClient#shouldInterceptRequest(android.webkit.WebView,%20android.webkit.WebResourceRequest))

### 5.3 Riset dan Kasus Nyata

- [CWE-346: Origin Validation Error](https://www.pentestreports.com/cwe/CWE-346)

### 5.4 Dokumentasi Tools

- [Semgrep Documentation](https://semgrep.dev/docs/)
- [Frida — Dynamic Instrumentation Toolkit](https://frida.re/docs/home/)

---

*Dokumen ini disusun berdasarkan konten resmi OWASP MASTG (`tests-beta/android/MASVS-CODE/MASTG-TEST-0398.md`, `MASTG-KNOW-0018`), analisis rule `mastg-android-webview-url-handlers.yml`, serta riset CWE-346 yang mengonfirmasi pola kelemahan validasi substring persis seperti yang disebut eksplisit di evaluasi resmi test ini. Nuansa metodologis terpenting: dua method interception (`shouldOverrideUrlLoading`/`shouldInterceptRequest`) memiliki **jangkauan yang tidak lengkap** — masing-masing tidak dipanggil untuk kategori request tertentu (POST/XHR/iframe/script untuk yang pertama; javascript:/blob: untuk yang kedua) — menciptakan ilusi keamanan bila developer tidak menyadari celah ini. Evaluasi juga mengenali kategori unik "missing client implementation": pemanggilan `setWebViewClient()` yang terlihat seperti kontrol keamanan namun tanpa override method apa pun di dalamnya, meninggalkan perilaku navigasi tetap tidak terbatas meski developer mengira sudah menerapkan pembatasan.*
