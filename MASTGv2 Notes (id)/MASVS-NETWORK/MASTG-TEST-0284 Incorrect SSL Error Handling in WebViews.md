# MASTG-TEST-0284 Incorrect SSL Error Handling in WebViews

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0284 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-NETWORK (MASVS-NETWORK-2) |
| **Weakness** | MASWE-0027 — *Insecure Certificate Validation* (kelompok yang sama dengan MASTG-TEST-0234/0282/0283 dalam seri riset ini) |
| **API yang disorot** | `WebViewClient#onReceivedSslError(...)`, `SslErrorHandler#proceed()`, `SslErrorHandler#cancel()` |
| **Tipe Pengujian** | Static, Code, **Manual** |
| **Profile** | L1, L2 |
| **Knowledge** | MASTG-KNOW-0010 (Exception Handling, MASVS-CODE — sama seperti dirujuk MASTG-TEST-0282) |
| **Best Practice** | MASTG-BEST-0021 (Ensure Proper Error and Exception Handling) |
| **Teknik terkait** | MASTG-TECH-0013, MASTG-TECH-0014, MASTG-TECH-0023 (validasi lanjutan wajib) |
| **Test terkait** | **MASTG-TEST-0234/0282/0283** — keempat test bersama membentuk kelompok lengkap "validasi TLS yang salah diimplementasikan" pada Android, masing-masing menyasar API berbeda (`SSLSocket`, `X509TrustManager`, `HostnameVerifier`, dan kini `WebViewClient`) |
| **Demo terkait** | — (tidak ada) |
| **Rule resmi** | `mastg-android-network-onreceivedsslerror.yml` — **pola klaim-vs-implementasi yang identik** dengan dua rule lain yang sudah dibahas di MASTG-TEST-0282/0283 (lihat §3.2) |
| **CWE terkait** | CWE-295, CWE-297 |

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian dan Posisinya sebagai Anggota Keempat "Kuartet" Validasi TLS

Kutipan overview resmi MASTG:

> *"This test evaluates whether an Android app has WebViews that ignore SSL/TLS certificate errors by overriding the `onReceivedSslError(...)` method without proper validation."*

Test ini melengkapi **kuartet lengkap** kelemahan validasi TLS pada Android yang sudah dibahas dalam seri riset ini — keempatnya berbagi weakness yang sama (MASWE-0027) namun menyasar **empat permukaan API yang berbeda**:

| Test | API yang Disasar | Konteks Koneksi |
|---|---|---|
| MASTG-TEST-0234 | `SSLSocket` tanpa `HostnameVerifier` | Socket TLS level-rendah |
| MASTG-TEST-0282 | `X509TrustManager.checkServerTrusted()` cacat | Validasi rantai sertifikat kustom |
| MASTG-TEST-0283 | `HostnameVerifier.verify()` cacat | Validasi hostname kustom |
| **MASTG-TEST-0284** *(dokumen ini)* | `WebViewClient.onReceivedSslError()` cacat | **Konten yang dimuat di dalam WebView** |

Perbedaan konteks ini penting: ketiga test sebelumnya menyasar **traffic API networking native** aplikasi (HTTP client kustom), sementara test ini secara spesifik menyasar **traffic yang terjadi di dalam komponen WebView** — permukaan serangan yang berbeda karena melibatkan rendering konten web, bukan sekadar pertukaran data API murni.

### 1.2 Mekanisme `onReceivedSslError()`: Desain Default yang Aman, Diruntuhkan oleh Override

`WebViewClient.onReceivedSslError()` dipicu ketika WebView menemukan **kesalahan sertifikat SSL/TLS** saat memuat halaman. Poin krusial dari overview resmi:

> *"By default, the `WebView` cancels the request to protect users from insecure connections."*

Ini artinya **perilaku default Android sudah aman** — tanpa developer melakukan apa pun, WebView akan **menolak** koneksi yang bermasalah sertifikatnya. Kerentanan ini **murni muncul karena developer secara aktif mengambil alih (override)** perilaku ini dan **secara keliru** memanggil `SslErrorHandler.proceed()` — method yang secara eksplisit memberi tahu WebView untuk **melanjutkan** koneksi meski ada kesalahan sertifikat yang terdeteksi:

```java
@Override
public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {
    handler.proceed();  // BERBAHAYA — mengabaikan kesalahan sertifikat apa pun
}
```

Pola ini secara struktural mirip dengan anti-pattern "trust manager yang tidak melakukan apa-apa" pada MASTG-TEST-0282 — dalam kedua kasus, developer **secara sengaja menonaktifkan** mekanisme proteksi bawaan yang sebenarnya sudah bekerja dengan benar tanpa campur tangan mereka.

### 1.3 Panduan Resmi yang Sangat Tegas: Jangan Pernah `proceed()`, Jangan Pernah Tanya Pengguna

Ini bagian yang paling menarik dari test ini — overview resmi mengutip **panduan resmi Android yang sangat kategoris**, tanpa pengecualian kontekstual seperti pada test-test lain:

> *"According to official Android guidance, apps should never call `proceed()` in response to SSL errors. The correct behavior is to cancel the request to protect users from potentially insecure connections. **User prompts are also discouraged, as users cannot reliably evaluate SSL issues.**"*

Poin kedua ini secara khusus penting untuk dipahami — banyak developer yang **berusaha "melakukan hal benar"** dengan menampilkan dialog konfirmasi kepada pengguna sebelum melanjutkan koneksi yang bermasalah ("Sertifikat situs ini tidak valid. Lanjutkan?"), menganggap ini sebagai kompromi yang wajar antara keamanan dan fungsionalitas. **Panduan resmi Android secara eksplisit menolak pendekatan ini** — karena pengguna awam **tidak memiliki kapasitas teknis** untuk menilai apakah suatu kesalahan sertifikat SSL benar-benar berbahaya atau tidak; menyerahkan keputusan keamanan kritis ini kepada pengguna pada dasarnya adalah **memindahkan tanggung jawab keamanan tanpa memberi kemampuan nyata untuk mengambil keputusan yang tepat** — mirip dengan mengapa peringatan MITM browser modern (mis. Chrome) sengaja dibuat sulit di-bypass dengan klik sederhana.

### 1.4 Tiga Pola Anti-Pattern dari Klausul "Further Validation Required"

**1. Menerima error SSL tanpa syarat** — pola paling sederhana dan ekstrem, `proceed()` dipanggil tanpa pemeriksaan apa pun terhadap objek `SslError` yang diterima.

**2. Hanya bergantung pada primary error code** — pola yang lebih halus dan sering luput dari code review:

```java
@Override
public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {
    if (error.getPrimaryError() != SslError.SSL_UNTRUSTED) {
        handler.proceed();  // BAHAYA: mengabaikan error LAIN yang mungkin ada di chain
    } else {
        handler.cancel();
    }
}
```

`SslError.getPrimaryError()` hanya mengembalikan **satu** kode error yang dianggap paling signifikan oleh sistem — namun objek `SslError` sesungguhnya dapat memuat **kombinasi beberapa jenis kesalahan sekaligus** dalam satu rantai sertifikat (mis. sertifikat kedaluwarsa **dan** hostname tidak cocok secara bersamaan). Kode yang hanya memeriksa `getPrimaryError()` dan mengasumsikan "selama bukan `SSL_UNTRUSTED`, berarti aman untuk dilanjutkan" berisiko **melewatkan** jenis kesalahan lain yang sama berbahayanya namun tidak kebetulan menjadi "primary" dalam evaluasi sistem.

**3. Membungkam exception secara diam-diam** — pola yang menghubungkan test ini langsung ke **MASVS-CODE (Exception Handling)** sesuai referensi resmi ke MASTG-KNOW-0010/MASTG-BEST-0021 (sama seperti pola yang sudah dibahas di dokumen MASTG-TEST-0282 §1.4):

```java
@Override
public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {
    try {
        validateCertificate(error);
    } catch (Exception e) {
        // DIBUNGKAM — tidak ada handler.cancel() dipanggil di sini!
        // Koneksi diam-diam BERLANJUT karena tidak ada tindakan eksplisit yang diambil
    }
}
```

Ini adalah pola **"fail-open" tersembunyi** yang paling berbahaya — bila `validateCertificate()` melempar exception (mis. karena bug/edge-case tak terduga) dan exception tersebut **ditangkap tapi tidak diikuti pemanggilan `cancel()` eksplisit**, WebView bisa jadi **tetap melanjutkan** proses loading (tergantung implementasi default `SslErrorHandler` bila tidak ada tindakan eksplisit diambil) — sebuah kegagalan senyap yang jauh lebih sulit terdeteksi dibanding pola #1 yang eksplisit memanggil `proceed()`.

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | Fungsi |
|---|---|
| **jadx** | Dekompilasi DEX → Java untuk menemukan override `onReceivedSslError()` |
| **grep / ripgrep** | Pencarian pola implementasi dan verifikasi logika penanganan `SslError` |
| **semgrep** | Menjalankan rule resmi sebagai baseline lokasi |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **CodeQL** | Menelusuri **isi** method `onReceivedSslError()` — apakah `proceed()` dipanggil tanpa syarat, apakah hanya bergantung pada `getPrimaryError()`, apakah ada jalur `catch` tanpa `cancel()` |
| **MobSF** | Kadang menandai pola `onReceivedSslError` yang memanggil `proceed()` di laporan Code Analysis |
| **Frida** | Hooking `onReceivedSslError()` dan `SslErrorHandler.proceed()`/`cancel()` untuk konfirmasi runtime — dapat memicu kesalahan sertifikat sungguhan (via mitmproxy dengan sertifikat tidak sah) untuk melihat reaksi nyata WebView |
| **mitmproxy dengan sertifikat tidak valid** | Uji dinamis definitif — sajikan sertifikat kedaluwarsa/self-signed pada WebView target dan amati apakah konten tetap dimuat |

### 2.3 Prasyarat Lingkungan

- **Tidak butuh device/root** untuk analisis statis inti.
- **Butuh device + mitmproxy untuk konfirmasi dinamis** (opsional tapi sangat menguatkan bukti).
- **Review manual (MASTG-TECH-0023) mutlak diperlukan**, konsisten dengan tag `manual`.

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0013** untuk reverse engineer aplikasi.
2. Gunakan **MASTG-TECH-0014** untuk mencari API yang relevan.

### 3.2 Metode A — Rule Semgrep Resmi *(pola klaim-vs-implementasi yang sama seperti MASTG-TEST-0282/0283)*

```yaml
rules:
  - id: mastg-android-network-onreceivedsslerror
    severity: WARNING
    languages: [java]
    metadata:
      summary: This rule looks for the use of onReceivedSslError and ensures it throws an exception instead of silently muting TLS errors.
    message: Improper use of onReceivedSslError handler
    match:
      any:
        - public void onReceivedSslError(...) {...}
```

```bash
semgrep --config https://raw.githubusercontent.com/OWASP/mastg/master/rules/mastg-android-network-onreceivedsslerror.yml ./decompiled/sources/
```

**Ini pola ketiga yang identik ditemukan berturut-turut** dalam kelompok test validasi TLS (MASTG-TEST-0282, 0283, dan kini 0284) — `summary` rule mengklaim **"ensures it throws an exception instead of silently muting TLS errors"**, namun pattern `{...}` yang benar-benar dieksekusi hanyalah **wildcard body match**, mencocokkan **setiap** override `onReceivedSslError()` terlepas isinya — baik yang benar memanggil `cancel()` maupun yang secara berbahaya memanggil `proceed()` tanpa syarat. Ini menegaskan pola yang sudah teridentifikasi sebagai isu sistemik pada rule-rule "unsafe implementation" MASTG untuk kategori validasi TLS kustom — ketiganya secara konsisten hanya berfungsi sebagai **peta lokasi**, bukan penilai keamanan, meski deskripsi tekstualnya mengklaim sebaliknya.

### 3.3 Metode B — grep/ripgrep untuk Ketiga Pola Anti-Pattern

```bash
D=./decompiled/sources

# Pola #1: proceed() tanpa syarat apa pun
rg -n -B10 'handler\.proceed\(\)|\.proceed\(\)' $D | grep -B10 "onReceivedSslError"

# Pola #2: hanya bergantung pada getPrimaryError()
rg -n -B5 -A10 'onReceivedSslError' $D | grep -B5 -A5 'getPrimaryError\(\)'

# Pola #3: try-catch tanpa cancel() eksplisit
rg -n -B3 -A15 'onReceivedSslError' $D | grep -B3 -A15 'catch\s*(' | grep -v 'cancel()'
```

### 3.4 Metode C — CodeQL untuk Ketiga Pola Sekaligus

```ql
import java

class OnReceivedSslErrorMethod extends Method {
  OnReceivedSslErrorMethod() {
    this.hasName("onReceivedSslError") and
    this.getDeclaringType().getASupertype*().hasQualifiedName("android.webkit", "WebViewClient")
  }
}

// Pola #1: proceed() dipanggil tanpa dijaga kondisi apa pun
from OnReceivedSslErrorMethod m, MethodAccess proceedCall
where proceedCall.getMethod().hasName("proceed") and
      proceedCall.getEnclosingCallable() = m and
      not exists(IfStmt guard | guard.getAChild*() = proceedCall)
select proceedCall, "proceed() dipanggil TANPA kondisi apa pun — menerima semua kesalahan SSL"
```

```ql
// Pola #3: try-catch dalam onReceivedSslError tanpa pemanggilan cancel()
import java

from OnReceivedSslErrorMethod m, TryStmt t
where t.getEnclosingCallable() = m and
      not exists(MethodAccess cancelCall |
        cancelCall.getMethod().hasName("cancel") and
        cancelCall.getEnclosingCallable() = m)
select t, "Blok try-catch ditemukan di onReceivedSslError TANPA pemanggilan cancel() sama sekali"
```

### 3.5 Metode D — Frida + mitmproxy (Konfirmasi Dinamis Definitif)

```javascript
// hook-onreceivedsslerror.js
Java.perform(function () {
    var WebViewClient = Java.use("android.webkit.WebViewClient");
    WebViewClient.onReceivedSslError.implementation = function (view, handler, error) {
        console.log("[!] onReceivedSslError dipanggil — primaryError: " + error.getPrimaryError());
        var result = this.onReceivedSslError(view, handler, error);
        console.log("    Method selesai dieksekusi");
        return result;
    };

    var SslErrorHandler = Java.use("android.webkit.SslErrorHandler");
    SslErrorHandler.proceed.implementation = function () {
        console.log("[!!!] SslErrorHandler.proceed() DIPANGGIL — kesalahan SSL DIABAIKAN!");
        return this.proceed();
    };
});
```

```bash
# Sajikan sertifikat tidak valid ke WebView via mitmproxy
mitmproxy --mode transparent --certs=*=invalid-cert.pem

frida -U -f com.target.app -l hook-onreceivedsslerror.js --no-pause
```

Bila konten WebView **tetap termuat** meski `proceed()` terpanggil dengan sertifikat yang sengaja tidak valid, ini bukti definitif kondisi FAIL.

### 3.6 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Mendeteksi keberadaan? | Menilai keamanan isi? | Kapan dipakai |
|---|---|---|---|---|
| **A** | Rule semgrep resmi | ✅ | ❌ (klaim menyesatkan) | Inventarisasi lokasi saja |
| **B** | grep pola spesifik | ✅ | Sebagian | Baseline utama |
| **C** | CodeQL | ✅ | ✅ (ketiga pola sekaligus) | Codebase besar |
| **D** | Frida + mitmproxy | ✅ (runtime) | ✅ (bukti definitif) | Konfirmasi akhir |

**Kombinasi minimum yang aku rekomendasikan:** **A (JANGAN percaya klaim keamanannya) → C (CodeQL untuk ketiga pola) → D (konfirmasi dinamis dengan sertifikat tidak valid nyata)**, dilengkapi review manual MASTG-TECH-0023 pada setiap kandidat.

---

### 3.7 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG:**

> **Evaluation:** *"The test case fails if `onReceivedSslError(...)` is overridden and certificate errors are ignored without proper validation or user involvement."*

Catatan: bahkan **melibatkan pengguna** (dialog konfirmasi) **tidak** menyelamatkan implementasi dari kategori FAIL, sesuai panduan tegas §1.3 — perilaku benar satu-satunya adalah `cancel()`.

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila ditemukan salah satu dari tiga pola (§1.4):

| No | Pola |
|---|---|
| F1 | `proceed()` dipanggil tanpa syarat pemeriksaan apa pun |
| F2 | Keputusan hanya berdasarkan `getPrimaryError()`, mengabaikan kemungkinan multi-error dalam chain |
| F3 | Exception dibungkam tanpa pemanggilan `cancel()` eksplisit |
| F4 | Implementasi menampilkan dialog konfirmasi ke pengguna dan melanjutkan berdasarkan pilihan mereka — **tetap FAIL** meski melibatkan pengguna, sesuai §1.3 |

**Contoh bukti (ilustratif — MASTG belum menyediakan demo resmi untuk test ini):**

```java
@Override
public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {
    if (error.getPrimaryError() != SslError.SSL_UNTRUSTED) {
        handler.proceed();
    } else {
        handler.cancel();
    }
}
```

Interpretasi: pola #2 — hanya memeriksa `SSL_UNTRUSTED`, melewatkan kombinasi error lain seperti `SSL_EXPIRED` atau `SSL_IDMISMATCH` yang mungkin muncul bersamaan. **FAIL**.

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi |
|---|---|
| P1 | **Tidak ditemukan** override `onReceivedSslError()` sama sekali — WebView mengandalkan perilaku default aman (§1.2) |
| P2 | Override ditemukan, namun **selalu** memanggil `handler.cancel()` tanpa pengecualian apa pun |

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Jangan mengandalkan rule semgrep untuk menilai keamanan** — pola klaim-vs-implementasi yang sama ditemukan berulang pada ketiga rule "unsafe implementation" MASTG untuk kelompok test validasi TLS ini.

2. **Solusi teraman adalah TIDAK meng-override method ini sama sekali** — berbeda dari beberapa test lain di mana "tidak ada implementasi" bisa berarti kelalaian, di sini justru **default sistem sudah aman**, sehingga ketiadaan override adalah kondisi PASS terbaik.

3. **Dialog konfirmasi ke pengguna BUKAN mitigasi yang sah** — ini nuansa yang paling sering disalahpahami developer yang "berniat baik". Tandai FAIL meski implementasinya melibatkan interaksi pengguna.

4. **Korelasikan dengan MASTG-TEST-0234/0282/0283** untuk gambaran lengkap seluruh permukaan validasi TLS kustom aplikasi.

5. **Severity dimodulasi** oleh sensitivitas konten yang dimuat WebView — WebView yang menampilkan portal login/pembayaran jauh lebih kritis dibanding WebView yang menampilkan halaman bantuan statis.

6. **Dokumentasikan:** lokasi override, pola anti-pattern spesifik yang teridentifikasi, dan hasil konfirmasi dinamis bila dilakukan.

---

## 4. Rekomendasi Perbaikan

### 4.1 Solusi Terbaik: Jangan Override Sama Sekali

Bila tidak ada kebutuhan bisnis eksplisit, biarkan `WebViewClient` default menangani `onReceivedSslError()` — perilaku bawaan sudah aman.

### 4.2 Bila Terpaksa Override (mis. untuk Logging), Selalu `cancel()`

```java
@Override
public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {
    Log.w(TAG, "SSL error terdeteksi: " + error.toString());  // logging saja, TIDAK memengaruhi keputusan
    handler.cancel();  // SELALU cancel, tanpa pengecualian
}
```

### 4.3 Checklist Remediasi

- [ ] Seluruh override `onReceivedSslError()` diinventarisasi dan ditinjau isinya
- [ ] Tidak ada `proceed()` yang dipanggil tanpa syarat
- [ ] Tidak ada keputusan yang hanya berdasarkan `getPrimaryError()`
- [ ] Tidak ada exception yang dibungkam tanpa `cancel()` eksplisit
- [ ] Tidak ada dialog konfirmasi pengguna yang dipakai sebagai basis keputusan melanjutkan koneksi
- [ ] **Verifikasi ulang:** jalankan kembali MASTG-TEST-0284 pada APK release final setelah remediasi

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0284: Incorrect SSL Error Handling in WebViews](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0284/)
- [MASTG-TEST-0234: Missing Implementation of Server Hostname Verification with SSLSockets](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0234/)
- [MASTG-TEST-0282: Unsafe Custom Trust Evaluation](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0282/)
- [MASTG-TEST-0283: Incorrect Implementation of Server Hostname Verification](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0283/)
- [MASWE-0027: Insecure Certificate Validation](https://mas.owasp.org/MASWE/MASVS-NETWORK/MASWE-0027/)
- [MASTG-KNOW-0010: Exception Handling](https://mas.owasp.org/MASTG/knowledge/android/MASVS-CODE/MASTG-KNOW-0010/)
- [MASTG-BEST-0021: Ensure Proper Error and Exception Handling](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0021/)
- [Rule resmi: mastg-android-network-onreceivedsslerror.yml (GitHub)](https://github.com/OWASP/mastg/blob/master/rules/mastg-android-network-onreceivedsslerror.yml)

### 5.2 Dokumentasi Resmi Android

- [Android Developers — `WebViewClient#onReceivedSslError()`](https://developer.android.com/reference/android/webkit/WebViewClient#onReceivedSslError(android.webkit.WebView,%20android.webkit.SslErrorHandler,%20android.net.http.SslError))
- [Android Developers — `SslErrorHandler#proceed()`](https://developer.android.com/reference/android/webkit/SslErrorHandler#proceed())
- [Android Developers — `SslErrorHandler#cancel()`](https://developer.android.com/reference/android/webkit/SslErrorHandler#cancel())
- [Android Developers — `SslError#getPrimaryError()`](https://developer.android.com/reference/android/net/http/SslError#getPrimaryError())

### 5.3 Riset dan Sumber Pihak Ketiga

- [Georgiev et al. — The Most Dangerous Code in the World](http://www.cs.umd.edu/class/fall2019/cmsc818O/papers/most-dangerous-code.pdf)
- [CWE-295: Improper Certificate Validation](https://cwe.mitre.org/data/definitions/295.html)
- [CWE-297: Improper Validation of Certificate with Host Mismatch](https://cwe.mitre.org/data/definitions/297.html)

### 5.4 Dokumentasi Tools

- [Semgrep — Documentation](https://semgrep.dev/docs/)
- [CodeQL — Documentation](https://codeql.github.com/docs/)
- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [Frida — Dynamic instrumentation toolkit](https://frida.re/docs/javascript-api/)
- [mitmproxy](https://mitmproxy.org/)

---

*Dokumen ini disusun berdasarkan OWASP MASTG (rilis terkini per September 2026) dan dokumentasi resmi Android Developers. Melengkapi kuartet test validasi TLS kustom (bersama MASTG-TEST-0234/0282/0283), temuan berulang ketiga dalam seri ini: rule semgrep resmi untuk kategori "unsafe implementation" secara konsisten mengklaim kemampuan evaluasi keamanan yang sebenarnya tidak dimiliki pattern-nya. Nuansa terpenting secara substansi: panduan resmi Android bersifat tegas tanpa pengecualian — jangan pernah `proceed()`, dan jangan pernah melibatkan pengguna dalam keputusan ini, karena pengguna tidak memiliki kapasitas menilai keabsahan kesalahan SSL secara teknis.*
