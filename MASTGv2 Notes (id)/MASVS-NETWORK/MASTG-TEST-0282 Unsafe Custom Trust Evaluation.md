# MASTG-TEST-0282 Unsafe Custom Trust Evaluation

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0282 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-NETWORK (MASVS-NETWORK-2) |
| **Weakness** | MASWE-0027 — *Insecure Certificate Validation* (sama seperti MASTG-TEST-0234/0283 dalam seri riset ini) |
| **API yang disorot** | `X509TrustManager.checkServerTrusted(...)` |
| **Tipe Pengujian** | Static, Code, **Manual** |
| **Profile** | L1, L2 |
| **Knowledge** | MASTG-KNOW-0010 (Exception Handling — MASVS-CODE) |
| **Best Practice** | MASTG-BEST-0021 (Ensure Proper Error and Exception Handling) |
| **Teknik terkait** | MASTG-TECH-0013, MASTG-TECH-0014, MASTG-TECH-0023 (Reviewing Decompiled Java Code — validasi lanjutan wajib) |
| **Test terkait** | **MASTG-TEST-0234** (Missing Hostname Verification with SSLSockets), **MASTG-TEST-0283** (Incorrect Implementation of Server Hostname Verification) — ketiganya menyasar celah berbeda dalam ekosistem validasi TLS kustom Android |
| **Demo terkait** | — (tidak ada) |
| **Rule resmi** | `mastg-android-network-checkservertrusted.yml` — **cakupannya sangat menyesatkan**, hanya mendeteksi keberadaan method, klaim di deskripsi rule tidak sesuai implementasi pattern-nya (lihat §3.2, temuan paling signifikan dalam dokumen ini) |
| **CWE terkait** | CWE-295 (Improper Certificate Validation), CWE-297 |

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian

Kutipan overview resmi MASTG:

> *"This test evaluates whether an Android app uses `checkServerTrusted(...)` in an unsafe manner as part of a custom `TrustManager`, causing any connection configured to use that `TrustManager` to skip certificate validation."*

`checkServerTrusted()` adalah method inti dari interface `X509TrustManager` — dipanggil sistem TLS **setiap kali** koneksi HTTPS mencoba memvalidasi rantai sertifikat yang disajikan server. Bila developer membuat implementasi **kustom** dari interface ini (menggantikan `TrustManager` bawaan sistem yang sudah teruji), **seluruh tanggung jawab validasi keamanan** berpindah sepenuhnya ke tangan kode aplikasi tersebut — dan sesuai riset akademik klasik *"The Most Dangerous Code in the World"* yang secara luas mendokumentasikan pola ini di berbagai platform non-browser, **implementasi kustom semacam ini secara konsisten menjadi sumber kegagalan validasi TLS paling umum** di seluruh ekosistem software, bukan hanya Android.

### 1.2 Pola Anti-Pattern yang Secara Eksplisit Diperingatkan MASTG

Klausul **"Further Validation Required"** resmi test ini memberi daftar **enam pola konkret** yang harus diperiksa penguji pada setiap implementasi `checkServerTrusted()` yang ditemukan — ini salah satu daftar anti-pattern paling rinci yang ditemukan di seluruh seri riset dokumen ini:

1. **Memakai `checkServerTrusted()` padahal NSC sudah cukup** — flag arsitektural: keputusan memakai TrustManager kustom itu sendiri meningkatkan risiko (rujuk pembahasan mendalam soal ini di dokumen MASTG-TEST-0239 dalam seri riset ini, MASWE-0047 tentang penggunaan API non-standar untuk fungsi keamanan-kritis).
2. **Trust manager yang tidak melakukan apa-apa** — override `checkServerTrusted()` yang menerima **semua** sertifikat tanpa validasi apa pun, contoh paling ekstrem dan paling sering ditemukan di lapangan:
   ```java
   public void checkServerTrusted(X509Certificate[] chain, String authType) {
       // KOSONG — tidak ada validasi sama sekali, secara implisit "meloloskan" semua sertifikat
   }
   ```
3. **Mengabaikan error** — gagal melempar exception yang seharusnya (`CertificateException`, `IllegalArgumentException`) saat validasi gagal, atau **menangkap dan membungkam** exception tersebut (`catch (CertificateException e) { /* diam saja */ }`).
4. **Memakai `checkValidity()` sebagai pengganti validasi penuh** — `checkValidity()` **hanya** memeriksa apakah sertifikat sudah kedaluwarsa atau belum berlaku (rentang tanggal), namun **sama sekali tidak** memverifikasi apakah sertifikat tersebut **dipercaya** (diterbitkan CA sah) atau **cocok dengan hostname** tujuan — kesalahan konseptual yang sangat halus karena kode **tampak** melakukan validasi, padahal validasi yang dilakukan tidak menjawab pertanyaan keamanan yang sesungguhnya.
5. **Melonggarkan trust secara eksplisit** — menonaktifkan pemeriksaan trust untuk menerima sertifikat self-signed/tidak tepercaya demi kemudahan development/testing, **yang kemudian tertinggal** di kode produksi.
6. **Menyalahgunakan `getAcceptedIssuers()`** — mengembalikan `null` atau array kosong tanpa penanganan yang tepat dapat secara efektif **menonaktifkan validasi issuer** sama sekali.

### 1.3 Poin Krusial: `checkValidity()` Bukan Pengganti Validasi Trust (Anti-Pattern #4)

Ini nuansa paling halus dan paling layak disorot dari keenam pola di atas, karena **paling mudah lolos dari code review sekilas** — kode yang memanggil `checkValidity()` **terlihat** seperti sedang melakukan pekerjaan validasi yang benar:

```java
public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
    chain[0].checkValidity();  // TERLIHAT seperti validasi, tapi TIDAK CUKUP
    // Tidak ada verifikasi rantai kepercayaan (trust chain) ke root CA
    // Tidak ada verifikasi hostname
}
```

`checkValidity()` menjawab pertanyaan **"apakah sertifikat ini masih berlaku secara temporal?"** — pertanyaan yang **sama sekali berbeda** dari pertanyaan keamanan yang sesungguhnya: **"apakah sertifikat ini benar-benar diterbitkan oleh otoritas tepercaya untuk domain yang benar?"**. Seorang penyerang MITM dapat dengan mudah membuat sertifikat self-signed yang **masih berlaku secara tanggal** (`checkValidity()` akan lolos), namun sama sekali **tidak diterbitkan CA tepercaya mana pun** — implementasi yang hanya mengandalkan `checkValidity()` akan **menerima sertifikat palsu tersebut** tanpa keluhan.

### 1.4 Hubungan dengan MASVS-CODE: Exception Handling sebagai Akar Masalah

Perhatikan bahwa knowledge dan best practice yang dirujuk test ini (**MASTG-KNOW-0010 — Exception Handling**, **MASTG-BEST-0021**) berasal dari kategori **MASVS-CODE**, bukan MASVS-NETWORK — sebuah **cross-reference yang koheren** (bukan inkonsistensi metadata seperti beberapa kasus lain dalam seri riset ini), karena akar dari **tiga dari enam** anti-pattern di atas (mengabaikan error, membungkam exception) sebenarnya adalah masalah **penanganan exception yang buruk**, bukan murni masalah kriptografi/jaringan. MASTG-BEST-0021 menegaskan prinsip yang relevan langsung:

> *"Fail securely: Exceptions must not weaken security controls. Any failure in security checks should result in a **deny** outcome... Security mechanisms should default to denying access until explicitly granted, since **fail-open paths are a common attack vector**."*

`checkServerTrusted()` yang gagal melempar exception saat validasi gagal adalah contoh tekstual dari **"fail-open"** (CWE-636) — alih-alih menolak koneksi saat terjadi kondisi mencurigakan, kode secara diam-diam **melanjutkan seolah semuanya baik-baik saja**.

### 1.5 Konteks Akademik: Skala Masalah di Seluruh Industri

Riset seminal *"The Most Dangerous Code in the World: Validating SSL Certificates in Non-Browser Software"* (Georgiev et al.) mendokumentasikan bahwa validasi sertifikat SSL/TLS **rusak secara sistematis** di berbagai library dan aplikasi non-browser — bukan fenomena yang eksklusif untuk Android, melainkan pola kegagalan yang berulang di seluruh ekosistem software yang mengimplementasikan validasi TLS-nya sendiri alih-alih memakai jalur bawaan platform. Untuk Android secara spesifik, dua tool riset akademik dirancang khusus mendeteksi pola ini dalam skala besar:

- **MalloDroid**: melakukan analisis statis untuk mendeteksi berbagai cacat terkait penyalahgunaan SSL/TLS, termasuk penerimaan sertifikat/hostname apa pun tanpa validasi.
- **SMV-Hunter**: berfokus khusus pada **kode validasi kustom** — yaitu override `X509TrustManager` dan `HostnameVerifier` — persis target test ini.

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | Fungsi |
|---|---|
| **jadx** | Dekompilasi DEX → Java untuk menemukan implementasi `X509TrustManager` kustom |
| **grep / ripgrep** | Pencarian pola implementasi dan verifikasi isi method |
| **semgrep** | Menjalankan rule resmi sebagai baseline lokasi (dengan catatan celah signifikan, §3.2) |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **CodeQL** | Menelusuri **isi** method `checkServerTrusted()` secara terprogram — apakah method body benar-benar kosong, apakah ada pemanggilan validasi rantai (`CertPathValidator`), apakah ada `throw` pada jalur kegagalan |
| **MalloDroid** (akademik) | Tool riset yang secara spesifik dirancang mendeteksi pola penyalahgunaan SSL/TLS termasuk custom TrustManager yang cacat |
| **SMV-Hunter** (akademik) | Tool riset yang secara spesifik fokus pada override `X509TrustManager`/`HostnameVerifier` |
| **MobSF** | Kadang menandai pola `TrustManager` yang menerima semua sertifikat di laporan Code Analysis |
| **Frida** | Hooking `checkServerTrusted()` untuk mengonfirmasi runtime bahwa method benar-benar dipanggil dan melihat isi `X509Certificate[]` yang diterima saat koneksi nyata dibuat |

### 2.3 Prasyarat Lingkungan

- **Tidak butuh device/root** untuk analisis statis inti.
- **Review manual (MASTG-TECH-0023) adalah bagian wajib**, bukan opsional — ini eksplisit dinyatakan sebagai "Further Validation Required" resmi test ini, konsisten dengan tag `manual` pada tipe pengujiannya.

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0013** untuk reverse engineer aplikasi.
2. Gunakan **MASTG-TECH-0014** untuk mencari API yang relevan.

Dengan klausul **Further Validation Required** wajib: *"Inspect each reported code location using MASTG-TECH-0023"* terhadap keenam pola anti-pattern (§1.2).

### 3.2 Metode A — Rule Semgrep Resmi *(ADA, TAPI TEMUAN PALING SIGNIFIKAN: klaim rule TIDAK SESUAI implementasinya)*

Rule resmi:

```yaml
rules:
  - id: mastg-android-network-checkservertrusted
    severity: WARNING
    languages: [java]
    metadata:
      summary: This rule looks for the use of checkServerTrusted and ensures it throws an exception instead of silently muting invalid server certificates
    message: Improper Server Certificate verification detected.
    match:
        any:
        - public void checkServerTrusted (...) { ... }
```

```bash
semgrep --config https://raw.githubusercontent.com/OWASP/mastg/master/rules/mastg-android-network-checkservertrusted.yml ./decompiled/sources/
```

**Ini temuan paling signifikan dalam dokumen ini**: perhatikan **klaim di field `summary`** rule ini:

> *"This rule looks for the use of checkServerTrusted and **ensures it throws an exception** instead of silently muting invalid server certificates"*

Klaim ini secara eksplisit menyatakan rule akan **memverifikasi perilaku exception-throwing** — namun pattern yang benar-benar dieksekusi hanyalah:

```
public void checkServerTrusted (...) { ... }
```

Pola `{ ... }` dalam sintaks semgrep adalah **wildcard body match** — ia mencocokkan **method apa pun** dengan tanda tangan tersebut, **terlepas dari apa isi di dalamnya**. Ini berarti rule ini **akan selalu memicu warning untuk SETIAP implementasi `checkServerTrusted()`, baik yang aman maupun yang tidak aman** — termasuk implementasi yang benar-benar melempar exception dengan tepat saat validasi gagal. **Rule ini sama sekali tidak melakukan** apa yang diklaim `summary`-nya (memverifikasi keberadaan `throw`) — ia murni rule inventarisasi lokasi berkedok rule evaluasi keamanan.

Konsekuensi praktisnya:
- **Tidak ada false negative dari rule ini untuk keberadaan** — setiap implementasi custom `TrustManager` akan tertangkap.
- **Tapi rule ini tidak bisa dipakai untuk membedakan aman/tidak aman sama sekali** — severity `WARNING` yang sama akan muncul baik untuk implementasi yang sempurna aman maupun yang benar-benar kosong tanpa validasi apa pun. Ini bertentangan langsung dengan klaim tekstual `summary`-nya, dan merupakan kasus **rule description vs implementation mismatch** paling jelas yang ditemukan sepanjang seri riset dokumen ini.

### 3.3 Metode B — grep/ripgrep dengan Verifikasi Manual Isi Method

```bash
D=./decompiled/sources

# Temukan seluruh implementasi
rg -n -A20 'public void checkServerTrusted' $D > trustmanager_implementations.txt

# Deteksi otomatis pola paling mencurigakan: method body sangat pendek (indikasi kuat "tidak melakukan apa-apa")
rg -n -A5 'public void checkServerTrusted' $D | grep -B1 '^\s*}$' | grep -c "checkServerTrusted"

# Cari pola checkValidity() sebagai pengganti validasi penuh (anti-pattern #4, §1.3)
rg -n -B3 -A10 'public void checkServerTrusted' $D | grep -B5 'checkValidity()'

# Cari catch block yang membungkam exception (anti-pattern #3)
rg -n -B10 'catch\s*\(\s*CertificateException' $D | grep -B10 "^\s*}\s*$" | grep "checkServerTrusted"
```

### 3.4 Metode C — CodeQL (Analisis Isi Method Secara Terprogram)

```ql
import java

class CheckServerTrustedMethod extends Method {
  CheckServerTrustedMethod() {
    this.hasName("checkServerTrusted") and
    this.getDeclaringType().getASupertype*().hasQualifiedName("javax.net.ssl", "X509TrustManager")
  }
}

// Pola 1: Method body kosong atau tidak melempar exception sama sekali
from CheckServerTrustedMethod m
where not exists(ThrowStmt t | t.getEnclosingCallable() = m)
  and not exists(MethodAccess ma | ma.getEnclosingCallable() = m and
    ma.getMethod().getDeclaringType().hasQualifiedName("java.security.cert", "CertPathValidator"))
select m, "checkServerTrusted() tidak melempar exception dan tidak memanggil CertPathValidator — kandidat kuat validasi tidak aman"
```

```ql
// Pola 2: Hanya memanggil checkValidity() tanpa validasi trust chain (anti-pattern #4)
import java

from Method m, MethodAccess checkValidityCall
where m.hasName("checkServerTrusted") and
      checkValidityCall.getMethod().hasName("checkValidity") and
      checkValidityCall.getEnclosingCallable() = m and
      not exists(MethodAccess trustCall |
        trustCall.getEnclosingCallable() = m and
        trustCall.getMethod().getDeclaringType().hasQualifiedName("java.security.cert", "CertPathValidator"))
select m, "checkServerTrusted() HANYA memanggil checkValidity() tanpa validasi trust chain penuh"
```

### 3.5 Metode D — Frida (Konfirmasi Runtime)

```javascript
// hook-checkservertrusted.js
Java.perform(function () {
    Java.enumerateLoadedClasses({
        onMatch: function (className) {
            // Cari kelas kustom yang mengimplementasikan X509TrustManager
        },
        onComplete: function () {}
    });

    // Hooking langsung bila nama kelas custom TrustManager sudah diketahui dari analisis statis
    try {
        var CustomTM = Java.use("com.target.app.net.PermissiveTrustManager");
        CustomTM.checkServerTrusted.implementation = function (chain, authType) {
            console.log("[!] checkServerTrusted dipanggil dengan " + chain.length + " sertifikat");
            var result = this.checkServerTrusted(chain, authType);
            console.log("    Method selesai TANPA melempar exception — periksa apakah ini seharusnya gagal");
            return result;
        };
    } catch (e) { console.log("[x] Kelas TrustManager kustom tidak ditemukan/berbeda nama: " + e); }
});
```

### 3.6 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Mendeteksi keberadaan? | Menilai keamanan isi? | Kapan dipakai |
|---|---|---|---|---|
| **A** | Rule semgrep resmi | ✅ | ❌ (meski diklaim bisa, §3.2) | Inventarisasi lokasi saja |
| **B** | grep + verifikasi manual | ✅ | Manual (perlu mata) | Baseline utama |
| **C** | CodeQL | ✅ | ✅ (terprogram, mendeteksi pola spesifik) | **Paling bernilai** — codebase besar |
| **D** | Frida | ✅ (runtime) | Sebagian (konfirmasi eksekusi) | Konfirmasi kandidat prioritas tinggi |

**Kombinasi minimum yang aku rekomendasikan:** **A (inventarisasi lokasi, JANGAN percaya klaim keamanannya) → C (CodeQL untuk menilai isi secara terprogram) → review manual MASTG-TECH-0023** pada setiap kandidat yang tersisa, sesuai klausul wajib resmi.

---

### 3.7 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG:**

> **Evaluation:** *"The test case fails if `checkServerTrusted(...)` is implemented in a custom `X509TrustManager` and does **not** properly validate server certificates."*

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila ditemukan salah satu dari enam pola (§1.2):

| No | Pola |
|---|---|
| F1 | Method body kosong — menerima semua sertifikat tanpa validasi apa pun |
| F2 | Menangkap/membungkam exception validasi tanpa melempar ulang |
| F3 | Hanya memanggil `checkValidity()` tanpa validasi trust chain (§1.3) |
| F4 | Trust checks dilonggarkan secara eksplisit untuk sertifikat self-signed/tidak tepercaya |
| F5 | `getAcceptedIssuers()` mengembalikan `null`/array kosong tanpa penanganan tepat |
| F6 | Memakai `checkServerTrusted()` kustom padahal kebutuhan sudah bisa dipenuhi NSC (temuan arsitektural, meski implementasinya sendiri benar) |

**Contoh bukti (ilustratif — MASTG belum menyediakan demo resmi untuk test ini):**

```java
// Ditemukan di com/example/target/net/DevTrustManager.java
public class DevTrustManager implements X509TrustManager {
    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) {
        // TODO: hapus sebelum rilis produksi — sementara terima semua untuk testing
    }
    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) {}
    @Override
    public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[]{}; }
}
```

Interpretasi: nama kelas `DevTrustManager` dan komentar `TODO` mengonfirmasi ini adalah kode testing yang **tertinggal** di produksi — method body kosong (F1) dan `getAcceptedIssuers()` mengembalikan array kosong (F5). **FAIL kritis** — pola persis anti-pattern #2 dan #6 dari klausul resmi.

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi |
|---|---|
| P1 | **Tidak ditemukan** implementasi custom `X509TrustManager` sama sekali — aplikasi mengandalkan sepenuhnya `TrustManager` bawaan sistem/NSC |
| P2 | Implementasi custom ditemukan, namun **benar-benar** memanggil `CertPathValidator`/delegasi ke `TrustManager` sistem, melempar exception yang tepat pada kegagalan, dan tidak menyalahgunakan `getAcceptedIssuers()` |

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **JANGAN PERNAH memercayai klaim `summary` rule semgrep resmi tanpa verifikasi.** Ini pelajaran terpenting dari dokumen ini — rule ini secara eksplisit mengklaim memverifikasi keberadaan `throw`, padahal pattern-nya murni mendeteksi keberadaan method apa pun. Selalu baca isi teknis pattern semgrep, bukan hanya deskripsinya.

2. **Setiap temuan Metode A wajib dilanjutkan ke review isi method** — hasil kosong dari rule ini berarti PASS (tidak ada custom TrustManager sama sekali), tapi hasil **ada temuan** dari rule ini **tidak memberi informasi apa pun** tentang keamanan implementasinya.

3. **`checkValidity()` adalah jebakan paling halus** (§1.3) — kode yang "terlihat" melakukan validasi namun sebenarnya menjawab pertanyaan yang salah. Waspadai pola ini secara khusus saat review manual.

4. **Korelasikan dengan MASTG-TEST-0234/0283** — ekosistem validasi TLS kustom Android memiliki banyak titik kegagalan yang saling terkait (custom TrustManager, hostname verification, SSLSocket) — periksa ketiganya bersama untuk gambaran lengkap.

5. **Severity dimodulasi:**

   | Faktor | Severity |
   |---|---|
   | Method body kosong/selalu menerima, dipakai pada koneksi data sensitif | **Kritis** |
   | `checkValidity()` semata tanpa trust chain, data sensitif | **Tinggi** |
   | Exception dibungkam tapi ada logging yang mendeteksinya (meski tidak menolak koneksi) | **Tinggi** |
   | Implementasi custom yang terbukti benar dan lengkap | **Bukan temuan**, meski tetap dicatat sebagai F6 (pertimbangkan NSC) |

6. **Dokumentasikan:** lokasi kelas custom TrustManager, isi lengkap method `checkServerTrusted()`, pola anti-pattern spesifik yang teridentifikasi (dari keenam kategori §1.2), dan hasil konfirmasi runtime bila dilakukan.

---

## 4. Rekomendasi Perbaikan

### 4.1 Hindari Custom TrustManager Sepenuhnya — Pakai NSC (Sesuai Anti-Pattern #1)

```xml
<network-security-config>
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system" />
        </trust-anchors>
    </base-config>
</network-security-config>
```

### 4.2 Bila Custom TrustManager Tetap Diperlukan, Delegasikan ke Validator Standar

```java
public class ProperCustomTrustManager implements X509TrustManager {
    private final X509TrustManager defaultTrustManager;

    public ProperCustomTrustManager() throws Exception {
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init((KeyStore) null);
        defaultTrustManager = (X509TrustManager) tmf.getTrustManagers()[0];
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        defaultTrustManager.checkServerTrusted(chain, authType);  // delegasi, BUKAN reimplementasi manual
        // Tambahkan pinning di sini bila diperlukan, TETAP lempar exception bila gagal
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return defaultTrustManager.getAcceptedIssuers();  // JANGAN kembalikan null/kosong
    }
}
```

### 4.3 Checklist Remediasi

- [ ] Seluruh implementasi custom `X509TrustManager` sudah diinventarisasi dan ditinjau isi lengkapnya
- [ ] Method `checkServerTrusted()` mendelegasikan ke `TrustManagerFactory` default atau NSC, bukan reimplementasi manual dari nol
- [ ] Tidak ada method body kosong yang menerima semua sertifikat
- [ ] Exception validasi dilempar dengan benar, tidak dibungkam
- [ ] `getAcceptedIssuers()` tidak mengembalikan `null`/array kosong tanpa alasan yang valid
- [ ] Kode testing/development (mis. `DevTrustManager`) dipastikan tidak masuk build produksi
- [ ] **Verifikasi ulang:** jalankan kembali MASTG-TEST-0282 pada APK release final setelah remediasi

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0282: Unsafe Custom Trust Evaluation](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0282/)
- [MASTG-TEST-0234: Missing Implementation of Server Hostname Verification with SSLSockets](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0234/)
- [MASTG-TEST-0283: Incorrect Implementation of Server Hostname Verification](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0283/)
- [MASWE-0027: Insecure Certificate Validation](https://mas.owasp.org/MASWE/MASVS-NETWORK/MASWE-0027/)
- [MASTG-KNOW-0010: Exception Handling](https://mas.owasp.org/MASTG/knowledge/android/MASVS-CODE/MASTG-KNOW-0010/)
- [MASTG-BEST-0021: Ensure Proper Error and Exception Handling](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0021/)
- [Rule resmi: mastg-android-network-checkservertrusted.yml (GitHub)](https://github.com/OWASP/mastg/blob/master/rules/mastg-android-network-checkservertrusted.yml)

### 5.2 Dokumentasi Resmi Android

- [Android Developers — Unsafe X509TrustManager](https://developer.android.com/privacy-and-security/risks/unsafe-trustmanager)
- [Android Developers — `X509TrustManager` API reference](https://developer.android.com/reference/javax/net/ssl/X509TrustManager)
- [Google — How to Fix Apps Containing an Unsafe Implementation of TrustManager](https://support.google.com/faqs/answer/6346016?hl=en)
- [Android Developers — `X509Certificate#checkValidity()`](https://developer.android.com/reference/java/security/cert/X509Certificate#checkValidity())

### 5.3 Riset Akademik dan Sumber Pihak Ketiga

- [Georgiev et al. — The Most Dangerous Code in the World: Validating SSL Certificates in Non-Browser Software](http://www.cs.umd.edu/class/fall2019/cmsc818O/papers/most-dangerous-code.pdf)
- [MalloDroid — Static Analysis Tool for SSL/TLS Misuse Detection](https://www.researchgate.net/publication/262173624_The_most_dangerous_code_in_the_world_validating_SSL_certificates_in_non-browser_software)
- [OWASP — Fail Securely](https://owasp.org/www-community/Fail_securely)
- [OWASP — Improper Error Handling](https://owasp.org/www-community/Improper_Error_Handling)
- [CWE-636: Not Failing Securely ('Failing Open')](https://cwe.mitre.org/data/definitions/636.html)
- [CWE-295: Improper Certificate Validation](https://cwe.mitre.org/data/definitions/295.html)

### 5.4 Dokumentasi Tools

- [Semgrep — Documentation](https://semgrep.dev/docs/)
- [CodeQL — Documentation](https://codeql.github.com/docs/)
- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [Frida — Dynamic instrumentation toolkit](https://frida.re/docs/javascript-api/)
- [MobSF — Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)

---

*Dokumen ini disusun berdasarkan OWASP MASTG (rilis terkini per September 2026), dokumentasi resmi Android Developers, serta riset akademik seminal (Georgiev et al., MalloDroid, SMV-Hunter) tentang kegagalan validasi sertifikat TLS di software non-browser. Temuan paling signifikan dalam riset ini: rule semgrep resmi MASTG untuk test ini memiliki **ketidaksesuaian eksplisit antara klaim deskripsi (`summary`) dan implementasi pattern sebenarnya** — deskripsi mengklaim rule "memastikan exception dilempar", padahal pattern-nya murni mendeteksi keberadaan method apa pun tanpa menilai isinya sama sekali. Ini kasus rule-description-mismatch paling jelas yang ditemukan sepanjang seri riset dokumen ini, menegaskan bahwa verifikasi manual (MASTG-TECH-0023) terhadap keenam anti-pattern resmi tetap menjadi langkah yang benar-benar tidak tergantikan.*
