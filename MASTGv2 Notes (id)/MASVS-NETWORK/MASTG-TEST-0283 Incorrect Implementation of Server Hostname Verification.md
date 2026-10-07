# MASTG-TEST-0283 Incorrect Implementation of Server Hostname Verification

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0283 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-NETWORK (MASVS-NETWORK-2) |
| **Weakness** | MASWE-0027 — *Insecure Certificate Validation* (sama seperti MASTG-TEST-0234/0282) |
| **API yang disorot** | `HostnameVerifier`, `HostnameVerifier#verify(String, SSLSession)` |
| **Tipe Pengujian** | Static, Code, **Manual** |
| **Profile** | L1, L2 |
| **Teknik terkait** | MASTG-TECH-0013, MASTG-TECH-0014, MASTG-TECH-0023 (validasi lanjutan wajib) |
| **Test terkait** | **MASTG-TEST-0234** (Missing Implementation of Server Hostname Verification with SSLSockets — menguji **ketiadaan** `HostnameVerifier` sama sekali; test ini menguji **keberadaan** `HostnameVerifier` yang diimplementasikan **secara salah**), **MASTG-TEST-0282** (Unsafe Custom Trust Evaluation — kelemahan paralel pada `X509TrustManager`) |
| **Demo terkait** | — (tidak ada) |
| **Rule resmi** | `mastg-android-network-hostname-verification.yml` — **rule yang sama** yang dibahas di dokumen MASTG-TEST-0234, namun untuk test ini rule tersebut **secara semantik tepat sasaran** (lihat §1.2) — meski tetap mewarisi celah yang sama: hanya deteksi lokasi, bukan evaluasi keamanan isi |
| **CWE terkait** | CWE-297 (Improper Validation of Certificate with Host Mismatch), CWE-295 |

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian dan Posisinya sebagai Pasangan Komplementer MASTG-TEST-0234

Kutipan overview resmi MASTG:

> *"This test evaluates whether an Android app implements a `HostnameVerifier` that uses `verify(...)` in an unsafe manner, effectively turning off hostname validation for the affected connections."*

Test ini adalah **pasangan cermin** dari MASTG-TEST-0234 yang sudah dibahas mendalam di seri riset ini — keduanya menyasar celah yang identik konsekuensinya (identitas server tidak terverifikasi meski TLS handshake berhasil) namun dari **kondisi awal yang berlawanan**:

| | MASTG-TEST-0234 | MASTG-TEST-0283 *(dokumen ini)* |
|---|---|---|
| **Kondisi yang diperiksa** | `HostnameVerifier` **TIDAK ADA** sama sekali saat memakai `SSLSocket` | `HostnameVerifier` **ADA**, tapi diimplementasikan **secara salah** |
| **Sumber masalah** | Kelalaian — developer lupa/tidak tahu perlu memanggil verifikasi | Kesalahan implementasi — developer **berusaha** memverifikasi tapi logikanya cacat |

Catatan resmi MASTG-TEST-0234 sendiri secara eksplisit menyatakan urutan pengujian yang benar: *"If a `HostnameVerifier` is present, ensure it's not implemented in an unsafe manner. See MASTG-TEST-0283 for guidance"* — menegaskan bahwa kedua test ini **wajib dijalankan berurutan**, bukan sebagai alternatif satu sama lain.

### 1.2 Rule Semgrep yang Sama, Tapi Kini Tepat Sasaran

Ini poin menarik yang melengkapi analisis dari dokumen MASTG-TEST-0234: rule resmi `mastg-android-network-hostname-verification.yml` (yang di dokumen tersebut diidentifikasi **salah sasaran** karena mencari keberadaan `HostnameVerifier` padahal TEST-0234 justru menguji **ketiadaannya**) — untuk **test ini**, rule yang **sama persis** justru **secara semantik tepat**:

```yaml
rules:
  - id: mastg-android-network-hostname-verification
    severity: WARNING
    languages: [java]
    message: Improper server hostname verification detected
    match:
      any:
        - new HostnameVerifier() {...}
```

Karena MASTG-TEST-0283 memang bertujuan menemukan **lokasi keberadaan** implementasi `HostnameVerifier` kustom (untuk kemudian dinilai keamanannya), pola `new HostnameVerifier() {...}` **cocok secara tujuan** dengan kebutuhan test ini. Namun, **celah yang sama seperti dibahas di dokumen MASTG-TEST-0282** tetap berlaku di sini: `{...}` adalah **wildcard body match** — rule ini akan memicu warning **identik** baik untuk implementasi yang aman maupun yang benar-benar cacat (`return true` tanpa syarat). Rule ini **hanya berguna sebagai peta lokasi**, sama sekali tidak bisa dipakai untuk membedakan aman/tidak aman — review manual (MASTG-TECH-0023) tetap mutlak diperlukan pada setiap lokasi yang ditemukan.

### 1.3 Empat Pola Kesalahan Implementasi yang Diperiksa

Klausul "Further Validation Required" resmi memberi **empat pola spesifik**:

**1. Selalu menerima hostname apa pun** — pola paling ekstrem dan paling sering ditemukan di lapangan:

```java
HostnameVerifier allowAllHostnames = new HostnameVerifier() {
    @Override
    public boolean verify(String hostname, SSLSession session) {
        return true;  // SELALU true, terlepas dari hostname atau sertifikat apa pun
    }
};
```

Pola ini sering muncul sebagai "solusi cepat" untuk mengatasi error SSL saat development/debugging terhadap server dengan sertifikat self-signed, yang kemudian **tertinggal** di kode produksi.

**2. Aturan pencocokan yang terlalu longgar** — logika wildcard yang tidak disengaja mencocokkan domain yang tidak dimaksud:

```java
public boolean verify(String hostname, SSLSession session) {
    return hostname.endsWith("example.com");  // BAHAYA: cocok juga untuk "evil-example.com"!
}
```

Kesalahan klasik pemrograman string matching — `endsWith("example.com")` akan **juga** bernilai `true` untuk `"attacker-controlled-example.com"` atau domain apa pun yang secara kebetulan diakhiri string tersebut, bukan hanya subdomain sah dari `example.com`.

**3. Cakupan verifikasi yang tidak lengkap** — hostname verification **tidak diterapkan secara konsisten** di seluruh channel SSL/TLS yang dipakai aplikasi, termasuk yang dibuat lewat `SSLSocket` (koneksi ini yang **secara khusus** menjadi fokus MASTG-TEST-0234) atau saat proses **renegotiation** TLS terjadi di tengah sesi koneksi yang sudah berjalan.

**4. Verifikasi manual yang hilang** — tidak melakukan verifikasi hostname sama sekali ketika API level-rendah yang dipakai (`SSLSocket`) **tidak melakukannya secara otomatis** — ini adalah **irisan langsung** dengan MASTG-TEST-0234, dan overview resmi test ini secara eksplisit menyebutnya sebagai salah satu pola yang perlu diperiksa di sini juga, menegaskan hubungan erat kedua test.

### 1.4 Mengapa Pola #2 (Wildcard Terlalu Longgar) Paling Sulit Terdeteksi Otomatis

Di antara keempat pola, **pola #2** adalah yang paling sulit dideteksi murni lewat pattern-matching statis (semgrep/regex sederhana) — karena tidak ada satu "kata kunci berbahaya" yang bisa dicari; masalahnya terletak pada **logika string matching** yang bisa ditulis dengan berbagai cara (`endsWith`, `contains`, regex custom, `startsWith` yang salah arah). Ini menjelaskan mengapa **CodeQL dengan analisis data flow** (§3.3) jauh lebih bernilai dibanding grep sederhana untuk kategori kesalahan ini — pola logika string yang cacat menuntut pemahaman **struktur kode**, bukan sekadar kecocokan teks.

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | Fungsi |
|---|---|
| **jadx** | Dekompilasi DEX → Java untuk menemukan implementasi `HostnameVerifier` |
| **grep / ripgrep** | Pencarian pola implementasi dan verifikasi logika `verify()` |
| **semgrep** | Menjalankan rule resmi sebagai baseline lokasi |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **CodeQL** | Analisis data flow untuk pola #2 (§1.4) — menelusuri method mana yang dipanggil pada parameter `hostname` (`endsWith`/`contains`/`matches`) sebagai indikasi logika pencocokan yang berpotensi longgar |
| **MalloDroid / SMV-Hunter** (akademik, sama seperti dirujuk di dokumen MASTG-TEST-0282) | Tool riset yang secara spesifik mendeteksi override `HostnameVerifier` yang cacat dalam skala besar |
| **MobSF** | Kadang menandai pola `HostnameVerifier` yang selalu `return true` |
| **Frida** | Hooking `HostnameVerifier.verify()` untuk mengonfirmasi runtime nilai kembalian sesungguhnya dan argumen hostname yang diterima pada koneksi nyata |

### 2.3 Prasyarat Lingkungan

- **Tidak butuh device/root** untuk analisis statis inti.
- **Review manual (MASTG-TECH-0023) mutlak diperlukan** — konsisten dengan tag `manual` pada tipe pengujian test ini, dan sesuai celah rule resmi (§1.2).
- **Periksa SEMUA channel SSL/TLS**, bukan hanya `HttpsURLConnection` — sesuai pola #3 (§1.3), termasuk `SSLSocket` manual dan momen renegotiation.

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0013** untuk reverse engineer aplikasi.
2. Gunakan **MASTG-TECH-0014** untuk mencari API yang relevan.

### 3.2 Metode A — Rule Semgrep Resmi + grep untuk Verifikasi Isi

```bash
jadx -d ./decompiled ./target-app.apk
semgrep --config https://raw.githubusercontent.com/OWASP/mastg/master/rules/mastg-android-network-hostname-verification.yml ./decompiled/sources/
```

```bash
D=./decompiled/sources

# Pola #1: selalu return true tanpa syarat
rg -n -A8 'public boolean verify\(' $D | grep -B5 'return true;' | grep -B10 "^\s*}" | head -50

# Pola #2: logika string matching yang berpotensi longgar
rg -n -A5 'public boolean verify\(' $D | grep -E "endsWith|startsWith|contains|matches"
```

### 3.3 Metode B — CodeQL untuk Pola #1 dan #2

```ql
import java

class HostnameVerifierImpl extends AnonymousClass {
  HostnameVerifierImpl() {
    this.getASupertype().hasQualifiedName("javax.net.ssl", "HostnameVerifier")
  }
}

// Pola #1: verify() tidak pernah mengembalikan false pada jalur manapun
from HostnameVerifierImpl impl, Method verifyMethod
where verifyMethod = impl.getAMethod() and verifyMethod.hasName("verify")
  and not exists(ReturnStmt r | r.getEnclosingCallable() = verifyMethod and
    r.getResult().(BooleanLiteral).getBooleanValue() = false)
select verifyMethod, "verify() TIDAK PERNAH mengembalikan false — kandidat kuat 'always accept'"
```

```ql
// Pola #2: pemakaian String.endsWith/contains pada parameter hostname
import java

from Method verifyMethod, MethodAccess stringMatch
where verifyMethod.hasName("verify") and
      verifyMethod.getDeclaringType().getASupertype*().hasQualifiedName("javax.net.ssl", "HostnameVerifier") and
      stringMatch.getMethod().hasName(["endsWith", "contains", "startsWith"]) and
      stringMatch.getEnclosingCallable() = verifyMethod
select stringMatch, "Logika pencocokan hostname berpotensi longgar — verifikasi manual pola string ini"
```

### 3.4 Metode C — Frida (Konfirmasi Runtime)

```javascript
// hook-hostnameverifier.js
Java.perform(function () {
    Java.enumerateLoadedClasses({
        onMatch: function (className) {
            if (className.indexOf("HostnameVerifier") !== -1 || className.match(/\$\d+$/)) {
                try {
                    var cls = Java.use(className);
                    if (cls.verify) {
                        cls.verify.implementation = function (hostname, session) {
                            var result = this.verify(hostname, session);
                            console.log("[*] " + className + ".verify(" + hostname + ") -> " + result);
                            return result;
                        };
                    }
                } catch (e) {}
            }
        },
        onComplete: function () {}
    });
});
```

```bash
frida -U -f com.target.app -l hook-hostnameverifier.js --no-pause
```

Berinteraksi dengan aplikasi sambil mengamati output — bila `verify()` **selalu** mengembalikan `true` terlepas dari nilai `hostname` yang bervariasi antar koneksi, ini konfirmasi runtime langsung dari pola #1.

### 3.5 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Menemukan pola #1 (always true)? | Menemukan pola #2 (wildcard longgar)? | Kapan dipakai |
|---|---|---|---|---|
| **A** | Rule semgrep + grep | Sebagian (grep manual) | Sebagian | Baseline lokasi |
| **B** | CodeQL | ✅ | ✅ | **Paling bernilai** untuk kedua pola tersulit |
| **C** | Frida | ✅ (konfirmasi empiris) | ✅ (terlihat dari hostname bervariasi yang tetap lolos) | Konfirmasi kandidat prioritas tinggi |

**Kombinasi minimum yang aku rekomendasikan:** **A (inventarisasi lokasi) → B (CodeQL untuk kedua pola tersulit) → C (Frida untuk konfirmasi runtime)**, dilengkapi review manual MASTG-TECH-0023 pada seluruh temuan sesuai klausul wajib resmi.

---

### 3.6 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG:**

> **Evaluation:** *"The test case fails if the app does **not** properly validate that the server's hostname matches the certificate."*

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila ditemukan salah satu dari empat pola (§1.3):

| No | Pola |
|---|---|
| F1 | `verify()` di-override untuk selalu mengembalikan `true` tanpa syarat |
| F2 | Logika pencocokan hostname terlalu longgar (mis. `endsWith` tanpa validasi struktur domain yang tepat) |
| F3 | Verifikasi tidak diterapkan konsisten di semua channel (`SSLSocket`, renegotiation) |
| F4 | Verifikasi manual hilang saat memakai API level-rendah yang tidak otomatis melakukannya (irisan dengan MASTG-TEST-0234) |

**Contoh bukti (ilustratif — MASTG belum menyediakan demo resmi untuk test ini):**

```java
HostnameVerifier verifier = new HostnameVerifier() {
    @Override
    public boolean verify(String hostname, SSLSession session) {
        return hostname.contains("mycompany");  // Pola #2 — "evil-mycompany-phishing.com" akan LOLOS
    }
};
```

Interpretasi: logika `contains("mycompany")` akan meloloskan **domain apa pun** yang mengandung substring tersebut, termasuk domain milik penyerang yang sengaja menyisipkan kata kunci tersebut — **FAIL** sesuai pola #2.

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi |
|---|---|
| P1 | **Tidak ditemukan** implementasi custom `HostnameVerifier` — aplikasi mengandalkan verifikasi default sistem (`HttpsURLConnection`) |
| P2 | Implementasi custom ditemukan, namun mendelegasikan ke `HttpsURLConnection.getDefaultHostnameVerifier()` atau melakukan pencocokan struktural yang benar (exact match/pencocokan domain lengkap, bukan substring) |
| P3 | Verifikasi diterapkan konsisten di seluruh channel, termasuk `SSLSocket` |

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Jangan mengandalkan rule semgrep untuk menilai keamanan isi** — sama seperti dokumen MASTG-TEST-0282, rule ini hanya inventarisasi lokasi.

2. **Pola #2 (wildcard longgar) menuntut perhatian ekstra** — ini kesalahan yang paling mudah lolos code review karena kode **terlihat** melakukan validasi yang masuk akal secara sekilas.

3. **Selalu jalankan berdampingan dengan MASTG-TEST-0234** — sesuai §1.1, kedua test membentuk alur evaluasi lengkap: 0234 memastikan verifier **ada**, 0283 memastikan verifier tersebut **benar**.

4. **Severity dimodulasi** oleh sensitivitas data yang melewati koneksi yang terpengaruh, konsisten dengan pola di dokumen MASTG-TEST-0234/0282.

5. **Dokumentasikan:** lokasi implementasi `HostnameVerifier`, pola kesalahan spesifik yang teridentifikasi (dari keempat kategori), dan hasil konfirmasi runtime bila dilakukan.

---

## 4. Rekomendasi Perbaikan

### 4.1 Delegasikan ke Verifier Default Sistem

```java
HostnameVerifier verifier = HttpsURLConnection.getDefaultHostnameVerifier();
if (!verifier.verify(expectedHostname, sslSession)) {
    throw new SSLPeerUnverifiedException("Hostname tidak cocok: " + expectedHostname);
}
```

### 4.2 Bila Kustomisasi Diperlukan, Pakai Pencocokan Domain yang Tepat

```java
// SALAH
return hostname.endsWith("example.com");

// BENAR — pencocokan domain penuh, bukan substring
return hostname.equals("api.example.com") || hostname.equals("example.com");
```

### 4.3 Checklist Remediasi

- [ ] Seluruh implementasi custom `HostnameVerifier` diinventarisasi dan ditinjau isinya
- [ ] Tidak ada `verify()` yang selalu mengembalikan `true`
- [ ] Logika pencocokan hostname memakai exact match, bukan substring/wildcard longgar
- [ ] Verifikasi diterapkan konsisten di seluruh channel (`HttpsURLConnection`, `SSLSocket`)
- [ ] **Verifikasi ulang:** jalankan kembali MASTG-TEST-0283 berdampingan dengan MASTG-TEST-0234

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0283: Incorrect Implementation of Server Hostname Verification](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0283/)
- [MASTG-TEST-0234: Missing Implementation of Server Hostname Verification with SSLSockets](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0234/)
- [MASTG-TEST-0282: Unsafe Custom Trust Evaluation](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0282/)
- [MASWE-0027: Insecure Certificate Validation](https://mas.owasp.org/MASWE/MASVS-NETWORK/MASWE-0027/)
- [Rule resmi: mastg-android-network-hostname-verification.yml (GitHub)](https://github.com/OWASP/mastg/blob/master/rules/mastg-android-network-hostname-verification.yml)

### 5.2 Dokumentasi Resmi Android

- [Android Developers — Unsafe HostnameVerifier](https://developer.android.com/privacy-and-security/risks/unsafe-hostname)
- [Android Developers — `HostnameVerifier` API reference](https://developer.android.com/reference/javax/net/ssl/HostnameVerifier)
- [Android Developers — `HttpsURLConnection.getDefaultHostnameVerifier()`](https://developer.android.com/reference/javax/net/ssl/HttpsURLConnection#getDefaultHostnameVerifier())

### 5.3 Riset dan Sumber Pihak Ketiga

- [Georgiev et al. — The Most Dangerous Code in the World](http://www.cs.umd.edu/class/fall2019/cmsc818O/papers/most-dangerous-code.pdf)
- [CWE-297: Improper Validation of Certificate with Host Mismatch](https://cwe.mitre.org/data/definitions/297.html)

### 5.4 Dokumentasi Tools

- [Semgrep — Documentation](https://semgrep.dev/docs/)
- [CodeQL — Documentation](https://codeql.github.com/docs/)
- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [Frida — Dynamic instrumentation toolkit](https://frida.re/docs/javascript-api/)

---

*Dokumen ini disusun berdasarkan OWASP MASTG (rilis terkini per September 2026) dan dokumentasi resmi Android Developers. Sebagai pasangan cermin dari MASTG-TEST-0234, test ini melengkapi evaluasi hostname verification: memastikan implementasi yang **ada** benar-benar aman, bukan hanya memastikan keberadaannya. Rule semgrep resmi yang dibahas di dokumen MASTG-TEST-0234 (di sana dinilai salah sasaran) justru **tepat sasaran secara tujuan** untuk test ini — namun tetap mewarisi keterbatasan fundamental yang sama: hanya mendeteksi lokasi, tidak pernah mengevaluasi keamanan isi implementasinya.*
