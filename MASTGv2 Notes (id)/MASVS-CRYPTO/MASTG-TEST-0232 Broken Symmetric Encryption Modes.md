# MASTG-TEST-0232 Broken Symmetric Encryption Modes

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0232 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-CRYPTO (MASVS-CRYPTO-1: Aplikasi memakai kriptografi sesuai praktik industri) |
| **Weakness** | MASWE-0007 — *Improper Encryption* |
| **Tipe Pengujian** | Static, Code, **Manual** |
| **Profile** | L1, L2 |
| **Best Practice** | MASTG-BEST-0005 (Use Secure Encryption Modes) |
| **Teknik terkait** | MASTG-TECH-0013 (Reverse Engineering), MASTG-TECH-0014 (Static Analysis), MASTG-TECH-0023 (Reviewing Decompiled Java Code — validasi lanjutan wajib) |
| **Rule resmi** | `mastg-android-broken-encryption-modes.yaml` (ada, tapi cakupannya sempit — lihat §3.2) |
| **Demo terkait** | — (MASTG belum menyediakan demo resmi untuk test ini) |
| **Test terkait** | **MASTG-TEST-0221** (Broken Symmetric Encryption *Algorithms* — DES/RC4/Blowfish; ini menguji **algoritma**, TEST-0232 menguji **mode operasi**) |
| **CWE terkait** | CWE-327 (Use of a Broken or Risky Cryptographic Algorithm), CWE-326 (Inadequate Encryption Strength), CWE-329 (Generation of Predictable IV with CBC Mode) |

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian

Kutipan dari overview resmi MASTG:

> *"To test for the use of broken encryption modes in Android apps, we should focus on methods in cryptographic frameworks and libraries used to configure and apply encryption modes."*

Fokus test ini adalah **mode operasi block cipher** (bukan algoritmanya). Perbedaan dengan MASTG-TEST-0221 penting untuk dipahami sejak awal:

| | MASTG-TEST-0221 | MASTG-TEST-0232 *(dokumen ini)* |
|---|---|---|
| **Yang diuji** | **Algoritma** cipher (DES, 3DES, RC4, Blowfish) | **Mode operasi** cipher (ECB) |
| **Contoh temuan** | `Cipher.getInstance("DES/CBC/PKCS5Padding")` — algoritma DES sudah rusak apa pun mode-nya | `Cipher.getInstance("AES/ECB/PKCS5Padding")` — algoritma AES aman, tapi mode ECB-nya rusak |
| **MASWE** | Berbeda (MASWE algoritma) | MASWE-0007 |

Di Android, kelas `Cipher` (Java Cryptography Architecture/JCA) adalah API utama untuk menentukan mode enkripsi. `Cipher.getInstance()` menerima *transformation string* berformat `"Algorithm/Mode/Padding"`, misalnya `Cipher.getInstance("AES/ECB/PKCS5Padding")`.

### 1.2 Mengapa ECB Rusak

**ECB (Electronic Codebook)**, didefinisikan dalam **NIST SP 800-38A**, membagi plaintext menjadi blok-blok tetap (128-bit untuk AES) dan mengenkripsi **setiap blok secara independen dengan kunci yang sama**. Sifat ini membuatnya **deterministik**: blok plaintext yang identik akan selalu menghasilkan blok ciphertext yang identik.

Konsekuensinya:
- **Pola data bocor tanpa perlu mendekripsi apa pun.** Contoh klasik: gambar bitmap yang dienkripsi dengan ECB tetap menampilkan siluet gambar aslinya di ciphertext, karena area warna solid yang berulang menghasilkan blok ciphertext yang identik dan berulang pula.
- **Rentan known-plaintext attack dan chosen-plaintext attack** — bila penyerang tahu sebagian isi plaintext yang bersesuaian dengan sebagian ciphertext, ia bisa membangun tabel pemetaan blok untuk memecahkan bagian ciphertext lain yang memakai blok plaintext sama.
- **Tidak ada IV (Initialization Vector).** Ini pembeda struktural dari mode aman seperti CBC/GCM — ECB tidak mengacak input dengan nilai acak per operasi, sehingga mengenkripsi data yang sama dua kali dengan kunci yang sama akan selalu menghasilkan ciphertext yang sama persis.

**Catatan penting dari overview resmi:** Sejak 2023, **NIST secara resmi merevisi SP 800-38A** dan mengumumkan bahwa ECB "secara umum tidak dianjurkan" (*generally discouraged*) — meski tidak eksplisit dilarang di semua skenario, penggunaannya sangat dibatasi.

### 1.3 Daftar Transformation String yang Dianggap Rentan

Sesuai overview resmi, berikut yang **dianggap rentan** (dirujuk dari panduan Google Play Console):

- `"AES"` — memakai mode **ECB secara default** ketika hanya nama algoritma yang diberikan tanpa spesifikasi mode/padding eksplisit (default JCA provider)
- `"AES/ECB/NoPadding"`
- `"AES/ECB/PKCS5Padding"`
- `"AES/ECB/ISO10126Padding"`

Poin `"AES"` tanpa embel-embel apa pun ini yang paling sering luput dari perhatian — banyak developer mengira `Cipher.getInstance("AES")` "aman karena tidak menyebut ECB", padahal secara default provider JCA di Android/Java memang jatuh ke ECB.

### 1.4 Out of Scope: RSA dengan "ECB" di Transformation String

Bagian ini secara eksplisit ditekankan MASTG karena berpotensi menyebabkan **false positive** yang signifikan:

> *"Asymmetric encryption modes, such as RSA, are out of scope for this test because they don't use block modes like ECB."*

Pada transformation string seperti `"RSA/ECB/OAEPPadding"` atau `"RSA/ECB/PKCS1Padding"`, kata **`ECB` di sini menyesatkan** — RSA tidak beroperasi dalam mode block seperti ECB sama sekali. Penamaan `ECB` pada API kriptografi Java untuk RSA hanyalah **placeholder historis** dalam implementasi provider (lihat kutipan kode OpenJDK `RSACipher.java` yang dirujuk MASTG), bukan indikasi bahwa RSA memakai mode ECB. Memahami nuansa ini penting agar penguji **tidak salah menandai** setiap kemunculan literal string `"ECB"` sebagai temuan valid — konteks algoritma (RSA vs AES/DES/dll.) harus selalu diperiksa lebih dulu.

### 1.5 Kasus Nyata: MEGA Android App & CVE-2026-22906

Dua contoh nyata memperkuat urgensi test ini:

- **MEGA Android app**: Peneliti keamanan dari Digit Institute (Jerman) menemukan `Cipher.getInstance("AES")` pada baris kode tertentu yang secara default jatuh ke `"AES/ECB/PKCS5Padding"` — dilaporkan melalui GitHub issue publik (`meganz/android#299`).
- **CVE-2026-22906**: Kerentanan disclosure informasi akibat kombinasi **AES-ECB dengan hardcoded key** — kredensial pengguna disimpan memakai AES-ECB dengan kunci yang di-embed langsung di aplikasi, memungkinkan penyerang tak terautentikasi yang memperoleh file konfigurasi untuk mendekripsi username/password plaintext. Kasus ini menunjukkan bahwa risiko ECB **berlipat ganda** ketika dikombinasikan dengan masalah lain seperti hardcoded key (MASTG-TEST-0212) — dua kelemahan kriptografi independen yang saling memperparah dampak.

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | MASTG ID | Fungsi |
|---|---|---|
| **jadx** | MASTG-TOOL-0018 | Dekompilasi DEX → Java (MASTG-TECH-0013), dasar untuk pencarian pola transformation string |
| **semgrep** | MASTG-TOOL | Menjalankan rule resmi `mastg-android-broken-encryption-modes.yaml` |
| **grep / ripgrep** | — | Melengkapi cakupan rule resmi yang sempit (lihat §3.2) |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **CodeQL** | Taint analysis — melacak apakah hasil `Cipher.getInstance("AES/ECB/...")` benar-benar dipakai untuk mengenkripsi data sensitif, bukan hanya keberadaan string |
| **MobSF** | Analisis otomatis, sering menandai penggunaan ECB dalam laporan Code Analysis kategori kriptografi |
| **mobsfscan** | CLI mobsf-scan, cocok untuk CI/CD |
| **apktool + baksmali** | Analisis smali untuk kasus di mana transformation string dibangun secara dinamis/di-obfuscate sehingga tidak tertangkap dekompilasi jadx yang bersih |
| **Frida** | Hooking `Cipher.getInstance()` saat runtime untuk menangkap transformation string yang **dibangun secara dinamis** (concatenation, hasil dari config remote) — tidak terlihat oleh analisis statis murni |
| **JEB Decompiler / Ghidra** | Untuk kasus enkripsi diimplementasikan di **kode native** (JNI, OpenSSL `EVP_CIPHER_CTX` dengan `EVP_aes_256_ecb()`), yang di luar jangkauan analisis Java/Kotlin |

### 2.3 Prasyarat Lingkungan

- **Tidak butuh device/root** untuk analisis statis dasar — cukup APK dan tool dekompilasi.
- **Butuh device + Frida** hanya bila menduga ada transformation string yang dibangun dinamis (lihat §2.2, §3.4).
- Sama seperti test kriptografi lain (TEST-0208, 0212, 0221), fokus pengujian sebaiknya pada operasi yang menangani **data sensitif** — bukan setiap pemanggilan `Cipher` di codebase (mis. library pihak ketiga yang memakai ECB untuk data non-sensitif secara internal berisiko lebih rendah, meski tetap layak dicatat).

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0013** untuk reverse engineer aplikasi.
2. Gunakan **MASTG-TECH-0014** untuk mencari API yang relevan.

**Validasi lanjutan wajib** (dari klausul "Further Validation Required" resmi):

> *"Inspect each reported code location using MASTG-TECH-0023 to determine whether this is being used to perform encryption or decryption operations on sensitive data."*

Klausul ini eksplisit menuntut bahwa **setiap temuan lokasi kode harus ditinjau manual** untuk memastikan operasi tersebut benar-benar memproses data sensitif — bukan sekadar keberadaan string `"ECB"` di kode.

### 3.2 Metode A — Rule Semgrep Resmi *(ada, tapi cakupannya sempit)*

Rule resmi MASTG untuk test ini:

```yaml
rules:
  - id: mastg-android-broken-encryption-modes
    languages:
      - java
    severity: WARNING
    metadata:
      summary: This rule looks for broken encryption modes.
    message: "[MASVS-CRYPTO-1] Broken encryption modes found in use."
    pattern-either:
      - pattern: Cipher.getInstance("AES")
      - pattern-regex: Cipher\.getInstance\("?[A-Za-z0-9]+/ECB(/[A-Za-z0-9]+)?"?\)
```

```bash
jadx -d ./decompiled ./target-app.apk
semgrep --config https://raw.githubusercontent.com/OWASP/mastg/master/rules/mastg-android-broken-encryption-modes.yaml ./decompiled/sources/
```

**Celah cakupan yang perlu diketahui penguji** (verifikasi langsung terhadap isi rule di atas):

1. **`languages: [java]` saja** — meski semgrep Java parser umumnya dapat mem-parsing sebagian sintaks yang mirip Kotlin hasil dekompilasi, rule ini **tidak secara eksplisit mendukung Kotlin**. Kode Kotlin asli yang memakai sintaks idiomatik berbeda (mis. penggunaan named argument, string template) berpotensi tidak tertangkap. **Mitigasi:** jalankan tetap pada hasil dekompilasi jadx yang menghasilkan output mirip-Java, atau tambahkan rule kustom berlabel `languages: [java, kotlin]` (Metode B).
2. **Hanya menangkap literal string yang eksplisit** — pola seperti `Cipher.getInstance(algo + "/ECB/PKCS5Padding")` (concatenation) atau `Cipher.getInstance(CIPHER_TRANSFORM_CONST)` (referensi ke konstanta yang didefinisikan di tempat lain) **tidak akan tertangkap** oleh `pattern-regex` yang mengasumsikan literal langsung di dalam pemanggilan.
3. **Tidak mencakup API kriptografi native/BouncyCastle** — implementasi ECB lewat `org.bouncycastle.crypto.modes` atau kode native (`EVP_aes_256_ecb()`) di luar jangkauan rule ini yang murni menyasar `javax.crypto.Cipher`.
4. **Tidak memvalidasi konteks data sensitif** — sesuai klausul "Further Validation Required" resmi, rule ini hanya menandai *lokasi*, bukan menilai apakah operasi tersebut memproses data sensitif.

### 3.3 Metode B — grep/ripgrep + Rule Semgrep Kustom *(menutup celah §3.2)*

```bash
# Menangkap literal AES tanpa mode eksplisit dan variasi ECB
rg -n 'Cipher\.getInstance\(\s*"AES"\s*\)' $D
rg -n 'Cipher\.getInstance\([^)]*ECB[^)]*\)' $D

# Menangkap kasus concatenation / referensi konstanta (celah #2 rule resmi)
rg -n 'Cipher\.getInstance\(\s*\w+\s*\+' $D                    # concatenation
rg -n 'val\s+\w+\s*=\s*"[A-Za-z0-9]+/ECB' $D                   # deklarasi konstanta Kotlin
rg -n 'static final String.*ECB' $D                             # deklarasi konstanta Java

# BouncyCastle ECB mode
rg -n 'org\.bouncycastle\.crypto\.modes\.(AESEngine|.*ECB)' $D
```

Rule semgrep kustom yang mencakup Kotlin dan pola konstanta:

```yaml
rules:
  - id: custom-broken-encryption-modes-extended
    languages: [java, kotlin]
    severity: WARNING
    message: "[MASVS-CRYPTO-1] Kemungkinan penggunaan mode ECB atau default AES tanpa mode eksplisit"
    pattern-either:
      - pattern: Cipher.getInstance("AES")
      - pattern-regex: 'Cipher\.getInstance\(\s*"?[A-Za-z0-9]+/ECB(/[A-Za-z0-9]+)?"?\s*\)'
      - pattern: Cipher.getInstance($CONST)
        metavariable-regex:
          metavariable: $CONST
          regex: '.*(ECB|AES_ECB|CIPHER_TRANSFORM).*'
```

### 3.4 Metode C — Frida (transformation string dinamis, hanya terlihat saat runtime)

Untuk kasus di mana mode dibangun secara dinamis (celah #2 pada §3.2) — misalnya mode dipilih berdasarkan konfigurasi remote atau feature flag — analisis statis murni tidak akan menemukan apa pun. Hooking `Cipher.getInstance()` saat runtime menangkap **nilai transformation string yang benar-benar dipakai**, apa pun cara ia dibangun:

```javascript
// hook-cipher-getinstance.js
Java.perform(function () {
    var Cipher = Java.use("javax.crypto.Cipher");
    Cipher.getInstance.overload("java.lang.String").implementation = function (transformation) {
        console.log("[Cipher.getInstance] transformation = " + transformation);
        if (transformation.indexOf("ECB") !== -1 ||
            transformation === "AES" ||
            transformation === "DES" ||
            transformation === "Blowfish") {
            console.log("  [!] MODE BERPOTENSI RUSAK (ECB / default) terdeteksi saat runtime!");
            console.log("  Stack trace:\n" + Java.use("android.util.Log").getStackTraceString(
                Java.use("java.lang.Throwable").$new()));
        }
        return this.getInstance(transformation);
    };
});
```

```bash
frida -U -f com.target.app -l hook-cipher-getinstance.js --no-pause
```

Metode ini juga berguna untuk **konfirmasi** temuan statis Metode A/B — memastikan kode yang ditemukan benar-benar tereksekusi dan bukan dead code.

### 3.5 Metode D — CodeQL (taint analysis untuk validasi "data sensitif")

Menjawab langsung klausul "Further Validation Required" resmi secara terprogram:

```ql
import java
import semmle.code.java.dataflow.TaintTracking

class SensitiveDataSource extends DataFlow::Node {
  SensitiveDataSource() {
    exists(Variable v |
      v.getName().toLowerCase().regexpMatch(".*(password|token|secret|pin|creditcard|ssn|apikey).*") and
      this.asExpr() = v.getAnAccess()
    )
  }
}

class ECBCipherSink extends DataFlow::Node {
  ECBCipherSink() {
    exists(MethodAccess ma |
      ma.getMethod().hasName("getInstance") and
      ma.getMethod().getDeclaringType().hasQualifiedName("javax.crypto", "Cipher") and
      ma.getAnArgument().(StringLiteral).getValue().matches("%ECB%") |
      this.asExpr() = ma.getAnArgument()
    )
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink
where TaintTracking::localFlow(source, sink)
select sink, source, sink, "Data berlabel sensitif berpotensi terhubung ke operasi Cipher bermode ECB"
```

### 3.6 Metode E — MobSF

```bash
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest
```

Bagian **Code Analysis** MobSF biasanya mencantumkan temuan kategori "ECB mode is known to be weak" atau serupa berdasarkan aturan internalnya sendiri (independen dari rule resmi MASTG) — berguna sebagai **cross-check** kedua terhadap Metode A/B.

### 3.7 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Menemukan literal eksplisit? | Menemukan string dinamis? | Menilai konteks data sensitif? | Kapan dipakai |
|---|---|---|---|---|---|
| **A** | Rule semgrep resmi | ✅ | ❌ | ❌ | Baseline cepat, CI/CD gate awal |
| **B** | grep + rule kustom | ✅ (+konstanta) | Sebagian (referensi var) | ❌ | Menutup celah cakupan rule resmi |
| **C** | Frida | ✅ (yang tereksekusi) | ✅ | ❌ (tapi mengonfirmasi eksekusi nyata) | Menduga transformation string dibangun dinamis |
| **D** | CodeQL | ✅ | ❌ | ✅ (heuristik nama variabel) | Codebase besar, mengurangi beban review manual |
| **E** | MobSF | ✅ | ❌ | ❌ | Triase cepat, laporan siap kutip |

**Kombinasi minimum yang aku rekomendasikan:** **A (rule resmi) → B (grep pelengkap) → review manual MASTG-TECH-0023** pada setiap temuan untuk memenuhi klausul validasi resmi. Tambahkan **C (Frida)** bila aplikasi diketahui memakai konfigurasi kriptografi yang dapat berubah dinamis (mis. driven oleh remote config/feature flag), dan **D (CodeQL)** untuk codebase besar guna mempersempit kandidat yang perlu ditinjau manual.

---

### 3.8 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG:**

> **Observation:** *"The output should contain a list of locations where broken encryption modes are used in cryptographic operations."*
>
> **Evaluation:** *"The test case fails if any broken modes are identified in the app."*
>
> **Further Validation Required:** Setiap lokasi harus diperiksa untuk memastikan bahwa operasi tersebut benar-benar dipakai untuk enkripsi/dekripsi data sensitif.

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi | Contoh bukti |
|---|---|---|
| F1 | Ditemukan `Cipher.getInstance("AES")` tanpa mode eksplisit (default jatuh ke ECB) yang dipakai untuk data sensitif | `Cipher.getInstance("AES")` dipakai mengenkripsi field kredensial |
| F2 | Ditemukan literal eksplisit `"AES/ECB/NoPadding"`, `"AES/ECB/PKCS5Padding"`, atau `"AES/ECB/ISO10126Padding"` pada operasi data sensitif | `Cipher.getInstance("AES/ECB/PKCS5Padding")` untuk enkripsi token sesi |
| F3 | Mode ECB ditemukan melalui transformation string yang dibangun **dinamis** dan dikonfirmasi tereksekusi lewat hooking runtime (Metode C) | Hasil hook Frida menunjukkan `transformation = "AES/ECB/PKCS5Padding"` saat aplikasi menyimpan data ke local storage |
| F4 | Ditemukan implementasi ECB melalui library kriptografi non-JCA (BouncyCastle `AESEngine` dibungkus mode ECB manual, atau kode native `EVP_aes_256_ecb()`) untuk data sensitif | `rg` menemukan `org.bouncycastle.crypto.modes` dikombinasikan ECB pada modul enkripsi payload API |
| F5 | ECB dikombinasikan dengan kelemahan kriptografi lain (mis. hardcoded key dari MASTG-TEST-0212), memperparah dampak eksploitasi | Pola serupa CVE-2026-22906: AES-ECB + hardcoded key untuk menyimpan kredensial |

**Contoh bukti (ilustratif — MASTG belum menyediakan demo resmi untuk test ini):**

```kotlin
// Ditemukan di com/example/target/crypto/DataCrypto.kt (hasil dekompilasi jadx)
object DataCrypto {
    fun encryptUserProfile(data: ByteArray, key: SecretKey): ByteArray {
        val cipher = Cipher.getInstance("AES")   // baris 18 — default ke ECB, TIDAK ADA IV
        cipher.init(Cipher.ENCRYPT_MODE, key)
        return cipher.doFinal(data)
    }
}
```

```bash
$ rg -n 'Cipher\.getInstance\(\s*"AES"\s*\)' ./decompiled/sources/
com/example/target/crypto/DataCrypto.kt:18:        val cipher = Cipher.getInstance("AES")   // default ECB
```

Interpretasi: dipanggil dari `encryptUserProfile` yang jelas memproses data pengguna — **FAIL**. Verifikasi lebih lanjut (MASTG-TECH-0023) harus menelusuri pemanggil `encryptUserProfile` untuk mengonfirmasi jenis data (`data: ByteArray`) benar-benar berisi field sensitif dari profil pengguna.

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi | Contoh bukti |
|---|---|---|
| P1 | **Tidak ditemukan** referensi mode ECB atau `Cipher.getInstance("AES")` tanpa mode eksplisit di seluruh basis kode | Hasil semgrep + grep kosong |
| P2 | Ditemukan literal `"ECB"` tetapi terkonfirmasi konteksnya adalah **RSA** (false positive yang dijelaskan §1.4), bukan symmetric cipher | `Cipher.getInstance("RSA/ECB/OAEPPadding")` — placeholder API, bukan mode block cipher sungguhan |
| P3 | Mode ECB ditemukan, tetapi hanya dipakai untuk data **non-sensitif** yang terbukti lewat review manual (mis. checksum internal, data publik) | Enkripsi ECB dipakai pada modul caching internal untuk data non-rahasia yang sudah publik |
| P4 | Semua operasi enkripsi data sensitif memakai mode terautentikasi seperti **AES/GCM/NoPadding** sesuai rekomendasi MASTG-BEST-0005 | `Cipher.getInstance("AES/GCM/NoPadding")` dengan IV unik per operasi |
| P5 | Kode ECB ditemukan tetapi terbukti **dead code**/tidak pernah dipanggil (dikonfirmasi lewat analisis reachability atau Frida yang tidak pernah menangkap eksekusinya) | Fungsi lama yang sudah tidak dipanggil di path manapun, tersisa dari refactoring |

**Contoh output yang menandakan PASS:**

```bash
$ rg -n 'Cipher\.getInstance\(\s*"AES"\s*\)|ECB' ./decompiled/sources/ | grep -v "RSA"
# (tidak ada hasil — atau seluruh hasil terkonfirmasi RSA placeholder / dead code / data non-sensitif)

$ rg -n 'Cipher\.getInstance\(\s*"AES/GCM' ./decompiled/sources/
com/example/target/crypto/DataCrypto.kt:18:        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
```

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Jangan menandai setiap kemunculan string `"ECB"` secara membabi buta.** Sesuai §1.4, `"RSA/ECB/OAEPPadding"` adalah **false positive murni** — RSA tidak memakai mode block. Selalu periksa algoritma yang mendahului `/ECB/` sebelum menyimpulkan temuan valid.

2. **`Cipher.getInstance("AES")` tanpa argumen mode adalah temuan yang sering terlewat** karena tidak secara literal mengandung kata "ECB" — inilah mengapa rule resmi secara eksplisit menambahkan pattern terpisah untuk kasus ini. Jangan hanya mencari literal string "ECB" saat melakukan grep manual.

3. **Klausul "Further Validation Required" bersifat wajib, bukan opsional.** Berbeda dari beberapa test lain di mana review manual disebut sebagai rekomendasi tambahan, MASTG secara eksplisit menuntut setiap lokasi temuan diperiksa untuk memastikan itu benar operasi pada **data sensitif**. Laporan yang hanya mencantumkan "ditemukan N lokasi ECB" tanpa penilaian konteks data belum memenuhi standar evaluasi resmi test ini.

4. **Transformation string dinamis adalah blind spot signifikan bagi analisis statis murni.** Bila aplikasi menggunakan wrapper kriptografi kustom yang menerima parameter mode dari luar (config, remote flag, atau bahkan hasil `BuildConfig`), grep/semgrep tidak akan menemukan literal `"ECB"` di lokasi pemanggilan — verifikasi lewat Frida (Metode C) menjadi penting untuk kasus ini.

5. **Severity dimodulasi oleh jenis data dan skala paparan:**

   | Faktor | Severity |
   |---|---|
   | ECB dipakai untuk kredensial, PII, atau data finansial, dan dikombinasikan dengan hardcoded key (pola CVE-2026-22906) | **Kritis** |
   | ECB dipakai untuk data sensitif tanpa kombinasi kelemahan lain | **Tinggi** |
   | ECB ditemukan tapi hanya untuk data internal non-sensitif (dikonfirmasi manual) | **Rendah/Informational** |
   | `"AES"` tanpa mode ditemukan pada library pihak ketiga yang di-bundle (bukan kode aplikasi sendiri) | **Menengah** — tetap dilaporkan, tapi prioritas remediasi ada di vendor library |

6. **Dokumentasikan:** lokasi kode (file + baris) hasil dekompilasi, transformation string persis yang ditemukan, hasil analisis reachability/taint (data apa yang mengalir ke operasi tersebut), status konfirmasi manual (MASTG-TECH-0023), dan — bila relevan — hasil hooking runtime yang mengonfirmasi transformation string dinamis benar-benar dieksekusi.

---

## 4. Rekomendasi Perbaikan

### 4.1 Ganti ke Mode Terautentikasi (AES-GCM)

Sesuai **MASTG-BEST-0005**, solusi utama adalah mengganti mode tak-aman dengan **mode enkripsi terautentikasi** seperti **AES-GCM** atau **AES-CCM** (didefinisikan dalam **NIST SP 800-38D**), yang sekaligus menyediakan **kerahasiaan (confidentiality), integritas (integrity), dan autentikasi (authenticity)** dalam satu operasi:

```kotlin
// SEBELUM (rusak — ECB, tanpa IV, tanpa autentikasi integritas)
val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
cipher.init(Cipher.ENCRYPT_MODE, secretKey)
val ciphertext = cipher.doFinal(plaintext)

// SESUDAH (aman — GCM, IV unik per operasi, tag autentikasi built-in)
val cipher = Cipher.getInstance("AES/GCM/NoPadding")
val iv = ByteArray(12).also { SecureRandom().nextBytes(it) }  // IV 96-bit, HARUS unik per operasi
val gcmSpec = GCMParameterSpec(128, iv)                        // tag length 128-bit
cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec)
val ciphertext = cipher.doFinal(plaintext)
// simpan IV bersama ciphertext (IV tidak perlu rahasia, tapi WAJIB unik per enkripsi)
val output = iv + ciphertext
```

**Aturan emas GCM: IV tidak boleh pernah dipakai ulang dengan kunci yang sama.** Reuse IV pada GCM jauh lebih fatal dibanding pada CBC — dapat membocorkan authentication key GCM sepenuhnya (*forbidden attack*). Gunakan `SecureRandom` (bukan `Random`, lihat MASTG-TEST-0204) untuk membangkitkan IV setiap operasi.

### 4.2 Hindari CBC Sebagai Alternatif Utama

Overview MASTG-BEST-0005 secara eksplisit merekomendasikan **menghindari CBC** meskipun CBC lebih aman dibanding ECB:

> *"We recommend avoiding CBC, which while being more secure than ECB, improper implementation, especially incorrect padding, can lead to vulnerabilities such as padding oracle attacks."*

Jika migrasi ke GCM tidak memungkinkan dalam jangka pendek (mis. kompatibilitas dengan sistem legacy), **CBC dengan HMAC terpisah** (encrypt-then-MAC) adalah kompromi yang lebih aman dibanding CBC polos — namun tetap lebih rumit dan rawan kesalahan implementasi dibanding memakai GCM langsung. Prioritaskan GCM untuk implementasi baru.

### 4.3 Gunakan Android Keystore untuk Manajemen Kunci

Kombinasikan perbaikan mode operasi dengan penyimpanan kunci yang aman lewat **Android Keystore System**, alih-alih hardcode kunci di kode (lihat MASTG-TEST-0212):

```kotlin
val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
keyGenerator.init(
    KeyGenParameterSpec.Builder("myAppKeyAlias", KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)   // hanya izinkan mode GCM sejak level pembangkitan kunci
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
        .build()
)
val secretKey = keyGenerator.generateKey()
```

Dengan membatasi `setBlockModes(KeyProperties.BLOCK_MODE_GCM)` sejak level Keystore, penggunaan mode lain (termasuk ECB) untuk kunci tersebut akan **ditolak sistem** — ini mekanisme defense-in-depth yang mencegah regresi ke mode tidak aman di masa depan.

### 4.4 Integrasikan Pemeriksaan ke CI/CD

```bash
#!/bin/bash
# ci-check-ecb-mode.sh
APK=$1
jadx -d /tmp/decompiled_check "$APK" 2>/dev/null
FOUND=$(semgrep --config ./rules/mastg-android-broken-encryption-modes.yaml /tmp/decompiled_check/sources/ --json | jq '.results | length')
if [ "$FOUND" -gt "0" ]; then
    echo "[GAGAL] Ditemukan $FOUND kemungkinan penggunaan mode ECB — periksa dan pastikan bukan false positive RSA"
    exit 1
fi
```

### 4.5 Checklist Remediasi

- [ ] Seluruh pemanggilan `Cipher.getInstance()` di codebase sudah diinventarisasi (termasuk `"AES"` tanpa mode eksplisit)
- [ ] Setiap temuan literal `"ECB"` sudah diverifikasi bukan false positive RSA (§1.4, §3.8 P2)
- [ ] Setiap temuan yang valid sudah ditinjau manual (MASTG-TECH-0023) untuk memastikan/menyangkal keterlibatan data sensitif
- [ ] Seluruh operasi enkripsi data sensitif sudah bermigrasi ke `AES/GCM/NoPadding` dengan IV unik per operasi via `SecureRandom`
- [ ] Kunci kriptografi dikelola lewat Android Keystore dengan `setBlockModes()` dibatasi ke GCM
- [ ] Transformation string dinamis (bila ada) sudah diverifikasi lewat hooking runtime (Frida) untuk memastikan tidak jatuh ke ECB saat production
- [ ] Rule semgrep (resmi + kustom §3.3) diintegrasikan sebagai gate CI/CD
- [ ] **Verifikasi ulang:** jalankan kembali MASTG-TEST-0232 pada APK release final setelah remediasi

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0232: Broken Symmetric Encryption Modes](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0232/)
- [MASTG-TEST-0221: Broken Symmetric Encryption Algorithms](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0221/)
- [MASWE-0007: Improper Encryption](https://mas.owasp.org/MASWE/MASVS-CRYPTO/MASWE-0007/)
- [MASTG-BEST-0005: Use Secure Encryption Modes](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0005/)
- [MASTG-TECH-0013: Reverse Engineering Android Apps](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/)
- [MASTG-TECH-0014: Static Analysis on Android](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/)
- [MASTG-TECH-0023: Reviewing Decompiled Java Code](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0023/)
- [MASTG Document 0x04g — Testing Cryptography](https://mas.owasp.org/MASTG/0x04g-Testing-Cryptography/)
- [Rule resmi: mastg-android-broken-encryption-modes.yaml (GitHub)](https://github.com/OWASP/mastg/blob/master/rules/mastg-android-broken-encryption-modes.yaml)
- [OWASP Mobile Top 10 2024 — M10: Insufficient Cryptography](https://owasp.org/www-project-mobile-top-10/2023-risks/m10-insufficient-cryptography)

### 5.2 Standar dan Dokumentasi Resmi

- [NIST SP 800-38A: Recommendation for Block Cipher Modes of Operation](https://csrc.nist.gov/pubs/sp/800/38/a/final)
- [NIST — Decision to Revise NIST SP 800-38A (2023)](https://csrc.nist.gov/news/2023/decision-to-revise-nist-sp-800-38a)
- [NIST IR 8459 — Report on the Block Cipher Modes of Operation in the NIST SP 800-38 Series](https://nvlpubs.nist.gov/nistpubs/ir/2024/NIST.IR.8459.pdf)
- [NIST SP 800-38D: Recommendation for Block Cipher Modes of Operation — GCM and GMAC](https://csrc.nist.gov/pubs/sp/800/38/d/final)
- [Google — Remediation for Unsafe Encryption Mode Usage (Play Console FAQ)](https://support.google.com/faqs/answer/10046138?hl=en)
- [Android Developers — `Cipher` API reference](https://developer.android.com/reference/javax/crypto/Cipher)
- [Android Developers — Cryptography guidance](https://developer.android.com/privacy-and-security/cryptography)
- [Android Developers — Android Keystore System](https://developer.android.com/privacy-and-security/keystore)
- [Wikipedia — Block cipher mode of operation: ECB](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_codebook_(ECB))
- [Wikipedia — Known-plaintext attack](https://en.wikipedia.org/wiki/Known-plaintext_attack)
- [Wikipedia — Chosen-plaintext attack](https://en.wikipedia.org/wiki/Chosen-plaintext_attack)
- [CWE-327: Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)
- [CWE-329: Generation of Predictable IV with CBC Mode](https://cwe.mitre.org/data/definitions/329.html)

### 5.3 Kasus Nyata & Riset Pihak Ketiga

- [CVE-2026-22906: Information Disclosure Vulnerability (AES-ECB + hardcoded key)](https://www.sentinelone.com/vulnerability-database/cve-2026-22906/)
- [meganz/android GitHub Issue #299 — Insecure AES Usage: Defaults to ECB Mode](https://github.com/meganz/android/issues/299)
- [OpenJDK Source — RSACipher.java (penjelasan placeholder "ECB" untuk RSA)](https://github.com/openjdk/jdk/blob/680ac2cebecf93e5924a441a5de6918cd7adf118/src/java.base/share/classes/com/sun/crypto/provider/RSACipher.java#L126)

### 5.4 Dokumentasi Tools

- [Semgrep — Documentation](https://semgrep.dev/docs/)
- [CodeQL — Documentation](https://codeql.github.com/docs/)
- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [Frida — Dynamic instrumentation toolkit](https://frida.re/docs/javascript-api/#cipher)
- [MobSF — Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)
- [mobsfscan](https://github.com/MobSF/mobsfscan)

---

*Dokumen ini disusun berdasarkan OWASP MASTG (rilis terkini per September 2026), publikasi NIST SP 800-38A/D, dokumentasi resmi Android Developers, panduan Google Play Console, serta riset dan laporan kerentanan dunia nyata (CVE-2026-22906, kasus MEGA Android). Test ini memiliki rule semgrep resmi namun dengan cakupan terbatas — rujuk §3.2–3.3 untuk celah cakupan dan cara menutupnya.*
