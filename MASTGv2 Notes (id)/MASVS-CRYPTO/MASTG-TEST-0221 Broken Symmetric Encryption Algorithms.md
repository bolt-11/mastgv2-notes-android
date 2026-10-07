# MASTG-TEST-0221 Broken Symmetric Encryption Algorithms

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0221 |
| **Platform** | Android |
| **Kategori MASVS** | **MASVS-CRYPTO** (MASVS-CRYPTO-1: Aplikasi menggunakan kriptografi terkini yang diterapkan dengan benar) |
| **Weakness** | **MASWE-0007** — *Use of a Broken or Risky Cryptographic Algorithm* |
| **Tipe Pengujian** | **Static**, Code, Manual |
| **Profile** | L1, L2 |
| **Best Practice** | MASTG-BEST-0009 (Use Secure Encryption Algorithms) |
| **Teknik terkait** | MASTG-TECH-0013 (Reverse Engineering Android Apps), MASTG-TECH-0014 (Static Analysis on Android), MASTG-TECH-0023 (Reviewing Decompiled Java Code) |
| **Demo terkait** | MASTG-DEMO-0022 (Uses of Broken Symmetric Encryption Algorithms in Cipher with semgrep) |
| **Test bersaudara** | MASTG-TEST-0232 (Uses of Broken Encryption Modes — ECB/CBC-tanpa-MAC), MASTG-TEST-0208 (Insufficient Key Sizes), MASTG-TEST-0212 (Hardcoded Keys) |
| **APIs utama** | `javax.crypto.Cipher.getInstance(String)`, `javax.crypto.SecretKeyFactory.getInstance(String)`, `javax.crypto.KeyGenerator.getInstance(String)` |
| **CWE terkait** | CWE-327 (Use of a Broken or Risky Cryptographic Algorithm), CWE-326 (Inadequate Encryption Strength), CWE-328 (Use of Weak Hash — untuk algoritma turunan), CWE-1240 (Use of a Cryptographic Primitive with a Risky Implementation) |

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian

Test ini mencari penggunaan **algoritma enkripsi simetris yang sudah dinyatakan rusak (broken)** di dalam kode aplikasi Android, melalui analisis statis.

Kutipan langsung dari overview MASTG:

> *"To test for the use of broken encryption algorithms in Android apps, we need to focus on methods from cryptographic frameworks and libraries that are used to perform encryption and decryption operations."*

Tiga titik masuk API yang disebut eksplisit:

| API | Fungsi |
|---|---|
| **`Cipher.getInstance(String)`** | Inisialisasi objek Cipher untuk enkripsi/dekripsi. **Titik masuk utama** — nama algoritma jadi argumen string |
| **`SecretKeyFactory.getInstance(String)`** | Mengonversi key material menjadi `SecretKey`. Nama algoritma di sini menunjukkan **skema kunci** yang dipakai (mis. `"DES"`, `"DESede"`) |
| **`KeyGenerator.getInstance(String)`** | Menghasilkan kunci simetris. Nama algoritma menentukan jenis kunci yang dibuat |

**Perbedaan mendasar dengan MASTG-TEST-0208** (Insufficient Key Sizes): test itu menilai **ukuran** kunci untuk algoritma yang masih dianggap sah (RSA-1024 vs RSA-3072, AES-128 vs AES-256). Test ini menilai **algoritmanya sendiri** — DES, 3DES, RC4, dan Blowfish tidak bisa diperbaiki dengan memperbesar kunci; mereka rusak secara struktural dan harus **diganti total**.

### 1.2 Empat Algoritma yang Disebut Eksplisit MASTG

MASTG mendaftar empat algoritma broken beserta alasan teknisnya masing-masing — ini bukan opini, melainkan status resmi dari badan standar.

**DES (Data Encryption Standard):**
> *"56-bit key, breakable, [withdrawn by NIST in 2005](https://csrc.nist.gov/pubs/fips/46-3/final)."*

Ruang kunci 56-bit (2⁵⁶ kemungkinan) sudah dapat di-brute-force dengan hardware khusus sejak akhir 1990-an (proyek EFF "Deep Crack" memecahkannya dalam 56 jam pada 1998). NIST menarik FIPS 46-3 (standar DES) pada 2005 — artinya DES **secara resmi bukan lagi standar kriptografi yang disetujui** pemerintah AS selama hampir dua dekade.

**3DES / Triple DES (Triple Data Encryption Algorithm / TDEA):**
> *"64-bit block size, [vulnerable to Sweet32 birthday attacks](https://sweet32.info/), [withdrawn by NIST on January 1, 2024](https://csrc.nist.gov/pubs/sp/800/67/r2/final)."*

3DES memecahkan masalah ruang kunci DES (dengan menerapkan DES tiga kali), tetapi **mewarisi ukuran block 64-bit** yang menjadi masalah baru: **Sweet32 (CVE-2016-2183)**. Ini adalah *birthday attack* — setelah ~2³² block (~32 GB data) yang dienkripsi dengan kunci yang sama dalam mode CBC, peluang **collision** antar ciphertext block menjadi signifikan. Ketika dua ciphertext block bertabrakan, meng-XOR keduanya mengungkap XOR dari plaintext-nya; bila salah satu plaintext diketahui (atau dapat ditebak), plaintext lainnya dapat dipulihkan. Untuk koneksi/enkripsi berumur panjang yang memproses data dalam jumlah besar dengan kunci tetap, ini risiko nyata — bukan sekadar teoretis. **NIST menarik 3DES sepenuhnya per 1 Januari 2024** (SP 800-67 Rev. 2).

**RC4:**
> *"Predictable key stream, allows plaintext recovery [RC4 Weakness](https://www.rc4nomore.com/), disapproved by [NIST](https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-52r1.pdf) in 2014 and prohibited by [IETF](https://datatracker.ietf.org/doc/html/rfc7465) in 2015."*

RC4 adalah stream cipher dengan bias statistik pada byte-byte awal keystream-nya, memungkinkan pemulihan plaintext tanpa perlu mengetahui kunci — terutama saat plaintext yang sama dienkripsi berulang kali (skenario umum di HTTP, seperti cookie). **IETF secara resmi melarang RC4 di TLS lewat RFC 7465 (2015)** — pelarangan protokol tingkat internet, bukan sekadar rekomendasi.

**Blowfish:**
> *"64-bit block size, [vulnerable to Sweet32 attacks](https://en.wikipedia.org/wiki/Birthday_attack), never FIPS-approved, and listed under 'Non-Approved algorithms' in FIPS."*

Blowfish tidak pernah menjadi standar FIPS sejak awal, dan mewarisi masalah block 64-bit yang sama dengan 3DES — rentan Sweet32. Sering muncul di aplikasi karena dianggap "cepat dan sederhana", tanpa disadari kelemahan struktural block size-nya.

**Tabel ringkas untuk referensi cepat:**

| Algoritma | Masalah utama | Status resmi | Kerentanan bernama |
|---|---|---|---|
| **DES** | Kunci 56-bit — brute-forceable | Ditarik NIST (2005) | — |
| **3DES/DESede/TDEA** | Block 64-bit | Ditarik NIST (1 Jan 2024) | Sweet32 (CVE-2016-2183) |
| **RC4/ARCFOUR** | Bias keystream | Dilarang IETF (RFC 7465, 2015); disapproved NIST (2014) | RC4 biases (Royal Holloway attack, dkk.) |
| **Blowfish** | Block 64-bit | Tidak pernah FIPS-approved | Sweet32 |

### 1.3 Algoritma Lain yang Termasuk Broken (Di Luar Empat yang Disebut MASTG)

Overview MASTG eksplisit menyebut "some broken symmetric encryption algorithms **include**" — bukan daftar lengkap. Dokumentasi Android yang dirujuk MASTG (*Broken or Risky Cryptographic Algorithm*) menyebut cakupan lebih luas mencakup fungsi hash dan skema signature, dan dalam praktik pengujian nyata kamu juga harus mencari:

| Algoritma | Kategori | Masalah |
|---|---|---|
| **RC2** | Simetris | Sangat lemah, praktis usang, mirip RC4 dalam ketidakamanan |
| **IDEA** | Simetris | Jarang dipakai, dianggap usang meski belum broken separah DES |
| **SKIPJACK** | Simetris | Algoritma NSA lama (Clipper chip), kunci 80-bit, sudah usang |
| **XOR "encryption"** | Bukan enkripsi sungguhan | Sering ditemukan sebagai implementasi kustom — masuk kategori *"non-approved algorithm"*, bukan sekadar "lemah" |
| **AES/ECB** | Mode, bukan algoritma | AES sendiri kuat, tetapi mode ECB rusak — ini cakupan **MASTG-TEST-0232**, bukan test ini |
| **MD5, SHA-1** (sebagai bagian skema enkripsi/HMAC) | Hash | Disebut Android sebagai *"vulnerable"*; relevan bila dipakai dalam konteks integritas ciphertext |

> **Batasan cakupan test ini:** MASTG-TEST-0221 fokus pada **algoritma enkripsi simetris**. Algoritma hash lemah (MD5/SHA-1) dan mode enkripsi yang salah (ECB) punya test/pembahasan terpisah — jangan campur adukkan saat melaporkan, meski akar masalahnya serupa (kriptografi usang).

### 1.4 Kenapa "Broken" Berbeda dari "Insufficient"

Ini nuansa penting yang membedakan test ini dari MASTG-TEST-0208:

- **AES-128** dianggap MASTG *insufficient* — tetap merupakan algoritma yang solid secara matematis, hanya ukuran kuncinya yang diperdebatkan (lihat pembahasan Grover's algorithm di dokumen MASTG-TEST-0208). Solusinya: **naikkan ukuran kunci**, algoritmanya tetap sama (AES-256).
- **DES/3DES/RC4/Blowfish** dianggap *broken* — cacatnya bersifat **struktural**: ruang kunci terlalu kecil (DES), block size terlalu kecil (3DES/Blowfish), atau bias matematis pada keystream (RC4). **Tidak ada cara memperbaikinya** dengan memperbesar parameter apa pun. Satu-satunya remediasi adalah **mengganti algoritmanya sepenuhnya**.

Ini juga berarti severity default test ini secara umum **lebih tinggi** daripada MASTG-TEST-0208 — tidak ada "cukup aman untuk sekarang, tingkatkan nanti"; broken adalah broken.

### 1.5 Konteks yang "Relevan Secara Keamanan" — Tetap Berlaku di Sini

Sama seperti MASTG-TEST-0204/0205/0212, kriteria evaluasi MASTG mensyaratkan validasi konteks:

> *"Inspect each reported code location using MASTG-TECH-0023 to determine whether the algorithm is used in a **security-relevant context** to protect sensitive data."*

Namun bobotnya berbeda dari test PRNG: penggunaan DES/RC4/Blowfish **hampir selalu** merupakan temuan yang layak dilaporkan, karena:

- Algoritma-algoritma ini **jarang** dipakai untuk keperluan non-kriptografis (checksum, dsb.) — tidak seperti `java.util.Random` yang wajar dipakai untuk animasi.
- Kehadirannya di kode **modern** hampir selalu menandakan salah satu dari: (a) kode warisan yang belum di-refactor, (b) kompatibilitas dengan sistem eksternal lama (mis. integrasi dengan mainframe/API bank lama yang masih mensyaratkan 3DES), atau (c) kesalahan pemilihan algoritma oleh developer.

Tetap lakukan verifikasi MASTG-TECH-0023, tetapi jangan berharap menemukan banyak *false positive* legitimate seperti pada test PRNG — di sini yang perlu ditentukan lebih ke arah **severity** (data apa yang dilindungi) daripada **relevansi** (apakah ini kerentanan sama sekali).

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | MASTG ID | Fungsi |
|---|---|---|
| **jadx** | MASTG-TOOL-0018 | **Dekompilasi DEX → Java** (MASTG-TECH-0013). Wajib untuk MASTG-TECH-0023 — meninjau data apa yang dienkripsi |
| **semgrep** | MASTG-TOOL-0110 | **Pattern matching**. MASTG menyediakan rule `mastg-android-broken-encryption-algorithms.yaml` |
| **ripgrep/grep** | — | Pelengkap wajib — rule MASTG cukup sempit (lihat §3.4) |
| **apktool** | MASTG-TOOL-0011 | Alternatif dekompilasi; analisis smali |

### 2.2 Tools Pendukung

| Tool | Fungsi |
|---|---|
| **CodeQL** | Taint analysis — melacak apakah output `Cipher.getInstance("DES")` benar-benar mengenkripsi data sensitif, bukan sekadar dipanggil di kode mati |
| **MobSF / mobsfscan** | SAST mobile; punya rule bawaan untuk algoritma kripto lemah |
| **SonarQube** | Rule `java:S5547` — *Cipher algorithms should be robust*; `java:S4790` — hashing lemah |
| **Android Lint** | `TrustAllX509TrustManager`, dan check kripto bawaan Android Studio |
| **Frida** (MASTG-TOOL-0001) | Konfirmasi dinamis algoritma yang benar-benar dipakai saat runtime (§3.5) — penting ketika nama algoritma berasal dari variabel/konfigurasi |
| **Ghidra / `strings`** | Konfigurasi kripto di kode native — OpenSSL/BoringSSL yang di-bundle sering memakai konstanta `EVP_des_cbc()`, `EVP_rc4()`, dsb. |
| **APKiD** | Deteksi packer/obfuscator untuk menilai keandalan analisis statis |

### 2.3 Prasyarat Lingkungan

- **Tidak butuh device dan tidak butuh root** untuk analisis statis — cukup APK. Mudah diotomatisasi di CI/CD.
- **APK lengkap**, termasuk semua split APK / dynamic feature module.
- **Rule hanya `languages: java`** — bekerja pada kode hasil dekompilasi, bukan sumber Kotlin. Karena rule ini berbasis `pattern-regex` (bukan pattern AST), ia sebenarnya cukup toleran terhadap variasi sintaks — tetapi tetap butuh string literal nama algoritma untuk terpicu.
- **Ketahui `SecretKeySpec` yang menyertai.** Nama algoritma di `Cipher.getInstance()` harus dikonfirmasi dengan objek kunci yang dipakai (`SecretKeySpec(bytes, "DES")`) — keduanya harus konsisten dan sama-sama menjadi bukti.
- **Waspadai obfuscation nama string.** Nama algoritma (`"DES"`, `"RC4"`) adalah string literal biasa, **bukan** nama API sistem — sehingga **bisa** di-obfuscate (di-XOR, dipecah, di-Base64) oleh developer yang sudah sadar risikonya dan mencoba menyembunyikannya. Ini berbeda dari nama kelas/metode framework yang tidak pernah di-obfuscate ProGuard/R8.

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0013** (*Reverse Engineering Android Apps*) untuk me-reverse engineer aplikasi.
2. Gunakan **MASTG-TECH-0014** (*Static Analysis on Android*) untuk mencari API yang relevan.

Untuk evaluasi: gunakan **MASTG-TECH-0023** untuk meninjau setiap lokasi temuan dan menentukan konteksnya.

### 3.2 Metode A — semgrep dengan rule resmi MASTG *(baseline)*

**Langkah 1 — Dekompilasi:**

```bash
jadx -d ./decompiled ./target-app.apk
```

**Langkah 2 — Jalankan rule resmi MASTG:**

```yaml
rules:
  - id: mastg-android-broken-encryption-algorithms
    languages:
      - java
    severity: WARNING
    metadata:
      summary: This rule looks for broken encryption algorithms.
    message: "[MASVS-CRYPTO-1] Broken encryption algorithms found in use."
    pattern-regex: Cipher\.getInstance\("?(DES|DESede|RC4|Blowfish)(/[A-Za-z0-9]+(/[A-Za-z0-9]+)?)?"?\)
```

```bash
NO_COLOR=true semgrep -c ./rules/mastg-android-broken-encryption-algorithms.yaml \
  ./MastgTest_reversed.java > output.txt
```

Untuk aplikasi nyata:

```bash
NO_COLOR=true semgrep \
  -c ./mastg/rules/mastg-android-broken-encryption-algorithms.yaml \
  ./decompiled/sources/ --json -o findings-broken-crypto.json
```

**Langkah 3 — Review setiap temuan (MASTG-TECH-0023).** Untuk setiap lokasi:
1. Data apa yang dienkripsi/didekripsi di sana?
2. Apakah alur ini benar-benar dieksekusi (bukan dead code)?
3. Apakah ada alasan kompatibilitas eksternal yang sah (integrasi sistem lama), atau murni pilihan yang salah?

### 3.3 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG:**

> **Observation:** *"The output should contain a list of locations where insecure symmetric encryption algorithms are used."*
>
> **Evaluation:** *"The test case **fails** if you can find insecure or deprecated encryption algorithms being used."*
>
> **Further Validation Required:** *"Inspect each reported code location using MASTG-TECH-0023 to determine whether the algorithm is used in a security-relevant context to protect sensitive data."*

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi | Contoh bukti |
|---|---|---|
| F1 | `Cipher.getInstance("DES"...)` dipakai untuk mengenkripsi data | `Cipher.getInstance("DES")` diikuti `cipher.doFinal(sensitiveData)` |
| F2 | `Cipher.getInstance("DESede"...)` (3DES) dipakai | Rentan Sweet32 pada data bervolume besar / koneksi berumur panjang |
| F3 | `Cipher.getInstance("RC4"...)` / `"ARCFOUR"` dipakai | Bias keystream memungkinkan pemulihan plaintext |
| F4 | `Cipher.getInstance("Blowfish"...)` dipakai | Rentan Sweet32; tidak pernah FIPS-approved |
| F5 | `SecretKeyFactory.getInstance("DES")` / `"DESede"` dipakai untuk membangun kunci | Menunjukkan skema kunci untuk algoritma broken, meski `Cipher` belum tampak di baris yang sama |
| F6 | `KeyGenerator.getInstance("DES")` / `"DESede"` / `"RC4"` / `"Blowfish"` | Aplikasi secara aktif membuat kunci untuk algoritma broken |
| F7 | Algoritma broken lain: RC2, IDEA, SKIPJACK, atau XOR kustom | Tidak tercakup rule MASTG — perlu grep tambahan (§3.4) |
| F8 | Algoritma broken dipakai di **kode native** | `strings lib.so` → `EVP_des_cbc`, `EVP_rc4`, `DES_encrypt` |
| F9 | Nama algoritma **di-obfuscate** (dipecah/di-XOR/di-Base64) untuk menghindari deteksi string | `"D"+"E"+"S"` atau `base64decode("UkM0")` (= "RC4") sebelum `getInstance()` |
| F10 | Algoritma broken dikonfirmasi **benar-benar dipanggil** saat runtime (Frida) | Backtrace menunjuk fungsi yang memproses data sensitif |

**Contoh output yang menandakan FAIL — MASTG-DEMO-0022:**

Kode sampel (`MastgTest.kt`) — empat fungsi, masing-masing satu algoritma broken:

```kotlin
// Broken: DES
fun vulnerableDesEncryption(data: String): String {
    val keyBytes = ByteArray(8)
    SecureRandom().nextBytes(keyBytes)
    val keySpec = DESKeySpec(keyBytes)
    val keyFactory = SecretKeyFactory.getInstance("DES")
    val secretKey: Key = keyFactory.generateSecret(keySpec)
    val cipher = Cipher.getInstance("DES")                 // <-- baris 39 (di Java hasil dekompilasi)
    cipher.init(Cipher.ENCRYPT_MODE, secretKey)
    val encryptedData = cipher.doFinal(data.toByteArray())
    return Base64.encodeToString(encryptedData, Base64.DEFAULT)
}

// Broken: 3DES
fun vulnerable3DesEncryption(data: String): String {
    val keyBytes = ByteArray(24)
    val keySpec = DESedeKeySpec(keyBytes)
    val keyFactory = SecretKeyFactory.getInstance("DESede")
    val secretKey: Key = keyFactory.generateSecret(keySpec)
    val cipher = Cipher.getInstance("DESede")               // <-- baris 62
    ...
}

// Broken: RC4
fun vulnerableRc4Encryption(data: String): String {
    val secretKey = SecretKeySpec(keyBytes, "RC4")
    val cipher = Cipher.getInstance("RC4")                  // <-- baris 81
    ...
}

// Broken: Blowfish
fun vulnerableBlowfishEncryption(data: String): String {
    val secretKey: SecretKey = SecretKeySpec(keyBytes, "Blowfish")
    val cipher = Cipher.getInstance("Blowfish")             // <-- baris 100
    ...
}
```

Output semgrep (`output.txt`):

```
┌─────────────────┐
│ 4 Code Findings │
└─────────────────┘

    MastgTest_reversed.java
    ❯❱ rules.mastg-android-broken-encryption-algorithms
          [MASVS-CRYPTO-1] Broken encryption algorithms found in use.

           39┆ Cipher cipher = Cipher.getInstance("DES");
            ⋮┆----------------------------------------
           62┆ Cipher cipher = Cipher.getInstance("DESede");
            ⋮┆----------------------------------------
           81┆ Cipher cipher = Cipher.getInstance("RC4");
            ⋮┆----------------------------------------
          100┆ Cipher cipher = Cipher.getInstance("Blowfish");
```

Evaluasi MASTG: *"The test **fails** due to the use of broken encryption algorithms, specifically DES, 3DES, RC4 and Blowfish."*

**Tiga observasi dari demo ini:**

1. **Rule hanya menangkap `Cipher.getInstance()`, bukan `SecretKeyFactory`/`KeyGenerator`.** Perhatikan bahwa `SecretKeyFactory.getInstance("DES")` dan `SecretKeyFactory.getInstance("DESede")` **tidak muncul** di output, meski keduanya jelas-jelas bagian dari alur enkripsi broken yang sama. Rule ini secara desain sempit — hanya empat baris `Cipher.getInstance` yang terdeteksi dari total delapan pemanggilan API kripto broken di sampel.
2. **Sampel demo ini bersih secara struktur** — setiap fungsi memakai satu algoritma dengan alur lengkap (buat kunci → cipher → enkripsi → encode), memudahkan atribusi. Aplikasi nyata jarang serapi ini; algoritma dan kunci sering dipisah jauh secara baris kode.
3. **Kunci untuk DES/Blowfish sengaja dibuat pendek** (`ByteArray(8)` = 64-bit) dalam sampel — komentar kode menyebutnya *"insufficient key length"*. Ini menunjukkan sampel yang sama **juga** melanggar MASTG-TEST-0208 sekaligus MASTG-TEST-0221: algoritmanya broken **dan** kuncinya juga terlalu pendek. Dalam praktik, jangan berhenti melaporkan hanya satu dimensi ketika keduanya bermasalah.

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi | Contoh bukti |
|---|---|---|
| P1 | **Tidak ada temuan** dari semgrep maupun grep pelengkap | `0 Code Findings`; grep pada RC2/IDEA/XOR juga bersih |
| P2 | Semua enkripsi simetris memakai **AES** (128/256-bit, idealnya 256) dengan mode **GCM** | `Cipher.getInstance("AES/GCM/NoPadding")` |
| P3 | Alternatif modern **ChaCha20-Poly1305** dipakai | `Cipher.getInstance("ChaCha20-Poly1305")` |
| P4 | Ditemukan referensi algoritma broken, tetapi terbukti **dead code** / tidak pernah dipanggil | Dikonfirmasi via call-graph jadx **dan** tidak muncul di trace Frida runtime |
| P5 | Algoritma broken hanya dipakai untuk **interoperabilitas dengan protokol eksternal yang mewajibkannya**, dengan data yang **tidak sensitif** | Kasus langka — tetap dokumentasikan sebagai *risk accepted*, bukan otomatis PASS bersih |
| P6 | Enkripsi dilakukan lewat **library tervalidasi** (Google Tink) yang secara default memilih algoritma aman | `Aead aead = ...; aead.encrypt(plaintext, aad)` — Tink tidak mengekspos pilihan algoritma broken |

**Contoh output yang menandakan PASS:**

```bash
$ NO_COLOR=true semgrep -c mastg-android-broken-encryption-algorithms.yaml ./decompiled/sources/
┌──────────────────┐
│ 0 Code Findings  │
└──────────────────┘

$ rg -n --no-heading '"(DES|DESede|RC4|ARCFOUR|RC2|Blowfish|IDEA|SKIPJACK)"' ./decompiled/sources/
# (tidak ada hasil)
```

Kode yang benar:

```kotlin
// ✅ AES-256-GCM — authenticated encryption, tidak ada mode/algoritma broken
val cipher = Cipher.getInstance("AES/GCM/NoPadding")
cipher.init(Cipher.ENCRYPT_MODE, secretKeyFromKeyStore)
val ciphertext = cipher.doFinal(plaintext)
val iv = cipher.iv

// ✅ Alternatif: ChaCha20-Poly1305 (baik untuk platform tanpa akselerasi AES hardware)
val cipher2 = Cipher.getInstance("ChaCha20-Poly1305")
```

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Rule MASTG hanya menangkap `Cipher.getInstance()` — bukan `SecretKeyFactory` maupun `KeyGenerator`.** Ini celah signifikan yang terbukti langsung di demo resminya sendiri (lihat observasi #1 di atas). Wajib pakai grep pelengkap (§3.4) untuk cakupan penuh sesuai yang disebutkan overview MASTG.

2. **Konteks security-relevant tetap perlu diverifikasi, tetapi jarang jadi alasan PASS.** Berbeda dari test PRNG, kehadiran DES/RC4/Blowfish di kode modern nyaris selalu merupakan temuan yang sah — fokus review MASTG-TECH-0023 di sini lebih ke **menentukan severity** (data apa yang dilindungi) daripada menyaring false positive.

3. **Jangan lupa `SecretKeyFactory` dan `KeyGenerator` sebagai bukti pendukung.** Ketika `Cipher.getInstance("DES")` ditemukan, telusuri ke belakang: dari mana `SecretKey`-nya berasal? Bila dari `SecretKeyFactory.getInstance("DES")`, itu memperkuat bukti bahwa seluruh alur memang dirancang untuk DES, bukan kebetulan.

4. **String algoritma bisa di-obfuscate — beda dari nama API framework.** Nama kelas `Cipher`/`SecretKeyFactory` tidak pernah di-obfuscate (API sistem), tetapi **argumen string** `"DES"`/`"RC4"` adalah data biasa yang **bisa** disembunyikan lewat concatenation, XOR, atau Base64 oleh developer yang menyadari risikonya. Ini pola yang justru meningkatkan kecurigaan — developer yang sengaja menyembunyikan pilihan algoritma broken tahu itu bermasalah.

5. **Waspadai alias nama algoritma yang berbeda antar provider.** `"RC4"` juga dikenal sebagai `"ARCFOUR"`; `"DESede"` juga muncul sebagai `"TripleDES"` atau `"3DES"` tergantung provider JCA. Rule regex MASTG hanya mencakup nama kanonik Java (`DES`, `DESede`, `RC4`, `Blowfish`) — pastikan grep pelengkap mencakup alias-aliasnya.

6. **Output kosong ≠ otomatis PASS.** Penyebab false pass: celah cakupan API (catatan 3), obfuscation string (catatan 4), kode native (titik buta total rule Java), refleksi (`Cipher.getInstance((String) Class.forName(...).getField("ALGO").get(null))`), dan split APK yang tidak dianalisis.

7. **Severity dimodulasi oleh algoritma dan konteks data:**

   | Faktor | Severity |
   |---|---|
   | RC4/DES dipakai untuk data finansial, kesehatan, atau kredensial | **Kritis** |
   | 3DES/Blowfish dipakai pada volume data besar atau koneksi berumur panjang (rentan Sweet32) | **Tinggi** |
   | Algoritma broken untuk data non-sensitif murni (checksum internal, cache non-rahasia) | Rendah — tetap dilaporkan sebagai hygiene issue |
   | Algoritma broken di kode mati/tidak terpanggil | Informational |
   | Algoritma broken untuk interoperabilitas wajib dengan sistem eksternal legacy, data dienkripsi ulang dengan AES setelahnya | Menengah — mitigasi berlapis mengurangi risiko |
   | Nama algoritma di-obfuscate secara sengaja | **Naikkan severity** — indikasi kesadaran risiko tanpa remediasi yang benar |

8. **Dokumentasikan bukti lengkap per temuan:** rule/metode yang menemukan, path + nomor baris, potongan kode dekompilasi (`Cipher.getInstance` **dan** `SecretKeyFactory`/`KeyGenerator` terkait), algoritma spesifik, data yang dilindungi, apakah kode aktif dieksekusi, alias nama yang ditemukan, dan rekomendasi migrasi. Cantumkan juga apakah ditemukan pelanggaran ganda (mis. algoritma broken **dan** kunci pendek sekaligus, seperti pada demo).

### 3.4 Celah Rule MASTG dan Pemeriksaan Pelengkap

| Celah | Contoh yang lolos |
|---|---|
| Tidak mencakup `SecretKeyFactory.getInstance()` | `SecretKeyFactory.getInstance("DESede")` tanpa `Cipher` di baris yang sama |
| Tidak mencakup `KeyGenerator.getInstance()` | `KeyGenerator.getInstance("RC4")` |
| Tidak mencakup **RC2, IDEA, SKIPJACK** | Tidak disebut sama sekali di pattern |
| Tidak mencakup alias (`ARCFOUR`, `TripleDES`) | `Cipher.getInstance("ARCFOUR")` |
| Tidak mencakup XOR kustom (bukan API JCA) | Implementasi `for (i) { out[i] = in[i] ^ key[i % key.length] }` |
| `languages: java` saja | Sumber Kotlin tidak dipindai |
| String yang dipecah/di-obfuscate | `Cipher.getInstance("D" + "ES")` |
| Kode native | Titik buta total |

**Perintah pemeriksaan pelengkap:**

```bash
D=./decompiled/sources

# 1. SecretKeyFactory & KeyGenerator — celah terbesar rule MASTG
rg -n --no-heading 'SecretKeyFactory\.getInstance\(\s*"(DES|DESede|RC4|ARCFOUR|Blowfish|RC2|IDEA)"' $D
rg -n --no-heading 'KeyGenerator\.getInstance\(\s*"(DES|DESede|RC4|ARCFOUR|Blowfish|RC2|IDEA)"' $D

# 2. Cipher.getInstance dengan alias yang tidak tercakup rule
rg -n --no-heading 'Cipher\.getInstance\(\s*"(ARCFOUR|TripleDES|3DES|RC2|IDEA|SKIPJACK)"' $D

# 3. KeySpec yang menandakan algoritma broken meski Cipher-nya tidak terlihat langsung
rg -n --no-heading 'DESKeySpec|DESedeKeySpec|new SecretKeySpec\([^)]*,\s*"(DES|RC4|Blowfish|RC2)"' $D

# 4. Implementasi XOR kustom (bukan enkripsi sungguhan)
rg -n --no-heading '\^\s*key\[|xor.*[Ee]ncrypt|[Ee]ncrypt.*xor' $D

# 5. String algoritma yang mungkin di-obfuscate/dipecah
rg -n --no-heading '"D"\s*\+\s*"ES"|"R"\s*\+\s*"C4"|Base64\.decode\("[A-Za-z0-9+/=]+"\).*getInstance' $D

# 6. Kode native — titik buta total
unzip -o ./target-app.apk -d ./apk_x >/dev/null
for so in $(find ./apk_x -name "*.so"); do
  echo "--- $so"
  strings "$so" | grep -aE "EVP_des|EVP_rc4|DES_encrypt|DES_set_key|BF_encrypt|BF_set_key|RC4\("
done

# 7. Deteksi proteksi yang membatasi keandalan analisis
apkid ./target-app.apk
```

**Rule semgrep perluasan** untuk menutup celah utama:

```yaml
rules:
  - id: custom-broken-crypto-keyfactory-keygen
    severity: ERROR
    languages: [java, kotlin]
    message: "[MASVS-CRYPTO-1] SecretKeyFactory/KeyGenerator untuk algoritma broken"
    pattern-either:
      - pattern: javax.crypto.SecretKeyFactory.getInstance("DES")
      - pattern: javax.crypto.SecretKeyFactory.getInstance("DESede")
      - pattern: javax.crypto.KeyGenerator.getInstance("DES")
      - pattern: javax.crypto.KeyGenerator.getInstance("DESede")
      - pattern: javax.crypto.KeyGenerator.getInstance("RC4")
      - pattern: javax.crypto.KeyGenerator.getInstance("Blowfish")

  - id: custom-broken-crypto-aliases
    severity: ERROR
    languages: [java, kotlin]
    message: "[MASVS-CRYPTO-1] Algoritma broken dengan nama alias"
    pattern-regex: '(Cipher|KeyGenerator|SecretKeyFactory)\.getInstance\(\s*"(ARCFOUR|TripleDES|3DES|RC2|IDEA|SKIPJACK)"'

  - id: custom-broken-crypto-keyspec
    severity: WARNING
    languages: [java, kotlin]
    message: "[MASVS-CRYPTO-1] KeySpec untuk algoritma broken terdeteksi"
    pattern-either:
      - pattern: new javax.crypto.spec.DESKeySpec(...)
      - pattern: new javax.crypto.spec.DESedeKeySpec(...)
```

### 3.5 Konfirmasi Dinamis Opsional

MASTG tidak menyediakan test dinamis untuk ini, tetapi hooking berguna ketika nama algoritma berasal dari **variabel/konfigurasi** yang tidak dapat diselesaikan secara statis, atau untuk menembus obfuscation string.

```javascript
// broken_cipher_trace.js
function bt(max = 10) {
    const E = Java.use("java.lang.Exception");
    const st = E.$new().getStackTrace();
    return Array.from({length: Math.min(max, st.length)}, (_, i) => "    " + st[i]).join("\n");
}

const BROKEN = /^(DES|DESede|RC4|ARCFOUR|Blowfish|RC2|IDEA|SKIPJACK)(\/|$)/i;

Java.perform(() => {
    const Cipher = Java.use("javax.crypto.Cipher");
    Cipher.getInstance.overloads.forEach(ov => {
        ov.implementation = function (...a) {
            const algo = a[0];
            const flag = BROKEN.test(algo) ? "  [!! BROKEN !!]" : "";
            console.log(`\n[Cipher] getInstance("${algo}")${flag}`);
            if (flag) console.log(bt());
            return ov.apply(this, a);
        };
    });

    ['SecretKeyFactory', 'KeyGenerator'].forEach(cls => {
        const K = Java.use(`javax.crypto.${cls}`);
        K.getInstance.overloads.forEach(ov => {
            ov.implementation = function (...a) {
                const algo = a[0];
                const flag = BROKEN.test(algo) ? "  [!! BROKEN !!]" : "";
                console.log(`\n[${cls}] getInstance("${algo}")${flag}`);
                if (flag) console.log(bt());
                return ov.apply(this, a);
            };
        });
    });
});
```

```bash
frida -U -f com.example.target -l broken_cipher_trace.js -o cipher.log
grep -B10 "BROKEN" cipher.log
```

Keunggulan: menangkap nilai `algo` **aktual** meski string-nya dibangun dinamis (concatenation, decode runtime, dari konfigurasi remote) — sesuatu yang mustahil diselesaikan pattern matching statis murni.

---

## 4. Rekomendasi Perbaikan

### 4.1 Prinsip Utama (MASTG-BEST-0009)

MASTG-BEST-0009 menyatakan secara ringkas dan tegas:

> *"Replace insecure encryption algorithms with secure ones such as **AES-256** (preferably in **GCM mode**) or **ChaCha20**."*

**Prioritas 1 — Ganti algoritma broken dengan AES-256-GCM.**

```kotlin
// ❌ SALAH — algoritma broken
val cipher = Cipher.getInstance("DES")
val cipher2 = Cipher.getInstance("DESede")
val cipher3 = Cipher.getInstance("RC4")
val cipher4 = Cipher.getInstance("Blowfish")

// ✅ BENAR — AES-256-GCM (authenticated encryption)
val keyGen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
keyGen.init(
    KeyGenParameterSpec.Builder("vault_key", KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
        .setKeySize(256)
        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
        .setRandomizedEncryptionRequired(true)
        .build()
)
keyGen.generateKey()

val cipher = Cipher.getInstance("AES/GCM/NoPadding")
cipher.init(Cipher.ENCRYPT_MODE, keyFromKeyStore)
val ciphertext = cipher.doFinal(plaintext)
val iv = cipher.iv   // simpan bersama ciphertext
```

**Prioritas 2 — Alternatif ChaCha20-Poly1305** (baik untuk perangkat tanpa akselerasi hardware AES):

```kotlin
val cipher = Cipher.getInstance("ChaCha20-Poly1305")
```

**Prioritas 3 — Gunakan library kripto tervalidasi, bukan konfigurasi manual.** Dokumentasi Android yang dirujuk MASTG-BEST-0009 merekomendasikan **Google Tink**:

```kotlin
// Tink — pilihan algoritma aman secara default, mengurangi kesalahan konfigurasi
val aead = KeysetHandle.generateNew(KeyTemplates.get("AES256_GCM")).getPrimitive(Aead::class.java)
val ciphertext = aead.encrypt(plaintext, associatedData)
val decrypted = aead.decrypt(ciphertext, associatedData)
```

Keunggulan Tink: API-nya **tidak mengekspos** pilihan algoritma broken sama sekali — mustahil secara desain untuk secara tidak sengaja memilih DES/RC4/Blowfish lewat library ini.

**Prioritas 4 — Migrasi bertahap untuk sistem yang mewajibkan algoritma lama.** Bila DES/3DES dipakai untuk interoperabilitas dengan sistem eksternal (mis. HSM bank lama, protokol legacy):

- **Isolasi** penggunaan algoritma lama ke satu lapisan adapter yang jelas terdokumentasi.
- **Enkripsi ulang** (re-encrypt) data dengan AES-256-GCM segera setelah keluar dari lapisan interoperabilitas tersebut — jangan biarkan data "istirahat" dalam bentuk yang dilindungi algoritma broken.
- Tetap **laporkan sebagai temuan** dengan severity yang dikalibrasi terhadap eksposur riil, bukan otomatis di-*whitelist*.
- Rencanakan **migrasi jangka panjang** bersama pemilik sistem eksternal — 3DES sudah ditarik NIST sejak 2024, tekanan kepatuhan hanya akan meningkat.

**Prioritas 5 — Audit ulang kunci dan mode setelah mengganti algoritma.** Mengganti algoritma tanpa memeriksa dimensi lain tidak cukup:
- Pastikan ukuran kunci memadai (MASTG-TEST-0208).
- Pastikan mode enkripsi benar — **hindari ECB**, pakai GCM (MASTG-TEST-0232).
- Pastikan kunci tidak hardcoded (MASTG-TEST-0212) dan berasal dari Android KeyStore.
- Pastikan sumber kunci acak yang benar (MASTG-TEST-0204/0205).

**Prioritas 6 — Tegakkan secara struktural.**
- Tambahkan rule SAST (semgrep + perluasan §3.4) ke CI/CD, gagalkan build bila ditemukan pemanggilan algoritma broken baru.
- Buat **daftar algoritma yang diizinkan** (allowlist) di kebijakan kripto organisasi: AES-256-GCM, ChaCha20-Poly1305, dan larang eksplisit DES/3DES/RC4/RC2/Blowfish/IDEA/SKIPJACK.
- Aktifkan **SonarQube `java:S5547`** atau Android Lint kripto sebagai gate tambahan di IDE.
- Audit library pihak ketiga — jalankan pemindaian juga pada kode library hasil dekompilasi, karena SDK usang kadang masih memakai DES/RC4 secara internal.

### 4.2 Checklist Remediasi

- [ ] Setiap temuan `Cipher.getInstance` untuk algoritma broken sudah ditinjau dengan MASTG-TECH-0023
- [ ] `SecretKeyFactory.getInstance` dan `KeyGenerator.getInstance` untuk algoritma broken juga sudah diperiksa (celah rule MASTG)
- [ ] Tidak ada penggunaan DES, 3DES/DESede, RC4/ARCFOUR, atau Blowfish
- [ ] Tidak ada penggunaan RC2, IDEA, SKIPJACK, atau implementasi XOR kustom sebagai "enkripsi"
- [ ] Semua enkripsi simetris memakai **AES-256-GCM** atau **ChaCha20-Poly1305**
- [ ] Pertimbangkan migrasi ke **Google Tink** untuk mengeliminasi risiko salah pilih algoritma
- [ ] Bila algoritma lama tetap dipakai untuk interoperabilitas eksternal: diisolasi ke satu lapisan, data di-re-encrypt dengan AES setelahnya, dan didokumentasikan sebagai risiko yang diterima
- [ ] Kode native (`.so`) diperiksa untuk `EVP_des_*`, `EVP_rc4`, `DES_*`, `BF_*`
- [ ] String nama algoritma yang di-obfuscate/dipecah sudah ditelusuri dan dievaluasi
- [ ] Ukuran kunci, mode enkripsi, sumber kunci, dan penyimpanan kunci diverifikasi ulang setelah migrasi algoritma (silang dengan TEST-0208/0212/0204/0205/0232)
- [ ] Library pihak ketiga diaudit untuk penggunaan algoritma broken internal
- [ ] Semua split APK / dynamic feature module ikut dianalisis
- [ ] Daftar algoritma yang diizinkan (allowlist) didokumentasikan sebagai kebijakan kripto organisasi
- [ ] Scan SAST (semgrep + perluasan, SonarQube) terintegrasi di CI/CD sebagai gate
- [ ] **Verifikasi ulang:** jalankan kembali MASTG-TEST-0221 + grep pelengkap → tidak ada algoritma broken tersisa
- [ ] **Verifikasi silang:** MASTG-TEST-0232 (mode enkripsi), MASTG-TEST-0208 (ukuran kunci), MASTG-TEST-0212 (kunci hardcoded)

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0221: Broken Symmetric Encryption Algorithms](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0221/)
- [MASWE-0007: Use of a Broken or Risky Cryptographic Algorithm](https://mas.owasp.org/MASWE/MASVS-CRYPTO/MASWE-0007/)
- [MASTG-DEMO-0022: Uses of Broken Symmetric Encryption Algorithms in Cipher with semgrep](https://mas.owasp.org/MASTG/demos/android/MASVS-CRYPTO/MASTG-DEMO-0022/MASTG-DEMO-0022/)
- [MASTG-BEST-0009: Use Secure Encryption Algorithms](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0009/)
- [MASTG-TEST-0232: Uses of Broken Encryption Modes](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0232/)
- [MASTG-TEST-0208: Insufficient Key Sizes](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0208/)
- [MASTG-TEST-0212: Use of Hardcoded Cryptographic Keys in Code](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0212/)
- [MASTG-TECH-0013: Reverse Engineering Android Apps](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/)
- [MASTG-TECH-0014: Static Analysis on Android](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/)
- [MASTG-TECH-0023: Reviewing Decompiled Java Code](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0023/)
- [MASTG-TOOL-0110: semgrep](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0110/)
- [MASTG Rules — `mastg-android-broken-encryption-algorithms.yaml`](https://github.com/OWASP/mastg/blob/master/rules/mastg-android-broken-encryption-algorithms.yaml)
- [MASTG — Testing Cryptography (Identifying Insecure and/or Deprecated Cryptographic Algorithms)](https://mas.owasp.org/MASTG/0x04g-Testing-Cryptography/)
- [MASVS-CRYPTO: Cryptography](https://mas.owasp.org/MASVS/06-MASVS-CRYPTO/)
- [OWASP Mobile Top 10 2024 — M10: Insufficient Cryptography](https://owasp.org/www-project-mobile-top-10/2023-risks/m10-insufficient-cryptography.html)

### 5.2 Dokumentasi Resmi Android / Google / Java

- [Broken or Risky Cryptographic Algorithm — Android Security Risks](https://developer.android.com/privacy-and-security/risks/broken-cryptographic-algorithm)
- [`javax.crypto.Cipher` — API reference](https://developer.android.com/reference/javax/crypto/Cipher)
- [`javax.crypto.Cipher.getInstance` — API reference](https://developer.android.com/reference/javax/crypto/Cipher#getInstance(java.lang.String))
- [`javax.crypto.SecretKeyFactory` — API reference](https://developer.android.com/reference/javax/crypto/SecretKeyFactory)
- [`javax.crypto.KeyGenerator` — API reference](https://developer.android.com/reference/javax/crypto/KeyGenerator)
- [Java Cryptography Architecture — Standard Algorithm Names](https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html)
- [Android Keystore system](https://developer.android.com/privacy-and-security/keystore)
- [Cryptography best practices](https://developer.android.com/privacy-and-security/cryptography)
- [Google Tink — what is Tink](https://developers.google.com/tink/what-is)
- [Android Security Lints (GitHub)](https://github.com/google/android-security-lints)

### 5.3 Standar Kriptografi & Riwayat Deprecation

- [NIST FIPS 46-3 (DES) — withdrawn 2005](https://csrc.nist.gov/pubs/fips/46-3/final)
- [NIST SP 800-67 Rev. 2 — 3DES withdrawn effective January 1, 2024](https://csrc.nist.gov/pubs/sp/800/67/r2/final)
- [NIST SP 800-52 Rev. 1 — RC4 disapproved](https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-52r1.pdf)
- [RFC 7465 — Prohibiting RC4 Cipher Suites (IETF, 2015)](https://datatracker.ietf.org/doc/html/rfc7465)
- [RC4 NOMORE — RC4 weakness research](https://www.rc4nomore.com/)
- [FIPS 140-2 Security Policy — Blowfish listed under Non-Approved algorithms](https://csrc.nist.gov/csrc/media/projects/cryptographic-module-validation-program/documents/security-policies/140sp2092.pdf)
- [CWE-327: Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)
- [CWE-326: Inadequate Encryption Strength](https://cwe.mitre.org/data/definitions/326.html)
- [CWE-328: Use of Weak Hash](https://cwe.mitre.org/data/definitions/328.html)
- [CWE-1240: Use of a Cryptographic Primitive with a Risky Implementation](https://cwe.mitre.org/data/definitions/1240.html)
- [SonarQube Rule java:S5547 — Cipher algorithms should be robust](https://rules.sonarsource.com/java/RSPEC-5547/)
- [NIST SP 800-163 Rev.1 — Vetting the Security of Mobile Applications](https://csrc.nist.gov/publications/detail/sp/800-163/rev-1/final)

### 5.4 Riset Keamanan & Artikel Teknis (Sweet32, RC4)

- [Sweet32.info — Birthday attacks on 64-bit block ciphers in TLS and OpenVPN (CVE-2016-2183)](https://sweet32.info/)
- [Rapid7 — TLS/SSL Birthday attacks on 64-bit block ciphers (SWEET32)](https://www.rapid7.com/db/vulnerabilities/ssl-cve-2016-2183-sweet32/)
- [Red Hat — SWEET32: Birthday attacks against TLS ciphers with 64-bit block size](https://access.redhat.com/articles/2548661)
- [SonicWall — SWEET32 vulnerability of 64-bit ciphers (3DES/Blowfish)](https://www.sonicwall.com/support/knowledge-base/sweet32-vulnerability-of-64-bit-ciphers-3des-blowfish-cve-2016-2183/170505312196945/)
- [Acunetix — TLS/SSL Sweet32 attack](https://www.acunetix.com/vulnerabilities/web/tls-ssl-sweet32-attack/)
- [Wikipedia — Birthday attack](https://en.wikipedia.org/wiki/Birthday_attack)
- [HackTricks — Android Applications Pentesting](https://book.hacktricks.wiki/en/mobile-pentesting/android-app-pentesting/index.html)

### 5.5 Dokumentasi Tools

- [Semgrep — Documentation](https://semgrep.dev/docs/)
- [CodeQL — Documentation](https://codeql.github.com/docs/)
- [MobSF — Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)
- [mobsfscan](https://github.com/MobSF/mobsfscan)
- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [apktool — Reverse engineering Android APK files](https://apktool.org/)
- [Frida — Documentation Home](https://frida.re/docs/home/)
- [Ghidra — software reverse engineering framework](https://ghidra-sre.org/)
- [APKiD — Android Application Identifier](https://github.com/rednaga/APKiD)
- [Google Tink — cryptographic library](https://github.com/tink-crypto/tink)

---

*Dokumen ini disusun berdasarkan OWASP MASTG (rilis terkini per September 2026), dokumentasi resmi Android Developers dan Java, standar NIST/IETF/CWE, serta riset keamanan pihak ketiga tentang Sweet32 dan kelemahan RC4.*
