# MASTG-TEST-0208 Insufficient Key Sizes

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0208 |
| **Platform** | Android |
| **Kategori MASVS** | **MASVS-CRYPTO** (MASVS-CRYPTO-1: Aplikasi menggunakan kriptografi terkini yang diterapkan dengan benar) |
| **Weakness** | **MASWE-0013** — *Improper Cryptographic Key Generation* |
| **Tipe Pengujian** | **Static**, Code |
| **Profile** | L1, L2 |
| **Knowledge** | MASTG-KNOW-0012 (Key Generation) |
| **Teknik terkait** | MASTG-TECH-0013 (Reverse Engineering Android Apps), MASTG-TECH-0014 (Static Analysis on Android), MASTG-TECH-0023 (Reviewing Decompiled Java Code) |
| **Demo terkait** | MASTG-DEMO-0012 (Cryptographic Key Generation With Insufficient Key Length) |
| **APIs utama** | `javax.crypto.KeyGenerator` (`init(int keysize)`), `java.security.KeyPairGenerator` (`initialize(int keysize)`) |
| **CWE terkait** | CWE-326 (Inadequate Encryption Strength), CWE-310 (Cryptographic Issues), CWE-327 (Use of a Broken or Risky Cryptographic Algorithm), CWE-1240 (Use of a Cryptographic Primitive with a Risky Implementation) |
| **Standar acuan** | NIST SP 800-57 Part 1, NIST SP 800-131A Rev. 2, NIST IR 8547, CNSA 2.0, BSI TR-02102-1, ECRYPT-CSA |

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian

Test ini mencari **penggunaan panjang kunci (key size) yang tidak memadai** dalam aplikasi Android melalui analisis statis.

Kutipan langsung dari overview MASTG:

> *"In this test case, we will look for the use insufficient key sizes in Android apps. To do this, we need to focus on the cryptographic frameworks and libraries that are available in Android and the methods that are used to generate, inspect and manage cryptographic keys."*
>
> *"The Java Cryptography Architecture (JCA) provides foundational classes for key generation which are often used directly when portability or compatibility with older systems is a concern."*
>
> - *"**`KeyGenerator`**: ... used to generate symmetric keys including **AES, DES, ChaCha20 or Blowfish**, as well as various **HMAC** keys. The key size can be specified using the `init(int keysize)` method."*
> - *"**`KeyPairGenerator`**: ... used for generating key pairs for asymmetric encryption (e.g., **RSA, EC**). The key size can be specified using the `initialize(int keysize)` method."*

Jadi ada **dua titik masuk utama** yang harus diperiksa, dan masing-masing punya metode penentu ukuran kunci yang berbeda:

| Kelas | Untuk | Metode penentu ukuran |
|---|---|---|
| `javax.crypto.KeyGenerator` | Kunci **simetris** (AES, DES, ChaCha20, Blowfish) dan **HMAC** | `init(int keysize)` |
| `java.security.KeyPairGenerator` | Key pair **asimetris** (RSA, EC/ECDSA, DSA) | `initialize(int keysize)` |

Perhatikan juga catatan MASTG bahwa JCA sering dipakai langsung *"when portability or compatibility with older systems is a concern"* — ini petunjuk penting: kode yang memakai JCA polos (tanpa Android KeyStore) biasanya adalah kode lama atau kode lintas-platform, dan justru di situlah ukuran kunci warisan sering tertinggal.

### 1.2 Landasan Teknis: Key Size vs Security Bits

Kesalahpahaman paling umum di test ini adalah menyamakan **panjang kunci** dengan **tingkat keamanan**. Keduanya hanya setara pada algoritma simetris; pada algoritma asimetris, hubungannya sangat tidak linier.

**Tabel ekuivalensi kekuatan (berdasarkan NIST SP 800-57 Part 1):**

| Bits of security | Simetris (AES) | RSA (modulus) | ECC (kurva) | Diffie-Hellman / DSA |
|---|---|---|---|---|
| 80 | — (SKIPJACK) | 1024 | 160–223 | 1024 |
| **112** | 3TDEA | **2048** | 224–255 | 2048 |
| **128** | **AES-128** | **3072** | **256–383** | 3072 |
| 192 | AES-192 | 7680 | 384–511 | 7680 |
| 256 | AES-256 | 15360 | 512+ | 15360 |

Implikasi praktisnya:

- **RSA-1024 hanya memberi ~80-bit security** — sudah lama tidak memadai dan sudah *disallowed* oleh NIST.
- **RSA-2048 memberi 112-bit security** — masih dapat diterima, tetapi **dideprecate menuju 2030**.
- **RSA-3072 memberi 128-bit security** — inilah yang setara AES-128 dan direkomendasikan untuk sistem baru yang perlu bertahan setelah 2030.
- **ECC jauh lebih efisien**: EC-256 (P-256) memberi ~128-bit security, setara RSA-3072. Karena itu jangan menganggap "256" pada EC sebanding dengan "256" pada RSA.
- Untuk **HMAC**, panjang kunci sebaiknya minimal sebesar output hash-nya (mis. ≥ 256 bit untuk HMAC-SHA256).

### 1.3 Rekomendasi Panjang Kunci per Algoritma

| Algoritma | ❌ Insufficient | ⚠️ Deprecated / transisi | ✅ Direkomendasikan |
|---|---|---|---|
| **AES** | ≤ 64 bit; algoritma DES/3DES | **128** (lihat §1.4) | **256** |
| **RSA** (enkripsi/signature) | 512, 768, **1024** | **2048** (sampai ~2030) | **3072** atau lebih; 4096 umum dipakai |
| **EC / ECDSA / ECDH** | < 224 (mis. 160, 192) | 224 | **256** (P-256) atau **384** (P-384) |
| **DSA / DH** | 1024 | 2048 | 3072+ |
| **ChaCha20** | — (ukuran kunci tetap) | — | **256** (default) |
| **Blowfish** | < 128; **hindari sepenuhnya** (block 64-bit → *Sweet32*) | — | Ganti ke AES |
| **DES** | **56** — broken | — | Ganti ke AES |
| **3DES / TDEA** | 2-key (112) | 3-key (168 → 112 efektif) — *disallowed* NIST | Ganti ke AES |
| **HMAC** | < ukuran output hash | — | ≥ 256 bit (HMAC-SHA256+) |
| **PBKDF2** (panjang kunci turunan) | < 128 bit | 128 | **256 bit**, dengan iterasi tinggi (lihat §1.6) |

### 1.4 Catatan Penting: Posisi MASTG tentang AES-128 Lebih Ketat daripada NIST

Ini perlu dipahami dengan tepat sebelum melaporkan temuan, karena berpotensi diperdebatkan developer.

Kriteria evaluasi MASTG menyatakan:

> *"For example, a **1024-bit key size is considered insufficient for RSA** encryption and a **128-bit key size is considered insufficient for AES** encryption **considering quantum computing attacks**."*

Pernyataan tentang RSA-1024 tidak kontroversial — semua badan standar sepakat itu sudah tidak memadai. Tetapi pernyataan tentang **AES-128 adalah posisi konservatif yang lebih ketat daripada NIST**, dan penting untuk mengetahui konteksnya:

**Argumen di balik posisi MASTG (algoritma Grover):** algoritma Grover memberi *quadratic speed-up* atas brute-force klasik — pencarian kunci simetris `k` bit yang klasik butuh O(2^k) operasi turun menjadi O(2^(k/2)). Dengan logika ini, AES-128 "turun" menjadi setara ~64-bit terhadap penyerang kuantum, yang jelas tidak memadai. AES-256 tetap memberi ~128-bit efektif — aman untuk masa depan yang terlihat.

**Namun posisi badan standar berbeda:**

- **NIST tetap menganggap AES-128 aman** — bahkan menjadikannya *benchmark* untuk mengukur keamanan primitif post-quantum (PQC Security Category 1). AES-128 masih *approved* di FIPS dan SP 800-131A.
- **CNSA 2.0 (NSA) mewajibkan AES-256** untuk National Security Systems. Menariknya, dengan menerima AES-256 pada level keamanan 256-bit (bukan menuntut "AES-512" yang tidak ada), **CNSA 2.0 sendiri secara implisit mengakui bahwa Grover tidak benar-benar membelah kekuatan AES** dalam praktik.
- **Analisis praktis** menunjukkan serangan Grover terhadap AES-128 tidak realistis karena kebutuhan *circuit depth* yang sangat besar dan sulitnya paralelisasi — Grover tidak paralel dengan baik, sehingga speed-up teoretis tidak terealisasi pada skala nyata.
- Sebaliknya, **kriptografi asimetris (RSA/ECC) memang benar-benar terancam** oleh algoritma Shor. NIST IR 8547 merencanakan **larangan semua kripto kunci publik yang rentan kuantum — termasuk RSA-3072, P-256, P-384 — pada 2035**.

**Cara melaporkan yang saya sarankan:**

| Temuan | Severity yang proporsional |
|---|---|
| RSA ≤ 1024, DES, 3DES, EC < 224 | **Tinggi** — konsensus semua standar; eksploitabilitas nyata |
| RSA 2048 | **Rendah / hardening** — masih approved, tetapi rencanakan migrasi sebelum 2030 |
| **AES-128** | **Rendah / hardening** — laporkan sesuai MASTG, tetapi **nyatakan bahwa NIST/FIPS masih menyetujuinya**; rekomendasikan AES-256 sebagai praktik terbaik dan penyelarasan dengan CNSA 2.0 |
| Kunci asimetris apa pun tanpa rencana migrasi PQC | Informational — relevan untuk roadmap 2030–2035 |

Menyajikannya seperti ini membuat temuanmu **dapat dipertahankan**: kamu mengikuti MASTG (sehingga check-nya FAIL), tetapi tidak melebih-lebihkan risikonya sehingga kredibilitas laporan tetap terjaga. Melaporkan AES-128 sebagai kerentanan kritis akan langsung dibantah oleh tim kripto yang kompeten.

### 1.5 Konteks Android: KeyGenParameterSpec dan Android KeyStore

MASTG-KNOW-0012 menjelaskan bahwa Android 6.0 (API 23) memperkenalkan `KeyGenParameterSpec` untuk memastikan penggunaan kunci yang benar. Ini relevan untuk test ini karena **ukuran kunci dapat ditentukan di beberapa tempat berbeda**, dan tidak semuanya tertangkap rule MASTG:

```kotlin
// Jalur A — JCA polos (yang dicari rule MASTG)
val keyGen = KeyGenerator.getInstance("AES")
keyGen.init(128)                                    // <-- ukuran kunci di sini

val kpg = KeyPairGenerator.getInstance("RSA")
kpg.initialize(1024, SecureRandom())                // <-- ukuran kunci di sini

// Jalur B — KeyGenParameterSpec + Android KeyStore (TIDAK tertangkap rule MASTG)
val spec = KeyGenParameterSpec.Builder("alias", PURPOSE_ENCRYPT or PURPOSE_DECRYPT)
    .setKeySize(128)                                // <-- ukuran kunci di sini
    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
    .build()
KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").init(spec)

// Jalur C — KeyPairGeneratorSpec (deprecated, tetapi masih ada di kode lama)
val kpSpec = KeyPairGeneratorSpec.Builder(context)
    .setAlias(RSA_KEY_ALIAS)
    .setKeySize(4096)                               // <-- ukuran kunci di sini
    .build()

// Jalur D — PBEKeySpec (panjang kunci turunan)
val keySpec = PBEKeySpec(password, salt, iterationCount, 128)   // <-- keyLength di sini

// Jalur E — SecretKeySpec dari byte array (ukuran ditentukan panjang array)
val key = SecretKeySpec(ByteArray(16), "AES")       // <-- 16 byte = 128 bit
```

Kelima jalur ini semuanya menentukan ukuran kunci, tetapi **rule semgrep MASTG hanya mencakup Jalur A** — dan bahkan tidak seluruhnya (lihat §3.4).

Catatan tambahan dari MASTG-KNOW-0012 yang relevan:

- Sebelum Android 6.0 (API 23), **generasi kunci AES tidak didukung** di KeyStore. Akibatnya banyak implementasi memilih RSA dan membuat key pair, atau memakai `SecureRandom` untuk membuat kunci AES. Ini menjelaskan mengapa kode lama sering memuat RSA dengan ukuran warisan.
- Contoh RSA di KNOW-0012 memakai **4096-bit** — praktik yang baik.
- **Sejak Android 11 (API 30), AndroidKeyStore tidak mendukung enkripsi/dekripsi dengan kunci EC** — EC hanya untuk signature. Jadi jangan "memperbaiki" RSA lemah dengan mengganti ke EC untuk enkripsi di KeyStore.
- KNOW-0012 juga memberi peringatan penting: ada **keyakinan salah yang tersebar luas** bahwa NDK dapat dipakai untuk menyembunyikan operasi kriptografi dan kunci hardcoded. Mekanisme ini **tidak efektif** — kunci tetap dapat di-dump dari memori dengan Frida, dan sejak Android 7.0 (API 24) penggunaan API privat tidak diizinkan.

### 1.6 Parameter Lain yang Juga "Insufficient" (Perlu Diperiksa Bersamaan)

Meski test ini secara formal tentang *key size*, dalam praktik pemeriksaan generasi kunci (MASWE-0013) sebaiknya mencakup:

| Parameter | Batas yang tidak memadai | Rekomendasi |
|---|---|---|
| **Iterasi PBKDF2** | MASTG-KNOW-0012 mencontohkan `iterationCount = 10000` — angka ini **sudah usang** | OWASP kini merekomendasikan **600.000** iterasi untuk PBKDF2-HMAC-SHA256; lebih baik lagi gunakan **Argon2id** atau scrypt |
| **Algoritma PRF PBKDF2** | `PBKDF2WithHmacSHA1` | `PBKDF2withHmacSHA256` — KNOW-0012 sendiri menyarankan ini untuk API level di atas Android 8.0 (API 26) |
| **Panjang salt** | < 16 byte | ≥ 16 byte dari `SecureRandom` |
| **Panjang GCM tag** | < 128 bit | 128 bit (`GCMParameterSpec(128, iv)`) |
| **Panjang nonce GCM** | ≠ 12 byte (memicu re-derivasi internal) | 12 byte (96 bit) |
| **Sumber kunci** | `java.util.Random`, timestamp, nilai hardcoded | `SecureRandom` / KeyStore — lihat MASTG-TEST-0204 & 0205 |
| **Ukuran modulus RSA vs padding** | RSA dengan PKCS#1 v1.5 | OAEP untuk enkripsi, PSS untuk signature |

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | MASTG ID | Fungsi dalam test ini |
|---|---|---|
| **jadx** | MASTG-TOOL-0018 | **Dekompilasi DEX → Java** (MASTG-TECH-0013). Wajib juga untuk MASTG-TECH-0023 — memverifikasi konteks penggunaan kunci |
| **semgrep** | MASTG-TOOL-0110 | **Pattern matching**. MASTG menyediakan rule `mastg-android-key-generation-with-insufficient-key-length.yml` |
| **grep / ripgrep** | — | **Pelengkap wajib** — rule MASTG sangat sempit (lihat §3.4) |
| **apktool** | MASTG-TOOL-0011 | Alternatif dekompilasi; analisis smali bila jadx gagal |

### 2.2 Tools Pendukung

| Tool | Fungsi |
|---|---|
| **CodeQL** | Berguna untuk kasus di mana ukuran kunci datang dari **variabel atau konstanta** (mis. `init(KEY_SIZE)`), yang tidak dapat diselesaikan semgrep dengan pattern literal |
| **mobsfscan / MobSF** | SAST mobile; punya rule weak key size bawaan |
| **SonarQube** | Rule `java:S4426` — *Cryptographic keys should be robust* (mendeteksi RSA < 2048, EC < 224, dsb.) |
| **semgrep-rules-android-security** (IMQ Minded Security) | Koleksi rule pihak ketiga; pelengkap rule resmi MASTG |
| **jadx-gui** | Navigasi interaktif + "Find Usage" untuk melacak konstanta ukuran kunci |
| **Frida** | MASTG-TOOL-0001 — **konfirmasi dinamis** ukuran kunci yang benar-benar dipakai saat runtime (lihat §3.5). Sangat berguna ketika ukuran kunci ditentukan variabel |
| **`keytool` / `openssl`** | Memeriksa ukuran kunci pada sertifikat/keystore yang di-bundle di APK (`res/raw/`, `assets/`) |
| **Ghidra / `strings`** | Analisis `.so` — operasi kripto dari kode native tidak terjangkau rule Java |
| **APKiD** | Deteksi packer/obfuscator untuk menilai keandalan analisis statis |

### 2.3 Prasyarat Lingkungan

- **Tidak butuh device dan tidak butuh root** — cukup file APK. Mudah diotomatisasi di CI/CD.
- **APK lengkap**, termasuk semua split APK / dynamic feature module.
- **semgrep terinstall** dan rule MASTG tersedia (`github.com/OWASP/mastg`, direktori `rules/`).
- **Rule hanya `languages: java`** — pemindaian dilakukan pada kode hasil dekompilasi, bukan sumber Kotlin.
- **Perhatikan efek dekompilasi pada konstanta.** Ini penting secara praktis: di sumber Kotlin, demo memakai `KeyProperties.KEY_ALGORITHM_RSA`, tetapi di Java hasil dekompilasi menjadi **literal `"RSA"`**. Rule MASTG mencocokkan literal string, sehingga ia **hanya bekerja pada kode hasil dekompilasi** — bukan pada source code asli yang memakai konstanta `KeyProperties.*`.
- **Waspadai obfuscation.** Nama API JCA (`KeyGenerator`, `KeyPairGenerator`, `init`, `initialize`) tidak di-obfuscate R8/ProGuard karena API sistem, sehingga deteksi tetap efektif. Yang tersulitkan adalah tahap review konteks (nama kelas aplikasi jadi satu huruf).
- **Sediakan tabel acuan panjang kunci** (§1.3) sebagai baseline penilaian, dan sepakati dengan klien standar mana yang dipakai (NIST, BSI, atau CNSA 2.0) — ini menentukan apakah AES-128 dan RSA-2048 dihitung sebagai temuan.

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0013** (*Reverse Engineering Android Apps*) untuk me-reverse engineer aplikasi.
2. Gunakan **MASTG-TECH-0014** (*Static Analysis on Android*) untuk mencari API yang relevan.

Untuk evaluasi: gunakan **MASTG-TECH-0023** (*Reviewing Decompiled Java Code*) untuk meninjau setiap lokasi temuan.

### 3.2 Implementasi Praktis (MASTG-DEMO-0012)

**Langkah 1 — Dekompilasi**

```bash
jadx -d ./decompiled ./target-app.apk

# Bila split APK / AAB, ambil dan dekompilasi semua bagian
adb shell pm path com.example.target
```

**Langkah 2 — Jalankan rule semgrep resmi MASTG**

Rule `mastg-android-key-generation-with-insufficient-key-length.yml`:

```yaml
rules:
  - id: mastg-android-key-generation-with-insufficient-key-length
    severity: WARNING
    languages:
      - java
    metadata:
      summary: This rule looks for methods that create keys with insufficient length in encryption algorithms.
    message: "[MASVS-CRYPTO] Make sure that the key size is according to security best practices"
    pattern-either:
      - pattern: |
          $K = $G.getInstance("RSA");
          ...
          $K.initialize(1024, new SecureRandom());
      - pattern: |
          $K = $G.getInstance("RSA");
          ...
          $K.initialize(512, new SecureRandom());
      - pattern: |
          $K = $G.getInstance("AES");
          ...
          $K.init(128);
```

Menjalankannya (`run.sh` dari demo):

```bash
NO_COLOR=true semgrep -c ../../../../rules/mastg-android-key-generation-with-insufficient-key-length.yml \
  ./MastgTest_reversed.java > output.txt
```

Untuk aplikasi nyata:

```bash
NO_COLOR=true semgrep \
  -c ./mastg/rules/mastg-android-key-generation-with-insufficient-key-length.yml \
  ./decompiled/sources/ --json -o findings-keysize.json
```

**Langkah 3 — Review setiap temuan (MASTG-TECH-0023)**

Untuk setiap lokasi, tentukan:

1. **Algoritma apa** dan **ukuran kunci berapa** persisnya?
2. **Kunci ini dipakai untuk apa** — enkripsi data at-rest, signature, key exchange, atau hanya demo/test code?
3. **Apakah ada lokasi lain** yang menentukan ukuran kunci untuk kunci yang sama (mis. `KeyGenParameterSpec.setKeySize`)?
4. **Apakah kode ini benar-benar dieksekusi** (bukan dead code / library tak terpakai)?

### 3.3 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG:**

> **Observation:** *"The output should contain a list of locations where insufficient key lengths are used."*
>
> **Evaluation:** *"The test case **fails** if you can find the use of insufficient key sizes within the source code. For example, a **1024-bit key size is considered insufficient for RSA** encryption and a **128-bit key size is considered insufficient for AES** encryption considering quantum computing attacks."*

Berbeda dari MASTG-TEST-0204/0205, **test ini tidak mensyaratkan pembuktian konteks security-relevant**. Kriterianya langsung: **ditemukan ukuran kunci tidak memadai → FAIL**. Ini masuk akal karena berbeda dari `Random` (yang punya banyak penggunaan sah), pembuatan kunci kriptografi **selalu** security-relevant secara definisi.

Namun tetap gunakan MASTG-TECH-0023 untuk memastikan kodenya benar-benar aktif dan memahami dampaknya.

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi | Contoh bukti | Severity |
|---|---|---|---|
| F1 | **RSA 512 / 768 / 1024** dipakai | `generator.initialize(1024, new SecureRandom())` | **Tinggi** |
| F2 | **AES-128** dipakai (per kriteria MASTG) | `keyGen1.init(128)` | Rendah/hardening — lihat §1.4 |
| F3 | **DES (56-bit)** atau **3DES** dipakai | `KeyGenerator.getInstance("DES").init(56)` | **Tinggi** — juga algoritma broken (bertaut MASTG-TEST-0221) |
| F4 | **Blowfish** dengan kunci pendek, atau Blowfish sama sekali | `KeyGenerator.getInstance("Blowfish").init(64)` | **Tinggi** — block 64-bit rentan *Sweet32* |
| F5 | **EC / ECDSA dengan kurva < 224 bit** | `kpg.initialize(160)`; kurva `secp160r1`, `prime192v1` | **Tinggi** |
| F6 | **DSA / DH 1024-bit** | `KeyPairGenerator.getInstance("DSA").initialize(1024)` | **Tinggi** |
| F7 | `KeyGenParameterSpec.setKeySize()` dengan nilai tidak memadai | `.setKeySize(128)` untuk AES; `.setKeySize(1024)` untuk RSA | Sesuai algoritma — **tidak tertangkap rule MASTG** |
| F8 | `KeyPairGeneratorSpec.setKeySize()` (deprecated) dengan nilai tidak memadai | `.setKeySize(1024)` | **Tinggi** — **tidak tertangkap rule MASTG** |
| F9 | `SecretKeySpec` dari byte array terlalu pendek | `SecretKeySpec(ByteArray(8), "AES")` → 64 bit | **Tinggi** — **tidak tertangkap rule MASTG** |
| F10 | `PBEKeySpec` dengan `keyLength` tidak memadai | `PBEKeySpec(pw, salt, 10000, 128)` | Menengah — **tidak tertangkap rule MASTG** |
| F11 | Ukuran kunci datang dari **variabel/konstanta** bernilai tidak memadai | `private static final int KEY_SIZE = 1024; ... kpg.initialize(KEY_SIZE)` | Sesuai nilai — **tidak tertangkap rule MASTG** |
| F12 | **RSA-2048** pada aplikasi dengan kebutuhan proteksi jangka panjang (> 2030) | `initialize(2048)` | Rendah/hardening |
| F13 | Ukuran kunci tidak memadai di **kode native** | `strings lib.so` → `RSA_generate_key`, `EVP_PKEY_keygen` dengan parameter kecil | Sesuai — titik buta rule Java |
| F14 | Sertifikat / keystore yang **di-bundle di APK** memakai kunci lemah | `openssl x509 -in assets/pinned.crt -text \| grep "Public-Key"` → `1024 bit` | **Tinggi** |
| F15 | Parameter generasi kunci lain tidak memadai (iterasi PBKDF2 rendah, salt pendek, GCM tag < 128) | `PBEKeySpec(..., 1000, 256)`; `GCMParameterSpec(96, iv)` | Menengah — lihat §1.6 |

**Contoh output yang menandakan FAIL — MASTG-DEMO-0012:**

Kode sampel (`MastgTest.kt`):

```kotlin
val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA)
generator.initialize(1024, SecureRandom())                    // <-- FAIL: RSA-1024
val keypair = generator.genKeyPair()

val keyGen1 = KeyGenerator.getInstance("AES")
keyGen1.init(128)                                             // <-- FAIL: AES-128
val secretKey1: SecretKey = keyGen1.generateKey()

val keyGen2 = KeyGenerator.getInstance("AES")
keyGen2.init(256)                                             // <-- PASS: AES-256
val secretKey2: SecretKey = keyGen2.generateKey()
```

Kode hasil dekompilasi yang dipindai semgrep (`MastgTest_reversed.java`):

```java
public final String mastgTest() {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");     // <-- baris 27
    generator.initialize(1024, new SecureRandom());                      // <-- baris 28
    KeyPair keypair = generator.genKeyPair();
    Log.d("Keypair generated RSA", Base64.encodeToString(keypair.getPublic().getEncoded(), 0));
    KeyGenerator keyGen1 = KeyGenerator.getInstance("AES");               // <-- baris 31
    keyGen1.init(128);                                                   // <-- baris 32
    SecretKey secretKey1 = keyGen1.generateKey();
    ...
    KeyGenerator keyGen2 = KeyGenerator.getInstance("AES");
    keyGen2.init(256);                                                   // tidak terpicu
    ...
}
```

Output semgrep (`output.txt`):

```
┌─────────────────┐
│ 2 Code Findings │
└─────────────────┘

    MastgTest_reversed.java
    ❯❱ rules.mastg-android-key-generation-with-insufficient-key-length
          [MASVS-CRYPTO] Make sure that the key size is according to security best practices

           27┆ KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
           28┆ generator.initialize(1024, new SecureRandom());
            ⋮┆----------------------------------------
           31┆ KeyGenerator keyGen1 = KeyGenerator.getInstance("AES");
           32┆ keyGen1.init(128);
```

Evaluasi MASTG: *"The test **fails** because the key size of the RSA key is set to `1024` bits, and the size of the AES key is set to `128`, which is considered insufficient in both cases."*

**Empat observasi dari demo ini:**

1. **Rule menampilkan DUA baris per temuan** — baris `getInstance(...)` dan baris `init/initialize(...)`. Ini karena pattern-nya bersifat sekuensial (`$K = $G.getInstance("RSA"); ... ; $K.initialize(...)`), sehingga match-nya mencakup rentang kode. Berguna karena langsung memperlihatkan algoritma **dan** ukurannya.
2. **`keyGen2.init(256)` tidak terpicu** — membuktikan rule membedakan ukuran yang memadai dan tidak.
3. **`KeyProperties.KEY_ALGORITHM_RSA` menjadi literal `"RSA"`** setelah dekompilasi. Inilah mengapa rule bekerja pada kode dekompilasi tetapi tidak pada sumber Kotlin yang memakai konstanta.
4. **Demo ini memakai JCA polos tanpa Android KeyStore** — kunci yang dihasilkan berada di memori/heap aplikasi, bukan di secure hardware. Meski bukan fokus test ini, itu **temuan tambahan** yang layak dicatat (bertaut MASWE-0013 dan penyimpanan kunci). Perhatikan juga bahwa sampel demo bahkan **mencatat kunci publik ke log** via `Log.d` (bertaut MASTG-TEST-0203) — untuk kunci publik ini tidak sensitif, tetapi pola yang sama dengan `secretKey.encoded` akan menjadi kebocoran kunci privat.

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi | Contoh bukti |
|---|---|---|
| P1 | **Tidak ada temuan** dari semgrep maupun grep pelengkap | `0 Code Findings`; grep pada `setKeySize`, `PBEKeySpec`, `SecretKeySpec` bersih |
| P2 | Semua kunci simetris **AES-256** | `keyGen.init(256)` atau `.setKeySize(256)` |
| P3 | Semua RSA ≥ **3072** (idealnya 4096) | `initialize(4096)`; atau `KeyPairGeneratorSpec.setKeySize(4096)` |
| P4 | Semua EC ≥ **256** (P-256/P-384) | `initialize(256)`; `ECGenParameterSpec("secp256r1")` |
| P5 | Ukuran kunci **tidak ditentukan eksplisit** dan default provider sudah memadai | `KeyPairGenerator.getInstance("RSA").generateKeyPair()` → default 2048 pada Android modern. **Tetap sebaiknya dieksplisitkan** — catat sebagai hardening |
| P6 | Kunci dihasilkan & dikelola **Android KeyStore** dengan ukuran memadai | `KeyGenParameterSpec.Builder(...).setKeySize(256)` + provider `"AndroidKeyStore"` |
| P7 | Tidak ada DES / 3DES / Blowfish / RC4 | grep bersih |
| P8 | Parameter pendukung memadai: PBKDF2 iterasi tinggi + SHA256, salt ≥ 16 byte, GCM tag 128 bit | `PBEKeySpec(pw, salt16, 600000, 256)`; `GCMParameterSpec(128, iv)` |
| P9 | Sertifikat/keystore yang di-bundle memakai kunci ≥ 2048 (RSA) atau ≥ 256 (EC) | `openssl x509 ... \| grep Public-Key` → `4096 bit` |

**Contoh output yang menandakan PASS:**

```bash
$ NO_COLOR=true semgrep -c mastg-android-key-generation-with-insufficient-key-length.yml ./decompiled/sources/
┌──────────────────┐
│ 0 Code Findings  │
└──────────────────┘

# Grep pelengkap untuk jalur yang tidak tercakup rule
$ grep -rnE "setKeySize\(|initialize\(|\.init\(" ./decompiled/sources/ | grep -E "\((512|768|1024|128|160|192|56|64)[,)]"
# (tidak ada hasil)

$ grep -rniE "\"DES\"|DESede|Blowfish|RC4|RC2" ./decompiled/sources/
# (tidak ada hasil)
```

Kode yang benar:

```kotlin
// ✅ AES-256 via Android KeyStore — kunci tidak pernah keluar dari secure hardware
val keyGen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
keyGen.init(
    KeyGenParameterSpec.Builder(
        "vault_key",
        KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
    )
        .setKeySize(256)                                      // AES-256
        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
        .setRandomizedEncryptionRequired(true)
        .build()
)
keyGen.generateKey()

// ✅ RSA-4096 via Android KeyStore, dengan OAEP
val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore")
kpg.initialize(
    KeyGenParameterSpec.Builder("rsa_key", KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
        .setKeySize(4096)                                     // RSA-4096
        .setDigests(KeyProperties.DIGEST_SHA256)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
        .build()
)
kpg.generateKeyPair()

// ✅ EC P-256 untuk signature (ingat: KeyStore tidak mendukung enkripsi EC sejak API 30)
val ecKpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
ecKpg.initialize(
    KeyGenParameterSpec.Builder("sign_key", KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY)
        .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
        .setDigests(KeyProperties.DIGEST_SHA256)
        .build()
)
ecKpg.generateKeyPair()
```

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Rule MASTG sangat sempit — ini karakteristik terpenting test ini.** Rule-nya hanya mencocokkan tiga pola literal yang sangat spesifik. Banyak kasus nyata **lolos total**. Jangan menyimpulkan PASS hanya dari output semgrep kosong; lihat §3.4 untuk daftar celah dan grep pelengkap.

2. **Posisi AES-128 perlu dinyatakan dengan hati-hati di laporan.** Lihat §1.4. Laporkan sesuai kriteria MASTG (sehingga check-nya FAIL), tetapi klasifikasikan sebagai **hardening / severity rendah** dan sebutkan bahwa NIST/FIPS masih menyetujui AES-128. Ini membuat temuanmu dapat dipertahankan saat didebat.

3. **Jangan menyamakan angka antar algoritma.** "256" pada AES ≠ "256" pada RSA. EC-256 setara RSA-3072, bukan RSA-256. Gunakan tabel §1.2 saat menilai dan saat menjelaskan ke developer.

4. **Ukuran kunci bisa ditentukan di lima tempat berbeda** (§1.5) — dan rule MASTG hanya mencakup satu. Periksa `KeyGenParameterSpec.setKeySize`, `KeyPairGeneratorSpec.setKeySize`, `PBEKeySpec` `keyLength`, dan panjang byte array pada `SecretKeySpec`.

5. **Perhatikan ukuran kunci yang berasal dari variabel.** Pattern literal semgrep tidak akan menangkap `initialize(KEY_SIZE)`. Gunakan grep untuk konstanta bernilai kecil, atau CodeQL untuk penyelesaian nilai konstan, atau konfirmasi dinamis dengan Frida (§3.5).

6. **Ketiadaan pemanggilan `init()`/`initialize()` bukan otomatis aman — tetapi juga bukan otomatis temuan.** Bila ukuran tidak dieksplisitkan, provider memakai default (pada Android modern: RSA 2048, AES 128 atau 256 tergantung provider/versi). Ini ambigu dan bergantung platform, sehingga **sebaiknya tetap dieksplisitkan** — catat sebagai rekomendasi hardening, bukan temuan keras.

7. **Ukuran kunci yang benar tidak menyelamatkan algoritma/mode yang salah.** AES-256 dengan mode **ECB** tetap tidak aman. Test ini hanya menilai satu dimensi; lengkapi dengan MASTG-TEST-0221 (algoritma simetris broken) dan MASTG-TEST-0232 (mode enkripsi broken).

8. **Ukuran kunci yang benar juga tidak menyelamatkan kunci yang dihasilkan dari sumber lemah.** Kunci AES-256 yang dibuat dari `java.util.Random` atau dari timestamp hanya punya entropi sebesar sumbernya. Lengkapi dengan **MASTG-TEST-0204** dan **MASTG-TEST-0205**.

9. **Output kosong ≠ otomatis PASS.** Penyebab false pass: celah rule (catatan 1), obfuscation/packing, refleksi (`Class.forName("javax.crypto.KeyGenerator")`), kode native, kode yang dimuat runtime, split APK yang tidak dianalisis, dan library pihak ketiga yang tidak ikut dipindai.

10. **Periksa juga aset kripto yang di-bundle.** Sertifikat untuk pinning, keystore JKS/BKS/PKCS#12 di `assets/` atau `res/raw/`, dan public key yang di-hardcode semuanya punya ukuran kunci yang bisa lemah — dan tidak akan ditemukan dengan memindai kode.

11. **Dokumentasikan bukti lengkap per temuan:** rule ID (atau metode grep), path + nomor baris, potongan kode dekompilasi, **algoritma dan ukuran kunci persisnya**, **bits of security ekuivalen** (dari tabel §1.2), tujuan penggunaan kunci, standar acuan yang dipakai untuk menilai (NIST SP 800-57 / BSI / CNSA 2.0), severity yang diusulkan beserta justifikasinya, dan batasan analisis (obfuscation, kode native, library belum dipindai).

### 3.4 Celah Rule MASTG dan Pemeriksaan Pelengkap

Rule MASTG hanya mencakup **tiga pola literal**. Berikut celahnya:

| Celah | Contoh yang lolos |
|---|---|
| `initialize(1024)` **tanpa** argumen `new SecureRandom()` | `kpg.initialize(1024)` — tidak cocok karena pattern mensyaratkan dua argumen |
| RSA 768 | `kpg.initialize(768, new SecureRandom())` — hanya 512 & 1024 yang di-pattern |
| `init(128, ...)` dengan argumen kedua | `keyGen.init(128, new SecureRandom())` |
| AES dengan ukuran lain yang lemah | `init(64)` |
| **DES, 3DES, Blowfish, RC2/RC4** | Tidak disebut sama sekali di rule |
| **EC / ECDSA / DSA / DH** | Tidak disebut sama sekali di rule |
| **HMAC** | Tidak disebut |
| **`KeyGenParameterSpec.setKeySize()`** | Jalur Android KeyStore — tidak tercakup |
| **`KeyPairGeneratorSpec.setKeySize()`** | Jalur deprecated — tidak tercakup |
| **`PBEKeySpec` `keyLength`** | Tidak tercakup |
| **`SecretKeySpec(ByteArray(n), ...)`** | Tidak tercakup |
| Ukuran dari **variabel/konstanta** | Pattern literal tidak menyelesaikan nilai |
| `getInstance()` dan `init()` di **fungsi berbeda** | Pattern sekuensial mensyaratkan keduanya di satu blok |
| `languages: java` saja | Sumber Kotlin tidak dipindai |
| Kode **native** | Titik buta total |

**Perintah pemeriksaan pelengkap:**

```bash
D=./decompiled/sources

# 1. Semua pemanggilan penentu ukuran kunci, lalu saring nilai kecil
grep -rnE "\.(initialize|init)\(\s*(56|64|96|128|160|192|224|512|768|1024)\b" $D
grep -rnE "setKeySize\(\s*(56|64|96|128|160|192|224|512|768|1024|2048)\s*\)" $D

# 2. Semua pemanggilan generasi kunci (tinjau manual ukurannya)
grep -rnE "KeyGenerator\.getInstance|KeyPairGenerator\.getInstance|KeyGenParameterSpec|KeyPairGeneratorSpec" $D

# 3. Algoritma broken / lemah (bertaut MASTG-TEST-0221)
grep -rniE "\"DES\"|\"DESede\"|TripleDES|\"Blowfish\"|\"RC2\"|\"RC4\"|\"ARCFOUR\"|\"IDEA\"" $D

# 4. Kurva EC yang lemah
grep -rnE "ECGenParameterSpec\(|secp(160|192)|prime192|brainpoolP160" $D

# 5. SecretKeySpec dengan array pendek (64/128-bit)
grep -rnE "new SecretKeySpec\(new byte\[(8|16)\]|ByteArray\((8|16)\)" $D

# 6. PBEKeySpec — keyLength & iterationCount
grep -rnE "new PBEKeySpec\(" $D -A2
grep -rnE "PBKDF2WithHmacSHA1" $D          # gunakan SHA256 untuk API 26+

# 7. Parameter GCM (tag length harus 128)
grep -rnE "new GCMParameterSpec\(" $D

# 8. Konstanta ukuran kunci yang didefinisikan di tingkat kelas
grep -rnE "(static )?(final )?int [A-Z_]*KEY[_]?(SIZE|LEN|LENGTH)[A-Z_]* *= *[0-9]+" $D

# 9. Aset kripto yang di-bundle di APK
unzip -o ./target-app.apk -d ./apk_x >/dev/null
find ./apk_x -iname "*.crt" -o -iname "*.pem" -o -iname "*.cer" -o -iname "*.der" \
     -o -iname "*.jks" -o -iname "*.bks" -o -iname "*.p12" -o -iname "*.keystore"
for c in $(find ./apk_x -iname "*.crt" -o -iname "*.pem" -o -iname "*.cer"); do
  echo "--- $c"
  openssl x509 -in "$c" -noout -text 2>/dev/null | grep -E "Public-Key|Signature Algorithm" | head -3
done
keytool -list -v -keystore ./apk_x/res/raw/mykeystore.bks -storetype BKS 2>/dev/null | grep -iE "algorithm|key size"

# 10. Kripto dari kode native
for so in $(find ./apk_x -name "*.so"); do
  echo "--- $so"
  strings "$so" | grep -xE "RSA_generate_key|RSA_generate_key_ex|EVP_PKEY_keygen|DH_generate_parameters|EC_KEY_new_by_curve_name|DES_set_key|BF_set_key"
done

# 11. Deteksi proteksi yang membatasi keandalan analisis
apkid ./target-app.apk
```

**Rule semgrep perluasan** untuk menutup celah utama:

```yaml
rules:
  - id: custom-insufficient-key-size-extended
    severity: ERROR
    languages: [java, kotlin]
    message: "[MASVS-CRYPTO-1] Ukuran kunci tidak memadai atau algoritma lemah pada generasi kunci"
    pattern-either:
      # --- RSA / DSA / DH: semua ukuran < 2048 ---
      - pattern-regex: \.initialize\(\s*(512|768|1024)\b
      # --- Simetris: ukuran kecil ---
      - pattern-regex: \.init\(\s*(56|64|96)\b
      # --- KeyGenParameterSpec / KeyPairGeneratorSpec ---
      - pattern-regex: setKeySize\(\s*(56|64|96|128|512|768|1024)\s*\)
      # --- Algoritma broken (ukuran kunci tidak relevan lagi) ---
      - pattern: javax.crypto.KeyGenerator.getInstance("DES", ...)
      - pattern: javax.crypto.KeyGenerator.getInstance("DESede", ...)
      - pattern: javax.crypto.KeyGenerator.getInstance("Blowfish", ...)
      - pattern: javax.crypto.KeyGenerator.getInstance("RC4", ...)
      - pattern: javax.crypto.KeyGenerator.getInstance("ARCFOUR", ...)
      # --- Kurva EC lemah ---
      - pattern-regex: ECGenParameterSpec\(\s*"(secp160r1|secp160k1|secp192r1|prime192v1|brainpoolP160r1)"
      # --- SecretKeySpec dari array pendek ---
      - pattern-regex: new SecretKeySpec\(\s*new byte\[(8|16)\]

  - id: custom-aes-128-hardening
    severity: INFO
    languages: [java, kotlin]
    message: "[MASVS-CRYPTO-1] AES-128 terdeteksi. MASTG merekomendasikan AES-256; catat bahwa NIST/FIPS masih menyetujui AES-128 (severity: hardening)"
    pattern-either:
      - pattern-regex: \.init\(\s*128\b
      - pattern-regex: setKeySize\(\s*128\s*\)

  - id: custom-weak-kdf-params
    severity: WARNING
    languages: [java, kotlin]
    message: "[MASVS-CRYPTO-1] Parameter KDF tidak memadai (iterasi rendah / PRF lama / keyLength kecil)"
    pattern-either:
      - pattern: javax.crypto.SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1", ...)
      - pattern-regex: new PBEKeySpec\([^,]+,[^,]+,\s*([0-9]{1,5})\s*,   # iterasi < 100.000
```

### 3.5 Konfirmasi Dinamis Opsional

MASTG tidak menyediakan test dinamis untuk ini, tetapi hooking sangat berguna dalam dua situasi: ketika ukuran kunci berasal dari **variabel** (sehingga analisis statis tidak dapat menyelesaikannya), dan ketika kode **ter-obfuscate** atau dimuat saat runtime.

```javascript
Java.perform(() => {
    function bt(max = 10) {
        const E = Java.use("java.lang.Exception");
        const st = E.$new().getStackTrace();
        const out = [];
        for (let i = 0; i < Math.min(max, st.length); i++) out.push("    " + st[i]);
        return out.join("\n");
    }

    // Batas minimum sesuai standar
    const MIN = { AES: 256, RSA: 3072, EC: 256, DSA: 3072, DH: 3072, ChaCha20: 256 };

    // --- KeyGenerator (simetris + HMAC) ---
    const KG = Java.use("javax.crypto.KeyGenerator");
    KG.getInstance.overloads.forEach(ov => {
        ov.implementation = function (...a) {
            const inst = ov.apply(this, a);
            console.log(`\n[*] KeyGenerator.getInstance("${a[0]}")`);
            console.log(bt());
            return inst;
        };
    });
    KG.init.overloads.forEach(ov => {
        ov.implementation = function (...a) {
            if (typeof a[0] === 'number') {
                const algo = this.getAlgorithm();
                const min = MIN[algo] || 256;
                const flag = a[0] < min ? `  [!! INSUFFICIENT (min ${min}) !!]` : "  [ok]";
                console.log(`\n[*] KeyGenerator(${algo}).init(${a[0]})${flag}`);
                console.log(bt());
            }
            return ov.apply(this, a);
        };
    });

    // --- KeyPairGenerator (asimetris) ---
    const KPG = Java.use("java.security.KeyPairGenerator");
    KPG.initialize.overloads.forEach(ov => {
        ov.implementation = function (...a) {
            if (typeof a[0] === 'number') {
                const algo = this.getAlgorithm();
                const min = MIN[algo] || 3072;
                const flag = a[0] < min ? `  [!! INSUFFICIENT (min ${min}) !!]` : "  [ok]";
                console.log(`\n[*] KeyPairGenerator(${algo}).initialize(${a[0]})${flag}`);
                console.log(bt());
            } else {
                console.log(`\n[*] KeyPairGenerator(${this.getAlgorithm()}).initialize(<spec>) -> ${a[0]}`);
                console.log(bt());
            }
            return ov.apply(this, a);
        };
    });

    // --- SecretKeySpec: ukuran ditentukan panjang array ---
    const SKS = Java.use("javax.crypto.spec.SecretKeySpec");
    SKS.$init.overload('[B', 'java.lang.String').implementation = function (k, algo) {
        const bits = k.length * 8;
        const flag = bits < 256 ? `  [!! ${bits}-bit !!]` : `  [${bits}-bit]`;
        console.log(`\n[*] new SecretKeySpec(byte[${k.length}], "${algo}")${flag}`);
        console.log(bt());
        return this.$init(k, algo);
    };

    // --- PBEKeySpec: keyLength & iterationCount ---
    const PBE = Java.use("javax.crypto.spec.PBEKeySpec");
    PBE.$init.overload('[C', '[B', 'int', 'int').implementation = function (pw, salt, iter, len) {
        console.log(`\n[*] PBEKeySpec(salt=${salt.length}B, iterations=${iter}, keyLength=${len})`);
        if (iter < 100000) console.log("    [!! iterasi terlalu rendah !!]");
        if (len < 256)     console.log("    [!! keyLength kecil !!]");
        if (salt.length < 16) console.log("    [!! salt < 16 byte !!]");
        console.log(bt());
        return this.$init(pw, salt, iter, len);
    };
});
```

Jalankan dengan:

```bash
frida -U -f com.example.target -l keysize_trace.js -o keysize.log
```

Keunggulannya: **melihat nilai ukuran kunci yang benar-benar dipakai**, termasuk ketika berasal dari variabel, konfigurasi remote, atau kode ter-obfuscate — plus backtrace yang menunjukkan lokasi pemanggil.

---

### 3.6 Metode Pengujian Alternatif (Multi-Tool)

Rule MASTG hanya mencakup tiga pola literal dan meninggalkan 16 celah (§3.4). Berikut jalur alternatif.

#### Metode B — ripgrep terstruktur *(menutup kelima jalur penentu ukuran kunci)*

Lihat §3.4 untuk daftar perintah lengkap. Intinya: rule MASTG hanya mencakup **Jalur A** (JCA polos), sementara ukuran kunci dapat ditentukan di **lima tempat** (§1.5).

```bash
D=./decompiled/sources

# Semua jalur penentu ukuran kunci sekaligus, lalu saring nilai kecil
rg -n --no-heading "\.(initialize|init)\(\s*(56|64|96|128|160|192|224|512|768|1024)\b" $D
rg -n --no-heading "setKeySize\(\s*(56|64|96|128|512|768|1024|2048)\s*\)" $D
rg -n --no-heading "new SecretKeySpec\(\s*new byte\[(8|16)\]|ByteArray\((8|16)\)" $D
rg -n --no-heading "new PBEKeySpec\(" $D -A1
rg -n --no-heading "ECGenParameterSpec\(|secp(160|192)|prime192|brainpoolP160" $D

# Algoritma broken — ukuran kunci tidak relevan lagi
rg -ni --no-heading '"DES"|"DESede"|TripleDES|"Blowfish"|"RC2"|"RC4"|"ARCFOUR"|"IDEA"' $D

# Konstanta ukuran kunci tingkat kelas (celah pattern literal)
rg -n --no-heading "(static )?(final )?int [A-Z_]*KEY[_]?(SIZE|LEN|LENGTH)[A-Z_]* *= *[0-9]+" $D
```

#### Metode C — SonarQube / SonarLint *(paling tepat sasaran untuk test ini)*

**Rule `java:S4426` — *Cryptographic keys should be robust*** adalah implementasi yang jauh lebih lengkap daripada rule MASTG: ia memahami konteks algoritma dan menerapkan batas yang berbeda untuk RSA, EC, DH, dan simetris — termasuk ketika ukuran berasal dari konstanta.

```bash
sonar-scanner -Dsonar.projectKey=android-app -Dsonar.sources=./app/src -Dsonar.java.binaries=./app/build
```

Rule terkait yang sekaligus tercakup: `java:S5542` (mode/padding enkripsi), `java:S4790` (hashing lemah), `java:S2278` (DES). Keunggulan besar: muncul di IDE developer via **SonarLint** sebelum commit.

#### Metode D — CodeQL *(menyelesaikan nilai konstanta lintas fungsi)*

Menjawab celah terbesar rule MASTG: ukuran kunci yang berasal dari **variabel atau konstanta**.

```bash
codeql database create ./cqldb --language=java --command="./gradlew assembleDebug"
codeql database analyze ./cqldb \
  codeql/java-queries:Security/CWE/CWE-326/InsufficientKeySize.ql \
  --format=sarif-latest --output=keysize.sarif
```

```ql
/**
 * @name Insufficient key size (resolves constants)
 * @kind problem
 */
import java

from MethodAccess ma, int size, string algo
where
  (ma.getMethod().hasName("initialize") or ma.getMethod().hasName("init") or
   ma.getMethod().hasName("setKeySize")) and
  size = ma.getArgument(0).(CompileTimeConstantExpr).getIntValue() and
  algo = ma.getQualifier().(MethodAccess).getArgument(0).(StringLiteral).getValue() and
  (
    (algo = "RSA" and size < 3072) or
    (algo = "AES" and size < 256) or
    (algo = "EC"  and size < 256) or
    (algo = "DSA" and size < 3072)
  )
select ma, "Ukuran kunci " + size + " tidak memadai untuk " + algo
```

> `getIntValue()` pada `CompileTimeConstantExpr` inilah kuncinya — CodeQL **menyelesaikan** `private static final int KEY_SIZE = 1024; ... initialize(KEY_SIZE)` yang tidak mungkin ditangkap pattern literal semgrep.

#### Metode E — MobSF *(laporan siap kutip)*

Cari di **Code Analysis**: *"The App uses RSA Crypto with less than 2048 bit key length"*, *"The App uses a weak encryption algorithm"*. MobSF juga memeriksa `Cipher` mode/padding sekaligus, sehingga memberi gambaran kripto menyeluruh dalam satu pass.

#### Metode F — mobsfscan *(CLI untuk CI/CD)*

```bash
mobsfscan --json -o out.json ./decompiled/sources/
jq '.results | to_entries[] | select(.key | test("key|rsa|crypto"))' out.json
mobsfscan --exit-warning ./decompiled/sources/     # gate CI
```

#### Metode G — Pemeriksaan aset kripto yang di-bundle *(titik buta semua scanner kode)*

Sertifikat pinning, keystore, dan public key di `assets/`/`res/raw/` punya ukuran kunci sendiri — dan **tidak akan ditemukan dengan memindai kode**.

```bash
unzip -o ./target-app.apk -d ./apk_x >/dev/null

# Sertifikat
for c in $(find ./apk_x -iname "*.crt" -o -iname "*.pem" -o -iname "*.cer" -o -iname "*.der"); do
  echo "--- $c"
  openssl x509 -in "$c" -noout -text 2>/dev/null | grep -E "Public-Key|Signature Algorithm" | head -3
done

# Keystore (BKS/JKS/PKCS#12)
for k in $(find ./apk_x -iname "*.bks" -o -iname "*.jks" -o -iname "*.p12" -o -iname "*.keystore"); do
  echo "--- $k"
  keytool -list -v -keystore "$k" -storetype BKS -storepass "" 2>/dev/null | grep -iE "Algorithm|key size|Owner"
done

# Public key di-hardcode sebagai Base64 (mis. untuk pinning)
rg -n --no-heading "MII[A-Za-z0-9+/]{40,}" ./decompiled/sources/ | head
```

#### Metode H — Analisis kode native

```bash
for so in $(find ./apk_x -name "*.so"); do
  echo "--- $so"
  strings "$so" | grep -xE "RSA_generate_key|RSA_generate_key_ex|EVP_PKEY_keygen|EVP_PKEY_CTX_set_rsa_keygen_bits|DH_generate_parameters|EC_KEY_new_by_curve_name|DES_set_key|BF_set_key"
done
```

#### Metode I — APKHunt & semgrep registry

```bash
APKHunt -p ./target-app.apk -l
semgrep --config "p/java" --config "p/mobsfscan" ./decompiled/sources/
semgrep --config "r/java.lang.security.audit.crypto.weak-rsa.use-of-weak-rsa-key" ./decompiled/sources/
```

---

### 3.7 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Butuh device? | Butuh source? | Menyelesaikan konstanta? | Mencakup 5 jalur (§1.5)? | Kapan dipakai |
|---|---|---|---|---|---|---|
| **A** | semgrep (MASTG) | Tidak | Tidak | ❌ | ❌ (hanya Jalur A, sebagian) | Baseline resmi & gate CI |
| **B** | ripgrep terstruktur | Tidak | Tidak | Manual | ✅ | **Verifikasi silang wajib** |
| **C** | SonarQube `java:S4426` | Tidak | Ya | ✅ | ✅ | **Paling tepat sasaran**; shift-left di IDE |
| **D** | CodeQL | Tidak | Ya (ideal) | ✅ **otomatis** | ✅ | Terbaik bila ukuran dari variabel/konstanta |
| **E** | MobSF | Tidak | Tidak | Sebagian | Sebagian | Laporan siap kutip + audit kripto menyeluruh |
| **F** | mobsfscan | Tidak | Tidak | Sebagian | Sebagian | Gate CI/CD ringan |
| **G** | openssl / keytool | Tidak | Tidak | — | — | **Aset kripto di-bundle** — titik buta scanner kode |
| **H** | `strings` / Ghidra | Tidak | Tidak | Manual | ✅ (native) | APK dengan `.so` |
| **I** | APKHunt / semgrep registry | Tidak | Tidak | ❌ | Sebagian | Pass otomatis tambahan |
| **J** | Frida (§3.5) | **Ya** | Tidak | ✅ (nilai runtime) | ✅ | Ukuran dari variabel, konfigurasi remote, kode ter-obfuscate |

**Kombinasi minimum yang aku rekomendasikan:** **B (ripgrep) → A (semgrep) → G (aset bundle)**.
B menutup kelima jalur penentu ukuran kunci, A memberi baseline selaras MASTG, G memeriksa permukaan yang tidak tersentuh scanner kode. Bila source tersedia, **C (SonarQube `java:S4426`)** adalah pengganti yang lebih baik daripada A karena ia benar-benar memahami konteks algoritma. Tambahkan **J (Frida)** bila ukuran kunci tidak dapat ditentukan secara statis.

---

## 4. Rekomendasi Perbaikan

### 4.1 Prinsip Utama (urutan prioritas)

**Prioritas 1 — Naikkan ukuran kunci ke tingkat yang direkomendasikan.**

```kotlin
// ❌ SALAH
KeyPairGenerator.getInstance("RSA").initialize(1024, SecureRandom())
KeyGenerator.getInstance("AES").init(128)
KeyGenerator.getInstance("DES").init(56)
KeyPairGenerator.getInstance("EC").initialize(160)

// ✅ BENAR
KeyPairGenerator.getInstance("RSA").initialize(4096, SecureRandom())   // ≥ 3072
KeyGenerator.getInstance("AES").init(256)
KeyPairGenerator.getInstance("EC").initialize(256)                      // P-256
```

Gunakan tabel §1.3 sebagai acuan. Dan **selalu eksplisitkan ukuran kunci** — jangan bergantung pada default provider yang bisa berbeda antar versi Android dan antar implementasi.

**Prioritas 2 — Lebih baik lagi: gunakan Android KeyStore, bukan JCA polos.**

Ini perbaikan yang lebih kuat karena sekaligus menyelesaikan masalah penyimpanan kunci. Sampel MASTG-DEMO-0012 memakai JCA polos, sehingga kunci berada di heap aplikasi dan dapat di-dump. Dengan KeyStore, **key material tidak pernah keluar dari secure hardware**.

```kotlin
// ✅ AES-256 GCM via Android KeyStore
val keyGen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
keyGen.init(
    KeyGenParameterSpec.Builder(
        "vault_key",
        KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
    )
        .setKeySize(256)
        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
        .setRandomizedEncryptionRequired(true)
        .setUserAuthenticationRequired(true)       // untuk data paling sensitif
        .setIsStrongBoxBacked(true)                // bila hardware mendukung
        .build()
)
keyGen.generateKey()
```

> **Catat dua batasan Android KeyStore** yang relevan saat memperbaiki:
> - **Sejak Android 11 (API 30), AndroidKeyStore tidak mendukung enkripsi/dekripsi dengan kunci EC** — EC hanya untuk signature. Jadi jangan mengganti RSA lemah dengan EC untuk enkripsi.
> - Sebelum Android 6.0 (API 23), generasi kunci AES tidak didukung KeyStore. Bila `minSdkVersion` masih di bawah 23, perlu jalur fallback — tetapi API 23 sudah sangat lama, sebaiknya naikkan `minSdkVersion`.

**Prioritas 3 — Ganti algoritma yang broken, bukan hanya memperbesar kuncinya.**

| Ganti dari | Ganti ke | Alasan |
|---|---|---|
| DES, 3DES | **AES-256-GCM** | DES broken (56-bit); 3DES *disallowed* NIST, block 64-bit |
| Blowfish | **AES-256-GCM** atau ChaCha20-Poly1305 | Block 64-bit → rentan *Sweet32* |
| RC4, RC2, IDEA | **AES-256-GCM** | Broken / usang |
| RSA PKCS#1 v1.5 (enkripsi) | **RSA-OAEP** ≥ 3072, atau lebih baik: **hybrid** (ECDH + AES-GCM) | Padding oracle |
| RSA PKCS#1 v1.5 (signature) | **RSA-PSS** ≥ 3072, atau **ECDSA P-256** | Praktik terkini |
| `PBKDF2WithHmacSHA1` | **`PBKDF2withHmacSHA256`** (atau Argon2id) | SHA-1 usang; KNOW-0012 sendiri menyarankan SHA256 untuk API 26+ |

**Prioritas 4 — Perbaiki parameter pendukung generasi kunci** (§1.6).

```kotlin
// ✅ KDF dengan parameter memadai
val salt = ByteArray(16).also { SecureRandom().nextBytes(it) }   // salt ≥ 16 byte, dari CSPRNG
val spec = PBEKeySpec(password, salt, 600_000, 256)              // iterasi tinggi, keyLength 256
val factory = SecretKeyFactory.getInstance("PBKDF2withHmacSHA256")
val key = SecretKeySpec(factory.generateSecret(spec).encoded, "AES")

// ✅ GCM dengan tag 128-bit dan nonce 12 byte
val nonce = ByteArray(12).also { SecureRandom().nextBytes(it) }
cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, nonce))
```

> Perhatikan: MASTG-KNOW-0012 mencontohkan `iterationCount = 10000` untuk PBKDF2. Angka itu **sudah usang** — OWASP kini merekomendasikan **600.000** iterasi untuk PBKDF2-HMAC-SHA256. Bila memungkinkan, gunakan **Argon2id** yang tahan terhadap serangan berbasis GPU/ASIC.

**Prioritas 5 — Pastikan kuncinya dibuat dari sumber entropi yang benar.** Kunci AES-256 yang dihasilkan dari `java.util.Random` atau dari timestamp hanya punya entropi sebesar sumbernya — ukuran kunci menjadi tidak berarti. Lihat **MASTG-TEST-0204** dan **MASTG-TEST-0205**.

```kotlin
// ❌ Ukuran kunci besar, entropi kecil
val key = ByteArray(32); java.util.Random().nextBytes(key)

// ✅ Biarkan platform yang menghasilkan, atau pakai SecureRandom
KeyGenerator.getInstance("AES", "AndroidKeyStore").init(spec)     // terbaik
// atau
val key = ByteArray(32).also { SecureRandom().nextBytes(it) }
```

**Prioritas 6 — Jangan andalkan NDK untuk "menyembunyikan" kripto.** MASTG-KNOW-0012 menegaskan ini keyakinan yang salah dan tersebar luas: memindahkan operasi kripto atau kunci hardcoded ke kode native **tidak efektif**. Penyerang tetap dapat mengidentifikasi mekanismenya dan men-dump kunci dari memori dengan Frida, lalu menganalisis alur kontrol dengan radare2. Dan sejak Android 7.0 (API 24), penggunaan API privat tidak diizinkan sehingga efektivitas penyembunyian semakin berkurang. **Solusinya adalah Android KeyStore**, bukan obfuscation.

**Prioritas 7 — Perbarui aset kripto yang di-bundle.** Sertifikat pinning, keystore, dan public key yang di-hardcode di `assets/` atau `res/raw/` harus memakai RSA ≥ 2048 (idealnya 4096) atau EC ≥ 256. Ini sering terlupakan karena bukan bagian dari kode.

**Prioritas 8 — Rencanakan migrasi crypto-agility dan post-quantum.** Ini yang menjadikan test ini relevan untuk jangka panjang:

- **RSA-2048 dideprecate menuju 2030.** Bila aplikasi menyimpan data yang harus tetap terlindungi setelah 2030, migrasi ke ≥ 3072 sekarang.
- **NIST IR 8547 merencanakan larangan semua kripto kunci publik yang rentan kuantum — termasuk RSA-3072, P-256, P-384 — pada 2035.**
- Ancaman **"harvest now, decrypt later"**: data yang dienkripsi hari ini dengan RSA/ECC dan ditangkap penyerang dapat didekripsi nanti ketika komputer kuantum yang relevan tersedia. Untuk data dengan masa sensitif panjang (rekam medis, data identitas), ini risiko nyata **sekarang**.
- **Rancang crypto-agility**: buat lapisan abstraksi kripto sehingga algoritma dan ukuran kunci dapat diganti tanpa mengubah logika bisnis. Simpan penanda versi algoritma bersama ciphertext agar migrasi dapat dilakukan bertahap.
- Pantau standar PQC: **ML-KEM (Kyber)** untuk key encapsulation, **ML-DSA (Dilithium)** dan **SLH-DSA (SPHINCS+)** untuk signature. Pertimbangkan mode **hybrid** (klasik + PQC) sebagai langkah transisi.
- **AES-256 sudah quantum-resistant** untuk keperluan yang terlihat — ini alasan tambahan yang kuat untuk memilih AES-256 daripada AES-128, terlepas dari perdebatan di §1.4.

**Prioritas 9 — Tegakkan secara struktural.**
- Tambahkan rule SAST di CI/CD (rule MASTG + rule perluasan §3.4) dan gagalkan build bila muncul ukuran kunci di bawah kebijakan.
- Definisikan **kebijakan kripto organisasi** yang eksplisit (algoritma & ukuran kunci minimum), lalu tegakkan lewat lint/SAST — bukan lewat code review manual.
- Buat **satu utilitas kripto terpusat** (mis. `CryptoProvider.newAesKey()`, `CryptoProvider.newSigningKey()`) dan larang pemanggilan `KeyGenerator`/`KeyPairGenerator` langsung.
- Audit library pihak ketiga — jalankan pemindaian juga pada kode library hasil dekompilasi.

### 4.2 Checklist Remediasi

- [ ] Setiap temuan dari semgrep + grep pelengkap sudah ditinjau dengan MASTG-TECH-0023
- [ ] Tidak ada RSA/DSA/DH < 2048; target ≥ **3072** (idealnya 4096) untuk sistem baru
- [ ] Tidak ada RSA-1024 / 768 / 512 di kode maupun di sertifikat yang di-bundle
- [ ] Semua kunci simetris **AES-256**
- [ ] Tidak ada DES, 3DES, Blowfish, RC2, RC4, atau IDEA
- [ ] Semua kurva EC ≥ **256** (P-256/P-384); tidak ada secp160/192
- [ ] Kunci HMAC ≥ ukuran output hash (≥ 256 bit untuk HMAC-SHA256)
- [ ] Ukuran kunci **selalu dieksplisitkan** — tidak bergantung default provider
- [ ] Semua jalur penentu ukuran kunci diperiksa: `init()`, `initialize()`, `KeyGenParameterSpec.setKeySize()`, `KeyPairGeneratorSpec.setKeySize()`, `PBEKeySpec` `keyLength`, panjang array `SecretKeySpec`
- [ ] Ukuran kunci yang berasal dari variabel/konstanta sudah diverifikasi nilainya
- [ ] Kunci dihasilkan & dikelola **Android KeyStore** (bukan JCA polos); `setUserAuthenticationRequired` & StrongBox dipertimbangkan
- [ ] Mode & padding benar: AES-GCM (bukan ECB/CBC-tanpa-MAC), RSA-OAEP untuk enkripsi, RSA-PSS/ECDSA untuk signature
- [ ] GCM tag 128 bit, nonce 12 byte, nonce tidak pernah berulang untuk kunci yang sama
- [ ] KDF: `PBKDF2withHmacSHA256` (bukan SHA1) dengan iterasi ≥ 600.000, atau Argon2id; salt ≥ 16 byte dari `SecureRandom`
- [ ] Kunci dihasilkan dari **`SecureRandom`** atau KeyStore — bukan `java.util.Random`/timestamp (verifikasi silang MASTG-TEST-0204 & 0205)
- [ ] Tidak ada kunci hardcoded, dan tidak ada upaya "menyembunyikan" kripto di NDK
- [ ] Sertifikat/keystore yang di-bundle di APK memakai RSA ≥ 2048 (idealnya 4096) atau EC ≥ 256
- [ ] Kripto dari kode native diperiksa dan memenuhi kebijakan yang sama
- [ ] Library pihak ketiga diaudit
- [ ] Semua split APK / dynamic feature module ikut dianalisis
- [ ] **Crypto-agility**: lapisan abstraksi kripto ada, versi algoritma disimpan bersama ciphertext
- [ ] Roadmap migrasi: RSA-2048 → ≥3072 sebelum 2030; rencana PQC (ML-KEM/ML-DSA) menuju 2035
- [ ] Kebijakan kripto organisasi terdokumentasi dan ditegakkan lewat SAST di CI/CD
- [ ] Utilitas kripto terpusat dibuat; pemanggilan `KeyGenerator`/`KeyPairGenerator` langsung dilarang
- [ ] **Verifikasi ulang:** jalankan kembali MASTG-TEST-0208 + grep pelengkap → tidak ada ukuran kunci di bawah kebijakan
- [ ] **Verifikasi silang:** MASTG-TEST-0221 (algoritma broken), MASTG-TEST-0232 (mode broken), MASTG-TEST-0204/0205 (sumber entropi kunci)

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0208: Insufficient Key Sizes](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0208/)
- [MASWE-0013: Improper Cryptographic Key Generation](https://mas.owasp.org/MASWE/MASVS-CRYPTO/MASWE-0013/)
- [MASTG-DEMO-0012: Cryptographic Key Generation With Insufficient Key Length](https://mas.owasp.org/MASTG/demos/android/MASVS-CRYPTO/MASTG-DEMO-0012/MASTG-DEMO-0012/)
- [MASTG-KNOW-0012: Key Generation](https://mas.owasp.org/MASTG/knowledge/android/MASVS-CRYPTO/MASTG-KNOW-0012/)
- [MASTG-TEST-0221: Uses of Broken Symmetric Encryption Algorithms](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0221/)
- [MASTG-TEST-0232: Uses of Broken Encryption Modes](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0232/)
- [MASTG-TEST-0212: Use of Hardcoded AES Key in SecretKeySpec](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0212/)
- [MASTG-TEST-0204: Insecure Random API Usage](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0204/)
- [MASTG-TEST-0205: Non-random Sources Usage](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0205/)
- [MASTG-TECH-0013: Reverse Engineering Android Apps](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/)
- [MASTG-TECH-0014: Static Analysis on Android](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/)
- [MASTG-TECH-0023: Reviewing Decompiled Java Code](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0023/)
- [MASTG-TOOL-0110: semgrep](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0110/)
- [MASTG-TOOL-0018: jadx](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0018/)
- [MASTG Rules — `mastg-android-key-generation-with-insufficient-key-length.yml`](https://github.com/OWASP/mastg/blob/master/rules/mastg-android-key-generation-with-insufficient-key-length.yml)
- [MASTG — Testing Cryptography (Key Generation)](https://mas.owasp.org/MASTG/0x05e-Testing-Cryptography/)
- [MASVS-CRYPTO: Cryptography](https://mas.owasp.org/MASVS/06-MASVS-CRYPTO/)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [OWASP Password Storage Cheat Sheet (parameter PBKDF2/Argon2)](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [OWASP Mobile Top 10 2024 — M10: Insufficient Cryptography](https://owasp.org/www-project-mobile-top-10/2023-risks/m10-insufficient-cryptography.html)

### 5.2 Standar Kriptografi & Rekomendasi Panjang Kunci

- [NIST SP 800-57 Part 1 Rev. 5 — Recommendation for Key Management](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final)
- [NIST SP 800-57 Part 3 Rev. 1 — Application-Specific Key Management Guidance](https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-57pt3r1.pdf)
- [NIST SP 800-131A Rev. 2 — Transitioning the Use of Cryptographic Algorithms and Key Lengths](https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final)
- [NIST IR 8547 — Transition to Post-Quantum Cryptography Standards](https://csrc.nist.gov/pubs/ir/8547/ipd)
- [NIST SP 800-132 — Recommendation for Password-Based Key Derivation (PBKDF2)](https://csrc.nist.gov/publications/detail/sp/800-132/final)
- [NIST SP 800-38D — Galois/Counter Mode (GCM)](https://csrc.nist.gov/publications/detail/sp/800-38d/final)
- [NIST FIPS 197 — Advanced Encryption Standard (AES)](https://csrc.nist.gov/publications/detail/fips/197/final)
- [NIST FIPS 186-5 — Digital Signature Standard (DSS)](https://csrc.nist.gov/publications/detail/fips/186/5/final)
- [NIST Post-Quantum Cryptography — FAQs](https://csrc.nist.gov/projects/post-quantum-cryptography/faqs)
- [NSA CNSA 2.0 — Commercial National Security Algorithm Suite](https://www.nsa.gov/Press-Room/News-Highlights/Article/Article/3148990/)
- [BSI TR-02102-1 — Cryptographic Mechanisms: Recommendations and Key Lengths](https://www.bsi.bund.de/EN/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/Technische-Richtlinien/TR-nach-Thema-sortiert/tr02102/tr02102_node.html)
- [ECRYPT-CSA — Algorithms, Key Size and Protocols Report](https://www.ecrypt.eu.org/csa/documents/D5.4-FinalAlgKeySizeProt.pdf)
- [Keylength.com — perbandingan rekomendasi panjang kunci antar badan standar](https://www.keylength.com/)
- [RFC 8017 — PKCS #1 v2.2 (RSA, OAEP, PSS)](https://datatracker.ietf.org/doc/html/rfc8017)
- [RFC 7539 / 8439 — ChaCha20 and Poly1305](https://datatracker.ietf.org/doc/html/rfc8439)

### 5.3 Dokumentasi Resmi Android / Google / Java

- [`javax.crypto.KeyGenerator` — API reference](https://developer.android.com/reference/javax/crypto/KeyGenerator)
- [`KeyGenerator.init(int keysize)` — API reference](https://developer.android.com/reference/javax/crypto/KeyGenerator#init(int))
- [`java.security.KeyPairGenerator` — API reference](https://developer.android.com/reference/java/security/KeyPairGenerator)
- [`KeyPairGenerator.initialize(int keysize)` — API reference](https://developer.android.com/reference/java/security/KeyPairGenerator#initialize(int))
- [`KeyGenParameterSpec` — API reference](https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec)
- [`KeyGenParameterSpec.Builder.setKeySize()` — API reference](https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder#setKeySize(int))
- [`KeyPairGeneratorSpec` (deprecated) — API reference](https://developer.android.com/reference/android/security/KeyPairGeneratorSpec)
- [`PBEKeySpec` — API reference](https://developer.android.com/reference/javax/crypto/spec/PBEKeySpec)
- [`SecretKeySpec` — API reference](https://developer.android.com/reference/javax/crypto/spec/SecretKeySpec)
- [`GCMParameterSpec` — API reference](https://developer.android.com/reference/javax/crypto/spec/GCMParameterSpec)
- [Android — Cryptography (supported algorithms & ciphers)](https://developer.android.com/guide/topics/security/cryptography)
- [Android — Supported Cipher suites & EC limitation on KeyStore](https://developer.android.com/guide/topics/security/cryptography#SupportedCipher)
- [Android Keystore system](https://developer.android.com/privacy-and-security/keystore)
- [Cryptography best practices](https://developer.android.com/privacy-and-security/cryptography)
- [Android Developers Blog — Android changes for NDK developers](https://android-developers.googleblog.com/2016/06/android-changes-for-ndk-developers.html)
- [Google Tink — cryptographic library](https://developers.google.com/tink)
- [Conscrypt — Java Security Provider](https://github.com/google/conscrypt)

### 5.4 Standar & Taksonomi Kelemahan

- [CWE-326: Inadequate Encryption Strength](https://cwe.mitre.org/data/definitions/326.html)
- [CWE-310: Cryptographic Issues](https://cwe.mitre.org/data/definitions/310.html)
- [CWE-327: Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)
- [CWE-1240: Use of a Cryptographic Primitive with a Risky Implementation](https://cwe.mitre.org/data/definitions/1240.html)
- [SonarQube Rule java:S4426 — Cryptographic keys should be robust](https://rules.sonarsource.com/java/RSPEC-4426/)
- [SEI CERT Oracle Coding Standard for Java — MSC61-J: Do not use insecure or weak cryptographic algorithms](https://wiki.sei.cmu.edu/confluence/display/java/MSC61-J.+Do+not+use+insecure+or+weak+cryptographic+algorithms)
- [NIST SP 800-163 Rev.1 — Vetting the Security of Mobile Applications](https://csrc.nist.gov/publications/detail/sp/800-163/rev-1/final)
- [CodeQL — Java query help (weak cryptography)](https://codeql.github.com/codeql-query-help/java/)

### 5.5 Riset & Artikel Teknis

- [Filippo Valsorda — *Quantum Computers Are Not a Threat to 128-bit Symmetric Keys*](https://words.filippo.io/128-bits/)
- [PostQuantum.com — CNSA 2.0: Complete Guide to NSA's PQC Requirements](https://postquantum.com/cnsa-2-0/complete-guide/)
- [Encryption Consulting — NIST Post-Quantum Cryptography Security Levels (Categories 1–5)](https://www.encryptionconsulting.com/nist-post-quantum-cryptography-security-levels/)
- [ADHDecode — Key Size Guide: SP 800-57, ECRYPT, BSI](https://adhdecode.com/cryptography/reference-and-decision-guides/key-size-guide/)
- [AQtive Guard — Cryptographic keylengths reference](https://docs.aqtiveguard.com/kb-articles/cryptographic-keylengths/)
- [DEV Community — Why Can We Use "Shorter" Keys? Key Length vs Security Bits](https://dev.to/kanywst/why-can-we-use-shorter-keys-key-length-vs-security-bits-the-real-story-1gl3)
- [arXiv — *Post-Quantum Security: Origin, Fundamentals, and Adoption*](https://arxiv.org/pdf/2405.11885)
- [arXiv — *The Impact of Quantum Computing on Present Cryptography*](https://arxiv.org/pdf/1804.00200)
- [Sweet32 — Birthday attacks on 64-bit block ciphers](https://sweet32.info/)
- [HackTricks — Android Applications Pentesting](https://book.hacktricks.wiki/en/mobile-pentesting/android-app-pentesting/index.html)

### 5.6 Dokumentasi Tools

- [Semgrep — Documentation](https://semgrep.dev/docs/)
- [Semgrep — Pattern syntax reference](https://semgrep.dev/docs/writing-rules/pattern-syntax/)
- [mindedsecurity/semgrep-rules-android-security](https://github.com/mindedsecurity/semgrep-rules-android-security)
- [mobsfscan — static analysis untuk Android/iOS](https://github.com/MobSF/mobsfscan)
- [MobSF — Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)
- [CodeQL — Documentation](https://codeql.github.com/docs/)
- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [apktool — Reverse engineering Android APK files](https://apktool.org/)
- [APKiD — Android Application Identifier](https://github.com/rednaga/APKiD)
- [Frida — Documentation Home](https://frida.re/docs/home/)
- [OpenSSL — `x509` command](https://www.openssl.org/docs/man3.0/man1/openssl-x509.html)
- [keytool — Java key and certificate management tool](https://docs.oracle.com/en/java/javase/17/docs/specs/man/keytool.html)

---

*Dokumen ini disusun berdasarkan OWASP MASTG (rilis terkini per September 2026), dokumentasi resmi Android Developers, standar NIST/FIPS/BSI/ECRYPT/CNSA 2.0, serta riset kriptografi pihak ketiga.*
