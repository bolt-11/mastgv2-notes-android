# MASTG-TEST-0212 Use of Hardcoded Cryptographic Keys in Code

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0212 |
| **Platform** | Android |
| **Kategori MASVS** | **MASVS-CRYPTO** (MASVS-CRYPTO-1: Aplikasi menggunakan kriptografi terkini yang diterapkan dengan benar) |
| **Weakness** | **MASWE-0003** — *Cryptographic Keys Stored Outside of Platform Keystore* |
| **Tipe Pengujian** | **Static**, Code |
| **Profile** | L1, L2 |
| **Knowledge** | MASTG-KNOW-0012 (Key Generation) |
| **Teknik terkait** | MASTG-TECH-0013 (Reverse Engineering Android Apps), MASTG-TECH-0014 (Static Analysis on Android), MASTG-TECH-0023 (Reviewing Decompiled Java Code) |
| **Demo terkait** | MASTG-DEMO-0017 (Use of Hardcoded AES Key in SecretKeySpec with semgrep) |
| **API utama** | `javax.crypto.spec.SecretKeySpec` (membuat `SecretKey` dari byte array) |
| **CWE terkait** | CWE-321 (Use of Hard-coded Cryptographic Key), CWE-798 (Use of Hard-coded Credentials), CWE-259 (Use of Hard-coded Password), CWE-547 (Use of Hard-coded, Security-relevant Constants), CWE-922 (Insecure Storage of Sensitive Information) |
| **Prinsip yang dilanggar** | **Kerckhoffs's principle** — keamanan sistem tidak boleh bergantung pada kerahasiaan algoritma/implementasinya, hanya pada kerahasiaan kunci |

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian

Test ini mencari **penggunaan kunci kriptografi yang di-hardcode** di dalam aplikasi Android melalui analisis statis.

Kutipan langsung dari overview MASTG:

> *"In this test case, we will look for the use of hardcoded keys in Android applications. To do this, we need to focus on the cryptographic implementations of hardcoded keys. The Java Cryptography Architecture (JCA) provides the `SecretKeySpec` class, which allows you to create a `SecretKey` from a **byte array**."*

Jadi titik fokusnya adalah **`SecretKeySpec`** — kelas yang menjadi "jembatan" antara byte array biasa dan objek `SecretKey` yang dapat dipakai `Cipher`. Setiap kali kunci berasal dari byte array literal, di situlah kelemahan ini muncul.

### 1.2 Kenapa Ini Selalu Gagal: Kunci di Dalam APK Bukan Rahasia

Aplikasi mobile **didistribusikan kepada penyerang**. Ini perbedaan fundamental dengan aplikasi server: setiap orang yang memasang aplikasi memiliki salinan lengkap kodenya, dan dapat mendekompilasinya kapan saja tanpa batas waktu maupun deteksi.

Dokumentasi Android menegaskan bahwa hardcoded cryptographic secrets **melanggar Kerckhoffs's principle** dan merusak seluruh model keamanan:

> *"Developers commonly hardcode secrets as strings, byte arrays, or in asset files like `strings.xml`, making them **easily retrievable through reverse engineering**."*

Dampaknya menurut dokumentasi Android:
- **Attacker access** — tool reverse engineering dapat mengekstraksi secret hardcoded dengan mudah
- **Security breach** — akses tidak sah ke data sensitif
- **Compromised encryption** — **seluruh model keamanan kriptografi menjadi rusak**

Konsekuensi praktis yang perlu dipahami:

| Konsekuensi | Penjelasan |
|---|---|
| **Kunci berlaku untuk SEMUA pengguna** | Satu kunci hardcoded = satu kunci untuk seluruh basis pengguna. Mengekstraksi kunci dari satu perangkat membuka data semua pengguna |
| **Tidak dapat dirotasi tanpa update aplikasi** | Bila kunci bocor, satu-satunya cara memperbaikinya adalah merilis versi baru — dan pengguna yang belum update tetap rentan |
| **Data historis tetap terekspos** | Data yang sudah dienkripsi dengan kunci itu tidak menjadi aman kembali setelah rotasi |
| **Obfuscation tidak menolong** | Menyembunyikan kunci hanya menambah satu langkah; kunci tetap harus berada di memori saat dipakai, sehingga dapat di-dump dengan Frida |
| **Backend ikut terekspos** | Bila kunci hardcoded adalah API key/secret backend, penyerang dapat menyalahgunakan layanan berbayar atas nama aplikasi |

**Skala masalahnya di dunia nyata:** riset menunjukkan hardcoded secret tetap menjadi temuan yang sangat umum. Studi *Leaky Apps* (ACM CCS 2025) melakukan analisis skala besar terhadap API key dan material kriptografi di aplikasi Android dan iOS. Pemindaian terhadap 30.000 aplikasi menemukan **2.772 aplikasi mengekspos setidaknya satu secret yang dapat langsung dikorelasikan**. Hardcoded API key secara konsisten disebut sebagai **temuan nomor satu pada pentest mobile**.

### 1.3 Weakness-nya Lebih Luas daripada Judul Test: MASWE-0003

Ini nuansa penting yang mudah terlewat. Judul test adalah *"Use of Hardcoded Cryptographic Keys in **Code**"*, tetapi weakness yang dipetakan adalah **MASWE-0003: *Cryptographic Keys Stored Outside of Platform Keystore***.

Artinya, masalah sebenarnya bukan semata "kunci ditulis di kode", melainkan **"kunci tidak dikelola oleh platform keystore"**. Ini memperluas cakupan yang perlu kamu periksa:

| Bentuk | Termasuk MASWE-0003? |
|---|---|
| Kunci sebagai byte array literal di kode | ✅ Ya — fokus utama test ini |
| Kunci sebagai string literal (`"my secret".toByteArray()`) | ✅ Ya |
| Kunci di `strings.xml` / `res/raw/` / `assets/` | ✅ Ya |
| Kunci di `BuildConfig` (dari `gradle.properties`) | ✅ Ya — tetap masuk ke APK |
| Kunci di kode native (`.so`) | ✅ Ya |
| Kunci di-Base64/XOR/obfuscate di dalam APK | ✅ Ya — obfuscation bukan perlindungan |
| Kunci disimpan plaintext di `SharedPreferences`/file sandbox | ✅ Ya (juga MASWE-0001 / MASTG-TEST-0207) |
| Kunci diturunkan dari nilai statis (IMEI, package name, timestamp) | ✅ Ya (juga MASTG-TEST-0205) |
| Kunci dihasilkan `SecureRandom` lalu disimpan di file tanpa enkripsi | ✅ Ya — tidak hardcoded, tetapi tetap di luar keystore |
| Kunci dihasilkan & disimpan di **Android KeyStore** | ❌ Tidak — inilah target remediasi |

Sehingga **arah remediasinya jelas dan tunggal: pindahkan pengelolaan kunci ke Android KeyStore** (atau KeyChain untuk kredensial sistem), bukan sekadar "sembunyikan kuncinya lebih baik".

### 1.4 Di Mana Kunci Hardcoded Bersembunyi

Analisis statis pada kode Java saja tidak cukup. Berikut peta lokasi yang perlu disapu:

| Lokasi | Cara memeriksa |
|---|---|
| **Byte array / string literal di kode** | Rule semgrep MASTG (fokus utama) |
| **`res/values/strings.xml`** | `grep` pada hasil apktool; nilai panjang bergaya Base64/hex |
| **`res/raw/`, `assets/`** | File `.key`, `.pem`, `.jks`, `.bks`, `.p12`, `.properties`, `.json`, `.cfg` |
| **`BuildConfig`** | Field dari `buildConfigField` — sering diisi dari `gradle.properties` dan **tetap masuk ke APK sebagai konstanta** |
| **`AndroidManifest.xml` `<meta-data>`** | API key sering ditaruh di sini (mis. Maps API key) |
| **`google-services.json` / `firebase`** | Config Firebase; sebagian nilainya memang publik, tetapi periksa apakah ada server key |
| **Kode native (`.so`)** | `strings` + Ghidra. **Titik buta total rule Java.** Ingat peringatan MASTG-KNOW-0012: menyembunyikan kunci di NDK **tidak efektif** |
| **String yang dipecah/di-obfuscate** | String concatenation, array of chars, XOR di runtime, decoding di `<clinit>` |
| **String ter-encode** | Base64, hex, ROT13 — cari string panjang lalu dekode |
| **Keystore/sertifikat yang di-bundle** | `.jks`/`.bks`/`.p12` beserta password-nya yang juga sering hardcoded |
| **Kode yang dimuat runtime** | DEX/JS bundle yang diunduh — perlu analisis dinamis |
| **Library pihak ketiga** | SDK yang membawa kunci default/demo |

### 1.5 Pola "Enkripsi Palsu" yang Sering Ditemukan

Tiga pola yang tampak aman tetapi sebenarnya setara dengan kunci hardcoded:

```kotlin
// ❌ 1. Kunci hardcoded yang "diobfuscate" — tetap hardcoded
val part1 = "aX9k"; val part2 = "mQ2v"; val part3 = "T7pL"
val key = SecretKeySpec((part1 + part2 + part3).toByteArray(), "AES")

// ❌ 2. Kunci hardcoded yang di-XOR — kunci XOR-nya juga hardcoded
val enc = byteArrayOf(0x3A, 0x1F, 0x77, ...)
val key = SecretKeySpec(enc.map { (it.toInt() xor 0x5A).toByte() }.toByteArray(), "AES")

// ❌ 3. Kunci "diturunkan" dari nilai statis yang diketahui penyerang
val key = SecretKeySpec(
    MessageDigest.getInstance("SHA-256")
        .digest((context.packageName + Build.SERIAL).toByteArray()),
    "AES"
)
// Deterministik & dapat direproduksi -> setara hardcoded (bertaut MASTG-TEST-0205)
```

Untuk pola ketiga, prinsip yang berlaku sama seperti pada MASTG-TEST-0205: **hashing tidak menambah entropi**. `sha256(packageName + serial)` terlihat seperti kunci 256-bit acak, tetapi penyerang cukup mereproduksi input-nya.

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | MASTG ID | Fungsi dalam test ini |
|---|---|---|
| **jadx** | MASTG-TOOL-0018 | **Dekompilasi DEX → Java** (MASTG-TECH-0013). Wajib juga untuk MASTG-TECH-0023 — menentukan apakah kunci benar-benar hardcoded dan dipakai di konteks sensitif |
| **semgrep** | MASTG-TOOL-0110 | **Pattern matching**. MASTG menyediakan rule `mastg-android-hardcoded-crypto-keys-usage.yml` |
| **apktool** | MASTG-TOOL-0011 | **Penting untuk test ini** — mendekode resource (`strings.xml`, `res/raw/`) yang tidak terlihat di jadx `--no-res` |
| **grep / ripgrep** | — | **Pelengkap wajib** — rule MASTG hanya mencakup `SecretKeySpec` |

### 2.2 Tools Pendukung (Sangat Relevan untuk Test Ini)

| Tool | Fungsi |
|---|---|
| **apkleaks** | **MASTG-TOOL-0125.** Mendekompilasi APK dengan jadx lalu memindai hardcoded secret, API key, URI, dan endpoint memakai 50+ pola regex (AWS access key, Google API key, JWT, Firebase URL, dll.). Tool paling tepat sasaran untuk test ini |
| **TruffleHog** | Deteksi secret dengan **analisis entropi** + verifikasi aktif: bila sebuah string tampak seperti live key suatu layanan, TruffleHog **memanggil API layanan tersebut** untuk memverifikasi apakah kuncinya valid. Ini mengubah temuan dari "dugaan" menjadi "terbukti aktif" |
| **gitleaks** | Alternatif berbasis regex + entropi |
| **MobSF** | Analisis statis menyeluruh; menandai hardcoded secret di kode dan resource |
| **mobsfscan** | SAST mobile berbasis semgrep; punya rule hardcoded key |
| **nuclei** (template mobile/secret) | Pemindaian pola secret pada file hasil ekstraksi |
| **SonarQube** | Rule `java:S6418` — *Hard-coded secrets are security-sensitive*; `java:S2068` — hard-coded credentials |
| **CodeQL** | Taint analysis — melacak apakah konstanta benar-benar mengalir ke API kripto (mengurangi false positive rule semgrep) |
| **jadx-gui** | "Find Usage" + pencarian string global — untuk melacak konstanta dan string yang dipecah |
| **Frida** | MASTG-TOOL-0001 — **konfirmasi dinamis paling kuat** (lihat §3.5). Hook `SecretKeySpec.$init` dan `Cipher.init` untuk men-dump kunci **aktual** saat runtime, menembus obfuscation, string-splitting, dan kode native |
| **Ghidra / `strings`** | Analisis `.so` — kunci di kode native |
| **`ent` / analisis entropi** | Menyaring kandidat: string dengan entropi tinggi lebih mungkin merupakan kunci |
| **`keytool` / `openssl`** | Memeriksa keystore & sertifikat yang di-bundle di APK |
| **APKiD** | Deteksi packer/obfuscator untuk menilai keandalan analisis statis |

### 2.3 Prasyarat Lingkungan

- **Tidak butuh device dan tidak butuh root** untuk bagian statis — cukup file APK. Mudah diotomatisasi di CI/CD.
- **APK lengkap**, termasuk semua split APK / dynamic feature module.
- **Dekode resource juga, bukan hanya kode.** Jalankan `apktool d` (tanpa `-s`) agar `strings.xml` dan `res/raw/` terbaca. Ini sering menjadi tempat kunci bersembunyi dan **tidak akan ditemukan** bila kamu hanya memindai `./decompiled/sources/`.
- **Rule hanya `languages: java`** — pemindaian dilakukan pada kode hasil dekompilasi.
- **Perhatikan efek dekompilasi pada literal.** Di sumber Kotlin, byte array ditulis `byteArrayOf(0x6C, 0x61, ...)` (heksadesimal); di Java hasil dekompilasi menjadi **desimal** `{108, 97, ...}`. Rule MASTG mencocokkan struktur `byte[] $KEY = {...}`, sehingga bekerja pada kedua bentuk — tetapi bila kamu melakukan `grep` manual, cari **kedua notasi**.
- **Siapkan Frida untuk konfirmasi.** Untuk aplikasi yang diproteksi obfuscator/packer, analisis statis akan tidak lengkap; hooking adalah jalan paling andal.
- **Penuhi konteks terlebih dahulu.** Kriteria evaluasi mensyaratkan kunci *"used in security-sensitive contexts"*, jadi kamu perlu tahu apa yang dilindungi aplikasi.

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0013** (*Reverse Engineering Android Apps*) untuk me-reverse engineer aplikasi.
2. Gunakan **MASTG-TECH-0014** (*Static Analysis on Android*) untuk mencari API yang relevan.

Untuk evaluasi: gunakan **MASTG-TECH-0023** (*Reviewing Decompiled Java Code*) untuk meninjau setiap lokasi temuan.

### 3.2 Implementasi Praktis (MASTG-DEMO-0017)

**Langkah 1 — Dekompilasi kode DAN resource**

```bash
# Kode
jadx -d ./decompiled ./target-app.apk

# Resource (WAJIB — strings.xml, res/raw, assets)
apktool d -f -o ./decoded ./target-app.apk

# Ekstraksi mentah untuk aset biner & .so
unzip -o ./target-app.apk -d ./apk_x >/dev/null
```

**Langkah 2 — Jalankan rule semgrep resmi MASTG**

Rule `mastg-android-hardcoded-crypto-keys-usage.yml`:

```yaml
rules:
  - id: mastg-android-hardcoded-crypto-keys-usage
    severity: WARNING
    languages:
      - java
    metadata:
      summary: This rule looks for hardcoded keys in use.
    message: "[MASVS-CRYPTO-1] Hardcoded cryptographic keys found in use."
    pattern-either:
      - pattern: SecretKeySpec $_ = new SecretKeySpec($KEY, $ALGO);
      - pattern: |-
          byte[] $KEY = {...};
          ...
          new SecretKeySpec($KEY, $ALGO);
```

Menjalankannya (`run.sh` dari demo):

```bash
NO_COLOR=true semgrep -c ../../../../rules/mastg-android-hardcoded-crypto-keys-usage.yml \
  ./MastgTest_reversed.java > output.txt
```

Untuk aplikasi nyata:

```bash
NO_COLOR=true semgrep \
  -c ./mastg/rules/mastg-android-hardcoded-crypto-keys-usage.yml \
  ./decompiled/sources/ --json -o findings-hardcoded-keys.json
```

**Langkah 3 — Jalankan pemindai secret khusus (pelengkap yang sangat berguna)**

```bash
# apkleaks (MASTG-TOOL-0125) — 50+ pola regex untuk secret & endpoint
apkleaks -f ./target-app.apk -o apkleaks-report.txt

# TruffleHog — entropi + VERIFIKASI aktif ke API layanan
trufflehog filesystem ./decompiled ./decoded --results=verified,unknown

# gitleaks
gitleaks detect --no-git -s ./decompiled -r gitleaks.json
```

**Langkah 4 — Review setiap temuan (MASTG-TECH-0023)**

Untuk setiap lokasi, jawab empat pertanyaan:

1. **Apakah nilainya benar-benar hardcoded?** (literal, atau berasal dari KeyStore/PBKDF2/server?) — ini krusial karena rule MASTG menghasilkan banyak false positive (§3.4).
2. **Kunci ini dipakai untuk apa?** Enkripsi data at-rest, HMAC, token signing, atau hanya test/demo code?
3. **Apakah konteksnya security-sensitive?** Ini syarat eksplisit dalam kriteria evaluasi.
4. **Apakah ada kunci lain** di resource/native yang belum tertangkap?

### 3.3 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG:**

> **Observation:** *"The output should contain a list of locations where hardcoded keys are used."*
>
> **Evaluation:** *"The test case **fails** if you find any hardcoded keys that are **used in security-sensitive contexts**."*

Perhatikan kualifikasi **"used in security-sensitive contexts"** — sama seperti MASTG-TEST-0204/0205. Kunci hardcoded di kode test/demo, atau konstanta yang bukan kunci kriptografi, bukan temuan.

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi | Contoh bukti |
|---|---|---|
| F1 | **Byte array literal** dipakai sebagai kunci kriptografi | `byte[] keyBytes = {108, 97, 107, ...}; new SecretKeySpec(keyBytes, "AES")` |
| F2 | **String literal** dikonversi menjadi kunci | `SecretKeySpec("my secret here".toByteArray(), "AES")` |
| F3 | Kunci hardcoded dipakai untuk **enkripsi data sensitif** | `cipher.init(ENCRYPT_MODE, hardcodedKey)` pada data user |
| F4 | Kunci hardcoded dipakai untuk **HMAC / signing / token verification** | `Mac.getInstance("HmacSHA256").init(new SecretKeySpec("secret".getBytes(), "HmacSHA256"))` |
| F5 | **IV hardcoded** bersama kunci hardcoded | `new IvParameterSpec("1234567890123456".getBytes())` — memperburuk F1/F2 |
| F6 | Kunci/secret di **`strings.xml`** atau resource lain | `<string name="api_secret">sk_live_...</string>` |
| F7 | Kunci di **`assets/` atau `res/raw/`** | `assets/private.pem`, `res/raw/keystore.bks` + password hardcoded |
| F8 | Kunci di **`BuildConfig`** | `BuildConfig.API_SECRET` — dari `gradle.properties`, tetap masuk APK sebagai konstanta |
| F9 | Kunci di **`AndroidManifest.xml` `<meta-data>`** | API key layanan berbayar |
| F10 | Kunci hardcoded di **kode native** | `strings lib.so` → string bergaya kunci; dikonfirmasi Ghidra. **Titik buta rule** |
| F11 | Kunci hardcoded yang **di-obfuscate / dipecah / di-XOR / di-Base64** | String concatenation, array char, decoding di `<clinit>` — tetap hardcoded |
| F12 | Kunci **diturunkan dari nilai statis** yang diketahui penyerang | `sha256(packageName + Build.SERIAL)` — deterministik (bertaut MASTG-TEST-0205) |
| F13 | **Password keystore** hardcoded | `keyStore.load(inputStream, "changeit".toCharArray())` |
| F14 | **Salt PBKDF2 hardcoded** sehingga kunci turunan menjadi deterministik lintas pengguna | `PBEKeySpec(pw, "fixedsalt".toByteArray(), 10000, 256)` |
| F15 | Kunci dihasilkan dengan benar tetapi **disimpan di luar KeyStore** tanpa perlindungan | `SecureRandom` → disimpan plaintext di `SharedPreferences` (juga MASWE-0001) |
| F16 | Kunci hardcoded **dicatat ke log atau ditampilkan di UI** | `Log.d(TAG, Base64.encodeToString(key.encoded, ...))` — memperburuk (bertaut MASTG-TEST-0203) |
| F17 | Verifikasi aktif (mis. TruffleHog) membuktikan **secret masih valid/live** | Kunci layanan pihak ketiga terkonfirmasi aktif → **severity kritis** |

**Contoh output yang menandakan FAIL — MASTG-DEMO-0017:**

Kode sampel (`MastgTest.kt`):

```kotlin
fun mastgTest(): String {

    // Bad: Use of a hardcoded key (from bytes) for encryption
    val keyBytes = byteArrayOf(0x6C, 0x61, 0x6B, 0x64, 0x73, 0x6C, 0x6A, 0x6B,
                               0x61, 0x6C, 0x6B, 0x6A, 0x6C, 0x6B, 0x6C, 0x73)
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    val secretKey = SecretKeySpec(keyBytes, "AES")
    cipher.init(Cipher.ENCRYPT_MODE, secretKey)

    // Bad: Hardcoded key directly in code (security risk)
    val badSecretKeySpec = SecretKeySpec("my secret here".toByteArray(), "AES")

    return "SUCCESS!!\n\n... Hardcoded AES Encryption Key: " +
           "${Base64.encodeToString(keyBytes, Base64.DEFAULT)}\n" +
           "Hardcoded Key from string: ${Base64.encodeToString(badSecretKeySpec.encoded, Base64.DEFAULT)}\n"
}
```

Kode hasil dekompilasi yang dipindai semgrep (`MastgTest_reversed.java`):

```java
public final String mastgTest() {
    byte[] keyBytes = {108, 97, 107, 100, 115, 108, 106, 107,
                       97, 108, 107, 106, 108, 107, 108, 115};      // <-- baris 24
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");        // <-- baris 25
    SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");   // <-- baris 26
    cipher.init(1, secretKey);
    byte[] bytes = "my secret here".getBytes(Charsets.UTF_8);
    SecretKeySpec badSecretKeySpec = new SecretKeySpec(bytes, "AES"); // <-- baris 30
    return "SUCCESS!!..." + Base64.encodeToString(keyBytes, 0) + ...;
}
```

Output semgrep (`output.txt`):

```
┌─────────────────┐
│ 3 Code Findings │
└─────────────────┘

    MastgTest_reversed.java
    ❯❱ rules.mastg-android-hardcoded-crypto-keys-usage
          [MASVS-CRYPTO-1] Hardcoded cryptographic keys found in use.

           24┆ byte[] keyBytes = {108, 97, 107, 100, 115, 108, 106, 107, 97, 108, 107, 106, 108, 107, 108,
               115};
           25┆ Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
           26┆ SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");
            ⋮┆----------------------------------------
           26┆ SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");
            ⋮┆----------------------------------------
           30┆ SecretKeySpec badSecretKeySpec = new SecretKeySpec(bytes, "AES");
```

Evaluasi MASTG:

> *"The test **fails** because hardcoded cryptographic keys are present in the code. Specifically:*
> - *On **line 24**, a byte array that represents a cryptographic key is directly hardcoded into the source code.*
> - *This hardcoded key is then used on **line 26** to create a `SecretKeySpec`.*
> - *Additionally, on **line 30**, another instance of hardcoded data is used to create a separate `SecretKeySpec`."*

**Enam observasi teknis dari demo ini:**

1. **Ada 3 findings, tetapi hanya 2 kunci.** Baris 26 dilaporkan **dua kali** — sekali oleh pattern kedua (yang mencakup rentang baris 24–26 karena mensyaratkan `byte[] $KEY = {...}` mendahuluinya) dan sekali oleh pattern pertama (`SecretKeySpec $_ = new SecretKeySpec(...)`). **Jangan hitung ganda** saat melaporkan jumlah temuan.

2. **Byte array yang tampak acak ternyata ASCII yang terbaca.** Decode `{108, 97, 107, 100, 115, 108, 106, 107, 97, 108, 107, 106, 108, 107, 108, 115}` → **`"lakdsljkalkjlkls"`**. Ini pola yang sangat umum di aplikasi nyata: developer mengetik sembarang di keyboard, hasilnya *terlih* seperti data biner di kode dekompilasi tetapi sebenarnya string ASCII berentropi rendah. **Selalu decode byte array temuan ke ASCII** — ini memperkuat bukti di laporan dan kadang mengungkap kata/frasa bermakna.

3. **Kunci pertama panjangnya 16 byte = AES-128** — sehingga sampel ini **sekaligus gagal MASTG-TEST-0208** (Insufficient Key Sizes, yang menilai AES-128 tidak memadai). Contoh bagus bahwa satu potongan kode bisa memicu beberapa test MASVS-CRYPTO.

4. **Kunci kedua (`"my secret here"`) panjangnya 14 byte** — bukan 16/24/32, sehingga **bukan panjang kunci AES yang valid**. Bila `badSecretKeySpec` benar-benar dipakai untuk `cipher.init()`, akan melempar `InvalidKeyException`. Di sampel ini ia tidak dipakai untuk enkripsi, hanya di-encode ke Base64 untuk ditampilkan. Ini menandai `badSecretKeySpec` sebagai **kunci yang terbentuk tetapi tidak dipakai** — dalam penilaian aplikasi nyata, kondisi seperti ini perlu dicek: apakah kunci tersebut benar-benar dipakai di konteks sensitif, atau hanya sisa kode?

5. **Sampel juga membocorkan kunci melalui output aplikasi** — `Base64.encodeToString(keyBytes, ...)` dikembalikan ke UI. Pada aplikasi nyata pola yang sama (mis. `Log.d` dengan `key.encoded`) adalah kebocoran kunci langsung, dan merupakan temuan tambahan (bertaut MASTG-TEST-0203).

6. **Mode enkripsinya sudah benar (AES/GCM/NoPadding)** — ini pengingat bahwa mode yang benar tidak menyelamatkan kunci yang salah. Ketiga dimensi (algoritma/mode, ukuran kunci, asal kunci) harus benar bersamaan.

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi | Contoh bukti |
|---|---|---|
| P1 | **Tidak ada temuan** dari semgrep, apkleaks, TruffleHog, maupun grep pada resource/native | `0 Code Findings`; apkleaks report bersih |
| P2 | Semua kunci **dihasilkan & dikelola Android KeyStore** | `KeyGenerator.getInstance(..., "AndroidKeyStore")` + `KeyGenParameterSpec`; tidak ada `SecretKeySpec` dari literal |
| P3 | Kunci **diturunkan dari input user** dengan KDF yang benar dan **salt acak per pengguna** | `PBEKeySpec(userPassword, randomSalt, 600_000, 256)` dengan salt dari `SecureRandom` |
| P4 | Kunci **diambil dari server** melalui kanal terautentikasi, tidak disimpan permanen | Key provisioning saat login; kunci hanya di memori |
| P5 | Ada `SecretKeySpec`, tetapi **input-nya bukan literal** — berasal dari KeyStore, KDF, atau server | Review kode membuktikan sumber non-literal → **false positive rule** |
| P6 | Temuan hanya berada di **kode test/demo yang tidak masuk build release** | Dikonfirmasi: kelas tersebut tidak ada di APK release |
| P7 | Konstanta yang terdeteksi **bukan kunci kriptografi** | Mis. magic bytes untuk validasi format file, konstanta protokol |
| P8 | `strings.xml`, `assets/`, `res/raw/`, `BuildConfig`, `AndroidManifest` bersih dari secret | grep + apkleaks bersih |
| P9 | Kredensial sistem memakai **KeyChain** (bukan hardcoded) | `KeyChain.getPrivateKey(context, alias)` |

**Contoh output yang menandakan PASS:**

```bash
$ NO_COLOR=true semgrep -c mastg-android-hardcoded-crypto-keys-usage.yml ./decompiled/sources/
┌──────────────────┐
│ 0 Code Findings  │
└──────────────────┘

$ apkleaks -f ./target-app.apk -o report.txt && grep -cE "^\[" report.txt
0

$ trufflehog filesystem ./decompiled ./decoded --results=verified
# (tidak ada verified secret)

$ grep -rnE "(secret|api[_-]?key|token|password|private[_-]?key)" ./decoded/res/values/strings.xml
# (tidak ada hasil)
```

Kode yang benar:

```kotlin
// ✅ Kunci dihasilkan & disimpan di Android KeyStore — key material tidak pernah
//    ada di kode maupun di file, dan tidak dapat diekstraksi dari secure hardware
private const val KEYSTORE_PROVIDER = "AndroidKeyStore"
private const val KEY_ALIAS = "AES_KEY_DEMO"

private fun createAndStoreSecretKey() {
    val keySpec = KeyGenParameterSpec.Builder(
        KEY_ALIAS,
        KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
    )
        .setKeySize(256)
        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
        .setRandomizedEncryptionRequired(true)
        .build()

    val keyGen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE_PROVIDER)
    keyGen.init(keySpec)
    keyGen.generateKey()
}

private fun encryptWithKeyStore(plainText: String): ByteArray {
    val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
    val entry = keyStore.getEntry(KEY_ALIAS, null) as KeyStore.SecretKeyEntry
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    cipher.init(Cipher.ENCRYPT_MODE, entry.secretKey)
    // Simpan cipher.iv bersama ciphertext
    return cipher.doFinal(plainText.toByteArray())
}
```

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Pattern pertama rule MASTG menghasilkan BANYAK false positive — ini kelemahan terpentingnya.** Pattern `SecretKeySpec $_ = new SecretKeySpec($KEY, $ALGO);` mencocokkan **setiap** pembuatan `SecretKeySpec` yang di-assign ke variabel bertipe `SecretKeySpec`, **tanpa memeriksa apakah `$KEY` benar-benar hardcoded**. Kode yang sepenuhnya benar pun akan terpicu:

   ```java
   // Semuanya AMAN, tetapi tetap terpicu oleh pattern pertama:
   SecretKeySpec k1 = new SecretKeySpec(factory.generateSecret(pbeSpec).getEncoded(), "AES"); // dari PBKDF2
   SecretKeySpec k2 = new SecretKeySpec(keyFromServer, "AES");                                // dari server
   SecretKeySpec k3 = new SecretKeySpec(randomBytes, "AES");                                  // dari SecureRandom
   ```

   **Konsekuensi:** setiap temuan **wajib** diverifikasi dengan MASTG-TECH-0023 untuk menentukan asal `$KEY`. Melaporkan output semgrep apa adanya akan menghasilkan banyak false positive dan merusak kredibilitas laporan. Untuk otomatisasi yang lebih presisi, gunakan **CodeQL** (taint analysis) atau rule perluasan di §3.4.

2. **Jangan hitung temuan ganda.** Seperti terlihat di demo: baris 26 dilaporkan dua kali karena kedua pattern cocok. Laporkan per **kunci unik**, bukan per match.

3. **Selalu decode byte array temuan ke ASCII/hex.** Byte array yang tampak biner sering merupakan string ASCII berentropi rendah (demo: `"lakdsljkalkjlkls"`). Ini memperkuat bukti dan kadang mengungkap kata bermakna yang menunjukkan asal kuncinya.

4. **Output kosong ≠ otomatis PASS.** Penyebab false pass:
   - **Kunci di resource** (`strings.xml`, `assets/`, `res/raw/`) — tidak dipindai bila kamu hanya scan `sources/`
   - **Kunci di `BuildConfig`** atau `<meta-data>` manifest
   - **Kunci di kode native** (`.so`) — titik buta total rule Java
   - **String yang dipecah/di-obfuscate/di-XOR** — tidak cocok pattern literal
   - **Tipe deklarasi berbeda**: `SecretKey key = new SecretKeySpec(...)` (dideklarasikan sebagai `SecretKey`, bukan `SecretKeySpec`) **tidak cocok pattern pertama**
   - **API kunci lain**: `PBEKeySpec`, `IvParameterSpec`, `KeyStore.load(is, password)`, `Mac.init()` — tidak dicakup
   - Packing/obfuscation berat, refleksi, kode dimuat runtime, split APK tidak dianalisis
   
   **Mitigasi:** jalankan grep pelengkap (§3.4), apkleaks, TruffleHog, dan **konfirmasi dinamis dengan Frida** (§3.5) yang menembus semua hambatan di atas.

5. **Obfuscation bukan mitigasi — dan menemukannya justru memperkuat temuan.** Bila kamu menemukan kunci yang dipecah atau di-XOR, itu bukti developer **sadar** kuncinya sensitif tetapi memilih solusi yang salah. Ingat peringatan MASTG-KNOW-0012 bahwa menyembunyikan kripto di NDK adalah keyakinan salah yang tersebar luas — kunci tetap dapat di-dump dari memori.

6. **Verifikasi apakah secret masih aktif.** Untuk API key layanan pihak ketiga, TruffleHog dapat memverifikasi validitasnya dengan memanggil API layanan tersebut. Secret yang terbukti **live** naik ke severity kritis dan perlu dilaporkan sebagai insiden, bukan hanya temuan — karena berarti sudah dapat disalahgunakan sekarang.
   > Lakukan verifikasi ini hanya dalam lingkup engagement yang diizinkan, dan pertimbangkan bahwa memanggil API pihak ketiga dengan kredensial temuan dapat memicu alert atau biaya pada akun klien. Konfirmasikan dulu dengan klien.

7. **Kunci hardcoded membatalkan seluruh kontrol kripto lainnya.** Sampel demo memakai AES/GCM/NoPadding — mode yang benar — tetapi tetap tidak aman. Saat melaporkan, jelaskan bahwa ini bukan masalah "konfigurasi kripto" melainkan **kegagalan model keamanan**: tidak ada rahasia yang tersisa.

8. **Severity dimodulasi oleh beberapa faktor:**

   | Faktor | Severity |
   |---|---|
   | Kunci hardcoded melindungi data user (enkripsi at-rest, PII, finansial, kesehatan) | **Kritis** |
   | API key/secret backend layanan berbayar, **terkonfirmasi aktif** | **Kritis** — penyalahgunaan langsung |
   | Kunci hardcoded untuk HMAC/token signing (bypass autentikasi/integritas) | **Kritis** |
   | Kunci hardcoded + IV hardcoded | **Kritis** — ciphertext deterministik |
   | Password keystore hardcoded | **Tinggi** |
   | Salt PBKDF2 hardcoded (kunci turunan sama lintas pengguna) | **Tinggi** |
   | Kunci diturunkan dari nilai statis (packageName, serial, timestamp) | **Tinggi** |
   | Kunci dihasilkan benar tetapi disimpan plaintext di luar KeyStore | **Tinggi** |
   | Kunci hardcoded untuk data non-sensitif (mis. checksum konfigurasi lokal) | Rendah |
   | Kunci hardcoded di kode test yang tidak masuk release | **Bukan temuan** (catat sebagai hygiene) |
   | Konstanta yang bukan kunci kriptografi | **Bukan temuan** (false positive) |

9. **Dokumentasikan bukti lengkap per temuan:** path + nomor baris, potongan kode dekompilasi, **nilai kunci** (redaksi sebagian, sertakan bentuk ASCII/hex hasil decode), panjang kunci dalam byte/bit, algoritma dan mode yang memakainya, **asal `$KEY`** hasil pelacakan (literal / KDF / server / KeyStore), konteks penggunaan dan mengapa security-sensitive, hasil verifikasi aktif bila dilakukan, serta batasan analisis (obfuscation, kode native belum dianalisis, resource belum disapu). Cantumkan juga jumlah **kunci unik** vs jumlah match semgrep untuk menghindari kesan menempel output tool.

### 3.4 Celah Rule MASTG dan Pemeriksaan Pelengkap

| Celah | Contoh yang lolos |
|---|---|
| Deklarasi bertipe `SecretKey`, bukan `SecretKeySpec` | `SecretKey k = new SecretKeySpec(literal, "AES");` — pattern pertama butuh tipe `SecretKeySpec` |
| `SecretKeySpec` tanpa assignment | `cipher.init(1, new SecretKeySpec(literal, "AES"));` |
| Array literal di **field tingkat kelas** | `private static final byte[] KEY = {...};` — pattern kedua butuh keduanya di satu blok |
| `char[]` / `String` literal untuk password keystore | `keyStore.load(is, "changeit".toCharArray())` |
| **`PBEKeySpec`** dengan password/salt hardcoded | `new PBEKeySpec("pw".toCharArray(), "salt".getBytes(), 1000, 256)` |
| **`IvParameterSpec`** / **`GCMParameterSpec`** dengan IV hardcoded | `new IvParameterSpec("0123456789abcdef".getBytes())` |
| **`Mac.init()`** dengan kunci hardcoded | HMAC secret |
| **`KeyFactory`/`X509EncodedKeySpec`** dengan kunci publik/privat hardcoded | Pinning key, RSA private key di kode |
| **Resource**: `strings.xml`, `res/raw/`, `assets/` | Tidak dipindai bila hanya scan `sources/` |
| **`BuildConfig`**, `<meta-data>` manifest | Tidak dicakup |
| **Kode native** (`.so`) | Titik buta total |
| String dipecah / di-XOR / di-Base64 | Tidak cocok pattern literal |
| `languages: java` saja | Sumber Kotlin tidak dipindai |

**Perintah pemeriksaan pelengkap:**

```bash
D=./decompiled/sources
R=./decoded
X=./apk_x

# ===== 1. Semua API yang menerima material kunci (tinjau asal argumennya) =====
grep -rnE "new SecretKeySpec\(|new PBEKeySpec\(|new IvParameterSpec\(|new GCMParameterSpec\(" $D
grep -rnE "Mac\.getInstance|\.init\(.*SecretKeySpec" $D
grep -rnE "X509EncodedKeySpec|PKCS8EncodedKeySpec|KeyFactory\.getInstance" $D

# ===== 2. Literal yang langsung menjadi kunci =====
grep -rnE "new SecretKeySpec\(\s*\"" $D                       # string literal langsung
grep -rnE "new SecretKeySpec\([A-Za-z_]+\.getBytes" $D        # string -> bytes
grep -rnE "(static )?(final )?byte\[\] [A-Z_a-z]*(KEY|SECRET|IV)[A-Za-z_]* *= *\{" $D

# ===== 3. Array byte literal panjang 16/24/32 (kandidat kunci AES) =====
grep -rnoE "byte\[\] [A-Za-z_]+ = \{[0-9, -]{40,}\}" $D | head -40

# ===== 4. Password keystore & PBKDF2 hardcoded =====
grep -rnE "\.load\([^,]+, *\"" $D                             # keyStore.load(is, "password")
grep -rnE "toCharArray\(\)" $D | grep -iE "\"[^\"]{4,}\""
grep -rnE "new PBEKeySpec\(" $D -A1

# ===== 5. IV hardcoded =====
grep -rnE "new (IvParameterSpec|GCMParameterSpec)\([^)]*\"" $D
grep -rnE "new (IvParameterSpec|GCMParameterSpec)\([^)]*\{" $D

# ===== 6. Kunci "diturunkan" dari nilai statis (bertaut MASTG-TEST-0205) =====
grep -rnE "getPackageName\(\)|Build\.SERIAL|ANDROID_ID|getDeviceId|getMacAddress" $D \
  | grep -iE "digest|sha|md5|key|secret"

# ===== 7. RESOURCE — sering terlewat =====
grep -rniE "(secret|api[_-]?key|apikey|token|password|passwd|private[_-]?key|client[_-]?secret|aes[_-]?key)" \
  $R/res/values/*.xml
find $R/res/raw $R/assets -type f 2>/dev/null | head -50
grep -rnaiE "BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY" $R $X | head
grep -rniE "(secret|key|token|password)" $R/AndroidManifest.xml

# ===== 8. BuildConfig =====
grep -rnE "class BuildConfig" $D -A40 | grep -iE "SECRET|KEY|TOKEN|PASSWORD"

# ===== 9. String berentropi tinggi / bergaya Base64-hex (kandidat kunci) =====
grep -rnoE "\"[A-Za-z0-9+/]{32,}={0,2}\"" $D | head -40       # Base64 ≥ 32 char
grep -rnoE "\"[0-9a-fA-F]{32,}\"" $D | head -40               # hex ≥ 32 char

# ===== 10. Keystore & sertifikat yang di-bundle =====
find $X -iname "*.jks" -o -iname "*.bks" -o -iname "*.p12" -o -iname "*.keystore" \
        -o -iname "*.pem" -o -iname "*.key" -o -iname "*.der" -o -iname "*.crt"
for p in $(find $X -iname "*.pem" -o -iname "*.key"); do
  echo "--- $p"; head -2 "$p"
done

# ===== 11. Kunci di kode native =====
for so in $(find $X -name "*.so"); do
  echo "--- $so"
  strings -n 16 "$so" | grep -aE "^[A-Za-z0-9+/]{32,}={0,2}$|^[0-9a-fA-F]{32,}$" | head
  strings "$so" | grep -aiE "BEGIN .*PRIVATE KEY|secret|api_key|password" | head
done

# ===== 12. Pemindai secret khusus =====
apkleaks -f ./target-app.apk -o apkleaks.txt
trufflehog filesystem $D $R --results=verified,unknown
gitleaks detect --no-git -s $D -r gitleaks.json

# ===== 13. Deteksi proteksi =====
apkid ./target-app.apk
```

**Rule semgrep perluasan** — mengurangi false positive **dan** menutup celah:

```yaml
rules:
  # --- Presisi tinggi: literal benar-benar mengalir ke SecretKeySpec ---
  - id: custom-hardcoded-key-literal-direct
    severity: ERROR
    languages: [java, kotlin]
    message: "[MASVS-CRYPTO-1] Kunci kriptografi hardcoded (literal langsung ke SecretKeySpec)"
    pattern-either:
      - pattern: new javax.crypto.spec.SecretKeySpec("...".getBytes(...), ...)
      - pattern: new javax.crypto.spec.SecretKeySpec("...".toByteArray(...), ...)
      - patterns:
          - pattern-inside: |
              byte[] $K = {...};
              ...
          - pattern: new javax.crypto.spec.SecretKeySpec($K, ...)
      - patterns:
          - pattern-inside: |
              static final byte[] $K = {...};
              ...
          - pattern: new javax.crypto.spec.SecretKeySpec($K, ...)

  # --- IV / nonce hardcoded ---
  - id: custom-hardcoded-iv
    severity: ERROR
    languages: [java, kotlin]
    message: "[MASVS-CRYPTO-1] IV/nonce hardcoded — ciphertext menjadi deterministik"
    pattern-either:
      - pattern: new javax.crypto.spec.IvParameterSpec("...".getBytes(...))
      - pattern: new javax.crypto.spec.GCMParameterSpec($T, "...".getBytes(...))
      - patterns:
          - pattern-inside: |
              byte[] $IV = {...};
              ...
          - pattern: new javax.crypto.spec.IvParameterSpec($IV)

  # --- Password keystore / PBKDF2 hardcoded ---
  - id: custom-hardcoded-keystore-password
    severity: ERROR
    languages: [java, kotlin]
    message: "[MASVS-CRYPTO-1] Password keystore atau parameter KDF hardcoded"
    pattern-either:
      - pattern: (java.security.KeyStore $KS).load($IS, "...".toCharArray())
      - pattern: new javax.crypto.spec.PBEKeySpec("...".toCharArray(), ...)
      - pattern: new javax.crypto.spec.PBEKeySpec($P, "...".getBytes(...), ...)

  # --- HMAC dengan kunci hardcoded ---
  - id: custom-hardcoded-hmac-key
    severity: ERROR
    languages: [java, kotlin]
    message: "[MASVS-CRYPTO-1] Kunci HMAC hardcoded"
    patterns:
      - pattern: (javax.crypto.Mac $M).init(new javax.crypto.spec.SecretKeySpec("...".getBytes(...), ...))

  # --- Sinyal lemah (perlu review manual, severity INFO agar tidak membanjiri) ---
  - id: custom-secretkeyspec-review-source
    severity: INFO
    languages: [java, kotlin]
    message: "[MASVS-CRYPTO-1] SecretKeySpec terdeteksi — verifikasi asal material kunci (KeyStore/KDF/server = OK)"
    pattern: new javax.crypto.spec.SecretKeySpec(...)
```

Pendekatan ini memisahkan **temuan presisi tinggi** (severity ERROR, literal terbukti) dari **sinyal yang perlu review** (severity INFO) — sehingga output CI tetap dapat dipakai sebagai gate.

### 3.5 Konfirmasi Dinamis — Cara Paling Andal

MASTG tidak menyediakan test dinamis untuk ini, tetapi hooking adalah **jalan paling ampuh** untuk test ini karena menembus semua hambatan analisis statis sekaligus: obfuscation, string-splitting, XOR runtime, kode native, refleksi, dan kode yang dimuat saat runtime. Kunci **harus** berada dalam bentuk plaintext di memori saat dipakai — tidak ada cara menghindarinya.

```javascript
// dump_keys.js — men-dump material kunci aktual yang dipakai aplikasi
function hex(bytes) {
    return Array.from(bytes, b => ('0' + (b & 0xff).toString(16)).slice(-2)).join('');
}
function ascii(bytes) {
    return Array.from(bytes, b => (b >= 32 && b < 127) ? String.fromCharCode(b) : '.').join('');
}
function bt(max = 12) {
    const E = Java.use("java.lang.Exception");
    const st = E.$new().getStackTrace();
    const out = [];
    for (let i = 0; i < Math.min(max, st.length); i++) {
        const f = st[i].toString();
        if (f.indexOf("javax.crypto") === 0) continue;
        out.push("    " + f);
    }
    return out.join("\n");
}

Java.perform(() => {
    // --- SecretKeySpec: titik masuk utama menurut MASTG ---
    const SKS = Java.use("javax.crypto.spec.SecretKeySpec");
    SKS.$init.overload('[B', 'java.lang.String').implementation = function (k, algo) {
        const bytes = Java.array('byte', k);
        console.log(`\n[KEY] new SecretKeySpec(${bytes.length} B = ${bytes.length * 8} bit, "${algo}")`);
        console.log(`      hex   : ${hex(bytes)}`);
        console.log(`      ascii : ${ascii(bytes)}`);
        console.log(bt());
        return this.$init(k, algo);
    };

    // --- Cipher.init: memperlihatkan kunci & IV yang benar-benar dipakai ---
    const Cipher = Java.use("javax.crypto.Cipher");
    Cipher.init.overloads.forEach(ov => {
        ov.implementation = function (...a) {
            try {
                const algo = this.getAlgorithm();
                console.log(`\n[CIPHER] Cipher("${algo}").init(mode=${a[0]})`);
                if (a[1] && a[1].getEncoded) {
                    const enc = a[1].getEncoded();
                    if (enc) {
                        const b = Java.array('byte', enc);
                        console.log(`      key hex   : ${hex(b)}  (${b.length * 8} bit)`);
                        console.log(`      key ascii : ${ascii(b)}`);
                    } else {
                        console.log(`      key: <non-extractable — kemungkinan dari AndroidKeyStore>`);
                    }
                }
                console.log(bt());
            } catch (e) { /* ignore */ }
            return ov.apply(this, a);
        };
    });

    // --- IV / nonce ---
    ['javax.crypto.spec.IvParameterSpec', 'javax.crypto.spec.GCMParameterSpec'].forEach(cls => {
        try {
            const C = Java.use(cls);
            C.$init.overloads.forEach(ov => {
                ov.implementation = function (...a) {
                    const arr = a.find(x => x && x.length !== undefined);
                    if (arr) {
                        const b = Java.array('byte', arr);
                        console.log(`\n[IV] ${cls}  ${b.length} B  hex=${hex(b)}  ascii=${ascii(b)}`);
                        console.log(bt());
                    }
                    return ov.apply(this, a);
                };
            });
        } catch (e) { /* ignore */ }
    });

    // --- Mac (HMAC) ---
    const Mac = Java.use("javax.crypto.Mac");
    Mac.init.overloads.forEach(ov => {
        ov.implementation = function (...a) {
            try {
                if (a[0] && a[0].getEncoded) {
                    const enc = a[0].getEncoded();
                    if (enc) {
                        const b = Java.array('byte', enc);
                        console.log(`\n[MAC] ${this.getAlgorithm()} key hex=${hex(b)} ascii=${ascii(b)}`);
                        console.log(bt());
                    }
                }
            } catch (e) { /* ignore */ }
            return ov.apply(this, a);
        };
    });

    // --- KeyStore.load: password keystore hardcoded ---
    const KS = Java.use("java.security.KeyStore");
    KS.load.overload('java.io.InputStream', '[C').implementation = function (is, pw) {
        if (pw !== null) {
            const s = Java.array('char', pw).map(c => String.fromCharCode(c)).join('');
            console.log(`\n[KS] KeyStore.load(password="${s}")`);
            console.log(bt());
        }
        return this.load(is, pw);
    };

    // --- PBEKeySpec: password, salt, iterasi ---
    const PBE = Java.use("javax.crypto.spec.PBEKeySpec");
    PBE.$init.overload('[C', '[B', 'int', 'int').implementation = function (pw, salt, iter, len) {
        const p = Java.array('char', pw).map(c => String.fromCharCode(c)).join('');
        const s = Java.array('byte', salt);
        console.log(`\n[PBE] password="${p}" salt=${hex(s)} (${s.length}B) iter=${iter} keyLen=${len}`);
        console.log(bt());
        return this.$init(pw, salt, iter, len);
    };
});
```

Jalankan:

```bash
frida -U -f com.example.target -l dump_keys.js -o keys.log
# lalu exercise fitur yang memakai kripto (login, simpan data, enkripsi lokal)
```

**Cara membaca outputnya** — ini poin diagnostik yang sangat berguna:

| Output | Artinya |
|---|---|
| `key hex` dan `key ascii` menampilkan nilai | Kunci **dapat diekstraksi** → berada di luar KeyStore → **FAIL** |
| `key: <non-extractable>` | `getEncoded()` mengembalikan `null` — ciri khas kunci dari **AndroidKeyStore** yang tidak dapat diekstraksi → **PASS** |
| Nilai kunci **sama** di beberapa perangkat / instalasi berbeda | Terbukti hardcoded atau deterministik lintas pengguna → **FAIL** |
| Nilai kunci **berbeda** per instalasi | Kemungkinan dihasilkan per-perangkat — periksa penyimpanannya (bisa tetap FAIL bila di luar KeyStore) |
| `ascii` menampilkan teks terbaca | Kunci berentropi rendah dari string — bukti kuat |
| `[PBE] salt=...` sama di setiap perangkat | Salt hardcoded → kunci turunan identik lintas pengguna → **FAIL** |

> **Uji dua perangkat/instalasi** adalah cara paling meyakinkan untuk membedakan kunci hardcoded dari kunci per-perangkat. Bila nilai hex-nya identik, tidak ada ruang untuk debat.

---

### 3.6 Metode Pengujian Alternatif (Multi-Tool)

Test ini punya karakter khusus: rule MASTG **terlalu longgar** (mencocokkan setiap `SecretKeySpec` tanpa memeriksa asal kuncinya, §3.3 catatan 1) **sekaligus terlalu sempit** (13 celah, §3.4). Metode alternatif di bawah menyelesaikan keduanya.

#### Metode B — Pemindai secret khusus: apkleaks, TruffleHog, gitleaks *(paling tepat sasaran)*

**Ini metode yang aku rekomendasikan sebagai pelengkap utama.** Tool-tool ini dirancang khusus untuk menemukan secret dan mencakup permukaan yang jauh lebih luas daripada rule MASTG — termasuk resource, aset, dan manifest.

```bash
# --- apkleaks (MASTG-TOOL-0125) — 50+ pola regex, langsung dari APK ---
pip install apkleaks
apkleaks -f ./target-app.apk -o apkleaks-report.txt
#   Mencakup: AWS key, Google API key, JWT, Firebase URL, Slack token,
#             private key PEM, endpoint, dan URI internal

# Dengan pola kustom tambahan
cat > custom-patterns.json <<'JSON'
{
  "AES Key Candidate (Base64 32B)": "\\b[A-Za-z0-9+/]{43}=\\b",
  "AES Key Candidate (hex 32B)": "\\b[0-9a-fA-F]{64}\\b",
  "Keystore Password": "(?i)(keystore|truststore)[_-]?(pass|password)\\s*[=:]\\s*\\S+"
}
JSON
apkleaks -f ./target-app.apk -p custom-patterns.json -o apkleaks-custom.txt

# --- TruffleHog — entropi + VERIFIKASI AKTIF ke API layanan ---
trufflehog filesystem ./decompiled ./decoded --results=verified,unknown --json > th.json
jq 'select(.Verified == true) | {detector: .DetectorName, raw: .Raw, file: .SourceMetadata.Data.Filesystem.file}' th.json
#   Secret yang "Verified: true" = TERBUKTI MASIH AKTIF -> severity kritis

# --- gitleaks — regex + entropi, cepat ---
gitleaks detect --no-git -s ./decompiled -r gitleaks.json --redact
gitleaks detect --no-git -s ./decoded   -r gitleaks-res.json --redact
```

> **Peringatan operasional untuk TruffleHog:** mode verifikasi memanggil API layanan pihak ketiga dengan kredensial temuan. Lakukan **hanya** dalam lingkup engagement yang diizinkan, dan konfirmasikan dulu ke klien — pemanggilan itu bisa memicu alert keamanan atau biaya pada akun mereka.

#### Metode C — ripgrep terstruktur *(menutup 13 celah rule, presisi tinggi)*

Lihat §3.4 untuk perintah lengkap. Ringkasan yang paling penting:

```bash
D=./decompiled/sources
R=./decoded

# Literal LANGSUNG menjadi kunci (presisi tinggi — bukan sekadar "ada SecretKeySpec")
rg -n --no-heading 'new SecretKeySpec\(\s*"' $D
rg -n --no-heading 'new SecretKeySpec\([A-Za-z_]+\.getBytes' $D
rg -n --no-heading '(static )?(final )?byte\[\] [A-Za-z_]*(KEY|SECRET|IV)[A-Za-z_]* *= *\{' $D

# API kunci lain yang TIDAK dicakup rule MASTG
rg -n --no-heading 'new PBEKeySpec\(|new IvParameterSpec\(|new GCMParameterSpec\(' $D
rg -n --no-heading '\.load\([^,]+, *"' $D                    # password keystore
rg -n --no-heading 'X509EncodedKeySpec|PKCS8EncodedKeySpec' $D
rg -n --no-heading 'Mac\.getInstance' $D -A2

# RESOURCE — permukaan yang sering terlewat total
rg -ni --no-heading '(secret|api[_-]?key|token|password|private[_-]?key|client[_-]?secret)' $R/res/values/*.xml
rg -ni --no-heading '(secret|key|token|password)' $R/AndroidManifest.xml
rg -n --no-heading 'class BuildConfig' $D -A40 | rg -i 'SECRET|KEY|TOKEN|PASSWORD'

# String berentropi tinggi (kandidat kunci)
rg -no --no-heading '"[A-Za-z0-9+/]{32,}={0,2}"' $D | head -40
rg -no --no-heading '"[0-9a-fA-F]{32,}"' $D | head -40
```

#### Metode D — CodeQL *(menghilangkan false positive rule MASTG secara otomatis)*

**Inilah solusi untuk kelemahan terbesar rule MASTG.** Taint analysis dapat membedakan `SecretKeySpec` yang menerima literal dari yang menerima hasil PBKDF2/KeyStore/server — sesuatu yang tidak mungkin dilakukan pattern matching.

```bash
codeql database create ./cqldb --language=java --command="./gradlew assembleDebug"
codeql database analyze ./cqldb \
  codeql/java-queries:Security/CWE/CWE-798/HardcodedCredentialsApiCall.ql \
  codeql/java-queries:Security/CWE/CWE-798/HardcodedPasswordField.ql \
  codeql/java-queries:Security/CWE/CWE-321/HardcodedCryptoKey.ql \
  --format=sarif-latest --output=keys.sarif

jq '.runs[].results[] | {rule: .ruleId, msg: .message.text}' keys.sarif
```

```ql
/**
 * @name Hardcoded literal flows into cryptographic key material
 * @kind path-problem
 * @problem.severity error
 */
import java
import semmle.code.java.dataflow.TaintTracking

class LiteralSource extends DataFlow::Node {
  LiteralSource() {
    this.asExpr() instanceof StringLiteral or
    this.asExpr() instanceof ArrayInit or
    this.asExpr() instanceof CompileTimeConstantExpr
  }
}

class KeyMaterialSink extends DataFlow::Node {
  KeyMaterialSink() {
    exists(ClassInstanceExpr cie |
      cie.getConstructedType().hasQualifiedName("javax.crypto.spec",
        ["SecretKeySpec", "PBEKeySpec", "IvParameterSpec", "GCMParameterSpec"]) |
      this.asExpr() = cie.getAnArgument()
    )
    or
    exists(MethodAccess ma |
      ma.getMethod().hasName("load") and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.security", "KeyStore") |
      this.asExpr() = ma.getArgument(1)
    )
  }
}
```

Hasilnya: `new SecretKeySpec(factory.generateSecret(pbeSpec).getEncoded(), "AES")` **tidak** dilaporkan (benar), sementara `new SecretKeySpec("my secret".getBytes(), "AES")` dilaporkan dengan jalur alirannya.

#### Metode E — SonarQube / SonarLint

Rule yang relevan: **`java:S6418`** (*Hard-coded secrets are security-sensitive* — memakai analisis entropi, bukan hanya regex), **`java:S2068`** (*Hard-coded credentials*), dan **`java:S6437`** (*Credentials should not be hard-coded*). Keunggulan: deteksi entropi membuatnya menemukan kunci yang tidak cocok pola nama apa pun, dan muncul langsung di IDE via SonarLint.

```bash
sonar-scanner -Dsonar.projectKey=android-app -Dsonar.sources=./app/src
```

#### Metode F — MobSF *(laporan siap kutip + pemindaian resource)*

```bash
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest
```

| Bagian laporan | Isinya |
|---|---|
| **Hardcoded Secrets** | Daftar string yang dicurigai sebagai secret, hasil pemindaian kode **dan** resource — inilah bagian paling relevan |
| **Code Analysis** | *"Files may contain hardcoded sensitive information like usernames, passwords, keys"* |
| **Firebase / Third-party** | Konfigurasi Firebase, endpoint, dan API key yang terdeteksi |

MobSF unggul karena memindai `strings.xml`, `assets/`, dan `res/raw/` sekaligus — permukaan yang tidak disentuh rule MASTG.

#### Metode G — mobsfscan *(CLI untuk CI/CD)*

```bash
mobsfscan --json -o out.json ./decompiled/sources/ ./decoded/
jq '.results | to_entries[] | select(.key | test("hardcode|secret|key"))' out.json
mobsfscan --exit-warning ./decompiled/sources/
```

#### Metode H — nuclei *(template-based scanning pada file hasil ekstraksi)*

```bash
unzip -o ./target-app.apk -d ./apk_x >/dev/null

# Template token/secret exposure dari nuclei-templates
nuclei -t ~/nuclei-templates/file/keys/ -target ./apk_x -file
nuclei -t ~/nuclei-templates/file/android/ -target ./apk_x -file
```

Berguna karena nuclei-templates dipelihara komunitas dan pola secret-nya terus diperbarui untuk layanan baru.

#### Metode I — APKHunt

```bash
go install github.com/Cyber-Buddy/APKHunt@latest
APKHunt -p ./target-app.apk -l
grep -iA3 "hardcode\|secret\|key" APKHunt_Report.txt
```

#### Metode J — Analisis kode native + string obfuscation

Rule Java tidak menjangkau `.so`, dan kunci yang dipecah/di-XOR tidak cocok pattern literal.

```bash
# 1. String bergaya kunci di .so
for so in $(find ./apk_x -name "*.so"); do
  echo "--- $so"
  strings -n 16 "$so" | grep -aE "^[A-Za-z0-9+/]{32,}={0,2}$|^[0-9a-fA-F]{32,}$" | head
  strings "$so" | grep -aiE "BEGIN .*PRIVATE KEY|secret|api_key|password" | head
done

# 2. Kunci yang di-XOR — pulihkan kuncinya
xortool -c 00 ./apk_x/assets/blob.bin
xortool-xor -f ./apk_x/assets/blob.bin -s $'\x5a' | strings | head

# 3. Kandidat blob terenkripsi/terkompresi di assets
binwalk -e ./apk_x/assets/*
file ./apk_x/assets/* ./apk_x/res/raw/*

# 4. String concatenation / array char (obfuscation sederhana)
rg -n --no-heading 'new char\[\]\s*\{' ./decompiled/sources/ | head
rg -n --no-heading '"[A-Za-z0-9]{4}"\s*\+\s*"[A-Za-z0-9]{4}"' ./decompiled/sources/ | head
```

#### Metode K — Verifikasi multi-perangkat *(pembuktian definitif, tanpa perlu baca kode)*

Ini metode yang paling sulit dibantah dan tidak memerlukan analisis kode sama sekali:

```bash
# Jalankan script dump kunci (§3.5) pada DUA perangkat/emulator berbeda
frida -U -f com.example.target -l dump_keys.js -o keys_device_A.log   # perangkat A
frida -U -f com.example.target -l dump_keys.js -o keys_device_B.log   # perangkat B

# Bandingkan nilai hex kunci yang tercatat
grep "hex" keys_device_A.log | sort > a.txt
grep "hex" keys_device_B.log | sort > b.txt
comm -12 a.txt b.txt
#   Kunci yang IDENTIK di kedua perangkat  -> HARDCODED / deterministik  -> FAIL
#   Kunci yang BERBEDA                     -> per-perangkat (periksa penyimpanannya)
#   getEncoded() = null                    -> dari AndroidKeyStore        -> PASS
```

Tambahan: ulangi setelah **uninstall + reinstall** pada perangkat yang sama. Kunci yang tetap sama setelah reinstall berarti tidak dihasilkan per-instalasi.

---

### 3.7 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Butuh device? | Butuh source? | Memindai resource/aset? | Membedakan literal vs KDF? | Kapan dipakai |
|---|---|---|---|---|---|---|
| **A** | semgrep (MASTG) | Tidak | Tidak | ❌ | ❌ **(false positive tinggi)** | Baseline resmi; **wajib diverifikasi manual** |
| **B** | apkleaks / TruffleHog / gitleaks | Tidak | Tidak | ✅ | Sebagian | **Pelengkap utama** — cakupan terluas; TruffleHog bisa verifikasi aktif |
| **C** | ripgrep terstruktur | Tidak | Tidak | ✅ | Manual | Verifikasi silang presisi tinggi |
| **D** | CodeQL | Tidak | Ya (ideal) | ❌ | ✅ **otomatis** | **Menghilangkan false positive rule MASTG** |
| **E** | SonarQube `java:S6418` | Tidak | Ya | Sebagian | ✅ | Deteksi berbasis entropi; shift-left di IDE |
| **F** | MobSF | Tidak | Tidak | ✅ | ❌ | Laporan siap kutip + resource scanning |
| **G** | mobsfscan | Tidak | Tidak | ✅ | ❌ | Gate CI/CD ringan |
| **H** | nuclei | Tidak | Tidak | ✅ | ❌ | Pola secret komunitas yang terus diperbarui |
| **I** | APKHunt | Tidak | Tidak | Sebagian | ❌ | Pass otomatis tambahan |
| **J** | `strings`/Ghidra/xortool/binwalk | Tidak | Tidak | ✅ | Manual | Kode native & kunci ter-obfuscate |
| **L** | Frida (§3.5) | **Ya** | Tidak | — | ✅ (nilai aktual) | **Menembus semua obfuscation** — kunci harus plaintext di memori |
| **K** | Frida multi-perangkat | **Ya** (2×) | Tidak | — | ✅ | **Pembuktian definitif** untuk laporan |

**Kombinasi minimum yang aku rekomendasikan:** **B (apkleaks + TruffleHog) → L (Frida dump) → K (verifikasi 2 perangkat)**.
B memberi cakupan terluas termasuk resource dan aset; L menembus obfuscation karena kunci wajib plaintext di memori saat dipakai; K memberi bukti yang tidak bisa didebat. Gunakan **A (semgrep)** sebagai gate CI saja, dan **D (CodeQL)** bila source tersedia untuk menekan false positive-nya. Tambahkan **J** bila APK memuat `.so` atau aset biner.

---

## 4. Rekomendasi Perbaikan

### 4.1 Prinsip Utama (urutan prioritas)

**Prioritas 1 — Gunakan Android KeyStore. Ini remediasi definitif untuk MASWE-0003.**

Dokumentasi Android menempatkan ini sebagai mitigasi utama: kunci dihasilkan **di dalam** secure hardware dan **tidak pernah ada dalam bentuk plaintext** — tidak di kode, tidak di file, dan tidak dapat diekstraksi bahkan dari perangkat yang di-root.

```kotlin
private const val KEYSTORE_PROVIDER = "AndroidKeyStore"
private const val KEY_ALIAS = "AES_KEY_DEMO"

// ✅ Buat kunci DI DALAM KeyStore — tidak ada key material di kode
private fun createAndStoreSecretKey() {
    val keySpec = KeyGenParameterSpec.Builder(
        KEY_ALIAS,
        KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
    )
        .setKeySize(256)                                   // AES-256 (lihat MASTG-TEST-0208)
        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
        .setRandomizedEncryptionRequired(true)             // IV acak dijamin sistem
        .setUserAuthenticationRequired(true)               // untuk data paling sensitif
        .setIsStrongBoxBacked(true)                        // bila hardware mendukung
        .build()

    val keyGen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE_PROVIDER)
    keyGen.init(keySpec)
    keyGen.generateKey()
}

// ✅ Pakai kunci tanpa pernah menyentuh key material-nya
private fun encryptWithKeyStore(plainText: String): Pair<ByteArray, ByteArray> {
    val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
    val entry = keyStore.getEntry(KEY_ALIAS, null) as KeyStore.SecretKeyEntry
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    cipher.init(Cipher.ENCRYPT_MODE, entry.secretKey)
    return cipher.doFinal(plainText.toByteArray()) to cipher.iv   // simpan IV bersama ciphertext
}
```

Untuk **kredensial sistem yang dibagikan antar aplikasi**, gunakan **KeyChain**:

```kotlin
val privateKey = KeyChain.getPrivateKey(context, alias)
val chain = KeyChain.getCertificateChain(context, alias)
```

**Prioritas 2 — Turunkan kunci dari input pengguna dengan KDF yang benar.** Bila kunci harus bergantung pada pengetahuan pengguna (mis. vault dengan master password):

```kotlin
// ✅ Salt ACAK per pengguna (bukan hardcoded), iterasi tinggi, PRF modern
val salt = ByteArray(16).also { SecureRandom().nextBytes(it) }   // simpan salt, bukan rahasia
val keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
val keySpec = PBEKeySpec(userPassword, salt, 600_000, 256)
val key = SecretKeySpec(keyFactory.generateSecret(keySpec).encoded, "AES")
```

Syarat agar ini bukan temuan:
- **Salt acak per pengguna** dari `SecureRandom` — salt hardcoded membuat kunci identik lintas pengguna (F14)
- **Iterasi tinggi** — 600.000 untuk PBKDF2-HMAC-SHA256 (bukan 10.000 seperti contoh lama); lebih baik **Argon2id**
- **PRF modern** — `PBKDF2WithHmacSHA256`, bukan SHA1
- Password **tidak** disimpan; hanya salt dan parameter

> Perhatikan: `SecretKeySpec` masih dipakai di sini, dan **akan tetap terpicu rule MASTG** — inilah false positive yang dibahas di §3.3 catatan 1. Yang penting adalah asal `$KEY`-nya bukan literal.

**Prioritas 3 — Provisioning kunci dari server (untuk kunci kritis).** Dokumentasi Android merekomendasikan untuk kunci paling kritis:

- Simpan master key di **backend yang aman**, gunakan **HSM** bila tersedia
- Ambil kunci melalui **kanal terautentikasi** (TLS + autentikasi pengguna)
- Terapkan **kebijakan rotasi kunci**
- **Jangan** simpan kunci hasil provisioning secara permanen di perangkat; bila harus, bungkus (wrap) dengan kunci KeyStore

Ini juga menyelesaikan masalah paling mendasar dari kunci hardcoded: **rotasi menjadi mungkin tanpa merilis aplikasi baru**.

**Prioritas 4 — Pindahkan secret backend keluar dari aplikasi sama sekali.** Untuk API key/secret layanan pihak ketiga, tidak ada cara aman menyimpannya di klien. Solusinya arsitektural:

- **Proksikan melalui backend sendiri** — aplikasi memanggil backend-mu, backend memanggil layanan pihak ketiga dengan secret yang tersimpan di server
- Gunakan **token berumur pendek** yang di-issue backend, bukan long-lived API key
- Untuk kunci yang **memang publik secara desain** (mis. Firebase API key, Maps API key), amankan dengan **pembatasan sisi server**: API restriction, package name + signing certificate restriction, kuota, dan monitoring

**Prioritas 5 — Jangan andalkan obfuscation, NDK, atau white-box crypto sebagai pengganti.** MASTG-KNOW-0012 menyatakan ini keyakinan salah yang tersebar luas:

> *"There is a widespread false belief that the NDK should be used to hide cryptographic operations and hardcoded keys. However, this mechanism is **ineffective**. Attackers can still use tools to identify the mechanism in use and **dump the key from memory**."*

Kunci **harus** berada dalam bentuk plaintext di memori saat dipakai — Frida akan menemukannya (lihat §3.5). Obfuscation hanya menaikkan biaya serangan sedikit, bukan mencegahnya. Gunakan obfuscation sebagai **lapisan tambahan** (MASVS-RESILIENCE), **bukan** sebagai solusi untuk MASWE-0003.

**Prioritas 6 — Bersihkan seluruh permukaan APK, bukan hanya kode.**

```gradle
// ❌ SALAH — buildConfigField tetap masuk APK sebagai konstanta
buildConfigField "String", "API_SECRET", "\"${project.property('apiSecret')}\""

// ✅ Jangan masukkan secret ke BuildConfig sama sekali.
//    Untuk nilai yang memang publik, gunakan pembatasan sisi server.
```

- Hapus secret dari `strings.xml`, `res/raw/`, `assets/`, `<meta-data>` manifest
- Hapus file `.pem`, `.key`, `.jks`, `.p12` yang tidak perlu dari APK
- Jangan hardcode password keystore; bila keystore harus di-bundle, pertimbangkan ulang desainnya
- Aktifkan **R8/ProGuard** — bukan sebagai perlindungan kunci, tetapi untuk mengurangi permukaan informasi

**Prioritas 7 — Perlakukan kunci yang sudah bocor sebagai insiden.** Bila test ini menemukan kunci hardcoded di aplikasi yang **sudah dirilis**, memperbaiki kodenya saja tidak cukup — kunci itu harus dianggap **sudah dikompromikan**:

- **Rotasi/revoke** kunci dan kredensial tersebut segera
- **Audit log** layanan terkait untuk penyalahgunaan yang mungkin sudah terjadi
- Untuk data yang sudah dienkripsi dengan kunci bocor: **enkripsi ulang** dengan kunci baru
- Rencanakan migrasi bagi pengguna versi lama

**Prioritas 8 — Tegakkan secara struktural.**
- **Secret scanning di CI/CD**: jalankan apkleaks/TruffleHog/gitleaks pada artifact APK setiap build, dan gagalkan build bila ada temuan baru di luar allowlist
- Tambahkan rule SAST presisi tinggi (§3.4) sebagai gate; pisahkan sinyal INFO agar tidak membanjiri
- Buat **satu utilitas kripto terpusat** (mis. `KeyProvider.getDataKey()`) yang **hanya** mengambil kunci dari KeyStore, lalu larang pemanggilan `SecretKeySpec` langsung lewat lint kustom atau code review checklist
- **Pre-commit hook** untuk mencegah secret masuk repo sejak awal
- Audit library pihak ketiga — jalankan pemindaian juga pada kode library hasil dekompilasi

### 4.2 Checklist Remediasi

- [ ] Setiap temuan semgrep sudah diverifikasi dengan MASTG-TECH-0023 untuk memastikan **asal material kunci** (literal / KDF / server / KeyStore)
- [ ] Jumlah **kunci unik** dilaporkan, bukan jumlah match (hindari hitung ganda)
- [ ] Byte array temuan sudah di-decode ke ASCII/hex sebagai bukti
- [ ] Tidak ada byte array / string literal yang dipakai sebagai kunci kriptografi
- [ ] Tidak ada IV/nonce hardcoded
- [ ] Tidak ada password keystore hardcoded
- [ ] Tidak ada salt PBKDF2 hardcoded; salt acak per pengguna dari `SecureRandom`
- [ ] Tidak ada kunci yang diturunkan dari nilai statis (packageName, `Build.SERIAL`, ANDROID_ID, timestamp)
- [ ] Semua kunci enkripsi data **dihasilkan & dikelola Android KeyStore**; `setUserAuthenticationRequired` & StrongBox dipertimbangkan
- [ ] Kredensial sistem yang dibagikan memakai **KeyChain**
- [ ] Kunci turunan dari password memakai `PBKDF2WithHmacSHA256` (atau Argon2id), iterasi ≥ 600.000, salt ≥ 16 byte acak
- [ ] Kunci kritis di-provision dari server melalui kanal terautentikasi, dengan kebijakan rotasi
- [ ] Secret backend/API key pihak ketiga **dipindahkan ke server** (diproksikan), bukan disimpan di klien
- [ ] Kunci yang memang publik secara desain dibatasi di sisi server (API restriction, package + signing cert, kuota, monitoring)
- [ ] `strings.xml`, `res/raw/`, `assets/`, `BuildConfig`, dan `<meta-data>` manifest bersih dari secret
- [ ] File `.pem`/`.key`/`.jks`/`.p12` yang tidak perlu dihapus dari APK
- [ ] Kode native (`.so`) bersih dari kunci hardcoded; **tidak ada upaya menyembunyikan kunci di NDK**
- [ ] Tidak ada kunci yang dicatat ke log atau ditampilkan di UI/output aplikasi
- [ ] Ukuran kunci memadai (AES-256, RSA ≥ 3072) — verifikasi silang **MASTG-TEST-0208**
- [ ] Algoritma & mode benar (AES-GCM, bukan ECB) — verifikasi silang **MASTG-TEST-0221 / 0232**
- [ ] Library pihak ketiga diaudit; semua split APK / dynamic feature module ikut dianalisis
- [ ] **Kunci yang sudah bocor di versi rilis sudah dirotasi/direvoke**, log layanan diaudit, dan data yang terdampak dienkripsi ulang
- [ ] Secret scanning (apkleaks/TruffleHog/gitleaks) + rule SAST terintegrasi di CI/CD sebagai gate
- [ ] Utilitas kripto terpusat dibuat; pemanggilan `SecretKeySpec` langsung dilarang
- [ ] **Verifikasi ulang statis:** jalankan kembali MASTG-TEST-0208-style scan + grep pelengkap → bersih
- [ ] **Verifikasi ulang dinamis:** jalankan `dump_keys.js` → `getEncoded()` mengembalikan `null` (kunci non-extractable dari KeyStore), dan nilai kunci **berbeda** antar perangkat

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0212: Use of Hardcoded Cryptographic Keys in Code](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0212/)
- [MASWE-0003: Cryptographic Keys Stored Outside of Platform Keystore](https://mas.owasp.org/MASWE/MASVS-CRYPTO/MASWE-0003/)
- [MASWE-0004: Sensitive Data Hardcoded in the App Package](https://mas.owasp.org/MASWE/MASVS-STORAGE/MASWE-0004/)
- [MASTG-DEMO-0017: Use of Hardcoded AES Key in SecretKeySpec with semgrep](https://mas.owasp.org/MASTG/demos/android/MASVS-CRYPTO/MASTG-DEMO-0017/MASTG-DEMO-0017/)
- [MASTG-KNOW-0012: Key Generation](https://mas.owasp.org/MASTG/knowledge/android/MASVS-CRYPTO/MASTG-KNOW-0012/)
- [MASTG-TEST-0208: Insufficient Key Sizes](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0208/)
- [MASTG-TEST-0221: Uses of Broken Symmetric Encryption Algorithms](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0221/)
- [MASTG-TEST-0232: Uses of Broken Encryption Modes](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0232/)
- [MASTG-TEST-0205: Non-random Sources Usage](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0205/)
- [MASTG-TEST-0207: Runtime Storage of Unencrypted Data in the App Sandbox](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0207/)
- [MASTG-TECH-0013: Reverse Engineering Android Apps](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/)
- [MASTG-TECH-0014: Static Analysis on Android](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/)
- [MASTG-TECH-0023: Reviewing Decompiled Java Code](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0023/)
- [MASTG-TOOL-0125: Apkleaks](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0125/)
- [MASTG-TOOL-0110: semgrep](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0110/)
- [MASTG-TOOL-0018: jadx](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0018/)
- [MASTG-TOOL-0011: apktool](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0011/)
- [MASTG Rules — `mastg-android-hardcoded-crypto-keys-usage.yml`](https://github.com/OWASP/mastg/blob/master/rules/mastg-android-hardcoded-crypto-keys-usage.yml)
- [MASTG — Testing Cryptography](https://mas.owasp.org/MASTG/0x05e-Testing-Cryptography/)
- [MASVS-CRYPTO: Cryptography](https://mas.owasp.org/MASVS/06-MASVS-CRYPTO/)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
- [OWASP Key Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html)
- [OWASP Mobile Top 10 2024 — M1: Improper Credential Usage](https://owasp.org/www-project-mobile-top-10/2023-risks/m1-improper-credential-usage.html)
- [OWASP Mobile Top 10 2024 — M10: Insufficient Cryptography](https://owasp.org/www-project-mobile-top-10/2023-risks/m10-insufficient-cryptography.html)

### 5.2 Dokumentasi Resmi Android / Google / Java

- [Hardcoded Cryptographic Secrets — Android Security Risks](https://developer.android.com/privacy-and-security/risks/hardcoded-cryptographic-secrets)
- [`javax.crypto.spec.SecretKeySpec` — API reference](https://developer.android.com/reference/javax/crypto/spec/SecretKeySpec)
- [`javax.crypto.SecretKey` — API reference](https://developer.android.com/reference/javax/crypto/SecretKey)
- [Android Keystore system](https://developer.android.com/privacy-and-security/keystore)
- [`KeyStore` — API reference](https://developer.android.com/reference/java/security/KeyStore)
- [`KeyChain` — API reference](https://developer.android.com/reference/android/security/KeyChain)
- [`KeyGenParameterSpec` — API reference](https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec)
- [`PBEKeySpec` — API reference](https://developer.android.com/reference/javax/crypto/spec/PBEKeySpec)
- [`SecretKeyFactory` — API reference](https://developer.android.com/reference/javax/crypto/SecretKeyFactory)
- [Cryptography best practices](https://developer.android.com/privacy-and-security/cryptography)
- [Hardware-backed Keystore (AOSP)](https://source.android.com/docs/security/features/keystore)
- [StrongBox Keymaster (AOSP)](https://source.android.com/docs/security/best-practices/hardware)
- [Android Developers Blog — Android changes for NDK developers](https://android-developers.googleblog.com/2016/06/android-changes-for-ndk-developers.html)
- [Google Cloud — API key best practices & restrictions](https://cloud.google.com/docs/authentication/api-keys)
- [Firebase — Are API keys for Firebase safe to expose?](https://firebase.google.com/docs/projects/api-keys)
- [Google Tink — cryptographic library](https://developers.google.com/tink)

### 5.3 Standar & Taksonomi Kelemahan

- [CWE-321: Use of Hard-coded Cryptographic Key](https://cwe.mitre.org/data/definitions/321.html)
- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [CWE-259: Use of Hard-coded Password](https://cwe.mitre.org/data/definitions/259.html)
- [CWE-547: Use of Hard-coded, Security-relevant Constants](https://cwe.mitre.org/data/definitions/547.html)
- [CWE-922: Insecure Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/922.html)
- [CWE-1391: Use of Weak Credentials](https://cwe.mitre.org/data/definitions/1391.html)
- [Kerckhoffs's principle](https://en.wikipedia.org/wiki/Kerckhoffs%27s_principle)
- [NIST SP 800-57 Part 1 Rev. 5 — Recommendation for Key Management](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final)
- [NIST SP 800-132 — Recommendation for Password-Based Key Derivation](https://csrc.nist.gov/publications/detail/sp/800-132/final)
- [NIST SP 800-163 Rev.1 — Vetting the Security of Mobile Applications](https://csrc.nist.gov/publications/detail/sp/800-163/rev-1/final)
- [SonarQube Rule java:S6418 — Hard-coded secrets are security-sensitive](https://rules.sonarsource.com/java/RSPEC-6418/)
- [SonarQube Rule java:S2068 — Hard-coded credentials are security-sensitive](https://rules.sonarsource.com/java/RSPEC-2068/)
- [SEI CERT Oracle Coding Standard for Java — MSC03-J: Never hard code sensitive information](https://wiki.sei.cmu.edu/confluence/display/java/MSC03-J.+Never+hard+code+sensitive+information)
- [CodeQL — Java query help (hard-coded credentials)](https://codeql.github.com/codeql-query-help/java/)

### 5.4 Riset Keamanan & Artikel Teknis

- [ACM CCS 2025 — *Leaky Apps: Large-scale Analysis of Secrets Distributed in Android and iOS Apps*](https://dl.acm.org/doi/10.1145/3719027.3765033)
- [SBA Research — *Leaky Apps* (PDF versi penulis)](https://publications.sba-research.org/publications/Secrets_Distributed_in_Android_and_iOS_Apps-1_David%20Schmidt.pdf)
- [Empirical Software Engineering (Springer) — *How far are app secrets from being stolen? A case study on Android*](https://link.springer.com/article/10.1007/s10664-024-10607-9)
- [CEUR-WS — *Hardcoded credentials in Android apps: Service exposure analysis*](https://ceur-ws.org/Vol-3826/short8.pdf)
- [arXiv — *Automatically Detecting Checked-In Secrets in Android Apps: How Far Are We?*](https://arxiv.org/html/2412.10922)
- [arXiv — *A Longitudinal Study of Android Apps Signing Key Protection*](https://arxiv.org/pdf/2606.21487)
- [RedHunt Labs — *Scanning Android Apps for Secrets and More* (Project Resonance Wave 8)](https://redhuntlabs.com/blog/the-current-state-of-security-privacy-and-attack-surface-on-android-scanning-apps-for-secrets-and-more-wave-8-2/)
- [Cybernews — Android apps leak hard-coded secrets](https://cybernews.com/security/android-apps-leak-hardcoded-secrets/)
- [VAPT.PK — Hardcoded API Keys in Android Apps: 5-Minute Audit](https://vapt.pk/blog/hardcoded-api-keys-android/)
- [Undercode Testing — Exposing Hardcoded Secrets In Android Apps](https://undercodetesting.com/exposing-hardcoded-secrets-in-android-apps-a-cybersecurity-deep-dive/)
- [Jit — TruffleHog vs. Gitleaks: A Detailed Comparison of Secret Scanning Tools](https://www.jit.io/resources/appsec-tools/trufflehog-vs-gitleaks-a-detailed-comparison-of-secret-scanning-tools)
- [HackTricks — Android Applications Pentesting](https://book.hacktricks.wiki/en/mobile-pentesting/android-app-pentesting/index.html)

### 5.5 Dokumentasi Tools

- [apkleaks — Scanning APK file for URIs, endpoints & secrets](https://github.com/dwisiswant0/apkleaks)
- [TruffleHog — secret scanning with active verification](https://github.com/trufflesecurity/trufflehog)
- [gitleaks — secret detection](https://github.com/gitleaks/gitleaks)
- [MobSF — Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)
- [mobsfscan — static analysis untuk Android/iOS](https://github.com/MobSF/mobsfscan)
- [Semgrep — Documentation](https://semgrep.dev/docs/)
- [Semgrep — Pattern syntax reference](https://semgrep.dev/docs/writing-rules/pattern-syntax/)
- [CodeQL — Documentation](https://codeql.github.com/docs/)
- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [apktool — Reverse engineering Android APK files](https://apktool.org/)
- [APKiD — Android Application Identifier](https://github.com/rednaga/APKiD)
- [Frida — Documentation Home](https://frida.re/docs/home/)
- [Frida — JavaScript API: `Java`](https://frida.re/docs/javascript-api/#java)
- [Ghidra — software reverse engineering framework](https://ghidra-sre.org/)
- [keytool — Java key and certificate management tool](https://docs.oracle.com/en/java/javase/17/docs/specs/man/keytool.html)
- [OpenSSL — command-line tools](https://www.openssl.org/docs/man3.0/man1/)

---

*Dokumen ini disusun berdasarkan OWASP MASTG (rilis terkini per September 2026), dokumentasi resmi Android Developers, standar CWE/NIST/SEI CERT, serta riset keamanan pihak ketiga.*
