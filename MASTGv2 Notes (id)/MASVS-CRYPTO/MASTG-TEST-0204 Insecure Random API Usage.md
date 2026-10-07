# MASTG-TEST-0204 Insecure Random API Usage

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0204 |
| **Platform** | Android |
| **Kategori MASVS** | **MASVS-CRYPTO** (MASVS-CRYPTO-1: Aplikasi menggunakan kriptografi terkini yang diterapkan dengan benar) |
| **Weakness** | MASWE-0012 — *Insecure Random Number Generation* (penggunaan PRNG dengan entropi tidak memadai) |
| **Tipe Pengujian** | **Static**, Code, Manual |
| **Profile** | L1, L2 |
| **Knowledge** | MASTG-KNOW-0013 (Random Number Generation) |
| **Best Practice** | MASTG-BEST-0001 (Use Secure Random Number Generator APIs) |
| **Prerequisites** | `identify-sensitive-data`, `identify-security-relevant-contexts` |
| **Teknik terkait** | MASTG-TECH-0013 (Reverse Engineering Android Apps), MASTG-TECH-0014 (Static Analysis on Android), MASTG-TECH-0023 (Reviewing Decompiled Java Code) |
| **Demo terkait** | MASTG-DEMO-0007 (Common Uses of Insecure Random APIs) |
| **Test bersaudara** | MASTG-TEST-0205 (Non-random Sources Usage — sumber non-acak seperti timestamp) |
| **CWE terkait** | CWE-338 (Use of Cryptographically Weak PRNG), CWE-330 (Use of Insufficiently Random Values), CWE-337 (Predictable Seed in PRNG), CWE-335 (Incorrect Usage of Seeds in PRNG), CWE-341 (Predictable from Observable State) |

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian

Test ini menggunakan **analisis statis** untuk menemukan penggunaan **pseudorandom number generator (PRNG) yang tidak aman** di dalam aplikasi Android, lalu menilai apakah nilai acak yang dihasilkannya dipakai dalam **konteks yang relevan secara keamanan**.

Kutipan langsung dari overview MASTG:

> *"Android apps sometimes use an insecure pseudorandom number generator (PRNG), such as `java.util.Random`, which is a **linear congruential generator** and produces a **predictable sequence for any given seed value**. As a result, `java.util.Random` and `Math.random()` (the latter simply calls `nextDouble()` on a static `java.util.Random` instance) generate **reproducible sequences across all Java implementations** whenever the same seed is used. This predictability makes them unsuitable for cryptographic or other security-sensitive contexts."*
>
> *"In general, **if a PRNG is not explicitly documented as being cryptographically secure, it should not be used where randomness must be unpredictable**."*

Tiga hal penting dari kutipan itu:

1. **`java.util.Random` adalah Linear Congruential Generator (LCG)** — deterministik dan dapat diprediksi, bukan hanya "kurang acak".
2. **`Math.random()` bukan alternatif yang lebih baik** — ia hanya memanggil `nextDouble()` pada sebuah instance `java.util.Random` yang statis. Jadi keduanya sama-sama tidak aman.
3. **Aturan default yang aman:** bila sebuah PRNG tidak **secara eksplisit didokumentasikan** sebagai *cryptographically secure*, jangan pakai untuk hal yang harus tidak terprediksi. Ini prinsip yang berguna ketika kamu menemukan library PRNG yang tidak kamu kenal.

### 1.2 Mengapa `java.util.Random` Bisa Diprediksi — Landasan Teknis

Ini bukan kelemahan teoretis. `java.util.Random` dapat dipecahkan dengan usaha komputasi yang sangat kecil.

**Parameter LCG Java** (terdokumentasi publik di spesifikasi Java, bukan rahasia):

```
seed_berikutnya = (seed_sekarang × 0x5DEECE66D + 0xB) mod 2^48
```

| Parameter | Nilai |
|---|---|
| Multiplier (A) | `0x5DEECE66D` |
| Addend (C) | `0xB` |
| Modulus (M) | `2^48` |
| Ukuran state internal | **48 bit** |

**Serangan pemulihan state:** `java.util.Random` **tidak pernah mengeluarkan seluruh 48 bit state-nya** — ia mengeluarkan maksimal 32 bit pada setiap pemanggilan `nextInt()`, karena seed di-*bitshift* ke kanan sebanyak 16 bit. Konsekuensinya:

- Dengan **dua observasi berurutan** dari output `nextInt()`, penyerang dapat memulihkan seed dengan brute-force yang sangat kecil.
- 16 bit sisanya cukup di-brute-force seluruhnya: **hanya 65.536 kemungkinan** — selesai dalam hitungan milidetik di perangkat apa pun.
- Setelah seed diketahui, **seluruh nilai masa depan (dan masa lalu) dapat dihitung**.

Untuk kasus yang lebih sulit (mis. hanya beberapa bit per sampel yang terlihat, atau `nextInt(bound)` dengan bound kecil), tersedia teknik **lattice reduction (LLL)** yang memulihkan state dari lebih banyak sampel bernilai kecil. Alat siap pakai untuk ini sudah tersedia publik.

**Artinya secara praktis:** jika sebuah aplikasi menghasilkan token sesi, OTP, atau password reset token dengan `java.util.Random`, penyerang yang memperoleh dua token miliknya sendiri dapat memprediksi token milik user lain.

### 1.3 Kasus Nyata: Kerugian yang Sudah Terjadi

**Bug SecureRandom Android 2013 → pencurian Bitcoin.** Ini contoh paling instruktif karena melibatkan PRNG *yang seharusnya aman*:

- Android 4.1–4.3 (API 16–18) gagal menginisialisasi PRNG dengan benar. Google telah mengganti kode Apache Harmony yang rusak di Android 4.2 dengan implementasi berbasis OpenSSL PRNG sistem, **tetapi OpenSSL PRNG-nya tidak di-seed dengan benar**, sehingga justru lebih mudah diprediksi.
- Akibatnya, aplikasi yang memakai Java Cryptography Architecture (JCA) untuk *key generation*, *signing*, atau *random number generation* **tidak menerima nilai yang kuat secara kriptografis**.
- ECDSA mensyaratkan nonce (`k`) yang dipakai untuk menandatangani **hanya boleh dipakai sekali**. Bila nonce yang sama dipakai dua kali, **private key dapat dipulihkan** dari dua signature tersebut.
- Wallet Bitcoin di Android kadang menghasilkan nonce yang sama → **55,82 BTC dicuri** pada Agustus 2013. Wallet yang terdampak antara lain Bitcoin Wallet, blockchain.info wallet, BitcoinSpinner, dan Mycelium Wallet.
- Google merespons dengan artikel *"Some SecureRandom Thoughts"* di Android Developers Blog beserta patch untuk semua versi.

Inilah mengapa MASTG-KNOW-0013 memberi peringatan spesifik: bila aplikasi masih mendukung Android di bawah 4.4 (API 19), **perlu kehati-hatian ekstra untuk mengakali bug PRNG di API 16–18**.

**CVE lain akibat weak PRNG** (dirujuk dokumentasi Android): CVE-2013-6386 (Drupal), CVE-2006-3419 (Tor), CVE-2008-4102 (Joomla — predictable seed).

### 1.4 Kategori PRNG Tidak Aman yang Harus Dicari

**Kelompok A — PRNG yang memang tidak aman secara desain:**

| API | Masalah |
|---|---|
| `java.util.Random` | LCG 48-bit. **Jangan pernah** untuk keamanan |
| `Math.random()` | Memanggil `nextDouble()` pada instance `java.util.Random` statis. **Secara eksplisit dilarang** oleh dokumentasi Android untuk penggunaan sensitif apa pun |
| `java.util.concurrent.ThreadLocalRandom` | Juga LCG-based, tidak kriptografis. **Tidak tercakup rule MASTG** — harus dicari manual |
| `kotlin.random.Random` (`Random.nextInt()`, `Random.Default`) | Pada JVM/Android didelegasikan ke `java.util.Random`. **Sangat penting untuk aplikasi Kotlin** dan **tidak tercakup rule MASTG** |
| `org.apache.commons.lang3.RandomStringUtils.random(...)` | Memakai `Random` secara default (varian `...Secure` baru ditambahkan belakangan). Sering dipakai untuk men-generate token — persis konteks yang berbahaya |
| `org.apache.commons.lang3.RandomUtils` | Sama, berbasis `Random` |
| Implementasi PRNG kustom | Tidak punya jaminan kriptografis apa pun |

**Kelompok B — PRNG aman tetapi dipakai salah** (masuk MASWE-0012 juga, tetapi CWE-337/335):

| Pola | Masalah |
|---|---|
| `SecureRandom(seedByteArray)` dengan seed hardcoded | Output menjadi deterministik. Penyerang cukup mendekompilasi APK untuk memprediksi seluruh output |
| `secureRandom.setSeed(12345)` | Sama. Dokumentasi Android **melarang** ini |
| `SecureRandom` dengan provider lama/kustom | Dokumentasi menyebut perilaku `setSeed` dapat berbeda pada *old security provider* — bisa **mengganti** seed alih-alih menambahkannya |
| `new SecureRandom(...)` dengan konstruktor non-default | MASTG-KNOW-0013: *"Other constructors are for more advanced uses and, if used incorrectly, can lead to decreased randomness and security"* |

> Catat bahwa `SecureRandom` dengan seed hardcoded **tidak akan tertangkap** oleh rule semgrep MASTG untuk test ini. Ini perlu dicari terpisah.

**Kelompok C — Sumber non-acak** (ini ruang lingkup **MASTG-TEST-0205**, bukan test ini): `Date().getTime()`, `System.currentTimeMillis()`, `Calendar.MILLISECOND`, `nanoTime()`, `UUID` yang dibangun dari timestamp, ID perangkat. Keduanya berada di bawah MASWE-0012 dan BEST-0001, jadi dalam praktik pengujian sebaiknya dijalankan bersama.

### 1.5 Konteks yang "Relevan Secara Keamanan"

Ini inti test ini — dan inilah sebabnya ia punya **prerequisites** `identify-sensitive-data` dan `identify-security-relevant-contexts`. Berbeda dari test lain yang sudah kita bahas, **temuan `java.util.Random` saja bukan kerentanan**. Yang menentukan adalah **untuk apa** nilai acaknya dipakai.

MASTG menyebut konteks berikut sebagai security-relevant:

| Penggunaan | Mengapa kritis |
|---|---|
| **Kunci kriptografi** (symmetric key, key material) | Kunci yang dapat diprediksi = enkripsi tidak berarti |
| **Initialization Vector (IV)** | IV yang dapat diprediksi/berulang merusak keamanan CBC dan **fatal untuk GCM** (nonce reuse pada GCM membocorkan authentication key) |
| **Nonce** | Nonce ECDSA yang berulang → private key dapat dipulihkan (kasus Bitcoin 2013) |
| **Token autentikasi** | Penyerang dapat memprediksi token user lain |
| **Session identifier** | Session hijacking |
| **Password** (termasuk password yang di-generate aplikasi) | Dapat dihitung penyerang |
| **PIN** | Ruang nilai sudah kecil; PRNG lemah membuatnya makin mudah |
| **Salt** | Salt yang dapat diprediksi melemahkan perlindungan terhadap rainbow table |
| **OTP / kode verifikasi / token reset password** | Account takeover langsung |
| **CSRF token / state OAuth** | Bypass proteksi |
| **Nama file temporer di lokasi shared** | Race condition / prediksi path (bertaut dengan MASWE-0002) |

**Konteks yang TIDAK security-relevant** (sehingga `java.util.Random` dapat diterima):

- Shuffle playlist, urutan kartu dalam game non-kompetitif
- Jitter/backoff pada retry jaringan (kecuali dipakai sebagai anti-replay)
- Animasi, efek visual, posisi partikel
- Sampling untuk A/B testing atau analytics
- Pemilihan iklan atau konten acak

> Namun hati-hati dengan game yang melibatkan uang atau peringkat kompetitif — di situ "shuffle" menjadi security-relevant dan memerlukan CSPRNG.

### 1.6 Posisi Test Ini dalam Rangkaian MASVS-CRYPTO

| Test | Fokus | Pendekatan |
|---|---|---|
| **MASTG-TEST-0204** *(dokumen ini)* | Penggunaan **API PRNG yang tidak aman** (`Random`, `Math.random()`) | Statis |
| **MASTG-TEST-0205** | Penggunaan **sumber non-acak** (timestamp, `Calendar.MILLISECOND`) | Statis |

Keduanya berbagi weakness **MASWE-0012**, knowledge **MASTG-KNOW-0013**, dan best practice **MASTG-BEST-0001**. Keduanya juga sama-sama bertipe statis dengan prerequisites yang sama. **Jalankan berpasangan** — aplikasi yang memakai `java.util.Random` untuk token sering juga memakai timestamp sebagai seed atau sebagai komponen token.

Perlu dicatat: **tidak ada padanan dinamis resmi** untuk test ini di MASTG. Ini wajar karena mendeteksi "nilai ini berasal dari PRNG lemah" lewat runtime jauh lebih sulit daripada membaca kodenya. Namun untuk konfirmasi, hooking tetap bisa dipakai (lihat §3.5).

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | MASTG ID | Fungsi dalam test ini |
|---|---|---|
| **jadx** | MASTG-TOOL-0018 | **Dekompilasi DEX → Java** (MASTG-TECH-0013). Wajib juga untuk MASTG-TECH-0023 — menelusuri *bagaimana* nilai acak dipakai (ini bagian tersulit dan terpenting) |
| **semgrep** | MASTG-TOOL-0110 | **Pattern matching**. MASTG menyediakan rule `mastg-android-random-apis-insufficient-entropy.yml` |
| **grep / ripgrep** | — | Pelengkap wajib untuk menutup celah rule (lihat §3.4) |
| **apktool** | MASTG-TOOL-0011 | Alternatif dekompilasi; berguna untuk analisis smali bila jadx gagal |

### 2.2 Tools Pendukung

| Tool | Fungsi |
|---|---|
| **CodeQL** | **Sangat direkomendasikan untuk test ini.** Semgrep hanya pattern matching intra-file; CodeQL melakukan **taint analysis lintas-fungsi** — inilah yang dibutuhkan untuk menjawab "apakah nilai dari `Random` ini benar-benar mengalir ke pembuatan token?" Tersedia query `java/predictable-seed` dan terkait |
| **mobsfscan / MobSF** | SAST mobile berbasis semgrep; punya rule weak PRNG bawaan |
| **semgrep-rules-android-security** (IMQ Minded Security) | **Sumber asli** rule MASTG ini (`mstg-crypto-6.yaml`) — berguna untuk melihat varian yang lebih lengkap |
| **SonarQube** | Rule `java:S2245` — *Using pseudorandom number generators (PRNGs) is security-sensitive* |
| **Android Lint** | Beberapa check bawaan terkait `SecureRandom` |
| **jadx-gui** | Navigasi interaktif + fitur "Find Usage" — kunci untuk melacak penggunaan nilai acak |
| **APKiD** | Deteksi packer/obfuscator untuk menilai keandalan hasil analisis statis |
| **Frida** | MASTG-TOOL-0001. Untuk konfirmasi dinamis opsional (lihat §3.5) |
| **Ghidra / `strings`** | Analisis `.so` — PRNG dari kode native (`rand()`, `srand()`, `random()`) tidak terjangkau rule Java |
| **`java-prng-predict` / skrip LLL** | Alat publik untuk **membuktikan eksploitabilitas**: memulihkan seed dari dua output `nextInt()`. Berguna untuk demonstrasi PoC di laporan |

### 2.3 Prasyarat Lingkungan

- **Tidak butuh device dan tidak butuh root** — cukup file APK. Sama seperti MASTG-TEST-0202, ini membuatnya mudah diotomatisasi di CI/CD.
- **APK lengkap**, termasuk semua split APK / dynamic feature module bila aplikasi berupa AAB.
- **semgrep terinstall** dan rule MASTG tersedia (clone `github.com/OWASP/mastg`, direktori `rules/`).
- **Penuhi prerequisites terlebih dahulu.** Test ini secara formal mensyaratkan `identify-sensitive-data` dan `identify-security-relevant-contexts`. Praktisnya: sebelum memindai, pahami dulu **apa saja aset sensitif aplikasi** (token apa yang dipakai? ada enkripsi lokal? bagaimana alur autentikasinya?). Tanpa ini kamu tidak bisa menilai apakah suatu pemanggilan `Random` berbahaya atau tidak.
- **Perhatikan rule hanya untuk `languages: java`.** Karena itu pemindaian dilakukan pada **kode hasil dekompilasi (Java)**, bukan pada sumber Kotlin. Bila kamu punya akses ke source code Kotlin, rule MASTG ini **tidak akan bekerja** — perlu rule Kotlin terpisah atau grep.
- **Waspadai obfuscation.** Nama kelas framework (`java.util.Random`, `Math.random`) tidak di-obfuscate oleh R8/ProGuard karena API sistem, sehingga **deteksi tetap efektif**. Yang tersulitkan adalah tahap review penggunaan (MASTG-TECH-0023) karena nama kelas/metode aplikasi menjadi satu huruf.

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0013** (*Reverse Engineering Android Apps*) untuk me-reverse engineer aplikasi.
2. Gunakan **MASTG-TECH-0014** (*Static Analysis on Android*) untuk mencari API yang relevan.

Lalu untuk evaluasi: gunakan **MASTG-TECH-0023** (*Reviewing Decompiled Java Code*) pada setiap lokasi kode yang dilaporkan.

### 3.2 Implementasi Praktis (MASTG-DEMO-0007)

**Langkah 1 — Dekompilasi**

```bash
jadx -d ./decompiled ./target-app.apk

# Bila split APK / AAB, ambil dan dekompilasi semua bagian
adb shell pm path com.example.target
```

**Langkah 2 — Jalankan rule semgrep resmi MASTG**

Rule `mastg-android-random-apis-insufficient-entropy.yml`:

```yaml
rules:
  - id: mastg-android-random-apis-insufficient-entropy
    severity: WARNING
    languages:
      - java
    metadata:
      summary: This rule looks for common patterns including classes and methods.
      original_source: https://github.com/mindedsecurity/semgrep-rules-android-security/blob/main/rules/crypto/mstg-crypto-6.yaml
    message: "[MASVS-CRYPTO-1] The application makes use of random number generators with insufficient entropy."

    pattern-either:
        - patterns:
            - pattern-inside: $M(...){ ... }
            - pattern-either:
                - pattern: Math.random(...)
                - pattern: (java.util.Random $X).$Y(...)
```

Menjalankannya (`run.sh` dari demo):

```bash
NO_COLOR=true semgrep -c ../../../../rules/mastg-android-random-apis-insufficient-entropy.yml \
  ./MastgTest_reversed.java > output.txt
```

Untuk aplikasi nyata:

```bash
NO_COLOR=true semgrep \
  -c ./mastg/rules/mastg-android-random-apis-insufficient-entropy.yml \
  ./decompiled/sources/ --json -o findings-random.json
```

**Langkah 3 — Review setiap temuan (MASTG-TECH-0023)** — **wajib**

Untuk setiap baris yang dilaporkan, jawab:

1. **Nilai acak ini dipakai untuk apa?** Lacak variabelnya sampai titik penggunaan akhir.
2. **Apakah titik penggunaan itu security-relevant?** Bandingkan dengan tabel di §1.5.
3. **Jika temuan berada di dalam fungsi helper** (mis. `getRandom()`), **lacak semua pemanggilnya** — ini yang sering terlewat.

```bash
# Lacak penggunaan variabel hasil Random
grep -rn "random1\|random2\|random3" ./decompiled/sources/org/owasp/mastestapp/

# Cari pemanggil fungsi helper random
grep -rn "getRandom\|get_random\|randomString\|generateToken\|generateNonce" ./decompiled/sources/

# Di jadx-gui: klik kanan pada metode → "Find Usage"
```

### 3.3 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG:**

> **Observation:** *"The output should contain a list of locations where insecure random APIs are used."*
>
> **Evaluation:** *"The test case **fails** if you can find random numbers generated using those APIs that are **used in security-relevant contexts**, such as generating passwords or authentication tokens."*
>
> **Further Validation Required** — inspeksi setiap lokasi kode dengan MASTG-TECH-0023 untuk menentukan apakah penggunaannya security-relevant:
> - Tentukan apakah nilai acak yang dihasilkan dipakai untuk tujuan security-relevant, seperti pembuatan **kunci kriptografi, initialization vector (IV), nonce, token autentikasi, session identifier, password, atau PIN**.

**Poin kunci:** klausa *"used in security-relevant contexts"* adalah **syarat mutlak**. Temuan `java.util.Random` tanpa konteks security-relevant **bukan FAIL**. Ini berbeda dari MASTG-TEST-0203 (logging) yang cukup "ada data sensitif → FAIL".

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi | Contoh bukti |
|---|---|---|
| F1 | `java.util.Random` / `Math.random()` dipakai untuk **membuat password** | `password.append(characters[random.nextInt(characters.length)])` di dalam fungsi generator password |
| F2 | Dipakai untuk **token autentikasi / session ID / OTP / token reset** | `String token = Long.toHexString(new Random().nextLong())` |
| F3 | Dipakai untuk **kunci kriptografi** | `byte[] key = new byte[32]; new Random().nextBytes(key); new SecretKeySpec(key, "AES")` |
| F4 | Dipakai untuk **IV atau nonce** | `new Random().nextBytes(iv); new IvParameterSpec(iv)` → **kritis pada GCM**: nonce reuse membocorkan authentication key |
| F5 | Dipakai untuk **salt** pada hashing password / KDF | `new Random().nextBytes(salt)` sebelum PBKDF2 |
| F6 | Dipakai untuk **PIN atau kode verifikasi** | `int pin = 100000 + new Random().nextInt(900000)` |
| F7 | `SecureRandom` dipakai tetapi **di-seed dengan nilai hardcoded/deterministik** | `SecureRandom r = new SecureRandom(); r.setSeed(12345);` atau `new SecureRandom("mykey".getBytes())` → CWE-337. **Tidak tertangkap rule MASTG** |
| F8 | `kotlin.random.Random` / `ThreadLocalRandom` dipakai dalam konteks security-relevant | `Random.nextInt(999999)` untuk OTP → **tidak tertangkap rule MASTG** |
| F9 | `RandomStringUtils.random(...)` (Apache Commons, varian non-secure) dipakai untuk token | Sangat umum dan sangat berbahaya karena tampak seperti utilitas yang aman |
| F10 | Implementasi **PRNG kustom** dipakai untuk keamanan | Fungsi buatan sendiri dengan XOR/shift, tanpa jaminan kriptografis |
| F11 | Temuan berada di **fungsi helper** dan pelacakan pemanggil membuktikan pemakaian security-relevant | `get_random()` dipanggil oleh `createSessionId()` |
| F12 | `minSdkVersion` ≤ 18 **dan** tidak ada mitigasi untuk bug PRNG Android 4.1–4.3 | Aplikasi rentan meski memakai `SecureRandom` — lihat §1.3 |
| F13 | PRNG lemah dari **kode native** dipakai untuk keamanan | `strings lib.so` → `rand`, `srand` + review menunjukkan pemakaian untuk key/nonce |

**Contoh output yang menandakan FAIL — MASTG-DEMO-0007:**

Kode sampel (`MastgTest.kt`) — perhatikan anotasi FAIL/PASS yang disediakan MASTG:

```kotlin
fun mastgTest(): String {

    // FAIL: [android-insecure-random-use] The app insecurely uses random numbers
    //       for generating authentication tokens.
    val random1 = Random().nextDouble()

    // FAIL: [android-insecure-random-use] The title of the function indicates that it
    //       generates a random number, but it is unclear how it is actually used in the
    //       rest of the app. Review any calls to this function to ensure that the random
    //       number is not used in a security-relevant context.
    val random2 = 1 + Math.random()

    val length = 16
    val characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    val random = Random()
    val password = StringBuilder(length)

    for (i in 0 until length) {
        // FAIL: [android-insecure-random-use] The app insecurely uses random numbers for
        //       generating passwords, which is a security-relevant context.
        password.append(characters[random.nextInt(characters.length)])
    }

    val random3 = password.toString()

    // PASS: [android-insecure-random-use] The app uses a secure random number generator.
    val random4 = SecureRandom().nextInt(21)

    return "Generated random numbers:\n$random1 \n$random2 \n$random3 \n$random4"
}
```

Kode hasil dekompilasi yang dipindai semgrep (`MastgTest_reversed.java`):

```java
public final String mastgTest() {
    double random1 = new Random().nextDouble();                                   // <-- baris 22
    double random2 = 1 + Math.random();                                          // <-- baris 23
    Random random = new Random();
    StringBuilder password = new StringBuilder(16);
    for (int i = 0; i < 16; i++) {
        password.append("ABCDEFGHIJ...0123456789".charAt(
            random.nextInt("ABCDEFGHIJ...0123456789".length())));                // <-- baris 27
    }
    String random3 = password.toString();
    int random4 = new SecureRandom().nextInt(21);                                 // <-- PASS
    return "...";
}
```

Output semgrep (`output.txt`):

```
┌─────────────────┐
│ 3 Code Findings │
└─────────────────┘

    MastgTest_reversed.java
    ❯❱ rules.mastg-android-random-apis-insufficient-entropy
          [MASVS-CRYPTO-1] The application makes use of random number generators with insufficient entropy.

           22┆ double random1 = new Random().nextDouble();
            ⋮┆----------------------------------------
           23┆ double random2 = 1 + Math.random();
            ⋮┆----------------------------------------
           27┆ password.append("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".charAt(ran
               dom.nextInt("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".length())));
```

Evaluasi MASTG (mengacu ke nomor baris pada berkas **Kotlin**):

> - *"Line 12 seems to be used to generate random numbers for security purposes, in this case for generating **authentication tokens**."*
> - *"Line 17 is part of the function `get_random`. **Review any calls to this function** to ensure that the random number is not used in a security-relevant context."*
> - *"Line 27 is part of the **password generation** function which is a security-critical operation."*
> - *"Note that **line 37 did not trigger the rule** because the random number is generated using `SecureRandom` which is a secure random number generator."*

**Empat pelajaran penting dari demo ini:**

1. **Satu temuan bisa berarti banyak nilai lemah.** Baris 27 dilaporkan **satu kali**, padahal berada di dalam loop 16 iterasi — menghasilkan 16 karakter password yang semuanya dapat diprediksi. Jangan menilai keparahan dari jumlah temuan.
2. **Pola "temuan butuh pelacakan lanjutan" diakui eksplisit oleh MASTG.** Kasus baris 17 (`Math.random()` di dalam fungsi helper) tidak dapat dinilai tanpa memeriksa siapa pemanggilnya. Ini contoh langsung mengapa langkah MASTG-TECH-0023 wajib.
3. **`SecureRandom` tidak terpicu rule** — membuktikan rule membedakan PRNG aman dan tidak aman dengan benar.
4. **Ada dua ketidaksesuaian di artefak demo ini** yang perlu kamu sadari saat mereplikasi:
   - Bagian Observation menyebut *"identified **five** instances"*, sedangkan `output.txt` hanya menampilkan **3 Code Findings**. Angka "five" tampaknya sisa dari versi rule/sampel yang lebih lama.
   - Nomor baris di Evaluation (12, 17, 27, 37) mengacu ke **`MastgTest.kt`**, sementara semgrep dijalankan pada **`MastgTest_reversed.java`** dan melaporkan baris 22, 23, 27. Teks evaluasi juga menyebut nama fungsi `get_random` yang tidak ada di sampel Kotlin yang dipublikasikan.
   
   Tidak mengubah substansi pelajarannya, tapi jangan bingung saat mencocokkan angka.

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi | Contoh bukti |
|---|---|---|
| P1 | **Semgrep tidak menemukan temuan** dan grep pelengkap juga bersih | `0 Code Findings`; tidak ada `kotlin.random.Random` / `ThreadLocalRandom` / `RandomStringUtils` |
| P2 | Semua kebutuhan acak security-relevant memakai **`SecureRandom` dengan konstruktor default** | `new SecureRandom().nextBytes(iv)`; tidak ada `setSeed()` maupun seed pada konstruktor |
| P3 | Memakai `SecureRandom.getInstanceStrong()` | Sesuai rekomendasi dokumentasi Android untuk Android modern |
| P4 | Ada temuan `java.util.Random`/`Math.random()`, tetapi review membuktikan penggunaannya **bukan** security-relevant | `Math.random()` untuk jitter animasi; `Random().nextInt()` untuk memilih warna placeholder |
| P5 | Kunci/IV/nonce dihasilkan oleh **platform**, bukan oleh kode aplikasi | `KeyGenerator.getInstance("AES").generateKey()`; `KeyGenParameterSpec` + Android KeyStore; `Cipher` meng-generate IV sendiri lalu diambil via `cipher.getIV()` |
| P6 | Nilai acak berasal dari **server** melalui kanal TLS (mis. session token dibuat backend) | Tidak ada pembuatan token di sisi klien |
| P7 | `UUID.randomUUID()` dipakai — ini berbasis `SecureRandom` | Aman untuk identifier, **meski bukan pengganti untuk kunci kriptografi** |
| P8 | `minSdkVersion` ≥ 19, sehingga bug PRNG Android 4.1–4.3 tidak relevan | `aapt2 d badging` → `sdkVersion:'21'` |

**Contoh output yang menandakan PASS:**

```bash
$ NO_COLOR=true semgrep -c mastg-android-random-apis-insufficient-entropy.yml ./decompiled/sources/
┌──────────────────┐
│ 0 Code Findings  │
└──────────────────┘

# Grep pelengkap untuk celah rule
$ grep -rnE "kotlin\.random\.Random|ThreadLocalRandom|RandomStringUtils|RandomUtils" ./decompiled/sources/
# (tidak ada hasil)

$ grep -rnE "setSeed|new SecureRandom\([^)]" ./decompiled/sources/
# (tidak ada hasil — SecureRandom hanya dipakai dengan konstruktor default)
```

Kode yang benar:

```kotlin
// ✅ CSPRNG dengan konstruktor default — self-seeding dari entropi sistem
val secureRandom = SecureRandom()
val iv = ByteArray(12)
secureRandom.nextBytes(iv)

// ✅ Atau, sesuai rekomendasi dokumentasi Android untuk Android modern
val rand = SecureRandom.getInstanceStrong()
val randInt = rand.nextInt(1000)

// ✅ PALING BAIK untuk kunci — biarkan platform yang meng-generate
val keyGen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
keyGen.init(
    KeyGenParameterSpec.Builder("myKey", KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
        .build()
)
keyGen.generateKey()

// ✅ PALING BAIK untuk IV — biarkan Cipher yang meng-generate, lalu ambil hasilnya
val cipher = Cipher.getInstance("AES/GCM/NoPadding")
cipher.init(Cipher.ENCRYPT_MODE, key)
val iv = cipher.iv          // IV dihasilkan aman oleh provider
```

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Temuan tanpa konteks bukan kerentanan.** Klausa *"used in security-relevant contexts"* adalah syarat mutlak dalam kriteria evaluasi. Melaporkan semua hit `java.util.Random` sebagai kerentanan adalah praktik yang salah dan akan membanjiri laporan dengan false positive — aplikasi normal punya banyak pemakaian `Random` yang sah (animasi, jitter, shuffle).

2. **Penuhi prerequisites lebih dulu.** Test ini secara formal mensyaratkan `identify-sensitive-data` dan `identify-security-relevant-contexts`. Tanpa memahami aset dan alur keamanan aplikasi, kamu tidak punya dasar untuk menilai temuan. Ini prerequisite yang nyata, bukan formalitas.

3. **Lacak fungsi helper sampai pemanggilnya.** Pola paling sering terlewat: `Random` dipakai di dalam utilitas generik (`RandomUtil.nextString()`), lalu utilitas itu dipanggil dari berbagai tempat — sebagian aman, sebagian tidak. MASTG mengangkat kasus ini eksplisit di demo. Gunakan "Find Usage" di jadx-gui atau, lebih baik, **CodeQL untuk taint analysis**.

4. **Rule MASTG punya celah yang signifikan.** Perlu diketahui agar kamu tidak salah menyimpulkan PASS:

   | Celah | Dampak |
   |---|---|
   | `pattern-inside: $M(...){ ... }` mensyaratkan berada **di dalam body metode** | **Field initializer tingkat kelas tidak terdeteksi**, mis. `private static final Random RNG = new Random();` |
   | `languages: java` saja | **Sumber Kotlin tidak dipindai.** Hanya bekerja pada kode hasil dekompilasi |
   | Tidak mencakup `kotlin.random.Random` | Celah besar untuk aplikasi Kotlin modern |
   | Tidak mencakup `ThreadLocalRandom` | PRNG lemah lain yang lolos |
   | Tidak mencakup `RandomStringUtils` / `RandomUtils` (Apache Commons) | Justru sering dipakai untuk token |
   | Tidak mencakup `SecureRandom` dengan seed hardcoded / `setSeed()` | CWE-337 lolos total |
   | Tidak mencakup PRNG kustom maupun PRNG native | Lolos |
   
   **Mitigasi:** jalankan grep pelengkap (§3.4) dan pertimbangkan CodeQL.

5. **Output kosong ≠ otomatis PASS.** Selain celah rule di atas: obfuscation/packing, refleksi, kode yang dimuat runtime, dan split APK yang tidak dianalisis semuanya bisa menyembunyikan temuan. Jalankan APKiD dan analisis semua modul.

6. **Jangan tertipu nama yang terdengar aman.** `SecureRandom` yang di-`setSeed()` dengan konstanta lebih berbahaya daripada `java.util.Random` biasa, karena memberi rasa aman yang salah. Demikian pula `RandomStringUtils` yang tampak seperti utilitas siap pakai.

7. **Kasus GCM nonce perlu perhatian khusus.** Pada AES-GCM, **nonce reuse dengan kunci yang sama bersifat katastrofik** — bukan hanya membocorkan plaintext, tetapi juga memungkinkan pemulihan *authentication key* sehingga penyerang dapat memalsukan ciphertext. PRNG lemah untuk nonce GCM harus dinilai severity kritis, lebih tinggi daripada IV lemah untuk CBC.

8. **Severity dimodulasi oleh konteks penggunaan:**

   | Konteks | Severity |
   |---|---|
   | Kunci kriptografi, nonce GCM/ECDSA | **Kritis** |
   | Token autentikasi, session ID, token reset password, OTP | **Tinggi** |
   | IV CBC, salt | **Menengah–Tinggi** |
   | PIN, kode verifikasi | **Tinggi** (ruang nilai sudah kecil) |
   | Nama file temporer di shared storage | Menengah |
   | `SecureRandom` dengan seed hardcoded | **Tinggi** — deterministik penuh, mudah dieksploitasi setelah dekompilasi |
   | `minSdkVersion` ≤ 18 tanpa mitigasi bug PRNG | Naik |
   | Penggunaan non-security (animasi, jitter, shuffle non-kompetitif) | **Bukan temuan** |

9. **Buktikan eksploitabilitas bila memungkinkan.** Karena `java.util.Random` dapat dipecahkan dengan dua observasi output, kamu bisa membuat PoC yang sangat meyakinkan: kumpulkan dua token dari aplikasi, pulihkan seed, lalu prediksi token berikutnya. Alat publik untuk ini sudah tersedia. PoC semacam ini mengubah temuan dari "praktik buruk" menjadi "kerentanan terbukti".

10. **Dokumentasikan bukti lengkap per temuan:** rule ID, path file + nomor baris, potongan kode hasil dekompilasi, **hasil pelacakan penggunaan** (dari PRNG sampai titik konsumsi akhir), klasifikasi konteks (security-relevant atau tidak) beserta alasannya, `minSdkVersion`, dan PoC prediksi bila dibuat. Cantumkan juga batasan analisis (obfuscation, kode native, celah rule yang belum ditutup).

### 3.4 Pemeriksaan Pelengkap (Menutup Celah Rule)

Ini bagian yang tidak boleh dilewatkan.

```bash
D=./decompiled/sources

# 1. PRNG lemah yang TIDAK tercakup rule MASTG
grep -rnE "kotlin\.random\.Random|Random\.Default|Random\.nextInt|Random\.nextBytes" $D
grep -rnE "java\.util\.concurrent\.ThreadLocalRandom|ThreadLocalRandom\.current" $D
grep -rnE "RandomStringUtils|org\.apache\.commons\.lang3?\.RandomUtils" $D
grep -rnE "SplittableRandom|XorShift|MersenneTwister" $D

# 2. Field initializer tingkat kelas (celah pattern-inside)
grep -rnE "(static )?(final )?Random [A-Za-z_]+ *= *new Random" $D

# 3. SecureRandom yang dipakai SALAH (CWE-337/335) — tidak tercakup rule
grep -rnE "setSeed\(" $D
grep -rnE "new SecureRandom\([^)]+\)" $D              # konstruktor dengan argumen seed
grep -rnE "SecureRandom\.getInstance\(" $D            # periksa algoritma & provider-nya

# 4. Titik konsumsi security-relevant — untuk korelasi
grep -rnE "SecretKeySpec|IvParameterSpec|GCMParameterSpec|KeyGenerator|PBEKeySpec" $D
grep -rnE "generateToken|sessionId|session_id|nonce|otp|resetToken|csrf|salt" $D
grep -rniE "password|passcode|\bpin\b" $D | grep -iE "random|generate"

# 5. PRNG dari kode native (titik buta total rule Java)
for so in $(find ./extracted -name "*.so"); do
  echo "--- $so"; strings "$so" | grep -xE "rand|srand|random|srandom|rand_r|drand48|lrand48"
done

# 6. minSdkVersion — untuk menilai relevansi bug PRNG Android 4.1-4.3
aapt2 d badging ./target-app.apk | grep -E "sdkVersion|targetSdkVersion"

# 7. Deteksi proteksi yang bisa membatasi keandalan analisis
apkid ./target-app.apk
```

**Rule semgrep tambahan** untuk menutup celah utama:

```yaml
rules:
  - id: custom-insecure-random-extended
    severity: WARNING
    languages: [java, kotlin]
    message: "[MASVS-CRYPTO-1] Weak PRNG atau SecureRandom yang di-seed secara deterministik"
    pattern-either:
      # PRNG lemah lain
      - pattern: new java.util.concurrent.ThreadLocalRandom(...)
      - pattern: java.util.concurrent.ThreadLocalRandom.current(...)
      - pattern: kotlin.random.Random.$M(...)
      - pattern: org.apache.commons.lang3.RandomStringUtils.random(...)
      - pattern: org.apache.commons.lang3.RandomUtils.$M(...)
      # Field initializer (tanpa pattern-inside, sehingga tingkat kelas ikut tertangkap)
      - pattern: new java.util.Random(...)
      # SecureRandom yang dipakai salah -> CWE-337 / CWE-335
      - pattern: (java.security.SecureRandom $S).setSeed(...)
      - pattern: new java.security.SecureRandom($SEED)
```

### 3.5 Konfirmasi Dinamis Opsional

MASTG tidak menyediakan test dinamis untuk ini, tetapi hooking berguna untuk **membuktikan** bahwa nilai dari PRNG lemah benar-benar sampai ke konteks sensitif — sekaligus mengumpulkan sampel untuk PoC prediksi.

```javascript
// Hook java.util.Random + SecureRandom.setSeed, cetak backtrace
Java.perform(() => {
    function bt(max = 10) {
        const E = Java.use("java.lang.Exception");
        const st = E.$new().getStackTrace();
        let out = [];
        for (let i = 0; i < Math.min(max, st.length); i++) out.push("    " + st[i]);
        return out.join("\n");
    }

    const R = Java.use("java.util.Random");
    ['nextInt', 'nextLong', 'nextDouble', 'nextBytes', 'nextFloat'].forEach(m => {
        R[m].overloads.forEach(ov => {
            ov.implementation = function (...a) {
                const r = ov.apply(this, a);
                console.log(`\n[!] java.util.Random.${m}() -> ${r}`);
                console.log(bt());
                return r;
            };
        });
    });

    // Deteksi SecureRandom yang di-seed secara manual (CWE-337)
    const SR = Java.use("java.security.SecureRandom");
    SR.setSeed.overloads.forEach(ov => {
        ov.implementation = function (s) {
            console.log(`\n[!!] SecureRandom.setSeed(${s}) — SEED MANUAL, cek apakah deterministik`);
            console.log(bt());
            return ov.apply(this, [s]);
        };
    });
});
```

Backtrace-nya akan langsung memperlihatkan apakah pemanggilnya adalah `TokenGenerator.create()` atau hanya `AnimationHelper.jitter()` — menjawab pertanyaan konteks dengan bukti runtime.

---

### 3.6 Metode Pengujian Alternatif (Multi-Tool)

Rule semgrep MASTG hanya mencakup tiga pola dan meninggalkan banyak celah (§3.3 catatan 4). Berikut jalur alternatif, masing-masing dengan kekuatan berbeda.

#### Metode B — ripgrep/grep terstruktur *(menangkap seluruh keluarga PRNG lemah)*

Ini penutup celah paling langsung: rule MASTG tidak mencakup `kotlin.random.Random`, `ThreadLocalRandom`, `RandomStringUtils`, maupun field initializer tingkat kelas.

```bash
jadx -d ./decompiled ./target-app.apk
D=./decompiled/sources

# --- 1. PRNG lemah yang TIDAK tercakup rule MASTG ---
rg -n --no-heading "kotlin\.random\.Random|Random\.Default|RandomKt" $D
rg -n --no-heading "java\.util\.concurrent\.ThreadLocalRandom|ThreadLocalRandom\.current" $D
rg -n --no-heading "RandomStringUtils|org\.apache\.commons\.lang3?\.RandomUtils" $D
rg -n --no-heading "SplittableRandom|MersenneTwister|XorShift" $D

# --- 2. Field initializer tingkat kelas (celah pattern-inside) ---
rg -n --no-heading "(static )?(final )?Random [A-Za-z_]+ *= *new Random" $D

# --- 3. SecureRandom yang dipakai SALAH (CWE-337) — lolos total dari rule MASTG ---
rg -n --no-heading "setSeed\(" $D
rg -n --no-heading "new SecureRandom\([^)]" $D

# --- 4. Titik konsumsi security-relevant (untuk korelasi konteks) ---
rg -n --no-heading "SecretKeySpec|IvParameterSpec|GCMParameterSpec|KeyGenerator|PBEKeySpec" $D
rg -ni --no-heading "generateToken|sessionId|nonce|\botp\b|resetToken|csrf|\bsalt\b" $D

# --- 5. Analisis ARAH BALIK: mulai dari konsumsi, telusuri ke sumber ---
#     Lebih efisien karena titik konsumsi jauh lebih sedikit daripada pemanggilan Random
rg -n --no-heading -B5 "new SecretKeySpec|new IvParameterSpec" $D | rg -i "random|nextInt|nextBytes"
```

#### Metode C — MobSF *(laporan siap kutip)*

```bash
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest
```

Cari di bagian **Code Analysis**: temuan bertajuk *"The App uses an insecure Random Number Generator"* dengan mapping CWE-330 dan referensi MASVS. Keunggulannya: MobSF sudah mendeteksi `java.util.Random` **dan** `Math.random()` sekaligus, lengkap dengan severity yang bisa langsung dikutip.

#### Metode D — mobsfscan *(CLI untuk CI/CD)*

```bash
pip install mobsfscan
mobsfscan --json -o out.json ./decompiled/sources/
jq '.results | to_entries[] | select(.key | test("random|prng"))' out.json

# Gate CI
mobsfscan --exit-warning ./decompiled/sources/
```

#### Metode E — CodeQL *(taint analysis — menjawab pertanyaan konteks secara otomatis)*

**Ini metode paling tepat untuk test ini.** Kriteria evaluasi MASTG mensyaratkan nilai acak *"used in security-relevant contexts"* — pertanyaan aliran data yang tidak bisa dijawab semgrep, tetapi bisa dijawab CodeQL secara otomatis.

```bash
codeql database create ./cqldb --language=java --command="./gradlew assembleDebug"

# Query bawaan yang relevan
codeql database analyze ./cqldb \
  codeql/java-queries:Security/CWE/CWE-330/InsecureRandomness.ql \
  codeql/java-queries:Security/CWE/CWE-335/PredictableSeed.ql \
  --format=sarif-latest --output=random.sarif

jq '.runs[].results[] | {rule: .ruleId, msg: .message.text}' random.sarif
```

Query kustom yang persis menjawab kriteria MASTG:

```ql
/**
 * @name Weak PRNG output flows into a cryptographic sink
 * @kind path-problem
 */
import java
import semmle.code.java.dataflow.TaintTracking

class WeakRandomSource extends DataFlow::Node {
  WeakRandomSource() {
    exists(MethodAccess ma |
      ma.getMethod().getDeclaringType().hasQualifiedName("java.util", "Random") or
      ma.getMethod().hasQualifiedName("java.lang", "Math", "random") |
      this.asExpr() = ma
    )
  }
}

class CryptoSink extends DataFlow::Node {
  CryptoSink() {
    exists(ClassInstanceExpr cie |
      cie.getConstructedType().hasQualifiedName("javax.crypto.spec",
        ["SecretKeySpec", "IvParameterSpec", "GCMParameterSpec", "PBEKeySpec"]) |
      this.asExpr() = cie.getAnArgument()
    )
  }
}
```

#### Metode F — SonarQube / SonarLint *(integrasi IDE & quality gate)*

```bash
sonar-scanner \
  -Dsonar.projectKey=android-app \
  -Dsonar.sources=./app/src \
  -Dsonar.java.binaries=./app/build
```

Rule yang relevan: **`java:S2245`** — *Using pseudorandom number generators (PRNGs) is security-sensitive*, dan **`java:S4347`** — *Secure random number generators should not output predictable values* (mendeteksi `setSeed` deterministik). Keunggulan: muncul langsung di IDE developer via SonarLint, sehingga mencegah masalah sebelum commit.

#### Metode G — semgrep registry & rule pihak ketiga *(cakupan rule lebih luas)*

```bash
# Registry Semgrep
semgrep --config "p/java" --config "p/mobsfscan" ./decompiled/sources/
semgrep --config "r/java.lang.security.audit.crypto.weak-random.weak-random" ./decompiled/sources/

# Rule Android khusus (sumber asli rule MASTG ini)
git clone https://github.com/mindedsecurity/semgrep-rules-android-security
semgrep -c ./semgrep-rules-android-security/rules/crypto/ ./decompiled/sources/
```

#### Metode H — APKHunt *(scanner MASVS otomatis)*

```bash
go install github.com/Cyber-Buddy/APKHunt@latest
APKHunt -p ./target-app.apk -l
grep -iA3 "random" APKHunt_Report.txt
```

#### Metode I — Analisis kode native *(titik buta rule Java)*

```bash
unzip -o ./target-app.apk -d ./apk_x >/dev/null
for so in $(find ./apk_x -name "*.so"); do
  echo "--- $so"
  strings "$so" | grep -xE "rand|srand|random|srandom|rand_r|drand48|lrand48|arc4random"
done
```

> `arc4random` dan `getrandom`/`/dev/urandom` adalah tanda **baik** (CSPRNG). `rand`/`srand`/`drand48` adalah tanda **buruk**.

#### Metode J — Pembuktian eksploitabilitas *(PoC prediksi seed)*

Ini yang mengubah temuan dari "praktik buruk" menjadi "kerentanan terbukti" — dan hanya mungkin karena `java.util.Random` dapat dipecahkan dari dua observasi.

```bash
# 1. Kumpulkan ≥2 output berurutan dari aplikasi (token, OTP, ID)
#    via UI, API response, atau hook Frida (§3.5)

# 2. Pulihkan seed dan prediksi nilai berikutnya
git clone https://github.com/giuliocandre/java-prng-predict
cd java-prng-predict && python3 predict.py <output1> <output2>

# 3. Verifikasi prediksi dengan meminta nilai berikutnya dari aplikasi
```

Alternatif dengan lattice reduction (untuk `nextInt(bound)` bernilai kecil): skrip LLL dari Jorian Woltjer (lihat §5.4).

---

### 3.7 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Butuh device? | Butuh source code? | Menangkap PRNG non-JCA? | Menjawab konteks? | Kapan dipakai |
|---|---|---|---|---|---|---|
| **A** | semgrep (MASTG) | Tidak | Tidak | ❌ | ❌ | Baseline resmi & gate CI |
| **B** | ripgrep terstruktur | Tidak | Tidak | ✅ | Manual | **Verifikasi silang wajib** — menutup celah terbesar |
| **C** | MobSF | Tidak | Tidak | Sebagian | ❌ | Laporan siap kutip |
| **D** | mobsfscan | Tidak | Tidak | Sebagian | ❌ | Gate CI/CD ringan |
| **E** | CodeQL | Tidak | **Ya** (ideal) | ✅ | ✅ **otomatis** | **Terbaik** bila source tersedia — menjawab kriteria "security-relevant context" |
| **F** | SonarQube/SonarLint | Tidak | Ya | Sebagian | ❌ | Pencegahan di sisi developer (shift-left) |
| **G** | semgrep registry / rule pihak ketiga | Tidak | Tidak | ✅ | ❌ | Cakupan rule lebih luas tanpa menulis sendiri |
| **H** | APKHunt | Tidak | Tidak | Sebagian | ❌ | Pass otomatis tambahan |
| **I** | `strings` / Ghidra | Tidak | Tidak | ✅ (native) | Manual | APK dengan `.so` |
| **K** | Frida (§3.5) | **Ya** | Tidak | ✅ | ✅ (backtrace) | Ukuran/sumber dari variabel, kode ter-obfuscate |
| **J** | java-prng-predict / LLL | Sebagian | Tidak | — | — | **Membuktikan eksploitabilitas** untuk laporan |

**Kombinasi minimum yang aku rekomendasikan:** **B (ripgrep) → A (semgrep) → K (Frida)**.
B menutup celah keluarga PRNG, A memberi baseline selaras MASTG, K membuktikan konteks lewat backtrace runtime. Bila source code tersedia, **E (CodeQL) menggantikan sebagian besar pekerjaan manual** karena ia menjawab pertanyaan konteks secara otomatis. Tambahkan **J** bila temuannya perlu bobot ekstra di laporan.

---

## 4. Rekomendasi Perbaikan

### 4.1 Prinsip Utama (MASTG-BEST-0001)

MASTG-BEST-0001 menyatakan: *"Use a cryptographically secure pseudorandom number generator as provided by the platform or programming language you are using."*

**Prioritas 1 — Gunakan `java.security.SecureRandom` dengan konstruktor default.**

MASTG-BEST-0001 menjelaskan alasannya: `SecureRandom` memenuhi uji statistik generator bilangan acak yang ditetapkan **FIPS 140-2 bagian 4.9.1** dan memenuhi persyaratan kekuatan kriptografis dalam **RFC 4086** (*Randomness Requirements for Security*). Ia menghasilkan output non-deterministik dan **melakukan seeding otomatis saat inisialisasi objek menggunakan entropi sistem**, sehingga seeding manual umumnya tidak diperlukan dan **justru dapat melemahkan** keacakan bila dilakukan tidak benar.

```kotlin
// ✅ BENAR — konstruktor default, self-seeding dari entropi sistem (/dev/urandom)
val secureRandom = SecureRandom()
val token = ByteArray(32)
secureRandom.nextBytes(token)

// ✅ Sesuai rekomendasi dokumentasi Android untuk Android modern
val rand = SecureRandom.getInstanceStrong()
val randInt = rand.nextInt(1000)
```

```kotlin
// ❌ SALAH — semuanya deterministik atau lemah
val r1 = Random().nextInt(1000)                          // LCG, dapat diprediksi
val r2 = Math.random()                                    // sama, via Random statis
val r3 = SecureRandom().apply { setSeed(12345) }           // CWE-337
val r4 = SecureRandom("hardcoded".toByteArray())           // CWE-337
val r5 = kotlin.random.Random.nextInt(999999)              // delegasi ke java.util.Random
val r6 = ThreadLocalRandom.current().nextInt()             // LCG-based
val r7 = RandomStringUtils.random(16)                      // Apache Commons, non-secure
```

**Peringatan khusus soal seeding** dari MASTG-BEST-0001: meskipun [dokumentasi](https://developer.android.com/reference/java/security/SecureRandom) menyatakan seed yang diberikan biasanya **menambah** (supplement) seed yang sudah ada, **perilaku ini dapat berbeda bila provider keamanan lama digunakan** — artinya seed bisa saja **mengganti** entropi sistem. Untuk menghindari jebakan ini, pastikan aplikasi menargetkan versi Android modern dengan provider yang ter-update, atau konfigurasikan provider yang aman secara eksplisit (**AndroidOpenSSL**, atau **Conscrypt** pada rilis yang lebih baru).

**Prioritas 2 — Lebih baik lagi: jangan generate sendiri, biarkan platform yang melakukannya.**

Ini rekomendasi yang lebih kuat daripada sekadar mengganti `Random` → `SecureRandom`, karena menghilangkan seluruh kelas kesalahan.

```kotlin
// ✅ Kunci: generate di Android KeyStore — key material tidak pernah keluar dari secure hardware
val keyGen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
keyGen.init(
    KeyGenParameterSpec.Builder(
        "myKeyAlias",
        KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
    )
        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
        .setRandomizedEncryptionRequired(true)   // memaksa IV acak yang dihasilkan sistem
        .build()
)
keyGen.generateKey()

// ✅ IV/nonce: biarkan Cipher yang menghasilkannya, lalu ambil
val cipher = Cipher.getInstance("AES/GCM/NoPadding")
cipher.init(Cipher.ENCRYPT_MODE, key)
val iv = cipher.iv                    // dijamin acak oleh provider
// Simpan iv bersama ciphertext (IV tidak rahasia, tetapi harus unik)

// ✅ Enkripsi file/preferences: pakai abstraksi tingkat tinggi
//    (EncryptedFile / Google Tink) yang menangani key & nonce dengan benar
```

**Prioritas 3 — Ganti pola yang umum salah.**

| Kebutuhan | ❌ Jangan | ✅ Lakukan |
|---|---|---|
| Token autentikasi / session ID | `Random().nextLong()` | `SecureRandom().nextBytes(ByteArray(32))` lalu Base64-URL encode — **atau lebih baik, dibuat oleh server** |
| Identifier unik non-rahasia | `Random().nextInt()` | `UUID.randomUUID()` (berbasis `SecureRandom`) |
| Kunci simetris | `Random().nextBytes(key)` | `KeyGenerator` + Android KeyStore |
| IV / nonce | `Random().nextBytes(iv)` | `cipher.iv` atau `SecureRandom().nextBytes(iv)` |
| Salt untuk KDF | `Random().nextBytes(salt)` | `SecureRandom().nextBytes(salt)` (≥ 16 byte) |
| Password / passphrase | `Random().nextInt(chars.length)` | `SecureRandom().nextInt(chars.length)`, hindari modulo bias |
| OTP / PIN | `Random().nextInt(900000)` | `SecureRandom().nextInt(900000)` + rate limiting + masa berlaku pendek |
| Output pseudorandom yang **perlu reproducible** | `SecureRandom` dengan seed tetap | **HMAC, HKDF, atau SHAKE** — sesuai rekomendasi dokumentasi Android |

> Poin terakhir penting dan sering jadi alasan developer memakai `setSeed()`: bila kamu butuh output acak yang **dapat direproduksi** (mis. deterministic key derivation), **jangan** pakai `SecureRandom` dengan seed tetap. Gunakan fungsi derivasi yang memang dirancang untuk itu: HMAC, HKDF, atau SHAKE.

**Prioritas 4 — Tangani dukungan Android lama.** Bila aplikasi masih mendukung di bawah Android 4.4 (API 19), terapkan mitigasi untuk bug inisialisasi PRNG di API 16–18 (lihat patch dari artikel *"Some SecureRandom Thoughts"*). Solusi paling bersih: **naikkan `minSdkVersion` ke 19 atau lebih tinggi** — API 16–18 sudah jauh di luar dukungan keamanan.

**Prioritas 5 — Perhatikan bahasa/framework lain.** MASTG-BEST-0001 memberi peringatan yang relevan untuk aplikasi cross-platform: konsultasikan dokumentasi standard library untuk menemukan API yang mengekspos CSPRNG sistem operasi — ini biasanya pendekatan teraman, **asalkan tidak ada kerentanan yang diketahui pada implementasi random library tersebut**. MASTG mencontohkan **isu CSPRNG pada Flutter/Dart** sebagai pengingat bahwa beberapa framework punya kelemahan PRNG yang sudah diketahui. Jadi untuk aplikasi React Native, Flutter, atau Unity, jangan berasumsi API "random" bawaannya aman.

**Prioritas 6 — Hindari modulo bias.** Ini kesalahan yang lolos dari semua rule statis dan tetap melemahkan keacakan meski CSPRNG sudah dipakai:

```kotlin
// ❌ Bias: distribusi tidak seragam bila 256 tidak habis dibagi range
val idx = secureRandom.nextInt() % chars.length

// ✅ nextInt(bound) sudah menangani rejection sampling secara internal
val idx = secureRandom.nextInt(chars.length)
```

**Prioritas 7 — Tegakkan secara struktural.**
- Tambahkan **rule SAST di CI/CD** (semgrep MASTG + rule perluasan di §3.4) dan gagalkan build bila muncul temuan baru.
- Buat **satu utilitas terpusat** untuk semua kebutuhan acak security-relevant (mis. `CryptoRandom.bytes(n)`, `CryptoRandom.token()`), lalu larang pemakaian `Random` langsung lewat lint rule kustom.
- **Aktifkan SonarQube rule `java:S2245`** atau Android Lint yang setara.
- Audit library pihak ketiga — jalankan pemindaian juga pada kode library hasil dekompilasi.

### 4.2 Checklist Remediasi

- [ ] Setiap temuan dari semgrep sudah ditinjau dengan MASTG-TECH-0023 dan diklasifikasikan (security-relevant / tidak)
- [ ] Untuk setiap temuan di fungsi helper, **semua pemanggilnya** sudah dilacak
- [ ] Tidak ada `java.util.Random` / `Math.random()` di konteks security-relevant
- [ ] Tidak ada `kotlin.random.Random`, `ThreadLocalRandom`, `RandomStringUtils`, atau `RandomUtils` di konteks security-relevant
- [ ] Tidak ada implementasi PRNG kustom untuk keperluan keamanan
- [ ] Tidak ada `SecureRandom` yang di-seed manual (`setSeed()` atau seed pada konstruktor)
- [ ] Semua kebutuhan acak security-relevant memakai `SecureRandom()` default atau `SecureRandom.getInstanceStrong()`
- [ ] Kunci kriptografi dihasilkan oleh `KeyGenerator`/`KeyPairGenerator` + Android KeyStore, bukan oleh PRNG aplikasi
- [ ] IV/nonce dihasilkan `Cipher` atau `SecureRandom`; **nonce GCM dijamin tidak pernah berulang** untuk kunci yang sama
- [ ] Salt KDF ≥ 16 byte dari `SecureRandom`
- [ ] Tidak ada modulo bias (`nextInt() % n`); gunakan `nextInt(n)`
- [ ] Output pseudorandom yang perlu reproducible memakai HMAC/HKDF/SHAKE, bukan `SecureRandom` berseed tetap
- [ ] Provider aman dikonfigurasi (AndroidOpenSSL/Conscrypt), atau `targetSdkVersion` modern
- [ ] `minSdkVersion` ≥ 19, atau ada mitigasi eksplisit untuk bug PRNG Android 4.1–4.3
- [ ] PRNG dari kode native (`rand`/`srand`) tidak dipakai untuk keamanan
- [ ] Framework cross-platform (Flutter/RN/Unity) diperiksa — API random-nya benar-benar CSPRNG
- [ ] Utilitas acak terpusat dibuat, dan pemakaian `Random` langsung dilarang lewat lint
- [ ] Library pihak ketiga diaudit (semgrep dijalankan juga pada kode library)
- [ ] Semua split APK / dynamic feature module ikut dianalisis
- [ ] Scan SAST terintegrasi di CI/CD sebagai gate
- [ ] **Verifikasi ulang:** jalankan kembali MASTG-TEST-0204 + grep pelengkap → tidak ada temuan di konteks security-relevant
- [ ] **Verifikasi silang:** jalankan MASTG-TEST-0205 (sumber non-acak seperti timestamp)

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0204: Insecure Random API Usage](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0204/)
- [MASTG-TEST-0205: Non-random Sources Usage](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0205/)
- [MASWE-0012: Insecure Random Number Generation](https://mas.owasp.org/MASWE/MASVS-CRYPTO/MASWE-0012/)
- [MASTG-DEMO-0007: Common Uses of Insecure Random APIs](https://mas.owasp.org/MASTG/demos/android/MASVS-CRYPTO/MASTG-DEMO-0007/MASTG-DEMO-0007/)
- [MASTG-DEMO-0008: Uses of Non-random Sources](https://mas.owasp.org/MASTG/demos/android/MASVS-CRYPTO/MASTG-DEMO-0008/MASTG-DEMO-0008/)
- [MASTG-KNOW-0013: Random Number Generation](https://mas.owasp.org/MASTG/knowledge/android/MASVS-CRYPTO/MASTG-KNOW-0013/)
- [MASTG-BEST-0001: Use Secure Random Number Generator APIs](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0001/)
- [MASTG-TECH-0013: Reverse Engineering Android Apps](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/)
- [MASTG-TECH-0014: Static Analysis on Android](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/)
- [MASTG-TECH-0023: Reviewing Decompiled Java Code](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0023/)
- [MASTG-TOOL-0110: semgrep](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0110/)
- [MASTG-TOOL-0018: jadx](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0018/)
- [MASTG Rules — `mastg-android-random-apis-insufficient-entropy.yml`](https://github.com/OWASP/mastg/blob/master/rules/mastg-android-random-apis-insufficient-entropy.yml)
- [MASVS-CRYPTO: Cryptography](https://mas.owasp.org/MASVS/06-MASVS-CRYPTO/)
- [OWASP MASTG — Testing Cryptography (Random Number Generation)](https://mas.owasp.org/MASTG/0x05e-Testing-Cryptography/)
- [OWASP Cryptographic Storage Cheat Sheet — Secure Random Number Generation](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html#secure-random-number-generation)
- [OWASP Mobile Top 10 2024 — M10: Insufficient Cryptography](https://owasp.org/www-project-mobile-top-10/2023-risks/m10-insufficient-cryptography.html)

### 5.2 Dokumentasi Resmi Android / Google / Java

- [Weak PRNG — Android Security Risks](https://developer.android.com/privacy-and-security/risks/weak-prng)
- [`java.security.SecureRandom` — API reference](https://developer.android.com/reference/java/security/SecureRandom)
- [`SecureRandom.setSeed(byte[])` — API reference](https://developer.android.com/reference/java/security/SecureRandom#setSeed(byte[]))
- [`java.util.Random` — API reference](https://developer.android.com/reference/java/util/Random)
- [`Math.random()` — API reference](https://developer.android.com/reference/java/lang/Math#random())
- [`KeyGenerator` — API reference](https://developer.android.com/reference/javax/crypto/KeyGenerator)
- [`KeyGenParameterSpec` — API reference](https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec)
- [Android Keystore system](https://developer.android.com/privacy-and-security/keystore)
- [Cryptography best practices](https://developer.android.com/privacy-and-security/cryptography)
- [Android Developers Blog — *Some SecureRandom Thoughts* (2013)](https://android-developers.googleblog.com/2013/08/some-securerandom-thoughts.html)
- [Android Developers Blog — *Security "Crypto" provider deprecated in Android N*](https://android-developers.googleblog.com/2016/06/security-crypto-provider-deprecated-in.html)
- [Conscrypt — Java Security Provider](https://github.com/google/conscrypt)
- [Google Tink — cryptographic library](https://developers.google.com/tink)

### 5.3 Standar, Taksonomi, dan Guideline Lain

- [CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)](https://cwe.mitre.org/data/definitions/338.html)
- [CWE-330: Use of Insufficiently Random Values](https://cwe.mitre.org/data/definitions/330.html)
- [CWE-337: Predictable Seed in Pseudo-Random Number Generator (PRNG)](https://cwe.mitre.org/data/definitions/337.html)
- [CWE-335: Incorrect Usage of Seeds in Pseudo-Random Number Generator (PRNG)](https://cwe.mitre.org/data/definitions/335.html)
- [CWE-341: Predictable from Observable State](https://cwe.mitre.org/data/definitions/341.html)
- [FIPS 140-2 — Security Requirements for Cryptographic Modules (section 4.9.1)](http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.140-2.pdf)
- [RFC 4086 — Randomness Requirements for Security](https://tools.ietf.org/html/rfc4086)
- [NIST SP 800-90A Rev.1 — Recommendation for Random Number Generation Using Deterministic RBGs](https://csrc.nist.gov/publications/detail/sp/800-90a/rev-1/final)
- [NIST SP 800-90B — Entropy Sources Used for Random Bit Generation](https://csrc.nist.gov/publications/detail/sp/800-90b/final)
- [NIST SP 800-163 Rev.1 — Vetting the Security of Mobile Applications](https://csrc.nist.gov/publications/detail/sp/800-163/rev-1/final)
- [SonarQube Rule java:S2245 — Using pseudorandom number generators (PRNGs) is security-sensitive](https://rules.sonarsource.com/java/RSPEC-2245/)
- [CodeQL — Java query help (predictable seed & insecure randomness)](https://codeql.github.com/codeql-query-help/java/)
- [SEI CERT Oracle Coding Standard for Java — MSC02-J: Generate strong random numbers](https://wiki.sei.cmu.edu/confluence/display/java/MSC02-J.+Generate+strong+random+numbers)
- [NVD — CVE-2013-6386 (weak PRNG, Drupal)](https://nvd.nist.gov/vuln/detail/CVE-2013-6386)
- [NVD — CVE-2008-4102 (predictable seed, Joomla)](https://nvd.nist.gov/vuln/detail/CVE-2008-4102)
- [NVD — CVE-2006-3419 (weak PRNG, Tor)](https://nvd.nist.gov/vuln/detail/CVE-2006-3419)

### 5.4 Riset Keamanan & Artikel Teknis

- [Franklin Ta — *Predicting the next Math.random() in Java*](https://franklinta.com/2014/08/31/predicting-the-next-math-random-in-java/)
- [elttam — *Cracking the Odd Case of Randomness in Java*](https://www.elttam.com/blog/cracking-randomness-in-java)
- [James Roper (all that jazz) — *Cracking Random Number Generators, Part 1*](https://jazzy.id.au/2010/09/20/cracking_random_number_generators_part_1.html)
- [Jorian Woltjer — *Practical `java.util.Random` LCG attack using LLL reduction*](https://gist.github.com/JorianWoltjer/e10cf3235adfc47b1c6f6e90b8411fae)
- [Practical CTF — Pseudo-Random Number Generators (PRNG)](https://book.jorianwoltjer.com/cryptography/pseudo-random-number-generators-prng)
- [giuliocandre/java-prng-predict — Breaking Java LCG `Rand.nextInt()` with range](https://github.com/giuliocandre/java-prng-predict)
- [Ruptura InfoSecurity — *How Can Random Be Real When Random Isn't Real?*](https://ruptura-infosec.com/hack-of-the-month/how-can-random-be-real-when-random-isnt-real/)
- [Bitcoin.org — Android Security Vulnerability (2013 alert)](https://bitcoin.org/en/alert/2013-08-11-android)
- [The Register — *Android bug batters Bitcoin wallets*](https://www.theregister.com/2013/08/12/android_bug_batters_bitcoin_wallets/)
- [SiliconANGLE — *Android Crypto PRNG Flaw Aided Bitcoin Thieves*](https://siliconangle.com/2013/08/16/android-crypto-prng-flaw-aided-bitcoin-thieves-google-releases-patch/)
- [codepope — *Android SecureRandom: It gets worse*](https://codepope.dev/post/2013/08/android-securerandom-it-gets-worse/)
- [lxgr's blog — *Android's SecureRandom — not even nonce*](https://blog.lxgr.net/posts/2013/08/15/android-securerandom-not-even-nonce/)
- [Dr. Awesome Doge — *The 2013 Android Bitcoin Wallet Vulnerability: A Lesson in Randomness*](https://doge.tg/blog/2018/The-2013-Android-Bitcoin-Wallet-Vulnerability-A-Lesson-in-Randomness/)
- [Tangem — *Old Wallets, Weak Keys: How Poor Entropy Still Drains Millions in Crypto*](https://tangem.com/en/blog/post/randomness-importance/)
- [Zellic — *Proton, Dart/Flutter, and the CSPRNG that wasn't*](https://www.zellic.io/blog/proton-dart-flutter-csprng-prng/)
- [Terse Systems — *The Right Way to Use SecureRandom*](https://tersesystems.com/blog/2015/12/17/the-right-way-to-use-securerandom/)
- [Baeldung — *Java SecureRandom*](https://www.baeldung.com/java-secure-random)
- [GeeksforGeeks — *Random vs SecureRandom numbers in Java*](https://www.geeksforgeeks.org/random-vs-secure-random-numbers-java/)

### 5.5 Dokumentasi Tools

- [Semgrep — Documentation](https://semgrep.dev/docs/)
- [Semgrep — Pattern syntax reference](https://semgrep.dev/docs/writing-rules/pattern-syntax/)
- [mindedsecurity/semgrep-rules-android-security — sumber asli rule MASTG ini](https://github.com/mindedsecurity/semgrep-rules-android-security)
- [IMQ Minded Security — Semgrep Rules for Android Application Security](https://blog.mindedsecurity.com/2023/10/semgrep-rules-for-android-application.html)
- [mobsfscan — static analysis untuk Android/iOS](https://github.com/MobSF/mobsfscan)
- [MobSF — Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)
- [CodeQL — Documentation](https://codeql.github.com/docs/)
- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [apktool — Reverse engineering Android APK files](https://apktool.org/)
- [APKiD — Android Application Identifier](https://github.com/rednaga/APKiD)
- [Frida — Documentation Home](https://frida.re/docs/home/)
- [Ghidra — software reverse engineering framework](https://ghidra-sre.org/)

---

*Dokumen ini disusun berdasarkan OWASP MASTG (rilis terkini per September 2026), dokumentasi resmi Android Developers, standar CWE/FIPS/NIST/RFC, serta riset keamanan pihak ketiga.*
