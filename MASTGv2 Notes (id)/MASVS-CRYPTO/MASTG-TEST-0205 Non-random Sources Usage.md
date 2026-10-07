# MASTG-TEST-0205 Non-random Sources Usage

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0205 |
| **Platform** | Android |
| **Kategori MASVS** | **MASVS-CRYPTO** (MASVS-CRYPTO-1: Aplikasi menggunakan kriptografi terkini yang diterapkan dengan benar) |
| **Weakness** | MASWE-0012 — *Insecure Random Number Generation* |
| **Tipe Pengujian** | **Static**, Code, Manual |
| **Profile** | L1, L2 |
| **Knowledge** | MASTG-KNOW-0013 (Random Number Generation) |
| **Best Practice** | MASTG-BEST-0001 (Use Secure Random Number Generator APIs) |
| **Prerequisites** | `identify-sensitive-data`, `identify-security-relevant-contexts` |
| **Teknik terkait** | MASTG-TECH-0013 (Reverse Engineering Android Apps), MASTG-TECH-0014 (Static Analysis on Android), MASTG-TECH-0023 (Reviewing Decompiled Java Code) |
| **Demo terkait** | MASTG-DEMO-0008 (Uses of Non-random Sources) |
| **Test bersaudara** | MASTG-TEST-0204 (Insecure Random API Usage — PRNG lemah seperti `java.util.Random`) |
| **CWE terkait** | CWE-341 (Predictable from Observable State), CWE-330 (Use of Insufficiently Random Values), CWE-337 (Predictable Seed in PRNG), CWE-340 (Generation of Predictable Numbers or Identifiers), CWE-1241 (Use of Predictable Algorithm in Random Number Generator) |

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian

Test ini menggunakan **analisis statis** untuk menemukan penggunaan **sumber non-acak** (non-random sources) sebagai pengganti generator bilangan acak, lalu menilai apakah nilai yang dihasilkannya dipakai dalam konteks yang relevan secara keamanan.

Kutipan langsung dari overview MASTG:

> *"Android applications sometimes use **non-random sources** to generate 'random' values, leading to potential security vulnerabilities. Common practices include relying on the **current time**, such as `Date().getTime()`, or accessing `Calendar.MILLISECOND` to produce values that are **easily guessable and reproducible**."*

Perbedaan mendasar dengan MASTG-TEST-0204:

| | MASTG-TEST-0204 | MASTG-TEST-0205 *(dokumen ini)* |
|---|---|---|
| **Masalah** | PRNG **lemah** dipakai (`java.util.Random`, `Math.random()`) | **Bukan PRNG sama sekali** — nilai deterministik dipakai sebagai "acak" |
| Sifat nilai | Pseudorandom, tapi state-nya dapat dipulihkan | **Sama sekali tidak acak** — dapat ditebak dari pengetahuan waktu |
| Analogi | Kunci dengan kombinasi yang bisa dihitung | Kunci yang "kombinasinya" adalah jam saat ini |

Secara konseptual, test ini menangani masalah yang **lebih parah** daripada TEST-0204. `java.util.Random` setidaknya menghasilkan distribusi yang tampak acak dan butuh serangan pemulihan state. Sedangkan timestamp **sama sekali bukan nilai acak** — penyerang tidak perlu memecahkan apa pun, cukup tahu (atau menebak) kapan nilainya dihasilkan.

Kedua test berbagi weakness **MASWE-0012**, knowledge **MASTG-KNOW-0013**, best practice **MASTG-BEST-0001**, dan prerequisites yang sama. **Jalankan berpasangan** — pola keduanya sering muncul bersama di kode yang sama.

### 1.2 Mengapa Timestamp Bukan Sumber Acak — Analisis Entropi

Inti masalahnya adalah **entropi yang sangat rendah**, dan ini bisa dihitung.

**Kasus A — `Calendar.MILLISECOND`:** Field ini mengembalikan komponen milidetik dari waktu saat ini, yaitu bilangan **0–999 saja**.

```
Ruang nilai = 1.000 kemungkinan ≈ 9,97 bit entropi
```

Bandingkan dengan token yang aman (32 byte dari CSPRNG) yang punya 256 bit entropi. Token 10-bit dapat di-brute-force **secara instan** — bahkan secara manual. Jika sebuah aplikasi menghasilkan token autentikasi dari `Calendar.MILLISECOND`, penyerang hanya perlu mencoba maksimal 1.000 nilai.

**Kasus B — `Date().getTime()` / `System.currentTimeMillis()`:** Mengembalikan Unix epoch dalam milidetik. Secara nominal ini bilangan besar (~1,7 × 10¹²), tetapi **entropi efektifnya ditentukan oleh seberapa tepat penyerang dapat memperkirakan waktu pembuatannya**:

| Ketidakpastian waktu yang diketahui penyerang | Ruang pencarian | Entropi efektif |
|---|---|---|
| ± 1 detik | 2.000 nilai | ~11 bit |
| ± 1 menit | 120.000 nilai | ~17 bit |
| ± 1 jam | 7,2 juta nilai | ~22,8 bit |
| ± 1 hari | 172,8 juta nilai | ~27,4 bit |

Dalam skenario nyata, penyerang biasanya **tahu waktunya dengan sangat presisi**: ia memicu sendiri aksi yang menghasilkan token (misal menekan "Lupa Password"), lalu mencatat waktu responsnya. Ketidakpastiannya turun ke level ratusan milidetik → **ruang pencarian hanya beberapa ratus nilai**.

Lebih buruk lagi, `(int)` cast seperti pada demo MASTG (`Date().time.toInt()`) **memotong nilai 64-bit menjadi 32-bit**, yang bisa memperkenalkan pola tambahan yang mudah diprediksi.

**Kasus C — timestamp sebagai seed PRNG.** Ini kombinasi paling berbahaya dan sangat umum:

```kotlin
val r = Random(System.currentTimeMillis())   // ❌ seed dapat ditebak
```

Efeknya: seluruh rangkaian output PRNG menjadi dapat dihitung. Perhatikan bahwa `java.util.Random()` tanpa argumen **sudah** di-seed dari waktu sistem (dikombinasikan dengan nilai unik), sehingga menambahkan `System.currentTimeMillis()` sebagai seed **tidak memperbaiki apa pun** — justru membuatnya lebih mudah diprediksi karena menghilangkan komponen unik tersebut. Ini masuk **CWE-337 (Predictable Seed)**.

### 1.3 Sumber Non-Acak yang Perlu Dicari

**Kelompok A — Sumber waktu (yang eksplisit disebut MASTG dan dipindai rule-nya):**

| Sumber | Catatan |
|---|---|
| `new Date()` / `Date().getTime()` / `Date().time` | Disebut eksplisit di overview MASTG |
| `System.currentTimeMillis()` | Dipindai rule MASTG |
| `Calendar.getInstance().get(Calendar.MILLISECOND)` | Disebut eksplisit di overview MASTG. **Hanya 1.000 nilai** |
| `Calendar.get(...)` field lain (`SECOND`, `MINUTE`, `HOUR`, `DAY_OF_YEAR`) | Entropi bahkan lebih rendah lagi |
| `System.nanoTime()` | Lebih halus granularitasnya, tetapi **tetap bukan sumber acak** — monoton dan berkorelasi dengan waktu boot |
| `SystemClock.elapsedRealtime()` / `uptimeMillis()` / `currentThreadTimeMillis()` | **Tidak dipindai rule MASTG.** Bahkan lebih buruk: berkorelasi dengan waktu boot device |
| `LocalDateTime.now()` / `Instant.now()` / `ZonedDateTime.now()` (java.time) | **Tidak dipindai rule MASTG.** API modern dengan masalah yang sama |
| `java.sql.Timestamp` | Sama |

**Kelompok B — Sumber non-acak lain yang tidak disebut MASTG tetapi harus diperiksa:**

| Sumber | Mengapa berbahaya |
|---|---|
| **Identifier perangkat**: `Settings.Secure.ANDROID_ID`, IMEI, serial number, MAC address | Statis per perangkat, dan seringkali dapat dibaca aplikasi lain → **bukan rahasia** |
| **Counter / auto-increment** | `userId + 1`, nomor urut — sepenuhnya dapat diprediksi |
| **Hash dari data yang diketahui**: `md5(username)`, `sha1(email + timestamp)` | Hash bersifat deterministik. Hashing tidak menambah entropi — hanya mengaburkan |
| **`UUID.nameUUIDFromBytes(...)`** (UUID versi 3) | **Deterministik** dari input. Berbeda total dari `UUID.randomUUID()` yang berbasis `SecureRandom`. Jebakan yang sangat halus |
| **UUID versi 1** (time-based) | Mengandung timestamp dan MAC address — dapat diprediksi |
| `Object.hashCode()` / `System.identityHashCode()` | Berbasis alamat memori, bukan acak, dan dapat berulang |
| `Thread.currentThread().getId()` | Nilai kecil dan berurutan |
| `Process.myPid()` | Rentang nilai terbatas |
| Konstanta atau nilai hardcoded yang "terlihat acak" | Statis; ditemukan lewat dekompilasi |
| Kombinasi dari beberapa sumber di atas | Menggabungkan sumber non-acak **tidak menghasilkan keacakan** — entropinya tetap rendah |

> **Prinsip yang perlu dipegang:** entropi tidak bisa dibuat dengan mengombinasikan, meng-hash, atau meng-encode nilai yang dapat diprediksi. `sha256(timestamp + androidId)` terlihat seperti nilai acak 256-bit, tetapi entropi sebenarnya hanya sebesar ketidakpastian input-nya — bisa di bawah 20 bit. Penyerang cukup melakukan brute-force pada **input**, bukan pada output.

### 1.4 Konteks yang "Relevan Secara Keamanan"

Sama seperti MASTG-TEST-0204, test ini punya **prerequisites** `identify-sensitive-data` dan `identify-security-relevant-contexts`. **Temuan `System.currentTimeMillis()` saja bukan kerentanan** — yang menentukan adalah untuk apa nilainya dipakai.

MASTG menyebut konteks berikut sebagai security-relevant:

| Penggunaan | Dampak bila dapat diprediksi |
|---|---|
| **Kunci kriptografi** | Enkripsi menjadi tidak berarti — penyerang dapat menurunkan kunci yang sama |
| **Initialization Vector (IV)** | IV berulang merusak CBC; **fatal untuk GCM** (nonce reuse membocorkan authentication key) |
| **Nonce** | Nonce ECDSA yang berulang → private key dapat dipulihkan |
| **Token autentikasi** | Penyerang memprediksi token user lain → account takeover |
| **Session identifier** | Session hijacking |
| **Password** (yang di-generate aplikasi) | Dapat dihitung |
| **PIN** | Ruang nilai sudah kecil; ditambah entropi rendah menjadi trivial |
| **Token reset password / OTP / kode verifikasi** | Account takeover langsung. **Ini kombinasi paling berbahaya** karena penyerang mengendalikan waktu pemicunya |
| **Salt** untuk hashing password / KDF | Salt yang dapat diprediksi melemahkan perlindungan terhadap precomputation |
| **CSRF token / OAuth `state` / PKCE `code_verifier`** | Bypass proteksi |
| **Nama file temporer** di lokasi shared | Race condition / prediksi path |

**Konteks yang TIDAK security-relevant** — di sini penggunaan timestamp memang **benar dan diharapkan**:

- Mencatat waktu kejadian (`createdAt`, `updatedAt`, log timestamp)
- Mengukur durasi/performa (`start = System.currentTimeMillis()` … `elapsed = now - start`)
- Cache expiry, TTL, penjadwalan, debounce, throttle
- Menampilkan tanggal/jam di UI (`Calendar.get(Calendar.YEAR)` untuk format tanggal)
- Perhitungan timeout dan retry backoff
- Nama file berbasis timestamp untuk keperluan penyortiran (non-rahasia)
- Analytics dan telemetri

> **Ini pembeda terpenting test ini.** Berbeda dari `java.util.Random` yang relatif jarang dipakai, `System.currentTimeMillis()` dan `new Date()` adalah **API yang sangat umum dan sah** di hampir semua aplikasi. Aplikasi normal bisa punya puluhan hingga ratusan pemanggilannya yang semuanya legitimate. Konsekuensinya untuk pengujian dibahas di §3.4.

### 1.5 Skenario Serangan Konkret

Agar temuan bisa dinilai dengan tepat, berikut bagaimana kelemahan ini dieksploitasi dalam praktik:

**Skenario 1 — Prediksi token reset password.**
1. Penyerang membuat akun sendiri dan memicu "Lupa Password", mencatat waktu presisi dan token yang diterima.
2. Dari beberapa sampel, penyerang menyimpulkan pola: `token = f(timestamp)`.
3. Penyerang memicu reset password untuk akun korban, mencatat waktu request.
4. Penyerang meng-generate seluruh kandidat token untuk jendela waktu tersebut (biasanya beberapa ratus sampai beberapa ribu nilai) dan mencobanya.
5. **Account takeover.** Tanpa rate limiting di sisi server, ini selesai dalam hitungan detik.

**Skenario 2 — Pemulihan kunci enkripsi lokal.** Bila kunci diturunkan dari timestamp instalasi, penyerang yang memperoleh akses ke perangkat (atau ke backup) dapat memperkirakan waktu instalasi dari metadata file (`stat` pada direktori aplikasi), lalu melakukan brute-force pada jendela waktu tersebut untuk memulihkan kunci dan mendekripsi seluruh data lokal.

**Skenario 3 — Nonce collision.** Bila nonce GCM diturunkan dari `Calendar.MILLISECOND` (1.000 nilai), tabrakan nonce menjadi **hampir pasti** terjadi setelah beberapa puluh operasi enkripsi (paradoks ulang tahun: ~50% tabrakan setelah ~37 operasi). Pada AES-GCM, nonce reuse dengan kunci yang sama memungkinkan pemulihan *authentication key* → penyerang dapat memalsukan ciphertext.

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | MASTG ID | Fungsi dalam test ini |
|---|---|---|
| **jadx** | MASTG-TOOL-0018 | **Dekompilasi DEX → Java** (MASTG-TECH-0013). Juga wajib untuk MASTG-TECH-0023 — menelusuri bagaimana nilai waktu dipakai. Fitur "Find Usage" sangat penting di sini |
| **semgrep** | MASTG-TOOL-0110 | **Pattern matching**. MASTG menyediakan rule `mastg-android-non-random-use.yml` |
| **grep / ripgrep** | — | Pelengkap wajib untuk menutup celah rule (lihat §3.5) |
| **apktool** | MASTG-TOOL-0011 | Alternatif dekompilasi; analisis smali bila jadx gagal |

### 2.2 Tools Pendukung

| Tool | Fungsi |
|---|---|
| **CodeQL** | **Paling penting untuk test ini.** Karena rule semgrep akan menghasilkan sangat banyak false positive, **taint analysis** yang melacak aliran dari sumber waktu ke titik konsumsi kriptografis adalah cara paling efisien untuk memisahkan temuan nyata dari noise |
| **mobsfscan / MobSF** | SAST mobile; punya rule terkait weak PRNG dan predictable value |
| **semgrep-rules-android-security** (IMQ Minded Security) | **Sumber asli** rule MASTG ini (`mstg-crypto-6.yaml`) |
| **SonarQube** | Rule `java:S2245` (PRNG security-sensitive) dan rule terkait predictable seed |
| **jadx-gui** | Navigasi interaktif + "Find Usage" — kunci untuk melacak aliran nilai waktu |
| **Frida** | MASTG-TOOL-0001. Untuk konfirmasi dinamis (lihat §3.6) — sangat efektif untuk test ini karena dapat memperlihatkan nilai token yang dihasilkan beserta backtrace |
| **Alat analisis token** (mis. Burp Sequencer, `ent`) | Menganalisis kumpulan token dari aplikasi untuk mendeteksi pola/korelasi waktu — **bukti eksploitabilitas yang kuat** |
| **APKiD** | Deteksi packer/obfuscator untuk menilai keandalan analisis statis |
| **Ghidra / `strings`** | Analisis `.so` — `time()`, `gettimeofday()`, `clock()` dari kode native |

### 2.3 Prasyarat Lingkungan

- **Tidak butuh device dan tidak butuh root** — cukup file APK.
- **APK lengkap**, termasuk semua split APK / dynamic feature module.
- **semgrep terinstall** dan rule MASTG tersedia (clone `github.com/OWASP/mastg`, direktori `rules/`).
- **Penuhi prerequisites terlebih dahulu.** Untuk test ini prerequisites bahkan lebih krusial daripada di TEST-0204, karena rasio noise-nya jauh lebih tinggi. Kamu harus sudah tahu: token apa saja yang dipakai aplikasi? Ada enkripsi lokal? Bagaimana alur reset password/OTP? Tanpa peta ini, memindai `System.currentTimeMillis()` akan menghasilkan ratusan temuan tanpa arah.
- **Rule hanya `languages: java`** — pemindaian dilakukan pada kode hasil dekompilasi, bukan sumber Kotlin.
- **Catat efek dekompilasi pada konstanta.** Ini penting secara praktis: di kode sumber tertulis `Calendar.MILLISECOND`, tetapi di **Java hasil dekompilasi konstanta itu menjadi literal angka `14`** (lihat demo: `c.get(14)`). Artinya `grep "Calendar.MILLISECOND"` pada kode hasil dekompilasi **tidak akan menemukan apa pun**. Kamu perlu mencari `.get(` dengan literal numerik, atau mengandalkan rule semgrep yang mencocokkan `(Calendar $C).get(...)` secara umum.

**Tabel konstanta `Calendar` yang berguna saat membaca kode dekompilasi:**

| Literal | Konstanta | Ruang nilai |
|---|---|---|
| `1` | `YEAR` | — |
| `2` | `MONTH` | 0–11 |
| `5` | `DAY_OF_MONTH` | 1–31 |
| `6` | `DAY_OF_YEAR` | 1–366 |
| `11` | `HOUR_OF_DAY` | 0–23 |
| `12` | `MINUTE` | 0–59 |
| `13` | `SECOND` | 0–59 |
| **`14`** | **`MILLISECOND`** | **0–999** |

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0013** (*Reverse Engineering Android Apps*) untuk me-reverse engineer aplikasi.
2. Gunakan **MASTG-TECH-0014** (*Static Analysis on Android*) untuk mencari API yang relevan.

Lalu untuk evaluasi: gunakan **MASTG-TECH-0023** (*Reviewing Decompiled Java Code*) pada setiap lokasi kode yang dilaporkan.

### 3.2 Implementasi Praktis (MASTG-DEMO-0008)

**Langkah 1 — Dekompilasi**

```bash
jadx -d ./decompiled ./target-app.apk

# Bila split APK / AAB, ambil dan dekompilasi semua bagian
adb shell pm path com.example.target
```

**Langkah 2 — Jalankan rule semgrep resmi MASTG**

Rule `mastg-android-non-random-use.yml`:

```yaml
rules:
  - id: mastg-android-non-random-use
    severity: WARNING
    languages:
      - java
    metadata:
      summary: This rule looks for common patterns including classes and methods that represent non-random sources e.g. via `Calendar.MILLISECOND` or `new Date()`.
      original_source: https://github.com/mindedsecurity/semgrep-rules-android-security/blob/main/rules/crypto/mstg-crypto-6.yaml
    message: "[MASVS-CRYPTO-1] The application makes use of non-random sources."
    pattern-either:
        - patterns:
            - pattern-inside: $M(...){ ... }
            - pattern-either:
                - pattern: new Date()
                - pattern: System.currentTimeMillis()
                - pattern: (Calendar $C).get(...)
```

Menjalankannya (`run.sh` dari demo):

```bash
NO_COLOR=true semgrep -c ../../../../rules/mastg-android-non-random-use.yml \
  ./MastgTest_reversed.java > output.txt
```

Untuk aplikasi nyata — **gunakan output JSON** karena jumlah temuan akan besar:

```bash
NO_COLOR=true semgrep \
  -c ./mastg/rules/mastg-android-non-random-use.yml \
  ./decompiled/sources/ --json -o findings-nonrandom.json

# Lihat dulu skala temuannya sebelum mulai review
jq '.results | length' findings-nonrandom.json
```

**Langkah 3 — Triase (wajib, sebelum review)**

Karena rule ini sangat noisy, jangan langsung review satu per satu. Persempit dulu dengan mencari temuan yang **berdekatan dengan konteks kriptografis/token**:

```bash
# Ambil daftar file yang punya temuan
jq -r '.results[].path' findings-nonrandom.json | sort -u > files_with_findings.txt

# Persempit: file yang JUGA menyentuh konteks security-relevant
grep -lE "SecretKeySpec|IvParameterSpec|GCMParameterSpec|KeyGenerator|PBEKeySpec|MessageDigest|Mac\.getInstance" \
  $(cat files_with_findings.txt) 2>/dev/null > priority_files.txt

grep -liE "token|session|nonce|otp|passcode|reset|verify|csrf|salt|secret|credential" \
  $(cat files_with_findings.txt) 2>/dev/null >> priority_files.txt

sort -u priority_files.txt
```

**Langkah 4 — Review setiap temuan prioritas (MASTG-TECH-0023)**

Untuk setiap temuan, jawab tiga pertanyaan:

1. **Nilai waktu ini dipakai untuk apa?** Lacak variabelnya sampai titik konsumsi akhir.
2. **Apakah titik itu security-relevant?** Bandingkan dengan tabel §1.4.
3. **Jika temuan berada di fungsi helper, lacak semua pemanggilnya.**

```bash
# Lacak variabel hasil sumber waktu
grep -rn "random1\|random2\|seed\|nonce" ./decompiled/sources/org/owasp/mastestapp/

# Cari pemanggil fungsi helper
grep -rn "generateToken\|createSession\|getNonce\|newId\|generateOtp" ./decompiled/sources/
```

### 3.3 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG:**

> **Observation:** *"The output should contain a list of locations where non-random sources are used."*
>
> **Evaluation:** *"The test case **fails** if you can find **security-relevant values, such as passwords or tokens, generated using non-random sources**."*
>
> **Further Validation Required** — inspeksi setiap lokasi kode dengan MASTG-TECH-0023 untuk menentukan apakah penggunaannya security-relevant:
> - Tentukan apakah nilai yang dihasilkan dipakai untuk tujuan security-relevant, seperti pembuatan **kunci kriptografi, initialization vector (IV), nonce, token autentikasi, session identifier, password, atau PIN**.

Evaluasi dari MASTG-DEMO-0008 sendiri sangat singkat — hanya *"Review each of the reported instances."* Karena itu kerangka penilaian di bawah ini diperlukan untuk membuat keputusan yang konsisten.

**Klausa kunci:** *"security-relevant values ... generated using non-random sources"*. Sumber non-acak **harus terbukti mengalir ke nilai yang security-relevant** untuk dinyatakan FAIL.

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi | Contoh bukti |
|---|---|---|
| F1 | Timestamp dipakai langsung sebagai **token autentikasi / session ID** | `int random1 = (int) new Date().getTime();` lalu dipakai sebagai token |
| F2 | `Calendar.MILLISECOND` (atau field Calendar lain) dipakai sebagai nilai "acak" security-relevant | `int random2 = c.get(14);` → **hanya 1.000 kemungkinan** |
| F3 | Timestamp dipakai sebagai **seed PRNG** | `new Random(System.currentTimeMillis())` → CWE-337; seluruh rangkaian output dapat dihitung |
| F4 | Timestamp dipakai untuk **menurunkan kunci kriptografi** | `SecretKeySpec(sha256(System.currentTimeMillis().toString()), "AES")` |
| F5 | Timestamp dipakai sebagai **IV atau nonce** | `IvParameterSpec(longToBytes(System.currentTimeMillis()))` → **kritis pada GCM** |
| F6 | Timestamp dipakai untuk **token reset password / OTP / kode verifikasi** | **Severity tertinggi** — penyerang mengendalikan waktu pemicunya |
| F7 | Timestamp dipakai sebagai **salt** | `PBEKeySpec(pass, timestampBytes, iter, len)` |
| F8 | **Identifier perangkat** (`ANDROID_ID`, IMEI, MAC, serial) dipakai sebagai sumber "acak" | Statis per perangkat dan bukan rahasia |
| F9 | **Counter / nilai berurutan** dipakai sebagai token atau ID rahasia | `token = lastId + 1` |
| F10 | **Hash dari data yang diketahui** dipakai sebagai nilai rahasia | `md5(username + timestamp)` — hashing tidak menambah entropi |
| F11 | `UUID.nameUUIDFromBytes(...)` (UUID v3, **deterministik**) dipakai untuk nilai yang harus tidak dapat diprediksi | Jebakan halus — mudah dikira sama dengan `UUID.randomUUID()` |
| F12 | `System.nanoTime()` / `SystemClock.*` dipakai sebagai sumber acak security-relevant | **Tidak tertangkap rule MASTG** |
| F13 | API waktu modern (`LocalDateTime.now()`, `Instant.now()`) dipakai sebagai sumber acak | **Tidak tertangkap rule MASTG** |
| F14 | **Kombinasi beberapa sumber non-acak** dipakai, dengan asumsi keliru bahwa itu menghasilkan keacakan | `sha256(timestamp + androidId + pid)` — entropi tetap rendah |
| F15 | Sumber waktu dari **kode native** dipakai untuk keamanan | `strings lib.so` → `time`, `gettimeofday`, `clock` + review menunjukkan pemakaian untuk key/nonce |

**Contoh output yang menandakan FAIL — MASTG-DEMO-0008:**

Kode sampel (`MastgTest.kt`) — perhatikan anotasi FAIL yang disediakan MASTG:

```kotlin
fun mastgTest(): String {
    // SUMMARY: This sample demonstrates different ways of creating non-random tokens in Java.

    // FAIL: [android-insecure-random-use] The app uses Date().time for generating authentication tokens.
    val random1 = Date().time.toInt()

    val c = Calendar.getInstance()
    // FAIL: [android-insecure-random-use] The app uses Calendar.getInstance().timeInMillis
    //       for generating authentication tokens.
    val random2 = c.get(Calendar.MILLISECOND)

    return "Generated random numbers:\n$random1 \n$random2"
}
```

Kode hasil dekompilasi yang dipindai semgrep (`MastgTest_reversed.java`):

```java
public final String mastgTest() {
    int random1 = (int) new Date().getTime();       // <-- baris 22
    Calendar c = Calendar.getInstance();
    int random2 = c.get(14);                        // <-- baris 24 (14 = Calendar.MILLISECOND)
    return "Generated random numbers:\n" + random1 + " \n" + random2;
}
```

Output semgrep (`output.txt`):

```
┌─────────────────┐
│ 2 Code Findings │
└─────────────────┘

    MastgTest_reversed.java
    ❯❱ rules.mastg-android-non-random-use
          [MASVS-CRYPTO-1] The application makes use of non-random sources.

           22┆ int random1 = (int) new Date().getTime();
            ⋮┆----------------------------------------
           24┆ int random2 = c.get(14);
```

**Lima pelajaran penting dari demo ini:**

1. **`Calendar.MILLISECOND` menjadi literal `14` setelah dekompilasi.** Ini konsekuensi praktis yang sangat penting: `grep "Calendar.MILLISECOND"` pada kode hasil dekompilasi **tidak akan menemukan apa pun**. Rule semgrep berhasil menangkapnya karena mencocokkan `(Calendar $C).get(...)` secara umum — bukan karena mengenali konstanta spesifiknya. Gunakan tabel konstanta di §2.3 saat membaca kode dekompilasi.
2. **`random2` hanya punya 1.000 kemungkinan nilai.** Bila dipakai sebagai token autentikasi seperti yang dinyatakan komentar demo, ini dapat di-brute-force secara instan.
3. **Cast `(int)` memotong nilai 64-bit menjadi 32-bit.** `Date().time.toInt()` kehilangan informasi dan dapat memperkenalkan pola tambahan.
4. **Rule tidak membedakan `new Date()` untuk keperluan sah.** Ia mencocokkan pembuatan objek `Date` apa pun, di mana pun. Inilah sumber utama false positive pada aplikasi nyata.
5. **Ada dua ketidaksesuaian kecil di artefak demo** yang perlu disadari saat mereplikasi:
   - Komentar FAIL kedua menyebut `Calendar.getInstance().timeInMillis`, sementara kodenya sebenarnya `c.get(Calendar.MILLISECOND)`. Keduanya bermasalah, tetapi entropinya sangat berbeda (timestamp penuh vs 1.000 nilai).
   - Tag pada komentar berbunyi `[android-insecure-random-use]`, yaitu tag dari rule MASTG-DEMO-0007 (TEST-0204), bukan `mastg-android-non-random-use` yang sebenarnya dipakai di sini.

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi | Contoh bukti |
|---|---|---|
| P1 | **Semgrep tidak menemukan temuan** dan grep pelengkap juga bersih | `0 Code Findings`; tidak ada `nanoTime`, `SystemClock`, `Instant.now()` di jalur kripto |
| P2 | Ada banyak temuan sumber waktu, tetapi review membuktikan **semuanya untuk keperluan sah** | `System.currentTimeMillis()` untuk pengukuran durasi, cache TTL, `createdAt`, format tanggal UI |
| P3 | Semua nilai security-relevant berasal dari **`SecureRandom`**, bukan dari sumber waktu | `SecureRandom().nextBytes(tokenBytes)` |
| P4 | `SecureRandom` dipakai dengan **konstruktor default**, tanpa seeding dari timestamp | Tidak ada `SecureRandom(timeBytes)` maupun `setSeed(System.currentTimeMillis())` |
| P5 | Kunci/IV/nonce dihasilkan **platform**, bukan diturunkan dari waktu | `KeyGenerator` + Android KeyStore; `cipher.iv` |
| P6 | Timestamp dipakai **bersama** nilai acak dari CSPRNG, di mana keamanan bersandar pada komponen acaknya | `token = base64(secureRandomBytes(32)) + ":" + timestamp` — timestamp hanya untuk expiry, bukan sumber entropi |
| P7 | `UUID.randomUUID()` dipakai (berbasis `SecureRandom`), **bukan** `UUID.nameUUIDFromBytes()` | Aman untuk identifier |
| P8 | Token security-relevant dihasilkan **server**, bukan klien | Tidak ada pembuatan token di sisi aplikasi |

**Contoh output yang menandakan PASS:**

```bash
$ NO_COLOR=true semgrep -c mastg-android-non-random-use.yml ./decompiled/sources/ --json -o f.json
$ jq '.results | length' f.json
47
# 47 temuan — TAPI setelah triase, semuanya di konteks non-security:
```

```bash
# Tidak ada temuan di file yang menyentuh konteks kriptografis/token
$ grep -lE "SecretKeySpec|IvParameterSpec|GCMParameterSpec|PBEKeySpec" $(jq -r '.results[].path' f.json | sort -u)
# (tidak ada hasil)

# Tidak ada timestamp yang dipakai sebagai seed
$ grep -rnE "new Random\([^)]|setSeed\(|new SecureRandom\([^)]" ./decompiled/sources/
# (tidak ada hasil)

# Sumber non-acak lain yang tidak tercakup rule juga bersih di jalur kripto
$ grep -rnE "nanoTime|SystemClock\.|Instant\.now|nameUUIDFromBytes|ANDROID_ID" ./decompiled/sources/
# (hanya di kelas telemetri, tidak di jalur token/kripto)
```

Kode yang benar:

```kotlin
// ✅ Nilai security-relevant dari CSPRNG
val secureRandom = SecureRandom()
val tokenBytes = ByteArray(32)
secureRandom.nextBytes(tokenBytes)
val token = Base64.encodeToString(tokenBytes, Base64.URL_SAFE or Base64.NO_WRAP)

// ✅ Timestamp BOLEH dipakai untuk expiry — keamanan bersandar pada komponen acak
val expiresAt = System.currentTimeMillis() + 15 * 60 * 1000
val payload = "$token:$expiresAt"

// ✅ Kunci: biarkan platform yang meng-generate
val keyGen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
keyGen.init(
    KeyGenParameterSpec.Builder("myKey", KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
        .setRandomizedEncryptionRequired(true)
        .build()
)
keyGen.generateKey()

// ✅ IV: dari Cipher, bukan dari waktu
val cipher = Cipher.getInstance("AES/GCM/NoPadding")
cipher.init(Cipher.ENCRYPT_MODE, key)
val iv = cipher.iv

// ✅ Penggunaan timestamp yang memang sah — bukan temuan
val start = System.currentTimeMillis()
doWork()
Log.d(TAG, "took ${System.currentTimeMillis() - start}ms")
```

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Rule ini JAUH lebih noisy daripada rule MASTG-TEST-0204 — ini karakteristik terpenting test ini.** `new Date()`, `System.currentTimeMillis()`, dan `Calendar.get()` adalah API yang benar-benar umum dan sah. Aplikasi nyata akan menghasilkan puluhan hingga ratusan temuan yang **hampir semuanya legitimate**. Melaporkan output semgrep apa adanya bukan hanya salah, tetapi juga akan merusak kredibilitas laporan. **Lakukan triase (§3.2 Langkah 3) sebelum review.**

2. **Pola `(Calendar $C).get(...)` mencocokkan SEMUA pemanggilan `Calendar.get()`** — termasuk `c.get(Calendar.YEAR)` untuk menampilkan tanggal di UI. Rule tidak membedakan field mana yang diambil. Gunakan tabel konstanta di §2.3 untuk menilai: `get(14)` (MILLISECOND) sangat mencurigakan; `get(1)` (YEAR) hampir pasti untuk format tanggal.

3. **Arah analisis yang lebih efisien: mulai dari titik konsumsi, bukan dari sumber.** Karena sumbernya terlalu umum, lebih produktif mencari dulu **semua titik pembuatan token/kunci/nonce**, lalu periksa ke belakang apakah input-nya berasal dari sumber non-acak. Ini kebalikan dari alur biasa dan jauh lebih hemat waktu:

   ```bash
   # Mulai dari titik konsumsi security-relevant
   grep -rnE "SecretKeySpec|IvParameterSpec|GCMParameterSpec|PBEKeySpec|new Random\(" ./decompiled/sources/
   grep -rniE "fun .*(generateToken|createSession|newNonce|generateOtp|resetToken)" ./decompiled/sources/
   # -> lalu periksa asal input setiap lokasi tersebut
   ```

4. **`Calendar.MILLISECOND` tidak dapat ditemukan dengan grep pada kode dekompilasi** — ia menjadi literal `14`. Jangan simpulkan aman hanya karena `grep "MILLISECOND"` kosong.

5. **Hashing/encoding tidak menambah entropi.** `sha256(timestamp)` terlihat seperti nilai 256-bit acak, tetapi entropinya hanya sebesar ketidakpastian timestamp-nya. Jangan tertipu oleh kehadiran `MessageDigest` di jalur kode — periksa **apa yang di-hash**.

6. **Timestamp bersama CSPRNG itu boleh.** Pola `secureRandomBytes + timestamp` adalah praktik yang benar (timestamp untuk expiry, entropi dari CSPRNG). Yang salah adalah timestamp **sebagai** sumber entropi. Bedakan keduanya dengan cermat agar tidak menghasilkan false positive.

7. **Output kosong ≠ otomatis PASS.** Celah rule (lihat catatan 8), obfuscation, refleksi, kode native, dan split APK yang tidak dianalisis semuanya bisa menyembunyikan temuan.

8. **Celah rule MASTG yang perlu ditutup:**

   | Celah | Dampak |
   |---|---|
   | `pattern-inside: $M(...){ ... }` mensyaratkan di dalam body metode | **Field initializer tingkat kelas lolos**, mis. `private static final long SEED = System.currentTimeMillis();` |
   | `languages: java` saja | Sumber Kotlin tidak dipindai |
   | Tidak mencakup `System.nanoTime()` | Lolos |
   | Tidak mencakup `SystemClock.elapsedRealtime/uptimeMillis` | Lolos — padahal spesifik Android |
   | Tidak mencakup `java.time` (`Instant.now()`, `LocalDateTime.now()`) | Lolos — API modern |
   | Tidak mencakup `Date(long)`, `Date.from(...)`, `Calendar.getTimeInMillis()` | `new Date()` saja yang dicocokkan (tanpa argumen) |
   | Tidak mencakup identifier perangkat, counter, hash deterministik, `UUID.nameUUIDFromBytes` | Seluruh Kelompok B (§1.3) lolos |
   | Tidak mencakup sumber waktu native | Lolos |

9. **Severity dimodulasi oleh entropi efektif dan konteks:**

   | Faktor | Severity |
   |---|---|
   | Timestamp/Calendar dipakai untuk kunci kripto atau nonce GCM/ECDSA | **Kritis** |
   | Dipakai untuk token reset password / OTP | **Kritis** — penyerang mengendalikan waktu pemicunya sehingga ruang pencarian sangat kecil |
   | Dipakai untuk token autentikasi / session ID | **Tinggi** |
   | `Calendar.MILLISECOND` sebagai sumber (1.000 nilai ≈ 10 bit) | **Naik** — entropi jauh lebih rendah daripada timestamp penuh |
   | Dipakai sebagai seed PRNG | **Tinggi** — seluruh rangkaian output dapat dihitung |
   | Dipakai untuk IV CBC atau salt | **Menengah–Tinggi** |
   | Identifier perangkat sebagai sumber "acak" | **Tinggi** — statis dan tidak rahasia |
   | Ada rate limiting + masa berlaku pendek di sisi server | Turun sedikit — memperbesar biaya serangan, **tetapi tidak memperbaiki akar masalah** |
   | Penggunaan non-security (timestamp log, durasi, TTL, format tanggal) | **Bukan temuan** |

10. **Buktikan eksploitabilitas bila memungkinkan.** Ini test yang PoC-nya relatif mudah dan sangat meyakinkan: kumpulkan beberapa token dari aplikasi beserta waktu pembuatannya, tunjukkan korelasinya (mis. dengan Burp Sequencer atau plot sederhana), lalu demonstrasikan prediksi token berikutnya. Ini mengubah temuan dari "praktik buruk" menjadi "kerentanan terbukti".

11. **Dokumentasikan bukti lengkap per temuan:** rule ID, path + nomor baris, potongan kode dekompilasi (**sertakan arti literal Calendar bila ada**, mis. `get(14)` = `MILLISECOND`), hasil pelacakan aliran dari sumber ke titik konsumsi, klasifikasi konteks beserta alasannya, **estimasi entropi efektif**, dan PoC bila dibuat. Cantumkan juga jumlah total temuan vs jumlah yang lolos triase — ini menunjukkan kualitas analisis dan mencegah pembaca mengira kamu hanya menempel output tool.

### 3.4 Pemeriksaan Pelengkap (Menutup Celah Rule)

```bash
D=./decompiled/sources

# 1. Sumber waktu yang TIDAK tercakup rule MASTG
grep -rnE "System\.nanoTime\(\)" $D
grep -rnE "SystemClock\.(elapsedRealtime|uptimeMillis|currentThreadTimeMillis)" $D
grep -rnE "Instant\.now|LocalDateTime\.now|LocalDate\.now|ZonedDateTime\.now|OffsetDateTime\.now" $D
grep -rnE "getTimeInMillis\(\)|new Date\([^)]|Date\.from\(" $D
grep -rnE "new Timestamp\(" $D

# 2. Field initializer tingkat kelas (celah pattern-inside)
grep -rnE "(static )?(final )?(long|int) [A-Za-z_]+ *= *System\.currentTimeMillis" $D

# 3. Timestamp sebagai SEED PRNG — pola paling berbahaya (CWE-337)
grep -rnE "new Random\(" $D                      # periksa argumennya
grep -rnE "setSeed\(" $D
grep -rnE "new SecureRandom\([^)]" $D

# 4. Sumber non-acak lain (Kelompok B, tidak tercakup rule)
grep -rnE "ANDROID_ID|getDeviceId|getImei|getSerial|Build\.SERIAL|getMacAddress" $D
grep -rnE "nameUUIDFromBytes" $D                 # UUID v3 = DETERMINISTIK
grep -rnE "hashCode\(\)|identityHashCode" $D
grep -rnE "Thread\.currentThread\(\)\.getId|Process\.myPid" $D

# 5. Literal konstanta Calendar yang mencurigakan pada kode dekompilasi
grep -rnE "\.get\(1[1-4]\)|\.get\(13\)|\.get\(14\)" $D      # 11=HOUR,12=MIN,13=SEC,14=MILLISECOND

# 6. Titik konsumsi security-relevant (untuk analisis arah balik — lihat catatan 3)
grep -rnE "SecretKeySpec|IvParameterSpec|GCMParameterSpec|KeyGenerator|PBEKeySpec|KeyPairGenerator" $D
grep -rniE "generateToken|sessionId|session_id|nonce|\botp\b|resetToken|csrf|\bsalt\b|verifyCode" $D

# 7. Sumber waktu dari kode native
for so in $(find ./extracted -name "*.so"); do
  echo "--- $so"; strings "$so" | grep -xE "time|gettimeofday|clock|clock_gettime|times"
done

# 8. Deteksi proteksi yang membatasi keandalan analisis
apkid ./target-app.apk
```

**Rule semgrep perluasan** untuk menutup celah utama:

```yaml
rules:
  - id: custom-non-random-sources-extended
    severity: WARNING
    languages: [java, kotlin]
    message: "[MASVS-CRYPTO-1] Sumber non-acak dipakai; verifikasi apakah mengalir ke konteks security-relevant"
    pattern-either:
      # Sumber waktu yang lolos rule MASTG
      - pattern: System.nanoTime(...)
      - pattern: android.os.SystemClock.elapsedRealtime(...)
      - pattern: android.os.SystemClock.uptimeMillis(...)
      - pattern: java.time.Instant.now(...)
      - pattern: java.time.LocalDateTime.now(...)
      - pattern: (java.util.Calendar $C).getTimeInMillis(...)
      # Field initializer (tanpa pattern-inside)
      - pattern: System.currentTimeMillis()
      # UUID deterministik — sering dikira aman
      - pattern: java.util.UUID.nameUUIDFromBytes(...)
      # Identifier perangkat sebagai "sumber acak"
      - pattern: android.os.Build.SERIAL

  - id: custom-predictable-seed
    severity: ERROR
    languages: [java, kotlin]
    message: "[MASVS-CRYPTO-1] PRNG di-seed dengan nilai yang dapat diprediksi (CWE-337)"
    pattern-either:
      - pattern: new java.util.Random(System.currentTimeMillis())
      - pattern: new java.util.Random((new java.util.Date()).getTime())
      - pattern: (java.security.SecureRandom $S).setSeed(System.currentTimeMillis())
      - pattern: (java.util.Random $R).setSeed(System.currentTimeMillis())
```

### 3.5 Konfirmasi Dinamis Opsional

MASTG tidak menyediakan test dinamis untuk ini, tetapi hooking sangat efektif di sini — terutama untuk **memisahkan pemakaian waktu yang sah dari yang berbahaya** berdasarkan backtrace, sekaligus mengumpulkan sampel token untuk PoC.

```javascript
Java.perform(() => {
    function bt(max = 12) {
        const E = Java.use("java.lang.Exception");
        const st = E.$new().getStackTrace();
        const out = [];
        for (let i = 0; i < Math.min(max, st.length); i++) {
            const f = st[i].toString();
            if (f.indexOf("java.lang.System") === 0) continue;
            out.push("    " + f);
        }
        return out.join("\n");
    }

    // Tandai hanya bila backtrace menyentuh konteks yang mencurigakan
    const SUSPECT = /token|session|nonce|otp|crypto|cipher|key|secret|random|auth|reset|salt/i;

    const System_ = Java.use("java.lang.System");
    System_.currentTimeMillis.implementation = function () {
        const r = this.currentTimeMillis();
        const trace = bt();
        if (SUSPECT.test(trace)) {
            console.log(`\n[!] System.currentTimeMillis() -> ${r}  (konteks mencurigakan)`);
            console.log(trace);
        }
        return r;
    };

    const Cal = Java.use("java.util.Calendar");
    Cal.get.implementation = function (field) {
        const r = this.get(field);
        // 14 = MILLISECOND, 13 = SECOND
        if (field === 14 || field === 13) {
            console.log(`\n[!] Calendar.get(${field}${field === 14 ? " = MILLISECOND" : " = SECOND"}) -> ${r}`);
            console.log(bt());
        }
        return r;
    };

    // Deteksi PRNG yang di-seed secara deterministik (CWE-337)
    const R = Java.use("java.util.Random");
    R.$init.overload('long').implementation = function (seed) {
        console.log(`\n[!!] new Random(${seed}) — SEED EKSPLISIT, cek apakah berasal dari waktu`);
        console.log(bt());
        return this.$init(seed);
    };
    R.setSeed.overload('long').implementation = function (seed) {
        console.log(`\n[!!] Random.setSeed(${seed})`);
        console.log(bt());
        return this.setSeed(seed);
    };
});
```

> Filter `SUSPECT` pada backtrace penting di sini — tanpa itu, hook `currentTimeMillis()` akan menghasilkan ribuan baris karena API ini dipanggil terus-menerus oleh framework.

**Analisis kualitas token** (bukti eksploitabilitas):

```bash
# Kumpulkan banyak token dari aplikasi, lalu periksa apakah ada korelasi waktu
# Token yang berasal dari timestamp akan tampak monoton/berurutan
sort tokens.txt | uniq -c | head
ent tokens_raw.bin        # entropi rendah => bukan dari CSPRNG
# Atau gunakan Burp Sequencer untuk analisis statistik otomatis
```

---

### 3.6 Metode Pengujian Alternatif (Multi-Tool)

Test ini punya tantangan khusus: rule MASTG mencocokkan API yang **sangat umum dan sah** (`new Date()`, `System.currentTimeMillis()`), sehingga menghasilkan puluhan hingga ratusan temuan yang hampir semuanya legitimate. Metode alternatif di bawah dipilih terutama untuk **menekan noise**, bukan hanya memperluas cakupan.

#### Metode B — Analisis arah balik dengan ripgrep *(paling efisien untuk test ini)*

**Ini pendekatan yang aku rekomendasikan sebagai default.** Alih-alih memindai sumber waktu (terlalu umum), mulai dari **titik konsumsi** yang jumlahnya jauh lebih sedikit, lalu periksa ke belakang.

```bash
jadx -d ./decompiled ./target-app.apk
D=./decompiled/sources

# --- LANGKAH 1: Temukan SEMUA titik konsumsi security-relevant (jumlahnya sedikit) ---
rg -n --no-heading "SecretKeySpec|IvParameterSpec|GCMParameterSpec|PBEKeySpec|KeyGenerator|KeyPairGenerator" $D > sinks.txt
rg -ni --no-heading "generateToken|createSession|newNonce|generateOtp|resetToken|csrf|verifyCode|\bsalt\b" $D >> sinks.txt
wc -l sinks.txt        # biasanya puluhan, bukan ratusan

# --- LANGKAH 2: Untuk setiap file yang muncul di sinks.txt, cari sumber waktu DI DALAMNYA ---
for f in $(cut -d: -f1 sinks.txt | sort -u); do
  hit=$(rg -n "currentTimeMillis|new Date\(|nanoTime|Calendar|Instant\.now|SystemClock" "$f")
  [ -n "$hit" ] && { echo "=== $f"; echo "$hit"; }
done

# --- LANGKAH 3: Pola paling berbahaya — timestamp sebagai SEED PRNG (CWE-337) ---
rg -n --no-heading "new Random\(" $D            # periksa argumennya satu per satu
rg -n --no-heading "setSeed\(" $D
rg -n --no-heading "new SecureRandom\([^)]" $D

# --- LANGKAH 4: Sumber waktu yang TIDAK tercakup rule MASTG ---
rg -n --no-heading "System\.nanoTime\(\)" $D
rg -n --no-heading "SystemClock\.(elapsedRealtime|uptimeMillis|currentThreadTimeMillis)" $D
rg -n --no-heading "Instant\.now|LocalDateTime\.now|LocalDate\.now|ZonedDateTime\.now|OffsetDateTime\.now" $D
rg -n --no-heading "getTimeInMillis\(\)|new Timestamp\(" $D

# --- LANGKAH 5: Kelompok B — sumber non-acak selain waktu (lolos rule MASTG) ---
rg -n --no-heading "ANDROID_ID|getDeviceId|getImei|getSerial|Build\.SERIAL|getMacAddress" $D
rg -n --no-heading "nameUUIDFromBytes" $D       # UUID v3 = DETERMINISTIK
rg -n --no-heading "hashCode\(\)|identityHashCode|Thread\.currentThread\(\)\.getId|Process\.myPid" $D

# --- LANGKAH 6: Literal konstanta Calendar mencurigakan pada kode dekompilasi ---
#     Ingat: Calendar.MILLISECOND menjadi literal 14 setelah dekompilasi
rg -n --no-heading "\.get\(1[1-4]\)" $D
```

#### Metode C — CodeQL *(satu-satunya yang menekan noise secara otomatis)*

**Ini metode paling tepat untuk test ini.** Karena masalah utamanya adalah rasio noise, taint analysis yang melacak aliran `currentTimeMillis()` → sink kriptografis adalah satu-satunya cara mendapatkan daftar temuan yang benar-benar relevan tanpa review manual ratusan hit.

```bash
codeql database create ./cqldb --language=java --command="./gradlew assembleDebug"

codeql database analyze ./cqldb \
  codeql/java-queries:Security/CWE/CWE-335/PredictableSeed.ql \
  codeql/java-queries:Security/CWE/CWE-330/InsecureRandomness.ql \
  --format=sarif-latest --output=nonrandom.sarif
```

Query kustom yang persis memodelkan masalah test ini:

```ql
/**
 * @name Time-based value flows into a security-sensitive sink
 * @kind path-problem
 * @problem.severity error
 */
import java
import semmle.code.java.dataflow.TaintTracking

class TimeSource extends DataFlow::Node {
  TimeSource() {
    exists(MethodAccess ma |
      ma.getMethod().hasQualifiedName("java.lang", "System", ["currentTimeMillis", "nanoTime"]) or
      ma.getMethod().getDeclaringType().hasQualifiedName("java.util", "Date") or
      ma.getMethod().getDeclaringType().hasQualifiedName("java.util", "Calendar") or
      ma.getMethod().getDeclaringType().hasQualifiedName("android.os", "SystemClock") or
      ma.getMethod().getDeclaringType().hasQualifiedName("java.time", ["Instant", "LocalDateTime"]) |
      this.asExpr() = ma
    )
  }
}

class SecuritySink extends DataFlow::Node {
  SecuritySink() {
    // Seed PRNG
    exists(ClassInstanceExpr cie |
      cie.getConstructedType().hasQualifiedName("java.util", "Random") |
      this.asExpr() = cie.getAnArgument())
    or
    // Material kunci / IV / salt
    exists(ClassInstanceExpr cie |
      cie.getConstructedType().hasQualifiedName("javax.crypto.spec",
        ["SecretKeySpec", "IvParameterSpec", "GCMParameterSpec", "PBEKeySpec"]) |
      this.asExpr() = cie.getAnArgument())
    or
    // setSeed
    exists(MethodAccess ma |
      ma.getMethod().hasName("setSeed") |
      this.asExpr() = ma.getAnArgument())
  }
}
```

Dengan query ini, aplikasi yang punya 200 pemanggilan `System.currentTimeMillis()` untuk logging/TTL akan menghasilkan **nol** temuan, dan hanya jalur yang benar-benar mengalir ke kripto yang dilaporkan.

#### Metode D — MobSF *(laporan siap kutip)*

Cari di **Code Analysis**: temuan *"The App may use weak PRNG"* dan *"App uses time-based values for cryptographic purposes"* (bila terdeteksi). Catat bahwa MobSF juga cenderung noisy untuk kategori ini — perlakukan sebagai daftar kandidat, bukan daftar kerentanan.

#### Metode E — SonarQube / SonarLint

Rule yang relevan: **`java:S2245`** (PRNG security-sensitive) dan **`java:S4347`** (*Secure random number generators should not output predictable values* — menangkap `setSeed` deterministik, termasuk dari timestamp). Sonar unggul di sini karena ia memahami konteks konstruktor `new Random(seed)`.

```bash
sonar-scanner -Dsonar.projectKey=android-app -Dsonar.sources=./app/src
```

#### Metode F — semgrep registry & rule pihak ketiga

```bash
semgrep --config "r/java.lang.security.audit.crypto.weak-random.weak-random" ./decompiled/sources/
semgrep --config "p/java" ./decompiled/sources/

git clone https://github.com/mindedsecurity/semgrep-rules-android-security
semgrep -c ./semgrep-rules-android-security/rules/crypto/ ./decompiled/sources/
```

#### Metode G — Analisis kualitas token secara statistik *(pembuktian tanpa akses kode)*

Ini jalur unik untuk test ini: kamu bisa membuktikan token berasal dari timestamp **tanpa membaca kode sama sekali**, cukup dari outputnya.

```bash
# 1. Kumpulkan banyak token dari aplikasi (via UI/API, atau hook Frida §3.5)
#    Catat WAKTU setiap token diperoleh.

# 2. Uji monotonisitas — token dari timestamp akan berurutan naik
sort -c tokens.txt && echo "[!] Token MONOTON -> indikasi kuat berbasis waktu"

# 3. Uji entropi — token dari CSPRNG mendekati 8 bit/byte
xxd -r -p tokens_hex.txt > tokens.bin
ent tokens.bin
#   Entropy < 6.0 bits/byte  => bukan dari CSPRNG

# 4. Uji korelasi selisih token vs selisih waktu
#    Bila delta_token ≈ delta_waktu(ms), token = timestamp
paste waktu_ms.txt tokens_dec.txt | awk 'NR>1 {print $1-pw, $2-pt} {pw=$1; pt=$2}'

# 5. Burp Sequencer — analisis statistik otomatis (FIPS test, entropi per-bit)
#    Intercept request yang mengembalikan token -> kirim ke Sequencer -> Start live capture
```

Burp Sequencer sangat efektif di sini: ia menjalankan rangkaian uji FIPS dan melaporkan estimasi entropi efektif per bit. Token berbasis timestamp akan menunjukkan entropi sangat rendah pada bit-bit tinggi.

#### Metode H — Frida untuk mengumpulkan sampel token *(pelengkap Metode G)*

Script di §3.5 sudah meng-hook sumber waktu. Untuk mengumpulkan **token yang dihasilkan** (bukan sumbernya), hook titik keluarannya:

```javascript
Java.perform(() => {
    // Contoh: hook metode yang mengembalikan token
    const Klass = Java.use("com.example.app.TokenGenerator");
    Klass.generate.implementation = function () {
        const t = this.generate();
        console.log(`${Date.now()}\t${t}`);     // timestamp host \t token
        return t;
    };
});
```

```bash
frida -U -f com.example.target -l collect_tokens.js -o tokens.tsv
# Lalu jalankan Metode G langkah 2–4 pada tokens.tsv
```

#### Metode I — Analisis kode native

```bash
unzip -o ./target-app.apk -d ./apk_x >/dev/null
for so in $(find ./apk_x -name "*.so"); do
  echo "--- $so"
  strings "$so" | grep -xE "time|gettimeofday|clock|clock_gettime|times|mktime"
done
```

---

### 3.7 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Butuh device? | Butuh source? | Rasio noise | Menjawab konteks? | Kapan dipakai |
|---|---|---|---|---|---|---|
| **A** | semgrep (MASTG) | Tidak | Tidak | **Sangat tinggi** | ❌ | Baseline resmi; **wajib ditriase** |
| **B** | ripgrep arah balik | Tidak | Tidak | **Rendah** | Manual | **Default yang aku rekomendasikan** — mulai dari sink |
| **C** | CodeQL | Tidak | Ya (ideal) | **Sangat rendah** | ✅ **otomatis** | **Terbaik** bila source tersedia |
| **D** | MobSF | Tidak | Tidak | Tinggi | ❌ | Laporan siap kutip |
| **E** | SonarQube/SonarLint | Tidak | Ya | Menengah | Sebagian | Shift-left di sisi developer; kuat untuk `new Random(seed)` |
| **F** | semgrep registry | Tidak | Tidak | Tinggi | ❌ | Cakupan rule lebih luas |
| **G** | Analisis token statistik / Burp Sequencer | Sebagian | **Tidak** | — | — | **Pembuktian tanpa akses kode**; bukti terkuat untuk laporan |
| **H** | Frida (kumpulkan token) | **Ya** | Tidak | — | ✅ (backtrace) | Pelengkap G; kode ter-obfuscate |
| **I** | `strings` / Ghidra | Tidak | Tidak | Menengah | Manual | APK dengan `.so` |

**Kombinasi minimum yang aku rekomendasikan:** **B (ripgrep arah balik) → G (analisis token)**.
B menekan noise dengan mulai dari titik konsumsi; G memberi bukti empiris yang sulit dibantah. Tambahkan **C (CodeQL)** bila source code tersedia — untuk test ini nilainya paling besar dibanding test lain, karena masalah utamanya justru rasio noise. Hindari melaporkan output mentah **A** atau **D** tanpa triase.

---

## 4. Rekomendasi Perbaikan

### 4.1 Prinsip Utama (MASTG-BEST-0001)

**Prioritas 1 — Jangan pakai waktu (atau sumber deterministik apa pun) sebagai sumber keacakan. Gunakan `SecureRandom`.**

MASTG-BEST-0001 menyatakan: *"Use a cryptographically secure pseudorandom number generator as provided by the platform or programming language you are using."* Untuk Java/Kotlin: `java.security.SecureRandom`, yang memenuhi uji statistik **FIPS 140-2 bagian 4.9.1** dan persyaratan kekuatan kriptografis **RFC 4086**. Ia menghasilkan output non-deterministik dan **melakukan seeding otomatis dari entropi sistem** saat inisialisasi.

```kotlin
// ❌ SALAH — semuanya deterministik / entropi sangat rendah
val t1 = Date().time.toInt()                                  // timestamp sebagai token
val t2 = Calendar.getInstance().get(Calendar.MILLISECOND)      // hanya 1.000 nilai
val t3 = System.currentTimeMillis()                            // dapat ditebak
val t4 = System.nanoTime()                                     // monoton, bukan acak
val t5 = Random(System.currentTimeMillis())                     // CWE-337: seed dapat ditebak
val t6 = sha256("${System.currentTimeMillis()}$androidId")      // hash tidak menambah entropi
val t7 = UUID.nameUUIDFromBytes(email.toByteArray())            // UUID v3 = deterministik

// ✅ BENAR — CSPRNG dengan konstruktor default
val secureRandom = SecureRandom()
val tokenBytes = ByteArray(32)
secureRandom.nextBytes(tokenBytes)
val token = Base64.encodeToString(tokenBytes, Base64.URL_SAFE or Base64.NO_WRAP)

// ✅ Atau, sesuai rekomendasi dokumentasi Android untuk Android modern
val rand = SecureRandom.getInstanceStrong()
val otp = 100000 + rand.nextInt(900000)
```

**Prioritas 2 — Lebih baik lagi: jangan generate sendiri, biarkan platform yang melakukannya.**

```kotlin
// ✅ Kunci: Android KeyStore — key material tidak pernah keluar dari secure hardware
val keyGen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
keyGen.init(
    KeyGenParameterSpec.Builder("myKey", KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
        .setRandomizedEncryptionRequired(true)
        .build()
)
keyGen.generateKey()

// ✅ IV/nonce: dihasilkan Cipher, bukan diturunkan dari waktu
val cipher = Cipher.getInstance("AES/GCM/NoPadding")
cipher.init(Cipher.ENCRYPT_MODE, key)
val iv = cipher.iv

// ✅ Identifier unik non-rahasia
val id = UUID.randomUUID()          // berbasis SecureRandom — BUKAN nameUUIDFromBytes()
```

**Prioritas 3 — Pindahkan pembuatan token security-critical ke server.** Untuk token reset password, OTP, dan session identifier, sisi klien bukan tempat yang tepat. Server punya sumber entropi yang lebih baik, dapat menerapkan rate limiting, dan tidak dapat diinspeksi penyerang lewat dekompilasi.

**Prioritas 4 — Pakai timestamp untuk tujuan yang benar saja.** Timestamp **boleh dan seharusnya** dipakai untuk expiry, TTL, pengukuran durasi, dan pencatatan waktu. Yang dilarang adalah memakainya **sebagai sumber entropi**.

```kotlin
// ✅ Pola yang benar — entropi dari CSPRNG, timestamp hanya untuk expiry
val random = ByteArray(32).also { SecureRandom().nextBytes(it) }
val token = Base64.encodeToString(random, Base64.URL_SAFE or Base64.NO_WRAP)
val expiresAt = System.currentTimeMillis() + 15 * 60 * 1000    // 15 menit
storeToken(token, expiresAt)
```

**Prioritas 5 — Bila butuh nilai deterministik yang aman, gunakan fungsi derivasi yang tepat.** Ini menjawab alasan paling umum developer memakai timestamp/ID perangkat sebagai seed: mereka butuh nilai yang **dapat direproduksi**. Solusinya bukan seed deterministik, melainkan **KDF berkunci**:

```kotlin
// ❌ SALAH — "reproducible" dengan seed deterministik
val key = sha256(androidId + installTimestamp)

// ✅ BENAR — HKDF dengan kunci master dari KeyStore
//    Reproducible, tetapi keamanannya bersandar pada kunci master, bukan pada input
val mac = Mac.getInstance("HmacSHA256").apply { init(masterKeyFromKeyStore) }
val derived = mac.doFinal("purpose:local-db-encryption".toByteArray())
```

Dokumentasi Android menyatakan: untuk output pseudorandom yang perlu reproducible, gunakan **HMAC, HKDF, atau SHAKE** — bukan `SecureRandom` dengan seed tetap.

**Prioritas 6 — Jangan pakai identifier perangkat sebagai rahasia.** `ANDROID_ID`, IMEI, serial, dan MAC address bersifat statis, sering dapat dibaca aplikasi/pihak lain, dan pada Android modern aksesnya dibatasi. Untuk kebutuhan "identitas instalasi", gunakan nilai dari `SecureRandom` yang di-generate sekali saat instalasi lalu disimpan di internal storage atau KeyStore.

**Prioritas 7 — Terapkan pertahanan berlapis (mitigasi, bukan perbaikan).** Perlu ditegaskan: langkah-langkah ini **tidak memperbaiki akar masalah** dan tidak mengubah temuan menjadi PASS. Namun tetap penting:
- **Rate limiting** ketat pada verifikasi token/OTP di sisi server
- **Masa berlaku pendek** (mis. 15 menit untuk token reset password)
- **Single-use token** — invalidasi setelah dipakai
- **Panjang token memadai** — minimal 128 bit entropi (16 byte acak)
- **Monitoring** terhadap percobaan token yang gagal secara beruntun

**Prioritas 8 — Tegakkan secara struktural.**
- Tambahkan rule SAST di CI/CD (semgrep MASTG + rule perluasan §3.4), dengan **allowlist untuk pemakaian timestamp yang sah** agar gate tidak selalu merah.
- Buat **satu utilitas terpusat** untuk semua kebutuhan acak security-relevant (`CryptoRandom.token()`, `CryptoRandom.bytes(n)`), lalu larang pembuatan nilai rahasia di luar utilitas itu lewat code review checklist atau lint kustom.
- Pertimbangkan **CodeQL taint analysis** di pipeline untuk melacak aliran sumber waktu → titik kripto secara otomatis, karena inilah yang tidak bisa dilakukan semgrep.
- Periksa framework cross-platform (Flutter/React Native/Unity) — jangan berasumsi API random atau ID bawaannya aman.

### 4.2 Checklist Remediasi

- [ ] Seluruh temuan semgrep sudah melalui triase, dan yang prioritas sudah ditinjau dengan MASTG-TECH-0023
- [ ] Untuk setiap temuan di fungsi helper, **semua pemanggilnya** sudah dilacak
- [ ] Tidak ada timestamp (`Date().getTime()`, `System.currentTimeMillis()`, `nanoTime()`, `SystemClock.*`, `Instant.now()`) yang dipakai sebagai sumber entropi
- [ ] Tidak ada `Calendar.get(...)` — khususnya `MILLISECOND` (literal `14`) — yang dipakai sebagai nilai "acak"
- [ ] Tidak ada PRNG yang di-seed dari waktu (`new Random(System.currentTimeMillis())`, `setSeed(...)`)
- [ ] Tidak ada identifier perangkat (`ANDROID_ID`, IMEI, serial, MAC) yang dipakai sebagai sumber acak atau rahasia
- [ ] Tidak ada counter/nilai berurutan yang dipakai sebagai token rahasia
- [ ] Tidak ada hash dari data yang diketahui (`md5(username+timestamp)`) yang dipakai sebagai nilai rahasia
- [ ] Tidak ada `UUID.nameUUIDFromBytes()` (deterministik) di konteks yang butuh tidak-terprediksi; gunakan `UUID.randomUUID()`
- [ ] Semua nilai security-relevant berasal dari `SecureRandom()` default atau `SecureRandom.getInstanceStrong()`
- [ ] Kunci dihasilkan `KeyGenerator`/`KeyPairGenerator` + Android KeyStore
- [ ] IV/nonce dihasilkan `Cipher` atau `SecureRandom`; **nonce GCM dijamin tidak pernah berulang** untuk kunci yang sama
- [ ] Salt KDF ≥ 16 byte dari `SecureRandom`
- [ ] Token security-critical (reset password, OTP, session) dihasilkan di **server**, bukan di klien
- [ ] Timestamp hanya dipakai untuk expiry/TTL/durasi/pencatatan — tidak sebagai entropi
- [ ] Nilai deterministik yang memang dibutuhkan diturunkan dengan **HKDF/HMAC berkunci KeyStore**, bukan dari seed deterministik
- [ ] Panjang token ≥ 128 bit entropi, single-use, dengan masa berlaku pendek
- [ ] Rate limiting diterapkan di sisi server untuk verifikasi token/OTP
- [ ] Sumber waktu dari kode native (`time`, `gettimeofday`, `clock`) tidak dipakai untuk keamanan
- [ ] Framework cross-platform diperiksa — API random/ID bawaannya benar-benar aman
- [ ] Utilitas acak terpusat dibuat; pembuatan nilai rahasia di luar utilitas itu dilarang
- [ ] Semua split APK / dynamic feature module ikut dianalisis
- [ ] Scan SAST terintegrasi di CI/CD dengan allowlist untuk pemakaian timestamp yang sah
- [ ] **Verifikasi ulang:** jalankan kembali MASTG-TEST-0205 + grep pelengkap → tidak ada sumber non-acak di konteks security-relevant
- [ ] **Verifikasi silang:** jalankan MASTG-TEST-0204 (PRNG lemah seperti `java.util.Random`)

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0205: Non-random Sources Usage](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0205/)
- [MASTG-TEST-0204: Insecure Random API Usage](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0204/)
- [MASWE-0012: Insecure Random Number Generation](https://mas.owasp.org/MASWE/MASVS-CRYPTO/MASWE-0012/)
- [MASTG-DEMO-0008: Uses of Non-random Sources](https://mas.owasp.org/MASTG/demos/android/MASVS-CRYPTO/MASTG-DEMO-0008/MASTG-DEMO-0008/)
- [MASTG-DEMO-0007: Common Uses of Insecure Random APIs](https://mas.owasp.org/MASTG/demos/android/MASVS-CRYPTO/MASTG-DEMO-0007/MASTG-DEMO-0007/)
- [MASTG-KNOW-0013: Random Number Generation](https://mas.owasp.org/MASTG/knowledge/android/MASVS-CRYPTO/MASTG-KNOW-0013/)
- [MASTG-BEST-0001: Use Secure Random Number Generator APIs](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0001/)
- [MASTG-TECH-0013: Reverse Engineering Android Apps](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/)
- [MASTG-TECH-0014: Static Analysis on Android](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/)
- [MASTG-TECH-0023: Reviewing Decompiled Java Code](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0023/)
- [MASTG-TOOL-0110: semgrep](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0110/)
- [MASTG-TOOL-0018: jadx](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0018/)
- [MASTG Rules — `mastg-android-non-random-use.yml`](https://github.com/OWASP/mastg/blob/master/rules/mastg-android-non-random-use.yml)
- [MASVS-CRYPTO: Cryptography](https://mas.owasp.org/MASVS/06-MASVS-CRYPTO/)
- [OWASP MASTG — Testing Cryptography (Random Number Generation)](https://mas.owasp.org/MASTG/0x05e-Testing-Cryptography/)
- [OWASP Cryptographic Storage Cheat Sheet — Secure Random Number Generation](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html#secure-random-number-generation)
- [OWASP Session Management Cheat Sheet — Session ID Entropy](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#session-id-entropy)
- [OWASP Forgot Password Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html)
- [OWASP Mobile Top 10 2024 — M10: Insufficient Cryptography](https://owasp.org/www-project-mobile-top-10/2023-risks/m10-insufficient-cryptography.html)

### 5.2 Dokumentasi Resmi Android / Google / Java

- [Weak PRNG — Android Security Risks](https://developer.android.com/privacy-and-security/risks/weak-prng)
- [`java.security.SecureRandom` — API reference](https://developer.android.com/reference/java/security/SecureRandom)
- [`java.util.Calendar` — API reference (konstanta field)](https://developer.android.com/reference/java/util/Calendar)
- [`java.util.Date` — API reference](https://developer.android.com/reference/java/util/Date)
- [`System.currentTimeMillis()` — API reference](https://developer.android.com/reference/java/lang/System#currentTimeMillis())
- [`SystemClock` — API reference](https://developer.android.com/reference/android/os/SystemClock)
- [`UUID` — API reference (`randomUUID` vs `nameUUIDFromBytes`)](https://developer.android.com/reference/java/util/UUID)
- [`KeyGenerator` — API reference](https://developer.android.com/reference/javax/crypto/KeyGenerator)
- [`KeyGenParameterSpec` — API reference](https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec)
- [Android Keystore system](https://developer.android.com/privacy-and-security/keystore)
- [Cryptography best practices](https://developer.android.com/privacy-and-security/cryptography)
- [Best practices for unique identifiers](https://developer.android.com/training/articles/user-data-ids)
- [Android Developers Blog — *Some SecureRandom Thoughts* (2013)](https://android-developers.googleblog.com/2013/08/some-securerandom-thoughts.html)
- [Google Tink — cryptographic library](https://developers.google.com/tink)

### 5.3 Standar, Taksonomi, dan Guideline Lain

- [CWE-341: Predictable from Observable State](https://cwe.mitre.org/data/definitions/341.html)
- [CWE-330: Use of Insufficiently Random Values](https://cwe.mitre.org/data/definitions/330.html)
- [CWE-337: Predictable Seed in Pseudo-Random Number Generator (PRNG)](https://cwe.mitre.org/data/definitions/337.html)
- [CWE-340: Generation of Predictable Numbers or Identifiers](https://cwe.mitre.org/data/definitions/340.html)
- [CWE-1241: Use of Predictable Algorithm in Random Number Generator](https://cwe.mitre.org/data/definitions/1241.html)
- [CWE-338: Use of Cryptographically Weak PRNG](https://cwe.mitre.org/data/definitions/338.html)
- [FIPS 140-2 — Security Requirements for Cryptographic Modules (section 4.9.1)](http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.140-2.pdf)
- [RFC 4086 — Randomness Requirements for Security](https://tools.ietf.org/html/rfc4086)
- [NIST SP 800-90A Rev.1 — Recommendation for Random Number Generation Using Deterministic RBGs](https://csrc.nist.gov/publications/detail/sp/800-90a/rev-1/final)
- [NIST SP 800-90B — Entropy Sources Used for Random Bit Generation](https://csrc.nist.gov/publications/detail/sp/800-90b/final)
- [NIST SP 800-108 Rev.1 — Recommendation for Key Derivation Using Pseudorandom Functions](https://csrc.nist.gov/publications/detail/sp/800-108/rev-1/final)
- [NIST SP 800-163 Rev.1 — Vetting the Security of Mobile Applications](https://csrc.nist.gov/publications/detail/sp/800-163/rev-1/final)
- [SEI CERT Oracle Coding Standard for Java — MSC02-J: Generate strong random numbers](https://wiki.sei.cmu.edu/confluence/display/java/MSC02-J.+Generate+strong+random+numbers)
- [SonarQube Rule java:S2245 — Using pseudorandom number generators (PRNGs) is security-sensitive](https://rules.sonarsource.com/java/RSPEC-2245/)
- [CodeQL — Java query help](https://codeql.github.com/codeql-query-help/java/)

### 5.4 Riset Keamanan & Artikel Teknis

- [turingpoint — CWE-330: Use of Insufficiently Random Values](https://turingpoint.de/en/vulnerability-database/CWE-330/)
- [CQR — Insecure Token Generation](https://cqr.company/web-vulnerabilities/insecure-token-generation-2/)
- [Offensive360 — Insecure Randomness](https://offensive360.com/knowledge-base/insecure-random/)
- [elttam — *Cracking the Odd Case of Randomness in Java*](https://www.elttam.com/blog/cracking-randomness-in-java)
- [Franklin Ta — *Predicting the next Math.random() in Java*](https://franklinta.com/2014/08/31/predicting-the-next-math-random-in-java/)
- [Practical CTF — Pseudo-Random Number Generators (PRNG)](https://book.jorianwoltjer.com/cryptography/pseudo-random-number-generators-prng)
- [Terse Systems — *The Right Way to Use SecureRandom*](https://tersesystems.com/blog/2015/12/17/the-right-way-to-use-securerandom/)
- [Baeldung — *Java SecureRandom*](https://www.baeldung.com/java-secure-random)
- [Bitcoin.org — Android Security Vulnerability (2013 alert)](https://bitcoin.org/en/alert/2013-08-11-android)
- [Zellic — *Proton, Dart/Flutter, and the CSPRNG that wasn't*](https://www.zellic.io/blog/proton-dart-flutter-csprng-prng/)
- [arXiv — *Measurements of the Most Significant Software Security Weaknesses*](https://arxiv.org/pdf/2104.05375)
- [HackTricks — Android Applications Pentesting](https://book.hacktricks.wiki/en/mobile-pentesting/android-app-pentesting/index.html)

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
- [Burp Suite — Sequencer (analisis kualitas token)](https://portswigger.net/burp/documentation/desktop/tools/sequencer)
- [ent — Pseudorandom number sequence test (entropi)](https://www.fourmilab.ch/random/)

---

*Dokumen ini disusun berdasarkan OWASP MASTG (rilis terkini per September 2026), dokumentasi resmi Android Developers, standar CWE/FIPS/NIST/RFC, serta riset keamanan pihak ketiga.*
