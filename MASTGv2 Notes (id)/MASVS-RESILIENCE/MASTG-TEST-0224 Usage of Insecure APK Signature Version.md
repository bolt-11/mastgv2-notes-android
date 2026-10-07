# MASTG-TEST-0224 Usage of Insecure APK Signature Version

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0224 |
| **Platform** | Android |
| **Kategori MASVS** | **MASVS-RESILIENCE** (Resilience Against Reverse Engineering and Tampering) |
| **Weakness** | **MASWE-0056** — *Usage of Insecure APK Signature Version* |
| **Tipe Pengujian** | **Static**, Code |
| **Profile** | **R** (Resilience) — lihat §1.2 untuk penjelasan profile ini |
| **`available_since`** | **24** — relevansi test ini terikat pada API level 24 (kemunculan v2 scheme), lihat §1.3 |
| **Knowledge** | MASTG-KNOW-0003 (App Signing) |
| **Best Practice** | MASTG-BEST-0006 (Use Up-to-Date APK Signing Schemes) |
| **Teknik terkait** | MASTG-TECH-0117 (Obtaining Information from the AndroidManifest), MASTG-TECH-0150 (Analyzing the AndroidManifest), MASTG-TECH-0116 (Obtaining Information about the APK Signature) |
| **Demo terkait** | — (MASTG belum menyediakan demo untuk test ini) |
| **CVE terkait** | **CVE-2017-13156** ("Janus") |
| **CWE terkait** | CWE-345 (Insufficient Verification of Data Authenticity), CWE-353 (Missing Support for Integrity Check), CWE-494 (Download of Code Without Integrity Check) |

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian

Kutipan langsung dari overview MASTG:

> *"Not using newer APK signing schemes means that the app lacks the enhanced security provided by more robust, updated mechanisms."*
>
> *"This test checks if the **outdated v1 signature scheme** is enabled. The v1 scheme is vulnerable to certain attacks, such as the **'Janus' vulnerability** (CVE-2017-13156), because it **does not cover all parts of the APK file**, allowing malicious actors to potentially **modify parts of the APK without invalidating the signature**. Relying solely on v1 signing therefore increases the risk of tampering and compromises app security."*

Test ini murni tentang **konfigurasi penandatanganan (signing) APK** — bukan tentang kode aplikasi. Tujuannya memverifikasi bahwa aplikasi tidak **hanya** mengandalkan skema tanda tangan v1 (JAR signing) yang sudah usang, melainkan juga menggunakan skema v2/v3 yang lebih kuat.

### 1.2 Mengapa Profile-nya "R" (Resilience), Bukan L1/L2

Ini pola pikir penting untuk memahami *kenapa* test ini ada dan bagaimana ia berbeda dari test-test kripto/storage yang sudah kita bahas sebelumnya.

Profile **R** ditujukan khusus untuk *"apps that require resilience against reverse engineering and tampering, independently of the security level"* — terpisah dari L1 (keamanan dasar) dan L2 (keamanan tinggi untuk data sensitif). Profile R relevan untuk aplikasi di mana **binary itu sendiri adalah target serangan**: aplikasi dengan konten berlisensi DRM, aplikasi pembayaran, aplikasi dengan algoritma proprietary, atau aplikasi di mana bypass logika sisi klien dapat menyebabkan kerugian finansial langsung.

Konsekuensi praktisnya untuk test ini: **integritas APK** (memastikan APK tidak dimodifikasi sejak ditandatangani developer) adalah pertahanan lini pertama terhadap **tampering** — memodifikasi APK resmi untuk menyisipkan kode jahat, menghapus pengecekan lisensi, atau membajak logika bisnis, lalu mendistribusikannya kembali (repackaging) seolah-olah itu aplikasi asli. Ini berbeda secara kualitatif dari test MASVS-STORAGE/CRYPTO yang berfokus pada *bagaimana data ditangani*, bukan *apakah binary aplikasi itu sendiri autentik*.

### 1.3 Signifikansi `available_since: 24`

Field ini menandakan bahwa relevansi test ini terikat erat dengan **Android 7.0 (API level 24)** — versi Android tempat **APK Signature Scheme v2** pertama kali diperkenalkan. Ini konteks penting untuk memahami kriteria evaluasi di §3.9: kriteria FAIL secara eksplisit hanya berlaku untuk aplikasi dengan `minSdkVersion` ≥ 24, karena di bawah versi itu, v2 signing **bahkan tidak dapat dipakai** (tidak didukung platform) — sehingga mengandalkan v1 saja bukanlah pilihan yang salah, melainkan **satu-satunya opsi yang tersedia**.

### 1.4 Tiga (Sebenarnya Empat) Skema Penandatanganan APK

MASTG-KNOW-0003 mendaftar skema-skema ini beserta dukungan versi Android-nya:

| Skema | Diperkenalkan di | Cara kerja | Cakupan perlindungan |
|---|---|---|---|
| **v1 (JAR signing)** | Android 1.0 | Menandatangani setiap **entri ZIP secara individual** dalam manifest `META-INF/MANIFEST.MF` | **Hanya** entri ZIP yang secara eksplisit terdaftar — **tidak mencakup byte tambahan** di luar entri ZIP |
| **v2 (APK Signature Scheme v2)** | Android 7.0 (API 24) | Menandatangani **seluruh konten file APK sebagai satu blok** (whole-file signing), disisipkan di antara *Central Directory* dan *End of Central Directory* pada format ZIP | **Seluruh byte APK** — jauh lebih komprehensif |
| **v3 (APK Signature Scheme v3)** | Android 9 (API 28) | Sama seperti v2, ditambah dukungan **key rotation** — memungkinkan developer mengganti kunci signing seiring waktu sambil tetap mempertahankan kompatibilitas dengan kunci lama | Sama seperti v2, plus fleksibilitas rotasi kunci |
| **v3.1** | Android 11+ | Varian v3 dengan penanganan rotasi kunci berbasis target SDK yang lebih baik | Sama seperti v3 |
| **v4** | Android 11 (API 30) | Skema tambahan untuk mendukung **incremental APK installation** (ADB Incremental / Android App Bundle) | **Bukan pengganti** v2/v3 — v4 **wajib dipasangkan** dengan v2 atau v3, tidak memberi proteksi integritas sendiri |

MASTG-KNOW-0003 menegaskan prinsip penting: *"For each signing scheme the release builds should always be signed via all its previous schemes as well."* — artinya APK modern yang benar akan menunjukkan **v1 = true, v2 = true, v3 = true** sekaligus (bukan salah satu saja), demi kompatibilitas mundur dengan perangkat Android versi lama yang belum mendukung v2/v3.

**MASTG-BEST-0006 menegaskan ulang untuk v4:** *"v4 alone does not provide security protections and should be used alongside v2 or v3."* — ini poin yang sering disalahpahami: mengaktifkan v4 **tanpa** v2/v3 tidak memberi manfaat keamanan apa pun, hanya manfaat kecepatan instalasi.

### 1.5 Kerentanan "Janus" (CVE-2017-13156) — Mengapa v1 Saja Berbahaya

Ini kerentanan yang menjadi alasan utama keberadaan test ini, dinamai sesuai dewa Romawi berwajah dua (Janus) — merujuk pada kemampuan sebuah file untuk menjadi **dua hal sekaligus secara valid**.

**Akar masalah teknis:** sebuah file dapat menjadi APK yang valid **dan** file DEX yang valid **secara bersamaan**. Ini dimungkinkan karena:

- Format **APK adalah arsip ZIP**, yang secara spesifikasi mengizinkan byte tambahan sembarang **sebelum** dan **di antara** entri-entri ZIP-nya, tanpa merusak validitas arsip ZIP itu sendiri.
- **Skema tanda tangan v1 hanya memperhitungkan entri ZIP** yang terdaftar dalam manifest — ia **mengabaikan byte tambahan apa pun** di luar entri-entri tersebut saat menghitung atau memverifikasi tanda tangan aplikasi.

**Cara eksploitasinya:**

1. Penyerang mengambil DEX file jahat (berisi payload/malware).
2. Penyerang **menyisipkan (prepend)** seluruh isi APK asli yang sudah ditandatangani secara sah, **setelah** DEX jahat tersebut.
3. Hasilnya adalah satu file yang: (a) tetap merupakan **APK ZIP yang valid** karena entri ZIP asli masih ada di lokasi yang benar relatif terhadap akhir file, **dan** (b) juga merupakan **file DEX yang valid** karena dimulai dengan header DEX yang sah.
4. Karena Android Runtime (Dalvik/ART pada versi yang rentan) memuat file ini **sebagai DEX terlebih dahulu** — sementara sistem verifikasi tanda tangan v1 memverifikasinya **sebagai APK** dan hanya memeriksa entri ZIP yang tidak berubah — **tanda tangan tetap valid**, meski secara efektif kode yang benar-benar dieksekusi adalah DEX jahat yang disisipkan di depan.

**Dampak dan cakupan:**

- Kerentanan ini memengaruhi perangkat Android **5.1.1 hingga 8.0** — pada saat ditemukan (2017), ini mencakup **sekitar 74% dari seluruh perangkat Android** yang aktif.
- **APK yang ditandatangani dengan skema v2 terlindungi** dari kerentanan ini, karena — berbeda dari v1 — v2 memperhitungkan **seluruh byte dalam file APK**, sehingga penyisipan byte tambahan apa pun (seperti DEX jahat di depan) akan **langsung membatalkan validitas tanda tangan**.
- GuardSquare melaporkan kerentanan ini ke Google pada 31 Juli 2017; Google merilis patch ke mitra pada November 2017 dan mempublikasikan CVE-2017-13156 pada Android Security Bulletin Desember 2017.

**Mengapa ini penting di luar "sekadar versi lama":** Janus bukan kerentanan teoretis — ia memungkinkan penyerang **mendistribusikan ulang aplikasi yang tampak identik** (nama paket, ikon, tanda tangan developer yang "valid" menurut v1) tetapi sebenarnya menjalankan kode berbahaya. Ini jenis serangan **repackaging/tampering** yang persis menjadi fokus profile Resilience (§1.2) — mengancam integritas dan reputasi merek aplikasi, bukan hanya data pengguna individual.

### 1.6 Mengapa Ini Bukan Sekadar "Pakai Skema Terbaru"

Poin nuansa yang perlu dipahami: kriteria evaluasi MASTG **tidak** mensyaratkan v3 atau v4 — ia hanya mensyaratkan **bukan hanya v1**. Ini karena:

- **v2 saja sudah cukup** untuk menutup celah Janus, karena v2 sudah memvalidasi seluruh byte APK.
- **v3 memberi manfaat tambahan** (key rotation) tetapi bukan syarat mutlak untuk lolos test ini — meski MASTG-BEST-0006 tetap merekomendasikannya *"for optimal security and compatibility"*.
- **v4 tidak relevan untuk keamanan** dalam konteks test ini sama sekali — ia murni fitur performa instalasi.

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | MASTG ID | Fungsi |
|---|---|---|
| **apksigner** | MASTG-TOOL-0123 | **Tool resmi MASTG dan resmi Android SDK.** Satu-satunya tool yang dapat memverifikasi skema v3/v3.1/v4 secara definitif |
| **jadx / apktool** | MASTG-TOOL-0018 / 0011 | Ekstraksi `AndroidManifest.xml` untuk mendapatkan `minSdkVersion` |
| **aapt2** | MASTG-TOOL-0124 | Alternatif cepat untuk membaca `minSdkVersion` tanpa dekompilasi penuh |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **apkanalyzer** (bagian Android SDK) | Alternatif dari Google — menampilkan info signing di tab APK Analyzer Android Studio, atau via CLI |
| **unzip / zipinfo** | Verifikasi manual keberadaan `META-INF/MANIFEST.MF`, `.SF`, `.RSA`/`.DSA` (indikasi v1) — pelengkap bukti visual |
| **Python `pyaxmlparser` / `androguard`** | Scripting untuk audit massal banyak APK sekaligus, ekstraksi `minSdkVersion` dan info signing terprogram |
| **MobSF** | Analisis otomatis, melaporkan skema signing yang dipakai dalam laporan APK |
| **Frida/Objection** | Tidak relevan langsung untuk test ini (test bersifat statis murni pada file APK, bukan pada aplikasi yang berjalan) |
| **VirusTotal / Koodous** | Untuk APK yang sudah beredar di publik, dapat memeriksa metadata signing tanpa perlu mengunduh file secara manual |

### 2.3 Prasyarat Lingkungan

- **Tidak butuh device dan tidak butuh root** — cukup file APK. Sepenuhnya dapat diotomatisasi di CI/CD.
- **Gunakan APK yang benar-benar dirilis (release build)**, bukan debug build development — konfigurasi signing sering berbeda drastis antara keduanya, dan debug build tidak relevan untuk penilaian keamanan produksi.
- **`apksigner` adalah bagian dari Android SDK Build-Tools** — pastikan tersedia di `$ANDROID_HOME/build-tools/<versi>/apksigner`, atau instal terpisah via `sdkmanager`.
- **Periksa APK final yang didistribusikan**, bukan hanya AAB (Android App Bundle) mentah — Google Play melakukan re-signing pada APK yang di-generate dari AAB, sehingga skema signing pada APK yang benar-benar terpasang di perangkat pengguna bisa berbeda dari yang terlihat di file build lokal. Untuk audit yang representatif, ambil APK hasil `bundletool` yang mensimulasikan proses Play Store, atau ekstrak langsung dari perangkat yang sudah menginstal aplikasi tersebut.

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0117** (*Obtaining Information from the AndroidManifest*) untuk mendapatkan `AndroidManifest.xml`.
2. Gunakan **MASTG-TECH-0150** (*Analyzing the AndroidManifest*) untuk mendapatkan atribut `minSdkVersion` dari manifest.
3. Gunakan **MASTG-TECH-0116** (*Obtaining Information about the APK Signature*) untuk mendaftar semua skema tanda tangan yang dipakai.

### 3.2 Metode A — apksigner *(resmi MASTG dan resmi Android)*

**Langkah 1 — Dapatkan `minSdkVersion`:**

```bash
# Via aapt2 (tercepat, tanpa dekompilasi)
aapt2 d badging YourApp.apk | grep -E "sdkVersion|minSdkVersion"

# Via jadx (bila sudah dekompilasi untuk keperluan lain)
jadx --no-src -d out_dir YourApp.apk
grep -i "minSdkVersion" out_dir/resources/AndroidManifest.xml

# Via apktool
apktool d -f -o out_dir YourApp.apk
cat out_dir/apktool.yml | grep -A2 sdkInfo
```

**Langkah 2 — Verifikasi skema tanda tangan:**

```bash
apksigner verify --verbose YourApp.apk
```

Contoh output resmi MASTG-TECH-0116:

```
Verifies
Verified using v1 scheme (JAR signing): false
Verified using v2 scheme (APK Signature Scheme v2): true
Verified using v3 scheme (APK Signature Scheme v3): true
Verified using v3.1 scheme (APK Signature Scheme v3.1): false
Verified using v4 scheme (APK Signature Scheme v4): false
Verified for SourceStamp: false
Number of signers: 1
```

**Langkah 3 (opsional) — Detail sertifikat penandatangan**, berguna untuk verifikasi identitas developer dan validitas masa berlaku sertifikat:

```bash
apksigner verify --print-certs --verbose YourApp.apk
```

```
Signer #1 certificate DN: CN=Example Developers, OU=Android, O=Example
Signer #1 certificate SHA-256 digest: 1fc4de52d0daa33a9c0e3d67217a77c895b46266ef020fad0d48216a6ad6cb70
Signer #1 key algorithm: RSA
Signer #1 key size (bits): 2048
```

### 3.3 Metode B — apkanalyzer *(alternatif langsung dari Android SDK)*

```bash
# Via CLI (bagian dari Android SDK cmdline-tools)
apkanalyzer apk summary YourApp.apk

# Via Android Studio: Build > Analyze APK... > lihat panel signing info
```

Keunggulan: terintegrasi langsung dalam workflow Android Studio, memudahkan developer memeriksa sendiri sebelum rilis tanpa berpindah ke terminal.

### 3.4 Metode C — androguard / pyaxmlparser *(scripting untuk audit massal)*

Berguna ketika kamu perlu mengaudit **banyak APK sekaligus** (mis. seluruh portofolio aplikasi organisasi, atau memantau rilis kompetitor).

```python
# check_signing.py
from androguard.core.apk import APK
import subprocess
import glob

def check_signing_schemes(apk_path):
    result = subprocess.run(
        ["apksigner", "verify", "--verbose", apk_path],
        capture_output=True, text=True
    )
    return result.stdout

def get_min_sdk(apk_path):
    a = APK(apk_path)
    return a.get_min_sdk_version()

for apk_path in glob.glob("./apks/*.apk"):
    min_sdk = get_min_sdk(apk_path)
    signing_info = check_signing_schemes(apk_path)
    v1 = "v1 scheme (JAR signing): true" in signing_info
    v2 = "v2 scheme (APK Signature Scheme v2): true" in signing_info
    v3 = "v3 scheme (APK Signature Scheme v3): true" in signing_info

    verdict = "FAIL" if (int(min_sdk) >= 24 and v1 and not v2 and not v3) else "PASS"
    print(f"{apk_path}: minSdk={min_sdk}, v1={v1}, v2={v2}, v3={v3} -> {verdict}")
```

```bash
pip install androguard
python3 check_signing.py
```

### 3.5 Metode D — Verifikasi manual struktur ZIP *(bukti pendukung visual)*

Ini bukan pengganti `apksigner`, tetapi berguna sebagai **bukti tambahan yang mudah dipahami** dalam laporan — menunjukkan secara visual keberadaan (atau ketiadaan) artefak masing-masing skema.

```bash
# v1 (JAR signing) meninggalkan jejak berupa file di META-INF/
unzip -l YourApp.apk | grep -E "META-INF/(MANIFEST\.MF|.*\.SF|.*\.(RSA|DSA|EC))"
# Contoh output bila v1 aktif:
#   META-INF/MANIFEST.MF
#   META-INF/CERT.SF
#   META-INF/CERT.RSA

# v2/v3 tidak meninggalkan jejak file terpisah di dalam struktur ZIP -
# blok tanda tangannya disisipkan di antara Central Directory dan
# End of Central Directory, sehingga TIDAK terlihat lewat `unzip -l` biasa.
# Untuk itu, apksigner/APK Signing Block parser tetap WAJIB dipakai untuk v2/v3.
```

> **Peringatan penting:** ketiadaan file `META-INF/*.RSA` **tidak serta-merta membuktikan** v1 nonaktif dengan pasti dalam semua kasus edge, dan yang lebih krusial: **kamu tidak bisa memverifikasi v2/v3 sama sekali** hanya dengan melihat struktur ZIP, karena keduanya memang tidak meninggalkan artefak file yang terlihat lewat `unzip -l`. **Selalu gunakan `apksigner` sebagai sumber kebenaran utama** — metode ini murni pelengkap ilustratif.

### 3.6 Metode E — MobSF *(otomatis, laporan siap kutip)*

```bash
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest
```

Upload APK → cari bagian **Certificate Analysis** / **APK Signing Scheme** di laporan. MobSF biasanya menampilkan status v1/v2/v3 sekaligus flag peringatan bila hanya v1 yang aktif, dan detail sertifikat (validitas, algoritma, ukuran kunci) dalam satu tampilan.

### 3.7 Metode F — bundletool *(untuk APK yang didistribusikan via Android App Bundle)*

Karena mayoritas aplikasi modern dirilis dalam format **AAB**, penting menguji APK **hasil generate** yang benar-benar akan sampai ke perangkat pengguna — bukan AAB mentah itu sendiri (yang tidak ditandatangani dengan skema yang sama).

```bash
# Generate APK set dari AAB, mensimulasikan proses Google Play
bundletool build-apks --bundle=YourApp.aab --output=YourApp.apks \
  --ks=release.keystore --ks-key-alias=release

# Ekstrak APK dasar untuk diverifikasi
unzip -p YourApp.apks universal.apk > universal_extracted.apk
apksigner verify --verbose universal_extracted.apk
```

### 3.8 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Memverifikasi v1? | Memverifikasi v2/v3/v4 secara definitif? | Cocok untuk audit massal? | Kapan dipakai |
|---|---|---|---|---|---|
| **A** | apksigner (MASTG) | ✅ | ✅ **(satu-satunya yang pasti)** | Sedang (perlu scripting) | **Baseline resmi — wajib dipakai** |
| **B** | apkanalyzer | ✅ | ✅ | Rendah | Verifikasi cepat di dalam Android Studio |
| **C** | androguard/pyaxmlparser | ✅ (via apksigner internal) | ✅ | ✅ **(terbaik untuk skala besar)** | Audit portofolio banyak APK, integrasi CI |
| **D** | unzip / zipinfo manual | Sebagian (indikatif) | ❌ **(tidak bisa)** | Rendah | **Hanya bukti pendukung visual**, bukan sumber kebenaran |
| **E** | MobSF | ✅ | ✅ | Sebagian | Laporan menyeluruh siap kutip |
| **F** | bundletool | ✅ (pada hasil generate) | ✅ | Sedang | Aplikasi yang dirilis via AAB — representasi APK sebenarnya |

**Kombinasi minimum yang aku rekomendasikan:** **A (apksigner) selalu, tanpa terkecuali**.
Ini test di mana satu tool resmi (`apksigner`) sudah memberi jawaban definitif dan lengkap — tidak seperti test statis kode lain yang butuh banyak jalur untuk menutup celah rule. Tambahkan **F (bundletool)** bila aplikasi dirilis via AAB agar kamu menguji APK yang benar-benar representatif, dan **C (androguard)** bila perlu mengaudit banyak APK sekaligus secara otomatis.

---

### 3.9 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG:**

> **Observation:** *"The output should contain the value of the `minSdkVersion` attribute and the used signature schemes (for example `Verified using v3 scheme (APK Signature Scheme v3): true`)."*
>
> **Evaluation:** *"The test case **fails** if the app has a `minSdkVersion` attribute of **24 and above**, and **only the v1 signature scheme** is enabled."*

Perhatikan bahwa kriteria FAIL ini adalah **kombinasi dua kondisi yang harus terpenuhi bersamaan**:

1. `minSdkVersion` ≥ 24, **DAN**
2. Hanya v1 yang aktif (v2/v3/v3.1/v4 semuanya `false`)

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi | Contoh bukti |
|---|---|---|
| F1 | `minSdkVersion` ≥ 24 **dan** hanya v1 yang `true`, v2/v3 keduanya `false` | `minSdkVersion: 26`; `apksigner verify` → v1: true, v2: false, v3: false |
| F2 | `minSdkVersion` ≥ 28 (mendukung v3) tetapi hanya v1 yang aktif | Kehilangan manfaat tambahan v3 (key rotation) sekaligus rentan Janus |
| F3 | v4 diaktifkan **sendirian** tanpa v2/v3 (kombinasi tidak valid secara keamanan) | `apksigner verify` → v1: true, v2: false, v3: false, v4: true — v4 tidak memberi proteksi integritas mandiri |
| F4 | APK hasil `bundletool`/rilis Play Store menunjukkan hasil berbeda dari APK build lokal — hanya v1 pada APK final | Verifikasi dengan Metode F menunjukkan downgrade skema signing pada tahap distribusi |
| F5 | Aplikasi rentan Janus dapat direproduksi: DEX jahat dapat disisipkan di depan APK asli tanpa membatalkan verifikasi v1 | Uji PoC (§3.5 sebagai indikasi, verifikasi definitif tetap via `apksigner`) |

**Contoh bukti (ilustratif — MASTG belum menyediakan demo resmi untuk test ini):**

```bash
$ aapt2 d badging LegacyApp.apk | grep sdkVersion
sdkVersion:'26'

$ apksigner verify --verbose LegacyApp.apk
Verifies
Verified using v1 scheme (JAR signing): true
Verified using v2 scheme (APK Signature Scheme v2): false
Verified using v3 scheme (APK Signature Scheme v3): false
Verified using v3.1 scheme (APK Signature Scheme v3.1): false
Verified using v4 scheme (APK Signature Scheme v4): false
Number of signers: 1
```

Interpretasi: `minSdkVersion` 26 (≥ 24) **dan** hanya v1 yang aktif → **FAIL**. Aplikasi ini berpotensi rentan terhadap Janus (CVE-2017-13156) pada perangkat Android 5.1.1–8.0, dan secara umum kehilangan proteksi integritas menyeluruh yang diberikan v2/v3.

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi | Contoh bukti |
|---|---|---|
| P1 | `minSdkVersion` ≥ 24 **dan** v2 dan/atau v3 aktif (terlepas apakah v1 juga aktif untuk kompatibilitas mundur) | `apksigner verify` → v1: true, v2: true, v3: true |
| P2 | `minSdkVersion` < 24 **dan** hanya v1 yang aktif | Wajar — v2 tidak didukung platform target sama sekali (§1.3) |
| P3 | v4 aktif **bersamaan** dengan v2/v3 (bukan sendirian) | v2: true, v3: true, v4: true — kombinasi valid, v4 memberi manfaat kecepatan instalasi tanpa mengorbankan keamanan |
| P4 | APK hasil rilis final (via bundletool/Play Store) menunjukkan skema yang sama amannya dengan build lokal | Diverifikasi dengan Metode F |

**Contoh output yang menandakan PASS:**

```bash
$ aapt2 d badging ModernApp.apk | grep sdkVersion
sdkVersion:'26'

$ apksigner verify --verbose ModernApp.apk
Verifies
Verified using v1 scheme (JAR signing): true
Verified using v2 scheme (APK Signature Scheme v2): true
Verified using v3 scheme (APK Signature Scheme v3): true
Verified using v3.1 scheme (APK Signature Scheme v3.1): false
Verified using v4 scheme (APK Signature Scheme v4): false
Number of signers: 1
```

Interpretasi: `minSdkVersion` 26, dan v2 **serta** v3 aktif → **PASS**. Kehadiran v1 = true di sini **bukan masalah** — justru direkomendasikan MASTG-KNOW-0003 untuk kompatibilitas mundur dengan perangkat pra-API 24, selama v2/v3 juga aktif untuk melindungi seluruh integritas file pada perangkat yang mendukungnya.

Contoh PASS lain — aplikasi dengan target device sangat lama:

```bash
$ aapt2 d badging OldTargetApp.apk | grep sdkVersion
sdkVersion:'19'

$ apksigner verify --verbose OldTargetApp.apk
Verifies
Verified using v1 scheme (JAR signing): true
Verified using v2 scheme (APK Signature Scheme v2): false
Number of signers: 1
```

Interpretasi: `minSdkVersion` 19 (< 24) — v2 memang tidak dapat didukung untuk kasus ini karena platform target tidak mengenalnya. **PASS**, meski hanya v1 yang aktif — ini konsisten dengan §1.3.

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **v1 = true bukan masalah selama v2/v3 juga true.** Ini kesalahan interpretasi yang paling umum. Kriteria FAIL adalah "**hanya** v1" — bukan "v1 aktif sama sekali". Kehadiran v1 di samping v2/v3 justru merupakan **praktik yang benar** untuk kompatibilitas mundur.

2. **Perhatikan `minSdkVersion`, bukan `targetSdkVersion`.** Kriteria evaluasi MASTG secara eksplisit merujuk `minSdkVersion` — atribut yang menentukan versi Android **paling rendah** yang didukung aplikasi. `targetSdkVersion` (versi yang jadi target optimasi) tidak relevan untuk penentuan kriteria FAIL/PASS di test ini.

3. **v4 sendirian tanpa v2/v3 harus dilaporkan sebagai temuan (F3)**, meski secara literal tidak disebutkan eksplisit dalam kriteria FAIL resmi (yang berfokus pada "hanya v1"). Ini konsisten dengan penegasan MASTG-BEST-0006 bahwa v4 tanpa v2/v3 **tidak memberi proteksi keamanan apa pun** — kombinasi ini secara praktik sama bermasalahnya dengan hanya mengandalkan v1, meski secara teknis bukan skenario yang persis dijelaskan di kriteria evaluasi resmi.

4. **Uji APK final yang didistribusikan, bukan hanya build lokal.** Proses signing Google Play App Signing dapat menghasilkan APK akhir dengan konfigurasi berbeda dari yang kamu lihat di mesin development. Selalu verifikasi APK yang benar-benar terpasang di perangkat pengguna, idealnya diekstrak langsung dari perangkat atau melalui `bundletool` yang mensimulasikan proses distribusi.

5. **Verifikasi manual struktur ZIP (Metode D) tidak bisa membuktikan v2/v3.** Jangan menyimpulkan status v2/v3 hanya dari ketiadaan/keberadaan file di `META-INF/` — v2/v3 disisipkan di lokasi ZIP yang berbeda dan tidak terlihat lewat `unzip -l`. `apksigner` adalah satu-satunya sumber kebenaran yang bisa diandalkan.

6. **Sertakan bukti PoC Janus bila memungkinkan** (dalam lingkup pengujian yang diizinkan) untuk memperkuat temuan FAIL — menunjukkan secara konkret bahwa DEX jahat dapat disisipkan tanpa membatalkan verifikasi tanda tangan v1 jauh lebih meyakinkan bagi stakeholder non-teknis daripada sekadar menyebut nomor CVE.

7. **Severity dimodulasi oleh konteks aplikasi (mengingat ini profile R):**

   | Faktor | Severity |
   |---|---|
   | Aplikasi finansial/pembayaran/DRM dengan `minSdkVersion` ≥ 24, hanya v1 | **Tinggi** — risiko repackaging langsung berdampak pada kerugian finansial atau pembajakan konten |
   | Aplikasi umum non-kritis dengan `minSdkVersion` ≥ 24, hanya v1 | **Menengah** |
   | `minSdkVersion` < 24, hanya v1 (wajar secara teknis) | **Bukan temuan** |
   | v1 + v2/v3 aktif bersamaan | **Bukan temuan** |
   | v4 aktif tanpa v2/v3 | **Menengah** — kesalahan konfigurasi yang perlu diperbaiki meski bukan risiko separah "hanya v1" pada rentang perangkat rentan Janus |

8. **Dokumentasikan:** `minSdkVersion` aplikasi, output lengkap `apksigner verify --verbose`, versi Android mana yang terdampak potensi Janus bila FAIL (5.1.1–8.0), detail sertifikat (`--print-certs`) untuk verifikasi identitas developer, dan apakah APK yang diuji adalah build lokal atau hasil distribusi final (bundletool/Play Store).

---

## 4. Rekomendasi Perbaikan

### 4.1 Prinsip Utama (MASTG-BEST-0006)

MASTG-BEST-0006 menyatakan:

> *"Ensure that the app is signed with **at least the v2 or v3** APK signing scheme, as these provide comprehensive integrity checks and protect the entire APK from tampering. For optimal security and compatibility, consider using **v3**, which also supports key rotation."*

**Prioritas 1 — Aktifkan v2 dan v3 signing di konfigurasi build.**

```kotlin
// build.gradle.kts
android {
    signingConfigs {
        create("release") {
            storeFile = file("release.keystore")
            storePassword = System.getenv("KEYSTORE_PASSWORD")
            keyAlias = "release"
            keyPassword = System.getenv("KEY_PASSWORD")

            enableV1Signing = true   // pertahankan untuk kompatibilitas mundur (< API 24)
            enableV2Signing = true   // WAJIB — menutup celah Janus
            enableV3Signing = true   // direkomendasikan — mendukung key rotation
        }
    }
}
```

```groovy
// build.gradle (Groovy)
android {
    signingConfigs {
        release {
            storeFile file("release.keystore")
            storePassword System.getenv("KEYSTORE_PASSWORD")
            keyAlias "release"
            keyPassword System.getenv("KEY_PASSWORD")

            enableV1Signing true
            enableV2Signing true
            enableV3Signing true
        }
    }
}
```

**Prioritas 2 — Bila menambahkan v4, selalu pasangkan dengan v2/v3.**

```kotlin
signingConfigs {
    create("release") {
        // ...
        enableV3Signing = true
        enableV4Signing = true   // manfaat incremental install, BUKAN pengganti v2/v3
    }
}
```

**Prioritas 3 — Pertimbangkan Google Play App Signing.** Ini layanan Google yang mengelola kunci signing final atas nama developer, secara otomatis menerapkan skema signing terkini sesuai kebijakan Play Store, sekaligus memberi proteksi tambahan (kunci upload terpisah dari kunci signing final, sehingga kompromi kunci upload tidak langsung mengekspos kunci signing produksi).

**Prioritas 4 — Verifikasi signing sebagai bagian dari pipeline rilis.** Tambahkan pemeriksaan otomatis `apksigner verify` sebagai gate sebelum APK/AAB final di-approve untuk distribusi:

```bash
#!/bin/bash
# ci-verify-signing.sh
APK=$1
MIN_SDK=$(aapt2 d badging "$APK" | grep -oP "sdkVersion:'?\K[0-9]+")
V2=$(apksigner verify --verbose "$APK" | grep "v2 scheme" | grep -c "true")
V3=$(apksigner verify --verbose "$APK" | grep "v3 scheme" | grep -c "true")

if [ "$MIN_SDK" -ge 24 ] && [ "$V2" -eq 0 ] && [ "$V3" -eq 0 ]; then
    echo "[GAGAL] APK hanya menggunakan v1 signing dengan minSdkVersion >= 24"
    exit 1
fi
echo "[OK] Konfigurasi signing memadai"
```

**Prioritas 5 — Naikkan `minSdkVersion` bila relevan bisnis mengizinkan.** Basis pengguna Android < 7.0 (API 24) sangat kecil pada 2026 di mayoritas pasar. Menaikkan `minSdkVersion` ke ≥ 24 memastikan v2 signing selalu tersedia dan dipakai, sekaligus membuka akses ke berbagai perbaikan keamanan platform lain yang diperkenalkan sejak API 24.

**Prioritas 6 — Verifikasi APK final pasca-distribusi, bukan hanya build lokal.** Terutama untuk aplikasi yang memakai Google Play App Signing atau distribusi via AAB — audit APK yang benar-benar sampai ke perangkat pengguna secara berkala (§3.7).

### 4.2 Checklist Remediasi

- [ ] `minSdkVersion` aplikasi diketahui dan didokumentasikan
- [ ] Bila `minSdkVersion` ≥ 24: v2 signing diaktifkan (`enableV2Signing = true`)
- [ ] v3 signing diaktifkan untuk mendapatkan dukungan key rotation (`enableV3Signing = true`)
- [ ] v1 tetap dipertahankan **bersama** v2/v3 untuk kompatibilitas mundur dengan perangkat pra-API 24 (bukan dihapus)
- [ ] Bila v4 dipakai untuk incremental install, dipastikan **selalu** berdampingan dengan v2/v3
- [ ] Konfigurasi signing diverifikasi dengan `apksigner verify --verbose` sebelum setiap rilis
- [ ] APK final hasil distribusi (Play Store/bundletool) diverifikasi terpisah dari build lokal
- [ ] Pemeriksaan signing scheme diintegrasikan sebagai gate otomatis di pipeline CI/CD rilis
- [ ] Pertimbangkan migrasi ke Google Play App Signing untuk manajemen kunci yang lebih aman
- [ ] Sertifikat signing memiliki masa berlaku memadai (≥ 25 tahun, atau berakhir setelah 22 Oktober 2033 untuk syarat Google Play)
- [ ] **Verifikasi ulang:** jalankan kembali MASTG-TEST-0224 setelah setiap perubahan konfigurasi signing

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0224: Usage of Insecure APK Signature Version](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0224/)
- [MASWE-0056: Usage of Insecure APK Signature Version](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0056/)
- [MASTG-KNOW-0003: App Signing](https://mas.owasp.org/MASTG/knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0003/)
- [MASTG-BEST-0006: Use Up-to-Date APK Signing Schemes](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0006/)
- [MASTG-TECH-0116: Obtaining Information about the APK Signature](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0116/)
- [MASTG-TECH-0117: Obtaining Information from the AndroidManifest](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0117/)
- [MASTG-TECH-0150: Analyzing the AndroidManifest](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0150/)
- [MASTG-TOOL-0123: apksigner](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0123/)
- [MASTG — Platform Overview: Signing Process](https://mas.owasp.org/MASTG/0x05a-Platform-Overview/#signing-process)
- [MASVS-RESILIENCE: Resilience Against Reverse Engineering and Tampering](https://mas.owasp.org/MASVS/11-MASVS-RESILIENCE/)
- [MASTG Profiles — MAS-R (Resilience)](https://mas.owasp.org/MASTG/Profiles/)
- [OWASP Mobile Top 10 2024 — M7: Insufficient Binary Protections](https://owasp.org/www-project-mobile-top-10/2023-risks/m7-insufficient-binary-protections.html)
- [OWASP Mobile Top 10 2024 — M8: Security Misconfiguration](https://owasp.org/www-project-mobile-top-10/2023-risks/m8-security-misconfiguration.html)

### 5.2 Dokumentasi Resmi Android / Google

- [Android — Application Signing](https://developer.android.com/studio/publish/app-signing.html)
- [Android — APK Signature Scheme v2](https://source.android.com/docs/security/features/apksigning/v2)
- [Android — APK Signature Scheme v3](https://source.android.com/docs/security/features/apksigning/v3)
- [Android — APK Signature Scheme v4](https://source.android.com/docs/security/features/apksigning/v4)
- [Android — Sign your app (Android Studio)](https://developer.android.com/studio/publish/app-signing)
- [Android — Google Play App Signing](https://support.google.com/googleplay/android-developer/answer/9842756)
- [Android — Incremental APK installation (Android 11 features)](https://developer.android.com/about/versions/11/features#incremental)
- [Android — apksigner tool reference](https://developer.android.com/tools/apksigner)
- [Android — bundletool reference](https://developer.android.com/tools/bundletool)
- [Android — Signing Considerations (25-year validity, Play Store 2033 requirement)](https://developer.android.com/studio/publish/app-signing#considerations)

### 5.3 Kerentanan Janus (CVE-2017-13156)

- [NVD — CVE-2017-13156](https://nvd.nist.gov/vuln/detail/CVE-2017-13156)
- [GuardSquare — Janus Vulnerability: Threats and Mitigation](https://www.guardsquare.com/blog/new-android-vulnerability-allows-attackers-to-modify-apps-without-affecting-their-signatures-guardsquare)
- [Trend Micro — Janus Android Vulnerability Allows App Modifications](https://www.trendmicro.com/en_us/research/17/l/janus-android-app-signature-bypass-allows-attackers-modify-legitimate-apps.html)
- [The Hacker News — Android Flaw Lets Hackers Inject Malware Into Apps Without Altering Signatures](https://thehackernews.com/2017/12/android-malware-signature.html)
- [Security Affairs — Android Janus vulnerability allows attackers to inject malware](https://securityaffairs.com/66513/hacking/janus-vulnerability-android.html)
- [XDA Developers — Janus Vulnerability Allows Attackers to Modify Apps without Affecting their Signatures](https://www.xda-developers.com/janus-vulnerability-android-apps/)
- [Medium (mobis3c) — Exploiting Apps vulnerable to Janus (CVE-2017-13156)](https://medium.com/mobis3c/exploiting-apps-vulnerable-to-janus-cve-2017-13156-8d52c983b4e0)
- [Exploit-DB — Android Janus APK Signature Bypass (Metasploit)](https://www.exploit-db.com/exploits/47601)

### 5.4 Standar & Taksonomi

- [CWE-345: Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html)
- [CWE-353: Missing Support for Integrity Check](https://cwe.mitre.org/data/definitions/353.html)
- [CWE-494: Download of Code Without Integrity Check](https://cwe.mitre.org/data/definitions/494.html)
- [NIST SP 800-163 Rev.1 — Vetting the Security of Mobile Applications](https://csrc.nist.gov/publications/detail/sp/800-163/rev-1/final)

### 5.5 Dokumentasi Tools

- [apksigner — Android Developers tool reference](https://developer.android.com/tools/apksigner)
- [apkanalyzer — Android Developers tool reference](https://developer.android.com/tools/apkanalyzer)
- [Androguard — Android APK/DEX analysis library](https://github.com/androguard/androguard)
- [MobSF — Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)
- [bundletool — Android App Bundle tooling](https://github.com/google/bundletool)

---

*Dokumen ini disusun berdasarkan OWASP MASTG (rilis terkini per September 2026), dokumentasi resmi Android Open Source Project mengenai APK Signature Scheme, serta laporan riset GuardSquare tentang kerentanan Janus (CVE-2017-13156). Test ini belum memiliki demo (MASTG-DEMO) resmi dari MASTG.*
