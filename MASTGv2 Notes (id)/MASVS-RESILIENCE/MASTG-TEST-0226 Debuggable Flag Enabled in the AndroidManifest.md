# MASTG-TEST-0226 Debuggable Flag Enabled in the AndroidManifest

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0226 |
| **Platform** | Android |
| **Kategori MASVS** | **MASVS-RESILIENCE** (Resilience Against Reverse Engineering and Tampering) |
| **Weakness** | **MASWE-0063** — *Debug Mechanisms Not Disabled* |
| **Tipe Pengujian** | **Static**, Code |
| **Profile** | **R** (Resilience) |
| **Knowledge** | MASTG-KNOW-0007 (Debuggable Apps) |
| **Best Practice** | MASTG-BEST-0007 (Debuggable Flag Disabled in the AndroidManifest) |
| **Teknik terkait** | MASTG-TECH-0117 (Obtaining Information from the AndroidManifest), MASTG-TECH-0150 (Analyzing the AndroidManifest) |
| **Demo terkait** | — (MASTG belum menyediakan demo untuk test ini) |
| **Weakness terkait erat** | **MASWE-0064** — *Debugger Detection Not Implemented* (lihat MASTG-TEST-0352/0353) — lapisan pertahanan lanjutan setelah flag ini |
| **Test bersaudara** | MASTG-TEST-0227 (Debugging Enabled for WebViews) — objek berbeda (WebView, bukan aplikasi native) tetapi tema serupa |
| **CVE terkait** | CVE-2024-31317 (Zygote JDWP flag injection), CVE-2024-0044 (`run-as` sandbox bypass) — lihat §1.4 |
| **CWE terkait** | CWE-489 (Active Debug Code), CWE-215 (Insertion of Sensitive Information Into Debugging Code), CWE-1244 (Internal Asset Exposed to Unsafe Debug Access) |

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian

Kutipan langsung dari overview MASTG:

> *"This test case checks if the app has the `debuggable` flag (`android:debuggable`) set to `true` in the `AndroidManifest.xml`. When this flag is enabled, it allows the app to be debugged enabling attackers to inspect the app's internals, bypass security controls, or manipulate runtime behavior."*
>
> *"Although having the `debuggable` flag set to `true` **is not considered a direct vulnerability**, it **significantly increases the attack surface** by providing unauthorized access to app data and resources, particularly in production environments."*

Perhatikan nuansa penting yang secara eksplisit diakui MASTG sendiri, dengan merujuk langsung dokumentasi Android: flag ini **bukan kerentanan langsung** (tidak ada eksploitasi otomatis yang terjadi hanya karena flag-nya `true`), melainkan **pembesar attack surface** — ia membuka pintu bagi serangkaian teknik lanjutan yang membutuhkan akses fisik/ADB terlebih dahulu. Ini memengaruhi cara menilai severity (§3.9).

### 1.2 Apa yang Sebenarnya Terjadi Saat `debuggable="true"`

MASTG-KNOW-0007 menjelaskan mekanisme teknisnya secara ringkas:

> *"Every debugger-enabled process runs an **extra thread for handling JDWP protocol packets**. This thread is started only for apps that have the `android:debuggable="true"` attribute in the `Application` element within the Android Manifest."*

**JDWP (Java Debug Wire Protocol)** adalah protokol yang dipakai IDE (Android Studio) untuk berkomunikasi dengan proses Dalvik/ART yang sedang berjalan di perangkat — mengatur breakpoint, menginspeksi variabel, memodifikasi nilai saat runtime, dan mengendalikan alur eksekusi. Ketika `android:debuggable="true"`:

- Sistem menjalankan **thread tambahan** khusus untuk menangani paket protokol JDWP pada proses aplikasi tersebut.
- Proses aplikasi menjadi **dapat di-attach** oleh debugger apa pun yang bisa terhubung ke socket JDWP-nya — baik lewat Android Studio yang sah, maupun tool command-line seperti `jdb` yang dijalankan penyerang melalui `adb`.
- **Atribut ini berlaku di level aplikasi secara keseluruhan** dan **tidak bisa di-override per komponen** — sekali `true`, seluruh proses aplikasi (semua Activity, Service, dsb.) menjadi target yang sama-sama dapat di-debug.

**Dampak konkret yang dijelaskan dokumentasi Android** yang dirujuk MASTG:

| Dampak | Penjelasan |
|---|---|
| **Unauthorized Access** | Penyerang dapat men-debug aplikasi untuk mengakses fungsionalitas sensitif yang seharusnya tersembunyi |
| **Resource Exploitation** | Akses tidak sah ke resource dan data aplikasi |
| **Administrative Functions Exposed** | Antarmuka debugging yang seharusnya hanya untuk developer menjadi dapat diakses penyerang |
| **Information Disclosure** | Memudahkan reverse engineering dan ekstraksi data sensitif |

### 1.3 Konsekuensi Praktis: Apa yang Bisa Dilakukan Penyerang

Ini bagian yang sering kurang konkret di dokumentasi resmi, tetapi penting untuk memahami *severity* riil temuan ini. Dengan aplikasi debuggable dan akses `adb` (perangkat fisik atau emulator, tidak perlu root), penyerang dapat:

**1. Mengakses sandbox aplikasi via `run-as` — tanpa root:**

```bash
adb shell run-as com.example.target ls -la /data/data/com.example.target/
```

Perintah `run-as` **hanya berfungsi untuk aplikasi debuggable** pada device non-rooted. Ini setara langsung dengan akses `root`-level ke sandbox aplikasi tersebut — membuka seluruh `shared_prefs/`, `databases/`, `files/` yang seharusnya terisolasi (bertaut langsung dengan MASTG-TEST-0207).

**2. Attach debugger langsung dan memanipulasi eksekusi runtime:**

```bash
# Cari proses yang debuggable
adb jdwp
# Forward port JDWP
adb forward tcp:8700 jdwp:<pid>
# Attach dengan jdb
jdb -attach localhost:8700
```

Dari sini penyerang dapat men-set breakpoint pada fungsi validasi lisensi/pembayaran, membaca nilai variabel runtime (termasuk kunci yang sempat berada di memori dalam bentuk plaintext), memanggil method secara arbitrer, dan **memodifikasi nilai return** untuk melewati pengecekan keamanan (mis. mengubah hasil fungsi `isLicensed()` dari `false` menjadi `true`).

**3. Memudahkan instrumentasi lanjutan (Frida, dsb.).** Meski Frida tidak *mensyaratkan* `debuggable="true"` secara mutlak (frida-gadget dapat disuntikkan lewat repackaging), aplikasi yang sudah debuggable membuat seluruh rantai serangan — dari eksplorasi awal hingga instrumentasi penuh — jauh lebih cepat dan tidak memerlukan modifikasi APK sama sekali.

### 1.4 Konteks 2024: Mengapa Kontrol Ini Tetap Relevan Bahkan Jika Flag-nya `false`

Ini nuansa penting yang melampaui apa yang tertulis di overview MASTG, dan menjelaskan mengapa MASWE-0064 (*Debugger Detection Not Implemented*) ada sebagai lapisan tambahan setelah kontrol dasar ini.

**CVE-2024-31317 (diperbaiki Android Security Bulletin Juni 2024):** Riset menunjukkan bahwa **bahkan aplikasi yang TIDAK di-ship dengan `android:debuggable="true"`** tetap dapat dipaksa berjalan dengan flag runtime `DEBUG_ENABLE_JDWP` melalui eksploitasi cara Zygote mem-parsing argumen command-line. Penyerang yang dapat menjangkau `system_server` (misalnya melalui `adb shell` yang memiliki permission `WRITE_SECURE_SETTINGS`) dapat menyisipkan parameter tambahan saat proses aplikasi di-spawn. Begitu proses ter-spawn dengan flag ini, socket JDWP terbuka dan **seluruh teknik dynamic-debug standar** (penggantian method, patching variabel, injeksi Frida langsung) menjadi mungkin **tanpa memodifikasi APK maupun boot image**. Dampaknya mencakup akses baca/tulis penuh ke direktori data privat aplikasi mana pun (termasuk aplikasi privileged seperti `com.android.settings`), pencurian token, bypass MDM, dan potensi eskalasi privilese lewat IPC endpoint yang ter-ekspos.

**CVE-2024-0044 (diperbaiki Android Security Bulletin Maret 2024):** Kerentanan kritis pada perintah `run-as` itu sendiri di Android 12/13/14 — memungkinkan penyerang **membajak mekanisme `run-as`** untuk membuat sistem *mengira* aplikasi target debuggable padahal tidak, lewat celah pada fungsi `check_directory()` yang secara keliru melewati validasi UID untuk path `/data/user/0`. Ini secara efektif membajak Application Sandbox Android **tanpa perlu root** untuk aplikasi apa pun di perangkat, bukan hanya yang memang debuggable.

**Meta Red Team X** juga mendokumentasikan teknik bypass **pemeriksaan debuggability `run-as`** lewat *newline injection*, menunjukkan bahwa asumsi "hanya aplikasi debuggable yang rentan lewat `run-as`" tidak sepenuhnya kokoh terhadap penyerang yang cukup termotivasi.

**Implikasi untuk pengujian:** temuan `debuggable="true"` tetaplah temuan langsung dan pasti (tidak butuh kerentanan platform tambahan untuk dieksploitasi). Tetapi konteks di atas menjelaskan mengapa MASTG-BEST-0007 secara eksplisit menyatakan menonaktifkan flag ini **"is an important first step but does not fully protect the app from advanced attacks"** — karena penyerang yang cukup canggih memiliki jalur alternatif menuju kapabilitas debugging yang setara, baik lewat kerentanan platform (seperti kedua CVE di atas) maupun lewat **binary patching** untuk mengaktifkan ulang flag ini secara paksa pada salinan APK yang sudah di-repackage.

### 1.5 Posisi dalam Rangkaian Pertahanan Berlapis

MASTG-BEST-0007 secara eksplisit menempatkan test ini sebagai **lapisan pertama**, bukan solusi tunggal:

> *"Disabling debugging via the `debuggable` flag is an important first step but does not fully protect the app from advanced attacks. Skilled attackers can enable debugging through various means, such as **binary patching** to allow attachment of a debugger or the use of **binary instrumentation tools like Frida** to achieve similar capabilities. For apps requiring a higher level of security, consider implementing **anti-debugging techniques** as an additional layer of defense."*

| Lapisan | Test MASTG | Apa yang diperiksa |
|---|---|---|
| **1. Konfigurasi dasar** | **MASTG-TEST-0226** *(dokumen ini)* | Apakah flag `debuggable` dinonaktifkan di manifest — pertahanan pasif, tidak butuh kode tambahan |
| **2. Deteksi aktif (statis)** | MASTG-TEST-0352 (*References to Debugging Detection APIs*) | Apakah kode memiliki referensi ke API pendeteksi debugger (`Debug.isDebuggerConnected()`, dsb.) |
| **3. Deteksi aktif (dinamis)** | MASTG-TEST-0353 (*Runtime Use of Debugging Detection APIs*) | Apakah deteksi tersebut benar-benar berfungsi dan sulit di-bypass saat runtime |

Untuk aplikasi berprofil R yang memerlukan resiliensi tinggi (finansial, DRM, anti-cheat), lolos MASTG-TEST-0226 saja **tidak cukup** — idealnya ketiga lapisan ini diuji sebagai satu rangkaian.

### 1.6 Ketidaksesuaian Kategori: KNOW-0007 vs Penempatan Test

Catatan teknis kecil yang layak diketahui: file sumber **MASTG-KNOW-0007** (Debuggable Apps) memiliki metadata `masvs_category: MASVS-CODE`, sementara **test yang memakainya (MASTG-TEST-0226) berada di bawah MASVS-RESILIENCE**. Ini kemungkinan sisa dari reorganisasi taksonomi MASTG V2 yang belum sepenuhnya konsisten di seluruh cross-reference — tidak memengaruhi cara pengujian maupun kriteria evaluasi, tetapi baik diketahui agar tidak membingungkan saat menelusuri dokumen sumber MASTG secara langsung.

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | MASTG ID | Fungsi |
|---|---|---|
| **jadx / apktool** | MASTG-TOOL-0018 / 0011 | Ekstraksi `AndroidManifest.xml` (MASTG-TECH-0117) |
| **aapt2** | MASTG-TOOL-0124 | Cara **tercepat** membaca status flag ini — didukung langsung oleh MASTG-TECH-0150 |
| **grep** | — | Pencarian pola sederhana pada manifest hasil ekstraksi |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **adb** | Verifikasi status debuggable pada aplikasi yang **sudah terpasang** di perangkat (bukan hanya file APK statis) — via `dumpsys package` |
| **apkanalyzer** | Alternatif GUI/CLI Android SDK untuk inspeksi manifest |
| **Python `androguard` / `pyaxmlparser`** | Scripting untuk audit massal banyak APK sekaligus |
| **MobSF** | Analisis otomatis, menandai flag debuggable sebagai temuan dalam laporan APK |
| **`adb jdwp` + `jdb`** | **Bukti eksploitabilitas** — mengonfirmasi aplikasi benar-benar dapat di-attach debugger, bukan hanya membaca nilai manifest |

### 2.3 Prasyarat Lingkungan

- **Tidak butuh device dan tidak butuh root** untuk pemeriksaan statis dasar — cukup file APK.
- **Untuk verifikasi eksploitabilitas** (§3.5), butuh device/emulator dengan USB debugging aktif — tidak perlu root.
- **Sama seperti test-test signing (0224/0225): uji APK final yang didistribusikan**, bukan hanya build lokal. Ini **sangat krusial** untuk test ini secara khusus: kesalahan konfigurasi Gradle (mis. `applicationVariants.all` yang salah target, atau flavor build yang tertukar) dapat menyebabkan flag `debuggable="true"` **tanpa sengaja ikut ke build release** — sesuatu yang hanya dapat dipastikan dengan memeriksa artefak akhir, bukan asumsi dari konfigurasi source `build.gradle`.
- **Perhatikan bahwa flag ini juga bisa berbeda antara APK development internal (mis. untuk QA) dan APK yang benar-benar dirilis ke Play Store** — pastikan target pengujian jelas.

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0117** (*Obtaining Information from the AndroidManifest*) untuk mendapatkan `AndroidManifest.xml`.
2. Gunakan **MASTG-TECH-0150** (*Analyzing the AndroidManifest*) untuk mendapatkan flag `debuggable`.

### 3.2 Metode A — aapt2 *(tercepat, tanpa dekompilasi — dicontohkan langsung MASTG-TECH-0150)*

Ini metode yang secara eksplisit dicontohkan di MASTG-TECH-0150 sebagai pendekatan utama:

```bash
aapt2 d badging YourApp.apk | grep -i debuggable
```

Contoh output ketika flag **aktif** (sesuai contoh resmi MASTG-TECH-0150):

```
application-debuggable
```

**Bila flag tidak muncul sama sekali di output** → flag bernilai `false` (default untuk release build).

### 3.3 Metode B — grep pada manifest hasil dekompilasi *(apktool/jadx)*

```bash
# Ekstraksi dengan apktool
apktool d -f -o out_dir YourApp.apk
grep -i "android:debuggable" out_dir/AndroidManifest.xml

# Contoh output ketika aktif:
#   android:debuggable="true"

# Ekstraksi dengan jadx
jadx --no-src -d out_dir YourApp.apk
grep -i "android:debuggable" out_dir/resources/AndroidManifest.xml
```

> Sesuai catatan resmi MASTG-TECH-0150: *"If the attribute is absent, the flag **defaults to `false`** for release builds."* — ketiadaan baris ini di output `grep` (tanpa error) berarti **PASS**, bukan hasil yang tidak lengkap.

### 3.4 Metode C — adb dumpsys *(verifikasi pada aplikasi yang SUDAH TERPASANG di perangkat)*

Ini pelengkap penting: memverifikasi status *runtime* aktual pada aplikasi yang terinstal, bukan hanya membaca file APK statis — berguna untuk mengonfirmasi bahwa APK yang benar-benar berjalan di perangkat pengguna konsisten dengan APK yang diaudit.

```bash
adb shell dumpsys package com.example.target | grep -i debuggable

# Contoh output:
#   flags=[ DEBUGGABLE HAS_CODE ALLOW_CLEAR_USER_DATA ... ]
```

Kehadiran flag `DEBUGGABLE` dalam daftar `flags=[...]` mengonfirmasi status aktual pada instalasi tersebut.

### 3.5 Metode D — Verifikasi eksploitabilitas dengan `run-as` dan JDWP *(bukti konkret, bukan hanya nilai manifest)*

Ini metode yang mengangkat temuan dari "nilai konfigurasi" menjadi "bukti dampak nyata" — sangat direkomendasikan untuk laporan pentest, bukan sekadar audit compliance.

```bash
PKG=com.example.target

# 1. Buktikan akses sandbox via run-as TANPA ROOT
adb shell run-as $PKG ls -la /data/data/$PKG/
# Berhasil menampilkan isi direktori privat -> BUKTI KONKRET dampak nyata

adb shell run-as $PKG cat /data/data/$PKG/shared_prefs/*.xml

# 2. Buktikan proses dapat di-attach debugger via JDWP
adb jdwp
# Menampilkan daftar PID proses yang membuka socket JDWP

PID=$(adb shell pidof -s $PKG)
adb forward tcp:8700 jdwp:$PID
jdb -attach localhost:8700
# > berhasil attach -> breakpoint, inspeksi variabel, manipulasi return value dimungkinkan
```

> **Catatan etika/lingkup:** jalankan langkah ini hanya pada aplikasi target dalam lingkup pengujian yang sah (milik sendiri, atau dengan otorisasi eksplisit klien pentest).

### 3.6 Metode E — androguard *(scripting untuk audit massal)*

```python
# check_debuggable.py
from androguard.core.apk import APK
import glob

for apk_path in glob.glob("./apks/*.apk"):
    a = APK(apk_path)
    is_debuggable = a.get_element("application", "debuggable")
    verdict = "FAIL" if is_debuggable == "true" else "PASS"
    print(f"{apk_path}: debuggable={is_debuggable} -> {verdict}")
```

```bash
pip install androguard
python3 check_debuggable.py
```

### 3.7 Metode F — MobSF

```bash
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest
```

Upload APK → bagian **Manifest Analysis** menampilkan temuan eksplisit *"Debug Enabled For App"* dengan severity `high` bila `android:debuggable="true"` terdeteksi, lengkap dengan referensi CWE.

### 3.8 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Butuh device? | Sumber data | Membuktikan eksploitabilitas nyata? | Kapan dipakai |
|---|---|---|---|---|---|
| **A** | aapt2 (MASTG) | Tidak | File APK | ❌ | **Baseline resmi — tercepat** |
| **B** | grep manual (apktool/jadx) | Tidak | File APK | ❌ | Verifikasi silang; bila `aapt2` tidak tersedia |
| **C** | adb dumpsys | Ya | Perangkat terpasang | ❌ | Verifikasi status *runtime* aktual, konsistensi APK vs instalasi |
| **D** | `run-as` + JDWP/jdb | Ya | Perangkat terpasang | ✅ **(kunci)** | **Laporan pentest** — mengubah temuan jadi bukti konkret |
| **E** | androguard | Tidak | File APK | ❌ | Audit massal banyak APK, integrasi CI |
| **F** | MobSF | Tidak | File APK | ❌ | Laporan siap kutip dengan referensi CWE |

**Kombinasi minimum yang aku rekomendasikan:** **A (aapt2) selalu**, ditambah **D (run-as/JDWP)** setiap kali test ini menghasilkan FAIL dan konteksnya adalah pentest (bukan sekadar audit compliance) — bukti eksploitabilitas jauh lebih meyakinkan bagi stakeholder daripada sekadar mengutip nilai atribut manifest. Tambahkan **C** untuk verifikasi bahwa APK yang beredar di perangkat pengguna konsisten dengan yang diaudit.

---

### 3.9 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG:**

> **Observation:** *"The output should explicitly show whether the `debuggable` flag is set (`true` or `false`). If the flag is **not specified**, it is treated as **`false` by default** for release builds."*
>
> **Evaluation:** *"The test case **fails** if the `debuggable` flag is **explicitly set to `true`**. This indicates that the app is configured to allow debugging, which is inappropriate for production environments."*

Kriterianya sangat lugas — **satu kondisi biner**, tanpa nuansa kontekstual seperti pada test-test kripto.

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi | Contoh bukti |
|---|---|---|
| F1 | `android:debuggable="true"` eksplisit tercantum di manifest APK rilis | `aapt2 d badging` → `application-debuggable` |
| F2 | Flag `true` pada APK **final yang didistribusikan** (bukan hanya build development internal) | Diverifikasi via APK dari Play Store/bundletool, bukan hanya build lokal |
| F3 | `adb shell dumpsys package` menunjukkan flag `DEBUGGABLE` pada aplikasi yang terinstal di perangkat produksi | `flags=[ DEBUGGABLE ... ]` |
| F4 | `run-as` berhasil memberi akses ke sandbox aplikasi tanpa root, mengonfirmasi dampak nyata | `adb shell run-as <pkg> ls` berhasil menampilkan isi `/data/data/<pkg>/` |
| F5 | Proses aplikasi berhasil di-attach lewat JDWP (`jdb`) dan memungkinkan manipulasi variabel/return value | Breakpoint berhasil dipasang pada fungsi validasi kritis |

**Contoh bukti (ilustratif — MASTG belum menyediakan demo resmi untuk test ini):**

```bash
$ aapt2 d badging LegacyBuild.apk | grep -i debuggable
application-debuggable

$ adb install -r LegacyBuild.apk
$ adb shell run-as com.example.legacyapp ls -la /data/data/com.example.legacyapp/shared_prefs/
-rw-rw---- 1 u0_a123 u0_a123  842 2026-09-01 10:15 auth_prefs.xml
-rw-rw---- 1 u0_a123 u0_a123  156 2026-09-01 10:15 user_settings.xml
```

Interpretasi: flag `debuggable="true"` terkonfirmasi statis **dan** dampaknya terbukti nyata — `run-as` memberi akses langsung ke `shared_prefs/` yang seharusnya terisolasi sandbox → **FAIL** dengan bukti eksploitabilitas konkret.

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi | Contoh bukti |
|---|---|---|
| P1 | Atribut `android:debuggable` **tidak muncul sama sekali** di manifest (default `false` untuk release) | `aapt2 d badging` tidak menampilkan `application-debuggable` |
| P2 | Atribut secara eksplisit di-set `android:debuggable="false"` | `grep` menunjukkan nilai `"false"` secara eksplisit |
| P3 | `run-as` gagal (`run-as: package not debuggable`) pada aplikasi yang terinstal | Konfirmasi bahwa sandbox terlindungi sebagaimana mestinya |
| P4 | `adb jdwp` tidak menampilkan PID untuk proses aplikasi target | Tidak ada socket JDWP terbuka — proses tidak dapat di-attach |

**Contoh output yang menandakan PASS:**

```bash
$ aapt2 d badging ProductionApp.apk | grep -i debuggable
# (tidak ada output)

$ adb install -r ProductionApp.apk
$ adb shell run-as com.example.productionapp ls
run-as: Package 'com.example.productionapp' is not debuggable
```

Interpretasi: tidak ada `application-debuggable` di badging, **dan** `run-as` menolak akses secara eksplisit dengan pesan yang mengonfirmasi status non-debuggable → **PASS**.

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Uji APK final, bukan build development.** Ini catatan paling penting untuk test ini secara spesifik. Sangat umum bagi tim untuk memiliki build "internal"/"staging" dengan `debuggable=true` untuk kebutuhan QA — pastikan objek pengujian benar-benar APK yang dirilis ke pengguna akhir (via Play Store atau saluran distribusi resmi lain), bukan artefak internal yang secara sengaja berbeda konfigurasi.

2. **Ketiadaan atribut = PASS, bukan hasil ambigu.** MASTG menegaskan eksplisit bahwa tanpa deklarasi, nilai default adalah `false` untuk build release standar Android Gradle Plugin. Jangan menandai ini sebagai "perlu verifikasi lanjutan" — ini kondisi PASS yang definitif berdasarkan perilaku default platform.

3. **Selalu coba buktikan dampak nyata (`run-as`/JDWP) saat menemukan FAIL dalam konteks pentest.** Nilai atribut manifest saja adalah bukti konfigurasi; `run-as` yang berhasil adalah bukti **dampak**. Perbedaan ini penting untuk kredibilitas laporan — terutama karena MASTG sendiri menyatakan flag ini *"is not considered a direct vulnerability"*, sehingga menunjukkan dampak konkret memperkuat justifikasi severity yang diberikan.

4. **`debuggable="false"` bukan solusi lengkap (§1.4, §1.5).** Meski test ini PASS, untuk aplikasi berprofil R yang membutuhkan resiliensi tinggi, tetap periksa **MASTG-TEST-0352/0353** (deteksi debugger aktif) sebagai lapisan pertahanan tambahan — mengingat CVE-2024-31317 dan CVE-2024-0044 membuktikan penyerang canggih memiliki jalur menuju kapabilitas debugging yang tidak bergantung sepenuhnya pada flag manifest ini.

5. **Periksa juga konsistensi antara file APK dan instalasi aktual di perangkat (Metode C).** Dalam kasus yang jarang namun mungkin (kesalahan pipeline distribusi, sideloading APK yang salah, dsb.), status pada perangkat produksi bisa berbeda dari yang terlihat pada file APK yang kamu audit secara terpisah.

6. **Ini bukan false-positive-prone seperti test kripto** — tidak ada skenario "flag `true` tetapi ternyata aman" yang sah untuk build produksi. Berbeda dari MASTG-TEST-0223 (stack canary) yang punya pengecualian legitimate (Flutter/React Native), **tidak ada alasan sah** bagi APK produksi untuk memiliki `debuggable="true"`. Bila ditemukan, ini murni kesalahan konfigurasi build, bukan keputusan desain yang dapat dipertahankan.

7. **Severity dimodulasi oleh konteks aplikasi (profile R):**

   | Faktor | Severity |
   |---|---|
   | Aplikasi finansial/pembayaran/DRM dengan `debuggable="true"` pada APK produksi | **Tinggi** — memudahkan bypass logika bisnis kritis secara langsung |
   | Aplikasi umum dengan `debuggable="true"` pada APK produksi | **Menengah-Tinggi** — tetap signifikan karena akses sandbox penuh via `run-as` |
   | `run-as` terbukti berhasil memberi akses ke kredensial/token di sandbox | **Tinggi** — dampak terkonfirmasi, bukan sekadar potensi |
   | `debuggable="true"` hanya pada build internal/QA yang tidak pernah didistribusikan ke pengguna | **Bukan temuan** untuk penilaian produksi (tetap dokumentasikan kebijakan pemisahan build) |
   | `debuggable="false"` atau tidak dideklarasikan | **Bukan temuan** |

8. **Dokumentasikan:** hasil pemeriksaan manifest (aapt2/grep), status pada perangkat terpasang (dumpsys), dan — bila memungkinkan dalam lingkup yang diizinkan — bukti konkret hasil `run-as`/JDWP sebagai lampiran pendukung tingkat dampak. Sertakan juga informasi apakah APK yang diuji adalah build final terdistribusi atau build internal.

---

## 4. Rekomendasi Perbaikan

### 4.1 Prinsip Utama (MASTG-BEST-0007)

MASTG-BEST-0007 menyatakan:

> *"Ensure the debuggable flag in the AndroidManifest.xml is set to `false` for all release builds."*

**Prioritas 1 — Pastikan konfigurasi build type Gradle menangani ini secara otomatis, jangan andalkan penetapan manual di manifest.**

```kotlin
// build.gradle.kts
android {
    buildTypes {
        release {
            isDebuggable = false   // eksplisit, meski ini sudah default AGP untuk release
            isMinifyEnabled = true
            // ...
        }
        debug {
            isDebuggable = true    // hanya untuk build development
        }
    }
}
```

```groovy
// build.gradle (Groovy)
android {
    buildTypes {
        release {
            debuggable false
        }
        debug {
            debuggable true
        }
    }
}
```

**Jangan** menetapkan `android:debuggable` secara langsung di `AndroidManifest.xml` — biarkan Android Gradle Plugin yang mengelolanya berdasarkan build type, karena penetapan manual di manifest berisiko **override** perilaku build type secara tidak sengaja (mis. developer menambahkan `android:debuggable="true"` di manifest untuk debugging lokal, lalu lupa menghapusnya sebelum commit).

**Prioritas 2 — Verifikasi sebagai bagian dari pipeline rilis, bukan hanya asumsi konfigurasi source.** Sesuai catatan §2.3 — konfigurasi `build.gradle` yang benar tidak menjamin artefak akhir bebas dari kesalahan (mis. flavor build yang tertukar). Tambahkan gate otomatis:

```bash
#!/bin/bash
# ci-verify-debuggable.sh
APK=$1
if aapt2 d badging "$APK" | grep -q "application-debuggable"; then
    echo "[GAGAL] APK rilis terdeteksi debuggable=true"
    exit 1
fi
echo "[OK] APK tidak debuggable"
```

**Prioritas 3 — Untuk aplikasi berprofil R (finansial/DRM/anti-cheat), implementasikan deteksi debugger aktif sebagai lapisan tambahan** (MASWE-0064, MASTG-TEST-0352/0353), mengingat MASTG-BEST-0007 sendiri menegaskan flag ini saja "does not fully protect the app from advanced attacks":

```kotlin
// Contoh deteksi dasar (dapat di-bypass penyerang canggih — bukan pengganti flag debuggable=false)
if (Debug.isDebuggerConnected() || Debug.waitingForDebugger()) {
    // Tindakan responsif: exit, log, atau degradasi fungsi sensitif
}
```

> Perlu ditegaskan: teknik deteksi semacam ini **dapat di-bypass** oleh penyerang yang memakai Frida atau binary patching — ini pertahanan tambahan (defense in depth), bukan jaminan absolut. Jangan mengandalkannya sebagai satu-satunya kontrol untuk logika keamanan kritis.

**Prioritas 4 — Terapkan prinsip least-privilege pada infrastruktur ADB di lingkungan produksi.** Mengingat CVE-2024-31317 mengeksploitasi akses `adb shell` dengan permission `WRITE_SECURE_SETTINGS`, pastikan perangkat produksi (mis. perangkat khusus untuk POS, kios, atau MDM korporat) membatasi akses USB debugging dan tidak memberikan permission istimewa kepada shell yang tidak diperlukan.

**Prioritas 5 — Pastikan patch level keamanan Android terkini diterapkan** pada perangkat yang dikelola organisasi (MDM), khususnya mencakup Android Security Bulletin **Maret 2024** (CVE-2024-0044) dan **Juni 2024** (CVE-2024-31317) atau yang lebih baru, untuk menutup jalur eksploitasi debug yang tidak bergantung pada flag manifest aplikasi itu sendiri.

**Prioritas 6 — Audit rutin sebagai bagian dari code review dan pra-rilis.** Jadikan pemeriksaan `android:debuggable` sebagai item checklist wajib pra-rilis, bukan hanya diandalkan lewat CI otomatis semata — mengingat kesalahan ini seringkali berasal dari kekeliruan manusia (lupa menghapus baris konfigurasi debug) daripada kegagalan tooling.

### 4.2 Checklist Remediasi

- [ ] `android:debuggable` **tidak** ditetapkan secara manual di `AndroidManifest.xml`
- [ ] Konfigurasi `debuggable` dikelola sepenuhnya lewat `buildTypes` di Gradle (`release { debuggable false }`)
- [ ] APK/AAB final yang didistribusikan (bukan hanya build lokal) diverifikasi dengan `aapt2 d badging`
- [ ] Verifikasi tambahan pada aplikasi yang terinstal di perangkat produksi (`adb shell dumpsys package`)
- [ ] `run-as` dan `adb jdwp` dikonfirmasi **gagal/tidak berlaku** pada APK produksi
- [ ] Pemeriksaan flag debuggable diintegrasikan sebagai gate otomatis di pipeline CI/CD rilis
- [ ] Untuk aplikasi profil R: deteksi debugger aktif (MASWE-0064) diimplementasikan sebagai lapisan tambahan
- [ ] Perangkat produksi/kios/POS yang dikelola organisasi membatasi akses ADB dan permission shell istimewa
- [ ] Patch level keamanan Android pada perangkat terkelola mencakup bulletin Maret 2024 dan Juni 2024 atau lebih baru
- [ ] Checklist pra-rilis manual mencakup verifikasi status debuggable sebagai item wajib
- [ ] **Verifikasi ulang:** jalankan kembali MASTG-TEST-0226 setelah setiap perubahan konfigurasi build/signing

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0226: Debuggable Flag Enabled in the AndroidManifest](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0226/)
- [MASTG-TEST-0227: Debugging Enabled for WebViews](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0227/)
- [MASTG-TEST-0352: References to Debugging Detection APIs](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0352/)
- [MASTG-TEST-0353: Runtime Use of Debugging Detection APIs](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0353/)
- [MASWE-0063: Debug Mechanisms Not Disabled](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0063/)
- [MASWE-0064: Debugger Detection Not Implemented](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0064/)
- [MASTG-KNOW-0007: Debuggable Apps](https://mas.owasp.org/MASTG/knowledge/android/MASVS-CODE/MASTG-KNOW-0007/)
- [MASTG-BEST-0007: Debuggable Flag Disabled in the AndroidManifest](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0007/)
- [MASTG-TECH-0117: Obtaining Information from the AndroidManifest](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0117/)
- [MASTG-TECH-0150: Analyzing the AndroidManifest](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0150/)
- [MASTG-TECH-0038: Bypassing Debugger Detection (binary patching)](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0038/)
- [MASTG-TEST-0207: Runtime Storage of Unencrypted Data in the App Sandbox](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0207/)
- [MASVS-RESILIENCE: Resilience Against Reverse Engineering and Tampering](https://mas.owasp.org/MASVS/11-MASVS-RESILIENCE/)
- [OWASP Mobile Top 10 2024 — M7: Insufficient Binary Protections](https://owasp.org/www-project-mobile-top-10/2023-risks/m7-insufficient-binary-protections.html)

### 5.2 Dokumentasi Resmi Android / Google

- [android:debuggable — Android Security Risks](https://developer.android.com/privacy-and-security/risks/android-debuggable)
- [`<application>` element — `android:debuggable` attribute](https://developer.android.com/guide/topics/manifest/application-element#debug)
- [Android Security Bulletin — March 2024 (CVE-2024-0044)](https://source.android.com/docs/security/bulletin/2024-03-01)
- [Android Security Bulletin — June 2024 (CVE-2024-31317)](https://source.android.com/docs/security/bulletin/2024-06-01)
- [Android — Debug your app](https://developer.android.com/studio/debug)
- [Android — Java Debug Wire Protocol (JDWP) overview](https://docs.oracle.com/javase/8/docs/technotes/guides/jpda/jdwp-spec.html)
- [Android — run-as command](https://developer.android.com/studio/command-line/adb)

### 5.3 Riset Kerentanan & Artikel Teknis

- [NVD — CVE-2024-31317](https://nvd.nist.gov/vuln/detail/CVE-2024-31317)
- [NVD — CVE-2024-0044](https://nvd.nist.gov/vuln/detail/CVE-2024-0044)
- [Meta Red Team X — Bypassing the "run-as" debuggability check on Android via newline injection](https://rtx.meta.security/exploitation/2024/03/04/Android-run-as-forgery.html)
- [Talsec — Breaking the Android Sandbox and How to Defend Against It](https://docs.talsec.app/appsec-articles/articles/breaking-the-android-sandbox-and-how-to-defend-against-it)
- [HackTricks — Exploiting a debuggable application](https://book.hacktricks.wiki/en/mobile-pentesting/android-app-pentesting/exploiting-a-debuggeable-applciation.html)
- [Infosec Institute — Exploiting debuggable Android applications](https://www.infosecinstitute.com/resources/application-security/android-hacking-security-part-6-exploiting-debuggable-android-applications/)
- [Manifest Security — Android Application Security Part 21: Exploiting Debuggable Applications](https://manifestsecurity.com/android-application-security-part-21/)

### 5.4 Standar & Taksonomi

- [CWE-489: Active Debug Code](https://cwe.mitre.org/data/definitions/489.html)
- [CWE-215: Insertion of Sensitive Information Into Debugging Code](https://cwe.mitre.org/data/definitions/215.html)
- [CWE-1244: Internal Asset Exposed to Unsafe Debug Access](https://cwe.mitre.org/data/definitions/1244.html)
- [NIST SP 800-163 Rev.1 — Vetting the Security of Mobile Applications](https://csrc.nist.gov/publications/detail/sp/800-163/rev-1/final)

### 5.5 Dokumentasi Tools

- [aapt2 — Android Asset Packaging Tool](https://developer.android.com/tools/aapt2)
- [apktool — Reverse engineering Android APK files](https://apktool.org/)
- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [Androguard — Android APK/DEX analysis library](https://github.com/androguard/androguard)
- [MobSF — Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)
- [jdb — The Java Debugger (Oracle documentation)](https://docs.oracle.com/javase/8/docs/technotes/tools/windows/jdb.html)
- [AndBug — Android debugging toolkit](https://github.com/swdunlop/AndBug)

---

*Dokumen ini disusun berdasarkan OWASP MASTG (rilis terkini per September 2026), dokumentasi resmi Android Developers, Android Security Bulletin 2024, dan riset kerentanan pihak ketiga (Meta Red Team X, GuardSquare-style analysis). Test ini belum memiliki demo (MASTG-DEMO) resmi dari MASTG.*
