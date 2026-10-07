# MASTG-TEST-0223 Stack Canaries Not Enabled

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0223 |
| **Platform** | Android |
| **Kategori MASVS** | **MASVS-CODE** (MASVS-CODE-4: Aplikasi memvalidasi kualitas kompilasi & konfigurasi build) |
| **Weakness** | **MASWE-0045** — *Compiler-Provided Security Features Not Used* |
| **Tipe Pengujian** | **Static**, Code |
| **Profile** | **L2 saja** |
| **Knowledge** | MASTG-KNOW-0006 (Binary Protection Mechanisms) |
| **Teknik terkait** | MASTG-TECH-0157 (Extracting Bundled Native Libraries), MASTG-TECH-0115 (Obtaining Compiler-Provided Security Features) |
| **Demo terkait** | — (MASTG belum menyediakan demo untuk test ini) |
| **Test bersaudara** | **MASTG-TEST-0222** (Position Independent Code Not Enabled) — MASWE-0045 yang sama, langkah pengujian identik |
| **CWE terkait** | CWE-121 (Stack-based Buffer Overflow), CWE-787 (Out-of-bounds Write), CWE-693 (Protection Mechanism Failure) |
| **Objek yang diuji** | File `.so` (native library NDK) di dalam `lib/<abi>/` pada APK — **bukan** kode Java/Kotlin |

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian

Kutipan langsung dari overview MASTG:

> *"This test case checks if the native libraries of the app are compiled without common binary protection mechanisms, such as **stack smashing protection**, a mitigation technique against buffer overflow attacks."*
>
> *"NDK libraries should have stack canaries enabled since **the compiler does it by default**."*
>
> *"Other custom C/C++ libraries might not have stack canaries enabled because they **lack the necessary compiler flags** (`-fstack-protector-strong`, or `-fstack-protector-all`) or the canaries **were optimized out** by the compiler."*

Test ini adalah **pasangan langsung MASTG-TEST-0222** — sama-sama menguji binary native `.so`, memakai tool dan langkah pengujian yang identik persis (MASTG-TECH-0157 + MASTG-TECH-0115), dan berbagi weakness MASWE-0045. Perbedaannya hanya pada **fitur keamanan yang diperiksa**: PIC/PIE di TEST-0222, stack canary di sini.

### 1.2 Perbedaan Krusial dengan MASTG-TEST-0222: Tidak Ada Penegakan Sistem

Ini poin paling penting yang membedakan kedua test bersaudara ini secara fundamental, dan menjelaskan mengapa test ini **jauh lebih mungkin menghasilkan temuan nyata**.

| | MASTG-TEST-0222 (PIC/PIE) | MASTG-TEST-0223 (Stack Canary) *(dokumen ini)* |
|---|---|---|
| Ditegakkan oleh linker/OS? | **Ya** — sejak API 21, `.so` non-PIE gagal dimuat | **Tidak** — linker tidak pernah menolak `.so` tanpa canary |
| Status frontmatter MASTG | `deprecated_since: 21` | Tidak ada penanda deprecated |
| Kemungkinan realistis ditemukan pada 2026 | Sangat rendah (kecuali SDK usang) | **Signifikan lebih tinggi** — bergantung sepenuhnya pada flag kompilasi developer |
| Sumber kegagalan | Toolchain sangat usang, override sengaja | Lupa mengatur flag; kode C/C++ kustom; optimisasi compiler |

Konsekuensinya: **stack canary sepenuhnya bergantung pada disiplin build system developer**, bukan pada jaminan platform. Tidak ada mekanisme Android yang "menolak" `.so` tanpa canary — binary tersebut akan tetap dimuat dan berjalan normal, hanya saja tanpa lapisan pertahanan terhadap stack buffer overflow. Inilah mengapa test ini secara historis lebih produktif untuk pengujian keamanan mobile dibanding test PIC.

### 1.3 Landasan Teknis: Bagaimana Stack Canary Bekerja

**Stack smashing protection** (juga dikenal sebagai *StackGuard* — nama implementasi originalnya) adalah mitigasi terhadap **stack-based buffer overflow** (CWE-121), salah satu kelas kerentanan memory corruption tertua dan paling banyak dieksploitasi dalam sejarah keamanan software.

**Mekanisme kerjanya:**

1. **Function prologue** (awal fungsi): compiler menyisipkan kode yang menyalin nilai rahasia — disebut **canary** — dari variabel global/TLS ke dalam stack frame, tepat **sebelum** alamat pengembalian (*return address*) dan variabel penting lainnya.
2. **Function epilogue** (akhir fungsi, sebelum `return`): compiler menyisipkan kode yang **membandingkan** nilai canary di stack dengan nilai asli yang tersimpan.
3. **Bila keduanya cocok** → fungsi mengembalikan kontrol secara normal.
4. **Bila terjadi mismatch** → ini artinya sesuatu telah **menimpa memori di antara** lokasi canary dan lokasi variabel yang overflow — indikasi kuat serangan buffer overflow sedang berlangsung. Compiler memanggil **`__stack_chk_fail()`**, yang menghentikan proses secara paksa (biasanya via `abort()`) **sebelum** alamat pengembalian yang sudah dimanipulasi penyerang sempat dipakai.

**Mengapa ini efektif menghentikan eksploitasi klasik:** serangan buffer overflow konvensional menimpa data di stack secara berurutan untuk akhirnya menimpa *return address* dan mengalihkan alur eksekusi ke kode penyerang (shellcode/gadget ROP). Karena canary diletakkan **di antara** buffer yang rentan dan *return address*, penyerang **harus** menimpa canary terlebih dahulu untuk mencapai *return address*. Perubahan pada canary terdeteksi di epilogue sebelum `return` dieksekusi — serangan gagal sebelum mencapai tujuannya.

**Di mana nilai canary asli disimpan:** nilai canary (`__stack_chk_guard`) biasanya disimpan di **Thread-Local Storage (TLS)** — pada arsitektur x86-64 Linux/Android, ini diakses lewat segment register `fs` pada offset tertentu (`fs:0x28`). Penyimpanan di TLS (bukan variabel global biasa) membuat nilai lebih sulit ditebak/dibaca penyerang, dan aman dipakai lintas-thread tanpa race condition.

### 1.4 Tiga Level Cakupan Flag Kompilasi — Ini yang Menentukan Efektivitas Nyata

Ini nuansa teknis yang sering luput dari perhatian, padahal krusial untuk menilai kualitas mitigasi, bukan sekadar keberadaannya:

| Flag | Fungsi yang dilindungi | Overhead | Cakupan |
|---|---|---|---|
| **`-fstack-protector`** | Hanya fungsi yang mendeklarasikan array karakter ≥ 8 byte di stack-nya | Sangat rendah (nyaris tidak terukur) | **Sangat sempit** — hanya sebagian kecil fungsi dalam codebase tipikal |
| **`-fstack-protector-strong`** *(direkomendasikan MASTG)* | Semua di atas **plus** fungsi dengan array lokal jenis/ukuran apa pun (termasuk dalam struct/union), dan fungsi yang memakai alamat variabel lokal sebagai argumen atau di sisi kanan assignment | Rendah-menengah | **Luas** — riset menunjukkan cakupan meningkat drastis (dari ~2.8% fungsi dengan flag dasar menjadi ~20.5% fungsi dengan `-strong` pada studi kernel Linux) |
| **`-fstack-protector-all`** | **Semua fungsi tanpa kecuali**, terlepas apakah rentan atau tidak | Signifikan — berdampak nyata pada performa & ukuran binary | Maksimal, tetapi jarang dipakai karena biaya performanya |

MASTG secara eksplisit menyebut **`-fstack-protector-strong`** dan **`-fstack-protector-all`** sebagai flag yang perlu diverifikasi keberadaannya:

> *"Developers need to ensure that the flags `-fstack-protector-strong`, or `-fstack-protector-all` are set in the compiler flags for all native libraries."*

Ini artinya `-fstack-protector` polos (tanpa `-strong`/`-all`) **secara teknis mengaktifkan canary**, tetapi cakupannya begitu sempit sehingga MASTG tidak menganggapnya memadai sebagai baseline yang direkomendasikan.

### 1.5 False Positive yang Diakui Secara Eksplisit oleh MASTG — Bagian Terpenting Dokumen Ini

Berbeda dari kebanyakan test lain, MASTG memberi peringatan yang **sangat spesifik dan eksplisit** untuk test ini:

> *"When evaluating this please note that there are potential **expected false positives** for which the test case should be considered as passed. To be certain for these cases, they require **manual review of the original source code and the compilation flags used**."*

Ini adalah salah satu dari sedikit test MASTG yang secara eksplisit menginstruksikan tester untuk **tidak** melaporkan FAIL walau tool menunjukkan `canary: false` — dalam kondisi tertentu. Tiga kategori false positive yang didokumentasikan:

**Kategori 1 — Penggunaan Bahasa yang Memory-Safe (Flutter):**

> *"The Flutter framework does not use stack canaries because of the way [Dart mitigates buffer overflows]."*

Dart (bahasa di balik Flutter) memiliki manajemen memori yang berbeda dari C/C++ dan memitigasi kelas kerentanan buffer overflow melalui desain bahasanya sendiri, bukan lewat stack canary tingkat kompiler C. `libapp.so` hasil kompilasi AOT Dart **secara desain** tidak memakai mekanisme ini — ini bukan kelalaian, melainkan properti arsitektural framework tersebut.

**Kategori 2 — Optimisasi Compiler Menghilangkan Canary Meski Flag Sudah Benar (React Native):**

> *"Sometimes, due to the size of the library and the optimizations applied by the compiler, it might be possible that the library was originally compiled with stack canaries but they were optimized out."*

MASTG memberi contoh nyata dari ekosistem React Native, dengan dua sub-kasus:

- **File `.so` yang efektif kosong di build release** — contoh: `libruntimeexecutor.so`, `libreact_render_debug.so`. Meski di-build dengan `-fstack-protector-all`, tidak ada string `stack_chk_fail` yang muncul karena **tidak ada pemanggilan metode sama sekali** di dalamnya pada build release.
- **File berisi kode tetapi tanpa pemanggilan buffer stack** — contoh: `libreact_utils.so`, `libreact_config.so`, `libreact_debug.so`. File-file ini tidak kosong dan berisi pemanggilan metode, tetapi metode-metode tersebut **tidak mengandung stack buffer call** yang memicu penyisipan canary oleh compiler — sehingga tidak ada string `stack_chk_fail` di dalamnya, meski flag `-fstack-protector-strong` sudah aktif untuk seluruh proyek.

Developer React Native secara eksplisit menyatakan **tidak akan** menambahkan `-fstack-protector-all` untuk kasus ini, dengan alasan hal tersebut akan menambah **biaya performa tanpa manfaat keamanan efektif** — karena fungsi-fungsi tersebut memang tidak memiliki pola kode yang rentan buffer overflow untuk dilindungi.

**Implikasi metodologis penting:** ketiadaan string `__stack_chk_fail` dalam binary **tidak secara otomatis membuktikan** bahwa flag kompilasi tidak diaktifkan. Ia bisa juga berarti "flag aktif, tetapi tidak ada kode yang memerlukan proteksi tersebut untuk dimasukkan". **Alat statis (rabin2/checksec) tidak dapat membedakan kedua skenario ini** — hanya review manual terhadap source code dan build configuration yang bisa memastikan.

### 1.6 Cakupan Objek Uji

Identik dengan MASTG-TEST-0222 (§1.5 di dokumen tersebut): fokus pada **native library (`.so`)**, karena kode Java/Kotlin berjalan di ART yang sudah memory-safe untuk kelas kerentanan ini. Periksa **setiap ABI** (`arm64-v8a`, `armeabi-v7a`, `x86_64`, `x86`) dan bedakan `.so` milik aplikasi sendiri dari yang di-bundle sebagai dependency pihak ketiga (React Native core libraries, Flutter engine, SQLCipher, image processing library, dll.).

---

## 2. Tools yang Dipakai untuk Pengujian

Karena test ini memakai MASTG-TECH-0157 dan MASTG-TECH-0115 yang **sama persis** dengan MASTG-TEST-0222, seluruh tools di bawah ini identik — perbedaannya hanya pada kolom output (`canary` alih-alih `pic`) yang diperiksa.

### 2.1 Tools Wajib (Core)

| Tool | MASTG ID | Fungsi |
|---|---|---|
| **rabin2** (radare2) | MASTG-TOOL-0129 | **Tool resmi MASTG** untuk membaca fitur keamanan compiler, termasuk stack canary |
| **unzip / apktool** | MASTG-TOOL-0011 | Ekstraksi `.so` dari APK (MASTG-TECH-0157) |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **checksec / checksec.py** | Deteksi canary via signature `__stack_chk_fail` — output ringkas mencakup PIE+canary+RELRO+NX sekaligus |
| **readelf / nm / strings** | Mencari string `__stack_chk_fail`/`__stack_chk_guard` di symbol table secara manual — berguna untuk verifikasi silang |
| **objdump** | Disassembly untuk memverifikasi **secara pasti** apakah instruksi pembacaan/pembandingan canary benar-benar ada di prologue/epilogue fungsi tertentu (§1.5 Kategori 2) |
| **LIEF** | Scripting Python untuk audit massal, dapat memeriksa keberadaan symbol `__stack_chk_fail` secara terprogram |
| **MobSF** | Analisis `.so` otomatis, melaporkan status stack canary dalam laporan APK |
| **Ghidra / IDA Pro** | **Wajib untuk kasus false positive Kategori 2** — memverifikasi secara visual apakah suatu fungsi benar-benar memiliki stack buffer yang butuh proteksi, atau memang tidak relevan |
| **APKiD** | Identifikasi framework (Flutter/React Native/Xamarin) — langkah pertama untuk mengetahui apakah false positive Kategori 1/2 relevan |

### 2.3 Prasyarat Lingkungan

- **Tidak butuh device dan tidak butuh root** — cukup APK. Sepenuhnya dapat diotomatisasi di CI/CD.
- **Identifikasi framework yang dipakai terlebih dahulu.** Ini langkah pertama yang menentukan seluruh alur analisis: apakah aplikasi memakai Flutter (`libapp.so`, `libflutter.so`), React Native (`libreactnativejni.so`, `libhermes.so`), Xamarin/.NET MAUI, atau native murni (Java/Kotlin + NDK kustom). Gunakan APKiD atau periksa struktur `assets/flutter_assets/`, `assets/index.android.bundle` sebagai penanda.
- **Siapkan akses ke source code bila memungkinkan** (untuk pengujian first-party/white-box) — ini satu-satunya cara memastikan false positive Kategori 2 secara definitif, sesuai instruksi MASTG *"require manual review of the original source code and the compilation flags used"*.
- **Ekstrak semua ABI** yang ada di `lib/`.

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0157** (*Extracting Bundled Native Libraries*) untuk mengekstrak native library dari paket aplikasi.
2. Gunakan **MASTG-TECH-0115** (*Obtaining Compiler-Provided Security Features*) pada setiap native library untuk mendapatkan fitur keamanan yang disediakan compiler.

### 3.2 Metode A — rabin2 *(resmi MASTG)*

```bash
# Langkah 1: ekstrak (identik dengan MASTG-TEST-0222)
unzip -o YourApp.apk "lib/*" -d YourApp
find YourApp/lib -name "*.so"

# Langkah 2: periksa fitur canary
rabin2 -I YourApp/lib/arm64-v8a/libnative-lib.so | grep -E "canary|pic"
```

Contoh output **TIDAK AMAN** (sesuai contoh resmi MASTG-TECH-0115):

```
canary   false
```

Contoh output **AMAN**:

```
canary   true
```

**Untuk memeriksa SEMUA `.so` dan SEMUA ABI sekaligus:**

```bash
for so in $(find YourApp/lib -name "*.so"); do
  echo "=== $so ==="
  rabin2 -I "$so" | grep -E "^canary"
done
```

### 3.3 Metode B — Verifikasi manual via symbol table *(diperlukan untuk memvalidasi false positive)*

Ini metode yang **secara langsung menjawab** peringatan false positive MASTG di §1.5.

```bash
# Cari symbol __stack_chk_fail / __stack_chk_guard secara eksplisit
nm -D YourApp/lib/arm64-v8a/libnative-lib.so 2>/dev/null | grep stack_chk
readelf --dyn-syms YourApp/lib/arm64-v8a/libnative-lib.so | grep stack_chk

# Cari string terkait canary di dalam binary (bekerja meski stripped)
strings YourApp/lib/arm64-v8a/libnative-lib.so | grep -i stack_chk

# LANGKAH KRUSIAL: cek apakah .so kosong / hanya berisi sedikit simbol
# (relevan untuk kasus React Native — file "kosong" tidak butuh canary)
nm -D YourApp/lib/arm64-v8a/libreact_utils.so 2>/dev/null | wc -l
readelf -S YourApp/lib/arm64-v8a/libreact_utils.so | grep -E "\.text|\.symtab"

# Cek ukuran section .text — .so yang sangat kecil kemungkinan minim/tanpa fungsi rentan
readelf -S YourApp/lib/arm64-v8a/libreact_utils.so | grep "\.text"
```

> **Cara membaca hasil:** bila `strings` **dan** `nm`/`readelf` sama-sama tidak menemukan `stack_chk_fail`, **DAN** file tersebut ternyata kosong/minim `.text` (Kategori 2 di §1.5), ini indikasi kuat false positive — bukan kegagalan konfigurasi. Bila file berukuran signifikan dengan banyak fungsi C/C++ kompleks namun tetap tidak ada `stack_chk_fail` sama sekali, ini **temuan yang sah**.

### 3.4 Metode C — checksec.py *(satu perintah untuk canary + PIE + RELRO + NX)*

```bash
pip install checksec.py
checksec --file=YourApp/lib/arm64-v8a/libnative-lib.so
```

```
RELRO           STACK CANARY       NX            PIE             FILE
Full RELRO      No canary found    NX enabled    PIE enabled     libnative-lib.so
```

Untuk audit massal:

```bash
checksec --dir=YourApp/lib --output=json > checksec-report.json
jq '.[] | select(.["binary-type"] == "ELF") | {file: .file, canary: .["stack-canary"]}' checksec-report.json
```

### 3.5 Metode D — Identifikasi framework dengan APKiD *(langkah triase wajib sebelum menilai FAIL)*

```bash
apkid YourApp.apk
```

```
[!] YourApp.apk!classes.dex
    compiler : dexlib 2.x
[+] YourApp.apk!lib/arm64-v8a/libflutter.so
    manipulator : Flutter engine detected
```

Bila aplikasi teridentifikasi sebagai **Flutter** atau **React Native**, lanjutkan ke §3.6/§3.7 sebelum menyimpulkan FAIL pada `.so` milik framework tersebut.

### 3.6 Metode E — Validasi false positive Flutter

```bash
# Identifikasi .so milik Flutter engine
find YourApp/lib -iname "libapp.so" -o -iname "libflutter.so"

# Ini SECARA DESAIN tidak memakai stack canary — Dart memitigasi
# buffer overflow lewat mekanisme bahasa, bukan lewat kompiler C
rabin2 -I YourApp/lib/arm64-v8a/libapp.so | grep canary
# canary   false   <-- INI BUKAN OTOMATIS TEMUAN, lihat §1.5 Kategori 1
```

Rujukan resmi: [Flutter — Security false positives](https://docs.flutter.dev/reference/security-false-positives#shared-objects-should-use-stack-canary-values) menyatakan eksplisit bahwa ini adalah *expected behavior*, bukan kerentanan.

### 3.7 Metode F — Validasi false positive React Native (analisis mendalam dengan Ghidra)

```bash
# 1. Identifikasi .so milik React Native core
find YourApp/lib -iname "libreact*.so" -o -iname "libruntimeexecutor.so" -o -iname "libhermes.so"

# 2. Cek apakah file "kosong" (Kategori 2a)
for so in $(find YourApp/lib -iname "libreact*.so"); do
  size=$(stat -c%s "$so" 2>/dev/null || stat -f%z "$so")
  funcs=$(nm -D "$so" 2>/dev/null | grep " T " | wc -l)
  echo "$so: ${size} bytes, ${funcs} exported functions"
done

# 3. Untuk file yang TIDAK kosong tetapi tetap tanpa stack_chk_fail (Kategori 2b),
#    verifikasi dengan Ghidra apakah fungsi-fungsinya benar-benar tidak memiliki
#    stack buffer lokal yang berisiko
ghidra_headless ./project ./YourApp/lib/arm64-v8a/libreact_utils.so \
  -import -analyze -postScript CheckStackCanaryUsage.java
```

Bila hasil Ghidra menunjukkan fungsi memang tidak mendeklarasikan array/buffer lokal berisiko, ini konsisten dengan penjelasan resmi tim React Native di [GitHub issue #36870](https://github.com/react/react-native/issues/36870#issuecomment-1714007068) — **PASS dengan catatan**, bukan FAIL.

### 3.8 Metode G — LIEF *(audit massal terprogram, membedakan file kosong vs tidak)*

```python
# check_canary.py
import lief
import glob

for so_path in glob.glob("YourApp/lib/**/*.so", recursive=True):
    binary = lief.parse(so_path)
    if binary is None:
        continue
    symbols = [s.name for s in binary.dynamic_symbols]
    has_canary = "__stack_chk_fail" in symbols
    text_section = next((s for s in binary.sections if s.name == ".text"), None)
    text_size = text_section.size if text_section else 0

    flag = ""
    if not has_canary and text_size < 200:
        flag = "  [KEMUNGKINAN FALSE POSITIVE - .text sangat kecil]"
    elif not has_canary:
        flag = "  [!! PERLU REVIEW MANUAL !!]"

    print(f"{so_path}: canary={has_canary}, .text={text_size}B{flag}")
```

```bash
pip install lief
python3 check_canary.py
```

### 3.9 Metode H — MobSF

```bash
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest
```

Upload APK → bagian **Binary Analysis** / **Shared Object Analysis** menampilkan status `STACK CANARY` per `.so`. Catat bahwa MobSF **tidak** secara otomatis menerapkan pengecualian false positive Flutter/React Native — hasil mentahnya tetap perlu ditinjau manual sesuai §1.5.

### 3.10 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Mendeteksi canary? | Membedakan false positive? | Cocok untuk CI/CD? | Kapan dipakai |
|---|---|---|---|---|---|
| **A** | rabin2 (MASTG) | ✅ | ❌ | Sedang | **Baseline resmi** — deteksi cepat |
| **B** | nm/readelf/strings manual | ✅ (lebih detail) | Sebagian (ukuran `.text`) | Rendah | Verifikasi awal indikasi false positive |
| **C** | checksec.py | ✅ | ❌ | ✅ | Ringkasan cepat + mencakup TEST-0222 sekaligus |
| **D** | APKiD | — (identifikasi framework) | ✅ **(langkah wajib)** | ✅ | **Triase pertama** sebelum menilai FAIL |
| **E** | Validasi Flutter | ✅ | ✅ **(definitif untuk Flutter)** | Sedang | `.so` teridentifikasi Flutter engine |
| **F** | Ghidra (React Native) | ✅ | ✅ **(paling definitif)** | Rendah | `.so` React Native tanpa canary, ukuran signifikan |
| **G** | LIEF | ✅ | Sebagian (heuristik ukuran) | ✅ **(terbaik untuk gate)** | Audit massal otomatis dengan flag awal false positive |
| **H** | MobSF | ✅ | ❌ | Sebagian | Laporan menyeluruh siap kutip |

**Kombinasi minimum yang aku rekomendasikan:** **D (APKiD) → A/C (rabin2/checksec) → B (verifikasi manual untuk setiap FAIL)**.
D menentukan apakah aplikasi memakai framework dengan false positive dikenal; A/C memberi hasil cepat; setiap `canary: false` yang tersisa **wajib** diverifikasi dengan Metode B sebelum dilaporkan sebagai temuan — inilah cara menjalankan instruksi eksplisit MASTG untuk "manual review of source code and compilation flags". Gunakan **F (Ghidra)** untuk kasus React Native yang meragukan, dan **G (LIEF)** sebagai gate CI dengan heuristik awal.

---

### 3.11 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG:**

> **Observation:** *"The output should show all the security features enabled for each native library, including stack canaries."*
>
> **Evaluation:** *"The test case **fails** if stack canaries are disabled."*
>
> *"When evaluating this please note that there are potential **expected false positives** for which the test case should be considered as **passed**."*

Berbeda dari MASTG-TEST-0222, kriteria di sini **secara eksplisit tidak sesederhana kelihatannya** — klausa false positive adalah bagian integral dari evaluasi, bukan catatan tambahan opsional.

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi | Contoh bukti |
|---|---|---|
| F1 | `.so` **bukan** milik Flutter/React Native (atau framework memory-safe lain) menunjukkan `canary: false` | `rabin2 -I libcustom_crypto.so` → `canary false`, dan file memiliki banyak fungsi C/C++ kompleks |
| F2 | Library C/C++ kustom milik aplikasi sendiri dikompilasi tanpa `-fstack-protector-strong`/`-all` | Verifikasi build script/`CMakeLists.txt` mengonfirmasi ketiadaan flag |
| F3 | `.so` React Native yang **signifikan ukurannya** dan memiliki stack buffer call, tetapi tidak ada `stack_chk_fail` | Dikonfirmasi via Ghidra (§3.7) — bukan kasus "kosong" atau "tanpa buffer lokal" |
| F4 | `.so` pihak ketiga (SDK non-Flutter/RN) yang dikompilasi dengan toolchain lama tanpa hardening | SDK usang, bukan bagian dari kerangka kerja dengan pengecualian resmi |
| F5 | Hanya sebagian ABI yang kekurangan canary sementara yang lain memilikinya | Build script tidak konsisten antar arsitektur |
| F6 | Hanya `-fstack-protector` polos (tanpa `-strong`/`-all`) dipakai untuk kode yang menangani data sensitif | Cakupan proteksi terlalu sempit (§1.4) — meski secara teknis tool melaporkan `canary: true`, MASTG-TECH-0023-style review menunjukkan fungsi kritis tidak tercakup |

> Catat bahwa F6 memerlukan analisis lebih dalam daripada sekadar `canary: true`/`false` biner — tool seperti `rabin2` umumnya hanya melaporkan **keberadaan** mekanisme canary di binary, bukan **cakupan** flag mana yang dipakai. Untuk membedakan `-fstack-protector` polos dari `-strong`/`-all`, perlu meninjau build configuration secara langsung.

**Contoh bukti (ilustratif — MASTG belum menyediakan demo resmi untuk test ini):**

```bash
$ apkid YourApp.apk | grep -A2 "libcustom_crypto"
[+] lib/arm64-v8a/libcustom_crypto.so
    (tidak teridentifikasi sebagai bagian framework dikenal)

$ rabin2 -I YourApp/lib/arm64-v8a/libcustom_crypto.so | grep canary
canary   false

$ nm -D YourApp/lib/arm64-v8a/libcustom_crypto.so | grep stack_chk
# (tidak ada hasil - benar-benar tidak ada)

$ readelf -S YourApp/lib/arm64-v8a/libcustom_crypto.so | grep "\.text"
  [13] .text  PROGBITS  0000000000012000  00012000  0000000000045000  ...
# .text berukuran 0x45000 (~280KB) - library SUBSTANSIAL dengan banyak fungsi
```

Interpretasi: library kripto kustom (bukan bagian Flutter/RN), berukuran signifikan, tanpa jejak `stack_chk_fail` sama sekali → **FAIL** yang sah, bukan false positive.

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi | Contoh bukti |
|---|---|---|
| P1 | Semua `.so` non-framework menunjukkan `canary: true` dengan cakupan `-strong`/`-all` terkonfirmasi | `canary true` + build script menunjukkan `-fstack-protector-strong` |
| P2 | `.so` teridentifikasi sebagai **Flutter engine** (`libapp.so`, `libflutter.so`) tanpa canary | **PASS by design** — Dart memitigasi buffer overflow lewat mekanisme bahasa |
| P3 | `.so` React Native yang **kosong/minim** di build release tanpa canary | `libruntimeexecutor.so` dengan `.text` mendekati nol, tidak ada method calls |
| P4 | `.so` React Native yang berisi kode tetapi **tidak memiliki stack buffer call** | Dikonfirmasi Ghidra: fungsi tidak mendeklarasikan array/buffer lokal berisiko, sesuai penjelasan resmi tim React Native |
| P5 | Library dikompilasi via NDK toolchain standar tanpa modifikasi flag yang menghilangkan proteksi | Build config bersih, tidak ada `-fno-stack-protector` |

**Contoh output yang menandakan PASS (kasus Flutter — bukan false alarm):**

```bash
$ apkid YourApp.apk
[+] lib/arm64-v8a/libapp.so
    manipulator : Dart AOT snapshot (Flutter)

$ rabin2 -I YourApp/lib/arm64-v8a/libapp.so | grep canary
canary   false

# INI BUKAN TEMUAN — sesuai https://docs.flutter.dev/reference/security-false-positives
# Dart memitigasi buffer overflow lewat memory safety bahasa, bukan lewat stack canary C.
```

**Contoh output yang menandakan PASS (kasus React Native "kosong" — bukan false alarm):**

```bash
$ python3 check_canary.py
YourApp/lib/arm64-v8a/libreact_render_debug.so: canary=False, .text=48B  [KEMUNGKINAN FALSE POSITIVE - .text sangat kecil]
YourApp/lib/arm64-v8a/libnative-lib.so: canary=True, .text=182340B
```

Verifikasi lanjutan pada `libreact_render_debug.so` mengonfirmasi file memang tidak memiliki method call di build release — konsisten dengan §1.5 Kategori 2a. **PASS dengan catatan dokumentasi.**

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Ini test di mana "output tool = FAIL" paling sering SALAH tanpa verifikasi lanjutan.** Tidak seperti kebanyakan test statis lain, MASTG secara eksplisit memperingatkan bahwa hasil mentah alat (`canary: false`) **tidak boleh langsung dilaporkan sebagai temuan** tanpa review manual source code dan compilation flags. Melaporkan output rabin2 apa adanya berisiko tinggi menghasilkan false positive yang akan dibantah developer dengan mudah (dan sah) menggunakan dokumentasi resmi Flutter/React Native.

2. **Selalu identifikasi framework LEBIH DULU (Metode D) sebelum menilai apa pun.** Ini urutan kerja yang benar: (1) identifikasi apakah `.so` berasal dari Flutter/React Native/framework lain dengan pengecualian dikenal, (2) baru kemudian jalankan pemeriksaan canary, (3) untuk `.so` non-framework yang FAIL, verifikasi lebih lanjut dengan Metode B/F.

3. **Ukuran `.text` dan jumlah symbol adalah sinyal awal yang berguna, tetapi bukan bukti definitif.** File yang sangat kecil (`.text` < ~200 byte) atau tanpa exported function kemungkinan besar false positive Kategori 2a. Namun untuk kepastian, ikuti instruksi MASTG: review source code atau gunakan Ghidra untuk memverifikasi struktur fungsi secara langsung.

4. **Daftar contoh false positive di overview MASTG (`libruntimeexecutor.so`, `libreact_render_debug.so`, dll.) bisa berubah antar versi React Native.** Jangan mem-blacklist nama file secara membabi buta sebagai "selalu PASS" — nama dan perilaku file `.so` dapat berubah antar rilis framework. Verifikasi ulang kondisi aktualnya (ukuran, symbol) setiap kali menguji versi aplikasi baru.

5. **Bedakan level flag, bukan hanya keberadaannya (§1.4).** `rabin2`/`checksec` pada umumnya melaporkan biner: canary ada atau tidak. Mereka **tidak membedakan** `-fstack-protector` polos (cakupan sempit) dari `-fstack-protector-strong`/`-all` (cakupan luas). Untuk pengujian white-box dengan akses source code, periksa langsung `CMakeLists.txt`/`Android.mk`/`build.gradle` untuk memastikan flag yang dipakai sesuai rekomendasi MASTG.

6. **Framework lain di luar Flutter/React Native juga mungkin punya alasan sah untuk tidak memakai canary** — misalnya library yang murni ditulis dalam Rust (yang punya jaminan memory safety sendiri) tetapi di-link sebagai `.so` di dalam APK Android. Terapkan prinsip yang sama: identifikasi bahasa/toolchain asal sebelum menyimpulkan FAIL.

7. **Output kosong (tidak ada `.so` sama sekali) berarti aplikasi murni Java/Kotlin — test ini secara otomatis PASS/Not Applicable**, karena tidak ada objek uji. Ini bukan kegagalan pengujian, melainkan cakupan yang memang tidak relevan bagi aplikasi tersebut.

8. **Severity dimodulasi:**

   | Faktor | Severity |
   |---|---|
   | `.so` non-framework yang memproses data sensitif/parsing input eksternal tanpa canary | **Tinggi** — kelas kerentanan CWE-121/CWE-787 lebih mudah dieksploitasi |
   | `.so` non-framework non-kritis tanpa canary | **Menengah** |
   | Hanya `-fstack-protector` polos dipakai (bukan `-strong`) pada kode yang menangani parsing data eksternal | **Menengah** — cakupan proteksi tidak memadai untuk fungsi berisiko |
   | Flutter/React Native "kosong" tanpa canary | **Bukan temuan** (false positive terdokumentasi) |
   | Semua `.so` non-framework memiliki canary dengan cakupan `-strong`/`-all` | **Bukan temuan** |

9. **Dokumentasikan secara eksplisit status false positive.** Untuk setiap `.so` yang menunjukkan `canary: false` tetapi dinilai PASS, catat **alasan spesifiknya** (Flutter by design / RN file kosong / RN tanpa stack buffer call / bahasa memory-safe lain) beserta bukti pendukung (ukuran `.text`, hasil Ghidra, atau referensi dokumentasi resmi framework). Ini penting agar hasil audit dapat direproduksi dan tidak terlihat sebagai "diloloskan tanpa alasan" oleh pembaca laporan.

---

## 4. Rekomendasi Perbaikan

### 4.1 Prinsip Utama

**Prioritas 1 — Pastikan flag stack protector yang memadai untuk kode C/C++ kustom.**

```cmake
# CMakeLists.txt
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fstack-protector-strong")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fstack-protector-strong")
```

```makefile
# Android.mk (bila masih memakai ndk-build)
LOCAL_CFLAGS += -fstack-protector-strong
LOCAL_CPPFLAGS += -fstack-protector-strong
```

Gunakan **`-fstack-protector-strong`** sebagai baseline (bukan `-fstack-protector` polos) — MASTG dan mayoritas panduan hardening modern (termasuk kernel Linux) merekomendasikan level ini sebagai keseimbangan terbaik antara cakupan keamanan dan biaya performa.

**Prioritas 2 — Jangan menonaktifkan proteksi ini secara manual.**

```cmake
# ❌ SALAH — jangan pernah menambahkan ini tanpa alasan kuat
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-stack-protector")
```

**Prioritas 3 — Gunakan toolchain NDK terkini.** NDK modern berbasis Clang biasanya sudah mengaktifkan `-fstack-protector-strong` secara default untuk build release — masalah umumnya muncul dari toolchain sangat lama atau override eksplisit.

**Prioritas 4 — Untuk pengembang framework (Flutter/React Native), dokumentasikan pengecualian secara eksplisit di kebijakan keamanan internal.** Bila tim kamu membangun/memelihara library native untuk framework semacam ini, ikuti pola yang sudah divalidasi tim React Native: jangan menambahkan proteksi yang tidak memberi manfaat keamanan nyata semata demi "melewati scanner", tetapi **dokumentasikan** alasan teknisnya secara terbuka sehingga auditor eksternal (dan tim keamanan internal) dapat memverifikasi klaim tersebut tanpa ambiguitas — seperti yang dilakukan Flutter dan React Native dalam dokumentasi publik mereka.

**Prioritas 5 — Audit SDK pihak ketiga non-framework.** Bila library kripto/parsing/image-processing pihak ketiga (bukan bagian dari Flutter/RN) ditemukan tanpa canary, ini murni tanggung jawab vendor tersebut — minta build ulang dengan flag yang sesuai, atau evaluasi penggantian.

**Prioritas 6 — Verifikasi ulang di setiap rilis, dengan kesadaran soal false positive.** Integrasikan Metode G (LIEF) ke CI/CD, tetapi **jangan** membuatnya gagal otomatis untuk `.so` yang sudah diketahui dan didokumentasikan sebagai false positive — gunakan allowlist eksplisit untuk file-file tersebut (dengan justifikasi tertaut) agar gate tidak menghasilkan noise berulang.

```python
# Contoh allowlist di CI
KNOWN_FALSE_POSITIVES = {
    "libapp.so": "Flutter Dart AOT - memory safety by language design",
    "libflutter.so": "Flutter engine - same as above",
    "libruntimeexecutor.so": "React Native - empty in release build",
    "libreact_render_debug.so": "React Native - empty in release build",
}
```

**Prioritas 7 — Terapkan hardening menyeluruh, bukan hanya canary.** Sejalan dengan MASTG-TEST-0222 dan MASTG-KNOW-0006, canary paling efektif dikombinasikan dengan PIE, RELRO, NX, dan `_FORTIFY_SOURCE`:

```cmake
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fstack-protector-strong -D_FORTIFY_SOURCE=2")
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,-z,relro,-z,now -Wl,-z,noexecstack")
```

### 4.2 Checklist Remediasi

- [ ] Framework yang dipakai aplikasi sudah diidentifikasi (Flutter/React Native/native murni/lainnya) sebagai langkah pertama
- [ ] Setiap `.so` dengan `canary: false` sudah diverifikasi: false positive terdokumentasi, atau temuan sah
- [ ] Untuk temuan sah: kode C/C++ kustom dikompilasi dengan `-fstack-protector-strong` (bukan hanya `-fstack-protector` polos)
- [ ] Tidak ada `-fno-stack-protector` di konfigurasi build
- [ ] Toolchain NDK yang dipakai adalah versi terkini
- [ ] Setiap pengecualian false positive didokumentasikan secara eksplisit dengan bukti (ukuran `.text`, hasil Ghidra, atau referensi resmi framework)
- [ ] Library pihak ketiga non-framework yang tanpa canary sudah dikonfirmasi ke vendor atau diganti
- [ ] Semua ABI (`arm64-v8a`, `armeabi-v7a`, `x86_64`, `x86`) diverifikasi konsisten
- [ ] Allowlist false positive terdokumentasi diintegrasikan ke gate CI/CD agar tidak menghasilkan noise berulang
- [ ] Hardening menyeluruh diterapkan (canary + PIE + RELRO + NX + FORTIFY_SOURCE)
- [ ] **Verifikasi ulang:** jalankan kembali MASTG-TEST-0223 setelah setiap perubahan dependency native
- [ ] **Verifikasi silang:** jalankan MASTG-TEST-0222 (PIC/PIE) — tool dan langkah identik, laporkan sebagai temuan terpisah

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0223: Stack Canaries Not Enabled](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0223/)
- [MASTG-TEST-0222: Position Independent Code (PIC) Not Enabled](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0222/)
- [MASWE-0045: Compiler-Provided Security Features Not Used](https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-0045/)
- [MASTG-KNOW-0006: Binary Protection Mechanisms](https://mas.owasp.org/MASTG/knowledge/android/MASVS-CODE/MASTG-KNOW-0006/)
- [MASTG-TECH-0157: Extracting Bundled Native Libraries](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0157/)
- [MASTG-TECH-0115: Obtaining Compiler-Provided Security Features](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0115/)
- [MASTG — Testing Code Quality (Binary Protection Mechanisms, Stack Smashing Protection)](https://mas.owasp.org/MASTG/0x04h-Testing-Code-Quality/)
- [MASTG-TOOL-0129: radare2 (rabin2)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0129/)
- [MASVS-CODE: Code Quality](https://mas.owasp.org/MASVS/08-MASVS-CODE/)
- [OWASP Mobile Top 10 2024 — M7: Insufficient Binary Protections](https://owasp.org/www-project-mobile-top-10/2023-risks/m7-insufficient-binary-protections.html)

### 5.2 Dokumentasi Framework (Sumber False Positive Resmi)

- [Flutter — Security false positives (Shared objects should use stack canary values)](https://docs.flutter.dev/reference/security-false-positives#shared-objects-should-use-stack-canary-values)
- [React Native GitHub Issue #36870 — Stack canary discussion](https://github.com/react/react-native/issues/36870#issuecomment-1714007068)
- [OWASP MASTG PR #3049 — React Native stack protector discussion](https://github.com/OWASP/mastg/pull/3049#pullrequestreview-2420837259)

### 5.3 Dokumentasi Resmi Android / Google / AOSP

- [NDK Build System Maintainers Guide — Additional Required Arguments](https://android.googlesource.com/platform/ndk/+/master/docs/BuildSystemMaintainers.md#additional-required-arguments)
- [Android — Use of native code (security risks)](https://developer.android.com/privacy-and-security/risks/use-of-native-code)
- [Android NDK — Application Binary Interfaces (ABI)](https://developer.android.com/ndk/guides/abis)

### 5.4 Riset Teknis Stack Canary

- [Red Hat — Security Technologies: Stack Smashing Protection (StackGuard)](https://www.redhat.com/en/blog/security-technologies-stack-smashing-protection-stackguard)
- [Red Hat Developer — Use compiler flags for stack protection in GCC and Clang](https://developers.redhat.com/articles/2022/06/02/use-compiler-flags-stack-protection-gcc-and-clang)
- [LWN.net — "Strong" stack protection for GCC](https://lwn.net/Articles/584225/)
- [outflux.net — -fstack-protector-strong explained (Kees Cook)](https://outflux.net/blog/archives/2014/01/27/fstack-protector-strong/)
- [ARM Developer — -fstack-protector, -fstack-protector-all, -fstack-protector-strong, -fno-stack-protector](https://developer.arm.com/documentation/dui0774/latest/Compiler-Command-line-Options/-fstack-protector---fstack-protector-all---fstack-protector-strong---fno-stack-protector)
- [HackTricks — Stack Canaries](https://hacktricks.wiki/en/binary-exploitation/common-binary-protections-and-bypasses/stack-canaries/index.html)
- [CTF Wiki EN — Canary](https://ctf-wiki.mahaloz.re/pwn/linux/mitigation/canary/)
- [Phrack #67 — StackGuard internals](http://phrack.org/archives/issues/67/13.txt)
- [Zatoichi Engineer — Stack Smashing Protection and Its Performance Impact](https://zatoichi-engineer.github.io/2017/10/04/stack-smashing-protection.html)
- [arXiv — Is the Canary Dead? On the Effectiveness of Stack Canaries](https://cactilab.github.io/assets/pdf/canary2024xi.pdf)

### 5.5 Standar & Taksonomi

- [CWE-121: Stack-based Buffer Overflow](https://cwe.mitre.org/data/definitions/121.html)
- [CWE-787: Out-of-bounds Write](https://cwe.mitre.org/data/definitions/787.html)
- [CWE-693: Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html)
- [NIST SP 800-163 Rev.1 — Vetting the Security of Mobile Applications](https://csrc.nist.gov/publications/detail/sp/800-163/rev-1/final)

### 5.6 Dokumentasi Tools

- [radare2 — rabin2 documentation](https://book.rada.re/tools/rabin2/headers.html)
- [checksec.py — PyPI](https://pypi.org/project/checksec.py/)
- [LIEF — Library to Instrument Executable Formats](https://github.com/lief-project/LIEF)
- [MobSF — Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)
- [APKiD — Android Application Identifier](https://github.com/rednaga/APKiD)
- [Ghidra — software reverse engineering framework](https://ghidra-sre.org/)
- [GNU Binutils — nm / readelf / objdump](https://www.gnu.org/software/binutils/)

---

*Dokumen ini disusun berdasarkan OWASP MASTG (rilis terkini per September 2026), dokumentasi resmi Flutter dan React Native (sumber utama false positive), dokumentasi AOSP/NDK, serta riset teknis tentang mekanisme stack smashing protection. Test ini belum memiliki demo (MASTG-DEMO) resmi dari MASTG.*
