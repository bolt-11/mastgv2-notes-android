# MASTG-TEST-0222 Position Independent Code (PIC) Not Enabled

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0222 |
| **Platform** | Android |
| **Kategori MASVS** | **MASVS-CODE** (MASVS-CODE-4: Aplikasi memvalidasi kualitas kompilasi & konfigurasi build) |
| **Weakness** | **MASWE-0045** — *Compiler-Provided Security Features Not Used* |
| **Tipe Pengujian** | **Static**, Code |
| **Profile** | **L2 saja** |
| **⚠️ Status khusus** | **`deprecated_since: 21`** — lihat §1.2, ini mengubah cara test ini harus dibaca |
| **Knowledge** | MASTG-KNOW-0006 (Binary Protection Mechanisms) |
| **Teknik terkait** | MASTG-TECH-0157 (Extracting Bundled Native Libraries), MASTG-TECH-0115 (Obtaining Compiler-Provided Security Features) |
| **Demo terkait** | — (MASTG belum menyediakan demo untuk test ini) |
| **Test bersaudara** | MASTG-TEST-0223 (Stack Canaries Not Enabled) — MASWE-0045 yang sama, langkah identik |
| **CWE terkait** | CWE-1259 (Improper Restriction of Security Token Assignment), CWE-121 (Stack-based Buffer Overflow), CWE-787 (Out-of-bounds Write), CWE-1173 (Improper Use of Validation Framework) — lebih tepatnya dipetakan lewat **CWE-119** (memory buffer boundary) sebagai konteks eksploitasi yang dimitigasi PIE |
| **Objek yang diuji** | File `.so` (native library NDK) di dalam `lib/<abi>/` pada APK — **bukan** kode Java/Kotlin |

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian

Kutipan langsung dari overview MASTG:

> *"This test case checks if the native libraries of the app are compiled without enabling **Position Independent Code (PIC)**, a common mitigation technique against memory corruption attacks."*
>
> *"Since Android 5.0 (API level 21), Android **requires all dynamically linked executables to support PIE**."*
>
> *"Android requires Position-independent executables beginning with API 21. **Clang builds PIE executables by default.** If invoking the linker directly or not using Clang, use `-pie` when linking."*

Test ini murni tentang **binary native** — file `.so` yang dikompilasi dari kode C/C++ via Android NDK, atau library pihak ketiga yang di-bundle dalam bentuk pre-compiled. Ini **bukan** tentang kode Java/Kotlin (yang berjalan di ART/Dalvik dan sudah aman dari kelas kerentanan ini secara desain).

### 1.2 Catatan Kritis: Frontmatter `deprecated_since: 21`

Ini hal pertama yang harus dipahami sebelum menjalankan test ini, dan **tidak dijelaskan eksplisit** di teks overview — hanya terlihat di metadata frontmatter file sumber MASTG.

Nilai `deprecated_since: 21` menandakan bahwa test ini **secara efektif sudah usang sejak API level 21**, karena:

> *"With Android 5.0 (API level 21), support for **non-PIE enabled native libraries was dropped**, and since then, **PIE is enforced by the linker**."* — MASTG-KNOW-0006

Konsekuensi praktisnya sangat penting untuk cara kamu membaca hasil test ini:

- **Sejak API 21, dynamic linker Android (`linker`/`linker64`) menolak me-load `.so` yang bukan PIE.** Ini bukan sekadar rekomendasi kompiler — ini **penegakan tingkat sistem operasi**. Kode sumbernya ada di `bionic/linker/linker_main.cpp` (dirujuk MASTG-KNOW-0006).
- **Hampir semua aplikasi Android yang dirilis hari ini menargetkan `minSdkVersion` ≥ 21** (Google Play sendiri mewajibkan `targetSdkVersion` jauh lebih tinggi). Artinya, native library non-PIE **tidak akan pernah berhasil dimuat** di perangkat modern — aplikasi akan crash saat startup, bukan diam-diam berjalan dengan mitigasi yang lemah.
- **Clang (compiler default NDK) membuat binary PIE secara default** sejak lama. Untuk menghasilkan `.so` non-PIE hari ini, developer harus **secara aktif dan sengaja** menambahkan flag `-no-pie` atau memakai toolchain yang sangat usang — sesuatu yang nyaris tidak pernah terjadi tanpa disengaja.

**Bagaimana ini mengubah cara menilai temuan:**

| Skenario | Kemungkinan realistis | Implikasi |
|---|---|---|
| Aplikasi modern dengan `minSdkVersion` ≥ 21 memakai toolchain NDK standar | **Hampir pasti PASS** tanpa perlu diuji secara mendalam | Test ini jadi *sanity check* cepat, bukan area investigasi utama |
| Aplikasi dengan `minSdkVersion` < 21 (sangat jarang di 2026) | Berpotensi FAIL bila memang menyasar perangkat lama | Periksa apakah developer benar-benar mendukung Android < 5.0 |
| `.so` pihak ketiga yang di-bundle (SDK closed-source, library lama) | Kemungkinan kecil tapi **bukan nol** — SDK usang yang di-compile ulang tanpa update toolchain | **Inilah target investigasi paling realistis** untuk test ini |
| Binary yang dimuat secara manual via `dlopen()` di luar linker sistem (jarang) | Bisa jadi non-PIE tanpa terdeteksi linker enforcement | Kasus tepi yang jarang ditemukan di aplikasi konsumen |

**Kesimpulan praktis:** jangan mengharapkan menemukan banyak native library non-PIE pada aplikasi modern. Nilai test ini pada 2026 lebih sebagai **audit kepatuhan/hygiene** dan **jaring pengaman untuk library pihak ketiga usang**, bukan sebagai area yang secara statistik sering menghasilkan temuan pada aplikasi baru. Tetap laporkan hasilnya secara jujur — tetapi kalibrasikan ekspektasi tim dan effort yang dialokasikan sesuai kenyataan ini.

### 1.3 Landasan Teknis: Apa itu PIC/PIE dan Mengapa Penting

**Position Independent Code (PIC)** adalah kode mesin yang dapat dieksekusi dengan benar **di alamat memori mana pun**, tanpa perlu dimodifikasi (tidak memakai alamat absolut hardcoded, melainkan referensi relatif). **Position Independent Executable (PIE)** adalah executable (atau shared library) yang seluruh bagiannya dikompilasi sebagai PIC, sehingga **seluruh image binary** — bukan hanya bagian tertentu — dapat dimuat di alamat berapa pun.

**Hubungannya dengan ASLR (Address Space Layout Randomization)** adalah kuncinya:

- **ASLR** adalah mitigasi tingkat OS yang mengacak lokasi memori dari stack, heap, dan shared library setiap kali proses dijalankan.
- **Tanpa PIE, base address dari binary executable itu sendiri tetap tetap (fixed)** meski ASLR aktif untuk komponen lain. Ini membuka celah nyata: penyerang yang mengeksploitasi kerentanan memory corruption (buffer overflow, dsb.) dapat **menghitung alamat gadget dengan pasti** dari segmen `.text`, `.plt`, dan `.got` binary yang tidak ter-randomize — memungkinkan serangan **Return-Oriented Programming (ROP)** dan teknik **ret2plt** untuk mem-bypass ASLR sepenuhnya.
- **Dengan PIE, seluruh binary (termasuk dependensinya) dimuat di alamat acak setiap eksekusi** — melengkapi ASLR sehingga penyerang tidak lagi punya "jangkar" alamat tetap untuk membangun rantai ROP secara andal.

Riset akademik menegaskan ini secara langsung: binary yang dikompilasi tanpa opsi PIE **tetap rentan meski ASLR aktif penuh**, karena penyerang dapat memanfaatkan segmen `.text`/`.plt`/`.got` di dalam executable itu sendiri. Menambahkan PIE membuat eksploitasi semacam ini gagal, karena setiap eksekusi memuat binary dan seluruh dependensinya di lokasi virtual memory yang acak.

**Ringkasan mitigasi:**

| Tanpa PIE | Dengan PIE |
|---|---|
| Base address binary **tetap** meski ASLR aktif | Base address binary **ikut ter-randomize** |
| Gadget ROP dapat dihitung dari alamat fixed | Alamat gadget berubah setiap eksekusi — ROP jauh lebih sulit dibangun andal |
| Serangan ret2plt/ret2libc terhadap `.plt`/`.got` layak dilakukan | Serangan yang sama menjadi tidak praktis tanpa kebocoran alamat tambahan (info leak) |

### 1.4 Posisi dalam Rangkaian Binary Protection Mechanisms

MASTG-KNOW-0006 mendaftar beberapa mekanisme proteksi binary untuk Android native library, dan PIC/PIE hanyalah satu di antaranya:

| Mekanisme | Test MASTG terkait | Status di Android |
|---|---|---|
| **PIC/PIE** | **MASTG-TEST-0222** *(dokumen ini)* | Enforced oleh linker sejak API 21 |
| **Stack Smashing Protection (canary)** | MASTG-TEST-0223 (langkah identik, tool sama) | **Tidak** ditegakkan sistem — bergantung flag kompilasi (`-fstack-protector-strong`) |
| **Manajemen memori** | — (tidak ada test statis spesifik; relevan untuk review kode manual C/C++) | Manual — developer bertanggung jawab penuh, tidak ada garbage collection di native |

Perhatikan asimetri penting: **PIE ditegakkan sistem operasi**, sementara **stack canary tidak**. Inilah mengapa MASTG-TEST-0223 (test bersaudara langsung, dengan langkah pengujian yang identik) jauh lebih mungkin menghasilkan temuan nyata — linker tidak menolak me-load `.so` yang kekurangan canary, hanya PIE yang ditegakkan secara keras. Jalankan kedua test ini bersamaan karena keduanya memakai tool dan alur yang sama persis (MASTG-TECH-0157 + MASTG-TECH-0115).

### 1.5 Cakupan Objek Uji

MASTG-KNOW-0006 menjelaskan mengapa fokusnya hanya pada native library:

> *"In general all binaries should be tested... However, on Android we will focus on **native libraries** since the **main executables are considered safe**."*

Ini karena:
- Kode aplikasi Java/Kotlin dikompilasi ke Dalvik bytecode dan dieksekusi via ART — dianggap **memory-safe** untuk kelas kerentanan buffer overflow yang dimitigasi PIE/canary.
- Yang perlu diuji adalah **`.so` di dalam `lib/<abi>/`** — baik yang dikompilasi sendiri lewat NDK, maupun yang **di-bundle sebagai dependency pihak ketiga** (SDK analytics, image processing, kripto native, game engine, dll.).

**Arsitektur (ABI) yang biasanya ada dalam satu APK:**

| ABI | Target |
|---|---|
| `arm64-v8a` | Perangkat ARM 64-bit modern (mayoritas device saat ini) |
| `armeabi-v7a` | Perangkat ARM 32-bit lama |
| `x86_64` | Emulator/perangkat x86 64-bit |
| `x86` | Emulator/perangkat x86 32-bit lama |

**Penting:** periksa **setiap ABI**, bukan hanya satu. Kadang hanya satu arsitektur yang luput dari hardening (mis. build script custom yang berbeda untuk `armeabi-v7a` versi lama), sementara `arm64-v8a` sudah benar.

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | MASTG ID | Fungsi |
|---|---|---|
| **rabin2** (bagian dari radare2) | MASTG-TOOL-0129 | **Tool resmi MASTG** untuk membaca header ELF dan properti keamanan binary, termasuk PIC/PIE |
| **unzip / apktool** | MASTG-TOOL-0011 | Ekstraksi `.so` dari APK (MASTG-TECH-0157) |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **readelf** (binutils) | Alternatif standar Linux — membaca `e_type` header ELF (`DYN` = PIE/shared, `EXEC` = non-PIE) |
| **checksec / checksec.py** | Ringkasan siap pakai: PIE, RELRO, NX, Canary, Fortify dalam satu perintah |
| **file** | Deteksi cepat tipe file ELF, termasuk `pie executable` vs `LSB executable` di beberapa versi |
| **objdump** | Analisis header & disassembly tambahan bila perlu investigasi lebih dalam |
| **Ghidra / IDA Pro** | Analisis mendalam bila perlu memverifikasi struktur relokasi (`.rela.dyn`) secara visual |
| **MobSF** | Menganalisis `.so` secara otomatis dan melaporkan status binary protection dalam laporan APK |
| **APKiD** | Deteksi compiler/toolchain yang dipakai — membantu menjelaskan *mengapa* suatu `.so` non-PIE (toolchain usang?) |
| **LIEF** (Library to Instrument Executable Formats) | Scripting Python untuk audit massal banyak `.so` sekaligus, cocok untuk CI/CD |

### 2.3 Prasyarat Lingkungan

- **Tidak butuh device dan tidak butuh root** — cukup file APK. Sepenuhnya dapat diotomatisasi di CI/CD.
- **Ekstrak semua ABI** yang ada di `lib/` — jangan hanya menguji satu arsitektur.
- **Ketahui `minSdkVersion` aplikasi** (§1.2) — ini konteks penting untuk interpretasi hasil, meski tidak mengubah kriteria evaluasi biner PASS/FAIL itu sendiri.
- **Bedakan `.so` milik aplikasi vs pihak ketiga.** Cek nama file dan simbol untuk mengidentifikasi asal library (mis. `libcrashlytics.so`, `libflutter.so`, `libreactnativejni.so`) — ini menentukan siapa yang bertanggung jawab melakukan remediasi.

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0157** (*Extracting Bundled Native Libraries*) untuk mengekstrak native library dari paket aplikasi.
2. Gunakan **MASTG-TECH-0115** (*Obtaining Compiler-Provided Security Features*) pada setiap native library untuk mendapatkan fitur keamanan yang disediakan compiler.

### 3.2 Metode A — rabin2 *(resmi MASTG)*

**Langkah 1 — Ekstrak native library (MASTG-TECH-0157):**

```bash
# Opsi 1: unzip langsung
unzip -o YourApp.apk "lib/*" -d YourApp
find YourApp/lib -name "*.so"
# YourApp/lib/arm64-v8a/libnative-lib.so
# YourApp/lib/armeabi-v7a/libnative-lib.so
# ...

# Opsi 2: apktool (mempertahankan struktur direktori)
apktool d YourApp.apk -o YourApp
ls -1 YourApp/lib/arm64-v8a/
```

**Langkah 2 — Periksa fitur keamanan compiler (MASTG-TECH-0115):**

```bash
rabin2 -I YourApp/lib/arm64-v8a/libnative-lib.so | grep -E "canary|pic"
```

Contoh output **AMAN** (PIC aktif):

```
canary   true
pic      true
```

Contoh output **TIDAK AMAN** (PIC nonaktif — sesuai contoh resmi MASTG-TECH-0115):

```
pic      false
```

**Untuk melihat seluruh informasi keamanan sekaligus:**

```bash
rabin2 -I YourApp/lib/arm64-v8a/libnative-lib.so
```

```
arch     arm
baddr    0x0
binsz    123456
bintype  elf
bits     64
canary   true
nx       true
pic      true
relocs   true
relro    full
sanitiz  false
static   false
stripped true
...
```

**Untuk memeriksa SEMUA `.so` dan SEMUA ABI sekaligus:**

```bash
for so in $(find YourApp/lib -name "*.so"); do
  echo "=== $so ==="
  rabin2 -I "$so" | grep -E "^pic|^canary|^arch"
done
```

### 3.3 Metode B — readelf *(standar POSIX/binutils, tanpa radare2)*

```bash
# e_type = DYN artinya shared object ATAU position-independent executable (PIE)
# e_type = EXEC artinya executable NON-PIE (bermasalah)
readelf -h YourApp/lib/arm64-v8a/libnative-lib.so | grep "Type:"

# Contoh output PIE (aman):
#   Type: DYN (Shared object file)

# Contoh output NON-PIE (bermasalah, untuk main executable):
#   Type: EXEC (Executable file)
```

> **Catatan penting:** untuk file `.so` (shared library), `e_type` **selalu** `DYN` secara desain ELF — ini tidak secara langsung membuktikan PIE dalam pengertian "posisi independen sepenuhnya". Yang lebih akurat untuk `.so` adalah memeriksa keberadaan **tag dinamis `DT_FLAGS_1` dengan bit `DF_1_PIE`**, atau lebih praktis: percayakan pada `rabin2`/`checksec` yang sudah menangani nuansa ini dengan benar.

```bash
# Cek tag dinamis terkait PIE
readelf -d YourApp/lib/arm64-v8a/libnative-lib.so | grep -i "flags"

# Cek relokasi — binary PIE punya banyak entri R_*_RELATIVE
readelf -r YourApp/lib/arm64-v8a/libnative-lib.so | grep -c "RELATIVE"
```

### 3.4 Metode C — checksec.py *(ringkasan siap pakai, mencakup PIC + fitur lain sekaligus)*

Ini keunggulan besar untuk efisiensi: satu perintah mencakup PIE, RELRO, NX, Canary, dan Fortify — mencakup **baik test ini maupun MASTG-TEST-0223** dalam satu langkah.

```bash
pip install checksec.py
checksec --file=YourApp/lib/arm64-v8a/libnative-lib.so
```

Contoh output:

```
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols      FORTIFY  Fortified  Fortifiable  FILE
Full RELRO      Canary found      NX enabled    PIE enabled     No RPATH   No RUNPATH   No Symbols   Yes      12         15           libnative-lib.so
```

Untuk memeriksa banyak file sekaligus dan mengekspor sebagai JSON (cocok untuk CI):

```bash
checksec --dir=YourApp/lib --output=json > checksec-report.json
jq '.[] | select(.["binary-type"] == "ELF") | {file: .file, pie: .pie}' checksec-report.json
```

### 3.5 Metode D — LIEF *(scripting Python, audit massal untuk CI/CD)*

```python
# check_pie.py
import lief
import glob
import sys

failed = []
for so_path in glob.glob("YourApp/lib/**/*.so", recursive=True):
    binary = lief.parse(so_path)
    if binary is None:
        continue
    is_pie = binary.is_pie
    print(f"{so_path}: PIE={is_pie}")
    if not is_pie:
        failed.append(so_path)

if failed:
    print(f"\n[!] {len(failed)} library TIDAK PIE:")
    for f in failed:
        print(f"    {f}")
    sys.exit(1)
else:
    print("\n[+] Semua native library PIE-enabled.")
```

```bash
pip install lief
python3 check_pie.py
```

Keunggulan: dapat langsung diintegrasikan sebagai *build gate* di pipeline CI/CD (exit code non-zero saat ada temuan), dan lebih mudah di-maintain daripada parsing output teks `rabin2`/`readelf` dengan `grep`.

### 3.6 Metode E — MobSF *(otomatis, laporan siap kutip)*

```bash
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest
```

Upload APK → cari bagian **Binary Analysis** / **Shared Object Analysis** di laporan. MobSF menampilkan status `NX`, `STACK CANARY`, `RELRO`, dan `PIE` untuk setiap `.so` yang ditemukan, biasanya berbasis `checksec` di baliknya. Keunggulan: satu laporan mencakup seluruh aspek keamanan APK (bukan hanya binary protection), memudahkan penyajian ke non-teknis.

### 3.7 Metode F — file / objdump *(pemeriksaan cepat pelengkap)*

```bash
# Identifikasi cepat tipe file
file YourApp/lib/arm64-v8a/libnative-lib.so
# ELF 64-bit LSB shared object, ARM aarch64, ... dynamically linked

# objdump untuk melihat header program (Program Headers) dan segmen
objdump -p YourApp/lib/arm64-v8a/libnative-lib.so | head -30
```

### 3.8 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Mencakup PIE saja? | Mencakup canary/RELRO/NX sekaligus? | Cocok untuk CI/CD batch? | Kapan dipakai |
|---|---|---|---|---|---|
| **A** | rabin2 (MASTG) | ✅ + lainnya | ✅ | Sedang (perlu scripting grep) | **Baseline resmi** |
| **B** | readelf | ✅ (dengan nuansa) | Sebagian | Sedang | Verifikasi silang tanpa radare2; investigasi mendalam struktur ELF |
| **C** | checksec.py | ✅ + lainnya | ✅ **(satu perintah)** | ✅ (output JSON) | **Paling praktis** — sekaligus menjawab TEST-0222 & TEST-0223 |
| **D** | LIEF (Python) | ✅ | ✅ (API lengkap) | ✅ **(terbaik untuk gate CI)** | Audit massal, integrasi pipeline otomatis |
| **E** | MobSF | ✅ | ✅ | Sebagian | Laporan menyeluruh siap kutip |
| **F** | file / objdump | Sebagian (indikatif) | ❌ | Rendah | Triase cepat / sanity check |

**Kombinasi minimum yang aku rekomendasikan:** **C (checksec.py) → A (rabin2 untuk verifikasi silang)**.
checksec.py memberi jawaban paling cepat dan mencakup MASTG-TEST-0223 sekaligus dalam output yang sama; rabin2 sebagai verifikasi karena itu tool yang eksplisit direferensikan MASTG. Untuk audit rutin/CI, gunakan **D (LIEF)** sebagai gate otomatis.

---

### 3.9 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG:**

> **Observation:** *"The output should show all the security features enabled for each native library, including PIC."*
>
> **Evaluation:** *"The test case **fails** if PIC is disabled."*

Kriteria ini sangat sederhana secara literal — tidak ada klausa konteks tambahan seperti pada test kripto. **Satu `.so` dengan PIC/PIE nonaktif sudah cukup untuk FAIL** pada library tersebut.

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi | Contoh bukti |
|---|---|---|
| F1 | `rabin2 -I` menunjukkan `pic false` untuk `.so` mana pun | `pic      false` |
| F2 | `checksec` menunjukkan `No PIE` / `PIE disabled` | `PIE             No PIE` |
| F3 | `readelf -h` menunjukkan `e_type: EXEC` pada binary yang seharusnya PIE | Jarang terjadi pada `.so` murni; lebih relevan untuk binary executable yang di-bundle |
| F4 | Library pihak ketiga (SDK closed-source) di-bundle dalam bentuk non-PIE | SDK lama yang belum di-compile ulang dengan toolchain modern |
| F5 | Hanya sebagian ABI yang non-PIE (mis. `armeabi-v7a` non-PIE, `arm64-v8a` PIE) | Build script custom yang tidak konsisten antar arsitektur |
| F6 | `minSdkVersion` < 21 **dan** aplikasi benar-benar mendukung perangkat tersebut dengan `.so` non-PIE | Kombinasi yang memungkinkan binary non-PIE benar-benar termuat di perangkat lama |

**Contoh bukti (ilustratif — MASTG belum menyediakan demo resmi untuk test ini):**

```bash
$ rabin2 -I lib/armeabi-v7a/libvendor_legacy.so | grep -E "canary|pic"
canary   false
pic      false
```

```bash
$ checksec --file=lib/armeabi-v7a/libvendor_legacy.so
RELRO         STACK CANARY    NX          PIE          RPATH      RUNPATH      FILE
No RELRO      No canary found NX enabled  No PIE       No RPATH   No RUNPATH   libvendor_legacy.so
```

> Catat: MASTG-TECH-0115 sendiri memberi contoh output `pic false` sebagai ilustrasi format perintah — bukan dari skenario aplikasi nyata. Contoh nama file `libvendor_legacy.so` di atas disusun untuk ilustrasi skenario paling realistis (§1.2): SDK/library pihak ketiga yang usang.

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi | Contoh bukti |
|---|---|---|
| P1 | **Semua** `.so` di **semua ABI** menunjukkan `pic true` / `PIE enabled` | `rabin2 -I` → `pic      true` untuk setiap file |
| P2 | Aplikasi dikompilasi dengan NDK/Clang standar tanpa modifikasi linker flag | Tidak ada `-no-pie` di `Android.mk`/`CMakeLists.txt`/`build.gradle` |
| P3 | Library pihak ketiga yang di-bundle juga PIE (SDK modern, di-compile ulang dengan toolchain terkini) | Diverifikasi per-file, bukan diasumsikan |

**Contoh output yang menandakan PASS:**

```bash
$ for so in $(find YourApp/lib -name "*.so"); do
    echo -n "$so: "; rabin2 -I "$so" | grep "^pic"
  done

YourApp/lib/arm64-v8a/libnative-lib.so: pic      true
YourApp/lib/armeabi-v7a/libnative-lib.so: pic      true
YourApp/lib/x86_64/libnative-lib.so: pic      true
YourApp/lib/x86/libnative-lib.so: pic      true
```

```bash
$ python3 check_pie.py
YourApp/lib/arm64-v8a/libnative-lib.so: PIE=True
YourApp/lib/armeabi-v7a/libnative-lib.so: PIE=True

[+] Semua native library PIE-enabled.
```

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Ekspektasikan PASS pada mayoritas aplikasi modern (§1.2).** Ini bukan alasan untuk melewati test, tetapi konteks yang harus disampaikan ke stakeholder: temuan FAIL pada test ini di 2026 adalah **sinyal kuat** ada sesuatu yang tidak biasa (toolchain sangat usang, atau `minSdkVersion` rendah yang disengaja) — bukan hasil dari kelalaian konfigurasi build standar.

2. **`.so` yang berbeda dalam satu APK bisa punya status berbeda.** Jangan berhenti setelah memeriksa satu file — periksa **semua** `.so` di **semua** direktori ABI. Library pihak ketiga yang di-bundle developer sering luput dari hardening yang konsisten dengan kode aplikasi sendiri.

3. **`e_type: DYN` pada `readelf` tidak secara otomatis membuktikan PIE untuk `.so`.** Semua shared object secara desain ELF punya `e_type: DYN` — baik yang PIE maupun tidak dalam pengertian yang lebih ketat. Andalkan `rabin2`/`checksec` yang sudah menangani nuansa deteksi PIE dengan benar melalui kombinasi header dan tag dinamis, bukan `readelf -h` saja.

4. **Bedakan tanggung jawab remediasi.** Bila `.so` yang gagal adalah kode milik developer sendiri, perbaikannya ada di tangan tim (§4). Bila itu SDK pihak ketiga closed-source, opsinya terbatas pada: melaporkan ke vendor, mencari alternatif SDK, atau menerima risiko dengan dokumentasi eksplisit.

5. **Periksa apakah `minSdkVersion` benar-benar mengharuskan kompatibilitas API < 21.** Bila FAIL ditemukan pada aplikasi dengan `minSdkVersion` ≥ 21, ini anomali yang layak diselidiki lebih dalam — kemungkinan build pipeline yang salah konfigurasi, bukan keputusan desain yang disengaja.

6. **Jangan campur adukkan dengan MASTG-TEST-0223.** Meski langkahnya identik dan sering diperiksa dalam satu perintah yang sama (`checksec`/`rabin2`), keduanya adalah dua weakness yang secara nominal terpisah dalam pelaporan MASWE-0045 — laporkan status PIE dan status canary sebagai baris temuan yang berbeda, meski berasal dari satu perintah pengujian.

7. **Severity dimodulasi:**

   | Faktor | Severity |
   |---|---|
   | `.so` inti aplikasi (memproses data sensitif/kripto) non-PIE | **Tinggi** — memperbesar dampak eksploitasi memory corruption bila ada |
   | `.so` pihak ketiga non-kritis (mis. library UI/animasi) non-PIE | **Menengah** |
   | Semua `.so` PIE-enabled | **Bukan temuan** |
   | Temuan hanya pada `minSdkVersion` < 21 yang memang disengaja mendukung perangkat lama | **Informational** — dokumentasikan trade-off dukungan legacy vs keamanan |

8. **Dokumentasikan:** path lengkap setiap `.so` yang diuji beserta ABI-nya, output mentah tool (`rabin2`/`checksec`), status PIE per file, identifikasi apakah file milik aplikasi atau pihak ketiga (berdasarkan nama/simbol), `minSdkVersion` aplikasi, dan — bila FAIL ditemukan — rekomendasi konkret (rebuild sendiri vs kontak vendor).

---

## 4. Rekomendasi Perbaikan

### 4.1 Prinsip Utama

**Prioritas 1 — Jangan menonaktifkan PIE secara manual.** Ini remediasi paling sederhana: Clang (compiler default NDK) sudah membuat PIE secara default. Masalah biasanya muncul karena **override eksplisit**, bukan karena default yang salah.

```gradle
// ❌ SALAH — jangan pernah tambahkan flag ini secara manual
externalNativeBuild {
    cmake {
        cppFlags "-no-pie"     // <-- HAPUS baris ini bila ada
    }
}
```

```cmake
# ❌ SALAH di CMakeLists.txt
set(CMAKE_POSITION_INDEPENDENT_CODE OFF)   # <-- jangan matikan ini

# ✅ BENAR — biarkan default NDK (ON secara implisit untuk shared library)
# Tidak perlu menulis apa pun; atau eksplisitkan untuk kejelasan:
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
```

**Prioritas 2 — Gunakan toolchain NDK terkini.** Jangan memakai `ndk-build` dengan konfigurasi sangat lama (`Android.mk` era `gcc`) tanpa update. NDK modern berbasis Clang menjamin PIE secara default untuk `minSdkVersion` ≥ 21.

```gradle
android {
    ndkVersion "27.0.12077973"   // gunakan versi NDK terkini yang didukung AGP
}
```

**Prioritas 3 — Audit dan tekan vendor untuk library pihak ketiga non-PIE.** Bila `.so` bermasalah berasal dari SDK closed-source:
- Update ke versi terbaru SDK — vendor yang aktif memelihara biasanya sudah memperbaiki ini.
- Bila SDK sudah tidak dipelihara, evaluasi penggantian dengan alternatif yang lebih modern.
- Bila tidak ada pilihan lain dalam jangka pendek, dokumentasikan sebagai **risiko yang diterima** dengan justifikasi bisnis dan rencana mitigasi/penggantian jangka panjang.

**Prioritas 4 — Naikkan `minSdkVersion` bila memungkinkan.** Mendukung Android < 5.0 (API 21) pada 2026 memiliki basis pengguna yang sangat kecil di sebagian besar pasar, sementara mempertahankannya membuka celah untuk kompatibilitas dengan binary non-PIE dan hilangnya berbagai proteksi keamanan platform lainnya (lihat juga MASTG-TEST-0223 dan pertimbangan `targetSdkVersion` di test-test MASVS-CODE lain).

**Prioritas 5 — Verifikasi hardening di setiap rilis, bukan hanya sekali.** Tambahkan pemeriksaan otomatis (Metode D — LIEF, atau checksec) sebagai bagian dari pipeline CI/CD, sehingga perubahan build script atau penambahan dependency baru yang secara tidak sengaja menonaktifkan PIE langsung terdeteksi sebelum rilis.

```bash
# Contoh gate CI sederhana
python3 check_pie.py || { echo "Build gagal: ditemukan .so non-PIE"; exit 1; }
```

**Prioritas 6 — Terapkan hardening lengkap, bukan hanya PIE.** Sejalan dengan MASTG-TEST-0223 dan MASTG-KNOW-0006, pastikan flag kompiler berikut aktif untuk seluruh kode native kustom (di luar cakupan strict test ini, tetapi bagian dari kebijakan hardening yang sama):

```cmake
# CMakeLists.txt — hardening menyeluruh
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fstack-protector-strong -D_FORTIFY_SOURCE=2 -Wformat -Wformat-security")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fstack-protector-strong -D_FORTIFY_SOURCE=2 -Wformat -Wformat-security")
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,-z,relro,-z,now -Wl,-z,noexecstack")
```

### 4.2 Checklist Remediasi

- [ ] Semua `.so` di **semua ABI** (`arm64-v8a`, `armeabi-v7a`, `x86_64`, `x86`) diverifikasi PIE-enabled
- [ ] Tidak ada flag `-no-pie` atau `CMAKE_POSITION_INDEPENDENT_CODE OFF` di konfigurasi build
- [ ] Toolchain NDK yang dipakai adalah versi terkini yang didukung Android Gradle Plugin
- [ ] Library pihak ketiga (SDK closed-source) diverifikasi PIE — bukan diasumsikan aman
- [ ] SDK vendor yang terbukti non-PIE sudah diperbarui, diganti, atau didokumentasikan sebagai risiko diterima
- [ ] `minSdkVersion` ditinjau — apakah dukungan Android < 5.0 masih diperlukan secara bisnis
- [ ] Flag hardening lengkap diterapkan pada kode native kustom (`-fstack-protector-strong`, `-D_FORTIFY_SOURCE=2`, `RELRO`, `NX`)
- [ ] Pemeriksaan PIE diintegrasikan ke pipeline CI/CD sebagai gate otomatis (mis. dengan LIEF/checksec)
- [ ] **Verifikasi ulang:** jalankan kembali MASTG-TEST-0222 setelah setiap perubahan dependency native
- [ ] **Verifikasi silang:** jalankan MASTG-TEST-0223 (Stack Canaries) — langkah dan tool identik, laporkan sebagai temuan terpisah

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0222: Position Independent Code (PIC) Not Enabled](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0222/)
- [MASTG-TEST-0223: Stack Canaries Not Enabled](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0223/)
- [MASWE-0045: Compiler-Provided Security Features Not Used](https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-0045/)
- [MASTG-KNOW-0006: Binary Protection Mechanisms](https://mas.owasp.org/MASTG/knowledge/android/MASVS-CODE/MASTG-KNOW-0006/)
- [MASTG-TECH-0157: Extracting Bundled Native Libraries](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0157/)
- [MASTG-TECH-0115: Obtaining Compiler-Provided Security Features](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0115/)
- [MASTG-TECH-0007: Obtaining Information from the App Package](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0007/)
- [MASTG — Testing Code Quality (Binary Protection Mechanisms, Position Independent Code)](https://mas.owasp.org/MASTG/0x04h-Testing-Code-Quality/)
- [MASTG-TOOL-0129: radare2 (rabin2)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0129/)
- [MASTG-TOOL-0011: apktool](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0011/)
- [MASVS-CODE: Code Quality](https://mas.owasp.org/MASVS/08-MASVS-CODE/)
- [OWASP Mobile Top 10 2024 — M7: Insufficient Binary Protections](https://owasp.org/www-project-mobile-top-10/2023-risks/m7-insufficient-binary-protections.html)

### 5.2 Dokumentasi Resmi Android / Google / AOSP

- [Android Security Enhancements — Android 5.0 (PIE enforcement)](https://source.android.com/docs/security/enhancements/enhancements50)
- [Android Security Enhancements — Android 5 overview](https://source.android.com/docs/security/enhancements/#android-5)
- [NDK Build System Maintainers Guide — Additional Required Arguments (PIE)](https://android.googlesource.com/platform/ndk/+/master/docs/BuildSystemMaintainers.md#additional-required-arguments)
- [Bionic linker source — PIE enforcement (`linker_main.cpp`)](https://cs.android.com/android/platform/superproject/+/master:bionic/linker/linker_main.cpp)
- [Android linker changes for NDK developers](https://android.googlesource.com/platform/bionic/+/master/android-changes-for-ndk-developers.md)
- [Android NDK — Application Binary Interfaces (ABI)](https://developer.android.com/ndk/guides/abis)
- [Android — Use of native code (security risks)](https://developer.android.com/privacy-and-security/risks/use-of-native-code)
- [Android Runtime (ART) overview](https://source.android.com/devices/tech/dalvik/configure)
- [Flutter — Security false positives (stack canary, shared objects)](https://docs.flutter.dev/reference/security-false-positives#shared-objects-should-use-stack-canary-values)

### 5.3 Format ELF & Riset Teknis

- [ELF Format Specification (Linux Foundation)](https://refspecs.linuxfoundation.org/elf/gabi4+/contents.html)
- [LIEF — Android executable formats tutorial](https://lief-project.github.io/doc/latest/tutorials/10_android_formats.html)
- [ResearchGate — ASLR and ROP Attack Mitigations for ARM-Based Android Devices](https://www.researchgate.net/publication/320952677_ASLR_and_ROP_Attack_Mitigations_for_ARM-Based_Android_Devices)
- [FortiGuard Labs — Tutorial of ARM Stack Overflow Exploit: Defeating ASLR with ret2plt](https://www.fortinet.com/blog/threat-research/tutorial-of-arm-stack-overflow-exploit-defeating-aslr-with-ret2plt)
- [arXiv — Security Mitigations for Return-Oriented Programming Attacks](https://arxiv.org/pdf/1008.4099)
- [0x00sec — Exploit Mitigation Techniques: ASLR](https://archive.0x00sec.org/t/exploit-mitigation-techniques-address-space-layout-randomization-aslr/5452)
- [Opensource.com — Identify security properties on Linux using checksec](https://opensource.com/article/21/6/linux-checksec)
- [Siphos blog — High level explanation on some binary executable security](https://blog.siphos.be/2011/07/high-level-explanation-on-some-binary-executable-security/)

### 5.4 Standar & Taksonomi

- [CWE-1259: Improper Restriction of Security Token Assignment](https://cwe.mitre.org/data/definitions/1259.html)
- [CWE-121: Stack-based Buffer Overflow](https://cwe.mitre.org/data/definitions/121.html)
- [CWE-787: Out-of-bounds Write](https://cwe.mitre.org/data/definitions/787.html)
- [NIST SP 800-163 Rev.1 — Vetting the Security of Mobile Applications](https://csrc.nist.gov/publications/detail/sp/800-163/rev-1/final)

### 5.5 Dokumentasi Tools

- [radare2 — rabin2 documentation (The Official Radare2 Book)](https://book.rada.re/tools/rabin2/headers.html)
- [checksec.py — PyPI](https://pypi.org/project/checksec.py/)
- [LIEF — Library to Instrument Executable Formats](https://github.com/lief-project/LIEF)
- [MobSF — Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)
- [APKiD — Android Application Identifier](https://github.com/rednaga/APKiD)
- [Ghidra — software reverse engineering framework](https://ghidra-sre.org/)
- [GNU Binutils — readelf / objdump](https://www.gnu.org/software/binutils/)

---

*Dokumen ini disusun berdasarkan OWASP MASTG (rilis terkini per September 2026), dokumentasi resmi Android Open Source Project (AOSP), spesifikasi ELF, serta riset teknis pihak ketiga tentang ASLR/PIE/ROP. Test ini belum memiliki demo (MASTG-DEMO) resmi dari MASTG, dan frontmatter sumbernya menandai test ini `deprecated_since: 21` — lihat §1.2 untuk penjelasan dampaknya terhadap interpretasi hasil.*
