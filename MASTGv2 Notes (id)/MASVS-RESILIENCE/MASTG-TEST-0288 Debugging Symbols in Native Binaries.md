# MASTG-TEST-0288 Debugging Symbols in Native Binaries

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0288 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-RESILIENCE |
| **Weakness** | MASWE-0061 — *Debug Artifacts Not Removed* (sama seperti kelompok test `StrictMode` — MASTG-TEST-0263/0264/0265 — dalam seri riset ini, kini diterapkan pada binary native) |
| **Tipe Pengujian** | Static, Code |
| **Teknik terkait** | MASTG-TECH-0140 (Obtaining Debugging Information and Symbols) |
| **Demo terkait** | — (tidak ada) |
| **Rule resmi** | — (tidak relevan; ini analisis biner ELF, bukan pattern-matching kode Java/Kotlin) |
| **CWE terkait** | CWE-215 (Insertion of Sensitive Information Into Debugging Code), CWE-540 (Inclusion of Sensitive Information in Source Code) |

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian

Kutipan overview resmi MASTG:

> *"This test checks whether the app includes debugging symbols in its native binaries. Debugging symbols can provide valuable information during reverse engineering and vulnerability analysis by exposing sensitive implementation details such as function names, variable names, and source file references."*

Test ini menyasar **binary native** (`.so`, format ELF) yang dikompilasi dari kode C/C++ lewat Android NDK — bukan bytecode DEX seperti kebanyakan test lain dalam seri riset ini. Simbol debugging (nama fungsi asli, nama variabel, referensi file sumber `.cpp`/baris kode) yang tertinggal di biner rilis memberi **peta gratis** bagi upaya reverse engineering — konsep yang sama seperti dibahas mendalam di dokumen MASTG-TEST-0263 (StrictMode) mengenai bagaimana artefak debug membocorkan struktur internal aplikasi, kini diterapkan pada konteks kode native.

### 1.2 Temuan Paling Penting: NDK Sudah Melakukan Stripping Secara Otomatis dan Agresif

Ini adalah nuansa paling krusial yang membedakan test ini dari kebanyakan test "artefak debug" lain dalam seri riset ini (mis. MASTG-TEST-0226 debuggable flag, MASTG-TEST-0263-0265 StrictMode) — pada test-test tersebut, **developer harus secara aktif menerapkan guard** (`BuildConfig.DEBUG`) untuk mencegah kebocoran ke produksi. Untuk simbol debugging native, situasinya justru **terbalik**: riset komunitas developer NDK menemukan bahwa **toolchain Android NDK secara default dan otomatis melakukan stripping simbol debug**, bahkan dijelaskan sebagai:

> *"The Android SDK (NDK) will strip debugging symbols from native libraries going into an application automatically (in fact **it is very hard to disable**)."*

Ini artinya, **berbeda dari kebanyakan test resilience lain dalam seri ini, kondisi FAIL untuk test ini relatif jarang terjadi pada proyek modern** yang memakai toolchain build standar (Gradle + CMake/ndk-build) tanpa modifikasi konfigurasi eksplisit. FAIL biasanya muncul karena **kesengajaan mengubah pengaturan default** atau **kesalahan konfigurasi build yang spesifik** — bukan kelalaian pasif seperti kebanyakan test lain. Ini mengubah cara penguji harus mendekati investigasi: alih-alih bertanya "apakah developer lupa menambahkan guard?", pertanyaan yang lebih tepat adalah **"konfigurasi build spesifik apa yang menyebabkan simbol ini tertinggal?"**

### 1.3 Perbedaan Krusial: Debug Symbols vs Dynamic Symbols — Mengapa "Nol Simbol" Bukan Ekspektasi yang Realistis

Ini pembeda teknis yang **wajib** dipahami sebelum mengevaluasi hasil pemeriksaan biner, karena berpotensi menyebabkan kesalahan interpretasi yang signifikan:

| Jenis Simbol | Apa isinya | Bisa/harus dihapus? |
|---|---|---|
| **Debug symbols** (`.symtab`, info DWARF) | Nama variabel lokal, nomor baris, referensi file `.cpp` sumber, nama fungsi internal/statis | **Ya, harus dihapus** — inilah target evaluasi test ini |
| **Dynamic symbols** (`.dynsym`) | Nama fungsi yang **wajib tetap terlihat** agar dapat dipanggil dari luar biner — khususnya **entry point JNI** (`Java_com_example_MainActivity_stringFromJNI`) | **Tidak bisa dihapus** — akan merusak fungsionalitas aplikasi bila dihapus |

Riset komunitas menegaskan batasan teknis ini secara eksplisit:

> *"Strip won't remove dynamic symbols, or it would make the library unusable... If your .so is a JNI library, you need to have the JNI entry point functions visible externally."*

**Implikasi penting bagi evaluasi**: penguji **tidak boleh** mengharapkan hasil "nol simbol apa pun" sebagai kondisi PASS — sebuah `.so` yang menjadi JNI library **akan selalu** menampilkan nama fungsi `Java_<package>_<class>_<method>` di tabel `.dynsym` sebagai bagian yang **tidak bisa dihindari** dari cara kerja JNI itu sendiri. Nama-nama fungsi JNI ini memang **membocorkan sedikit informasi** (nama package/class/method Java yang memanggilnya), namun ini adalah **batasan arsitektural** yang berbeda kategorinya dari kebocoran informasi implementasi internal (nama variabel lokal, logika internal fungsi non-JNI, path source file developer) yang menjadi fokus sesungguhnya test ini.

### 1.4 Konsekuensi Keamanan Nyata: Native Code sebagai Permukaan Risiko Memori yang Berbeda

Kode native (C/C++) memiliki profil risiko yang secara fundamental berbeda dari kode Java/Kotlin, karena tidak memiliki proteksi memori otomatis:

> *"Native code languages like C/C++ lack the memory safety features of Java/Kotlin, making them susceptible to vulnerabilities like buffer overflows, use-after-free errors, and other memory corruption issues."*

Ini menjelaskan mengapa kebocoran simbol debugging pada binary native memiliki bobot risiko yang **lebih signifikan** dibanding rekan Java/Kotlin-nya: nama fungsi dan variabel yang bocor memberi peneliti kerentanan (baik defender maupun attacker) **peta langsung** untuk mengidentifikasi fungsi yang menangani parsing input, manajemen buffer, atau operasi memori mentah — titik-titik yang secara historis menjadi lokasi paling umum ditemukannya kerentanan memory corruption (buffer overflow, use-after-free) pada kode C/C++. Riset akademik ("A Risk Estimation Study of Native Code Vulnerabilities in Android Applications") menegaskan bahwa penggunaan kode native lewat JNI **memang** memperluas permukaan risiko aplikasi Android dengan cara yang tidak dimiliki aplikasi Java/Kotlin murni.

### 1.5 Konteks Reverse Engineering: FLIRT dan Batasan Nyata Stripping

Penting untuk memberi ekspektasi yang realistis: **stripping simbol debug bukan jaminan mutlak** terhadap reverse engineering, hanya **menaikkan biaya usahanya**. Tool reverse engineering profesional seperti IDA Pro memiliki teknologi **FLIRT (Fast Library Identification and Recognition Technology)** yang dapat **mengenali kembali** fungsi-fungsi dari library standar/populer bahkan pada biner yang sudah di-strip sepenuhnya, dengan mencocokkan pola byte instruksi terhadap database signature yang sudah dikenal. Riset akademik lain (`punstrip`, ACSAC 2020) bahkan mengeksplorasi teknik machine learning untuk **memulihkan nama fungsi** dari biner stripped. Ini konteks penting bagi laporan audit: stripping simbol debug tetap **wajib** dilakukan sebagai *hardening* dasar (dan sesuai §1.2, sudah dilakukan otomatis oleh toolchain modern), namun **bukan pengganti** kontrol resilience lain seperti obfuscation kode native, anti-tampering, atau deteksi debugger — ia hanya salah satu lapisan dalam strategi defense-in-depth yang lebih luas.

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core, Sesuai MASTG-TECH-0140)

| Tool | Fungsi |
|---|---|
| **radare2** | `i~stripped,linenum,lsyms` — cara cepat memeriksa status stripped/tidak; `is`/`rabin2 -s` untuk melihat simbol yang tersisa |
| **objdump** | `objdump --syms` — cara standar Binutils untuk memeriksa symbol table ELF |
| **nm** | Ekstraksi tabel simbol; `nm -a` untuk simbol lokal, dibandingkan dengan `nm` biasa untuk mendeteksi keberadaan `.symtab` |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **rabin2** (radare2 suite) | `rabin2 -s libnative-lib.so \| grep JNI` — filter khusus simbol JNI untuk memisahkan dari simbol debug lainnya |
| **readelf** | `readelf -S libnative-lib.so` — memeriksa keberadaan section `.debug_info`, `.debug_line` (DWARF) secara langsung, pelengkap yang lebih presisi dibanding sekadar memeriksa symbol table |
| **file** (Unix) | `file libnative-lib.so` — output mencantumkan `not stripped` atau `stripped` secara eksplisit sebagai pemeriksaan sangat cepat |
| **strings** | Ekstraksi string literal dari biner — meski bukan simbol debug secara teknis, string path source file (`/home/dev/project/src/native/...`) yang tertinggal juga membocorkan info struktur proyek serupa |
| **IDA Pro / Ghidra dengan FLIRT/signature matching** | Untuk menilai secara realistis seberapa banyak informasi yang **tetap bisa dipulihkan** meski biner sudah di-strip — memberi konteks tingkat proteksi nyata di luar sekadar cek biner "stripped/tidak" |

### 2.3 Prasyarat Lingkungan

- **Tidak butuh device/root** — sepenuhnya dapat dilakukan dari file APK, cukup ekstrak file `.so` dari direktori `lib/<abi>/`.
- **Uji pada APK RELEASE final**, bukan build debug — build debug secara wajar menyertakan simbol lengkap untuk kebutuhan debugging development.
- **Periksa SEMUA arsitektur ABI** (`armeabi-v7a`, `arm64-v8a`, `x86`, `x86_64`) yang di-bundle — konfigurasi build yang tidak konsisten bisa menghasilkan status stripping yang berbeda antar-arsitektur.

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0140** untuk mengambil informasi debugging yang ada pada binary native.

### 3.2 Metode A — radare2 *(metode resmi utama)*

```bash
unzip -o target-app.apk 'lib/*' -d ./native_libs
r2 -A ./native_libs/lib/arm64-v8a/libnative-lib.so
[0x0003e360]> i~stripped,linenum,lsyms
```

Contoh output yang mengindikasikan **FAIL**:

```
linenum  true
lsyms    true
stripped false
```

Contoh output yang mengindikasikan **PASS**:

```
linenum  false
lsyms    false
stripped true
```

Untuk melihat simbol yang tersisa (termasuk membedakan JNI vs non-JNI sesuai §1.3):

```bash
rabin2 -s ./native_libs/lib/arm64-v8a/libnative-lib.so | grep -v "JNI\|Java_"
```

Bila hasil filter ini (simbol **selain** JNI) menunjukkan banyak entri, ini indikasi kuat kondisi FAIL — karena simbol non-JNI seharusnya tidak perlu tetap terlihat.

### 3.3 Metode B — objdump / nm (Alternatif Binutils Standar)

```bash
objdump --syms ./native_libs/lib/arm64-v8a/libnative-lib.so
```

```bash
# Bandingkan simbol biasa vs SEMUA simbol (termasuk lokal)
diff <(nm ./native_libs/lib/arm64-v8a/libnative-lib.so) \
     <(nm -a ./native_libs/lib/arm64-v8a/libnative-lib.so)
```

Sesuai MASTG-TECH-0140: **output diff kosong** = simbol debug sudah di-strip (PASS); **ada entri tambahan** dengan nama fungsi/referensi source file = simbol debug masih ada (FAIL).

### 3.4 Metode C — readelf (Verifikasi Langsung Section DWARF)

```bash
readelf -S ./native_libs/lib/arm64-v8a/libnative-lib.so | grep -i debug
```

Bila muncul section seperti `.debug_info`, `.debug_line`, `.debug_str`, ini bukti langsung keberadaan informasi debugging DWARF lengkap — indikasi FAIL yang sangat kuat, bahkan lebih presisi dibanding sekadar memeriksa symbol table.

### 3.5 Metode D — Pemeriksaan Cepat dengan `file`

```bash
file ./native_libs/lib/*/*.so
```

```
libnative-lib.so: ELF 64-bit LSB shared object, ARM aarch64, ..., not stripped
```

Kata kunci **"not stripped"** langsung memberi sinyal cepat tanpa perlu tool tambahan — berguna untuk pemeriksaan awal cepat sebelum analisis lebih mendalam dengan Metode A-C.

### 3.6 Metode E — Audit Konfigurasi Build (Whitebox, Mengidentifikasi Akar Penyebab)

Sesuai §1.2, karena stripping sudah default, temuan FAIL biasanya berasal dari konfigurasi eksplisit yang salah. Periksa:

```gradle
// build.gradle atau CMakeLists.txt — cari override yang menonaktifkan stripping default
externalNativeBuild {
    cmake {
        arguments "-DANDROID_STL=c++_shared"
        // Cari baris yang secara eksplisit menonaktifkan strip, mis. cppFlags "-g" tanpa strip lanjutan
    }
}
```

```bash
# Periksa apakah packagingOptions/jniLibs eksplisit mengecualikan stripping
grep -n "doNotStrip\|debugSymbolLevel" app/build.gradle
```

Flag **`packagingOptions.doNotStrip`** di Gradle adalah penyebab paling umum ditemukannya biner tidak ter-strip pada build produksi — biasanya sengaja diaktifkan untuk keperluan **crash reporting bersimbol** (agar stack trace crash native lebih informatif) namun **tertinggal** aktif di build release final, bukan hanya build internal untuk debugging tim.

### 3.7 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Presisi | Kapan dipakai |
|---|---|---|---|
| **A** | radare2 | Tinggi, membedakan JNI vs non-JNI | **Baseline resmi utama** |
| **B** | objdump/nm | Tinggi, standar Binutils | Alternatif tanpa radare2 |
| **C** | readelf | Sangat tinggi (langsung ke section DWARF) | Verifikasi paling presisi |
| **D** | file | Rendah tapi sangat cepat | Triase awal cepat |
| **E** | Audit build config | N/A (identifikasi akar penyebab) | **Wajib** bila ditemukan FAIL, untuk remediasi presisi |

**Kombinasi minimum yang aku rekomendasikan:** **D (triase cepat) → A/C (konfirmasi presisi, membedakan JNI dari simbol debug sesungguhnya) → E (identifikasi akar penyebab konfigurasi bila FAIL)**.

---

### 3.8 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG:**

> **Observation:** *"The output should identify all instances of debugging information in the native binaries."*
>
> **Evaluation:** *"The test case fails if debugging information is present in any native binary, including if actual debugging symbols were successfully extracted."*

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi |
|---|---|
| F1 | `radare2`/`objdump`/`nm` menunjukkan biner **tidak** ter-strip (`stripped: false`, atau `nm -a` menghasilkan entri tambahan dibanding `nm` biasa) |
| F2 | `readelf -S` menunjukkan keberadaan section `.debug_info`/`.debug_line` (DWARF lengkap) |
| F3 | Simbol yang ditemukan **bukan** hanya entry point JNI (`Java_*`) — mencakup nama fungsi internal, variabel, atau referensi file source `.cpp` |
| F4 | Ditemukan konfigurasi build eksplisit (`doNotStrip`, `debugSymbolLevel=FULL`) yang menonaktifkan stripping default pada build release |

**Contoh bukti (ilustratif — MASTG belum menyediakan demo resmi untuk test ini):**

```bash
$ file libnative-lib.so
libnative-lib.so: ELF 64-bit LSB shared object, ARM aarch64, ..., not stripped

$ readelf -S libnative-lib.so | grep -i debug
  [27] .debug_info       PROGBITS
  [28] .debug_line       PROGBITS

$ rabin2 -s libnative-lib.so | grep -v "Java_"
150 0x00003a20 GLOBAL FUNC 64 validateSessionToken
151 0x00003a80 GLOBAL FUNC 128 decryptPayloadInternal
```

Interpretasi: section DWARF lengkap ditemukan, ditambah simbol fungsi internal (`validateSessionToken`, `decryptPayloadInternal`) yang jelas bukan entry point JNI dan membocorkan langsung fungsi apa yang menangani sesi/dekripsi. **FAIL kritis**.

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi |
|---|---|
| P1 | Seluruh biner `.so` di semua arsitektur ABI menunjukkan status `stripped: true` |
| P2 | `readelf -S` **tidak** menunjukkan section DWARF apa pun |
| P3 | Simbol yang tersisa (bila ada) **hanya** entry point JNI yang memang wajib terlihat (§1.3) — bukan pelanggaran, ini batasan arsitektural yang tidak terhindarkan |

**Contoh output yang menandakan PASS:**

```bash
$ file libnative-lib.so
libnative-lib.so: ELF 64-bit LSB shared object, ARM aarch64, ..., stripped

$ rabin2 -s libnative-lib.so
150 0x00003a20 GLOBAL FUNC 16 Java_com_example_target_MainActivity_stringFromJNI
# (hanya entry point JNI, tidak ada simbol internal lain)
```

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Jangan mengharapkan "nol simbol" sebagai standar PASS** — sesuai §1.3, entry point JNI **wajib** tetap terlihat di `.dynsym` demi fungsionalitas aplikasi. Fokus evaluasi pada **simbol debug** (DWARF, symbol table lokal `.symtab`), bukan seluruh simbol tanpa pandang bulu.

2. **Ingat bahwa kondisi ini relatif jarang FAIL pada proyek modern** (§1.2) karena toolchain NDK sudah melakukan stripping otomatis dan agresif — bila ditemukan FAIL, ini **sinyal kuat** adanya konfigurasi eksplisit yang perlu diinvestigasi (Metode E), bukan sekadar kelalaian pasif seperti banyak test lain.

3. **Verifikasi section DWARF langsung (`readelf -S`) memberi kepastian tertinggi** — lebih presisi dibanding sekadar mengandalkan flag `stripped` dari radare2, karena beberapa skenario stripping parsial mungkin menyisakan sebagian informasi debug yang tidak selalu tercermin sempurna di flag ringkasan tersebut.

4. **Investigasi akar penyebab bila ditemukan FAIL** — kemungkinan besar disebabkan `packagingOptions.doNotStrip` yang sengaja diaktifkan untuk crash reporting bersimbol namun tertinggal di release. Rekomendasi remediasi harus mengarahkan tim ke solusi yang benar: **unggah simbol secara terpisah ke layanan crash reporting** (mis. Firebase Crashlytics, Play Console native symbol upload) alih-alih membiarkan simbol tertinggal di dalam biner yang didistribusikan ke pengguna.

5. **Stripping bukan proteksi mutlak** (§1.5) — jangan biarkan status PASS pada test ini membuat laporan audit terkesan bahwa kode native sudah sepenuhnya terlindungi dari reverse engineering; ini hanya satu lapisan dasar, pertimbangkan juga obfuscation kode native dan kontrol anti-tampering lain sebagai bagian strategi resilience yang lebih luas.

6. **Severity dimodulasi:**

   | Faktor | Severity |
   |---|---|
   | Section DWARF lengkap + simbol fungsi kriptografi/autentikasi terbuka | **Tinggi** |
   | Simbol fungsi non-sensitif (mis. util rendering UI native) terbuka | **Menengah/Rendah** |
   | Hanya entry point JNI terlihat (kondisi wajar) | **Bukan temuan** |

7. **Dokumentasikan:** status stripped/tidak per file `.so` per arsitektur ABI, keberadaan section DWARF, daftar simbol non-JNI yang ditemukan (bila ada), dan hasil audit konfigurasi build yang mengidentifikasi akar penyebab.

---

## 4. Rekomendasi Perbaikan

### 4.1 Pastikan Konfigurasi Build Tidak Menonaktifkan Stripping Default

```gradle
android {
    packagingOptions {
        jniLibs {
            // JANGAN aktifkan doNotStrip kecuali benar-benar diperlukan,
            // dan bila diperlukan, batasi HANYA untuk build debug/internal
        }
    }
    buildTypes {
        release {
            externalNativeBuild {
                cmake {
                    // Pastikan tidak ada flag -g atau -DANDROID_ARM_NEON tanpa strip lanjutan
                }
            }
        }
    }
}
```

### 4.2 Unggah Simbol Debug Secara Terpisah untuk Crash Reporting (Solusi yang Benar)

```bash
# Simpan simbol tidak-di-strip secara TERPISAH dari APK yang didistribusikan
cp -r app/build/intermediates/merged_native_libs/release/out/lib ./symbols_backup/

# Unggah ke Play Console untuk deobfuscation crash native otomatis
# (Play Console > App Bundle Explorer > Native Debug Symbols)
```

Ini pola yang benar: simbol tetap tersedia untuk **tim internal** menganalisis crash report, namun **tidak pernah didistribusikan** ke pengguna di dalam APK/AAB yang dipublikasikan.

### 4.3 Verifikasi Otomatis di CI/CD

```bash
#!/bin/bash
# ci-check-native-symbols.sh
for so_file in $(find ./native_libs -name "*.so"); do
    if file "$so_file" | grep -q "not stripped"; then
        echo "[GAGAL] $so_file tidak ter-strip!"
        exit 1
    fi
done
echo "[OK] Seluruh binary native sudah ter-strip."
```

### 4.4 Checklist Remediasi

- [ ] Seluruh biner `.so` di semua arsitektur ABI diverifikasi berstatus stripped
- [ ] Tidak ada section DWARF (`.debug_info`, `.debug_line`) ditemukan
- [ ] Konfigurasi `packagingOptions.doNotStrip` (bila ada) dibatasi hanya untuk build debug/internal
- [ ] Simbol debug diunggah terpisah ke layanan crash reporting, bukan dibiarkan di APK produksi
- [ ] CI/CD menyertakan gate otomatis untuk mendeteksi regresi stripping
- [ ] **Verifikasi ulang:** jalankan kembali MASTG-TEST-0288 pada APK release final setiap rilis

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0288: Debugging Symbols in Native Binaries](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0288/)
- [MASTG-TEST-0263: Logging of StrictMode Violations](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0263/) — sesama kelompok MASWE-0061
- [MASWE-0061: Debug Artifacts Not Removed](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0061/)
- [MASTG-TECH-0140: Obtaining Debugging Information and Symbols](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0140/)

### 5.2 Dokumentasi Resmi Android

- [Android Developers — Include Native Symbols in Your Release Build](https://developer.android.com/build/include-native-symbols)
- [Android Developers — Use of Native Code (Security Risks)](https://developer.android.com/privacy-and-security/risks/use-of-native-code)

### 5.3 Riset dan Diskusi Komunitas

- [Google Groups android-ndk — debug builds and strip --strip-unneeded](https://groups.google.com/g/android-ndk/c/pewNn32pDeE)
- [arXiv — A Risk Estimation Study of Native Code Vulnerabilities in Android Applications](https://arxiv.org/html/2406.02011v1)
- [Hex-Rays — Igor's Tip of the Week #55: Using Debug Symbols](https://hex-rays.com/blog/igors-tip-of-the-week-55-using-debug-symbols)
- [ACSAC 2020 — Punstrip: Function Name Recovery in Stripped Binaries](https://s2lab.cs.ucl.ac.uk/downloads/acsac20-punstrip.pdf)
- [Wikipedia — Strip (Unix)](https://en.wikipedia.org/wiki/Strip_(Unix))
- [CWE-215: Insertion of Sensitive Information Into Debugging Code](https://cwe.mitre.org/data/definitions/215.html)
- [CWE-540: Inclusion of Sensitive Information in Source Code](https://cwe.mitre.org/data/definitions/540.html)

### 5.4 Dokumentasi Tools

- [radare2](https://github.com/radareorg/radare2)
- [rabin2 documentation](https://book.rada.re/tools/rabin2/symbols.html)
- [Binutils — objdump, nm, readelf](https://www.gnu.org/software/binutils/)
- [Ghidra](https://ghidra-sre.org/)
- [IDA Pro / FLIRT](https://hex-rays.com/ida-pro)

---

*Dokumen ini disusun berdasarkan OWASP MASTG (rilis terkini per September 2026), dokumentasi resmi Android Developers, serta riset akademik dan diskusi komunitas NDK tentang symbol stripping dan reverse engineering biner native. Nuansa terpenting: berbeda dari kebanyakan test artefak debug lain dalam seri riset ini, toolchain Android NDK sudah melakukan stripping simbol debug secara otomatis dan agresif secara default — kondisi FAIL biasanya berasal dari konfigurasi build eksplisit (`doNotStrip`) yang sengaja diaktifkan untuk kebutuhan crash reporting namun tertinggal di release, bukan kelalaian pasif. Penguji juga wajib membedakan simbol debug (target evaluasi test ini) dari simbol dinamis JNI yang secara arsitektural wajib tetap terlihat demi fungsionalitas aplikasi.*
