# MASTG-TEST-0369 Insufficient Obfuscation of Security-Relevant Native Code

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0369 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-RESILIENCE |
| **Weakness** | MASWE-0059 |
| **Tipe Pengujian** | Static, Package, **Manual** |
| **Teknik terkait** | MASTG-TECH-0157 (Extracting Bundled Native Libraries), MASTG-TECH-0018 (Disassembling Native Code), MASTG-TECH-0024 (Reviewing Disassembled Native Code) |
| **Knowledge terkait** | MASTG-KNOW-0033 (Obfuscation) |
| **Best Practice terkait** | MASTG-BEST-0029 |
| **Test terkait** | **MASTG-TEST-0368** — pasangan layer Java/Kotlin dalam seri riset ini; test ini menyasar **native layer** (`.so`), dengan teknik dan skenario ancaman yang paralel namun berbeda alat |
| **Rule resmi** | — (tidak ada; murni penilaian kualitatif manusia, sama seperti TEST-0368) |

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian dan Kesalahpahaman Umum yang Disasar

Kutipan overview resmi MASTG:

> *"If native libraries that implement security-relevant logic are not obfuscated, reverse engineering of packaged native code can expose business logic, device attestation and environment checks, integrity checks, and other implementation details that help an attacker understand the app and model attacks."*

Test ini adalah pasangan **native layer** dari MASTG-TEST-0368 (Java/Kotlin layer) yang sudah dibahas sebelumnya dalam seri riset ini. Skenario ancaman resmi secara eksplisit menyasar **kesalahpahaman umum** developer yang menjadi motivasi utama memindahkan logika ke native code sejak awal:

> *"Suppose a banking app moves its integrity and root checks into a native library, assuming native code is inherently harder to analyze, but does not apply any obfuscation."*

Asumsi *"native code is inherently harder to analyze"* **tidak sepenuhnya salah** (disassembly native memang menuntut keterampilan berbeda dari membaca Java/Kotlin terdekompilasi), namun **sangat menyesatkan bila dijadikan satu-satunya alasan** untuk tidak menerapkan obfuskasi tambahan — "lebih sulit" tidak sama dengan "aman", dan skenario resmi menunjukkan betapa cepatnya kesalahan asumsi ini terbongkar.

### 1.2 Tiga Langkah Skenario Serangan yang Menunjukkan Kecepatan Reverse Engineering Tanpa Obfuskasi

> *"Plaintext strings in the .rodata section immediately reveal every file path and system property the library checks, requiring no further analysis to identify the protection's scope. The exported JNI function name and call structure fully expose the check's logic — the attacker understands it within minutes. The attacker hooks the function at runtime to return a benign result regardless of device state, bypasses the integrity check on a rooted device."*

Perhatikan bahwa skenario ini **tidak memerlukan disassembly mendalam sama sekali** untuk langkah pertama — section `.rodata` (data read-only, tempat string literal disimpan di binary ELF) dapat diperiksa dengan tool `strings` paling dasar, tanpa perlu membuka disassembler sama sekali. Ini adalah paralel langsung dengan temuan di TEST-0368 §1.2 bahwa string literal adalah "peta jalan" tercepat bagi penyerang — prinsip yang sama berlaku identik di native layer.

### 1.3 Tujuh Teknik Obfuskasi Native Layer (Sesuai MASTG-KNOW-0033)

Berbeda dari enam teknik layer Java/Kotlin yang sudah dibahas di TEST-0368, MASTG-KNOW-0033 menjabarkan **tujuh** teknik khusus untuk native layer (umumnya berbasis LLVM, dicontohkan dengan tool open-source O-MVLL):

| Teknik | Yang Disamarkan |
|---|---|
| **Symbol Stripping** | Nama fungsi dan informasi debug — namun **fungsi JNI dengan konvensi `Java_*` tetap terekspos** kecuali didaftarkan dinamis via `RegisterNatives` |
| **Control Flow Flattening** | Struktur branching asli — diganti dispatcher berbasis loop+switch |
| **Junk Code** | Menambah basic block duplikat/jalur kode redundan untuk memperbesar noise analisis |
| **Arithmetic Obfuscation** | Operasi aritmatika/bitwise sederhana diganti ekspresi setara yang lebih kompleks |
| **Strings Encoding** | Literal string di `.rodata` — identik tujuannya dengan String Encryption di Java layer |
| **Opaque Constants** | Konstanta integer/magic number — direkonstruksi saat runtime, bukan tertulis langsung |
| **Obfuscated Function Calls** | Call graph — panggilan langsung diubah jadi panggilan tidak langsung (indirect call) |

### 1.4 Nuansa Teknis Penting: Symbol Stripping Tidak Otomatis Menyembunyikan Fungsi JNI

Ini adalah detail yang sangat spesifik dan mudah terlewat, dikutip langsung dari MASTG-KNOW-0033 (sudah dicatat di dokumen TEST-0368 namun sangat relevan diulang di sini karena test ini secara langsung menyasar native layer):

> *"Native libraries that use name-based JNI resolution still expose descriptive exported `Java_*` symbols even after symbol stripping. Registering native methods dynamically through `JNI_OnLoad` and `RegisterNatives` can reduce that exposure, as the symbols of such functions can be stripped due to not needing to follow the `Java_*` convention."*

Ini menjelaskan secara tepat **mengapa** skenario ancaman resmi (§1.2) menyebut *"exported JNI function name... fully expose the check's logic"* — bila fungsi native dipanggil dari Java memakai **konvensi penamaan otomatis** (`Java_com_example_app_SecurityChecker_isRooted`), nama fungsi itu **wajib** tetap deskriptif di symbol table agar JVM dapat menemukannya secara otomatis saat memuat library — bahkan setelah symbol stripping diterapkan ke fungsi-fungsi lain. Satu-satunya cara menghindari ini adalah **mendaftarkan fungsi secara manual** lewat `RegisterNatives` di dalam `JNI_OnLoad`, yang membebaskan nama fungsi dari keharusan mengikuti konvensi `Java_*` dan memungkinkan nama tersebut ikut di-strip.

### 1.5 Tiga Kriteria Diagnostik, Paralel dengan TEST-0368 Namun untuk Artefak Native

> *"Determine whether native library strings or constants... are in plaintext. Determine whether the disassembled function structure and call edges still reveal the original security-relevant logic with recognizable patterns. Determine whether exported JNI symbols retain descriptive names that can be directly correlated with security-relevant functionality."*

Struktur tiga kriteria ini **secara sengaja paralel** dengan TEST-0368 (string, struktur/control-flow, identifier/symbol) — menegaskan bahwa kedua test ini memakai kerangka evaluasi konseptual yang sama, hanya diterapkan pada format artefak yang berbeda (DEX bytecode terdekompilasi vs ELF binary ter-disassembly).

### 1.6 Bukti Nyata: Teknik Bypass yang Sudah Terdokumentasi Luas untuk Root Detection Native Tanpa Obfuskasi

Riset komunitas mengonfirmasi bahwa kombinasi root detection native tanpa obfuskasi adalah target yang sangat mudah dieksploitasi dengan tools standar:

> *"Non-obfuscated native library implementations can be identified and analyzed during reverse engineering. Product names and versions can be retrieved from the strings section (.rodata section) of ELF files, while defined functions can be retrieved from the Symbol Table section."*

Dan teknik bypass konkret yang terdokumentasi:

> *"Decompilers like Ghidra can be used to decompile root detection functions, and by patching the instruction to always return 0, the modified .so binary can be pushed back to the app directory to bypass root detection."*

Ini menunjukkan bahwa risiko dari test ini tidak terbatas pada **pemahaman** logika semata (seperti ditekankan skenario resmi), tapi bisa langsung berlanjut ke **patching biner** — begitu fungsi target teridentifikasi dengan mudah lewat symbol table dan string yang plaintext, modifikasi langsung terhadap instruksi assembly (membuat fungsi selalu mengembalikan nilai "aman") menjadi langkah lanjutan yang relatif sederhana bagi penyerang berpengalaman.

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | Fungsi |
|---|---|
| **unzip/apktool** | Ekstraksi native libraries `.so` (MASTG-TECH-0157) |
| **Ghidra / IDA Pro / radare2** | Disassembly dan review native code (MASTG-TECH-0018, MASTG-TECH-0024) |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **strings / objdump** | Pemeriksaan cepat section `.rodata` sebelum disassembly penuh (replikasi langkah pertama skenario ancaman §1.2) |
| **nm / readelf** | Pemeriksaan symbol table untuk fungsi JNI yang tetap terekspos meski symbol stripping diterapkan (§1.4) |
| **APKiD** | Deteksi signature obfuskator native yang dikenal (O-MVLL, dsb.), dengan keterbatasan deteksi yang sama seperti dibahas di TEST-0368 |

### 2.3 Prasyarat Lingkungan

- Tidak butuh device/root — murni analisis statis terhadap file `.so` yang diekstrak.
- Kemampuan membaca disassembly ARM/x86 dasar sangat direkomendasikan.

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0157** untuk mengekstrak native libraries dari paket aplikasi.

(Sama seperti TEST-0368, langkah resmi sengaja singkat — menegaskan inti test adalah penilaian kualitatif terhadap hasil ekstraksi/disassembly, bukan pencarian pola bertahap.)

### 3.2 Metode A — Pemeriksaan Cepat Section .rodata (Replikasi Langkah Pertama Skenario Resmi)

```bash
unzip -o target.apk "lib/*" -d extracted_libs
strings extracted_libs/lib/arm64-v8a/libsecuritycheck.so | grep -iE '/proc/|su|magisk|busybox|ro\.secure|TracerPid'
```

### 3.3 Metode B — Pemeriksaan Symbol Table untuk Fungsi JNI (Sesuai §1.4)

```bash
nm -D extracted_libs/lib/arm64-v8a/libsecuritycheck.so | grep 'Java_'
readelf -sW extracted_libs/lib/arm64-v8a/libsecuritycheck.so | grep FUNC
```

Bila banyak fungsi dengan nama deskriptif (`Java_com_example_app_SecurityChecker_isRooted`) muncul, ini mengindikasikan symbol stripping **tidak diterapkan secara efektif** atau fungsi tersebut memakai konvensi JNI otomatis tanpa `RegisterNatives`.

### 3.4 Metode C — Disassembly Penuh untuk Menilai Struktur dan Call Graph

```bash
# Via Ghidra (headless) atau radare2 interaktif
r2 -A extracted_libs/lib/arm64-v8a/libsecuritycheck.so
[0x...]> afl  # daftar fungsi
[0x...]> pdf @ sym.Java_com_example_app_SecurityChecker_isRooted
```

Nilai: apakah control flow mudah diikuti (branching linear sederhana), atau sudah mengalami flattening/junk code yang signifikan?

### 3.5 Metode D — Verifikasi Signature Obfuskator yang Dikenal

```bash
apkid target.apk
```

### 3.6 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Kapan dipakai |
|---|---|---|
| **A** | strings | Baseline wajib — replikasi langkah pertama skenario ancaman |
| **B** | nm/readelf | Verifikasi kriteria diagnostik ketiga (symbol JNI) |
| **C** | Ghidra/radare2 | Verifikasi kriteria diagnostik kedua (struktur/call graph) |
| **D** | APKiD | Identifikasi tool obfuskasi yang dipakai (dengan keterbatasan) |

**Kombinasi minimum yang aku rekomendasikan:** **A + B (wajib, cepat) → C (wajib untuk kasus ambigu)**.

---

### 3.7 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG:**

> **Evaluation:** *"The test case fails if the app's native libraries allow an attacker to identify, correlate, and reverse engineer security-relevant logic with reasonable effort."*

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi |
|---|---|
| F1 | String/konstanta sensitif plaintext di `.rodata`, **dan/atau** symbol JNI deskriptif tetap terekspos, **dan/atau** struktur call graph mudah diikuti tanpa disassembly mendalam |

**Contoh bukti (merefleksikan skenario resmi §1.2):**

```bash
$ strings libsecuritycheck.so | grep -i proc
/proc/self/status
/system/bin/su

$ nm -D libsecuritycheck.so | grep Java_
0000000000001234 T Java_com_example_bank_SecurityChecker_isRooted
```

Interpretasi: path file yang diperiksa (`/proc/self/status`, `/system/bin/su`) dan nama fungsi JNI (`isRooted`) langsung mengungkap lingkup dan tujuan proteksi tanpa perlu disassembly mendalam. **FAIL** — persis skenario resmi.

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi |
|---|---|
| P1 | String/konstanta sensitif dienkripsi (tidak plaintext di `.rodata`), **dan** |
| P2 | Fungsi JNI didaftarkan via `RegisterNatives` dengan symbol stripping efektif (tidak ada nama deskriptif di symbol table), **dan** |
| P3 | Control flow logika kritis telah diobfuskasi (flattening/junk code/indirect call) |

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Mulai selalu dari pemeriksaan `.rodata` dan symbol table** — ini adalah langkah termudah dan tercepat, sering sudah cukup untuk menyimpulkan FAIL tanpa perlu disassembly mendalam, persis mereplikasi jalan pintas yang dipakai penyerang sesungguhnya.

2. **Periksa secara spesifik apakah fungsi memakai konvensi `Java_*` otomatis** — sesuai §1.4, ini adalah penyebab paling umum mengapa symbol stripping "gagal" menyembunyikan fungsi JNI paling kritis, meski fungsi-fungsi internal lain berhasil distripping.

3. **Jangan simpulkan PASS hanya karena tidak ada signature obfuskator dikenal** — sama seperti TEST-0368 §1.6, obfuskasi kustom buatan sendiri tetap mungkin ada meski tidak terdeteksi tool signature-based.

4. **Severity dimodulasi:**

   | Faktor | Severity |
   |---|---|
   | Integrity/root check finansial dapat dipahami dan di-patch dalam hitungan menit | **Tinggi** |
   | Logika sensitif memerlukan disassembly signifikan untuk dipahami | **Sedang** |
   | Ketiga kriteria diagnostik terpenuhi, termasuk penanganan khusus symbol JNI | **Bukan temuan** |

5. **Dokumentasikan:** nama library `.so`, string/symbol spesifik yang ditemukan plaintext, hasil pemeriksaan `RegisterNatives` vs konvensi otomatis, dan estimasi waktu/usaha untuk memahami logika via disassembly.

---

## 4. Rekomendasi Perbaikan

### 4.1 Daftarkan Fungsi JNI Secara Manual untuk Memungkinkan Symbol Stripping Penuh

```c
// SEBELUM — konvensi otomatis, nama WAJIB deskriptif agar JVM menemukannya
JNIEXPORT jboolean JNICALL
Java_com_example_bank_SecurityChecker_isRooted(JNIEnv *env, jobject thiz) { ... }

// SESUDAH — RegisterNatives, nama fungsi internal bebas distripping
static JNINativeMethod methods[] = {
    {"isRooted", "()Z", (void *)nativeCheck} // nama Java tetap "isRooted", nama C bebas
};

JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    JNIEnv *env;
    vm->GetEnv((void **)&env, JNI_VERSION_1_6);
    jclass clazz = env->FindClass("com/example/bank/SecurityChecker");
    env->RegisterNatives(clazz, methods, 1);
    return JNI_VERSION_1_6;
}
```

### 4.2 Enkripsi String Sensitif dan Obfuskasi Control Flow

```python
# Konfigurasi O-MVLL untuk fungsi integrity check spesifik
def obfuscate_string(self, _, __, string: bytes):
    if string in [b"/proc/self/status", b"/system/bin/su"]:
        return omvll.StringEncOptLocal()
    return False

def flatten_cfg(self, mod, func):
    return func.name == "nativeCheck"
```

### 4.3 Checklist Remediasi

- [ ] Fungsi JNI yang menangani logika sensitif didaftarkan via `RegisterNatives`, bukan konvensi `Java_*` otomatis
- [ ] String/konstanta sensitif (path, token, nilai pembanding integrity) dienkripsi
- [ ] Control flow fungsi integrity/root check diobfuskasi (flattening/indirect call)
- [ ] Diverifikasi ulang dengan `strings`/`nm` setelah build untuk memastikan tidak ada kebocoran yang luput

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0369 (source, tests-beta)](https://github.com/OWASP/mastg/blob/master/tests-beta/android/MASVS-RESILIENCE/MASTG-TEST-0369.md)
- [MASTG-TEST-0368 (dokumen pasangan layer Java/Kotlin dalam seri riset ini)](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0368/)
- [MASTG-KNOW-0033: Obfuscation](https://mas.owasp.org/MASTG/knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0033/)
- [MASTG-TECH-0024: Reviewing Disassembled Native Code](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0024/)

### 5.2 Riset dan Kasus Nyata

- [8kSec: Frida Part 5 — Root Detection Bypass](https://www.8ksec.io/advanced-root-detection-bypass-techniques/)
- [arXiv: A Risk Estimation Study of Native Code Vulnerabilities in Android Applications](https://arxiv.org/pdf/2406.02011)
- [O-MVLL: LLVM-based Native Obfuscator](https://obfuscator.re/omvll/)

### 5.3 Dokumentasi Tools

- [Ghidra — NSA Reverse Engineering Framework](https://ghidra-sre.org/)
- [radare2](https://rada.re/n/)
- [APKiD](https://github.com/rednaga/APKiD)

---

*Dokumen ini disusun berdasarkan konten resmi OWASP MASTG (`tests-beta/android/MASVS-RESILIENCE/MASTG-TEST-0369.md`, `MASTG-KNOW-0033`), dengan cross-reference mendalam ke dokumen MASTG-TEST-0368 (pasangan layer Java/Kotlin) dalam seri riset ini, serta riset komunitas tentang teknik bypass root detection native yang sudah terdokumentasi luas. Nuansa metodologis terpenting dan paling spesifik untuk native layer: fungsi JNI yang memakai konvensi penamaan otomatis `Java_*` **tetap wajib** memiliki nama deskriptif di symbol table agar dapat ditemukan JVM, bahkan setelah symbol stripping diterapkan ke seluruh fungsi internal lainnya — satu-satunya cara menghindari ini adalah mendaftarkan fungsi secara manual via `RegisterNatives` di `JNI_OnLoad`. Ini menjelaskan secara teknis tepat mengapa skenario ancaman resmi menyebut nama fungsi JNI yang terekspor sebagai salah satu sumber kebocoran informasi paling signifikan.*
