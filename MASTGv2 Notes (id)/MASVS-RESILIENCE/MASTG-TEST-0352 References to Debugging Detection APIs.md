# MASTG-TEST-0352 References to Debugging Detection APIs

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0352 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-RESILIENCE |
| **Weakness** | MASWE-0064 |
| **Tipe Pengujian** | Static, Code, **Manual** |
| **Teknik terkait** | MASTG-TECH-0013, MASTG-TECH-0014, MASTG-TECH-0157 (Extracting Bundled Native Libraries), MASTG-TECH-0018 (Disassembling Native Code), MASTG-TECH-0023 |
| **Knowledge terkait** | MASTG-KNOW-0007 (Debuggable Apps), MASTG-KNOW-0028 (Anti-Debugging) |
| **Best Practice terkait** | MASTG-BEST-0007, MASTG-BEST-0029, MASTG-BEST-0047 (Continuous Anti-Debugging Checks) |
| **Test terkait** | **MASTG-TEST-0353** — counterpart dinamis yang mengonfirmasi mekanisme aktif saat runtime |
| **Rule resmi** | Tiga rule: `mastg-android-debugger-checks.yml`, `mastg-android-native-debugger-checks.yml`, `mastg-android-debuggable-flag.yml` — ditemukan **kesenjangan cakupan signifikan** terhadap native code, lihat §1.4 |

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian

Kutipan overview resmi MASTG:

> *"Apps can implement debugging detection at the Java/Kotlin level using APIs such as `Debug.isDebuggerConnected()`, or at the native level using mechanisms such as `ptrace` calls, `TracerPid` checks in `/proc/self/status`, or inlined syscalls. If these checks are absent or not applied in security-relevant code paths, an attacker can attach a debugger undetected and use it to inspect or modify runtime state, extract sensitive data, or bypass security controls."*

### 1.2 Dua Protokol Debugging yang Harus Sama-sama Diperhitungkan

MASTG-KNOW-0028 menjelaskan pembedaan arsitektural penting:

> *"We have to deal with two debugging protocols on Android: we can debug on the Java level with JDWP or on the native layer via a ptrace-based debugger. A good anti-debugging scheme should defend against both types of debugging."*

| Protokol | Target | Teknik Deteksi Khas |
|---|---|---|
| **JDWP** (Java Debug Wire Protocol) | Kode Java/Kotlin, lewat thread debugging yang dimulai bila `android:debuggable="true"` | `ApplicationInfo.FLAG_DEBUGGABLE`, `Debug.isDebuggerConnected()`, timing check (`Debug.threadCpuTimeNanos()`) |
| **ptrace-based debugger** | Kode native (C/C++) | Memeriksa `TracerPid` di `/proc/self/status`, mendeteksi `ptrace(PTRACE_ATTACH)` yang sudah dipakai proses lain (self-attach trick) |

Prinsip kunci yang ditegaskan MASTG-KNOW-0028: *"The 'more-is-better' rule applies: to maximize effectiveness, defenders combine multiple methods of prevention and detection that operate on different API layers."* — mekanisme yang hanya menyasar satu protokol (misalnya hanya JDWP) meninggalkan celah besar bagi penyerang yang beralih ke debugging native murni.

### 1.3 Teknik Timing Check: Pendekatan Tidak Lazim yang Layak Diketahui

Salah satu teknik dari MASTG-KNOW-0028 yang jarang dibahas di test lain dalam seri riset ini patut disorot karena pendekatannya cukup unik — bukan memeriksa API/flag, melainkan **mengukur anomali waktu eksekusi**:

> *"Debug.threadCpuTimeNanos indicates the amount of time that the current thread has been executing code. Because debugging slows down process execution, you can use the difference in execution time to guess whether a debugger is attached."*

Teknik ini relevan untuk disertakan dalam pencarian manual (§3.3) karena **tidak tercakup rule resmi mana pun** (§1.4) — pencariannya menuntut pengenalan pola kode yang mengukur selisih waktu sebelum/sesudah loop sederhana, bukan sekadar nama API tunggal yang mudah dicari.

### 1.4 Temuan Analitis Kritis: Rule Resmi Bersifat Java-Only, Tidak Pernah Memindai Binary Native Sungguhan

Ini adalah temuan paling signifikan dari analisis rule untuk test ini. Perhatikan metadata `languages` pada rule yang **namanya sendiri menyebut "native"**:

```yaml
- id: mastg-android-native-debugger-checks
  languages: [java]  # <-- perhatikan ini
  metadata:
    summary: Detects Java references to native anti-debugging checks based on TracerPid and ptrace-related indicators.
  patterns:
    - pattern-either:
        - pattern: '"/proc/self/status"'
        - pattern: '"TracerPid:"'
        - pattern-regex: PTRACE_(ATTACH|SEIZE)
```

Rule ini **hanya berbahasa Java** — ia mencari string literal `"/proc/self/status"`/`"TracerPid:"` atau pola regex `PTRACE_ATTACH`/`PTRACE_SEIZE` **di dalam kode Java/Kotlin**, bukan di dalam file biner native (`.so`) itu sendiri. Ini berarti rule ini hanya akan menangkap kasus di mana kode Java **mereferensikan string tersebut secara langsung** (misalnya memanggil `new File("/proc/self/status")` langsung dari Java) — namun **sama sekali tidak akan mendeteksi** implementasi anti-debugging yang ditulis **murni dalam kode native C/C++** yang dikompilasi ke `.so` dan dipanggil lewat JNI tanpa jembatan string di sisi Java.

Kesenjangan ini sangat signifikan karena **langkah resmi test ini sendiri** (§ Steps poin 3-4) secara eksplisit menuntut:

> *"Use MASTG-TECH-0157 to extract the native libraries from the app package. Use MASTG-TECH-0018 to look for native debugging detection patterns in the extracted libraries, such as calls to ptrace, reads of /proc/self/status, or checks for the TracerPid field."*

Dengan kata lain, **MASTG sendiri mengharuskan analisis langsung terhadap binary native** (lewat disassembler, bukan Semgrep terhadap source Java), namun **tidak menyediakan rule otomatis** untuk tugas ini — tidak ada rule bahasa C/Assembly dalam katalog resmi untuk memindai pemanggilan `ptrace()` langsung di disassembly `.so`. Ini konsisten dengan keterbatasan umum Semgrep sebagai tool berbasis source-code pattern matching — ia tidak dirancang untuk menganalisis ELF binary terkompilasi secara native. Penguji **wajib** melakukan disassembly manual (via Ghidra/IDA/radare2) untuk benar-benar memenuhi langkah 3-4 resmi, karena tidak ada jalan pintas otomatis yang tersedia.

### 1.5 Konteks Nyata: Teknik Bypass yang Sudah Sangat Matang di Komunitas

Riset komunitas menunjukkan bahwa ekosistem bypass untuk kelas kerentanan ini sudah sangat matang, termasuk teknik yang secara spesifik menyasar dua protokol debugging yang disebut §1.2:

> *"Frida spawn mode can bypass dual process (ptrace) detection, /proc status checks, and detection of special task names like 'gum-js-loop', 'gmain', 'gdbus', or 'pool-frida'."*
>
> *"Anti-debugging methods can be bypassed by using the LD_PRELOAD environment variable, which allows control over the loading path of a shared library."*

Teknik **LD_PRELOAD** di sini khususnya relevan — ia memungkinkan penyerang menyuntikkan shared library kustom yang **mengintersep pemanggilan syscall tingkat rendah sebelum mencapai implementasi asli**, secara efektif menetralisir pengecekan `ptrace`/`TracerPid` tanpa perlu memodifikasi binary aplikasi itu sendiri sama sekali. Ini menegaskan prinsip defense-in-depth MASTG-BEST-0047 — satu lapis pengecekan, betapapun canggihnya, tetap dapat dinetralisir oleh teknik injeksi tingkat sistem yang sudah dikenal luas di komunitas reverse engineering.

### 1.6 Struktur Validasi Lanjutan: Dua Pertanyaan Kunci yang Membedakan Temuan Berkualitas

Bagian "Further Validation Required" menuntut dua pemeriksaan spesifik yang **tidak bisa otomatis**:

> *"Determine whether the check is called in release builds and not only in debug configurations. Determine whether the app takes a security-relevant action when a debugger is detected (for example, process termination or feature restriction)."*

Poin pertama sangat penting dan mudah terlewat — developer terkadang menulis anti-debugging check namun **hanya mengaktifkannya di build variant tertentu** (mis. dibungkus dalam `if (BuildConfig.DEBUG)` secara terbalik/salah logika, atau sengaja dinonaktifkan di build config CI untuk mempermudah testing internal dan lupa diaktifkan kembali untuk rilis produksi). Kehadiran kode anti-debugging di source **tidak otomatis berarti kode tersebut aktif di APK yang dirilis ke pengguna**.

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | Fungsi |
|---|---|
| **jadx** | Dekompilasi DEX → Java (MASTG-TECH-0013) |
| **Semgrep** + tiga rule resmi | Deteksi pola Java-level dan referensi string native (cakupan terbatas, §1.4) |
| **Ghidra / IDA Pro / radare2** | **Wajib** untuk memindai langsung pemanggilan `ptrace()` di disassembly binary `.so` (MASTG-TECH-0018) — satu-satunya cara memenuhi langkah resmi 3-4 secara memadai |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **grep/ripgrep** | Mencari pola timing check (`threadCpuTimeNanos`) dan variasi string yang mungkin terlewat rule resmi |
| **unzip/apktool** | Ekstraksi direktori `lib/` untuk memperoleh file `.so` (MASTG-TECH-0157) |
| **MobSF** | Laporan otomatis yang kadang menyertakan deteksi dasar anti-debugging |

### 2.3 Prasyarat Lingkungan

- Tidak butuh device/root untuk analisis statis.
- **Kemampuan membaca disassembly ARM/x86 dasar sangat direkomendasikan** mengingat keterbatasan rule otomatis terhadap kode native (§1.4).

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0013** untuk reverse engineer aplikasi.
2. Gunakan **MASTG-TECH-0014** untuk mencari API Java/Kotlin yang relevan.
3. Gunakan **MASTG-TECH-0157** untuk mengekstrak native libraries.
4. Gunakan **MASTG-TECH-0018** untuk mencari pola debugging detection native di library yang diekstrak.

### 3.2 Metode A — Semgrep dengan Tiga Rule Resmi (Cakupan Terbatas untuk Native)

```bash
semgrep --config mastg-android-debugger-checks.yml \
        --config mastg-android-native-debugger-checks.yml \
        --config mastg-android-debuggable-flag.yml \
        ./decompiled/sources ./AndroidManifest.xml
```

**Catatan wajib:** hasil dari rule kedua hanya menangkap referensi string di Java, **bukan** pemanggilan `ptrace` sesungguhnya di binary native (§1.4). Lanjutkan ke Metode B untuk memenuhi langkah resmi secara utuh.

### 3.3 Metode B — grep/ripgrep untuk Timing Check dan Variasi Tambahan

```bash
D=./decompiled/sources
rg -n 'threadCpuTimeNanos' $D
rg -n 'FLAG_DEBUGGABLE|isDebuggerConnected' $D
```

### 3.4 Metode C — Disassembly Manual Binary Native (Wajib untuk Langkah 3-4 Resmi)

```bash
# Ekstrak native libraries
unzip -o target.apk "lib/*" -d extracted_libs

# Cari string literal terkait di binary (triase cepat sebelum disassembly penuh)
strings extracted_libs/lib/arm64-v8a/libnative-lib.so | grep -E 'TracerPid|proc/self/status'

# Disassembly untuk mencari pemanggilan ptrace() sesungguhnya
objdump -d extracted_libs/lib/arm64-v8a/libnative-lib.so | grep -A5 'bl.*ptrace'
```

Atau gunakan Ghidra/radare2 untuk analisis fungsi yang lebih mendalam, menelusuri call graph ke symbol `ptrace` yang di-import.

### 3.5 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Kapan dipakai |
|---|---|---|
| **A** | Semgrep + 3 rule resmi | Triase awal untuk sisi Java, cakupan native sangat terbatas |
| **B** | grep/ripgrep | Menutup celah timing check dan variasi string |
| **C** | Disassembly manual (wajib) | **Satu-satunya cara** memenuhi langkah resmi 3-4 untuk kode native sungguhan |

**Kombinasi minimum yang aku rekomendasikan:** **A + B (sisi Java) → C (wajib untuk sisi native)**, lalu lanjutkan ke **MASTG-TEST-0353** untuk konfirmasi runtime.

---

### 3.6 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG:**

> **Evaluation:** *"The test case fails if the app contains no debugging detection patterns in either its Java/Kotlin code or its native libraries."*

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi |
|---|---|
| F1 | **Tidak ditemukan** satu pun pola deteksi debugging baik di sisi Java/Kotlin **maupun** setelah disassembly manual native libraries |

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi |
|---|---|
| P1 | Ditemukan minimal satu pola deteksi di sisi Java **atau** native, **dan** |
| P2 | Check tersebut terkonfirmasi aktif di build release (bukan hanya debug config), **dan** |
| P3 | Ada aksi keamanan yang jelas saat debugger terdeteksi (terminasi, pembatasan fitur) — sesuai §1.6 |

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Jangan simpulkan FAIL hanya dari hasil Semgrep** — sesuai §1.4, rule resmi tidak pernah memindai binary native sungguhan; FAIL final hanya valid setelah disassembly manual (Metode C) juga tidak menemukan apa pun.

2. **Verifikasi build variant** — kehadiran kode di source tidak menjamin aktif di rilis produksi (§1.6); periksa konfigurasi build (ProGuard/R8 rules, flavor-specific source sets) untuk memastikan check tidak di-strip atau dinonaktifkan di build release.

3. **Kombinasikan selalu dengan MASTG-TEST-0353** — test ini murni presence di level kode; efektivitas sesungguhnya (termasuk ketahanan terhadap teknik LD_PRELOAD/Frida spawn mode di §1.5) hanya bisa dinilai lewat pengujian dinamis.

4. **Severity dimodulasi:**

   | Faktor | Severity |
   |---|---|
   | Tidak ada deteksi debugging sama sekali (Java maupun native terkonfirmasi lewat disassembly) pada aplikasi yang menangani data sangat sensitif | **Tinggi** |
   | Deteksi hanya menyasar satu protokol (JDWP saja, tanpa native) | **Sedang** |
   | Deteksi berlapis di kedua protokol, aktif di build release, dengan aksi keamanan yang jelas | **Bukan temuan** |

5. **Dokumentasikan:** lokasi kode Java, hasil disassembly native (fungsi yang memanggil `ptrace`, bila ada), build variant yang diverifikasi, dan rekomendasi lanjutan ke MASTG-TEST-0353.

---

## 4. Rekomendasi Perbaikan

### 4.1 Kombinasikan Deteksi JDWP dan Native (Sesuai MASTG-KNOW-0028)

```java
public static boolean isUnderAttack() {
    boolean jdwpFlag = (context.getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0;
    boolean jdwpConnected = Debug.isDebuggerConnected();
    boolean nativeDebug = nativeCheckTracerPid(); // JNI call ke implementasi native
    return jdwpFlag || jdwpConnected || nativeDebug;
}
```

### 4.2 Terapkan Checkpoint Berulang, Bukan Hanya Sekali di Startup (Sesuai MASTG-BEST-0047)

```java
// Panggil ulang sebelum setiap operasi sensitif, bukan hanya onCreate()
fun approvePayment() {
    if (AntiDebug.isUnderAttack()) { terminateSession(); return }
    // lanjutkan transaksi
}
```

### 4.3 Checklist Remediasi

- [ ] Deteksi mencakup kedua protokol: JDWP (Java) dan ptrace-based (native)
- [ ] Check terkonfirmasi aktif di build release melalui verifikasi APK produksi, bukan hanya source code
- [ ] Check diulang di titik checkpoint sebelum operasi sensitif, bukan hanya sekali saat startup
- [ ] Aksi keamanan yang jelas (terminasi/pembatasan fitur) terpasang saat debugger terdeteksi
- [ ] Hasil dikonfirmasi lewat MASTG-TEST-0353 untuk verifikasi efektivitas runtime

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0352 (source, tests-beta)](https://github.com/OWASP/mastg/blob/master/tests-beta/android/MASVS-RESILIENCE/MASTG-TEST-0352.md)
- [MASTG-TEST-0353: Runtime Use of Debugging Detection Techniques](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0353/)
- [MASTG-KNOW-0028: Anti-Debugging](https://mas.owasp.org/MASTG/knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0028/)
- [MASTG-BEST-0047: Continuous Anti-Debugging Checks](https://github.com/OWASP/mastg/blob/master/best-practices/MASTG-BEST-0047.md)
- [MASTG-TECH-0018: Disassembling Native Code](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0018/)
- [MASTG-TECH-0157: Extracting Bundled Native Libraries](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0157/)

### 5.2 Riset dan Referensi Teknis

- [Guided Hacking: Tutorial Bypass Ptrace Anti-Debugger in Android](https://guidedhacking.com/threads/bypass-ptrace-anti-debugger-in-android.17099/)
- [Recursively: Android Anti-debugging Tricks — Part 1](https://recursively.review/2021/04/25/Android-Anti-debugging-Tricks-Part-1/)

### 5.3 Dokumentasi Tools

- [Semgrep Documentation](https://semgrep.dev/docs/)
- [Ghidra — NSA Reverse Engineering Framework](https://ghidra-sre.org/)
- [radare2](https://rada.re/n/)

---

*Dokumen ini disusun berdasarkan konten resmi OWASP MASTG (`tests-beta/android/MASVS-RESILIENCE/MASTG-TEST-0352.md`, `MASTG-KNOW-0028`), analisis tiga rule resmi, serta riset komunitas tentang teknik bypass anti-debugging yang sudah matang (Frida spawn mode, LD_PRELOAD injection). Nuansa metodologis terpenting: rule `mastg-android-native-debugger-checks.yml`, meski namanya menyebut "native", secara teknis **hanya berbahasa Java** (`languages: [java]`) dan tidak pernah memindai binary `.so` sungguhan — sementara langkah resmi test ini sendiri (poin 3-4) secara eksplisit menuntut ekstraksi dan analisis disassembly native libraries. Ini berarti tidak ada jalan pintas otomatis untuk memenuhi langkah resmi test secara utuh; disassembly manual (Ghidra/radare2) terhadap binary native adalah kewajiban, bukan opsional, meski secara teknis di luar kemampuan tool pattern-matching source-code seperti Semgrep.*
