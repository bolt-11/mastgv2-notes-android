# MASTG-TEST-0353 Runtime Use of Debugging Detection APIs

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0353 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-RESILIENCE |
| **Weakness** | MASWE-0064 |
| **Tipe Pengujian** | Dynamic, Hooks, **Manual** |
| **Teknik terkait** | MASTG-TECH-0005, MASTG-TECH-0043, MASTG-TECH-0032 (Execution Tracing), MASTG-TECH-0023, MASTG-TECH-0031 (Debugging — attach JDWP/native debugger) |
| **Knowledge terkait** | MASTG-KNOW-0007, MASTG-KNOW-0028 (Anti-Debugging) |
| **Best Practice terkait** | MASTG-BEST-0007, MASTG-BEST-0029, MASTG-BEST-0047 (Continuous Anti-Debugging Checks) |
| **Test terkait** | **MASTG-TEST-0352** — counterpart statis, hubungan dua arah (sama seperti pola TEST-0324/0325) |

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian dan Alasan Keberadaannya

Kutipan overview resmi MASTG:

> *"Even if an app references debugging detection APIs, those checks may not execute in security-relevant code paths at runtime. For example, they may only run in debug build variants, fire only once at startup, or be dead code that's never reached. If the app doesn't invoke its debugging detection logic at the right moments, an attacker can attach a debugger without triggering any defensive response."*

Pembukaan overview ini secara langsung menjustifikasi mengapa test dinamis ini **perlu ada secara terpisah** dari MASTG-TEST-0352 — dan secara spesifik mengonfirmasi tiga skenario celah yang sudah diantisipasi di dokumen TEST-0352 §1.6 (build variant yang salah, check sekali di startup, dead code). Test statis hanya bisa menemukan **referensi kode**; ia tidak bisa membuktikan apakah referensi tersebut benar-benar **tereksekusi** pada kondisi nyata yang relevan.

### 1.2 Hubungan Dua Arah dengan MASTG-TEST-0352

Sama seperti pasangan root detection (TEST-0324/0325), overview test ini secara eksplisit mengizinkan dua urutan kerja:

> *"Obtain a list of potential debugging detection mechanisms from static analysis and then focus your dynamic testing on those specific checks to confirm they are triggered at runtime. Alternatively, you can perform dynamic testing first to identify any debugging detection mechanisms that are active at runtime, and then use static analysis to further investigate their implementation and coverage."*

Mengingat kesenjangan cakupan signifikan yang sudah dibahas di dokumen TEST-0352 (rule resmi tidak pernah memindai binary native sungguhan), **Jalur B (dinamis dulu)** memiliki nilai strategis yang lebih tinggi untuk test ini dibanding kebanyakan pasangan serupa — observasi runtime bisa **menemukan** mekanisme native yang analisis statis gagal konfirmasi lewat Semgrep, kemudian penguji melacak balik ke disassembly untuk memahami implementasi lengkapnya.

### 1.3 Fleksibilitas Kondisi Pengujian: Debugger Aktif vs Build Debuggable vs Tanpa Keduanya

Overview memberi tiga opsi kondisi pengujian dengan tingkat keandalan berbeda:

> *"It is recommended to run this test while actively attempting to attach a debugger (or on a debuggable build), to ensure that debugging detection mechanisms are triggered during testing. However, even without attaching a debugger, this test can still surface debugging detection logic if the app runs those checks unconditionally."*

Ini penting secara praktis — banyak mekanisme deteksi (`ApplicationInfo.FLAG_DEBUGGABLE`, timing check) **berjalan tanpa syarat** setiap kali aplikasi dijalankan, terlepas dari apakah debugger sungguhan sedang terpasang. Artinya hooking bisa menangkap pemanggilan API ini bahkan **tanpa** penguji perlu benar-benar melakukan upaya attach debugger — namun untuk mekanisme yang **secara kondisional** hanya aktif saat debugger benar-benar terdeteksi (misalnya pengecekan `TracerPid` yang nilainya nol kecuali memang ada proses yang melakukan ptrace), simulasi kondisi nyata (attach debugger sungguhan via MASTG-TECH-0031, atau memakai build debuggable) diperlukan untuk memicu jalur kode tersebut secara lengkap.

### 1.4 Dua Validasi Lanjutan yang Menuntut Simulasi Serangan Sungguhan

Bagian "Further Validation Required" test ini unik karena secara eksplisit menuntut penguji **benar-benar melakukan** aksi yang ingin dideteksi aplikasi (attach debugger sungguhan), bukan sekadar mengamati pasif:

> *"Using the backtraces from the hook output, inspect the code locations... and additionally use MASTG-TECH-0031 to attach a JDWP or native debugger to verify the app's defensive response: Determine whether the checks are called in release builds and not only in debug configurations. Determine whether the app changes its behavior when a debugger is attached (for example, issues a warning, restricts access, or terminates)."*

Ini membedakan test ini dari pola hooking pasif biasa — verifikasi penuh menuntut **dua jenis instrumentasi berjalan bersamaan**: Frida untuk observasi pemanggilan API, dan debugger JDWP/native sungguhan (via MASTG-TECH-0031) untuk mensimulasikan skenario ancaman yang sesungguhnya coba dideteksi aplikasi. Mengamati hook API saja tanpa benar-benar mencoba attach debugger hanya membuktikan "API dipanggil", bukan "API memberi hasil yang benar saat debugger sungguhan hadir".

### 1.5 Risiko Khusus: Mengaktifkan Mode Debuggable Bisa Mengganggu Integrity Check Lain

MASTG-TECH-0031 memberi catatan praktis yang relevan untuk perencanaan pengujian — opsi untuk memaksa aplikasi menjadi debuggable (demi memicu kondisi pengujian §1.3) memiliki efek samping:

> *"Hook Android framework checks so the app appears debuggable... This approach requires root and a hooking framework, and apps may detect it... Enable system-wide app debugging by changing system properties... This approach is noisy and easy for apps to detect."*

Ini menciptakan potensi **confounding factor** yang sama seperti dibahas di dokumen root/emulator detection sebelumnya dalam seri riset ini — bila aplikasi juga memiliki mekanisme deteksi terhadap `resetprop`/modifikasi sistem, upaya memaksa mode debuggable itu sendiri bisa memicu respons defensif yang **tidak terkait langsung** dengan logika anti-debugging yang ingin diuji, menciptakan ambiguitas dalam interpretasi hasil.

### 1.6 Expected False Negatives: Pola yang Konsisten dengan Keluarga Test Resilience Lain

> *"This test may produce false negatives if the app uses debugging detection techniques that are not covered by the hooks or traces used in this test, or if the debugging detection logic is implemented in a way that evades detection (for example, through obfuscation, dynamic code loading, or anti-instrumentation techniques)."*

Pola kalimat ini **identik secara struktural** dengan Expected False Negatives pada TEST-0325 (root) dan TEST-0351 (emulator) dalam seri riset ini — mengonfirmasi kembali bahwa seluruh keluarga test "runtime detection technique" di MASVS-RESILIENCE memakai template metodologi yang konsisten. Anti-instrumentation (deteksi Frida itu sendiri) tetap menjadi confounding factor yang relevan di sini — aplikasi yang mendeteksi Frida sebelum hook anti-debugging sempat teramati berjalan normal bisa menghasilkan kesan keliru "tidak ada deteksi debugging".

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core, Sesuai MASTG-TECH)

| Tool | Fungsi |
|---|---|
| **Frida** | Hooking API anti-debugging (MASTG-TECH-0043) |
| **strace** | Tracing system call `ptrace` tingkat native (MASTG-TECH-0032) |
| **jdb / Android Studio Debugger** | Attach debugger JDWP sungguhan untuk verifikasi lanjutan (MASTG-TECH-0031) |
| **ADB** | Instalasi app, `adb jdwp`/`adb forward` untuk setup debugging |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **Objection** | Hooking cepat tanpa script kustom |
| **lldb-server** | Attach debugger native (ptrace-based) untuk mensimulasikan skenario debugging layer native secara spesifik |
| **Build APK debuggable kustom** | Alternatif attach debugger sungguhan — modifikasi manifest `android:debuggable="true"` lalu re-sign, untuk memicu kondisi pengujian tanpa perlu root (MASTG-TECH-0038) |

### 2.3 Prasyarat Lingkungan

- Device rooted/emulator dengan `frida-server`.
- Kemampuan attach debugger JDWP/native sungguhan (via Android Studio atau `jdb`) untuk memenuhi validasi lanjutan §1.4 — bukan sekadar observasi pasif.

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0005** untuk instalasi aplikasi.
2. Gunakan **MASTG-TECH-0043** untuk hook API yang relevan.
3. Gunakan **MASTG-TECH-0032** untuk trace system call yang relevan.
4. Exercise aplikasi secara ekstensif untuk memicu sebanyak mungkin alur.

### 3.2 Metode A — Frida: Hook Observasi Pasif terhadap API Anti-Debugging

```javascript
Java.perform(function () {
    var Debug = Java.use("android.os.Debug");
    Debug.isDebuggerConnected.implementation = function () {
        var result = this.isDebuggerConnected();
        console.log("[Debug.isDebuggerConnected] -> " + result);
        console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));
        return result;
    };

    var ApplicationInfo = Java.use("android.content.pm.ApplicationInfo");
    // Amati pembacaan field flags untuk deteksi FLAG_DEBUGGABLE secara tidak langsung via logging akses
});
```

```bash
frida -U -f com.example.targetapp -l hook_antidebug.js --no-pause
```

### 3.3 Metode B — strace untuk Menangkap Pengecekan Native (TracerPid/ptrace)

```bash
adb shell strace -f -e trace=openat,read -p $(adb shell pidof com.example.targetapp) 2>&1 | grep -i 'proc.*status'
```

### 3.4 Metode C — Attach Debugger Sungguhan untuk Verifikasi Lanjutan (Wajib, Sesuai §1.4)

```bash
# JDWP
adb jdwp
adb forward tcp:7777 jdwp:<pid>
jdb -attach localhost:7777

# Amati: apakah aplikasi crash/menampilkan peringatan/membatasi fitur segera setelah attach berhasil?
```

```bash
# Native (ptrace-based) — alternatif
adb shell
gdbserver :5039 --attach <pid>
```

### 3.5 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Kapan dipakai |
|---|---|---|
| **A** | Frida observasi pasif | Baseline wajib — menangkap API yang terpanggil tanpa mengubah hasil |
| **B** | strace | Menangkap pengecekan native-level yang tidak terlihat dari hook Java |
| **C** | Attach debugger sungguhan | **Wajib** — satu-satunya cara memverifikasi respons defensif terhadap kondisi ancaman nyata (§1.4) |

**Kombinasi minimum yang aku rekomendasikan:** **A + B (observasi) → C (wajib, verifikasi respons nyata)**.

---

### 3.6 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG:**

> **Evaluation:** *"The test case fails if no debugging detection API calls are observed during app execution."*

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi |
|---|---|
| F1 | Tidak ada satu pun pemanggilan API/trace syscall terkait anti-debugging yang teramati, **meski** sudah mencoba attach debugger sungguhan (§1.3-1.4) |

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi |
|---|---|
| P1 | Teramati minimal satu pemanggilan API anti-debugging selama exercise/attach debugger |
| P2 | *(Validasi lanjutan wajib)* Aplikasi terbukti **mengubah perilaku** (peringatan/restriksi/terminasi) saat debugger sungguhan benar-benar terpasang — bukan sekadar memanggil API tanpa efek apa pun |

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Observasi pemanggilan API saja tidak cukup untuk PASS penuh** — sesuai §1.4, validasi wajib menuntut bukti bahwa perilaku aplikasi benar-benar berubah saat debugger sungguhan terpasang, bukan sekadar API terpanggil tanpa konsekuensi.

2. **Waspadai confounding factor dari memaksa mode debuggable** (§1.5) — bila hasil tidak sesuai ekspektasi, pertimbangkan apakah ini disebabkan mekanisme deteksi lain (bukan anti-debugging) yang terpicu akibat teknik `resetprop`/hooking yang dipakai untuk mensimulasikan kondisi debuggable.

3. **Korelasikan dengan hasil MASTG-TEST-0352** — bila statis menemukan banyak kandidat namun dinamis tidak mengamati satu pun terpanggil (bahkan setelah attach debugger sungguhan), kemungkinan kode tersebut dead code atau terkunci di build variant yang salah (persis skenario yang diantisipasi overview §1.1).

4. **Severity dimodulasi:**

   | Faktor | Severity |
   |---|---|
   | Tidak ada deteksi teramati sama sekali meski sudah attach debugger sungguhan, pada aplikasi data sensitif | **Tinggi** |
   | API terpanggil namun tidak ada perubahan perilaku nyata saat debugger terpasang (checks ada tapi tidak efektif) | **Sedang-Tinggi** (lebih buruk dari sekadar "tidak ada usaha" — memberi kesan keamanan palsu) |
   | API terpanggil dan perilaku berubah nyata (terminasi/restriksi) saat diverifikasi | **Bukan temuan** |

5. **Dokumentasikan:** API yang teramati terpanggil, backtrace, hasil attach debugger sungguhan (JDWP dan/atau native), dan perubahan perilaku yang terobservasi (atau tidak ada perubahan).

---

## 4. Rekomendasi Perbaikan

Rekomendasi sama dengan pasangan statisnya (MASTG-TEST-0352) — lihat dokumen tersebut untuk detail lengkap. Poin tambahan spesifik untuk hasil verifikasi dinamis:

### 4.1 Pastikan Respons Defensif Benar-Benar Terpicu, Bukan Hanya Logging

```java
// LEMAH — hanya mencatat log, tidak ada aksi defensif nyata
if (Debug.isDebuggerConnected()) {
    Log.w(TAG, "Debugger terdeteksi");
    // tidak ada aksi lanjutan!
}

// LEBIH BAIK — aksi defensif nyata
if (Debug.isDebuggerConnected()) {
    clearSensitiveDataFromMemory();
    finishAffinity();
    System.exit(0);
}
```

### Checklist Remediasi

- [ ] Verifikasi dinamis mengonfirmasi perubahan perilaku nyata, bukan hanya pemanggilan API tanpa efek
- [ ] Check terkonfirmasi aktif di build release melalui attach debugger langsung pada APK produksi
- [ ] Hasil dikorelasikan dengan MASTG-TEST-0352 untuk gambaran lengkap cakupan statis vs dinamis

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0353 (source, tests-beta)](https://github.com/OWASP/mastg/blob/master/tests-beta/android/MASVS-RESILIENCE/MASTG-TEST-0353.md)
- [MASTG-TEST-0352: References to Debugging Detection APIs (dokumen pasangan statis dalam seri riset ini)](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0352/)
- [MASTG-KNOW-0028: Anti-Debugging](https://mas.owasp.org/MASTG/knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0028/)
- [MASTG-BEST-0047: Continuous Anti-Debugging Checks](https://github.com/OWASP/mastg/blob/master/best-practices/MASTG-BEST-0047.md)
- [MASTG-TECH-0031: Debugging](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0031/)

### 5.2 Dokumentasi Tools

- [Frida — Dynamic Instrumentation Toolkit](https://frida.re/docs/home/)
- [Objection — Runtime Mobile Exploration](https://github.com/sensepost/objection)
- [Android Studio Debugger Documentation](https://developer.android.com/studio/debug)

---

*Dokumen ini disusun berdasarkan konten resmi OWASP MASTG (`tests-beta/android/MASVS-RESILIENCE/MASTG-TEST-0353.md`, `MASTG-KNOW-0028`, `MASTG-TECH-0031`), dilengkapi cross-reference mendalam dengan dokumen MASTG-TEST-0352 (pasangan statisnya) dalam seri riset ini yang sudah membahas kesenjangan cakupan rule resmi terhadap native code. Nuansa metodologis terpenting: validasi lanjutan test ini secara eksplisit menuntut penguji benar-benar melakukan attach debugger sungguhan (JDWP/native) untuk memverifikasi respons defensif nyata — hanya mengamati API terpanggil via hooking pasif tidak cukup untuk PASS penuh, karena API yang terpanggil tanpa efek perilaku apa pun justru menciptakan kesan keamanan palsu yang lebih berbahaya daripada tidak ada mekanisme sama sekali.*
