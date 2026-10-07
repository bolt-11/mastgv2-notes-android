# MASTG-TEST-0325 Runtime Use of Root Detection Techniques

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0325 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-RESILIENCE |
| **Weakness** | MASWE-0051 |
| **Tipe Pengujian** | Dynamic, Hooks |
| **Teknik terkait** | MASTG-TECH-0005 (Installing Apps), MASTG-TECH-0043 (Method Hooking), MASTG-TECH-0032 (Execution Tracing), MASTG-TECH-0144 (Bypassing Root Detection, opsional) |
| **Best Practice terkait** | MASTG-BEST-0029, MASTG-BEST-0030 (Implementing Root Detection) |
| **Knowledge terkait** | MASTG-KNOW-0027 (Root Detection) |
| **Test terkait** | **MASTG-TEST-0324** — counterpart **statis**, hubungan dua arah (sudah dibahas di dokumen TEST-0324 §1.2) |

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian

Kutipan overview resmi MASTG:

> *"This test verifies whether an app implements runtime root detection by attempting to hook into common root detection mechanisms."*

Test ini adalah penyelesaian dari sisi **konfirmasi aktif** terhadap temuan **MASTG-TEST-0324** — namun berbeda dari pola "statis-kandidat lalu dinamis-konfirmasi" yang dipakai di banyak pasangan test lain (mis. TEST-0318/0319), di sini overview resmi secara eksplisit mengizinkan kedua arah kerja (sudah dibahas detail di dokumen TEST-0324 §1.2). Yang membedakan test ini secara spesifik adalah **fokusnya pada observasi API/system call yang benar-benar terpanggil saat aplikasi berjalan**, bukan sekadar menemukan referensi di kode.

### 1.2 Fleksibilitas Device: Rooted Disarankan, Tapi Tidak Mutlak Wajib

Nuansa penting yang membedakan test ini dari kebanyakan test dinamis lain yang menuntut device rooted secara ketat:

> *"It is recommended to run this test using a rooted device or emulator to ensure that root detection mechanisms are triggered during testing. However, even on a non-rooted device, this test can still surface root detection logic if the app performs checks that do not require root access (for example, checking for the presence of root-related files or system properties)."*

Ini logis secara teknis — banyak pola root detection (pengecekan `File.exists()` terhadap path `su`, pembacaan `Build.TAGS`) **tidak butuh akses root untuk dieksekusi**; aplikasi hanya memeriksa **ketidakhadiran** indikator tersebut. Artinya meski hook berjalan di device non-rooted, pemanggilan method-nya tetap akan terjadi (dan terdeteksi hook) — hanya hasil pengecekannya saja yang akan selalu "bersih"/tidak rooted. Ini relevan untuk tim yang tidak memiliki akses ke device rooted dalam environment pengujian mereka.

### 1.3 Pendekatan Opsional: Bypass Aktif sebagai Sinyal Tambahan, Bukan Sekadar Observasi Pasif

Overview memberi opsi yang lebih agresif dibanding sekadar hooking-dan-mencatat:

> *"But, optionally, you can use MASTG-TECH-0144 to try to bypass root detection checks in the app and observe the results. For example, successful bypassing of certain checks or failed detections may indicate the presence of root detection mechanisms."*

Ini adalah teknik inferensi tidak langsung yang cerdas: bila penguji mencoba **membypass** sebuah mekanisme (memaksa `File.exists()` selalu mengembalikan `false`) dan **perilaku aplikasi berubah** (fitur yang sebelumnya diblokir menjadi dapat diakses), itu sendiri adalah **bukti kuat** bahwa mekanisme root detection memang ada dan fungsional — bahkan tanpa perlu melihat kode sumbernya sama sekali. Ini berguna khususnya untuk kasus mekanisme **native code terobfuskasi** yang disebutkan sebagai limitasi di MASTG-TEST-0324, karena bypass-dan-observasi-perilaku tidak bergantung pada kemampuan membaca logic internalnya.

### 1.4 Expected False Negatives: Pengakuan Eksplisit MASTG tentang Keterbatasan Hooking

Bagian ini unik karena MASTG secara eksplisit menyediakan subbagian khusus "Expected False Negatives" (jarang ditemukan selengkap ini di test lain dalam seri riset):

> *"This test may produce false negatives if the app uses root detection techniques that are not covered by the hooks or traces used in this test, or if the root detection logic is implemented in a way that evades detection (for example, through obfuscation, dynamic code loading, or anti-instrumentation techniques). In such cases, the absence of findings does not guarantee the absence of root detection."*

Poin **anti-instrumentation techniques** di sini sangat relevan secara nyata — banyak aplikasi finansial modern justru mendeteksi **kehadiran Frida itu sendiri** sebagai sinyal risiko terpisah (anti-Frida detection), yang berarti proses hooking yang dilakukan penguji untuk test ini bisa jadi **memicu mekanisme pertahanan lain** yang mengubah perilaku aplikasi (mis. app keluar paksa) sebelum root-check sempat teramati berjalan normal. Ini menciptakan paradoks metodologis: untuk menguji root detection, penguji mungkin perlu **lebih dulu membypass deteksi Frida**, yang sendirinya adalah lapisan resilience yang berbeda (di luar scope test ini, tapi harus diwaspadai sebagai confounding factor).

### 1.5 Konteks Nyata: "Perlombaan Senjata" antara Root-Hiding Modern dan Deteksi Aplikasi

Riset komunitas menunjukkan bahwa ekosistem bypass root detection kini sudah jauh lebih matang dibanding sekadar mengganti nama binary `su`. Stack modern yang dipakai secara luas untuk mengelabui aplikasi finansial sungguhan meliputi kombinasi berlapis:

> *"The full stack for hiding root includes Zygisk → DenyList → Play Integrity Fix → Shamiko → HideMyAppList. This stack has been tested with major banking apps including Chase, Bank of America, Wells Fargo, Capital One, and others."*

Komponen **Shamiko** secara spesifik dirancang untuk menetralisir deteksi berbasis **DenyList Magisk** itu sendiri:

> *"Shamiko is a Zygisk module that works in conjunction with Magisk's DenyList, making Magisk's presence virtually undetectable by specific apps and helping to pass SafetyNet/Play Integrity checks."*

Ini konteks penting untuk menilai temuan test: bahkan bila aplikasi target lulus PASS pada test ini (root detection terkonfirmasi aktif saat runtime), realitas di lapangan menunjukkan **mekanisme client-side saja sudah tidak lagi cukup** melawan device yang benar-benar disiapkan secara serius untuk mengelabui deteksi — inilah yang mendasari rekomendasi MASTG-BEST-0030 untuk validasi server-side sebagai lapisan wajib, bukan opsional (sudah dibahas di dokumen TEST-0324 §1.6, §4.3).

### 1.6 Risiko Berlapis: Frida sebagai Vektor Serangan Nyata di Luar Konteks Pengujian Sah

Penting dicatat secara seimbang — teknik yang sama dipakai penguji sah (dengan otorisasi) untuk memverifikasi root detection juga dipakai sebagai vektor serangan nyata bila jatuh ke tangan pihak tidak berwenang:

> *"For mobile banking specifically, attackers can use Frida for: SSL pinning bypass through scripts that disable certificate validation in seconds, exposing all API traffic to interception; hooking network libraries to read request/response bodies, steal authentication tokens, modify transaction amounts, and replay requests."*

Ini menegaskan bahwa root detection bukan kontrol yang berdiri sendiri — ia adalah salah satu **sinyal** dalam rangkaian pertahanan berlapis (anti-Frida, SSL pinning, server-side risk engine) yang secara kolektif menaikkan biaya serangan, konsisten dengan prinsip "cost-raising measure" yang sudah ditegaskan MASTG-BEST-0030.

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core, Sesuai MASTG-TECH)

| Tool | Fungsi |
|---|---|
| **Frida** | Hooking API root detection (MASTG-TECH-0043), opsional sekaligus untuk bypass aktif (MASTG-TECH-0144) |
| **strace** | Tracing system call tingkat kernel (MASTG-TECH-0032), menangkap pemanggilan native yang tidak terlihat dari hooking Java |
| **ADB** | Instalasi app (MASTG-TECH-0005) |
| **Objection** | Bypass cepat via `android root disable` tanpa menulis script kustom |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **Magisk + Zygisk + DenyList + Shamiko** | Mensimulasikan device "root-hidden" tingkat lanjut untuk menguji apakah mekanisme aplikasi tetap terpicu meski root disembunyikan secara agresif — skenario uji realistis sesuai §1.5 |
| **LSPosed** | Framework hooking Java/native tingkat sistem, alternatif Frida untuk bypass yang lebih persisten (modul, bukan skrip sesi) |
| **frida-antiantijb** / script anti-anti-detection komunitas | Melawan mekanisme anti-Frida yang mungkin memicu sebelum root-check sempat teramati (menangani confounding factor di §1.4) |
| **KernelSU** | Simulasi root-hiding tingkat kernel (bukan user-space) untuk menguji ketahanan terhadap skenario paling canggih |

### 2.3 Prasyarat Lingkungan

- **Device rooted/emulator direkomendasikan**, namun non-rooted tetap bisa dipakai untuk kasus terbatas (§1.2).
- Siapkan penanganan untuk kemungkinan anti-Frida detection pada aplikasi target (§1.4) — pertimbangkan Frida dengan konfigurasi tersembunyi (custom frida-server rename, dsb.) bila diperlukan.
- Daftar sensitif/skenario yang perlu dipicu selama exercise (sesuai langkah 4 resmi: "exercise the app extensively... enter sensitive data wherever you can").

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0005** untuk instalasi aplikasi.
2. Gunakan **MASTG-TECH-0043** untuk hook API yang relevan.
3. Gunakan **MASTG-TECH-0032** untuk trace system call yang relevan.
4. Exercise aplikasi secara ekstensif untuk memicu sebanyak mungkin alur.

### 3.2 Metode A — Frida: Hook Observasi Pasif (Tanpa Mengubah Hasil)

```javascript
Java.perform(function () {
    var File = Java.use("java.io.File");
    File.exists.overload().implementation = function () {
        var path = this.getAbsolutePath();
        var result = this.exists();
        console.log("[File.exists] " + path + " -> " + result);
        return result; // tidak diubah, murni observasi
    };

    var Runtime = Java.use("java.lang.Runtime");
    Runtime.exec.overload('java.lang.String').implementation = function (cmd) {
        console.log("[Runtime.exec] " + cmd);
        return this.exec(cmd);
    };

    var PackageManager = Java.use("android.app.ApplicationPackageManager");
    PackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function (pkg, flags) {
        console.log("[getPackageInfo] " + pkg);
        return this.getPackageInfo(pkg, flags);
    };
});
```

```bash
frida -U -f com.example.targetapp -l observe_root_checks.js --no-pause
```

### 3.3 Metode B — strace untuk Menangkap Native-Level Checks

```bash
adb shell strace -f -e trace=stat,openat,access -p $(adb shell pidof com.example.targetapp) 2>&1 | grep -iE 'su|magisk|busybox'
```

Melengkapi Metode A — menangkap pengecekan file yang dilakukan lewat **kode native (JNI)**, yang tidak akan terlihat dari hooking method Java saja.

### 3.4 Metode C — Objection untuk Bypass Cepat dan Observasi Perubahan Perilaku (Sesuai §1.3)

```bash
objection -g com.example.targetapp explore
# di dalam REPL:
android root disable
```

Jalankan app setelah bypass, lalu bandingkan perilaku dengan kondisi tanpa bypass — perubahan perilaku (fitur yang sebelumnya terblokir kini dapat diakses) adalah bukti tidak langsung keberadaan mekanisme (§1.3).

### 3.5 Metode D — Stack Root-Hiding Lanjutan untuk Menguji Ketahanan Nyata (Sesuai §1.5)

```
Prosedur:
1. Siapkan device dengan Magisk + Zygisk + DenyList + Shamiko aktif
2. Tambahkan package aplikasi target ke DenyList
3. Jalankan aplikasi, amati apakah mekanisme root detection tetap terpicu (lewat hook Metode A) meski root disembunyikan di tingkat sistem
4. Bandingkan hasil dengan Metode A di device rooted tanpa hiding stack
```

Ini melampaui scope resmi test (observasi dasar), namun relevan untuk menilai apakah temuan PASS pada test ini benar-benar tahan terhadap skenario root-hiding realistis yang dipakai di lapangan.

### 3.6 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Kapan dipakai |
|---|---|---|
| **A** | Frida observasi pasif | Baseline wajib — mencatat API yang terpanggil tanpa mengubah hasil |
| **B** | strace | Menangkap pengecekan native/JNI yang tidak terlihat dari hook Java |
| **C** | Objection bypass | Inferensi tidak langsung lewat observasi perubahan perilaku (§1.3) |
| **D** | Stack root-hiding (Shamiko dkk) | Menilai ketahanan nyata terhadap skenario lapangan, di luar scope dasar resmi |

**Kombinasi minimum yang aku rekomendasikan:** **A (wajib, observasi pasif) + B (menutup celah native)**. Metode C berguna sebagai pelengkap bila A/B tidak memberi hasil jelas. Metode D hanya untuk audit ketahanan mendalam, bukan pengujian standar.

---

### 3.7 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG:**

> **Evaluation:** *"The test case fails if no instances of root detection checks are observed. However, results from this test should be interpreted as evidence of the presence of root detection logic, not as an assessment of its robustness or effectiveness."*

Sama seperti TEST-0324, arah evaluasi **terbalik** — ketidakhadiran observasi adalah FAIL.

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi |
|---|---|
| F1 | Setelah exercise ekstensif dengan hooking aktif (Metode A/B), **tidak ada satu pun** pemanggilan API/system call terkait root detection yang teramati |

**Catatan kehati-hatian wajib:** sebelum menyimpulkan FAIL final, pastikan bukan disebabkan oleh **anti-instrumentation** yang mencegah Frida berfungsi normal (§1.4) — verifikasi dulu bahwa aplikasi berjalan normal dengan Frida terpasang, baru simpulkan FAIL bila memang tidak ada aktivitas root-check sama sekali.

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi |
|---|---|
| P1 | Teramati minimal satu pemanggilan API/system call yang cocok dengan pola root detection dari MASTG-KNOW-0027 selama exercise |
| P2 | *(Opsional, sinyal kualitas tambahan)* Bypass aktif (Metode C) menunjukkan perubahan perilaku nyata — bukti fungsional, bukan hanya pemanggilan API kosong tanpa efek apa pun |

**Contoh bukti:**

```
[File.exists] /system/xbin/su -> false
[File.exists] /system/bin/su -> false
[getPackageInfo] com.topjohnwu.magisk
```

Interpretasi: API dipanggil secara aktif saat runtime terhadap path dan package yang relevan root detection. **PASS**.

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Ini juga murni test presence, bukan efektivitas** — sama seperti TEST-0324, hasil PASS tidak menjamin mekanisme tahan terhadap stack root-hiding modern (§1.5); pertimbangkan Metode D untuk audit lebih dalam bila risiko bisnis tinggi (mis. aplikasi finansial).

2. **Waspadai anti-instrumentation sebagai confounding factor** — bila app langsung crash/keluar saat Frida terpasang, ini **bukan** berarti tidak ada root detection; ini justru sinyal adanya lapisan resilience tambahan (anti-Frida) yang perlu dibypass dulu secara terpisah sebelum test ini bisa dijalankan dengan valid.

3. **Observasi pasif (tanpa mengubah return value) lebih disukai untuk menghindari bias** — mengubah hasil di awal (seperti Metode C) bisa menyembunyikan mekanisme berlapis lain yang baru terpicu setelah check pertama "lolos"; jalankan observasi pasif dulu secara menyeluruh sebelum mencoba bypass aktif.

4. **Korelasikan dengan hasil MASTG-TEST-0324** — bila statis menemukan banyak kandidat namun dinamis tidak mengamati satu pun terpanggil, kemungkinan logic tersebut **dead code**, dipanggil hanya pada kondisi tertentu yang belum terpicu, atau ada di jalur yang tidak teruji; investigasi lanjutan diperlukan sebelum menyimpulkan ketidaksesuaian ini.

5. **Severity dimodulasi:**

   | Faktor | Severity |
   |---|---|
   | Tidak ada root detection teramati sama sekali, aplikasi menangani data/transaksi sensitif | **Tinggi** |
   | Root detection teramati tapi mudah dinetralisir dengan bypass dasar (hanya 1 lapis, tanpa server-side validation) | **Sedang** |
   | Root detection teramati, berlapis, dan tetap terpicu meski stack root-hiding lanjutan diaktifkan | **Bukan temuan**/informasi positif |

6. **Dokumentasikan:** API/system call yang teramati terpanggil beserta argumen, hasil observasi perubahan perilaku dari bypass aktif (bila dilakukan), dan interaksi dengan kemungkinan anti-instrumentation yang terdeteksi.

---

## 4. Rekomendasi Perbaikan

### 4.1 Kombinasikan Deteksi dengan Respons Proporsional, Bukan Hanya Blokir Keras

```java
// LEMAH — hanya satu titik keputusan biner
if (RootDetector.isRooted()) { finish(); }

// LEBIH BAIK — sinyal risiko dikombinasikan, dikirim ke server untuk keputusan kontekstual
RiskSignal signal = RiskSignal.builder()
    .rootDetected(RootDetector.isRooted())
    .fridaDetected(AntiInstrumentation.isHooked())
    .build();
riskEngine.evaluate(signal); // keputusan akhir di server, bukan murni client
```

### 4.2 Uji Ketahanan Terhadap Stack Root-Hiding Modern Secara Berkala

Jadikan pengujian dengan Magisk+Zygisk+DenyList+Shamiko (§3.5) sebagai bagian dari siklus audit keamanan rutin, mengingat stack ini terus berkembang dan APK perlu diuji ulang setiap rilis besar.

### 4.3 Checklist Remediasi

- [ ] Root detection teramati aktif berjalan saat runtime (bukan hanya ada di kode tapi tidak pernah terpanggil)
- [ ] Mekanisme bertahan terhadap bypass dasar (Objection `android root disable`, Frida script umum)
- [ ] Diuji juga terhadap stack root-hiding lanjutan (Shamiko dkk) untuk aplikasi berisiko tinggi
- [ ] Hasil sinyal risiko dikombinasikan dengan validasi server-side, bukan keputusan client-only
- [ ] Dikombinasikan dengan anti-instrumentation (anti-Frida) sebagai lapisan terpisah

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0325 (source, tests-beta)](https://github.com/OWASP/mastg/blob/master/tests-beta/android/MASVS-RESILIENCE/MASTG-TEST-0325.md)
- [MASTG-TEST-0324: References to Root Detection Mechanisms](https://github.com/OWASP/mastg/blob/master/tests-beta/android/MASVS-RESILIENCE/MASTG-TEST-0324.md)
- [MASTG-TECH-0144: Bypassing Root Detection](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0144/)
- [MASTG-KNOW-0027: Root Detection](https://mas.owasp.org/MASTG/knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0027/)
- [MASTG-BEST-0030: Implementing Root Detection](https://github.com/OWASP/mastg/blob/master/best-practices/MASTG-BEST-0030.md)

### 5.2 Riset dan Kasus Nyata

- [Approov: Frida Detection & Prevention](https://approov.io/knowledge/frida-detection-prevention)
- [Approov: What is Frida and How Can Apps Protect Against It?](https://approov.io/knowledge/what-is-frida-and-how-can-apps-protect-against-it)
- [GitHub: frida-antiantijb — Jailbreak Detection Bypasses Based on Frida](https://github.com/juliangrtz/frida-antiantijb)
- [Wikipedia: Magisk (software)](https://en.wikipedia.org/wiki/Magisk_(software))
- [XDA Forums: Hide Magisk Root (Bank Apps, SafetyNet, Play Integrity)](https://xdaforums.com/t/hide-magisk-root-bank-apps-safetynet-play-integrity.4729480/)

### 5.3 Dokumentasi Tools

- [Frida — Dynamic Instrumentation Toolkit](https://frida.re/docs/home/)
- [Objection — Runtime Mobile Exploration](https://github.com/sensepost/objection)
- [LSPosed Framework](https://github.com/LSPosed/LSPosed)
- [KernelSU](https://github.com/tiann/KernelSU)

---

*Dokumen ini disusun berdasarkan konten resmi OWASP MASTG (`tests-beta/android/MASVS-RESILIENCE/MASTG-TEST-0325.md`, `MASTG-TECH-0144`), serta riset komunitas tentang evolusi stack root-hiding modern (Zygisk, DenyList, Shamiko, Play Integrity Fix) yang terbukti efektif mengelabui aplikasi perbankan nyata (Chase, Bank of America, Wells Fargo, dsb.) per 2026. Nuansa metodologis terpenting: subbagian "Expected False Negatives" resmi MASTG secara eksplisit mengakui bahwa anti-instrumentation (deteksi Frida itu sendiri) dapat menjadi confounding factor yang mencegah test ini berjalan valid — penguji harus memverifikasi Frida berfungsi normal pada aplikasi target sebelum menyimpulkan ketidakhadiran root detection, dan hasil PASS pada test ini tetap tidak menjamin ketahanan terhadap stack root-hiding modern yang sudah terbukti efektif di lapangan.*
