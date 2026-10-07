# MASTG-TEST-0264 Runtime Use of StrictMode APIs

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0264 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-RESILIENCE |
| **Weakness** | MASWE-0061 — *Debug Artifacts Not Removed* |
| **API yang disorot** | `StrictMode.setVmPolicy`, `StrictMode.VmPolicy.Builder.penaltyLog` |
| **Tipe Pengujian** | **Dynamic, Hooks** |
| **Profile** | **R (Resilience) saja** |
| **Teknik terkait** | MASTG-TECH-0005 (Install App), MASTG-TECH-0043 (Method Hooking) |
| **Test terkait** | **MASTG-TEST-0263** (Logging of StrictMode Violations) — pendekatan yang **berbeda** untuk risiko yang sama, lihat §1.2 |
| **Demo terkait** | — (tidak ada) |
| **Rule resmi** | — (tidak relevan; test dinamis berbasis hooking, bukan analisis kode statis) |
| **CWE terkait** | CWE-215, CWE-489 |

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian

Kutipan overview resmi MASTG:

> *"This test checks whether the app uses `StrictMode` by dynamically analyzing the app's behavior and placing relevant hooks to detect the use of `StrictMode` APIs, such as `StrictMode.setVmPolicy` and `StrictMode.VmPolicy.Builder.penaltyLog`."*

Seluruh konteks konseptual mendalam — mengapa `StrictMode` yang aktif di produksi berbahaya, detail informasi apa saja yang bocor lewat stack trace pelanggarannya (nama kelas, method, baris kode), dan bagaimana ini memberi "peta gratis" bagi upaya reverse engineering — **sudah dibahas lengkap di dokumen MASTG-TEST-0263**. Dokumen ini fokus pada **perbedaan metodologis** antara kedua test, yang meski berbagi weakness (MASWE-0061) dan profile (R) yang identik, sebenarnya **mengukur hal yang secara halus berbeda**.

### 1.2 Perbedaan Fundamental dengan MASTG-TEST-0263: Deteksi Konfigurasi vs Deteksi Pelanggaran

Ini nuansa metodologis paling penting yang membedakan kedua test — meski sekilas tampak seperti "versi hooking" dari test logcat sebelumnya, keduanya sebenarnya **mengukur sinyal yang berbeda**:

| | MASTG-TEST-0263 (Logging of Violations) | MASTG-TEST-0264 *(dokumen ini)* |
|---|---|---|
| **Yang dideteksi** | **Bukti pelanggaran** kebijakan yang benar-benar terjadi dan tercatat di Logcat | **Keberadaan konfigurasi** `StrictMode` itu sendiri, terlepas apakah ada pelanggaran yang benar-benar terpicu |
| **Metode** | Memantau Logcat pasif (`adb logcat`) | Hooking aktif pada API konfigurasi (`setVmPolicy`, `penaltyLog`) |
| **Prasyarat untuk FAIL** | Minimal **satu pelanggaran kebijakan** harus benar-benar terjadi selama sesi (mis. ada disk I/O di main thread) | **Cukup** API konfigurasi `StrictMode` dipanggil — **tidak perlu** pelanggaran benar-benar terjadi |

Konsekuensi praktisnya: **MASTG-TEST-0264 secara struktural lebih sensitif** dibanding MASTG-TEST-0263 untuk kasus tertentu. Bayangkan skenario di mana aplikasi mengaktifkan `StrictMode` di build produksi, namun **selama sesi pengujian tertentu**, kebetulan tidak ada satu pun operasi yang melanggar kebijakan yang dikonfigurasi (mis. seluruh disk I/O sudah dipindah ke background thread dengan benar, sehingga tidak pernah memicu `StrictModeDiskReadViolation`). Pada skenario ini:

- **MASTG-TEST-0263 akan menunjukkan hasil PASS** (tidak ada log pelanggaran ditemukan) — meski secara teknis ini bisa jadi **false negative**, karena `StrictMode` yang aktif tetap merupakan artefak debug yang seharusnya tidak ada di produksi, terlepas apakah kebetulan tidak ada pelanggaran yang terpicu pada sesi pengujian tersebut.
- **MASTG-TEST-0264 akan tetap menunjukkan hasil FAIL** — karena hook pada `setVmPolicy()`/`penaltyLog()` akan terpicu **begitu API tersebut dipanggil saat inisialisasi aplikasi**, tidak peduli apakah pelanggaran kebijakan sungguhan terjadi setelahnya.

Inilah mengapa **kedua test saling melengkapi**, bukan duplikat — MASTG-TEST-0264 menutup celah cakupan yang berpotensi terlewat oleh pendekatan pasif MASTG-TEST-0263.

### 1.3 Mengapa `penaltyLog()` Secara Spesifik Disorot

Overview resmi secara khusus menyebut `StrictMode.VmPolicy.Builder.penaltyLog` sebagai target hooking, bukan hanya `setVmPolicy()` secara umum. Ini penting karena `StrictMode` mendukung berbagai jenis **penalty** (tindakan yang diambil saat pelanggaran terdeteksi) — `penaltyLog()` (mencatat ke Logcat, inilah yang menjadi akar risiko kebocoran informasi di MASTG-TEST-0263), `penaltyDeath()` (memaksa crash aplikasi), `penaltyDropBox()` (mencatat ke sistem DropBox internal Android), dan lainnya. Dengan hooking khusus pada `penaltyLog()`, penguji dapat memastikan **secara spesifik** bahwa konfigurasi yang ditemukan benar-benar mengarah ke risiko pencatatan log (bukan sekadar `penaltyDeath()` semata, misalnya, yang punya profil risiko berbeda — meski tetap merupakan artefak debug yang tidak seharusnya ada di produksi).

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | Fungsi |
|---|---|
| **Frida** | Instrumentasi dinamis inti — hooking API konfigurasi `StrictMode` |
| **frida-tools** (`frida-trace`) | Tracing cepat tanpa skrip kustom |
| **objection** | Wrapper Frida siap pakai |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **Xposed/LSPosed** | Alternatif hooking persisten sesuai MASTG-TECH-0043 |
| **adb logcat** | Pelengkap untuk korelasi dengan hasil MASTG-TEST-0263 |

### 2.3 Prasyarat Lingkungan

- **Wajib device/emulator dengan Frida server** — test murni dinamis berbasis hooking.
- **Target pengujian harus APK build produksi/release**, sama seperti MASTG-TEST-0263.
- **Interaksi menyeluruh** — meski test ini lebih sensitif terhadap keberadaan konfigurasi (§1.2), `StrictMode` biasanya dikonfigurasi sekali saat inisialisasi aplikasi (`Application.onCreate()`), sehingga hook idealnya sudah terpasang **sebelum** aplikasi selesai start untuk menangkap momen inisialisasi tersebut.

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0005** untuk menginstal aplikasi.
2. Gunakan **MASTG-TECH-0043** untuk melakukan hooking pada pemanggilan API yang relevan.
3. Jelajahi aplikasi secara menyeluruh, masukkan data sensitif di mana pun memungkinkan.

### 3.2 Metode A — Hooking Konfigurasi `StrictMode` Secara Menyeluruh *(metode utama)*

```javascript
// hook-strictmode-runtime.js
Java.perform(function () {
    function getBacktrace() {
        return Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());
    }

    // 1. setVmPolicy — konfigurasi level VM/aplikasi
    try {
        var StrictMode = Java.use("android.os.StrictMode");
        StrictMode.setVmPolicy.overload("android.os.StrictMode$VmPolicy").implementation = function (policy) {
            console.log("\n[!] StrictMode.setVmPolicy() dipanggil pada build ini!");
            console.log("    Policy: " + policy.toString());
            console.log("    Stack trace:\n" + getBacktrace());
            return this.setVmPolicy(policy);
        };
    } catch (e) { console.log("[x] Hook setVmPolicy gagal: " + e); }

    // 2. setThreadPolicy — konfigurasi level thread (pelengkap, tidak disebut eksplisit tapi relevan)
    try {
        StrictMode.setThreadPolicy.overload("android.os.StrictMode$ThreadPolicy").implementation = function (policy) {
            console.log("\n[!] StrictMode.setThreadPolicy() dipanggil pada build ini!");
            console.log("    Stack trace:\n" + getBacktrace());
            return this.setThreadPolicy(policy);
        };
    } catch (e) { console.log("[x] Hook setThreadPolicy gagal: " + e); }

    // 3. penaltyLog() pada VmPolicy.Builder — secara spesifik disorot overview resmi
    try {
        var VmPolicyBuilder = Java.use("android.os.StrictMode$VmPolicy$Builder");
        VmPolicyBuilder.penaltyLog.overload().implementation = function () {
            console.log("\n[!] StrictMode.VmPolicy.Builder.penaltyLog() dipanggil!");
            console.log("    Stack trace:\n" + getBacktrace());
            return this.penaltyLog();
        };
    } catch (e) { console.log("[x] Hook penaltyLog (VmPolicy) gagal: " + e); }

    // 4. penaltyLog() pada ThreadPolicy.Builder
    try {
        var ThreadPolicyBuilder = Java.use("android.os.StrictMode$ThreadPolicy$Builder");
        ThreadPolicyBuilder.penaltyLog.overload().implementation = function () {
            console.log("\n[!] StrictMode.ThreadPolicy.Builder.penaltyLog() dipanggil!");
            console.log("    Stack trace:\n" + getBacktrace());
            return this.penaltyLog();
        };
    } catch (e) { console.log("[x] Hook penaltyLog (ThreadPolicy) gagal: " + e); }
});
```

```bash
frida -U -f com.target.app -l hook-strictmode-runtime.js --no-pause
```

**Catatan penting**: skrip **wajib** dijalankan dengan `-f` (spawn, bukan attach ke proses yang sudah berjalan) dan `--no-pause`, karena konfigurasi `StrictMode` hampir selalu terjadi di `Application.onCreate()` — momen yang sangat awal dalam siklus hidup aplikasi. Bila hook dipasang **setelah** aplikasi sudah berjalan (attach ke proses existing), momen pemanggilan `setVmPolicy()` kemungkinan besar sudah lewat dan tidak akan pernah tertangkap.

### 3.3 Metode B — objection (Tanpa Menulis Skrip Kustom)

```bash
objection -g com.target.app explore
android hooking watch class_method android.os.StrictMode.setVmPolicy --dump-args --dump-backtrace
android hooking watch class_method 'android.os.StrictMode$VmPolicy$Builder.penaltyLog' --dump-backtrace
```

### 3.4 Metode C — frida-trace (Tracing Cepat via Wildcard)

```bash
frida-trace -U -f com.target.app -m "android.os.StrictMode*!*"
```

### 3.5 Metode D — Korelasi dengan MASTG-TEST-0263 untuk Gambaran Lengkap

Jalankan kedua test secara berdampingan untuk memperoleh gambaran paling lengkap:

```bash
# Terminal 1: hooking konfigurasi (test ini)
frida -U -f com.target.app -l hook-strictmode-runtime.js --no-pause

# Terminal 2: pemantauan pelanggaran aktual (MASTG-TEST-0263)
adb logcat | grep -i "StrictMode"
```

Bila Terminal 1 menangkap pemanggilan `setVmPolicy()`/`penaltyLog()` **namun** Terminal 2 tidak pernah menunjukkan pelanggaran nyata selama sesi yang sama, ini mengonfirmasi persis skenario yang dijelaskan di §1.2 — bukti konkret bahwa MASTG-TEST-0264 menangkap kondisi FAIL yang **terlewat** oleh MASTG-TEST-0263 semata.

### 3.6 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Kelebihan | Kapan dipakai |
|---|---|---|---|
| **A** | Skrip Frida kustom (spawn) | Mencakup 4 API sekaligus + backtrace | Baseline utama, wajib pakai `-f` |
| **B** | objection | Cepat tanpa scripting | Eksplorasi awal cepat |
| **C** | frida-trace | Tracing otomatis via wildcard | Overview cepat |
| **D** | Korelasi paralel dengan MASTG-TEST-0263 | Membuktikan nilai tambah unik test ini | Analisis komparatif menyeluruh |

**Kombinasi minimum yang aku rekomendasikan:** **A (hooking spawn sejak awal, wajib `-f`) → D (korelasi dengan MASTG-TEST-0263)** untuk laporan yang menunjukkan baik status konfigurasi maupun bukti pelanggaran aktual bila ada.

---

### 3.7 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG:**

> **Observation:** *"The output should show the runtime usage of `StrictMode` APIs."*
>
> **Evaluation:** *"The test case fails if the output shows the runtime usage of `StrictMode` APIs."*

Kriteria ini **jauh lebih sederhana** dibanding MASTG-TEST-0263 — tidak ada syarat "harus ada pelanggaran yang tercatat", cukup **bukti bahwa API tersebut dipanggil** sudah memenuhi kondisi FAIL.

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi |
|---|---|
| F1 | Hook `setVmPolicy`/`setThreadPolicy` **terpicu sama sekali** selama sesi pengujian pada build produksi, terlepas apakah pelanggaran kebijakan nyata terjadi setelahnya |
| F2 | Hook `penaltyLog()` (VmPolicy atau ThreadPolicy) terpicu — konfirmasi eksplisit bahwa penalty logging diaktifkan |

**Contoh bukti (ilustratif — MASTG belum menyediakan demo resmi untuk test ini):**

```
[!] StrictMode.setVmPolicy() dipanggil pada build ini!
    Policy: VmPolicy{mask=13, mCtsLog=...}
    Stack trace:
        at com.target.app.MyApplication.onCreate(MyApplication.java:18)
        at android.app.Instrumentation.callApplicationOnCreate(Instrumentation.java:1270)

[!] StrictMode.VmPolicy.Builder.penaltyLog() dipanggil!
    Stack trace:
        at com.target.app.MyApplication.onCreate(MyApplication.java:17)
```

Interpretasi: `StrictMode` dikonfigurasi lengkap dengan `penaltyLog()` sejak `Application.onCreate()` pada build yang diuji (yang seharusnya adalah build produksi) — **FAIL**, terlepas dari apakah Logcat pada sesi ini kebetulan menunjukkan pelanggaran nyata atau tidak.

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi |
|---|---|
| P1 | **Tidak ada** hook API `StrictMode` yang terpicu sama sekali selama sesi pengujian menyeluruh pada build produksi |

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Ini test yang lebih ketat dari pasangannya (MASTG-TEST-0263) — manfaatkan untuk menutup celah false negative.** Sesuai §1.2, sebuah aplikasi bisa PASS di MASTG-TEST-0263 (tidak ada pelanggaran tercatat pada sesi tertentu) namun tetap FAIL di sini (konfigurasi terbukti ada). Selalu jalankan **keduanya**, jangan hanya salah satu, untuk kesimpulan yang benar-benar solid.

2. **Pastikan hook terpasang SEBELUM aplikasi start (`-f`, bukan attach)** — ini kesalahan teknis paling umum yang menyebabkan false negative pada test ini, karena konfigurasi `StrictMode` biasanya terjadi sangat awal di `Application.onCreate()`.

3. **Pastikan menguji build produksi/release**, konsisten dengan prasyarat yang sama seperti MASTG-TEST-0263.

4. **Backtrace hasil hook memberi lokasi kode presisi untuk remediasi** — manfaatkan untuk langsung menunjuk baris kode yang perlu dibungkus guard `BuildConfig.DEBUG`, sama seperti pola di dokumen MASTG-TEST-0238/0249/0251 dalam seri riset ini.

5. **Severity mengikuti pola yang sama seperti MASTG-TEST-0263** — meski kriteria FAIL di sini tidak menuntut bukti pelanggaran aktual, dampak sesungguhnya (kebocoran arsitektural) baru benar-benar terwujud saat pelanggaran nyata terjadi dan ter-log; kombinasikan hasil kedua test untuk penilaian dampak paling akurat.

6. **Dokumentasikan:** API `StrictMode` mana yang terpicu (`setVmPolicy`/`setThreadPolicy`/`penaltyLog`), backtrace lokasi konfigurasinya, dan hasil korelasi dengan MASTG-TEST-0263 (apakah pelanggaran nyata juga ditemukan pada sesi yang sama).

---

## 4. Rekomendasi Perbaikan

Rekomendasi identik dengan **dokumen MASTG-TEST-0263 §4** — bungkus seluruh pemanggilan `StrictMode` dengan guard `BuildConfig.DEBUG`, verifikasi lewat ProGuard/R8 dead-code elimination, dan integrasikan pengujian ke CI/CD.

Tambahan spesifik untuk sudut pandang hooking:

### 4.1 Integrasikan Kedua Test ke Regression Test Otomatis

```bash
#!/bin/bash
# ci-check-strictmode-hooks-and-logs.sh — kombinasikan kedua pendekatan
frida -U -f com.target.app -l hook-strictmode-runtime.js --no-pause > frida_output.log &
FRIDA_PID=$!
adb logcat -c
sleep 3
./run-ui-test-suite.sh
kill $FRIDA_PID

if grep -q "StrictMode.setVmPolicy() dipanggil" frida_output.log; then
    echo "[GAGAL] StrictMode API terdeteksi aktif pada build ini (MASTG-TEST-0264)"
    exit 1
fi
```

### 4.2 Checklist Remediasi

- [ ] Hook mencakup `setVmPolicy`, `setThreadPolicy`, dan `penaltyLog` pada kedua builder
- [ ] Hook dipasang via spawn (`-f`), bukan attach, untuk menangkap inisialisasi awal
- [ ] Hasil dikorelasikan dengan MASTG-TEST-0263 untuk gambaran lengkap
- [ ] Seluruh pemanggilan `StrictMode` yang ditemukan sudah dibungkus guard `BuildConfig.DEBUG`
- [ ] **Verifikasi ulang:** jalankan kembali MASTG-TEST-0264 pada setiap build release baru

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0264: Runtime Use of StrictMode APIs](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0264/)
- [MASTG-TEST-0263: Logging of StrictMode Violations](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0263/)
- [MASWE-0061: Debug Artifacts Not Removed](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0061/)
- [MASTG-TECH-0005: Installing Apps](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0005/)
- [MASTG-TECH-0043: Method Hooking](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0043/)

### 5.2 Dokumentasi Resmi Android

- [Android Developers — `StrictMode` API reference](https://developer.android.com/reference/android/os/StrictMode)
- [Android Developers — `StrictMode.VmPolicy.Builder`](https://developer.android.com/reference/android/os/StrictMode.VmPolicy.Builder)
- [Android Developers — `StrictMode.ThreadPolicy.Builder`](https://developer.android.com/reference/android/os/StrictMode.ThreadPolicy.Builder)

### 5.3 Dokumentasi Tools

- [Frida — Dynamic instrumentation toolkit](https://frida.re/docs/javascript-api/)
- [frida-trace — Documentation](https://frida.re/docs/frida-trace/)
- [Objection — Runtime Mobile Exploration toolkit](https://github.com/sensepost/objection)
- [LSPosed Framework](https://github.com/LSPosed/LSPosed)

---

*Dokumen ini disusun berdasarkan OWASP MASTG (rilis terkini per September 2026) dan dokumentasi resmi Android Developers. Meski berbagi weakness dan profile yang identik dengan MASTG-TEST-0263, test ini mengukur sinyal yang secara fundamental berbeda: **keberadaan konfigurasi** `StrictMode` lewat hooking API, bukan **bukti pelanggaran** lewat pemantauan Logcat pasif. Perbedaan ini membuat test ini secara struktural lebih sensitif — mampu mendeteksi kondisi FAIL bahkan pada sesi pengujian di mana kebetulan tidak ada pelanggaran kebijakan yang benar-benar terpicu, sebuah skenario yang akan luput dari MASTG-TEST-0263 semata. Kedua test direkomendasikan dijalankan berdampingan untuk cakupan evaluasi yang paling lengkap.*
