# MASTG-TEST-0249 Runtime Use of Secure Screen Lock Detection APIs

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0249 |
| **Platform** | Android |
| **Lokasi test resmi** | Folder MASVS-RESILIENCE (sama seperti MASTG-TEST-0247 — dan mewarisi kesimpangsiuran kategori MASVS yang sama, lihat dokumen MASTG-TEST-0247 §1.1) |
| **Weakness** | MASWE-0017 — *Device Secure Lock Not Enforced* |
| **API yang disorot** | `KeyguardManager.isDeviceSecure()`, `BiometricManager#canAuthenticate()` |
| **Tipe Pengujian** | **Dynamic, Hooks** |
| **Profile** | **L2 saja** |
| **Knowledge** | MASTG-KNOW-0001 *(rujukan ini bermasalah — lihat catatan di dokumen MASTG-TEST-0247 §1.6)* |
| **Teknik terkait** | MASTG-TECH-0005 (Install App), MASTG-TECH-0043 (Method Hooking) |
| **Test terkait** | **MASTG-TEST-0247** (References to APIs for Detecting Secure Screen Lock — counterpart statis; overview resmi test ini secara eksplisit menyatakan *"This test is the dynamic counterpart to MASTG-TEST-0247"*) |
| **Demo terkait** | — (tidak ada) |
| **Rule resmi** | — (tidak relevan; test dinamis berbasis hooking) |
| **CWE terkait** | CWE-287 (Improper Authentication), CWE-862 (Missing Authorization) |

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian dan Hubungannya dengan MASTG-TEST-0247

Overview resmi MASTG untuk test ini sangat ringkas dan langsung menyatakan posisinya:

> *"This test is the dynamic counterpart to MASTG-TEST-0247. In this case, we'll look for uses of `KeyguardManager.isDeviceSecure` and `BiometricManager.canAuthenticate` APIs."*

Seluruh konteks konseptual — mengapa deteksi secure lock screen ini penting (koneksinya dengan `KeyGenParameterSpec.setUserAuthenticationRequired(true)` pada Android Keystore), batasan bahwa aplikasi tidak bisa memaksa pengguna mengaktifkan lock screen di level sistem, dan alasan `BiometricManager#canAuthenticate()` menjadi jalur fallback ketika `KeyguardManager` dibatasi vendor tertentu — **sudah dibahas mendalam di dokumen MASTG-TEST-0247** dan sepenuhnya berlaku untuk test ini. Dokumen ini akan fokus pada **apa yang unik** dari sudut pandang dinamis: nilai tambah hooking runtime dibanding analisis statis semata, dan metodologi implementasinya.

### 1.2 Nilai Unik Pendekatan Dinamis: Konfirmasi Eksekusi Nyata dan Menangkap yang Terlewat Analisis Statis

Sesuai pola yang berulang di seluruh pasangan test statis-dinamis dalam seri riset ini (MASTG-TEST-0200/0201, 0203/0231, dsb.), pendekatan dinamis di sini memberi dua nilai tambah spesifik:

1. **Konfirmasi bahwa pengecekan benar-benar tereksekusi**, bukan sekadar ada di kode tapi tidak pernah dipanggil (dead code, cabang kondisi yang tidak pernah terpenuhi).
2. **Menangkap kasus yang luput dari analisis statis** — terutama relevan untuk test ini karena celah spesifik yang sudah diidentifikasi di dokumen MASTG-TEST-0247 §3.2: rule semgrep resmi untuk versi statisnya (`mastg-android-device-passcode-present.yml`) memiliki cakupan sempit (bergantung pada pola literal string `"keyguard"`, tidak mencakup `isKeyguardSecure()`, hanya menyasar bahasa Java). Pemanggilan API yang dibangun secara **dinamis** (lewat reflection, string yang dirakit saat runtime, atau kode yang sengaja di-obfuscate untuk menghindari deteksi pola statis) akan **selalu luput** dari pendekatan statis manapun, namun **tetap akan terekam** oleh hooking runtime karena instrumentasi menempel langsung pada pemanggilan method itu sendiri, terlepas dari bagaimana argumen/pemanggilnya dibangun di kode.

### 1.3 Mengapa "Exercise the App Extensively" adalah Instruksi yang Sangat Relevan di Sini

Langkah resmi ketiga menekankan:

> *"Exercise the app extensively to trigger as many flows as possible and enter sensitive data wherever you can."*

Ini instruksi umum yang muncul di banyak test dinamis, tapi punya relevansi khusus untuk test ini mengingat konteks §1.3 dokumen MASTG-TEST-0247: pengecekan secure lock screen **paling mungkin dipanggil tepat sebelum operasi sensitif** — seperti membuka dompet kripto, mengonfirmasi transaksi finansial, atau mengakses data terenkripsi yang kuncinya dilindungi `setUserAuthenticationRequired`. Bila penguji hanya membuka aplikasi dan menjelajahi halaman utama tanpa benar-benar **memicu alur sensitif tersebut** (login, konfirmasi pembayaran, akses ke brankas data), hook yang dipasang **tidak akan pernah terpicu** — bukan karena aplikasi tidak memiliki pengecekan tersebut, melainkan karena jalur kode yang memuatnya tidak pernah dieksekusi selama sesi pengujian. Ini pengingat penting bahwa **hasil kosong dari test dinamis ini punya ambiguitas** yang sama seperti pola berulang di seluruh seri riset dokumen ini (bandingkan dengan catatan serupa di dokumen MASTG-TEST-0238 §1.3 tentang cakupan instrumentasi).

### 1.4 Kelengkapan Instrumentasi: Pastikan Mencakup Kedua Jalur API

Sesuai dokumen MASTG-TEST-0247 §1.5, ada dua jalur API yang saling melengkapi (bukan duplikat) — `KeyguardManager` dan `BiometricManager` — karena beberapa vendor device membatasi/memodifikasi perilaku salah satunya. Instrumentasi hooking untuk test dinamis ini **wajib mencakup kedua jalur sekaligus varian metodenya** (`isDeviceSecure()` **dan** `isKeyguardSecure()`) agar tidak mewarisi celah cakupan yang sama seperti rule statis resminya.

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | Fungsi |
|---|---|
| **Frida** | Instrumentasi dinamis inti — hooking API deteksi secure lock dan pengambilan stack trace |
| **frida-tools** (`frida-trace`) | Cara cepat melakukan tracing tanpa menulis skrip kustom |
| **objection** | Wrapper Frida siap pakai untuk hooking cepat tanpa scripting |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **Xposed / LSPosed** | Alternatif hooking berbasis modul sistem, sesuai contoh metodologi di MASTG-TECH-0043 — cocok untuk skenario yang membutuhkan hook persisten di seluruh sesi tanpa perlu re-attach berulang |
| **adb logcat** | Baseline sederhana — beberapa implementasi mencatat log saat pengecekan status keamanan device dilakukan (tergantung level verbosity aplikasi) |
| **Emulator/device dengan kondisi lock screen bervariasi** | Menjalankan aplikasi pada kondisi device **dengan** dan **tanpa** secure lock untuk membandingkan perilaku nyata, melengkapi hasil hooking semata |

### 2.3 Prasyarat Lingkungan

- **Wajib device/emulator dengan Frida server terpasang** — test ini murni dinamis.
- **Root atau frida-gadget** untuk aplikasi non-debuggable pada perangkat non-root.
- **Siapkan skenario uji yang mencakup alur sensitif aplikasi** (login, akses data terenkripsi, konfirmasi transaksi) sesuai §1.3 — bukan sekadar navigasi permukaan.
- **Idealnya jalankan dua sesi berbeda**: satu dengan device memiliki secure lock aktif, satu tanpa — untuk mengamati apakah perilaku aplikasi benar-benar berbeda sesuai hasil pengecekan (menjawab pertanyaan yang sama seperti Metode D di dokumen MASTG-TEST-0247, tapi kini terintegrasi sebagai bagian inti metodologi test dinamis ini).

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0005** untuk menginstal aplikasi.
2. Gunakan **MASTG-TECH-0043** untuk melakukan hooking pada pemanggilan API yang relevan.
3. Jelajahi aplikasi secara menyeluruh untuk memicu sebanyak mungkin alur, dan masukkan data sensitif di mana pun memungkinkan.

### 3.2 Metode A — Skrip Frida Meng-hook Kedua Jalur API Sekaligus *(metode utama)*

```javascript
// hook-secure-lock-detection.js
Java.perform(function () {
    function getBacktrace() {
        return Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());
    }

    // 1. KeyguardManager.isDeviceSecure()
    try {
        var KeyguardManager = Java.use("android.app.KeyguardManager");
        KeyguardManager.isDeviceSecure.overload().implementation = function () {
            var result = this.isDeviceSecure();
            console.log("\n[*] KeyguardManager.isDeviceSecure() dipanggil -> " + result);
            console.log("    Stack:\n" + getBacktrace());
            return result;
        };
    } catch (e) { console.log("[x] isDeviceSecure hook gagal: " + e); }

    // 2. KeyguardManager.isKeyguardSecure() — celah cakupan rule statis resmi, JANGAN dilewatkan
    try {
        var KeyguardManager2 = Java.use("android.app.KeyguardManager");
        KeyguardManager2.isKeyguardSecure.overload().implementation = function () {
            var result = this.isKeyguardSecure();
            console.log("\n[*] KeyguardManager.isKeyguardSecure() dipanggil -> " + result);
            console.log("    Stack:\n" + getBacktrace());
            return result;
        };
    } catch (e) { console.log("[x] isKeyguardSecure hook gagal: " + e); }

    // 3. BiometricManager.canAuthenticate() — framework API
    try {
        var BiometricManager = Java.use("android.hardware.biometrics.BiometricManager");
        BiometricManager.canAuthenticate.overload("int").implementation = function (authenticators) {
            var result = this.canAuthenticate(authenticators);
            console.log("\n[*] BiometricManager.canAuthenticate(" + authenticators + ") dipanggil -> " + result);
            console.log("    Stack:\n" + getBacktrace());
            return result;
        };
    } catch (e) { console.log("[x] BiometricManager (framework) hook gagal: " + e); }

    // 4. androidx.biometric.BiometricManager — Jetpack, lebih umum dipakai aplikasi modern
    try {
        var BiometricManagerX = Java.use("androidx.biometric.BiometricManager");
        BiometricManagerX.canAuthenticate.overload("int").implementation = function (authenticators) {
            var result = this.canAuthenticate(authenticators);
            console.log("\n[*] androidx.biometric.BiometricManager.canAuthenticate(" + authenticators + ") -> " + result);
            console.log("    Stack:\n" + getBacktrace());
            return result;
        };
    } catch (e) { console.log("[x] AndroidX BiometricManager hook gagal: " + e); }
});
```

```bash
frida -U -f com.target.app -l hook-secure-lock-detection.js --no-pause
# Jelajahi aplikasi menyeluruh, terutama alur login/akses data sensitif/konfirmasi transaksi
```

### 3.3 Metode B — objection (Tanpa Menulis Skrip Kustom)

```bash
objection -g com.target.app explore
# Di dalam console objection:
android hooking watch class_method android.app.KeyguardManager.isDeviceSecure --dump-backtrace
android hooking watch class_method android.app.KeyguardManager.isKeyguardSecure --dump-backtrace
android hooking watch class_method androidx.biometric.BiometricManager.canAuthenticate --dump-args --dump-backtrace
```

### 3.4 Metode C — frida-trace (Tracing Cepat)

```bash
frida-trace -U -f com.target.app -m "android.app.KeyguardManager!is*Secure*" -m "*BiometricManager!canAuthenticate"
```

`frida-trace` secara otomatis membuat *stub* untuk seluruh method yang cocok dengan pola wildcard, memberi gambaran cepat tanpa perlu menulis hook detail untuk setiap variasi API.

### 3.5 Metode D — Xposed/LSPosed (Alternatif Hooking Persisten)

```java
// Contoh modul Xposed sesuai pola MASTG-TECH-0043
XposedHelpers.findAndHookMethod(
    "android.app.KeyguardManager", lpparam.classLoader, "isDeviceSecure",
    new XC_MethodHook() {
        @Override
        protected void afterHookedMethod(MethodHookParam param) {
            XposedBridge.log("[*] isDeviceSecure() dipanggil, hasil: " + param.getResult());
        }
    }
);
```

Berguna sebagai pendekatan alternatif ketika Frida terdeteksi/diblokir oleh mekanisme anti-tampering aplikasi target (lihat pembahasan deteksi Frida di dokumen-dokumen MASVS-RESILIENCE lain dalam seri ini).

### 3.6 Metode E — Uji Perbandingan Kondisi Device (Melengkapi Hasil Hooking)

```bash
# Sesi 1: device DENGAN secure lock aktif
adb shell locksettings set-pin 1234
frida -U -f com.target.app -l hook-secure-lock-detection.js --no-pause
# Jelajahi alur sensitif, catat hasil hook dan perilaku aplikasi

# Sesi 2: device TANPA secure lock
adb shell locksettings clear --old 1234
frida -U -f com.target.app -l hook-secure-lock-detection.js --no-pause
# Jelajahi alur yang sama, bandingkan: apakah aplikasi bereaksi berbeda?
```

Perbandingan dua sesi ini menjawab pertanyaan yang lebih bernilai secara keamanan dibanding sekadar "apakah API dipanggil": **apakah hasil pengecekan tersebut benar-benar memengaruhi perilaku aplikasi** di kedua kondisi, sesuai semangat evaluasi yang sama seperti dibahas di dokumen MASTG-TEST-0247 §3.4 (CodeQL untuk menilai korelasi secara statis) — di sini dikonfirmasi secara empiris lewat perilaku runtime nyata.

### 3.7 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Kelebihan | Kapan dipakai |
|---|---|---|---|
| **A** | Skrip Frida kustom | Kontrol penuh, mencakup 4 varian API sekaligus | Baseline utama |
| **B** | objection | Cepat, tanpa scripting | Eksplorasi awal cepat |
| **C** | frida-trace | Tracing otomatis lewat wildcard | Overview cepat sebelum hooking detail |
| **D** | Xposed/LSPosed | Tahan terhadap deteksi Frida tertentu | Aplikasi dengan anti-Frida aktif |
| **E** | Perbandingan dua kondisi device | Menjawab efek nyata pada perilaku aplikasi | **Wajib** untuk kesimpulan yang bermakna, bukan sekadar "API dipanggil" |

**Kombinasi minimum yang aku rekomendasikan:** **A (hooking komprehensif 4 varian API) → interaksi menyeluruh sesuai §1.3 → E (uji perbandingan dua kondisi device)** untuk kesimpulan yang benar-benar menjawab nilai keamanan dari pengecekan yang ditemukan, bukan sekadar mencatat keberadaannya.

---

### 3.8 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG:**

> **Observation:** *"The output should contain a list of locations where relevant APIs are used."*
>
> **Evaluation:** *"The test case fails if an app doesn't use any API to verify the secure screen lock presence."*

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi |
|---|---|
| F1 | Seluruh hook (empat varian API, §3.2) **tidak pernah terpicu** selama sesi pengujian menyeluruh yang mencakup alur sensitif aplikasi |
| F2 | Hook terpicu, tapi Metode E menunjukkan **tidak ada perbedaan perilaku** aplikasi antara kondisi device dengan dan tanpa secure lock — mengindikasikan hasil pengecekan tidak benar-benar dipakai untuk mengambil keputusan keamanan |
| F3 | Interaksi menyeluruh sudah dilakukan (termasuk alur sensitif) namun API secure lock detection tetap tidak pernah terpanggil, sementara aplikasi diketahui memakai kunci `setUserAuthenticationRequired` (dikonfirmasi lewat dokumen MASTG-TEST-0247 atau pengujian kriptografi terkait) |

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi |
|---|---|
| P1 | Salah satu/lebih dari empat varian API terpicu selama interaksi menyeluruh dengan aplikasi |
| P2 | Metode E mengonfirmasi aplikasi **bereaksi berbeda** secara nyata antara kondisi device dengan dan tanpa secure lock (mis. menampilkan peringatan, membatasi fitur) |
| P3 | Stack trace hasil hook menunjukkan pemanggilan terjadi di lokasi yang relevan secara keamanan (mis. sebelum akses ke fitur finansial/data sensitif), bukan di kode yang tidak berpengaruh pada alur keamanan |

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Hasil kosong bisa berarti dua hal berbeda — jangan simpulkan tergesa.** Sesuai §1.3, tidak terpicunya hook bisa berarti (a) aplikasi memang tidak memiliki pengecekan ini sama sekali (FAIL sesungguhnya), atau (b) jalur kode yang memuatnya tidak pernah dieksekusi karena interaksi pengujian kurang menyeluruh (false negative metodologis). Selalu pastikan skenario uji mencakup alur sensitif sebelum menyimpulkan FAIL.

2. **Sekadar "API terpicu" tidak cukup — buktikan itu berefek nyata (Metode E).** Ini pelajaran yang sama berulang di berbagai test dinamis dalam seri riset ini: keberadaan pemanggilan API tidak otomatis berarti hasilnya dipakai untuk mengambil keputusan keamanan yang berarti. Test ini secara eksplisit lebih bernilai ketika dilengkapi bukti perbandingan perilaku nyata.

3. **Korelasikan selalu dengan MASTG-TEST-0247.** Kedua test ini idealnya dilaporkan bersamaan — hasil statis memberi peta lokasi kode yang menjadi kandidat, hasil dinamis mengonfirmasi mana yang benar-benar tereksekusi dan berefek nyata.

4. **Manfaatkan celah cakupan yang sudah diidentifikasi di versi statisnya.** Karena rule semgrep resmi MASTG-TEST-0247 memiliki celah (`isKeyguardSecure()` tidak tercakup, dependensi pada literal string), pendekatan dinamis di sini menjadi **jaring pengaman** yang sangat relevan — pastikan instrumentasi hooking benar-benar mencakup seluruh varian API (§1.4) agar celah yang sama tidak ikut terwarisi ke hasil pengujian dinamis.

5. **Severity mengikuti pola yang sama seperti dokumen MASTG-TEST-0247** — modulasi berdasarkan apakah aplikasi memakai kunci kriptografi yang bergantung pada status lock screen (`setUserAuthenticationRequired`), dan seberapa sensitif data/fitur yang terpengaruh.

6. **Dokumentasikan:** API mana yang terpicu (dari 4 varian), stack trace lokasi pemicunya, hasil perbandingan Metode E (perilaku dengan vs tanpa secure lock), dan cakupan interaksi aplikasi yang sudah dilakukan (untuk transparansi keterbatasan hasil "tidak ditemukan").

---

## 4. Rekomendasi Perbaikan

Karena akar masalah dan solusi teknisnya identik dengan MASTG-TEST-0247 (weakness yang sama, MASWE-0017), rujuk **dokumen MASTG-TEST-0247 §4** untuk rekomendasi implementasi lengkap (pengecekan berlapis dengan fallback, penolakan fitur sensitif tanpa secure lock, korelasi dengan `setUserAuthenticationRequired`).

Tambahan spesifik dari sudut pandang dinamis:

### 4.1 Integrasikan Hooking ke Regression Test Otomatis

```bash
#!/bin/bash
# ci-dynamic-secure-lock-check.sh — jalankan sebagai bagian smoke test otomatis
frida -U -f com.target.app -l hook-secure-lock-detection.js --no-pause &
FRIDA_PID=$!
sleep 5
./run-ui-test-suite.sh --scenario=login,payment,vault-access
kill $FRIDA_PID
```

### 4.2 Uji Kedua Kondisi Device sebagai Bagian dari QA Rutin

Jadikan Metode E (perbandingan device dengan/tanpa secure lock) sebagai bagian standar dari siklus QA untuk fitur apa pun yang memakai kunci kriptografi terproteksi otentikasi — bukan hanya dilakukan sekali saat audit keamanan.

### 4.3 Checklist Remediasi

- [ ] Instrumentasi hooking mencakup keempat varian API (`isDeviceSecure`, `isKeyguardSecure`, `BiometricManager` framework dan Jetpack)
- [ ] Interaksi pengujian sudah mencakup seluruh alur sensitif aplikasi (login, akses data terenkripsi, transaksi)
- [ ] Perbandingan perilaku aplikasi pada device dengan vs tanpa secure lock sudah dilakukan dan didokumentasikan
- [ ] Hasil dikorelasikan dengan temuan MASTG-TEST-0247 (statis)
- [ ] **Verifikasi ulang:** jalankan kembali MASTG-TEST-0249 setelah perubahan pada alur autentikasi/kriptografi

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0249: Runtime Use of Secure Screen Lock Detection APIs](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0249/)
- [MASTG-TEST-0247: References to APIs for Detecting Secure Screen Lock](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0247/)
- [MASWE-0017: Device Secure Lock Not Enforced](https://mas.owasp.org/MASWE/MASVS-CRYPTO/MASWE-0017/)
- [MASTG-TECH-0005: Installing Apps](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0005/)
- [MASTG-TECH-0043: Method Hooking](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0043/)

### 5.2 Dokumentasi Resmi Android

- [Android Developers — `KeyguardManager` API reference](https://developer.android.com/reference/android/app/KeyguardManager)
- [Android Developers — `BiometricManager#canAuthenticate(int)`](https://developer.android.com/reference/android/hardware/biometrics/BiometricManager#canAuthenticate(int))
- [Android Developers — androidx.biometric library](https://developer.android.com/jetpack/androidx/releases/biometric)

### 5.3 Dokumentasi Tools

- [Frida — Dynamic instrumentation toolkit](https://frida.re/docs/javascript-api/)
- [frida-trace — Documentation](https://frida.re/docs/frida-trace/)
- [Objection — Runtime Mobile Exploration toolkit](https://github.com/sensepost/objection)
- [LSPosed Framework](https://github.com/LSPosed/LSPosed)

---

*Dokumen ini disusun berdasarkan OWASP MASTG (rilis terkini per September 2026) dan dokumentasi resmi Android Developers. Sebagai counterpart dinamis langsung dari MASTG-TEST-0247, konteks konseptual mendalam (koneksi dengan Android Keystore `setUserAuthenticationRequired`, batasan aplikasi tidak dapat memaksa pengaturan sistem) dibahas lengkap di dokumen tersebut. Nilai unik test ini adalah kemampuannya menangkap pemanggilan API yang dibangun secara dinamis/di-obfuscate yang luput dari analisis statis, serta memberi bukti empiris — lewat perbandingan perilaku aplikasi pada device dengan dan tanpa secure lock — bahwa pengecekan yang ditemukan benar-benar berefek nyata pada keputusan keamanan aplikasi, bukan sekadar dipanggil tanpa konsekuensi.*
