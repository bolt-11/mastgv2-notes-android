# MASTG-TEST-0341 Runtime Use of Hook Detection Techniques

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0341 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-RESILIENCE |
| **Weakness** | MASWE-0058 |
| **Tipe Pengujian** | Dynamic, Hooks |
| **Teknik terkait** | MASTG-TECH-0005 (Installing Apps), MASTG-TECH-0043 (Method Hooking) |
| **Knowledge terkait** | MASTG-KNOW-0030 (Reverse Engineering Tool Detection), MASTG-KNOW-0032 (Runtime Integrity Verification), MASTG-KNOW-0118 |
| **Best Practice terkait** | MASTG-BEST-0041 (Hardening Against Runtime Hooking) |
| **Test terkait** | MASTG-TEST-0324/0325 (root detection) — kontrol pencegahan pelengkap, namun hooking tetap mungkin terjadi di device non-rooted (§1.5) |
| **Rule resmi** | — (tidak ada; test murni dinamis, konsisten dengan sifat test lain yang menyasar respons runtime, bukan pola kode statis) |

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian

Kutipan overview resmi MASTG:

> *"This test verifies whether the app detects and responds to instrumentation and hooking attempts at runtime."*

Test ini adalah jantung dari kategori MASVS-RESILIENCE — ia tidak menyasar satu kerentanan kode spesifik, melainkan menguji apakah **lapisan pertahanan terakhir** aplikasi berfungsi: ketika seorang penyerang/penguji berhasil memasang hook pada fungsi sensitif (via Frida, Xposed, dsb.), apakah aplikasi **menyadari** hal itu dan **merespons** secara defensif, atau tetap berjalan normal seolah tidak terjadi apa-apa.

### 1.2 Tujuh Kategori Fungsi Sensitif sebagai Target Hook Beserta Dampaknya

Overview memberi daftar konkret API yang, bila berhasil di-hook tanpa terdeteksi, membuka jalan ke eksfiltrasi data sangat sensitif:

| API yang Di-hook | Data yang Terekspos |
|---|---|
| `AccountManager.getPassword()` / `getAuthToken()` | Token OAuth, kredensial sesi, password akun tersimpan |
| `KeyStore.getKey()` / `getCertificate()` | Kunci kriptografis dan sertifikat |
| `Cipher.doFinal()` | Kunci sesi/ephemeral yang sedang diproses |
| `SQLiteDatabase.rawQuery()` / `query()` / `execSQL()` | Isi database lokal |
| `EncryptedSharedPreferences` APIs | Data yang seharusnya terenkripsi |
| `KeyGenParameterSpec.Builder.setUserAuthenticationRequired()` | Bypass autentikasi — menghubungkan langsung ke risiko yang dibahas di TEST-0327 |

Catatan penting yang diberikan overview secara eksplisit: *"This list is just indicative, and each app may have its own defensive response mechanisms."* — daftar ini bukan daftar tertutup; API sensitif apa pun yang spesifik bagi logika bisnis aplikasi target layak dijadikan titik uji tambahan.

### 1.3 Mekanisme Evaluasi yang Unik: Hasil Pengujian Diukur dari Kegagalan Hook, Bukan Keberhasilannya

Ini adalah salah satu test dengan logika evaluasi paling tidak lazim dalam seluruh seri riset ini — alih-alih penguji mencoba **mengonfirmasi** sesuatu bekerja, penguji di sini secara aktif **mencoba menyerang** aplikasi, dan **kegagalan serangan tersebut** adalah tanda PASS:

> **Evaluation:** *"The test case fails if the hook executes successfully and returns the expected data, indicating the app lacks runtime integrity verification. The test case passes if the hooking attempt fails due to the app's defensive response (e.g., session terminates unexpectedly, hook callbacks never execute, or the process exits)."*

Ini membalik intuisi umum "hasil error = bug" — dalam konteks test ini, **crash/exit yang dipicu secara sengaja oleh mekanisme pertahanan aplikasi sendiri justru adalah hasil yang diinginkan**. Penguji perlu membedakan dengan jelas antara dua jenis "kegagalan hook": (a) kegagalan karena **bug di script Frida milik penguji sendiri**, versus (b) kegagalan karena **respons defensif yang sengaja dipicu aplikasi**. Observasi resmi (§ Observation) membantu membedakan ini dengan meminta pencatatan detail sinyal kegagalan — pesan error spesifik, waktu terjadinya relatif terhadap pemanggilan hook, dan konsistensi perilaku lintas percobaan berulang.

### 1.4 Pengakuan Jujur: PASS Hari Ini Bukan Garansi Permanen

Catatan penutup resmi memberi peringatan penting tentang interpretasi hasil PASS:

> *"Even if the test case passes, it might still be possible to bypass the app's defensive response."*

Ini konsisten dengan prinsip yang ditegaskan berulang kali di MASTG-KNOW-0032:

> *"Runtime integrity verification is inherently a cat-and-mouse game. Detection methods and bypass defensive controls evolve continuously. Determined attackers with sufficient time and resources can typically circumvent these protections, especially on rooted devices."*

Implikasi praktis: laporan hasil test ini **tidak boleh** menyatakan "aplikasi tahan hooking secara permanen" — hanya dapat menyatakan "mekanisme pertahanan berhasil menggagalkan teknik hooking spesifik yang diuji pada tanggal pengujian tertentu, dengan versi tool tertentu".

### 1.5 Dua Kategori Deteksi yang Saling Melengkapi, Bukan Saling Menggantikan

MASTG-KNOW-0030 dan MASTG-KNOW-0032 secara eksplisit membedakan dua pendekatan yang berbeda secara fundamental:

> *"Some tools can be detected both by their artifacts and by the modifications they make to the runtime. [MASTG-KNOW-0030] focuses on identifying the presence of known tools, while MASTG-KNOW-0032 focuses on identifying unauthorized runtime modification."*

| Kategori | Yang Dideteksi | Contoh Teknik | Kelemahan Utama |
|---|---|---|---|
| **Artifact-based** (KNOW-0030) | Keberadaan tool (proses, file, port, string) | Cek `/proc/self/maps` untuk `frida-agent`, cek sertifikat signing APK | Rapuh — nama file/proses mudah diganti penyerang |
| **Integrity-based** (KNOW-0032) | Modifikasi yang ditimbulkan tool pada memori/kode | Verifikasi PLT/GOT, vtable, ART method entry point | Lebih kuat, namun implementasi kompleks dan spesifik-versi Android |

MASTG-BEST-0041 menegaskan **keduanya wajib dikombinasikan**: *"Do not rely on only one approach, as each has blind spots the other covers."* Ini relevan langsung untuk desain test: penguji sebaiknya mencoba **kedua jenis** teknik hooking (langsung via Frida default vs melalui Frida Gadget yang di-embed/disembunyikan) untuk menilai cakupan pertahanan aplikasi secara menyeluruh, bukan hanya satu skenario.

### 1.6 Nuansa Penting: Hooking Tidak Memerlukan Root — Ancaman Berlaku Juga di Device Non-Rooted

Poin krusial dari MASTG-BEST-0041 yang relevan untuk konteks ancaman menyeluruh:

> *"Because hooking can also occur on non-rooted devices (e.g., by repackaging the app with an embedded frida-gadget), do not rely solely on preventive controls."*

Ini berarti **root detection (TEST-0324/0325) tidak cukup** sebagai satu-satunya lini pertahanan terhadap hooking — seorang penyerang dapat mengekstrak APK, menyuntikkan `libfrida-gadget.so`, menandatangani ulang APK, lalu memasangnya di device non-rooted mana pun, sepenuhnya melewati kebutuhan root. Inilah alasan mengapa MASTG-BEST-0041 mengelompokkan kontrol menjadi empat kategori (preventive, detective, deterrent, responsive) alih-alih hanya mengandalkan preventive (root detection) sendirian.

### 1.7 Teknik Deterrent yang Canggih: Inlining dan Randomisasi Penempatan Check

Dua teknik pertahanan yang jarang dibahas di test lain namun diberikan secara mendalam di MASTG-BEST-0041 layak dicatat sebagai standar kualitas tinggi untuk evaluasi:

> *"A named function has a fixed entry point that hooking frameworks can intercept with a single hook. When detection logic is inlined directly into the surrounding application code, there is no entry point to target — the check becomes an inseparable part of the surrounding control flow."*

> *"Randomize check placement at build time forces attackers to do fresh analysis for every release, significantly increasing the cost of maintaining automated bypass tools."*

Kedua teknik ini menjelaskan mengapa beberapa aplikasi tahan lama terhadap bypass generik yang dipublikasikan komunitas — tanpa titik masuk fungsi yang bisa di-hook sekali untuk semua kasus, dan dengan penempatan yang berubah di setiap rilis, script bypass yang bekerja di versi N tidak lagi otomatis bekerja di versi N+1.

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | Fungsi |
|---|---|
| **Frida** | Hooking tujuh API sensitif (MASTG-TECH-0043) untuk memicu dan mengamati respons defensif aplikasi |
| **ADB** | Instalasi app (MASTG-TECH-0005) |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **Frida Gadget + apktool** | Mereplikasi skenario hooking **non-rooted** (§1.6) — menyuntikkan `libfrida-gadget.so` ke APK, menandatangani ulang, instal di device biasa |
| **Objection** | Hooking cepat tanpa script kustom untuk eksplorasi awal API mana yang terproteksi |
| **Xposed/LSPosed** | Menguji ketahanan terhadap kategori hooking framework berbeda dari Frida, melengkapi cakupan jenis instrumentasi yang diuji |
| **strace** | Mengamati perilaku proses di level sistem untuk mengonfirmasi jenis respons defensif (exit paksa, SIGKILL, dsb.) |

### 2.3 Prasyarat Lingkungan

- Device rooted/emulator dengan `frida-server` untuk skenario hooking standar.
- Device non-rooted tambahan untuk skenario Frida Gadget embedded (§1.6) — memberi cakupan pengujian yang MASTG-BEST-0041 secara eksplisit tekankan pentingnya.

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0005** untuk instalasi aplikasi.
2. Gunakan **MASTG-TECH-0043** untuk hook API yang relevan.
3. Exercise aplikasi secara ekstensif untuk memicu sebanyak mungkin alur, masukkan data sensitif di mana pun memungkinkan.

### 3.2 Metode A — Frida: Hook Tujuh Kategori API Resmi

```javascript
Java.perform(function () {
    var AccountManager = Java.use("android.accounts.AccountManager");
    AccountManager.getPassword.implementation = function (account) {
        console.log("[HOOK TEST] AccountManager.getPassword() dipanggil, hook BERHASIL");
        return this.getPassword(account);
    };

    var KeyStore = Java.use("java.security.KeyStore");
    KeyStore.getKey.implementation = function (alias, password) {
        console.log("[HOOK TEST] KeyStore.getKey() dipanggil, hook BERHASIL");
        return this.getKey(alias, password);
    };

    var Cipher = Java.use("javax.crypto.Cipher");
    Cipher.doFinal.overload().implementation = function () {
        console.log("[HOOK TEST] Cipher.doFinal() dipanggil, hook BERHASIL");
        return this.doFinal();
    };
});
```

```bash
frida -U -f com.example.targetapp -l hook_test.js --no-pause
```

Amati: apakah pesan "[HOOK TEST]... hook BERHASIL" muncul di konsol (mengindikasikan FAIL), atau sesi berhenti/app keluar sebelum hook sempat terpicu (mengindikasikan PASS)?

### 3.3 Metode B — Replikasi Skenario Non-Rooted dengan Frida Gadget

```bash
# Ekstrak APK, suntikkan libfrida-gadget.so
apktool d target.apk -o target_decoded
cp libfrida-gadget-arm64.so target_decoded/lib/arm64-v8a/
# tambahkan System.loadLibrary("frida-gadget") di smali entry point
apktool b target_decoded -o target_patched.apk
apksigner sign --ks debug.keystore target_patched.apk

# Instal di device NON-ROOTED
adb install target_patched.apk
```

Jalankan aplikasi dan amati apakah mekanisme pertahanan tetap terpicu meski device tidak rooted — sesuai penekanan §1.6 bahwa preventive control (root detection) saja tidak cukup.

### 3.4 Metode C — Objection untuk Eksplorasi Cepat

```bash
objection -g com.example.targetapp explore
# di dalam REPL, coba watch berbagai method sensitif
android hooking watch class_method android.accounts.AccountManager.getPassword --dump-args
```

### 3.5 Metode D — strace untuk Mengonfirmasi Jenis Respons Defensif

```bash
adb shell strace -f -p $(adb shell pidof com.example.targetapp) 2>&1 | grep -E 'exit_group|SIGKILL'
```

Membedakan apakah "kegagalan hook" benar-benar disebabkan exit paksa oleh aplikasi sendiri, atau hanya script Frida penguji yang gagal terhubung (confounding factor penting, §1.3).

### 3.6 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Kapan dipakai |
|---|---|---|
| **A** | Frida standar | Baseline wajib — menguji tujuh kategori API resmi di device rooted |
| **B** | Frida Gadget embedded | Wajib untuk cakupan menyeluruh — menguji skenario non-rooted (§1.6) |
| **C** | Objection | Eksplorasi cepat sebelum menulis script kustom |
| **D** | strace | Memastikan jenis kegagalan adalah respons defensif sungguhan, bukan error script penguji |

**Kombinasi minimum yang aku rekomendasikan:** **A (wajib, device rooted) + B (wajib, device non-rooted)** — menguji hanya salah satu dari dua skenario ini memberi gambaran yang tidak lengkap mengingat penekanan eksplisit MASTG-BEST-0041 bahwa keduanya adalah ancaman yang berbeda.

---

### 3.7 Kriteria Evaluasi: Positive Case & Negative Case

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi |
|---|---|
| F1 | Hook pada API sensitif **berhasil dieksekusi** dan mengembalikan data yang diharapkan (callback data, argumen, return value) tanpa terganggu |

**Contoh bukti:**

```
[HOOK TEST] AccountManager.getPassword() dipanggil, hook BERHASIL
Return value: "s3cr3tP@ssw0rd"
```

Interpretasi: hook pada `getPassword()` berjalan sempurna, password akun berhasil diekstrak tanpa ada respons defensif apa pun dari aplikasi. **FAIL**.

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi |
|---|---|
| P1 | Sesi/proses aplikasi berhenti tidak terduga segera setelah hook dipasang/dipicu |
| P2 | Callback hook tidak pernah tereksekusi sama sekali |
| P3 | Aplikasi keluar (exit) sebagai respons langsung terhadap upaya hooking |

**Contoh bukti:**

```
$ frida -U -f com.example.targetapp -l hook_test.js --no-pause
[*] Spawned `com.example.targetapp`
Process terminated
```

**PASS** — namun **wajib** diberi catatan pembatas sesuai §1.4 (tidak permanen, teknik lain mungkin masih berhasil).

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Bedakan dengan hati-hati antara respons defensif sungguhan vs error script penguji sendiri** — sebelum menyimpulkan PASS, verifikasi ulang script Frida bekerja normal terhadap aplikasi kontrol (mis. aplikasi contoh tanpa proteksi) untuk memastikan kegagalan memang berasal dari mekanisme pertahanan target, bukan bug di tooling penguji.

2. **Selalu uji kedua skenario root dan non-root (§1.6)** — PASS yang hanya diuji di device rooted (hooking standar) tidak memberi informasi tentang ketahanan terhadap skenario Frida Gadget embedded yang tidak memerlukan root sama sekali.

3. **PASS tidak pernah permanen** — selalu cantumkan tanggal pengujian, versi aplikasi, versi Frida/tool yang dipakai, dan pernyataan eksplisit bahwa hasil ini bisa berubah dengan teknik bypass yang lebih canggih di masa depan (§1.4).

4. **Nilai juga kualitas respons, bukan hanya keberadaannya** — sesuai MASTG-BEST-0041, respons yang **hanya** terjadi di satu titik terpusat lebih mudah dibypass (sekali ditemukan, sekali dinetralkan) dibanding respons yang tersebar di banyak titik dan diulang sebelum setiap operasi sensitif (§1.7); bila memungkinkan, uji apakah bypass satu instance check cukup untuk melewati seluruh alur, atau apakah check berulang di titik lain tetap menghalangi.

5. **Severity dimodulasi:**

   | Faktor | Severity |
   |---|---|
   | Hook pada API kredensial/kunci kriptografis berhasil tanpa respons apa pun | **Tinggi** |
   | Respons defensif ada namun hanya di satu titik terpusat (mudah dibypass sekali ditemukan) | **Sedang** |
   | Respons defensif tersebar, diuji tahan di kedua skenario root dan non-root | **Bukan temuan** (dengan catatan pembatas §1.4) |

6. **Dokumentasikan:** API yang diuji, hasil tiap percobaan hook (berhasil/gagal beserta detail sinyal kegagalan), skenario device (rooted/non-rooted), dan versi tool yang dipakai untuk reproduktifitas laporan.

---

## 4. Rekomendasi Perbaikan

### 4.1 Terapkan Deteksi Berlapis (Artifact + Integrity-Based)

Jangan hanya mengandalkan satu jenis deteksi — kombinasikan pengecekan artefak (`/proc/self/maps` untuk string `frida`) dengan verifikasi integritas runtime (PLT/GOT, ART entry point) sesuai MASTG-BEST-0041.

### 4.2 Implementasikan Logika Deteksi di Native Code, Inline, dan Acak Posisinya

```cpp
// Native C/C++, inline di setiap call site, BUKAN function terpisah yang bisa di-hook sekali
__attribute__((always_inline)) static inline bool quickIntegrityCheck() {
    // verifikasi PLT/GOT secara ringan langsung di tempat
}
```

### 4.3 Respons Berlapis dan Terdistribusi

Ulangi check sebelum setiap operasi sensitif (transfer dana, unlock fitur premium), bukan hanya sekali saat startup — sesuai prinsip "Repeat Checks Before Sensitive Operations" MASTG-BEST-0041.

### 4.4 Checklist Remediasi

- [ ] Ketujuh kategori API sensitif memiliki mekanisme deteksi hooking yang teruji tahan
- [ ] Deteksi dikombinasikan artifact-based DAN integrity-based
- [ ] Logika deteksi diimplementasikan di native code, inline, bukan function terpisah
- [ ] Check diulang di banyak titik sebelum operasi sensitif, bukan terpusat satu tempat
- [ ] Diuji tahan di SKENARIO ROOT DAN NON-ROOT (Frida Gadget embedded)
- [ ] Respons mencakup terminasi sesi, pembersihan data sensitif dari memori, dan notifikasi ke backend

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0341 (source, tests-beta)](https://github.com/OWASP/mastg/blob/master/tests-beta/android/MASVS-RESILIENCE/MASTG-TEST-0341.md)
- [MASTG-KNOW-0030: Reverse Engineering Tool Detection](https://mas.owasp.org/MASTG/knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0030/)
- [MASTG-KNOW-0032: Runtime Integrity Verification](https://mas.owasp.org/MASTG/knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0032/)
- [MASTG-BEST-0041: Hardening Against Runtime Hooking](https://github.com/OWASP/mastg/blob/master/best-practices/MASTG-BEST-0041.md)
- [MASTG-TEST-0324/0325: Root Detection (dokumen terkait dalam seri riset ini)](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0324/)

### 5.2 Riset dan Referensi Teknis

- [Bernhard Mueller: The Jiu-Jitsu of Detecting Frida](https://web.archive.org/web/20181227120751/http://www.vantagepoint.sg/blog/90-the-jiu-jitsu-of-detecting-frida)
- [Tan, 2016 — Black Hat: Attacking BYOD Enterprise Mobile Security Solutions](https://www.blackhat.com/docs/us-16/materials/us-16-Tan-Bad-For-Enterprise-Attacking-BYOD-Enterprise-Mobile-Security-Solutions-wp.pdf)
- [Clang Control Flow Integrity Documentation](https://clang.llvm.org/docs/ControlFlowIntegrity.html)

### 5.3 Dokumentasi Tools

- [Frida — Dynamic Instrumentation Toolkit](https://frida.re/docs/home/)
- [Frida Gadget Documentation](https://www.frida.re/docs/gadget/)
- [Objection — Runtime Mobile Exploration](https://github.com/sensepost/objection)
- [xHook — Android PLT Hook Library](https://github.com/iqiyi/xHook)

---

*Dokumen ini disusun berdasarkan konten resmi OWASP MASTG (`tests-beta/android/MASVS-RESILIENCE/MASTG-TEST-0341.md`, `MASTG-KNOW-0030`, `MASTG-KNOW-0032`, `MASTG-BEST-0041`), yang memberikan salah satu pembahasan teknis paling mendalam dalam seluruh seri riset ini mengenai mekanisme pertahanan runtime (PLT/GOT hook detection, vtable hook detection, ART entry point verification). Nuansa metodologis terpenting: ini adalah test dengan logika evaluasi terbalik — kegagalan upaya hooking penguji sendiri (bukan keberhasilannya) adalah tanda PASS, dan hasil PASS harus selalu disertai catatan pembatas bahwa ini bukan garansi permanen (cat-and-mouse game yang terus berevolusi). Hooking juga tidak memerlukan akses root (via Frida Gadget embedded), sehingga pengujian yang hanya dilakukan di device rooted memberi cakupan yang tidak lengkap terhadap ancaman sesungguhnya.*
