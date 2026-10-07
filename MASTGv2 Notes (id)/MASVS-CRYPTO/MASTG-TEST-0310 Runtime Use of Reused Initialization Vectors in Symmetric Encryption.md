# MASTG-TEST-0310 Runtime Use of Reused Initialization Vectors in Symmetric Encryption

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0310 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-CRYPTO (MASVS-CRYPTO-1) |
| **Weakness** | MASWE-0007 — *Improper Encryption* |
| **Tipe Pengujian** | **Dynamic, Hooks** |
| **Status resmi MASTG** | **`placeholder`** — belum ada Overview/Steps/Evaluation lengkap |
| **Catatan resmi** | **Identik verbatim** dengan catatan MASTG-TEST-0309 — rujuk dokumen tersebut §1 untuk pembahasan konseptual lengkap (perbedaan persyaratan CBC/NIST SP 800-38A vs GCM/NIST SP 800-38D, "forbidden attack" Joux, kasus nyata) |
| **Test terkait** | **MASTG-TEST-0309** (References to Reused Initialization Vectors in Symmetric Encryption) — counterpart statis; keduanya berbagi **catatan resmi yang sama persis**, mengindikasikan hubungan pasangan statis-dinamis yang eksplisit meski tidak dinyatakan langsung dalam kalimat seperti pasangan test lain |
| **Demo terkait** | — (tidak ada) |
| **Rule resmi** | — (tidak relevan; test dinamis berbasis hooking) |
| **CWE terkait** | CWE-1204, CWE-323, CWE-329 |

---

## 1. Penjelasan

### 1.1 Hubungan dengan MASTG-TEST-0309

Catatan resmi test ini **identik kata demi kata** dengan MASTG-TEST-0309 — fakta ini sendiri sudah menjadi sinyal metodologis yang jelas: kedua test menyasar **permasalahan konseptual yang sama persis** (pengulangan pasangan kunci-IV/nonce pada enkripsi simetris), hanya berbeda pada **sudut pengujian**. Seluruh landasan teoretis — perbedaan persyaratan *unpredictability* (CBC, NIST SP 800-38A) vs *uniqueness* (GCM/CTR, NIST SP 800-38D), mekanisme "forbidden attack" Joux yang membuat pengulangan nonce GCM katastropik, serta kasus nyata (`InsecureBankv2`, CVE-2026-50210) — **sudah dibahas lengkap di dokumen MASTG-TEST-0309**. Dokumen ini berfokus murni pada **nilai tambah unik** pendekatan dinamis berbasis hooking.

### 1.2 Mengapa Pendekatan Dinamis Diperlukan Melebihi yang Statis Bisa Capai

Analisis statis (MASTG-TEST-0309) sangat efektif untuk mendeteksi kasus **paling umum dan paling mudah**: IV/nonce yang dibangun dari **literal byte array langsung di kode** (`new byte[]{0,0,0,...}` atau array yang tidak diinisialisasi). Namun ada beberapa skenario di mana **hanya observasi runtime** yang dapat memberi jawaban definitif:

1. **Sumber IV/nonce yang kompleks secara alur kontrol** — IV yang dibangun lewat beberapa fungsi perantara, hasil kombinasi beberapa sumber data, atau diturunkan dari kode native (JNI) yang tidak sepenuhnya terlihat dari dekompilasi Java/Kotlin murni.
2. **Counter yang gagal dipersist dengan benar antar-siklus hidup aplikasi** — kode yang **secara statis terlihat benar** (mis. memakai counter yang di-increment setiap operasi) namun **gagal menyimpan nilai counter** ke penyimpanan permanen antar-restart aplikasi — menyebabkan counter **kembali ke nilai awal** (mis. 0) setiap kali aplikasi dimulai ulang, yang secara efektif menciptakan pengulangan nonce **lintas sesi aplikasi** yang tidak akan pernah terdeteksi hanya dengan membaca kode sumber dalam satu sesi analisis statis.
3. **Race condition pada skenario konkuren** — aplikasi yang melakukan operasi enkripsi dari **beberapa thread secara simultan** berpotensi mengalami kondisi race yang menyebabkan dua operasi **kebetulan memperoleh nilai IV/nonce yang sama** (mis. akibat bug sinkronisasi pada mekanisme pembangkitan counter), sebuah kegagalan yang **murni bersifat perilaku runtime** dan mustahil dipastikan hanya dari membaca kode secara statis.
4. **Nilai yang terlihat acak secara statis namun sebenarnya memiliki entropi rendah** — mis. IV yang dibangkitkan dari `Random` (bukan `SecureRandom`) dengan seed yang dapat ditebak (rujuk pembahasan mendalam soal `Random` vs `SecureRandom` di dokumen-dokumen MASTG-TEST-0204/0205 dalam seri riset ini) — kode **tampak** memakai sumber "acak", namun nilai yang dihasilkan tetap dapat berulang dalam praktik karena keterbatasan periode generator pseudo-random yang dipakai.

### 1.3 Target Hooking: `Cipher.init()` sebagai Titik Observasi Tunggal yang Efektif

Berbeda dari test lain yang mungkin perlu hooking beberapa API berbeda, test ini dapat **secara efisien** menangkap seluruh kasus relevan lewat **satu titik observasi**: pemanggilan `Cipher.init()` dengan parameter `AlgorithmParameterSpec` (yang membawa `IvParameterSpec`/`GCMParameterSpec`). Karena **setiap** operasi enkripsi/dekripsi simetris pada akhirnya harus melalui titik inisialisasi ini, hooking di sini memberi **cakupan menyeluruh** tanpa perlu melacak titik-titik pembangkitan IV yang mungkin tersebar di berbagai lokasi kode.

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | Fungsi |
|---|---|
| **Frida** | Instrumentasi dinamis inti — hooking `Cipher.init()` untuk menangkap IV/nonce aktual |
| **frida-tools** (`frida-trace`) | Tracing cepat |
| **objection** | Wrapper Frida siap pakai |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **Xposed/LSPosed** | Alternatif hooking persisten |
| **adb** | Memaksa restart aplikasi berulang kali untuk menguji skenario #2 di §1.2 (counter yang gagal dipersist) |

### 2.3 Prasyarat Lingkungan

- **Wajib device/emulator dengan Frida server**.
- **Interaksi menyeluruh DAN berulang** — sesuai §1.2, beberapa skenario kegagalan (counter yang tidak dipersist, race condition) **hanya muncul** ketika aplikasi dijalankan ulang beberapa kali atau dipicu secara konkuren, bukan sekadar satu sesi interaksi linear tunggal.
- **Idealnya uji skenario restart aplikasi** sebagai bagian wajib metodologi — bukan hanya satu sesi panjang tanpa interupsi.

---

## 3. Cara Pengujian

Karena tidak ada langkah resmi rinci (status placeholder), metodologi berikut mengembangkan Metode C yang sudah diperkenalkan di dokumen MASTG-TEST-0309 menjadi pendekatan utama dan lebih komprehensif.

### 3.1 Langkah Umum

1. Install aplikasi dan pasang hook pada `Cipher.init()`.
2. Jelajahi aplikasi secara menyeluruh, picu operasi enkripsi berulang kali dalam satu sesi.
3. **Restart aplikasi beberapa kali** dan ulangi operasi enkripsi yang sama, untuk menguji persistensi counter/nonce lintas sesi.
4. Bandingkan seluruh nilai IV/nonce yang tertangkap — identifikasi pengulangan apa pun.

### 3.2 Metode A — Skrip Frida Komprehensif dengan Persistensi Log Lintas-Sesi

```javascript
// hook-iv-nonce-runtime-comprehensive.js
Java.perform(function () {
    var seenPairs = {};  // kombinasi (alias kunci + IV) yang sudah teramati

    function bytesToHex(byteArray) {
        return Array.from(Java.array('byte', byteArray))
            .map(b => (b & 0xff).toString(16).padStart(2, '0')).join('');
    }

    function getBacktrace() {
        return Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());
    }

    var Cipher = Java.use("javax.crypto.Cipher");
    Cipher.init.overload("int", "java.security.Key", "java.security.spec.AlgorithmParameterSpec").implementation = function (opmode, key, spec) {
        try {
            var specClassName = spec.getClass().getName();
            var ivBytes = null;

            if (specClassName.indexOf("IvParameterSpec") !== -1) {
                var ivSpec = Java.cast(spec, Java.use("javax.crypto.spec.IvParameterSpec"));
                ivBytes = ivSpec.getIV();
            } else if (specClassName.indexOf("GCMParameterSpec") !== -1) {
                var gcmSpec = Java.cast(spec, Java.use("javax.crypto.spec.GCMParameterSpec"));
                ivBytes = gcmSpec.getIV();
            }

            if (ivBytes !== null) {
                var ivHex = bytesToHex(ivBytes);
                var keyIdentifier = key.toString();  // proxy identitas kunci
                var pairKey = keyIdentifier + ":" + ivHex;

                console.log("[*] Cipher.init(opmode=" + opmode + ") -> IV/nonce: " + ivHex + " (key: " + keyIdentifier + ")");

                if (seenPairs[pairKey]) {
                    console.log("\n[!!!] PENGULANGAN IV/NONCE TERDETEKSI!");
                    console.log("    Pasangan (kunci, IV) ini SUDAH PERNAH dipakai sebelumnya.");
                    console.log("    Backtrace:\n" + getBacktrace());
                }
                seenPairs[pairKey] = (seenPairs[pairKey] || 0) + 1;
            }
        } catch (e) { console.log("[x] Error saat memproses spec: " + e); }

        return this.init(opmode, key, spec);
    };
});
```

```bash
# Sesi 1
frida -U -f com.target.app -l hook-iv-nonce-runtime-comprehensive.js --no-pause
# Jelajahi, picu enkripsi, catat hasil

# Restart aplikasi SECARA PENUH (bukan hanya background-foreground)
adb shell am force-stop com.target.app

# Sesi 2 — ulangi dengan skrip yang SAMA untuk menguji persistensi lintas-restart
frida -U -f com.target.app -l hook-iv-nonce-runtime-comprehensive.js --no-pause
```

**Catatan penting**: untuk menguji skenario §1.2 poin #2 secara efektif, bandingkan hasil **Sesi 1** dan **Sesi 2** secara manual — bila IV/nonce yang identik muncul di kedua sesi untuk kunci yang sama, ini konfirmasi bahwa mekanisme counter/pembangkitan nonce **tidak dipersist** dengan benar lintas restart aplikasi, meski dalam satu sesi tunggal tidak menunjukkan pengulangan apa pun.

### 3.3 Metode B — objection

```bash
objection -g com.target.app explore
android hooking watch class_method javax.crypto.Cipher.init --dump-args --dump-backtrace
```

Dengan pendekatan ini, deteksi pengulangan dilakukan **manual** dari hasil dump, berbeda dari Metode A yang mengotomasi deteksi lewat `seenPairs`.

### 3.4 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Deteksi otomatis? | Menguji persistensi lintas-restart? | Kapan dipakai |
|---|---|---|---|---|
| **A** | Skrip Frida komprehensif | ✅ | ✅ (dengan prosedur restart manual) | **Baseline utama** |
| **B** | objection | ❌ (manual) | Manual | Eksplorasi awal cepat |

**Kombinasi minimum yang aku rekomendasikan:** **A, dijalankan minimal dua kali dengan restart aplikasi penuh di antaranya**, sesuai §1.2 poin #2 yang menjadi nilai tambah paling unik dari pendekatan dinamis dibanding statis.

---

### 3.5 Kriteria Evaluasi: Positive Case & Negative Case

Karena tidak ada klausul Evaluation resmi (status placeholder) dan catatan resminya identik dengan MASTG-TEST-0309, kriteria berikut mengadaptasi prinsip yang sama untuk konteks observasi runtime.

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi |
|---|---|
| F1 | Pasangan (kunci, IV/nonce) yang **identik** teramati dipakai lebih dari satu kali selama satu sesi pengujian |
| F2 | Pasangan (kunci, IV/nonce) yang identik teramati berulang **lintas sesi restart aplikasi** — mengonfirmasi kegagalan persistensi counter/mekanisme pembangkitan nonce (§1.2 poin #2) |
| F3 | Mode GCM/CTR menunjukkan nonce berulang — kondisi paling kritis mengingat "forbidden attack" (rujuk MASTG-TEST-0309 §1.4) |

**Contoh bukti (ilustratif — MASTG belum menyediakan demo resmi untuk test ini):**

```
=== Sesi 1 ===
[*] Cipher.init(opmode=1) -> IV/nonce: 000000000000000000000000 (key: SecretKey@a1b2)

=== Setelah restart aplikasi ===
=== Sesi 2 ===
[*] Cipher.init(opmode=1) -> IV/nonce: 000000000000000000000000 (key: SecretKey@a1b2)

[!!!] PENGULANGAN IV/NONCE TERDETEKSI!
    Pasangan (kunci, IV) ini SUDAH PERNAH dipakai sebelumnya (lintas restart aplikasi).
```

Interpretasi: nonce yang identik (`000000...`) muncul baik di sesi pertama maupun setelah aplikasi di-restart penuh — mengindikasikan nonce dibangkitkan dari counter yang **selalu dimulai dari nol** setiap aplikasi dijalankan ulang, tanpa persistensi nilai counter sebelumnya. **FAIL**, dengan akar penyebab yang hanya bisa dikonfirmasi lewat pengujian dinamis lintas-sesi seperti ini.

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi |
|---|---|
| P1 | Seluruh pasangan (kunci, IV/nonce) yang teramati **unik**, baik dalam satu sesi maupun lintas beberapa sesi restart aplikasi |

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Pengujian dalam satu sesi tunggal tidak cukup untuk menangkap seluruh kelas kegagalan** — sesuai §1.2, beberapa skenario (persistensi counter, race condition) **hanya muncul** lewat pengujian lintas-restart atau skenario konkuren. Laporan yang hanya menguji satu sesi interaksi panjang berisiko melewatkan kelas kegagalan ini.

2. **Korelasikan selalu dengan MASTG-TEST-0309** — hasil statis memberi peta kandidat lokasi pembangkitan IV/nonce yang perlu diprioritaskan dipicu saat sesi dinamis; hasil dinamis memberi konfirmasi/penolakan definitif atas kandidat tersebut, sekaligus mengungkap kelas kegagalan yang tidak mungkin terlihat secara statis (persistensi, race condition).

3. **Identitas kunci (proxy via `key.toString()` atau pendekatan serupa) harus diverifikasi keandalannya** — pastikan representasi yang dipakai benar-benar unik per kunci yang berbeda, agar tidak salah mengelompokkan IV dari kunci-kunci yang sebenarnya berbeda sebagai "pasangan yang sama".

4. **Severity mengikuti pola yang sama seperti MASTG-TEST-0309** — prioritaskan temuan pada mode GCM di atas CBC mengingat tingkat keparahan "forbidden attack".

5. **Dokumentasikan:** nilai IV/nonce yang teramati per sesi, hasil perbandingan lintas-restart, backtrace lokasi pemanggilan, dan korelasi dengan temuan statis MASTG-TEST-0309.

---

## 4. Rekomendasi Perbaikan

Rekomendasi teknis identik dengan **dokumen MASTG-TEST-0309 §4** (bangkitkan IV/nonce segar via `SecureRandom` untuk setiap operasi). Tambahan spesifik untuk temuan yang unik tertangkap lewat pengujian dinamis:

### 4.1 Pastikan Counter/State Pembangkit Nonce Dipersist dengan Benar

Bila mekanisme pembangkitan nonce memakai counter (bukan `SecureRandom` murni), pastikan nilai counter **disimpan secara persisten** (mis. di `EncryptedSharedPreferences`/Keystore-backed storage) dan **dibaca kembali** saat aplikasi dimulai ulang — jangan biarkan counter selalu dimulai dari nol pada setiap proses baru.

### 4.2 Hindari Pembangkitan Nonce Berbasis Counter Sama Sekali Bila Memungkinkan

Untuk menghindari kompleksitas manajemen persistensi counter, pertimbangkan memakai `SecureRandom` dengan ruang nilai yang cukup besar (96-bit untuk GCM) — risiko kolisi acak pada ruang nilai sebesar ini secara praktis dapat diabaikan tanpa perlu mekanisme persistensi counter yang rawan bug.

### 4.3 Checklist Remediasi

- [ ] Hooking `Cipher.init()` dijalankan minimal dua sesi dengan restart aplikasi penuh di antaranya
- [ ] Tidak ada pasangan (kunci, IV/nonce) yang teridentifikasi berulang, baik dalam sesi maupun lintas sesi
- [ ] Mekanisme pembangkitan nonce dimigrasikan ke `SecureRandom` murni, atau counter yang dipersist dengan benar
- [ ] Hasil dikorelasikan dengan MASTG-TEST-0309
- [ ] **Verifikasi ulang:** jalankan kembali MASTG-TEST-0310 setelah setiap perubahan pada mekanisme pembangkitan IV/nonce

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0310: Runtime Use of Reused Initialization Vectors in Symmetric Encryption](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0310/)
- [MASTG-TEST-0309: References to Reused Initialization Vectors in Symmetric Encryption](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0309/)
- [MASTG-TEST-0204: Insecure Random API Usage](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0204/)
- [MASWE-0007: Improper Encryption](https://mas.owasp.org/MASWE/MASVS-CRYPTO/MASWE-0007/)

### 5.2 Standar Resmi

- [NIST SP 800-38A: Recommendation for Block Cipher Modes of Operation](https://csrc.nist.gov/pubs/sp/800/38/a/final)
- [NIST SP 800-38D: Recommendation for Block Cipher Modes of Operation — GCM and GMAC](https://csrc.nist.gov/pubs/sp/800/38/d/final)

### 5.3 Dokumentasi Tools

- [Frida — Dynamic instrumentation toolkit](https://frida.re/docs/javascript-api/)
- [Objection — Runtime Mobile Exploration toolkit](https://github.com/sensepost/objection)

---

*Dokumen ini disusun berdasarkan OWASP MASTG (rilis terkini per September 2026) dan standar NIST yang dirujuk catatan resminya, yang identik persis dengan MASTG-TEST-0309. Sebagai counterpart dinamis, nilai unik test ini terletak pada kemampuannya menangkap kelas kegagalan yang **mustahil terdeteksi lewat analisis statis murni** — khususnya kegagalan persistensi counter/nonce lintas-restart aplikasi dan race condition pada skenario konkuren. Metodologi yang direkomendasikan secara eksplisit menuntut pengujian **lintas-sesi** (dengan restart aplikasi penuh di antaranya), bukan hanya satu sesi interaksi linear tunggal, untuk mengungkap kelas kegagalan unik yang menjadi alasan keberadaan test dinamis ini.*
