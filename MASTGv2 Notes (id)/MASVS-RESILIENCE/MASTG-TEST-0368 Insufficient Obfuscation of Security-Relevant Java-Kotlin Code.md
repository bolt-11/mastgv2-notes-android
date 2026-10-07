# MASTG-TEST-0368 Insufficient Obfuscation of Security-Relevant Java/Kotlin Code

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0368 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-RESILIENCE |
| **Weakness** | MASWE-0059 |
| **Tipe Pengujian** | Static, Code, **Manual** |
| **Teknik terkait** | MASTG-TECH-0013 (Reverse Engineering), MASTG-TECH-0023 (Reviewing Decompiled Java Code), MASTG-TECH-0016 (Smali, sebagai fallback) |
| **Knowledge terkait** | MASTG-KNOW-0033 (Obfuscation) |
| **Best Practice terkait** | MASTG-BEST-0029 (Implementing Resilience and RASP Signals — `status: placeholder`) |
| **Rule resmi** | — (tidak ada; test ini murni penilaian kualitatif manusia, konsisten dengan sifatnya) |

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian

Kutipan overview resmi MASTG:

> *"If security-relevant Java or Kotlin code is not sufficiently obfuscated, decompilation of the app's DEX bytecode can expose business logic, device attestation and environment checks, integrity checks, and other implementation details that help an attacker understand the app and model attacks."*

Test ini unik dalam seri riset ini karena **pertanyaannya bukan "apakah ada" tapi "apakah cukup"** — obfuskasi hampir selalu *ada* dalam bentuk minimal (default R8 minification pada build release modern), namun pertanyaan sesungguhnya adalah apakah tingkat obfuskasi tersebut **cukup kuat** untuk menghalangi pemahaman logika sensitif dalam waktu yang wajar. Ini menjadikan test ini salah satu yang paling bergantung pada **penilaian kualitatif manusia** dibanding deteksi pola otomatis.

### 1.2 Skenario Ancaman Konkret: Fraud-Scoring Fintech yang Hanya Dilindungi R8 Default

Overview memberi skenario langkah-demi-langkah yang sangat spesifik:

> *"Suppose a fintech app implements its fraud-detection scoring in Java/Kotlin, relying solely on R8 identifier renaming to protect the logic. An attacker decompiles the APK and, despite the shortened class and method names, locates the fraud-scoring logic within minutes by following the plaintext string constants that remain in the code. The attacker reads the exact detection thresholds and decision criteria directly from the decompiled output. Armed with this knowledge, the attacker crafts transactions that stay just below the detection thresholds."*

Skenario ini mengandung pelajaran metodologis penting: **penyerang tidak perlu memahami nama kelas/metode untuk menemukan logika sensitif** — mereka cukup mengikuti **string literal yang tetap plaintext** (nama pesan error, nama field JSON, label kondisi) sebagai "peta jalan" menuju logika yang relevan, bahkan ketika identifier sudah diacak sepenuhnya oleh R8. Riset industri mengonfirmasi bahwa pola serangan ini bukan skenario hipotetis belaka:

> *"In fintech applications, reverse engineering can expose transaction limits, OTP flows, and risk scoring logic, allowing attackers to design highly targeted fraud strategies."*

### 1.3 Enam Teknik Obfuskasi Layer Java/Kotlin dan Kekuatan Relatifnya

MASTG-KNOW-0033 menjabarkan enam kategori teknik, masing-masing menyasar aspek reverse engineering yang berbeda:

| Teknik | Yang Disamarkan | Catatan Kekuatan |
|---|---|---|
| **Identifier Renaming** (R8/ProGuard) | Nama kelas/metode/field | **Layout obfuscation** — tidak memengaruhi performa, namun **tidak menyembunyikan string literal** (celah utama di §1.2) |
| **String Encryption** | Literal string (URL, API key, pesan error, artefak deteksi root) | String hanya terlihat saat runtime, bukan di static decompiled output |
| **Dynamic Code Loading/Packing** | Lokasi fisik kode (dipisah dari DEX statis) | Memakai `DexClassLoader`/`InMemoryDexClassLoader`; logika sensitif baru "muncul" setelah proses loading berjalan |
| **Reflection/Indirect Invocation** | Call site langsung di decompiled output | `Class.forName` + `getDeclaredMethod` mengurangi jumlah pemanggilan eksplisit yang terlihat |
| **Control Flow Obfuscation** | Struktur alur logika asli | Opaque predicate, `GOTO` kompleks — memperumit control-flow graph hasil dekompilasi |
| **Dead Code Injection** | Rasio sinyal-ke-noise kode | Menambah "derau" analisis statis tanpa mengubah perilaku sesungguhnya |

Poin kunci yang harus dipahami penguji: **Identifier Renaming saja (skenario di §1.2) termasuk kategori yang PALING LEMAH** dari keenam teknik ini — ia hanya mengubah "label", tidak menyembunyikan **isi** (string literal) maupun **struktur** (control flow) logika. Evaluasi test ini pada dasarnya menilai **seberapa jauh** aplikasi melangkah melampaui baseline minimal ini.

### 1.4 Tiga Pertanyaan Diagnostik untuk Menilai Kecukupan Obfuskasi

Bagian "Further Validation Required" memberi kerangka tiga pertanyaan yang **saling melengkapi**, bukan dievaluasi sendiri-sendiri:

> *"Determine whether class names, method names, field names, or local variables have been renamed to meaningless identifiers. Determine whether string literals... remain in plaintext and can be used to locate security-relevant logic. Determine whether the control flow is structured in a way that still makes the original logic easy to follow."*

Ketiga pertanyaan ini secara langsung berpadanan dengan tiga dari enam teknik di §1.3 (Identifier Renaming, String Encryption, Control Flow Obfuscation) — ini bukan kebetulan, melainkan menunjukkan bahwa evaluasi resmi secara implisit mengharapkan penguji mempertimbangkan **kombinasi** teknik, bukan hanya satu. Aplikasi yang hanya memakai Identifier Renaming (seperti skenario fraud-scoring di §1.2) **gagal** pada dua dari tiga kriteria diagnostik ini secara otomatis.

### 1.5 Fallback Metodologis: Smali Saat Dekompilasi Gagal

Catatan praktis yang relevan untuk kasus aplikasi dengan obfuskasi/proteksi agresif:

> *"If the decompiled output is incomplete or unreliable, use MASTG-TECH-0016 to inspect the corresponding Smali code."*

Ini penting karena obfuskasi yang **sangat kuat** (terutama dikombinasikan dengan control flow obfuscation yang agresif) terkadang justru **membuat decompiler Java/Kotlin gagal** atau menghasilkan output yang tidak valid secara sintaksis — dalam kasus ini, penguji tidak boleh menyimpulkan "tidak bisa dianalisis, berarti FAIL/PASS oleh default", melainkan turun ke level Smali (representasi assembly-like Dalvik bytecode yang lebih dekat ke bytecode mentah) yang biasanya tetap bisa diekstrak meski decompiler Java gagal total.

### 1.6 Keterbatasan Deteksi Dynamic Loading/Packing

Catatan penting dari MASTG-KNOW-0033 yang relevan untuk kejujuran laporan:

> *"Use MASTG-TOOL-0009 with MASTG-TECH-0165 to identify known compilers, obfuscators, and packers in APKs. The absence of a known signature does not prove that dynamic loading or custom packing is not present."*

Ini adalah pengingat penting — **ketidakhadiran tanda tangan tool obfuskasi yang dikenal tidak membuktikan ketidakhadiran mekanisme itu sendiri**. Packer/loader kustom yang dibuat sendiri oleh tim developer (bukan tool komersial yang punya signature dikenal) akan lolos dari deteksi berbasis signature, namun tetap secara fungsional menyembunyikan logika dari analisis statis biasa.

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | Fungsi |
|---|---|
| **jadx** | Dekompilasi DEX → Java untuk penilaian kualitatif (MASTG-TECH-0013, MASTG-TECH-0023) |
| **baksmali/apktool** | Fallback ke Smali bila dekompilasi Java gagal (MASTG-TECH-0016) |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **MASTG-TOOL-0009 + MASTG-TECH-0165** | Deteksi signature tool obfuskasi/packer yang dikenal (dengan keterbatasan di §1.6) |
| **strings** | Pemeriksaan cepat seberapa banyak string literal bermakna yang masih tersisa di DEX mentah, sebelum dekompilasi penuh |
| **R8/ProGuard mapping file (bila tersedia dari developer untuk audit internal)** | Membandingkan nama asli vs nama hasil obfuskasi untuk menilai cakupan rename yang sesungguhnya diterapkan |

### 2.3 Prasyarat Lingkungan

- Tidak butuh device/root — ini murni analisis statis.
- Siapkan daftar logika "security-relevant" yang menjadi target evaluasi (fraud scoring, root/attestation check, integrity verification) sebelum memulai, sesuai cakupan yang disebut overview (§1.1).

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0013** untuk reverse engineer aplikasi.

(Langkah tunggal — menegaskan bahwa inti test ini adalah **penilaian kualitatif** terhadap hasil dekompilasi, bukan serangkaian pencarian pola bertahap.)

### 3.2 Metode A — Dekompilasi dan Pemeriksaan Visual Langsung

```bash
jadx -d ./decompiled target.apk
```

Buka hasil dekompilasi dan nilai langsung: apakah nama kelas/metode berupa `a.b.c`/`a()`, atau tetap deskriptif (`FraudScoringEngine.calculateRiskScore()`)?

### 3.3 Metode B — Pemeriksaan String Literal yang Tersisa (Sesuai Kriteria Diagnostik §1.4)

```bash
# Cek string mentah di classes.dex tanpa dekompilasi penuh
strings classes.dex | grep -iE 'threshold|fraud|risk_score|root|debugger|api_key|endpoint'
```

Bila banyak string bermakna langsung muncul (nama variabel kondisi, pesan log debug, nama endpoint), ini mengindikasikan **String Encryption tidak diterapkan** meski Identifier Renaming mungkin sudah aktif.

### 3.4 Metode C — Fallback ke Smali Saat Dekompilasi Gagal

```bash
apktool d target.apk -o target_smali
# Baca langsung file .smali yang relevan bila jadx menghasilkan output tidak valid
```

### 3.5 Metode D — Deteksi Signature Tool Obfuskasi/Packer

```bash
# Contoh pendekatan umum, sesuaikan dengan tool spesifik MASTG-TOOL-0009
apkid target.apk
```

### 3.6 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Kapan dipakai |
|---|---|---|
| **A** | jadx | Baseline wajib — penilaian visual langsung |
| **B** | strings/grep | Verifikasi kriteria diagnostik kedua (string literal) secara cepat |
| **C** | apktool/Smali | Fallback bila dekompilasi A gagal/tidak reliable |
| **D** | Signature detector | Identifikasi tool obfuskasi yang dipakai (dengan keterbatasan §1.6) |

**Kombinasi minimum yang aku rekomendasikan:** **A + B (wajib, dua kriteria diagnostik utama)**, dengan **C** sebagai fallback kondisional.

---

### 3.7 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG:**

> **Evaluation:** *"The test case fails if the Java or Kotlin layer allows an attacker to identify, correlate, and reverse engineer security-relevant logic with reasonable effort."*

Catatan penting: evaluasi ini **secara inheren kualitatif** — "reasonable effort" tidak memiliki ambang kuantitatif resmi, menuntut judgment penguji yang berpengalaman dan dapat dipertanggungjawabkan secara transparan.

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi |
|---|---|
| F1 | Logika security-relevant dapat diidentifikasi dan dipahami dalam waktu wajar (skenario §1.2: "dalam hitungan menit") lewat kombinasi nama identifier yang masih informatif **dan/atau** string literal plaintext yang tersisa |

**Contoh bukti (merefleksikan skenario resmi §1.2):**

```java
// Hasil dekompilasi — hanya Identifier Renaming R8 default
public class a {
    public boolean a(double d) {
        if (d > 5000000.0) { // threshold TERLIHAT jelas meski nama kelas/metode disamarkan
            return true;
        }
        return false;
    }
}
```

String log yang ditemukan di sekitar: `"FRAUD_THRESHOLD_EXCEEDED"`, `"risk_score_calculated"`.

Interpretasi: meski nama kelas `a` dan metode `a()` sudah diacak, **nilai threshold (`5000000.0`) dan string penanda logika (`FRAUD_THRESHOLD_EXCEEDED`) tetap plaintext** — penyerang dapat langsung memahami kondisi fraud detection dalam hitungan menit. **FAIL**.

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi |
|---|---|
| P1 | Identifier telah di-rename secara menyeluruh, **dan** |
| P2 | String literal terkait logika sensitif telah dienkripsi (tidak muncul plaintext di static analysis), **dan** |
| P3 | Control flow logika kritis telah diobfuskasi sehingga alur asli tidak mudah diikuti kembali |

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Jangan berhenti pada "apakah ada obfuskasi"** — hampir semua build release modern memiliki Identifier Renaming default; pertanyaan sesungguhnya adalah apakah ketiga kriteria diagnostik (§1.4) terpenuhi **bersamaan**, bukan hanya satu.

2. **String literal adalah "peta jalan" tercepat bagi penyerang** — sesuai §1.2, bahkan dengan nama kelas/metode yang sepenuhnya acak, string literal yang tersisa tetap memungkinkan navigasi cepat ke logika sensitif; ini sering menjadi satu-satunya kriteria yang paling menentukan hasil evaluasi akhir.

3. **Pertimbangkan kemungkinan dynamic loading/packing kustom** — sesuai §1.6, ketidakhadiran hasil positif dari signature detector **tidak membuktikan** ketidakhadiran mekanisme serupa; bila logika sensitif yang diharapkan "hilang" dari static decompiled output tanpa penjelasan jelas, pertimbangkan investigasi dinamis tambahan sebelum menyimpulkan PASS.

4. **Dokumentasikan secara transparan basis penilaian "reasonable effort"** — karena evaluasi ini kualitatif, cantumkan secara eksplisit berapa lama waktu yang dibutuhkan penguji untuk menemukan/memahami logika target, dan string/pola spesifik apa yang menjadi penunjuk jalan, agar laporan dapat diverifikasi ulang oleh pihak lain.

5. **Severity dimodulasi:**

   | Faktor | Severity |
   |---|---|
   | Logika fraud-detection/anti-tampering finansial dapat dipahami dalam hitungan menit | **Tinggi** |
   | Logika sensitif memerlukan usaha signifikan (jam/hari) untuk dipahami meski akhirnya berhasil | **Sedang** |
   | Ketiga kriteria diagnostik terpenuhi, logika sensitif efektif tersembunyi | **Bukan temuan** (dengan catatan ini tetap bukan garansi permanen, sesuai prinsip cat-and-mouse resilience) |

6. **Dokumentasikan:** logika spesifik yang dievaluasi, hasil pemeriksaan ketiga kriteria diagnostik, string/pola yang menjadi penunjuk jalan (bila ditemukan), dan estimasi waktu/usaha yang dibutuhkan untuk memahami logika tersebut.

---

## 4. Rekomendasi Perbaikan

### 4.1 Kombinasikan Minimal Tiga Teknik, Bukan Hanya Identifier Renaming

```pro
# Identifier Renaming (baseline, R8/ProGuard)
-obfuscationdictionary dictionary.txt

# String Encryption (via DexGuard/sejenis)
-obfuscate-strings class com.example.fraud.ScoringEngine {
    private static double FRAUD_THRESHOLD;
}

# Control Flow Obfuscation untuk logika paling kritis
-obfuscate-control-flow class com.example.fraud.** { *; }
```

### 4.2 Pindahkan Threshold/Konstanta Sensitif ke Server-Side

Alih-alih menyimpan nilai threshold fraud-detection secara hardcoded di client (yang pasti suatu saat dapat ditemukan, betapapun kuat obfuskasinya), pertimbangkan memindahkan keputusan akhir ke server — client hanya mengirim fitur mentah, server melakukan scoring dengan logika yang **tidak pernah ada di APK sama sekali**.

### 4.3 Checklist Remediasi

- [ ] Identifier renaming diterapkan secara menyeluruh untuk kelas/metode/field terkait logika sensitif
- [ ] String literal terkait logika sensitif (threshold, nama kondisi, endpoint) dienkripsi
- [ ] Control flow logika paling kritis diobfuskasi
- [ ] Pertimbangkan pemindahan keputusan paling sensitif (fraud scoring final) ke server-side
- [ ] Hasil obfuskasi diverifikasi ulang dengan percobaan dekompilasi langsung setelah setiap rilis besar

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0368 (source, tests-beta)](https://github.com/OWASP/mastg/blob/master/tests-beta/android/MASVS-RESILIENCE/MASTG-TEST-0368.md)
- [MASTG-KNOW-0033: Obfuscation](https://mas.owasp.org/MASTG/knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0033/)
- [MASTG-TECH-0016: Using Smali](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0016/)
- [MASTG-TECH-0023: Reviewing Decompiled Java Code](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0023/)

### 5.2 Dokumentasi Resmi dan Riset

- [Android Developers: Enable App Optimization (R8)](https://developer.android.com/topic/performance/app-optimization/enable-app-optimization)
- [Guardsquare ProGuard Manual](https://www.guardsquare.com/manual/configuration/usage)
- [O-MVLL: LLVM-based Obfuscator Documentation](https://obfuscator.re/omvll/)
- [Simpa Labs: Has Your Fintech App Been Reverse Engineered?](https://www.simpalabs.com/blog/how-to-tell-mobile-app-reverse-engineered)
- [Protectt.ai: What is Android App Reverse Engineering? Prevention and Impact on Businesses](https://protectt.ai/blog/what-is-android-app-reverse-engineering-and-how-to-prevent)

### 5.3 Dokumentasi Tools

- [jadx — Dex to Java Decompiler](https://github.com/skylot/jadx)
- [APKiD — Android Application Identifier for Packers, Protectors, Obfuscators](https://github.com/rednaga/APKiD)

---

*Dokumen ini disusun berdasarkan konten resmi OWASP MASTG (`tests-beta/android/MASVS-RESILIENCE/MASTG-TEST-0368.md`, `MASTG-KNOW-0033`), serta riset industri yang mengonfirmasi bahwa reverse engineering logika fraud-detection/risk-scoring di aplikasi fintech adalah pola serangan nyata dan aktif, bukan skenario hipotetis. Nuansa metodologis terpenting: test ini adalah salah satu yang paling bergantung pada penilaian kualitatif manusia dalam seluruh seri riset ini — tidak ada rule otomatis, dan kriteria "reasonable effort" dalam evaluasi resmi menuntut penguji secara transparan mendokumentasikan basis penilaiannya. Skenario ancaman resmi secara spesifik menunjukkan bahwa Identifier Renaming saja (teknik paling lemah dari enam kategori obfuskasi layer Java/Kotlin) tidak cukup — string literal yang tersisa plaintext tetap menjadi "peta jalan" tercepat bagi penyerang menuju logika sensitif, terlepas seberapa acak nama kelas/metode yang menyelubunginya.*
