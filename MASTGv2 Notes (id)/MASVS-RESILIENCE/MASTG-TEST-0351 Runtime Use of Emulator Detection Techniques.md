# MASTG-TEST-0351 Runtime Use of Emulator Detection Techniques

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0351 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-RESILIENCE |
| **Weakness** | MASWE-0053 |
| **Tipe Pengujian** | Dynamic, Hooks |
| **Teknik terkait** | MASTG-TECH-0005 (Installing Apps), MASTG-TECH-0043 (Method Hooking), MASTG-TECH-0032 (Execution Tracing) |
| **Knowledge terkait** | MASTG-KNOW-0031 (Emulator Detection) |
| **Best Practice terkait** | MASTG-BEST-0046 (Hardening Against Emulation) |
| **Catatan struktural** | Berbeda dari root detection (TEST-0324/0325), test ini **tidak memiliki pasangan statis** dalam katalog MASTG saat ini — ia berdiri sendiri sebagai test dinamis murni |

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian

Kutipan overview resmi MASTG:

> *"This test verifies whether an app implements runtime emulator detection by attempting to hook into common emulator detection mechanisms. These may include checks for build properties and artifacts typically associated with emulated devices, as well as calls to known emulator detection APIs."*

Tujuan emulator detection secara konseptual mirip root detection (TEST-0324/0325) — keduanya adalah kontrol **anti-reversing** yang menaikkan biaya analisis, bukan mencegah serangan secara absolut. MASTG-KNOW-0031 menegaskan ini secara eksplisit:

> *"In the context of anti-reversing, the goal of emulator detection is to increase the difficulty of running the app on an emulated device. This increased difficulty forces the reverse engineer to defeat the emulator checks or use a physical device, thereby limiting the access required for large-scale device analysis."*

Frasa *"limiting the access required for large-scale device analysis"* adalah kunci — emulator detection sangat relevan untuk mencegah **analisis otomatis skala besar** (fuzzing, scanning massal), karena menjalankan ribuan instance aplikasi di device fisik jauh lebih mahal dan sulit dibanding menjalankannya di emulator.

### 1.2 Enam Kategori Indikator Emulator (Sesuai MASTG-KNOW-0031)

| Kategori | Contoh Indikator |
|---|---|
| **Build characteristics** | `Build.FINGERPRINT` mengandung `generic`/`test-keys`; `Build.MODEL` seperti `sdk`, `genymotion`, `nox` |
| **Telephony characteristics** | `getLine1Number()` mengembalikan `15555215554`–`15555215584` (rentang tetap QEMU) |
| **Package name indicators** | Package emulator terpasang: `com.bignox.`, `com.bluestacks`, `com.microvirt.`, dsb. |
| **Available activities/services** | Launcher activity dengan prefix `com.bluestacks.` |
| **File system artifacts** | `/dev/socket/qemud`, `/dev/goldfish_pipe`, `/dev/socket/genyd` |
| **OpenGL renderer** | String renderer GLES mengandung `Bluestacks` atau `Translator` |

Kekayaan kategori ini jauh lebih beragam dibanding root detection — emulator detection memanfaatkan **artefak arsitektural** (virtualisasi perangkat keras tidak bisa disembunyikan sepenuhnya) selain sekadar file/proses yang bisa diganti nama.

### 1.3 Nuansa Penting: Package Visibility Restriction Membatasi Deteksi Berbasis Package

Satu detail teknis yang MASTG-KNOW-0031 soroti secara spesifik dan relevan untuk interpretasi hasil test:

> *"On Android 11 (API level 30) and later, package visibility restrictions affect package-based emulator detection. If a package is installed but not visible to the app, getPackageInfo behaves the same as if the package were not installed... This can create false negatives for package-based emulator detection."*

Ini berarti aplikasi yang **ditargetkan ke API 30+** namun tidak mendeklarasikan elemen `<queries>` yang sesuai di manifest-nya **tidak akan mampu** mendeteksi package emulator tertentu sama sekali, meski kode pengecekannya secara teknis "ada". Ini relevan untuk evaluasi §3.7 — ketidakhadiran **hasil positif** dari deteksi berbasis package bisa jadi bukan karena mekanismenya tidak ada, melainkan karena keterbatasan arsitektural platform modern yang membatasi visibilitas package.

### 1.4 Perbandingan Langsung dengan Root Detection (TEST-0324/0325)

Struktur test ini **hampir identik** dengan pasangan root detection dalam seri riset ini, namun dengan beberapa perbedaan nuansa yang layak dicatat:

| | Root Detection (TEST-0324/0325) | Emulator Detection (test ini) |
|---|---|---|
| **Pasangan statis** | Ada (TEST-0324) | **Tidak ada** — test ini berdiri sendiri |
| **Fleksibilitas device uji** | Rooted direkomendasikan, non-rooted sebagian tetap berfungsi | Emulator direkomendasikan, *"some checks may still surface on a physical device if the app runs them unconditionally"* |
| **Bypass opsional** | Disebutkan sebagai teknik inferensi tidak langsung | Pola kalimat yang **identik persis** — *"successful bypassing of certain checks or failed detections may indicate the presence"* |
| **Expected False Negatives** | Ada, menyebut anti-instrumentation sebagai confounding factor | Ada, pola kalimat yang **identik persis** |
| **Scope keterbatasan** | Out of scope untuk robustness/efektivitas | Out of scope untuk robustness/efektivitas (pola kalimat identik) |

Kemiripan struktural yang sangat tinggi ini mengindikasikan bahwa MASTG menerapkan **template metodologi yang konsisten** untuk seluruh test resilience kategori "deteksi lingkungan berisiko" (root, emulator, debugger, dsb.) — sesuatu yang berguna diketahui penguji karena pengalaman menguji salah satu test dalam keluarga ini akan sangat transferable ke test-test sejenis lainnya.

### 1.5 Mengapa Tidak Ada Pasangan Statis: Kemungkinan Alasan Struktural

Berbeda dari root detection yang memiliki pasangan statis eksplisit (TEST-0324), test emulator detection ini **berdiri sendiri** sebagai test dinamis. Ini konsisten dengan sifat sebagian besar indikator di §1.2 — banyak di antaranya (OpenGL renderer, telephony characteristic, file system artifact) **hanya bisa diverifikasi secara bermakna saat runtime** di lingkungan yang relevan, karena nilai-nilai pembandingnya (`Build.MODEL`, dsb.) adalah **string literal sederhana** yang mudah ditemukan statis namun **tidak informatif** tanpa konteks eksekusi — artinya kandidat statis untuk test seperti ini kemungkinan tidak memberi nilai tambah investigasi yang signifikan dibanding langsung melakukan pendekatan dinamis.

### 1.6 Konteks Nyata: Skala Industri Penipuan Berbasis Emulator Farm

Riset industri keamanan anti-fraud menunjukkan bahwa ancaman yang coba dimitigasi test ini **bukan isu reversing semata**, melainkan vektor penipuan finansial skala besar yang aktif terjadi:

> *"Mobile app fraud involves the abuse of Android and iOS applications using automation, fake devices, emulators, and manipulated runtime environments, with 2025 dominated by mobile bots, emulators, device farms, fake installs, and account takeover (ATO) attacks... Android emulators are heavily used by fraud rings running click farms and account farming operations."*

Insiden nyata yang terdokumentasi dari kuartal pertama 2025 menunjukkan pola serangan konkret:

> *"During Q1-Q2 2025, Southeast Asia experienced an organized credit-card fraud incident where attackers exploited design weaknesses in top-up mechanisms, bypassed user-side verification, bound stolen credit cards to Sybil accounts for fraudulent top-ups, and completed cash-out through collusive merchants."*

Catatan penting tentang keterbatasan deteksi berbasis nilai statis, menguatkan prinsip "cat-and-mouse" yang sudah ditegaskan MASTG-KNOW-0031:

> *"Emulator system values can be modified to fool fingerprinting attempts, with emulators like Bliss OS, Waydroid, and LDPlayer 9 allowing extensive system value spoofing."*

Konteks ini penting — emulator modern yang dipakai operasi penipuan skala besar **secara sengaja dirancang** untuk memalsukan nilai `Build.*` agar tampak seperti device fisik, menegaskan mengapa keandalan jangka panjang satu lapis deteksi saja tidak cukup (sejalan dengan prinsip layered defense MASTG-BEST-0046).

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core, Sesuai MASTG-TECH)

| Tool | Fungsi |
|---|---|
| **Frida** | Hooking API emulator detection (MASTG-TECH-0043) |
| **strace** | Tracing system call untuk menangkap pengecekan native-level (MASTG-TECH-0032) |
| **ADB** | Instalasi app (MASTG-TECH-0005) |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **Objection** | Hooking cepat tanpa script kustom |
| **Beberapa jenis emulator berbeda (AVD standar, Genymotion, LDPlayer, Bliss OS)** | Menguji cakupan deteksi terhadap berbagai jenis emulator — emulator yang satu mungkin terdeteksi sementara yang lain tidak, mengingat keberagaman karakteristik artefak (§1.2) |
| **Device fisik** | Verifikasi pembanding — memastikan mekanisme yang ditemukan **tidak false-positive** menandai device fisik asli sebagai emulator |

### 2.3 Prasyarat Lingkungan

- **Emulator direkomendasikan** sebagai lingkungan utama pengujian, namun device fisik tetap berguna sebagai pembanding (§2.2) dan untuk menangkap pengecekan yang berjalan unconditional.
- Variasikan jenis emulator yang dipakai untuk menilai cakupan deteksi secara lebih representatif.

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0005** untuk instalasi aplikasi.
2. Gunakan **MASTG-TECH-0043** untuk hook API yang relevan.
3. Gunakan **MASTG-TECH-0032** untuk trace system call yang relevan.
4. Exercise aplikasi secara ekstensif untuk memicu sebanyak mungkin alur.

### 3.2 Metode A — Frida: Hook Observasi Pasif terhadap Build Properties

```javascript
Java.perform(function () {
    var Build = Java.use("android.os.Build");
    ["FINGERPRINT", "MODEL", "MANUFACTURER", "HARDWARE", "PRODUCT"].forEach(function (field) {
        console.log("[Build." + field + "] " + Build.class.getField(field).get(null));
    });

    var PackageManager = Java.use("android.app.ApplicationPackageManager");
    PackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function (pkg, flags) {
        if (pkg.indexOf("bignox") !== -1 || pkg.indexOf("bluestacks") !== -1 || pkg.indexOf("microvirt") !== -1) {
            console.log("[getPackageInfo] cek package emulator: " + pkg);
        }
        return this.getPackageInfo(pkg, flags);
    };
});
```

### 3.3 Metode B — strace untuk Menangkap Pengecekan File System Artifact

```bash
adb shell strace -f -e trace=access,openat,stat -p $(adb shell pidof com.example.targetapp) 2>&1 | grep -iE 'qemud|goldfish|genyd|qemu_pipe'
```

### 3.4 Metode C — Objection untuk Bypass Cepat dan Observasi Perubahan Perilaku

```bash
objection -g com.example.targetapp explore
# di dalam REPL, hook manual terhadap Build fields atau gunakan modul emulator bypass pihak ketiga
```

Amati apakah memaksa nilai `Build.*` menjadi nilai device fisik mengubah perilaku aplikasi (sesuai teknik inferensi tidak langsung di overview resmi §1.1).

### 3.5 Metode D — Pengujian Lintas Jenis Emulator

```
Prosedur:
1. Jalankan aplikasi di AVD standar (goldfish/ranchu) — amati hasil hook
2. Ulangi di Genymotion — amati hasil hook
3. Ulangi di LDPlayer/Bliss OS (dirancang untuk spoofing, §1.6) — amati hasil hook
4. Bandingkan cakupan deteksi antar jenis emulator
```

### 3.6 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Kapan dipakai |
|---|---|---|
| **A** | Frida | Baseline wajib — observasi pasif Build properties & package check |
| **B** | strace | Menangkap pengecekan file system artifact native-level |
| **C** | Objection bypass | Inferensi tidak langsung lewat perubahan perilaku |
| **D** | Lintas emulator | Menilai cakupan deteksi terhadap emulator yang secara sengaja dirancang menyamarkan diri |

**Kombinasi minimum yang aku rekomendasikan:** **A + B (wajib)**, dengan **D** sangat direkomendasikan untuk aplikasi finansial mengingat skala penipuan nyata berbasis emulator farm (§1.6).

---

### 3.7 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG:**

> **Evaluation:** *"The test case fails if no instances of emulator detection checks are observed. However, results from this test should be interpreted as evidence of the presence of emulator detection logic, not as an assessment of its robustness or effectiveness."*

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi |
|---|---|
| F1 | Tidak ada satu pun pemanggilan API/pengecekan artefak terkait emulator yang teramati selama exercise ekstensif |

**Catatan kehati-hatian:** sebelum menyimpulkan FAIL, pertimbangkan apakah ketidakhadiran hasil disebabkan keterbatasan package visibility (§1.3) atau anti-instrumentation (sesuai pola Expected False Negatives), bukan benar-benar tidak adanya mekanisme.

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi |
|---|---|
| P1 | Teramati minimal satu pemanggilan API/pengecekan artefak yang cocok dengan kategori MASTG-KNOW-0031 (§1.2) |
| P2 | *(Opsional, sinyal kualitas tambahan)* Mekanisme tetap terpicu konsisten di berbagai jenis emulator (§3.5 Metode D), tidak hanya satu jenis tertentu |

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Murni test presence, bukan efektivitas** — identik dengan prinsip root detection (TEST-0325); PASS tidak menjamin ketahanan terhadap emulator modern yang secara sengaja memalsukan nilai sistem (§1.6).

2. **Variasikan jenis emulator uji** — mekanisme yang hanya diuji di satu jenis emulator (mis. AVD standar) mungkin memberi kesan cakupan yang lebih luas dari yang sesungguhnya; emulator seperti LDPlayer/Bliss OS yang dirancang untuk spoofing adalah uji ketahanan yang lebih representatif terhadap ancaman nyata.

3. **Pertimbangkan keterbatasan package visibility API 30+** sebelum menyimpulkan FAIL untuk deteksi berbasis package (§1.3) — periksa juga apakah manifest memiliki elemen `<queries>` yang sesuai.

4. **Severity dimodulasi:**

   | Faktor | Severity |
   |---|---|
   | Tidak ada emulator detection sama sekali pada aplikasi finansial yang rawan fraud emulator farm | **Tinggi** |
   | Deteksi ada namun hanya mencakup satu kategori (mis. hanya Build properties, mudah dispoofing) | **Sedang** |
   | Deteksi berlapis, konsisten di berbagai jenis emulator, dikombinasikan dengan Play Integrity API | **Bukan temuan** |

5. **Dokumentasikan:** API/artefak yang teramati terpicu, jenis emulator yang dipakai pengujian, dan hasil perbandingan cakupan antar jenis emulator bila dilakukan.

---

## 4. Rekomendasi Perbaikan

### 4.1 Kombinasikan Deteksi Berlapis dengan Google Play Integrity API

```java
// Sinyal lokal saja tidak cukup — kombinasikan dengan server-side attestation
RiskSignal signal = RiskSignal.builder()
    .emulatorDetected(EmulatorDetector.checkBuildProperties() || EmulatorDetector.checkFileArtifacts())
    .playIntegrityVerdict(playIntegrityManager.requestIntegrityToken())
    .build();
riskEngine.evaluate(signal);
```

### 4.2 Deklarasikan `<queries>` untuk Package-Based Detection pada API 30+

```xml
<queries>
    <package android:name="com.bignox.app" />
    <package android:name="com.bluestacks" />
</queries>
```

### 4.3 Checklist Remediasi

- [ ] Emulator detection mencakup minimal tiga kategori berbeda (build properties, file artifact, package/activity)
- [ ] Diuji terhadap minimal tiga jenis emulator berbeda termasuk yang dirancang untuk spoofing
- [ ] Dikombinasikan dengan Google Play Integrity API untuk verdict server-side
- [ ] Elemen `<queries>` dideklarasikan untuk package-based detection pada target API 30+
- [ ] Hasil sinyal risiko dikombinasikan dengan keputusan server, bukan client-only

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0351 (source, tests-beta)](https://github.com/OWASP/mastg/blob/master/tests-beta/android/MASVS-RESILIENCE/MASTG-TEST-0351.md)
- [MASTG-KNOW-0031: Emulator Detection](https://mas.owasp.org/MASTG/knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0031/)
- [MASTG-BEST-0046: Hardening Against Emulation](https://github.com/OWASP/mastg/blob/master/best-practices/MASTG-BEST-0046.md)
- [MASTG-TEST-0324/0325: Root Detection (dokumen terkait dalam seri riset ini, pola metodologi yang serupa)](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0324/)

### 5.2 Riset dan Kasus Nyata

- [Veriff: Emerging Emulator and Injection Attacks — Protect Your Bank Cards in 2025](https://www.veriff.com/fraud/news/bank-card-fraud-2025)
- [Appdome: What Is Mobile App Fraud? 2026 Trends & Risks](https://www.appdome.com/dev-sec-blog/what-is-mobile-app-fraud/)
- [Cryptomathic: Protecting Mobile Banking in 2025 with Emulator Detection](https://www.cryptomathic.com/blog/securing-mobile-banking-apps-in-2025-stay-ahead-of-emulator-attacks)
- [Surepass: Emulator Detection — What It Is and Why Apps Need It](https://surepass.io/blog/what-is-emulator-detection/)

### 5.3 Dokumentasi Tools

- [Frida — Dynamic Instrumentation Toolkit](https://frida.re/docs/home/)
- [Objection — Runtime Mobile Exploration](https://github.com/sensepost/objection)

---

*Dokumen ini disusun berdasarkan konten resmi OWASP MASTG (`tests-beta/android/MASVS-RESILIENCE/MASTG-TEST-0351.md`, `MASTG-KNOW-0031`, `MASTG-BEST-0046`), serta riset industri anti-fraud tentang skala nyata penipuan berbasis emulator farm (bot banking, account farming, insiden kartu kredit Asia Tenggara Q1-Q2 2025). Nuansa metodologis terpenting: berbeda dari root detection yang memiliki pasangan statis eksplisit (TEST-0324), test ini berdiri sendiri sebagai test dinamis murni — kemungkinan karena nilai-nilai pembanding (Build properties, dsb.) tidak informatif tanpa konteks eksekusi. Struktur evaluasinya mengikuti template yang hampir identik dengan root detection (presence-based, bukan efektivitas, dengan Expected False Negatives akibat anti-instrumentation), namun emulator modern yang dipakai operasi fraud skala besar secara sengaja dirancang memalsukan nilai sistem — menegaskan bahwa PASS pada test ini tidak menjamin ketahanan terhadap device farm yang sudah teroptimasi untuk evasion.*
