# MASTG-TEST-0285 Outdated Android Version Allowing Trust in User-Provided CAs

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0285 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-NETWORK (MASVS-NETWORK-2) |
| **Weakness** | MASWE-0027 — *Insecure Certificate Validation* |
| **Tipe Pengujian** | Static, Code |
| **Field khusus** | **`deprecated_since: 24`** — pola metadata yang sama seperti ditemukan di MASTG-TEST-0222 dalam seri riset ini, menandai bahwa risiko test ini **sudah tidak relevan** untuk aplikasi dengan `minSdkVersion` ≥ 24 |
| **Knowledge** | MASTG-KNOW-0014 (Android Network Security Configuration) |
| **Teknik terkait** | MASTG-TECH-0013, MASTG-TECH-0117 (Obtaining AndroidManifest), MASTG-TECH-0150 (Analyzing AndroidManifest) |
| **Test terkait** | **MASTG-TEST-0234/0282/0283/0284** — kelompok MASWE-0027 yang sama, namun test ini **unik**: satu-satunya dalam kelompok yang murni ditentukan oleh **satu angka di manifest** (`minSdkVersion`), bukan oleh kualitas implementasi kode |
| **Demo terkait** | — (tidak ada) |
| **Rule resmi** | — (tidak relevan; evaluasi murni ekstraksi nilai atribut manifest, terlalu sederhana untuk memerlukan rule semgrep) |
| **CWE terkait** | CWE-295, CWE-1104 (analog: mewarisi kelemahan platform lawas) |

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian

Kutipan overview resmi MASTG:

> *"This test evaluates whether an Android app **implicitly** trusts user-added CA certificates by default, which is the case for apps that can be installed to devices running API level 23 or lower."*

Test ini menyasar konsekuensi keamanan dari **`minSdkVersion` yang rendah** — bukan soal bug di kode aplikasi, melainkan soal **apakah aplikasi bahkan bisa diinstal** pada device Android lawas (Android 6.0/API 23 ke bawah) yang secara **struktural platform** mempercayai sertifikat CA yang ditambahkan pengguna secara default.

### 1.2 Perubahan Kebijakan Trust Anchor di Android Nougat (API 24) — Konteks Historis

Sesuai riset dan dokumentasi resmi Android:

> *"By default, secure connections from all apps trust the pre-installed system CAs, and apps targeting Android 6.0 (API level 23) and lower also trust the user-added CA store by default. Apps that target API Level 24 and above no longer trust user or admin-added CAs for secure connections, by default."*

Ini adalah **perubahan keamanan yang disengaja** yang diperkenalkan di Android Nougat (2016) — pengumuman resmi dari Android Developers Blog secara eksplisit menjelaskan motivasinya: mengurangi permukaan serangan MITM, karena sertifikat CA yang ditambahkan pengguna (baik sengaja oleh pengguna maupun **diam-diam disuntikkan malware/MDM perusahaan yang disusupi**) sebelumnya **otomatis dipercaya** oleh seluruh aplikasi di device tersebut tanpa terkecuali.

### 1.3 Nuansa Paling Penting: Mengapa Test Ini Memeriksa `minSdkVersion`, Bukan `targetSdkVersion`

Ini adalah **temuan konseptual paling penting** dalam dokumen ini, dan sekilas tampak bertentangan dengan pola yang sudah dibahas di berbagai dokumen lain dalam seri riset ini (MASTG-TEST-0235, 0245, 0252) — di mana **`targetSdkVersion`**, bukan `minSdkVersion`, yang biasanya menentukan **default behavior** suatu API/kebijakan platform. Bila mengikuti pola tersebut, seharusnya intuisi pertama adalah: "bukankah default trust anchor ditentukan oleh `targetSdkVersion`, seperti yang dijelaskan MASTG-KNOW-0014?" (Sesuai tabel resmi: `targetSdkVersion` ≤23 → trust user+system CA; `targetSdkVersion` 24-27/28+ → trust system CA saja).

**Namun test ini secara eksplisit dan benar memeriksa `minSdkVersion`, bukan `targetSdkVersion`** — dan inilah alasan teknis mendalam yang menjelaskan mengapa ini justru **tepat**, bukan kesalahan:

**Network Security Configuration (NSC) — mekanisme yang memungkinkan developer mengonfigurasi/override kebijakan trust anchor — itu sendiri baru diperkenalkan di API 24.** Pada device dengan **API 23 ke bawah**, NSC **sama sekali tidak ada** sebagai fitur platform — sistem operasi pada device tersebut menjalankan **logika trust anchor bawaan versi lama**, yang selalu mempercayai CA sistem **dan** CA pengguna, **tanpa cara apa pun bagi aplikasi untuk mengubahnya** — bahkan bila developer mendeklarasikan `targetSdkVersion` setinggi apa pun, atau menyertakan file `network_security_config.xml` yang sempurna sekalipun.

Ini artinya: **`targetSdkVersion` tinggi TIDAK memberi perlindungan apa pun bagi pengguna yang menjalankan aplikasi pada device Android lawas** — karena OS pada device tersebut **secara harfiah tidak memiliki mekanisme (NSC) untuk membaca/menghormati konfigurasi trust anchor apa pun yang dideklarasikan aplikasi**. Satu-satunya faktor yang benar-benar menentukan apakah pengguna tersebut **berpotensi terpapar** risiko ini adalah: **apakah aplikasi mengizinkan dirinya diinstal di device tersebut sejak awal** — yaitu ditentukan oleh **`minSdkVersion`**.

Tabel ringkas untuk memperjelas perbedaan mendasar ini:

| Skenario | `targetSdkVersion` | `minSdkVersion` | Device yang menjalankan | Hasil |
|---|---|---|---|---|
| A | 34 (tinggi) | 21 (rendah) | Android 6.0 (API 23) | **Tetap trust user CA** — NSC tidak ada di OS ini, `targetSdkVersion` tidak relevan sama sekali |
| B | 34 (tinggi) | 24+ | Android 6.0 (API 23) | **Tidak mungkin terjadi** — aplikasi tidak bisa diinstal sejak awal karena `minSdkVersion` mengeksklusi device ini |
| C | 23 (rendah) | 24+ | Android 7.0+ | Trust system CA saja — NSC ada di OS ini, dan berlaku default aman API 24+ terlepas `targetSdkVersion` yang rendah *(catatan: skenario ini jarang terjadi dalam praktik karena `targetSdkVersion` lazimnya ≥ `minSdkVersion`)* |

Baris **A** adalah inti dari mengapa test ini secara spesifik menyasar `minSdkVersion` — ini satu-satunya kontrol yang benar-benar efektif mencegah risiko ini muncul di dunia nyata, karena ia mengontrol **populasi device**, bukan **perilaku software** pada device yang sudah kadung terpasang.

### 1.4 Konsekuensi Praktis: Dampak Ganda pada Keamanan dan Alur Kerja Pentest

Perubahan kebijakan API 24 ini memiliki **dua sisi dampak** yang saling berlawanan kepentingan, dan keduanya relevan untuk dipahami penguji:

- **Sisi keamanan (relevan untuk test ini)**: aplikasi dengan `minSdkVersion` ≥24 **terlindungi secara struktural** dari CA jahat yang ditambahkan pengguna/malware/MDM tersusupi pada device manapun yang menjalankannya — karena seluruh device yang berhak menginstalnya sudah memiliki NSC yang secara default menolak trust user CA.
- **Sisi alur kerja pengujian keamanan (dampak sampingan yang perlu diketahui penguji)**: perubahan yang sama ini **mempersulit pekerjaan pentester/peneliti keamanan sendiri** — sertifikat yang diterbitkan tool intersepsi seperti **Burp Suite** atau **mitmproxy** (yang bekerja dengan cara menambahkan dirinya sebagai CA yang dipercaya pengguna di device uji) **tidak lagi otomatis dipercaya** oleh aplikasi yang menargetkan API 24+ — kecuali NSC aplikasi tersebut secara eksplisit dikonfigurasi untuk mempercayai CA pengguna (`<certificates src="user"/>`), sesuatu yang **jarang dilakukan** aplikasi produksi kecuali untuk kebutuhan debug khusus. Ini alasan teknis mengapa penguji keamanan mobile modern sering perlu melakukan **patching APK** (menyisipkan NSC kustom lewat apktool) atau memakai teknik bypass lain untuk tetap bisa melakukan intersepsi HTTPS pada aplikasi modern — topik yang sudah disinggung sepintas terkait pinning bypass di beberapa dokumen lain dalam seri riset MASVS-NETWORK ini.

### 1.5 Mengapa `deprecated_since: 24`

Field `deprecated_since: 24` pada frontmatter test ini — mengikuti pola yang sama seperti dibahas di dokumen **MASTG-TEST-0222** dalam seri riset ini — menandakan bahwa risiko yang diuji test ini **secara struktural sudah tidak mungkin terjadi** untuk aplikasi dengan `minSdkVersion` ≥24 sejak awal, karena mekanisme proteksi (NSC default aman) sudah menjadi bagian intrinsik platform sejak versi tersebut. Berbeda dengan MASTG-TEST-0222 (PIE) yang relevansinya menurun karena **hampir seluruh device modern** sudah di atas ambang batas tersebut, relevansi test ini sedikit berbeda nuansanya: ia tetap **sangat relevan untuk diperiksa** karena `minSdkVersion` adalah **pilihan sadar developer** yang bisa saja masih diset rendah demi jangkauan device yang lebih luas — bukan sesuatu yang otomatis "sudah usang" seiring waktu tanpa keterlibatan keputusan developer.

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | Fungsi |
|---|---|
| **jadx --no-src** | Ekstraksi `AndroidManifest.xml` untuk membaca elemen `<uses-sdk>` |
| **aapt2 / apkanalyzer** | Cara resmi Android SDK untuk membaca `minSdkVersion` tanpa dekompilasi penuh |
| **grep** | Ekstraksi nilai atribut secara cepat |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **androguard** | Ekstraksi `minSdkVersion` secara terprogram (Python), cocok untuk audit skala besar/CI |
| **MobSF** | Menampilkan `minSdkVersion`/`targetSdkVersion` di ringkasan Manifest Analysis |
| **Verifikasi dinamis pada emulator API 23** (opsional, untuk pembuktian empiris) | Menjalankan aplikasi pada image emulator Android 6.0 dan mengonfirmasi secara langsung bahwa CA pengguna yang ditambahkan manual benar-benar dipercaya sistem untuk koneksi HTTPS aplikasi tersebut |

### 2.3 Prasyarat Lingkungan

- **Tidak butuh device/root** untuk analisis statis inti — cukup ekstraksi manifest dari APK.
- **Opsional**: emulator dengan image Android 6.0 (API 23) untuk verifikasi empiris perilaku trust anchor secara langsung, bila diperlukan bukti definitif di luar sekadar pembacaan nilai `minSdkVersion`.

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0013** untuk reverse engineer aplikasi.
2. Gunakan **MASTG-TECH-0117** untuk memperoleh `AndroidManifest.xml`.
3. Gunakan **MASTG-TECH-0150** untuk membaca nilai `minSdkVersion` dari elemen `<uses-sdk>`.

### 3.2 Metode A — jadx + grep *(metode resmi utama, paling sederhana di antara seluruh seri riset ini)*

```bash
jadx --no-src -d ./out target-app.apk
grep -oP 'minSdkVersion="\K[0-9]+' ./out/resources/AndroidManifest.xml
```

**Catatan penting berdasarkan MASTG-TECH-0117**: gunakan **jadx**, bukan apktool, untuk langkah ini — MASTG-TECH-0117 secara eksplisit mencatat bahwa elemen `<uses-sdk>` (yang memuat `minSdkVersion`) **hilang** dari hasil dekompilasi apktool, sementara jadx menyertakannya secara lengkap.

### 3.3 Metode B — aapt2 (Cara Resmi Android SDK)

```bash
aapt2 dump badging target-app.apk | grep -i "sdkVersion"
```

atau

```bash
apkanalyzer manifest print target-app.apk | grep -i "minSdkVersion"
```

### 3.4 Metode C — androguard (Automasi/CI)

```python
from androguard.core.apk import APK
apk = APK("target-app.apk")
min_sdk = apk.get_min_sdk_version()
print(f"minSdkVersion: {min_sdk}")
if int(min_sdk) < 24:
    print("[FAIL] Aplikasi dapat diinstal pada device yang mempercayai user CA secara default")
```

### 3.5 Metode D — Verifikasi Empiris pada Emulator API 23 (Pembuktian Definitif, Opsional)

Untuk penguji yang ingin bukti langsung di luar sekadar pembacaan angka manifest:

```bash
# 1. Jalankan emulator Android 6.0 (API 23)
emulator -avd api23-test &

# 2. Install sertifikat CA kustom sebagai "user CA" (bukan system CA)
adb push malicious-ca.pem /sdcard/
# Lalu install lewat Settings > Security > Install from storage (memerlukan interaksi manual)

# 3. Jalankan aplikasi target dan intersepsi lewat proxy yang memakai CA tersebut
mitmproxy --mode transparent

# 4. Amati: apakah koneksi HTTPS aplikasi BERHASIL melalui proxy dengan CA yang baru ditambahkan sebagai USER CA?
```

Bila koneksi berhasil tanpa penolakan, ini konfirmasi empiris langsung bahwa device API 23 memang mempercayai user CA untuk aplikasi ini — melengkapi (bukan menggantikan) hasil pembacaan `minSdkVersion` statis.

### 3.6 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Kapan dipakai |
|---|---|---|
| **A** | jadx + grep | **Baseline resmi wajib** — cepat dan definitif |
| **B** | aapt2/apkanalyzer | Alternatif resmi Android SDK, tanpa dekompilasi |
| **C** | androguard | Automasi/CI, audit skala besar |
| **D** | Emulator API 23 + mitmproxy | Pembuktian empiris tambahan, jarang diperlukan karena hasil statis sudah definitif |

**Kombinasi minimum yang aku rekomendasikan:** **A atau B saja sudah cukup** untuk kesimpulan yang solid — test ini termasuk salah satu yang **paling sederhana** dalam seluruh seri riset dokumen ini karena evaluasinya murni pembacaan satu nilai integer, tanpa ambiguitas interpretasi. Metode D hanya relevan sebagai demonstrasi edukatif atau untuk audit yang menuntut bukti empiris eksplisit, bukan kebutuhan rutin.

---

### 3.7 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG:**

> **Observation:** *"The output should contain the value of `minSdkVersion`."*
>
> **Evaluation:** *"The test case fails if `minSdkVersion` is less than 24."*

Ini salah satu kriteria evaluasi **paling jelas dan tidak ambigu** di seluruh seri riset dokumen ini — murni perbandingan numerik tunggal.

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi |
|---|---|
| F1 | `minSdkVersion` < 24 (Android 7.0/Nougat) |

**Contoh bukti (ilustratif — MASTG belum menyediakan demo resmi untuk test ini):**

```bash
$ grep -oP 'minSdkVersion="\K[0-9]+' AndroidManifest.xml
21
```

Interpretasi: `minSdkVersion=21` (Android 5.0) — aplikasi ini dapat diinstal pada device yang **secara struktural platform** mempercayai user CA tanpa cara apa pun bagi aplikasi untuk mengubahnya. **FAIL**, terlepas dari `targetSdkVersion` atau konfigurasi NSC apa pun yang mungkin sudah diterapkan (§1.3).

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi |
|---|---|
| P1 | `minSdkVersion` ≥ 24 |

```bash
$ grep -oP 'minSdkVersion="\K[0-9]+' AndroidManifest.xml
28
```

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Jangan bingungkan dengan `targetSdkVersion`** — ini kesalahan paling mungkin terjadi bagi penguji yang sudah terbiasa dengan pola "targetSdkVersion menentukan default" dari test-test lain dalam seri ini (MASTG-TEST-0235). Untuk test **khusus ini**, `minSdkVersion` adalah atribut yang benar dan relevan, karena alasan mendalam yang dijelaskan di §1.3 — NSC sebagai mekanisme override sama sekali tidak eksis pada API<24.

2. **Konfigurasi NSC apa pun yang diterapkan aplikasi TIDAK RELEVAN untuk device API<24** — jangan biarkan keberadaan `network_security_config.xml` yang sempurna (hasil lolos MASTG-TEST-0235/0242) membuat penguji berasumsi risiko ini sudah tertangani; NSC hanya berlaku pada OS yang memang mendukung fiturnya.

3. **Ini test yang murni ditentukan oleh keputusan bisnis/kompatibilitas developer**, bukan kualitas kode — remediasinya adalah **keputusan produk** (menaikkan `minSdkVersion`, mengorbankan jangkauan device lawas) yang mungkin melibatkan pertimbangan non-teknis (data analitik populasi pengguna, kebijakan dukungan device).

4. **Severity cenderung konsisten tinggi** bila FAIL — karena dampaknya bersifat struktural (tidak ada mitigasi kode apa pun yang bisa menutup celah ini selain menaikkan `minSdkVersion` itu sendiri), berbeda dari kebanyakan test lain yang severity-nya bervariasi tergantung konteks pemakaian.

5. **Dokumentasikan:** nilai `minSdkVersion` persis, dan opsional: hasil verifikasi empiris pada emulator API 23 bila dilakukan.

---

## 4. Rekomendasi Perbaikan

### 4.1 Naikkan `minSdkVersion` ke Minimal 24

```gradle
android {
    defaultConfig {
        minSdkVersion 24  // atau lebih tinggi, idealnya sesuai rekomendasi MASTG-BEST-0010 (lihat dokumen MASTG-TEST-0245)
    }
}
```

### 4.2 Bila Menaikkan `minSdkVersion` Tidak Memungkinkan dalam Jangka Pendek

Bila terdapat kendala bisnis yang menghalangi kenaikan `minSdkVersion` segera (mis. basis pengguna signifikan masih memakai device lawas), dokumentasikan risiko ini secara eksplisit dalam penilaian risiko produk, dan pertimbangkan mitigasi tambahan di level aplikasi (mis. **certificate pinning** yang diimplementasikan secara manual di kode — bukan lewat NSC yang tidak berlaku pada OS tersebut — sebagai lapisan pertahanan tambahan yang independen dari trust store sistem, meski implementasinya harus sangat berhati-hati mengikuti praktik aman yang dibahas di dokumen MASTG-TEST-0282/0283 dalam seri riset ini).

### 4.3 Checklist Remediasi

- [ ] `minSdkVersion` dievaluasi dan idealnya dinaikkan ke ≥24 (atau lebih tinggi sesuai kebutuhan modernisasi keseluruhan, rujuk MASTG-TEST-0245)
- [ ] Bila `minSdkVersion` <24 harus dipertahankan karena alasan bisnis, risiko ini didokumentasikan eksplisit dalam penilaian risiko produk
- [ ] Pertimbangkan certificate pinning manual di kode sebagai mitigasi tambahan independen dari NSC untuk device lawas
- [ ] **Verifikasi ulang:** jalankan kembali MASTG-TEST-0285 setiap perubahan `minSdkVersion`

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0285: Outdated Android Version Allowing Trust in User-Provided CAs](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0285/)
- [MASTG-TEST-0222: Position Independent Code (PIC) Not Enabled](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0222/) — pola `deprecated_since` serupa
- [MASTG-TEST-0245: References to Platform Version APIs](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0245/)
- [MASWE-0027: Insecure Certificate Validation](https://mas.owasp.org/MASWE/MASVS-NETWORK/MASWE-0027/)
- [MASTG-KNOW-0014: Android Network Security Configuration](https://mas.owasp.org/MASTG/knowledge/android/MASVS-NETWORK/MASTG-KNOW-0014/)
- [MASTG-TECH-0117: Obtaining Information from the AndroidManifest](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0117/)
- [MASTG-TECH-0150: Analyzing the AndroidManifest](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0150/)

### 5.2 Dokumentasi Resmi Android

- [Android Developers — Network Security Configuration: Custom Trust](https://developer.android.com/privacy-and-security/security-config#CustomTrust)
- [Android Developers Blog — Changes to Trusted Certificate Authorities in Android Nougat](https://android-developers.googleblog.com/2016/07/changes-to-trusted-certificate.html)

### 5.3 Riset dan Artikel Komunitas

- [Hurricane Labs — Modifying Android Apps to Allow TLS Intercept with User CAs](https://hurricanelabs.com/blog/modifying-android-apps-to-allow-tls-intercept-with-user-cas/)
- [CWE-295: Improper Certificate Validation](https://cwe.mitre.org/data/definitions/295.html)

### 5.4 Dokumentasi Tools

- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [aapt2 — Android Asset Packaging Tool](https://developer.android.com/tools/aapt2)
- [apkanalyzer](https://developer.android.com/tools/apkanalyzer)
- [androguard](https://github.com/androguard/androguard)
- [MobSF — Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)

---

*Dokumen ini disusun berdasarkan OWASP MASTG (rilis terkini per September 2026) dan dokumentasi resmi Android Developers seputar perubahan kebijakan trust anchor di Android Nougat. Nuansa konseptual terpenting: berbeda dari test-test lain dalam seri riset ini di mana `targetSdkVersion` yang menentukan default behavior, test ini secara tepat menyasar `minSdkVersion` karena Network Security Configuration — mekanisme yang memungkinkan override kebijakan trust anchor — sama sekali tidak eksis sebagai fitur platform pada Android API 23 ke bawah. Ini berarti tidak ada konfigurasi kode/manifest apa pun yang dapat melindungi pengguna pada device lawas tersebut — satu-satunya kontrol efektif adalah mencegah aplikasi terinstal di sana sejak awal, lewat `minSdkVersion`.*
