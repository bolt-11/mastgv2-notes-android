# MASTG-TEST-0254 Dangerous App Permissions

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0254 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-PRIVACY |
| **Weakness** | MASWE-0066 — *Inadequate Permission Management* |
| **Tipe Pengujian** | Static, Code |
| **Profile** | **P (Privacy) saja** — bukan L1/L2, murni dievaluasi dari sudut pandang privasi pengguna, bukan keamanan teknis semata |
| **Knowledge** | MASTG-KNOW-0017 *(rujukan bermasalah — tidak ditemukan di kategori MASVS-PRIVACY yang seharusnya sesuai konvensi penomoran; pola inkonsistensi referensi serupa dengan yang sudah dicatat pada dokumen MASTG-TEST-0247)* |
| **Teknik terkait** | MASTG-TECH-0117 (Obtaining AndroidManifest), MASTG-TECH-0126 (Obtaining App Permissions) |
| **Test terkait** | Test ini adalah versi murni-manifest; pertimbangkan bersama dengan pengujian *runtime permission requests* dan analisis *permission usage* di kode (di luar cakupan test ini secara spesifik) |
| **Demo terkait** | — (tidak ada) |
| **Rule resmi** | `mastg-android-dangerous-app-permissions.yaml` — daftar lengkap seluruh dangerous permission AOSP, dicocokkan sebagai pattern XML literal (lihat §3.2) |
| **CWE terkait** | CWE-250 (Execution with Unnecessary Privileges), CWE-732 (Incorrect Permission Assignment for Critical Resource) |

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian

Kutipan overview resmi MASTG:

> *"In Android apps, permissions are acquired through different methods to access information and system functionalities, including the camera, location, or storage. The necessary permissions are specified in the `AndroidManifest.xml` file with `<uses-permission>` tags."*

Test ini murni **inventarisasi dan evaluasi kontekstual** terhadap permission berkategori **"dangerous"** menurut taksonomi resmi Android (berbeda dari kategori "normal" yang diberikan otomatis, atau "signature" yang hanya untuk aplikasi bertanda tangan sama). Dangerous permission adalah kategori yang **membutuhkan persetujuan eksplisit pengguna saat runtime** (sejak Android 6.0/API 23) karena berpotensi mengakses data atau fungsi yang berdampak signifikan terhadap privasi — kamera, lokasi, kontak, mikrofon, SMS, dsb.

### 1.2 Profile "P" — Murni Soal Privasi, Bukan Soal Keamanan Teknis

Poin metadata yang perlu digarisbawahi: test ini **hanya berlaku untuk profile P (Privacy)**, berbeda dari kebanyakan test lain dalam seri riset ini yang umumnya masuk L1/L2 (baseline keamanan) atau R (resilience). Ini mencerminkan sifat evaluasi test ini yang **bukan** tentang apakah permission tersebut "aman secara teknis" (mis. apakah `CAMERA` dieksploitasi lewat kerentanan), melainkan **apakah keberadaan permission itu sendiri proporsional** terhadap kebutuhan fungsional aplikasi dari kacamata privasi pengguna — evaluasi yang jauh lebih bersifat kontekstual/kebijakan dibanding pengujian teknis biner (rentan/tidak rentan).

### 1.3 Kriteria Evaluasi yang Sangat Bergantung Konteks — Bukan Sekadar Daftar Larangan

Ini karakteristik paling penting dari test ini yang membedakannya dari kebanyakan test lain dalam seri riset ini. Klausul Evaluation resmi secara literal terlihat sederhana:

> *"The test case fails if there are any dangerous permissions in the app."*

Namun overview resmi segera melengkapinya dengan klausul **"Context Consideration"** yang secara fundamental mengubah cara membaca kriteria di atas:

> *"Context is essential when evaluating permissions. For example, an app that uses the camera to scan QR codes should have the `CAMERA` permission. However, if the app does not have a camera feature, the permission is unnecessary and should be removed."*

Ini artinya kriteria FAIL **BUKAN** "aplikasi memiliki dangerous permission apa pun" (yang akan membuat hampir semua aplikasi fungsional gagal — aplikasi kamera, navigasi, messaging semua secara legitimate butuh dangerous permission). Kriteria sesungguhnya adalah: **"aplikasi memiliki dangerous permission yang TIDAK proporsional/tidak dibutuhkan fitur yang benar-benar ada."** Klausul literal resmi harus **selalu** dibaca berdampingan dengan bagian Context Consideration ini — pembacaan literal saja akan menghasilkan kesimpulan yang salah secara sistematis.

### 1.4 Rekomendasi Proaktif: Alternatif yang Lebih Privacy-Preserving

Overview resmi tidak berhenti di "hapus bila tidak perlu" — ia juga mendorong evaluasi **apakah ada cara mencapai fungsi yang sama tanpa permission dangerous sama sekali**:

> *"Also, consider if there are any privacy-preserving alternatives to the permissions used by the app. For example, instead of using the `CAMERA` permission, the app could use the device's built-in camera app to capture photos or videos by invoking the `ACTION_IMAGE_CAPTURE` or `ACTION_VIDEO_CAPTURE` intent actions."*

Ini pola arsitektural penting: alih-alih aplikasi **memiliki akses langsung** ke hardware kamera (yang menuntut permission `CAMERA` dan berjalan dalam proses aplikasi itu sendiri — berisiko lebih tinggi bila terjadi bug/eksploitasi kode), aplikasi bisa **mendelegasikan** tugas pengambilan foto/video ke aplikasi kamera bawaan sistem lewat Intent (`ACTION_IMAGE_CAPTURE`/`ACTION_VIDEO_CAPTURE`), lalu hanya menerima **hasil akhirnya** (file gambar/video) tanpa pernah menyentuh API kamera mentah sama sekali. Pola serupa berlaku untuk banyak permission dangerous lain — mis. memakai `Storage Access Framework` alih-alih `READ_EXTERNAL_STORAGE` langsung, atau `Contact Picker Intent` alih-alih `READ_CONTACTS` penuh.

### 1.5 Kasus Nyata: Riset Avast tentang Aplikasi Senter (Flashlight)

Ini contoh yang secara sempurna menggambarkan skenario **"dangerous permission tanpa fitur yang membenarkannya"** yang dijelaskan di §1.3 — sebuah kasus klasik dalam riset keamanan mobile:

> Riset Avast menganalisis **937 aplikasi senter (flashlight)** di Google Play dan menemukan bahwa aplikasi jenis ini **rata-rata meminta 25 permission**, dengan beberapa aplikasi meminta hingga **77 permission**. Sepuluh aplikasi terburuk (dengan total ~5,5 juta unduhan) meminta antara 68-77 permission. Di antara permission yang **sulit dijelaskan** untuk fungsi sekadar menyalakan lampu kilat: **77 aplikasi meminta `RECORD_AUDIO`**, **180 aplikasi meminta `READ_CONTACTS`**, **21 aplikasi meminta `WRITE_CONTACTS`**, ditambah permission lokasi, Bluetooth, panggilan telepon, dan SMS.

Fungsi menyalakan lampu kilat kamera **hanya membutuhkan** akses kamera dasar (bahkan pada implementasi modern, cukup lewat `CameraManager.setTorchMode()` tanpa permission `CAMERA` sama sekali untuk kasus penggunaan sederhana) — sehingga permintaan `RECORD_AUDIO`, `READ_CONTACTS`, atau akses lokasi **sama sekali tidak proporsional** terhadap fitur yang ditawarkan. Riset ini menyimpulkan bahwa meski hanya sebagian kecil (7 dari 937) yang secara resmi diklasifikasikan berbahaya/malware, **hampir seluruhnya** memiliki hak sistem yang cukup untuk mencuri data pengguna, mematikan pemindaian antivirus, atau memasang perangkat lunak berbahaya — inilah esensi risiko privasi yang coba dicegah test ini: bukan tentang niat jahat yang sudah terbukti, tapi tentang **permukaan risiko** yang tidak perlu.

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | Fungsi |
|---|---|
| **aapt / aapt2** | `aapt d permissions app.apk` — cara resmi tercepat melihat seluruh permission yang dideklarasikan |
| **adb** | `adb shell dumpsys package <package>` — melihat permission beserta **status runtime** (granted/denied), berguna untuk korelasi dengan perilaku nyata aplikasi terpasang |
| **jadx / apktool** | Ekstraksi `AndroidManifest.xml` sesuai MASTG-TECH-0117 |
| **semgrep** | Menjalankan rule resmi untuk deteksi cepat |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **MobSF** | Otomatis mengklasifikasikan dan menampilkan seluruh permission (normal/dangerous/signature) dengan deskripsi risiko masing-masing dalam laporan Manifest Analysis — sangat efisien untuk triase awal |
| **Exodus Privacy** | Platform analisis APK yang berfokus khusus pada privasi — menampilkan permission **beserta tracker pihak ketiga** yang terdeteksi, memberi konteks tambahan tentang *mengapa* suatu permission mungkin diminta (mis. SDK iklan yang membutuhkan lokasi) |
| **Google Play Console (App Content > Data Safety)** | Untuk aplikasi yang sudah dipublikasikan, deklarasi data safety resmi dapat dibandingkan dengan permission aktual untuk menemukan ketidaksesuaian |
| **androguard** | `androguard axml`/API Python untuk ekstraksi permission secara terprogram, cocok untuk audit skala besar/CI |
| **CodeQL** | Menelusuri apakah permission yang dideklarasikan benar-benar **dipakai** di kode (API yang berkorelasi, mis. `Camera2 API` untuk `CAMERA`) — membedakan permission yang benar-benar dipakai dari yang dideklarasikan tapi tidak pernah direalisasikan fungsinya |

### 2.3 Prasyarat Lingkungan

- **Tidak butuh device/root** untuk analisis statis inti — cukup APK.
- **Pemahaman fitur aplikasi yang sesungguhnya** adalah prasyarat kunci (§1.3) — penguji perlu menggunakan aplikasi secara langsung atau membaca deskripsi Play Store/dokumentasi untuk menilai fitur apa saja yang benar-benar ada, sebagai dasar menilai proporsionalitas permission.
- **Daftar dangerous permission Android berubah antar versi API** — selalu rujuk sumber resmi terkini (`AndroidManifest.xml` AOSP atau `Manifest.permission` reference) alih-alih daftar statis yang mungkin sudah usang.

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0117** untuk memperoleh `AndroidManifest.xml`.
2. Gunakan **MASTG-TECH-0126** untuk memperoleh daftar permission yang dideklarasikan.

### 3.2 Metode A — aapt/adb *(cara resmi tercepat)*

```bash
aapt d permissions target-app.apk
```

```bash
adb install target-app.apk
adb shell dumpsys package org.owasp.mastestapp | grep -A20 "requested permissions:"
```

### 3.3 Metode B — Rule Semgrep Resmi (Daftar Lengkap Dangerous Permission AOSP)

```yaml
rules:
  - id: detect-dangerous-android-permissions
    languages: [xml]
    message: "Dangerous Android permission found:"
    severity: WARNING
    pattern-either:
      - pattern: <uses-permission android:name="android.permission.CAMERA"/>
      - pattern: <uses-permission android:name="android.permission.RECORD_AUDIO"/>
      - pattern: <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION"/>
      - pattern: <uses-permission android:name="android.permission.READ_CONTACTS"/>
      # ... (lihat file lengkap: mastg-android-dangerous-app-permissions.yaml, mencakup 40+ permission)
```

```bash
semgrep --config https://raw.githubusercontent.com/OWASP/mastg/master/rules/mastg-android-dangerous-app-permissions.yaml ./out/resources/AndroidManifest.xml
```

**Catatan tentang rule ini**: rule ini adalah salah satu yang **paling komprehensif** ditemukan dalam seri riset dokumen ini — mencakup lebih dari 40 permission dangerous individual sesuai daftar resmi AOSP (`frameworks/base/core/res/AndroidManifest.xml`), termasuk permission yang relatif baru seperti `NEARBY_WIFI_DEVICES`, `READ_MEDIA_VISUAL_USER_SELECTED`, `BODY_SENSORS_BACKGROUND`, dan `POST_NOTIFICATIONS`. Namun sesuai sifat rule berbasis pattern-matching literal, rule ini **hanya mendeteksi keberadaan**, sama sekali **tidak dapat menilai proporsionalitas** yang menjadi inti evaluasi test ini (§1.3) — validasi konteks manual tetap mutlak diperlukan setelah rule ini dijalankan.

### 3.4 Metode C — MobSF (Klasifikasi Otomatis + Konteks Risiko)

```bash
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest
```

Bagian **Manifest Analysis** MobSF secara otomatis mengelompokkan permission ke kategori (`dangerous`, `normal`, `signature`) beserta deskripsi risiko singkat untuk masing-masing — mempercepat triase awal sebelum analisis kontekstual manual.

### 3.5 Metode D — Exodus Privacy (Konteks Tracker Pihak Ketiga)

```bash
# Via web (upload APK) atau CLI exodus-standalone
pip install exodus-standalone
exodus-standalone target-app.apk
```

Hasil Exodus memetakan **tracker SDK pihak ketiga** yang terdeteksi berdampingan dengan daftar permission — sangat berguna untuk kasus di mana dangerous permission ternyata dibutuhkan bukan oleh fitur inti aplikasi, melainkan oleh SDK iklan/analitik yang di-bundle (mis. `ACCESS_FINE_LOCATION` yang ternyata dipakai SDK targeting iklan, bukan fitur peta aplikasi).

### 3.6 Metode E — CodeQL (Verifikasi Pemakaian Nyata di Kode)

```ql
import java

class CameraPermissionUsage extends MethodAccess {
  CameraPermissionUsage() {
    this.getMethod().getDeclaringType().getASupertype*().hasQualifiedName("android.hardware.camera2", "CameraManager") or
    this.getMethod().getDeclaringType().hasQualifiedName("android.hardware", "Camera")
  }
}

from CameraPermissionUsage usage
select usage, "Pemakaian API kamera ditemukan — korelasikan dengan deklarasi permission CAMERA di manifest"
```

Bila permission dideklarasikan di manifest **tapi tidak ditemukan pemakaian API terkait di kode** (hasil query kosong), ini indikasi kuat permission tersebut **tidak terpakai** — kandidat FAIL yang kuat sesuai klausul Context Consideration (§1.3).

### 3.7 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Mendeteksi keberadaan? | Menilai proporsionalitas/konteks? | Kapan dipakai |
|---|---|---|---|---|
| **A** | aapt/adb | ✅ | ❌ | Baseline resmi tercepat |
| **B** | Rule semgrep resmi | ✅ (paling komprehensif) | ❌ | Baseline otomatis, CI/CD |
| **C** | MobSF | ✅ + kategorisasi | Sebagian (deskripsi risiko umum) | Triase cepat |
| **D** | Exodus Privacy | ✅ + korelasi tracker | ✅ (mengungkap sumber SDK pihak ketiga) | Menjawab "permission ini untuk siapa" |
| **E** | CodeQL | ✅ (indirect) | ✅ (verifikasi pemakaian nyata) | Menjawab "apakah benar-benar dipakai" |

**Kombinasi minimum yang aku rekomendasikan:** **A/B (inventarisasi lengkap) → E (verifikasi pemakaian nyata di kode) → D (identifikasi sumber SDK pihak ketiga bila ada permission tak terjelaskan) → penilaian manual kontekstual** terhadap fitur aplikasi yang sesungguhnya (§1.3), idealnya dengan mencoba langsung aplikasinya atau membaca deskripsi resminya di Play Store.

---

### 3.8 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG:**

> **Observation:** *"The output should contain the list of permissions declared by the app."*
>
> **Evaluation:** *"The test case fails if there are any dangerous permissions in the app"* — **dibaca bersamaan dengan klausul Context Consideration** yang menuntut evaluasi proporsionalitas terhadap fitur aplikasi.

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi |
|---|---|
| F1 | Dangerous permission dideklarasikan **tanpa fitur yang membenarkannya** di aplikasi (dikonfirmasi lewat penggunaan langsung atau CodeQL Metode E menunjukkan tidak ada pemakaian API terkait) |
| F2 | Dangerous permission dipakai untuk fitur yang **memiliki alternatif privacy-preserving** yang tidak diadopsi (mis. `CAMERA` penuh dipakai hanya untuk mengambil satu foto profil, padahal `ACTION_IMAGE_CAPTURE` cukup) |
| F3 | Dangerous permission terkonfirmasi (Metode D) dipakai oleh **SDK pihak ketiga** (iklan/analitik) tanpa kaitan dengan fitur inti yang diklaim aplikasi, dan tidak diungkapkan transparan ke pengguna |
| F4 | Pola sesuai kasus riset Avast (§1.5) — permission yang jumlah dan jenisnya jauh melampaui kebutuhan fungsi inti aplikasi yang dideskripsikan |

**Contoh bukti (ilustratif — MASTG belum menyediakan demo resmi untuk test ini):**

```bash
$ aapt d permissions flashlight-app.apk
package: com.example.flashlightapp
uses-permission: name='android.permission.CAMERA'
uses-permission: name='android.permission.RECORD_AUDIO'
uses-permission: name='android.permission.READ_CONTACTS'
uses-permission: name='android.permission.ACCESS_FINE_LOCATION'
```

```bash
$ # Verifikasi fitur aplikasi: hanya menyalakan/mematikan lampu kilat, tanpa fitur rekam suara/kontak/lokasi
$ # CodeQL: tidak ditemukan pemakaian API AudioRecord, ContactsContract, atau FusedLocationProviderClient di kode
```

Interpretasi: `RECORD_AUDIO`, `READ_CONTACTS`, dan `ACCESS_FINE_LOCATION` tidak berkorelasi dengan fitur apa pun yang teramati dari aplikasi senter ini — **FAIL** dengan tiga permission yang tidak proporsional, persis pola yang diungkap riset Avast.

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi |
|---|---|
| P1 | **Tidak ada** dangerous permission yang dideklarasikan sama sekali |
| P2 | Seluruh dangerous permission yang dideklarasikan **berkorelasi jelas** dengan fitur yang benar-benar ada dan dipakai di aplikasi (dikonfirmasi Metode E) |
| P3 | Untuk setiap dangerous permission yang dipakai, sudah dipertimbangkan dan didokumentasikan mengapa alternatif privacy-preserving (Intent delegation, dsb.) tidak sesuai untuk kasus penggunaan tersebut |
| P4 | Permission yang dipakai SDK pihak ketiga (dikonfirmasi Metode D) diungkapkan transparan dalam kebijakan privasi/Data Safety aplikasi |

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Jangan pernah menyimpulkan FAIL murni dari keberadaan dangerous permission tanpa evaluasi kontekstual.** Ini kesalahan paling fatal untuk test ini — pembacaan literal klausul Evaluation tanpa mempertimbangkan Context Consideration (§1.3) akan menghasilkan false positive masif pada hampir semua aplikasi fungsional.

2. **Aplikasi kamera, navigasi, dan komunikasi secara legitimate membutuhkan dangerous permission** — fokus evaluasi pada **proporsionalitas dan cakupan**, bukan keberadaan biner. `CAMERA` pada aplikasi kamera profesional jelas proporsional; `CAMERA` pada aplikasi kalkulator jelas tidak.

3. **Selalu coba pahami fitur aplikasi yang sesungguhnya** sebelum menilai — ini test yang **tidak bisa** dilakukan murni dari analisis kode/manifest tanpa pemahaman fungsional produk. Idealnya gunakan aplikasi secara langsung atau baca deskripsi resminya.

4. **Manfaatkan Exodus Privacy untuk mengungkap "siapa yang sebenarnya menggunakan permission ini"** — permission yang tampak tidak berkaitan dengan fitur inti seringkali ternyata dipakai SDK pihak ketiga yang di-bundle, bukan kode aplikasi sendiri.

5. **Perhatikan tren permission granular sejak Android 13+** (mis. `READ_MEDIA_IMAGES`/`READ_MEDIA_VIDEO`/`READ_MEDIA_AUDIO` menggantikan `READ_EXTERNAL_STORAGE` yang lebih luas cakupannya) — aplikasi yang masih meminta permission lama yang lebih luas padahal hanya butuh subset tertentu (mis. hanya gambar) adalah kandidat temuan yang baik, karena granularitas yang lebih sempit tersedia namun tidak dimanfaatkan.

6. **Severity dimodulasi:**

   | Faktor | Severity |
   |---|---|
   | Dangerous permission sensitif (lokasi, mikrofon, kontak) tanpa fitur yang membenarkan sama sekali | **Tinggi** (dari perspektif privasi) |
   | Dangerous permission dipakai fitur nyata tapi cakupannya lebih luas dari kebutuhan (mis. `READ_EXTERNAL_STORAGE` penuh padahal cukup Storage Access Framework) | **Menengah** |
   | Dangerous permission proporsional dan sesuai fitur, tanpa alternatif privacy-preserving yang jelas lebih baik | **Bukan temuan** |

7. **Dokumentasikan:** daftar lengkap dangerous permission, fitur aplikasi yang mengklaim membutuhkannya (atau ketiadaannya), hasil verifikasi pemakaian kode (Metode E), sumber SDK pihak ketiga bila relevan (Metode D), dan penilaian alternatif privacy-preserving yang tersedia.

---

## 4. Rekomendasi Perbaikan

### 4.1 Hapus Permission yang Tidak Dipakai

```xml
<!-- SEBELUM -->
<uses-permission android:name="android.permission.READ_CONTACTS"/>  <!-- tidak dipakai fitur apa pun -->

<!-- SESUDAH: dihapus sepenuhnya -->
```

### 4.2 Gunakan Alternatif Privacy-Preserving (Sesuai §1.4)

```kotlin
// SEBELUM: akses kamera langsung, butuh permission CAMERA
// SESUDAH: delegasikan ke aplikasi kamera sistem
val takePictureIntent = Intent(MediaStore.ACTION_IMAGE_CAPTURE)
startActivityForResult(takePictureIntent, REQUEST_IMAGE_CAPTURE)
// Tidak perlu <uses-permission android:name="android.permission.CAMERA"/> sama sekali
```

### 4.3 Gunakan Permission Granular Modern

```xml
<!-- SEBELUM (Android 12 ke bawah, cakupan luas) -->
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>

<!-- SESUDAH (Android 13+, granular sesuai kebutuhan) -->
<uses-permission android:name="android.permission.READ_MEDIA_IMAGES"/>
```

### 4.4 Audit SDK Pihak Ketiga Secara Berkala

Jalankan Exodus Privacy (Metode D) sebagai bagian rutin evaluasi dependency baru — permission yang "tiba-tiba" muncul di manifest final sering berasal dari SDK yang baru ditambahkan, bukan kode aplikasi sendiri.

### 4.5 Integrasikan ke CI/CD

```bash
#!/bin/bash
# ci-check-permission-proportionality.sh
APK=$1
aapt d permissions "$APK" > declared_permissions.txt
semgrep --config ./mastg-android-dangerous-app-permissions.yaml ./decompiled/resources/AndroidManifest.xml
# Bandingkan dengan whitelist permission yang sudah disetujui tim untuk fitur yang ada
```

### 4.6 Checklist Remediasi

- [ ] Seluruh dangerous permission sudah diinventarisasi dan dikorelasikan dengan fitur nyata (Metode E)
- [ ] Permission yang tidak dipakai/tidak proporsional sudah dihapus
- [ ] Alternatif privacy-preserving (Intent delegation) sudah dipertimbangkan untuk setiap dangerous permission yang tersisa
- [ ] Permission granular modern (API 33+) diadopsi menggantikan permission cakupan luas yang lama
- [ ] SDK pihak ketiga sudah diaudit sumber permission-nya (Exodus Privacy)
- [ ] Permission yang tersisa diungkapkan transparan dalam kebijakan privasi/Data Safety
- [ ] **Verifikasi ulang:** jalankan kembali MASTG-TEST-0254 setiap penambahan dependency/fitur baru

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0254: Dangerous App Permissions](https://mas.owasp.org/MASTG/tests/android/MASVS-PRIVACY/MASTG-TEST-0254/)
- [MASWE-0066: Inadequate Permission Management](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0066/)
- [MASTG-TECH-0117: Obtaining Information from the AndroidManifest](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0117/)
- [MASTG-TECH-0126: Obtaining App Permissions](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0126/)
- [Rule resmi: mastg-android-dangerous-app-permissions.yaml (GitHub)](https://github.com/OWASP/mastg/blob/master/rules/mastg-android-dangerous-app-permissions.yaml)
- [OWASP Mobile Top 10 2024 — M6: Inadequate Privacy Controls](https://owasp.org/www-project-mobile-top-10/2023-risks/m6-inadequate-privacy-controls)

### 5.2 Dokumentasi Resmi Android

- [Android Developers — `Manifest.permission` reference](https://developer.android.com/reference/android/Manifest.permission)
- [AOSP Source — Daftar Lengkap Dangerous Permission (AndroidManifest.xml)](https://android.googlesource.com/platform/frameworks/base/+/master/core/res/AndroidManifest.xml)
- [Android Developers — Minimize Permission Requests](https://developer.android.com/privacy-and-security/minimize-permission-requests)
- [Android Developers — Request App Permissions](https://developer.android.com/training/permissions/requesting)
- [Android Developers — Photo Picker (alternatif privacy-preserving untuk storage)](https://developer.android.com/training/data-storage/shared/photopicker)

### 5.3 Riset dan Kasus Nyata

- [Avast — Flashlight Apps on Google Play Request Up to 77 Permissions](https://blog.avast.com/flashlight-apps-on-google-play-request-up-to-77-permissions-avast-finds)
- [SecurityWeek — Android Flashlight Apps Request 77 Permissions](https://www.securityweek.com/android-flashlight-apps-request-77-permissions/)
- [Forbes — Google Play Warning: Harmless Flashlight Apps Secretly Access Data](https://www.forbes.com/sites/zakdoffman/2019/09/15/google-warning-as-harmless-apps-installed-by-millions-secretly-access-user-data-report/)
- [Exodus Privacy](https://exodus-privacy.eu.org/)
- [CWE-250: Execution with Unnecessary Privileges](https://cwe.mitre.org/data/definitions/250.html)
- [CWE-732: Incorrect Permission Assignment for Critical Resource](https://cwe.mitre.org/data/definitions/732.html)

### 5.4 Dokumentasi Tools

- [aapt2 — Android Asset Packaging Tool](https://developer.android.com/tools/aapt2)
- [Semgrep — Documentation](https://semgrep.dev/docs/)
- [CodeQL — Documentation](https://codeql.github.com/docs/)
- [MobSF — Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)
- [Exodus Standalone (CLI)](https://github.com/Exodus-Privacy/exodus-standalone)
- [androguard](https://github.com/androguard/androguard)

---

*Dokumen ini disusun berdasarkan OWASP MASTG (rilis terkini per September 2026), dokumentasi resmi Android Developers dan AOSP, serta riset Avast tentang aplikasi senter sebagai contoh nyata "dangerous permission tanpa fitur yang membenarkannya". Nuansa terpenting test ini: kriteria evaluasi literal ("gagal bila ada dangerous permission") harus **selalu** dibaca berdampingan dengan klausul Context Consideration resmi — pembacaan literal tanpa penilaian proporsionalitas fitur akan menghasilkan false positive sistematis pada hampir semua aplikasi fungsional.*
