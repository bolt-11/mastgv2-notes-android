# MASTG-TEST-0318 References to SDK APIs Known to Handle Sensitive User Data

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0318 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-PRIVACY |
| **Weakness** | MASWE-0073 — *Inadequate Data Collection Declarations* |
| **Tipe Pengujian** | Static, Code |
| **Teknik terkait** | MASTG-TECH-0013, MASTG-TECH-0014 |
| **Test terkait** | **MASTG-TEST-0319** — counterpart yang **mengonfirmasi** data sungguhan benar-benar dikirim (test ini hanya mendeteksi **potensi**, lihat §1.3); **MASTG-TEST-0206** (Undeclared PII in Network Traffic Capture) dalam seri riset ini juga merujuk balik ke test ini sebagai pelengkap analisis statis |
| **Demo terkait** | — (tidak ada) |
| **Rule resmi** | — (tidak ada rule generik; setiap SDK pihak ketiga punya API entry point berbeda, menuntut rule kustom per-SDK, lihat §3.2) |
| **CWE terkait** | CWE-200, CWE-359 |

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian

Kutipan overview resmi MASTG:

> *"This test verifies whether an app uses SDK (third-party library) APIs known to handle sensitive user data (e.g., as defined in Google Play's Data safety section or the relevant privacy regulations)."*

Test ini menyasar risiko yang **sumbernya bukan kode aplikasi sendiri**, melainkan **SDK pihak ketiga** (analitik, iklan, crash reporting, dsb.) yang di-bundle ke dalam aplikasi — dan secara spesifik API **entry point** dari SDK tersebut yang **diketahui secara dokumentatif** dirancang untuk mengumpulkan data pengguna. Ini perbedaan penting dari banyak test lain dalam seri riset ini yang berfokus pada kode yang ditulis developer aplikasi sendiri — di sini, developer **mungkin tidak menulis logika pengumpulan data apa pun secara langsung**, namun tetap bertanggung jawab secara regulasi begitu mereka **memanggil** API SDK yang memicu pengumpulan tersebut.

### 1.2 Prasyarat Metodologis yang Unik: Memahami "Kamus" API per SDK

Berbeda dari kebanyakan test lain yang menyasar API Android/Java standar yang seragam, test ini menuntut **pemahaman spesifik per-SDK** — setiap library pihak ketiga memiliki **himpunan API entry point** yang berbeda-beda untuk mengumpulkan data, dan penguji harus **meninjau dokumentasi/codebase library tersebut** sebelum dapat mencari polanya secara efektif:

> *"As a prerequisite, we need to identify the SDK API methods it uses as entry points for data collection by reviewing the library's documentation or codebase."*

Contoh konkret yang diberikan overview resmi — **Firebase Analytics** (`FirebaseAnalytics` class) menyediakan beberapa entry point data collection yang berbeda fungsinya:

| Method | Fungsi | Jenis Data yang Berpotensi Dikumpulkan |
|---|---|---|
| `setUserId(String)` | Menetapkan identifier pengguna unik untuk tracking lintas-sesi | Identifier pengguna (bisa jadi PII bila berupa email/nomor telepon) |
| `setUserProperty(String, String)` | Menetapkan atribut kustom pengguna (mis. tier pelanggan, preferensi) | Atribut profil pengguna, berpotensi sensitif tergantung nama/nilai yang dikirim |
| `logEvent(String, Bundle)` | Mencatat event kustom beserta parameter tambahan | Konten `Bundle` bisa membawa **apa pun** yang diteruskan developer, termasuk data sensitif bila dipakai secara tidak hati-hati |

Ini menegaskan bahwa test ini **tidak dapat dijalankan secara generik** seperti test lain yang menyasar API Android standar — penguji perlu membangun **daftar referensi** entry point API untuk **setiap SDK** yang di-bundle aplikasi target, berdasarkan dokumentasi resmi masing-masing SDK.

### 1.3 Nuansa Krusial: "Potensi" vs "Konfirmasi" — Hubungan dengan MASTG-TEST-0319

Ini adalah pembeda metodologis paling penting yang secara eksplisit ditegaskan overview resmi dengan kalimat yang sangat jelas:

> *"Note: This test detects only **potential** sensitive user data handling. For **confirming** that actual user data are being shared, please refer to MASTG-TEST-0319."*

Ini konsisten dengan pola berulang "statis menemukan kandidat, dinamis mengonfirmasi" yang sudah dibahas di berbagai pasangan test lain dalam seri riset ini — namun di sini nuansanya **lebih tajam**: sekadar **menemukan pemanggilan** `setUserId()`/`logEvent()` di kode **tidak secara otomatis berarti data sensitif benar-benar dikirim**. Developer bisa saja memanggil `logEvent("button_clicked", bundle)` dengan `Bundle` yang **hanya berisi nama tombol** (data non-sensitif) — pemanggilan API-nya terdeteksi, tapi **tidak ada** data sensitif yang sesungguhnya mengalir. **Konfirmasi sesungguhnya** — apakah nilai yang diteruskan ke parameter API tersebut benar-benar data sensitif — menuntut **MASTG-TEST-0319** (analisis nilai parameter) dan/atau korelasi dengan capture jaringan nyata (rujuk dokumen **MASTG-TEST-0206** dalam seri riset ini, yang secara eksplisit merujuk balik ke test ini sebagai komponen analisis statis pelengkapnya).

### 1.4 Konteks Regulasi: Google Play Data Safety Section

Test ini memiliki **jangkar regulasi/marketplace yang konkret** — overview resmi merujuk langsung ke **Google Play Data Safety section**, formulir deklarasi wajib yang harus diisi developer saat mempublikasikan aplikasi ke Play Store, menjelaskan **jenis data apa** yang dikumpulkan/dibagikan aplikasi dan **untuk tujuan apa**. Test ini pada dasarnya membantu **memverifikasi konsistensi** antara apa yang **benar-benar dilakukan kode aplikasi** (lewat pemanggilan SDK) dengan apa yang **dideklarasikan** developer di formulir tersebut — sebuah celah kepatuhan yang, berdasarkan riset independen, ternyata **sangat luas** terjadi di ekosistem Play Store secara nyata.

### 1.5 Skala Masalah Nyata: Riset Mozilla tentang Akurasi Label Data Safety

Ini bukti paling kuat tentang **skala nyata** masalah yang coba diatasi test ini — riset independen oleh **Mozilla Foundation** menemukan:

> *"Mozilla Foundation accused Google of incorrectly labelling apps as 'Data Safe' as much as **80 percent** of the time in its Play digital bazaar, with **TikTok, Facebook and Twitter** among the misdescribed software."*

Fakta bahwa aplikasi dari perusahaan teknologi **terbesar dan paling diawasi** sekalipun (TikTok, Facebook, Twitter) termasuk dalam temuan ketidaksesuaian label menunjukkan bahwa **kesenjangan antara deklarasi dan perilaku nyata kode** adalah masalah yang **sistemik**, bukan kelalaian kecil yang terbatas pada developer app kecil tanpa sumber daya compliance. Riset juga menyoroti celah definisi yang dimanfaatkan secara sengaja:

> *"Data sharing with 'service providers' doesn't have to be reported, and Google has narrow definitions for the 'collection' and 'sharing' of data, which makes it possible for developers to conceal details and mislead users."*

### 1.6 Mekanisme Enforcement Nyata dari Google

Penting dicatat bahwa ini bukan sekadar isu reputasi tanpa konsekuensi nyata — Google memiliki mekanisme deteksi dan penegakan aktif:

> *"Google detects user data transmitted off device that developers have not disclosed in their app's Data safety form as user data collected... store teams can force edits, require updates, or remove apps whose labels are persistently inaccurate."*

Ini berarti temuan dari test ini **memiliki implikasi bisnis nyata** di luar sekadar risiko keamanan abstrak — ketidaksesuaian antara pemanggilan SDK yang terdeteksi dan deklarasi Data Safety yang sudah dipublikasikan berpotensi memicu **penegakan langsung dari Google** (pemblokiran update, penghapusan aplikasi dari Play Store), menjadikan test ini relevan tidak hanya bagi tim keamanan tapi juga tim legal/compliance dan product.

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | Fungsi |
|---|---|
| **jadx** | Dekompilasi DEX → Java untuk pencarian pola pemanggilan API SDK |
| **grep / ripgrep** | Pencarian pola API spesifik per-SDK (dibangun berdasarkan riset dokumentasi, §1.2) |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **Exodus Privacy** | Database tracker SDK yang sudah dikenal — memberi daftar awal SDK analitik/iklan yang terdeteksi di APK tanpa perlu membangun daftar referensi dari nol untuk SDK yang sudah umum |
| **AppBrain / ClassyShark** | Identifikasi library pihak ketiga yang di-bundle berdasarkan struktur package di APK |
| **CodeQL** | Menelusuri korelasi antara pemanggilan API SDK dan sumber data yang diteruskan (menjembatani ke MASTG-TEST-0319) |
| **MobSF** | Laporan otomatis yang kadang mengidentifikasi SDK tracker yang dikenal beserta API-nya |

### 2.3 Prasyarat Lingkungan

- **Tidak butuh device/root** untuk analisis statis inti.
- **Riset dokumentasi SDK adalah prasyarat wajib** sesuai §1.2 — tanpa mengetahui API entry point spesifik SDK yang dipakai aplikasi target, pencarian pola tidak dapat dilakukan secara efektif.
- **Peroleh salinan formulir Data Safety** aplikasi target dari listing Play Store (bila tersedia publik) untuk verifikasi konsistensi sesuai §1.4.

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0013** untuk reverse engineer aplikasi.
2. Gunakan **MASTG-TECH-0014** untuk mencari API yang relevan.

### 3.2 Metode A — Identifikasi SDK dan Bangun Daftar API Referensi *(langkah prasyarat wajib)*

```bash
jadx -d ./decompiled ./target-app.apk

# Identifikasi package SDK pihak ketiga yang di-bundle
find ./decompiled/sources -maxdepth 3 -type d | grep -vE "com/example/target|android/|androidx/"
```

Untuk setiap SDK yang teridentifikasi (mis. `com/google/firebase/analytics`, `com/facebook/appevents`, `com/adjust/sdk`), **tinjau dokumentasi resmi SDK tersebut** untuk membangun daftar API entry point data collection yang relevan — contoh untuk Firebase Analytics sudah diberikan di §1.2.

### 3.3 Metode B — grep/ripgrep Berdasarkan Daftar Referensi

```bash
D=./decompiled/sources

# Contoh untuk Firebase Analytics (sesuaikan untuk SDK lain yang teridentifikasi)
rg -n 'FirebaseAnalytics.*setUserId\(|FirebaseAnalytics.*setUserProperty\(|FirebaseAnalytics.*logEvent\(' $D

# Contoh untuk Facebook SDK
rg -n 'AppEventsLogger.*setUserID\(|AppEventsLogger.*logEvent\(' $D

# Pola umum lain yang sering menjadi entry point SDK analitik/iklan
rg -n '\.setUserId\(|\.setUserProperty\(|\.logEvent\(|\.identify\(|\.trackEvent\(' $D
```

### 3.4 Metode C — Exodus Privacy untuk Identifikasi SDK Dikenal

```bash
# Via web upload atau CLI exodus-standalone
exodus-standalone target-app.apk
```

Hasil Exodus memberi daftar tracker yang sudah teridentifikasi di database mereka, mempercepat langkah 3.2 untuk SDK-SDK yang sudah umum dikenal tanpa perlu riset dokumentasi dari nol.

### 3.5 Metode D — CodeQL untuk Korelasi dengan Sumber Data (Menjembatani ke MASTG-TEST-0319)

```ql
import java

class SdkDataCollectionCall extends MethodAccess {
  SdkDataCollectionCall() {
    this.getMethod().hasName(["setUserId", "setUserProperty", "logEvent"]) and
    this.getMethod().getDeclaringType().getName().matches("%Analytics%")
  }
}

from SdkDataCollectionCall call
select call, call.getAnArgument(), "Pemanggilan API SDK data collection ditemukan — lanjutkan ke MASTG-TEST-0319 untuk konfirmasi apakah nilai yang diteruskan benar-benar data sensitif"
```

### 3.6 Metode E — Verifikasi Konsistensi dengan Data Safety Section

```
Prosedur manual:
1. Unduh/salin formulir Data Safety aplikasi target dari listing Play Store publik
2. Bandingkan kategori data yang DIDEKLARASIKAN dengan API SDK yang TERDETEKSI dari Metode B/C
3. Tandai ketidaksesuaian: API terdeteksi mengumpulkan kategori data yang TIDAK disebutkan dalam deklarasi
```

### 3.7 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Kapan dipakai |
|---|---|---|
| **A** | Identifikasi SDK + riset dokumentasi | **Wajib pertama** sebelum metode lain |
| **B** | grep berdasarkan referensi | Baseline utama |
| **C** | Exodus Privacy | Mempercepat untuk SDK yang sudah umum dikenal |
| **D** | CodeQL | Menjembatani ke MASTG-TEST-0319 |
| **E** | Verifikasi Data Safety | Konteks regulasi/compliance, relevan untuk tim legal |

**Kombinasi minimum yang aku rekomendasikan:** **A (wajib) → B/C (deteksi) → E (konteks compliance)**, dilanjutkan ke **MASTG-TEST-0319** untuk konfirmasi data sungguhan sebelum menyimpulkan temuan final.

---

### 3.8 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG:**

> **Observation:** *"The output should list the locations where SDK methods are called."*
>
> **Evaluation:** *"The test case fails if you can find the use of these SDK methods in the app code, indicating that the app is sharing sensitive user data with the third-party SDK."*

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi |
|---|---|
| F1 | Ditemukan pemanggilan API entry point SDK yang diketahui menangani data sensitif (sesuai daftar referensi yang dibangun di §1.2) |
| F2 | Ketidaksesuaian terdeteksi antara API yang dipanggil dan deklarasi Data Safety aplikasi (Metode E) — kategori data yang terdeteksi dari kode **tidak** disebutkan dalam formulir deklarasi publik |

**Contoh bukti (ilustratif — MASTG belum menyediakan demo resmi untuk test ini):**

```java
// Ditemukan di com/example/target/analytics/UserTracker.java
FirebaseAnalytics analytics = FirebaseAnalytics.getInstance(context);
analytics.setUserId(user.getEmail());  // Email pengguna diteruskan sebagai User ID
```

Interpretasi: `setUserId()` dipanggil dengan **email pengguna** sebagai nilai — entry point SDK data collection terkonfirmasi dipakai untuk menangani data yang secara jelas berpotensi PII. **FAIL** (kandidat kuat; konfirmasi penuh menuntut MASTG-TEST-0319 untuk memverifikasi nilai parameter secara runtime).

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi |
|---|---|
| P1 | **Tidak ditemukan** pemanggilan API entry point SDK data collection yang diketahui dari daftar referensi yang relevan |
| P2 | API entry point ditemukan, namun nilai yang diteruskan terverifikasi (lewat review manual/MASTG-TEST-0319) **bukan** data sensitif (mis. `logEvent("button_clicked")` tanpa parameter sensitif) |
| P3 | Deklarasi Data Safety aplikasi **konsisten** dengan API yang terdeteksi dari kode |

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Ini test yang menuntut riset per-SDK, bukan pencarian pola generik** — tanpa membangun daftar referensi API entry point untuk SDK spesifik yang dipakai aplikasi target, hasil pencarian akan tidak lengkap/tidak relevan.

2. **"Ditemukan pemanggilan API" ≠ "konfirmasi data sensitif benar-benar dikirim"** — sesuai §1.3, ini hanya mengidentifikasi **kandidat**; selalu lanjutkan ke MASTG-TEST-0319 sebelum menyimpulkan FAIL final yang meyakinkan.

3. **Manfaatkan konteks regulasi untuk meningkatkan urgensi** — ketidaksesuaian dengan Data Safety section memiliki konsekuensi bisnis nyata (enforcement Google), bukan hanya risiko keamanan abstrak; ini argumen kuat untuk prioritas remediasi di mata product/legal.

4. **Skala masalah ini sistemik** (§1.5) — bahkan aplikasi raksasa (TikTok, Facebook, Twitter) ditemukan tidak konsisten; jangan berasumsi aplikasi dari perusahaan besar otomatis sudah benar.

5. **Severity dimodulasi:**

   | Faktor | Severity |
   |---|---|
   | API dipanggil dengan nilai yang jelas PII (email, nomor telepon) dan tidak dideklarasikan | **Tinggi** (risiko regulasi + privasi) |
   | API dipanggil tapi nilai tidak sensitif atau sudah dideklarasikan dengan benar | **Bukan temuan**/Informational |

6. **Dokumentasikan:** SDK yang teridentifikasi, API entry point yang dipanggil beserta lokasi kode, nilai parameter (bila dapat diverifikasi), dan hasil perbandingan dengan deklarasi Data Safety.

---

## 4. Rekomendasi Perbaikan

### 4.1 Audit dan Minimalkan Pemanggilan API Data Collection

```java
// SEBELUM — mengirim email sebagai User ID
analytics.setUserId(user.getEmail());

// SESUDAH — gunakan identifier yang di-hash/pseudonim, bukan PII langsung
analytics.setUserId(hashUserId(user.getId()));
```

### 4.2 Pastikan Deklarasi Data Safety Section Akurat dan Terkini

Jadikan audit API SDK (hasil test ini) sebagai **input rutin** untuk memperbarui formulir Data Safety setiap kali SDK baru ditambahkan atau pemanggilan API berubah — bukan hanya diisi sekali saat rilis pertama dan dibiarkan usang.

### 4.3 Checklist Remediasi

- [ ] Seluruh SDK pihak ketiga yang di-bundle diidentifikasi dan API entry point data collection-nya diteliti
- [ ] Pemanggilan API yang membawa data sensitif diminimalkan/dianonimkan
- [ ] Deklarasi Data Safety section diverifikasi konsisten dengan temuan audit kode
- [ ] Hasil dikorelasikan dengan MASTG-TEST-0319 untuk konfirmasi data sungguhan
- [ ] **Verifikasi ulang:** jalankan kembali MASTG-TEST-0318 setiap penambahan SDK pihak ketiga baru

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0318: References to SDK APIs Known to Handle Sensitive User Data](https://mas.owasp.org/MASTG/tests/android/MASVS-PRIVACY/MASTG-TEST-0318/)
- [MASTG-TEST-0319](https://mas.owasp.org/MASTG/tests/android/MASVS-PRIVACY/MASTG-TEST-0319/) — counterpart konfirmasi
- [MASTG-TEST-0206: Undeclared PII in Network Traffic Capture](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0206/)
- [MASWE-0073: Inadequate Data Collection Declarations](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0073/)

### 5.2 Dokumentasi Resmi

- [Google Play Console — Provide Information for Data Safety Section](https://support.google.com/googleplay/android-developer/answer/10787469?hl=en)
- [Android Developers Blog — New Safety Section in Google Play](https://android-developers.googleblog.com/2021/05/new-safety-section-in-google-play-will.html)
- [Firebase — Google Analytics for Firebase Documentation](https://firebase.google.com/docs/analytics)

### 5.3 Riset dan Kasus Nyata

- [Android Police — Mozilla: Google Play Store's Fancy Data Safety Labels Are Essentially Worthless](https://www.androidpolice.com/mozilla-google-play-store-data-privacy-labels-misleading/)
- [The Register — Mozilla Says 80 Percent of Google Play's App Safety Labels Are Inaccurate](https://forums.theregister.com/forum/all/2023/02/24/mozilla_says_safety_labels_on/)
- [GitHub commons-app/apps-android-commons#5708 — App Rejected by Google Play Due to Data Safety Section](https://github.com/commons-app/apps-android-commons/issues/5708)
- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
- [CWE-359: Exposure of Private Personal Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/359.html)

### 5.4 Dokumentasi Tools

- [Exodus Privacy](https://exodus-privacy.eu.org/)
- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [CodeQL — Documentation](https://codeql.github.com/docs/)
- [MobSF — Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)

---

*Dokumen ini disusun berdasarkan OWASP MASTG (rilis terkini per September 2026), dokumentasi resmi Google Play Console, serta riset Mozilla Foundation tentang akurasi label Data Safety yang mengungkap skala masalah sistemik (80% ketidaksesuaian, termasuk aplikasi raksasa seperti TikTok, Facebook, Twitter). Nuansa metodologis terpenting: test ini menuntut riset dokumentasi spesifik per-SDK sebagai prasyarat (bukan pencarian pola generik), dan hasil "ditemukan pemanggilan API" hanya mengidentifikasi **potensi**, bukan **konfirmasi** — kepastian penuh menuntut kelanjutan ke MASTG-TEST-0319 untuk verifikasi nilai parameter sesungguhnya.*
