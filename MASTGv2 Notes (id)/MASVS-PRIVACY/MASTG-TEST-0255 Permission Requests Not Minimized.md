# MASTG-TEST-0255 Permission Requests Not Minimized

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0255 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-PRIVACY |
| **Weakness** | MASWE-0066 — *Inadequate Permission Management* (sama seperti MASTG-TEST-0254) |
| **Status resmi MASTG** | **`placeholder`** — belum ada Overview/Steps/Evaluation lengkap |
| **Catatan resmi (satu-satunya konten yang tersedia)** | *"This test checks if the app requests permissions that have privacy-preserving alternatives."* |
| **Profile** | **P (Privacy) saja** |
| **Knowledge** | MASTG-KNOW-0017 *(rujukan bermasalah, sama seperti dicatat di dokumen MASTG-TEST-0254)* |
| **Test terkait** | **MASTG-TEST-0254** (Dangerous App Permissions — memeriksa **proporsionalitas** permission terhadap fitur; test ini melangkah lebih jauh: memeriksa **apakah fitur itu sendiri bisa dicapai tanpa permission dangerous sama sekali**) |
| **Demo terkait** | — (tidak ada) |
| **Rule resmi** | — (tidak ada) |
| **CWE terkait** | CWE-250 (Execution with Unnecessary Privileges) |

---

## 1. Penjelasan

### 1.1 Status Test Ini dan Hubungannya dengan MASTG-TEST-0254

Test ini berstatus **`placeholder`** — hanya tersedia satu kalimat catatan resmi. Namun kalimat tersebut sebenarnya **sudah pernah disinggung** di dokumen MASTG-TEST-0254 (§1.4) sebagai bagian dari klausul "Context Consideration"-nya:

> *"Also, consider if there are any privacy-preserving alternatives to the permissions used by the app."*

MASTG-TEST-0255 pada dasarnya **mengangkat poin ini menjadi test tersendiri** dengan fokus lebih sempit dan spesifik:

| | MASTG-TEST-0254 | MASTG-TEST-0255 *(dokumen ini)* |
|---|---|---|
| **Pertanyaan inti** | Apakah dangerous permission ini **proporsional** terhadap fitur yang ada? | Apakah fitur yang sama bisa dicapai **tanpa** dangerous permission ini sama sekali, lewat mekanisme alternatif yang disediakan platform? |
| **Kondisi FAIL** | Permission ada tapi fitur tidak ada/tidak jelas | Permission ada, fitur **memang ada dan legitimate**, tapi platform menyediakan cara mencapai fitur yang sama tanpa permission tersebut |

Dengan kata lain: MASTG-TEST-0254 menjawab "apakah permission ini masuk akal?", sedangkan MASTG-TEST-0255 menjawab "meski masuk akal, apakah ini benar-benar **cara paling minimal** untuk mencapainya?" — sebuah pertanyaan yang tetap relevan bahkan untuk permission yang **sudah lolos** evaluasi MASTG-TEST-0254.

### 1.2 Peta Lengkap Alternatif Privacy-Preserving per Kategori Permission

Karena tidak ada Steps/Evaluation resmi, dokumen ini merujuk pada **panduan resmi Android Developers** ("Minimize Permission Requests") yang secara eksplisit dirujuk di overview MASTG-TEST-0254 sebagai sumber utama pola-pola berikut. Ini adalah peta lengkap alternatif yang menjadi acuan evaluasi test ini:

| Permission Dangerous | Alternatif Privacy-Preserving | Mekanisme |
|---|---|---|
| `CAMERA` | Delegasi ke aplikasi kamera sistem | Intent `ACTION_IMAGE_CAPTURE` / `ACTION_VIDEO_CAPTURE` |
| `CAMERA` (untuk scan barcode/QR) | Tidak perlu akses kamera mentah | Google Code Scanner API / ML Kit Barcode Scanning API |
| `CAMERA` (untuk input kartu pembayaran) | Tidak perlu akses kamera mentah | Debit and Credit Card Recognition library (Google Play services) |
| `READ_EXTERNAL_STORAGE` / `READ_MEDIA_*` (memilih foto/video) | Tidak butuh runtime permission sama sekali | **Photo Picker** (`ActivityResultContracts.PickVisualMedia`) |
| `READ_EXTERNAL_STORAGE` (mengakses dokumen milik app lain) | Akses terbatas by-design | Storage Access Framework (`ACTION_OPEN_DOCUMENT`) |
| `READ_CONTACTS` (memilih satu/beberapa kontak) | Akses terbatas hanya ke kontak yang dipilih pengguna | **Contact Picker** Intent (`ACTION_PICK`) |
| `ACCESS_FINE_LOCATION` (kebutuhan sesaat, "cari di sekitar sini") | Tidak perlu izin lokasi berkelanjutan | Location Button / one-time location request |
| `ACCESS_FINE_LOCATION` (kebutuhan presisi rendah) | Cukup lokasi kasar | Gunakan `ACCESS_COARSE_LOCATION` alih-alih `ACCESS_FINE_LOCATION` |
| `ACCESS_FINE_LOCATION`/`ACCESS_COARSE_LOCATION` (untuk pairing perangkat Bluetooth) | Tidak perlu izin lokasi/Bluetooth admin sama sekali | **Companion Device Pairing API** |
| `READ_SMS` (verifikasi OTP) | Tidak perlu membaca seluruh kotak masuk SMS | **SMS Retriever API** atau SMS User Consent API |
| `READ_PHONE_STATE` (verifikasi nomor telepon) | Tidak perlu status telepon penuh | Digital Credentials API / Phone Number Hint library |
| `READ_PHONE_STATE` (filter panggilan spam) | Cukup lewat API screening resmi | `CallScreeningService` |
| `READ_PHONE_STATE` (menangani interupsi audio saat panggilan masuk) | Tidak perlu status telepon sama sekali | `AudioManager.OnAudioFocusChangeListener` |
| `CALL_PHONE` (menempatkan panggilan) | Delegasi ke aplikasi telepon sistem | Intent `ACTION_DIAL` (bukan `ACTION_CALL`) |
| Akses ID perangkat (IMEI, dst.) | Tidak perlu identifier permanen tingkat perangkat | Instance ID library / `UUID.randomUUID()` yang di-scope per-app |

### 1.3 Prinsip Inti: Intent-Based Delegation dan Scoped Picker API

Seluruh pola di atas berbagi **filosofi arsitektural yang sama**, yang dirangkum eksplisit oleh dokumentasi resmi Android:

> *"Use intent-based approaches, pickers, and scoped APIs rather than declaring broad permissions."*

Ada dua kategori mekanisme yang mendasari hampir seluruh alternatif ini:

1. **Delegasi lewat Intent ke komponen sistem** (`ACTION_IMAGE_CAPTURE`, `ACTION_DIAL`, `ACTION_PICK`): aplikasi **tidak pernah menyentuh** data/hardware sensitif secara langsung. Sistem operasi (lewat aplikasi kamera/telepon/kontak bawaan) yang menangani interaksi sensitif tersebut, dan aplikasi hanya menerima **hasil akhirnya** (URI foto, hasil pemilihan kontak) lewat callback `ActivityResult`. Karena aplikasi tidak pernah memegang akses langsung ke hardware/database sensitif, ia **tidak butuh permission** untuk itu sama sekali.
2. **Scoped Picker API** (Photo Picker, Storage Access Framework): pengguna secara eksplisit **memilih item spesifik** yang boleh diakses aplikasi (satu foto, satu dokumen), dan sistem hanya memberi akses **ke item yang dipilih tersebut** — bukan akses penuh ke seluruh galeri/penyimpanan. Ini prinsip *least privilege* yang diterapkan di level granularitas data, bukan hanya level kategori permission.

### 1.4 Mengapa Test Ini Signifikan Meski Fiturnya "Legitimate"

Ini nuansa penting yang membedakan test ini dari kesan pertama yang mungkin muncul. Sebuah aplikasi galeri foto yang meminta `READ_EXTERNAL_STORAGE`/`READ_MEDIA_IMAGES` untuk **fitur memilih foto profil** akan **lolos** MASTG-TEST-0254 (fitur ada, permission proporsional terhadap fitur tersebut) — namun tetap bisa **FAIL** di MASTG-TEST-0255, karena **Photo Picker** menyediakan cara mencapai persis fitur yang sama (memilih satu foto) **tanpa perlu runtime permission apa pun**. Perbedaan dampaknya nyata bagi pengguna: dengan Photo Picker, aplikasi **tidak pernah** melihat galeri penuh pengguna — hanya foto spesifik yang dipilih; dengan `READ_MEDIA_IMAGES` penuh, aplikasi **berpotensi** (secara teknis, meski mungkin tidak diniatkan) membaca seluruh koleksi foto pengguna.

### 1.5 Fondasi Akademik: Konsep "Over-Privilege" dalam Riset Keamanan Android

Konsep di balik test ini bukan hal baru — ia berakar dari riset akademik keamanan Android yang sudah matang selama lebih dari satu dekade. Dua karya rujukan klasik di bidang ini:

- **Stowaway** (Felt et al.) — tool riset yang membangun **peta permission-ke-API** (permission map): daftar API mana yang membutuhkan permission mana. Dengan menganalisis reachability kode aplikasi terhadap API tersebut, Stowaway dapat menentukan secara otomatis apakah suatu aplikasi **over-privileged** — memiliki permission yang API-nya tidak pernah benar-benar dipanggil kode.
- **PScout** — pendekatan serupa yang mengotomatisasi ekstraksi peta permission-API langsung dari source code framework Android, menghasilkan dataset yang lebih akurat dan terkini dibanding anotasi manual.

Kedua riset ini menjawab pertanyaan yang **sedikit berbeda** dari MASTG-TEST-0255 (mereka fokus pada "permission tidak dipakai sama sekali", bukan "permission dipakai tapi ada alternatif lebih minimal") — namun **metodologi reachability analysis** yang mereka kembangkan tetap sangat relevan sebagai dasar teknis untuk mengimplementasikan pengujian test ini secara otomatis (lihat §3.4).

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | Fungsi |
|---|---|
| **jadx** | Dekompilasi untuk menelusuri implementasi fitur terkait setiap dangerous permission |
| **aapt/adb** | Ekstraksi daftar permission (sama seperti MASTG-TEST-0254) |
| **grep / ripgrep** | Pencarian pola API alternatif (Photo Picker, Intent delegation) vs API langsung |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **APKPerm** | Tool modern (Python) untuk analisis statis referensi permission dalam APK terdekompilasi — dapat dipakai sebagai basis untuk membangun pemetaan permission-ke-lokasi-kode |
| **CodeQL** | Menelusuri **API spesifik** yang dipanggil terkait setiap permission — kunci untuk membedakan "memakai API kamera langsung" vs "memanggil Intent `ACTION_IMAGE_CAPTURE`" |
| **MobSF** | Laporan Manifest Analysis dasar sebagai titik awal identifikasi permission yang perlu ditelusuri lebih lanjut |
| **Android Studio Lint** | Beberapa lint check bawaan Android Studio (kategori Correctness/Usability) dapat menandai pemakaian API storage/kontak lama yang punya alternatif lebih modern |

### 2.3 Prasyarat Lingkungan

- **Tidak butuh device/root** untuk analisis statis inti.
- **Pemahaman fitur aplikasi tetap krusial** — sama seperti MASTG-TEST-0254, penguji perlu tahu **untuk apa** setiap dangerous permission dipakai sebelum bisa menilai apakah ada alternatif yang lebih minimal untuk kasus penggunaan spesifik tersebut.
- **Referensi ke peta alternatif (§1.2) sebagai checklist** — jalankan pengecekan sistematis untuk setiap dangerous permission yang ditemukan di MASTG-TEST-0254.

---

## 3. Cara Pengujian

Karena tidak ada langkah resmi (status placeholder), metodologi berikut disusun berdasarkan elaborasi catatan resmi dan panduan Android Developers yang dirujuk silang dari MASTG-TEST-0254.

### 3.1 Langkah Umum

1. Ambil daftar dangerous permission dari hasil **MASTG-TEST-0254**.
2. Untuk setiap permission, telusuri **lokasi kode** yang memakainya (MASTG-TECH-0014/0023).
3. Identifikasi **API spesifik** yang dipanggil pada lokasi tersebut.
4. Bandingkan dengan peta alternatif (§1.2) — apakah API langsung (butuh permission) atau API delegasi/scoped (tidak butuh permission) yang dipakai?

### 3.2 Metode A — grep/ripgrep untuk Pola API Langsung vs Alternatif

```bash
D=./decompiled/sources

# Kamera: cari pemakaian API langsung vs delegasi Intent
echo "=== Pemakaian API Camera2 langsung (butuh permission CAMERA) ==="
rg -l 'android\.hardware\.camera2\.CameraManager|Camera\.open\(' $D

echo "=== Delegasi via Intent (TIDAK butuh permission CAMERA) ==="
rg -l 'MediaStore\.ACTION_IMAGE_CAPTURE|MediaStore\.ACTION_VIDEO_CAPTURE' $D

# Storage: Photo Picker vs akses langsung
echo "=== Akses storage langsung ==="
rg -l 'MediaStore\.Images\.Media\.query|ContentResolver.*EXTERNAL_CONTENT_URI' $D

echo "=== Photo Picker (TIDAK butuh runtime permission) ==="
rg -l 'ActivityResultContracts\.PickVisualMedia|ACTION_PICK_IMAGES' $D

# Kontak: Contact Picker vs query langsung
echo "=== Query ContactsContract langsung (butuh READ_CONTACTS) ==="
rg -l 'ContactsContract\.Contacts\.CONTENT_URI' $D

echo "=== Contact Picker Intent (akses terbatas ke kontak dipilih) ==="
rg -l 'Intent\.ACTION_PICK.*Contacts\.CONTENT_URI' $D

# Telepon: ACTION_DIAL vs ACTION_CALL
echo "=== ACTION_CALL langsung (butuh CALL_PHONE) ==="
rg -l 'Intent\.ACTION_CALL' $D

echo "=== ACTION_DIAL (TIDAK butuh CALL_PHONE) ==="
rg -l 'Intent\.ACTION_DIAL' $D
```

### 3.3 Metode B — Korelasi Permission-ke-API dengan CodeQL

```ql
import java

class DirectCameraApiUsage extends MethodAccess {
  DirectCameraApiUsage() {
    this.getMethod().getDeclaringType().hasQualifiedName("android.hardware.camera2", "CameraManager") and
    this.getMethod().hasName("openCamera")
  }
}

class ImageCaptureIntentUsage extends FieldAccess {
  ImageCaptureIntentUsage() {
    this.getField().hasName("ACTION_IMAGE_CAPTURE")
  }
}

from DirectCameraApiUsage direct
select direct, "Pemakaian CameraManager.openCamera() langsung ditemukan — pertimbangkan ACTION_IMAGE_CAPTURE bila kasus penggunaan hanya mengambil satu foto/video"
```

Query serupa dapat dibangun untuk setiap pasangan API-langsung vs API-alternatif pada tabel §1.2, memberi cakupan sistematis dan dapat diulang untuk audit berkelanjutan.

### 3.4 Metode C — Reachability Analysis (Terinspirasi Stowaway/PScout)

Terapkan pendekatan akademik klasik: bangun peta permission-ke-API, lalu periksa **apakah API yang sesuai kategori permission tersebut benar-benar dipanggil**, dan **API mana persisnya** (langsung vs delegasi):

```python
PERMISSION_API_MAP = {
    "android.permission.CAMERA": {
        "direct": ["android.hardware.camera2.CameraManager", "android.hardware.Camera"],
        "alternative": ["MediaStore.ACTION_IMAGE_CAPTURE", "MediaStore.ACTION_VIDEO_CAPTURE"]
    },
    "android.permission.READ_CONTACTS": {
        "direct": ["ContactsContract.Contacts.CONTENT_URI query"],
        "alternative": ["Intent.ACTION_PICK + Contacts.CONTENT_URI"]
    },
    "android.permission.CALL_PHONE": {
        "direct": ["Intent.ACTION_CALL"],
        "alternative": ["Intent.ACTION_DIAL"]
    },
    # ... lengkapi sesuai tabel §1.2
}

def evaluate_minimization(declared_permissions, code_api_usage):
    findings = []
    for perm in declared_permissions:
        mapping = PERMISSION_API_MAP.get(perm)
        if not mapping:
            continue
        uses_direct = any(api in code_api_usage for api in mapping["direct"])
        uses_alternative = any(api in code_api_usage for api in mapping["alternative"])
        if uses_direct and not uses_alternative:
            findings.append(f"[KANDIDAT FAIL] {perm}: memakai API langsung, alternatif tersedia tapi tidak dipakai")
    return findings
```

### 3.5 Metode D — Verifikasi Manual terhadap Kasus Penggunaan Spesifik

Untuk setiap kandidat temuan dari Metode A-C, verifikasi manual apakah alternatif **benar-benar cocok** dengan kasus penggunaan aplikasi — tidak semua kasus bisa memakai alternatif:

```
Pertanyaan verifikasi:
1. Apakah aplikasi hanya butuh mengambil SATU foto sesaat? -> ACTION_IMAGE_CAPTURE cocok
2. Apakah aplikasi butuh preview kamera real-time/custom UI (mis. AR, filter)? -> CAMERA permission langsung tetap diperlukan, TIDAK FAIL
3. Apakah aplikasi hanya butuh MEMILIH kontak sesekali? -> Contact Picker cocok
4. Apakah aplikasi butuh SINKRONISASI kontak berkelanjutan (mis. aplikasi manajemen kontak)? -> READ_CONTACTS penuh tetap diperlukan, TIDAK FAIL
```

Ini langkah krusial — Metode A-C hanya menghasilkan **kandidat**, bukan kesimpulan final, karena beberapa kasus penggunaan **secara legitimate** membutuhkan akses penuh yang tidak dapat digantikan alternatif scoped/delegated.

### 3.6 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Kelebihan | Kapan dipakai |
|---|---|---|---|
| **A** | grep pola API | Cepat, langsung menunjukkan bukti tekstual | Baseline awal |
| **B** | CodeQL | Presisi tinggi, dapat diulang sebagai gate CI/CD | Codebase besar |
| **C** | Reachability map (Python) | Sistematis, mencakup seluruh kategori permission sekaligus | Audit menyeluruh terstruktur |
| **D** | Verifikasi manual kasus pakai | Menyaring false positive dari kasus legitimate | **Wajib** sebelum kesimpulan final |

**Kombinasi minimum yang aku rekomendasikan:** **A/C (deteksi kandidat sistematis) → D (verifikasi manual kasus pakai) → korelasi dengan hasil MASTG-TEST-0254**.

---

### 3.7 Kriteria Evaluasi: Positive Case & Negative Case

Karena tidak ada klausul Evaluation resmi (status placeholder), kriteria berikut diturunkan dari catatan resmi dan prinsip minimisasi permission Android.

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi |
|---|---|
| F1 | Dangerous permission dipakai lewat **API langsung** padahal kasus penggunaan aplikasi (dikonfirmasi manual, Metode D) **cocok sepenuhnya** dengan yang bisa dicapai lewat alternatif privacy-preserving (§1.2) |
| F2 | Aplikasi meminta `READ_EXTERNAL_STORAGE`/`READ_MEDIA_IMAGES` penuh hanya untuk fitur **memilih satu/beberapa item media**, padahal Photo Picker tersedia dan cukup |
| F3 | Aplikasi memakai `Intent.ACTION_CALL` (butuh `CALL_PHONE`) padahal fitur hanya **menempatkan panggilan biasa** tanpa kebutuhan otomatisasi tanpa interaksi pengguna |
| F4 | Aplikasi query `ContactsContract` penuh untuk fitur **memilih satu kontak** (mis. "bagikan ke kontak"), padahal Contact Picker mencukupi |

**Contoh bukti (ilustratif — MASTG belum menyediakan demo resmi untuk test ini):**

```bash
$ rg -n 'Intent\.ACTION_CALL' ./decompiled/sources/com/example/target/ui/ContactDetailActivity.java
44:    val callIntent = Intent(Intent.ACTION_CALL, Uri.parse("tel:$phoneNumber"))
45:    startActivity(callIntent)
```

```xml
<uses-permission android:name="android.permission.CALL_PHONE"/>
```

Interpretasi: fitur "hubungi kontak ini" memakai `ACTION_CALL` yang langsung menempatkan panggilan tanpa konfirmasi pengguna di aplikasi telepon — padahal fitur ini (menghubungi nomor dari detail kontak) adalah kasus klasik yang **sepenuhnya bisa** digantikan `ACTION_DIAL` (membuka aplikasi telepon dengan nomor sudah terisi, pengguna tinggal menekan tombol panggil). **FAIL** — permission `CALL_PHONE` tidak minimal untuk kasus penggunaan ini.

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi |
|---|---|
| P1 | Seluruh dangerous permission yang dideklarasikan memakai API **langsung** karena kasus penggunaannya **memang membutuhkan** akses penuh (terverifikasi manual, bukan bisa digantikan alternatif) |
| P2 | Aplikasi sudah memakai alternatif privacy-preserving (Photo Picker, Contact Picker, `ACTION_DIAL`, dsb.) untuk seluruh kasus penggunaan yang cocok |
| P3 | Tidak ada dangerous permission yang dideklarasikan sama sekali (permission yang ada, bila ada, sudah minimal) |

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Ini bukan larangan mutlak memakai API langsung** — sesuai §3.5, banyak kasus penggunaan (preview kamera real-time, sinkronisasi kontak penuh, panggilan otomatis dari sistem VoIP) secara legitimate membutuhkan akses penuh yang tidak tergantikan. Fokus evaluasi pada **kecocokan** kasus penggunaan dengan kapabilitas alternatif, bukan larangan API langsung secara umum.

2. **Verifikasi manual (Metode D) adalah langkah yang tidak boleh dilewatkan** — deteksi otomatis (grep/CodeQL) hanya menghasilkan kandidat; keputusan akhir menuntut pemahaman kasus penggunaan spesifik aplikasi.

3. **Photo Picker adalah kasus paling umum dan paling mudah diverifikasi** — karena kemunculannya relatif baru (Android 13+) dan bawaan sepenuhnya dari Jetpack/AndroidX, ketiadaan pemakaiannya pada aplikasi yang jelas-jelas hanya butuh "pilih satu foto" adalah sinyal FAIL yang kuat dan mudah dikonfirmasi.

4. **Korelasikan selalu dengan MASTG-TEST-0254** — kedua test saling melengkapi: 0254 menjawab "apakah permission ini masuk akal", 0255 menjawab "apakah ini caranya yang paling minimal".

5. **Severity umumnya lebih rendah dibanding MASTG-TEST-0254** — ini soal *hardening* privasi tambahan (mengurangi permukaan akses meski permission-nya sendiri legitimate), bukan penghapusan permission yang sama sekali tidak dibutuhkan.

6. **Dokumentasikan:** daftar dangerous permission beserta API spesifik yang dipakai (langsung vs alternatif), kasus penggunaan yang diverifikasi manual, dan rekomendasi migrasi ke alternatif spesifik per temuan.

---

## 4. Rekomendasi Perbaikan

### 4.1 Migrasi ke Photo Picker

```kotlin
val pickMedia = registerForActivityResult(ActivityResultContracts.PickVisualMedia()) { uri ->
    uri?.let { /* pakai uri terpilih, TANPA perlu READ_MEDIA_IMAGES */ }
}
pickMedia.launch(PickVisualMediaRequest(ActivityResultContracts.PickVisualMedia.ImageOnly))
```

### 4.2 Migrasi ke Contact Picker

```kotlin
val pickContact = registerForActivityResult(ActivityResultContracts.PickContact()) { uri ->
    uri?.let { /* pakai uri kontak terpilih, TANPA perlu READ_CONTACTS penuh */ }
}
pickContact.launch()
```

### 4.3 Ganti `ACTION_CALL` dengan `ACTION_DIAL` Bila Memungkinkan

```kotlin
// SEBELUM: butuh CALL_PHONE, langsung menelepon tanpa konfirmasi
val callIntent = Intent(Intent.ACTION_CALL, Uri.parse("tel:$phoneNumber"))

// SESUDAH: tidak butuh permission, pengguna konfirmasi lewat aplikasi telepon
val dialIntent = Intent(Intent.ACTION_DIAL, Uri.parse("tel:$phoneNumber"))
```

### 4.4 Checklist Remediasi

- [ ] Setiap dangerous permission dari hasil MASTG-TEST-0254 sudah dipetakan ke API spesifik yang memakainya
- [ ] Setiap pemakaian API langsung sudah diverifikasi manual — apakah kasus penggunaannya benar-benar butuh akses penuh?
- [ ] Fitur pemilihan media bertransisi ke Photo Picker
- [ ] Fitur pemilihan kontak bertransisi ke Contact Picker
- [ ] Fitur menempatkan panggilan yang tidak butuh otomatisasi penuh bertransisi ke `ACTION_DIAL`
- [ ] Permission yang berhasil dihapus setelah migrasi sudah dikonfirmasi tidak lagi dideklarasikan di manifest
- [ ] **Verifikasi ulang:** jalankan kembali MASTG-TEST-0255 setelah setiap migrasi ke alternatif

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0255: Permission Requests Not Minimized](https://mas.owasp.org/MASTG/tests/android/MASVS-PRIVACY/MASTG-TEST-0255/)
- [MASTG-TEST-0254: Dangerous App Permissions](https://mas.owasp.org/MASTG/tests/android/MASVS-PRIVACY/MASTG-TEST-0254/)
- [MASWE-0066: Inadequate Permission Management](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0066/)
- [OWASP Mobile Top 10 2024 — M6: Inadequate Privacy Controls](https://owasp.org/www-project-mobile-top-10/2023-risks/m6-inadequate-privacy-controls)

### 5.2 Dokumentasi Resmi Android

- [Android Developers — Minimize Permission Requests](https://developer.android.com/privacy-and-security/minimize-permission-requests)
- [Android Developers — Photo Picker](https://developer.android.com/training/data-storage/shared/photopicker)
- [Android Developers — Storage Access Framework](https://developer.android.com/guide/topics/providers/document-provider)
- [Android Developers — Companion Device Pairing](https://developer.android.com/guide/topics/connectivity/companion-device-pairing)
- [Google — SMS Retriever API](https://developers.google.com/identity/sms-retriever/overview)
- [Google — Phone Number Hint](https://developers.google.com/identity/phone-number-hint/android)
- [Android Developers — `CallScreeningService`](https://developer.android.com/reference/android/telecom/CallScreeningService)
- [Google — Debit and Credit Card Recognition](https://developers.google.com/pay/payment-card-recognition/debit-credit-card-recognition)

### 5.3 Riset Akademik

- [Felt et al. — Android Permissions Demystified (Stowaway)](https://people.eecs.berkeley.edu/~dawnsong/papers/2011%20Android%20permissions%20demystified.pdf)
- [PScout — Analyzing the Android Permission Specification](https://arxiv.org/pdf/1311.4201)
- [CWE-250: Execution with Unnecessary Privileges](https://cwe.mitre.org/data/definitions/250.html)

### 5.4 Dokumentasi Tools

- [APKPerm — Static permission reference analyzer](https://github.com/INCT-DD/APKPerm)
- [CodeQL — Documentation](https://codeql.github.com/docs/)
- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [MobSF — Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)

---

*Dokumen ini disusun terutama dari elaborasi catatan resmi singkat MASTG-TEST-0255 (status placeholder), dilengkapi panduan resmi Android Developers "Minimize Permission Requests" secara ekstensif dan fondasi riset akademik klasik (Stowaway, PScout) tentang deteksi over-privilege. Nuansa terpenting: test ini melengkapi MASTG-TEST-0254 dengan pertanyaan yang lebih tajam — bukan "apakah permission ini masuk akal", melainkan "apakah ini cara paling minimal untuk mencapai fitur yang sama", dan verifikasi manual terhadap kasus penggunaan spesifik tetap menjadi langkah yang tidak tergantikan otomasi sepenuhnya.*
