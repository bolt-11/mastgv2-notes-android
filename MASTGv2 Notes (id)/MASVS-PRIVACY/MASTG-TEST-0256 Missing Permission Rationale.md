# MASTG-TEST-0256 Missing Permission Rationale

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0256 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-PRIVACY |
| **Weakness** | MASWE-0066 — *Inadequate Permission Management* (sama seperti MASTG-TEST-0254/0255) |
| **Status resmi MASTG** | **`placeholder`** — belum ada Overview/Steps/Evaluation lengkap |
| **Catatan resmi (satu-satunya konten yang tersedia)** | *"This test checks if the app does not provide a rationale for requesting permissions."* — dengan dua rujukan resmi Android Developers |
| **Profile** | **P (Privacy) saja** |
| **Knowledge** | MASTG-KNOW-0017 *(rujukan bermasalah, konsisten dengan catatan di dokumen MASTG-TEST-0254/0255)* |
| **Test terkait** | **MASTG-TEST-0254** (apakah permission-nya proporsional), **MASTG-TEST-0255** (apakah permission-nya paling minimal) — test ini melengkapi keduanya dengan pertanyaan ketiga: **apakah pengguna diberi tahu MENGAPA permission ini diminta?** |
| **Demo terkait** | — (tidak ada) |
| **Rule resmi** | — (tidak ada) |
| **CWE terkait** | CWE-1021 (Improper Restriction of Rendered UI Layers or Frames) — kurang tepat; lebih relevan sebagai *usable security/transparency gap*, tidak selalu terpetakan bersih ke CWE teknis |

---

## 1. Penjelasan

### 1.1 Status Test Ini dan Posisinya dalam Trio MASTG-TEST-0254/0255/0256

Test ini berstatus **`placeholder`**, namun catatan resminya merujuk dua halaman dokumentasi Android Developers yang sangat spesifik dan actionable. Bersama MASTG-TEST-0254 dan MASTG-TEST-0255, ketiganya membentuk **rangkaian evaluasi permission privasi yang lengkap**:

| Test | Pertanyaan Inti |
|---|---|
| **MASTG-TEST-0254** | Apakah permission ini **proporsional** terhadap fitur yang ada? |
| **MASTG-TEST-0255** | Apakah ini cara **paling minimal** untuk mencapai fitur tersebut? |
| **MASTG-TEST-0256** *(dokumen ini)* | Apakah pengguna diberi **penjelasan yang jelas** tentang mengapa permission ini dibutuhkan, **sebelum dan sesudah** permintaan dilakukan? |

Sebuah permission bisa saja **proporsional** (lolos 0254) dan **sudah paling minimal** (lolos 0255), namun tetap **FAIL** di test ini bila aplikasi tidak pernah menjelaskan kepada pengguna mengapa ia dibutuhkan — pengguna dipaksa menghadapi dialog sistem generik ("Izinkan Aplikasi X mengakses Lokasi?") tanpa konteks apa pun tentang **fitur spesifik** yang membutuhkannya.

### 1.2 Dua Mekanisme Rationale yang Berbeda dan Saling Melengkapi

Catatan resmi merujuk **dua** halaman Android Developers yang menjelaskan **dua mekanisme rationale yang berbeda**, beroperasi di titik waktu yang berbeda dalam siklus hidup interaksi pengguna dengan permission:

| Mekanisme | Kapan Ditampilkan | Siapa yang Menampilkan |
|---|---|---|
| **In-app rationale** (`shouldShowRequestPermissionRationale`) | **Sebelum** dialog permission sistem muncul (khususnya setelah penolakan pertama) | UI kustom milik aplikasi sendiri |
| **Privacy Dashboard rationale** (`VIEW_PERMISSION_USAGE`) | **Setelah** permission diberikan — saat pengguna meninjau riwayat akses lewat Privacy Dashboard sistem (Android 12+) | Activity kustom aplikasi, ditampilkan **di dalam** UI sistem Privacy Dashboard |

Keduanya menjawab kebutuhan transparansi pada **fase yang berbeda** — satu di titik keputusan (apakah memberi izin atau tidak), satu lagi di titik audit (pengguna meninjau kembali mengapa suatu aplikasi pernah mengakses data sensitifnya).

### 1.3 Mekanisme Pertama: In-App Rationale dengan `shouldShowRequestPermissionRationale()`

Android menyediakan API khusus untuk menentukan **kapan** UI edukasi/rationale sebaiknya ditampilkan:

```kotlin
ActivityCompat.shouldShowRequestPermissionRationale(
    this, Manifest.permission.REQUESTED_PERMISSION)
```

API ini mengembalikan `true` **secara spesifik** ketika pengguna **pernah menolak** permintaan permission ini sebelumnya, namun **belum** memilih "Jangan tanya lagi" — sinyal bahwa pengguna mungkin ragu, dan inilah **momen paling tepat** untuk menjelaskan manfaatnya sebelum meminta lagi. Dokumentasi resmi memberi alur keputusan lengkap:

```kotlin
when {
    ContextCompat.checkSelfPermission(context, permission) == PackageManager.PERMISSION_GRANTED -> {
        // Permission sudah diberikan, langsung pakai API terkait
    }
    ActivityCompat.shouldShowRequestPermissionRationale(this, permission) -> {
        // TAMPILKAN UI edukasi: jelaskan MENGAPA fitur ini butuh permission,
        // apa yang tidak akan berfungsi bila ditolak, sertakan tombol "batal"/"tidak, terima kasih"
        showInContextUI(...)
    }
    else -> {
        // Minta langsung tanpa rationale tambahan (permintaan pertama kali)
        requestPermissionLauncher.launch(permission)
    }
}
```

Praktik terbaik resmi untuk isi UI rationale ini:

1. **Jelaskan secara spesifik** mengapa fitur tertentu butuh permission ini, dan apa yang tidak berfungsi bila ditolak.
2. **Sediakan jalan keluar** — tombol "batal"/"tidak, terima kasih" agar pengguna bisa tetap memakai aplikasi tanpa memberi izin.
3. **Konteks yang tepat** — minta izin **tepat saat** pengguna mencoba memakai fitur terkait, bukan di awal (mis. saat `onCreate` aplikasi pertama dibuka).
4. **Spesifik tentang data** — jelaskan data apa yang diakses dan untuk tujuan apa.
5. **Jangan berasumsi dari perilaku sebelumnya** — selalu minta permission setiap kali dibutuhkan, jangan mengasumsikan status dari sesi sebelumnya.

### 1.4 Mekanisme Kedua: Rationale di Privacy Dashboard (Android 12+)

Ini mekanisme yang **kurang dikenal** namun signifikan untuk transparansi jangka panjang. Sejak Android 12, sistem menyediakan **Privacy Dashboard** — layar terpusat yang menunjukkan **riwayat** aplikasi mana saja yang mengakses lokasi, kamera, dan mikrofon. Android memungkinkan developer menyediakan **penjelasan kontekstual** yang muncul **langsung di dalam** dashboard sistem ini (bukan di UI aplikasi sendiri), lewat mekanisme berikut:

```xml
<activity android:name=".DataAccessRationaleActivity"
          android:permission="android.permission.START_VIEW_PERMISSION_USAGE"
          android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.VIEW_PERMISSION_USAGE" />
        <action android:name="android.intent.action.VIEW_PERMISSION_USAGE_FOR_PERIOD" />
        <category android:name="android.intent.category.DEFAULT" />
    </intent-filter>
</activity>
```

Dua action berbeda memicu konteks tampilan yang berbeda:

- **`VIEW_PERMISSION_USAGE`** — memicu ikon info di halaman izin aplikasi (berlaku untuk seluruh runtime permission), membawa extra `EXTRA_PERMISSION_GROUP_NAME`.
- **`VIEW_PERMISSION_USAGE_FOR_PERIOD`** — memicu ikon info **langsung di layar Privacy Dashboard**, membawa extra tambahan `EXTRA_ATTRIBUTION_TAGS`, `EXTRA_START_TIME`, `EXTRA_END_TIME` — memungkinkan aplikasi menjelaskan **akses spesifik pada periode waktu tertentu** (mis. "Aplikasi mengakses lokasi Anda pukul 14:00-14:05 untuk memperbarui perkiraan waktu tiba pesanan").

Poin arsitektural penting: `Activity` ini **wajib** `android:exported="true"` (karena dipanggil sistem dari proses terpisah — Privacy Dashboard adalah komponen sistem, bukan bagian dari proses aplikasi), namun dilindungi permission sistem `START_VIEW_PERMISSION_USAGE` yang **hanya bisa dipegang komponen sistem** — sehingga meski `exported="true"`, ia **tidak bisa dipicu sembarang aplikasi pihak ketiga**, hanya oleh Privacy Dashboard resmi. Ini pola exported-tapi-aman yang relevan untuk dikorelasikan dengan pengujian *exported components* di kategori MASVS-PLATFORM lain dalam seri riset ini — jangan langsung menandai `exported="true"` di sini sebagai temuan tanpa memeriksa proteksi permission-nya terlebih dahulu.

### 1.5 Mengapa Rationale Penting: Bukan Sekadar Formalitas UX

Dokumentasi resmi menyimpulkan alasan mendasarnya secara langsung:

> *"Research shows that users are much more comfortable with permission requests when they understand why the app needs them."*

Ini bukan murni soal kenyamanan UX, tapi berdampak langsung pada **kualitas keputusan privasi pengguna**. Dialog sistem default hanya menyatakan **API mana** yang diminta ("Aplikasi X ingin mengakses lokasi perangkat Anda") — tanpa konteks **fitur spesifik** yang membutuhkannya. Pengguna yang tidak paham konteks cenderung membuat keputusan berdasarkan **kebiasaan** (selalu menekan "Izinkan" tanpa membaca, atau selalu menolak karena curiga) alih-alih **pemahaman nyata** — kedua pola ini sama-sama tidak ideal dari perspektif privasi yang sehat. Rationale yang baik menjembatani celah informasi ini, memungkinkan **consent yang benar-benar informed** (persetujuan yang benar-benar dipahami), bukan sekadar formalitas klik.

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | Fungsi |
|---|---|
| **jadx** | Dekompilasi untuk mencari pola `shouldShowRequestPermissionRationale` dan implementasi Activity `VIEW_PERMISSION_USAGE` |
| **grep / ripgrep** | Pencarian pola API rationale di kode dan manifest |
| **apktool/jadx (manifest)** | Ekstraksi `AndroidManifest.xml` untuk memeriksa keberadaan Activity Privacy Dashboard rationale |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **Device/emulator Android 12+** | Wajib untuk verifikasi dinamis mekanisme Privacy Dashboard (§1.4), karena fitur ini tidak ada di versi lebih lama |
| **UI Automator / Espresso** | Menguji alur UI secara otomatis — memicu penolakan permission pertama kali, lalu memverifikasi apakah UI edukasi muncul sebelum permintaan kedua |
| **MobSF** | Kadang menampilkan daftar permission beserta ada/tidaknya string terkait penjelasan di resource aplikasi (heuristik kasar) |
| **Manual UX walkthrough** | Karena ini pada dasarnya evaluasi kualitas komunikasi ke pengguna, penelusuran manual alur aplikasi sebagai pengguna sungguhan tetap menjadi metode paling andal |

### 2.3 Prasyarat Lingkungan

- **Tidak butuh device untuk analisis statis dasar** (pencarian pola API/manifest).
- **Butuh device/emulator untuk verifikasi dinamis lengkap** — terutama untuk mensimulasikan alur "tolak lalu minta lagi" yang memicu `shouldShowRequestPermissionRationale() = true`.
- **Idealnya device Android 12+** untuk menguji mekanisme Privacy Dashboard (§1.4).

---

## 3. Cara Pengujian

Karena tidak ada langkah resmi (status placeholder), metodologi berikut disusun berdasarkan elaborasi kedua halaman Android Developers yang dirujuk langsung oleh catatan resmi.

### 3.1 Langkah Umum

1. Ambil daftar dangerous permission dari hasil **MASTG-TEST-0254**.
2. Untuk setiap permission, telusuri kode di sekitar pemanggilan `requestPermissionLauncher.launch()`/`ActivityCompat.requestPermissions()`.
3. Periksa apakah ada pemanggilan `shouldShowRequestPermissionRationale()` yang **diikuti** tampilan UI edukasi sebelum permintaan aktual.
4. Periksa manifest untuk keberadaan Activity dengan intent-filter `VIEW_PERMISSION_USAGE`/`VIEW_PERMISSION_USAGE_FOR_PERIOD`.
5. Verifikasi dinamis: picu alur penolakan pertama, amati apakah UI edukasi benar-benar muncul sebelum permintaan kedua.

### 3.2 Metode A — grep/ripgrep untuk Mekanisme In-App Rationale

```bash
D=./decompiled/sources

# Cari pemanggilan API rationale
rg -n 'shouldShowRequestPermissionRationale' $D

# Untuk setiap kemunculan, periksa apakah diikuti tampilan dialog/UI edukasi (bukan langsung request lagi)
rg -n -A15 'shouldShowRequestPermissionRationale' $D | grep -i "AlertDialog\|showInContextUI\|DialogFragment\|Snackbar"

# Cari pemanggilan requestPermissions TANPA didahului pengecekan rationale sama sekali
rg -l 'requestPermissions\(|ActivityResultContracts\.RequestPermission' $D > files_requesting_permission.txt
for f in $(cat files_requesting_permission.txt); do
    if ! grep -q "shouldShowRequestPermissionRationale" "$f"; then
        echo "[!] $f meminta permission TANPA pemeriksaan rationale sama sekali"
    fi
done
```

### 3.3 Metode B — Pemeriksaan Manifest untuk Privacy Dashboard Rationale

```bash
jadx --no-src -d ./out target-app.apk
grep -A5 "VIEW_PERMISSION_USAGE" ./out/resources/AndroidManifest.xml
grep -B3 "START_VIEW_PERMISSION_USAGE" ./out/resources/AndroidManifest.xml
```

Bila tidak ditemukan sama sekali, aplikasi **tidak menyediakan** penjelasan kontekstual di Privacy Dashboard sistem — kandidat temuan untuk mekanisme kedua (§1.4).

### 3.4 Metode C — CodeQL (Korelasi Permintaan Permission dengan Pengecekan Rationale)

```ql
import java

class PermissionRequestCall extends MethodAccess {
  PermissionRequestCall() {
    this.getMethod().hasName(["requestPermissions", "launch"]) and
    exists(this.getAnArgument().getType().(RefType).getASupertype*() |
      it.hasQualifiedName("java.lang", "String"))
  }
}

class RationaleCheckCall extends MethodAccess {
  RationaleCheckCall() {
    this.getMethod().hasName("shouldShowRequestPermissionRationale")
  }
}

from PermissionRequestCall req
where not exists(RationaleCheckCall check | check.getEnclosingCallable() = req.getEnclosingCallable())
select req, "Permintaan permission ditemukan tanpa pemeriksaan shouldShowRequestPermissionRationale pada method yang sama"
```

### 3.5 Metode D — Verifikasi Dinamis Alur Penolakan-Permintaan Ulang

```bash
# 1. Install aplikasi, jalankan, picu fitur yang butuh dangerous permission, TOLAK permintaan
adb shell pm grant/revoke tidak relevan di sini -- lakukan penolakan lewat UI langsung

# 2. Picu fitur yang sama LAGI
# Amati secara manual: apakah muncul UI edukasi/rationale SEBELUM dialog sistem kedua muncul,
# atau langsung menampilkan dialog sistem generik lagi tanpa konteks tambahan?
```

```bash
# Verifikasi status permission via adb untuk memastikan state penolakan tercatat
adb shell dumpsys package com.target.app | grep -A3 "runtime permissions"
```

### 3.6 Metode E — Uji Privacy Dashboard Secara Langsung (Android 12+)

```bash
# Setelah aplikasi diberi salah satu dari lokasi/kamera/mikrofon
# Buka Privacy Dashboard sistem secara manual:
adb shell am start -a android.settings.PRIVACY_CONTROLS_SETTINGS
```

Navigasi manual ke riwayat akses aplikasi target, periksa apakah muncul **ikon info** yang bisa diklik untuk melihat penjelasan tambahan dari aplikasi (indikasi mekanisme §1.4 aktif dan berfungsi).

### 3.7 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Mekanisme yang diuji | Kapan dipakai |
|---|---|---|---|
| **A** | grep | In-app rationale | Baseline statis untuk mekanisme pertama |
| **B** | grep manifest | Privacy Dashboard rationale | Baseline statis untuk mekanisme kedua |
| **C** | CodeQL | In-app rationale (korelasi presisi) | Codebase besar |
| **D** | Verifikasi dinamis manual | In-app rationale (perilaku nyata) | Konfirmasi UX sesungguhnya |
| **E** | Privacy Dashboard langsung | Privacy Dashboard rationale (perilaku nyata) | Konfirmasi UX sesungguhnya, device Android 12+ |

**Kombinasi minimum yang aku rekomendasikan:** **A+B (baseline statis kedua mekanisme) → D+E (konfirmasi dinamis nyata)** — karena ini pada dasarnya evaluasi kualitas komunikasi ke pengguna, konfirmasi dinamis/manual jauh lebih meyakinkan dibanding kesimpulan statis semata.

---

### 3.8 Kriteria Evaluasi: Positive Case & Negative Case

Karena tidak ada klausul Evaluation resmi (status placeholder), kriteria berikut diturunkan dari kedua panduan resmi yang dirujuk.

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi |
|---|---|
| F1 | Aplikasi meminta dangerous permission **tanpa** pemanggilan `shouldShowRequestPermissionRationale()` sama sekali di alur kodenya |
| F2 | `shouldShowRequestPermissionRationale()` dipanggil, tapi hasilnya **tidak diikuti** tampilan UI edukasi apa pun — kode langsung meminta ulang tanpa penjelasan tambahan |
| F3 | Verifikasi dinamis (Metode D) mengonfirmasi setelah penolakan pertama, permintaan kedua muncul **tanpa** konteks tambahan apa pun dari aplikasi |
| F4 | Tidak ditemukan Activity dengan intent-filter `VIEW_PERMISSION_USAGE`/`VIEW_PERMISSION_USAGE_FOR_PERIOD`, sehingga Privacy Dashboard sistem tidak menampilkan penjelasan kontekstual apa pun untuk aplikasi ini |

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi |
|---|---|
| P1 | Aplikasi mengimplementasikan alur `shouldShowRequestPermissionRationale()` sesuai pola resmi, dengan UI edukasi yang jelas dan menyediakan opsi "batal" |
| P2 | Aplikasi menyediakan Activity rationale untuk Privacy Dashboard (§1.4), memberi konteks tambahan yang terlihat di sistem |
| P3 | Verifikasi dinamis (Metode D/E) mengonfirmasi kedua mekanisme benar-benar berfungsi dan tampil sesuai desain |
| P4 | Aplikasi **tidak memiliki** dangerous permission sama sekali (rationale menjadi tidak relevan) |

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Ini evaluasi kualitas UX/transparansi, bukan murni kerentanan teknis** — beri bobot pada kejelasan dan kejujuran isi rationale (apakah benar-benar menjelaskan dengan spesifik, bukan sekadar teks generik "Aplikasi butuh izin ini untuk berfungsi dengan baik").

2. **Dua mekanisme ini independen** — aplikasi bisa mengimplementasikan salah satu tanpa yang lain. Evaluasi dan laporkan keduanya secara terpisah, jangan menganggap salah satu cukup mewakili keduanya.

3. **`android:exported="true"` pada Activity Privacy Dashboard BUKAN kerentanan** (§1.4) — jangan salah tandai ini sebagai temuan exported component yang berbahaya; ia dilindungi permission sistem `START_VIEW_PERMISSION_USAGE` yang hanya dipegang komponen sistem resmi.

4. **Korelasikan dengan MASTG-TEST-0254/0255** — permission yang sudah proporsional dan minimal tetap bisa menjadi pengalaman pengguna yang buruk (dan berpotensi menurunkan trust) bila tidak dijelaskan dengan baik.

5. **Severity umumnya rendah-menengah** — ini soal kualitas transparansi/UX privasi, bukan kerentanan keamanan aktif; namun tetap relevan untuk kepatuhan terhadap prinsip *informed consent* yang mendasari banyak regulasi privasi modern (GDPR, dsb.).

6. **Dokumentasikan:** daftar dangerous permission, status implementasi kedua mekanisme rationale per permission, kualitas isi teks rationale (spesifik vs generik), dan hasil verifikasi dinamis alur penolakan-permintaan ulang.

---

## 4. Rekomendasi Perbaikan

### 4.1 Implementasikan In-App Rationale Sesuai Pola Resmi

```kotlin
when {
    ContextCompat.checkSelfPermission(this, Manifest.permission.CAMERA) ==
            PackageManager.PERMISSION_GRANTED -> {
        openCameraFeature()
    }
    ActivityCompat.shouldShowRequestPermissionRationale(this, Manifest.permission.CAMERA) -> {
        AlertDialog.Builder(this)
            .setTitle("Izin Kamera Diperlukan")
            .setMessage("Fitur pemindaian QR code membutuhkan akses kamera. " +
                    "Tanpa izin ini, Anda tetap bisa memasukkan kode secara manual.")
            .setPositiveButton("Beri Izin") { _, _ ->
                requestPermissionLauncher.launch(Manifest.permission.CAMERA)
            }
            .setNegativeButton("Tidak, Terima Kasih") { dialog, _ -> dialog.dismiss() }
            .show()
    }
    else -> {
        requestPermissionLauncher.launch(Manifest.permission.CAMERA)
    }
}
```

### 4.2 Implementasikan Activity Rationale untuk Privacy Dashboard

```xml
<activity android:name=".PermissionRationaleActivity"
          android:permission="android.permission.START_VIEW_PERMISSION_USAGE"
          android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.VIEW_PERMISSION_USAGE" />
        <action android:name="android.intent.action.VIEW_PERMISSION_USAGE_FOR_PERIOD" />
        <category android:name="android.intent.category.DEFAULT" />
    </intent-filter>
</activity>
```

```kotlin
class PermissionRationaleActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val permissionGroup = intent.getStringExtra(Intent.EXTRA_PERMISSION_GROUP_NAME)
        // Tampilkan penjelasan spesifik berdasarkan permissionGroup
        setContentView(buildRationaleView(permissionGroup))
    }
}
```

### 4.3 Tulis Isi Rationale yang Spesifik, Bukan Generik

```
BURUK:  "Aplikasi ini membutuhkan izin lokasi untuk berfungsi dengan baik."
BAIK:   "Kami menggunakan lokasi Anda untuk menampilkan restoran terdekat dan
         memperkirakan waktu pengantaran. Lokasi tidak dibagikan ke pihak ketiga
         dan hanya diakses saat Anda membuka fitur pencarian restoran."
```

### 4.4 Checklist Remediasi

- [ ] Setiap dangerous permission memiliki alur `shouldShowRequestPermissionRationale()` dengan UI edukasi yang jelas
- [ ] UI edukasi menyediakan opsi menolak tanpa memblokir penggunaan aplikasi
- [ ] Isi rationale spesifik terhadap fitur dan data, bukan teks generik
- [ ] Activity rationale Privacy Dashboard diimplementasikan untuk permission location/camera/microphone
- [ ] Verifikasi dinamis alur penolakan-permintaan ulang sudah dilakukan
- [ ] **Verifikasi ulang:** jalankan kembali MASTG-TEST-0256 setelah setiap perubahan alur permintaan permission

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0256: Missing Permission Rationale](https://mas.owasp.org/MASTG/tests/android/MASVS-PRIVACY/MASTG-TEST-0256/)
- [MASTG-TEST-0254: Dangerous App Permissions](https://mas.owasp.org/MASTG/tests/android/MASVS-PRIVACY/MASTG-TEST-0254/)
- [MASTG-TEST-0255: Permission Requests Not Minimized](https://mas.owasp.org/MASTG/tests/android/MASVS-PRIVACY/MASTG-TEST-0255/)
- [MASWE-0066: Inadequate Permission Management](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0066/)
- [OWASP Mobile Top 10 2024 — M6: Inadequate Privacy Controls](https://owasp.org/www-project-mobile-top-10/2023-risks/m6-inadequate-privacy-controls)

### 5.2 Dokumentasi Resmi Android

- [Android Developers — Request App Permissions: Explain access to sensitive data](https://developer.android.com/training/permissions/requesting#explain)
- [Android Developers — Explain access to more sensitive information (Privacy Dashboard rationale)](https://developer.android.com/training/permissions/explaining-access#privacy-dashboard-show-rationale)
- [Android Developers — `shouldShowRequestPermissionRationale()` API reference](https://developer.android.com/reference/android/app/Activity#shouldShowRequestPermissionRationale(java.lang.String))
- [Android Developers — Privacy Dashboard](https://developer.android.com/about/versions/12/features/privacy-dashboard)

### 5.3 Dokumentasi Tools

- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [CodeQL — Documentation](https://codeql.github.com/docs/)
- [UI Automator — Testing framework](https://developer.android.com/training/testing/other-components/ui-automator)
- [MobSF — Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)

---

*Dokumen ini disusun terutama dari elaborasi dua halaman dokumentasi resmi Android Developers yang dirujuk langsung oleh catatan resmi MASTG-TEST-0256 (status placeholder). Test ini melengkapi trio evaluasi permission privasi bersama MASTG-TEST-0254 (proporsionalitas) dan MASTG-TEST-0255 (minimalitas) dengan dimensi ketiga: transparansi. Dua mekanisme rationale yang berbeda — in-app (`shouldShowRequestPermissionRationale`) dan Privacy Dashboard sistem (`VIEW_PERMISSION_USAGE`) — beroperasi independen dan keduanya perlu dievaluasi terpisah untuk gambaran lengkap kualitas komunikasi privasi aplikasi kepada penggunanya.*
