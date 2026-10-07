# MASTG-TEST-0293 `setSecure` Not Used to Prevent Screenshots in SurfaceViews

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0293 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-PLATFORM |
| **Weakness** | MASWE-0038 — *Insufficient Protection of Sensitive Data from Screenshots or Screen Recordings* (sama seperti MASTG-TEST-0289/0291/0292) |
| **API yang disorot** | `SurfaceView.setSecure(boolean)` |
| **Tipe Pengujian** | Static, Code |
| **Status resmi MASTG** | **`placeholder`** — belum ada Overview/Steps/Evaluation lengkap |
| **Catatan resmi (satu-satunya konten yang tersedia)** | *"This test verifies whether an app prevents sensitive data from being captured in screenshots and screen recordings of `SurfaceView` components."* |
| **Knowledge** | MASTG-KNOW-0053 |
| **Best Practice** | MASTG-BEST-0014, MASTG-BEST-0017 (Use `setSecure` to Prevent Screenshots in SurfaceViews — **juga berstatus placeholder**) |
| **Test terkait** | **MASTG-TEST-0289/0291/0292** — seluruh kelompok MASWE-0038; test ini menyasar **celah arsitektural spesifik** yang tidak tercakup `FLAG_SECURE` sama sekali (lihat §1.2) |
| **Demo terkait** | — (tidak ada) |
| **Rule resmi** | — (tidak ada; test placeholder) |
| **CWE terkait** | CWE-200, CWE-311 |

---

## 1. Penjelasan

### 1.1 Status Test Ini

Sama seperti MASTG-TEST-0292, baik test ini maupun best practice yang dirujuknya (**MASTG-BEST-0017**) sama-sama berstatus **`placeholder`**. Dokumen ini disusun sepenuhnya dari riset independen terhadap dokumentasi resmi Android dan pemahaman arsitektur rendering Android.

### 1.2 Temuan Paling Penting: `SurfaceView` Beroperasi di Luar Jangkauan `FLAG_SECURE` — Sebuah Celah Arsitektural, Bukan Sekadar API Alternatif

Ini adalah **nuansa paling kritis** dalam dokumen ini, dan berbeda secara fundamental dari hubungan `setRecentsScreenshotEnabled` vs `FLAG_SECURE` yang dibahas di dokumen MASTG-TEST-0292 (di mana keduanya bersifat **redundan** untuk skenario Recents). Untuk `SurfaceView`, situasinya justru **terbalik**: `FLAG_SECURE` yang diterapkan pada window Activity **tidak secara otomatis melindungi** konten yang dirender lewat `SurfaceView` yang ada di dalam window tersebut.

Alasan teknisnya berakar pada **arsitektur rendering Android** yang unik untuk `SurfaceView`:

> *"Unlike regular Views that render into the Activity window's surface, `SurfaceView` creates its own dedicated rendering surface that is composited by the system compositor (SurfaceFlinger)... `SurfaceView` surfaces can be promoted to hardware overlays on devices that support them, meaning they may bypass the standard window buffer entirely."*

Berbeda dari `View` biasa (`TextView`, `ImageView`, `EditText`, dll.) yang semuanya digambar **ke dalam satu buffer window yang sama** — sehingga `FLAG_SECURE` pada window tersebut secara otomatis melindungi **seluruh** kontennya — `SurfaceView` bekerja dengan cara yang berbeda: ia membuat **"lubang" (hole punch)** di window Activity dan menampilkan konten dari **surface terpisah** yang dikelola langsung oleh compositor sistem (**SurfaceFlinger**), berpotensi bahkan langsung oleh **hardware overlay** perangkat. Karena surface ini secara arsitektural **independen** dari buffer window utama, `FLAG_SECURE` yang diterapkan pada window **tidak memiliki jangkauan** untuk melindunginya — inilah mengapa Android menyediakan API **terpisah**, `SurfaceView.setSecure(boolean)`, yang harus diterapkan **secara eksplisit** pada objek `SurfaceView` itu sendiri.

### 1.3 Mengapa Ini Celah yang Sangat Mudah Terlewat oleh Developer

Ini adalah **jebakan mental model** yang sangat umum bagi developer yang sudah familiar dengan `FLAG_SECURE`: asumsi wajar (namun **keliru**) bahwa *"saya sudah menerapkan `FLAG_SECURE` pada Activity ini, jadi seluruh kontennya pasti terlindungi."* Asumsi ini **benar** untuk komponen UI standar, namun **gagal total** begitu Activity tersebut menyertakan `SurfaceView` — sebuah komponen yang **sangat umum** dipakai untuk:

- **Preview kamera** (`Camera2`/`CameraX` — biasanya lewat `TextureView` atau `SurfaceView` sebagai backing surface)
- **Pemutaran video** (`VideoView`, `ExoPlayer`/Media3 yang menggunakan `SurfaceView` sebagai output rendering)
- **Peta interaktif** (Google Maps SDK, yang secara historis memakai `SurfaceView` untuk rendering peta performa tinggi)
- **Game engine dan rendering grafis kustom** (OpenGL ES via `GLSurfaceView`, turunan langsung dari `SurfaceView`)

Kombinasi konteks ini menciptakan skenario risiko nyata yang sangat relevan: **aplikasi verifikasi identitas video (video KYC)**, **aplikasi panggilan video** yang menampilkan wajah/dokumen identitas pengguna, atau **aplikasi pemindaian dokumen** yang menggunakan preview kamera untuk menangkap KTP/paspor — seluruhnya **secara umum memakai `SurfaceView`** untuk menampilkan feed kamera/video secara real-time. Developer yang menerapkan `FLAG_SECURE` pada Activity tersebut (mengikuti praktik standar yang sudah benar untuk komponen UI lain) **bisa jadi tetap meninggalkan celah nyata** pada konten `SurfaceView` itu sendiri — screenshot atau perekaman layar tetap dapat menangkap feed kamera/video sensitif tersebut, meski `FLAG_SECURE` sudah "diterapkan" pada level Activity.

### 1.4 Persyaratan Timing yang Ketat: Harus Dipanggil Sebelum Surface Ter-attach

Dokumentasi resmi memberi persyaratan teknis presisi yang mirip nuansa timing yang sudah dibahas di dokumen MASTG-TEST-0289 (celah `FLAG_SECURE` vs `onPause()`), namun di sini persyaratannya lebih tegas dan eksplisit:

> *"This must be set before the surface view's containing window is attached to the window manager."*

Ini berarti `setSecure(true)` **harus** dipanggil pada `SurfaceView` **sebelum** proses attachment window terjadi — biasanya berarti **sesegera mungkin** setelah instansiasi objek `SurfaceView`, idealnya di `onCreate()` sebelum `setContentView()` menyelesaikan inflasi layout, atau segera setelah `findViewById()` memperoleh referensinya. Pemanggilan yang **terlambat** (mis. di `onResume()` setelah surface sudah ter-attach dan mulai me-render konten) berpotensi **tidak efektif** — celah timing yang secara konsep mirip dengan kerentanan `FLAG_SECURE` vs `onPause()` yang dibahas di MASTG-TEST-0289, namun di sini persyaratannya secara eksplisit didokumentasikan resmi, bukan sekadar temuan riset komunitas.

### 1.5 Konteks Historis: Desain Awal untuk DRM, Bukan Murni untuk Keamanan Aplikasi

Poin historis yang menarik dan penting untuk konteks laporan audit — riset menemukan bahwa:

> *"The `FLAG_SECURE` flag is not primarily used for security but rather relates to copyrighted content in the context of DRM and displays—secure content would be something like a DVD, and a secure display would be an HDTV."*

Ini menjelaskan **mengapa** `SurfaceView.setSecure()` ada sebagai API terpisah sejak awal — kebutuhan aslinya adalah **proteksi konten berhak cipta (DRM)** saat pemutaran video premium (mis. layanan streaming yang perlu memastikan output video tidak bisa direkam ulang oleh perangkat perekam layar/HDMI capture), bukan murni dirancang sebagai kontrol privasi data pengguna. Meski demikian, **mekanisme teknis yang sama persis** — mencegah surface tertentu muncul di screenshot/recording — juga **efektif dipakai** untuk tujuan melindungi privasi konten sensitif pengguna (feed kamera KYC, preview dokumen identitas), sehingga tetap sepenuhnya relevan untuk evaluasi keamanan MASWE-0038 meski tujuan desain awalnya berbeda.

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | Fungsi |
|---|---|
| **jadx** | Dekompilasi DEX → Java untuk pencarian pola `SurfaceView`/`setSecure` |
| **grep / ripgrep** | Pencarian pola API dan identifikasi instansiasi `SurfaceView`/turunannya |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **CodeQL** | Menelusuri seluruh kelas yang **meng-extend** `SurfaceView` (termasuk `GLSurfaceView`, dan `SurfaceView` yang menjadi backing view komponen `CameraX`/ExoPlayer) beserta memverifikasi timing pemanggilan `setSecure()` relatif terhadap siklus hidup |
| **jadx-gui "Find Usage"** | Menelusuri seluruh pemakaian `SurfaceView`/`TextureView` di layout XML dan kode, termasuk yang dibungkus library pihak ketiga (Camera, video player) |
| **MASTG-TEST-0289 (metodologi ekstraksi screenshot)** | Verifikasi dinamis — konfirmasi definitif apakah konten `SurfaceView` benar-benar bocor ke screenshot/Recents |

### 2.3 Prasyarat Lingkungan

- **Tidak butuh device/root** untuk analisis statis inti.
- **Identifikasi seluruh penggunaan `SurfaceView`** (langsung maupun tidak langsung lewat library kamera/video pihak ketiga) sebagai langkah pertama wajib — banyak developer tidak sadar bahwa SDK kamera/video yang mereka pakai secara internal memakai `SurfaceView`.
- **Untuk verifikasi dinamis**, siapkan device/emulator dan picu skenario yang menampilkan feed kamera/video, lalu coba screenshot manual dan capture Recents secara bersamaan.

---

## 3. Cara Pengujian

Karena tidak ada langkah resmi (status placeholder), metodologi berikut disusun dari riset independen.

### 3.1 Langkah Umum

1. Identifikasi seluruh Activity/Fragment yang memakai `SurfaceView`/turunannya (langsung atau lewat SDK pihak ketiga).
2. Untuk setiap penggunaan, periksa apakah `setSecure(true)` dipanggil, dan **kapan** relatif terhadap attachment window.
3. Nilai apakah konten yang ditampilkan `SurfaceView` tersebut tergolong sensitif (feed kamera KYC, video call, preview dokumen).

### 3.2 Metode A — grep/ripgrep

```bash
D=./decompiled/sources

# Temukan seluruh kelas yang extend SurfaceView (langsung)
rg -n 'extends SurfaceView|extends GLSurfaceView' $D

# Cari pemanggilan setSecure
rg -n '\.setSecure\(true\)|\.setSecure\(false\)' $D

# Cari instansiasi SurfaceView di layout XML
rg -n '<SurfaceView\|<android\.opengl\.GLSurfaceView' ./decompiled/resources/res/layout/
```

### 3.3 Metode B — CodeQL untuk Verifikasi Timing dan Cakupan

```ql
import java

class SurfaceViewSubclass extends Class {
  SurfaceViewSubclass() {
    this.getASupertype*().hasQualifiedName("android.view", "SurfaceView")
  }
}

class SetSecureCall extends MethodAccess {
  SetSecureCall() {
    this.getMethod().hasName("setSecure")
  }
}

// Temukan SurfaceView (langsung/turunan) yang TIDAK PERNAH memanggil setSecure(true) di mana pun
from SurfaceViewSubclass sv
where not exists(SetSecureCall call |
  call.getQualifier().getType() = sv and
  call.getArgument(0).(BooleanLiteral).getBooleanValue() = true)
select sv, "Kelas turunan SurfaceView ditemukan TANPA pemanggilan setSecure(true) di mana pun dalam basis kode"
```

### 3.4 Metode C — Audit SDK Pihak Ketiga (Kamera/Video)

```bash
# Periksa dependency yang diketahui memakai SurfaceView secara internal
grep -E "camerax|exoplayer|media3|google-maps|mapbox" app/build.gradle
```

Untuk SDK pihak ketiga, periksa dokumentasi masing-masing apakah mereka menyediakan konfigurasi untuk mengaktifkan mode "secure surface" (mis. beberapa versi CameraX/ExoPlayer menyediakan opsi terkait) — tanggung jawab konfigurasi ini mungkin **berada di tangan aplikasi**, bukan otomatis ditangani library.

### 3.5 Metode D — Verifikasi Dinamis (Bukti Definitif)

```bash
# 1. Picu layar yang menampilkan feed kamera/video sensitif
adb shell am start -n com.target.app/.VideoKycActivity

# 2. Coba screenshot manual SAAT feed kamera aktif
adb shell screencap -p /sdcard/test_surfaceview.png
adb pull /sdcard/test_surfaceview.png

# 3. Periksa gambar: apakah area SurfaceView menampilkan feed kamera nyata, atau hitam/kosong?
```

Bila hasil screenshot menunjukkan **feed kamera/video yang benar-benar terlihat** (bukan area hitam), ini bukti definitif bahwa `setSecure(true)` **tidak** diterapkan dengan efektif pada `SurfaceView` tersebut — terlepas dari apakah `FLAG_SECURE` sudah diterapkan pada Activity-nya (area di luar `SurfaceView` mungkin tetap ter-blank, tapi area `SurfaceView` itu sendiri tetap bocor).

### 3.6 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Kapan dipakai |
|---|---|---|
| **A** | grep | Baseline cepat identifikasi `SurfaceView` |
| **B** | CodeQL | Verifikasi cakupan menyeluruh (semua turunan SurfaceView) |
| **C** | Audit SDK pihak ketiga | Mengidentifikasi SurfaceView tersembunyi dari library eksternal |
| **D** | Verifikasi dinamis | **Bukti definitif**, sangat direkomendasikan mengingat sifat celah ini yang mudah luput dari asumsi "FLAG_SECURE sudah cukup" |

**Kombinasi minimum yang aku rekomendasikan:** **A+C (identifikasi seluruh SurfaceView, termasuk dari SDK pihak ketiga) → B (verifikasi cakupan setSecure) → D (bukti definitif dinamis)** — Metode D sangat penting untuk test ini mengingat betapa mudahnya celah ini luput dari asumsi developer yang keliru.

---

### 3.7 Kriteria Evaluasi: Positive Case & Negative Case

Karena tidak ada klausul Evaluation resmi (status placeholder), kriteria berikut disusun berdasarkan catatan resmi singkat dan prinsip dasar arsitektural yang dijelaskan di §1.2.

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi |
|---|---|
| F1 | `SurfaceView`/turunannya dipakai untuk menampilkan konten sensitif (feed kamera KYC, video call, preview dokumen identitas) **tanpa** pemanggilan `setSecure(true)` sama sekali |
| F2 | `setSecure(true)` dipanggil, namun **terlambat** — setelah surface sudah ter-attach ke window manager (dikonfirmasi Metode B/D) |
| F3 | Verifikasi dinamis (Metode D) mengonfirmasi konten `SurfaceView` tetap terlihat jelas pada screenshot manual meski `FLAG_SECURE` sudah diterapkan pada Activity-nya — bukti definitif celah arsitektural (§1.2) |
| F4 | Developer **keliru berasumsi** `FLAG_SECURE` pada Activity sudah cukup melindungi `SurfaceView` di dalamnya, tanpa verifikasi eksplisit |

**Contoh bukti (ilustratif — MASTG belum menyediakan demo resmi untuk test ini):**

```java
// VideoKycActivity.java
protected void onCreate(Bundle savedInstanceState) {
    getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);  // Diterapkan pada Activity
    super.onCreate(savedInstanceState);
    setContentView(R.layout.activity_video_kyc);
    SurfaceView cameraPreview = findViewById(R.id.camera_preview_surface);
    // TIDAK ADA pemanggilan cameraPreview.setSecure(true) di sini!
    startCameraPreview(cameraPreview);
}
```

Interpretasi: `FLAG_SECURE` diterapkan pada Activity, namun `SurfaceView` yang menampilkan feed kamera untuk verifikasi identitas **tidak** diberi `setSecure(true)` — sesuai §1.2, ini celah nyata: feed kamera (berpotensi menampilkan wajah pengguna dan dokumen identitas) tetap dapat ter-screenshot/terekam meski `FLAG_SECURE` "sudah diterapkan". **FAIL kritis**.

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi |
|---|---|
| P1 | Seluruh `SurfaceView` yang menampilkan konten sensitif memiliki `setSecure(true)` yang diterapkan **sebelum** attachment window (dikonfirmasi timing lewat Metode B) |
| P2 | Verifikasi dinamis (Metode D) mengonfirmasi area `SurfaceView` benar-benar hitam/kosong pada screenshot manual selama konten sensitif ditampilkan |
| P3 | Aplikasi tidak memakai `SurfaceView` untuk menampilkan konten sensitif apa pun (mis. hanya dipakai untuk elemen UI non-sensitif seperti animasi latar) |

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Ini catatan terpenting di seluruh dokumen ini: JANGAN simpulkan PASS hanya karena `FLAG_SECURE` sudah ditemukan diterapkan pada Activity.** Sesuai §1.2, ini adalah kesalahan asumsi yang sangat umum — `FLAG_SECURE` window **tidak** menjangkau konten `SurfaceView` sama sekali. Selalu periksa `SurfaceView` secara terpisah dan independen dari hasil audit `FLAG_SECURE` (MASTG-TEST-0291).

2. **Audit SDK pihak ketiga adalah langkah yang sering terlewat** — banyak developer tidak menyadari bahwa library kamera/video/peta yang mereka pakai secara internal memakai `SurfaceView`. Periksa dependency secara eksplisit (Metode C).

3. **Perhatikan timing pemanggilan secara ketat** — berbeda dari kebanyakan test lain di mana "sudah ada pemanggilan API" cukup untuk kandidat PASS, di sini **kapan** API dipanggil sama pentingnya dengan **apakah** ia dipanggil.

4. **Verifikasi dinamis sangat direkomendasikan untuk test ini** — mengingat sifat celah arsitektural yang tidak intuitif ini, bukti visual definitif (Metode D) memberi kepastian yang jauh lebih meyakinkan dibanding kesimpulan dari analisis statis semata.

5. **Severity dimodulasi:**

   | Faktor | Severity |
   |---|---|
   | `SurfaceView` menampilkan feed kamera KYC/dokumen identitas/video call sensitif tanpa `setSecure` | **Kritis** |
   | `SurfaceView` menampilkan video/media non-sensitif tanpa `setSecure` | **Bukan temuan** (kecuali konten berlisensi DRM, relevan untuk kepatuhan lisensi bukan privasi pengguna) |
   | `setSecure(true)` dipanggil tapi terlambat (celah timing) | **Tinggi** — efektivitas tidak terjamin |

6. **Dokumentasikan:** daftar lengkap `SurfaceView`/turunannya (langsung dan dari SDK pihak ketiga), status dan timing pemanggilan `setSecure()` untuk masing-masing, klasifikasi sensitivitas konten yang ditampilkan, dan hasil verifikasi dinamis.

---

## 4. Rekomendasi Perbaikan

### 4.1 Terapkan `setSecure(true)` Sesegera Mungkin Setelah Instansiasi

```java
public class VideoKycActivity extends AppCompatActivity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_video_kyc);

        SurfaceView cameraPreview = findViewById(R.id.camera_preview_surface);
        cameraPreview.setSecure(true);  // SEBELUM surface holder callback/attachment terjadi

        SurfaceHolder holder = cameraPreview.getHolder();
        holder.addCallback(surfaceCallback);
    }
}
```

### 4.2 Terapkan Keduanya: `FLAG_SECURE` untuk UI Umum, `setSecure` untuk SurfaceView

```java
protected void onCreate(Bundle savedInstanceState) {
    getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);  // Lindungi elemen UI umum
    super.onCreate(savedInstanceState);
    setContentView(R.layout.activity_video_kyc);
    findViewById(R.id.camera_preview_surface).setSecure(true);  // Lindungi SurfaceView secara terpisah
}
```

### 4.3 Audit Konfigurasi SDK Kamera/Video Pihak Ketiga

Periksa dokumentasi CameraX/ExoPlayer/Media3 untuk opsi konfigurasi `SurfaceView` secure yang mungkin disediakan, dan terapkan secara eksplisit bila tersedia — jangan berasumsi SDK menangani ini secara otomatis.

### 4.4 Checklist Remediasi

- [ ] Seluruh `SurfaceView`/turunannya (langsung dan dari SDK pihak ketiga) diinventarisasi
- [ ] `setSecure(true)` diterapkan pada seluruh `SurfaceView` yang menampilkan konten sensitif, sebelum attachment window
- [ ] Verifikasi dinamis mengonfirmasi area `SurfaceView` benar-benar terlindungi pada screenshot manual
- [ ] Tim developer diedukasi bahwa `FLAG_SECURE` TIDAK melindungi `SurfaceView` secara otomatis
- [ ] **Verifikasi ulang:** jalankan kembali MASTG-TEST-0293 setiap penambahan komponen kamera/video baru

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0293: setSecure Not Used to Prevent Screenshots in SurfaceViews](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0293/)
- [MASTG-TEST-0289: Runtime Verification of Sensitive Content Exposure in Screenshots](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0289/)
- [MASTG-TEST-0291: References to Screen Capturing Prevention APIs](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0291/)
- [MASTG-TEST-0292: setRecentsScreenshotEnabled Not Used to Prevent Screenshots When Backgrounded](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0292/)
- [MASWE-0038: Insufficient Protection of Sensitive Data from Screenshots or Screen Recordings](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0038/)
- [MASTG-BEST-0017: Use setSecure to Prevent Screenshots in SurfaceViews](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0017/)

### 5.2 Dokumentasi Resmi Android

- [Android Developers — `SurfaceView#setSecure()`](https://developer.android.com/reference/android/view/SurfaceView#setSecure(boolean))
- [Android Developers — `SurfaceView` class overview](https://developer.android.com/reference/android/view/SurfaceView)
- [Android Developers — Secure Sensitive Activities](https://developer.android.com/security/fraud-prevention/activities)
- [Android Developers — Surface Types (Media3)](https://developer.android.com/media/media3/ui/surface)

### 5.3 Riset dan Artikel Komunitas

- [Nightwatch Cybersecurity — Research: Securing Android Applications from Screen Capture (FLAG_SECURE)](https://wwws.nightwatchcybersecurity.com/2016/04/13/research-securing-android-applications-from-screen-capture/)
- [Google CameraX Developers Group — setSecure on PreviewView's underlying SurfaceView](https://groups.google.com/a/android.com/g/camerax-developers/c/z9THRAPo6Wo)
- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)

### 5.4 Dokumentasi Tools

- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [CodeQL — Documentation](https://codeql.github.com/docs/)

---

*Dokumen ini disusun sepenuhnya dari riset independen (dokumentasi resmi Android Developers dan pemahaman arsitektur rendering) karena baik MASTG-TEST-0293 maupun MASTG-BEST-0017 yang dirujuknya sama-sama berstatus **placeholder**. Temuan paling signifikan: `SurfaceView` beroperasi pada surface compositor yang secara arsitektural terpisah dari buffer window utama (berpotensi bahkan hardware overlay), sehingga `FLAG_SECURE` pada Activity **tidak** secara otomatis melindungi kontennya — sebuah celah yang sangat mudah terlewat karena bertentangan dengan asumsi wajar developer bahwa "FLAG_SECURE pada Activity melindungi semuanya". Ini paling relevan untuk aplikasi yang memakai `SurfaceView` untuk feed kamera KYC, video call, atau preview dokumen identitas — konteks yang sangat umum namun jarang disadari memiliki celah proteksi screenshot yang terpisah.*
