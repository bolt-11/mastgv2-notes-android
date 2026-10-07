# MASTG-TEST-0289 Runtime Verification of Sensitive Content Exposure in Screenshots During App Backgrounding

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0289 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-PLATFORM |
| **Weakness** | MASWE-0038 — *Insufficient Protection of Sensitive Data from Screenshots or Screen Recordings* |
| **Tipe Pengujian** | **Dynamic, Filesystem, Manual** |
| **Prasyarat** | `identify-sensitive-screens` |
| **Knowledge** | MASTG-KNOW-0053 |
| **Best Practice** | MASTG-BEST-0014 (Preventing Screenshots and Screen Recording) |
| **Teknik terkait** | MASTG-TECH-0002 (Retrieving Files from Device Storage) |
| **Test terkait** | Rangkaian ini dilengkapi test-test lain MASWE-0038 yang menyasar `FLAG_SECURE` dari sudut pandang statis/runtime hooking (di luar cakupan dokumen ini) |
| **Demo terkait** | — (tidak ada) |
| **Rule resmi** | — (tidak relevan; test murni dinamis, bukti berupa file gambar) |
| **CWE terkait** | CWE-200, CWE-311, CWE-1258 (Exposure of Sensitive System Information Due to Uncleared Debug Information — analog konseptual) |

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian

Kutipan overview resmi MASTG:

> *"This test verifies that the app hides sensitive content from the screen when it moves to the background. This is important because Android captures a task screenshot of the app UI when it moves to the background. This screenshot is used for the Recents screen and transitions, and can expose sensitive content if the app does not protect it."*

Ini adalah salah satu **perilaku sistem Android yang paling mudah diabaikan** oleh developer karena sifatnya **otomatis dan tak terlihat langsung** — setiap kali aplikasi berpindah ke background (menekan tombol Home, membuka Recents/Overview screen, menerima panggilan telepon masuk, atau bahkan notifikasi sistem yang menutupi layar), Android **secara otomatis mengambil screenshot** dari tampilan aplikasi saat itu untuk ditampilkan sebagai thumbnail pratinjau di layar Recents. Screenshot ini **disimpan sebagai file gambar sungguhan** di penyimpanan sistem — bukan sekadar buffer tampilan sementara di memori.

### 1.2 Lokasi Penyimpanan dan Signifikansinya

Overview resmi secara eksplisit mencantumkan lokasi penyimpanan sistem tempat screenshot ini di-cache:

> *"The system stores the screenshots in their containers `/data/system_ce/0/snapshots` or `/data/system`."*

Poin penting: lokasi ini berada di **partisi sistem** (bukan direktori privat aplikasi `/data/data/<package>/`), yang berarti screenshot ini **berpotensi diakses** oleh entitas dengan hak akses lebih tinggi (root, forensik device, atau — pada device yang telah di-root/dikompromikan — aplikasi jahat dengan hak akses sistem). Ini menciptakan **jalur kebocoran yang independen** dari seberapa baik aplikasi mengamankan penyimpanan internalnya sendiri (rujuk dokumen-dokumen MASVS-STORAGE lain dalam seri riset ini) — meski seluruh data di database/SharedPreferences aplikasi terenkripsi sempurna, **tampilan visual** dari data tersebut tetap bisa ter-capture dan tersimpan sebagai file gambar biasa yang dapat dibaca lewat aplikasi galeri/file explorer forensik apa pun.

### 1.3 Solusi Resmi: `FLAG_SECURE`

MASTG-BEST-0014 memberi solusi tunggal yang direkomendasikan resmi:

> *"Setting `FLAG_SECURE` on the window prevents screenshots (or appear black), blocks screen recording, and hides content on nonsecure displays and in the system task switcher."*

```kotlin
window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
```

Ketika flag ini aktif pada sebuah `Activity`, sistem akan **menampilkan area hitam kosong** sebagai pengganti konten sesungguhnya — baik pada screenshot manual pengguna, screen recording, tampilan pada layar non-aman (casting/mirroring), **maupun** pada thumbnail Recents screen yang menjadi fokus test ini.

### 1.4 Temuan Paling Signifikan: Celah Timing yang Membuat `FLAG_SECURE` Bisa Gagal Meski Sudah Diterapkan

Ini adalah **nuansa teknis paling penting** dalam dokumen ini, dan menjelaskan mengapa test ini secara eksplisit dirancang sebagai **pengujian dinamis manual** (memeriksa screenshot sungguhan) alih-alih cukup memverifikasi keberadaan kode `FLAG_SECURE` secara statis. Riset komunitas mengungkap kerentanan berbasis **race condition** yang nyata:

> *"The core of the issue is that the timing of the system capturing a screenshot for the Recents screen is not guaranteed to be synchronized with the Activity's lifecycle callbacks, specifically `onPause()`. When a user presses the Recents button, the system immediately captures the current screen to prepare for a smooth transition animation and preview. This capture process can occur **before** the app's `onPause()` method is called and completed."*

Ini artinya: **developer yang menerapkan `FLAG_SECURE` secara kondisional di dalam `onPause()`** (pola yang cukup umum ditemukan — mis. untuk menampilkan konten normal saat aktif namun menyembunyikannya hanya saat akan berpindah ke background) **berisiko mengalami kondisi race** di mana sistem sudah mengambil screenshot **sebelum** flag tersebut sempat diterapkan. Konsekuensinya: **kode yang secara statis terlihat benar** (ada pemanggilan `FLAG_SECURE` di lokasi yang "masuk akal") **tetap bisa gagal secara nyata** pada kondisi runtime tertentu — inilah alasan mendasar mengapa test ini **harus** dilakukan secara dinamis dengan memeriksa **hasil aktual** screenshot yang tersimpan, bukan sekadar audit kode statis pemanggilan `FLAG_SECURE`.

**Implikasi praktis untuk rekomendasi remediasi**: `FLAG_SECURE` idealnya diterapkan **sejak `onCreate()`** (state permanen sepanjang siklus hidup Activity yang menampilkan data sensitif) alih-alih diaktifkan/dinonaktifkan secara dinamis di `onPause()`/`onResume()` — pendekatan yang jauh lebih rentan terhadap celah timing ini.

### 1.5 Kasus Nyata: Aplikasi Password Manager

Riset dan laporan komunitas mendokumentasikan kasus nyata yang secara sempurna menggambarkan konsekuensi dari kegagalan ini:

> *"Sensitive data such as the master password and generated passwords were visible in screenshots and in the Android recent apps view, exposing them to other apps with screen capture permissions in real-world password management apps that initially didn't implement `FLAG_SECURE` properly."*

Ini contoh yang sangat ironis dan instruktif — **aplikasi yang tujuan intinya adalah mengamankan kredensial** justru gagal melindungi lapisan yang paling mendasar: tampilan visualnya sendiri. Kasus serupa terlihat pada perbaikan `FLAG_SECURE` yang diajukan komunitas pada proyek open-source pengelola password (`lesspass/lesspass#906`) — menunjukkan bahwa kelalaian ini **bukan kasus langka atau eksotis**, melainkan kesalahan konfigurasi yang **cukup umum** ditemukan bahkan pada aplikasi dengan tujuan keamanan yang eksplisit.

### 1.6 Kategori Konten yang Paling Berisiko

MASTG-BEST-0014 dan konteks tambahan dari riset industri menggarisbawahi kategori tampilan yang paling kritis untuk dilindungi:

- **Kredensial**: password, PIN, passcode, kata sandi master
- **Data finansial**: saldo rekening, riwayat transaksi, nomor kartu pembayaran, mutasi bank
- **Kode otentikasi sekali pakai (OTP)**
- **Data identitas pribadi (PII)**: NIK, nomor identitas, data kesehatan
- **Keystroke pada keyboard/keypad kustom** — poin yang secara khusus disorot MASTG-BEST-0014: *"Protect on screen keyboards or custom keypad views as they may leak keystrokes from passcode fields"* — bahkan **animasi ketukan tombol** pada keypad PIN kustom yang sedang di-capture pada momen tertentu berpotensi membocorkan jejak digit yang sedang dimasukkan.

### 1.7 Trade-off yang Perlu Dipahami: `FLAG_SECURE` adalah Instrumen yang Kasar

Riset industri memberi catatan penting soal keterbatasan solusi ini:

> *"It's a blunt instrument that blocks everything, including screenshots and screen recordings that your users might legitimately need."*

`FLAG_SECURE` bekerja pada **level seluruh window Activity** — tidak ada mekanisme bawaan untuk "menyembunyikan hanya sebagian tampilan" (mis. hanya nomor kartu, membiarkan elemen UI lain tetap ter-screenshot). Ini berarti developer perlu mempertimbangkan **granularitas Activity** dengan cermat — memisahkan layar yang benar-benar menampilkan data sangat sensitif ke dalam `Activity`/`Fragment` terpisah yang diberi `FLAG_SECURE`, alih-alih menerapkannya secara membabi buta ke seluruh aplikasi (yang akan mengganggu pengalaman pengguna legitimate, mis. pengguna yang ingin screenshot riwayat pesanan untuk dokumentasi pribadi).

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | Fungsi |
|---|---|
| **adb** | Ekstraksi file screenshot cache dari `/data/system_ce/0/snapshots` atau `/data/system` (MASTG-TECH-0002) |
| **Peninjauan visual manual** | Wajib — inspeksi setiap gambar untuk keberadaan data sensitif, sesuai tag `manual` pada tipe pengujian |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **scrcpy** | Merekam/mengamati transisi layar secara real-time saat aplikasi berpindah ke background, untuk mengonfirmasi secara visual momen kegagalan (celah timing §1.4) tanpa perlu mengekstrak file snapshot |
| **OCR (Tesseract, dll.)** | Untuk audit skala besar/otomatis — menjalankan OCR pada koleksi screenshot yang diekstrak untuk mendeteksi pola teks sensitif (mis. format nomor kartu, kata kunci "password") secara semi-otomatis sebelum verifikasi visual manual final |
| **Frida** | Hooking `Window.setFlags()`/`Window.addFlags()` untuk mengonfirmasi runtime **kapan tepatnya** `FLAG_SECURE` diterapkan relatif terhadap siklus hidup Activity — berguna untuk mendiagnosis kasus F LAG_SECURE yang diterapkan "terlalu terlambat" (§1.4) |

### 2.3 Prasyarat Lingkungan

- **Butuh device/emulator** — test murni dinamis.
- **Root diperlukan** untuk mengakses direktori sistem `/data/system_ce/0/snapshots`/`/data/system` secara langsung (di luar sandbox aplikasi biasa).
- **Identifikasi layar sensitif terlebih dahulu** (prasyarat `identify-sensitive-screens`) — memetakan alur aplikasi mana saja yang menampilkan kredensial/data finansial/PII sebelum memulai pengujian sistematis.
- **Uji berbagai mekanisme trigger background**, bukan hanya tombol Home — sesuai langkah resmi: tombol Home **dan** membuka Recents screen lalu keluar lagi — keduanya bisa memicu perilaku capture yang sedikit berbeda tergantung implementasi sistem/vendor.

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Jelajahi aplikasi hingga mencapai setiap layar yang teridentifikasi sensitif. Pada setiap layar tersebut, pindahkan aplikasi ke background (mis. menekan Home atau membuka Recents screen lalu keluar), lanjutkan ke layar berikutnya.
2. Gunakan **MASTG-TECH-0002** untuk menyalin screenshot yang diambil sistem ke laptop untuk analisis lebih lanjut.

### 3.2 Metode A — Ekstraksi dan Peninjauan Visual Manual *(metode resmi utama)*

```bash
# Root diperlukan untuk mengakses direktori sistem
adb root
adb shell "ls /data/system_ce/0/snapshots/"
adb pull /data/system_ce/0/snapshots/ ./snapshots_extracted/

# Lokasi alternatif tergantung versi Android
adb shell "ls /data/system/"
adb pull /data/system/ ./system_extracted/ 2>/dev/null
```

```bash
# Tinjau setiap file gambar secara visual
for img in ./snapshots_extracted/*; do
    echo "=== $img ==="
    # Buka dengan image viewer atau proses OCR (Metode C)
done
```

Untuk setiap layar sensitif yang diidentifikasi (prasyarat), lakukan siklus: buka layar → background via Home → catat waktu → background via Recents → catat waktu → ekstrak dan bandingkan hasil snapshot terkait.

### 3.3 Metode B — scrcpy untuk Observasi Real-Time Celah Timing

```bash
scrcpy --record=recording.mp4
```

Sambil merekam, picu transisi ke background pada layar sensitif berulang kali (idealnya dengan variasi kecepatan/timing interaksi) untuk mengamati secara visual apakah ada **frame transisi** di mana konten sensitif sempat terlihat sekilas sebelum area hitam `FLAG_SECURE` muncul — bukti visual langsung dari celah timing yang dijelaskan di §1.4.

### 3.4 Metode C — OCR untuk Triase Otomatis pada Audit Skala Besar

```bash
for img in ./snapshots_extracted/*.png; do
    tesseract "$img" - | grep -iE "password|pin|card|balance|token|ssn" && echo "  -> ditemukan di: $img"
done
```

Ini metode **pelengkap** untuk mempercepat triase pada aplikasi dengan sangat banyak layar — namun **tidak menggantikan** peninjauan visual manual penuh sesuai klausul resmi "Further Validation Required", karena OCR tidak dapat mendeteksi kebocoran visual non-tekstual (mis. foto KTP, foto kartu kredit fisik, avatar/nama yang tampil sebagai gambar).

### 3.5 Metode D — Frida untuk Diagnosis Timing `FLAG_SECURE`

```javascript
// hook-flag-secure-timing.js
Java.perform(function () {
    var Window = Java.use("android.view.Window");
    Window.setFlags.overload("int", "int").implementation = function (flags, mask) {
        var FLAG_SECURE = 0x00002000;
        if ((flags & FLAG_SECURE) !== 0) {
            console.log("[*] FLAG_SECURE diterapkan pada: " + new Date().toISOString());
            console.log("    Stack:\n" + Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
        }
        return this.setFlags(flags, mask);
    };

    var Activity = Java.use("android.app.Activity");
    Activity.onPause.implementation = function () {
        console.log("[*] onPause() dipanggil pada: " + new Date().toISOString());
        return this.onPause();
    };
});
```

```bash
frida -U -f com.target.app -l hook-flag-secure-timing.js --no-pause
```

Bandingkan timestamp `FLAG_SECURE` vs `onPause()` — bila `FLAG_SECURE` diterapkan **di dalam** `onPause()` (bukan lebih awal, mis. `onCreate()`), ini konfirmasi langsung risiko celah timing yang dijelaskan §1.4.

### 3.6 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Kelebihan | Kapan dipakai |
|---|---|---|---|
| **A** | adb pull + review manual | Bukti definitif sesuai klausul resmi | **Wajib**, metode utama |
| **B** | scrcpy recording | Observasi visual celah timing secara langsung | Diagnosis kasus F LAG_SECURE "hampir berhasil" |
| **C** | OCR otomatis | Triase cepat pada banyak layar | Pelengkap, bukan pengganti review manual |
| **D** | Frida timing hook | Diagnosis akar penyebab teknis | Menjelaskan MENGAPA suatu layar FAIL |

**Kombinasi minimum yang aku rekomendasikan:** **A (wajib, sesuai klausul resmi) → D (bila ditemukan FAIL, untuk mendiagnosis akar penyebab timing) → B (konfirmasi visual tambahan bila diperlukan)**.

---

### 3.7 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG:**

> **Observation:** *"The output should include a collection of screenshots cached when the app entered the background state."*
>
> **Evaluation:** *"The test case fails if any screenshot displays sensitive data that should have been protected."*

Dengan klausul **Further Validation Required** wajib: *"Inspect each screenshot visually, looking for sensitive information such as passwords, tokens, personally identifiable information, or other sensitive content."*

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi |
|---|---|
| F1 | Screenshot cache yang diekstrak menampilkan data sensitif secara jelas terbaca (kredensial, token, PII, data finansial) |
| F2 | Layar dengan keypad/keyboard kustom untuk PIN/password menampilkan jejak visual input pengguna pada momen capture |
| F3 | `FLAG_SECURE` ditemukan diterapkan di kode (analisis statis pendukung), namun tetap FAIL secara dinamis karena celah timing (§1.4) — dikonfirmasi Metode D menunjukkan `FLAG_SECURE` diterapkan setelah/bersamaan `onPause()`, bukan lebih awal |

**Contoh bukti (ilustratif — MASTG belum menyediakan demo resmi untuk test ini):**

```bash
$ adb pull /data/system_ce/0/snapshots/ ./snapshots_extracted/
$ ls ./snapshots_extracted/
com.example.target_task5.png

# Peninjauan visual: gambar menampilkan layar "Konfirmasi Pembayaran"
# dengan nomor kartu penuh "4532 **** **** 1234" dan tombol "Bayar Rp 5.000.000" terlihat jelas
```

Interpretasi: layar pembayaran yang seharusnya sensitif ter-capture penuh tanpa proteksi — **FAIL kritis**.

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi |
|---|---|
| P1 | Screenshot untuk layar sensitif menampilkan **area hitam kosong** (indikasi `FLAG_SECURE` bekerja dengan benar) |
| P2 | Konfirmasi Metode D menunjukkan `FLAG_SECURE` diterapkan **sejak `onCreate()`** (state permanen), bukan secara kondisional di `onPause()` — mengeliminasi risiko celah timing |
| P3 | Screenshot untuk layar non-sensitif (di luar cakupan prasyarat) tetap tampil normal — mengonfirmasi `FLAG_SECURE` diterapkan secara **tepat sasaran** (bukan diterapkan berlebihan ke seluruh aplikasi yang bisa mengganggu UX legitimate, §1.7) |

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Audit kode statis `FLAG_SECURE` saja TIDAK CUKUP** — ini pelajaran terpenting dokumen ini. Sesuai §1.4, kode yang secara tekstual benar bisa tetap gagal secara runtime akibat celah timing race condition. Verifikasi dinamis dengan screenshot sungguhan adalah satu-satunya cara memastikan proteksi benar-benar berfungsi.

2. **Uji SEMUA mekanisme trigger background**, bukan hanya satu cara — tombol Home dan Recents screen bisa memicu perilaku capture yang berbeda tergantung versi/vendor Android.

3. **Perhatikan momen capture untuk keypad/keyboard kustom secara khusus** (§1.6) — ini kategori risiko yang mudah terlewat karena fokus audit biasanya ke tampilan data "diam" (mis. daftar transaksi), bukan interaksi input yang sedang berlangsung.

4. **Root diperlukan untuk akses langsung ke direktori snapshot sistem** — bila tidak tersedia device root, pertimbangkan pendekatan alternatif dengan mengambil screenshot manual pada momen transisi background (kurang presisi dibanding ekstraksi cache sistem asli, tapi tetap dapat memberi indikasi awal).

5. **Jangan rekomendasikan `FLAG_SECURE` diterapkan membabi buta ke seluruh aplikasi** (§1.7) — pertimbangkan granularitas per-Activity/Fragment untuk keseimbangan antara keamanan dan pengalaman pengguna legitimate.

6. **Severity dimodulasi:**

   | Faktor | Severity |
   |---|---|
   | Kredensial/data finansial/OTP terlihat jelas di screenshot | **Kritis** |
   | PII (nama, alamat) terlihat tanpa data super-sensitif lain | **Menengah** |
   | Keystroke keypad PIN terekam sebagian | **Tinggi** |
   | Layar non-sensitif ter-screenshot normal (di luar cakupan prasyarat) | **Bukan temuan** |

7. **Dokumentasikan:** daftar layar sensitif yang diuji, mekanisme trigger background yang dipakai per layar, hasil visual setiap screenshot (redaksi bila perlu untuk laporan), dan hasil diagnosis timing (Metode D) bila ditemukan FAIL.

---

## 4. Rekomendasi Perbaikan

### 4.1 Terapkan `FLAG_SECURE` Sejak `onCreate()` (Menghindari Celah Timing)

```kotlin
class PaymentConfirmationActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )  // Diterapkan SEBELUM konten apa pun dirender, bukan di onPause()
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_payment_confirmation)
    }
}
```

### 4.2 Pisahkan Layar Sensitif ke Activity/Fragment Terpisah untuk Granularitas

Hindari menerapkan `FLAG_SECURE` secara global di `Application` — terapkan spesifik hanya pada Activity yang benar-benar menampilkan data sensitif, sesuai hasil pemetaan prasyarat `identify-sensitive-screens`.

### 4.3 Lindungi Keypad/Keyboard Kustom Secara Khusus

Untuk komponen input PIN/password kustom (bukan `EditText` standar), pastikan `FLAG_SECURE` pada Activity/Dialog yang menampungnya aktif sejak awal, dan pertimbangkan menonaktifkan animasi visual feedback tombol yang bisa membocorkan jejak digit yang ditekan.

### 4.4 Integrasikan Verifikasi ke Regression Test

```bash
#!/bin/bash
# ci-check-flag-secure-screenshots.sh
adb shell am start -n com.target.app/.PaymentConfirmationActivity
sleep 2
adb shell input keyevent KEYCODE_HOME
sleep 1
adb root
adb pull /data/system_ce/0/snapshots/ ./ci_snapshots/
# Verifikasi otomatis: file gambar harus didominasi warna hitam solid (heuristik sederhana)
```

### 4.5 Checklist Remediasi

- [ ] Seluruh layar sensitif hasil pemetaan prasyarat sudah diuji dengan ekstraksi screenshot nyata
- [ ] `FLAG_SECURE` diterapkan sejak `onCreate()`, bukan secara kondisional di `onPause()`
- [ ] Keypad/keyboard kustom untuk PIN/password dilindungi secara eksplisit
- [ ] Diagnosis timing (Frida) dilakukan untuk setiap temuan FAIL guna memastikan akar penyebab
- [ ] `FLAG_SECURE` diterapkan dengan granularitas tepat (per-Activity sensitif, bukan global)
- [ ] **Verifikasi ulang:** jalankan kembali MASTG-TEST-0289 setiap penambahan layar baru yang menampilkan data sensitif

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0289: Runtime Verification of Sensitive Content Exposure in Screenshots During App Backgrounding](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0289/)
- [MASWE-0038: Insufficient Protection of Sensitive Data from Screenshots or Screen Recordings](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0038/)
- [MASTG-BEST-0014: Preventing Screenshots and Screen Recording](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0014/)
- [MASTG-TECH-0002: Retrieving Files from Device Storage](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0002/)

### 5.2 Dokumentasi Resmi Android

- [Android Developers — Secure Sensitive Activities (Fraud Prevention)](https://developer.android.com/security/fraud-prevention/activities)
- [Android Developers — `FLAG_SECURE` reference](https://developer.android.com/security/fraud-prevention/activities#flag_secure)
- [Android Developers — Recents Screen (Overview)](https://developer.android.com/guide/components/activities/recents)
- [Google Play Console Help — FLAG_SECURE and REQUIRE_SECURE_ENV](https://support.google.com/googleplay/android-developer/answer/14638385?hl=en)

### 5.3 Riset dan Kasus Nyata

- [Medium — Handling the Recents Screen with FLAG_SECURE (celah timing onPause)](https://kimmandoo.medium.com/handling-the-recents-screen-with-flag-secure-bd13f70ada0e)
- [GitHub lesspass/lesspass#906 — Fix: add FLAG_SECURE to prevent screenshots and recent apps exposure](https://github.com/lesspass/lesspass/pull/906)
- [Ostorlab — Understanding Android's FLAG_SECURE for Screen Security](https://blog.ostorlab.co/understanding-android-flag-secure-screen-security.html)
- [Medium — Stop Using FLAG_SECURE: A Better Way to Protect Sensitive Screens in Jetpack Compose](https://medium.com/pickme-engineering-blog/stop-using-flag-secure-heres-a-better-way-to-protect-sensitive-screens-in-jetpack-compose-bf03fc853674)
- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
- [CWE-311: Missing Encryption of Sensitive Data](https://cwe.mitre.org/data/definitions/311.html)

### 5.4 Dokumentasi Tools

- [scrcpy — Display and control Android devices](https://github.com/Genymobile/scrcpy)
- [Tesseract OCR](https://github.com/tesseract-ocr/tesseract)
- [Frida — Dynamic instrumentation toolkit](https://frida.re/docs/javascript-api/)

---

*Dokumen ini disusun berdasarkan OWASP MASTG (rilis terkini per September 2026), dokumentasi resmi Android Developers, serta riset komunitas dan kasus nyata (termasuk kerentanan pada aplikasi password manager) tentang kebocoran data lewat screenshot Recents screen. Temuan paling signifikan: `FLAG_SECURE` yang diterapkan secara kondisional di `onPause()` rentan terhadap **celah timing race condition** — sistem dapat mengambil screenshot sebelum flag tersebut sempat diterapkan, karena capture tidak dijamin sinkron dengan siklus hidup Activity. Ini alasan fundamental mengapa test ini dirancang sebagai pengujian dinamis yang memeriksa bukti visual nyata, bukan sekadar audit kode statis keberadaan `FLAG_SECURE`.*
