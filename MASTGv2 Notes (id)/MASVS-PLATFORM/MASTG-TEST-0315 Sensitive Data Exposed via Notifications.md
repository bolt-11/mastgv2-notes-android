# MASTG-TEST-0315 Sensitive Data Exposed via Notifications

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0315 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-PLATFORM (MASVS-PLATFORM-3) |
| **Weakness** | MASWE-0037 — *Unnecessary Exposure of Sensitive Data via Notifications* |
| **API yang disorot** | `NotificationManager`, `Notification.Builder`/`NotificationCompat.Builder` (`setContentTitle`, `setContentText`) |
| **Tipe Pengujian** | Static, Code |
| **Prasyarat** | `identify-sensitive-data` |
| **Best Practice** | MASTG-BEST-0027 (Preventing Sensitive Data Exposure in Notifications — berstatus placeholder) |
| **Teknik terkait** | MASTG-TECH-0013, MASTG-TECH-0014, MASTG-TECH-0117, MASTG-TECH-0150, MASTG-TECH-0126 |
| **Demo terkait** | — (tidak ada) |
| **Rule resmi** | `mastg-android-sensitive-data-in-notifications.yml` — hanya mendeteksi keberadaan `setContentTitle`/`setContentText`, tidak menilai isi (pola yang konsisten dengan beberapa rule inventarisasi lain dalam seri riset ini) |
| **CWE terkait** | CWE-200, CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor) |

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian

Kutipan overview resmi MASTG:

> *"This test verifies that the app correctly handles notifications, ensuring that sensitive information, such as personally identifiable information (PII), one-time passwords (OTPs), or other sensitive data, like health or financial details, is not exposed."*

Notifikasi Android adalah permukaan kebocoran data yang **unik** dibanding kebanyakan vektor lain dalam seri riset ini — ia dirancang **secara sengaja untuk terlihat** oleh siapa pun yang berada di dekat device, **termasuk saat device terkunci** (lock screen). Ini menciptakan risiko *"shoulder surfing"* yang secara eksplisit disebut overview resmi: *"Notification usage should not expose sensitive information that could be disclosed accidentally, e.g., through shoulder surfing or when sharing the device with another person."*

### 1.2 Konteks Risiko Nyata: OTP di Lock Screen

Ini kasus yang **sangat umum dialami** pengguna nyata dan menjadi contoh paling ikonik dari risiko test ini — laporan komunitas pengguna secara eksplisit mengeluhkan:

> *"OTP is received on the lock screen and is clearly visible to others, which violates security — the received OTP message tells users not to share the OTP, but in this case it could be seen by anyone who glances at the device."*

Ironi dari kasus ini cukup tajam: pesan OTP itu sendiri biasanya **secara eksplisit memperingatkan** pengguna untuk tidak membagikan kode tersebut ke siapa pun — namun **notifikasi yang menampilkan kode tersebut secara penuh di lock screen** pada dasarnya **membagikannya** kepada siapa pun yang melihat ke arah layar device, tanpa perlu membuka kunci atau memiliki akses apa pun ke aplikasi.

### 1.3 Respons Platform Terkini: Android 16 Secara Otomatis Menyamarkan OTP

Ini konteks yang sangat relevan dan terkini — Google sendiri **mengakui skala masalah ini cukup signifikan** sehingga membangun mitigasi di level platform:

> *"Android 16 will automatically redact the contents of notifications containing one-time passwords (OTPs) from the lock screen in higher risk scenarios, such as when a user's device is not connected to Wi-Fi and has not been recently unlocked."*

Fakta bahwa Google merasa perlu membangun **deteksi otomatis berbasis heuristik** (mendeteksi pola teks yang menyerupai OTP dan secara otomatis menyamarkannya) sebagai fitur platform — alih-alih sepenuhnya mengandalkan developer aplikasi menerapkan praktik yang benar — adalah **pengakuan implisit** bahwa kelas kerentanan ini **sangat umum** terjadi di ekosistem aplikasi Android secara luas, cukup signifikan untuk menjustifikasi investasi rekayasa platform-level. Meski demikian, mitigasi otomatis ini **tidak bisa diandalkan sebagai satu-satunya pertahanan** — ia hanya aktif pada "skenario berisiko tinggi" tertentu (device tidak terhubung Wi-Fi dan belum baru saja dibuka kuncinya) dan baru tersedia sejak Android 16, sehingga **tetap menjadi tanggung jawab developer** untuk tidak menampilkan data sensitif di notifikasi sejak awal, pada seluruh versi Android yang didukung aplikasi.

### 1.4 Vektor Risiko Tambahan: `NotificationListenerService` dan Pencurian OTP oleh Malware

Di luar risiko *shoulder surfing* fisik, ada vektor serangan **digital** yang relevan sebagai konteks tambahan: aplikasi Android yang diberi **akses notifikasi** (`NotificationListenerService`, izin yang diminta pengguna lewat Settings, umum dipakai aplikasi legitimate seperti smartwatch companion app) dapat **membaca seluruh notifikasi** yang muncul di device — termasuk notifikasi OTP dari aplikasi lain. Ini adalah teknik yang **secara nyata dieksploitasi malware** untuk mencuri kode OTP perbankan secara otomatis tanpa perlu phishing atau interaksi pengguna sama sekali. Meski mitigasi untuk vektor spesifik ini (membatasi aplikasi mana yang boleh membaca notifikasi) berada di luar kendali langsung developer aplikasi yang **mengirim** notifikasi, ini tetap relevan sebagai konteks yang menguatkan **mengapa** tidak menampilkan OTP penuh di notifikasi sejak awal adalah pertahanan yang jauh lebih kuat dibanding mengandalkan pengguna untuk mengelola izin aplikasi pihak ketiga dengan benar.

### 1.5 Nuansa Krusial: Mengapa Evaluasi Memakai `minSdkVersion`, Bukan `targetSdkVersion`

Ini bagian **paling penting secara metodologis** dari test ini, dan overview resmi memberi penjelasan **paling eksplisit dan jelas** di antara seluruh test dalam seri riset ini yang pernah membahas nuansa serupa (bandingkan dengan pembahasan yang lebih implisit di dokumen MASTG-TEST-0245/0252/0285):

> *"Why `minSdkVersion` and not `targetSdkVersion`?: Using `minSdkVersion` ensures the test accounts for the **least secure environment** in which the app can operate, which is what determines the real exposure risk. `targetSdkVersion` only influences how the app behaves on newer Android versions and how the system enforces newer platform restrictions. It does not change the behavior of older Android versions. As a result, an app with a high `targetSdkVersion` but a low `minSdkVersion` must still be evaluated against the security guarantees, or lack thereof, of those older versions."*

Konteks konkret untuk test ini: sejak **Android 13 (API 33)**, aplikasi yang menargetkan API tersebut **wajib meminta** izin runtime `POST_NOTIFICATIONS` sebelum dapat mengirim notifikasi sama sekali — izin ini memberi pengguna **kendali eksplisit** untuk menolak notifikasi dari aplikasi tertentu sepenuhnya. Namun **di bawah API 33**, notifikasi **selalu diizinkan secara default** tanpa perlu persetujuan eksplisit apa pun dari pengguna. Ini artinya **populasi pengguna** yang menjalankan aplikasi pada device dengan API di bawah 33 **tidak memiliki kendali** atas apakah notifikasi (termasuk yang berisi data sensitif) akan muncul atau tidak — satu-satunya pertahanan yang tersisa adalah **developer tidak menempatkan data sensitif di notifikasi sejak awal**. Inilah mengapa `minSdkVersion` — yang menentukan **populasi device terburuk** yang bisa menjalankan aplikasi — menjadi parameter yang relevan untuk dievaluasi, bukan `targetSdkVersion` yang hanya memengaruhi perilaku pada versi Android yang lebih baru.

### 1.6 Formulasi Kondisi FAIL yang Presisi Berdasarkan `minSdkVersion`

Klausul Evaluation resmi memberi formulasi kondisi yang presisi, mengombinasikan temuan data sensitif dengan dua skenario `minSdkVersion` yang berbeda:

> *"The test case fails if the app exposes any sensitive data in any notifications **and** either:*
> - *`minSdkVersion` is `33` or higher and the `POST_NOTIFICATIONS` permission is declared in the manifest file, or*
> - *`minSdkVersion` is `32` or lower, regardless of whether the `POST_NOTIFICATIONS` permission is declared."*

Perhatikan **asimetri logis** pada kedua cabang kondisi ini:

| Skenario `minSdkVersion` | Kondisi Tambahan yang Diperlukan untuk FAIL |
|---|---|
| **≥ 33** | **Harus** ada deklarasi `POST_NOTIFICATIONS` di manifest (bila tidak dideklarasikan, aplikasi **tidak bisa** mengirim notifikasi sama sekali pada populasi device tersebut — menjadi moot point) |
| **≤ 32** | **Tidak peduli** apakah `POST_NOTIFICATIONS` dideklarasikan atau tidak — notifikasi akan tetap bisa dikirim secara default pada populasi device tersebut |

Asimetri ini **konsisten secara logis** dengan §1.5 — pada device API 33+, keberadaan izin runtime memberi **sinyal yang relevan** untuk dicek (tanpa izin tersebut, notifikasi sama sekali tidak bisa muncul, sehingga risiko data sensitif di notifikasi menjadi tidak relevan secara praktis pada populasi tersebut); pada device API 32 ke bawah, **tidak ada mekanisme kontrol pengguna apa pun**, sehingga keberadaan deklarasi izin sama sekali tidak relevan untuk evaluasi — notifikasi tetap akan muncul apa pun yang dideklarasikan di manifest.

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | Fungsi |
|---|---|
| **jadx** | Dekompilasi DEX → Java untuk pencarian pola `setContentTitle`/`setContentText` |
| **grep / ripgrep** | Pencarian pola API dan verifikasi konten yang diteruskan |
| **semgrep** | Menjalankan rule resmi sebagai baseline lokasi |
| **aapt2 / apkanalyzer** | Ekstraksi `minSdkVersion` dan status deklarasi `POST_NOTIFICATIONS` |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **CodeQL** | Menelusuri apakah variabel yang diteruskan ke `setContentText`/`setContentTitle` berasal dari sumber yang diketahui sensitif (field bernama `otp`, `password`, hasil API response finansial, dsb.) |
| **Frida** | Hooking `Notification.Builder.setContentText()`/`setContentTitle()` untuk menangkap nilai **aktual** yang ditampilkan saat runtime, termasuk kasus di mana teks dibangun secara dinamis dan sulit dianalisis statis |
| **MobSF** | Kadang menampilkan penggunaan `NotificationManager` di laporan Code Analysis |

### 2.3 Prasyarat Lingkungan

- **Tidak butuh device/root** untuk analisis statis inti.
- **Ekstraksi `minSdkVersion` dan status `POST_NOTIFICATIONS` adalah langkah wajib pertama** (§1.6) — evaluasi FAIL/PASS tidak dapat ditentukan tanpa kedua informasi ini.
- **Identifikasi data sensitif terlebih dahulu** (prasyarat `identify-sensitive-data`) untuk menentukan jenis konten notifikasi apa yang relevan diperiksa.

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0013** untuk reverse engineer aplikasi.
2. Gunakan **MASTG-TECH-0014** untuk mencari API yang relevan.
3. Gunakan **MASTG-TECH-0117** untuk memperoleh `AndroidManifest.xml`.
4. Gunakan **MASTG-TECH-0150** untuk memperoleh `minSdkVersion`.
5. Gunakan **MASTG-TECH-0126** untuk memperoleh izin yang relevan (`POST_NOTIFICATIONS`).

### 3.2 Metode A — Rule Semgrep Resmi + Verifikasi Konteks Manual

```yaml
rules:
  - id: mastg-android-sensitive-data-in-notifications
    languages: [java]
    severity: WARNING
    message: "[MASVS-PLATFORM-3] Ensure that notifications do not contain sensitive information"
    pattern-either:
      - pattern: $X.setContentTitle(...)
      - pattern: $X.setContentText(...)
```

```bash
semgrep --config https://raw.githubusercontent.com/OWASP/mastg/master/rules/mastg-android-sensitive-data-in-notifications.yml ./decompiled/sources/
```

**Catatan tentang rule ini**: sesuai pola yang konsisten ditemukan pada rule-rule "inventarisasi lokasi" lain di seri riset ini, rule ini **hanya mendeteksi keberadaan** pemanggilan — tidak menilai apakah konten yang diteruskan benar-benar sensitif. Verifikasi isi tetap wajib dilakukan manual atau via Metode B/C.

```bash
jadx --no-src -d ./out target-app.apk
grep -oP 'minSdkVersion="\K[0-9]+' ./out/resources/AndroidManifest.xml
grep -i "POST_NOTIFICATIONS" ./out/resources/AndroidManifest.xml
```

### 3.3 Metode B — grep/ripgrep dengan Verifikasi Konten

```bash
D=./decompiled/sources

rg -n -B5 'setContentText\(|setContentTitle\(' $D | grep -iE "otp|password|token|balance|account|ssn|pin" -B5
```

### 3.4 Metode C — CodeQL untuk Korelasi Sumber Data Sensitif

```ql
import java

class NotificationContentCall extends MethodAccess {
  NotificationContentCall() {
    this.getMethod().hasName(["setContentText", "setContentTitle"])
  }
}

from NotificationContentCall call, Variable v
where v.getName().toLowerCase().regexpMatch(".*(otp|password|token|pin|balance|account|ssn).*") and
      call.getAnArgument() = v.getAnAccess()
select call, "Konten notifikasi berasal dari variabel bernama sensitif: " + v.getName()
```

### 3.5 Metode D — Frida untuk Konfirmasi Runtime

```javascript
// hook-notification-content.js
Java.perform(function () {
    var Builder = Java.use("android.app.Notification$Builder");
    Builder.setContentText.overload("java.lang.CharSequence").implementation = function (text) {
        console.log("[*] setContentText: " + text);
        return this.setContentText(text);
    };
    Builder.setContentTitle.overload("java.lang.CharSequence").implementation = function (title) {
        console.log("[*] setContentTitle: " + title);
        return this.setContentTitle(title);
    };
});
```

### 3.6 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Menilai isi? | Kapan dipakai |
|---|---|---|---|
| **A** | Rule semgrep + ekstraksi manifest | ❌ (hanya lokasi) | Baseline wajib |
| **B** | grep konteks | Manual | Verifikasi cepat |
| **C** | CodeQL | ✅ (heuristik nama variabel) | Codebase besar |
| **D** | Frida | ✅ (nilai aktual runtime) | Konfirmasi definitif, termasuk konten dinamis |

**Kombinasi minimum yang aku rekomendasikan:** **A (ekstraksi minSdkVersion/POST_NOTIFICATIONS wajib) → C/D (verifikasi isi) → terapkan formula evaluasi §1.6**.

---

### 3.7 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG** (rujuk §1.6 untuk penjelasan lengkap logikanya).

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi |
|---|---|
| F1 | Ditemukan data sensitif (OTP, PII, data finansial/kesehatan) dalam `setContentText`/`setContentTitle`, **DAN** (`minSdkVersion` ≥33 dengan `POST_NOTIFICATIONS` dideklarasikan) **ATAU** (`minSdkVersion` ≤32, terlepas status izin) |

**Contoh bukti (ilustratif — MASTG belum menyediakan demo resmi untuk test ini):**

```java
notificationBuilder.setContentTitle("Kode OTP Anda")
    .setContentText("Kode verifikasi: " + otpCode);  // OTP PENUH ditampilkan di notifikasi
```

```bash
$ grep -oP 'minSdkVersion="\K[0-9]+' AndroidManifest.xml
23
```

Interpretasi: `minSdkVersion=23` (≤32) — notifikasi berisi OTP penuh akan selalu muncul tanpa kendali pengguna apa pun pada seluruh populasi device yang didukung aplikasi. **FAIL**, persis pola yang dikeluhkan pengguna nyata (§1.2).

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi |
|---|---|
| P1 | Notifikasi tidak menampilkan data sensitif sama sekali (mis. "Anda memiliki kode verifikasi baru" tanpa menyertakan kode itu sendiri) |
| P2 | `minSdkVersion` ≥33 **dan** `POST_NOTIFICATIONS` **tidak** dideklarasikan (notifikasi tidak mungkin dikirim pada populasi device tersebut) |
| P3 | Data sensitif yang ditampilkan disamarkan (mis. `setVisibility(VISIBILITY_PRIVATE)` dikombinasikan dengan konten publik yang generik, menyembunyikan detail hanya di lock screen) |

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Terapkan formula §1.6 secara presisi** — jangan menyimpulkan FAIL/PASS tanpa terlebih dahulu mengekstrak `minSdkVersion` dan status `POST_NOTIFICATIONS`; kedua cabang kondisi memiliki logika yang berbeda.

2. **Rule resmi hanya menemukan lokasi, bukan menilai sensitivitas** — verifikasi isi tetap mutlak diperlukan.

3. **Manfaatkan `setVisibility(VISIBILITY_PRIVATE)` sebagai mitigasi parsial** — bila data sensitif memang harus ditampilkan di body notifikasi untuk kebutuhan UX, setidaknya sembunyikan detail tersebut dari lock screen dengan tetap menampilkan notifikasi generik.

4. **Jangan hanya mengandalkan mitigasi otomatis Android 16** (§1.3) — fitur ini baru, terbatas pada skenario tertentu, dan tidak berlaku pada versi Android yang lebih lama yang mungkin masih menjadi bagian signifikan dari basis pengguna aplikasi.

5. **Severity dimodulasi:**

   | Faktor | Severity |
   |---|---|
   | OTP/kredensial penuh di notifikasi, `minSdkVersion` rendah | **Tinggi** |
   | PII (nama, sebagian nomor) di notifikasi | **Menengah** |
   | Notifikasi generik tanpa data sensitif | **Bukan temuan** |

6. **Dokumentasikan:** lokasi kode pembuatan notifikasi, isi konten yang ditemukan, `minSdkVersion`, status `POST_NOTIFICATIONS`, dan hasil penerapan formula evaluasi §1.6.

---

## 4. Rekomendasi Perbaikan

### 4.1 Hindari Menampilkan Data Sensitif Secara Langsung

```java
// SEBELUM
.setContentText("Kode verifikasi: " + otpCode)

// SESUDAH
.setContentText("Anda memiliki kode verifikasi baru. Buka aplikasi untuk melihatnya.")
```

### 4.2 Gunakan `setVisibility(VISIBILITY_PRIVATE)` sebagai Lapisan Tambahan

```java
Notification notification = new Notification.Builder(context, channelId)
    .setContentTitle("Transaksi Baru")
    .setContentText("Rp 500.000 telah ditransfer")
    .setVisibility(Notification.VISIBILITY_PRIVATE)  // Detail disembunyikan di lock screen
    .setPublicVersion(genericNotification)  // Versi generik yang ditampilkan di lock screen
    .build();
```

### 4.3 Checklist Remediasi

- [ ] Seluruh pembuatan notifikasi diinventarisasi dan diperiksa isinya
- [ ] Data sensitif (OTP, kredensial, PII, data finansial) tidak ditampilkan langsung di `setContentText`/`setContentTitle`
- [ ] `setVisibility(VISIBILITY_PRIVATE)` diterapkan untuk notifikasi yang tetap mengandung sebagian info sensitif
- [ ] `minSdkVersion` dan status `POST_NOTIFICATIONS` didokumentasikan sebagai konteks evaluasi
- [ ] **Verifikasi ulang:** jalankan kembali MASTG-TEST-0315 setiap penambahan jenis notifikasi baru

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0315: Sensitive Data Exposed via Notifications](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0315/)
- [MASWE-0037: Unnecessary Exposure of Sensitive Data via Notifications](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0037/)
- [MASTG-BEST-0027: Preventing Sensitive Data Exposure in Notifications](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0027/)
- [MASTG-TEST-0245: References to Platform Version APIs](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0245/) — pembahasan terkait nuansa minSdkVersion

### 5.2 Dokumentasi Resmi Android

- [Android Developers — `POST_NOTIFICATIONS` permission](https://developer.android.com/reference/android/Manifest.permission#POST_NOTIFICATIONS)
- [Android Developers — `Notification.Builder`](https://developer.android.com/reference/android/app/Notification.Builder)
- [Android Developers — `Notification.Builder#setVisibility()`](https://developer.android.com/reference/android/app/Notification.Builder#setVisibility(int))

### 5.3 Riset dan Kasus Nyata

- [OnePlus Community — OTP is received on lock screen and is clearly visible to others](https://community.oneplus.com/threads/otp-is-received-on-lock-screen-and-is-clearly-visible-to-others-which-violates-security.1083459/)
- [Android Authority — Android 16 automatically hides some sensitive notifications from the lock screen](https://www.androidauthority.com/android-16-sensitive-notifications-lock-screen-3501564/)
- [Android Police — Android 16 makes a subtle change to keep your OTPs safe](https://www.androidpolice.com/android-16-subtle-change-keeps-otps-safe/)
- [Android Police — Android 15 could stop apps from spying on your most sensitive notifications](https://www.androidpolice.com/android-15-stop-malware-from-stealing-otps/)
- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
- [CWE-359: Exposure of Private Personal Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/359.html)

### 5.4 Dokumentasi Tools

- [Semgrep — Documentation](https://semgrep.dev/docs/)
- [CodeQL — Documentation](https://codeql.github.com/docs/)
- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [Frida — Dynamic instrumentation toolkit](https://frida.re/docs/javascript-api/)

---

*Dokumen ini disusun berdasarkan OWASP MASTG (rilis terkini per September 2026), dokumentasi resmi Android Developers, serta riset komunitas dan laporan media tentang kebocoran OTP lewat notifikasi lock screen — termasuk respons platform terkini Android 16 yang membangun deteksi otomatis untuk masalah ini. Nuansa metodologis terpenting: test ini memberi penjelasan paling eksplisit di antara seluruh test dalam seri riset ini tentang mengapa `minSdkVersion` (bukan `targetSdkVersion`) menjadi parameter evaluasi yang benar — karena ia mencerminkan "populasi device paling tidak aman" yang bisa menjalankan aplikasi, yang menentukan risiko eksposur nyata, sementara `targetSdkVersion` hanya memengaruhi perilaku pada versi Android yang lebih baru.*
