# MASTG-TEST-0295 GMS Security Provider Not Updated

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0295 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-NETWORK (MASVS-NETWORK-1) |
| **Weakness** | MASWE-0027 — *Insecure Certificate Validation* |
| **API yang disorot** | `ProviderInstaller.installIfNeeded()`, `ProviderInstaller.installIfNeededAsync()`, `ProviderInstaller.ProviderInstallListener` |
| **Tipe Pengujian** | Static, Code |
| **Knowledge** | MASTG-KNOW-0011, MASTG-KNOW-0010 (Exception Handling) |
| **Best Practice** | MASTG-BEST-0020 (Update the GMS Security Provider) |
| **Teknik terkait** | MASTG-TECH-0013, MASTG-TECH-0014 |
| **Demo terkait** | — (tidak ada) |
| **Rule resmi** | — (**tidak ada rule semgrep khusus** untuk topik ini; sebuah rule bernama serupa `mastg-android-hardcoded-security-provider.yaml` ditemukan di repositori MASTG, namun menyasar topik yang **sama sekali berbeda** — hardcoded crypto provider di `Cipher.getInstance()`, bukan `ProviderInstaller` — lihat §3.2) |
| **CWE terkait** | CWE-295, CWE-327 (Use of a Broken or Risky Cryptographic Algorithm) |

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian

Kutipan overview resmi MASTG:

> *"This test checks whether the Android app ensures the Security Provider is updated to mitigate SSL/TLS vulnerabilities. The provider should be updated using Google Play Services APIs, and the implementation should handle exceptions properly."*

Test ini menyasar mekanisme yang **cukup unik** dibanding kebanyakan test MASVS-NETWORK lain dalam seri riset ini — bukan soal konfigurasi kode aplikasi sendiri (seperti NSC, `HostnameVerifier`, `TrustManager`), melainkan soal **apakah aplikasi memanfaatkan mekanisme pembaruan independen** yang disediakan **Google Play Services** untuk menambal komponen kriptografi inti sistem operasi — **tanpa** perlu menunggu update OS Android itu sendiri.

### 1.2 Mengapa Mekanisme Ini Diperlukan: Fragmentasi Android dan Update OS yang Lambat

MASTG-BEST-0020 menjelaskan rationale fundamental di balik keberadaan mekanisme ini:

> *"Android devices vary widely in OS version and update frequency. Relying solely on platform-level security can leave apps exposed to outdated SSL/TLS implementations and known vulnerabilities."*

Ini mengatasi masalah **fragmentasi Android** yang sudah lama dikenal — produsen perangkat (OEM) seringkali **lambat atau berhenti sama sekali** mendistribusikan update keamanan OS ke device yang sudah dijual, meninggalkan jutaan pengguna dengan implementasi SSL/TLS yang usang dan rentan secara struktural, **terlepas** dari seberapa baik kode aplikasi itu sendiri ditulis. **GMS Security Provider** (dikirim lewat Google Play Services) memecahkan masalah ini dengan cara yang elegan:

> *"The GMS Security Provider addresses this by updating critical cryptographic components—such as `OpenSSL` and `TrustManager`—**independently of the Android OS**."*

Ini artinya komponen kriptografi inti (implementasi `OpenSSL`, `TrustManager`) dapat **diperbarui lewat Google Play Services** — jalur distribusi yang jauh lebih cepat dan tidak bergantung pada OEM — **tanpa** perlu menunggu update OS Android penuh yang mungkin tidak akan pernah datang untuk device tersebut.

### 1.3 Kasus Nyata: CVE-2014-0224 (Celah yang Mendasari Dibuatnya Mekanisme Ini)

Dokumentasi resmi Android secara eksplisit mengutip kerentanan konkret yang menjadi motivasi historis penciptaan mekanisme ini:

> *"CVE-2014-0224 in OpenSSL allowed on-path attackers to decrypt secure traffic. Google Play services version 5.0+ offers fixes."*

CVE-2014-0224 adalah kerentanan **ChangeCipherSpec Injection** pada OpenSSL — memungkinkan penyerang *on-path* (MITM) memaksa kedua pihak komunikasi memakai kunci sesi yang lemah/dapat diprediksi, secara efektif mendekripsi traffic yang seharusnya terenkripsi TLS. Karena OpenSSL adalah komponen inti dari stack TLS Android, kerentanan semacam ini **mustahil diperbaiki** hanya lewat kode aplikasi semata — ia menuntut pembaruan pada level library sistem itu sendiri, yang kemudian menjadi justifikasi langsung bagi keberadaan `ProviderInstaller`.

### 1.4 Caveat Kritis yang Sering Terlewat: `SSLCertificateSocketFactory` TIDAK Ikut Diperbarui

Ini adalah **nuansa paling penting** dari seluruh dokumen ini, dan secara eksplisit diperingatkan dokumentasi resmi:

> *"Updating the `Provider` does **not** update the deprecated `android.net.SSLCertificateSocketFactory`, which remains vulnerable. Use high-level methods like `HttpsURLConnection` instead."*

Ini konsisten dengan pola tema berulang yang sudah dibahas di beberapa dokumen lain dalam seri riset ini (MASTG-TEST-0234 tentang `SSLSocket`) — **API level-rendah yang dibangun manual** cenderung berada **di luar jangkauan** mekanisme proteksi platform yang bekerja di level lebih tinggi. Aplikasi yang **masih memakai** `SSLCertificateSocketFactory` (API yang sudah **deprecated**, namun masih mungkin ditemukan di basis kode lawas) **tidak akan mendapat manfaat apa pun** dari pembaruan `ProviderInstaller`, **meski** `installIfNeeded()` berhasil dipanggil dan dieksekusi dengan sempurna. Ini artinya evaluasi test ini **tidak lengkap** bila hanya memeriksa keberadaan pemanggilan `ProviderInstaller` — penguji **juga harus** memverifikasi bahwa aplikasi tidak memakai jalur API lawas yang tidak tersentuh pembaruan ini sama sekali.

### 1.5 Dua Jalur Implementasi dan Kebutuhan Penanganan Exception yang Berbeda

Overview resmi menyoroti dua pendekatan implementasi yang masing-masing menuntut pola penanganan error yang berbeda:

**`installIfNeeded()` (sinkron)** — dipakai saat thread pemanggil boleh blocking (mis. background worker):

```kotlin
try {
    ProviderInstaller.installIfNeeded(context)
} catch (e: GooglePlayServicesRepairableException) {
    // Google Play Services usang — tampilkan notifikasi perbaikan ke pengguna
    GoogleApiAvailability.getInstance().showErrorNotification(context, e.connectionStatusCode)
} catch (e: GooglePlayServicesNotAvailableException) {
    // Error permanen — provider TIDAK BISA diperbarui di device ini
}
```

**`installIfNeededAsync()` (asinkron)** — dipakai di UI thread, melaporkan hasil lewat `ProviderInstallListener`:

```kotlin
override fun onProviderInstalled() {
    // Provider sudah terkini — aman melanjutkan koneksi jaringan
}
override fun onProviderInstallFailed(errorCode: Int, recoveryIntent: Intent) {
    if (GoogleApiAvailability.getInstance().isUserResolvableError(errorCode)) {
        // Tampilkan dialog perbaikan
    } else {
        // Treat seluruh komunikasi HTTP sebagai RENTAN
    }
}
```

Tabel exception dan penanganannya:

| Exception/Callback | Penyebab | Penanganan yang Benar |
|---|---|---|
| `GooglePlayServicesRepairableException` | Google Play Services usang/nonaktif/tidak tersedia | Tampilkan dialog ke pengguna untuk install/update/aktifkan Play Services |
| `GooglePlayServicesNotAvailableException` | Error permanen, provider **tidak bisa** diperbarui | **Perlakukan seluruh komunikasi HTTP sebagai rentan** — ambil tindakan fallback yang sesuai |
| `onProviderInstallFailed()` dengan error tidak dapat diperbaiki pengguna | Sama seperti di atas, via jalur async | Sama — anggap komunikasi HTTP rentan |

### 1.6 Poin Evaluasi Kritis: Timing — Harus Terjadi SEBELUM Koneksi Jaringan

Klausul Evaluation resmi menegaskan persyaratan timing yang tegas:

> *"Check that these calls occur **before any network connections are made**."*

Ini logis secara langsung — bila `ProviderInstaller.installIfNeeded()` dipanggil **setelah** aplikasi sudah mulai membuat koneksi jaringan menggunakan provider kriptografi yang lama/rentan, maka koneksi-koneksi awal tersebut **tetap akan memakai implementasi yang belum diperbarui**, membuat keseluruhan upaya pembaruan menjadi tidak efektif untuk jendela waktu tersebut. Pemanggilan ini idealnya terjadi **sedini mungkin** dalam siklus hidup aplikasi — pada `Application.onCreate()` atau activity peluncur paling awal, **sebelum** inisialisasi HTTP client (`OkHttpClient`, `Retrofit`, dsb.) selesai dibangun dan dipakai.

### 1.7 Skenario Khusus: Device Tanpa Google Play Services

MASTG-BEST-0020 memberi catatan penting untuk ekosistem device yang semakin terfragmentasi:

> *"If your app needs to support devices both with and without Google Play Services (such as Huawei devices, Amazon tablets, or AOSP-based ROMs), implement runtime checks to detect Play Services availability... On non-GMS devices, consider bundling a secure TLS library like Conscrypt."*

Ini relevan khususnya untuk aplikasi yang didistribusikan di luar Google Play Store resmi atau menargetkan pasar dengan ekosistem Android alternatif (mis. Huawei AppGallery/HMS, device Amazon Fire) — **seluruh mekanisme `ProviderInstaller` menjadi tidak relevan** pada device tanpa GMS, dan aplikasi membutuhkan **strategi mitigasi terpisah** (mem-bundle library TLS mandiri seperti **Conscrypt**) untuk tetap memastikan keamanan kriptografi yang konsisten di seluruh basis penggunanya.

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | Fungsi |
|---|---|
| **jadx** | Dekompilasi DEX → Java untuk pencarian pola `ProviderInstaller` |
| **grep / ripgrep** | Pencarian pola API dan penanganan exception terkait |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **CodeQL** | Menelusuri apakah pemanggilan `ProviderInstaller.installIfNeeded()` benar-benar terjadi **sebelum** inisialisasi HTTP client (`OkHttpClient.Builder().build()`, dsb.) dalam urutan eksekusi kode (§1.6) |
| **grep untuk `SSLCertificateSocketFactory`** | Verifikasi tambahan wajib sesuai §1.4 — memastikan aplikasi tidak memakai API lawas yang tidak tersentuh pembaruan provider |
| **MobSF** | Kadang menampilkan penggunaan Google Play Services API di laporan Code Analysis |
| **Frida** | Hooking `ProviderInstaller.installIfNeeded()`/`installIfNeededAsync()` untuk konfirmasi runtime bahwa pemanggilan benar-benar terjadi dan tidak melempar exception yang tidak tertangani |

### 2.3 Prasyarat Lingkungan

- **Tidak butuh device/root** untuk analisis statis inti.
- **Untuk verifikasi dinamis**, idealnya diuji pada device/emulator dengan Google Play Services yang sengaja diset usang/nonaktif untuk mengonfirmasi penanganan exception bekerja sesuai desain.
- **Periksa apakah aplikasi menargetkan device non-GMS** (§1.7) sebagai konteks evaluasi — bila ya, keberadaan `ProviderInstaller` saja tidak cukup; periksa juga strategi fallback untuk device tersebut.

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0013** untuk reverse engineer aplikasi.
2. Gunakan **MASTG-TECH-0014** untuk mencari API yang relevan.

### 3.2 Metode A — grep/ripgrep untuk Pemanggilan dan Exception Handling

```bash
D=./decompiled/sources

# Temukan pemanggilan ProviderInstaller
rg -n 'ProviderInstaller\.installIfNeeded\(|ProviderInstaller\.installIfNeededAsync\(' $D

# Verifikasi penanganan exception untuk jalur sinkron
rg -n -A15 'ProviderInstaller\.installIfNeeded\(' $D | grep -A15 "installIfNeeded" | grep -c "GooglePlayServicesRepairableException\|GooglePlayServicesNotAvailableException"

# Verifikasi implementasi ProviderInstallListener untuk jalur asinkron
rg -n 'implements ProviderInstaller\.ProviderInstallListener|onProviderInstalled\(\)|onProviderInstallFailed\(' $D

# WAJIB: cari pemakaian API lawas yang TIDAK tersentuh pembaruan provider (§1.4)
rg -n 'SSLCertificateSocketFactory' $D
```

**Catatan tentang rule resmi**: tidak ada rule semgrep MASTG yang secara spesifik menyasar topik `ProviderInstaller` ini. Rule bernama mirip (`mastg-android-hardcoded-security-provider.yaml`) yang tersedia di repositori sama **menyasar topik yang sama sekali berbeda** — ia mendeteksi pemanggilan `Cipher.getInstance(algo, provider)` dengan provider kriptografi yang di-hardcode secara eksplisit (relevan untuk audit kualitas implementasi kriptografi umum, bukan untuk verifikasi pembaruan provider via Google Play Services). Penguji **tidak boleh** keliru mengasosiasikan rule tersebut dengan test ini.

### 3.3 Metode B — CodeQL untuk Verifikasi Timing

```ql
import java

class ProviderInstallerCall extends MethodAccess {
  ProviderInstallerCall() {
    this.getMethod().hasName(["installIfNeeded", "installIfNeededAsync"]) and
    this.getMethod().getDeclaringType().hasQualifiedName("com.google.android.gms.security", "ProviderInstaller")
  }
}

class HttpClientInit extends MethodAccess {
  HttpClientInit() {
    this.getMethod().hasName("build") and
    this.getMethod().getDeclaringType().hasQualifiedName("okhttp3", "OkHttpClient$Builder")
  }
}

from HttpClientInit httpInit
where not exists(ProviderInstallerCall call |
  call.getControlFlowNode().getASuccessor*() = httpInit.getControlFlowNode())
select httpInit, "Inisialisasi HTTP client ditemukan TANPA ProviderInstaller dipanggil lebih dulu dalam urutan eksekusi"
```

### 3.4 Metode C — Frida untuk Konfirmasi Runtime

```javascript
// hook-provider-installer.js
Java.perform(function () {
    try {
        var ProviderInstaller = Java.use("com.google.android.gms.security.ProviderInstaller");
        ProviderInstaller.installIfNeeded.overload("android.content.Context").implementation = function (ctx) {
            console.log("[*] ProviderInstaller.installIfNeeded() dipanggil pada: " + new Date().toISOString());
            try {
                return this.installIfNeeded(ctx);
            } catch (e) {
                console.log("    [!] Exception: " + e);
                throw e;
            }
        };
    } catch (e) { console.log("[x] ProviderInstaller tidak ditemukan/tidak dipakai: " + e); }
});
```

### 3.5 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Kapan dipakai |
|---|---|---|
| **A** | grep | Baseline, termasuk verifikasi `SSLCertificateSocketFactory` |
| **B** | CodeQL | Verifikasi timing relatif terhadap inisialisasi HTTP client |
| **C** | Frida | Konfirmasi runtime pemanggilan dan exception |

**Kombinasi minimum yang aku rekomendasikan:** **A (termasuk pemeriksaan wajib `SSLCertificateSocketFactory`) → B (verifikasi timing)**.

---

### 3.6 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG:**

> **Evaluation:** *"The test case fails if the app does not update the provider, or it does not handle exceptions properly. Check that these calls occur before any network connections are made."*

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi |
|---|---|
| F1 | Aplikasi **tidak** memanggil `ProviderInstaller.installIfNeeded()`/`installIfNeededAsync()` sama sekali |
| F2 | Dipanggil, namun `GooglePlayServicesRepairableException`/`GooglePlayServicesNotAvailableException` **tidak ditangani** dengan benar (dibungkam, atau tidak ada fallback untuk kasus permanen) |
| F3 | Pemanggilan `installIfNeeded()` ditemukan terjadi **setelah** koneksi jaringan pertama dibuat (dikonfirmasi Metode B) |
| F4 | Aplikasi masih memakai `android.net.SSLCertificateSocketFactory` di jalur komunikasi mana pun — **tidak tersentuh** pembaruan provider sama sekali (§1.4) |

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi |
|---|---|
| P1 | `ProviderInstaller` dipanggil sedini mungkin, sebelum inisialisasi HTTP client manapun |
| P2 | Kedua jenis exception/callback ditangani sesuai pola resmi (§1.5), termasuk fallback eksplisit untuk kasus tidak dapat diperbaiki |
| P3 | Aplikasi **tidak** memakai `SSLCertificateSocketFactory` di jalur mana pun |
| P4 | Untuk aplikasi yang menargetkan device non-GMS, terdapat strategi fallback eksplisit (mis. Conscrypt) |

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **JANGAN bingung dengan rule semgrep yang namanya mirip** — sesuai §3.2, rule `mastg-android-hardcoded-security-provider.yaml` menyasar topik berbeda sama sekali.

2. **Verifikasi `SSLCertificateSocketFactory` adalah langkah wajib yang mudah terlewat** — `ProviderInstaller` yang diimplementasikan sempurna tetap tidak memberi proteksi apa pun bagi jalur komunikasi yang memakai API lawas ini.

3. **Timing adalah kriteria eksplisit resmi, bukan sekadar praktik terbaik** — verifikasi urutan eksekusi, bukan hanya keberadaan pemanggilan.

4. **Severity dimodulasi:**

   | Faktor | Severity |
   |---|---|
   | Tidak ada `ProviderInstaller` sama sekali, aplikasi menangani data sensitif | **Tinggi** |
   | `ProviderInstaller` ada tapi exception dibungkam/tidak ditangani | **Menengah-Tinggi** |
   | Masih memakai `SSLCertificateSocketFactory` di jalur mana pun | **Tinggi** — bypass langsung terhadap seluruh mekanisme proteksi ini |

5. **Dokumentasikan:** lokasi pemanggilan `ProviderInstaller`, status penanganan exception, hasil verifikasi timing, dan hasil pemeriksaan `SSLCertificateSocketFactory`.

---

## 4. Rekomendasi Perbaikan

### 4.1 Panggil Sedini Mungkin dengan Penanganan Exception Lengkap

```kotlin
class MyApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        try {
            ProviderInstaller.installIfNeeded(this)
        } catch (e: GooglePlayServicesRepairableException) {
            GoogleApiAvailability.getInstance().showErrorNotification(this, e.connectionStatusCode)
        } catch (e: GooglePlayServicesNotAvailableException) {
            // Tandai komunikasi HTTP sebagai rentan; terapkan fallback (mis. tolak fitur sensitif)
        }
    }
}
```

### 4.2 Hindari `SSLCertificateSocketFactory`

Migrasi seluruh jalur yang masih memakai API deprecated ini ke `HttpsURLConnection`/OkHttp.

### 4.3 Checklist Remediasi

- [ ] `ProviderInstaller` dipanggil sedini mungkin, sebelum koneksi jaringan apa pun
- [ ] Kedua jenis exception ditangani dengan fallback yang jelas
- [ ] `SSLCertificateSocketFactory` tidak dipakai di mana pun
- [ ] Strategi fallback untuk device non-GMS sudah dipertimbangkan (bila relevan)
- [ ] **Verifikasi ulang:** jalankan kembali MASTG-TEST-0295 setelah perubahan inisialisasi jaringan

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0295: GMS Security Provider Not Updated](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0295/)
- [MASWE-0027: Insecure Certificate Validation](https://mas.owasp.org/MASWE/MASVS-NETWORK/MASWE-0027/)
- [MASTG-BEST-0020: Update the GMS Security Provider](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0020/)

### 5.2 Dokumentasi Resmi Android

- [Android Developers — Updating Your Security Provider to Protect Against SSL Exploits](https://developer.android.com/privacy-and-security/security-gms-provider)
- [Android Developers — `ProviderInstaller` API reference](https://developers.google.com/android/reference/com/google/android/gms/security/ProviderInstaller)
- [NVD — CVE-2014-0224 (OpenSSL ChangeCipherSpec Injection)](https://nvd.nist.gov/vuln/detail/CVE-2014-0224)
- [Conscrypt — TLS/crypto library untuk device non-GMS](https://conscrypt.org)

### 5.3 CWE

- [CWE-295: Improper Certificate Validation](https://cwe.mitre.org/data/definitions/295.html)
- [CWE-327: Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)

### 5.4 Dokumentasi Tools

- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [CodeQL — Documentation](https://codeql.github.com/docs/)
- [Frida — Dynamic instrumentation toolkit](https://frida.re/docs/javascript-api/)

---

*Dokumen ini disusun berdasarkan OWASP MASTG (rilis terkini per September 2026), dokumentasi resmi Android Developers, dan referensi CVE-2014-0224 sebagai konteks historis nyata yang mendasari keberadaan mekanisme `ProviderInstaller`. Nuansa terpenting: pembaruan provider via Google Play Services **tidak** menjangkau API level-rendah yang deprecated (`SSLCertificateSocketFactory`) — evaluasi yang lengkap menuntut verifikasi ganda: memastikan `ProviderInstaller` dipanggil dengan benar DAN memastikan tidak ada jalur komunikasi yang luput dari perlindungannya lewat API lawas tersebut. Tidak ditemukan rule semgrep resmi MASTG yang secara spesifik menyasar topik ini.*
