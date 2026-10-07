# MASTG-TEST-0247 References to APIs for Detecting Secure Screen Lock

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0247 |
| **Platform** | Android |
| **Lokasi test resmi** | Folder **MASVS-RESILIENCE** di source MASTG |
| **Weakness** | MASWE-0017 — *Device Secure Lock Not Enforced* (dikategorikan di bawah **MASVS-CRYPTO**) |
| **Pesan rule semgrep resmi** | Menyebut **`[MASVS-STORAGE]`** |
| **API yang disorot** | `KeyguardManager` (`isDeviceSecure()`, `isKeyguardSecure()`), `BiometricManager#canAuthenticate()` |
| **Tipe Pengujian** | Static, Code |
| **Profile** | **L2 saja** |
| **Knowledge** | MASTG-KNOW-0001 *(catatan: ID ini sebenarnya tidak ada di kategori MASVS-STORAGE seperti pola penomoran umumnya — dokumen MASTG-KNOW-0001 yang valid berjudul "Biometric Authentication" di bawah kategori **MASVS-AUTH**, lihat §1.6)* |
| **Teknik terkait** | MASTG-TECH-0013 (Reverse Engineering), MASTG-TECH-0014 (Static Analysis) |
| **Test terkait** | Berkaitan erat dengan pengujian Android Keystore (`setUserAuthenticationRequired`) dan biometric authentication (MASVS-AUTH) |
| **Demo terkait** | — (tidak ada) |
| **Rule resmi** | `mastg-android-device-passcode-present.yml` (ada, tapi cakupannya sempit — lihat §3.2) |
| **CWE terkait** | CWE-287 (Improper Authentication), CWE-862 (Missing Authorization) |

---

## 1. Penjelasan

### 1.1 Sorotan Metadata: Empat Sumber Resmi, Tiga Kategori MASVS Berbeda

Sebelum membahas substansi teknis, ada temuan metadata yang perlu ditegaskan di awal karena ini yang **paling mencolok** ditemukan sepanjang seri riset dokumen ini. Untuk satu test yang sama, empat sumber resmi MASTG memberikan atribusi kategori MASVS yang **saling berbeda**:

| Sumber | Kategori MASVS yang tersirat |
|---|---|
| Lokasi file test `MASTG-TEST-0247.md` di repositori | **MASVS-RESILIENCE** |
| `maswe: [MASWE-0017]` di frontmatter test | Merujuk ke weakness yang dikategorikan **MASVS-CRYPTO** |
| Pesan rule semgrep resmi (`mastg-android-device-passcode-present.yml`) | **`[MASVS-STORAGE]`** |
| Substansi teknis API (`KeyguardManager`, `BiometricManager`) | Paling relevan secara konseptual dengan **MASVS-AUTH** (autentikasi) |

Ini bukan sekadar detail administratif — kesimpangsiuran kategori berdampak nyata pada bagaimana temuan test ini **dikelompokkan dan diprioritaskan** dalam laporan audit atau sistem tracking kerentanan yang mengorganisasi hasil berdasarkan kategori MASVS. Untuk keperluan praktis, dokumen ini akan mengikuti substansi teknisnya (autentikasi/kontrol akses kunci kriptografi) sambil tetap mencatat ketiga atribusi resmi tersebut apa adanya.

### 1.2 Tujuan Pengujian

Kutipan overview resmi MASTG:

> *"This test verifies whether an app is running on a device with a passcode set. Android apps can determine whether a secure screen lock (such as PIN, or password) is enabled by using platform-provided APIs."*

Dua jalur API resmi yang diperiksa test ini:

1. **`KeyguardManager.isDeviceSecure()`** — mengembalikan `true` bila device memiliki lock screen aman (PIN/pola/password), berbeda dari sekadar swipe-to-unlock atau tanpa lock sama sekali.
2. **`BiometricManager#canAuthenticate(int)`** — dapat dipakai sebagai **jalur alternatif** ketika `KeyguardManager` tidak tersedia atau dibatasi vendor device tertentu, karena otentikasi biometrik di Android **mensyaratkan** adanya screen lock aman sebagai fallback-nya.

### 1.3 Mengapa Ini Penting: Koneksi ke Android Keystore dan `setUserAuthenticationRequired`

Ini konteks teknis paling penting yang menjelaskan **mengapa** test ini dikategorikan terkait kriptografi (MASWE-0017/MASVS-CRYPTO) meski API yang diperiksa terlihat seperti masalah autentikasi murni. Android Keystore System menyediakan flag `setUserAuthenticationRequired(true)` saat membuat kunci kriptografi — flag ini **mengikat kemampuan memakai kunci tersebut** pada status device yang sudah di-unlock lewat kredensial pengguna (PIN/pola/password/biometrik).

Sesuai persyaratan kompatibilitas Android (Android CDD — Compatibility Definition Document):

> *"Devices MUST NOT authenticate access to keystores if the application has called `KeyGenParameterSpec.Builder.setUserAuthenticationRequired(true)`. Keys MUST be unlocked for third-party developer apps to use when the user unlocks the secure lock screen."*

Konsekuensi krusialnya: **bila device tidak memiliki secure lock screen sama sekali**, mekanisme "unlock lewat kredensial pengguna" ini **tidak pernah bisa terpicu** — perilaku sistem terhadap kunci yang dilindungi `setUserAuthenticationRequired(true)` pada kondisi ini bervariasi tergantung versi Android dan implementasi vendor, namun secara umum menciptakan **kondisi ambigu** yang tidak diantisipasi desain keamanan aplikasi: kunci mungkin tetap dapat diakses tanpa gate otentikasi yang seharusnya berlaku, atau sebaliknya aplikasi mengalami kegagalan fungsi tak terduga. Kasus nyata dari proyek dompet kripto open-source (`dashpay/platform`, pull request *"keep Keystore's unlocked-device gate from bricking wallets and signing on defective OEM builds"*) menggambarkan sisi lain dari masalah ini: beberapa build OEM yang cacat/tidak standar menyebabkan gate ini justru **mem-brick** kemampuan dompet untuk menandatangani transaksi — menunjukkan betapa rapuhnya asumsi "device pasti punya secure lock" bila tidak diverifikasi secara eksplisit oleh aplikasi terlebih dahulu.

**Inilah nilai dari test ini**: dengan memeriksa `isDeviceSecure()` **sebelum** mengandalkan kunci yang dilindungi `setUserAuthenticationRequired`, aplikasi dapat secara proaktif menampilkan peringatan kepada pengguna ("Aktifkan kunci layar untuk memakai fitur ini") alih-alih membiarkan perilaku ambigu sistem terjadi secara diam-diam.

### 1.4 Keterbatasan yang Diakui Secara Eksplisit: Aplikasi Tidak Bisa Memaksa

Overview resmi memberi batasan penting yang harus dipahami sebelum menilai temuan:

> *"Apps **cannot force** users to enable biometrics at the system level, only enforce their use within the app for accessing sensitive functionality."*

Ini artinya nilai dari test ini **bukan** tentang mengubah pengaturan sistem pengguna, melainkan tentang **apakah aplikasi bereaksi secara tepat** terhadap kondisi tersebut — mis. menolak mengaktifkan fitur yang membutuhkan kunci terproteksi otentikasi, atau menampilkan peringatan eksplisit, ketimbang diam-diam melanjutkan operasi sensitif tanpa mempedulikan status keamanan device sama sekali.

### 1.5 Dua Metode API yang Saling Melengkapi, Bukan Duplikat

Sesuai §1.2, `BiometricManager#canAuthenticate()` bukan sekadar cara lain untuk memeriksa hal yang sama — ia punya alasan keberadaan spesifik: **beberapa produsen device membatasi atau memodifikasi perilaku `KeyguardManager`** di luar spesifikasi AOSP standar (fragmentasi ekosistem Android yang terkenal luas). Ketergantungan hanya pada satu API berisiko memberi hasil salah pada device dari vendor tertentu. Aplikasi yang robust idealnya memiliki **fallback logic** yang mencoba kedua jalur ini.

### 1.6 Catatan tentang MASTG-KNOW-0001

Frontmatter resmi test ini merujuk `knowledge: [MASTG-KNOW-0001]`, namun penelusuran langsung terhadap ID tersebut di jalur kategori yang lazim (`MASVS-STORAGE`, mengikuti pola penomoran kebanyakan dokumen `MASTG-KNOW-00xx` awal yang jatuh di kategori Storage) mengembalikan hasil tidak ditemukan. Dokumen dengan judul paling relevan secara substansi (**"Biometric Authentication"**) justru ditemukan di kategori **MASVS-AUTH**. Ini konsisten dengan pola inkonsistensi referensi metadata yang berulang kali ditemukan di seri riset dokumen ini (lihat juga catatan pada MASTG-TEST-0226, MASTG-TEST-0245) — kemungkinan menunjukkan skema penomoran/kategorisasi MASTG-KNOW sedang mengalami migrasi atau belum sepenuhnya konsisten di semua tautan silang antar dokumen.

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | Fungsi |
|---|---|
| **jadx** | Dekompilasi DEX → Java untuk pencarian pola `KeyguardManager`/`BiometricManager` |
| **grep / ripgrep** | Pencarian pola API — melengkapi cakupan rule resmi yang sempit |
| **semgrep** | Menjalankan rule resmi sebagai baseline |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **CodeQL** | Menelusuri apakah hasil `isDeviceSecure()`/`canAuthenticate()` benar-benar dipakai untuk mengondisikan akses ke kunci kriptografi (`setUserAuthenticationRequired`), bukan sekadar dipanggil tanpa efek nyata terhadap alur keamanan |
| **MobSF** | Kadang menandai penggunaan `KeyguardManager` di laporan Code Analysis |
| **Frida** | Hooking `KeyguardManager.isDeviceSecure()`/`isKeyguardSecure()` dan `BiometricManager.canAuthenticate()` untuk konfirmasi runtime — termasuk memaksa nilai kembalian palsu (`false`) untuk menguji bagaimana aplikasi bereaksi terhadap device yang **tidak** memiliki secure lock (uji perilaku aplikasi pada kondisi tepi) |
| **Android emulator tanpa lock screen** | Lingkungan uji dinamis paling langsung — jalankan aplikasi pada emulator/device uji yang sengaja tidak diset PIN/pola/password untuk mengamati perilaku aktual aplikasi |

### 2.3 Prasyarat Lingkungan

- **Tidak butuh device/root** untuk analisis statis inti.
- **Untuk uji dinamis**, siapkan emulator/device fisik dengan kondisi lock screen bervariasi (aman vs tidak aman/tanpa lock) untuk mengamati perbedaan perilaku aplikasi secara langsung.
- **Periksa juga apakah aplikasi memakai `setUserAuthenticationRequired`** pada `KeyGenParameterSpec`-nya (lihat dokumen-dokumen kriptografi terkait dalam seri ini) — ini konteks yang menentukan seberapa krusial temuan test ini bagi aplikasi tertentu.

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0013** untuk reverse engineer aplikasi.
2. Gunakan **MASTG-TECH-0014** untuk mencari API yang relevan.

### 3.2 Metode A — Rule Semgrep Resmi *(ada, tapi perlu diperluas)*

```yaml
rules:
  - id: mastg-android-device-passcode-present
    languages:
      - java
    severity: INFO
    metadata:
      summary: This rule searches for API that checks whether the device passcode is set.
    message: "[MASVS-STORAGE] Make sure to verify that your app runs on a device with a passcode set"
    pattern-either:
      - pattern: |
          $X.getSystemService("keyguard");
          ...
          $Y.isDeviceSecure();
      - pattern: |
          BiometricManager $BM = (BiometricManager) $X.getSystemService(BiometricManager.class);
          ...
          $BM.canAuthenticate($VAL);
```

```bash
jadx -d ./decompiled ./target-app.apk
semgrep --config https://raw.githubusercontent.com/OWASP/mastg/master/rules/mastg-android-device-passcode-present.yml ./decompiled/sources/
```

**Celah cakupan yang perlu diketahui:**

1. **`isKeyguardSecure()` tidak dicakup** — overview resmi menyebut dua metode (`isDeviceSecure()` dan `isKeyguardSecure()`), tapi rule hanya mencocokkan `isDeviceSecure()`. Kode yang murni memakai `isKeyguardSecure()` tidak akan terdeteksi rule ini.
2. **Pola bergantung pada literal string `"keyguard"`** sebagai argumen `getSystemService()` — kode yang memakai konstanta `Context.KEYGUARD_SERVICE` (pola yang justru lebih umum dan direkomendasikan dalam praktik idiomatis Android) berpotensi tidak cocok tergantung bagaimana semgrep menangani resolusi konstanta pada mesin pattern-matching-nya.
3. **`languages: [java]` saja** — pola serupa yang berulang ditemukan pada beberapa rule resmi lain dalam seri ini; kode Kotlin murni (bukan hasil dekompilasi jadx yang menyerupai Java) berisiko tidak cocok penuh.
4. **Severity `INFO`** — level severity terendah yang ditemukan di antara seluruh rule resmi MASTG yang sudah diperiksa dalam seri riset ini, mengindikasikan bahwa tim MASTG sendiri memandang ini sebagai sinyal informasional, bukan temuan tegas — konsisten dengan sifat test ini yang lebih ke arah *best practice* daripada kerentanan aktif berdampak langsung.

### 3.3 Metode B — grep/ripgrep untuk Menutup Celah `isKeyguardSecure()`

```bash
D=./decompiled/sources

# Pola resmi yang tercakup rule
rg -n 'isDeviceSecure\(\)' $D

# Pola yang TIDAK dicakup rule resmi
rg -n 'isKeyguardSecure\(\)' $D

# Variasi pemanggilan getSystemService dengan konstanta
rg -n 'getSystemService\(Context\.KEYGUARD_SERVICE\)|getSystemService\("keyguard"\)' $D

# BiometricManager — termasuk via Jetpack androidx.biometric
rg -n 'BiometricManager.*canAuthenticate|androidx\.biometric\.BiometricManager' $D
```

### 3.4 Metode C — CodeQL (Menilai Efek Nyata Pengecekan)

```ql
import java

class KeyguardCheck extends MethodAccess {
  KeyguardCheck() {
    this.getMethod().hasName(["isDeviceSecure", "isKeyguardSecure"]) or
    (this.getMethod().hasName("canAuthenticate") and
     this.getMethod().getDeclaringType().hasQualifiedName(["android.hardware.biometrics", "androidx.biometric"], "BiometricManager"))
  }
}

class UserAuthRequiredKeySpec extends MethodAccess {
  UserAuthRequiredKeySpec() {
    this.getMethod().hasName("setUserAuthenticationRequired")
  }
}

from KeyguardCheck check, UserAuthRequiredKeySpec keySpec
where check.getEnclosingCallable() = keySpec.getEnclosingCallable()
select check, "Pengecekan secure lock ditemukan pada method yang sama dengan konfigurasi kunci setUserAuthenticationRequired — korelasi baik"
```

Query ini membantu menjawab pertanyaan yang lebih bernilai secara keamanan dibanding sekadar "apakah API dipanggil": **apakah pengecekan tersebut benar-benar berkorelasi** dengan penggunaan kunci kriptografi yang bergantung pada status lock screen (§1.3), atau berdiri sendiri tanpa pengaruh nyata pada alur keamanan aplikasi.

### 3.5 Metode D — Uji Dinamis (Perilaku Aplikasi pada Device Tanpa Secure Lock)

```bash
# Pada emulator/device uji, hapus/nonaktifkan lock screen sepenuhnya
adb shell locksettings clear --old <PIN_LAMA>

# Jalankan aplikasi dan amati perilaku fitur yang seharusnya membutuhkan secure lock
# (mis. apakah tetap menampilkan opsi "aktifkan fitur X" tanpa peringatan?)
```

Hooking Frida untuk memaksa nilai kembalian (menguji ketahanan logika aplikasi terhadap kedua kondisi):

```javascript
// hook-force-no-secure-lock.js
Java.perform(function () {
    var KeyguardManager = Java.use("android.app.KeyguardManager");
    KeyguardManager.isDeviceSecure.overload().implementation = function () {
        console.log("[*] isDeviceSecure() dipanggil — memaksa return false untuk pengujian");
        return false;
    };
});
```

```bash
frida -U -f com.target.app -l hook-force-no-secure-lock.js --no-pause
```

Amati apakah aplikasi bereaksi sesuai ekspektasi (menampilkan peringatan/membatasi fitur) ketika API ini dipaksa mengembalikan `false`, dibanding tidak bereaksi sama sekali.

### 3.6 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Cakupan | Kapan dipakai |
|---|---|---|---|
| **A** | Rule semgrep resmi | Sebagian (`isDeviceSecure` saja) | Baseline cepat |
| **B** | grep pola lengkap | Penuh (termasuk `isKeyguardSecure`) | Baseline utama yang direkomendasikan |
| **C** | CodeQL | Menilai korelasi dengan penggunaan kunci kriptografi | Menjawab nilai keamanan sesungguhnya dari pengecekan |
| **D** | Uji dinamis + Frida | Perilaku nyata aplikasi | Konfirmasi bahwa pengecekan statis benar-benar berefek pada UX/keamanan |

**Kombinasi minimum yang aku rekomendasikan:** **B (grep lengkap, bukan hanya rule resmi) → C (korelasi dengan penggunaan kunci kriptografi) → D (konfirmasi perilaku dinamis)**.

---

### 3.7 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG:**

> **Observation:** *"The output should contain a list of locations where relevant APIs are used."*
>
> **Evaluation:** *"The test case fails if an app doesn't use any APIs to verify the presence of a secure screen lock."*

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi |
|---|---|
| F1 | **Tidak ditemukan** referensi `KeyguardManager.isDeviceSecure()`/`isKeyguardSecure()` maupun `BiometricManager#canAuthenticate()` di seluruh codebase |
| F2 | Aplikasi memakai kunci kriptografi dengan `setUserAuthenticationRequired(true)` **tanpa** pengecekan status secure lock terlebih dahulu (dikonfirmasi Metode C) — berisiko menghadapi perilaku ambigu sistem yang tidak diantisipasi (§1.3) |
| F3 | Uji dinamis (Metode D) menunjukkan aplikasi **tidak bereaksi** (tidak ada peringatan/pembatasan fitur) ketika device tidak memiliki secure lock, padahal fitur sensitif tetap dapat diakses |

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi |
|---|---|
| P1 | Ditemukan pengecekan `isDeviceSecure()`/`isKeyguardSecure()` atau `canAuthenticate()` yang dipakai untuk mengondisikan akses fitur sensitif |
| P2 | Korelasi (Metode C) mengonfirmasi pengecekan tersebut memang dilakukan sebelum atau berdekatan dengan penggunaan kunci `setUserAuthenticationRequired` |
| P3 | Uji dinamis (Metode D) mengonfirmasi aplikasi menampilkan peringatan yang sesuai/membatasi fitur sensitif ketika device tidak memiliki secure lock |

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Severity resmi rendah (`INFO`) mencerminkan sifat test ini sebagai *best practice*, bukan kerentanan berdampak langsung** — jangan melebih-lebihkan urgensi temuan ini dibanding kelemahan kriptografi aktif (mis. hardcoded key, algoritma rusak) yang sudah dibahas di dokumen-dokumen lain seri ini.

2. **Nilai sesungguhnya dari test ini terletak pada korelasinya dengan `setUserAuthenticationRequired`** (§1.3) — bila aplikasi tidak memakai kunci kriptografi yang terikat status lock screen sama sekali, ketiadaan pengecekan `isDeviceSecure()` jauh lebih kecil dampaknya dibanding pada aplikasi yang benar-benar bergantung padanya (mis. dompet kripto, aplikasi perbankan).

3. **Jangan lupakan `isKeyguardSecure()`** — rule resmi hanya mencakup `isDeviceSecure()`, sehingga pemeriksaan manual/grep tambahan (§3.3) wajib dilakukan agar tidak melewatkan implementasi yang memakai varian API yang lain.

4. **Ingat batasan yang diakui resmi (§1.4)**: aplikasi tidak bisa memaksa pengguna mengaktifkan lock screen di level sistem — evaluasi PASS/FAIL berfokus pada **reaksi aplikasi** terhadap kondisi tersebut, bukan pada kemampuannya mengubah pengaturan sistem.

5. **Severity dimodulasi:**

   | Faktor | Severity |
   |---|---|
   | Tidak ada pengecekan, **dan** aplikasi memakai `setUserAuthenticationRequired` untuk data finansial/kredensial sensitif | **Menengah** |
   | Tidak ada pengecekan, aplikasi tidak memakai kunci berbasis autentikasi sama sekali | **Rendah/Informational** — sesuai severity resmi rule |
   | Ada pengecekan tapi tidak berkorelasi dengan penggunaan kunci sensitif manapun | **Informational** |

6. **Dokumentasikan:** lokasi kode pengecekan (bila ada), API spesifik yang dipakai (`isDeviceSecure` vs `isKeyguardSecure` vs `canAuthenticate`), hasil korelasi dengan `setUserAuthenticationRequired`, dan hasil uji dinamis perilaku aplikasi pada device tanpa secure lock.

---

## 4. Rekomendasi Perbaikan

### 4.1 Terapkan Pengecekan dengan Fallback Berlapis

```kotlin
fun isDeviceSecureLockEnabled(context: Context): Boolean {
    val keyguardManager = context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
    if (keyguardManager.isDeviceSecure) {
        return true
    }
    // Fallback untuk device yang membatasi KeyguardManager (§1.5)
    val biometricManager = BiometricManager.from(context)
    return biometricManager.canAuthenticate(BiometricManager.Authenticators.DEVICE_CREDENTIAL) ==
            BiometricManager.BIOMETRIC_SUCCESS
}
```

### 4.2 Tolak/Batasi Fitur Sensitif Bila Tidak Ada Secure Lock

```kotlin
if (!isDeviceSecureLockEnabled(context)) {
    showWarningDialog(
        "Fitur ini membutuhkan kunci layar aman (PIN/pola/password) untuk melindungi data Anda. " +
        "Silakan aktifkan di Pengaturan > Keamanan."
    )
    return
}
// Lanjutkan dengan operasi yang memakai kunci setUserAuthenticationRequired
```

### 4.3 Selalu Korelasikan dengan Penggunaan Kunci Kriptografi

Pastikan setiap kunci yang dibuat dengan `setUserAuthenticationRequired(true)` didahului pengecekan ini di alur kode yang sama, agar pengguna mendapat pesan yang jelas alih-alih menghadapi kegagalan operasi kriptografi yang membingungkan.

### 4.4 Checklist Remediasi

- [ ] Pengecekan `isDeviceSecure()`/`isKeyguardSecure()` dengan fallback `BiometricManager` sudah diterapkan
- [ ] Fitur yang memakai kunci `setUserAuthenticationRequired` sudah dikorelasikan dengan pengecekan ini
- [ ] Aplikasi menampilkan pesan yang jelas ketika device tidak memiliki secure lock
- [ ] Uji dinamis pada device tanpa secure lock sudah dilakukan untuk memverifikasi perilaku
- [ ] **Verifikasi ulang:** jalankan kembali MASTG-TEST-0247 setelah perubahan terkait fitur autentikasi/kriptografi

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0247: References to APIs for Detecting Secure Screen Lock](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0247/)
- [MASWE-0017: Device Secure Lock Not Enforced](https://mas.owasp.org/MASWE/MASVS-CRYPTO/MASWE-0017/)
- [MASTG-KNOW: Biometric Authentication (MASVS-AUTH)](https://mas.owasp.org/MASTG/knowledge/android/MASVS-AUTH/MASTG-KNOW-0001/)
- [MASTG-TECH-0013: Reverse Engineering Android Apps](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/)
- [MASTG-TECH-0014: Static Analysis on Android](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/)
- [Rule resmi: mastg-android-device-passcode-present.yml (GitHub)](https://github.com/OWASP/mastg/blob/master/rules/mastg-android-device-passcode-present.yml)

### 5.2 Dokumentasi Resmi Android

- [Android Developers — `KeyguardManager` API reference](https://developer.android.com/reference/android/app/KeyguardManager)
- [Android Developers — `KeyguardManager.isDeviceSecure()`](https://developer.android.com/reference/android/app/KeyguardManager#isDeviceSecure())
- [Android Developers — `BiometricManager#canAuthenticate(int)`](https://developer.android.com/reference/android/hardware/biometrics/BiometricManager#canAuthenticate(int))
- [Android Developers — `BiometricPrompt`](https://developer.android.com/reference/android/hardware/biometrics/BiometricPrompt)
- [Android Compatibility Definition Document — Keys and Credentials](https://android.googlesource.com/platform/compatibility/cdd/+/refs/heads/o-mr1-iot-preview-6/9_security-model/9_11_keys-and-credentials.md)
- [Google Support — Set a screen lock on your Android device](https://support.google.com/android/answer/9079129)

### 5.3 Riset dan Kasus Nyata

- [GitHub dashpay/platform#4643 — Keep Keystore's unlocked-device gate from bricking wallets and signing on defective OEM builds](https://github.com/dashpay/platform/pull/4643)
- [Debug Labs — Secure Android App Development Part 1](https://chaitanyaduse.medium.com/secure-android-app-development-part-1-38f9b1b5a902)
- [OSV — ASB-A-407562568 (Keyguard/lockscreen bypass advisory)](https://osv.dev/vulnerability/ASB-A-407562568)
- [CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)
- [CWE-862: Missing Authorization](https://cwe.mitre.org/data/definitions/862.html)

### 5.4 Dokumentasi Tools

- [Semgrep — Documentation](https://semgrep.dev/docs/)
- [CodeQL — Documentation](https://codeql.github.com/docs/)
- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [Frida — Dynamic instrumentation toolkit](https://frida.re/docs/javascript-api/)
- [MobSF — Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)

---

*Dokumen ini disusun berdasarkan OWASP MASTG (rilis terkini per September 2026), dokumentasi resmi Android Developers (termasuk Android CDD), serta kasus nyata dari proyek open-source terkait keamanan dompet kripto. Temuan metadata paling mencolok dalam riset ini: test yang sama dirujuk dengan tiga kategori MASVS berbeda oleh empat sumber resmi (lokasi file: RESILIENCE, weakness: CRYPTO, pesan rule: STORAGE) — dicatat apa adanya karena berpotensi memengaruhi bagaimana temuan dikelompokkan dalam pelaporan audit.*
