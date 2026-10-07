# MASTG-TEST-0316 App Exposing User Authentication Data in Text Input Fields

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0316 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-PLATFORM |
| **Weakness** | **MASWE-0036** (Unnecessary Exposure of Sensitive Data via the User Interface) **DAN** **MASWE-0040** (Sensitive Data Leaked via Accessibility Services) — pemetaan dua weakness yang menjadi kunci pemahaman test ini, lihat §1.3 |
| **Tipe Pengujian** | Static, Code, **Manual** |
| **Teknik terkait** | MASTG-TECH-0013, MASTG-TECH-0014, MASTG-TECH-0023 (validasi lanjutan wajib) |
| **Demo terkait** | — (tidak ada) |
| **Rule resmi** | `mastg-android-input-field-usage.yml` — **rule yang secara teknis dirancang untuk mencocokkan bytecode terdekompilasi/termangle Jetpack Compose**, bukan kode sumber Kotlin biasa (lihat §3.2, temuan teknis menarik) |
| **CWE terkait** | CWE-200, CWE-549 (Missing Password Field Masking) |

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian: Masking Visual, Bukan Sekadar Keyboard Caching

Kutipan overview resmi MASTG:

> *"This test verifies that the app handles user input correctly, ensuring that access codes (passwords or pins) and verification codes (OTPs) are not exposed in plain text within text input fields. Proper masking (e.g., dots instead of input characters) of these codes is essential to protect user privacy."*

Penting membedakan test ini dari **MASTG-TEST-0258** (References to Keyboard Caching Attributes) yang sudah dibahas mendalam di seri riset ini — keduanya memakai mekanisme konfigurasi yang **tumpang tindih** (`android:inputType="textPassword"`), namun **tujuan evaluasinya berbeda**:

| | MASTG-TEST-0258 | MASTG-TEST-0316 *(dokumen ini)* |
|---|---|---|
| **Fokus** | Mencegah **keyboard IME** menyimpan cache/saran kata dari input sensitif | Mencegah **tampilan visual** menunjukkan karakter asli yang diketik (mis. tampil sebagai `••••` bukan `1234`) |
| **Risiko yang dicegah** | Kebocoran lewat dictionary prediksi keyboard, snapshot sistem | Kebocoran lewat **shoulder surfing** visual langsung, screen recording, screenshot |

Kedua test saling melengkapi — field yang benar secara `inputType` untuk mencegah caching **belum tentu** otomatis menyamarkan tampilan visualnya dengan benar di semua framework UI (terutama Jetpack Compose, dibahas §1.2), sehingga keduanya layak diuji secara terpisah.

### 1.2 Mekanisme Masking di Dua Dunia UI: XML View vs Jetpack Compose

**Pada sistem View XML tradisional**, masking cukup sederhana — atribut `android:inputType="textPassword"` otomatis menampilkan karakter sebagai titik:

```xml
<EditText android:inputType="textPassword" />
```

**Pada Jetpack Compose**, mekanismenya lebih granular lewat `SecureTextField` dan parameter `TextObfuscationMode`:

```kotlin
SecureTextField(
    textObfuscationMode = TextObfuscationMode.RevealLastTyped,  // default
    // atau TextObfuscationMode.Hidden
)
```

Terdapat **tiga** nilai `TextObfuscationMode` yang relevan untuk evaluasi:

| Nilai | Perilaku | Status Keamanan |
|---|---|---|
| **`RevealLastTyped`** (default) | Karakter terakhir yang diketik **sempat terlihat sesaat** sebelum berubah jadi titik, karakter sebelumnya tersamarkan | Dianggap **cukup aman** oleh overview resmi — ini default bawaan |
| **`Hidden`** | Seluruh karakter **selalu** tersamarkan, tanpa reveal sesaat sama sekali | **Paling aman** |
| **`Visible`** | Seluruh karakter ditampilkan **sepenuhnya tanpa penyamaran** | **Tidak aman** — inilah kondisi FAIL utama test ini |

### 1.3 Mengapa Dua Weakness Sekaligus (MASWE-0036 dan MASWE-0040): Masking Visual ≠ Proteksi Penuh dari Accessibility Service

Ini adalah **temuan konseptual paling penting** dari dokumen ini, dan menjelaskan mengapa test ini dipetakan ke **dua** weakness berbeda secara bersamaan — pola yang jarang ditemukan di test lain dalam seri riset ini. Masking visual (menampilkan titik alih-alih karakter asli) **menyelesaikan** risiko MASWE-0036 (eksposur lewat UI yang terlihat mata/screenshot/screen recording) — namun **tidak secara otomatis menyelesaikan** risiko MASWE-0040 (kebocoran lewat **Accessibility Service**).

**Accessibility Service** adalah API resmi Android yang dirancang untuk membantu pengguna dengan disabilitas (pembaca layar, dll.) dengan cara **membaca konten layar secara terprogram**, termasuk isi node `EditText`/`TextField`. Riset keamanan mobile secara ekstensif mendokumentasikan **penyalahgunaan** kapabilitas ini oleh malware nyata:

> *"Accessibility services can read the text content of any application displayed on screen — including banking apps... This enables credential harvesting without a network proxy or overlay: the malware simply reads credentials from the screen as the user types them."*

Keluarga malware nyata yang secara spesifik memanfaatkan teknik ini sudah didokumentasikan luas dalam riset keamanan: **FluBot**, **RatHat**, dan **Manic Trojan** — seluruhnya menggunakan Accessibility Service sebagai **keylogger** yang membaca perubahan pada field input secara real-time, **terlepas dari bagaimana field tersebut ditampilkan secara visual** kepada pengguna. Inilah akar mengapa MASWE-0040 relevan di sini: **masking visual (dots) adalah pertahanan terhadap mata manusia dan capture visual**, tapi **bukan pertahanan terhadap API yang membaca struktur data UI secara terprogram** — dua lapisan ancaman yang berbeda, membutuhkan mitigasi yang berbeda pula (mis. memastikan field sensitif memiliki flag yang tepat agar nilai sesungguhnya tidak terekspos ke pohon aksesibilitas, bukan hanya mengandalkan tampilan dots semata).

### 1.4 Peringatan Resmi Paling Krusial: Mode Aman Bisa Diubah Secara Dinamis

Overview resmi menyertakan catatan yang **secara eksplisit** mengantisipasi kegagalan analisis statis murni:

> *"Even if `SecureTextField` uses the default `TextObfuscationMode.RevealLastTyped` or is configured explicitly with `RevealLastTyped` or `Hidden`, **it can later be changed to `Visible` programmatically**."*

Ini artinya **konfigurasi awal yang terlihat aman** di titik deklarasi komponen **tidak menjamin** field tersebut akan **tetap** aman sepanjang siklus hidupnya — kode di tempat lain (mis. fitur "tampilkan password" yang umum ditemukan di form login) bisa saja **mengubah** `textObfuscationMode` menjadi `Visible` secara dinamis berdasarkan state tertentu (toggle tombol mata, dsb.). Analisis statis yang **hanya memeriksa titik deklarasi awal** komponen berisiko melewatkan logika pengubahan mode yang terjadi di tempat lain dalam basis kode — menuntut penelusuran **menyeluruh** atas seluruh referensi ke instance `SecureTextField`/state `textObfuscationMode` terkait, bukan hanya titik deklarasinya.

### 1.5 Keterbatasan yang Diakui Secara Eksplisit: False Negative pada UI Kustom

Ini salah satu dari sedikit kasus dalam seri riset ini di mana **MASTG sendiri secara proaktif mengakui keterbatasan metodologinya** dalam klausul terpisah bernama **"Expected False Negatives"**:

> *"This test may produce false negatives if the app uses custom text input controls that do not rely on standard classes such as `TextField` or `SecureTextField` (for example in custom UI frameworks or game engines)."*

Ini pengakuan jujur bahwa aplikasi yang membangun **komponen input teks kustom dari nol** (umum ditemukan pada aplikasi berbasis game engine seperti Unity, atau framework rendering UI kustom) **sama sekali tidak akan tertangkap** oleh metodologi deteksi standar berbasis pencarian kelas `TextField`/`SecureTextField`/`EditText` — karena komponen tersebut secara arsitektural **tidak** mewarisi/memanggil kelas-kelas standar tersebut sama sekali. Penguji yang menghadapi aplikasi semacam ini perlu **secara eksplisit mendokumentasikan keterbatasan ini** dalam laporan, bukan serta-merta menyimpulkan PASS hanya karena pencarian pola standar tidak menemukan apa pun.

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | Fungsi |
|---|---|
| **jadx** | Dekompilasi DEX → Java/Kotlin-like untuk pencarian pola `EditText`/`TextField`/`SecureTextField` |
| **apktool** | Ekstraksi layout XML mentah untuk atribut `android:inputType` |
| **grep / ripgrep** | Pencarian pola API dan `TextObfuscationMode` |
| **semgrep** | Menjalankan rule resmi (dengan catatan teknis khusus, §3.2) |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **CodeQL** | Menelusuri **seluruh** referensi ke instance `SecureTextField`/variabel `textObfuscationMode`, termasuk pengubahan nilai di luar titik deklarasi awal (§1.4) |
| **Accessibility Scanner (Google)** | Tool resmi Google untuk inspeksi pohon aksesibilitas — dapat membantu memverifikasi secara empiris apakah nilai sesungguhnya dari field sensitif benar-benar terekspos ke accessibility tree (relevan untuk MASWE-0040, §1.3) |
| **Frida** | Hooking `SecureTextField`/`TextObfuscationMode` setter untuk menangkap perubahan mode secara runtime — melengkapi analisis statis untuk kasus §1.4 |

### 2.3 Prasyarat Lingkungan

- **Tidak butuh device/root** untuk analisis statis inti.
- **Device/emulator diperlukan** untuk verifikasi dengan Accessibility Scanner atau Frida.
- **Review manual (MASTG-TECH-0023) mutlak diperlukan**, konsisten dengan tag `manual` pada tipe pengujian — klausul "Further Validation Required" resmi secara eksplisit menuntut ini.

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0013** untuk reverse engineer aplikasi.
2. Gunakan **MASTG-TECH-0014** untuk mencari API yang relevan.

### 3.2 Metode A — Rule Semgrep Resmi *(temuan teknis menarik: dirancang untuk bytecode Compose yang di-mangle)*

```yaml
rules:
  - id: mastg-android-input-field-usage
    severity: WARNING
    languages: [java]
    metadata:
      summary: This rule looks for TextFields and SecureTextField.
    message: "[MASVS-PLATFORM] Detected TextFields and SecureTextField."
    pattern-either:
      - pattern: androidx.compose.material3.TextFieldKt
      - pattern-regex: SecureTextFieldKt.m\d+SecureTextField\w+\(.+TextObfuscationMode.Companion.m\d+getVisible\w+\(\).+\);
```

**Catatan teknis yang menarik dan unik untuk rule ini** dibanding seluruh rule lain yang sudah dianalisis dalam seri riset ini: pattern kedua secara eksplisit mencocokkan nama method seperti `m\d+SecureTextField\w+` dan `m\d+getVisible\w+` — pola penamaan ini adalah **artefak dari proses kompilasi Jetpack Compose**, bukan kode sumber Kotlin yang ditulis developer. Compose compiler plugin melakukan **transformasi nama method** (menambahkan suffix numerik seperti `$1`, `m1`, dll.) saat mengompilasi fungsi composable ke bytecode JVM/DEX — pola yang hanya terlihat setelah **dekompilasi APK**, bukan di source code asli. Ini mengindikasikan rule ini **secara spesifik dirancang untuk dijalankan pada hasil dekompilasi APK (blackbox)**, bukan pada source code proyek (whitebox) — berbeda dari asumsi umum yang mungkin dibuat penguji bahwa semua rule semgrep MASTG bisa dijalankan secara seragam pada kedua jenis target.

```bash
jadx -d ./decompiled ./target-app.apk
semgrep --config https://raw.githubusercontent.com/OWASP/mastg/master/rules/mastg-android-input-field-usage.yml ./decompiled/sources/
```

**Implikasi praktis**: bila penguji menjalankan rule ini pada **source code Kotlin asli** (whitebox, sebelum kompilasi), pattern regex `m\d+SecureTextField\w+` **tidak akan pernah cocok** karena nama method belum di-mangle — rule ini **harus** dijalankan pada hasil dekompilasi APK untuk berfungsi sebagaimana dirancang.

### 3.3 Metode B — grep/ripgrep untuk XML View dan Verifikasi Manual

```bash
D=./decompiled/sources

# XML View — cari inputType yang BUKAN textPassword pada field yang namanya terkait otentikasi
rg -n '<EditText' ./decompiled/resources/res/layout/ -A3 | grep -iE "password|pin|otp|cvv" -B3 | grep -v "textPassword"

# Compose — cari TextObfuscationMode.Visible secara eksplisit
rg -n 'TextObfuscationMode\.Visible' $D

# Cari penggunaan TextField (bukan SecureTextField) pada konteks yang namanya terkait otentikasi
rg -n -B5 'TextField\(' $D | grep -iE "password|pin|otp" -B5
```

### 3.4 Metode C — CodeQL untuk Menelusuri Perubahan Mode Dinamis

```ql
import java

class SecureTextFieldUsage extends MethodAccess {
  SecureTextFieldUsage() {
    this.getMethod().hasName("SecureTextField")
  }
}

class ObfuscationModeChange extends MethodAccess {
  ObfuscationModeChange() {
    this.getMethod().hasName("setValue") and
    this.getAnArgument().toString().matches("%TextObfuscationMode.Visible%")
  }
}

from ObfuscationModeChange change
select change, "Ditemukan perubahan textObfuscationMode menjadi Visible secara dinamis — verifikasi konteks (fitur 'tampilkan password' yang sah, atau kebocoran tak disengaja?)"
```

### 3.5 Metode D — Accessibility Scanner untuk Verifikasi MASWE-0040

```bash
# Install Accessibility Scanner dari Google Play pada device uji
# Aktifkan lewat Settings > Accessibility > Accessibility Scanner
```

Jalankan aplikasi pada field sensitif yang sedang diisi, picu pemeriksaan Accessibility Scanner, dan periksa apakah **nilai sesungguhnya** dari field tersebut (bukan representasi dots) terekspos ke informasi node yang ditangkap scanner — ini verifikasi empiris langsung terhadap risiko MASWE-0040 yang dijelaskan di §1.3.

### 3.6 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Target yang tepat | Mendeteksi perubahan dinamis? | Kapan dipakai |
|---|---|---|---|---|
| **A** | Rule semgrep resmi | **APK terdekompilasi, bukan source** | ❌ | Baseline, HARUS pada hasil dekompilasi |
| **B** | grep | Keduanya | ❌ | Pelengkap, verifikasi manual |
| **C** | CodeQL | Source code | ✅ | Menangkap kasus §1.4 |
| **D** | Accessibility Scanner | N/A (dinamis) | N/A | Verifikasi MASWE-0040 secara empiris |

**Kombinasi minimum yang aku rekomendasikan:** **A (pada APK terdekompilasi) + B → C (perubahan dinamis) → D (verifikasi MASWE-0040)**, dilengkapi review manual MASTG-TECH-0023 pada setiap kandidat sesuai klausul wajib resmi.

---

### 3.7 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG:**

> **Evaluation:** *"The test case fails if any text input field used for access or verification codes is found to be unmasked. For example, due to the following: `TextField` is used; `SecureTextField` is used but configured with `TextObfuscationMode.Visible`."*

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi |
|---|---|
| F1 | Field password/PIN/OTP memakai `TextField` biasa (bukan `SecureTextField`) di Compose |
| F2 | `SecureTextField` dikonfigurasi dengan `TextObfuscationMode.Visible` |
| F3 | Mode aman pada deklarasi awal, namun terdeteksi **diubah secara dinamis** menjadi `Visible` tanpa justifikasi UX yang sah (§1.4) |
| F4 | Field XML View memakai `android:inputType="text"` biasa untuk konten yang jelas password/PIN |

**Contoh bukti (ilustratif — MASTG belum menyediakan demo resmi untuk test ini):**

```kotlin
@Composable
fun PinEntryScreen() {
    var pin by remember { mutableStateOf("") }
    TextField(  // SALAH — seharusnya SecureTextField
        value = pin,
        onValueChange = { pin = it },
        label = { Text("Masukkan PIN") }
    )
}
```

Interpretasi: field untuk input PIN memakai `TextField` biasa yang menampilkan karakter apa adanya tanpa penyamaran apa pun — **FAIL**.

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi |
|---|---|
| P1 | Field password/PIN/OTP memakai `SecureTextField` dengan `RevealLastTyped` (default) atau `Hidden` |
| P2 | Verifikasi CodeQL mengonfirmasi tidak ada perubahan dinamis ke `Visible` tanpa kontrol UX yang eksplisit dan sah (mis. tombol "tampilkan" yang dikendalikan pengguna sendiri) |
| P3 | XML View memakai `android:inputType="textPassword"`/`numberPassword` sesuai konteks |

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Jalankan rule semgrep resmi pada hasil dekompilasi APK, bukan source code** — sesuai temuan teknis §3.2, pattern regex-nya secara spesifik menyasar nama method yang sudah di-mangle oleh Compose compiler.

2. **"Mode aman di titik deklarasi" tidak menjamin aman sepanjang siklus hidup komponen** — selalu telusuri seluruh referensi terkait untuk kemungkinan perubahan dinamis ke `Visible` (§1.4).

3. **Masking visual tidak otomatis menyelesaikan risiko Accessibility Service** — ini poin paling sering terlewat; pertimbangkan verifikasi tambahan dengan Accessibility Scanner untuk kelengkapan evaluasi MASWE-0040.

4. **Dokumentasikan secara eksplisit keterbatasan false negative** untuk aplikasi berbasis game engine/UI kustom (§1.5) — jangan simpulkan PASS murni dari ketiadaan hasil pencarian pola standar.

5. **Tombol "tampilkan password" yang dikendalikan pengguna BUKAN otomatis FAIL** — ini pola UX legitimate yang umum; fokus pada apakah perubahan ke `Visible` terjadi **tanpa** kontrol eksplisit pengguna (mis. bug yang membuat field selalu visible tanpa pengguna memintanya).

6. **Severity dimodulasi:**

   | Faktor | Severity |
   |---|---|
   | Field PIN/password/OTP sama sekali tidak termasking sejak awal | **Tinggi** |
   | Mode aman diubah ke Visible tanpa kontrol pengguna yang jelas | **Tinggi** |
   | Tombol "tampilkan password" legitimate dengan kontrol pengguna eksplisit | **Bukan temuan** |

7. **Dokumentasikan:** lokasi field, jenis komponen (`TextField`/`SecureTextField`/`EditText`), mode obfuscation yang dikonfigurasi, hasil penelusuran perubahan dinamis, dan hasil verifikasi Accessibility Scanner bila dilakukan.

---

## 4. Rekomendasi Perbaikan

### 4.1 Gunakan `SecureTextField` dengan Mode Aman

```kotlin
SecureTextField(
    state = pinState,
    textObfuscationMode = TextObfuscationMode.Hidden  // paling aman untuk PIN/OTP
)
```

### 4.2 Kendalikan Toggle "Tampilkan Password" Secara Eksplisit dan Aman

```kotlin
var obfuscationMode by remember { mutableStateOf(TextObfuscationMode.Hidden) }
SecureTextField(
    state = passwordState,
    textObfuscationMode = obfuscationMode
)
IconButton(onClick = {
    obfuscationMode = if (obfuscationMode == TextObfuscationMode.Hidden)
        TextObfuscationMode.Visible else TextObfuscationMode.Hidden
}) { /* ikon mata */ }
```

### 4.3 Checklist Remediasi

- [ ] Seluruh field password/PIN/OTP memakai `SecureTextField`/`android:inputType="textPassword"` yang sesuai
- [ ] Tidak ada perubahan dinamis ke `Visible` tanpa kontrol pengguna eksplisit
- [ ] Verifikasi Accessibility Scanner dilakukan untuk field yang paling sensitif
- [ ] Keterbatasan false negative pada UI kustom/game engine didokumentasikan bila relevan
- [ ] **Verifikasi ulang:** jalankan kembali MASTG-TEST-0316 pada hasil dekompilasi APK release terbaru

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0316: App Exposing User Authentication Data in Text Input Fields](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0316/)
- [MASTG-TEST-0258: References to Keyboard Caching Attributes in UI Elements](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0258/)
- [MASWE-0036: Unnecessary Exposure of Sensitive Data via the User Interface](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0036/)
- [MASWE-0040: Sensitive Data Leaked via Accessibility Services](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0040/)
- [Rule resmi: mastg-android-input-field-usage.yml (GitHub)](https://github.com/OWASP/mastg/blob/master/rules/mastg-android-input-field-usage.yml)

### 5.2 Dokumentasi Resmi Android

- [Android Developers — `SecureTextField` source (androidx)](https://cs.android.com/androidx/platform/frameworks/support/+/androidx-main:compose/material/material/src/commonMain/kotlin/androidx/compose/material/SecureTextField.kt)
- [Android Developers — Accessibility Scanner](https://play.google.com/store/apps/details?id=com.google.android.apps.accessibility.auditor)

### 5.3 Riset dan Kasus Nyata

- [SRLabs — FluBot Abuses Accessibility Features to Steal Data](https://srlabs.de/blog/flubot-abuses-accessibility-features-to-steal-data)
- [Security Affairs — RatHat Turns Android Accessibility Into an Attack Weapon](https://securityaffairs.com/199317/malware/rathat-turns-android-accessibility-into-an-attack-weapon.html)
- [Kaspersky — Manic Trojan: Android Malware Steals Banking Credentials](https://me-en.kaspersky.com/blog/manic-android-trojan/26036/)
- [FAU CS1 — How Android's UI Security is Undermined by Accessibility](https://www.cs1.tf.fau.de/research/system-security-group/how-androids-ui-security-is-undermined-by-accessibility/)
- [CWE-549: Missing Password Field Masking](https://cwe.mitre.org/data/definitions/549.html)
- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)

### 5.4 Dokumentasi Tools

- [Semgrep — Documentation](https://semgrep.dev/docs/)
- [CodeQL — Documentation](https://codeql.github.com/docs/)
- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [Frida — Dynamic instrumentation toolkit](https://frida.re/docs/javascript-api/)

---

*Dokumen ini disusun berdasarkan OWASP MASTG (rilis terkini per September 2026), dokumentasi resmi Android/Jetpack Compose, serta riset keamanan mobile tentang penyalahgunaan Accessibility Service oleh malware nyata (FluBot, RatHat, Manic Trojan). Dua temuan terpenting: (1) test ini dipetakan ke **dua weakness sekaligus** (MASWE-0036 dan MASWE-0040) karena masking visual tidak otomatis melindungi dari pembacaan terprogram lewat Accessibility Service — dua lapisan ancaman berbeda yang butuh mitigasi berbeda; dan (2) rule semgrep resminya secara teknis dirancang khusus untuk dijalankan pada **bytecode hasil dekompilasi APK** (nama method ter-mangle Compose compiler), bukan source code asli — detail implementasi yang mudah terlewat bila penguji tidak memeriksa isi pattern secara saksama.*
