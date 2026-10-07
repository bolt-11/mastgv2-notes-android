# MASTG-TEST-0258 References to Keyboard Caching Attributes in UI Elements

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0258 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-PLATFORM (sesuai lokasi file resmi dan MASWE-0036) |
| **Weakness** | MASWE-0036 — *Unnecessary Exposure of Sensitive Data via the User Interface* |
| **Tipe Pengujian** | Static, Code |
| **Profile** | **L2 saja** |
| **Knowledge** | MASTG-KNOW-0055 (Keyboard Cache) — **catatan: dokumen knowledge ini sendiri dikategorikan `masvs_category: MASVS-STORAGE`**, dan pesan rule semgrep resmi juga menyebut `[MASVS-STORAGE]` — sebuah pola atribusi silang-kategori yang konsisten secara internal antara KNOW dan rule, namun berbeda dari kategori test resminya sendiri (MASVS-PLATFORM) |
| **Best Practice** | MASTG-BEST-0019 (Use Non-Caching Input Types for Sensitive Fields) |
| **Teknik terkait** | MASTG-TECH-0013, MASTG-TECH-0014, MASTG-TECH-0007 (Extract Layout Files) |
| **Demo terkait** | — (tidak ada) |
| **Rule resmi** | `mastg-android-keyboard-cache-input-types.yml` — hanya mendeteksi pemanggilan `setInputType()`, **tidak mencakup atribut XML maupun Jetpack Compose** (lihat §3.2) |
| **CWE terkait** | CWE-200 (Exposure of Sensitive Information), CWE-524 (Use of Cache Containing Sensitive Information) |

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian

Kutipan overview resmi MASTG:

> *"This test verifies that the app appropriately configures text input fields to prevent the keyboard from caching sensitive information, such as passwords or personal data."*

Ini test yang menyasar lapisan interaksi yang **sering terlupakan** dalam audit keamanan mobile: **perilaku keyboard software (IME — Input Method Editor)**, bukan kode aplikasi itu sendiri. Meski aplikasi sudah benar mengenkripsi data saat disimpan (lolos test-test MASVS-CRYPTO/STORAGE lain dalam seri ini), data sensitif yang **diketik pengguna** tetap dapat bocor lewat mekanisme yang sepenuhnya berada di luar kendali langsung kode aplikasi: **cache prediksi/auto-suggestion keyboard**.

### 1.2 Tiga Cara Mengonfigurasi Input Type, Satu Tujuan

Overview resmi menjabarkan tiga jalur teknis berbeda untuk mencapai tujuan yang sama — mengonfigurasi `inputType` field agar keyboard tidak melakukan caching:

1. **Layout XML** — atribut `android:inputType` pada elemen `<EditText>`.
2. **Kode terprogram (View System tradisional)** — pemanggilan `setInputType()` dengan konstanta `InputType.*`.
3. **Jetpack Compose** — parameter `keyboardType` dan `autoCorrect` pada konstruktor `KeyboardOptions`.

Poin krusial dari MASTG-KNOW-0055 yang menjelaskan hubungan ketiganya: **Jetpack Compose secara internal tetap memetakan ke `inputType` yang sama** — `KeyboardType.Password` pada akhirnya diterjemahkan menjadi `InputType.TYPE_CLASS_TEXT or EditorInfo.TYPE_TEXT_VARIATION_PASSWORD` di level implementasi. Ini berarti **ketiga jalur ini secara fundamental adalah satu mekanisme yang sama** dilihat dari tiga API permukaan berbeda — namun bagi penguji, ini berarti **tiga pola berbeda yang harus dicari secara terpisah**, karena representasi tekstualnya di kode/resource sangat berbeda satu sama lain.

### 1.3 Daftar Resmi Non-Caching Input Types

MASTG-KNOW-0055 memberi tabel definitif tipe input yang **secara resmi menonaktifkan** saran dan caching keyboard:

| `android:inputType` (XML) | Konstanta `InputType` (kode) | API level minimum |
|---|---|---|
| `textNoSuggestions` | `TYPE_TEXT_FLAG_NO_SUGGESTIONS` | 3 |
| `textPassword` | `TYPE_TEXT_VARIATION_PASSWORD` | 3 |
| `textVisiblePassword` | `TYPE_TEXT_VARIATION_VISIBLE_PASSWORD` | 3 |
| `numberPassword` | `TYPE_NUMBER_VARIATION_PASSWORD` | 11 |
| `textWebPassword` | `TYPE_TEXT_VARIATION_WEB_PASSWORD` | 11 |

Catatan penting soal `minSdkVersion` dari overview resmi (konsisten dengan nuansa `minSdkVersion` yang sudah dibahas mendalam di dokumen MASTG-TEST-0245/0252 dalam seri riset ini):

> *"In the MASTG tests we won't be checking the minimum required SDK version... because we are considering testing modern apps. If you are testing an older app, you should check it. For example, Android API level 11 is required for `textWebPassword`. Otherwise, the compiled app would not honor the used input type constants allowing keyboard caching."*

Ini pengecualian metodologis eksplisit dari MASTG sendiri — berbeda dari test-test lain dalam seri riset ini yang secara ketat menuntut pemeriksaan `minSdkVersion` (mis. MASTG-TEST-0252), test ini **secara default mengasumsikan** aplikasi modern (API ≥11 bukan masalah praktis di 2026). Namun overview tetap **secara eksplisit mewanti-wanti** penguji yang menangani aplikasi legacy untuk tetap memverifikasi `minSdkVersion` — terutama untuk `numberPassword`/`textWebPassword` yang membutuhkan API 11.

### 1.4 Sifat Bitwise dari `inputType` — Sumber Kesalahan Konfigurasi yang Halus

Poin teknis yang sering luput dari pemeriksaan sekilas: atribut `inputType` bukan nilai enum tunggal, melainkan **kombinasi bitwise** dari flag dan class:

> *"The `inputType` attribute is a bitwise combination of flags and classes... The flags are defined as `TYPE_TEXT_FLAG_*` and the classes are defined as `TYPE_CLASS_*`."*

Konsekuensi praktisnya: sebuah field bisa saja terlihat "aman" karena menyertakan flag `TYPE_TEXT_FLAG_NO_SUGGESTIONS`, namun bila **base class**-nya salah atau digabung dengan flag lain yang bertentangan, perilaku akhir bisa tidak sesuai ekspektasi. Contoh pola yang benar dari MASTG-KNOW-0055 untuk PIN numerik:

```kotlin
inputType = InputType.TYPE_CLASS_NUMBER or InputType.TYPE_NUMBER_VARIATION_PASSWORD
```

Penguji perlu memeriksa **kombinasi lengkap** flag yang di-OR-kan, bukan hanya mencari satu konstanta spesifik secara terisolasi — pencarian pola yang terlalu sempit (mis. hanya mencari string `"textPassword"`) berisiko melewatkan kombinasi bitwise yang valid namun ditulis dengan urutan/kombinasi konstanta berbeda.

### 1.5 Mengapa Keyboard Caching Berbahaya: Bukti dari Insiden Nyata

Berbeda dari sebagian besar test lain dalam seri ini yang risikonya bersifat teoretis/kontekstual, risiko keyboard caching memiliki **preseden insiden nyata berskala besar** yang sangat konkret:

- **Kasus Ai.Type (2017)**: aplikasi keyboard pihak ketiga populer ini mengumpulkan dan menyimpan **teks yang diketik pengguna** — termasuk nomor telepon, informasi sensitif, istilah pencarian, alamat email, dan **kata sandi** — pada server yang **tidak dilindungi kata sandi sama sekali**, mengakibatkan kebocoran **577GB data** dari sekitar **31 juta pengguna**.
- **Riset Citizen Lab**: menganalisis aplikasi keyboard Pinyin (pasar Tiongkok) dan menemukan **8 dari 9 aplikasi** yang diperiksa memiliki kerentanan yang memungkinkan **pengungkapan penuh isi keystroke** kepada penyerang pasif yang menyadap jaringan — akibat enkripsi buatan sendiri (*homegrown encryption*) yang lemah pada transmisi data keyboard.
- **Riset akademik tentang cross-app KeyEvent injection**: mengidentifikasi kerentanan pada framework pemrosesan `KeyEvent` Android yang memungkinkan penyerang **memanen entri dari personal dictionary** pengguna — kamus prediksi personal yang terbentuk dari kebiasaan mengetik pengguna — lewat aplikasi yang tampak tidak berbahaya dengan permission umum.
- **Bahkan keyboard populer resmi** (Google Gboard, Microsoft SwiftKey) secara rutin mengirim data telemetri tentang **setiap kata yang diketik**, termasuk panjang kata, waktu input presisi, dan konteks aplikasi tempat pengetikan terjadi — meski untuk tujuan legitimate (peningkatan prediksi), ini menegaskan bahwa **data yang diketik di field tanpa proteksi `inputType` yang sesuai berpotensi meninggalkan jejak di luar kendali aplikasi**, terlepas dari niat baik/buruk keyboard yang dipakai.

Kasus-kasus ini menggarisbawahi mengapa test ini penting: **aplikasi tidak memiliki kendali atas keyboard software mana yang dipasang pengguna** — pengguna Android bebas memasang keyboard pihak ketiga apa pun, termasuk yang berperilaku seperti kasus Ai.Type di atas. Satu-satunya lapisan pertahanan yang **sepenuhnya berada dalam kendali developer aplikasi** adalah memastikan field sensitif dikonfigurasi dengan `inputType` yang secara eksplisit memberi tahu **sistem** (bukan keyboard tertentu) untuk menonaktifkan suggestion/caching pada level tersebut.

### 1.6 Manfaat Tambahan: Perlindungan dari Snapshot/Recording Sistem

MASTG-BEST-0019 memberi catatan tambahan yang memperluas alasan pentingnya praktik ini di luar sekadar isu cache IME:

> *"Using non-caching input types helps protect sensitive data from being exposed in system-generated snapshots and recordings."*

Ini terhubung dengan fakta bahwa **strip saran kata** (suggestion bar) yang ditampilkan sebagian besar keyboard software adalah bagian dari **tampilan layar** yang bisa ikut tertangkap dalam screenshot otomatis sistem (mis. saat aplikasi masuk background dan Android mengambil thumbnail untuk App Switcher) atau perekaman layar. Menonaktifkan suggestion lewat `textNoSuggestions`/`textPassword` secara tidak langsung juga **menghilangkan konten sensitif yang berpotensi muncul di strip saran tersebut** dari jangkauan mekanisme snapshot/recording sistem — melengkapi (bukan menggantikan) proteksi `FLAG_SECURE` yang dibahas di test-test MASVS-STORAGE terkait screenshot lain dalam seri MASTG.

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | Fungsi |
|---|---|
| **apktool** | Ekstraksi layout XML mentah (MASTG-TECH-0007) — penting karena `android:inputType` di layout paling akurat dibaca dari XML asli, bukan hasil dekompilasi Java |
| **jadx** | Dekompilasi kode untuk pencarian `setInputType()` dan `KeyboardOptions` |
| **grep / ripgrep** | Pencarian pola ketiga jalur konfigurasi (§1.2) |
| **semgrep** | Menjalankan rule resmi sebagai baseline parsial |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **CodeQL** | Menelusuri kombinasi bitwise flag `InputType` secara terprogram (§1.4), dan mengorelasikan field input dengan nama variabel/hint yang mengindikasikan sensitivitas (mis. `password`, `pin`, `ssn`) |
| **MobSF** | Kadang menandai field password yang tidak dikonfigurasi dengan benar di laporan Manifest/Layout Analysis |
| **Frida** | Hooking `EditText.setInputType()` saat runtime untuk menangkap nilai yang benar-benar diterapkan, termasuk yang dibangun dinamis |
| **Accessibility Scanner (Google)** | Tool aksesibilitas resmi Google yang **secara tidak langsung** dapat membantu mengidentifikasi field input dan propertinya lewat inspeksi UI tree — pendekatan blackbox tambahan di luar cakupan resmi MASTG |

### 2.3 Prasyarat Lingkungan

- **Tidak butuh device/root** untuk analisis statis inti.
- **Identifikasi field yang menangani data sensitif terlebih dahulu** (password, PIN, nomor kartu, SSN/NIK, dsb.) sebagai target prioritas — bukan setiap `<EditText>`/`TextField` perlu diperiksa dengan bobot yang sama.
- **Untuk aplikasi Jetpack Compose**, pastikan tooling dekompilasi dapat menangani kode Kotlin dengan baik karena sintaks `KeyboardOptions` cukup berbeda dari pola `EditText` tradisional.

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0013** untuk reverse engineer aplikasi.
2. Gunakan **MASTG-TECH-0014** untuk mencari API yang relevan.
3. Gunakan **MASTG-TECH-0007** untuk mengekstrak layout files dari paket aplikasi.

### 3.2 Metode A — Rule Semgrep Resmi *(ada, tapi cakupannya hanya 1 dari 3 jalur)*

```yaml
rules:
  - id: mastg-android-non-caching-input-types
    severity: WARNING
    languages: [java]
    metadata:
      summary: This rule scans all usages of setInputType().
    message: "[MASVS-STORAGE] Set input type detected ($OBJ) with $ARG"
    patterns:
      - pattern: $OBJ.setInputType($ARG)
```

```bash
semgrep --config https://raw.githubusercontent.com/OWASP/mastg/master/rules/mastg-android-keyboard-cache-input-types.yml ./decompiled/sources/
```

**Celah cakupan yang signifikan**: rule ini **hanya** mencakup jalur kedua dari tiga jalur resmi (§1.2) — pemanggilan `setInputType()` terprogram. Ia **sama sekali tidak mencakup**:
1. **Atribut XML `android:inputType`** di layout — padahal ini justru jalur **paling umum** dipakai developer untuk field statis seperti form login.
2. **Jetpack Compose `KeyboardOptions`** — semakin umum dipakai pada aplikasi modern, dan sintaksnya berbeda total dari pola `setInputType()`.

Ini artinya rule resmi berpotensi melewatkan **mayoritas** kasus nyata di lapangan bila developer memakai pola XML atau Compose (yang justru direkomendasikan Google sebagai pendekatan modern) — Metode B di bawah wajib menutup kedua celah ini.

### 3.3 Metode B — grep/ripgrep untuk Ketiga Jalur Sekaligus

```bash
# Ekstrak layout XML mentah
apktool d -s -f -o ./apktool_out target-app.apk
jadx -d ./decompiled target-app.apk

# 1. XML Layout — android:inputType
rg -n 'android:inputType="[^"]*"' ./apktool_out/res/layout/

# 2. Kode terprogram — setInputType() (sama seperti rule resmi, tapi grep lebih fleksibel)
rg -n '\.setInputType\(' ./decompiled/sources/

# 3. Jetpack Compose — KeyboardOptions
rg -n 'KeyboardOptions\(' ./decompiled/sources/ -A5 | grep -i "keyboardType\|autoCorrect"

# Cari field yang KEMUNGKINAN sensitif tapi TIDAK memakai non-caching input type
rg -n -B3 '<EditText' ./apktool_out/res/layout/ | grep -i "password\|pin\|ssn\|card\|cvv" -A3 | grep -v "textPassword\|textNoSuggestions\|numberPassword\|textWebPassword\|textVisiblePassword"
```

### 3.4 Metode C — CodeQL (Verifikasi Kombinasi Bitwise + Korelasi Sensitivitas)

```ql
import java

class SensitiveFieldDeclaration extends VarAccess {
  SensitiveFieldDeclaration() {
    this.getVariable().getName().toLowerCase().regexpMatch(".*(password|pin|cvv|ssn|nik|secret).*")
  }
}

class SetInputTypeCall extends MethodAccess {
  SetInputTypeCall() {
    this.getMethod().hasName("setInputType")
  }
}

from SensitiveFieldDeclaration field
where not exists(SetInputTypeCall call |
  call.getQualifier().toString() = field.toString())
select field, "Field bernama sensitif ditemukan tanpa pemanggilan setInputType yang eksplisit — periksa apakah dikonfigurasi via XML/Compose"
```

Query ini secara khusus berguna untuk memicu verifikasi silang: bila field bernama sensitif **tidak** ditemukan lewat `setInputType()`, penguji harus menelusuri lebih lanjut apakah field tersebut dikonfigurasi via XML/Compose (bukan otomatis disimpulkan FAIL).

### 3.5 Metode D — Frida (Konfirmasi Runtime)

```javascript
// hook-edittext-inputtype.js
Java.perform(function () {
    var EditText = Java.use("android.widget.EditText");
    EditText.setInputType.overload("int").implementation = function (type) {
        console.log("[*] EditText.setInputType(" + type + ") dipanggil");
        // Bandingkan dengan konstanta non-caching yang diketahui
        var NO_SUGGESTIONS = 0x80000; // TYPE_TEXT_FLAG_NO_SUGGESTIONS
        var VARIATION_PASSWORD = 0x80; // TYPE_TEXT_VARIATION_PASSWORD (bagian dari kombinasi)
        if ((type & NO_SUGGESTIONS) === 0 && (type & VARIATION_PASSWORD) === 0) {
            console.log("    [!] Kemungkinan TIDAK non-caching — verifikasi manual diperlukan");
        }
        return this.setInputType(type);
    };
});
```

### 3.6 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Cakupan jalur konfigurasi | Kapan dipakai |
|---|---|---|---|
| **A** | Rule semgrep resmi | Hanya `setInputType()` (1 dari 3 jalur) | Baseline parsial saja |
| **B** | grep menyeluruh | Ketiga jalur (XML, kode, Compose) | **Baseline utama wajib** |
| **C** | CodeQL | Korelasi sensitivitas nama field + verifikasi bitwise | Codebase besar, mengurangi review manual |
| **D** | Frida | Nilai runtime aktual, termasuk dinamis | Konfirmasi kasus yang dibangun secara kondisional |

**Kombinasi minimum yang aku rekomendasikan:** **B (menyeluruh ketiga jalur) → C (korelasi sensitivitas nama field)**, dengan Metode A hanya sebagai referensi tambahan karena cakupannya sangat terbatas dibanding kebutuhan sesungguhnya test ini.

---

### 3.7 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG:**

> **Observation:** *"The output should include: All `android:inputType` XML attributes... All calls to the `setInputType` method and the input type values passed to it."*
>
> **Evaluation:** *"The test case fails if there are any fields handling sensitive data for which the app does not use non-caching input types."*

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi |
|---|---|
| F1 | Field yang menangani password/PIN/data sensitif lain memakai `android:inputType` biasa (`text`, `textCapWords`, dsb.) tanpa flag/variation non-caching |
| F2 | Field sensitif di Jetpack Compose memakai `KeyboardType.Text` biasa dengan `autoCorrect = true` (default), bukan `KeyboardType.Password` |
| F3 | Kombinasi bitwise `InputType` yang dipakai **tampak** menyertakan flag non-caching tapi ternyata salah kombinasi/base class sehingga tidak efektif (dikonfirmasi Metode C/D) |
| F4 | Field sensitif sama sekali **tidak** memiliki pengaturan `inputType` eksplisit apa pun (mewarisi default `text` biasa) |

**Contoh bukti (ilustratif — MASTG belum menyediakan demo resmi untuk test ini):**

```xml
<!-- res/layout/activity_login.xml -->
<EditText
    android:id="@+id/password"
    android:hint="Password"
    android:inputType="text" />   <!-- SALAH: field password tapi inputType biasa -->
```

```bash
$ rg -n 'android:inputType="[^"]*"' ./apktool_out/res/layout/activity_login.xml
android:inputType="text"
```

Interpretasi: field dengan `id="password"` dan hint "Password" memakai `inputType="text"` biasa — keyboard akan menampilkan saran kata dan dapat meng-cache input ini. **FAIL** — seharusnya memakai `textPassword`.

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi |
|---|---|
| P1 | Seluruh field sensitif memakai salah satu dari lima non-caching input type resmi (§1.3) |
| P2 | Field Jetpack Compose sensitif memakai `KeyboardType.Password`/`NumberPassword` dengan `autoCorrect = false` |
| P3 | Kombinasi bitwise terverifikasi benar secara fungsional (dikonfirmasi Metode C/D) |
| P4 | Untuk aplikasi dengan `minSdkVersion` di bawah API 11 yang memakai `numberPassword`/`textWebPassword`, sudah diverifikasi API tersebut tetap dihormati pada `minSdkVersion` yang dideklarasikan (§1.3) |

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Rule resmi hanya menutup sepertiga cakupan sesungguhnya** — jangan mengandalkan hasil kosong dari Metode A sebagai bukti PASS; selalu jalankan pencarian menyeluruh (Metode B) yang mencakup XML dan Jetpack Compose.

2. **Periksa kombinasi bitwise secara utuh, bukan mencari substring** — sesuai §1.4, field bisa saja memakai kombinasi konstanta yang valid namun ditulis dengan urutan berbeda dari pola pencarian sederhana.

3. **Prioritaskan berdasarkan sensitivitas data, bukan jumlah field.** Field pencarian atau komentar publik yang memakai `inputType` biasa bukan temuan; fokus pada password, PIN, kartu pembayaran, dan data identitas.

4. **Manfaatkan preseden insiden nyata (§1.5) untuk mengomunikasikan urgensi ke tim developer** — risiko ini bukan hipotetis, sudah terbukti nyata pada skala jutaan pengguna (kasus Ai.Type).

5. **Ingat manfaat ganda non-caching input type** (§1.6) — selain mencegah cache IME, ini juga mengurangi risiko kebocoran lewat snapshot/recording sistem, sehingga temuan ini relevan silang dengan pengujian `FLAG_SECURE`/screenshot protection lain dalam seri MASTG.

6. **Severity dimodulasi:**

   | Faktor | Severity |
   |---|---|
   | Field password/PIN utama aplikasi tanpa non-caching input type | **Tinggi** |
   | Field data sensitif sekunder (mis. jawaban keamanan, alamat) tanpa non-caching input type | **Menengah** |
   | Field non-sensitif tanpa non-caching input type | **Bukan temuan** |

7. **Dokumentasikan:** lokasi field (layout XML/kode/Compose), nilai `inputType`/`KeyboardType` yang dipakai, klasifikasi sensitivitas data field tersebut, dan hasil verifikasi kombinasi bitwise bila relevan.

---

## 4. Rekomendasi Perbaikan

### 4.1 XML Layout

```xml
<EditText
    android:id="@+id/password"
    android:hint="Password"
    android:inputType="textPassword" />
```

### 4.2 Kode Terprogram (View System)

```kotlin
val pinInput = EditText(context).apply {
    hint = "Enter PIN"
    inputType = InputType.TYPE_CLASS_NUMBER or InputType.TYPE_NUMBER_VARIATION_PASSWORD
}
```

### 4.3 Jetpack Compose

```kotlin
OutlinedTextField(
    value = password,
    onValueChange = { password = it },
    label = { Text("Password") },
    visualTransformation = PasswordVisualTransformation(),
    keyboardOptions = KeyboardOptions(
        keyboardType = KeyboardType.Password,
        autoCorrect = false
    )
)
```

### 4.4 Integrasikan ke CI/CD

```bash
#!/bin/bash
# ci-check-keyboard-caching.sh
apktool d -s -f -o /tmp/layout_check "$1"
grep -rn 'password\|pin\|cvv' /tmp/layout_check/res/layout/ | grep -v 'inputType="text[NP]assword\|numberPassword\|textVisiblePassword\|textWebPassword\|textNoSuggestions'
```

### 4.5 Checklist Remediasi

- [ ] Seluruh field password/PIN/data sensitif diidentifikasi di ketiga jalur (XML, kode, Compose)
- [ ] Setiap field sensitif memakai salah satu dari lima non-caching input type resmi
- [ ] Kombinasi bitwise diverifikasi benar secara fungsional (bukan hanya tampak benar secara tekstual)
- [ ] `minSdkVersion` diverifikasi untuk kompatibilitas `numberPassword`/`textWebPassword` bila menangani aplikasi legacy
- [ ] **Verifikasi ulang:** jalankan kembali MASTG-TEST-0258 setiap penambahan form input baru

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0258: References to Keyboard Caching Attributes in UI Elements](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0258/)
- [MASWE-0036: Unnecessary Exposure of Sensitive Data via the User Interface](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0036/)
- [MASTG-KNOW-0055: Keyboard Cache](https://mas.owasp.org/MASTG/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0055/)
- [MASTG-BEST-0019: Use Non-Caching Input Types for Sensitive Fields](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0019/)
- [MASTG-TECH-0007: Extract Layout Files](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0007/)
- [Rule resmi: mastg-android-keyboard-cache-input-types.yml (GitHub)](https://github.com/OWASP/mastg/blob/master/rules/mastg-android-keyboard-cache-input-types.yml)

### 5.2 Dokumentasi Resmi Android

- [Android Developers — `TextView` `android:inputType` reference](https://developer.android.com/reference/android/widget/TextView#attr_android:inputType)
- [Android Developers — `InputType` class reference](https://developer.android.com/reference/android/text/InputType)
- [Android Developers — Jetpack Compose `KeyboardOptions`](https://developer.android.com/reference/kotlin/androidx/compose/foundation/text/KeyboardOptions)
- [Android Source — `InputType.java`](https://cs.android.com/android/platform/superproject/main/+/main:frameworks/base/core/java/android/text/InputType.java)

### 5.3 Riset dan Kasus Nyata

- [Gearbrain — Android Keyboard App (Ai.Type) Spills Personal Data of 31M Users](https://www.gearbrain.com/aitype-android-keyboard-data-leak-2515327775.html)
- [Citizen Lab — The Not-So-Silent Type: Vulnerabilities Across Keyboard Apps](https://citizenlab.ca/research/vulnerabilities-across-keyboard-apps-reveal-keystrokes-to-network-eavesdroppers/)
- [ResearchGate — Keyboard or Keylogger? A Security Analysis of Third-Party Keyboards on Android](https://www.researchgate.net/publication/308820014_Keyboard_or_keylogger_A_security_analysis_of_third-party_keyboards_on_Android)
- [Kaspersky — Is It Possible to Spy on Keystrokes from an Android On-Screen Keyboard?](https://www.kaspersky.com/blog/prevent-android-keylogging-and-ime-spying/51281/)
- [Zeltser — Security of Third-Party Keyboard Apps on Mobile Devices](https://zeltser.com/third-party-keyboards-security)
- [IEEE S&P 2020 Poster — Android IME Privacy Leakage Analyzer](https://www.ieee-security.org/TC/SP2020/poster-abstracts/hotcrp_sp20posters-final12.pdf)
- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
- [CWE-524: Use of Cache Containing Sensitive Information](https://cwe.mitre.org/data/definitions/524.html)

### 5.4 Dokumentasi Tools

- [apktool](https://apktool.org/)
- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [Semgrep — Documentation](https://semgrep.dev/docs/)
- [CodeQL — Documentation](https://codeql.github.com/docs/)
- [Frida — Dynamic instrumentation toolkit](https://frida.re/docs/javascript-api/)
- [Accessibility Scanner (Google Play)](https://play.google.com/store/apps/details?id=com.google.android.apps.accessibility.auditor)

---

*Dokumen ini disusun berdasarkan OWASP MASTG (rilis terkini per September 2026), dokumentasi resmi Android Developers, serta riset dan insiden nyata (kasus Ai.Type, riset Citizen Lab) tentang risiko keamanan aplikasi keyboard pihak ketiga. Nuansa terpenting: rule semgrep resmi hanya mencakup satu dari tiga jalur konfigurasi (`setInputType()`), melewatkan XML layout dan Jetpack Compose yang justru menjadi pola paling umum dipakai developer — pemeriksaan manual/grep menyeluruh terhadap ketiga jalur adalah wajib untuk evaluasi yang benar-benar lengkap.*
