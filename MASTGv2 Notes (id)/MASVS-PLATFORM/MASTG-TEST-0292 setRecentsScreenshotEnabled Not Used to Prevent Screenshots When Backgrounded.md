# MASTG-TEST-0292 `setRecentsScreenshotEnabled` Not Used to Prevent Screenshots When Backgrounded

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0292 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-PLATFORM |
| **Weakness** | MASWE-0038 — *Insufficient Protection of Sensitive Data from Screenshots or Screen Recordings* (sama seperti MASTG-TEST-0289/0291) |
| **API yang disorot** | `Activity.setRecentsScreenshotEnabled(boolean)` — API 33+ |
| **Tipe Pengujian** | Static, Code |
| **Status resmi MASTG** | **`placeholder`** — belum ada Overview/Steps/Evaluation lengkap |
| **Catatan resmi (satu-satunya konten yang tersedia)** | *"This test verifies whether an app prevents sensitive data from being captured in the Recents screen when backgrounded."* |
| **Knowledge** | MASTG-KNOW-0053 |
| **Best Practice** | MASTG-BEST-0014 (Preventing Screenshots and Screen Recording), MASTG-BEST-0015 (Use `setRecentsScreenshotEnabled` to Prevent Screenshots When Backgrounded — **juga berstatus placeholder**) |
| **Test terkait** | **MASTG-TEST-0289** (bukti visual dinamis), **MASTG-TEST-0291** (References to Screen Capturing Prevention APIs — menyasar `FLAG_SECURE`; test ini menyasar API **berbeda** yang melengkapi, bukan menggantikan, `FLAG_SECURE`) |
| **Demo terkait** | — (tidak ada) |
| **Rule resmi** | — (tidak ada; test placeholder) |
| **CWE terkait** | CWE-200, CWE-311 |

---

## 1. Penjelasan

### 1.1 Status Test Ini dan Dua Placeholder Sekaligus

Ini kasus yang **jarang terjadi** dalam seri riset ini: **baik test ini maupun best practice yang dirujuknya (MASTG-BEST-0015) sama-sama berstatus `placeholder`**. Ini kemungkinan mencerminkan bahwa API `setRecentsScreenshotEnabled` masih tergolong **relatif baru** (diperkenalkan di Android 13/API 33, tahun 2022) dibanding `FLAG_SECURE` yang sudah menjadi standar sejak API 1 — dokumentasi resmi MASTG untuk topik ini kemungkinan masih dalam proses penyusunan lebih lengkap. Dokumen ini disusun sepenuhnya dari **riset independen** terhadap dokumentasi resmi Android Developers dan artikel komunitas.

### 1.2 Apa Itu `setRecentsScreenshotEnabled` dan Mengapa Ia Berbeda dari `FLAG_SECURE`

Ini API yang secara khusus **menyasar satu skenario spesifik** — thumbnail preview di layar Recents/Overview — berbeda dari `FLAG_SECURE` (dibahas mendalam di dokumen MASTG-TEST-0289/0291) yang bekerja secara **jauh lebih luas**:

```java
// Diperkenalkan di Activity sejak API 33 (Android 13)
setRecentsScreenshotEnabled(false);
```

Sesuai dokumentasi resmi Android:

> *"By default, this value is `true`... What this does: Hides your activity's thumbnail in Recents. What it does NOT do: Does not block normal screenshots; Does not stop screen recording."*

Perbedaan cakupan antara kedua API secara ringkas:

| Aspek | `FLAG_SECURE` | `setRecentsScreenshotEnabled(false)` |
|---|---|---|
| **Cakupan** | **Global** — memblokir screenshot manual pengguna, screen recording, tampilan pada display non-aman (casting), **dan** thumbnail Recents sekaligus | **Sempit** — **hanya** memengaruhi thumbnail di layar Recents/Overview |
| **Screenshot manual pengguna** | Diblokir (layar hitam) | **Tetap berhasil normal** — pengguna masih bisa screenshot manual seperti biasa |
| **Screen recording** | Diblokir | **Tidak terpengaruh** |
| **API minimum** | API 1 (tersedia sejak awal) | **API 33** (Android 13) |
| **Dampak UX** | Signifikan — seluruh interaksi screenshot/recording pengguna terblokir di window tersebut | Minimal — pengguna nyaris tidak menyadari perbedaan kecuali mencoba melihat preview di Recents |

### 1.3 Mengapa API Ini Bernilai Sebagai Pelengkap, Bukan Pengganti `FLAG_SECURE`

Poin konseptual terpenting yang menjelaskan **kapan** API ini relevan dipakai: `FLAG_SECURE` adalah — sesuai istilah yang sudah dikutip di dokumen MASTG-TEST-0289 — *"instrumen yang kasar"* (blunt instrument) yang memblokir **segalanya** sekaligus, termasuk kebutuhan screenshot legitimate yang mungkin diinginkan pengguna (mis. menyimpan bukti transaksi, screenshot riwayat pesanan untuk dokumentasi pribadi). `setRecentsScreenshotEnabled(false)` menawarkan **titik keseimbangan berbeda**: ia menutup **jalur kebocoran pasif otomatis** (thumbnail Recents yang muncul tanpa tindakan sadar pengguna) sembari **tetap mengizinkan** pengguna mengambil screenshot secara sadar jika mereka benar-benar menginginkannya.

Ini relevan khususnya untuk skenario di mana:
- Developer ingin **menghindari friksi UX** yang muncul dari `FLAG_SECURE` (pengguna komplain tidak bisa screenshot struk transaksi untuk kebutuhan pribadi), namun tetap ingin menutup celah **thumbnail otomatis** yang muncul tanpa kesadaran pengguna sama sekali.
- Aplikasi menargetkan **API 33+ secara eksklusif** dan ingin kontrol yang lebih granular dibanding pendekatan "semua-atau-tidak-sama-sekali" dari `FLAG_SECURE`.

### 1.4 Keterbatasan Penting: Sistem Tetap Bisa Mengambil Screenshot dalam Konteks Lain

Dokumentasi resmi memberi catatan penting yang harus dipahami sebagai batasan API ini:

> *"The system may still take screenshots of the activity in other contexts; for example, when the user takes a screenshot of the entire screen, or when the active `VoiceInteractionService` requests a screenshot."*

Ini menegaskan **cakupan API yang benar-benar sempit** — `setRecentsScreenshotEnabled(false)` **murni** menghentikan proses generasi screenshot otomatis khusus untuk keperluan Recents, dan **tidak** memberi proteksi apa pun terhadap mekanisme capture lain (screenshot manual pengguna, permintaan capture dari layanan asisten suara/`VoiceInteractionService`, atau aplikasi aksesibilitas dengan izin capture layar). Ini **bukan** solusi umum untuk MASWE-0038 — ia hanya menutup **satu celah spesifik** dari sekian banyak jalur kebocoran visual yang mungkin ada.

### 1.5 Rekomendasi Kombinasi: Kapan Memakai yang Mana

Berdasarkan sintesis pemahaman kedua API:

| Skenario | Rekomendasi |
|---|---|
| Layar menampilkan kredensial/data finansial sangat sensitif (PIN, kata sandi, nomor kartu) | **`FLAG_SECURE`** — proteksi maksimal diperlukan, friksi UX dapat diterima demi keamanan |
| Layar menampilkan data yang cukup sensitif namun pengguna secara wajar mungkin ingin screenshot untuk kebutuhan pribadi (mis. detail pesanan, e-tiket, struk pembayaran yang sudah selesai) | **`setRecentsScreenshotEnabled(false)`** — menutup celah thumbnail pasif tanpa mengorbankan kemampuan screenshot sadar pengguna |
| Aplikasi mendukung API di bawah 33 dan butuh proteksi Recents | **Wajib `FLAG_SECURE`** — `setRecentsScreenshotEnabled` tidak tersedia, dan `FLAG_SECURE` sendiri **sudah** menutup celah Recents sebagai bagian dari cakupannya yang lebih luas (dibahas di dokumen MASTG-TEST-0289) |
| Kombinasi keduanya | Untuk layar yang sangat sensitif pada aplikasi dengan `minSdkVersion` < 33, tetap andalkan `FLAG_SECURE` saja — kedua API pada dasarnya **redundan** untuk kasus Recents spesifik, karena `FLAG_SECURE` sudah mencakupnya |

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | Fungsi |
|---|---|
| **jadx** | Dekompilasi DEX → Java untuk pencarian pola `setRecentsScreenshotEnabled` |
| **grep / ripgrep** | Pencarian pola API |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **CodeQL** | Sama seperti dokumen MASTG-TEST-0291, membangun peta Activity sensitif dan mengorelasikan dengan kedua API (`FLAG_SECURE` **dan** `setRecentsScreenshotEnabled`) sekaligus untuk gambaran proteksi menyeluruh |
| **aapt2 / apkanalyzer** | Ekstraksi `targetSdkVersion`/`minSdkVersion` — relevan karena API ini hanya berfungsi pada API 33+ |
| **MASTG-TEST-0289 (metodologi ekstraksi screenshot)** | Verifikasi dinamis — bandingkan hasil thumbnail Recents sebelum/sesudah penerapan API ini |

### 2.3 Prasyarat Lingkungan

- **Tidak butuh device/root** untuk analisis statis inti.
- **Untuk verifikasi dinamis**, dibutuhkan device/emulator dengan **Android 13+** — API ini tidak berfungsi pada versi lebih lama.
- **Periksa `minSdkVersion`/`targetSdkVersion`** sebagai konteks wajib — sama seperti pola berulang di berbagai test dalam seri riset ini (MASTG-TEST-0245, 0252), keberadaan/ketiadaan API ini harus dinilai relatif terhadap rentang versi yang didukung aplikasi.

---

## 3. Cara Pengujian

Karena tidak ada langkah resmi (status placeholder), metodologi berikut disusun dari riset independen.

### 3.1 Langkah Umum

1. Identifikasi layar sensitif (prasyarat `identify-sensitive-screens`, sama seperti MASTG-TEST-0289/0291).
2. Untuk setiap layar, periksa apakah `FLAG_SECURE` **dan/atau** `setRecentsScreenshotEnabled(false)` diterapkan.
3. Nilai kombinasi keduanya relatif terhadap `minSdkVersion` aplikasi (§1.5).

### 3.2 Metode A — grep/ripgrep

```bash
D=./decompiled/sources

rg -n 'setRecentsScreenshotEnabled\(' $D
```

```bash
# Korelasikan dengan targetSdkVersion untuk menilai relevansi
grep -oP 'targetSdkVersion="\K[0-9]+' AndroidManifest.xml
```

### 3.3 Metode B — CodeQL untuk Peta Proteksi Ganda

```ql
import java

class ActivityClass extends Class {
  ActivityClass() {
    this.getASupertype*().hasQualifiedName("android.app", "Activity")
  }
}

class FlagSecureCall extends MethodAccess {
  FlagSecureCall() {
    this.getMethod().hasName(["addFlags", "setFlags"]) and
    this.getAnArgument().toString().matches("%FLAG_SECURE%")
  }
}

class RecentsScreenshotCall extends MethodAccess {
  RecentsScreenshotCall() {
    this.getMethod().hasName("setRecentsScreenshotEnabled")
  }
}

from ActivityClass activity
where activity.getName().toLowerCase().regexpMatch(".*(payment|pin|password|card|wallet|otp).*")
  and not exists(FlagSecureCall f | f.getEnclosingCallable().getDeclaringType() = activity)
  and not exists(RecentsScreenshotCall r | r.getEnclosingCallable().getDeclaringType() = activity)
select activity, "Activity sensitif TANPA FLAG_SECURE maupun setRecentsScreenshotEnabled"
```

### 3.4 Metode C — Verifikasi Dinamis (Android 13+, Perbandingan dengan MASTG-TEST-0289)

```bash
# Ekstrak snapshot Recents sebelum dan sesudah penerapan API ini pada device Android 13+
adb pull /data/system_ce/0/snapshots/ ./before/
# ... picu ulang setelah perubahan kode ...
adb pull /data/system_ce/0/snapshots/ ./after/
diff -rq ./before/ ./after/
```

### 3.5 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Kapan dipakai |
|---|---|---|
| **A** | grep | Baseline cepat |
| **B** | CodeQL | Peta proteksi ganda (`FLAG_SECURE` + API ini) untuk seluruh Activity sensitif |
| **C** | Verifikasi dinamis | Konfirmasi definitif pada device Android 13+ |

**Kombinasi minimum yang aku rekomendasikan:** **B (peta menyeluruh, menilai KEDUA API sekaligus per Activity) → C (konfirmasi dinamis bila device Android 13+ tersedia)**.

---

### 3.6 Kriteria Evaluasi: Positive Case & Negative Case

Karena tidak ada klausul Evaluation resmi (status placeholder), kriteria berikut disusun berdasarkan catatan resmi singkat dan prinsip dasar MASWE-0038.

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi |
|---|---|
| F1 | Aplikasi menargetkan API 33+ secara eksklusif untuk suatu fitur, layar sensitif teridentifikasi **tidak memiliki** `FLAG_SECURE` **maupun** `setRecentsScreenshotEnabled(false)` |
| F2 | Verifikasi dinamis (Metode C, Android 13+) mengonfirmasi thumbnail Recents tetap menampilkan konten sensitif meski API ini **seharusnya** diterapkan |

**Catatan penting**: karena `FLAG_SECURE` **sudah** menutup celah Recents sebagai bagian dari cakupannya (dibahas di MASTG-TEST-0289), **ketiadaan** `setRecentsScreenshotEnabled` **bukan otomatis FAIL** bila `FLAG_SECURE` sudah diterapkan dengan benar pada layar yang sama — kedua API redundan untuk skenario ini.

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi |
|---|---|
| P1 | Layar sensitif dilindungi `FLAG_SECURE` (mencakup celah Recents secara otomatis) — `setRecentsScreenshotEnabled` menjadi tidak relevan/opsional |
| P2 | Layar sensitif (yang secara sengaja tidak diberi `FLAG_SECURE` demi UX, sesuai skenario §1.5) diberi `setRecentsScreenshotEnabled(false)` sebagai kompromi yang tepat |
| P3 | Verifikasi dinamis mengonfirmasi thumbnail Recents kosong/placeholder untuk layar tersebut |

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Jangan menuntut API ini bila `FLAG_SECURE` sudah diterapkan dengan benar** — sesuai §1.5, keduanya redundan untuk kasus Recents. Fokus evaluasi pada **apakah SALAH SATU** dari keduanya menutup celah ini, bukan menuntut keduanya sekaligus.

2. **Nilai unik API ini justru muncul ketika `FLAG_SECURE` SENGAJA tidak dipakai** demi UX — dalam skenario ini, ketiadaan `setRecentsScreenshotEnabled` justru menjadi celah nyata yang perlu ditandai.

3. **API 33 adalah batas keras** — jangan menuntut penggunaan API ini pada aplikasi dengan `minSdkVersion`/`targetSdkVersion` di bawah 33; untuk kasus tersebut, `FLAG_SECURE` tetap menjadi satu-satunya jalur yang valid.

4. **Ingat keterbatasan cakupan API ini** (§1.4) — jangan biarkan laporan menyiratkan bahwa API ini memberi proteksi setara `FLAG_SECURE`; ia murni menutup celah thumbnail Recents saja.

5. **Dokumentasikan:** status kedua API per layar sensitif, `minSdkVersion`/`targetSdkVersion` aplikasi, dan justifikasi bila `FLAG_SECURE` sengaja tidak dipakai demi UX.

---

## 4. Rekomendasi Perbaikan

### 4.1 Terapkan sebagai Pelengkap untuk Skenario UX-Sensitif

```kotlin
class OrderDetailActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            setRecentsScreenshotEnabled(false)  // Izinkan screenshot manual, blokir thumbnail Recents
        }
        // TIDAK menerapkan FLAG_SECURE di sini — pengguna boleh screenshot manual untuk struk pesanan
    }
}
```

### 4.2 Checklist Remediasi

- [ ] Untuk setiap layar sensitif, tentukan kebijakan yang tepat: `FLAG_SECURE` penuh vs `setRecentsScreenshotEnabled` saja vs kombinasi
- [ ] API `setRecentsScreenshotEnabled` dibungkus pengecekan `Build.VERSION.SDK_INT >= 33`
- [ ] Verifikasi dinamis dilakukan pada device Android 13+ untuk mengonfirmasi efektivitas
- [ ] **Verifikasi ulang:** jalankan kembali MASTG-TEST-0292 setiap penambahan layar baru

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0292: setRecentsScreenshotEnabled Not Used to Prevent Screenshots When Backgrounded](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0292/)
- [MASTG-TEST-0289: Runtime Verification of Sensitive Content Exposure in Screenshots](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0289/)
- [MASTG-TEST-0291: References to Screen Capturing Prevention APIs](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0291/)
- [MASWE-0038: Insufficient Protection of Sensitive Data from Screenshots or Screen Recordings](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0038/)
- [MASTG-BEST-0015: Use setRecentsScreenshotEnabled to Prevent Screenshots When Backgrounded](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0015/)

### 5.2 Dokumentasi Resmi Android

- [Android Developers — `Activity#setRecentsScreenshotEnabled()`](https://developer.android.com/reference/android/app/Activity#setRecentsScreenshotEnabled(boolean))
- [Android Developers — Secure Sensitive Activities](https://developer.android.com/security/fraud-prevention/activities)

### 5.3 Riset dan Artikel Komunitas

- [ProAndroidDev — Multitasking Intrusion and Preventing Screenshots in Android Apps](https://proandroiddev.com/multitasking-intrusion-and-preventing-screenshots-in-android-app-15bd8757c24d)
- [Worth Doing Badly — Accessing Screenshots from Android's Recent Apps Screen](https://worthdoingbadly.com/androidrecents/)
- [Jojonosaurus — Behind the Screen: Detecting and Preventing Screenshots in Android](https://jojonosaur.us/posts/flag-secure/)
- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)

### 5.4 Dokumentasi Tools

- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [CodeQL — Documentation](https://codeql.github.com/docs/)

---

*Dokumen ini disusun sepenuhnya dari riset independen (dokumentasi resmi Android Developers dan artikel komunitas) karena baik MASTG-TEST-0292 maupun MASTG-BEST-0015 yang dirujuknya sama-sama berstatus **placeholder**. Nuansa terpenting: `setRecentsScreenshotEnabled(false)` bukan pengganti `FLAG_SECURE`, melainkan alat yang jauh lebih sempit cakupannya — hanya menutup celah thumbnail Recents tanpa memblokir screenshot manual atau screen recording. Nilainya justru muncul sebagai kompromi UX ketika `FLAG_SECURE` dianggap terlalu restriktif untuk suatu layar, bukan sebagai kewajiban tambahan pada layar yang sudah terlindungi `FLAG_SECURE` penuh.*
