# MASTG-TEST-0294 `SecureOn` Not Used to Prevent Screenshots in Compose Dialogs

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0294 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-PLATFORM |
| **Weakness** | MASWE-0038 — *Insufficient Protection of Sensitive Data from Screenshots or Screen Recordings* (sama seperti MASTG-TEST-0289/0291/0292/0293) |
| **API yang disorot** | `androidx.compose.ui.window.DialogProperties(securePolicy = ...)`, `SecureFlagPolicy` (`SecureOn`, `SecureOff`, `Inherit`) |
| **Tipe Pengujian** | Static, Code |
| **Status resmi MASTG** | **`placeholder`** — belum ada Overview/Steps/Evaluation lengkap |
| **Catatan resmi (satu-satunya konten yang tersedia)** | *"This test verifies whether an app prevents sensitive data from being captured in screenshots and screen recordings of Jetpack Compose dialogs."* |
| **Knowledge** | MASTG-KNOW-0053 |
| **Best Practice** | MASTG-BEST-0014, MASTG-BEST-0018 (Use `SecureFlagPolicy.SecureOn` to Prevent Screenshots in Compose Components — **juga berstatus placeholder**) |
| **Test terkait** | **MASTG-TEST-0289/0291/0292/0293** — kelompok lengkap MASWE-0038; test ini melengkapi **MASTG-TEST-0293** (SurfaceView) sebagai celah arsitektural kedua yang spesifik-komponen, kini untuk konteks **Jetpack Compose** |
| **Demo terkait** | — (tidak ada) |
| **Rule resmi** | — (tidak ada; test placeholder) |
| **CWE terkait** | CWE-200, CWE-311 |

---

## 1. Penjelasan

### 1.1 Status Test Ini

Sama seperti MASTG-TEST-0292 dan MASTG-TEST-0293, baik test ini maupun best practice yang dirujuknya (**MASTG-BEST-0018**) sama-sama berstatus **`placeholder`**. Dokumen ini disusun sepenuhnya dari riset independen terhadap dokumentasi resmi Jetpack Compose dan riwayat isu publik terkait topik ini.

### 1.2 Akar Masalah: `Dialog` Compose Membuat Window Android yang Sepenuhnya Baru

Ini adalah kelanjutan konseptual langsung dari celah arsitektural yang dibahas di dokumen **MASTG-TEST-0293** (`SurfaceView`), namun dengan **mekanisme teknis yang berbeda**. Komponen `Dialog` pada Jetpack Compose **tidak dirender di dalam window Activity yang sama** — ia secara internal membuat **`android.view.Window` yang benar-benar baru** (via `android.app.Dialog` di level platform), terpisah sepenuhnya dari window Activity induknya. Ini berbeda dari celah `SurfaceView` (yang tetap berada dalam window yang sama namun di compositor layer terpisah) — di sini, **window itu sendiri yang baru**, sehingga pertanyaan "apakah `FLAG_SECURE` menular ke window baru ini?" menjadi relevan secara arsitektural.

### 1.3 Evolusi Historis: Dari Celah ke Perilaku Default yang Diperbaiki

Ini bagian paling menarik dari riset untuk test ini — berbeda dari `SurfaceView` (MASTG-TEST-0293) yang **sampai sekarang** tidak otomatis mewarisi `FLAG_SECURE`, celah serupa pada Compose `Dialog` **sudah diperbaiki** menjadi perilaku default yang lebih aman, namun riwayatnya penting dipahami untuk menilai risiko pada versi Compose yang lebih lama:

- **Masalah historis** (didokumentasikan di laporan isu publik Google Issue Tracker #143778149 dan #171682480): implementasi awal widget Compose **gagal secara otomatis** menerapkan `FLAG_SECURE` pada window Dialog baru yang dibuatnya, **meski** window Activity yang meluncurkannya sudah memiliki `FLAG_SECURE` aktif. Rationale perbaikan yang diajukan komunitas saat itu secara eksplisit menyatakan: *"the ideal solution would be for `FLAG_SECURE` to be propagated: if `FLAG_SECURE` is set on an activity or fragment displaying a composable, then those composables should also set `FLAG_SECURE` on any windows they create."*
- **Perilaku saat ini** (versi Compose modern): `DialogProperties` menyediakan parameter `securePolicy` dengan **default value `SecureFlagPolicy.Inherit`** — yang berarti, **sejak perbaikan ini diterapkan**, Dialog Compose **secara otomatis mewarisi** status `FLAG_SECURE` dari window peluncurnya tanpa developer perlu melakukan apa pun secara eksplisit.

### 1.4 Tiga Nilai `SecureFlagPolicy` dan Implikasinya

```kotlin
enum class SecureFlagPolicy {
    Inherit,    // Default — mewarisi status FLAG_SECURE dari window induk secara otomatis
    SecureOn,   // Memaksa FLAG_SECURE AKTIF pada Dialog ini, terlepas status window induk
    SecureOff   // Memaksa FLAG_SECURE NONAKTIF pada Dialog ini, terlepas status window induk
}
```

| Nilai | Perilaku | Kapan relevan |
|---|---|---|
| **`Inherit`** (default) | Dialog otomatis "ikut" status `FLAG_SECURE` window peluncurnya | Skenario paling umum — developer tidak perlu melakukan apa pun |
| **`SecureOn`** | Dialog **selalu** aman, bahkan bila window peluncurnya **tidak** memiliki `FLAG_SECURE` | Dialog yang menampilkan konten sensitif (PIN, OTP) **meski diluncurkan dari Activity yang tidak sensitif secara umum** |
| **`SecureOff`** | Dialog **selalu tidak aman**, bahkan bila window peluncurnya **memiliki** `FLAG_SECURE` | **Berbahaya** bila diterapkan tanpa justifikasi — secara eksplisit melepas proteksi yang seharusnya diwarisi |

### 1.5 Mengapa Test Ini Tetap Relevan Meski Default Sudah Diperbaiki

Berbeda dari `SurfaceView` (di mana risikonya **selalu** relevan karena tidak ada perilaku default aman), test ini punya nuansa yang lebih bersyarat — namun tetap penting diperiksa karena beberapa skenario risiko nyata:

1. **Versi Jetpack Compose yang lebih lama** yang belum menerapkan perbaikan `SecureFlagPolicy.Inherit` sebagai default — aplikasi dengan dependency Compose yang tidak diperbarui tetap mewarisi celah historis ini.
2. **`securePolicy = SecureFlagPolicy.SecureOff` diterapkan secara eksplisit** — baik karena kesalahan copy-paste kode, kebutuhan debugging yang tertinggal, atau kesalahpahaman developer tentang parameter ini.
3. **`Inherit` hanya efektif bila window INDUK memang sudah memiliki `FLAG_SECURE`** — bila Activity peluncur **tidak** memiliki `FLAG_SECURE` (karena memang bukan layar sensitif secara umum), namun Dialog yang dimunculkannya **menampilkan** konten sensitif (mis. dialog konfirmasi PIN di tengah alur checkout yang sebagian besar non-sensitif), **`Inherit` tidak cukup** — developer **wajib** secara eksplisit memakai `SecureFlagPolicy.SecureOn` untuk Dialog spesifik tersebut.
4. **Komponen `Popup` Compose** (berbeda dari `Dialog`) memiliki riwayat dan properti konfigurasi yang terpisah — perlu diperiksa secara independen apakah perilaku pewarisannya identik.

Poin #3 di atas adalah **nuansa evaluasi paling penting** — mirip dengan pola di MASTG-TEST-0292 (`setRecentsScreenshotEnabled`), di mana `Inherit` yang berfungsi sempurna **tidak serta merta cukup** bila granularitas proteksi yang dibutuhkan berbeda dari window induknya.

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | Fungsi |
|---|---|
| **jadx** | Dekompilasi DEX → Java/Kotlin-like untuk pencarian pola `DialogProperties`/`securePolicy` |
| **grep / ripgrep** | Pencarian pola API |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **CodeQL** | Menelusuri seluruh pemanggilan `Dialog(...)` Compose, memeriksa parameter `properties`/`securePolicy` yang diberikan, dan mengorelasikan dengan status `FLAG_SECURE` Activity induk |
| **Audit versi dependency (`build.gradle`)** | Memeriksa versi `androidx.compose.ui` yang dipakai — relevan untuk menilai apakah perbaikan default `Inherit` sudah berlaku pada versi tersebut |
| **MASTG-TEST-0289 (metodologi ekstraksi screenshot)** | Verifikasi dinamis definitif |

### 2.3 Prasyarat Lingkungan

- **Tidak butuh device/root** untuk analisis statis inti.
- **Periksa versi Jetpack Compose** (`androidx.compose.ui:ui` di `build.gradle`) sebagai konteks wajib.
- **Identifikasi seluruh Dialog Compose** yang menampilkan konten sensitif (konfirmasi PIN, OTP, detail kartu) sebagai target audit utama.

---

## 3. Cara Pengujian

Karena tidak ada langkah resmi (status placeholder), metodologi berikut disusun dari riset independen.

### 3.1 Langkah Umum

1. Identifikasi seluruh pemanggilan `Dialog(...)`/`AlertDialog(...)` Compose dalam basis kode.
2. Untuk setiap Dialog yang menampilkan konten sensitif, periksa parameter `securePolicy` yang diberikan (atau ketiadaannya, yang berarti default `Inherit`).
3. Untuk kasus `Inherit`, verifikasi apakah Activity/window peluncur benar-benar memiliki `FLAG_SECURE` — bila tidak, `Inherit` tidak memberi proteksi apa pun.

### 3.2 Metode A — grep/ripgrep

```bash
D=./decompiled/sources

# Temukan seluruh pemanggilan Dialog Compose dengan securePolicy eksplisit
rg -n 'securePolicy\s*=\s*SecureFlagPolicy\.' $D

# Temukan secara khusus kasus BERBAHAYA: SecureOff eksplisit
rg -n 'SecureFlagPolicy\.SecureOff' $D

# Temukan Dialog TANPA securePolicy sama sekali (default Inherit) — perlu verifikasi manual window induk
rg -n -B10 'Dialog\(' $D | grep -v "securePolicy"
```

### 3.3 Metode B — CodeQL untuk Korelasi dengan Window Induk

```ql
import java

class ComposeDialogCall extends MethodAccess {
  ComposeDialogCall() {
    this.getMethod().hasName("Dialog") and
    this.getMethod().getDeclaringType().getPackage().getName().matches("androidx.compose.ui.window%")
  }
}

from ComposeDialogCall dialog
where not exists(string s | s = dialog.toString() and s.matches("%securePolicy%"))
select dialog, "Dialog Compose ditemukan tanpa securePolicy eksplisit — verifikasi manual apakah window induk memiliki FLAG_SECURE (Inherit)"
```

### 3.4 Metode C — Audit Versi Dependency

```bash
grep -A2 "androidx.compose.ui:ui" app/build.gradle
```

Bandingkan versi yang ditemukan dengan changelog resmi Jetpack Compose untuk memastikan perbaikan `SecureFlagPolicy.Inherit` default sudah berlaku pada versi tersebut.

### 3.5 Metode D — Verifikasi Dinamis

```bash
# Picu Dialog yang menampilkan konten sensitif, lalu screenshot manual
adb shell input tap <koordinat_tombol_pemicu_dialog>
adb shell screencap -p /sdcard/dialog_test.png
adb pull /sdcard/dialog_test.png
```

Bila screenshot menunjukkan konten Dialog secara jelas (bukan hitam/kosong), ini bukti definitif proteksi tidak efektif — baik karena `SecureOff` eksplisit, versi Compose lama, atau window induk yang tidak memiliki `FLAG_SECURE` sementara Dialog mengandalkan `Inherit`.

### 3.6 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Kapan dipakai |
|---|---|---|
| **A** | grep | Baseline cepat, identifikasi `SecureOff` eksplisit (paling kritis) |
| **B** | CodeQL | Korelasi sistematis Dialog dengan status window induk |
| **C** | Audit versi | Menilai relevansi risiko historis |
| **D** | Verifikasi dinamis | Bukti definitif |

**Kombinasi minimum yang aku rekomendasikan:** **A (cari `SecureOff` eksplisit dulu, paling kritis) → B (korelasi Dialog dengan Inherit) → D (konfirmasi dinamis)**.

---

### 3.7 Kriteria Evaluasi: Positive Case & Negative Case

Karena tidak ada klausul Evaluation resmi (status placeholder), kriteria berikut disusun berdasarkan catatan resmi singkat dan prinsip arsitektural yang dijelaskan di §1.2–1.5.

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi |
|---|---|
| F1 | Dialog Compose yang menampilkan konten sensitif menggunakan `securePolicy = SecureFlagPolicy.SecureOff` secara eksplisit |
| F2 | Dialog mengandalkan `Inherit` (default), namun Activity/window peluncurnya **tidak** memiliki `FLAG_SECURE` — sehingga Dialog yang menampilkan konten sensitif tetap tidak terlindungi |
| F3 | Aplikasi memakai versi Jetpack Compose lama yang belum menerapkan perbaikan default `Inherit`, dan tidak ada `securePolicy` eksplisit yang dikonfigurasi sebagai kompensasi |
| F4 | Verifikasi dinamis mengonfirmasi konten Dialog sensitif tetap terlihat jelas pada screenshot |

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi |
|---|---|
| P1 | Dialog yang menampilkan konten sensitif secara eksplisit memakai `SecureFlagPolicy.SecureOn` — proteksi terjamin terlepas status window induk |
| P2 | Dialog mengandalkan `Inherit`, **dan** dikonfirmasi window induknya memang memiliki `FLAG_SECURE` aktif |
| P3 | Versi Jetpack Compose yang dipakai sudah menerapkan default `Inherit` yang benar, dikonfirmasi lewat audit versi |

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **`Inherit` BUKAN proteksi mutlak — efektivitasnya bergantung sepenuhnya pada status window induk.** Ini kesalahan evaluasi paling mungkin terjadi: menyimpulkan PASS hanya karena `securePolicy` tidak diset secara eksplisit (sehingga "memakai default yang aman"), tanpa memverifikasi apakah window induk benar-benar memiliki `FLAG_SECURE`.

2. **`SecureFlagPolicy.SecureOff` eksplisit adalah sinyal FAIL prioritas tertinggi** — ini pola yang paling jelas dan tidak ambigu, mirip `clearFlags()` tanpa justifikasi pada dokumen MASTG-TEST-0291.

3. **Untuk Dialog sensitif yang bisa dipicu dari Activity non-sensitif, `SecureOn` eksplisit adalah satu-satunya pilihan yang benar** — jangan mengandalkan `Inherit` untuk kasus ini.

4. **Periksa versi Compose sebagai konteks wajib** — risiko ini jauh lebih relevan pada basis kode dengan dependency Compose yang sudah lama tidak diperbarui.

5. **Severity dimodulasi:**

   | Faktor | Severity |
   |---|---|
   | `SecureOff` eksplisit pada Dialog PIN/OTP/kartu | **Kritis** |
   | `Inherit` dipakai pada Dialog sensitif yang dipicu dari Activity non-`FLAG_SECURE` | **Tinggi** |
   | Versi Compose lama tanpa kompensasi eksplisit | **Menengah-Tinggi** |
   | `SecureOn` eksplisit sudah diterapkan dengan benar | **Bukan temuan** |

6. **Dokumentasikan:** daftar Dialog sensitif beserta nilai `securePolicy` masing-masing, status `FLAG_SECURE` window induk untuk setiap kasus `Inherit`, dan versi Jetpack Compose yang dipakai.

---

## 4. Rekomendasi Perbaikan

### 4.1 Terapkan `SecureOn` Eksplisit untuk Dialog Sensitif

```kotlin
@Composable
fun PinConfirmationDialog(onConfirm: (String) -> Unit) {
    Dialog(
        onDismissRequest = { /* ... */ },
        properties = DialogProperties(
            securePolicy = SecureFlagPolicy.SecureOn  // Selalu aman, terlepas window induk
        )
    ) {
        // UI input PIN
    }
}
```

### 4.2 Perbarui Dependency Jetpack Compose

```gradle
dependencies {
    implementation "androidx.compose.ui:ui:1.7.0"  // Versi terkini yang sudah menerapkan default Inherit
}
```

### 4.3 Checklist Remediasi

- [ ] Seluruh Dialog Compose yang menampilkan konten sensitif diinventarisasi
- [ ] Dialog yang bisa dipicu dari Activity non-sensitif menggunakan `SecureOn` eksplisit
- [ ] Tidak ada `SecureOff` yang diterapkan tanpa justifikasi jelas
- [ ] Versi Jetpack Compose diperbarui ke rilis yang mendukung default `Inherit` yang benar
- [ ] **Verifikasi ulang:** jalankan kembali MASTG-TEST-0294 setiap penambahan Dialog baru

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0294: SecureOn Not Used to Prevent Screenshots in Compose Dialogs](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0294/)
- [MASTG-TEST-0293: setSecure Not Used to Prevent Screenshots in SurfaceViews](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0293/)
- [MASWE-0038: Insufficient Protection of Sensitive Data from Screenshots or Screen Recordings](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0038/)
- [MASTG-BEST-0018: Use SecureFlagPolicy.SecureOn to Prevent Screenshots in Compose Components](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0018/)

### 5.2 Dokumentasi Resmi Android

- [Android Developers — `DialogProperties` (Jetpack Compose)](https://developer.android.com/reference/kotlin/androidx/compose/ui/window/DialogProperties)
- [Android Developers — Secure Sensitive Activities](https://developer.android.com/security/fraud-prevention/activities)

### 5.3 Riset dan Riwayat Komunitas

- [CommonsWare — Securing Jetpack Compose](https://commonsware.com/blog/2019/12/10/securing-jetpack-compose.html)
- [Google Issue Tracker #143778149 — FLAG_SECURE propagation](https://issuetracker.google.com/issues/143778149?hl=ja)
- [Google Issue Tracker #171682480 — Status Update](https://issuetracker.google.com/issues/171682480?hl=ja)
- [ProAndroidDev — Android Security in the Age of Jetpack Compose](https://proandroiddev.com/android-security-in-the-age-of-jetpack-compose-from-task-hijacking-to-tapjacking-edbbc78be943)
- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)

### 5.4 Dokumentasi Tools

- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [CodeQL — Documentation](https://codeql.github.com/docs/)

---

*Dokumen ini disusun sepenuhnya dari riset independen karena baik MASTG-TEST-0294 maupun MASTG-BEST-0018 yang dirujuknya sama-sama berstatus **placeholder**. Berbeda dari celah `SurfaceView` (MASTG-TEST-0293) yang tidak memiliki perilaku default aman, komponen `Dialog` Jetpack Compose **sudah diperbaiki** untuk secara otomatis mewarisi `FLAG_SECURE` dari window induknya (`SecureFlagPolicy.Inherit` sebagai default). Namun nilai "Inherit" ini bukan proteksi mutlak — efektivitasnya bergantung penuh pada status window induk, sehingga Dialog sensitif yang bisa dipicu dari Activity non-sensitif tetap membutuhkan `SecureFlagPolicy.SecureOn` eksplisit sebagai satu-satunya jaminan proteksi yang benar.*
