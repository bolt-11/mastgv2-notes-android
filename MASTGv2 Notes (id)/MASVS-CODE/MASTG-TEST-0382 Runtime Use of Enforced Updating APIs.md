# MASTG-TEST-0382 Runtime Use of Enforced Updating APIs

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0382 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-CODE |
| **Weakness** | MASWE-0043 |
| **Tipe Pengujian** | Dynamic, Network, Hooks, **Manual** |
| **Teknik terkait** | MASTG-TECH-0005, MASTG-TECH-0010 (Capture App Traffic), MASTG-TECH-0043, MASTG-TECH-0023 |
| **Knowledge terkait** | MASTG-KNOW-0023 (Enforced Updating) |
| **Rule resmi** | — (tidak ada; murni dinamis dan behavioral, tidak ada pasangan statis dalam katalog saat ini) |

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian dan Mengapa Enforced Updating Relevan untuk Keamanan

Kutipan overview resmi MASTG:

> *"At runtime, Android apps implementing enforced updating typically either invoke the Google Play In-App Updates API... or perform a custom version check... If the app does not perform this check before access to protected functionality or backend services, or if the enforcement can be bypassed... the app fails to properly enforce the update."*

MASTG-KNOW-0023 menjelaskan **mengapa** memaksa update penting dari sudut pandang keamanan, bukan sekadar fitur produk biasa:

> *"Forcing a user to update the application can be necessary in multiple cases: A client-side vulnerability was discovered which needs to be fixed. Cryptographical key material that needs to be rotated (e.g. public key pinning). Migrating to a new API so that the old API can be decommissioned more quickly."*

Ini menegaskan bahwa enforced updating adalah **mekanisme respons insiden** — ketika kerentanan ditemukan di versi aplikasi yang sudah beredar luas, satu-satunya cara memastikan **seluruh basis pengguna** benar-benar terlindungi adalah memaksa mereka berpindah ke versi yang sudah diperbaiki, bukan sekadar menyediakan update dan berharap pengguna menginstalnya secara sukarela.

### 1.2 Catatan Penting: Update Tidak Menyelesaikan Masalah di Backend

Nuansa yang sering terlewat namun ditegaskan secara eksplisit:

> *"Keep in mind that updating the app does not resolve vulnerabilities residing on backend systems. A secure update mechanism should complement proper API and service lifecycle management."*

Ini relevan untuk konteks evaluasi yang lebih luas — enforced updating adalah **satu komponen** dari strategi keamanan lifecycle API/versi, bukan solusi tunggal. Bila kerentanan sesungguhnya berada di backend (bukan di client), memaksa update client tidak akan menyelesaikan akar masalah — backend tetap harus menerapkan API versioning dan deprecation policy-nya sendiri secara independen.

### 1.3 Dua Mekanisme Berbeda: Play In-App Updates API vs Backend-Gated Flow

| Mekanisme | Kapan Dipakai | API Inti |
|---|---|---|
| **Google Play In-App Updates API** | Aplikasi didistribusikan via Google Play, device mendukung (API 21+) | `AppUpdateManager`, `getAppUpdateInfo()`, `startUpdateFlowForResult()` |
| **Backend-Gated Flow (custom)** | Distribusi di luar Play Store, atau butuh enforcement lebih ketat | `BuildConfig.VERSION_CODE`/`VERSION_NAME`, `PackageManager.getPackageInfo()`, dibandingkan terhadap `minVersion` dari backend |

MASTG-KNOW-0023 secara eksplisit menegaskan keunggulan API resmi dibanding pendekatan lama yang rapuh:

> *"This mechanism is far more reliable than legacy methods such as scraping Play Store pages or calling undocumented endpoints, which are unstable and unsupported."*

### 1.4 Dua Mode Play In-App Updates dan Tiga Skenario Kegagalan Enforcement yang Spesifik

> *"Immediate updates, which use a full-screen flow requiring the user to update and restart the app before continuing... Flexible updates, which allow users to continue using the app while the update downloads in the background."*

Untuk update **immediate** (mode yang relevan untuk kerentanan kritis), overview resmi mengidentifikasi **tiga skenario kegagalan enforcement** yang sangat spesifik dan harus diuji satu per satu:

> *"Users can cancel or decline an immediate update, and an immediate update can become stalled if the app is closed or backgrounded before completion."*

1. **Dismissal langsung** — pengguna menutup dialog update tanpa melanjutkan.
2. **Pembatalan di tengah proses** — update flow sudah dimulai namun dibatalkan sebelum selesai.
3. **Backgrounding** — aplikasi diminimalkan/ditutup sebelum proses update tuntas, menghasilkan status `UpdateAvailability.DEVELOPER_TRIGGERED_UPDATE_IN_PROGRESS` yang **wajib** ditangani:

> *"The app should... check update state when the app returns to the foreground, for example in `onResume`... If `UpdateAvailability.DEVELOPER_TRIGGERED_UPDATE_IN_PROGRESS` is reported, restart the immediate update flow."*

Ketiga skenario ini secara langsung menjadi dasar struktur pengujian dinamis test ini (§3) — penguji **harus** mencoba masing-masing secara terpisah, karena aplikasi bisa menangani skenario pertama dengan benar namun gagal pada skenario ketiga (backgrounding), atau sebaliknya.

### 1.5 Keterbatasan Play Console Recovery Tools: Bukan Pengganti Enforcement Sesungguhnya

Catatan penting yang relevan untuk evaluasi — ada mekanisme **tingkat Play Console** yang terlihat seperti enforcement namun sesungguhnya jauh lebih lemah:

> *"Google Play also provides Play Console recovery tools that can prompt users... This is configured in Play Console rather than implemented directly in app code, and it should not be treated as a substitute for app-side or server-side enforcement when strict blocking is required, because users can dismiss the prompt and will be shown it again after a cold restart."*

Ini penting untuk membedakan: prompt Play Console **bukan** blocking sejati — pengguna tetap bisa menutup dialog dan melanjutkan menggunakan aplikasi versi lama sepenuhnya, hanya akan diingatkan kembali setelah restart dingin. Bila sebuah aplikasi **hanya** mengandalkan mekanisme ini dan menyebutnya sebagai "enforced update", ini adalah kesalahpahaman arsitektural yang harus ditandai sebagai temuan.

### 1.6 Praktik Backend-Gated Flow yang Baik, Termasuk Pertimbangan Integritas

MASTG-KNOW-0023 memberi panduan konkret untuk flow backend-gated, termasuk poin keamanan yang sering terlewat:

> *"Enforce the policy on backend services where possible by rejecting requests from unsupported app versions, especially for security-critical updates."*
>
> *"Consider integrity and tamper resistance. Avoid trusting only client-provided data, use platform integrity signals where appropriate, sign update policy responses if they are security-sensitive, and handle offline scenarios with a cached policy, a reasonable TTL, and a safe fallback."*

Poin pertama ini krusial — **enforcement yang benar-benar kuat** tidak hanya bergantung pada UI blocking di client (yang secara inheren dapat di-bypass lewat manipulasi lokal), tapi juga menolak **permintaan API itu sendiri** dari versi yang tidak didukung di sisi server. Ini sejalan dengan prinsip defense-in-depth yang berulang dalam seri riset ini — client-side check saja, betapapun baik dirancang, tetap rentan dimanipulasi oleh penyerang yang memiliki kendali penuh atas device mereka sendiri (root, Frida, proxy interception).

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | Fungsi |
|---|---|
| **ADB** | Instalasi app, kontrol siklus hidup aplikasi (background/foreground) untuk replikasi skenario §1.4 |
| **mitmproxy/Burp Suite** | Capture traffic (MASTG-TECH-0010) dan manipulasi nilai versi yang dikirim ke backend |
| **Frida** | Hooking `AppUpdateManager`/`getAppUpdateInfo()`/`startUpdateFlowForResult()` (MASTG-TECH-0043) |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **Objection** | Eksplorasi cepat method call terkait update tanpa script kustom |
| **adb shell am** | Mensimulasikan backgrounding paksa/restart cold untuk menguji skenario `DEVELOPER_TRIGGERED_UPDATE_IN_PROGRESS` |

### 2.3 Prasyarat Lingkungan

- Device/emulator dengan Google Play Services (untuk pengujian Play In-App Updates API) ATAU kemampuan intercept traffic (untuk backend-gated flow).
- Kemampuan menginstal versi aplikasi yang **lebih lama** dari versi minimum yang diharapkan, untuk memicu kondisi "update diperlukan" secara realistis.

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0005** untuk instalasi aplikasi.
2. Gunakan **MASTG-TECH-0010** untuk menangkap traffic aplikasi.
3. Gunakan **MASTG-TECH-0043** untuk hook API yang relevan.
4. Exercise aplikasi secara ekstensif untuk memicu sebanyak mungkin alur.

### 3.2 Metode A — Hook Play In-App Updates API

```javascript
Java.perform(function () {
    var AppUpdateManager = Java.use("com.google.android.play.core.appupdate.AppUpdateManagerFactory");
    // Hook getAppUpdateInfo dan startUpdateFlowForResult untuk mengamati kapan/apakah dipanggil
    var Mgr = Java.use("com.google.android.play.core.appupdate.AppUpdateManager");
    Mgr.getAppUpdateInfo.implementation = function () {
        console.log("[getAppUpdateInfo] dipanggil");
        return this.getAppUpdateInfo();
    };
});
```

### 3.3 Metode B — Replikasi Tiga Skenario Kegagalan Enforcement (Wajib, Sesuai §1.4)

```
Prosedur manual:
1. Picu update flow immediate → tutup dialog langsung tanpa melanjutkan → amati apakah akses tetap terblokir
2. Picu update flow immediate → mulai proses → batalkan di tengah jalan → amati status akses
3. Picu update flow immediate → background aplikasi (tombol Home) sebelum selesai → kembalikan ke foreground via adb → amati apakah app mendeteksi DEVELOPER_TRIGGERED_UPDATE_IN_PROGRESS dan menghalangi akses
```

```bash
adb shell am start -n com.example.app/.MainActivity  # kembali ke foreground setelah backgrounding manual
```

### 3.4 Metode C — Manipulasi Versi untuk Backend-Gated Flow

```bash
mitmproxy --mode regular
```

```python
# mitmproxy addon script untuk menurunkan versionCode yang dikirim
def request(flow):
    if "versionCode" in flow.request.text:
        flow.request.text = flow.request.text.replace('"versionCode":100', '"versionCode":1')
```

Amati: apakah backend merespons dengan kebijakan "update required", dan apakah aplikasi benar-benar memblokir akses sesuai respons tersebut? Sebaliknya, coba juga **menaikkan** versionCode secara artifisial untuk menguji apakah aplikasi bisa "menipu diri sendiri" melewati enforcement.

### 3.5 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Kapan dipakai |
|---|---|---|
| **A** | Frida | Observasi dasar pemanggilan API Play In-App Updates |
| **B** | Manual + ADB | **Wajib** — menguji tiga skenario kegagalan spesifik |
| **C** | mitmproxy | **Wajib** untuk backend-gated flow — menguji manipulasi versi langsung |

**Kombinasi minimum yang aku rekomendasikan:** **A/C (sesuai mekanisme yang dipakai aplikasi) → B (wajib untuk kedua mekanisme)**.

---

### 3.6 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG:**

> **Evaluation:** *"The test case fails if the app does not perform a runtime update check, or if the update is not enforced at runtime."*

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi |
|---|---|
| F1 | Tidak ada pengecekan update sama sekali saat runtime |
| F2 | Pengguna dapat melewati enforcement dengan menutup dialog/membatalkan proses/backgrounding aplikasi |
| F3 | Menurunkan versionCode yang dikirim ke backend tidak memicu respons "update required" yang ditegakkan |

**Contoh bukti:**

```
Skenario: Backgrounding selama immediate update flow
1. Update dialog muncul, proses download dimulai
2. Tekan tombol Home, tunggu 10 detik
3. Kembalikan app ke foreground via adb shell am start
4. HASIL: Dashboard langsung terbuka tanpa status DEVELOPER_TRIGGERED_UPDATE_IN_PROGRESS ditangani
```

**FAIL** — enforcement gagal setelah backgrounding.

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi |
|---|---|
| P1 | Pengecekan update dilakukan sebelum akses ke fungsionalitas terlindungi, **dan** |
| P2 | Ketiga skenario kegagalan (dismiss, cancel, background) tetap diblokir dengan benar, **dan** |
| P3 | *(untuk backend-gated)* Penurunan versionCode memicu enforcement nyata, **dan** backend juga menolak request dari versi lama (bukan hanya UI blocking client) |

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Jangan puas dengan satu skenario sukses** — sesuai §1.4, uji ketiga skenario kegagalan secara terpisah; aplikasi yang menangani dismiss dengan benar bisa tetap gagal pada skenario backgrounding.

2. **Bedakan Play Console recovery prompt dari enforcement sesungguhnya** — sesuai §1.5, jangan keliru menganggap prompt yang bisa di-dismiss dan muncul lagi setelah cold restart sebagai mekanisme blocking yang efektif.

3. **Untuk backend-gated flow, verifikasi enforcement di KEDUA sisi** — client-side blocking saja tidak cukup; periksa juga apakah backend menolak request API dari versi lama secara independen (§1.6), karena client-side check dapat dilewati penyerang yang memiliki kendali penuh atas device.

4. **Severity dimodulasi:**

   | Faktor | Severity |
   |---|---|
   | Tidak ada enforcement sama sekali, update terkait kerentanan keamanan kritis | **Tinggi** |
   | Enforcement ada namun bisa dilewati via salah satu dari tiga skenario kegagalan | **Sedang-Tinggi** |
   | Enforcement client-side solid namun backend tidak menolak versi lama secara independen | **Sedang** |
   | Ketiga kriteria PASS terpenuhi penuh | **Bukan temuan** |

5. **Dokumentasikan:** mekanisme yang dipakai (Play In-App Updates/backend-gated), hasil masing-masing skenario pengujian (dismiss/cancel/background), hasil manipulasi versionCode, dan apakah backend menegakkan kebijakan secara independen.

---

## 4. Rekomendasi Perbaikan

### 4.1 Tangani Status DEVELOPER_TRIGGERED_UPDATE_IN_PROGRESS

```kotlin
override fun onResume() {
    super.onResume()
    appUpdateManager.appUpdateInfo.addOnSuccessListener { info ->
        if (info.updateAvailability() == UpdateAvailability.DEVELOPER_TRIGGERED_UPDATE_IN_PROGRESS) {
            appUpdateManager.startUpdateFlowForResult(info, AppUpdateType.IMMEDIATE, this, REQUEST_CODE)
        }
    }
}
```

### 4.2 Enforcement Ganda: Client Blocking + Backend Rejection

```kotlin
if (versionCode < minRequiredVersion) {
    showBlockingUpdateDialog() // non-dismissible
    return
}
```

```
Backend: tolak seluruh request API dari X-App-Version < minVersion dengan HTTP 426 Upgrade Required
```

### 4.3 Checklist Remediasi

- [ ] Status `DEVELOPER_TRIGGERED_UPDATE_IN_PROGRESS` ditangani di `onResume`/entry point lain
- [ ] Dialog update mandatory bersifat non-dismissible, tidak bisa dibatalkan
- [ ] Backend menolak request dari versi yang tidak didukung secara independen dari client
- [ ] Tidak mengandalkan Play Console recovery prompt sebagai satu-satunya mekanisme enforcement
- [ ] Diuji ulang terhadap ketiga skenario kegagalan setelah setiap perubahan

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0382 (source, tests-beta)](https://github.com/OWASP/mastg/blob/master/tests-beta/android/MASVS-CODE/MASTG-TEST-0382.md)
- [MASTG-KNOW-0023: Enforced Updating](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0023/)

### 5.2 Dokumentasi Resmi

- [Android Developers: In-App Updates](https://developer.android.com/guide/playcore/in-app-updates)
- [Google Play: Prompt Users to Update to Your Latest App Version](https://support.google.com/googleplay/android-developer/answer/13812041)
- [Firebase Remote Config](https://firebase.google.com/docs/remote-config)

### 5.3 Dokumentasi Tools

- [mitmproxy Documentation](https://docs.mitmproxy.org/stable/)
- [Frida — Dynamic Instrumentation Toolkit](https://frida.re/docs/home/)

---

*Dokumen ini disusun berdasarkan konten resmi OWASP MASTG (`tests-beta/android/MASVS-CODE/MASTG-TEST-0382.md`, `MASTG-KNOW-0023`). Test ini tidak memiliki pasangan rule Semgrep maupun pasangan test statis dalam katalog MASTG saat ini — sepenuhnya dinamis dan behavioral, karena menilai "apakah enforcement benar-benar menghalangi akses" menuntut observasi perilaku runtime sesungguhnya, bukan sekadar keberadaan referensi API di kode. Nuansa metodologis terpenting: evaluasi harus mencakup tiga skenario kegagalan spesifik yang disebut eksplisit overview resmi (dismiss dialog, cancel di tengah proses, backgrounding aplikasi) secara terpisah — kelulusan pada satu skenario tidak menjamin kelulusan pada skenario lain. Untuk backend-gated flow, enforcement yang benar-benar kuat menuntut penolakan di sisi server secara independen, bukan hanya UI blocking di client yang secara inheren dapat dimanipulasi oleh penyerang dengan kendali penuh atas device mereka sendiri.*
