# MASTG-TEST-0257 Not Resetting Unused Permissions

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0257 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-PRIVACY |
| **Weakness** | MASWE-0066 — *Inadequate Permission Management* (sama seperti MASTG-TEST-0254/0255/0256) |
| **Status resmi MASTG** | **`placeholder`** — belum ada Overview/Steps/Evaluation lengkap |
| **Catatan resmi (satu-satunya konten yang tersedia)** | *"This test checks if the app does not remove unnecessary access to granted permissions."* — merujuk https://developer.android.com/training/permissions/requesting#remove-access |
| **Profile** | **P (Privacy) saja** |
| **Knowledge** | MASTG-KNOW-0017 *(rujukan bermasalah, konsisten dengan catatan di dokumen MASTG-TEST-0254/0255/0256)* |
| **Test terkait** | Melengkapi trio **MASTG-TEST-0254/0255/0256** dengan dimensi keempat: **apakah aplikasi melepaskan permission secara proaktif setelah tidak lagi dibutuhkan?** |
| **Demo terkait** | — (tidak ada) |
| **Rule resmi** | — (tidak ada) |
| **CWE terkait** | CWE-459 (Incomplete Cleanup), CWE-250 (Execution with Unnecessary Privileges) |

---

## 1. Penjelasan

### 1.1 Status Test Ini dan Posisinya dalam Rangkaian Empat Test Permission Privasi

Test ini berstatus **`placeholder`**, melengkapi rangkaian evaluasi permission yang sudah dibahas di tiga dokumen sebelumnya:

| Test | Pertanyaan Inti |
|---|---|
| MASTG-TEST-0254 | Apakah permission ini **proporsional**? |
| MASTG-TEST-0255 | Apakah ini cara **paling minimal**? |
| MASTG-TEST-0256 | Apakah pengguna diberi **penjelasan** mengapa? |
| **MASTG-TEST-0257** *(dokumen ini)* | Setelah permission **tidak lagi dibutuhkan**, apakah aplikasi **melepaskannya secara proaktif**? |

Test ini menyoroti dimensi **siklus hidup** dari permission yang sering diabaikan: permission yang tadinya proporsional dan dibutuhkan (lolos ketiga test sebelumnya) bisa **menjadi tidak lagi relevan** seiring waktu — pengguna menonaktifkan fitur terkait di pengaturan aplikasi, fitur tersebut dihapus di versi update, atau pola pemakaian pengguna berubah. Pertanyaannya: **apakah aplikasi menyadari dan bereaksi terhadap perubahan ini**, atau terus memegang permission tersebut selamanya hanya karena tidak ada mekanisme yang secara aktif melepaskannya?

### 1.2 Perbedaan Krusial: Auto-Reset Sistem (Pasif) vs Self-Revocation Aplikasi (Proaktif)

Ini pembeda konseptual paling penting yang harus dipahami sebelum mengevaluasi test ini — ada **dua mekanisme yang sama sekali berbeda** yang mudah tertukar:

| | **Auto-Reset Permission Sistem** (Android 11+) | **Self-Revocation Aplikasi** (Android 13+, fokus test ini) |
|---|---|---|
| **Siapa yang menginisiasi** | **Sistem operasi**, otomatis | **Aplikasi itu sendiri**, lewat kode eksplisit |
| **Kapan terjadi** | Setelah aplikasi **tidak dipakai selama beberapa bulan** (heuristik sistem berbasis waktu tidak aktif) | **Kapan pun** aplikasi mendeteksi permission tidak lagi relevan — bisa segera setelah pengguna menonaktifkan fitur terkait |
| **Granularitas** | Seluruh permission aplikasi sekaligus (terkait App Hibernation) | Per-permission atau per-grup, dipilih spesifik oleh developer |
| **Dapat diandalkan sebagai satu-satunya lapisan?** | **Tidak** — ini jaring pengaman pasif berskala bulan, bukan respons cepat terhadap perubahan kebutuhan nyata |

Fitur auto-reset sistem (diperkenalkan Android 11, diperluas ke versi lebih lama lewat Google Play services update pada 2021) adalah **jaring pengaman pasif tingkat platform** — ia akan mereset permission aplikasi yang **tidak dibuka sama sekali** selama beberapa bulan, terlepas dari perilaku kode aplikasi. Ini **selalu berjalan** di background sistem dan **tidak dapat diuji atau dipengaruhi** lewat kode aplikasi — sehingga **bukan** ini yang menjadi objek evaluasi MASTG-TEST-0257.

**Fokus test ini** adalah mekanisme kedua: **API `revokeSelfPermissionOnKill()`/`revokeSelfPermissionsOnKill()`** yang secara eksplisit dirujuk halaman "remove-access" yang dikutip catatan resmi — kemampuan aplikasi untuk **secara proaktif dan segera** melepaskan permission yang diketahuinya sudah tidak lagi dibutuhkan, **tanpa menunggu** heuristik pasif sistem yang baru bereaksi setelah berbulan-bulan.

### 1.3 Mekanisme `revokeSelfPermissionOnKill()` (Android 13+)

Sesuai dokumentasi resmi Android Developers:

```kotlin
// Melepaskan satu permission
context.revokeSelfPermissionOnKill(Manifest.permission.RECORD_AUDIO)

// Melepaskan sekelompok permission sekaligus
context.revokeSelfPermissionsOnKill(listOf(
    Manifest.permission.RECORD_AUDIO,
    Manifest.permission.CAMERA
))
```

Karakteristik penting mekanisme ini:

1. **Proses asinkron** — pelepasan permission tidak terjadi seketika saat API dipanggil.
2. **Sistem menunggu waktu yang aman** — proses aplikasi baru benar-benar dihentikan (dan permission benar-benar dilepas) setelah sistem menentukan aplikasi sudah cukup lama berjalan di **background**, bukan di **foreground** — desain ini mencegah gangguan tiba-tiba terhadap sesi aktif pengguna.
3. **Granularitas grup permission** — untuk sistem menampilkan status "aplikasi ini tidak lagi mengakses [kategori data]" di pengaturan, aplikasi harus melepaskan **seluruh** permission dalam grup terkait, bukan sebagian.
4. **Kewajiban komunikasi ke pengguna** — dokumentasi resmi secara eksplisit merekomendasikan menampilkan dialog saat aplikasi berikutnya dibuka, memberi tahu pengguna bahwa aplikasi **tidak lagi membutuhkan** permission tertentu — pola komunikasi transparansi yang melengkapi (bukan menggantikan) rationale yang dibahas di MASTG-TEST-0256.

### 1.4 Mengapa Ini Penting: Membangun Trust dan Mengurangi Permukaan Risiko Jangka Panjang

Nilai dari mekanisme ini bersifat ganda:

- **Keamanan**: permission yang dipegang lebih lama dari yang dibutuhkan adalah **permukaan risiko yang tidak perlu** — bila aplikasi (atau salah satu dependency-nya) dikompromikan di kemudian hari, penyerang mewarisi akses ke seluruh permission yang **masih dipegang**, termasuk yang sudah lama tidak dipakai fungsinya.
- **Trust pengguna**: dokumentasi resmi menegaskan nilai psikologis dari transparansi proaktif ini:

> *"You might want to consider displaying a dialogue to users that lists the permissions you have proactively removed... users can feel safe if you tell them that you have revoked certain permissions at your will due to non-use."*

Ini pembalikan pola kebiasaan umum developer yang cenderung **hanya meminta** izin dan jarang **secara sukarela melepaskannya** — padahal tindakan melepaskan izin yang tidak lagi dipakai adalah sinyal kepercayaan yang kuat bagi pengguna, menunjukkan aplikasi benar-benar menerapkan prinsip *least privilege* secara berkelanjutan, bukan hanya di titik instalasi awal.

### 1.5 Skenario Kasus Penggunaan yang Relevan

Beberapa pola konkret di mana mekanisme ini seharusnya diterapkan namun sering diabaikan:

- **Fitur opsional dinonaktifkan pengguna**: aplikasi memiliki toggle "izinkan berbagi lokasi dengan teman" yang dimatikan pengguna — permission `ACCESS_FINE_LOCATION` seharusnya dilepas saat itu juga, bukan dipegang terus menunggu toggle diaktifkan kembali (yang mungkin tidak pernah terjadi).
- **Fitur dihapus di update aplikasi**: versi baru aplikasi menghapus fitur perekam suara memo, tapi permission `RECORD_AUDIO` yang sebelumnya diminta tetap dipegang tanpa pernah dilepas secara eksplisit di kode migrasi versi.
- **Onboarding yang tidak diselesaikan**: pengguna memberi izin kamera saat onboarding untuk fitur verifikasi wajah, tapi kemudian memilih metode verifikasi lain (OTP) — permission kamera yang sudah tidak relevan untuk alur yang dipilih tetap dipegang tanpa dilepas.

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | Fungsi |
|---|---|
| **jadx** | Dekompilasi untuk mencari pola pemanggilan `revokeSelfPermissionOnKill`/`revokeSelfPermissionsOnKill` |
| **grep / ripgrep** | Pencarian pola API dan korelasi dengan toggle/pengaturan fitur di kode |
| **aapt/adb** | Ekstraksi `targetSdkVersion` — relevan karena API ini hanya tersedia sejak API 33 |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **CodeQL** | Menelusuri apakah toggle/pengaturan yang menonaktifkan fitur (mis. `SharedPreferences.putBoolean("location_sharing", false)`) berkorelasi dengan pemanggilan API revoke di lokasi kode yang sama/berdekatan |
| **adb shell dumpsys** | Memeriksa status runtime permission aplikasi dari waktu ke waktu untuk mengonfirmasi perubahan status setelah interaksi tertentu |
| **UI Automator/Espresso** | Menguji skenario dinamis: nonaktifkan fitur lewat UI, amati apakah permission benar-benar dilepas setelah aplikasi masuk background |

### 2.3 Prasyarat Lingkungan

- **Tidak butuh device untuk analisis statis dasar.**
- **Butuh device/emulator Android 13+ untuk verifikasi dinamis** — API ini tidak tersedia di versi lebih lama.
- **`targetSdkVersion` aplikasi harus ≥33** agar API ini bahkan bisa dipanggil — bila `targetSdkVersion` di bawah itu, ketidaktersediaan mekanisme ini bukan sepenuhnya kesalahan implementasi, melainkan keterbatasan versi target (meski tetap layak dicatat sebagai rekomendasi peningkatan `targetSdkVersion`, konsisten dengan pembahasan MASTG-TEST-0245).

---

## 3. Cara Pengujian

Karena tidak ada langkah resmi (status placeholder), metodologi berikut disusun berdasarkan elaborasi halaman Android Developers yang dirujuk langsung oleh catatan resmi.

### 3.1 Langkah Umum

1. Ambil daftar dangerous permission dari hasil **MASTG-TEST-0254**.
2. Identifikasi fitur aplikasi yang **bisa dinonaktifkan** pengguna (toggle pengaturan) atau **berpotensi dihapus** di update mendatang, yang terkait dengan permission tersebut.
3. Telusuri apakah ada pemanggilan `revokeSelfPermissionOnKill`/`revokeSelfPermissionsOnKill` yang berkorelasi dengan penonaktifan fitur tersebut.
4. Verifikasi dinamis: nonaktifkan fitur terkait, amati status permission setelah aplikasi masuk background dalam durasi yang cukup.

### 3.2 Metode A — grep/ripgrep untuk Pemanggilan API

```bash
D=./decompiled/sources

# Cari pemanggilan API self-revocation
rg -n 'revokeSelfPermissionOnKill|revokeSelfPermissionsOnKill' $D

# Cari toggle/pengaturan terkait fitur berpermission dangerous
rg -n -B5 -A15 'putBoolean\("location_sharing"|putBoolean\(".*_enabled"|putBoolean\(".*_feature' $D | \
  grep -i "location\|camera\|contacts\|microphone\|record_audio"

# Periksa targetSdkVersion sebagai prasyarat ketersediaan API
grep -oP 'targetSdkVersion="\K[0-9]+' AndroidManifest.xml
```

### 3.3 Metode B — CodeQL (Korelasi Toggle Fitur dengan Pelepasan Permission)

```ql
import java

class FeatureToggleOff extends MethodAccess {
  FeatureToggleOff() {
    this.getMethod().hasName("putBoolean") and
    this.getArgument(1).(BooleanLiteral).getBooleanValue() = false
  }
}

class SelfRevokeCall extends MethodAccess {
  SelfRevokeCall() {
    this.getMethod().hasName(["revokeSelfPermissionOnKill", "revokeSelfPermissionsOnKill"])
  }
}

from FeatureToggleOff toggle
where not exists(SelfRevokeCall revoke | revoke.getEnclosingCallable() = toggle.getEnclosingCallable())
select toggle, "Fitur dinonaktifkan tanpa pelepasan permission terkait secara eksplisit"
```

### 3.4 Metode C — Verifikasi Dinamis dengan Simulasi Waktu Background

```bash
# 1. Install, berikan permission, gunakan fitur terkait
adb install target-app.apk
adb shell dumpsys package com.target.app | grep -A5 "RECORD_AUDIO"
# Amati: granted=true

# 2. Nonaktifkan fitur terkait lewat UI aplikasi (mis. toggle "rekam memo suara")

# 3. Paksa aplikasi ke background dan simulasikan idle
adb shell am force-stop com.target.app  # atau tunggu idle alami

# 4. Setelah durasi yang wajar (implementasi sesungguhnya menunggu "safe kill window" sistem),
#    periksa kembali status permission
adb shell dumpsys package com.target.app | grep -A5 "RECORD_AUDIO"
```

Bila status permission **tetap** `granted=true` meski fitur terkait sudah dinonaktifkan pengguna dan aplikasi sudah cukup lama di background, ini indikasi kuat mekanisme self-revocation **tidak diimplementasikan**.

### 3.5 Metode D — Audit Changelog/Rilis untuk Fitur yang Dihapus

Untuk whitebox testing, tinjau riwayat rilis/changelog aplikasi untuk mengidentifikasi fitur yang **pernah ada** namun dihapus di versi lebih baru, lalu verifikasi apakah permission terkait fitur tersebut turut dihapus dari manifest atau dilepas via kode migrasi:

```bash
git log --oneline --all -- AndroidManifest.xml | head -20
git diff <versi_lama> <versi_baru> -- AndroidManifest.xml
```

### 3.6 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Kelebihan | Kapan dipakai |
|---|---|---|---|
| **A** | grep | Cepat, langsung menunjukkan ada/tidaknya API dipanggil | Baseline awal |
| **B** | CodeQL | Korelasi presisi antara toggle fitur dan pelepasan permission | Codebase besar |
| **C** | Verifikasi dinamis | Bukti perilaku nyata | Konfirmasi akhir |
| **D** | Audit changelog | Menangkap kasus fitur dihapus di update (whitebox) | Audit historis/regresi |

**Kombinasi minimum yang aku rekomendasikan:** **A (baseline keberadaan API) → B (korelasi dengan toggle fitur) → C (konfirmasi dinamis)** untuk kesimpulan yang solid.

---

### 3.7 Kriteria Evaluasi: Positive Case & Negative Case

Karena tidak ada klausul Evaluation resmi (status placeholder), kriteria berikut diturunkan dari panduan resmi yang dirujuk.

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi |
|---|---|
| F1 | Aplikasi memiliki fitur yang dapat dinonaktifkan pengguna (toggle pengaturan) terkait dangerous permission, **namun tidak ada** pemanggilan `revokeSelfPermissionOnKill`/`revokeSelfPermissionsOnKill` yang berkorelasi dengan penonaktifan tersebut |
| F2 | Verifikasi dinamis (Metode C) mengonfirmasi permission **tetap granted** meski fitur terkait sudah lama dinonaktifkan dan aplikasi sudah lama di background |
| F3 | Fitur yang membutuhkan dangerous permission dihapus sepenuhnya di versi update, tapi permission terkait **tidak turut dihapus** dari manifest maupun dilepas via kode migrasi |
| F4 | `targetSdkVersion` sudah ≥33 (API tersedia) namun aplikasi sama sekali tidak memanfaatkan mekanisme ini untuk permission mana pun yang jelas bersifat kondisional/opsional |

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi |
|---|---|
| P1 | Setiap penonaktifan fitur opsional berkorelasi dengan pemanggilan `revokeSelfPermissionOnKill` untuk permission terkait |
| P2 | Verifikasi dinamis mengonfirmasi permission benar-benar dilepas (`granted=false`) setelah fitur dinonaktifkan dan periode background yang wajar terlewati |
| P3 | Aplikasi menampilkan dialog transparansi kepada pengguna saat permission dilepas (sesuai rekomendasi §1.3 poin 4) |
| P4 | `targetSdkVersion` di bawah 33 (API belum tersedia) — dalam kasus ini, catat sebagai rekomendasi peningkatan versi, bukan kegagalan implementasi murni |
| P5 | Aplikasi tidak memiliki permission yang bersifat kondisional/opsional sama sekali — seluruh dangerous permission dipakai secara konsisten selama aplikasi berjalan |

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Jangan tertukar dengan auto-reset sistem** (§1.2) — ini kesalahan paling mendasar yang bisa terjadi pada evaluasi test ini. Keberadaan fitur auto-reset Android 11+ **bukan** bukti bahwa aplikasi "lulus" test ini; auto-reset adalah jaring pengaman pasif sistem yang berjalan independen dari kode aplikasi, dengan skala waktu bulanan yang jauh lebih lambat dibanding respons proaktif yang dievaluasi di sini.

2. **API ini hanya tersedia sejak API 33** — evaluasi harus mempertimbangkan `targetSdkVersion` aplikasi. Ketiadaan implementasi pada aplikasi dengan `targetSdkVersion` rendah adalah keterbatasan platform, bukan murni kelalaian desain (meski tetap layak direkomendasikan untuk ditingkatkan).

3. **Fokus pada permission yang bersifat kondisional/opsional** — bukan setiap permission perlu mekanisme ini. Permission yang dipakai **terus-menerus** selama aplikasi berjalan (mis. `INTERNET` untuk aplikasi yang selalu online) tidak relevan untuk dievaluasi di sini; fokus pada permission yang terkait **fitur yang bisa dinonaktifkan/dihapus**.

4. **Verifikasi dinamis (Metode C) memerlukan kesabaran** — karena sistem menentukan sendiri "waktu aman" untuk mematikan proses (§1.3), pengujian mungkin perlu mensimulasikan periode background yang cukup panjang atau memakai tooling debugging tambahan untuk mempercepat siklus ini di lingkungan uji.

5. **Severity umumnya rendah-menengah** — ini soal higienitas siklus hidup permission jangka panjang, bukan kerentanan aktif langsung; namun berkontribusi pada permukaan risiko kumulatif dan kepercayaan pengguna jangka panjang.

6. **Dokumentasikan:** daftar fitur opsional yang terkait dangerous permission, status implementasi self-revocation untuk masing-masing, `targetSdkVersion` aplikasi, dan hasil verifikasi dinamis status permission dari waktu ke waktu.

---

## 4. Rekomendasi Perbaikan

### 4.1 Implementasikan Self-Revocation Saat Fitur Dinonaktifkan

```kotlin
fun onLocationSharingToggled(enabled: Boolean) {
    sharedPreferences.edit().putBoolean("location_sharing_enabled", enabled).apply()
    if (!enabled) {
        // Fitur dinonaktifkan -> lepas permission terkait secara proaktif
        context.revokeSelfPermissionOnKill(Manifest.permission.ACCESS_FINE_LOCATION)
    }
}
```

### 4.2 Bersihkan Permission Saat Migrasi Versi (Fitur Dihapus)

```kotlin
// Kode migrasi dijalankan saat update dari versi lama yang masih punya fitur rekam suara
fun migrateFromVersionWithVoiceMemoFeature() {
    if (permissionWasGrantedForRemovedFeature(Manifest.permission.RECORD_AUDIO)) {
        context.revokeSelfPermissionOnKill(Manifest.permission.RECORD_AUDIO)
    }
}
```

### 4.3 Beri Tahu Pengguna Secara Transparan

```kotlin
if (permissionsRevokedSinceLastLaunch.isNotEmpty()) {
    showDialog(
        title = "Izin Diperbarui",
        message = "Kami telah menghapus akses ke ${permissionsRevokedSinceLastLaunch.joinToString()} " +
                "karena fitur terkait tidak lagi Anda gunakan. Anda dapat mengaktifkannya kembali kapan saja di Pengaturan."
    )
}
```

### 4.4 Naikkan `targetSdkVersion` Bila Masih di Bawah 33

Rujuk pembahasan lengkap tentang pentingnya `targetSdkVersion` mutakhir di dokumen MASTG-TEST-0245 — ini prasyarat teknis mutlak agar API ini bisa dipakai sama sekali.

### 4.5 Checklist Remediasi

- [ ] Seluruh fitur opsional yang bergantung pada dangerous permission sudah diidentifikasi
- [ ] Setiap penonaktifan fitur terkait berkorelasi dengan pemanggilan `revokeSelfPermissionOnKill`
- [ ] Kode migrasi versi membersihkan permission untuk fitur yang dihapus
- [ ] Pengguna diberi tahu secara transparan saat permission dilepas
- [ ] `targetSdkVersion` sudah ≥33 untuk mengakses API ini
- [ ] Verifikasi dinamis status permission dari waktu ke waktu sudah dilakukan
- [ ] **Verifikasi ulang:** jalankan kembali MASTG-TEST-0257 setiap kali fitur baru yang bersifat opsional ditambahkan

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0257: Not Resetting Unused Permissions](https://mas.owasp.org/MASTG/tests/android/MASVS-PRIVACY/MASTG-TEST-0257/)
- [MASTG-TEST-0254: Dangerous App Permissions](https://mas.owasp.org/MASTG/tests/android/MASVS-PRIVACY/MASTG-TEST-0254/)
- [MASTG-TEST-0255: Permission Requests Not Minimized](https://mas.owasp.org/MASTG/tests/android/MASVS-PRIVACY/MASTG-TEST-0255/)
- [MASTG-TEST-0256: Missing Permission Rationale](https://mas.owasp.org/MASTG/tests/android/MASVS-PRIVACY/MASTG-TEST-0256/)
- [MASTG-TEST-0245: References to Platform Version APIs](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0245/)
- [MASWE-0066: Inadequate Permission Management](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0066/)

### 5.2 Dokumentasi Resmi Android

- [Android Developers — Request App Permissions: Remove access to a permission](https://developer.android.com/training/permissions/requesting#remove-access)
- [Android Developers — `Context.revokeSelfPermissionOnKill()` API reference](https://developer.android.com/reference/android/content/Context#revokeSelfPermissionOnKill(java.lang.String))
- [Android Developers — Permissions Updates in Android 11 (Auto-Reset)](https://developer.android.com/about/versions/11/privacy/permissions)
- [Android Developers — App Hibernation](https://developer.android.com/topic/performance/app-hibernation)
- [Android Developers Blog — Making Permissions Auto-Reset Available to Billions More Devices](https://android-developers.googleblog.com/2021/09/making-permissions-auto-reset-available.html)
- [AOSP Source — App Hibernation](https://source.android.com/docs/core/perf/hiber)

### 5.3 Riset dan Artikel Komunitas

- [GeeksforGeeks — Understanding Self-Downgrading App Permissions in Android 13](https://www.geeksforgeeks.org/android/understanding-self-downgrading-app-permissions-in-android-13/)
- [CWE-459: Incomplete Cleanup](https://cwe.mitre.org/data/definitions/459.html)
- [CWE-250: Execution with Unnecessary Privileges](https://cwe.mitre.org/data/definitions/250.html)

### 5.4 Dokumentasi Tools

- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [CodeQL — Documentation](https://codeql.github.com/docs/)
- [UI Automator — Testing framework](https://developer.android.com/training/testing/other-components/ui-automator)

---

*Dokumen ini disusun terutama dari elaborasi halaman dokumentasi resmi Android Developers "Remove access to a permission" yang dirujuk langsung oleh catatan resmi MASTG-TEST-0257 (status placeholder). Nuansa terpenting: test ini secara spesifik mengevaluasi mekanisme **self-revocation proaktif** aplikasi (`revokeSelfPermissionOnKill`, API 33+) — bukan fitur auto-reset pasif tingkat sistem (Android 11+) yang berjalan independen dari kode aplikasi dan tidak dapat dijadikan alasan aplikasi "lulus" tanpa implementasi eksplisit. Test ini melengkapi trio MASTG-TEST-0254/0255/0256 dengan dimensi siklus hidup: permission yang tadinya proporsional dapat menjadi usang seiring waktu, dan aplikasi yang baik seharusnya secara aktif menyadari serta merespons perubahan ini.*
