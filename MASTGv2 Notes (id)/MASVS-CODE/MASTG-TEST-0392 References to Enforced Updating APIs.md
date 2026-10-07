# MASTG-TEST-0392 References to Enforced Updating APIs

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0392 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-CODE |
| **Weakness** | MASWE-0043 |
| **Tipe Pengujian** | Static, Code, **Manual** |
| **Teknik terkait** | MASTG-TECH-0013, MASTG-TECH-0014, MASTG-TECH-0023 |
| **Knowledge terkait** | MASTG-KNOW-0023 (Enforced Updating) |
| **Test terkait** | **MASTG-TEST-0382** — counterpart **dinamis** yang mengonfirmasi enforcement benar-benar efektif saat runtime (sudah dibahas mendalam dalam seri riset ini) |
| **Rule resmi** | — (tidak ada; murni manual) |

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian dan Hubungannya dengan MASTG-TEST-0382

Kutipan overview resmi MASTG:

> *"Android apps may fail to enforce updates when critical security patches or minimum version requirements are needed... This test checks whether the app contains code that implements update enforcement, either through Play In-App Updates or through a custom version-based gating mechanism."*

Test ini adalah **pasangan statis** dari MASTG-TEST-0382 (sudah dibahas mendalam sebelumnya dalam seri riset ini) — mengikuti pola yang sudah berulang kali ditemukan dalam seri ini (root detection TEST-0324/0325, debugging detection TEST-0352/0353, dsb.): statis menemukan **referensi kode** terhadap mekanisme enforcement, dinamis mengonfirmasi mekanisme tersebut **benar-benar efektif** saat dieksploitasi secara aktif. Seluruh konteks mendalam tentang *mengapa* enforced updating penting (respons kerentanan, rotasi kunci kriptografis, migrasi API), dua mekanisme yang tersedia (Play In-App Updates vs backend-gated), dan keterbatasan Play Console recovery prompt — sudah dibahas lengkap di dokumen MASTG-TEST-0382 dan sepenuhnya berlaku sebagai konteks latar belakang untuk test ini.

### 1.2 Daftar API Konkret yang Menjadi Target Pencarian

Overview memberi daftar API yang sangat spesifik untuk kedua mekanisme, lebih detail dibanding overview TEST-0382:

**Play In-App Updates API:**
> `AppUpdateManagerFactory.create`, `AppUpdateManager#getAppUpdateInfo`, `UpdateAvailability.UPDATE_AVAILABLE`, `UpdateAvailability.DEVELOPER_TRIGGERED_UPDATE_IN_PROGRESS`, `AppUpdateType.IMMEDIATE`, `AppUpdateOptions`, `startUpdateFlowForResult`

**Backend-Gated Flow:**
> `BuildConfig.VERSION_NAME`/`BuildConfig.VERSION_CODE`, `PackageInfo` via `PackageManager`

Daftar ini memberi "kamus" lengkap untuk pencarian pola manual (§3), mengingat tidak ada rule Semgrep otomatis yang tersedia.

### 1.3 Nuansa Evaluasi Kunci: "Dismissible Dialog" Secara Eksplisit Dianggap Implementasi yang Salah

Ini adalah detail yang sangat penting dan diberikan secara eksplisit di overview, berbeda dari kebanyakan test lain yang baru membahas nuansa kualitas di bagian "Further Validation Required":

> *"If these mechanisms are absent, implemented incorrectly (for example, using only a dismissible dialog for a mandatory update), or not triggered before access to protected functionality or backend services, an outdated app may continue to be used."*

Ini berarti **ditemukan kode yang terlihat seperti enforcement** (ada dialog yang muncul meminta update) **belum cukup** untuk PASS — penguji harus secara spesifik memeriksa apakah dialog tersebut **bisa ditutup/diabaikan** oleh pengguna. Dialog yang dismissible untuk update yang seharusnya **mandatory** secara eksplisit dianggap sebagai "implementasi yang salah", bukan "implementasi yang lemah namun cukup" — ini klasifikasi tegas yang perlu dipegang penguji.

### 1.4 Validasi Lanjutan: Empat Pertanyaan yang Menuntut Analisis Call Graph

Bagian "Further Validation Required" menuntut analisis yang lebih dalam dari sekadar menemukan referensi API:

> *"Determine whether the update check executes before access to protected functionality or backend services and cannot be bypassed (for example, by checking the call graph or entry point context)."*

Frasa *"checking the call graph or entry point context"* menegaskan bahwa test ini **bukan sekadar grep sederhana** — penguji perlu memahami **struktur aplikasi** untuk menilai apakah pengecekan update benar-benar berada di jalur yang **tidak dapat dihindari** sebelum mengakses fungsi terlindungi (misalnya di `onCreate()` activity utama yang selalu dilewati, bukan di activity opsional yang bisa di-skip lewat deep link langsung).

Tiga pertanyaan validasi lanjutan lainnya **secara langsung paralel** dengan tiga skenario kegagalan spesifik yang sudah dibahas mendalam di dokumen MASTG-TEST-0382 — menegaskan kembali desain konsisten antara kedua test ini:

> *"For Google Play In-App Updates, determine whether the app handles cancellation or denial... checks update state when returning to the foreground, and restarts the immediate update flow when `UpdateAvailability.DEVELOPER_TRIGGERED_UPDATE_IN_PROGRESS` is reported."*
>
> *"For backend-gated flows, determine whether the app compares the installed version against a backend-supplied minimum version and blocks access when the current version does not meet the policy."*

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | Fungsi |
|---|---|
| **jadx** | Dekompilasi DEX → Java untuk pencarian referensi API (MASTG-TECH-0013, MASTG-TECH-0014) |
| **grep/ripgrep** | Pencarian pola API dari daftar lengkap di §1.2 — satu-satunya pendekatan karena tidak ada rule Semgrep resmi |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **MobSF** | Laporan otomatis yang kadang menyertakan deteksi dasar penggunaan Play Core library |
| **Androguard** | Analisis call graph untuk menilai posisi pengecekan update relatif terhadap entry point aplikasi (§1.4) |

### 2.3 Prasyarat Lingkungan

- Tidak butuh device/root — murni analisis statis.
- Pahami struktur navigasi aplikasi (activity mana yang menjadi entry point utama) untuk menilai call graph (§1.4).

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0013** untuk reverse engineer aplikasi.
2. Gunakan **MASTG-TECH-0014** untuk mencari API yang relevan.

### 3.2 Metode A — grep/ripgrep untuk Play In-App Updates API

```bash
D=./decompiled/sources

rg -n 'AppUpdateManagerFactory\.create|getAppUpdateInfo\(|startUpdateFlowForResult\(' $D
rg -n 'UpdateAvailability\.(UPDATE_AVAILABLE|DEVELOPER_TRIGGERED_UPDATE_IN_PROGRESS)' $D
rg -n 'AppUpdateType\.IMMEDIATE' $D
```

### 3.3 Metode B — grep/ripgrep untuk Backend-Gated Flow

```bash
rg -n 'BuildConfig\.VERSION_(NAME|CODE)' $D
rg -n 'getPackageInfo\(.*\)\.versionName|getLongVersionCode\(' $D
rg -n 'minVersion|min_version|minimumVersion' $D -i
```

### 3.4 Metode C — Analisis Call Graph untuk Posisi Entry Point (Wajib, Sesuai §1.4)

```bash
# Lacak lokasi pemanggilan relatif terhadap onCreate() activity utama
rg -n -B20 'getAppUpdateInfo\(|minVersion' $D | grep -E 'class \w+Activity|onCreate\('
```

Verifikasi manual: apakah pengecekan update terletak di activity yang **selalu** dilewati pengguna (splash screen, main activity `onCreate`), atau di activity opsional yang bisa dihindari?

### 3.5 Metode D — Review Manual untuk Kriteria Dismissible Dialog (Wajib, Sesuai §1.3)

Untuk setiap dialog/UI update yang ditemukan:

1. Periksa apakah dialog memiliki tombol "Nanti"/"Batal"/"Lewati", atau bisa ditutup dengan tombol back/tap di luar dialog.
2. Periksa apakah aplikasi tetap mengizinkan navigasi lanjutan setelah dialog ditutup.

### 3.6 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Kapan dipakai |
|---|---|---|
| **A/B** | grep/ripgrep | Baseline wajib — satu-satunya pendekatan karena tidak ada rule otomatis |
| **C** | Analisis call graph | **Wajib** — menilai posisi entry point |
| **D** | Review manual UI | **Wajib** — menilai kriteria dismissible dialog |

**Kombinasi minimum yang aku rekomendasikan:** **A/B (wajib) → C + D (wajib)**, dilanjutkan ke **MASTG-TEST-0382** untuk konfirmasi efektivitas runtime.

---

### 3.7 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG:**

> **Evaluation:** *"The test case fails if no code locations show an update enforcement mechanism."*

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi |
|---|---|
| F1 | Tidak ditemukan satu pun referensi API Play In-App Updates maupun backend-gated version check di seluruh codebase |

**Catatan kritis (§1.3):** bila ditemukan referensi API namun implementasinya berupa **dialog dismissible** untuk update yang seharusnya mandatory, ini **tetap dianggap FAIL secara kualitatif** meski secara teknis "ada kode update check" — evaluasi resmi secara eksplisit mengklasifikasikan ini sebagai "implemented incorrectly", setara dengan tidak ada mekanisme sama sekali dari segi hasil akhir.

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi |
|---|---|
| P1 | Ditemukan referensi API enforcement (Play In-App Updates atau backend-gated), **dan** |
| P2 | Lokasi pengecekan berada di entry point yang tidak dapat dihindari (§1.4), **dan** |
| P3 | Implementasi memakai immediate update flow atau blocking screen non-dismissible, bukan dialog yang bisa ditutup (§1.3) |

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Jangan berhenti di "ditemukan referensi API"** — sesuai §1.3, kualitas implementasi (dismissible vs non-dismissible) sama pentingnya dengan keberadaan kode; test ini secara eksplisit mengklasifikasikan dialog dismissible sebagai kesalahan, bukan sekadar kelemahan.

2. **Verifikasi posisi di call graph, bukan hanya keberadaan baris kode** — sesuai §1.4, pengecekan yang ada namun ditempatkan di jalur yang bisa dihindari (activity opsional, bukan entry point utama) secara efektif tidak memberi perlindungan nyata.

3. **Lanjutkan selalu ke MASTG-TEST-0382 untuk konfirmasi** — temuan statis di sini hanya mengidentifikasi **kandidat mekanisme**; apakah mekanisme tersebut benar-benar menghalangi akses saat diuji secara aktif (termasuk skenario backgrounding/cancel) hanya bisa dipastikan lewat pengujian dinamis.

4. **Severity dimodulasi:**

   | Faktor | Severity |
   |---|---|
   | Tidak ada mekanisme enforcement sama sekali | **Tinggi** (bila aplikasi memiliki riwayat kerentanan client-side yang memerlukan patch wajib) |
   | Mekanisme ada namun berupa dialog dismissible | **Tinggi** (diklasifikasikan setara tidak ada, sesuai §1.3) |
   | Mekanisme ada, non-dismissible, namun posisi call graph bisa dihindari | **Sedang** |
   | Seluruh kriteria PASS terpenuhi | **Bukan temuan** (pending konfirmasi dinamis MASTG-TEST-0382) |

5. **Dokumentasikan:** lokasi kode API enforcement, jenis mekanisme (Play In-App Updates/backend-gated), hasil analisis call graph, dan klasifikasi dismissible/non-dismissible dari UI yang ditemukan.

---

## 4. Rekomendasi Perbaikan

Rekomendasi identik dengan pasangan dinamisnya (MASTG-TEST-0382) — lihat dokumen tersebut untuk detail lengkap implementasi (penanganan `DEVELOPER_TRIGGERED_UPDATE_IN_PROGRESS`, enforcement ganda client+backend). Poin tambahan spesifik untuk hasil analisis statis:

### Checklist Remediasi

- [ ] Referensi API enforcement ditemukan dan posisinya terverifikasi di entry point yang tidak dapat dihindari
- [ ] UI update untuk kasus mandatory dipastikan non-dismissible (tidak ada tombol "Nanti"/"Lewati", tidak bisa ditutup via tombol back)
- [ ] Hasil analisis statis dikonfirmasi dengan pengujian dinamis MASTG-TEST-0382 sebelum dianggap final

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0392 (source, tests-beta)](https://github.com/OWASP/mastg/blob/master/tests-beta/android/MASVS-CODE/MASTG-TEST-0392.md)
- [MASTG-TEST-0382: Runtime Use of Enforced Updating APIs (dokumen pasangan dinamis dalam seri riset ini)](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0382/)
- [MASTG-KNOW-0023: Enforced Updating](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0023/)

### 5.2 Dokumentasi Resmi

- [Android Developers: In-App Updates](https://developer.android.com/guide/playcore/in-app-updates)

### 5.3 Dokumentasi Tools

- [Androguard](https://github.com/androguard/androguard)
- [MobSF — Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)

---

*Dokumen ini disusun berdasarkan konten resmi OWASP MASTG (`tests-beta/android/MASVS-CODE/MASTG-TEST-0392.md`, `MASTG-KNOW-0023`), dilengkapi cross-reference mendalam dengan dokumen MASTG-TEST-0382 (pasangan dinamisnya) dalam seri riset ini yang sudah membahas konteks lengkap mengapa enforced updating penting dan tiga skenario kegagalan enforcement spesifik. Nuansa metodologis terpenting dan paling tegas dari test ini: evaluasi resmi secara eksplisit mengklasifikasikan implementasi berupa **dialog dismissible** untuk update mandatory sebagai "implemented incorrectly" — setara dengan tidak ada mekanisme enforcement sama sekali dari segi hasil akhir, bukan sekadar kelemahan minor. Ini menuntut penguji menilai kualitas UI/UX enforcement secara eksplisit, tidak cukup hanya mengonfirmasi keberadaan referensi API di kode.*
