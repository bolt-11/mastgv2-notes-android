# MASTG-TEST-0364 Exported And Unprotected Activities That Expose Sensitive Functionality

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0364 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-PLATFORM |
| **Weakness** | MASWE-0018 |
| **Tipe Pengujian** | Static, Config, Code, **Manual** |
| **Teknik terkait** | MASTG-TECH-0013, MASTG-TECH-0117 (Obtain Manifest), MASTG-TECH-0160 (Enumerating Activities), MASTG-TECH-0014, MASTG-TECH-0023 |
| **Knowledge terkait** | MASTG-KNOW-0132 (Android Activities), MASTG-KNOW-0017 (App Permissions), MASTG-KNOW-0020 (IPC Mechanisms) |
| **Best Practice terkait** | MASTG-BEST-0052 (Restrict Access to Android App Components) |
| **Rule resmi** | — (tidak ada rule Semgrep khusus; test ini murni manual, konsisten dengan sifat kontekstualnya) |

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian

Kutipan overview resmi MASTG:

> *"If an exported activity does not define `android:permission` with a proper protection level and performs or grants access to sensitive functionality, another third-party app outside the intended trust boundary can start it with an Intent and reach that functionality without going through the app's intended flow."*

Frasa kunci di sini adalah **"without going through the app's intended flow"** — ini adalah inti dari seluruh kelas kerentanan ini. Activity, sebagai bagian dari model IPC Android (MASTG-KNOW-0020), bisa **dimulai langsung** oleh komponen aplikasi lain lewat `Intent`, **melompati** seluruh alur navigasi normal yang developer rancang (mis. splash screen → login → verifikasi PIN → dashboard). Bila `DashboardActivity` diekspor tanpa perlindungan, penyerang tidak perlu melewati langkah login sama sekali — cukup memanggil `startActivity()` dengan nama komponen target secara langsung.

### 1.2 Mekanisme Access Control dan Perubahan Penting di Android 12+

MASTG-KNOW-0132 menjelaskan tiga lapisan kontrol akses yang saling berinteraksi:

> *"`android:exported`: when true, components of other apps can start the activity... The default is false when an activity has no intent filters."*
>
> *"Historically, activities with intent filters and no explicit android:exported value could become reachable by other apps on older target SDK versions... apps targeting Android 12 (API level 31) or higher must set android:exported explicitly on activities with intent filters, or the app fails to install."*

Perubahan Android 12 ini penting untuk konteks historis — sebelum aturan ini diberlakukan, **banyak aplikasi secara tidak sengaja mengekspor activity** hanya karena memiliki `<intent-filter>` tanpa developer menyadari bahwa hal itu otomatis membuatnya exported pada target SDK lama. Developer yang menguji aplikasinya di Android versi lama/menengah mungkin tidak pernah menyadari status exported yang tidak diinginkan ini sampai aplikasi diaudit secara khusus.

Poin penting lain dari MASTG-KNOW-0132: *"Intent filters are not an access-control mechanism; use android:exported and permissions to control which external callers can start an activity."* — ini mengoreksi kesalahpahaman umum developer bahwa menambahkan validasi di dalam `<intent-filter>` (action/category/data) saja cukup sebagai kontrol keamanan; intent filter hanya mengatur **routing**, bukan **otorisasi**.

### 1.3 Tiga Kriteria "Sensitif" yang Menjadi Inti Evaluasi

Evaluasi resmi memberi tiga kategori konkret untuk menilai apakah suatu activity "mengekspos fungsionalitas sensitif":

> *"Determine whether the activity displays or returns sensitive data (for example, account details, messages, or stored secrets). Determine whether the activity performs a security-relevant action (for example, changing settings or credentials). Determine whether starting the activity directly bypasses an authentication step, such as a login or PIN screen, that the app relies on elsewhere."*

Kategori ketiga — **bypass otentikasi** — adalah yang paling sering muncul di kasus nyata (§1.5) dan paling mudah untuk diverifikasi secara dinamis: cukup panggil activity secara langsung dan amati apakah tampilan yang muncul adalah tampilan post-login, atau tetap meminta kredensial.

### 1.4 Nuansa Evaluasi Lanjutan: Pertanyaan "Apakah Memang Perlu Diekspor" Mendahului Pertanyaan "Apakah Permission-nya Memadai"

Struktur validasi lanjutan resmi memiliki urutan logis yang penting:

> *"Determine whether the activity has a legitimate reason to be started by third-party apps. If it doesn't, it shouldn't be exported."*

Baru setelah itu:

> *"If external access is required, determine whether the activity is protected by an appropriate android:permission or an equivalent access control... Verify that the permission is effective for that trust boundary, for example by using a signature protection level or another control that is not broadly grantable to untrusted apps."*

MASTG-BEST-0052 menegaskan poin krusial yang sejalan dengan prinsip yang sudah berulang kali dibahas di seri riset ini (TEST-0326, TEST-0355): *"Do not treat the presence of android:permission as sufficient by itself: a broadly grantable protection level (normal or dangerous) may still allow untrusted apps to invoke sensitive components."* — ini mengonfirmasi bahwa evaluasi test ini **tidak berhenti** pada "apakah ada atribut permission", melainkan harus menelusuri sampai ke `protectionLevel` dari permission yang dirujuk (sesuai tabel risiko lengkap MASTG-KNOW-0017).

### 1.5 Bukti Nyata: Dua Kasus Klasik Bypass Login via Exported Activity

Dua kasus dari riset komunitas pentest menggambarkan persis skenario ancaman kategori ketiga di §1.3 secara konkret:

> *"Trustwave documented a messaging app built for internal company use where the app's manifest exported activities that allowed logging in directly to the messaging system without credentials, allowing access to all messages."*

Dan kasus klasik dari aplikasi contoh populer di dunia pentest mobile:

> *"In Sieve.apk (a password manager), the FileSelectActivity had 'exported' set to 'true,' allowing outside access, and researchers were able to trigger the activity and successfully bypass the login screen without entering credentials."*

Kedua kasus ini menunjukkan pola yang sama: **activity post-login** (dashboard pesan, activity yang menampilkan file password manager) yang ternyata dapat dicapai **tanpa pernah melewati activity login** sama sekali, karena activity tersebut diekspor secara independen dan tidak memverifikasi status sesi penggunanya sendiri saat dibuka secara langsung. Catatan eksploitasi yang relevan untuk pemahaman severity:

> *"The simplest exploit is launching an exported Activity directly via ADB, and an attacker with physical access to a device or a malicious app installed on the same device could silently invoke this."*

Frasa *"silently invoke this"* penting — aplikasi berbahaya yang terinstal di perangkat yang sama **tidak memerlukan interaksi pengguna yang mencolok** untuk memicu bypass ini; cukup memanggil `startActivity()` dengan `Intent` eksplisit di latar belakang.

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | Fungsi |
|---|---|
| **aapt2 / xmlstarlet** | Enumerasi activity exported beserta permission-nya dari manifest (MASTG-TECH-0160) |
| **jadx** | Review kode implementasi activity untuk menilai sensitivitas fungsionalitas (MASTG-TECH-0014, MASTG-TECH-0023) |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **ADB (`am start`)** | Verifikasi dinamis paling langsung — memanggil activity secara eksplisit untuk mengamati apakah bypass benar-benar terjadi |
| **Drozer** | Enumerasi otomatis activity exported (`app.activity.info`) dan peluncuran dengan bantuan intent-crafting (`app.activity.start`) |
| **`adb shell dumpsys package`** | Inspeksi activity resolver table pada device/emulator untuk konfirmasi runtime |

### 2.3 Prasyarat Lingkungan

- Analisis statis manifest tidak butuh device/root.
- Verifikasi dinamis (ADB/Drozer) butuh device/emulator dengan aplikasi target terinstal.

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0013** untuk reverse engineer aplikasi.
2. Gunakan **MASTG-TECH-0117** untuk memperoleh `AndroidManifest.xml`.
3. Gunakan **MASTG-TECH-0160** untuk mendaftar activity exported beserta `android:permission`-nya.
4. Gunakan **MASTG-TECH-0014** untuk memeriksa kode setiap activity exported.

### 3.2 Metode A — Enumerasi Manifest dengan xmlstarlet

```bash
xmlstarlet sel -t -m "//activity | //activity-alias" \
  -v "name()" -o " name=" -v "@android:name" \
  -o " exported=" -v "@android:exported" \
  -o " permission=" -v "@android:permission" \
  -o " intent_filters=" -v "count(intent-filter)" -n \
  AndroidManifest.xml
```

### 3.3 Metode B — Enumerasi dengan aapt2

```bash
aapt2 d xmltree app.apk --file AndroidManifest.xml | grep -A20 -E "E: activity|E: activity-alias"
```

### 3.4 Metode C — Review Kode untuk Menilai Sensitivitas (Wajib, Sesuai MASTG-TECH-0023)

Untuk setiap activity exported tanpa permission yang teridentifikasi dari Metode A/B:

1. Periksa `onCreate()` — apakah ada pemeriksaan status sesi/login sebelum menampilkan konten?
2. Periksa apakah activity menampilkan data dari sumber yang memerlukan otentikasi (database lokal, hasil API yang memerlukan token sesi) tanpa validasi ulang.
3. Identifikasi apakah activity melakukan aksi yang mengubah state keamanan (ubah PIN, setting akun) langsung dari `onCreate()`/`onResume()` tanpa prasyarat.

### 3.5 Metode D — Verifikasi Dinamis dengan ADB (Replikasi Skenario Nyata §1.5)

```bash
# Daftar activity dari resolver table
adb shell dumpsys package com.example.app | grep -A5 'Activity Resolver Table'

# Coba panggil langsung activity yang diduga post-login
adb shell am start -n com.example.app/.DashboardActivity
```

Amati: apakah tampilan yang muncul adalah dashboard langsung (bypass berhasil, FAIL), atau aplikasi menolak/mengalihkan ke login (PASS)?

### 3.6 Metode E — Drozer untuk Triase Otomatis

```bash
dz> run app.activity.info -a com.example.app
dz> run app.activity.start --component com.example.app com.example.app.DashboardActivity
```

### 3.7 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Kapan dipakai |
|---|---|---|
| **A/B** | xmlstarlet/aapt2 | Baseline wajib — enumerasi lengkap activity exported |
| **C** | Review manual | Inti pengujian — menilai sensitivitas fungsionalitas |
| **D** | ADB `am start` | Verifikasi dinamis paling langsung, replikasi skenario nyata |
| **E** | Drozer | Triase otomatis banyak activity sekaligus |

**Kombinasi minimum yang aku rekomendasikan:** **A/B (enumerasi) → C (wajib, nilai sensitivitas) → D (konfirmasi dinamis)**.

---

### 3.8 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG:**

> **Evaluation:** *"The test case fails if any exported activity is not protected by an appropriate android:permission that restricts which apps can start it and exposes or performs sensitive functionality."*

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi |
|---|---|
| F1 | Activity `exported="true"` tanpa `android:permission` yang memadai, **dan** menampilkan/melakukan fungsi sensitif (§1.3) |

**Contoh bukti (merefleksikan pola nyata Trustwave/Sieve §1.5):**

```xml
<activity android:name=".DashboardActivity" android:exported="true" />
```

```bash
$ adb shell am start -n com.example.app/.DashboardActivity
Starting: Intent { cmp=com.example.app/.DashboardActivity }
# Dashboard langsung terbuka, tanpa prompt login
```

**FAIL** — bypass otentikasi terkonfirmasi.

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi |
|---|---|
| P1 | Activity sensitif diset `exported="false"` (tidak ada kebutuhan diakses eksternal), **atau** |
| P2 | Activity exported **dengan** `android:permission` yang dirujuk memakai `protectionLevel="signature"`, **atau** |
| P3 | Activity memverifikasi status sesi/otentikasi secara independen di `onCreate()` sebelum menampilkan konten sensitif, terlepas dari bagaimana ia dipanggil |

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Dahulukan pertanyaan "perlu diekspor atau tidak" sebelum menilai kekuatan permission** — sesuai §1.4, bila tidak ada alasan sah pihak ketiga memanggil activity tersebut, solusi paling sederhana dan kuat adalah `exported="false"`, bukan menambah permission.

2. **Intent filter bukan kontrol akses** — jangan tertipu anggapan bahwa activity dengan `<intent-filter>` yang "spesifik" (action/category/data tertentu) otomatis aman; sesuai §1.2, filter hanya mengatur routing, siapa pun masih bisa memanggilnya langsung via `Intent` eksplisit.

3. **Verifikasi independen di level activity adalah pertahanan kedua yang kuat** — bahkan bila terpaksa exported, activity yang memeriksa ulang status sesi di `onCreate()` (bukan mengandalkan asumsi "pasti datang dari flow normal") tetap aman meski dipanggil langsung — ini konsisten dengan prinsip defense-in-depth yang berulang di seri riset ini.

4. **Severity dimodulasi:**

   | Faktor | Severity |
   |---|---|
   | Bypass otentikasi terkonfirmasi, mengekspos data/fungsi finansial atau kredensial | **Tinggi** |
   | Menampilkan data sensitif non-finansial tanpa bypass otentikasi penuh | **Sedang** |
   | Permission ada namun `protectionLevel` lemah (`normal`/`dangerous`) | **Sedang-Tinggi** |
   | Non-exported, atau exported dengan `signature` + verifikasi sesi independen | **Bukan temuan** |

5. **Dokumentasikan:** nama activity, status exported, atribut permission dan `protectionLevel`-nya, hasil review kode (apakah ada verifikasi sesi independen), dan hasil verifikasi dinamis `am start`.

---

## 4. Rekomendasi Perbaikan

### 4.1 Non-Exported Bila Tidak Ada Kebutuhan Eksternal (Sesuai MASTG-BEST-0052)

```xml
<activity android:name=".DashboardActivity" android:exported="false" />
```

### 4.2 Permission Signature untuk Akses Eksternal yang Memang Diperlukan

```xml
<activity
    android:name=".ShareResultActivity"
    android:exported="true"
    android:permission="com.example.app.permission.TRUSTED_PARTNER" />

<permission
    android:name="com.example.app.permission.TRUSTED_PARTNER"
    android:protectionLevel="signature" />
```

### 4.3 Verifikasi Sesi Independen sebagai Pertahanan Kedua

```java
@Override
protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    if (!SessionManager.isAuthenticated()) {
        startActivity(new Intent(this, LoginActivity.class));
        finish();
        return;
    }
    setContentView(R.layout.activity_dashboard);
}
```

### 4.4 Checklist Remediasi

- [ ] Seluruh activity exported dievaluasi apakah benar-benar perlu diakses pihak eksternal
- [ ] Activity yang tidak perlu diekspor diset `exported="false"` secara eksplisit
- [ ] Activity exported yang diperlukan dilindungi permission dengan `protectionLevel="signature"`
- [ ] Activity sensitif memverifikasi status sesi/otentikasi secara independen di `onCreate()`, tidak mengandalkan asumsi urutan navigasi
- [ ] Diverifikasi secara dinamis dengan `adb shell am start` untuk setiap activity post-login

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0364 (source, tests-beta)](https://github.com/OWASP/mastg/blob/master/tests-beta/android/MASVS-PLATFORM/MASTG-TEST-0364.md)
- [MASTG-KNOW-0132: Android Activities](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0132/)
- [MASTG-KNOW-0017: App Permissions](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0017/)
- [MASTG-BEST-0052: Restrict Access to Android App Components](https://github.com/OWASP/mastg/blob/master/best-practices/MASTG-BEST-0052.md)
- [MASTG-TECH-0160: Enumerating Activities](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0160/)

### 5.2 Riset dan Kasus Nyata

- [RedFoxSec: How to Exploit Android Activities — Practical Attack Guide](https://www.redfoxsec.com/blog/how-to-exploit-android-activities)
- [Medium: Breaking In — Bypassing Sieve.apk's Authentication](https://medium.com/@r00t7h3ll/bypassing-login-screen-in-android-application-4277ec5b4c17)
- [Android Headlines: Any App Can Be Hit By This Authentication Bypass Vulnerability](https://www.androidheadlines.com/2020/06/app-authentication-bypass-vulnerability-android-manifests.html)
- [Oversecured: Android Deep Link Vulnerabilities — How Intent Filters Lead to Account Takeover](https://oversecured.com/blog/android-deep-link-vulnerabilities)

### 5.3 Dokumentasi Tools

- [Drozer — Android Security Assessment Framework](https://github.com/WithSecureLabs/drozer)
- [aapt2 Documentation](https://developer.android.com/tools/aapt2)

---

*Dokumen ini disusun berdasarkan konten resmi OWASP MASTG (`tests-beta/android/MASVS-PLATFORM/MASTG-TEST-0364.md`, `MASTG-KNOW-0132/0017/0020`, `MASTG-BEST-0052`), serta riset komunitas pentest yang mendokumentasikan dua kasus klasik bypass otentikasi via exported activity (aplikasi messaging internal yang didokumentasikan Trustwave, dan `FileSelectActivity` pada Sieve.apk). Nuansa metodologis terpenting: tidak ada rule Semgrep resmi untuk test ini — sepenuhnya bertumpu pada enumerasi manifest dan review manual, karena menentukan "apakah suatu activity mengekspos fungsionalitas sensitif" adalah pertanyaan kontekstual yang menuntut pemahaman logika bisnis aplikasi, tidak dapat direduksi menjadi pattern-matching sintaksis. Urutan evaluasi yang benar selalu dimulai dari "apakah activity ini perlu diekspor sama sekali" sebelum menilai kekuatan permission yang melindunginya.*
