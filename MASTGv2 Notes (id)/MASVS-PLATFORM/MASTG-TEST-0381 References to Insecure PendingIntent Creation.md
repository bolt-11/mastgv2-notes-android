# MASTG-TEST-0381 References to Insecure PendingIntent Creation

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0381 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-PLATFORM |
| **Weakness** | MASWE-0032 |
| **Tipe Pengujian** | Static |
| **Teknik terkait** | MASTG-TECH-0014 (Static Analysis for Relevant APIs) |
| **Knowledge terkait** | MASTG-KNOW-0024 (Pending Intents) |
| **Best Practice terkait** | MASTG-BEST-0063 (Use Immutable PendingIntents with Explicit Intents) |
| **Rule resmi** | `mastg-android-pendingintent-mutable.yml` — ditemukan **dua kesenjangan signifikan**, lihat §1.4 |

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian dan Mengapa PendingIntent Berbeda dari Intent Biasa

Kutipan overview resmi MASTG:

> *"A PendingIntent wraps an Intent that will be executed later on behalf of the app's identity and permissions, making it critical to configure them securely."*

Perbedaan fundamental yang menjadikan `PendingIntent` kategori risiko tersendiri (bukan sekadar variasi dari Intent biasa di TEST-0372/0374/0375 yang sudah dibahas dalam seri riset ini):

> *"What makes a PendingIntent secure is that, unlike a normal Intent, it grants permission to a foreign application to use the Intent (the base intent) it contains, **as if it were being executed by your application's own process**."*

Frasa *"as if it were being executed by your application's own process"* adalah inti risiko — `PendingIntent` secara desain memberikan **hak eksekusi atas nama aplikasi pembuatnya** kepada pihak yang menerimanya (notifikasi, widget, media browser service). Ini berarti kerentanan pada `PendingIntent` bukan sekadar "intent yang bisa dicegat", melainkan **delegasi identitas dan izin** yang bisa disalahgunakan.

### 1.2 Dua Kriteria Keamanan Independen yang Harus Sama-sama Dipenuhi

Overview secara eksplisit membagi risiko menjadi dua kategori independen:

> *"Mutability: A mutable PendingIntent allows the receiving app to modify the base intent's unfilled fields (action, data, categories, extras, etc.)."*
>
> *"Implicit Intents: Using an implicit base intent... can allow malicious apps to intercept the PendingIntent and redirect its execution."*

Kedua kriteria ini **saling independen** — sebuah `PendingIntent` bisa aman dari satu aspek namun tetap rentan dari aspek lain. Tabel kombinasi untuk memperjelas:

| Mutability | Base Intent | Hasil |
|---|---|---|
| `FLAG_IMMUTABLE` | Explicit | **Aman** |
| `FLAG_IMMUTABLE` | Implicit | Rentan hijacking saat `PendingIntent` dikirim ke pihak lain, meski field tidak bisa diubah |
| `FLAG_MUTABLE` | Explicit | Rentan — field (termasuk action/extras/data) bisa diisi penerima |
| `FLAG_MUTABLE` | Implicit | **Paling rentan** — gabungan kedua risiko |

### 1.3 Nuansa Historis Penting: Perubahan Default Android 12

Ini adalah detail versi API yang krusial untuk kriteria evaluasi:

> *"Prior to Android 12 (API level 31), PendingIntent objects were mutable by default... since Android 12 (API level 31), the mutability of each PendingIntent object must be specified using either FLAG_MUTABLE or the FLAG_IMMUTABLE flag. If the mutability isn't specified, the system throws an IllegalArgumentException and the app will crash."*

Ini menciptakan dinamika yang mirip dengan beberapa test lain dalam seri riset ini (TEST-0315, TEST-0285) — aplikasi dengan `minSdkVersion` di bawah 31 **wajib secara eksplisit** menambahkan `FLAG_IMMUTABLE` karena default lama tidak aman; sedangkan aplikasi yang **hanya** menargetkan API 31+ akan otomatis crash bila lupa — sebuah bentuk "fail-safe by design" yang serupa dengan temuan Android 14 untuk implicit intent internal di TEST-0372.

### 1.4 Temuan Analitis Kritis: Rule Resmi Tidak Menangani Ekspresi Flag Gabungan (Bitwise OR) dan Sepenuhnya Mengabaikan Kriteria Implicit Intent

Rule `mastg-android-pendingintent-mutable.yml` memakai `metavariable-regex` yang di-anchor penuh (`^...$`) terhadap nilai literal tunggal:

```yaml
metavariable-regex:
  metavariable: $FLAGS
  regex: ^(0|134217728|33554432|0x08000000|0x02000000|PendingIntent\.FLAG_UPDATE_CURRENT|PendingIntent\.FLAG_MUTABLE)$
```

Ini memiliki **kesenjangan paling signifikan** yang ditemukan sejauh ini terkait pola kode idiomatis yang sangat umum — **pola realistis paling sering dipakai developer** untuk `PendingIntent` notifikasi adalah **kombinasi dua flag** via bitwise OR, misalnya:

```java
PendingIntent.getActivity(context, 0, intent,
    PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE) // AMAN, tapi TIDAK dicek rule
```

atau versi berbahaya:

```java
PendingIntent.getActivity(context, 0, intent,
    PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_MUTABLE) // BERBAHAYA, TIDAK terdeteksi rule
```

Karena regex di-anchor penuh terhadap **satu token tunggal**, **ekspresi gabungan apa pun** (ditulis sebagai string `"PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_MUTABLE"` secara tekstual oleh Semgrep saat `$FLAGS` menangkap seluruh ekspresi) **tidak akan pernah cocok** dengan pola regex manapun dalam daftar — baik kasus **aman** (gabungan dengan `FLAG_IMMUTABLE`, seharusnya tidak flagged, dan memang tidak — kebetulan benar) maupun kasus **berbahaya** (gabungan dengan `FLAG_MUTABLE` tanpa justifikasi, seharusnya flagged namun **luput sepenuhnya**). Ini berarti rule hanya efektif untuk kasus yang jarang terjadi di kode nyata — flag tunggal tanpa kombinasi — sementara pola paling umum di produksi (kombinasi dengan `FLAG_UPDATE_CURRENT`/`FLAG_CANCEL_CURRENT`) sepenuhnya lolos dari deteksi, ke arah manapun hasilnya.

Kesenjangan kedua: rule ini **hanya menyasar kriteria mutability**, sama sekali **tidak mengandung pola apa pun** untuk kriteria kedua yang disebut eksplisit di overview — implicit base intent (§1.2). Dari tiga kriteria FAIL resmi (lihat §3.6), rule hanya menyentuh satu kriteria, dan bahkan untuk kriteria itu pun cakupannya terbatas pada flag tunggal non-gabungan.

### 1.5 Bukti Nyata: Dari Firmware Vendor Besar hingga Eskalasi Privilege Sistem

Riset dan database CVE menunjukkan bahwa kerentanan class ini sangat umum ditemukan di firmware vendor Android besar, dengan dampak yang beragam mulai dari pencurian file hingga bypass akses provider:

> *"CVE-2023-44123 and CVE-2023-44125 involve implicit PendingIntents without FLAG_IMMUTABLE set or with FLAG_MUTABLE set in LG apps, leading to theft and/or overwrite of arbitrary files with system privilege."*

> *"CVE-2023-30700 is a PendingIntent hijacking vulnerability in SemWifiApTimeOutImpl that allows local attackers to access ContentProvider without proper permission."*

Skala masalah di satu vendor saja cukup mengkhawatirkan:

> *"Samsung alone disclosed four PendingIntent hijacking CVEs between 2021 and 2023."*

Riset akademik BlackHat EU 2021 ("PendingIntent Redirection: A Universal Privilege Escalation Method for Android Systems and Popular Apps") menegaskan bahwa kelas kerentanan ini bukan isu sempit yang terbatas pada satu-dua aplikasi, melainkan **pola serangan universal** yang dapat diterapkan lintas banyak sistem dan aplikasi populer — konsisten dengan temuan empiris bahwa kesalahan ini terus berulang di banyak vendor berbeda dari waktu ke waktu.

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | Fungsi |
|---|---|
| **jadx** | Dekompilasi DEX → Java untuk analisis manual |
| **Semgrep** + rule resmi | Deteksi dasar flag tunggal non-gabungan (cakupan sangat terbatas, §1.4) |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **grep/ripgrep** | **Wajib** — menutup celah ekspresi flag gabungan dan kriteria implicit intent yang tidak tercakup rule resmi |

### 2.3 Prasyarat Lingkungan

- Tidak butuh device/root — murni analisis statis.
- Catat `minSdkVersion` aplikasi untuk kalibrasi kriteria FAIL pertama (§1.3).

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Jalankan static analysis tool untuk mengidentifikasi seluruh pemanggilan lima varian `PendingIntent.get*()`.
2. Untuk setiap pemanggilan, periksa parameter flags dan apakah base intent explicit/implicit.

### 3.2 Metode A — Semgrep dengan Rule Resmi (Cakupan Terbatas)

```bash
semgrep --config mastg-android-pendingintent-mutable.yml ./decompiled/sources
```

### 3.3 Metode B — grep/ripgrep untuk Menutup Celah Flag Gabungan (Wajib, §1.4)

```bash
D=./decompiled/sources

# Cari SELURUH pemanggilan PendingIntent.get*, termasuk yang memakai flag gabungan
rg -n 'PendingIntent\.get(Activity|Activities|Service|ForegroundService|Broadcast)\(' $D -A1

# Verifikasi manual: apakah FLAG_IMMUTABLE ada di ekspresi flag (tunggal ATAU gabungan)?
rg -n 'PendingIntent\.FLAG_IMMUTABLE' $D
rg -n 'PendingIntent\.FLAG_MUTABLE' $D
```

### 3.4 Metode C — Verifikasi Explicit vs Implicit Base Intent (Wajib, Kriteria Tidak Tercakup Rule Resmi)

```bash
# Lacak balik variabel intent yang diteruskan ke PendingIntent.get*()
rg -n -B10 'PendingIntent\.get(Activity|Service|Broadcast)\(' $D | grep -E 'new Intent\(|setClass\(|setComponent\(|setClassName\('
```

Untuk setiap base intent yang ditemukan, verifikasi apakah dibangun dengan konstruktor explicit (`Intent(context, Class)`) atau dipasangkan `setClass()`/`setComponent()`/`setClassName()` — bila tidak ada satu pun, intent tersebut implicit.

### 3.5 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Kapan dipakai |
|---|---|---|
| **A** | Semgrep + rule resmi | Baseline, hanya mendeteksi sebagian kecil kasus (flag tunggal) |
| **B** | grep/ripgrep manual | **Wajib** — satu-satunya cara menutup celah flag gabungan |
| **C** | Review manual | **Wajib** — satu-satunya cara memeriksa kriteria implicit intent |

**Kombinasi minimum yang aku rekomendasikan:** **B + C (wajib, baseline sesungguhnya)**, dengan Metode A hanya pelengkap kecil.

---

### 3.6 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG (tiga kriteria FAIL independen):**

> **Evaluation:** *"The test case fails if any of the following conditions are met: (1) A PendingIntent is created without FLAG_IMMUTABLE when minSdkVersion is below 31, unless properly justified. (2) A PendingIntent is created with FLAG_MUTABLE without a valid use case. (3) The base intent is implicit."*

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila salah satu dari:

| No | Kondisi |
|---|---|
| F1 | `PendingIntent` dibuat tanpa `FLAG_IMMUTABLE` pada `minSdkVersion` < 31, tanpa justifikasi mutability yang jelas |
| F2 | `PendingIntent` dibuat dengan `FLAG_MUTABLE` tanpa use case valid (bukan inline reply/app widget callback) |
| F3 | Base intent implicit (tidak ada `setClass`/`setComponent`/`setClassName`/konstruktor explicit) |

**Contoh bukti (merefleksikan pola nyata CVE-2023-44123/44125 §1.5):**

```java
Intent intent = new Intent(); // implicit — F3
intent.setAction("com.example.app.ACTION_SYNC");
PendingIntent pi = PendingIntent.getBroadcast(context, 0, intent,
    PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_MUTABLE); // F2, DAN tidak terdeteksi rule (§1.4)
```

**FAIL** — ganda: base intent implicit DAN mutable tanpa justifikasi, keduanya luput dari rule otomatis.

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi |
|---|---|
| P1 | `FLAG_IMMUTABLE` eksplisit (tunggal atau dikombinasikan via OR dengan flag lain seperti `FLAG_UPDATE_CURRENT`), **dan** |
| P2 | Base intent explicit (constructor `Intent(context, Class)` atau `setClass`/`setComponent`/`setClassName`) |

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Jangan andalkan rule resmi sebagai baseline** — sesuai §1.4, pola kode paling umum di produksi (flag gabungan) sepenuhnya lolos dari rule, ke arah manapun; grep manual adalah satu-satunya cara memverifikasi secara memadai.

2. **Periksa ketiga kriteria FAIL secara independen** — jangan berhenti setelah menemukan `FLAG_IMMUTABLE` ada; tetap periksa apakah base intent-nya explicit (kriteria F3 sama sekali berbeda dari F1/F2).

3. **Pertimbangkan `minSdkVersion` untuk kriteria F1** — pada aplikasi yang hanya menargetkan API 31+, ketidakhadiran flag mutability akan menyebabkan crash saat build/runtime (fail-safe platform), menjadikan F1 secara praktis tidak mungkin terjadi tanpa disadari; F1 jauh lebih relevan untuk aplikasi dengan `minSdkVersion` lebih rendah.

4. **Severity dimodulasi:**

   | Faktor | Severity |
   |---|---|
   | `PendingIntent` mutable + implicit, berkaitan dengan operasi sensitif (otentikasi, transaksi) | **Tinggi** |
   | Salah satu dari dua kriteria (mutable ATAU implicit) terpenuhi, bukan keduanya | **Sedang-Tinggi** |
   | `FLAG_IMMUTABLE` + explicit intent terverifikasi lengkap | **Bukan temuan** |

5. **Dokumentasikan:** lokasi kode, ekspresi flag lengkap (termasuk kombinasi OR), status explicit/implicit base intent, `minSdkVersion` aplikasi, dan justifikasi bila `FLAG_MUTABLE` memang diperlukan.

---

## 4. Rekomendasi Perbaikan

### 4.1 Selalu Gunakan FLAG_IMMUTABLE + Explicit Intent (Sesuai MASTG-BEST-0063)

```kotlin
// SEBELUM — implicit + flag gabungan tanpa IMMUTABLE
val intent = Intent("com.example.app.ACTION_SYNC")
val pendingIntent = PendingIntent.getBroadcast(context, 0, intent,
    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE)

// SESUDAH — explicit + IMMUTABLE
val intent = Intent(context, SyncReceiver::class.java).apply {
    setPackage(context.packageName)
}
val pendingIntent = PendingIntent.getBroadcast(context, 0, intent,
    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
```

### 4.2 Checklist Remediasi

- [ ] Seluruh pemanggilan `PendingIntent.get*()` memakai `FLAG_IMMUTABLE`, baik tunggal maupun dikombinasikan via OR
- [ ] `FLAG_MUTABLE` hanya dipakai untuk use case yang terjustifikasi (inline reply, app widget callback) dengan field yang dibatasi
- [ ] Seluruh base intent memakai `setClass`/`setComponent`/`setClassName`/konstruktor explicit
- [ ] Verifikasi dilakukan manual (grep), tidak hanya mengandalkan hasil Semgrep rule resmi

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0381 (source, tests-beta)](https://github.com/OWASP/mastg/blob/master/tests-beta/android/MASVS-PLATFORM/MASTG-TEST-0381.md)
- [MASTG-KNOW-0024: Pending Intents](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0024/)
- [MASTG-BEST-0063: Use Immutable PendingIntents with Explicit Intents](https://github.com/OWASP/mastg/blob/master/best-practices/MASTG-BEST-0063.md)

### 5.2 Riset dan Kasus Nyata

- [GitHub Advisory: CVE-2022-36829 — PendingIntent Hijacking in releaseAlarm](https://github.com/advisories/GHSA-pjg2-878f-mvhc)
- [Strix.ai: CVE-2023-30700 — PendingIntent Hijacking ContentProvider Access Bypass](https://www.strix.ai/cve/CVE-2023-30700)
- [arXiv: Exploiting PendingIntent Provenance Confusion to Spoof Android SDK Authentication](https://arxiv.org/pdf/2603.02539)
- [Android Developers: Pending Intents Risk](https://developer.android.com/privacy-and-security/risks/pending-intent)
- [SegmentFault: PendingIntent Redirection — A Universal Privilege Escalation Method (BlackHat EU 2021)](https://segmentfault.com/a/1190000041550819/en)

### 5.3 Dokumentasi Tools

- [Semgrep Documentation](https://semgrep.dev/docs/)

---

*Dokumen ini disusun berdasarkan konten resmi OWASP MASTG (`tests-beta/android/MASVS-PLATFORM/MASTG-TEST-0381.md`, `MASTG-KNOW-0024`, `MASTG-BEST-0063`), analisis rule `mastg-android-pendingintent-mutable.yml`, serta riset dan CVE nyata (CVE-2023-44123/44125 pada LG, CVE-2023-30700 Samsung, dengan total empat CVE PendingIntent hijacking dari Samsung sendiri periode 2021-2023, dan riset akademik BlackHat EU 2021 tentang PendingIntent Redirection sebagai metode eskalasi privilege universal). Nuansa metodologis terpenting dan paling signifikan: rule resmi memakai regex yang di-anchor penuh terhadap token flag tunggal, sehingga **ekspresi flag gabungan via bitwise OR** — pola kode paling umum dipakai di produksi nyata (`FLAG_UPDATE_CURRENT | FLAG_IMMUTABLE`/`FLAG_MUTABLE`) — **sepenuhnya lolos dari deteksi otomatis ke arah manapun**. Rule juga sama sekali tidak mencakup kriteria kedua (implicit base intent) yang disebut eksplisit di evaluasi resmi test ini. Verifikasi manual terhadap kombinasi flag dan status explicit/implicit base intent adalah kewajiban, bukan pelengkap opsional.*
