# MASTG-TEST-0319 Runtime Use of SDK APIs Known to Handle Sensitive User Data

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0319 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-PRIVACY |
| **Weakness** | MASWE-0073 — *Inadequate Data Collection Declarations* |
| **Tipe Pengujian** | Dynamic, Hooks |
| **Teknik terkait** | MASTG-TECH-0005 (Installing Apps), MASTG-TECH-0043 (Method Hooking) |
| **Prasyarat** | `identify-sensitive-data` — definisi "data sensitif" harus ditetapkan sebelum pengujian dimulai |
| **Test terkait** | **MASTG-TEST-0318** — counterpart **statis** yang mendeteksi **potensi** (test ini adalah pasangan **dinamis** yang **mengonfirmasi**, lihat §1.1) |

> **Catatan verifikasi sumber:** Permintaan WebFetch pertama terhadap halaman resmi test ini awalnya mengembalikan konten yang **keliru/tidak konsisten** (menyebutkan MASWE-0069 dan tipe "Runtime Test" generik, tidak cocok dengan pola MASTG-TEST-0318 yang menjadi pasangannya). Setelah verifikasi langsung ke source resmi `OWASP/mastg` di GitHub — ditemukan file ini berada di direktori **`tests-beta/android/MASVS-PRIVACY/`** (belum dipromosikan ke `tests/` final) — konten yang benar berhasil diperoleh dan dikonfirmasi: **MASWE-0073** (sama dengan TEST-0318) dan tipe `[dynamic, hooks]`. Dokumen ini disusun berdasarkan konten yang sudah diverifikasi tersebut.

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian dan Hubungan dengan MASTG-TEST-0318

Kutipan overview resmi MASTG:

> *"This test is the dynamic counterpart to MASTG-TEST-0318. In this case we will hook any SDK methods known to handle sensitive user data."*

Test ini adalah **penyelesaian** langsung dari keterbatasan yang sudah dijelaskan secara eksplisit di dokumen **MASTG-TEST-0318** — di sana ditegaskan bahwa analisis statis (menemukan pemanggilan `setUserId()`, `logEvent()`, dsb. di kode) hanya mengidentifikasi **potensi**, bukan **konfirmasi**, karena nilai parameter yang sesungguhnya diteruskan ke API tersebut **tidak dapat dipastikan dari kode sumber saja** (misalnya nilai berasal dari input pengguna, hasil kalkulasi runtime, atau respons API lain). Test ini menutup celah tersebut dengan **meng-hook API SDK secara langsung saat aplikasi berjalan** dan menangkap **nilai argumen sesungguhnya** yang diteruskan — inilah yang membedakan "kandidat ditemukan di kode" versus "data sensitif terkonfirmasi benar-benar dikirim".

### 1.2 Tiga Komponen Observasi yang Diminta: Lokasi, Stack Trace, dan Argumen

Bagian Observation resmi memberi tiga lapis informasi yang harus dicatat, bukan hanya satu:

> *"The output should list the locations where SDK methods are called, their stacktrace (call hierarchy leading to the call), and the arguments (values) passed to the SDK method at runtime."*

Ketiga komponen ini memiliki fungsi berbeda:

| Komponen | Fungsi |
|---|---|
| **Lokasi pemanggilan** | Mengidentifikasi titik di kode aplikasi tempat SDK dipanggil |
| **Stack trace / call hierarchy** | Menunjukkan **jalur pemicu** — apakah pemanggilan terjadi otomatis saat startup, dipicu oleh aksi pengguna tertentu (login, checkout, dsb.), atau dipicu oleh SDK lain secara berantai |
| **Argumen (nilai) saat runtime** | **Bukti konklusif** — inilah yang membedakan test ini dari TEST-0318; nilai aktual yang diteruskan menentukan apakah benar-benar data sensitif yang dikirim |

Stack trace secara khusus penting untuk investigasi **akar penyebab** — bila ditemukan data sensitif terkirim, stack trace menunjukkan **modul kode mana** yang memicu alur tersebut, sehingga remediasi dapat ditargetkan secara tepat alih-alih menebak.

### 1.3 Prasyarat Metodologis: Mendefinisikan "Data Sensitif" Sebelum Mulai

Test ini secara eksplisit mencantumkan prasyarat `identify-sensitive-data` — sebuah dokumen pendukung resmi MASTG yang menegaskan pentingnya **definisi yang jelas** sebelum pengujian dimulai:

> *"A definition of 'sensitive data' must be decided before testing begins because detecting sensitive data leakage without a definition may be impossible."*

Dokumen tersebut memberikan kategori acuan bila tidak ada kebijakan klasifikasi data organisasi:

- Informasi autentikasi pengguna (kredensial, PIN, dsb.)
- PII yang dapat disalahgunakan untuk pencurian identitas (SSN, nomor kartu kredit, nomor rekening bank, data kesehatan)
- Identifier perangkat yang dapat mengidentifikasi seseorang
- Data sangat sensitif yang bila dikompromikan menyebabkan kerugian reputasi/finansial
- Data yang perlindungannya merupakan obligasi hukum
- Data teknis yang dipakai untuk melindungi data/sistem lain (mis. encryption keys)

Ini relevan karena tanpa definisi yang disepakati, hasil hooking runtime (misalnya menangkap string `"premium_tier"` sebagai argumen `setUserProperty`) bisa diperdebatkan apakah itu "sensitif" atau bukan — definisi di muka menghindari ambiguitas evaluasi di akhir.

### 1.4 Mengapa Metode Resmi (Frida/Hooking Manual) Punya Keterbatasan Nyata

Pendekatan resmi MASTG — hooking manual per-metode SDK menggunakan Frida — sangat **presisi** tapi menuntut penguji sudah tahu persis API mana yang harus di-hook (hasil riset dari TEST-0318 §1.2). Riset akademik tentang pendekatan **taint-tracking sistem-wide** seperti **TaintDroid** menunjukkan pendekatan alternatif yang lebih luas jangkauannya — bukan hanya meng-hook API yang sudah diketahui, tapi melacak **aliran data** dari sumber sensitif (kontak, lokasi, IMEI) ke sink mana pun (termasuk SDK yang belum diketahui sebelumnya):

> *"TaintDroid uses taint sources (from which sensitive information like IMEI, text messages, contacts, GPS data, or camera pictures are obtained) and taint sinks (interfaces to the outside world like data networks or SMS) where tainted information is usually not expected to be sent."*

Temuan nyata dari riset TaintDroid terhadap 30 aplikasi populer memberi gambaran skala masalah ini di dunia nyata:

> *"Researchers found 68 instances of potential private information misuse, with 18 applications reporting users' locations to remote advertising servers, and seven collecting device ID, phone number, and SIM card serial number — in all, two-thirds of applications used sensitive data suspiciously."*

Namun taint-tracking sistem-wide juga punya keterbatasan yang relevan untuk dicatat penguji:

> *"TaintDroid has limitations: taint-based tracking can be easily circumvented using indirect information flows, requires trade-offs between false positives and false negatives, and misses native code."*

Ini menegaskan bahwa **hooking manual bertarget (metode resmi MASTG)** dan **taint-tracking sistem-wide (pendekatan akademik)** adalah dua pendekatan yang **saling melengkapi**, bukan saling menggantikan — hooking manual lebih presisi untuk SDK yang sudah diketahui, taint-tracking lebih baik untuk menemukan aliran data yang **tidak terduga** ke SDK yang belum pernah diperiksa sebelumnya.

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core, Sesuai MASTG-TECH-0043)

| Tool | Fungsi |
|---|---|
| **Frida** | Hooking method SDK secara dinamis, menangkap argumen dan stack trace saat runtime |
| **ADB** | Instalasi APK (MASTG-TECH-0005) dan komunikasi dengan device/emulator |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **Objection** | Front-end Frida tingkat tinggi — menyediakan perintah REPL siap pakai untuk hooking tanpa menulis script JavaScript dari nol |
| **Frida CodeShare** | Repositori script Frida siap pakai dari komunitas, termasuk script generik untuk logging argumen method apa pun |
| **TaintDroid** *(riset akademik, bukan tool produksi aktif)* | Pendekatan taint-tracking sistem-wide untuk melacak aliran data sensitif ke sink yang tidak terduga, melengkapi hooking bertarget |
| **mitmproxy / Burp Suite** | Korelasi dengan lalu lintas jaringan sungguhan — memverifikasi apakah data yang ditangkap di argumen SDK benar-benar diteruskan keluar perangkat (menjembatani ke MASTG-TEST-0206) |

### 2.3 Prasyarat Lingkungan

- **Device rooted / emulator** dengan `frida-server` berjalan.
- Aplikasi target **harus di-exercise secara ekstensif** mencakup sebanyak mungkin alur (login, checkout, pengisian form, dsb.) — hooking pasif tidak berguna bila fitur pemicu tidak dijalankan.
- **Definisi data sensitif sudah disepakati** sebelum sesi pengujian dimulai (§1.3).

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0005** untuk instalasi aplikasi.
2. Gunakan **MASTG-TECH-0043** untuk hook pemanggilan API yang relevan.
3. Jalankan/exercise aplikasi secara ekstensif untuk memicu sebanyak mungkin alur, dan masukkan data sensitif di mana pun memungkinkan.

### 3.2 Metode A — Frida Manual, Hook Langsung dengan Stack Trace

```javascript
Java.perform(function () {
    var FirebaseAnalytics = Java.use("com.google.firebase.analytics.FirebaseAnalytics");

    FirebaseAnalytics.setUserId.overload('java.lang.String').implementation = function (userId) {
        console.log("[setUserId] value: " + userId);
        console.log("[setUserId] stacktrace:\n" +
            Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));
        return this.setUserId(userId);
    };

    FirebaseAnalytics.logEvent.overload('java.lang.String', 'android.os.Bundle').implementation = function (name, bundle) {
        console.log("[logEvent] name: " + name + " | bundle: " + bundle.toString());
        return this.logEvent(name, bundle);
    };
});
```

```bash
frida -U -f com.example.targetapp -l hook_sdk.js --no-pause
```

### 3.3 Metode B — Objection untuk Hooking Cepat Tanpa Script Kustom

```bash
objection -g com.example.targetapp explore

# Di dalam REPL objection
android hooking watch class_method com.google.firebase.analytics.FirebaseAnalytics.setUserId --dump-args
android hooking watch class_method com.google.firebase.analytics.FirebaseAnalytics.logEvent --dump-args
```

Metode ini jauh lebih cepat untuk eksplorasi awal dibandingkan menulis script Frida kustom, terutama saat penguji belum tahu pasti method mana saja yang ingin dipantau.

### 3.4 Metode C — Korelasi dengan Lalu Lintas Jaringan (mitmproxy)

```bash
mitmproxy --mode transparent -p 8080
```

Jalankan secara paralel dengan hooking Frida — bandingkan nilai argumen yang ditangkap di SDK (Metode A/B) dengan payload yang benar-benar terkirim di request jaringan. Ini memberi **bukti ganda**: SDK dipanggil dengan data sensitif DAN data tersebut benar-benar meninggalkan perangkat.

### 3.5 Metode D — Pendekatan Taint-Tracking (Konteks Riset, Bukan Tool Siap Pakai)

Untuk kasus di mana SDK yang dicurigai **belum diketahui** sebelumnya (tidak ada daftar referensi API dari riset TEST-0318 §1.2), pendekatan taint-tracking sistem-wide seperti yang dirintis TaintDroid secara konseptual dapat membantu menemukan aliran data tak terduga — meski tool produksi modern untuk pendekatan ini terbatas, konsepnya bisa diadaptasi secara manual dengan menandai sumber data sensitif (mis. `Location.getLatitude()`) dan memeriksa secara manual proses binding dengan Frida ke semua sink jaringan/SDK yang teramati.

### 3.6 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Kapan dipakai |
|---|---|---|
| **A** | Frida manual | SDK & method sudah diketahui pasti dari TEST-0318, butuh stack trace detail |
| **B** | Objection | Eksplorasi cepat, banyak method yang perlu dipantau sekaligus |
| **C** | mitmproxy | Verifikasi akhir — data benar-benar keluar perangkat |
| **D** | Taint-tracking (konseptual) | SDK yang dicurigai belum diketahui / investigasi mendalam |

**Kombinasi minimum yang aku rekomendasikan:** **A atau B (hooking inti, wajib) → C (verifikasi jaringan)**. Metode D hanya relevan untuk investigasi lanjutan skala besar.

---

### 3.7 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG:**

> **Evaluation:** *"The test case fails if you can find sensitive user data being passed to these SDK methods in the app code, indicating that the app is sharing sensitive user data with the third-party SDK."*

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi |
|---|---|
| F1 | Hasil hooking Frida menangkap **nilai argumen nyata** yang termasuk kategori data sensitif (§1.3) diteruskan ke method SDK |
| F2 | Stack trace menunjukkan pemanggilan terjadi **otomatis** (mis. saat startup) tanpa ada consent/opt-in eksplisit dari pengguna sebelumnya |

**Contoh bukti (ilustratif):**

```
[setUserId] value: budi.santoso@gmail.com
[setUserId] stacktrace:
  at com.example.targetapp.analytics.UserTracker.trackLogin(UserTracker.java:42)
  at com.example.targetapp.auth.LoginActivity.onLoginSuccess(LoginActivity.java:88)
```

Interpretasi: nilai argumen yang ditangkap adalah **email pengguna sesungguhnya**, bukan sekadar nama variabel di kode seperti pada analisis statis TEST-0318 — ini **konfirmasi penuh**, bukan sekadar kandidat. **FAIL**.

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi |
|---|---|
| P1 | Hooking dijalankan secara ekstensif mencakup seluruh alur utama (login, checkout, pengisian profil, dsb.), dan **tidak ada** nilai argumen yang termasuk kategori data sensitif ditemukan |
| P2 | Argumen yang diteruskan sudah **dianonimkan/di-hash** sebelum dikirim ke SDK (mis. `setUserId(sha256(userId))`) |

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Ini adalah test KONFIRMASI, hasilnya lebih definitif dibanding TEST-0318** — jika TEST-0318 menemukan kandidat tapi TEST-0319 tidak menangkap data sensitif di argumen runtime, prioritaskan hasil TEST-0319 sebagai kesimpulan akhir (asalkan coverage exercise aplikasi memadai — lihat poin 2).

2. **Hasil PASS hanya valid jika coverage exercise memadai** — bila penguji tidak sempat memicu alur tertentu (mis. tidak pernah login), method yang hanya terpanggil di alur tersebut tidak akan pernah ter-hook sama sekali, menghasilkan **false negative**. Dokumentasikan secara eksplisit alur apa saja yang **berhasil** dipicu selama sesi pengujian.

3. **Stack trace adalah informasi forensik, bukan sekadar pelengkap** — gunakan untuk menentukan apakah pemanggilan dipicu otomatis (lebih berisiko, karena tidak ada kesempatan pengguna menolak) atau dipicu oleh aksi eksplisit pengguna.

4. **Korelasikan dengan verifikasi jaringan (Metode C) untuk bukti paling kuat** — argumen yang ditangkap di level SDK adalah apa yang **diberikan ke SDK**, bukan otomatis bukti bahwa data tersebut **meninggalkan perangkat** (SDK bisa saja melakukan filtering/anonimisasi internal sebelum transmisi — meski ini jarang terjadi di SDK analitik komersial).

5. **Severity dimodulasi:**

   | Faktor | Severity |
   |---|---|
   | Data sensitif terkonfirmasi terkirim ke SDK pihak ketiga tanpa consent eksplisit | **Tinggi** |
   | Data terkirim namun sudah dianonimkan/di-hash sebelum diteruskan | **Rendah/Informational** |
   | Tidak ditemukan data sensitif setelah exercise menyeluruh | **Bukan temuan** |

6. **Dokumentasikan:** daftar method yang berhasil di-hook, nilai argumen yang ditangkap (redaksi bila perlu untuk laporan), stack trace, dan alur aplikasi yang dipicu untuk mencapai setiap pemanggilan.

---

## 4. Rekomendasi Perbaikan

### 4.1 Hindari Meneruskan Data Mentah ke SDK Pihak Ketiga

```java
// SEBELUM — email mentah diteruskan sebagai User ID
analytics.setUserId(user.getEmail());

// SESUDAH — gunakan identifier yang sudah di-hash, bukan PII langsung
analytics.setUserId(hashUserId(user.getId()));
```

### 4.2 Minta Consent Eksplisit Sebelum Memanggil SDK Data Collection

Pastikan pemanggilan method seperti `setUserId`/`logEvent` hanya terjadi **setelah** pengguna memberikan persetujuan eksplisit (opt-in), bukan otomatis saat startup aplikasi — gunakan API consent SDK yang bersangkutan (mis. Firebase `setAnalyticsCollectionEnabled(false)` sampai consent diperoleh).

### 4.3 Checklist Remediasi

- [ ] Seluruh method SDK yang teridentifikasi di TEST-0318 sudah di-hook dan diverifikasi nilai argumen runtimenya
- [ ] Tidak ada data sensitif mentah (PII, kredensial) diteruskan tanpa anonimisasi
- [ ] Pemanggilan API data collection dikondisikan pada consent eksplisit pengguna
- [ ] Hasil hooking dikorelasikan dengan capture jaringan untuk verifikasi akhir
- [ ] **Verifikasi ulang** setelah setiap perubahan pada integrasi SDK pihak ketiga

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0319 (source, tests-beta)](https://github.com/OWASP/mastg/blob/master/tests-beta/android/MASVS-PRIVACY/MASTG-TEST-0319.md)
- [MASTG-TEST-0318: References to SDK APIs Known to Handle Sensitive User Data](https://mas.owasp.org/MASTG/tests/android/MASVS-PRIVACY/MASTG-TEST-0318/)
- [MASTG-TECH-0043: Method Hooking](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0043/)
- [MASTG-TECH-0005: Installing Apps](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0005/)
- [MASWE-0073: Inadequate Data Collection Declarations](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0073/)
- [Prerequisite: Identifying Sensitive Data](https://github.com/OWASP/mastg/blob/master/prerequisites/identify-sensitive-data.md)

### 5.2 Riset Akademik

- [TaintDroid: An Information-Flow Tracking System for Realtime Privacy Monitoring on Smartphones (USENIX OSDI 2010)](https://www.usenix.org/legacy/event/osdi10/tech/full_papers/Enck.pdf)
- [TaintDroid (ACM Transactions on Computer Systems, Vol 32)](https://dl.acm.org/doi/10.1145/2619091)
- [MobileAppScrutinator: A Simple yet Efficient Dynamic Analysis Approach for Detecting Privacy Leaks across Mobile OSs (arXiv)](https://arxiv.org/pdf/1605.08357)

### 5.3 Dokumentasi Tools

- [Frida — Dynamic Instrumentation Toolkit](https://frida.re/docs/home/)
- [Objection — Runtime Mobile Exploration](https://github.com/sensepost/objection)
- [Frida CodeShare](https://codeshare.frida.re/)
- [mitmproxy Documentation](https://docs.mitmproxy.org/stable/)

---

*Dokumen ini disusun berdasarkan konten resmi OWASP MASTG (diverifikasi langsung dari source `tests-beta/android/MASVS-PRIVACY/MASTG-TEST-0319.md` di repository `OWASP/mastg` setelah temuan ketidakcocokan pada hasil fetch pertama), riset akademik TaintDroid sebagai konteks pendekatan taint-tracking sistem-wide yang melengkapi hooking bertarget, serta dokumentasi tools Frida/Objection/mitmproxy. Nuansa metodologis terpenting: test ini adalah pasangan **konfirmasi dinamis** dari MASTG-TEST-0318 — hasil hooking yang menangkap nilai argumen sesungguhnya memberi bukti yang jauh lebih definitif dibanding sekadar menemukan pemanggilan API di kode statis, namun validitas hasil PASS sepenuhnya bergantung pada seberapa menyeluruh alur aplikasi dipicu selama sesi pengujian.*
