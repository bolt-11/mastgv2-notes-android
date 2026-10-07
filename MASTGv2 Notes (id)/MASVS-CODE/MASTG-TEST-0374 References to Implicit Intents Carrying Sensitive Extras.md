# MASTG-TEST-0374 References to Implicit Intents Carrying Sensitive Extras

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0374 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-CODE |
| **Weakness** | MASWE-0032 |
| **Tipe Pengujian** | Static, Code, **Manual** |
| **Teknik terkait** | MASTG-TECH-0013, MASTG-TECH-0014, MASTG-TECH-0023 |
| **Knowledge terkait** | MASTG-KNOW-0025 (Explicit vs Implicit Intents) |
| **Best Practice terkait** | MASTG-BEST-0056 (Use Explicit Intents for Internal IPC) |
| **Test terkait** | **MASTG-TEST-0372** — dokumen terkait dalam seri riset ini; perbedaan fokus dijelaskan di §1.1 |
| **Rule resmi** | `mastg-android-implicit-intent-leaking-extras.yml` — ditemukan **dua jenis kesenjangan berbeda**, lihat §1.4 |

---

## 1. Penjelasan

### 1.1 Perbedaan Fokus dengan MASTG-TEST-0372: Data, Bukan Sekadar Mekanisme

Kutipan overview resmi MASTG:

> *"The issue appears when the app attaches sensitive or security-relevant extras to an implicit intent without constraining the recipient. During intent resolution, any installed app with a matching `<intent-filter>` can become the selected recipient and receive the full extras Bundle."*

Test ini adalah **saudara dekat** MASTG-TEST-0372 (sudah dibahas dalam seri riset ini) namun dengan titik berat evaluasi yang berbeda secara mendasar:

| | MASTG-TEST-0372 | MASTG-TEST-0374 (test ini) |
|---|---|---|
| **Fokus evaluasi** | **Mekanisme** — apakah intent untuk komunikasi internal bersifat implicit | **Data** — apakah extras yang dibawa implicit intent bersifat sensitif |
| **Berlaku untuk intent "sah" eksternal?** | Tidak — ACTION_VIEW/ACTION_SEND di luar scope | **Bisa tetap jadi temuan** bila membawa data sensitif, meski action-nya terlihat sah secara mekanisme |

Nuansa kedua inilah yang membuat test ini lebih luas cakupannya dalam satu aspek — bahkan intent yang **sengaja** dirancang untuk delegasi eksternal (ACTION_SEND, chooser) tetap bisa menjadi temuan di test ini bila **isi extras-nya** mengandung data yang seharusnya tidak pernah dibagikan secara broadcast ke aplikasi apa pun yang mendaftar.

### 1.2 Dampak yang Lebih Konkret dan Beragam

Overview memberi daftar dampak yang jauh lebih spesifik dibanding TEST-0372, karena berfokus langsung pada konsekuensi kebocoran data:

> *"This can disclose credentials, session tokens, one-time codes, personal data, account identifiers, or internal state to an untrusted app. Depending on the data, the impact can include privacy leakage, session compromise, account takeover, or unauthorized use of backend APIs."*

Frasa *"account takeover"* di sini penting — ini bukan sekadar risiko kebocoran privasi pasif, melainkan **jalur eskalasi langsung** menuju kompromi akun penuh, bila token/kode OTP yang terekspos dapat dipakai penyerang untuk mengautentikasi diri sebagai korban.

### 1.3 Cara Mengekspos Extras yang Lebih Luas dari Sekadar putExtra

Overview mendaftar beberapa API penambahan extras yang berbeda, bukan hanya `putExtra`:

> *"Relevant patterns include creating an Intent with an action, adding extras with `putExtra`, `putExtras`, `replaceExtras`, or a `Bundle`."*

Perbedaan `putExtra` vs `putExtras`/`replaceExtras` penting dari segi analisis — `putExtras(Bundle)`/`replaceExtras(Bundle)` menerima **seluruh `Bundle` yang sudah terbentuk di tempat lain**, yang berarti isinya **tidak selalu terlihat langsung** di lokasi pemanggilan; penguji harus melacak balik ke mana `Bundle` tersebut dibangun untuk menilai sensitivitas datanya, berbeda dari `putExtra(key, value)` yang biasanya menampilkan key-value secara langsung di baris kode yang sama.

### 1.4 Temuan Analitis: Rule Resmi Memiliki Dua Jenis Masalah Berbeda

Rule `mastg-android-implicit-intent-leaking-extras.yml` memiliki kesenjangan cakupan yang **mirip** dengan TEST-0372 (hanya `startActivity` + `putExtra`, hanya Java, melewatkan `startService`/`bindService`/`sendBroadcast`/`startActivityForResult`/`ActivityResultLauncher.launch` dan `putExtras`/`replaceExtras`), namun test ini punya **masalah tambahan yang berbeda arah**:

```yaml
patterns:
  - pattern: |
      $I = new Intent(...);
      ...
      $I.putExtra($KEY, $VAL);
      ...
      $CTX.startActivity($I);
  # pattern-not untuk explicit constructor/setPackage/setComponent
```

Rule ini **tidak membedakan sama sekali** antara action internal kustom (`"com.example.app.SYNC"`) dan action standar sistem yang memang dirancang untuk delegasi eksternal (`Intent.ACTION_SEND`). Ini berarti rule akan **ikut menandai** pola `ACTION_SEND` + `putExtra` yang sepenuhnya legitimate (mis. berbagi teks biasa ke aplikasi chat pilihan pengguna) sebagai "WARNING", menciptakan potensi **false positive volume tinggi** pada aplikasi yang banyak memakai fitur share standar — berlawanan arah dengan kesenjangan cakupan (false negative) yang dominan ditemukan pada rule-rule lain dalam seri riset ini. Evaluasi resmi sendiri mengakui perlunya langkah penyaringan manual untuk ini:

> *"Check whether the dispatch is an intentional user-selected share/open flow, such as ACTION_SEND or a chooser."*

Ini menegaskan bahwa untuk test ini, **penyaringan false positive** (bukan hanya menutup false negative seperti test-test lain) adalah bagian penting dari pekerjaan manual yang tidak bisa dihindari.

### 1.5 Bukti Nyata Paling Signifikan dalam Seri Riset Ini: CVE-2014-8889 "DroppedIn" pada Dropbox SDK

Ini adalah salah satu bukti nyata paling kuat yang ditemukan sepanjang seri riset — kerentanan pada **SDK resmi Dropbox** sendiri (bukan aplikasi niche), yang berarti **setiap aplikasi pihak ketiga** yang mengintegrasikan SDK tersebut (versi 1.5.4–1.6.1) otomatis ikut terpengaruh:

> *"IBM discovered a vulnerability in the Dropbox SDK for Android, identified as CVE-2014-8889, known as the 'DroppedIn' vulnerability. The vulnerability involves the consumption of an Intent extra parameter named INTERNAL_WEB_HOST, which can be controlled by the attacker. An attacker can determine which web host the mobile browser surfs to when authenticating to Dropbox by manipulating this parameter... lets adversaries insert an arbitrary access token into the Dropbox SDK, completely bypassing the nonce protection."*

Vektor serangannya terdokumentasi mencakup skenario lokal **dan** remote:

> *"The vulnerability can be exploited in two ways: using a malicious application installed on the users' device or remotely using malicious links to drive-by download websites."*

Ini secara persis mengilustrasikan risiko "account takeover" yang disebut overview (§1.2) — dengan memanipulasi extra `INTERNAL_WEB_HOST` yang diteruskan lewat intent, penyerang bisa menyisipkan access token palsu yang kemudian diterima SDK sebagai token sah milik korban, sepenuhnya melewati mekanisme nonce yang dirancang untuk mencegah hal tersebut.

Kasus umum terkait OAuth token redirect via implicit intent juga terdokumentasi secara lebih luas:

> *"If an implicit intent handling sensitive data passes a session token within an extra URL string to open a WebView, any application specifying the proper intent filters can read this token... OAuth tokens can be returned via an implicit Intent targeting an app's unique URI scheme, creating a threat of stealing the returned OAuth access token."*

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | Fungsi |
|---|---|
| **jadx** | Dekompilasi DEX → Java/Kotlin |
| **Semgrep** + rule resmi | Deteksi dasar `startActivity` + `putExtra` (cakupan terbatas dua arah, §1.4) |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **grep/ripgrep** | **Wajib** — menutup celah API dispatch lain, `putExtras`/`replaceExtras`, dan kode Kotlin |

### 2.3 Prasyarat Lingkungan

- Tidak butuh device/root — murni analisis statis.
- Siapkan daftar kata kunci nama key extras yang umum menandakan data sensitif (`token`, `password`, `otp`, `session`, `auth`) untuk mempercepat triase.

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0013** untuk reverse engineer aplikasi.
2. Gunakan **MASTG-TECH-0014** untuk mencari API yang relevan.

### 3.2 Metode A — Semgrep dengan Rule Resmi

```bash
semgrep --config mastg-android-implicit-intent-leaking-extras.yml ./decompiled/sources
```

**Catatan wajib:** verifikasi manual setiap hasil untuk menyaring false positive dari `ACTION_SEND`/chooser yang sah (§1.4).

### 3.3 Metode B — grep/ripgrep untuk Cakupan Lengkap dan Triase Nama Key Sensitif

```bash
D=./decompiled/sources

# Seluruh API penambahan extras, termasuk yang tidak tercakup rule resmi
rg -n '\.putExtra\(|\.putExtras\(|\.replaceExtras\(' $D

# Triase cepat berdasarkan nama key yang mengindikasikan sensitivitas
rg -n 'putExtra\("[^"]*(token|password|otp|session|auth|secret|key)[^"]*"' $D -i

# Lima API dispatch lain yang tidak tercakup rule resmi (sama seperti TEST-0372)
rg -n '\.startService\(|\.bindService\(|\.sendBroadcast\(|\.startActivityForResult\(' $D
```

### 3.4 Metode C — Review Manual untuk Membedakan Share Flow Sah vs Internal (Wajib)

Untuk setiap hasil Metode A/B:

1. Apakah action-nya `ACTION_SEND`/`ACTION_SENDTO`/chooser standar (kemungkinan sah, §1.4)?
2. Apakah key extras mengindikasikan data sensitif (token, kredensial, OTP)?
3. Lacak balik sumber nilai `putExtras(Bundle)`/`replaceExtras(Bundle)` bila dipakai, untuk menemukan isi sesungguhnya.

### 3.5 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Kapan dipakai |
|---|---|---|
| **A** | Semgrep + rule resmi | Baseline, perlu penyaringan manual (false positive) |
| **B** | grep/ripgrep manual | **Wajib** — cakupan lengkap + triase nama key |
| **C** | Review manual | **Wajib** — membedakan share flow sah vs kebocoran sesungguhnya |

**Kombinasi minimum yang aku rekomendasikan:** **B (baseline sesungguhnya) → C (wajib)**.

---

### 3.6 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG:**

> **Evaluation:** *"The test case fails if an implicit intent carries sensitive or security-relevant extras and another app can declare or register a matching component to receive them."*

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi |
|---|---|
| F1 | Implicit intent membawa extras yang mengandung kredensial/token/OTP/data personal/account identifier, **dan** bukan intent yang explicit (tanpa `setPackage`/`setComponent`) |

**Contoh bukti (merefleksikan pola nyata CVE-2014-8889 §1.5):**

```java
Intent intent = new Intent("com.example.app.AUTH_CALLBACK");
intent.putExtra("access_token", sessionToken);
intent.putExtra("web_host", userControlledHost); // juga rentan manipulasi, pola DroppedIn
sendBroadcast(intent); // implicit, tidak tercakup rule resmi (hanya startActivity)
```

**FAIL** — token sesi dapat diintersep aplikasi mana pun yang mendaftarkan receiver dengan action yang sama.

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi |
|---|---|
| P1 | Intent yang membawa data sensitif memakai `setPackage`/`setComponent`/konstruktor explicit, **atau** |
| P2 | Intent implicit memang `ACTION_SEND`/chooser yang sah **dan** extras-nya terverifikasi hanya berisi konten yang memang dimaksudkan pengguna untuk dibagikan (bukan token/kredensial internal) |

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Lakukan penyaringan false positive secara aktif** — berbeda dari kebanyakan test lain dalam seri riset ini yang rule-nya under-match, rule ini berpotensi over-match pada share flow sah; jangan langsung melaporkan seluruh hasil Semgrep sebagai temuan.

2. **Lacak balik `putExtras(Bundle)`/`replaceExtras(Bundle)`** — isi sesungguhnya seringkali tidak terlihat langsung di lokasi pemanggilan (§1.3).

3. **Waspadai parameter konfigurasi yang bisa disalahgunakan**, bukan hanya data kredensial langsung — sesuai kasus DroppedIn (§1.5), extra yang terlihat tidak sensitif (`web_host`) justru menjadi vektor serangan nyata ketika dikombinasikan dengan logika yang mempercayainya tanpa validasi.

4. **Severity dimodulasi:**

   | Faktor | Severity |
   |---|---|
   | Token/kredensial/OTP terbawa implicit intent, berpotensi account takeover | **Tinggi** |
   | Data personal non-kredensial terbawa implicit intent | **Sedang** |
   | Share flow sah (ACTION_SEND) dengan konten yang memang dimaksudkan dibagikan pengguna | **Bukan temuan** |

5. **Dokumentasikan:** lokasi kode, action, key dan nilai extras (redaksi bila perlu), API dispatch, ada/tidaknya `setPackage`/`setComponent`, dan klasifikasi apakah ini share flow sah atau kebocoran.

---

## 4. Rekomendasi Perbaikan

### 4.1 Gunakan Explicit Intent untuk Data Sensitif (Sesuai MASTG-BEST-0056)

```java
// SEBELUM — implicit, token bisa diintersep
Intent intent = new Intent("com.example.app.AUTH_CALLBACK");
intent.putExtra("access_token", sessionToken);
sendBroadcast(intent);

// SESUDAH — explicit, hanya diterima komponen yang dituju
Intent intent = new Intent(context, AuthCallbackReceiver.class);
intent.putExtra("access_token", sessionToken);
context.sendBroadcast(intent); // atau LocalBroadcastManager/alternatif modern untuk komunikasi in-app
```

### 4.2 Checklist Remediasi

- [ ] Seluruh intent yang membawa data sensitif memakai `setComponent`/konstruktor explicit atau minimal `setPackage`
- [ ] Verifikasi mencakup `putExtras`/`replaceExtras`, tidak hanya `putExtra`
- [ ] Share flow sah (ACTION_SEND) diverifikasi tidak membawa token/kredensial internal
- [ ] Parameter konfigurasi yang diteruskan via intent (seperti kasus DroppedIn) divalidasi, tidak dipercaya mentah dari extras

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0374 (source, tests-beta)](https://github.com/OWASP/mastg/blob/master/tests-beta/android/MASVS-CODE/MASTG-TEST-0374.md)
- [MASTG-TEST-0372 (dokumen terkait dalam seri riset ini)](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0372/)
- [MASTG-KNOW-0025: Explicit vs Implicit Intents](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0025/)
- [MASTG-BEST-0056: Use Explicit Intents for Internal IPC](https://github.com/OWASP/mastg/blob/master/best-practices/MASTG-BEST-0056.md)

### 5.2 Riset dan Kasus Nyata

- [SecurityWeek: Dropbox Android SDK Flaw Exposes Mobile Users to Attack (CVE-2014-8889 "DroppedIn")](https://www.securityweek.com/dropbox-android-sdk-flaw-exposes-mobile-users-attack-ibm/)
- [Full Disclosure: Vulnerability in the Dropbox SDK for Android (CVE-2014-8889)](https://seclists.org/fulldisclosure/2015/Mar/61)
- [Android Developers: Implicit Intent Hijacking](https://developer.android.com/privacy-and-security/risks/implicit-intent-hijacking)
- [Ostorlab: One Scheme to Rule Them All — OAuth Account Takeover](https://blog.ostorlab.co/one-scheme-to-rule-them-all.html)

### 5.3 Dokumentasi Tools

- [Semgrep Documentation](https://semgrep.dev/docs/)

---

*Dokumen ini disusun berdasarkan konten resmi OWASP MASTG (`tests-beta/android/MASVS-CODE/MASTG-TEST-0374.md`, `MASTG-KNOW-0025`, `MASTG-BEST-0056`), analisis rule `mastg-android-implicit-intent-leaking-extras.yml`, serta salah satu bukti nyata paling kuat dalam seri riset ini: CVE-2014-8889 "DroppedIn" pada Dropbox SDK resmi, yang memungkinkan penyisipan access token palsu via manipulasi extra `INTERNAL_WEB_HOST`, berdampak pada setiap aplikasi pihak ketiga yang mengintegrasikan SDK versi rentan. Nuansa metodologis terpenting dan unik untuk test ini: berbeda dari kebanyakan rule lain dalam seri riset yang cenderung under-match (false negative), rule resmi test ini juga berisiko **over-match** pada share flow sah (`ACTION_SEND`) karena tidak membedakan action internal dari action delegasi eksternal yang legitimate — penyaringan false positive adalah bagian pekerjaan manual yang sama pentingnya dengan menutup celah cakupan.*
