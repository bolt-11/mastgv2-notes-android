# MASTG-TEST-0366 Exported And Unprotected Broadcast Receivers That Expose Sensitive Functionality

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0366 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-PLATFORM |
| **Weakness** | MASWE-0018 |
| **Tipe Pengujian** | Static, Config, Code, **Manual** |
| **Teknik terkait** | MASTG-TECH-0013, MASTG-TECH-0117, MASTG-TECH-0162 (Enumerating Broadcast Receivers), MASTG-TECH-0014, MASTG-TECH-0023 |
| **Knowledge terkait** | MASTG-KNOW-0134 (Android Broadcast Receivers), MASTG-KNOW-0017, MASTG-KNOW-0020 |
| **Best Practice terkait** | MASTG-BEST-0052 |
| **Test terkait** | **MASTG-TEST-0364/0365** — pola metodologi yang identik untuk Activity dan Service; dokumen ini menyasar komponen **Broadcast Receiver**, dengan nuansa tambahan untuk context-registered receiver (§1.2) |
| **Rule resmi** | — (tidak ada; murni manual, konsisten dengan pola TEST-0364/0365) |

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian

Kutipan overview resmi MASTG:

> *"If an exported receiver does not define `android:permission` with a proper protection level and performs or grants access to sensitive functionality, another third-party app outside the intended trust boundary can send a broadcast to it and invoke that functionality."*

Ini adalah test ketiga dalam rangkaian "exported component" dalam seri riset ini (setelah Activity/TEST-0364 dan Service/TEST-0365). Pola evaluasinya identik secara struktural, namun Broadcast Receiver membawa satu nuansa unik yang **tidak dimiliki** Activity maupun Service: kemungkinan didaftarkan **secara dinamis di kode**, bukan hanya di manifest.

### 1.2 Nuansa Unik: Context-Registered Receiver Tidak Muncul di Manifest Sama Sekali

Ini adalah pembeda paling signifikan dari dua test sebelumnya. MASTG-TECH-0162 menegaskan secara eksplisit:

> *"Note that context-registered receivers (registered at runtime with Context.registerReceiver) don't appear in the manifest and require code or runtime analysis."*

Artinya **enumerasi manifest saja tidak cukup** untuk test ini — berbeda dari TEST-0364/0365 di mana manifest adalah sumber kebenaran utama. Receiver yang didaftarkan lewat `registerReceiver()` di dalam kode (misalnya di `onCreate()` sebuah `Activity` atau `Service`) sepenuhnya **tidak terlihat** dalam audit manifest-only, dan baru bisa ditemukan lewat pencarian kode langsung terhadap pemanggilan `registerReceiver`/`ContextCompat.registerReceiver`.

Kontrol akses untuk context-registered receiver juga berbeda mekanismenya — bukan atribut XML, melainkan **parameter fungsi**:

> *"`flags`: controls whether the receiver can receive broadcasts from other apps. Use RECEIVER_EXPORTED when the receiver needs to receive broadcasts from other apps, and use RECEIVER_NOT_EXPORTED when it should receive broadcasts only from the same app... Since Android 14 (API level 34), apps targeting Android 14 or higher must explicitly specify the runtime export flags."*
>
> *"`broadcastPermission`: requires the sender to hold the named permission before the broadcast is delivered to the receiver. If broadcastPermission is null, no sender permission is required."*

Ini berarti penguji harus memeriksa **dua jenis sumber berbeda** untuk cakupan yang lengkap: elemen `<receiver>` di manifest, **dan** setiap pemanggilan `registerReceiver()` di kode — masing-masing dengan mekanisme kontrol akses dan API yang berbeda.

### 1.3 Sticky Broadcast: Mekanisme Lama Tanpa Kontrol Akses Sama Sekali

MASTG-KNOW-0134 menyebutkan satu detail historis yang relevan untuk aplikasi legacy:

> *"Sticky broadcasts, sent with the deprecated sendStickyBroadcast family of methods, persist after delivery and offer no access control."*

Meski API ini sudah deprecated, aplikasi lama yang masih memakainya (atau yang memakai library pihak ketiga lama) berpotensi memiliki broadcast yang **secara desain tidak memiliki mekanisme kontrol akses apa pun** — relevan untuk diperiksa pada aplikasi dengan basis kode yang sudah berumur panjang.

### 1.4 Dua Kriteria Validasi yang Spesifik untuk Receiver: Isi Intent dan Validasi Data

Berbeda sedikit dari TEST-0364/0365, validasi lanjutan untuk receiver menitikberatkan pada **bagaimana data dari Intent yang masuk diproses**:

> *"Determine whether `onReceive` performs a security-relevant action or discloses sensitive data based on the received intent (for example, reading extras and using them to send a message or change state). Determine whether the receiver validates the data it reads from the intent before acting on it."*

Ini menegaskan bahwa risiko bukan hanya "siapa yang bisa memanggil", tapi juga **apa yang dilakukan dengan isi** `Intent` yang diterima — `onReceive()` yang membaca `extras` lalu langsung memakainya untuk memicu aksi tanpa validasi adalah pola risiko yang spesifik untuk komponen ini, karena `onReceive()` secara desain **menerima data arbitrer** dari pengirim yang (bila exported tanpa kontrol) sepenuhnya tidak tepercaya.

### 1.5 Bukti Nyata: Ekstraksi Nomor Telepon dan Password Langsung dari Intent Extras

Riset pentest mendokumentasikan kasus nyata yang persis mengilustrasikan risiko di §1.4:

> *"MyBroadCastReceiver processes actions with name theBroadcast, is exported and not protected by a permission. Parameters are retrieved from the Intent including phone numbers and passwords."*

Kasus ini menunjukkan pola klasik: receiver yang dirancang untuk menerima data konfigurasi/kredensial dari komponen internal aplikasi, namun karena diekspor tanpa permission, **data sensitif yang sama bisa disuntikkan oleh aplikasi berbahaya mana pun** — baik untuk membaca nilai yang sudah ada (bila receiver mengembalikan sesuatu) atau untuk **menimpa** nilai kredensial yang tersimpan dengan nilai yang dikontrol penyerang.

Kasus lain menunjukkan risiko yang relevan bahkan pada library pihak ketiga populer:

> *"A third-party library, @voximplant/react-native-foreground-service, was found to register the receiver as exported, meaning any app, including malicious ones, can trigger the event."*

Dan pada tingkat kerentanan sistem Android sendiri, **CVE-2024-27207** (CVSS 9.1, Critical) menunjukkan bahwa kelas kerentanan ini relevan bahkan di komponen framework inti:

> *"Exported broadcast receivers allowing malicious apps to bypass broadcast protection."*

Severity CVSS 9.1 untuk kerentanan di level framework ini menegaskan betapa seriusnya kategori risiko ini secara umum, meski kerentanan spesifik tersebut berada di luar scope aplikasi individual yang diaudit dengan test ini.

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | Fungsi |
|---|---|
| **aapt2 / xmlstarlet** | Enumerasi receiver manifest-declared (MASTG-TECH-0162) |
| **grep/ripgrep** | **Wajib** — mencari pemanggilan `registerReceiver()` untuk context-registered receiver yang tidak muncul di manifest (§1.2) |
| **jadx** | Review implementasi `onReceive()` (MASTG-TECH-0014, MASTG-TECH-0023) |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **ADB (`am broadcast`)** | Verifikasi dinamis langsung — mengirim broadcast dengan extras yang dikontrol penguji |
| **Drozer** | Enumerasi dan pengiriman broadcast otomatis (`app.broadcast.info`, `app.broadcast.send`) |
| **`adb shell dumpsys activity broadcasts`** | Inspeksi broadcast terbaru (tanpa extras) untuk konteks tambahan |

### 2.3 Prasyarat Lingkungan

- Analisis statis manifest tidak butuh device/root, **namun** analisis kode untuk context-registered receiver tetap diperlukan (§1.2).
- Verifikasi dinamis butuh device/emulator dengan aplikasi target terinstal.

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0013** untuk reverse engineer aplikasi.
2. Gunakan **MASTG-TECH-0117** untuk memperoleh `AndroidManifest.xml`.
3. Gunakan **MASTG-TECH-0162** untuk mendaftar receiver exported **termasuk context-registered receiver** di kode.
4. Gunakan **MASTG-TECH-0014** untuk memeriksa implementasi `onReceive` setiap receiver exported.

### 3.2 Metode A — Enumerasi Manifest dengan xmlstarlet

```bash
xmlstarlet sel -t -m "//receiver" \
  -v "@android:name" -o " exported=" -v "@android:exported" \
  -o " permission=" -v "@android:permission" \
  -o " intent_filters=" -v "count(intent-filter)" -n \
  AndroidManifest.xml
```

### 3.3 Metode B — Pencarian Context-Registered Receiver di Kode (Wajib, §1.2)

```bash
D=./decompiled/sources

# Cari seluruh pemanggilan registerReceiver
rg -n 'registerReceiver\(|ContextCompat\.registerReceiver\(' $D

# Verifikasi flag yang dipakai
rg -n 'RECEIVER_EXPORTED|RECEIVER_NOT_EXPORTED' $D

# Cari penggunaan sticky broadcast lama (§1.3)
rg -n 'sendStickyBroadcast' $D
```

### 3.4 Metode C — Review onReceive() untuk Validasi Data Intent (Wajib, §1.4)

Untuk setiap receiver exported yang teridentifikasi:

1. Periksa apakah `onReceive()` membaca `intent.getExtras()`/`intent.getStringExtra()` dsb.
2. Lacak apakah nilai tersebut dipakai langsung untuk memicu aksi (kirim SMS, ubah setting, simpan kredensial) tanpa validasi tipe/format/sumber.

### 3.5 Metode D — Verifikasi Dinamis via ADB

```bash
adb shell am broadcast -a com.example.app.ACTION_UPDATE_CONFIG \
  --es "api_key" "attacker_controlled_value"
```

### 3.6 Metode E — Drozer untuk Enumerasi dan Pengiriman Otomatis

```bash
dz> run app.broadcast.info -a com.example.app
dz> run app.broadcast.send --action com.example.app.ACTION_UPDATE_CONFIG --extra string api_key "malicious_value"
```

### 3.7 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Kapan dipakai |
|---|---|---|
| **A** | xmlstarlet/aapt2 | Baseline wajib — receiver manifest-declared |
| **B** | grep/ripgrep | **Wajib** — menutup celah context-registered receiver yang tidak di manifest |
| **C** | Review manual | **Wajib** — menilai validasi data Intent |
| **D/E** | ADB/Drozer | Verifikasi dinamis konklusif |

**Kombinasi minimum yang aku rekomendasikan:** **A + B (wajib, cakupan lengkap) → C (wajib) → D/E (verifikasi)**.

---

### 3.8 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG:**

> **Evaluation:** *"The test case fails if any exported broadcast receiver is not protected by an appropriate android:permission that restricts which apps can send broadcasts to it and exposes or performs sensitive functionality."*

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi |
|---|---|
| F1 | Receiver exported (manifest **atau** context-registered dengan `RECEIVER_EXPORTED`) tanpa permission memadai, **dan** `onReceive()` melakukan aksi sensitif berdasarkan data Intent tanpa validasi |

**Contoh bukti (merefleksikan kasus nyata §1.5):**

```xml
<receiver android:name=".ConfigReceiver" android:exported="true">
    <intent-filter><action android:name="com.example.app.UPDATE_CONFIG" /></intent-filter>
</receiver>
```

```java
public void onReceive(Context context, Intent intent) {
    String apiKey = intent.getStringExtra("api_key"); // tidak divalidasi
    SharedPreferences.Editor editor = prefs.edit();
    editor.putString("api_key", apiKey).apply(); // langsung disimpan
}
```

**FAIL** — aplikasi mana pun dapat menimpa `api_key` tersimpan tanpa otorisasi apa pun.

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi |
|---|---|
| P1 | Receiver tidak perlu diakses eksternal, diset `exported="false"` (manifest) atau `RECEIVER_NOT_EXPORTED` (context-registered), **atau** |
| P2 | Receiver exported dengan `android:permission`/`broadcastPermission` berprotectionLevel `signature`, **dan** |
| P3 | `onReceive()` memvalidasi data Intent sebelum dipakai untuk aksi sensitif |

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Jangan hanya mengandalkan audit manifest** — sesuai §1.2, context-registered receiver sepenuhnya tidak terlihat di sana; pencarian kode terhadap `registerReceiver()` adalah langkah wajib yang tidak dapat digantikan.

2. **Periksa flag runtime untuk context-registered receiver secara spesifik** — `RECEIVER_EXPORTED` vs `RECEIVER_NOT_EXPORTED`, dan `broadcastPermission` yang diteruskan (bukan `null`).

3. **Validasi data Intent sama pentingnya dengan kontrol akses komponen** — sesuai §1.4, bahkan receiver yang "sengaja" diekspor untuk tujuan sah tetap harus memvalidasi isi `extras` sebelum dipakai untuk aksi sensitif.

4. **Severity dimodulasi:**

   | Faktor | Severity |
   |---|---|
   | Receiver memungkinkan mengubah kredensial/state keamanan tanpa validasi/otorisasi | **Tinggi** |
   | Receiver mengekspos data sensitif tanpa validasi/otorisasi | **Sedang-Tinggi** |
   | Permission ada namun `protectionLevel` lemah, atau tidak ada validasi data Intent | **Sedang** |
   | Non-exported/`RECEIVER_NOT_EXPORTED`, atau `signature` + validasi data lengkap | **Bukan temuan** |

5. **Dokumentasikan:** nama receiver, jenis (manifest/context-registered), status exported/flag, permission dan protectionLevel, hasil review `onReceive()`, dan hasil verifikasi dinamis.

---

## 4. Rekomendasi Perbaikan

### 4.1 Non-Exported Bila Tidak Perlu (Manifest dan Context-Registered)

```xml
<receiver android:name=".ConfigReceiver" android:exported="false" />
```

```java
ContextCompat.registerReceiver(context, receiver, filter, ContextCompat.RECEIVER_NOT_EXPORTED);
```

### 4.2 Permission Signature untuk Akses Eksternal yang Memang Diperlukan

```xml
<receiver
    android:name=".PartnerNotifyReceiver"
    android:exported="true"
    android:permission="com.example.app.permission.TRUSTED_PARTNER" />
```

### 4.3 Validasi Data Intent Sebelum Digunakan

```java
public void onReceive(Context context, Intent intent) {
    String apiKey = intent.getStringExtra("api_key");
    if (apiKey == null || !apiKey.matches("^[A-Za-z0-9]{32}$")) {
        return; // tolak nilai yang tidak sesuai format
    }
    // lanjutkan proses
}
```

### 4.4 Checklist Remediasi

- [ ] Seluruh receiver manifest DAN context-registered dievaluasi kebutuhan ekspornya
- [ ] Receiver yang tidak perlu diekspor diset `exported="false"`/`RECEIVER_NOT_EXPORTED`
- [ ] Receiver exported yang diperlukan dilindungi permission `signature`
- [ ] `onReceive()` memvalidasi seluruh data dari Intent sebelum memicu aksi
- [ ] Tidak ada penggunaan `sendStickyBroadcast` (deprecated, tanpa kontrol akses)
- [ ] Diverifikasi secara dinamis dengan `adb shell am broadcast`/Drozer

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0366 (source, tests-beta)](https://github.com/OWASP/mastg/blob/master/tests-beta/android/MASVS-PLATFORM/MASTG-TEST-0366.md)
- [MASTG-TEST-0364/0365 (dokumen terkait dalam seri riset ini)](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0364/)
- [MASTG-KNOW-0134: Android Broadcast Receivers](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0134/)
- [MASTG-BEST-0052: Restrict Access to Android App Components](https://github.com/OWASP/mastg/blob/master/best-practices/MASTG-BEST-0052.md)
- [MASTG-TECH-0162: Enumerating Broadcast Receivers](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0162/)

### 5.2 Riset dan Kasus Nyata

- [Android Developers: Insecure Broadcast Receivers](https://developer.android.com/privacy-and-security/risks/insecure-broadcast-receiver)
- [GitHub Advisory: CVE-2024-20853 — ThemeStore Broadcast Receiver Arbitrary File Write](https://github.com/advisories/GHSA-j4j9-wc5g-p586)
- [CyberStrike: CVE-2024-27207 — Android Exported Broadcast Receiver Bypass (CVSS 9.1)](https://cyberstrike.io/cve/CVE-2024-27207/)
- [Mattermost: Investigating and Mitigating Security Risks in a React Native App](https://mattermost.com/blog/mitigating-broadcast-receiver-security-risks-in-a-react-native-app/)
- [CWE-925: Improper Verification of Intent by Broadcast Receiver](https://cwe.mitre.org/data/definitions/925.html)

### 5.3 Dokumentasi Tools

- [Drozer — Android Security Assessment Framework](https://github.com/WithSecureLabs/drozer)
- [Android Developers: Broadcasts Overview](https://developer.android.com/guide/components/broadcasts)

---

*Dokumen ini disusun berdasarkan konten resmi OWASP MASTG (`tests-beta/android/MASVS-PLATFORM/MASTG-TEST-0366.md`, `MASTG-KNOW-0134/0017/0020`, `MASTG-BEST-0052`), serta riset komunitas yang mendokumentasikan kasus nyata ekstraksi nomor telepon dan password via broadcast receiver exported tanpa permission, kerentanan pada library pihak ketiga populer (`@voximplant/react-native-foreground-service`), dan CVE kritis di level framework Android (CVE-2024-27207, CVSS 9.1). Nuansa metodologis terpenting dibanding TEST-0364/0365: Broadcast Receiver dapat didaftarkan secara dinamis via `registerReceiver()` di kode, sepenuhnya tidak terlihat dalam audit manifest-only — pencarian kode untuk context-registered receiver dan pemeriksaan flag `RECEIVER_EXPORTED`/`RECEIVER_NOT_EXPORTED` adalah langkah wajib yang unik untuk kelas komponen ini, di luar cakupan yang sudah memadai untuk Activity dan Service.*
