# MASTG-TEST-0287 Runtime Storage of Unencrypted Data via the SharedPreferences API

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0287 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-STORAGE (MASVS-STORAGE-1) |
| **Weakness** | MASWE-0001 — *Sensitive Data Stored Unencrypted in Private Storage* |
| **API yang disorot** | `SharedPreferences.Editor.putString(...)`, `putStringSet(...)`, dan `put*` lainnya; API kriptografi terkait: `javax.crypto.Cipher`, `java.security.KeyStore`, `javax.crypto.KeyGenerator` |
| **Tipe Pengujian** | **Dynamic, Hooks, Manual** |
| **Prasyarat** | `identify-sensitive-data` |
| **Knowledge** | MASTG-KNOW-0036 (Shared Preferences) |
| **Best Practice** | MASTG-BEST-0050 |
| **Teknik terkait** | MASTG-TECH-0005 (Install App), MASTG-TECH-0043 (Method Hooking), MASTG-TECH-0008 (Retrieving Files/Data Directory), MASTG-TECH-0023 (Reviewing Decompiled Java Code) |
| **Test terkait** | **MASTG-TEST-0207** (Runtime Storage of Unencrypted Data in the App Sandbox) — pendekatan **filesystem diff generik** yang menangkap file apa pun terlepas API yang menulisnya; test ini adalah **versi API-spesifik** yang menyasar `SharedPreferences` secara langsung lewat hooking |
| **Demo terkait** | — (tidak ada) |
| **Rule resmi** | — (tidak relevan; test dinamis berbasis hooking) |
| **CWE terkait** | CWE-312 (Cleartext Storage of Sensitive Information), CWE-311 |

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian dan Hubungannya dengan MASTG-TEST-0207

Kutipan overview resmi MASTG:

> *"This test uses runtime instrumentation to detect when the app writes data via `SharedPreferences` and determines whether sensitive data is being stored unencrypted."*

Test ini adalah **versi API-spesifik** dari pendekatan yang lebih generik pada **MASTG-TEST-0207** (yang sudah dibahas dalam seri riset ini, bagian dari trio pengujian eksternal storage bersama MASTG-TEST-0200/0201/0202) — namun dengan filosofi metodologis yang berbeda:

| | MASTG-TEST-0207 | MASTG-TEST-0287 *(dokumen ini)* |
|---|---|---|
| **Pendekatan** | **Filesystem diff** — snapshot direktori data sebelum/sesudah, cari perubahan | **API hooking langsung** — instrumentasi pada `SharedPreferences.Editor.put*()` |
| **Cakupan** | Seluruh file apa pun yang berubah, **terlepas API penulisnya** | Spesifik hanya jalur `SharedPreferences` |
| **Nilai unik** | Menangkap kebocoran lewat mekanisme penyimpanan **apa pun** (file custom, database, cache) | Memberi **stack trace presisi** ke lokasi kode yang menulis, dan dapat mengorelasikan dengan pemanggilan `Cipher` di sekitar penulisan tersebut |

Kedua test **saling melengkapi**, bukan duplikat: MASTG-TEST-0207 memberi jaring pengaman luas (menangkap kebocoran di mekanisme penyimpanan apa pun), sementara MASTG-TEST-0287 memberi **presisi diagnostik** khusus untuk `SharedPreferences` — API penyimpanan yang secara statistik menjadi salah satu lokasi paling umum ditemukannya kebocoran kredensial pada aplikasi Android karena kemudahan penggunaannya bagi developer.

### 1.2 Mengapa `MODE_PRIVATE` Bukan Jaminan Keamanan

Poin konseptual paling penting dari overview resmi, dan seringkali disalahpahami sebagai "sudah cukup aman" oleh developer:

> *"While `MODE_PRIVATE` restricts file access to the app itself, it doesn't protect the data from being read by attackers who gain access to the device's file system (for example, through device compromise, backup extraction, or physical access to rooted/unlocked devices)."*

`MODE_PRIVATE` bekerja pada **lapisan izin filesystem Linux standar** — ia mencegah **aplikasi lain** (dengan UID Linux berbeda) membaca file tersebut dalam kondisi normal. Namun ini **sama sekali tidak setara** dengan enkripsi — bagi penyerang yang sudah punya akses **root**, akses **fisik ke device yang tidak terkunci**, atau kemampuan **mengekstrak backup** (rujuk pembahasan mendalam soal skema backup di dokumen MASTG-TEST-0216/0262 dalam seri riset ini), isi file `shared_prefs/*.xml` tetap **dapat dibaca langsung sebagai plaintext** tanpa hambatan tambahan apa pun. Sesuai contoh konkret dari MASTG-KNOW-0036:

```xml
<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
  <string name="username">administrator</string>
  <string name="password">supersecret</string>
</map>
```

Kredensial ini tersimpan **sepenuhnya dalam bentuk teks yang dapat dibaca manusia** — `MODE_PRIVATE` tidak memberi lapisan obfuscation atau enkripsi apa pun terhadap **isi** file, hanya mengontrol **siapa** yang secara normal diizinkan membacanya di level sistem operasi.

### 1.3 Peringatan Penting: `EncryptedSharedPreferences` Sudah Deprecated

Ini temuan penting yang perlu diketahui penguji saat menilai mitigasi yang mungkin sudah diterapkan aplikasi. MASTG-KNOW-0036 memberi peringatan eksplisit:

> *"The Jetpack Security Crypto library, including the `EncryptedFile` and `EncryptedSharedPreferences` classes, has been deprecated. All APIs in the library were deprecated in stable version `1.1.0`, and Android states that there will be no subsequent releases."*

Ini menciptakan **dilema transisi** bagi tim developer: `EncryptedSharedPreferences` (yang mengenkripsi key dengan `AES256_SIV` dan value dengan `AES256_GCM`) selama bertahun-tahun menjadi **solusi rekomendasi utama** untuk masalah yang diuji test ini — namun kini statusnya deprecated tanpa pengganti langsung yang setara kemudahannya. Panduan resmi menyarankan:

> *"For existing apps that must continue using `SharedPreferences` for sensitive data, `EncryptedSharedPreferences` may still be a practical mitigation, but it should not be treated as a long term storage strategy... plan a migration to a supported encryption approach when available."*

Bagi penguji, ini berarti: **menemukan `EncryptedSharedPreferences` yang dipakai dengan benar tetap dianggap PASS untuk saat ini** (karena masih menyediakan enkripsi aktual), namun layak dicatat sebagai **catatan teknis-utang** yang perlu dipantau tim developer seiring evolusi rekomendasi Android — bukan solusi permanen. Arah migrasi jangka panjang yang direkomendasikan Android adalah **DataStore** (Jetpack) dikombinasikan dengan enkripsi manual via **Android Keystore** langsung.

### 1.4 Catatan Penting Lain dari MASTG-KNOW-0036: Interaksi dengan Auto Backup

Poin teknis tambahan yang relevan silang dengan dokumen MASTG-TEST-0262 dalam seri riset ini:

> *"When using `EncryptedSharedPreferences`, exclude the encrypted preference file from Auto Backup... restoring the file may fail because the key used to encrypt it might no longer be available."*

Ini bukan soal kebocoran data, melainkan **kegagalan fungsional** — bila file `EncryptedSharedPreferences` ikut ter-backup namun kunci enkripsinya (tersimpan di Android Keystore, yang **tidak** ikut ter-backup ke cloud) tidak tersedia lagi saat restore di device baru, aplikasi akan gagal membaca data tersebut. Ini alasan tambahan mengapa file `EncryptedSharedPreferences` **harus** masuk daftar exclude di `data_extraction_rules.xml`/`backup_rules.xml` — menghubungkan langsung ke evaluasi MASTG-TEST-0262 yang sudah dibahas mendalam sebelumnya.

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | Fungsi |
|---|---|
| **Frida** | Instrumentasi dinamis inti — hooking `SharedPreferences.Editor.put*()` |
| **frida-tools** (`frida-trace`) | Tracing cepat tanpa skrip kustom |
| **objection** | Wrapper Frida siap pakai, memiliki modul bawaan untuk memantau `SharedPreferences` |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **TruffleHog** (MASTG-TOOL-0144) | Pemindaian pola secret (API key, token, kredensial) pada output hasil hooking maupun file `shared_prefs/*.xml` yang diekstrak — kombinasi entropy detection dan regex library luas untuk 800+ jenis kredensial, dengan kemampuan verifikasi langsung terhadap layanan asli (AWS, GitHub, dll.) untuk mengurangi false positive |
| **adb** | Ekstraksi file `shared_prefs/*.xml` (MASTG-TECH-0008) setelah sesi pengujian |
| **apkleaks / gitleaks** | Alternatif pemindaian pola secret, sama seperti dibahas mendalam di dokumen MASTG-TEST-0212 dalam seri riset ini |
| **CodeQL** | Untuk whitebox testing — menelusuri apakah nilai yang di-`putString()` berasal dari variabel yang sebelumnya melalui `Cipher.doFinal()` (indikasi terenkripsi) atau langsung dari input pengguna/API response mentah |

### 2.3 Prasyarat Lingkungan

- **Wajib device/emulator dengan Frida server** — test murni dinamis.
- **Root atau `run-as`** diperlukan untuk mengakses `shared_prefs/*.xml` langsung dari data direktori aplikasi (MASTG-TECH-0008).
- **Interaksi menyeluruh dengan aplikasi**, termasuk memasukkan data sensitif — sesuai instruksi resmi langkah 3: *"exercise the app extensively... enter sensitive data wherever you can"*.
- **Identifikasi data sensitif terlebih dahulu** (prasyarat `identify-sensitive-data`) — memahami jenis data apa yang relevan (kredensial, token, PII) sebelum mulai hooking.

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0005** untuk menginstal aplikasi.
2. Gunakan **MASTG-TECH-0043** untuk melakukan hooking pada pemanggilan API yang relevan.
3. Jelajahi aplikasi secara menyeluruh, masukkan data sensitif di mana pun memungkinkan.
4. Gunakan **MASTG-TECH-0008** untuk mengambil file XML `SharedPreferences` aplikasi.

### 3.2 Metode A — Hooking `SharedPreferences` dengan Korelasi Operasi Kriptografi *(metode utama)*

```javascript
// hook-sharedprefs-writes.js
Java.perform(function () {
    function getBacktrace() {
        return Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());
    }

    var Editor = Java.use("android.content.SharedPreferences$Editor");

    ["putString", "putStringSet"].forEach(function (method) {
        try {
            Editor[method].overloads.forEach(function (overload) {
                overload.implementation = function () {
                    var args = Array.prototype.slice.call(arguments);
                    console.log("\n[*] SharedPreferences.Editor." + method + "(" + args.join(", ") + ")");
                    console.log("    Backtrace:\n" + getBacktrace());
                    return this[method].apply(this, args);
                };
            });
        } catch (e) { console.log("[x] Hook gagal untuk " + method + ": " + e); }
    });

    // Korelasi dengan operasi kriptografi — hook Cipher.doFinal() untuk melihat urutan pemanggilan
    var Cipher = Java.use("javax.crypto.Cipher");
    Cipher.doFinal.overload().implementation = function () {
        console.log("\n[*] Cipher.doFinal() dipanggil (indikasi kemungkinan enkripsi sebelum penyimpanan)");
        console.log("    Backtrace:\n" + getBacktrace());
        return this.doFinal();
    };
});
```

```bash
frida -U -f com.target.app -l hook-sharedprefs-writes.js --no-pause
```

**Analisis urutan pemanggilan (sesuai klausul resmi "High-level trace inspection")**: bandingkan timestamp/urutan antara log `Cipher.doFinal()` dan `putString()` — bila `putString()` terpanggil **tanpa** ada `Cipher.doFinal()` yang mendahuluinya dalam alur yang sama, ini indikasi kuat nilai tersebut ditulis **tanpa enkripsi**.

### 3.3 Metode B — objection (Modul Bawaan untuk SharedPreferences)

```bash
objection -g com.target.app explore
android hooking watch class_method android.content.SharedPreferences$Editor.putString --dump-args --dump-backtrace
```

### 3.4 Metode C — Ekstraksi dan Pemindaian dengan TruffleHog

```bash
# Ekstrak file shared_prefs setelah sesi pengujian
adb shell run-as com.target.app cat /data/data/com.target.app/shared_prefs/*.xml > shared_prefs_dump.txt

# Pindai dengan TruffleHog untuk pola secret yang dikenali
trufflehog filesystem shared_prefs_dump.txt --only-verified
```

```bash
# Alternatif: apkleaks/gitleaks untuk pola tambahan
gitleaks detect --source shared_prefs_dump.txt --no-git
```

### 3.5 Metode D — CodeQL untuk Verifikasi Whitebox (Alur Enkripsi)

```ql
import java

class PutStringCall extends MethodAccess {
  PutStringCall() {
    this.getMethod().hasName(["putString", "putStringSet"]) and
    this.getMethod().getDeclaringType().hasQualifiedName("android.content", "SharedPreferences$Editor")
  }
}

class CipherDoFinalCall extends MethodAccess {
  CipherDoFinalCall() {
    this.getMethod().hasName("doFinal") and
    this.getMethod().getDeclaringType().hasQualifiedName("javax.crypto", "Cipher")
  }
}

from PutStringCall put
where not exists(CipherDoFinalCall cipher | cipher.getEnclosingCallable() = put.getEnclosingCallable())
select put, "putString() ditemukan TANPA pemanggilan Cipher.doFinal() pada method yang sama — kandidat penyimpanan tanpa enkripsi"
```

### 3.6 Metode E — Verifikasi Penggunaan `EncryptedSharedPreferences` (Membedakan Mitigasi yang Sudah Diterapkan)

```bash
rg -n 'EncryptedSharedPreferences\.create\(' ./decompiled/sources/
```

Bila ditemukan, verifikasi konfigurasi `MasterKey`/skema enkripsi yang dipakai sudah sesuai rekomendasi (AES256_SIV untuk key, AES256_GCM untuk value) dan **periksa apakah file terkait sudah dikecualikan dari backup** (§1.4, korelasi dengan MASTG-TEST-0262).

### 3.7 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Memberi stack trace? | Menilai enkripsi? | Kapan dipakai |
|---|---|---|---|---|
| **A** | Hook Frida + korelasi Cipher | ✅ | ✅ (heuristik urutan) | **Baseline utama** |
| **B** | objection | ✅ | ❌ (perlu tambahan manual) | Eksplorasi cepat |
| **C** | TruffleHog/gitleaks pada file XML | ❌ | Tidak langsung (deteksi pola secret) | Konfirmasi isi nyata file |
| **D** | CodeQL | N/A (statis) | ✅ (whitebox) | Codebase besar, whitebox testing |
| **E** | Verifikasi `EncryptedSharedPreferences` | N/A | ✅ (konfirmasi mitigasi ada) | Menilai kualitas mitigasi yang sudah diterapkan |

**Kombinasi minimum yang aku rekomendasikan:** **A (hooking dengan korelasi Cipher) → C (pemindaian isi file nyata dengan TruffleHog)** untuk kesimpulan yang solid, dilengkapi **E** bila ditemukan indikasi enkripsi untuk menilai kualitas implementasinya.

---

### 3.8 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG:**

> **Evaluation:** *"The test case fails if sensitive data is written to `SharedPreferences` without being encrypted first."*

Dengan tiga langkah **Further Validation Required** wajib: inspeksi urutan trace (Cipher mendahului putString atau tidak), pattern matching secret detector, dan verifikasi manual via MASTG-TECH-0023.

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi |
|---|---|
| F1 | `putString()`/`putStringSet()` dipanggil dengan nilai yang mengandung data sensitif (kredensial, token, PII), **tanpa** didahului operasi `Cipher`/enkripsi apa pun |
| F2 | Pemindaian file `shared_prefs/*.xml` hasil ekstraksi dengan TruffleHog/gitleaks **menemukan** pola secret yang terverifikasi |
| F3 | Ditemukan penggunaan enkripsi, namun implementasinya **cacat** (mis. kunci hardcoded — rujuk dokumen MASTG-TEST-0212, atau algoritma lemah — rujuk MASTG-TEST-0221) |

**Contoh bukti (ilustratif — MASTG belum menyediakan demo resmi untuk test ini):**

```
[*] SharedPreferences.Editor.putString(auth_token, eyJhbGciOiJIUzI1NiIs...)
    Backtrace:
        at com.example.target.auth.SessionManager.saveToken(SessionManager.java:34)
```

```bash
$ adb shell run-as com.example.target cat /data/data/com.example.target/shared_prefs/auth_prefs.xml
<map>
  <string name="auth_token">eyJhbGciOiJIUzI1NiIs...</string>
</map>
```

Interpretasi: token autentikasi (format JWT terlihat dari prefix `eyJ...`) ditulis dan ditemukan **dalam bentuk plaintext utuh** di file XML — tidak ada hook `Cipher.doFinal()` yang terpicu sebelumnya. **FAIL**.

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi |
|---|---|
| P1 | Seluruh nilai sensitif yang ditulis via `SharedPreferences` didahului operasi enkripsi yang terverifikasi benar (dikonfirmasi Metode A+D) |
| P2 | Aplikasi memakai `EncryptedSharedPreferences` dengan konfigurasi yang sesuai rekomendasi, dan file terkait dikecualikan dari backup (§1.4) |
| P3 | Pemindaian TruffleHog/gitleaks pada file XML hasil ekstraksi **tidak menemukan** pola secret apa pun |
| P4 | Aplikasi tidak menyimpan data sensitif via `SharedPreferences` sama sekali (memakai Android Keystore langsung atau mekanisme lain yang lebih sesuai) |

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **`MODE_PRIVATE` tidak pernah menjadi alasan PASS** — sesuai §1.2, ini kontrol akses filesystem, bukan enkripsi. Jangan biarkan kesalahpahaman umum ini memengaruhi kesimpulan.

2. **`EncryptedSharedPreferences` yang ditemukan dipakai dengan benar dianggap PASS untuk saat ini**, namun catat sebagai observasi teknis-utang mengingat status deprecated-nya (§1.3) — rekomendasikan tim developer memantau evolusi panduan Android untuk migrasi jangka panjang.

3. **Korelasi urutan Cipher-putString bersifat heuristik, bukan bukti absolut** — nilai bisa saja dienkripsi di tempat lain (mis. sebelum dikirim ke fungsi yang menyimpan) dengan pola pemanggilan yang tidak langsung berdekatan; selalu lengkapi dengan verifikasi manual MASTG-TECH-0023 sesuai klausul resmi.

4. **Selalu periksa file `shared_prefs/*.xml` secara langsung**, bukan hanya mengandalkan hasil hooking — nilai yang tampak "terenkripsi" dari hook (mis. base64) mungkin ternyata **hanya encoding**, bukan enkripsi sungguhan; isi file yang sebenarnya adalah bukti definitif.

5. **Korelasikan dengan MASTG-TEST-0207** untuk memastikan tidak ada mekanisme penyimpanan lain (di luar `SharedPreferences`) yang turut membocorkan data yang sama.

6. **Severity dimodulasi** oleh jenis data yang ditemukan plaintext — kredensial/token autentikasi jauh lebih kritis dibanding preferensi UI non-sensitif.

7. **Dokumentasikan:** stack trace lokasi penulisan, nilai yang ditulis (redaksi bila perlu untuk laporan), hasil korelasi dengan operasi Cipher, isi file XML hasil ekstraksi, dan hasil pemindaian secret detector.

---

## 4. Rekomendasi Perbaikan

### 4.1 Migrasi ke Android Keystore Langsung untuk Data Sangat Sensitif

Untuk kredensial/kunci kriptografi kritis, hindari `SharedPreferences` sama sekali — simpan langsung di Android Keystore (rujuk pola di dokumen MASTG-TEST-0212).

### 4.2 Gunakan `EncryptedSharedPreferences` sebagai Mitigasi Jangka Menengah

```kotlin
val masterKey = MasterKey.Builder(context)
    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
    .build()

val encryptedPrefs = EncryptedSharedPreferences.create(
    context,
    "secure_prefs",
    masterKey,
    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
)
encryptedPrefs.edit().putString("auth_token", token).apply()
```

**Catatan**: sesuai §1.3, rencanakan migrasi jangka panjang mengingat status deprecated library ini.

### 4.3 Kecualikan File Terkait dari Backup

Rujuk implementasi lengkap di dokumen MASTG-TEST-0262 §4 — pastikan `data_extraction_rules.xml` mengecualikan file `EncryptedSharedPreferences` dari `<cloud-backup>` dan `<device-transfer>`.

### 4.4 Checklist Remediasi

- [ ] Seluruh pemanggilan `SharedPreferences.Editor.put*()` diinventarisasi dan dikorelasikan dengan operasi enkripsi
- [ ] File `shared_prefs/*.xml` diverifikasi tidak mengandung secret plaintext (pemindaian TruffleHog/gitleaks)
- [ ] Data sangat sensitif dimigrasikan ke Android Keystore langsung
- [ ] `EncryptedSharedPreferences` (bila dipakai) dikonfigurasi sesuai rekomendasi dan dikecualikan dari backup
- [ ] Rencana migrasi jangka panjang dari Jetpack Security Crypto library sudah dipertimbangkan
- [ ] **Verifikasi ulang:** jalankan kembali MASTG-TEST-0287 setelah setiap perubahan penyimpanan data sensitif

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0287: Runtime Storage of Unencrypted Data via the SharedPreferences API](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0287/)
- [MASTG-TEST-0207: Runtime Storage of Unencrypted Data in the App Sandbox](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0207/)
- [MASTG-TEST-0212: Use of Hardcoded Cryptographic Keys in Code](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0212/)
- [MASTG-TEST-0262: References to Backup Configurations Not Excluding Sensitive Data](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0262/)
- [MASWE-0001: Sensitive Data Stored Unencrypted in Private Storage](https://mas.owasp.org/MASWE/MASVS-STORAGE/MASWE-0001/)
- [MASTG-KNOW-0036: Shared Preferences](https://mas.owasp.org/MASTG/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0036/)
- [MASTG-TECH-0043: Method Hooking](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0043/)
- [MASTG-TECH-0008: Retrieving Files](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0008/)

### 5.2 Dokumentasi Resmi Android

- [Android Developers — `SharedPreferences` API reference](https://developer.android.com/reference/android/content/SharedPreferences)
- [Android Developers — Use SharedPreferences in private mode](https://developer.android.com/privacy-and-security/security-best-practices#sharedpreferences)
- [Android Developers — `EncryptedSharedPreferences`](https://developer.android.com/reference/androidx/security/crypto/EncryptedSharedPreferences)
- [Android Developers — Cryptography (Jetpack Security Crypto deprecation notice)](https://developer.android.com/privacy-and-security/cryptography#jetpack_security_crypto_library)
- [Android Developers — DataStore](https://developer.android.com/topic/libraries/architecture/datastore)

### 5.3 Dokumentasi Tools

- [TruffleHog — Documentation](https://docs.trufflesecurity.com/)
- [Frida — Dynamic instrumentation toolkit](https://frida.re/docs/javascript-api/)
- [Objection — Runtime Mobile Exploration toolkit](https://github.com/sensepost/objection)
- [CodeQL — Documentation](https://codeql.github.com/docs/)
- [gitleaks](https://github.com/gitleaks/gitleaks)

### 5.4 CWE

- [CWE-312: Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)
- [CWE-311: Missing Encryption of Sensitive Data](https://cwe.mitre.org/data/definitions/311.html)

---

*Dokumen ini disusun berdasarkan OWASP MASTG (rilis terkini per September 2026) dan dokumentasi resmi Android Developers. Sebagai versi API-spesifik dari MASTG-TEST-0207, nilai unik test ini adalah kemampuan hooking memberi stack trace presisi dan korelasi langsung dengan operasi kriptografi di sekitarnya. Temuan penting yang perlu diperhatikan penguji: `EncryptedSharedPreferences` — solusi rekomendasi utama selama bertahun-tahun untuk masalah ini — kini berstatus **deprecated** tanpa pengganti langsung, menciptakan periode transisi di mana aplikasi yang memakainya dengan benar tetap dianggap PASS namun perlu direkomendasikan merencanakan migrasi jangka panjang ke pendekatan enkripsi yang didukung penuh.*
