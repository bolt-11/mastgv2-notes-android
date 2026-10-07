# MASTG-TEST-0365 Exported And Unprotected Services That Expose Sensitive Functionality

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0365 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-PLATFORM |
| **Weakness** | MASWE-0018 |
| **Tipe Pengujian** | Static, Config, Code, **Manual** |
| **Teknik terkait** | MASTG-TECH-0013, MASTG-TECH-0117, MASTG-TECH-0161 (Enumerating Services), MASTG-TECH-0014, MASTG-TECH-0023 |
| **Knowledge terkait** | MASTG-KNOW-0133 (Android Services), MASTG-KNOW-0017 (App Permissions), MASTG-KNOW-0020 (IPC Mechanisms) |
| **Best Practice terkait** | MASTG-BEST-0052 (Restrict Access to Android App Components) |
| **Test terkait** | **MASTG-TEST-0364** — pola metodologi yang identik untuk Activity; dokumen ini menyasar komponen **Service**, dengan nuansa tambahan untuk bound service (§1.3) |
| **Rule resmi** | — (tidak ada; murni manual, konsisten dengan TEST-0364) |

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian

Kutipan overview resmi MASTG:

> *"If an exported service does not define `android:permission` with a proper protection level and performs or grants access to sensitive functionality, another third-party app outside the intended trust boundary can start or bind to it and invoke that functionality."*

Struktur evaluasi test ini **secara metodologis identik** dengan MASTG-TEST-0364 (Activities) yang sudah dibahas dalam seri riset ini — perbedaan utamanya adalah jenis komponen yang disasar. Namun Service membawa **nuansa risiko tambahan** yang tidak dimiliki Activity: kemampuan untuk diakses lewat **dua cara berbeda** — `startService()` (fire-and-forget) dan `bindService()` (komunikasi dua arah via interface).

### 1.2 Dua Model Interaksi dengan Service dan Implikasinya pada Attack Surface

MASTG-KNOW-0133 membedakan dua model penggunaan service:

> *"Started services: launched with startService... and run until they stop themselves or are stopped."*
>
> *"Bound services: other components bind to them with bindService to interact through a client-server interface. A bound service must return an IBinder from onBind."*

Perbedaan ini penting untuk attack surface: **started service** umumnya hanya menerima satu `Intent` dan memproses satu kali (mirip Activity/Broadcast Receiver). **Bound service**, sebaliknya, membuka **koneksi interaktif dua arah** — penyerang bisa mengirim banyak permintaan dan menerima banyak respons melalui mekanisme:

> *"A Messenger, which serializes requests into Message objects delivered to a Handler. This is the simplest cross-process interface."*
>
> *"The Android Interface Definition Language (AIDL), which generates the marshalling code for a remote interface and allows concurrent calls across processes."*

Bound service via AIDL secara efektif **mengekspos seluruh API internal** yang didefinisikan interface-nya ke pemanggil eksternal — ini adalah kelas risiko yang jauh lebih luas dibanding sekadar "satu Intent memicu satu aksi", karena satu bound service bisa memiliki **puluhan method** yang semuanya menjadi permukaan serangan sekaligus bila tidak dilindungi dengan benar.

### 1.3 Lapisan Pertahanan Tambahan yang Unik untuk Service: Verifikasi Permission di Runtime

Ini adalah poin pembeda paling signifikan dari TEST-0364 — overview secara eksplisit menambahkan kriteria validasi keempat yang **tidak ada** pada test Activity:

> *"Determine whether the service verifies the caller's permission at runtime (for example, with `checkCallingPermission` or `enforceCallingPermission`) before processing sensitive requests."*

Ini relevan karena pada bound service via AIDL/Binder, `android:permission` di manifest **hanya melindungi langkah awal** (`bindService()`/`startService()`), namun **setelah** koneksi/binding berhasil terjalin, **setiap pemanggilan method individual** pada interface tersebut berpotensi perlu diverifikasi ulang secara terpisah — terutama bila service tersebut melayani **banyak klien dengan tingkat kepercayaan berbeda** sekaligus. MASTG-KNOW-0133 menjelaskan mekanismenya:

> *"Inside the service, `Context.checkCallingPermission` and related methods can verify at runtime whether the caller holds a required permission before processing a Binder transaction."*

Ini adalah bentuk **defense-in-depth tingkat method**, bukan hanya tingkat komponen — relevan khususnya untuk service kompleks yang mengekspos banyak operasi dengan tingkat sensitivitas yang berbeda-beda melalui satu interface yang sama.

### 1.4 Bukti Nyata: Reset Password via Exported MessengerService Tanpa Otentikasi Apa Pun

Ini adalah kasus nyata yang secara sempurna mengilustrasikan persis skenario kedua dari kriteria evaluasi resmi (§ Evaluation: *"allowing a caller to invoke a bound-service interface without authorization"*):

> *"The app initialized shared preferences with username 'root' and a SHA256 password hash, but any installed application could interact with this exported, unprotected service. The MessengerService accepted two message types: display toast notifications, and update the password hash... An attacker created a malicious app that bound to the victim app's service using an explicit intent, sent a message with what=2 containing a known password hash, and successfully reset the login credentials without authentication. This allowed bypassing the login entirely and accessing the protected admin panel."*

Kasus ini menunjukkan secara konkret bagaimana **bound service via Messenger** (§1.2) bisa menjadi vektor serangan yang jauh lebih berbahaya daripada sekadar "menampilkan data" — di sini, penyerang **mengubah state keamanan aplikasi** (password hash) lewat satu pesan sederhana (`what=2`), tanpa perlu melewati satu pun layar login. Rekomendasi penulis riset ini sejalan sepenuhnya dengan prinsip MASTG-BEST-0052:

> *"The author recommends using 'signature-level' permissions to restrict service access only to applications signed with the same certificate."*

### 1.5 Konteks Tambahan: Risiko di Level Sistem (Bukan Hanya Aplikasi Individual)

Riset keamanan tingkat lanjut menunjukkan bahwa kelas kerentanan Binder/bound service ini juga relevan di level **sistem operasi Android itu sendiri**, bukan hanya aplikasi pihak ketiga — **CVE-2023-20938** adalah use-after-free pada Binder driver yang dapat dieksploitasi untuk privilege escalation hingga root dari aplikasi tidak tepercaya. Meski ini adalah kerentanan di level kernel/framework (di luar scope langsung test aplikasi individual), ini menegaskan bahwa **Binder sebagai mekanisme IPC fundamental** memiliki riwayat kerentanan yang serius dan berkelanjutan di berbagai lapisan — menambah urgensi mengapa aplikasi individual tidak boleh menambah permukaan serangan yang tidak perlu lewat service yang dikonfigurasi longgar.

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | Fungsi |
|---|---|
| **aapt2 / xmlstarlet** | Enumerasi service exported beserta permission-nya (MASTG-TECH-0161) |
| **jadx** | Review kode `onBind()`/`onStartCommand()`/`handleMessage()` untuk menilai sensitivitas fungsionalitas (MASTG-TECH-0014, MASTG-TECH-0023) |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **ADB (`am startservice`)** | Verifikasi dinamis untuk started service |
| **Drozer** | Khusus sangat berguna untuk service — menyediakan `app.service.send` untuk mengirim `Message` terstruktur ke bound service tanpa perlu menulis aplikasi exploit kustom |
| **`adb shell dumpsys package`** | Inspeksi Service Resolver Table untuk konfirmasi runtime |

### 2.3 Prasyarat Lingkungan

- Analisis statis manifest tidak butuh device/root.
- Verifikasi dinamis butuh device/emulator dengan aplikasi target terinstal.

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0013** untuk reverse engineer aplikasi.
2. Gunakan **MASTG-TECH-0117** untuk memperoleh `AndroidManifest.xml`.
3. Gunakan **MASTG-TECH-0161** untuk mendaftar service exported beserta `android:permission`-nya.
4. Gunakan **MASTG-TECH-0014** untuk memeriksa kode setiap service exported.

### 3.2 Metode A — Enumerasi Manifest dengan xmlstarlet

```bash
xmlstarlet sel -t -m "//service" \
  -v "@android:name" -o " exported=" -v "@android:exported" \
  -o " permission=" -v "@android:permission" \
  -o " intent_filters=" -v "count(intent-filter)" -n \
  AndroidManifest.xml
```

### 3.3 Metode B — Review Kode untuk Identifikasi Interface yang Diekspos (Wajib)

Untuk setiap service exported tanpa permission yang teridentifikasi:

1. Periksa `onBind()` — interface apa yang dikembalikan (AIDL stub, `Messenger`, `Binder` custom)?
2. Untuk `Messenger`, periksa implementasi `Handler.handleMessage()` — apa yang dilakukan untuk setiap nilai `what`?
3. Untuk AIDL, periksa file `.aidl` dan implementasi stub-nya — method apa saja yang diekspos?
4. Periksa apakah `checkCallingPermission`/`enforceCallingPermission` dipanggil di dalam method-method tersebut (§1.3).

### 3.4 Metode C — Verifikasi Dinamis dengan Drozer (Replikasi Skenario Nyata §1.4)

```bash
dz> run app.service.info -a com.example.app
dz> run app.service.send com.example.app com.example.app.AdminMessengerService --msg 2 0 0 --extra string password_hash "known_hash_value"
```

### 3.5 Metode D — Verifikasi Dinamis untuk Started Service via ADB

```bash
adb shell am startservice -n com.example.app/.BackgroundSyncService
adb shell dumpsys package com.example.app | grep -A10 'Service Resolver Table'
```

### 3.6 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Kapan dipakai |
|---|---|---|
| **A** | xmlstarlet/aapt2 | Baseline wajib — enumerasi lengkap |
| **B** | Review manual | **Wajib** — mengidentifikasi interface dan method yang diekspos, menilai sensitivitas |
| **C** | Drozer | Verifikasi dinamis paling praktis untuk bound service (Messenger/AIDL) |
| **D** | ADB `am startservice` | Verifikasi dinamis untuk started service sederhana |

**Kombinasi minimum yang aku rekomendasikan:** **A → B (wajib) → C/D (sesuai jenis service)**.

---

### 3.7 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG:**

> **Evaluation:** *"The test case fails if any exported service is not protected by an appropriate android:permission that restricts which apps can start or bind to it and exposes or performs sensitive functionality... for example by returning sensitive data, performing a security-relevant action, or allowing a caller to invoke a bound-service interface without authorization."*

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi |
|---|---|
| F1 | Service `exported="true"` tanpa `android:permission` memadai, **dan** mengekspos data/aksi sensitif via started atau bound interface |

**Contoh bukti (merefleksikan kasus nyata §1.4):**

```xml
<service android:name=".AdminMessengerService" android:exported="true" />
```

```java
class IncomingHandler extends Handler {
    public void handleMessage(Message msg) {
        switch (msg.what) {
            case 2: // update password hash — TIDAK ADA pemeriksaan permission/otentikasi
                prefs.edit().putString("password_hash", (String) msg.obj).apply();
                break;
        }
    }
}
```

**FAIL** — aksi mengubah kredensial dapat dipicu aplikasi mana pun tanpa otorisasi.

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi |
|---|---|
| P1 | Service tidak perlu diakses eksternal, diset `exported="false"`, **atau** |
| P2 | Service exported dengan `android:permission` berprotectionLevel `signature`, **dan** |
| P3 | *(untuk bound service dengan banyak operasi sensitivitas berbeda)* Setiap method/handler sensitif memverifikasi permission secara independen di runtime via `checkCallingPermission`/`enforceCallingPermission` (§1.3) |

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Bedakan started vs bound service saat menilai permukaan serangan** — bound service via AIDL/Messenger berpotensi mengekspos banyak operasi sekaligus melalui satu komponen, menuntut audit setiap method/message type secara individual, tidak cukup hanya menilai satu titik masuk seperti pada Activity.

2. **`android:permission` di manifest hanya melindungi langkah bind/start awal** — untuk bound service kompleks, periksa juga apakah verifikasi permission runtime ada di dalam implementasi method individual (§1.3), terutama bila service melayani klien dengan tingkat kepercayaan berbeda.

3. **Dahulukan pertanyaan kebutuhan ekspor**, sama seperti prinsip di TEST-0364 — bila tidak ada alasan sah pihak ketiga memanggil service tersebut, `exported="false"` adalah solusi paling kuat.

4. **Severity dimodulasi:**

   | Faktor | Severity |
   |---|---|
   | Bound service memungkinkan mengubah kredensial/state keamanan tanpa otorisasi | **Tinggi** |
   | Bound service mengekspos data sensitif via read-only interface | **Sedang-Tinggi** |
   | `android:permission` ada namun `protectionLevel` lemah, atau tidak ada verifikasi runtime per-method pada bound service kompleks | **Sedang** |
   | Non-exported, atau `signature` + verifikasi runtime lengkap | **Bukan temuan** |

5. **Dokumentasikan:** nama service, jenis (started/bound), interface yang diekspos (AIDL/Messenger/Binder custom), method/message type yang tersedia, status permission dan protectionLevel, serta hasil verifikasi dinamis.

---

## 4. Rekomendasi Perbaikan

### 4.1 Non-Exported Bila Tidak Perlu (Sesuai MASTG-BEST-0052)

```xml
<service android:name=".AdminMessengerService" android:exported="false" />
```

### 4.2 Permission Signature + Verifikasi Runtime per Method (Sesuai §1.3)

```xml
<service
    android:name=".PartnerSyncService"
    android:exported="true"
    android:permission="com.example.app.permission.TRUSTED_PARTNER" />
```

```java
class IncomingHandler extends Handler {
    public void handleMessage(Message msg) {
        if (msg.what == UPDATE_CREDENTIALS) {
            // Verifikasi tambahan di level method untuk operasi paling sensitif
            if (context.checkCallingPermission("com.example.app.permission.ADMIN_ACTION")
                    != PackageManager.PERMISSION_GRANTED) {
                return; // tolak diam-diam atau lempar SecurityException
            }
            // lanjutkan proses
        }
    }
}
```

### 4.3 Checklist Remediasi

- [ ] Seluruh service exported dievaluasi apakah benar-benar perlu diakses pihak eksternal
- [ ] Service yang tidak perlu diekspor diset `exported="false"`
- [ ] Service exported yang diperlukan dilindungi permission `signature`
- [ ] Bound service dengan banyak operasi memverifikasi permission secara independen per method/message type di runtime
- [ ] Diverifikasi secara dinamis dengan Drozer (`app.service.send`) untuk setiap message type yang diekspos

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0365 (source, tests-beta)](https://github.com/OWASP/mastg/blob/master/tests-beta/android/MASVS-PLATFORM/MASTG-TEST-0365.md)
- [MASTG-TEST-0364 (dokumen terkait dalam seri riset ini — pola metodologi serupa untuk Activity)](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0364/)
- [MASTG-KNOW-0133: Android Services](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0133/)
- [MASTG-BEST-0052: Restrict Access to Android App Components](https://github.com/OWASP/mastg/blob/master/best-practices/MASTG-BEST-0052.md)
- [MASTG-TECH-0161: Enumerating Services](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0161/)

### 5.2 Riset dan Kasus Nyata

- [alright21.me: Exploiting Exported Services — IPC Messenger (Reset Password Case)](https://blog.alright21.me/security/exploiting_ipc_messenger/)
- [Android Offensive Security Blog: Attacking Android Binder — Analysis and Exploitation of CVE-2023-20938](https://androidoffsec.withgoogle.com/posts/attacking-android-binder-analysis-and-exploitation-of-cve-2023-20938/)
- [Black Hat US-15: Fuzzing Android System Services by Binder Call to Escalate Privilege](https://www.blackhat.com/docs/us-15/materials/us-15-Gong-Fuzzing-Android-System-Services-By-Binder-Call-To-Escalate-Privilege.pdf)
- [CWE-926: Improper Export of Android Application Components](https://cwe.mitre.org/data/definitions/926.html)

### 5.3 Dokumentasi Tools

- [Drozer — Android Security Assessment Framework](https://github.com/WithSecureLabs/drozer)
- [Android Developers: Bound Services](https://developer.android.com/guide/components/bound-services)

---

*Dokumen ini disusun berdasarkan konten resmi OWASP MASTG (`tests-beta/android/MASVS-PLATFORM/MASTG-TEST-0365.md`, `MASTG-KNOW-0133/0017/0020`, `MASTG-BEST-0052`), serta riset komunitas yang mendokumentasikan kasus nyata reset password via `MessengerService` exported tanpa otentikasi, dan riset Binder-level (CVE-2023-20938) yang menegaskan risiko fundamental mekanisme IPC Android. Nuansa metodologis terpenting dibanding MASTG-TEST-0364 (Activity): Service — khususnya bound service via AIDL/Messenger — dapat mengekspos **banyak operasi sekaligus** melalui satu komponen, menuntut audit per method/message type secara individual, dan `android:permission` di manifest saja tidak selalu cukup — verifikasi permission runtime (`checkCallingPermission`/`enforceCallingPermission`) di dalam implementasi method menjadi lapisan pertahanan tambahan yang relevan khusus untuk kelas komponen ini.*
