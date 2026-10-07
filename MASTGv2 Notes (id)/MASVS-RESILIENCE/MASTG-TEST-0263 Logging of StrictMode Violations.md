# MASTG-TEST-0263 Logging of StrictMode Violations

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0263 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-RESILIENCE |
| **Weakness** | MASWE-0061 — *Debug Artifacts Not Removed* |
| **API yang disorot** | `StrictMode` |
| **Tipe Pengujian** | **Dynamic, Logs** |
| **Profile** | **R (Resilience) saja** |
| **Teknik terkait** | MASTG-TECH-0005 (Install App), MASTG-TECH-0009 (Monitoring System Logs) |
| **Demo terkait** | — (tidak ada) |
| **Rule resmi** | `mastg-android-strictmode.yml` — hanya mencocokkan `StrictMode.setVmPolicy(...)`, tidak mencakup `setThreadPolicy(...)` (lihat §3.2) |
| **CWE terkait** | CWE-215 (Insertion of Sensitive Information Into Debugging Code), CWE-489 (Active Debug Code) |

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian

Kutipan overview resmi MASTG:

> *"This test checks whether an app enables `StrictMode` in production. While useful for developers to log policy violations such as disk I/O or network operations in production apps, leaving `StrictMode` enabled can expose sensitive implementation details in the logs that could be exploited by attackers."*

`StrictMode` adalah alat bantu developer yang secara desain **dimaksudkan untuk fase development** — ia memantau thread utama dan seluruh VM aplikasi untuk mendeteksi pola kode yang buruk (disk I/O di main thread yang menyebabkan ANR, koneksi jaringan tanpa `SocketTag`, kebocoran resource, dsb.) dan **mencatat detail lengkap pelanggaran tersebut** ke Logcat. Test ini murni memeriksa **apakah artefak debugging ini masih aktif** pada build produksi — konsisten dengan kategorisasinya di bawah **MASWE-0061 (Debug Artifacts Not Removed)**, bagian dari pola risiko yang lebih luas seputar sisa-sisa mekanisme development yang tertinggal saat rilis (bandingkan dengan MASTG-TEST-0226 tentang `debuggable` flag dalam seri riset ini).

### 1.2 Mengapa Test Ini Khusus Profile R (Resilience)

Test ini **hanya berlaku untuk profile R** — konsisten dengan beberapa test lain dalam seri riset ini yang menyasar *hardening* terhadap reverse engineering (mis. MASTG-TEST-0222/0223 tentang PIE/stack canary, MASTG-TEST-0224/0225 tentang skema tanda tangan APK). Ini mencerminkan sifat risiko `StrictMode`: dampaknya **bukan** kebocoran data pengguna secara langsung (seperti kredensial atau PII), melainkan **kebocoran detail implementasi internal** yang mempermudah upaya reverse engineering dan pemetaan arsitektur kode — relevan khususnya bagi aplikasi yang biner-nya sendiri menjadi target (DRM, aplikasi pembayaran, anti-cheat) sesuai definisi profile R dalam standar MASTG.

### 1.3 Apa Sebenarnya yang Bocor Lewat Log `StrictMode`

Untuk memahami dampak nyata test ini, penting mengetahui **detail konkret** yang dicatat `StrictMode` saat pelanggaran terdeteksi. Berdasarkan dokumentasi API resmi `StrictMode`, dua kategori kebijakan mencatat informasi yang cukup rinci:

**`StrictMode.VmPolicy`** (level VM/aplikasi) mendeteksi:
- Disk write/read di luar main thread
- Operasi jaringan di main thread
- Pembuatan socket tanpa tag
- Cleartext traffic
- Pelanggaran akses content provider
- Unsafe class loading

**`StrictMode.ThreadPolicy`** (level thread) mendeteksi:
- Operasi disk I/O (baca/tulis) di main thread
- Akses jaringan di main thread
- Pelanggaran kustom lewat `noteSlowCall()`

Setiap pelanggaran yang terdeteksi dicatat ke Logcat dengan **detail yang sangat rinci**:

```
StrictMode policy violation: ...
    at android.os.StrictMode$AndroidBlockGuardPolicy.onNetwork()
    at java.net.Socket.<init>()
    at com.example.app.internal.PaymentGatewayClient.connectDirectly(PaymentGatewayClient.java:87)
    at com.example.app.internal.PaymentGatewayClient.processTransaction(PaymentGatewayClient.java:42)
```

Perhatikan betapa banyak informasi arsitektural yang terungkap dari satu baris log ini saja: **nama package internal** (`com.example.app.internal`), **nama kelas yang mengungkap fungsi bisnis** (`PaymentGatewayClient`), **nama method** (`connectDirectly`, `processTransaction`), dan **nomor baris kode sumber persis**. Ini adalah kelas informasi yang secara khusus **coba disembunyikan** oleh mekanisme obfuscation/code shrinking (ProGuard/R8, dibahas di berbagai dokumen MASVS-RESILIENCE lain dalam seri ini) — namun `StrictMode` yang aktif di produksi secara efektif **membocorkan peta navigasi yang sama** lewat jalur yang sepenuhnya berbeda dan independen dari upaya obfuscation apa pun, karena stack trace runtime tetap menunjukkan struktur eksekusi nyata terlepas dari nama simbol yang di-obfuscate di level bytecode statis.

### 1.4 Hubungan dengan Reverse Engineering: "Peta Gratis" Tanpa Perlu Dekompilasi

Poin sintesis penting: seorang penyerang yang ingin memahami arsitektur internal aplikasi biasanya harus melalui proses dekompilasi dan analisis statis yang memakan waktu (persis metodologi yang dibahas di banyak dokumen lain dalam seri riset ini). Namun bila `StrictMode` aktif di build produksi, penyerang **cukup menjalankan aplikasi sambil memantau Logcat** — teknik yang jauh lebih murah dan cepat dibanding reverse engineering statis penuh — untuk memperoleh:

- Peta alur eksekusi nyata (bukan hanya struktur kode statis, tapi **urutan pemanggilan aktual** saat fitur tertentu dipakai)
- Titik-titik di kode yang melakukan I/O sensitif (disk/network), yang seringkali berkorelasi dengan lokasi pemrosesan data penting
- Nama kelas/method asli meski aplikasi sudah di-obfuscate (karena stack trace runtime tidak terpengaruh obfuscation nama simbol pada level source map yang tidak disertakan ke publik — nama yang muncul di stack trace adalah nama **setelah** obfuscation, tapi struktur kelas dan hierarki pemanggilan tetap terungkap secara fungsional)

Ini melengkapi wawasan dari riset umum tentang *log info disclosure* pada Android:

> *"Log Info Disclosure is a type of vulnerability where apps print sensitive data into the device log. If attackers gain access to log files or Logcat, they may extract sensitive user details, which could include confidential paths, API keys, or database queries... Activating logging in a production environment can disclose internal application information, thereby aiding potential attackers in the reverse-engineering process."*

`StrictMode` adalah kasus khusus dari kategori risiko ini — bedanya, log yang dihasilkan bukan hasil pemanggilan `Log.d()` yang sengaja ditulis developer (seperti dibahas di dokumen MASTG-TEST-0203/0231 dalam seri riset ini), melainkan **otomatis dihasilkan sistem** setiap kali kode aplikasi melanggar kebijakan yang dikonfigurasi — sehingga developer yang lupa menonaktifkannya di build rilis mungkin **tidak menyadari** bahwa log semacam ini terus dihasilkan tanpa mereka tulis secara eksplisit satu per satu.

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | Fungsi |
|---|---|
| **adb logcat** | Memantau output log sistem saat aplikasi berjalan (MASTG-TECH-0009) — metode utama resmi |
| **jadx** | Dekompilasi untuk analisis statis pendukung (mencari pemanggilan `StrictMode.setVmPolicy`/`setThreadPolicy` di kode) |
| **semgrep** | Menjalankan rule resmi sebagai baseline statis pendukung |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **grep / ripgrep** | Melengkapi cakupan rule resmi yang tidak mencakup `setThreadPolicy` (§3.2) |
| **pidcat / matlog** | Filter log yang lebih ramah dibanding `adb logcat` mentah, memudahkan mengisolasi baris terkait `StrictMode` di antara noise log lain |
| **Frida** | Hooking `StrictMode.setVmPolicy`/`setThreadPolicy` untuk konfirmasi runtime konfigurasi yang benar-benar diterapkan, termasuk yang dibangun kondisional (mis. dibungkus `if (BuildConfig.DEBUG)`) |
| **CodeQL** | Menelusuri apakah pemanggilan `StrictMode` benar-benar dibungkus pengecekan `BuildConfig.DEBUG` yang konsisten, atau tertinggal tanpa guard di jalur kode tertentu |

### 2.3 Prasyarat Lingkungan

- **Butuh device/emulator** — test ini murni dinamis, mensyaratkan aplikasi benar-benar dijalankan.
- **Target pengujian harus APK build produksi/release**, bukan build debug — overview resmi menegaskan ini secara eksplisit: *"The target of this test is the production build of the app."* Menguji build debug akan menghasilkan false positive karena `StrictMode` yang aktif di debug build adalah hal wajar dan diharapkan.
- **Interaksi menyeluruh dengan aplikasi** untuk memicu sebanyak mungkin jalur kode yang berpotensi melanggar kebijakan `StrictMode` (disk I/O, network call) — pola yang konsisten dengan test-test dinamis lain dalam seri riset ini.

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0005** untuk menginstal aplikasi.
2. Gunakan **MASTG-TECH-0009** untuk menampilkan log sistem yang dihasilkan `StrictMode`.
3. Buka aplikasi dan biarkan berjalan.

### 3.2 Metode A — `adb logcat` *(metode resmi utama)*

```bash
adb install target-app-release.apk
adb logcat -c
adb shell am start -n com.target.app/.MainActivity

# Filter khusus untuk StrictMode
adb logcat | grep -i "StrictMode"
```

Contoh output yang mengindikasikan FAIL:

```
D/StrictMode: StrictMode policy violation; ~duration=42 ms: android.os.StrictMode$StrictModeDiskReadViolation
    at com.target.app.data.LocalCache.readFromDisk(LocalCache.java:55)
```

### 3.3 Metode B — Rule Semgrep Resmi + grep Pelengkap *(rule resmi ada, tapi cakupan sempit)*

```yaml
rules:
  - id: mastg-android-strictmode
    severity: WARNING
    languages: [java]
    message: "[MASVS-RESILIENCE] Detected usage of StrictMode"
    patterns:
      - pattern: StrictMode.setVmPolicy(...)
```

```bash
semgrep --config https://raw.githubusercontent.com/OWASP/mastg/master/rules/mastg-android-strictmode.yml ./decompiled/sources/
```

**Celah cakupan**: rule ini **hanya mencocokkan `setVmPolicy()`**, sama sekali tidak mencakup `StrictMode.setThreadPolicy()` — padahal keduanya adalah dua API konfigurasi independen sesuai §1.3, dan aplikasi bisa saja hanya memakai salah satunya. Lengkapi dengan grep:

```bash
rg -n 'StrictMode\.setVmPolicy\(|StrictMode\.setThreadPolicy\(' ./decompiled/sources/

# Verifikasi apakah pemanggilan dibungkus guard BuildConfig.DEBUG
rg -n -B5 'StrictMode\.set(VmPolicy|ThreadPolicy)\(' ./decompiled/sources/ | grep -B5 "BuildConfig.DEBUG"
```

### 3.4 Metode C — CodeQL (Verifikasi Guard `BuildConfig.DEBUG`)

```ql
import java

class StrictModeCall extends MethodAccess {
  StrictModeCall() {
    this.getMethod().hasName(["setVmPolicy", "setThreadPolicy"]) and
    this.getMethod().getDeclaringType().hasQualifiedName("android.os", "StrictMode")
  }
}

from StrictModeCall call
where not exists(IfStmt guard |
  guard.getCondition().toString().matches("%BuildConfig.DEBUG%") and
  guard.getAChild*() = call.getEnclosingStmt())
select call, "Pemanggilan StrictMode ditemukan TANPA guard BuildConfig.DEBUG yang jelas"
```

### 3.5 Metode D — Frida (Konfirmasi Runtime pada Build Produksi)

```javascript
// hook-strictmode-config.js
Java.perform(function () {
    var StrictMode = Java.use("android.os.StrictMode");
    StrictMode.setVmPolicy.overload("android.os.StrictMode$VmPolicy").implementation = function (policy) {
        console.log("[!] StrictMode.setVmPolicy() dipanggil pada build ini — policy: " + policy.toString());
        return this.setVmPolicy(policy);
    };
    StrictMode.setThreadPolicy.overload("android.os.StrictMode$ThreadPolicy").implementation = function (policy) {
        console.log("[!] StrictMode.setThreadPolicy() dipanggil pada build ini — policy: " + policy.toString());
        return this.setThreadPolicy(policy);
    };
});
```

```bash
frida -U -f com.target.app -l hook-strictmode-config.js --no-pause
```

### 3.6 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Cakupan | Kapan dipakai |
|---|---|---|---|
| **A** | adb logcat | Bukti langsung sesuai definisi resmi test | **Wajib**, metode utama |
| **B** | Rule semgrep + grep | Statis, hanya `setVmPolicy` (rule) + pelengkap (grep) | Pendukung, identifikasi lokasi kode |
| **C** | CodeQL | Verifikasi guard `BuildConfig.DEBUG` | Codebase besar, audit kepatuhan pola |
| **D** | Frida | Konfirmasi konfigurasi aktif di build spesifik | Melengkapi Metode A dengan detail konfigurasi |

**Kombinasi minimum yang aku rekomendasikan:** **A (metode resmi wajib, bukti Logcat langsung) → B/C (identifikasi lokasi kode bila FAIL ditemukan, untuk remediasi presisi)**.

---

### 3.7 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG:**

> **Observation:** *"The output should contain a list of log statements related to `StrictMode`."*
>
> **Evaluation:** *"The test case fails if an app logs any `StrictMode` policy violations."*

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi |
|---|---|
| F1 | Logcat pada build **produksi/release** menunjukkan **satu pun** baris log pelanggaran `StrictMode` selama interaksi normal aplikasi |
| F2 | Ditemukan pemanggilan `setVmPolicy`/`setThreadPolicy` di kode **tanpa** guard `BuildConfig.DEBUG` yang konsisten |

**Contoh bukti (ilustratif — MASTG belum menyediakan demo resmi untuk test ini):**

```bash
$ adb logcat | grep -i "StrictMode"
D/StrictMode: StrictMode policy violation; ~duration=120 ms
    at com.target.app.storage.SecureVaultManager.loadKeyFromDisk(SecureVaultManager.java:33)
```

Interpretasi: log ini muncul pada build release, mengungkap nama kelas `SecureVaultManager` yang jelas menangani material kriptografi, beserta nama method dan baris kodenya — **FAIL**, dengan dampak lebih signifikan karena kebocoran arsitektural ini menyentuh komponen keamanan-kritis.

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi |
|---|---|
| P1 | Logcat pada build produksi **tidak menunjukkan** log pelanggaran `StrictMode` sama sekali selama interaksi menyeluruh |
| P2 | Analisis statis (Metode B/C) mengonfirmasi seluruh pemanggilan `StrictMode` dibungkus `if (BuildConfig.DEBUG)` secara konsisten |

**Contoh output yang menandakan PASS:**

```bash
$ adb logcat | grep -i "StrictMode"
# (tidak ada hasil setelah interaksi menyeluruh)
```

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Pastikan menguji build produksi, bukan debug** — ini prasyarat eksplisit resmi. Menguji build debug secara keliru akan selalu menghasilkan FAIL karena `StrictMode` memang wajar aktif di sana.

2. **Interaksi menyeluruh penting untuk hasil negatif yang meyakinkan** — sesuai pola berulang di seluruh test dinamis dalam seri ini, `StrictMode` hanya mencatat pelanggaran pada operasi yang **benar-benar terjadi**; jalur kode yang jarang dipakai (fitur langka, alur error) berisiko tidak memicu pelanggaran meski konfigurasinya tetap aktif.

3. **Manfaatkan analisis statis untuk mengidentifikasi lokasi remediasi presisi** bila hasil dinamis FAIL — Metode B/C langsung menunjukkan baris kode mana yang perlu dibungkus guard `BuildConfig.DEBUG`.

4. **Rule resmi hanya menutup separuh API (`setVmPolicy`)** — jangan simpulkan PASS dari hasil semgrep kosong tanpa memeriksa `setThreadPolicy` secara terpisah.

5. **Severity dimodulasi oleh isi stack trace yang terungkap** — pelanggaran yang stack trace-nya menyentuh kelas/method terkait fungsi keamanan-kritis (kriptografi, autentikasi, pemrosesan pembayaran) lebih signifikan dibanding yang menyentuh kode UI/rendering biasa.

6. **Dokumentasikan:** cuplikan lengkap log pelanggaran yang ditemukan, kelas/method yang terungkap dari stack trace, lokasi kode pemanggilan `StrictMode` (bila ditemukan lewat analisis statis), dan status guard `BuildConfig.DEBUG`.

---

## 4. Rekomendasi Perbaikan

### 4.1 Bungkus Seluruh Konfigurasi `StrictMode` dengan Guard Build

```kotlin
class MyApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        if (BuildConfig.DEBUG) {
            StrictMode.setVmPolicy(
                StrictMode.VmPolicy.Builder()
                    .detectAll()
                    .penaltyLog()
                    .build()
            )
            StrictMode.setThreadPolicy(
                StrictMode.ThreadPolicy.Builder()
                    .detectAll()
                    .penaltyLog()
                    .build()
            )
        }
    }
}
```

### 4.2 Verifikasi via ProGuard/R8 sebagai Lapisan Kedua

Untuk kepastian tambahan bahwa kode `StrictMode` benar-benar tidak masuk ke build release, pertimbangkan konfigurasi shrinking yang menghapus blok tersebut sepenuhnya bila `BuildConfig.DEBUG` diketahui `false` secara statis pada waktu build (R8 sudah mampu melakukan dead-code elimination untuk pola `if (false)` yang dihasilkan `BuildConfig.DEBUG=false` pada build release).

### 4.3 Integrasikan ke CI/CD

```bash
#!/bin/bash
# ci-check-strictmode-production.sh — jalankan pada APK RELEASE
adb install -r "$1"
adb logcat -c
adb shell am start -n "$2"
sleep 10
VIOLATIONS=$(adb logcat -d | grep -c "StrictMode policy violation")
if [ "$VIOLATIONS" -gt "0" ]; then
    echo "[GAGAL] Ditemukan $VIOLATIONS pelanggaran StrictMode pada build release!"
    exit 1
fi
```

### 4.4 Checklist Remediasi

- [ ] Seluruh pemanggilan `StrictMode.setVmPolicy`/`setThreadPolicy` dibungkus `if (BuildConfig.DEBUG)`
- [ ] Verifikasi dinamis pada APK release menunjukkan tidak ada log pelanggaran `StrictMode`
- [ ] CI/CD menyertakan gate otomatis untuk mendeteksi regresi di masa depan
- [ ] **Verifikasi ulang:** jalankan kembali MASTG-TEST-0263 pada setiap build release baru

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0263: Logging of StrictMode Violations](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0263/)
- [MASWE-0061: Debug Artifacts Not Removed](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0061/)
- [MASTG-TECH-0005: Installing Apps](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0005/)
- [MASTG-TECH-0009: Monitoring System Logs](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0009/)
- [MASTG Document 0x05i — Testing Code Quality and Build Settings](https://mas.owasp.org/MASTG/0x05i-Testing-Code-Quality-and-Build-Settings/)
- [Rule resmi: mastg-android-strictmode.yml (GitHub)](https://github.com/OWASP/mastg/blob/master/rules/mastg-android-strictmode.yml)

### 5.2 Dokumentasi Resmi Android

- [Android Developers — `StrictMode` API reference](https://developer.android.com/reference/android/os/StrictMode)
- [Android Developers — Log Info Disclosure](https://developer.android.com/privacy-and-security/risks/log-info-disclosure)

### 5.3 Riset dan Artikel Komunitas

- [SecureFlag Knowledge Base — Sensitive Information Disclosure in Android](https://knowledge-base.secureflag.com/vulnerabilities/sensitive_information_exposure/sensitive_information_disclosure_android.html)
- [Oversecured Blog — Android Security Checklist: Theft of Arbitrary Files](https://blog.oversecured.com/Android-security-checklist-theft-of-arbitrary-files/)
- [CWE-215: Insertion of Sensitive Information Into Debugging Code](https://cwe.mitre.org/data/definitions/215.html)
- [CWE-489: Active Debug Code](https://cwe.mitre.org/data/definitions/489.html)

### 5.4 Dokumentasi Tools

- [Semgrep — Documentation](https://semgrep.dev/docs/)
- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [CodeQL — Documentation](https://codeql.github.com/docs/)
- [Frida — Dynamic instrumentation toolkit](https://frida.re/docs/javascript-api/)
- [pidcat](https://github.com/JakeWharton/pidcat)

---

*Dokumen ini disusun berdasarkan OWASP MASTG (rilis terkini per September 2026), dokumentasi resmi Android Developers, serta riset umum tentang log information disclosure pada Android. Nuansa terpenting: `StrictMode` yang aktif di produksi membocorkan detail arsitektural (nama kelas, method, baris kode, stack trace eksekusi nyata) yang secara efektif memberi "peta gratis" bagi upaya reverse engineering — jauh lebih murah bagi penyerang dibanding dekompilasi statis penuh, dan berjalan independen dari upaya obfuscation/code shrinking yang mungkin sudah diterapkan pada level bytecode.*
