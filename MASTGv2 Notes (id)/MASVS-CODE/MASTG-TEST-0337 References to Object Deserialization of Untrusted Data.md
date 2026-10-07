# MASTG-TEST-0337 References to Object Deserialization of Untrusted Data

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0337 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-CODE |
| **Weakness** | MASWE-0050 |
| **Tipe Pengujian** | Static, Code |
| **Teknik terkait** | MASTG-TECH-0013 (Reverse Engineering), MASTG-TECH-0014 (Static Analysis for Relevant APIs) |
| **Knowledge terkait** | MASTG-KNOW-0021 (Object Serialization) |
| **Rule resmi** | `mastg-android-object-deserialization.yml` — **cakupan sangat sempit**, lihat §1.4 |

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian

Kutipan overview resmi MASTG:

> *"Android apps can reconstruct objects from serialized data received through platform mechanisms such as Intent extras, Bundle values, IPC payloads, files, or network responses. If the app deserializes data from these sources without restricting the allowed classes or validating the input before use, the deserialization logic can introduce unintended application behavior or unsafe state changes."*

Poin penting yang harus digarisbawahi sejak awal: overview resmi secara eksplisit menyebut **lima sumber data berbeda** (`Intent` extras, `Bundle`, IPC, file, respons jaringan) sebagai vektor yang relevan. Ini jauh lebih luas dari sekadar satu API tunggal — dan seperti akan dibahas di §1.4, inilah justru letak kesenjangan terbesar antara cakupan ancaman yang dijelaskan overview dan cakupan rule resmi yang tersedia.

### 1.2 Enam Mekanisme Serialisasi di Android (Sesuai MASTG-KNOW-0021)

MASTG-KNOW-0021 menjabarkan beragam cara Android dapat melakukan serialisasi/deserialisasi objek, masing-masing dengan profil risiko berbeda:

| Mekanisme | Risiko Deserialisasi Utama |
|---|---|
| **Java Serializable + `ObjectInputStream`** | Risiko klasik object injection — kelas yang dideserialisasi bisa dikontrol penyerang bila tidak difilter |
| **JSON (`JSONObject`, Gson, Jackson, Moshi)** | Risiko lebih rendah secara inheren (berbasis field, bukan tipe kelas arbitrer), namun tetap rentan bila memakai reflection tanpa validasi |
| **XML (`XmlPullParser`, SAX)** | Risiko utamanya **XML External Entity (XXE)**, bukan deserialisasi objek langsung |
| **ORM (OrmLite, Realm, dsb.)** | Tergantung pada apakah database yang mendasarinya terenkripsi |
| **`Parcelable`** | Dipakai luas untuk `Intent`/`Bundle` — rentan terhadap **parcel/unparcel mismatch** pada level framework (§1.5) |
| **Protocol Buffers** | Memiliki riwayat CVE (`CVE-2015-5237`), tidak menyediakan enkripsi built-in |

Keberagaman ini penting — test ini **bukan** hanya tentang satu API `ObjectInputStream.readObject()`, melainkan tentang **pola risiko** yang bisa muncul di banyak mekanisme berbeda, tergantung bagaimana aplikasi target benar-benar membangun fitur komunikasi antar-komponennya.

### 1.3 Kriteria FAIL: Kombinasi Sumber Tidak Terpercaya + Tanpa Validasi

> **Evaluation:** *"The test case fails if the app deserializes data received from untrusted sources (e.g., Intent extras from any other application) without proper validation or type filtering."*

Contoh sumber tidak terpercaya yang eksplisit disebut — **`Intent` extras dari aplikasi lain mana pun**. Ini relevan karena pada Android, komponen (`Activity`, `Service`, `BroadcastReceiver`) yang diekspor (`exported="true"`, atau tanpa deklarasi eksplisit pada API level lama) dapat menerima `Intent` dari **aplikasi pihak ketiga mana pun yang terinstal di perangkat**, bukan hanya dari aplikasi tepercaya atau sistem sendiri.

### 1.4 Temuan Analitis Penting: Rule Resmi Jauh Lebih Sempit dari Cakupan Ancaman yang Dijelaskan

Ini adalah bagian paling krusial dari analisis rule — dibanding kelima sumber dan enam mekanisme yang dijelaskan di §1.1-1.2, rule resmi `mastg-android-object-deserialization.yml` **hanya** menyasar satu pola spesifik:

```yaml
pattern: |-
  $VAR = new java.io.ObjectInputStream(...);
  ...
  $OBJ = $VAR.readObject();
```

Rule ini **sama sekali tidak mencakup**:

- `Intent.getSerializableExtra()` / `Intent.getParcelableExtra()` — padahal inilah **contoh persis** yang disebut sendiri oleh bagian Evaluation resmi (§1.3) sebagai sumber tidak terpercaya utama!
- `Bundle.getSerializable()` / `Bundle.getParcelable()`
- Implementasi kustom `Parcelable.Creator` yang rentan parcel/unparcel mismatch
- Deserialisasi via library pihak ketiga (Gson, Jackson) yang memakai reflection tanpa validasi tipe

Ini adalah kasus **kesenjangan cakupan paling ekstrem** yang ditemukan sejauh ini dalam seri riset ini — rule secara teknis valid untuk mendeteksi satu pola `ObjectInputStream` murni, namun **tidak dapat sama sekali** mendeteksi skenario yang dijadikan contoh utama di evaluasi resminya sendiri (`Intent` extras). Penguji **wajib** melengkapi Metode A dengan pencarian manual yang jauh lebih luas (§3.3) — mengandalkan rule resmi saja untuk test ini akan menghasilkan false negative yang sangat signifikan.

### 1.5 Konteks Nyata: Sejarah Panjang CVE Deserialisasi di Level Framework Android

Risiko deserialisasi pada Android bukan sekadar teori — ini memiliki riwayat CVE yang panjang dan berkelanjutan, bahkan di level **framework Android itu sendiri**, bukan hanya aplikasi pihak ketiga:

> *"CVE-2014-7911: A serious flaw where Android versions earlier than 5.0 didn't verify that received objects implement the Serializable interface, allowing arbitrary objects to be inserted into target apps or services."*

Ini adalah kasus klasik yang menjadi dasar kekhawatiran object injection di Android — sebelum Android 5.0, verifikasi tipe yang lemah memungkinkan objek sembarang disisipkan melalui mekanisme serialisasi platform.

Kerentanan kelas **parcel/unparcel mismatch** terus muncul hingga tahun-tahun belakangan di komponen framework yang sangat privileged:

> *"CVE-2023-20963: A WorkSource Parcelable deserialization vulnerability allowing attackers to send arbitrary Intents as the system user... A parcel mismatch occurs when there is an inconsistency between how data is written to a Parcel object and how it is subsequently read from that object... leading to type confusion scenarios where the attacker's controlled data is interpreted as privileged objects."*

Dan **EvilParcel** (CVE-2017-13315) menunjukkan teknik eksploitasi yang sangat canggih memanfaatkan perbedaan antara deserialisasi pertama dan berulang:

> *"To launch an arbitrary activity with system privileges, you only need to create a Bundle with the Intent field hidden upon the first deserialization and appearing during the repeated deserialization."*

Konteks ini penting untuk dipahami penguji — meski kerentanan-kerentanan di atas terjadi di **level framework/OS** (bukan aplikasi individual yang menjadi target test MASTG ini), mereka menunjukkan bahwa **kelas kerentanan ini nyata dan terus berevolusi**, dan menegaskan mengapa Google sendiri merasa perlu menerbitkan halaman panduan resmi khusus tentang risiko ini.

### 1.6 Mitigasi Resmi Google: Dua Pendekatan Berbeda untuk Dua Jenis Risiko

Dokumentasi resmi Android memberikan dua rekomendasi mitigasi yang masing-masing menyasar mekanisme berbeda:

**Untuk `Parcelable` via `Intent`/`Bundle` (Android 13+):**

> *"Use type-safer methods... `parcel.readParcelable(ClassLoader, Class)` with an explicit type parameter that catches mismatches."*

**Untuk `Serializable`/`ObjectInputStream` (pola Look-Ahead/Allowlist):**

> *"Implement the OWASP pattern to allowlist only expected classes during deserialization."*

Serta satu teknik defensif tambahan yang elegan — memblokir deserialisasi sama sekali pada kelas yang memang tidak boleh pernah direkonstruksi dari luar:

```java
private final void readObject(ObjectInputStream in) throws IOException {
    throw new IOException("Cannot be deserialized");
}
```

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | Fungsi |
|---|---|
| **jadx** | Dekompilasi DEX → Java (MASTG-TECH-0013) |
| **Semgrep** + rule resmi `mastg-android-object-deserialization.yml` | Mendeteksi pola `ObjectInputStream.readObject()` murni (cakupan terbatas, §1.4) |

### 2.2 Tools Alternatif & Pendukung (Wajib untuk Menutup Celah Rule Resmi)

| Tool | Fungsi |
|---|---|
| **grep/ripgrep** | **Wajib** — mencari `getSerializableExtra`, `getParcelableExtra`, `Bundle.getSerializable/getParcelable`, dan pola serupa yang sama sekali tidak tercakup rule resmi |
| **Androguard / jadx** | Analisis manifest untuk memetakan komponen `exported="true"` sebagai titik masuk `Intent` tidak terpercaya (menghubungkan ke §1.3) |
| **MobSF** | Laporan otomatis yang kadang menyertakan deteksi komponen exported dan penggunaan `Serializable`/`Parcelable` |
| **Frida** | Verifikasi dinamis — hook `readObject()`/`getSerializableExtra()` untuk mengamati tipe objek sesungguhnya yang dideserialisasi saat runtime, termasuk dari `Intent` yang dikirim komponen eksternal |

### 2.3 Prasyarat Lingkungan

- Tidak butuh device/root untuk analisis statis.
- Siapkan daftar komponen `exported` dari manifest sebagai peta titik masuk yang perlu diperiksa silang dengan temuan deserialisasi.

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0013** untuk reverse engineer aplikasi.
2. Gunakan **MASTG-TECH-0014** untuk mencari API yang relevan.

### 3.2 Metode A — Semgrep dengan Rule Resmi (Cakupan Terbatas)

```bash
semgrep --config mastg-android-object-deserialization.yml ./decompiled/sources
```

**Catatan wajib:** hasil ini **hanya** menangkap pola `ObjectInputStream` murni. Lanjutkan ke Metode B untuk cakupan yang memadai sesuai ancaman sesungguhnya yang dijelaskan overview resmi (§1.4).

### 3.3 Metode B — grep/ripgrep untuk Menutup Celah Cakupan (Wajib)

```bash
D=./decompiled/sources

# Entry point Intent/Bundle - CONTOH UTAMA dari evaluasi resmi, TIDAK tercakup rule A
rg -n 'getSerializableExtra\(|getParcelableExtra\(|getParcelableArrayListExtra\(' $D
rg -n '\.getBundle\(\).*\.(getSerializable|getParcelable)\(' $D

# Implementasi custom Parcelable.Creator (potensi parcel mismatch, §1.5)
rg -n 'Parcelable.Creator' $D

# Library pihak ketiga yang memakai reflection
rg -n 'new Gson\(\)\.fromJson|ObjectMapper\(\)\.readValue' $D
```

### 3.4 Metode C — Pemetaan Komponen Exported sebagai Sumber Tidak Terpercaya

```bash
# Ekstrak komponen exported dari manifest
aapt dump xmltree app.apk AndroidManifest.xml | grep -B5 'exported.*true'
```

Korelasikan hasil ini dengan temuan Metode B — deserialisasi yang terjadi di dalam `onReceive()`/`onCreate()` milik komponen yang terdaftar exported adalah kandidat FAIL paling kuat, sesuai definisi "untrusted source" resmi.

### 3.5 Metode D — Frida untuk Verifikasi Dinamis Tipe Objek Sesungguhnya

```javascript
Java.perform(function () {
    var Intent = Java.use("android.content.Intent");
    Intent.getSerializableExtra.overload('java.lang.String').implementation = function (key) {
        var result = this.getSerializableExtra(key);
        console.log("[getSerializableExtra] key=" + key + " class=" + (result ? result.getClass().getName() : "null"));
        return result;
    };
});
```

### 3.6 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Kapan dipakai |
|---|---|---|
| **A** | Semgrep + rule resmi | Baseline, namun cakupannya **sangat terbatas** (§1.4) |
| **B** | grep/ripgrep manual | **Wajib** — menutup celah cakupan utama, mencakup contoh sesungguhnya dari evaluasi resmi |
| **C** | Pemetaan exported component | Mengidentifikasi sumber tidak terpercaya nyata sesuai definisi resmi |
| **D** | Frida | Verifikasi dinamis tipe objek sesungguhnya saat runtime |

**Kombinasi minimum yang aku rekomendasikan:** **B + C sebagai inti pengujian** (bukan A) — mengingat kesenjangan cakupan di §1.4, rule resmi hanya pelengkap kecil, bukan baseline yang memadai untuk test ini.

---

### 3.7 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG:**

> **Evaluation:** *"The test case fails if the app deserializes data received from untrusted sources (e.g., Intent extras from any other application) without proper validation or type filtering."*

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi |
|---|---|
| F1 | Aplikasi mendeserialisasi data dari sumber tidak terpercaya (`Intent` extras dari komponen exported, IPC, file yang dapat diakses app lain, respons jaringan tanpa validasi skema) **tanpa** filtering tipe atau validasi |

**Contoh bukti (merefleksikan skenario yang persis disebut evaluasi resmi):**

```xml
<!-- AndroidManifest.xml -->
<receiver android:name=".SyncReceiver" android:exported="true" />
```

```java
// Ditemukan di com/example/app/SyncReceiver.java
public void onReceive(Context context, Intent intent) {
    SyncPayload payload = (SyncPayload) intent.getSerializableExtra("payload");
    payload.execute(); // tidak ada validasi tipe/isi sebelum eksekusi
}
```

Interpretasi: `BroadcastReceiver` exported menerima objek `Serializable` dari `Intent` yang bisa dikirim aplikasi pihak ketiga mana pun, tanpa validasi tipe apa pun sebelum dipakai. **FAIL** — persis skenario yang dicontohkan evaluasi resmi.

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi |
|---|---|
| P1 | Tidak ada deserialisasi dari sumber tidak terpercaya sama sekali, **atau** |
| P2 | Deserialisasi dari sumber tidak terpercaya selalu disertai validasi tipe eksplisit (mis. `instanceof` check, allowlist kelas, atau API type-safe Android 13+) |

**Contoh bukti:**

```java
public void onReceive(Context context, Intent intent) {
    Serializable raw = intent.getSerializableExtra("payload");
    if (raw instanceof SyncPayload) { // validasi tipe eksplisit
        ((SyncPayload) raw).execute();
    } else {
        Log.w(TAG, "Payload type tidak dikenali, diabaikan");
    }
}
```

**PASS**.

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Jangan andalkan rule resmi sebagai baseline utama** — sesuai §1.4, rule tersebut melewatkan contoh ancaman utama (`Intent`/`Bundle`) yang disebut dalam evaluasi resminya sendiri; Metode B (grep manual) adalah inti pengujian yang sesungguhnya untuk test ini.

2. **Selalu korelasikan dengan status exported komponen** — deserialisasi yang terjadi di komponen **tidak exported** (hanya diakses dari dalam aplikasi sendiri) memiliki profil risiko yang jauh lebih rendah dibanding yang terjadi di komponen exported yang menerima `Intent` dari aplikasi pihak ketiga mana pun.

3. **`instanceof` check saja terkadang belum cukup** — untuk kasus yang lebih kompleks (gadget chain, parcel mismatch di level framework seperti §1.5), validasi tipe permukaan bisa dilewati oleh teknik eksploitasi yang lebih canggih; untuk aplikasi high-risk, pertimbangkan API type-safe Android 13+ yang melakukan validasi di level platform, bukan hanya di level aplikasi.

4. **Severity dimodulasi:**

   | Faktor | Severity |
   |---|---|
   | Deserialisasi tanpa validasi di komponen exported, hasil objek langsung dieksekusi/dipakai untuk keputusan sensitif | **Tinggi** |
   | Deserialisasi tanpa validasi namun di komponen tidak exported (hanya risiko bila ada kerentanan lain yang mengizinkan injeksi) | **Sedang** |
   | Deserialisasi dengan validasi tipe eksplisit | **Bukan temuan** |

5. **Dokumentasikan:** lokasi kode, sumber data (Intent/Bundle/file/network), status exported komponen terkait, dan ada/tidaknya validasi tipe.

---

## 4. Rekomendasi Perbaikan

### 4.1 Gunakan API Type-Safe untuk Parcelable (Android 13+)

```java
// SEBELUM — tanpa type checking
UserParcelable user = intent.getParcelableExtra("user");

// SESUDAH — dengan parameter tipe eksplisit
UserParcelable user = intent.getParcelableExtra("user", UserParcelable.class);
```

### 4.2 Implementasikan Allowlist untuk ObjectInputStream (Pola OWASP Look-Ahead)

```java
ObjectInputStream ois = new ObjectInputStream(inputStream) {
    @Override
    protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
        if (!ALLOWED_CLASSES.contains(desc.getName())) {
            throw new InvalidClassException("Kelas tidak diizinkan: " + desc.getName());
        }
        return super.resolveClass(desc);
    }
};
```

### 4.3 Blokir Deserialisasi pada Kelas Sensitif yang Tidak Boleh Direkonstruksi dari Luar

```java
private final void readObject(ObjectInputStream in) throws IOException {
    throw new IOException("Kelas ini tidak boleh dideserialisasi");
}
```

### 4.4 Checklist Remediasi

- [ ] Seluruh titik deserialisasi dari `Intent`/`Bundle` di komponen exported memakai validasi tipe eksplisit atau API type-safe Android 13+
- [ ] `ObjectInputStream` dilindungi allowlist kelas (pola Look-Ahead OWASP)
- [ ] Kelas sensitif yang tidak boleh direkonstruksi dari luar mengoverride `readObject()` untuk menolak deserialisasi
- [ ] Komponen yang tidak perlu diekspos ke aplikasi lain diset `exported="false"`
- [ ] Hasil pengujian manual (Metode B) didokumentasikan sebagai pelengkap wajib terhadap hasil Semgrep yang terbatas

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0337 (source, tests-beta)](https://github.com/OWASP/mastg/blob/master/tests-beta/android/MASVS-CODE/MASTG-TEST-0337.md)
- [MASTG-KNOW-0021: Object Serialization](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0021/)

### 5.2 Dokumentasi Resmi Android

- [Android Developers: Unsafe Deserialization](https://developer.android.com/privacy-and-security/risks/unsafe-deserialization)
- [OWASP Deserialization Cheat Sheet — Harden Your Own java.io.ObjectInputStream](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html#harden-your-own-javaioobjectinputstream)

### 5.3 Riset dan Kasus Nyata (CVE)

- [USENIX WOOT '15: One Class to Rule Them All — 0-Day Deserialization Vulnerabilities in Android](https://www.usenix.org/system/files/conference/woot15/woot15-paper-peles.pdf)
- [Habr: EvilParcel Vulnerabilities Analysis (CVE-2017-13315)](https://habr.com/en/companies/drweb/articles/457610/)
- [Google Project Zero: CVE-2023-20963 — Mismatching Parcel/Unparcel Logic for WorkSource](https://googleprojectzero.github.io/0days-in-the-wild/0day-RCAs/2023/CVE-2023-20963.html)
- [GitHub: TheLastBundleMismatch — Writeup CVE-2023-45777](https://github.com/michalbednarski/TheLastBundleMismatch)
- [GitHub: ReparcelBug2 — CVE-2021-0928 Writeup](https://github.com/michalbednarski/ReparcelBug2)
- [arXiv: Deserialization Gadget Chains in AOSP](https://arxiv.org/pdf/2502.08447)

### 5.4 Dokumentasi Tools

- [Semgrep Documentation](https://semgrep.dev/docs/)
- [MobSF — Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)
- [Frida — Dynamic Instrumentation Toolkit](https://frida.re/docs/home/)

---

*Dokumen ini disusun berdasarkan konten resmi OWASP MASTG (`tests-beta/android/MASVS-CODE/MASTG-TEST-0337.md`, `MASTG-KNOW-0021`), analisis rule `mastg-android-object-deserialization.yml`, dokumentasi resmi Android tentang unsafe deserialization, serta riwayat CVE panjang terkait deserialisasi di level framework Android (CVE-2014-7911, CVE-2017-13315/EvilParcel, CVE-2023-20963, CVE-2021-0928). Nuansa metodologis terpenting dan paling signifikan dari seluruh analisis ini: rule Semgrep resmi untuk test ini memiliki **kesenjangan cakupan paling ekstrem** yang ditemukan dalam seri riset ini — rule hanya menyasar pola `ObjectInputStream.readObject()` murni, sementara contoh ancaman utama yang disebut eksplisit dalam bagian Evaluation resmi test ini sendiri (`Intent` extras) **sama sekali tidak tercakup** oleh rule tersebut. Mengandalkan hasil Semgrep semata untuk test ini akan menghasilkan false negative yang sangat signifikan — pencarian manual terhadap `getSerializableExtra`/`getParcelableExtra` dan korelasinya dengan status exported komponen adalah inti pengujian yang sesungguhnya, bukan pelengkap opsional.*
