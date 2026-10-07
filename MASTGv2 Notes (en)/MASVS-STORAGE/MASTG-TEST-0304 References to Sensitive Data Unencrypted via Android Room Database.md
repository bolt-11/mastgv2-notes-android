# MASTG-TEST-0304 References to Sensitive Data Unencrypted via Android Room Database

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0304 |
| **Platform** | Android |
| **MASVS Category** | MASVS-STORAGE (MASVS-STORAGE-1) |
| **Weakness** | MASWE-0001 — *Sensitive Data Stored Unencrypted in Private Storage* |
| **Test Type** | Static, Code |
| **Official MASTG Status** | **`placeholder`** — no complete Overview/Steps/Evaluation yet |
| **Official note (the only content available)** | *"This test checks if the app uses the default SQLite API (e.g., `SQLiteOpenHelper`, `context.openOrCreateDatabase`) to store sensitive data (e.g., tokens, PII) in an unencrypted database file within the app's sandbox. It confirms the absence of secure alternatives like SQLCipher or encrypted databases."* |
| **Knowledge** | MASTG-KNOW-0037 (SQLite Database) |
| **Related Tests** | Closely related to the MASTG-TEST-0200-series (external storage) and MASTG-TEST-0287 (SharedPreferences) — both target MASWE-0001 for different storage mechanisms |
| **Related Demo** | — (none) |
| **Official Rule** | — (none) |
| **Related CWE** | CWE-312 (Cleartext Storage of Sensitive Information), CWE-311 |

---

## 1. Explanation

### 1.1 This Test's Status and Clarifying the Title vs. the Mechanism Actually Being Tested

This test has a **`placeholder`** status, but there is an important nuance that needs clarifying from the outset: **the test's official title mentions "Android Room Database"**, while **its official note** actually describes the detection mechanism via the **`SQLiteOpenHelper`** and **`context.openOrCreateDatabase`** APIs — the low-level raw SQLite API, not the Room API (`@Entity`, `@Dao`, `@Database`, `Room.databaseBuilder()`) directly. This is **not an error or metadata inconsistency** (unlike some other cases already found in this research series) — it actually reflects the **correct architectural relationship**: **Room is built on top of `SQLiteOpenHelper`**. The Room library is an **abstraction layer (ORM)** that ultimately **generates `SQLiteOpenHelper` code** behind the scenes via annotation processing at compile time — it does **not** create a new, different storage format. A database created through Room, without additional encryption configuration, ultimately **remains stored as an ordinary SQLite `.db` file** fully identical in format to one created manually via `openOrCreateDatabase()` — both are **equally vulnerable** to the same issue when left unencrypted.

### 1.2 Important Implications for Detection Methodology: Different Search Patterns for Room vs. Raw SQLite

This is the **most important technical nuance** of this document. Because Room **hides** its `SQLiteOpenHelper` calls behind its abstraction layer (that code is **automatically generated** by Room's annotation processor at compile time, not written directly by the developer), **searching for the literal text `SQLiteOpenHelper` in the application code will find nothing** in an application using Room — even though the database it ultimately produces remains unencrypted in exactly the same way.

This creates **two entirely different search patterns** for the two SQLite database usage scenarios on Android:

| Scenario | Pattern to Search For | Where It Appears |
|---|---|---|
| **Raw SQLite API** (as stated in the official note) | `SQLiteOpenHelper`, `context.openOrCreateDatabase()` | Application code written directly by the developer |
| **Room** (as stated in the official title) | `@Database`, `@Entity`, `Room.databaseBuilder(...).build()` **WITHOUT** a `SupportFactory`/`SupportOpenHelperFactory` parameter (SQLCipher) | Abstract classes extending `RoomDatabase`, Room builder calls |

A tester who **only** follows the literal search pattern from the official note (`SQLiteOpenHelper`/`openOrCreateDatabase`) will **miss every Room-based application class** that is actually the primary focus according to this test's **title** — which is why this document expands the search methodology to explicitly cover **both** pathways, rather than following the official note literally alone.

### 1.3 Room's Encryption Mechanism: Pluggable SQLite via SQLCipher

The good news is that Room is designed with a **pluggable architecture** that facilitates encryption integration without needing to rewrite the entire data access layer. Community research explains:

> *"Room supports a pluggable SQLite implementation, and so developers can plug in a SQLite edition that supports encryption, such as SQLCipher for Android. Integration is accomplished by configuring Room's database builder to use SQLCipher's `SupportOpenHelperFactory` or `SupportFactory`, which requires minimal modifications beyond specifying the factory."*

Example of the configuration difference between an **unencrypted** and an **encrypted** Room database:

```kotlin
// UNENCRYPTED — the most commonly found pattern, and the target FAIL case for this test
val db = Room.databaseBuilder(context, AppDatabase::class.java, "app_database")
    .build()
```

```kotlin
// ENCRYPTED — with SQLCipher SupportFactory
val passphrase: ByteArray = SQLiteDatabase.getBytes("secret_passphrase".toCharArray())
val factory = SupportFactory(passphrase)
val db = Room.databaseBuilder(context, AppDatabase::class.java, "app_database")
    .openHelperFactory(factory)   // <-- THIS is what distinguishes secure from insecure
    .build()
```

The difference between the two code snippets above is **textually very subtle** (a single `.openHelperFactory(factory)` line) yet **highly significant** for security — testers need to specifically search for the **absence** of an `openHelperFactory()` line on every `Room.databaseBuilder()` call, not merely search for the existence of Room itself (which will almost certainly **always** be found in a modern application, since Room is the official, widely used Android Jetpack database library).

### 1.4 Concrete Evidence of the Risk: Location and Format of the Generated File

MASTG-KNOW-0037 provides a concrete example illustrating the real impact of the lack of encryption, using the raw SQLite API as an illustration (though the consequences are **identical** for a Room database without SQLCipher):

```kotlin
var notSoSecure = openOrCreateDatabase("privateNotSoSecure", Context.MODE_PRIVATE, null)
notSoSecure.execSQL("CREATE TABLE IF NOT EXISTS Accounts(Username VARCHAR, Password VARCHAR);")
notSoSecure.execSQL("INSERT INTO Accounts VALUES('admin','AdminPass');")
```

The result: the database file is stored at `/data/data/<package-name>/databases/privateNotSoSecure` as a **plain SQLite file fully openable and readable** by anyone with access to that directory (root, device forensics, backup extraction — refer to the MASTG-TEST-0262 discussion in this research series) using any standard SQLite tool (`sqlite3`, DB Browser for SQLite) with no cryptographic barrier whatsoever. **There is no difference** in this consequence between a database created via `openOrCreateDatabase()` directly or via `Room.databaseBuilder()` without a `SupportFactory` — both produce `.db` files that are **equally directly openable** with a generic SQLite tool.

### 1.5 Supporting Files That Also Need Checking: Journal and Lock Files

MASTG-KNOW-0037 provides an additional note relevant to audit completeness:

> *"The database's directory may contain several files besides the SQLite database: Journal files... Lock files..."*

SQLite journal files (`-journal`, `-wal` for Write-Ahead Logging) **can hold temporary copies of data** being written/modified — including sensitive data currently being processed — before the final transaction is committed to the main database file. A thorough audit should ideally **also check** the presence and content of these supporting files, not just the main `.db` file, since they can represent an **additional leakage window** that auditors who focus solely on the main database file rarely check.

---

## 2. Tools Used for Testing

### 2.1 Required Tools (Core)

| Tool | Function |
|---|---|
| **jadx** | DEX → Java/Kotlin-like decompilation for searching Room and raw SQLite patterns |
| **grep / ripgrep** | API pattern searches — covering BOTH pathways (Room and raw SQLite) per §1.2 |
| **sqlite3 (CLI)** / **DB Browser for SQLite** | Directly opening the `.db` file extracted from the device to verify whether its contents can truly be read without a password/key |

### 2.2 Alternative & Supporting Tools

| Tool | Function |
|---|---|
| **CodeQL** | Tracing every class that extends `RoomDatabase` and verifying whether the related `Room.databaseBuilder()` call includes `.openHelperFactory()` with an SQLCipher `SupportFactory` |
| **MobSF** | Sometimes flags SQLite/Room database usage in the Code Analysis report |
| **adb** | Directly extracting the `.db` file from `/data/data/<package>/databases/` (requires root/run-as) for direct verification |
| **TruffleHog/gitleaks** | Secret pattern scanning on dumped database table contents, as discussed in the MASTG-TEST-0287/0212 documents in this research series |

### 2.3 Environment Prerequisites

- **No device/root required** for the core static analysis.
- **Root/`run-as` required** for direct extraction and verification of the `.db` file from the device.
- **Identify sensitive data first** (an implied prerequisite, consistent with other MASVS-STORAGE tests in this research series) to determine which tables/columns are relevant to inspect.

---

## 3. Testing Methodology

Since there are no detailed official steps (placeholder status), the following methodology is composed from an elaboration of the official note plus an extension to cover Room per the test's title.

### 3.1 General Steps

1. Identify every database mechanism the application uses (Room **and/or** raw SQLite).
2. For raw SQLite: search for `SQLiteOpenHelper`/`openOrCreateDatabase()`.
3. For Room: search for `@Database` classes/classes extending `RoomDatabase`, then verify the presence of a `SupportFactory`.
4. Extract the `.db` file from the device and directly verify whether it can be opened without a key.

### 3.2 Method A — grep/ripgrep for Both Pathways

```bash
D=./decompiled/sources

# Pathway 1: raw SQLite (per the official note)
rg -n 'extends SQLiteOpenHelper|openOrCreateDatabase\(' $D

# Pathway 2: Room — find the database definition
rg -n '@Database\(|extends RoomDatabase' $D

# Pathway 2: Room — check EVERY databaseBuilder call and verify the SupportFactory
rg -n -A10 'Room\.databaseBuilder\(' $D | grep -B10 '\.build()' | grep -c "SupportFactory\|openHelperFactory"
```

If the final result shows **0** for a given `databaseBuilder()` block, this is a FAIL candidate — that Room database is built without encryption.

### 3.3 Method B — CodeQL for Systematic Verification of Every Room Instance

```ql
import java

class RoomDatabaseBuilderCall extends MethodAccess {
  RoomDatabaseBuilderCall() {
    this.getMethod().hasName("databaseBuilder") and
    this.getMethod().getDeclaringType().hasQualifiedName("androidx.room", "Room")
  }
}

class OpenHelperFactoryCall extends MethodAccess {
  OpenHelperFactoryCall() {
    this.getMethod().hasName("openHelperFactory")
  }
}

from RoomDatabaseBuilderCall builder
where not exists(OpenHelperFactoryCall factory |
  factory.getQualifier().toString() = builder.toString() or
  factory.getEnclosingCallable() = builder.getEnclosingCallable())
select builder, "Room.databaseBuilder() found WITHOUT an openHelperFactory (SQLCipher) — database likely unencrypted"
```

### 3.4 Method C — Direct Verification of the `.db` File (Definitive Evidence)

```bash
adb shell run-as com.target.app ls /data/data/com.target.app/databases/
adb shell run-as com.target.app cat /data/data/com.target.app/databases/app_database > ./app_database_dump.db

# Try opening it DIRECTLY without any password
sqlite3 ./app_database_dump.db ".tables"
sqlite3 ./app_database_dump.db "SELECT * FROM users LIMIT 5;"
```

If this command **succeeds** in displaying the table structure and data content without an error/password, this is definitive proof that the database is **unencrypted** — regardless of whether it was created via Room or raw SQLite. If the database is properly SQLCipher-encrypted, standard `sqlite3` will display an error (`file is not a database`) because the format no longer matches the plain SQLite specification.

### 3.5 Method D — Check Supporting Journal/Lock Files (§1.5)

```bash
adb shell run-as com.target.app ls -la /data/data/com.target.app/databases/
# Note files with the suffix -journal, -wal, -shm
adb shell run-as com.target.app cat /data/data/com.target.app/databases/app_database-wal > ./wal_dump.bin
strings ./wal_dump.bin | grep -iE "password|token|email"
```

### 3.6 Method Comparison: When to Use Which

| Method | Tool | Covers Room? | Covers raw SQLite? | Definitive evidence? | When to use |
|---|---|---|---|---|---|
| **A** | grep | ✅ | ✅ | ❌ | Baseline, **must cover both pathways** |
| **B** | CodeQL | ✅ (precise) | Partial | ❌ | Large codebases with many Room definitions |
| **C** | `.db` file verification | N/A | N/A | ✅ | **Mandatory** as final proof |
| **D** | Journal/lock files | N/A | N/A | ✅ (supplementary) | Audit thoroughness (§1.5) |

**Recommended minimum combination:** **A (covering both the Room AND raw SQLite pathways) → C (direct `.db` file verification as irrefutable evidence)**, supplemented by **D** for a more thorough audit.

---

### 3.7 Evaluation Criteria: Positive Case & Negative Case

Since there is no official Evaluation clause (placeholder status), the following criteria are composed based on the official note and the fundamental principles of MASWE-0001.

---

#### ❌ FAIL / ISSUE — The check is declared FAILED when:

| No | Condition |
|---|---|
| F1 | The application uses `SQLiteOpenHelper`/`openOrCreateDatabase()` to store sensitive data without additional encryption |
| F2 | The application uses Room (`Room.databaseBuilder()`) **without** an SQLCipher `.openHelperFactory()` for a table storing sensitive data |
| F3 | Direct verification (Method C) confirms the `.db` file can be fully opened and read by standard `sqlite3` without a password |
| F4 | A supporting journal/WAL file (Method D) is found to contain sensitive data in readable plaintext form |

**Example evidence (illustrative — MASTG does not yet provide an official demo for this test):**

```kotlin
// AppDatabase.kt
@Database(entities = [User::class], version = 1)
abstract class AppDatabase : RoomDatabase() {
    abstract fun userDao(): UserDao
}

// DatabaseModule.kt
val db = Room.databaseBuilder(context, AppDatabase::class.java, "user_database")
    .build()  // NO openHelperFactory
```

```bash
$ adb shell run-as com.example.target cat /data/data/com.example.target/databases/user_database > dump.db
$ sqlite3 dump.db "SELECT * FROM User;"
1|admin@example.com|5f4dcc3b5aa765d61d8327deb882cf99
```

Interpretation: the Room database is built without a `SupportFactory`, and direct verification confirms the `User` table (including the email and password hash) is fully readable with no obstacle whatsoever. **FAIL**.

---

#### ✅ PASS — The check is declared PASSED when:

| No | Condition |
|---|---|
| P1 | Every database (Room/raw SQLite) that stores sensitive data uses SQLCipher (`SupportFactory`) or an equivalent encryption mechanism |
| P2 | Direct verification (Method C) confirms that standard `sqlite3` **fails** to open the file (`file is not a database`) |
| P3 | Supporting journal/WAL files do not contain any readable sensitive plaintext data |

---

#### ⚠️ Important Notes on Assessment

1. **Do not merely follow the official note literally** — per §1.2, a search purely for `SQLiteOpenHelper` will miss every Room-based database, which is the primary focus per this test's title. Always cover both pathways.

2. **The code difference between secure and insecure is textually very subtle** (§1.3) — a single missing `.openHelperFactory()` line is the only distinguishing factor. Do not conclude FAIL/PASS merely from the general presence of Room (which is almost always present in a modern application); check each `databaseBuilder()` call specifically.

3. **Direct `.db` file verification is the most definitive and easiest-to-interpret evidence** — if `sqlite3` succeeds in opening and displaying the data, there is no ambiguity whatsoever about the encryption status.

4. **Don't forget the journal/WAL files** — an audit that only checks the main `.db` file may miss sensitive data still residing in temporary supporting files.

5. **Severity modulation:**

   | Factor | Severity |
   |---|---|
   | Table contains credentials/tokens/PII without encryption, verified directly readable | **Critical** |
   | Table contains non-sensitive data without encryption | **Not a finding** |
   | SQLCipher encryption applied but the passphrase is hardcoded (refer to MASTG-TEST-0212) | **High** — encryption exists but its own key is leaked |

6. **Document:** the database mechanism used (Room/raw SQLite), the `SupportFactory`/encryption status for each database instance, the direct `.db` file verification result, and the journal/WAL file inspection result.

---

## 4. Recommendations

### 4.1 Integrate SQLCipher into Room

```kotlin
dependencies {
    implementation "net.zetetic:android-database-sqlcipher:4.5.4"
}
```

```kotlin
val passphrase = SQLiteDatabase.getBytes(getSecurePassphraseFromKeystore())  // DO NOT hardcode
val factory = SupportFactory(passphrase)
val db = Room.databaseBuilder(context, AppDatabase::class.java, "user_database")
    .openHelperFactory(factory)
    .build()
```

**Important**: store the passphrase via the **Android Keystore** (refer to the pattern in the MASTG-TEST-0212 document), do not hardcode it in the code — encrypting the database has no value if its own key is leaked.

### 4.2 For Migrating Old, Not-Yet-Encrypted Databases

```kotlin
// Check whether the database is already encrypted; if not, encrypt it in place
if (!isDatabaseEncrypted(oldDbPath)) {
    SQLiteDatabase.loadLibs(context)
    val db = SQLiteDatabase.openDatabase(oldDbPath, "", null, SQLiteDatabase.OPEN_READWRITE)
    db.rawExecSQL("ATTACH DATABASE '$newEncryptedDbPath' AS encrypted KEY '$passphrase'")
    db.rawExecSQL("SELECT sqlcipher_export('encrypted')")
    db.rawExecSQL("DETACH DATABASE encrypted")
}
```

### 4.3 Remediation Checklist

- [ ] Every Room/raw SQLite instance storing sensitive data is inventoried
- [ ] SQLCipher (`SupportFactory`) is applied to every relevant database
- [ ] The passphrase is stored via the Android Keystore, not hardcoded
- [ ] Direct verification of the `.db` file confirms it cannot be opened without the key
- [ ] Journal/WAL files are checked for the absence of sensitive plaintext data
- [ ] **Re-verify:** rerun MASTG-TEST-0304 with every new table/entity addition

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0304: References to Sensitive Data Unencrypted via Android Room Database](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0304/)
- [MASTG-TEST-0287: Runtime Storage of Unencrypted Data via the SharedPreferences API](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0287/)
- [MASTG-TEST-0212: Use of Hardcoded Cryptographic Keys in Code](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0212/)
- [MASWE-0001: Sensitive Data Stored Unencrypted in Private Storage](https://mas.owasp.org/MASWE/MASVS-STORAGE/MASWE-0001/)
- [MASTG-KNOW-0037: SQLite Database](https://mas.owasp.org/MASTG/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0037/)

### 5.2 Official Android Documentation

- [Android Developers — Save data in a local database using Room](https://developer.android.com/training/data-storage/room)
- [Android Developers — SQLite Documentation](https://developer.android.com/training/data-storage/sqlite)
- [SQLite — Temporary Files (Journal)](https://www.sqlite.org/tempfiles.html)
- [SQLite — Lock Files](https://www.sqlite.org/lockingv3.html)

### 5.3 Research and Community Articles

- [CommonsWare — Introducing SQLCipher for Android](https://commonsware.com/Room/pages/chap-sqlcipher-001.html)
- [sonique6784 — Protect your Room database with SQLCipher on Android](https://sonique6784.medium.com/protect-your-room-database-with-sqlcipher-on-android-78e0681be687)
- [Medium — Encrypting an Existing Room Database with SQLCipher](https://medium.com/@khambhaytajaydip/encrypting-an-existing-room-database-with-sqlcipher-in-android-50cdc98fe6c)
- [GitHub — android-database-sqlcipher](https://github.com/OutSystems/android-database-sqlcipher)
- [CWE-312: Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)

### 5.4 Tool Documentation

- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [CodeQL — Documentation](https://codeql.github.com/docs/)
- [DB Browser for SQLite](https://sqlitebrowser.org/)
- [TruffleHog](https://docs.trufflesecurity.com/)

---

*This document was compiled based on OWASP MASTG (latest release as of September 2026), official Android Developers documentation, and community research on integrating SQLCipher with Room. The most important nuance: the test's title mentions "Room Database," but its official note describes detection via the raw SQLite API (`SQLiteOpenHelper`) — this is not an inconsistency, but reflects the architectural fact that Room is built on top of SQLiteOpenHelper and produces an identical storage format absent additional encryption configuration. A thorough evaluation requires searching for patterns across **both** pathways (Room and raw SQLite) explicitly, since searching for the literal `SQLiteOpenHelper` alone will miss every Room-based database that is actually this test's primary focus.*
