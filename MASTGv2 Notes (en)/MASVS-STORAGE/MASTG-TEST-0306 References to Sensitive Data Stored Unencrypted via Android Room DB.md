# MASTG-TEST-0306 References to Sensitive Data Stored Unencrypted via Android Room DB

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0306 |
| **Platform** | Android |
| **MASVS Category** | MASVS-STORAGE (MASVS-STORAGE-1) |
| **Weakness** | MASWE-0001 — *Sensitive Data Stored Unencrypted in Private Storage* |
| **Test Type** | Static, Code |
| **Official MASTG Status** | **`placeholder`** — no complete Overview/Steps/Evaluation yet |
| **Official note (the only content available)** | *"This test checks if the app uses the Android Room Persistence Library to store sensitive data (e.g., tokens, PII) without integrating an encryption layer (e.g., SQLCipher). It confirms the database file is stored in plaintext within the app's private sandbox."* |
| **Related Tests** | **MASTG-TEST-0304** (References to Sensitive Data Unencrypted via Android Room Database) — **see §1.1 for an important clarification about the relationship and possible overlap between these two tests** |
| **Related Demo** | — (none) |
| **Official Rule** | — (none) |
| **Related CWE** | CWE-312, CWE-311 |

---

## 1. Explanation

### 1.1 Important Clarification: Relationship and Overlap with MASTG-TEST-0304

This is a methodological note that **must** be stated at the very start of this document, because research found that **MASTG-TEST-0306 and MASTG-TEST-0304** — both with `placeholder` status, both targeting the identical MASWE-0001, both of type `static, code` — have **titles and scopes that overlap heavily**:

| | MASTG-TEST-0304 | MASTG-TEST-0306 *(this document)* |
|---|---|---|
| **Title** | *"...via Android Room **Database**"* | *"...via Android Room **DB**"* |
| **Focus of the official note** | **Raw SQLite** API (`SQLiteOpenHelper`, `openOrCreateDatabase`) — even though the title mentions "Room" | **Android Room Persistence Library** explicitly and specifically |
| **Confirmation criteria** | "Absence of secure alternatives like SQLCipher or encrypted databases" | "Without integrating an encryption layer (e.g., SQLCipher)... database file is stored in plaintext" |

An identifiable substantive difference: **MASTG-TEST-0304** (per the in-depth analysis in that document) actually focuses on **detecting the raw SQLite API** (`SQLiteOpenHelper`/`openOrCreateDatabase`) even though its title mentions "Room" — whereas **MASTG-TEST-0306** targets the **Room Persistence Library** itself (`@Database`, `Room.databaseBuilder()`) **far more explicitly and consistently** as its primary object of testing, without any ambiguity of reference to the raw SQLite API.

**Possible explanation**: this may potentially reflect an **ongoing content restructuring stage** within the MASTG beta test catalog — where MASTG-TEST-0304 may have originally been intended to cover the entire spectrum (both raw SQLite **and** Room), while MASTG-TEST-0306 was later added as a **more precise, Room-specific version**, leaving a temporary overlap before these two tests are likely to be reconciled/merged in a future final MASTG release. Regardless of the exact explanation, **for testers right now**, the practical implication is: **both tests fundamentally demand the same testing methodology** for the Room component — so this document will **extensively reference** the methodology already built in depth in the MASTG-TEST-0304 document, while reaffirming the specific focus on the Room Persistence Library per this test's official note.

### 1.2 The Core Issue: Room Encrypts Nothing by Default

Refer to **the MASTG-TEST-0304 document §1.1** for the complete architectural explanation of why Room — as an ORM layer built on top of `SQLiteOpenHelper` — **inherits the unencrypted storage characteristics** of the underlying SQLite, unless the developer explicitly integrates an additional encryption layer. This test's official note reaffirms the same point even more explicitly:

> *"It confirms the database file is stored in plaintext within the app's private sandbox."*

Without SQLCipher integration (or an equivalent encryption mechanism), every `@Entity` defined within a Room schema — including columns storing tokens, passwords, or PII — ultimately ends up stored as **pure plaintext** data rows within a standard SQLite `.db` file at `/data/data/<package>/databases/`, directly openable with any generic SQLite tool by anyone who gains access to that application's sandbox (root, device forensics, backup extraction).

### 1.3 A Difference in Emphasis: "Integrating an Encryption Layer" as an Explicit Criterion

Although substantively similar to MASTG-TEST-0304, this test's official note phrases its criterion in slightly different, **noteworthy** wording: *"without integrating an **encryption layer**"*. This phrase emphasizes that what is being sought is not merely "whether the word SQLCipher appears in a dependency," but **whether that encryption layer is actually functionally integrated** into the Room configuration being used — exactly matching the technical distinction already discussed in depth in the MASTG-TEST-0304 document §1.3, regarding the thin yet crucial difference between `Room.databaseBuilder().build()` (unencrypted) versus `.openHelperFactory(SupportFactory(passphrase)).build()` (encrypted).

---

## 2. Tools Used for Testing

The tool methodology for this test is **identical** to what has already been built in **the MASTG-TEST-0304 document §2**, specifically the portion targeting Room (not the raw SQLite portion, which is outside this test's specific scope). Summary:

| Tool | Function |
|---|---|
| **jadx** | Decompilation for finding `@Database`/`RoomDatabase` classes |
| **grep / ripgrep** | Finding `Room.databaseBuilder()` and verifying `.openHelperFactory()` |
| **CodeQL** | Systematic verification of every `Room.databaseBuilder()` instance for the presence of a `SupportFactory` |
| **adb + sqlite3** | Direct extraction and verification of the `.db` file from the device — definitive evidence |
| **DB Browser for SQLite** | Alternative GUI for opening the extracted `.db` file |

Refer to the MASTG-TEST-0304 document §2 for environment prerequisite details, which apply identically here.

---

## 3. Testing Methodology

Since there are no detailed official steps (placeholder status) and the methodology is identical to MASTG-TEST-0304, this section refers to the same methods with adjustments focused purely on Room.

### 3.1 General Steps

1. Identify all classes that extend `RoomDatabase` and are annotated with `@Database`.
2. For each Room database class found, trace the **call location** of `Room.databaseBuilder(...).build()` that instantiates it.
3. Verify whether that call includes `.openHelperFactory()` with a `SupportFactory` (SQLCipher) before `.build()`.
4. Confirm directly by extracting the `.db` file from the device.

### 3.2 Method A — grep/ripgrep (Refer to MASTG-TEST-0304 §3.2, Method A, Room Section)

```bash
D=./decompiled/sources

# Find Room database definitions
rg -n '@Database\(' $D

# Find instantiation and verify the presence of a SupportFactory
rg -n -A10 'Room\.databaseBuilder\(' $D | grep -B10 '\.build()' | grep -c "SupportFactory\|openHelperFactory"
```

### 3.3 Method B — CodeQL (Identical to MASTG-TEST-0304 §3.3)

Refer to the full CodeQL query in the MASTG-TEST-0304 document — that query already specifically targets `Room.databaseBuilder()` and `openHelperFactory()`, so it applies exactly the same way for this test.

### 3.4 Method C — Direct Verification of the `.db` File (Identical to MASTG-TEST-0304 §3.4)

```bash
adb shell run-as com.target.app ls /data/data/com.target.app/databases/
adb shell run-as com.target.app cat /data/data/com.target.app/databases/app_database > ./app_database_dump.db
sqlite3 ./app_database_dump.db ".tables"
sqlite3 ./app_database_dump.db "SELECT * FROM users LIMIT 5;"
```

Refer to the MASTG-TEST-0304 document §3.4 for the full interpretation of results.

### 3.5 Method Comparison

Refer to the full comparison table in the MASTG-TEST-0304 document §3.6 — it applies fully to this test without modification, since the Room scope in both documents is identical.

**Recommended minimum combination:** **grep/CodeQL to identify every Room instance without a SupportFactory → direct verification of the `.db` file as irrefutable evidence.**

---

### 3.6 Evaluation Criteria: Positive Case & Negative Case

Since there is no official Evaluation clause (placeholder status) and the criteria are substantively identical to the Room section of MASTG-TEST-0304, the following criteria are a version focused purely on the Room Persistence Library.

---

#### ❌ FAIL / ISSUE — The check is declared FAILED when:

| No | Condition |
|---|---|
| F1 | A `@Database`/`RoomDatabase` class storing entities with sensitive columns (tokens, PII, credentials) is instantiated via `Room.databaseBuilder()` **without** SQLCipher's `.openHelperFactory()` |
| F2 | Direct verification of the `.db` file (Method C) confirms standard `sqlite3` **successfully** opens and displays the table contents without a password |

**Example evidence (illustrative — MASTG does not yet provide an official demo for this test; also refer to the identical example in the MASTG-TEST-0304 document §3.7):**

```kotlin
@Database(entities = [AuthToken::class], version = 1)
abstract class AppDatabase : RoomDatabase() {
    abstract fun authTokenDao(): AuthTokenDao
}

val db = Room.databaseBuilder(context, AppDatabase::class.java, "secure_session_db")
    .build()  // NO openHelperFactory — this Room database is NOT encrypted
```

---

#### ✅ PASS — The check is declared PASSED when:

| No | Condition |
|---|---|
| P1 | Every Room database storing sensitive entities uses `.openHelperFactory()` with a correctly configured SQLCipher `SupportFactory` |
| P2 | Direct verification of the `.db` file confirms standard `sqlite3` **fails** to open the file (`file is not a database`) |
| P3 | The application does not use the Room Persistence Library to store sensitive data at all |

---

#### ⚠️ Important Notes on Assessment

1. **If MASTG-TEST-0304 has already been run in full (covering its Room portion), the test result for this test is most likely already answered** — given the scope overlap explained in §1.1. Explicitly document in the audit report that both test IDs were evaluated together using the same methodology, for transparency to the report's readers.

2. **Do not duplicate testing effort unnecessarily** — if an organization/audit team runs both tests separately without realizing the overlap, this risks wasting time and producing a confusing report (two "different" findings for the identical root cause). It is recommended to evaluate both within the same Room analysis session.

3. **Severity and remediation recommendations are identical to MASTG-TEST-0304** — refer to that document's §3.7 (evaluation notes) and §4 (recommendations) in full, since there is no substantive difference in how these two tests should be handled.

4. **Document:** the SQLCipher integration status for each Room instance, the `.db` file verification results, and an explicit note that this finding was evaluated together with MASTG-TEST-0304.

---

## 4. Recommendations

Refer to **the MASTG-TEST-0304 document §4** for the complete recommendations — SQLCipher integration via `SupportFactory`, storing the passphrase through the Android Keystore (not hardcoded), and migration strategies for old, unencrypted Room databases. All of those recommendations apply identically to this test without modification, since the root cause and technical solution are entirely the same.

### 4.1 Remediation Checklist

- [ ] All `@Database`/`RoomDatabase` classes storing sensitive entities are inventoried
- [ ] `SupportFactory` (SQLCipher) is applied to all relevant instances
- [ ] The passphrase is stored via the Android Keystore
- [ ] Direct verification of the `.db` file confirms it cannot be opened without the key
- [ ] Test results are explicitly correlated with MASTG-TEST-0304 to avoid duplicate reporting
- [ ] **Re-verify:** rerun MASTG-TEST-0306 after every addition of a new Room entity/table

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0306: References to Sensitive Data Stored Unencrypted via Android Room DB](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0306/)
- [MASTG-TEST-0304: References to Sensitive Data Unencrypted via Android Room Database](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0304/) — **primary reference for the complete methodology**
- [MASTG-TEST-0305: Sensitive Data Stored Unencrypted via DataStore](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0305/)
- [MASWE-0001: Sensitive Data Stored Unencrypted in Private Storage](https://mas.owasp.org/MASWE/MASVS-STORAGE/MASWE-0001/)

### 5.2 Official Android Documentation

- [Android Developers — Save data in a local database using Room](https://developer.android.com/training/data-storage/room)

### 5.3 Research and Community Articles

Refer to the complete list of SQLCipher/Room research in the MASTG-TEST-0304 document §5.3 — all of those sources are equally relevant to this test.

### 5.4 Tool Documentation

Refer to the complete list in the MASTG-TEST-0304 document §5.4.

---

*This document was compiled entirely from independent research because MASTG-TEST-0306 has a **placeholder** status. The most important methodological finding: this test has **substantial overlap** with MASTG-TEST-0304, already discussed earlier in this research series — both target MASWE-0001 within the context of the Room Persistence Library, with MASTG-TEST-0304 historically leaning more toward detecting the raw SQLite API (even though its title mentions Room) while MASTG-TEST-0306 explicitly and consistently focuses on the Room Persistence Library itself. Testers are advised to evaluate both test IDs within the same analysis session for efficiency, and to transparently document that both refer to identical methodology and findings until MASTG releases an official clarification/consolidation of these two beta tests.*
