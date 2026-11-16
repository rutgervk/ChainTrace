package nl.chaintrace.app.osint

import android.content.ContentValues
import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import org.json.JSONArray
import org.json.JSONObject

/**
 * Lokale OSINT-database op het apparaat. Alles staat in één SQLite-bestand:
 *  - label:       adres-labels uit open bronnen (OFAC, scamlijsten, exchanges, Tether-bevriezingen …)
 *  - observation: eigen waarnemingen uit traces (rol, classificatie, vlaggen per zaak)
 *  - source:      synchronisatiestatus per bron
 *  - kv:          cursors/hashes voor incrementele updates
 */
class OsintDb private constructor(ctx: Context) : SQLiteOpenHelper(ctx, "osint.db", null, 2) {

    override fun onConfigure(db: SQLiteDatabase) {
        db.enableWriteAheadLogging()
    }

    override fun onCreate(db: SQLiteDatabase) {
        db.execSQL(
            """CREATE TABLE label(
                address TEXT NOT NULL, chain TEXT, label TEXT NOT NULL, category TEXT NOT NULL,
                source TEXT NOT NULL, detail TEXT, updated INTEGER NOT NULL,
                PRIMARY KEY(address, source, label))"""
        )
        db.execSQL("CREATE INDEX label_addr ON label(address)")
        db.execSQL("CREATE INDEX label_text ON label(label COLLATE NOCASE)")
        db.execSQL(
            """CREATE TABLE observation(
                address TEXT NOT NULL, chain TEXT, case_seed TEXT NOT NULL, pattern TEXT,
                role TEXT, classification TEXT, flags TEXT, label TEXT, seen INTEGER NOT NULL,
                PRIMARY KEY(address, case_seed))"""
        )
        db.execSQL("CREATE INDEX obs_addr ON observation(address)")
        db.execSQL(
            """CREATE TABLE source(
                id TEXT PRIMARY KEY, name TEXT, url TEXT, last_sync INTEGER, count INTEGER,
                status TEXT, error TEXT)"""
        )
        db.execSQL("CREATE TABLE kv(k TEXT PRIMARY KEY, v TEXT)")
        createFreeze(db)
    }

    /** Laatste bevriezing en laatste opheffing per adres (Tether-blacklist). */
    private fun createFreeze(db: SQLiteDatabase) {
        db.execSQL(
            """CREATE TABLE IF NOT EXISTS freeze(
                address TEXT NOT NULL, chain TEXT NOT NULL, added INTEGER, removed INTEGER,
                PRIMARY KEY(address, chain))"""
        )
    }

    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
        if (oldVersion < 2) {
            createFreeze(db)
            // v1 kende geen opheffingen: Tether-bronnen opnieuw vanaf het begin opbouwen.
            db.delete("kv", "k LIKE 'tether_%'", null)
            db.delete("label", "source LIKE 'tether_%'", null)
        }
    }

    // ---------- schrijven ----------

    /** Vervangt alle labels van één bron in één transactie (snapshot-bronnen). */
    fun replaceSource(source: String, rows: Sequence<LabelRow>): Int = writeLabels(source, rows, replace = true)

    fun clearSource(source: String) {
        writableDatabase.delete("label", "source=?", arrayOf(source))
    }

    /** Voegt labels toe zonder bestaande te wissen (incrementele bronnen). */
    fun appendLabels(source: String, rows: Sequence<LabelRow>): Int = writeLabels(source, rows, replace = false)

    private fun writeLabels(source: String, rows: Sequence<LabelRow>, replace: Boolean): Int {
        val db = writableDatabase
        var n = 0
        db.beginTransaction()
        try {
            if (replace) db.delete("label", "source=?", arrayOf(source))
            val st = db.compileStatement(
                "INSERT OR REPLACE INTO label(address,chain,label,category,source,detail,updated) VALUES(?,?,?,?,?,?,?)"
            )
            val now = System.currentTimeMillis()
            for (r in rows) {
                if (r.address.isBlank()) continue
                st.clearBindings()
                st.bindString(1, normalize(r.address))
                bindOrNull(st, 2, r.chain)
                st.bindString(3, r.label.ifBlank { r.category }.take(200))
                st.bindString(4, r.category)
                st.bindString(5, source)
                bindOrNull(st, 6, r.detail?.take(500))
                st.bindLong(7, now)
                st.executeInsert()
                n++
            }
            db.setTransactionSuccessful()
        } finally {
            db.endTransaction()
        }
        return n
    }

    private fun bindOrNull(st: android.database.sqlite.SQLiteStatement, i: Int, v: String?) {
        if (v == null) st.bindNull(i) else st.bindString(i, v)
    }

    fun setSourceStatus(id: String, name: String, url: String, status: String, error: String? = null, success: Boolean = false) {
        val cv = ContentValues().apply {
            put("id", id); put("name", name); put("url", url); put("status", status); put("error", error)
            put("count", countForSource(id))
            if (success) put("last_sync", System.currentTimeMillis())
        }
        val db = writableDatabase
        if (db.update("source", cv, "id=?", arrayOf(id)) == 0) db.insert("source", null, cv)
    }

    private fun countForSource(id: String): Long =
        readableDatabase.rawQuery("SELECT COUNT(*) FROM label WHERE source=?", arrayOf(id)).use { c -> c.moveToFirst(); c.getLong(0) }

    fun recordFreezes(chain: String, events: List<FreezeEvent>) {
        if (events.isEmpty()) return
        val db = writableDatabase
        db.beginTransaction()
        try {
            val ins = db.compileStatement("INSERT OR IGNORE INTO freeze(address, chain) VALUES(?, ?)")
            val add = db.compileStatement("UPDATE freeze SET added = MAX(IFNULL(added, 0), ?) WHERE address=? AND chain=?")
            val rem = db.compileStatement("UPDATE freeze SET removed = MAX(IFNULL(removed, 0), ?) WHERE address=? AND chain=?")
            for (e in events) {
                val a = normalize(e.address)
                ins.bindString(1, a); ins.bindString(2, chain); ins.executeInsert()
                val st = if (e.added) add else rem
                st.bindLong(1, e.time); st.bindString(2, a); st.bindString(3, chain); st.executeUpdateDelete()
            }
            db.setTransactionSuccessful()
        } finally {
            db.endTransaction()
        }
    }

    /** Zet de labels van een Tether-bron gelijk aan de adressen die nu nog bevroren zijn. */
    fun rebuildFrozenLabels(source: String, chain: String, label: String): Int {
        val fmt = java.text.SimpleDateFormat("yyyy-MM-dd", java.util.Locale.ROOT)
        val rows = ArrayList<LabelRow>()
        readableDatabase.rawQuery(
            "SELECT address, added FROM freeze WHERE chain=? AND added IS NOT NULL AND (removed IS NULL OR added > removed)", arrayOf(chain)
        ).use { c ->
            while (c.moveToNext()) rows.add(LabelRow(c.getString(0), chain, label, "frozen", "bevroren sinds " + fmt.format(java.util.Date(c.getLong(1)))))
        }
        return replaceSource(source, rows.asSequence())
    }

    fun getKv(k: String): String? =
        readableDatabase.rawQuery("SELECT v FROM kv WHERE k=?", arrayOf(k)).use { if (it.moveToFirst()) it.getString(0) else null }

    fun setKv(k: String, v: String) {
        writableDatabase.insertWithOnConflict("kv", null, ContentValues().apply { put("k", k); put("v", v) }, SQLiteDatabase.CONFLICT_REPLACE)
    }

    fun recordObservations(json: String) {
        val o = JSONObject(json)
        val seed = o.getString("seed")
        val pattern = o.optString("pattern")
        val arr = o.getJSONArray("nodes")
        val db = writableDatabase
        db.beginTransaction()
        try {
            val now = System.currentTimeMillis()
            for (i in 0 until arr.length()) {
                val n = arr.getJSONObject(i)
                db.insertWithOnConflict("observation", null, ContentValues().apply {
                    put("address", normalize(n.getString("address")))
                    put("chain", n.optString("chain"))
                    put("case_seed", seed)
                    put("pattern", pattern)
                    put("role", n.optString("role").ifEmpty { null })
                    put("classification", n.optString("classification"))
                    put("flags", n.optJSONArray("flags")?.toString())
                    put("label", n.optString("label").ifEmpty { null })
                    put("seen", now)
                }, SQLiteDatabase.CONFLICT_REPLACE)
            }
            db.setTransactionSuccessful()
        } finally {
            db.endTransaction()
        }
    }

    fun setUserLabel(chain: String, address: String, label: String) {
        val addr = normalize(address)
        writableDatabase.delete("label", "address=? AND source='eigen'", arrayOf(addr))
        if (label.isNotBlank()) appendLabels("eigen", sequenceOf(LabelRow(addr, chain, label, "user", "Eigen label")))
    }

    // ---------- lezen ----------

    fun lookup(address: String, excludeCase: String?): JSONObject {
        val addr = normalize(address)
        val labels = JSONArray()
        readableDatabase.rawQuery(
            "SELECT label,category,source,detail,updated FROM label WHERE address=? LIMIT 50", arrayOf(addr)
        ).use { c ->
            while (c.moveToNext()) labels.put(JSONObject().apply {
                put("label", c.getString(0)); put("category", c.getString(1)); put("source", c.getString(2))
                put("detail", c.getString(3)); put("updated", c.getLong(4))
            })
        }
        val obs = JSONArray()
        readableDatabase.rawQuery(
            "SELECT case_seed,pattern,role,classification,label,seen FROM observation WHERE address=? AND case_seed<>? ORDER BY seen DESC LIMIT 20",
            arrayOf(addr, excludeCase?.let { normalize(it) } ?: "")
        ).use { c ->
            while (c.moveToNext()) obs.put(JSONObject().apply {
                put("caseSeed", c.getString(0)); put("pattern", c.getString(1)); put("role", c.getString(2))
                put("classification", c.getString(3)); put("label", c.getString(4)); put("seen", c.getLong(5))
            })
        }
        return JSONObject().put("labels", labels).put("observations", obs)
    }

    fun search(query: String, limit: Int = 60): JSONArray {
        val q = query.trim()
        val out = JSONArray()
        if (q.length < 3) return out
        val sql = "SELECT address,chain,label,category,source FROM label WHERE address LIKE ? OR label LIKE ? LIMIT ?"
        readableDatabase.rawQuery(sql, arrayOf(normalize(q) + "%", "%$q%", limit.toString())).use { c ->
            while (c.moveToNext()) out.put(JSONObject().apply {
                put("address", c.getString(0)); put("chain", c.getString(1)); put("label", c.getString(2))
                put("category", c.getString(3)); put("source", c.getString(4))
            })
        }
        return out
    }

    fun stats(dbFileSize: Long): JSONObject {
        val sources = JSONArray()
        readableDatabase.rawQuery("SELECT id,name,url,last_sync,count,status,error FROM source ORDER BY name", null).use { c ->
            while (c.moveToNext()) sources.put(JSONObject().apply {
                put("id", c.getString(0)); put("name", c.getString(1)); put("url", c.getString(2))
                put("lastSync", if (c.isNull(3)) JSONObject.NULL else c.getLong(3)); put("count", c.getLong(4))
                put("status", c.getString(5)); put("error", c.getString(6))
            })
        }
        val total = readableDatabase.rawQuery("SELECT COUNT(*), COUNT(DISTINCT address) FROM label", null)
            .use { it.moveToFirst(); it.getLong(0) to it.getLong(1) }
        val obs = readableDatabase.rawQuery("SELECT COUNT(DISTINCT address), COUNT(DISTINCT case_seed) FROM observation", null)
            .use { it.moveToFirst(); it.getLong(0) to it.getLong(1) }
        return JSONObject().apply {
            put("sources", sources); put("labels", total.first); put("addresses", total.second)
            put("observedAddresses", obs.first); put("cases", obs.second); put("bytes", dbFileSize)
            put("lastRun", getKv("last_run")?.toLongOrNull() ?: JSONObject.NULL)
            put("running", getKv("running") == "1")
        }
    }

    companion object {
        @Volatile private var instance: OsintDb? = null
        fun get(ctx: Context): OsintDb =
            instance ?: synchronized(this) { instance ?: OsintDb(ctx.applicationContext).also { instance = it } }

        /** EVM-adressen zijn hoofdletterongevoelig; BTC (base58) en Tron niet. */
        fun normalize(a: String): String {
            val t = a.trim()
            return if (t.startsWith("0x") || t.startsWith("0X") || t.startsWith("bc1", ignoreCase = true)) t.lowercase() else t
        }
    }
}

data class LabelRow(
    val address: String,
    val chain: String?,
    val label: String,
    val category: String,
    val detail: String? = null
)
