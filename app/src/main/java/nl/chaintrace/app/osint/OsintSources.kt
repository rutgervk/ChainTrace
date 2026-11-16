package nl.chaintrace.app.osint

import android.util.JsonReader
import android.util.Log
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest

/**
 * Open OSINT-bronnen. Elke bron downloadt naar een tijdelijk bestand en schrijft daarna
 * in één transactie naar [OsintDb]. Snapshot-bronnen vervangen hun labels volledig;
 * de Tether-bronnen werken incrementeel met een cursor.
 */
abstract class OsintSource(val id: String, val name: String, val url: String) {
    abstract fun sync(db: OsintDb, tmp: File): Int
}

private const val TAG = "ChainTraceOsint"
private const val GH = "https://raw.githubusercontent.com"

internal fun download(url: String, to: File): File {
    var lastErr: Exception? = null
    repeat(5) { attempt ->
        // Bij rate limiting: Retry-After volgen, anders exponentieel 5, 10, 20, 40 s.
        var waitMs = 5_000L shl attempt
        try {
            val c = URL(url).openConnection() as HttpURLConnection
            c.connectTimeout = 20_000
            c.readTimeout = 60_000
            c.setRequestProperty("User-Agent", "ChainTrace/1.0 (open-source OSINT)")
            c.setRequestProperty("Accept", "*/*")
            try {
                val code = c.responseCode
                if (code == 429 || code >= 500) {
                    c.getHeaderField("Retry-After")?.toLongOrNull()?.let { waitMs = (it * 1000).coerceIn(1_000, 120_000) }
                    throw RuntimeException("HTTP $code")
                }
                if (code != 200) throw IllegalStateException("HTTP $code voor $url")
                c.inputStream.use { inp -> to.outputStream().use { inp.copyTo(it) } }
                return to
            } finally {
                c.disconnect()
            }
        } catch (e: IllegalStateException) {
            throw e
        } catch (e: Exception) {
            lastErr = e
            if (attempt < 4) Thread.sleep(waitMs)
        }
    }
    throw lastErr ?: RuntimeException("Download mislukt")
}

internal fun getJson(url: String, tmp: File): String = download(url, tmp).readText()

/** Simpele CSV-splitter met ondersteuning voor aanhalingstekens. */
private fun splitCsv(line: String): List<String> {
    val out = ArrayList<String>()
    val sb = StringBuilder()
    var q = false
    var i = 0
    while (i < line.length) {
        val ch = line[i]
        when {
            ch == '"' && q && i + 1 < line.length && line[i + 1] == '"' -> { sb.append('"'); i++ }
            ch == '"' -> q = !q
            ch == ',' && !q -> { out.add(sb.toString()); sb.setLength(0) }
            else -> sb.append(ch)
        }
        i++
    }
    out.add(sb.toString())
    return out
}

private fun chainOf(a: String): String? = when {
    a.startsWith("0x") -> "evm"
    a.startsWith("T") && a.length == 34 -> "tron"
    a.startsWith("bc1") || a.startsWith("1") || a.startsWith("3") -> "btc"
    else -> null
}

// ---------- Tron base58check ----------
private const val B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

private fun sha256(b: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(b)

internal fun tronHexToBase58(hex: String): String {
    val h = hex.removePrefix("0x").let { if (it.length == 40) "41$it" else it }
    val payload = ByteArray(h.length / 2) { h.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    val full = payload + sha256(sha256(payload)).copyOfRange(0, 4)
    var num = java.math.BigInteger(1, full)
    val sb = StringBuilder()
    val base = java.math.BigInteger.valueOf(58)
    while (num > java.math.BigInteger.ZERO) {
        val (q, r) = num.divideAndRemainder(base)
        sb.append(B58[r.toInt()])
        num = q
    }
    for (b in full) if (b.toInt() == 0) sb.append('1') else break
    return sb.reverse().toString()
}

// ---------- bronnen ----------

class OfacSource : OsintSource("ofac", "OFAC-sanctielijst (0xB10C)", "https://github.com/0xB10C/ofac-sanctioned-digital-currency-addresses") {
    private val lists = listOf("XBT", "ETH", "TRX", "USDT", "USDC", "ARB", "BSC", "LTC")
    override fun sync(db: OsintDb, tmp: File): Int {
        val rows = ArrayList<LabelRow>()
        for (sym in lists) {
            val txt = download("$GH/0xB10C/ofac-sanctioned-digital-currency-addresses/lists/sanctioned_addresses_$sym.txt", tmp).readText()
            txt.split(Regex("\\s+")).filter { it.isNotBlank() }.forEach {
                rows.add(LabelRow(it, chainOf(it), "OFAC-sanctie ($sym)", "sanction", "Amerikaanse SDN-lijst"))
            }
        }
        return db.replaceSource(id, rows.asSequence())
    }
}

class ScamSnifferSource : OsintSource("scamsniffer", "ScamSniffer blacklist", "https://github.com/scamsniffer/scam-database") {
    override fun sync(db: OsintDb, tmp: File): Int {
        val arr = JSONArray(getJson("$GH/scamsniffer/scam-database/main/blacklist/address.json", tmp))
        return db.replaceSource(id, (0 until arr.length()).asSequence().map {
            LabelRow(arr.getString(it), "evm", "ScamSniffer: scam/drainer", "scam")
        })
    }
}

class MewDarklistSource : OsintSource("mew", "MyEtherWallet darklist", "https://github.com/MyEtherWallet/ethereum-lists") {
    override fun sync(db: OsintDb, tmp: File): Int {
        val arr = JSONArray(getJson("$GH/MyEtherWallet/ethereum-lists/master/src/addresses/addresses-darklist.json", tmp))
        return db.replaceSource(id, (0 until arr.length()).asSequence().map {
            val o = arr.getJSONObject(it)
            LabelRow(o.getString("address"), "evm", "MEW darklist", "scam", o.optString("comment").ifBlank { null })
        })
    }
}

class FortaSource : OsintSource("forta", "Forta labelled datasets (phishing, exploits)", "https://github.com/forta-network/labelled-datasets") {
    override fun sync(db: OsintDb, tmp: File): Int {
        val rows = ArrayList<LabelRow>()
        download("$GH/forta-network/labelled-datasets/main/labels/1/phishing_scams.csv", tmp).useLines { lines ->
            lines.drop(1).forEach { l ->
                val f = splitCsv(l)
                if (f.size >= 2) rows.add(LabelRow(f[0], "evm", f[1].ifBlank { "Phishing" }, "phishing", f.getOrNull(2)))
            }
        }
        download("$GH/forta-network/labelled-datasets/main/labels/1/malicious_smart_contracts.csv", tmp).useLines { lines ->
            lines.drop(1).forEach { l ->
                val f = splitCsv(l)
                if (f.size < 5) return@forEach
                rows.add(LabelRow(f[0], "evm", f[1].ifBlank { "Kwaadaardig contract" }, "exploit", f.getOrNull(6)))
                if (f[2].startsWith("0x")) rows.add(LabelRow(f[2], "evm", f[4].ifBlank { "Maker van kwaadaardig contract" }, "exploit", "Creator van ${f[0]}"))
            }
        }
        return db.replaceSource(id, rows.asSequence())
    }
}

class EtherscanLabelsSource : OsintSource("etherscan", "Etherscan-labels (brianleect)", "https://github.com/brianleect/etherscan-labels") {
    override fun sync(db: OsintDb, tmp: File): Int {
        download("$GH/brianleect/etherscan-labels/main/data/etherscan/combined/combinedAllLabels.json", tmp)
        val rows = sequence {
            JsonReader(tmp.reader()).use { r ->
                r.beginObject()
                while (r.hasNext()) {
                    val addr = r.nextName()
                    var name = ""
                    val labels = ArrayList<String>()
                    r.beginObject()
                    while (r.hasNext()) when (r.nextName()) {
                        "name" -> name = r.nextString()
                        "labels" -> { r.beginArray(); while (r.hasNext()) labels.add(r.nextString()); r.endArray() }
                        else -> r.skipValue()
                    }
                    r.endObject()
                    val all = labels.joinToString(",")
                    val cat = when {
                        Regex("phish|hack|scam|heist|exploit|blocked").containsMatchIn(all) -> "scam"
                        Regex("tornado|mixer").containsMatchIn(all) -> "mixer"
                        Regex("exchange").containsMatchIn(all) || Regex("(?i)binance|coinbase|kraken|okx|bybit|kucoin|bitfinex|huobi|gate\\.io").containsMatchIn(name) -> "exchange"
                        Regex("bridge").containsMatchIn(all) -> "bridge"
                        else -> "label"
                    }
                    yield(LabelRow(addr, "evm", name.ifBlank { labels.firstOrNull() ?: "Etherscan-label" }, cat, all.ifBlank { null }))
                }
                r.endObject()
            }
        }
        return db.replaceSource(id, rows)
    }
}

class RansomwhereSource : OsintSource("ransomwhere", "Ransomwhere (ransomware-betaaladressen)", "https://ransomwhe.re") {
    override fun sync(db: OsintDb, tmp: File): Int {
        download("https://api.ransomwhe.re/export", tmp)
        val rows = sequence {
            JsonReader(tmp.reader()).use { r ->
                r.beginObject()
                while (r.hasNext()) {
                    if (r.nextName() != "result") { r.skipValue(); continue }
                    r.beginArray()
                    while (r.hasNext()) {
                        var addr = ""; var family = ""; var chain = ""; var balance = 0.0
                        r.beginObject()
                        while (r.hasNext()) when (r.nextName()) {
                            "address" -> addr = r.nextString()
                            "family" -> family = r.nextString()
                            "blockchain" -> chain = r.nextString()
                            "balance" -> balance = runCatching { r.nextDouble() }.getOrElse { r.skipValue(); 0.0 }
                            else -> r.skipValue()
                        }
                        r.endObject()
                        val ch = if (chain == "bitcoin") "btc" else chainOf(addr)
                        val detail = if (ch == "btc") "Ontvangen: %.4f BTC".format(balance / 1e8) else null
                        yield(LabelRow(addr, ch, "Ransomware: ${family.ifBlank { "onbekend" }}", "ransomware", detail))
                    }
                    r.endArray()
                }
                r.endObject()
            }
        }
        return db.replaceSource(id, rows)
    }
}

class GraphSenseSource : OsintSource("graphsense", "GraphSense tagpacks", "https://github.com/graphsense/graphsense-tagpacks") {
    private val keepCurrencies = setOf("BTC", "ETH", "TRX", "USDT")

    override fun sync(db: OsintDb, tmp: File): Int {
        val listing = JSONArray(getJson("https://api.github.com/repos/graphsense/graphsense-tagpacks/contents/packs", tmp))
        val files = (0 until listing.length()).map { listing.getJSONObject(it) }
            .filter { it.getString("type") == "file" && it.getString("name").endsWith(".yaml") && !it.getString("name").startsWith("eosio") }
        // Alleen opnieuw verwerken als er een pack veranderd is.
        val hash = files.joinToString("|") { it.getString("sha") }.hashCode().toString()
        if (db.getKv("graphsense_hash") == hash) return -1
        // Per pack wegschrijven zodat grote packs (miners, richest) niet allemaal tegelijk in het geheugen staan.
        db.clearSource(id)
        var n = 0
        for (f in files) {
            val rows = ArrayList<LabelRow>()
            runCatching {
                parsePack(download("$GH/graphsense/graphsense-tagpacks/master/packs/${f.getString("name")}", tmp), f.getString("name"), rows)
                n += db.appendLabels(id, rows.asSequence())
            }.onFailure { Log.w(TAG, "graphsense ${f.getString("name")}: ${it.message}") }
        }
        db.setKv("graphsense_hash", hash)
        return n
    }

    private fun parsePack(file: File, packName: String, out: MutableList<LabelRow>) {
        val header = HashMap<String, String>()
        var item: HashMap<String, String>? = null
        var inTags = false
        fun flush() {
            val it = item ?: return
            val addr = it["address"] ?: return
            val cur = (it["currency"] ?: it["network"] ?: header["currency"] ?: header["network"] ?: "").uppercase()
            if (cur !in keepCurrencies) return
            val label = it["label"] ?: header["label"] ?: packName.removeSuffix(".yaml")
            val abuse = it["abuse"] ?: header["abuse"]
            val category = it["category"] ?: header["category"]
            val cat = when {
                abuse == "ransomware" -> "ransomware"
                abuse == "sanction" -> "sanction"
                abuse != null && abuse != "null" -> "scam"
                category == "exchange" -> "exchange"
                category in setOf("mixing_service", "coinjoin") -> "mixer"
                category in setOf("market", "darknet_crawled", "darkweb") -> "darknet"
                else -> "label"
            }
            val src = it["source"] ?: header["source"]
            out.add(LabelRow(addr, chainOf(addr), label, cat, listOfNotNull(abuse?.let { a -> "misbruik: $a" }, category, src).joinToString(" · ").ifBlank { null }))
        }
        file.forEachLine { raw ->
            if (raw.isBlank() || raw.trimStart().startsWith("#")) return@forEachLine
            val indented = raw.startsWith(" ") || raw.startsWith("-")
            val line = raw.trim()
            if (!indented) {
                val (k, v) = kv(line) ?: return@forEachLine
                if (k == "tags") inTags = true else if (!inTags) header[k] = v
                return@forEachLine
            }
            if (!inTags) return@forEachLine
            if (line.startsWith("- ")) {
                flush()
                item = HashMap()
                kv(line.removePrefix("- ").trim())?.let { (k, v) -> item!![k] = v }
            } else {
                kv(line)?.let { (k, v) -> item?.put(k, v) }
            }
        }
        flush()
    }

    private fun kv(line: String): Pair<String, String>? {
        val i = line.indexOf(':')
        if (i <= 0) return null
        val v = line.substring(i + 1).trim().trim('\'', '"')
        return line.substring(0, i).trim() to v
    }
}

val ALL_SOURCES: List<OsintSource> = listOf(
    OfacSource(), ScamSnifferSource(), MewDarklistSource(), FortaSource(), EtherscanLabelsSource(),
    RansomwhereSource(), GraphSenseSource(), TetherTronSource(), TetherEthSource()
)
