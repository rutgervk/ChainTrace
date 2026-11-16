package nl.chaintrace.app.osint

import android.util.Log
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.net.HttpURLConnection
import java.net.URL

private const val TETHER_LABEL = "Door Tether bevroren (USDT-blacklist)"
private const val USDT_ETH = "0xdac17f958d2ee523a2206206994597c13d831ec7"
// Gratis RPC zonder sleutel; levert logs voor recente blokken (geen archief), genoeg voor de dagelijkse aanvulling.
private const val RPC = "https://ethereum-rpc.publicnode.com"

/**
 * Tether (USDT) blacklist op Tron via TronGrid-events. AddedBlackList én RemovedBlackList worden
 * bijgehouden in de freeze-tabel, zodat opgeheven bevriezingen niet als "bevroren" blijven staan.
 */
class TetherTronSource : OsintSource("tether_tron", "Tether-bevriezingen (Tron)", "https://tronscan.org/#/contract/TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t") {
    // Ook na een gedeeltelijke sync de labels bijwerken met wat er al binnen is; de cursor bewaart de voortgang.
    override fun sync(db: OsintDb, tmp: File): Int =
        try { fetch(db, tmp); db.rebuildFrozenLabels(id, "tron", TETHER_LABEL) }
        catch (e: Exception) { db.rebuildFrozenLabels(id, "tron", TETHER_LABEL); throw e }

    private fun fetch(db: OsintDb, tmp: File) {
        for ((event, added) in listOf("AddedBlackList" to true, "RemovedBlackList" to false)) {
            val key = "tether_tron_ts_$event"
            var cursor = db.getKv(key)?.toLongOrNull() ?: 0L
            var next: String? = "https://api.trongrid.io/v1/contracts/TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t/events" +
                "?event_name=$event&order_by=block_timestamp,asc&limit=200&min_block_timestamp=${cursor + 1}"
            var pages = 0
            while (next != null && pages++ < 150) {
                val o = JSONObject(getJson(next, tmp))
                val data = o.optJSONArray("data") ?: break
                val events = ArrayList<FreezeEvent>()
                for (i in 0 until data.length()) {
                    val e = data.getJSONObject(i)
                    val hex = e.getJSONObject("result").optString("0")
                    if (hex.isBlank()) continue
                    val ts = e.getLong("block_timestamp")
                    cursor = maxOf(cursor, ts)
                    events.add(FreezeEvent(tronHexToBase58(hex), ts, added))
                }
                db.recordFreezes("tron", events)
                db.setKv(key, cursor.toString())
                next = o.optJSONObject("meta")?.optJSONObject("links")?.optString("next")?.ifBlank { null }
                Thread.sleep(1_100) // TronGrid zonder sleutel: ~1 verzoek/s
            }
        }
    }
}

/** Tether (USDT) blacklist op Ethereum via de Blockscout getLogs-API; Added- en RemovedBlackList, incrementeel per blok. */
class TetherEthSource : OsintSource("tether_eth", "Tether-bevriezingen (Ethereum)", "https://etherscan.io/token/0xdac17f958d2ee523a2206206994597c13d831ec7") {
    private val topics = listOf(
        "0x42e160154868087d6bfdc0ca23d96a1c1cfa32f1b72ba9ba27b69b98a0d819dc" to true,  // AddedBlackList(address)
        "0xd7e9ec6e6ecd65492dce6bf513cd6867560d49544421d0783ddf06e76c24470c" to false  // RemovedBlackList(address)
    )

    override fun sync(db: OsintDb, tmp: File): Int =
        try { fetch(db, tmp); db.rebuildFrozenLabels(id, "evm", TETHER_LABEL) }
        catch (e: Exception) { db.rebuildFrozenLabels(id, "evm", TETHER_LABEL); throw e }

    private fun fetch(db: OsintDb, tmp: File) {
        for ((topic, added) in topics) {
            val key = "tether_eth_block_" + topic.take(10)
            try {
                fetchBlockscout(db, tmp, topic, added, key)
            } catch (e: Exception) {
                // De volledige historie kan alleen via Blockscout; dagelijkse aanvulling kan ook via publieke RPC.
                if ((db.getKv(key)?.toLongOrNull() ?: 0L) == 0L) throw e
                Log.w("ChainTraceOsint", "tether_eth: Blockscout faalt (${e.message}), fallback naar RPC")
                fetchRpc(db, topic, added, key)
            }
        }
    }

    private fun fetchRpc(db: OsintDb, topic: String, added: Boolean, key: String) {
        val latest = java.lang.Long.decode(rpc("eth_blockNumber", JSONArray()).toString())
        var from = db.getKv(key)!!.toLong() + 1
        var chunks = 0
        while (from <= latest && chunks++ < 60) {
            val to = minOf(from + 4_999, latest)
            val filter = JSONObject().put("fromBlock", "0x" + from.toString(16)).put("toBlock", "0x" + to.toString(16))
                .put("address", USDT_ETH).put("topics", JSONArray().put(topic))
            val logs = rpc("eth_getLogs", JSONArray().put(filter)) as JSONArray
            val events = ArrayList<FreezeEvent>()
            for (i in 0 until logs.length()) {
                val l = logs.getJSONObject(i)
                val data = l.getString("data")
                if (data.length < 42) continue
                val block = java.lang.Long.decode(l.getString("blockNumber"))
                // blockTimestamp is niet overal aanwezig; anders schatten met ~12 s per blok.
                val ts = l.optString("blockTimestamp").takeIf { it.startsWith("0x") }?.let { java.lang.Long.decode(it) * 1000 }
                    ?: (System.currentTimeMillis() - (latest - block) * 12_000)
                events.add(FreezeEvent("0x" + data.takeLast(40), ts, added))
            }
            db.recordFreezes("evm", events)
            db.setKv(key, to.toString())
            from = to + 1
            Thread.sleep(300)
        }
    }

    private fun rpc(method: String, params: JSONArray): Any {
        val body = JSONObject().put("jsonrpc", "2.0").put("id", 1).put("method", method).put("params", params).toString()
        val c = URL(RPC).openConnection() as HttpURLConnection
        try {
            c.connectTimeout = 20_000
            c.readTimeout = 60_000
            c.requestMethod = "POST"
            c.doOutput = true
            c.setRequestProperty("Content-Type", "application/json")
            c.setRequestProperty("User-Agent", "ChainTrace/1.0 (open-source OSINT)")
            c.outputStream.use { it.write(body.toByteArray()) }
            if (c.responseCode != 200) throw RuntimeException("RPC HTTP ${c.responseCode}")
            val o = JSONObject(c.inputStream.bufferedReader().readText())
            o.optJSONObject("error")?.let { throw RuntimeException("RPC: ${it.optString("message")}") }
            return o.get("result")
        } finally {
            c.disconnect()
        }
    }

    private fun fetchBlockscout(db: OsintDb, tmp: File, topic: String, added: Boolean, key: String) {
        run {
            var from = db.getKv(key)?.toLongOrNull() ?: 0L
            for (page in 0 until 60) {
                val url = "https://eth.blockscout.com/api?module=logs&action=getLogs&fromBlock=$from&toBlock=latest" +
                    "&address=$USDT_ETH&topic0=$topic"
                val res = JSONObject(getJson(url, tmp)).optJSONArray("result") ?: break
                val events = ArrayList<FreezeEvent>()
                var maxBlock = from
                for (i in 0 until res.length()) {
                    val l = res.getJSONObject(i)
                    val data = l.getString("data")
                    if (data.length < 42) continue
                    maxBlock = maxOf(maxBlock, java.lang.Long.decode(l.getString("blockNumber")))
                    val ts = runCatching { java.lang.Long.decode(l.getString("timeStamp")) * 1000 }.getOrDefault(0L)
                    events.add(FreezeEvent("0x" + data.takeLast(40), ts, added))
                }
                db.recordFreezes("evm", events)
                db.setKv(key, maxBlock.toString())
                if (res.length() < 1000) break
                from = maxBlock
                Thread.sleep(400)
            }
        }
    }
}

data class FreezeEvent(val address: String, val time: Long, val added: Boolean)
