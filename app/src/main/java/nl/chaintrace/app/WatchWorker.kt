package nl.chaintrace.app

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.ExistingWorkPolicy
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.TimeUnit

/** Gevolgde adressen (gedeeld met de webapp via de bridge). */
object WatchStore {
    private const val PREFS = "watch"
    private const val KEY = "list"
    @Synchronized fun get(ctx: Context): String = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString(KEY, "[]") ?: "[]"
    @Synchronized fun set(ctx: Context, json: String) {
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putString(KEY, json).apply()
    }
}

/**
 * Controleert elke paar uur of er nieuwe transacties zijn op gevolgde adressen en geeft dan een melding.
 * De "vingerafdruk" per keten is dezelfde als in de webapp (watchSig in app.js).
 */
class WatchWorker(ctx: Context, params: WorkerParameters) : CoroutineWorker(ctx, params) {

    override suspend fun doWork(): Result = withContext(Dispatchers.IO) {
        val ctx = applicationContext
        val list = JSONArray(WatchStore.get(ctx))
        if (list.length() == 0) return@withContext Result.success()
        val changed = ArrayList<JSONObject>()
        val sigs = HashMap<String, String>()
        for (i in 0 until list.length()) {
            val w = list.getJSONObject(i)
            // Wallet-tracker: vingerafdruk van alle adressen van de wallet samen (zelfde opbouw als sigOf in app.js).
            val members = w.optJSONArray("members")
            val sig = runCatching {
                if (members == null) sig(w.getString("chain"), w.getString("addr"))
                else (0 until minOf(members.length(), 20)).map { i ->
                    sig(w.getString("chain"), members.getString(i)).also { Thread.sleep(250) }
                }.also { parts -> if (parts.any { it.isEmpty() }) throw RuntimeException("niet alle adressen bereikbaar") }.joinToString(",")
            }
                .onFailure { Log.w(TAG, "controle ${w.optString("addr")} mislukt: ${it.message}") }.getOrNull() ?: continue
            sigs[w.getString("chain") + ":" + w.getString("addr")] = sig
            Thread.sleep(400)
        }
        // Opnieuw lezen: de webapp kan intussen iets gewijzigd hebben.
        val fresh = JSONArray(WatchStore.get(ctx))
        val now = System.currentTimeMillis()
        for (i in 0 until fresh.length()) {
            val w = fresh.getJSONObject(i)
            val sig = sigs[w.getString("chain") + ":" + w.getString("addr")] ?: continue
            val old = w.optString("sig", "")
            if (old.isNotEmpty() && sig.isNotEmpty() && sig != old) {
                w.put("changed", true).put("lastChange", now)
                changed.add(w)
            }
            if (sig.isNotEmpty()) w.put("sig", sig)
            w.put("lastCheck", now)
        }
        WatchStore.set(ctx, fresh.toString())
        if (changed.isNotEmpty()) notify(ctx, changed)
        Result.success()
    }

    private fun sig(chain: String, addr: String): String = when (chain) {
        "btc" -> utxo("https://mempool.space/api", addr)
        "ltc" -> utxo("https://litecoinspace.org/api", addr)
        "eth", "op" -> {
            val base = if (chain == "eth") "https://eth.blockscout.com/api/v2" else "https://explorer.optimism.io/api/v2"
            val c = JSONObject(get("$base/addresses/$addr/counters"))
            "${c.optString("transactions_count", "0")}/${c.optString("token_transfers_count", "0")}"
        }
        "avax" -> {
            val b = "https://api.routescan.io/v2/network/mainnet/evm/43114/etherscan/api?module=account&address=$addr&page=1&offset=1&sort=desc"
            val a = JSONObject(get("$b&action=txlist")).optJSONArray("result")?.optJSONObject(0)?.optString("hash") ?: ""
            val t = JSONObject(get("$b&action=tokentx")).optJSONArray("result")?.optJSONObject(0)?.optString("hash") ?: ""
            "$a/$t"
        }
        "zksync" -> JSONObject(get("https://block-explorer-api.mainnet.zksync.io/address/$addr/transfers?limit=1"))
            .optJSONObject("meta")?.optLong("totalItems")?.toString() ?: "0"
        "sol" -> {
            val body = JSONObject().put("jsonrpc", "2.0").put("id", 1).put("method", "getSignaturesForAddress")
                .put("params", JSONArray().put(addr).put(JSONObject().put("limit", 1)))
            JSONObject(post("https://solana-rpc.publicnode.com", body.toString())).optJSONArray("result")
                ?.optJSONObject(0)?.optString("signature") ?: ""
        }
        else -> JSONObject(get("https://api.trongrid.io/v1/accounts/$addr/transactions/trc20?limit=1"))
            .optJSONArray("data")?.optJSONObject(0)?.optString("transaction_id") ?: ""
    }

    private fun utxo(base: String, addr: String): String {
        val o = JSONObject(get("$base/address/$addr"))
        val n = (o.optJSONObject("chain_stats")?.optInt("tx_count") ?: 0) + (o.optJSONObject("mempool_stats")?.optInt("tx_count") ?: 0)
        return n.toString()
    }

    private fun get(url: String): String = http(url, null)
    private fun post(url: String, body: String): String = http(url, body)
    private fun http(url: String, body: String?): String {
        val c = URL(url).openConnection() as HttpURLConnection
        try {
            c.connectTimeout = 20_000
            c.readTimeout = 30_000
            c.setRequestProperty("User-Agent", "ChainTrace/1.7 (open-source OSINT)")
            if (body != null) {
                c.requestMethod = "POST"
                c.doOutput = true
                c.setRequestProperty("Content-Type", "application/json")
                c.outputStream.use { it.write(body.toByteArray()) }
            }
            if (c.responseCode != 200) throw RuntimeException("HTTP ${c.responseCode}")
            return c.inputStream.bufferedReader().readText()
        } finally {
            c.disconnect()
        }
    }

    private fun notify(ctx: Context, changed: List<JSONObject>) {
        if (Build.VERSION.SDK_INT >= 33 &&
            ContextCompat.checkSelfPermission(ctx, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) return
        ensureChannel(ctx)
        val first = changed.first()
        val name = first.optString("label").ifEmpty { first.getString("addr").let { it.take(6) + "…" + it.takeLast(4) } }
        val open = Intent(ctx, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
            putExtra(MainActivity.EXTRA_WATCH, first.getString("addr"))
        }
        val pi = PendingIntent.getActivity(ctx, 1, open, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        val text = if (changed.size == 1) "Er is weer geld bewogen op $name. Tik om te bekijken."
        else "Er is weer geld bewogen op ${changed.size} gevolgde adressen, o.a. $name."
        val n = NotificationCompat.Builder(ctx, CHANNEL)
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setContentTitle("ChainTrace: nieuwe beweging")
            .setContentText(text)
            .setStyle(NotificationCompat.BigTextStyle().bigText(text))
            .setContentIntent(pi)
            .setAutoCancel(true)
            .build()
        runCatching { NotificationManagerCompat.from(ctx).notify(42, n) }
    }

    companion object {
        private const val TAG = "ChainTraceWatch"
        const val CHANNEL = "watch"
        private const val PERIODIC = "watch-periodic"
        private const val NOW = "watch-now"
        private val net = Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build()

        fun ensureChannel(ctx: Context) {
            if (Build.VERSION.SDK_INT < 26) return
            val nm = ctx.getSystemService(NotificationManager::class.java)
            if (nm.getNotificationChannel(CHANNEL) == null) {
                nm.createNotificationChannel(NotificationChannel(CHANNEL, "Gevolgde adressen", NotificationManager.IMPORTANCE_DEFAULT)
                    .apply { description = "Melding als er weer geld beweegt op een adres dat je volgt" })
            }
        }

        fun schedule(ctx: Context) {
            val req = PeriodicWorkRequestBuilder<WatchWorker>(3, TimeUnit.HOURS).setConstraints(net).build()
            WorkManager.getInstance(ctx).enqueueUniquePeriodicWork(PERIODIC, ExistingPeriodicWorkPolicy.KEEP, req)
        }

        fun runNow(ctx: Context) {
            val req = OneTimeWorkRequestBuilder<WatchWorker>().setConstraints(net).build()
            WorkManager.getInstance(ctx).enqueueUniqueWork(NOW, ExistingWorkPolicy.REPLACE, req)
        }
    }
}
