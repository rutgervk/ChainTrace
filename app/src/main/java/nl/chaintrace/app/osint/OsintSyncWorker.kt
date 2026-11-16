package nl.chaintrace.app.osint

import android.content.Context
import android.util.Log
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
import java.io.File
import java.util.concurrent.TimeUnit

/** Haalt dagelijks alle open bronnen opnieuw op. Fouten per bron blokkeren de andere bronnen niet. */
class OsintSyncWorker(ctx: Context, params: WorkerParameters) : CoroutineWorker(ctx, params) {

    override suspend fun doWork(): Result = withContext(Dispatchers.IO) {
        // De dagelijkse en een handmatige sync mogen nooit tegelijk lopen.
        if (!lock.tryLock()) return@withContext Result.success()
        try { syncAll() } finally { lock.unlock() }
    }

    private fun syncAll(): Result {
        val db = OsintDb.get(applicationContext)
        db.setKv("running", "1")
        val only = inputData.getStringArray(KEY_ONLY)?.toSet()
        val sources = ALL_SOURCES.filter { only == null || it.id in only }
        val failed = ArrayList<String>()
        var failures = 0
        try {
            for (src in sources) {
                if (isStopped) break
                val tmp = File(applicationContext.cacheDir, "osint-${src.id}.tmp")
                db.setSourceStatus(src.id, src.name, src.url, "bezig")
                try {
                    val n = src.sync(db, tmp)
                    db.setSourceStatus(src.id, src.name, src.url, if (n < 0) "ongewijzigd" else "ok", success = true)
                    Log.i(TAG, "${src.id}: ${if (n < 0) "ongewijzigd" else "$n records"}")
                } catch (e: Exception) {
                    failures++
                    failed.add(src.id)
                    Log.w(TAG, "${src.id} mislukt", e)
                    db.setSourceStatus(src.id, src.name, src.url, "fout", e.message ?: e.javaClass.simpleName)
                } finally {
                    tmp.delete()
                }
            }
            db.setKv("last_run", System.currentTimeMillis().toString())
        } finally {
            db.setKv("running", "0")
        }
        // Mislukte bronnen (bv. rate limit) over 2 uur opnieuw proberen, los van de dagelijkse run.
        if (failed.isNotEmpty() && failures < sources.size) retryLater(applicationContext, failed)
        return if (failures == sources.size) Result.retry() else Result.success()
    }

    companion object {
        private const val TAG = "ChainTraceOsint"
        private val lock = java.util.concurrent.locks.ReentrantLock()
        private const val DAILY = "osint-daily"
        private const val NOW = "osint-now"
        private const val RETRY = "osint-retry"
        private const val KEY_ONLY = "only"
        private val net = Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build()

        fun scheduleDaily(ctx: Context) {
            val req = PeriodicWorkRequestBuilder<OsintSyncWorker>(1, TimeUnit.DAYS)
                .setConstraints(net)
                .build()
            WorkManager.getInstance(ctx).enqueueUniquePeriodicWork(DAILY, ExistingPeriodicWorkPolicy.KEEP, req)
        }

        private fun retryLater(ctx: Context, ids: List<String>) {
            val req = OneTimeWorkRequestBuilder<OsintSyncWorker>()
                .setConstraints(net)
                .setInitialDelay(2, TimeUnit.HOURS)
                .setInputData(androidx.work.workDataOf(KEY_ONLY to ids.toTypedArray()))
                .build()
            WorkManager.getInstance(ctx).enqueueUniqueWork(RETRY, ExistingWorkPolicy.REPLACE, req)
        }

        fun runNow(ctx: Context) {
            val req = OneTimeWorkRequestBuilder<OsintSyncWorker>().setConstraints(net).build()
            WorkManager.getInstance(ctx).enqueueUniqueWork(NOW, ExistingWorkPolicy.KEEP, req)
        }
    }
}
