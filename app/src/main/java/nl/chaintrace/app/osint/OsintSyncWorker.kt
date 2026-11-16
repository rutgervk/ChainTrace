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
        var failures = 0
        try {
            for (src in ALL_SOURCES) {
                if (isStopped) break
                val tmp = File(applicationContext.cacheDir, "osint-${src.id}.tmp")
                db.setSourceStatus(src.id, src.name, src.url, "bezig")
                try {
                    val n = src.sync(db, tmp)
                    db.setSourceStatus(src.id, src.name, src.url, if (n < 0) "ongewijzigd" else "ok", success = true)
                    Log.i(TAG, "${src.id}: ${if (n < 0) "ongewijzigd" else "$n records"}")
                } catch (e: Exception) {
                    failures++
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
        return if (failures == ALL_SOURCES.size) Result.retry() else Result.success()
    }

    companion object {
        private const val TAG = "ChainTraceOsint"
        private val lock = java.util.concurrent.locks.ReentrantLock()
        private const val DAILY = "osint-daily"
        private const val NOW = "osint-now"
        private val net = Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build()

        fun scheduleDaily(ctx: Context) {
            val req = PeriodicWorkRequestBuilder<OsintSyncWorker>(1, TimeUnit.DAYS)
                .setConstraints(net)
                .build()
            WorkManager.getInstance(ctx).enqueueUniquePeriodicWork(DAILY, ExistingPeriodicWorkPolicy.KEEP, req)
        }

        fun runNow(ctx: Context) {
            val req = OneTimeWorkRequestBuilder<OsintSyncWorker>().setConstraints(net).build()
            WorkManager.getInstance(ctx).enqueueUniqueWork(NOW, ExistingWorkPolicy.KEEP, req)
        }
    }
}
