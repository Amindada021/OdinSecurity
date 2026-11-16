package com.odin.odin_security

import android.app.job.JobInfo
import android.app.job.JobParameters
import android.app.job.JobScheduler
import android.app.job.JobService
import android.content.ComponentName
import android.content.Context
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle
import java.net.URI
import java.util.UUID
import javax.net.ssl.HttpsURLConnection

/** One anonymous, explicitly approved HEAD request. No credentials, redirects,
 * payload capture, reboot persistence, periodic schedule or retry. */
object ScheduledCheck {
    private const val JOB = 7013
    private const val STORE = "odin_scheduled_check_v1"
    private fun prefs(context: Context) = context.getSharedPreferences(STORE, Context.MODE_PRIVATE)
    private fun scheduler(context: Context) = context.getSystemService(JobScheduler::class.java)

    private fun valid(project: String, target: String): Boolean = try {
        val uri = URI(target)
        project.matches(Regex("[a-f0-9]{32}")) && target.length <= 2048 &&
            uri.scheme == "https" && !uri.host.isNullOrEmpty() &&
            uri.rawUserInfo == null && uri.rawQuery == null && uri.rawFragment == null &&
            (uri.port == -1 || uri.port in 1..65535)
    } catch (_: Exception) { false }

    @Synchronized
    fun schedule(context: Context, project: String, target: String, minutes: Int) {
        require(valid(project, target) && minutes in listOf(15, 60, 180))
        val store = prefs(context)
        val state = store.getString("state", "")
        check(state != "pending" && state != "running") { "Cancel the existing job first." }
        val token = UUID.randomUUID().toString()
        val delay = minutes * 60_000L
        val due = System.currentTimeMillis() + delay
        check(store.edit().clear().putString("project", project).putString("target", target)
            .putString("token", token).putString("state", "pending").putLong("due", due)
            .putLong("expires", due + 6 * 60 * 60_000L).commit())
        val extras = PersistableBundle().apply { putString("token", token) }
        try {
            val job = JobInfo.Builder(JOB, ComponentName(context, ScheduledCheckService::class.java))
                .setMinimumLatency(delay).setRequiredNetworkType(JobInfo.NETWORK_TYPE_ANY)
                .setPersisted(false).setExtras(extras).build()
            check(scheduler(context).schedule(job) == JobScheduler.RESULT_SUCCESS)
        } catch (e: Exception) {
            store.edit().putString("state", "failed").commit()
            throw e
        }
    }

    @Synchronized
    fun status(context: Context): Map<String, Any?> {
        val store = prefs(context)
        var state = store.getString("state", "none") ?: "none"
        if (state == "pending" && System.currentTimeMillis() > store.getLong("expires", 0L)) {
            store.edit().putString("state", "expired").commit()
            scheduler(context).cancel(JOB)
            state = "expired"
        }
        if (state in listOf("pending", "running") && scheduler(context).getPendingJob(JOB) == null) {
            store.edit().putString("state", "interrupted").commit()
            state = "interrupted"
        }
        return mapOf("state" to state, "project" to store.getString("project", ""),
            "target" to store.getString("target", ""), "due" to store.getLong("due", 0L),
            "status" to store.getInt("status", -1), "elapsed" to store.getLong("elapsed", 0L))
    }

    @Synchronized
    fun cancel(context: Context, project: String) {
        val store = prefs(context)
        if (store.getString("project", "") != project) return
        if (store.getString("state", "") in listOf("pending", "running")) {
            check(store.edit().putString("state", "cancelled").commit())
            scheduler(context).cancel(JOB)
        }
    }

    @Synchronized
    fun begin(context: Context, token: String): String? {
        val store = prefs(context)
        if (store.getString("token", "") != token || store.getString("state", "") != "pending") return null
        val target = store.getString("target", "") ?: ""
        val project = store.getString("project", "") ?: ""
        val now = System.currentTimeMillis()
        if (!valid(project, target) || now < store.getLong("due", 0L) || now > store.getLong("expires", 0L)) {
            store.edit().putString("state", "expired").commit()
            return null
        }
        if (!store.edit().putString("state", "running").commit()) return null
        return target
    }

    @Synchronized
    fun active(context: Context, token: String): Boolean =
        prefs(context).let { it.getString("token", "") == token && it.getString("state", "") == "running" }

    @Synchronized
    fun finish(context: Context, token: String, state: String, status: Int = -1, elapsed: Long = 0L) {
        if (!active(context, token)) return
        prefs(context).edit().putString("state", state).putInt("status", status).putLong("elapsed", elapsed).commit()
    }
}

class ScheduledCheckService : JobService() {
    @Volatile private var connection: HttpsURLConnection? = null
    @Volatile private var worker: Thread? = null
    @Volatile private var runningToken: String? = null

    override fun onStartJob(params: JobParameters): Boolean {
        val token = params.extras.getString("token") ?: return false
        val target = ScheduledCheck.begin(this, token) ?: return false
        runningToken = token
        worker = Thread {
            val start = android.os.SystemClock.elapsedRealtime()
            var conn: HttpsURLConnection? = null
            var status = -1
            var state = "failed"
            try {
                if (!ScheduledCheck.active(this, token)) return@Thread
                val url = URI(target).toURL()
                conn = url.openConnection() as HttpsURLConnection
                conn.instanceFollowRedirects = false
                conn.useCaches = false
                conn.connectTimeout = 10_000
                conn.readTimeout = 10_000
                conn.requestMethod = "HEAD"
                conn.setRequestProperty("Cookie", "")
                connection = conn
                if (!ScheduledCheck.active(this, token)) return@Thread
                status = conn.responseCode
                if (status in 100..599) state = "completed"
            } catch (_: Exception) {
                // Metadata only: no exception, headers or payload stored.
            } finally {
                conn?.disconnect()
                if (runningToken == token) connection = null
                val elapsed = android.os.SystemClock.elapsedRealtime() - start
                Handler(Looper.getMainLooper()).post {
                    if (runningToken == token) {
                        ScheduledCheck.finish(this, token, state, status, elapsed)
                        runningToken = null
                        worker = null
                        jobFinished(params, false)
                    }
                }
            }
        }.also { it.start() }
        return true
    }

    override fun onStopJob(params: JobParameters): Boolean {
        val token = params.extras.getString("token") ?: return false
        if (runningToken == token) {
            runningToken = null
            ScheduledCheck.finish(this, token, "interrupted")
            worker?.interrupt()
            worker = null
            val old = connection
            connection = null
            if (old != null) Thread { old.disconnect() }.start()
        }
        return false
    }
}
