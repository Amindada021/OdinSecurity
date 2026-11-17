package com.odin.odin_security

import android.app.Activity
import android.content.Intent
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

class MainActivity : FlutterActivity() {
    private data class PendingExport(val bytes: ByteArray, val result: MethodChannel.Result)
    private var pendingExport: PendingExport? = null
    private val exportRequestCode = 7012

    private fun saveReport(fileName: String, mime: String, bytes: ByteArray, result: MethodChannel.Result) {
        if (pendingExport != null) {
            result.error("export_busy", "An export is already in progress.", null)
            return
        }
        if (bytes.isEmpty() || bytes.size > 32 * 1024 * 1024 ||
            fileName.length > 160 || !fileName.matches(Regex("[A-Za-z0-9._-]+")) ||
            mime !in setOf("application/pdf", "application/json", "text/html")) {
            result.error("export_invalid", "Invalid report data.", null)
            return
        }
        try {
            val intent = Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
                addCategory(Intent.CATEGORY_OPENABLE)
                type = mime
                putExtra(Intent.EXTRA_TITLE, fileName)
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION)
            }
            pendingExport = PendingExport(bytes, result)
            startActivityForResult(intent, exportRequestCode)
        } catch (_: Exception) {
            pendingExport = null
            result.error("export_picker", "Could not open the document picker.", null)
        }
    }

    @Deprecated("Activity result is used with FlutterActivity's existing embedding.")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode != exportRequestCode) return
        val pending = pendingExport ?: return
        if (resultCode != Activity.RESULT_OK) {
            pendingExport = null
            pending.result.success(null)
            return
        }
        val uri = data?.data
        if (uri == null) {
            pendingExport = null
            pending.result.error("export_uri", "No document was selected.", null)
            return
        }

        // Android's document picker creates the URI but does not populate it.
        // Write through ContentResolver and verify the actual bytes after close.
        Thread {
            try {
                contentResolver.openOutputStream(uri, "wt")?.use { stream ->
                    stream.write(pending.bytes)
                    stream.flush()
                } ?: throw IllegalStateException("No output stream")
                val written = contentResolver.openInputStream(uri)?.use { stream ->
                    var offset = 0
                    val buffer = ByteArray(8192)
                    while (true) {
                        val count = stream.read(buffer)
                        if (count < 0) break
                        if (count == 0) throw IllegalStateException("Empty read")
                        if (offset + count > pending.bytes.size) throw IllegalStateException("Incorrect length")
                        for (i in 0 until count) {
                            if (buffer[i] != pending.bytes[offset + i]) throw IllegalStateException("Incorrect contents")
                        }
                        offset += count
                    }
                    offset
                } ?: throw IllegalStateException("No input stream")
                if (written != pending.bytes.size) throw IllegalStateException("Incomplete report")
                runOnUiThread {
                    pendingExport = null
                    pending.result.success(written)
                }
            } catch (_: Exception) {
                runOnUiThread {
                    pendingExport = null
                    pending.result.error("export_write", "Could not write and verify report.", null)
                }
            }
        }.start()
    }

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, "odin/report-export").setMethodCallHandler { call, result ->
            if (call.method == "save") {
                val bytes = call.argument<ByteArray>("bytes")
                if (bytes == null) result.error("export_invalid", "No report data.", null)
                else saveReport(call.argument<String>("fileName") ?: "", call.argument<String>("mime") ?: "", bytes, result)
            } else result.notImplemented()
        }
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, "odin/scheduled-check").setMethodCallHandler { call, result ->
            try {
                when (call.method) {
                    "schedule" -> {
                        ScheduledCheck.schedule(this, call.argument<String>("project") ?: "",
                            call.argument<String>("target") ?: "", call.argument<Int>("minutes") ?: 0)
                        result.success(null)
                    }
                    "status" -> result.success(ScheduledCheck.status(this))
                    "cancel" -> {
                        ScheduledCheck.cancel(this, call.argument<String>("project") ?: "")
                        result.success(null)
                    }
                    else -> result.notImplemented()
                }
            } catch (_: Exception) { result.error("schedule_error", "Scheduled check unavailable.", null) }
        }
        flutterEngine.platformViewsController.registry.registerViewFactory(
            "odin/scoped-browser", ScopedBrowserFactory(flutterEngine.dartExecutor.binaryMessenger)
        )
    }
}
