package com.odin.odin_security

import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

class MainActivity : FlutterActivity() {
    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
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
