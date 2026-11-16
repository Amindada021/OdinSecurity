package com.odin.odin_security

import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine

class MainActivity : FlutterActivity() {
    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        flutterEngine.platformViewsController.registry.registerViewFactory(
            "odin/scoped-browser", ScopedBrowserFactory(flutterEngine.dartExecutor.binaryMessenger)
        )
    }
}
