package com.odin.odin_security

import android.content.Context
import android.graphics.Bitmap
import android.os.Build
import android.view.View
import android.webkit.CookieManager
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebSettings
import android.webkit.WebStorage
import android.webkit.WebView
import android.webkit.WebViewClient
import io.flutter.plugin.common.BinaryMessenger
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.StandardMessageCodec
import io.flutter.plugin.platform.PlatformView
import io.flutter.plugin.platform.PlatformViewFactory
import java.net.URI
import java.io.ByteArrayInputStream
import java.util.ArrayDeque
import java.util.Locale

private data class Origin(val host: String, val port: Int)

private class BrowserScope(start: String, urls: List<String>, private val excluded: List<String>) {
    private fun parse(raw: String): URI? {
        if (raw.length > 2048) return null
        val uri = runCatching { URI(raw) }.getOrNull() ?: return null
        if (!uri.scheme.equals("https", ignoreCase = true) || uri.host.isNullOrBlank() ||
            uri.userInfo != null || uri.port == 0 || uri.port > 65535) return null
        return uri
    }

    private fun origin(uri: URI): Origin =
        Origin(uri.host.lowercase(Locale.ROOT), if (uri.port == -1) 443 else uri.port)

    private val selected = origin(requireNotNull(parse(start)))
    private val allowed = urls.take(31).mapNotNull(::parse).map(::origin).toSet()

    private fun allowedPath(uri: URI): Boolean {
        val path = uri.path.orEmpty().ifEmpty { "/" }
        val normalized = uri.normalize().path.orEmpty().ifEmpty { "/" }
        // Refuse ambiguous path separators and traversal for observation/navigation.
        if (path.contains('\\') || path.split('/').any { it == "." || it == ".." }) return false
        return excluded.none { prefix ->
            val trimmed = prefix.trimEnd('/').ifEmpty { "/" }
            trimmed == "/" || path == trimmed || path.startsWith("$trimmed/") ||
                normalized == trimmed || normalized.startsWith("$trimmed/")
        }
    }

    fun permits(raw: String, mainFrame: Boolean): Boolean {
        val uri = parse(raw) ?: return false
        val candidate = origin(uri)
        return candidate in allowed && (!mainFrame || candidate == selected) && allowedPath(uri)
    }

    fun route(raw: String): String? =
        if (permits(raw, false)) raw.substringBefore('?').substringBefore('#') else null
}

class ScopedBrowserFactory(private val messenger: BinaryMessenger) :
    PlatformViewFactory(StandardMessageCodec.INSTANCE) {
    override fun create(context: Context, viewId: Int, args: Any?): PlatformView {
        val options = args as? Map<*, *> ?: error("Missing browser scope")
        require(options["authorized"] == true)
        val start = options["start"] as? String ?: error("Missing start")
        val urls = (options["origins"] as? List<*>)?.filterIsInstance<String>() ?: emptyList()
        val exclusions = (options["excluded"] as? List<*>)?.filterIsInstance<String>() ?: emptyList()
        require(urls.size in 1..31 && exclusions.size <= 100)
        return ScopedBrowserView(context, messenger, viewId, start, BrowserScope(start, urls, exclusions))
    }
}

private class ScopedBrowserView(
    context: Context, messenger: BinaryMessenger, viewId: Int,
    private val start: String, private val scope: BrowserScope
) : PlatformView {
    private val web = WebView(context)
    private val channel = MethodChannel(messenger, "odin/scoped-browser/$viewId")
    private val entries = ArrayDeque<Map<String, Any>>()
    private val lock = Any()
    private val methods = setOf("GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE")
    @Volatile private var disposed = false
    @Volatile private var capturing = true

    init {
        require(scope.permits(start, true))
        web.settings.apply {
            javaScriptEnabled = true
            domStorageEnabled = true
            allowFileAccess = false
            allowContentAccess = false
            mixedContentMode = WebSettings.MIXED_CONTENT_NEVER_ALLOW
            setSupportMultipleWindows(false)
            javaScriptCanOpenWindowsAutomatically = false
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) safeBrowsingEnabled = true
        }
        val cookieManager = CookieManager.getInstance()
        cookieManager.setAcceptThirdPartyCookies(web, false)
        web.webViewClient = object : WebViewClient() {
            override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean =
                disposed || (request.isForMainFrame && !scope.permits(request.url.toString(), true))

            override fun onPageStarted(view: WebView, url: String?, favicon: Bitmap?) {
                if (url == null || !scope.permits(url, true)) view.stopLoading()
            }

            override fun shouldInterceptRequest(view: WebView, request: WebResourceRequest): WebResourceResponse? {
                val raw = request.url.toString()
                if (request.isForMainFrame && !scope.permits(raw, true)) {
                    return WebResourceResponse("text/plain", "UTF-8", ByteArrayInputStream("Navigation outside scope blocked.".toByteArray(Charsets.UTF_8)))
                }
                // Callback runs off the UI thread. Do not read headers, credentials
                // or bodies. Only record in-scope metadata and leave loading alone.
                if (!disposed && capturing) {
                    val clean = scope.route(raw)
                    val method = request.method.uppercase(Locale.ROOT)
                    if (clean != null && method in methods) synchronized(lock) {
                        if (!disposed && capturing) {
                            entries.addFirst(mapOf(
                                "route" to clean, "method" to method,
                                "hadQuery" to (request.url.encodedQuery != null),
                                "mainFrame" to request.isForMainFrame,
                                "at" to System.currentTimeMillis()
                            ))
                            while (entries.size > 200) entries.removeLast()
                        }
                    }
                }
                return null
            }
        }
        channel.setMethodCallHandler { call, result ->
            if (disposed) {
                result.error("closed", "Browser is closed", null)
            } else when (call.method) {
                "snapshot" -> result.success(synchronized(lock) { entries.toList() })
                "clear" -> { synchronized(lock) { entries.clear() }; result.success(null) }
                "capture" -> { capturing = call.arguments == true; result.success(null) }
                "back" -> { if (web.canGoBack()) web.goBack(); result.success(null) }
                else -> result.notImplemented()
            }
        }
        // Separate from a previous in-app browsing session; no imported secrets.
        web.clearCache(true)
        WebStorage.getInstance().deleteAllData()
        cookieManager.removeAllCookies {
            if (!disposed) {
                cookieManager.flush()
                web.loadUrl(start)
            }
        }
    }

    override fun getView(): View = web

    override fun dispose() {
        disposed = true
        capturing = false
        channel.setMethodCallHandler(null)
        synchronized(lock) { entries.clear() }
        web.stopLoading()
        web.clearHistory()
        web.clearCache(true)
        WebStorage.getInstance().deleteAllData()
        CookieManager.getInstance().removeAllCookies { CookieManager.getInstance().flush() }
        web.destroy()
    }
}
