import 'dart:async';
import 'package:flutter/material.dart';
import 'localized.dart';
import 'package:webview_flutter/webview_flutter.dart';
import 'core/browser_login_policy.dart';
import 'core/scan_policy.dart';

class BrowserLoginResult {
  final Uri start;
  final String cookieHeader, cookiePath;
  const BrowserLoginResult(this.start, this.cookieHeader, this.cookiePath);
}

class BrowserLoginScreen extends StatefulWidget {
  final Uri target, login;
  final bool automatic, allowInsecureHttp;
  final ScanPolicy? policy;
  const BrowserLoginScreen({super.key, required this.target, required this.login,
    this.automatic = false, this.policy, this.allowInsecureHttp = false});
  @override
  State<BrowserLoginScreen> createState() => _BrowserLoginScreenState();
}

class _BrowserLoginScreenState extends State<BrowserLoginScreen> {
  WebViewController? controller;
  final cookies = WebViewCookieManager();
  bool busy = false, loaded = false;
  String? error;
  int progress = 0;
  bool cleaned = false;

  bool permits(Uri candidate) => BrowserLoginPolicy.allowsNavigation(widget.target, widget.login, candidate, widget.policy, allowInsecureHttp: widget.allowInsecureHttp);

  @override
  void initState() {
    super.initState();
    if (widget.automatic) WidgetsBinding.instance.addPostFrameCallback((_) { if (mounted) start(); });
  }

  Future<void> clearSession() async {
    if (cleaned) return;
    cleaned = true;
    try { await cookies.clearCookies(); } catch (_) { /* best-effort cleanup */ }
    try { await controller?.clearLocalStorage(); } catch (_) { /* best-effort cleanup */ }
    try { await controller?.clearCache(); } catch (_) { /* best-effort cleanup */ }
  }

  @override
  void dispose() {
    unawaited(clearSession());
    super.dispose();
  }

  Future<void> start() async {
    if (busy || !permits(widget.login)) return;
    setState(() { busy = true; error = null; });
    try {
      final web = WebViewController();
      await cookies.clearCookies();
      await web.clearCache();
      await web.clearLocalStorage();
      await web.setJavaScriptMode(JavaScriptMode.unrestricted);
      await web.setNavigationDelegate(NavigationDelegate(
        onProgress: (value) { if (mounted) setState(() => progress = value); },
        onPageStarted: (_) { if (mounted) setState(() => loaded = false); },
        onPageFinished: (url) {
          final uri = Uri.tryParse(url);
          if (mounted) setState(() => loaded = uri != null && permits(uri));
        },
        onNavigationRequest: (request) {
          final uri = Uri.tryParse(request.url);
          final permitted = uri != null && permits(uri);
          if (!permitted && mounted) setState(() => error = 'Navigation outside the permitted origin was blocked.');
          return permitted ? NavigationDecision.navigate : NavigationDecision.prevent;
        },
        onWebResourceError: (failure) {
          if (failure.isForMainFrame == true && mounted) {
            setState(() { error = 'The page failed to load.'; loaded = false; });
          }
        },
      ));
      if (!mounted) return;
      setState(() => controller = web);
      await web.loadRequest(widget.login);
    } catch (_) {
      if (mounted) setState(() => error = 'Could not open the login browser.');
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  Future<void> capture() async {
    final web = controller;
    if (web == null || !loaded || busy) return;
    setState(() { busy = true; error = null; });
    try {
      final current = Uri.tryParse(await web.currentUrl() ?? '');
      if (current == null || !permits(current)) {
        throw StateError('Not on the authorized origin.');
      }
      final scanStart = widget.automatic
          ? BrowserLoginPolicy.assessmentStart(widget.target, current, widget.policy, allowInsecureHttp: widget.allowInsecureHttp)
          : widget.target;
      final found = await cookies.getCookies(domain: scanStart);
      final header = BrowserLoginPolicy.cookieHeader(found.map((c) => MapEntry(c.name, c.value)));
      var cookiePath = scanStart.path.isEmpty ? '/' : scanStart.path;
      // Reuse the registered root scope only if the exact same cookies are
      // visible there. Otherwise preserve the more restrictive page path.
      if (widget.automatic && scanStart != widget.target) {
        final root = await cookies.getCookies(domain: widget.target);
        final rootPairs = root.map((c) => '${c.name}=${c.value}').toList()..sort();
        final pagePairs = found.map((c) => '${c.name}=${c.value}').toList()..sort();
        if (rootPairs.length == pagePairs.length &&
            rootPairs.asMap().entries.every((e) => e.value == pagePairs[e.key])) {
          cookiePath = widget.target.path.isEmpty ? '/' : widget.target.path;
        }
      }
      // Do not log, display, persist, or forward cookies to any other origin.
      final captured = BrowserLoginResult(scanStart, header, cookiePath);
      await clearSession();
      if (mounted) Navigator.pop(context, captured);
    } catch (_) {
      if (mounted) setState(() => error = widget.automatic ? 'No usable session cookie was found. If the site uses tokens, go back and choose Direct API sign-in.' : 'Could not import cookies for the selected target. Complete log-in first.');
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  @override
  Widget build(BuildContext context) => Scaffold(
    appBar: AppBar(title: Text('${tr(context, 'Browser sign-in')}: ${widget.login.host}')),
    body: Column(children: [
      if (error != null) Padding(padding: const EdgeInsets.all(8), child: LText(error!)),
      if (controller == null) Expanded(child: Center(child: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(mainAxisSize: MainAxisSize.min, children: [
          LText('Sign in manually to your authorized site, including any OTP. Start resets this app’s own embedded browser cookies and local storage.'),
          const SizedBox(height: 16),
          FilledButton(onPressed: busy ? null : start, child: const LText('Start private login')),
        ]),
      ))) else ...[
        if (widget.automatic) const Padding(padding: EdgeInsets.all(8), child: LText('Sign in on this page, then tap Continue to scan. Your password is not saved by OdinSecurity.')),
        if (progress < 100) LinearProgressIndicator(value: progress / 100),
        Expanded(child: WebViewWidget(controller: controller!)),
        SafeArea(top: false, child: Padding(padding: const EdgeInsets.all(8), child: FilledButton(
          onPressed: loaded && !busy ? capture : null, child: LText(widget.automatic ? 'Continue to scan' : 'Use this authenticated session'),
        ))),
      ],
    ]),
  );
}
