import 'package:flutter/material.dart';
import 'localized.dart';
import 'package:webview_flutter/webview_flutter.dart';
import 'core/browser_login_policy.dart';

class BrowserLoginScreen extends StatefulWidget {
  final Uri target, login;
  const BrowserLoginScreen({super.key, required this.target, required this.login});
  @override
  State<BrowserLoginScreen> createState() => _BrowserLoginScreenState();
}

class _BrowserLoginScreenState extends State<BrowserLoginScreen> {
  WebViewController? controller;
  final cookies = WebViewCookieManager();
  bool busy = false, loaded = false;
  String? error;
  int progress = 0;

  Future<void> start() async {
    if (busy || !BrowserLoginPolicy.allows(widget.target, widget.login)) return;
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
          if (mounted) setState(() => loaded = uri != null && BrowserLoginPolicy.allows(widget.target, uri));
        },
        onNavigationRequest: (request) {
          final uri = Uri.tryParse(request.url);
          final permitted = uri != null && BrowserLoginPolicy.allows(widget.target, uri);
          if (!permitted && mounted) setState(() => error = 'Navigation outside this HTTPS origin was blocked.');
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
      if (current == null || !BrowserLoginPolicy.allows(widget.target, current)) {
        throw StateError('Not on the authorized origin.');
      }
      final found = await cookies.getCookies(domain: widget.target);
      final header = BrowserLoginPolicy.cookieHeader(found.map((c) => MapEntry(c.name, c.value)));
      // Do not log, display, or send the imported credential to any other origin.
      await cookies.clearCookies();
      await web.clearLocalStorage();
      await web.clearCache();
      if (mounted) Navigator.pop(context, header);
    } catch (_) {
      if (mounted) setState(() => error = 'Could not import cookies for the selected target. Complete log-in first.');
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  @override
  Widget build(BuildContext context) => Scaffold(
    appBar: AppBar(title: Text('Login: ${widget.target.host}')),
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
        if (progress < 100) LinearProgressIndicator(value: progress / 100),
        Expanded(child: WebViewWidget(controller: controller!)),
        SafeArea(top: false, child: Padding(padding: const EdgeInsets.all(8), child: FilledButton(
          onPressed: loaded && !busy ? capture : null, child: const LText('Use this authenticated session'),
        ))),
      ],
    ]),
  );
}
