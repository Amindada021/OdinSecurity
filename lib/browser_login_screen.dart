import 'dart:async';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:webview_flutter/webview_flutter.dart';

import 'localized.dart';
import 'core/auth.dart';
import 'core/browser_login_policy.dart';
import 'core/login_network_capture.dart';
import 'core/project_storage.dart';
import 'core/quick_scan_preferences.dart';
import 'core/scan_policy.dart';

class BrowserLoginResult {
  final Uri start;
  final String cookieHeader, cookiePath;
  final String? token;
  final TokenDelivery tokenDelivery;
  final bool rememberCredential;

  const BrowserLoginResult.cookie(this.start, this.cookieHeader, this.cookiePath)
      : token = null, tokenDelivery = TokenDelivery.bearer,
        rememberCredential = false;

  const BrowserLoginResult.token(this.start, String value, this.tokenDelivery,
      {this.rememberCredential = false})
      : token = value, cookieHeader = '', cookiePath = '/';

  bool get usesToken => token != null;
}

class BrowserLoginScreen extends StatefulWidget {
  final Uri target, login;
  final String projectId;
  final bool automatic, allowInsecureHttp;
  final ScanPolicy? policy;
  const BrowserLoginScreen({
    super.key, required this.target, required this.login,
    this.projectId = '',
    this.automatic = false, this.policy, this.allowInsecureHttp = false,
  });

  @override
  State<BrowserLoginScreen> createState() => _BrowserLoginScreenState();
}

class _BrowserLoginScreenState extends State<BrowserLoginScreen> {
  WebViewController? controller;
  final cookies = WebViewCookieManager();
  final tokenField = TextEditingController();
  final network = <LoginNetworkResponse>[];
  bool busy = false, loaded = false, cleaned = false;
  bool hasTargetCookies = false, networkHookInstalled = false, showResponse = false;
  String? error;
  int progress = 0, selectedEntry = -1;
  TokenDelivery delivery = TokenDelivery.bearer;
  bool rememberToken = false;
  double networkFraction = 0.45;
  Future<LoginPanelPreferencesRepository> _panelRepo() async =>
      LoginPanelPreferencesRepository(PreferencesStorage(await SharedPreferences.getInstance()));

  Future<void> loadPanelSize() async {
    if (widget.projectId.isEmpty) return;
    try {
      final value = await (await _panelRepo()).load(widget.projectId);
      if (mounted) setState(() => networkFraction = value);
    } catch (_) { /* keep safe default */ }
  }

  Future<void> savePanelSize() async {
    if (widget.projectId.isEmpty) return;
    try {
      await (await _panelRepo()).save(widget.projectId, networkFraction);
    } catch (_) {
      if (mounted) setState(() => error = 'Network panel size could not be saved.');
    }
  }

  bool permits(Uri candidate) => BrowserLoginPolicy.allowsNavigation(
    widget.target, widget.login, candidate, widget.policy,
    allowInsecureHttp: widget.allowInsecureHttp,
  );

  @override
  void initState() {
    super.initState();
    loadPanelSize();
    if (widget.automatic) {
      WidgetsBinding.instance.addPostFrameCallback((_) {
        if (mounted) start();
      });
    }
  }

  Future<void> checkCookies() async {
    try {
      final currentCookies = await cookies.getCookies(domain: widget.target);
      if (mounted) setState(() => hasTargetCookies = currentCookies.isNotEmpty);
    } catch (_) {
      if (mounted) setState(() => hasTargetCookies = false);
    }
  }

  void acceptNetworkResponse(String raw) {
    if (!mounted) return;
    final entry = LoginNetworkResponse.fromBridge(
      raw, login: widget.login, target: widget.target, policy: widget.policy,
    );
    if (entry == null) return;
    setState(() {
      if (network.length >= 40) {
        network.removeAt(0);
        if (selectedEntry >= 0) selectedEntry--;
      }
      network.add(entry);
      selectedEntry = network.length - 1;
      showResponse = false;
    });
    unawaited(checkCookies());
  }

  Future<void> clearSession() async {
    if (cleaned) return;
    cleaned = true;
    tokenField.clear();
    network.clear();
    try { await cookies.clearCookies(); } catch (_) { /* best effort */ }
    try { await controller?.clearLocalStorage(); } catch (_) { /* best effort */ }
    try { await controller?.clearCache(); } catch (_) { /* best effort */ }
  }

  @override
  void dispose() {
    unawaited(clearSession());
    tokenField.dispose();
    super.dispose();
  }

  Future<void> start() async {
    if (busy || !permits(widget.login)) return;
    setState(() {
      busy = true;
      error = null;
      network.clear();
      selectedEntry = -1;
      networkHookInstalled = false;
      hasTargetCookies = false;
    });
    try {
      cleaned = false;
      final web = WebViewController();
      await cookies.clearCookies();
      await web.clearCache();
      await web.clearLocalStorage();
      await web.setJavaScriptMode(JavaScriptMode.unrestricted);
      await web.addJavaScriptChannel(
        'OdinLoginNetwork',
        onMessageReceived: (message) => acceptNetworkResponse(message.message),
      );
      await web.setNavigationDelegate(NavigationDelegate(
        onProgress: (value) {
          if (mounted) setState(() => progress = value);
        },
        onPageStarted: (_) {
          if (mounted) setState(() {
            loaded = false;
            networkHookInstalled = false;
          });
        },
        onPageFinished: (url) async {
          final uri = Uri.tryParse(url);
          if (!mounted) return;
          if (uri == null || !permits(uri)) {
            setState(() => loaded = false);
            return;
          }
          // The user has not yet submitted the login form on this page.
          // Capture subsequent fetch/XHR requests; initial navigation isn't captured.
          var installed = false;
          try {
            await web.runJavaScript(loginNetworkInstrumentation);
            installed = true;
          } catch (_) { /* Some pages do not support script injection. */ }
          if (!mounted) return;
          setState(() {
            loaded = true;
            networkHookInstalled = installed;
          });
          unawaited(checkCookies());
        },
        onNavigationRequest: (request) {
          final uri = Uri.tryParse(request.url);
          final permitted = uri != null && permits(uri);
          if (!permitted && mounted) {
            setState(() => error = 'Navigation outside the permitted origin was blocked.');
          }
          return permitted ? NavigationDecision.navigate : NavigationDecision.prevent;
        },
        onWebResourceError: (failure) {
          if (failure.isForMainFrame == true && mounted) {
            setState(() {
              error = 'The page failed to load.';
              loaded = false;
            });
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
          ? BrowserLoginPolicy.assessmentStart(
              widget.target, current, widget.policy,
              allowInsecureHttp: widget.allowInsecureHttp)
          : widget.target;
      final enteredToken = tokenField.text.trim();
      if (enteredToken.isNotEmpty) {
        // Validate before leaving the browser; never reveal or log the token.
        Authenticator.tokenHeaders(enteredToken, delivery);
        final captured = BrowserLoginResult.token(scanStart, enteredToken, delivery,
          rememberCredential: widget.automatic && rememberToken && widget.target.scheme == 'https');
        await clearSession();
        if (mounted) Navigator.pop(context, captured);
        return;
      }
      final found = await cookies.getCookies(domain: scanStart);
      final header = BrowserLoginPolicy.cookieHeader(
        found.map((c) => MapEntry(c.name, c.value)),
      );
      var cookiePath = scanStart.path.isEmpty ? '/' : scanStart.path;
      if (widget.automatic && scanStart != widget.target) {
        final root = await cookies.getCookies(domain: widget.target);
        final rootPairs = root.map((c) => '${c.name}=${c.value}').toList()..sort();
        final pagePairs = found.map((c) => '${c.name}=${c.value}').toList()..sort();
        if (rootPairs.length == pagePairs.length &&
            rootPairs.asMap().entries.every((e) => e.value == pagePairs[e.key])) {
          cookiePath = widget.target.path.isEmpty ? '/' : widget.target.path;
        }
      }
      final captured = BrowserLoginResult.cookie(scanStart, header, cookiePath);
      await clearSession();
      if (mounted) Navigator.pop(context, captured);
    } catch (_) {
      if (mounted) {
        setState(() => error = 'No usable cookie for the scan target. Select a token from a Network response or paste one below.');
      }
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  Widget networkPane(BuildContext context) {
    final selected = selectedEntry >= 0 && selectedEntry < network.length
        ? network[selectedEntry] : null;
    final suggestions = selected?.tokens ?? const <LoginTokenCandidate>[];
    return Container(
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.surfaceContainer,
        border: Border(top: BorderSide(color: Theme.of(context).colorScheme.outlineVariant)),
      ),
      child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(12, 6, 12, 2),
          child: Row(children: [
            const Icon(Icons.network_check, size: 18),
            const SizedBox(width: 8),
            LText('Network responses', style: Theme.of(context).textTheme.titleSmall),
            const SizedBox(width: 8),
            Text('${network.length}/40'),
            const Spacer(),
            if (hasTargetCookies) const Tooltip(
              message: 'Cookie found for scan target',
              child: Icon(Icons.cookie, color: Colors.green, size: 20),
            ),
            IconButton(
              tooltip: tr(context, 'Clear captured responses'),
              onPressed: () => setState(() {
                network.clear();
                selectedEntry = -1;
                showResponse = false;
              }),
              icon: const Icon(Icons.delete_outline, size: 20),
            ),
          ]),
        ),
        Expanded(
          flex: 2,
          child: network.isEmpty
              ? Center(child: Padding(
                  padding: const EdgeInsets.symmetric(horizontal: 12),
                  child: LText(networkHookInstalled
                      ? 'Waiting for fetch/XHR responses. Sign in using the browser above.'
                      : 'Response inspection is unavailable until the login page finishes loading.'),
                ))
              : ListView.builder(
                  itemCount: network.length,
                  itemBuilder: (context, index) {
                    final item = network[index];
                    return ListTile(
                      selected: selectedEntry == index, dense: true,
                      title: Text('${item.method} ${item.url.path}',
                        maxLines: 1, overflow: TextOverflow.ellipsis,
                        textDirection: TextDirection.ltr),
                      subtitle: Text('${item.url.host} · ${item.source}',
                        maxLines: 1, overflow: TextOverflow.ellipsis),
                      trailing: Text('${item.status}'),
                      onTap: () => setState(() {
                        selectedEntry = index;
                        showResponse = false;
                      }),
                    );
                  },
                ),
        ),
        if (selected != null) Expanded(
          flex: 3,
          child: SingleChildScrollView(
            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 4),
            child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Row(children: [
                Expanded(child: Text(
                  '${selected.status} · ${selected.contentType}',
                  maxLines: 1, overflow: TextOverflow.ellipsis)),
                TextButton(
                  onPressed: () => setState(() => showResponse = !showResponse),
                  child: LText(showResponse ? 'Hide response' : 'Show response'),
                ),
              ]),
              if (suggestions.isNotEmpty) ...[
                const LText('Token candidates in this response:'),
                for (final candidate in suggestions)
                  Wrap(crossAxisAlignment: WrapCrossAlignment.center, children: [
                    Text(candidate.path, style: Theme.of(context).textTheme.bodySmall),
                    TextButton.icon(
                      onPressed: () => setState(() => tokenField.text = candidate.value),
                      icon: const Icon(Icons.check_circle_outline, size: 16),
                      label: const LText('Use token'),
                    ),
                    IconButton(
                      tooltip: tr(context, 'Copy token'),
                      onPressed: () async {
                        await Clipboard.setData(ClipboardData(text: candidate.value));
                        if (context.mounted) ScaffoldMessenger.of(context).showSnackBar(
                          const SnackBar(content: LText('Token copied to device clipboard.')),
                        );
                      },
                      icon: const Icon(Icons.copy, size: 18),
                    ),
                  ]),
              ],
              if (showResponse)
                SelectableText(
                  selected.body.isEmpty ? '(empty)' : selected.body,
                  textDirection: TextDirection.ltr,
                  style: const TextStyle(fontFamily: 'monospace', fontSize: 11),
                ),
              if (selected.truncated) const LText('Response preview truncated.'),
            ]),
          ),
        ),
        Padding(
          padding: const EdgeInsets.fromLTRB(12, 2, 12, 4),
          child: Column(children: [
            TextField(
              controller: tokenField,
              obscureText: true,
              autocorrect: false,
              enableSuggestions: false,
              textDirection: TextDirection.ltr,
              decoration: InputDecoration(
                isDense: true,
                label: const LText('Selected or pasted token (optional)'),
                prefixIcon: const Icon(Icons.key_outlined),
                suffixIcon: IconButton(
                  tooltip: tr(context, 'Paste token'),
                  icon: const Icon(Icons.paste),
                  onPressed: () async {
                    final clip = await Clipboard.getData(Clipboard.kTextPlain);
                    if (clip?.text != null && mounted) {
                      setState(() => tokenField.text = clip!.text!);
                    }
                  },
                ),
              ),
              onChanged: (_) => setState(() => error = null),
            ),
            if (tokenField.text.isNotEmpty && widget.automatic && widget.target.scheme == 'https')
              CheckboxListTile(
                dense: true, contentPadding: EdgeInsets.zero,
                title: const LText('Remember selected token securely for this project'),
                subtitle: const LText('Optional; saved in encrypted storage. Expired tokens must be replaced.'),
                value: rememberToken,
                onChanged: (value) => setState(() => rememberToken = value ?? false),
              ),
            Row(children: [
              Expanded(child: DropdownButtonFormField<TokenDelivery>(
                initialValue: delivery,
                isDense: true,
                items: const [
                  DropdownMenuItem(value: TokenDelivery.bearer,
                    child: Text('Bearer (Authorization)')),
                  DropdownMenuItem(value: TokenDelivery.raw,
                    child: Text('Raw (Authorization)')),
                ],
                onChanged: (value) => setState(() {
                  if (value != null) delivery = value;
                }),
              )),
              const SizedBox(width: 8),
              Expanded(child: Text(hasTargetCookies
                  ? tr(context, 'Cookie found for scan target')
                  : tr(context, 'Cookies checked automatically'),
                maxLines: 2, style: Theme.of(context).textTheme.bodySmall)),
            ]),
          ]),
        ),
      ]),
    );
  }

  @override
  Widget build(BuildContext context) => Scaffold(
    appBar: AppBar(title: Text('${tr(context, 'Browser sign-in')}: ${widget.login.host}',
      overflow: TextOverflow.ellipsis)),
    body: Column(children: [
      if (error != null) Padding(
        padding: const EdgeInsets.all(8),
        child: Text(tr(context, error!), style: TextStyle(color: Theme.of(context).colorScheme.error)),
      ),
      if (controller == null) Expanded(child: Center(child: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(mainAxisSize: MainAxisSize.min, children: [
          const LText('Sign in manually to your authorized site, including any OTP.'),
          const SizedBox(height: 16),
          FilledButton(onPressed: busy ? null : start,
            child: const LText('Start private login')),
        ]),
      ))) else ...[
        if (progress < 100) LinearProgressIndicator(value: progress / 100),
        Padding(
          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 4),
          child: Row(children: [
            const Icon(Icons.shield_outlined, size: 17),
            const SizedBox(width: 6),
            Expanded(child: Text(
              '${tr(context, 'Scanning')}: ${widget.target.host}  ·  ${tr(context, 'Signing in')}: ${widget.login.host}',
              maxLines: 2, overflow: TextOverflow.ellipsis,
              style: Theme.of(context).textTheme.labelMedium,
            )),
          ]),
        ),
        Expanded(flex: ((1 - networkFraction) * 100).round(),
          child: WebViewWidget(controller: controller!)),
        GestureDetector(
          behavior: HitTestBehavior.opaque,
          onVerticalDragUpdate: (details) {
            final height = MediaQuery.sizeOf(context).height;
            if (height < 1) return;
            setState(() {
              networkFraction = LoginPanelPreferencesRepository.normalize(
                networkFraction - details.delta.dy / (height * 0.72));
            });
          },
          onVerticalDragEnd: (_) => unawaited(savePanelSize()),
          onDoubleTap: () {
            setState(() => networkFraction = networkFraction > 0.55 ? 0.3 : 0.70);
            unawaited(savePanelSize());
          },
          child: Container(
            height: 28,
            width: double.infinity,
            color: Theme.of(context).colorScheme.surfaceContainerHigh,
            child: Row(mainAxisAlignment: MainAxisAlignment.center, children: [
              const Icon(Icons.drag_handle, size: 24),
              const SizedBox(width: 6),
              LText('Drag to resize Network',
                style: Theme.of(context).textTheme.labelSmall),
              const SizedBox(width: 6),
              IconButton(
                tooltip: tr(context, 'Expand or shrink Network'),
                padding: EdgeInsets.zero,
                constraints: const BoxConstraints(minHeight: 24, minWidth: 32),
                icon: const Icon(Icons.unfold_more, size: 17),
                onPressed: () {
                  setState(() => networkFraction = networkFraction > 0.55 ? 0.3 : 0.70);
                  unawaited(savePanelSize());
                },
              ),
            ]),
          ),
        ),
        Expanded(flex: (networkFraction * 100).round(),
          child: networkPane(context)),
        SafeArea(top: false, child: Padding(
          padding: const EdgeInsets.all(8),
          child: Column(mainAxisSize: MainAxisSize.min, children: [
            const LText('Network shows fetch/XHR after page load, not all browser requests. Responses stay on this device for this sign-in.'),
            const SizedBox(height: 4),
            SizedBox(width: double.infinity, child: FilledButton(
              onPressed: loaded && !busy ? capture : null,
              child: LText(widget.automatic ? 'Continue to scan' : 'Use this authenticated session'),
            )),
          ]),
        )),
      ],
    ]),
  );
}
