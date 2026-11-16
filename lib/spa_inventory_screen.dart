import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'saved_routes_screen.dart';
import 'localized.dart';
import 'package:flutter/services.dart';
import 'package:webview_flutter/webview_flutter.dart';
import 'core/project.dart';
import 'core/route_inventory.dart';
import 'core/rendered_navigation.dart';
import 'core/har_traffic.dart';
import 'core/scan_policy.dart';

class SpaInventoryScreen extends StatefulWidget {
  final SecurityProject project;
  final Uri target;
  final ScanPolicy policy;
  const SpaInventoryScreen({super.key, required this.project, required this.target, required this.policy});
  @override
  State<SpaInventoryScreen> createState() => _SpaInventoryScreenState();
}

class _SpaInventoryScreenState extends State<SpaInventoryScreen> {
  WebViewController? browser;
  final cookies = WebViewCookieManager();
  List<RouteObservation> routes = [];
  bool authorized = false, busy = false, loaded = false, closing = false, showRoutes = false;
  String? error;
  bool autoRunning = false, stopRequested = false;
  int explored = 0;
  Uri? expectedNavigation;
  Completer<bool>? navigationFinished;

  void finishNavigation(bool success) {
    final pending = navigationFinished;
    if (pending != null && !pending.isCompleted) pending.complete(success);
  }

  @override
  void dispose() {
    stopRequested = true;
    finishNavigation(false);
    super.dispose();
  }

  bool permits(Uri? url) => url != null && url.scheme == 'https' &&
    SecurityProject.sameOrigin(widget.target, url) &&
    widget.project.contains(url) && widget.policy.permits(url);

  Future<void> start() async {
    if (!authorized || busy || !permits(widget.target)) return;
    setState(() { busy = true; error = null; });
    try {
      final web = WebViewController();
      await cookies.clearCookies();
      await web.clearCache();
      await web.clearLocalStorage();
      await web.setJavaScriptMode(JavaScriptMode.unrestricted);
      await web.setNavigationDelegate(NavigationDelegate(
        onNavigationRequest: (request) {
          final destination = Uri.tryParse(request.url);
          final unexpected = autoRunning && request.isMainFrame && destination != expectedNavigation;
          final allowed = !closing && permits(destination) && !unexpected;
          if (unexpected) { stopRequested = true; finishNavigation(false); }
          if (!allowed && mounted && !closing) setState(() => error = 'Navigation outside the selected HTTPS origin or allowed paths was blocked.');
          return allowed ? NavigationDecision.navigate : NavigationDecision.prevent;
        },
        onPageStarted: (_) { if (mounted && !closing) setState(() => loaded = false); },
        onPageFinished: (url) {
          final destination = Uri.tryParse(url);
          if (mounted && !closing) setState(() => loaded = permits(destination));
          if (autoRunning && destination == expectedNavigation) finishNavigation(true);
        },
        onWebResourceError: (failure) {
          if (mounted && !closing && failure.isForMainFrame == true) {
            setState(() { loaded = false; error = 'Page failed to load.'; });
            if (autoRunning) finishNavigation(false);
          }
        },
      ));
      if (!mounted) return;
      setState(() => browser = web);
      await web.loadRequest(widget.target);
    } catch (_) {
      if (mounted) setState(() => error = 'Could not start the embedded browser.');
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  Future<void> capture() async {
    final web = browser;
    if (web == null || busy || !loaded) return;
    setState(() { busy = true; error = null; });
    try {
      final before = Uri.tryParse(await web.currentUrl() ?? '');
      if (!permits(before)) throw const FormatException();
      final result = await web.runJavaScriptReturningResult(RouteInventory.browserSnapshot);
      final after = Uri.tryParse(await web.currentUrl() ?? '');
      if (before != after || !permits(after)) throw const FormatException();
      final found = RouteInventory.fromBrowser(widget.project, widget.policy, before!, result);
      if (mounted) setState(() { routes = RouteInventory.merge(routes, found); showRoutes = true; });
    } catch (_) {
      if (mounted) setState(() => error = 'Capture failed or the page changed. Try again after navigation finishes.');
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  Future<void> exploreSelected() async {
    final web = browser;
    if (web == null || busy || !loaded) return;
    final current = Uri.tryParse(await web.currentUrl() ?? '');
    if (!mounted || busy || !permits(current)) return;
    final candidates = RenderedNavigation.candidates(widget.project, widget.policy, widget.target, current!, routes);
    if (candidates.isEmpty) {
      setState(() => error = 'Capture queryless links before exploring selected pages.');
      return;
    }
    final selected = <Uri>{};
    final approved = await showDialog<List<Uri>>(context: context, builder: (context) => StatefulBuilder(
      builder: (context, update) => AlertDialog(
        title: const LText('Select rendered pages'),
        content: SingleChildScrollView(child: Column(mainAxisSize: MainAxisSize.min, children: [
          const LText('Select only known read-only staging pages. The browser will visit these exact URLs using the current session. Site scripts may run. No forms or buttons are automatically submitted.'),
          for (final route in candidates) CheckboxListTile(
            value: selected.contains(route), title: Text(route.toString(), textDirection: TextDirection.ltr),
            onChanged: (v) => update(() { if (v == true) { selected.add(route); } else { selected.remove(route); } })),
        ])),
        actions: [
          TextButton(onPressed: () => Navigator.pop(context), child: const LText('Cancel')),
          FilledButton(onPressed: selected.isEmpty ? null : () => Navigator.pop(context, selected.toList()), child: const LText('Explore selected pages')),
        ],
      ),
    ));
    if (approved == null || !mounted || busy) return;
    final stillCurrent = Uri.tryParse(await web.currentUrl() ?? '');
    if (!mounted || busy) return;
    if (stillCurrent != current || !permits(stillCurrent)) {
      setState(() => error = 'Rendered exploration stopped after a navigation change or page error.');
      return;
    }
    setState(() { busy = true; autoRunning = true; stopRequested = false; explored = 0; error = null; });
    try {
      for (final route in approved) {
        if (stopRequested || !mounted) break;
        if (!permits(route)) throw const FormatException();
        await Future<void>.delayed(Duration(milliseconds: widget.policy.delayMs));
        if (stopRequested || !mounted) break;
        expectedNavigation = route;
        final completion = Completer<bool>();
        navigationFinished = completion;
        await web.loadRequest(route).timeout(const Duration(seconds: 15));
        final success = await completion.future.timeout(const Duration(seconds: 15), onTimeout: () => false);
        if (!success || stopRequested || !mounted) break;
        if (Uri.tryParse(await web.currentUrl() ?? '') != route) break;
        final snapshot = await web.runJavaScriptReturningResult(RouteInventory.browserSnapshot).timeout(const Duration(seconds: 5));
        if (Uri.tryParse(await web.currentUrl() ?? '') != route) break;
        final found = RouteInventory.fromBrowser(widget.project, widget.policy, route, snapshot);
        if (!mounted) break;
        setState(() { routes = RouteInventory.merge(routes, found); explored++; showRoutes = true; });
      }
      if (mounted && explored != approved.length && !stopRequested) {
        setState(() => error = 'Rendered exploration stopped after a navigation change or page error.');
      }
    } catch (_) {
      if (mounted) setState(() => error = 'Rendered exploration stopped after a navigation change or page error.');
    } finally {
      finishNavigation(false);
      navigationFinished = null;
      expectedNavigation = null;
      if (mounted) setState(() { busy = false; autoRunning = false; });
    }
  }

  Future<void> close() async {
    if (busy || closing) return;
    setState(() => closing = true);
    try {
      final web = browser;
      if (web != null) {
        // Disable page navigation, then reset this app's WebView data.
        await web.setJavaScriptMode(JavaScriptMode.disabled);
        await web.clearLocalStorage();
        await web.clearCache();
        await cookies.clearCookies();
      }
    } catch (_) {
      if (mounted) setState(() { closing = false; error = 'Browser cleanup failed. Retry closing.'; });
      return;
    }
    if (mounted) Navigator.of(context).pop();
  }

  @override
  Widget build(BuildContext context) => PopScope(
    canPop: false,
    onPopInvokedWithResult: (didPop, _) { if (!didPop) close(); },
    child: Scaffold(
      appBar: AppBar(title: const LText('SPA explorer'), leading: IconButton(
        onPressed: busy || closing ? null : close, icon: const Icon(Icons.arrow_back)),
        actions: [if (browser != null) IconButton(
          tooltip: tr(context, 'Browser / captured routes'), onPressed: busy || closing ? null : () => setState(() => showRoutes = !showRoutes),
          icon: Icon(showRoutes ? Icons.language : Icons.list_alt))]),
      body: Column(children: [
        if (error != null) Padding(padding: const EdgeInsets.all(8), child: LText(error!)),
        if (busy || closing) const LinearProgressIndicator(),
        if (browser == null)
          Expanded(child: ListView(padding: const EdgeInsets.all(16), children: [
            Text('Open ${widget.target.host} and sign in manually, including OTP if required.'),
            const LText('You control browsing. Normal site scripts and subresources may contact other origins; only in-scope metadata is collected. Avoid actions that modify data. No automatic clicks, credential extraction, or request replay.'),
            CheckboxListTile(value: authorized, title: const LText('I am authorized to browse this target.'), onChanged: busy ? null : (v) => setState(() => authorized = v ?? false)),
            FilledButton(onPressed: busy || !authorized || !permits(widget.target) ? null : start, child: const LText('Open browser')),
          ]))
        else ...[
          Expanded(child: IndexedStack(index: showRoutes ? 1 : 0, children: [
            IgnorePointer(ignoring: autoRunning, child: WebViewWidget(controller: browser!)),
            RouteList(routes: routes),
          ])),
          SafeArea(top: false, child: Wrap(spacing: 8, children: [
            if (showRoutes) OutlinedButton(onPressed: busy || closing || routes.isEmpty ? null : () async {
              setState(() => busy = true);
              try { await saveObservedRoutes(context, widget.project, widget.policy, routes); }
              finally { if (mounted) setState(() => busy = false); }
            }, child: const LText('Save routes')),
            if (autoRunning) OutlinedButton(onPressed: stopRequested ? null : () => setState(() { stopRequested = true; finishNavigation(false); }), child: const LText('Stop')),
            if (autoRunning) Text('${uiNumber(context, explored)} ${tr(context, "Pages captured")}'),
            OutlinedButton(onPressed: loaded && !busy && !closing && routes.isNotEmpty ? exploreSelected : null, child: const LText('Explore selected pages')),
            FilledButton.icon(onPressed: loaded && !busy && !closing ? capture : null, icon: const Icon(Icons.search), label: const LText('Capture routes')),
            OutlinedButton(onPressed: busy || closing ? null : () => setState(() => showRoutes = !showRoutes),
              child: Text(showRoutes ? tr(context, 'Back to browser') : '${tr(context, 'Routes')} (${uiNumber(context, routes.length)})')),
          ])),
        ],
      ]),
    ),
  );
}

class RouteList extends StatelessWidget {
  final List<RouteObservation> routes;
  const RouteList({super.key, required this.routes});
  @override
  Widget build(BuildContext context) => ListView(padding: const EdgeInsets.all(12), children: [
    Text('${routes.length} observed routes (cap ${RouteInventory.maxEntries})'),
    const LText('Query strings and fragments omitted. Route paths may be sensitive. Resource timing does not establish an HTTP method or security finding.'),
    const LText('Form action and script destinations are observations only. Forms are never automatically submitted.'),
    for (final route in routes) ListTile(
      title: SelectableText(route.url.toString()), subtitle: Text(route.source),
      trailing: IconButton(tooltip: tr(context, 'Copy route'), icon: const Icon(Icons.copy),
        onPressed: () => Clipboard.setData(ClipboardData(text: route.url.toString()))),
    ),
  ]);
}

class HarInventoryScreen extends StatefulWidget {
  final SecurityProject project;
  final ScanPolicy policy;
  const HarInventoryScreen({super.key, required this.project, required this.policy});
  @override
  State<HarInventoryScreen> createState() => _HarInventoryScreenState();
}

class _HarInventoryScreenState extends State<HarInventoryScreen> {
  final source = TextEditingController();
  HarTrafficReport? traffic;
  List<RouteObservation> routes = [];
  String filter = 'all';
  bool showTraffic = true;
  String? error;
  bool busy = false;
  @override
  void dispose() { source.dispose(); super.dispose(); }

  void parse() {
    try {
      final found = HarTrafficAnalyzer.parse(widget.project, widget.policy, source.text);
      source.clear();
      setState(() { traffic = found; routes = found.routes; filter = 'all'; error = null; });
    } catch (_) {
      source.clear();
      setState(() { traffic = null; routes = []; error = 'Invalid or oversized HAR JSON.'; });
    }
  }

  Future<void> importFile() async {
    if (busy) return;
    setState(() { busy = true; error = null; });
    try {
      final selected = await FilePicker.platform.pickFiles(type: FileType.custom,
        allowedExtensions: ['har', 'json'], allowMultiple: false, withData: false, withReadStream: true);
      if (selected == null || !mounted) return;
      final file = selected.files.single;
      if (file.size > RouteInventory.maxInput) throw const FormatException();
      final stream = file.readStream ?? (file.path == null ? null : File(file.path!).openRead());
      if (stream == null) throw const FormatException();
      final bytes = <int>[];
      await for (final chunk in stream) {
        if (bytes.length + chunk.length > RouteInventory.maxInput) throw const FormatException();
        bytes.addAll(chunk);
      }
      final found = HarTrafficAnalyzer.parse(widget.project, widget.policy, utf8.decode(bytes));
      if (mounted) setState(() { traffic = found; routes = found.routes; filter = 'all'; source.clear(); });
    } catch (_) {
      if (mounted) setState(() { traffic = null; routes = []; error = 'Invalid or oversized HAR JSON.'; });
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  @override
  Widget build(BuildContext context) => Scaffold(
    appBar: AppBar(title: const LText('Offline HAR inventory')),
    body: Column(children: [
      Padding(padding: const EdgeInsets.all(12), child: Column(children: [
        const LText('Import sanitized HAR from an authorized test session. Analysis is offline; only scoped paths, methods, status, timing and sizes are retained in memory.'),
        TextField(controller: source, maxLines: 4, autocorrect: false, enableSuggestions: false,
          decoration: const InputDecoration(label: LText('HAR JSON (max 1 MiB)'))),
        Wrap(spacing: 8, children: [
          FilledButton(onPressed: busy ? null : parse, child: const LText('Import routes')),
          OutlinedButton.icon(onPressed: busy ? null : importFile, icon: const Icon(Icons.file_open), label: const LText('Import HAR file')),
          OutlinedButton(onPressed: busy || routes.isEmpty ? null : () async {
            setState(() => busy = true);
            try { await saveObservedRoutes(context, widget.project, widget.policy, routes); }
            finally { if (mounted) setState(() => busy = false); }
          }, child: const LText('Save routes')),
        ]),
        if (busy) const LinearProgressIndicator(),
        if (error != null) LText(error!),
      ])),
      if (traffic != null) Padding(padding: const EdgeInsets.symmetric(horizontal: 12), child: Wrap(spacing: 8, children: [
        ChoiceChip(label: const LText('Traffic summary'), selected: showTraffic, onSelected: (_) => setState(() => showTraffic = true)),
        ChoiceChip(label: const LText('Routes'), selected: !showTraffic, onSelected: (_) => setState(() => showTraffic = false)),
      ])),
      Expanded(child: traffic != null && showTraffic ? HarTrafficView(
        report: traffic!, filter: filter, onFilter: (value) => setState(() => filter = value),
      ) : RouteList(routes: routes)),
    ]),
  );
}

class HarTrafficView extends StatelessWidget {
  final HarTrafficReport report;
  final String filter;
  final ValueChanged<String> onFilter;
  const HarTrafficView({super.key, required this.report, required this.filter, required this.onFilter});

  @override
  Widget build(BuildContext context) {
    final shown = report.entries.where((e) => switch (filter) {
      'errors' => (e.status ?? 0) >= 400,
      'slow' => (e.elapsedMs ?? 0) >= 1000,
      _ => true,
    }).toList();
    return ListView.builder(
      padding: const EdgeInsets.all(12), itemCount: shown.length + 1,
      itemBuilder: (context, index) {
        if (index == 0) return Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Wrap(spacing: 8, runSpacing: 4, children: [
            Chip(label: Text('${tr(context, 'Requests')}: ${uiNumber(context, report.entries.length)}')),
            Chip(label: Text('4xx: ${uiNumber(context, report.clientErrors)}')),
            Chip(label: Text('5xx: ${uiNumber(context, report.serverErrors)}')),
            Chip(label: Text('${tr(context, 'Slow requests')}: ${uiNumber(context, report.slow)}')),
          ]),
          if (report.capped) const LText('Traffic summary capped at 1000 scoped entries.'),
          const LText('Timing and sizes are recorded by the source browser, not measured by Odin Security. Errors or slow requests are not evidence of a vulnerability.'),
          DropdownButtonFormField<String>(key: ValueKey(filter), initialValue: filter,
            items: const [
              DropdownMenuItem(value: 'all', child: LText('All requests')),
              DropdownMenuItem(value: 'errors', child: LText('HTTP errors')),
              DropdownMenuItem(value: 'slow', child: LText('Slow requests')),
            ],
            onChanged: (value) => onFilter(value ?? 'all'),
          ),
        ]);
        final item = shown[index - 1];
        final details = [
          if (item.status != null) 'HTTP ${item.status}' else 'HTTP ?',
          if (item.elapsedMs != null) '${item.elapsedMs!.toStringAsFixed(1)} ms',
          if (item.responseBytes != null) '${item.responseBytes} bytes',
        ].join(' | ');
        return ListTile(title: Text('${item.route.source} ${item.route.url}'), subtitle: Text(details));
      },
    );
  }
}
