import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'core/browser_traffic.dart';
import 'core/project.dart';
import 'core/scan_policy.dart';
import 'localized.dart';

class BrowserTrafficScreen extends StatefulWidget {
  final SecurityProject project;
  final Uri target;
  final ScanPolicy policy;
  const BrowserTrafficScreen({super.key, required this.project, required this.target, required this.policy});
  @override
  State<BrowserTrafficScreen> createState() => _BrowserTrafficScreenState();
}

class _BrowserTrafficScreenState extends State<BrowserTrafficScreen> {
  bool consent = false, started = false, showTraffic = false, capturing = true, busy = false, failed = false;
  MethodChannel? channel;
  List<BrowserTrafficRow> rows = [];

  Future<void> action(String method, [Object? arguments]) async {
    final native = channel;
    if (native == null || busy) return;
    setState(() { busy = true; failed = false; });
    try {
      if (method == 'snapshot') {
        final found = BrowserTraffic.parse(widget.project, widget.policy, await native.invokeMethod<Object?>('snapshot'));
        if (mounted) setState(() { rows = found; showTraffic = true; });
      } else {
        await native.invokeMethod<void>(method, arguments);
        if (mounted) setState(() {
          if (method == 'clear') rows = [];
          if (method == 'capture') capturing = arguments == true;
        });
      }
    } catch (_) {
      if (mounted) setState(() => failed = true);
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  @override
  Widget build(BuildContext context) => Scaffold(
    appBar: AppBar(title: const LText('Browser traffic observer')),
    body: Column(children: [
      if (failed) const Padding(padding: EdgeInsets.all(8), child: LText('Could not read browser traffic.')),
      if (!started)
        Expanded(child: ListView(padding: const EdgeInsets.all(16), children: [
          Text(widget.target.toString()),
          const LText('Observe actual request metadata from this embedded Android browser only. Sign in manually to your authorized staging site. No credentials, request bodies or query values are captured. Browser scripts may contact other origins.'),
          const LText('This does not intercept TLS, other apps, all redirects, or all WebSocket/service-worker traffic. Closing clears this app browser session.'),
          CheckboxListTile(value: consent, title: const LText('I authorize browsing and observation for this project.'),
            onChanged: (v) => setState(() => consent = v ?? false)),
          FilledButton(onPressed: !consent || kIsWeb || defaultTargetPlatform != TargetPlatform.android ||
              widget.target.scheme != 'https' || !widget.project.contains(widget.target) || !widget.policy.permits(widget.target)
            ? null : () => setState(() => started = true), child: const LText('Open browser')),
        ]))
      else ...[
        if (busy) const LinearProgressIndicator(),
        Expanded(child: IndexedStack(index: showTraffic ? 1 : 0, children: [
          AndroidView(viewType: 'odin/scoped-browser', creationParamsCodec: const StandardMessageCodec(),
            creationParams: {
              'authorized': true, 'start': widget.target.toString(),
              'origins': widget.project.targets.where((u) => u.scheme == 'https').map((u) => u.toString()).toList(),
              'excluded': widget.policy.excludedPaths,
            },
            onPlatformViewCreated: (id) { if (mounted) setState(() => channel = MethodChannel('odin/scoped-browser/$id')); }),
          ListView.builder(itemCount: rows.length, itemBuilder: (_, i) {
            final row = rows[i];
            return ListTile(title: Text('${row.method} ${row.route}', textDirection: TextDirection.ltr),
              subtitle: Text('${row.at.toLocal()} | ${row.mainFrame ? "document" : "resource"}${row.hadQuery ? " | query omitted" : ""}'));
          }),
        ])),
        SafeArea(top: false, child: Wrap(spacing: 8, children: [
          OutlinedButton(onPressed: channel == null || busy ? null : () => action('snapshot'), child: const LText('Refresh traffic')),
          OutlinedButton(onPressed: channel == null || busy ? null : () => action('capture', !capturing),
            child: LText(capturing ? 'Pause capture' : 'Resume capture')),
          OutlinedButton(onPressed: channel == null || busy ? null : () => action('clear'), child: const LText('Clear')),
          OutlinedButton(onPressed: channel == null || busy ? null : () => setState(() => showTraffic = !showTraffic),
            child: LText(showTraffic ? 'Back to browser' : 'Traffic logger')),
          if (!showTraffic) IconButton(onPressed: channel == null || busy ? null : () => action('back'), icon: const Icon(Icons.arrow_back)),
        ])),
      ],
    ]),
  );
}
