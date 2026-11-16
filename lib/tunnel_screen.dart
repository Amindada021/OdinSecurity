import 'dart:async';
import 'package:flutter/material.dart';
import 'core/project.dart';
import 'core/scan_policy.dart';
import 'core/scoped_tunnel.dart';
import 'localized.dart';

class TunnelScreen extends StatefulWidget {
  final SecurityProject project;
  final Uri target;
  final ScanPolicy policy;
  const TunnelScreen({super.key, required this.project, required this.target, required this.policy});

  @override
  State<TunnelScreen> createState() => _TunnelScreenState();
}

class _TunnelScreenState extends State<TunnelScreen> {
  ScopedTunnel? tunnel;
  StreamSubscription<void>? subscription;
  bool approved = false, starting = false;
  String? error;

  bool get running => tunnel != null && !tunnel!.closed;
  bool get eligible => widget.target.scheme == 'https' && widget.policy.excludedPaths.isEmpty;

  Future<void> start() async {
    if (!approved || starting || running || !eligible) return;
    setState(() { starting = true; approved = false; error = null; });
    try {
      final session = await ScopedTunnel.start(widget.project, widget.target, widget.policy, authorized: true);
      if (!mounted) { session.stop(); return; }
      await subscription?.cancel();
      if (!mounted) { session.stop(); return; }
      setState(() => tunnel = session);
      subscription = session.changes.listen((_) {
        if (mounted) setState(() {});
      });
    } catch (_) {
      if (mounted) setState(() => error = 'Could not start local tunnel.');
    } finally {
      if (mounted) setState(() => starting = false);
    }
  }

  @override
  void dispose() {
    unawaited(subscription?.cancel());
    tunnel?.stop();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final session = tunnel;
    return Scaffold(
      appBar: AppBar(title: const LText('Local HTTPS tunnel')),
      body: ListView(padding: const EdgeInsets.all(16), children: [
        const LText('Local CONNECT proxy for the selected HTTPS origin only. Use an explicitly configured test client on this device. TLS remains end-to-end; no request or response content is decrypted or stored.'),
        SelectableText(widget.target.host + ':' + widget.target.port.toString(), textDirection: TextDirection.ltr),
        const LText('The tunnel listens only on loopback, requires a random session password and stops after 90 seconds. It does not change system proxy settings.'),
        if (!eligible) const LText('Tunnel requires an HTTPS target and a policy without path exclusions because encrypted paths cannot be inspected.'),
        CheckboxListTile(value: approved, title: const LText('I authorize this local tunnel for the selected origin.'),
          onChanged: starting || running || !eligible ? null : (v) => setState(() => approved = v ?? false)),
        FilledButton(onPressed: starting || running || !approved || !eligible ? null : start,
          child: const LText('Start tunnel')),
        if (starting) const LinearProgressIndicator(),
        if (error != null) LText(error!),
        if (session != null) ...[
          LText(session.closed ? 'Disconnected' : 'Connected'),
          if (!session.closed) ...[
            SelectableText('127.0.0.1:' + session.port.toString(), textDirection: TextDirection.ltr),
            const LText('Proxy username and session password'),
            SelectableText('odin\n' + session.password, textDirection: TextDirection.ltr),
            OutlinedButton(onPressed: () { session.stop(); setState(() {}); }, child: const LText('Stop')),
          ],
          Text(tr(context, 'Tunnel connection count') + ': ' + uiNumber(context, session.connections)),
          Text(tr(context, 'Active connections') + ': ' + uiNumber(context, session.active)),
          Text('↑ ' + uiNumber(context, session.sentBytes) + ' B | ↓ ' + uiNumber(context, session.receivedBytes) + ' B'),
        ],
      ]),
    );
  }
}
