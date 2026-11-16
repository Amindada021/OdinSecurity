import 'dart:async';
import 'package:flutter/material.dart';
import 'core/local_lab_receiver.dart';
import 'localized.dart';

class LocalLabReceiverScreen extends StatefulWidget {
  const LocalLabReceiverScreen({super.key});
  @override
  State<LocalLabReceiverScreen> createState() => _LocalLabReceiverScreenState();
}
class _LocalLabReceiverScreenState extends State<LocalLabReceiverScreen> with WidgetsBindingObserver {
  final receiver = LocalLabReceiver();
  bool approved = false, starting = false, failed = false;
  @override
  void initState() { super.initState(); WidgetsBinding.instance.addObserver(this); }
  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state != AppLifecycleState.resumed) unawaited(receiver.stop());
  }
  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    unawaited(receiver.dispose());
    super.dispose();
  }
  Future<void> start() async {
    setState(() { starting = true; failed = false; });
    try { await receiver.start(approved: approved); }
    catch (_) { if (mounted) setState(() => failed = true); }
    finally { if (mounted) setState(() { starting = false; approved = false; }); }
  }
  @override
  Widget build(BuildContext context) => Scaffold(
    appBar: AppBar(title: const LText('Local laboratory receiver')),
    body: StreamBuilder<void>(stream: receiver.changes, builder: (context, _) {
      final uri = receiver.endpoint;
      return ListView(padding: const EdgeInsets.all(16), children: [
        const LText('Starts an HTTP listener bound only to this device’s loopback address. Use local test clients only. It closes after two minutes or ten accepted events. No request content is retained.'),
        CheckboxListTile(value: approved, title: const LText('I approve starting the local test listener.'),
          onChanged: uri != null || starting ? null : (value) => setState(() => approved = value ?? false)),
        FilledButton(onPressed: starting || !approved || uri != null ? null : start, child: const LText('Start local listener')),
        OutlinedButton(onPressed: uri == null ? null : () => unawaited(receiver.stop()), child: const LText('Stop')),
        if (failed) const LText('Could not start the local listener.'),
        if (uri != null) ...[
          const LText('Local callback URL'),
          SelectableText(uri.toString(), textDirection: TextDirection.ltr),
        ],
        const LText('Accepted events'),
        Text(uiNumber(context, receiver.events.length)),
        for (final event in receiver.events) ListTile(title: Text(event.method), subtitle: Text(event.time.toLocal().toString())),
        const LText('This is not a remotely reachable OAST or DNS service. Events do not prove which application generated them.'),
      ]);
    }),
  );
}
