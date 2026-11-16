import 'dart:async';
import 'dart:io';
import 'package:flutter/material.dart';

import 'core/auth.dart';
import 'core/live_websocket.dart';
import 'core/project.dart';
import 'core/scan_policy.dart';
import 'localized.dart';

class LiveWebSocketScreen extends StatefulWidget {
  final SecurityProject project;
  final ScanPolicy policy;
  final Uri target;
  final AuthProfile? auth;
  const LiveWebSocketScreen({super.key, required this.project, required this.policy, required this.target, this.auth});

  @override
  State<LiveWebSocketScreen> createState() => _LiveWebSocketScreenState();
}

class _LiveWebSocketScreenState extends State<LiveWebSocketScreen> {
  final url = TextEditingController();
  final messages = <SocketMessageMetadata>[];
  WebSocket? socket;
  StreamSubscription<dynamic>? subscription;
  Timer? timer;
  bool approved = false, connecting = false, connected = false, useAuth = false, preview = false;
  int generation = 0, bytes = 0;
  String status = 'Disconnected';
  String? lastPreview;

  bool get busy => connecting || connected;

  @override
  void initState() {
    super.initState();
    url.text = widget.target.scheme == 'https' ? widget.target.replace(scheme: 'wss').toString() : '';
  }

  Future<void> closeSocket(WebSocket? value) async {
    if (value == null) return;
    try { await value.close().timeout(const Duration(seconds: 5)); } catch (_) { /* Do not retain transport details. */ }
  }

  void stop([String reason = 'Disconnected']) {
    generation++;
    timer?.cancel();
    timer = null;
    final sub = subscription;
    subscription = null;
    if (sub != null) unawaited(sub.cancel());
    final active = socket;
    socket = null;
    unawaited(closeSocket(active));
    if (mounted) setState(() { connecting = false; connected = false; approved = false; status = reason; });
  }

  Future<void> connect() async {
    if (!approved || busy) return;
    final attempt = ++generation;
    final identity = useAuth ? widget.auth : null;
    setState(() { connecting = true; approved = false; bytes = 0; messages.clear(); lastPreview = null; status = 'Connecting'; });
    try {
      final target = Uri.parse(url.text.trim());
      final active = await LiveWebSocket().connect(widget.project, widget.policy, target,
        authorized: true, auth: identity);
      if (!mounted || generation != attempt) { await closeSocket(active); return; }
      socket = active;
      setState(() { connecting = false; connected = true; status = 'Connected'; });
      timer = Timer(LiveWebSocket.sessionDuration, () => stop('Session limit reached'));
      subscription = active.listen((dynamic value) {
        if (!mounted || generation != attempt) return;
        final info = SocketMessageMetadata.fromMessage(value, includePreview: preview);
        setState(() {
          bytes += info.bytes;
          // Keep message metadata only; the optional latest text preview is separate.
          messages.insert(0, SocketMessageMetadata(info.text, info.bytes, null));
          lastPreview = info.preview;
        });
        if (messages.length >= LiveWebSocket.maxMessages || bytes >= LiveWebSocket.maxObservedBytes) {
          stop('Session limit reached');
        }
      }, onDone: () { if (mounted && generation == attempt) stop(); },
        onError: (Object _) { if (mounted && generation == attempt) stop('Connection failed'); },
        cancelOnError: true);
    } catch (_) {
      if (mounted && generation == attempt) stop('Connection failed');
    }
  }

  @override
  void dispose() {
    generation++;
    timer?.cancel();
    final sub = subscription;
    if (sub != null) unawaited(sub.cancel());
    unawaited(closeSocket(socket));
    url.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => Scaffold(
    appBar: AppBar(title: const LText('Live WebSocket')),
    body: ListView(padding: const EdgeInsets.all(16), children: [
      const LText('Connect to an authorized WSS test endpoint. Receive only; no application messages are sent.'),
      TextField(controller: url, enabled: !busy, keyboardType: TextInputType.url,
        textDirection: TextDirection.ltr, decoration: const InputDecoration(label: LText('WebSocket URL')),
        onChanged: (_) => setState(() => approved = false)),
      if (widget.auth != null && !widget.auth!.isLogin)
        CheckboxListTile(value: useAuth, title: const LText('Use saved credentials for their exact origin'),
          onChanged: busy ? null : (v) => setState(() { useAuth = v ?? false; approved = false; })),
      CheckboxListTile(value: preview, title: const LText('Show latest text message (up to 4 KiB, in memory only)'),
        onChanged: busy ? null : (v) => setState(() { preview = v ?? false; approved = false; lastPreview = null; })),
      CheckboxListTile(value: approved, title: const LText('I authorize this exact request.'),
        onChanged: busy ? null : (v) => setState(() => approved = v ?? false)),
      FilledButton(onPressed: busy || !approved ? null : connect, child: const LText('Connect')),
      OutlinedButton(onPressed: busy ? () => stop() : null, child: const LText('Disconnect')),
      if (connecting) const LinearProgressIndicator(),
      LText(status),
      Text('${uiNumber(context, messages.length)} | ${uiNumber(context, bytes)} bytes'),
      const LText('Session stops after 45 seconds, 100 messages or 256 KiB observed. Individual messages are buffered by the Dart SDK before counting.'),
      if (lastPreview != null) ...[
        const LText('Latest text message'),
        SelectableText(lastPreview!, textDirection: TextDirection.ltr),
      ],
      for (final message in messages)
        ListTile(dense: true, title: LText(message.text ? 'Text message' : 'Binary message'),
          trailing: Text('${uiNumber(context, message.bytes)} B')),
      TextButton(onPressed: busy ? null : () => setState(() { messages.clear(); bytes = 0; lastPreview = null; }),
        child: const LText('Clear')),
    ]),
  );
}
