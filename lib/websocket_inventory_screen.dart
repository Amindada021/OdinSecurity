import 'package:flutter/material.dart';
import 'core/project.dart';
import 'core/scan_policy.dart';
import 'core/websocket_inventory.dart';
import 'localized.dart';

class WebSocketInventoryScreen extends StatefulWidget {
  final SecurityProject project;
  final ScanPolicy policy;
  const WebSocketInventoryScreen({super.key, required this.project, required this.policy});
  @override
  State<WebSocketInventoryScreen> createState() => _WebSocketInventoryScreenState();
}

class _WebSocketInventoryScreenState extends State<WebSocketInventoryScreen> {
  final source = TextEditingController();
  List<WebSocketObservation>? results;
  bool invalid = false;
  @override
  void dispose() { source.dispose(); super.dispose(); }

  void parse() {
    try {
      final found = WebSocketInventory.parse(widget.project, widget.policy, source.text);
      source.clear();
      setState(() { results = found; invalid = false; });
    } catch (_) {
      setState(() { results = null; invalid = true; });
    }
  }

  @override
  Widget build(BuildContext context) => Scaffold(
    appBar: AppBar(title: const LText('WebSocket traffic inventory')),
    body: ListView(padding: const EdgeInsets.all(16), children: [
      const LText('Import sanitized HAR JSON. Only scoped handshake routes, status and optional frame direction counts are retained. No live connection or message replay.'),
      TextField(controller: source, maxLines: 6, autocorrect: false, enableSuggestions: false,
        decoration: const InputDecoration(hintText: 'HAR JSON')),
      FilledButton(onPressed: parse, child: const LText('Import')),
      if (invalid) const LText('Invalid or oversized WebSocket capture.'),
      if (results != null) ...[
        Text(uiNumber(context, results!.length)),
        for (final row in results!) Card(child: Padding(padding: const EdgeInsets.all(12), child: Column(
          crossAxisAlignment: CrossAxisAlignment.start, children: [
            SelectableText(row.url.toString(), textDirection: TextDirection.ltr),
            Text('HTTP ${row.handshakeStatus ?? "?"}'),
            if (row.framesAvailable) ...[
              Text('${tr(context, "Sent frames")}: ${uiNumber(context, row.sent)}'),
              Text('${tr(context, "Received frames")}: ${uiNumber(context, row.received)}'),
              Text('${tr(context, "Unknown direction")}: ${uiNumber(context, row.unknown)}'),
            ] else const LText('Frame metadata unavailable in this capture.'),
          ],
        ))),
      ],
    ]),
  );
}
