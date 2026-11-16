import 'package:flutter/material.dart';
import 'localized.dart';
import 'core/openapi_inventory.dart';
import 'core/offline_tools.dart';

class InventoryScreen extends StatefulWidget {
  const InventoryScreen({super.key});
  @override
  State<InventoryScreen> createState() => _InventoryScreenState();
}

class _InventoryScreenState extends State<InventoryScreen> {
  final source = TextEditingController();
  List<ApiOperation> operations = [];
  String? error;
  @override
  void dispose() { source.dispose(); super.dispose(); }

  void parse() {
    try {
      final result = OpenApiInventory().parse(source.text);
      setState(() { operations = result; error = null; });
    } catch (_) {
      setState(() { operations = []; error = 'Invalid or unsupported OpenAPI JSON.'; });
    }
  }
  @override
  Widget build(BuildContext context) => Scaffold(
    appBar: AppBar(title: const LText('OpenAPI inventory')),
    body: ListView(padding: const EdgeInsets.all(16), children: [
      const LText('Paste Swagger 2.0 or OpenAPI 3.x JSON. Import is offline and does not call endpoints.'),
      const SizedBox(height: 8),
      TextField(controller: source, maxLines: 6, decoration: const InputDecoration(border: OutlineInputBorder(), hintText: 'OpenAPI JSON')),
      const SizedBox(height: 8),
      FilledButton(onPressed: parse, child: const LText('Import')),
      if (error != null) LText(error!),
      Text('${operations.length} operations'),
      for (final operation in operations) ListTile(
        leading: Text(operation.method), title: Text(operation.path), subtitle: operation.title.isEmpty ? null : Text(operation.title)),
    ]),
  );
}

class OfflineToolsScreen extends StatefulWidget {
  const OfflineToolsScreen({super.key});
  @override
  State<OfflineToolsScreen> createState() => _OfflineToolsScreenState();
}
class _OfflineToolsScreenState extends State<OfflineToolsScreen> {
  final source = TextEditingController();
  String mode = 'Base64 encode';
  String output = '';
  final operations = <String, String Function(String)>{
    'Base64 encode': OfflineTools.encodeBase64, 'Base64 decode': OfflineTools.decodeBase64,
    'URL encode': OfflineTools.encodeUrl, 'URL decode': OfflineTools.decodeUrl,
    'Format JSON': OfflineTools.formatJson, 'Inspect JWT (unverified)': OfflineTools.inspectJwt,
  };
  @override
  void dispose() { source.dispose(); super.dispose(); }
  @override
  Widget build(BuildContext context) => Scaffold(
    appBar: AppBar(title: const LText('Offline utilities')),
    body: ListView(padding: const EdgeInsets.all(16), children: [
      DropdownButtonFormField<String>(initialValue: mode, items: operations.keys.map((op) => DropdownMenuItem(value: op, child: LText(op))).toList(),
        onChanged: (value) => setState(() { mode = value!; output = ''; })),
      TextField(controller: source, maxLines: 5, autocorrect: false, enableSuggestions: false, decoration: const InputDecoration(label: LText('Input (local only)'))),
      FilledButton(onPressed: () {
        try {
          if (source.text.length > 1024 * 1024) throw const FormatException();
          final result = operations[mode]!(source.text);
          setState(() => output = result);
        } catch (_) {
          setState(() => output = 'Invalid input.');
        }
      }, child: const LText('Convert')),
      if (mode.startsWith('Inspect JWT')) const LText('Decoded JWT claims are not verified and must not be trusted.'),
      const SizedBox(height: 16),
      SelectableText(output),
    ]),
  );
}
