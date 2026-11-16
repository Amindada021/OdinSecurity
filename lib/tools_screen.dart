import 'package:flutter/material.dart';
import 'localized.dart';
import 'data_analysis_screen.dart';
import 'advisory_review_screen.dart';
import 'test_fixtures_screen.dart';
import 'graphql_inventory_screen.dart';
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
  ApiSecurityDeclaration? filter;
  String? error;
  @override
  void dispose() { source.dispose(); super.dispose(); }

  void parse() {
    try {
      final result = OpenApiInventory().parse(source.text);
      source.clear();
      setState(() { operations = result; filter = null; error = null; });
    } catch (_) {
      setState(() { operations = []; filter = null; error = 'Invalid or unsupported OpenAPI JSON.'; });
    }
  }
  String securityLabel(ApiSecurityDeclaration security) => switch (security) {
    ApiSecurityDeclaration.unspecified => 'Security not declared',
    ApiSecurityDeclaration.anonymousAllowed => 'Anonymous allowed by specification',
    ApiSecurityDeclaration.authRequired => 'Security required by specification',
    ApiSecurityDeclaration.invalid => 'Invalid or unknown security declaration',
  };

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
      Text('${uiNumber(context, operations.length)} ${tr(context, 'Operations')}'),
      if (operations.isNotEmpty) ...[
        const LText('Security declarations describe the API contract only. They do not establish the actual runtime authorization.'),
        for (final kind in ApiSecurityDeclaration.values)
          Text('${tr(context, securityLabel(kind))}: ${uiNumber(context, operations.where((op) => op.security == kind).length)}'),
        Text('${tr(context, 'HTTP server declared')}: ${uiNumber(context, operations.where((op) => op.httpDeclared).length)}'),
        DropdownButtonFormField<ApiSecurityDeclaration>(key: ValueKey(filter), initialValue: filter,
          hint: const LText('All operations'),
          decoration: const InputDecoration(label: LText('Filter by security declaration')),
          items: [
            const DropdownMenuItem<ApiSecurityDeclaration>(value: null, child: LText('All operations')),
            for (final kind in ApiSecurityDeclaration.values) DropdownMenuItem(value: kind, child: LText(securityLabel(kind))),
          ], onChanged: (value) => setState(() => filter = value)),
      ],
      for (final operation in operations.where((op) => filter == null || op.security == filter)) ListTile(
        leading: Text(operation.method), title: Text(operation.path), subtitle: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          if (operation.title.isNotEmpty) Text(operation.title),
          LText(securityLabel(operation.security)),
          if (operation.httpDeclared) const LText('HTTP server declared'),
          if (operation.security == ApiSecurityDeclaration.authRequired && !operation.authErrorDocumented)
            const LText('No 401/403 response documented'),
        ])),
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
    'Hex encode': OfflineTools.encodeHex, 'Hex decode': OfflineTools.decodeHex, 'HTML escape': OfflineTools.encodeHtml,
    'Format JSON': OfflineTools.formatJson, 'Inspect JWT (unverified)': OfflineTools.inspectJwt,
  };
  @override
  void dispose() { source.dispose(); super.dispose(); }
  @override
  Widget build(BuildContext context) => Scaffold(
    appBar: AppBar(title: const LText('Offline utilities')),
    body: ListView(padding: const EdgeInsets.all(16), children: [
      OutlinedButton.icon(onPressed: () => Navigator.of(context).push(MaterialPageRoute(builder: (_) => const TestFixturesScreen())), icon: const Icon(Icons.science_outlined), label: const LText('Offline test fixtures')),
      OutlinedButton.icon(onPressed: () => Navigator.of(context).push(MaterialPageRoute(builder: (_) => const AdvisoryReviewScreen())), icon: const Icon(Icons.security), label: const LText('Offline CVE review')),
      OutlinedButton.icon(onPressed: () => Navigator.of(context).push(MaterialPageRoute(builder: (_) => const GraphQlInventoryScreen())), icon: const Icon(Icons.account_tree_outlined), label: const LText('GraphQL inventory')),
      OutlinedButton.icon(onPressed: () => Navigator.of(context).push(MaterialPageRoute(builder: (_) => const ComparerScreen())), icon: const Icon(Icons.compare_arrows), label: const LText('Message comparer')),
      OutlinedButton.icon(onPressed: () => Navigator.of(context).push(MaterialPageRoute(builder: (_) => const TokenSamplesScreen())), icon: const Icon(Icons.analytics_outlined), label: const LText('Token sample analysis')),
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
