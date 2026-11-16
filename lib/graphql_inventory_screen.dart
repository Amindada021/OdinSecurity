import 'package:flutter/material.dart';
import 'core/graphql_inventory.dart';
import 'localized.dart';

class GraphQlInventoryScreen extends StatefulWidget {
  const GraphQlInventoryScreen({super.key});
  @override
  State<GraphQlInventoryScreen> createState() => _GraphQlInventoryScreenState();
}

class _GraphQlInventoryScreenState extends State<GraphQlInventoryScreen> {
  final source = TextEditingController();
  List<GraphQlField>? fields;
  GraphQlOperation? filter;
  bool invalid = false;

  @override
  void dispose() { source.dispose(); super.dispose(); }

  void parse() {
    try {
      final result = GraphQlInventory.parse(source.text);
      source.clear();
      setState(() { fields = result; invalid = false; filter = null; });
    } catch (_) {
      setState(() { fields = null; invalid = true; });
    }
  }

  @override
  Widget build(BuildContext context) => Scaffold(
    appBar: AppBar(title: const LText('GraphQL inventory')),
    body: ListView(padding: const EdgeInsets.all(16), children: [
      const LText('Paste a sanitized GraphQL introspection JSON response. Import is offline; no queries or mutations are sent.'),
      TextField(controller: source, maxLines: 6, autocorrect: false, enableSuggestions: false,
        decoration: const InputDecoration(border: OutlineInputBorder(), hintText: 'GraphQL JSON')),
      FilledButton(onPressed: parse, child: const LText('Import')),
      if (invalid) const LText('Invalid or oversized GraphQL schema.'),
      if (fields != null) ...[
        Wrap(spacing: 8, children: [
          ChoiceChip(label: const LText('All'), selected: filter == null, onSelected: (_) => setState(() => filter = null)),
          for (final operation in GraphQlOperation.values)
            ChoiceChip(label: Text(operation.name), selected: filter == operation, onSelected: (_) => setState(() => filter = operation)),
        ]),
        Text(uiNumber(context, fields!.where((field) => filter == null || filter == field.operation).length)),
        for (final field in fields!.where((field) => filter == null || filter == field.operation))
          ListTile(leading: Text(field.operation.name), title: SelectableText('${field.rootType}.${field.name}'),
            trailing: Text(uiNumber(context, field.argumentCount)), subtitle: const LText('Argument count')),
      ],
    ]),
  );
}
