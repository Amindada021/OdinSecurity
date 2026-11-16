import 'package:flutter/material.dart';
import 'core/advisory_review.dart';
import 'localized.dart';

class AdvisoryReviewScreen extends StatefulWidget {
  const AdvisoryReviewScreen({super.key});
  @override
  State<AdvisoryReviewScreen> createState() => _AdvisoryReviewScreenState();
}
class _AdvisoryReviewScreenState extends State<AdvisoryReviewScreen> {
  final catalog = TextEditingController(), product = TextEditingController(), version = TextEditingController();
  final inventory = TextEditingController();
  List<AdvisoryMatch>? matches;
  List<InventoryAdvisoryResult>? inventoryResults;
  bool bulk = false;
  bool invalid = false;
  @override
  void dispose() { catalog.dispose(); product.dispose(); version.dispose(); inventory.dispose(); super.dispose(); }
  void review() {
    try {
      final parsed = AdvisoryCatalog.parse(catalog.text);
      final result = bulk ? null : parsed.match(product.text, version.text.trim());
      final batch = bulk ? parsed.reviewInventory(inventory.text) : null;
      setState(() { matches = result; inventoryResults = batch; invalid = false; });
    } catch (_) { setState(() { matches = null; inventoryResults = null; invalid = true; }); }
  }
  void reset(String _) => setState(() { matches = null; inventoryResults = null; invalid = false; });
  @override
  Widget build(BuildContext context) => Scaffold(
    appBar: AppBar(title: const LText('Offline CVE review')),
    body: ListView(padding: const EdgeInsets.all(16), children: [
      const LText('Import your own verified advisory list and enter the known product and exact version. Matches are possible exposure, not confirmed vulnerabilities. No network requests.'),
      const SizedBox(height: 12),
      SwitchListTile(value: bulk, title: const LText('Review multiple components'), onChanged: (value) => setState(() { bulk = value; matches = null; inventoryResults = null; invalid = false; })),
      if (bulk) TextField(controller: inventory, onChanged: reset, maxLines: 5, decoration: const InputDecoration(label: LText('Component inventory JSON'), hintText: '[{"product":"fixture","version":"1.2.0"}]')),
      if (!bulk) TextField(controller: product, onChanged: reset, decoration: const InputDecoration(label: LText('Product'))),
      if (!bulk) TextField(controller: version, onChanged: reset, decoration: const InputDecoration(label: LText('Exact version'))),
      TextField(controller: catalog, onChanged: reset, maxLines: 7, autocorrect: false, enableSuggestions: false,
        decoration: const InputDecoration(label: LText('Advisory catalog JSON'), hintText: '[{"id":"CVE-2099-1234","product":"fixture","source":"https://example.test/advisory","affectedVersions":["1.2.0"]}]')),
      const LText('Optional version ranges: introduced is inclusive and fixed is exclusive. Three numeric components only. Use vendor-confirmed intervals.'),
      FilledButton(onPressed: review, child: const LText('Review advisories')),
      if (invalid) const LText('Invalid catalog or unsupported product version.'),
      if (inventoryResults != null) ...[
        for (final row in inventoryResults!) ExpansionTile(title: Text(row.product + ' ' + row.version), subtitle: Text(uiNumber(context, row.matches.length)), children: [
          if (row.matches.isEmpty) const LText('No matches in the supplied catalog.'),
          for (final m in row.matches) ListTile(title: SelectableText(m.id), subtitle: SelectableText(m.source)),
        ]),
      ],
      if (matches != null) ...[
        if (matches!.isEmpty) const LText('No matches in the supplied catalog. This does not establish safety.'),
        for (final m in matches!) ListTile(title: SelectableText(m.id), subtitle: SelectableText(m.product + '\n' + m.source)),
      ],
    ]),
  );
}
