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
  List<AdvisoryMatch>? matches;
  bool invalid = false;
  @override
  void dispose() { catalog.dispose(); product.dispose(); version.dispose(); super.dispose(); }
  void review() {
    try {
      final result = AdvisoryCatalog.parse(catalog.text).match(product.text, version.text.trim());
      setState(() { matches = result; invalid = false; });
    } catch (_) { setState(() { matches = null; invalid = true; }); }
  }
  void reset(String _) => setState(() { matches = null; invalid = false; });
  @override
  Widget build(BuildContext context) => Scaffold(
    appBar: AppBar(title: const LText('Offline CVE review')),
    body: ListView(padding: const EdgeInsets.all(16), children: [
      const LText('Import your own verified advisory list and enter the known product and exact version. Matches are possible exposure, not confirmed vulnerabilities. No network requests.'),
      const SizedBox(height: 12),
      TextField(controller: product, onChanged: reset, decoration: const InputDecoration(label: LText('Product'))),
      TextField(controller: version, onChanged: reset, decoration: const InputDecoration(label: LText('Exact version'))),
      TextField(controller: catalog, onChanged: reset, maxLines: 7, autocorrect: false, enableSuggestions: false,
        decoration: const InputDecoration(label: LText('Advisory catalog JSON'), hintText: '[{"id":"CVE-2099-1234","product":"fixture","source":"https://example.test/advisory","affectedVersions":["1.2.0"]}]')),
      FilledButton(onPressed: review, child: const LText('Review advisories')),
      if (invalid) const LText('Invalid catalog or unsupported product version.'),
      if (matches != null) ...[
        if (matches!.isEmpty) const LText('No exact matches in this catalog. This does not establish safety.'),
        for (final m in matches!) ListTile(title: SelectableText(m.id), subtitle: SelectableText(m.product + '\n' + m.source)),
      ],
    ]),
  );
}
