import 'dart:convert';
import 'dart:typed_data';
import 'core/report_file_saver.dart';
import 'package:flutter/material.dart';
import 'localized.dart';
import 'finding_cards.dart';
import 'core/finding_explanations.dart';
import 'core/history.dart';
import 'core/report.dart';
import 'advisory_review_screen.dart';

class ReportScreen extends StatefulWidget {
  final ScanRecord record;
  final ScanRecord? previous;
  final List<ScanRecord> baselines;
  const ReportScreen({super.key, required this.record, this.previous, this.baselines = const []});
  @override
  State<ReportScreen> createState() => _ReportScreenState();
}

class _ReportScreenState extends State<ReportScreen> {
  bool saving = false;
  String filter = 'all';
  int baselineIndex = 0;
  Future<void> export(String extension, ReportSummary report) async {
    setState(() => saving = true);
    try {
      final Uint8List bytes = switch (extension) {
        'pdf' => await report.exportPdf(),
        'html' => Uint8List.fromList(utf8.encode(report.exportHtml())),
        _ => Uint8List.fromList(utf8.encode(widget.record.exportJson())),
      };
      final saved = await ReportFileSaver.save(
        fileName: 'OdinSecurity-${widget.record.finishedAt.millisecondsSinceEpoch}.$extension',
        extension: extension, bytes: bytes,
      );
      if (mounted && saved) {
        ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: LText('Report saved.')));
      }
    } catch (_) {
      if (mounted) ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: LText('Could not save report. Choose another format or location.')));
    } finally {
      if (mounted) setState(() => saving = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final report = ReportSummary(widget.record);
    final fa = Localizations.localeOf(context).languageCode == 'fa';
    final candidates = widget.record.declaredInventory();
    final baselines = widget.baselines.isNotEmpty ? widget.baselines : [if (widget.previous != null) widget.previous!];
    final previous = baselineIndex >= 0 && baselineIndex < baselines.length ? baselines[baselineIndex] : null;
    final comparison = previous == null ? null : report.compare(ReportSummary(previous));
    final visible = report.findings.where((f) => filter == 'all' || f.severity == filter);
    return Scaffold(
      appBar: AppBar(title: const LText('Security report')),
      body: ListView(padding: const EdgeInsets.all(16), children: [
        Text(widget.record.finishedAt.toLocal().toString()),
        Card(child: Padding(padding: const EdgeInsets.all(16), child: Column(
          crossAxisAlignment: CrossAxisAlignment.start, children: [
            LText('Security report', style: Theme.of(context).textTheme.titleLarge),
            const SizedBox(height: 8),
            Text('${tr(context, 'Pages checked')}: ${uiNumber(context, widget.record.pages.length)}'),
            Text('${tr(context, 'Security observations')}: ${uiNumber(context, widget.record.observationCount)}'),
            Text('${tr(context, 'Failed requests')}: ${uiNumber(context, widget.record.failedCount)}'),
            if (widget.record.cancelled) const LText('Scan stopped'),
            const SizedBox(height: 8),
            LText(ReportSummary.limitation),
          ]))),
        const SizedBox(height: 12),
        Wrap(spacing: 8, runSpacing: 8, children: [
          for (final ext in ['json', 'html', 'pdf'])
            OutlinedButton.icon(onPressed: saving ? null : () => export(ext, report),
              icon: const Icon(Icons.download), label: Text(ext.toUpperCase())),
        ]),
        if (widget.record.files.isNotEmpty)
          Card(child: ExpansionTile(leading: const Icon(Icons.folder_open),
            title: const LText('Linked files'),
            subtitle: Text('${tr(context, 'Accessible files')}: ${uiNumber(context, widget.record.files.where((f) => f['outcome'] == 'File accessible').length)} / ${uiNumber(context, widget.record.files.length)}'),
            children: [
              for (final file in widget.record.files)
                ListTile(title: SelectableText(file['url'] as String, textDirection: TextDirection.ltr),
                  subtitle: Text("${tr(context, file['outcome'] as String)}  ${(file['status'] ?? 0) == 0 ? '' : 'HTTP ${file['status']}'}\n${tr(context, 'Linked from')}: ${file['source']}")),
            ])),
        if (candidates.isNotEmpty && candidates.length <= 100)
          OutlinedButton.icon(onPressed: () => Navigator.of(context).push(MaterialPageRoute(builder: (_) => AdvisoryReviewScreen(initialInventory: const JsonEncoder.withIndent('  ').convert(candidates)))), icon: const Icon(Icons.security), label: const LText('Review declared versions against catalog')),
        if (candidates.length > 100) const LText('Too many declared components for one advisory review. Use a smaller inventory.'),
        if (saving) const LinearProgressIndicator(),
        const Divider(),
        Wrap(spacing: 8, children: [
          ChoiceChip(label: Text('${tr(context, 'All')}: ${uiNumber(context, widget.record.observationCount)}'), selected: filter == 'all', onSelected: (_) => setState(() => filter = 'all')),
          for (final level in const ['critical', 'high', 'medium', 'low', 'info'])
            ChoiceChip(avatar: Icon(Icons.circle, size: 10, color: severityColor(context, level)), label: Text('${tr(context, level)}: ${uiNumber(context, report.counts[level] ?? 0)}'), selected: filter == level, onSelected: (_) => setState(() => filter = level)),
        ]),
        if (baselines.isNotEmpty) DropdownButtonFormField<int>(initialValue: baselineIndex,
          decoration: const InputDecoration(label: LText('Comparison baseline')),
          items: [const DropdownMenuItem(value: -1, child: LText('No comparison')),
            for (var i = 0; i < baselines.length; i++) DropdownMenuItem(value: i,
              child: Text(baselines[i].finishedAt.toLocal().toString()))],
          onChanged: (value) => setState(() => baselineIndex = value ?? -1)),
        if (comparison != null) ...[
          const Divider(),
          Text('${tr(context, "Comparable pages")}: ${uiNumber(context, comparison.comparablePages)}'),
          Text('${tr(context, "Baseline-only routes")}: ${uiNumber(context, comparison.baselineOnly)} | ${tr(context, "Current-only routes")}: ${uiNumber(context, comparison.currentOnly)}'),
          const LText('Status code changes are diagnostic only; differing sessions or coverage may explain them.'),
          for (final row in comparison.statusChanges) ListTile(title: Text(row.url), subtitle: Text('HTTP ${row.before} → ${row.after}')),
          Text('Newly observed: ${comparison.added.length} | Not observed again: ${comparison.notObserved.length}'),
          for (final f in comparison.added) ListTile(title: Text('${tr(context, 'New finding')}: ${explainFinding(f.id, f.title, f.remediation, persian: fa).title}'), subtitle: Text(f.url)),
          for (final f in comparison.notObserved) ListTile(title: Text('${tr(context, 'Not observed again')}: ${explainFinding(f.id, f.title, f.remediation, persian: fa).title}'), subtitle: Text(f.url)),
        ],
        const Divider(),
        const LText('Pages and technology observations'),
        for (final page in widget.record.pages)
          ExpansionTile(title: Text(page['url'] as String), subtitle: Text("HTTP ${page['statusCode']}"),
            children: [
              if (page['bodyTruncated'] == true) const ListTile(title: LText('Response truncated')),
              if (page['redirectNotFollowed'] == true) const ListTile(title: LText('Redirect not followed')),
              for (final tech in (page['technologies'] as List? ?? []))
                TechnologyTile(name: tech['name'] as String, layer: tech['layer'] as String, confidence: tech['confidence'] as String,
                  evidence: tech['evidence'] as String, version: tech['observedVersion'] as String?),
            ]),
        const Divider(),
        const LText('Security observations'),
        if (visible.isEmpty) const LText('No matching observations. This does not establish security.'),
        for (final f in visible)
          FindingTile(id: f.id, title: f.title, severity: f.severity, evidence: f.evidence, remediation: f.remediation, url: f.url),
      ]),
    );
  }
}
