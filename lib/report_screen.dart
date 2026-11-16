import 'dart:convert';
import 'dart:typed_data';
import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'localized.dart';
import 'core/history.dart';
import 'core/report.dart';

class ReportScreen extends StatefulWidget {
  final ScanRecord record;
  final ScanRecord? previous;
  const ReportScreen({super.key, required this.record, this.previous});
  @override
  State<ReportScreen> createState() => _ReportScreenState();
}

class _ReportScreenState extends State<ReportScreen> {
  bool saving = false;
  String filter = 'all';
  Future<void> export(String extension, ReportSummary report) async {
    setState(() => saving = true);
    try {
      final Uint8List bytes = switch (extension) {
        'pdf' => await report.exportPdf(),
        'html' => Uint8List.fromList(utf8.encode(report.exportHtml())),
        _ => Uint8List.fromList(utf8.encode(widget.record.exportJson())),
      };
      final path = await FilePicker.platform.saveFile(
        fileName: 'OdinSecurity-${widget.record.finishedAt.millisecondsSinceEpoch}.$extension',
        bytes: bytes, type: FileType.custom, allowedExtensions: [extension],
      );
      if (mounted && path != null) {
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
    final previous = widget.previous;
    final comparison = previous == null ? null : report.compare(ReportSummary(previous));
    final visible = report.findings.where((f) => filter == 'all' || f.severity == filter);
    return Scaffold(
      appBar: AppBar(title: const LText('Security report')),
      body: ListView(padding: const EdgeInsets.all(16), children: [
        Text(widget.record.finishedAt.toLocal().toString()),
        Text(report.overview),
        const Text(ReportSummary.limitation),
        const SizedBox(height: 12),
        Wrap(spacing: 8, runSpacing: 8, children: [
          for (final ext in ['json', 'html', 'pdf'])
            OutlinedButton.icon(onPressed: saving ? null : () => export(ext, report),
              icon: const Icon(Icons.download), label: Text(ext.toUpperCase())),
        ]),
        if (saving) const LinearProgressIndicator(),
        const Divider(),
        Wrap(spacing: 8, children: [
          ChoiceChip(label: Text('All: ${widget.record.observationCount}'), selected: filter == 'all', onSelected: (_) => setState(() => filter = 'all')),
          for (final entry in report.counts.entries)
            ChoiceChip(label: Text('${entry.key}: ${entry.value}'), selected: filter == entry.key, onSelected: (_) => setState(() => filter = entry.key)),
        ]),
        if (comparison != null) ...[
          const Divider(),
          Text('Compared with previous scan: ${comparison.comparablePages} comparable pages'),
          Text('Newly observed: ${comparison.added.length} | Not observed again: ${comparison.notObserved.length}'),
          for (final f in comparison.added) ListTile(title: Text('New: ${f.title}'), subtitle: Text(f.url)),
          for (final f in comparison.notObserved) ListTile(title: Text('Not observed again: ${f.title}'), subtitle: Text(f.url)),
        ],
        const Divider(),
        const LText('Pages and technology observations'),
        for (final page in widget.record.pages)
          ExpansionTile(title: Text(page['url'] as String), subtitle: Text("HTTP ${page['statusCode']}"),
            children: [
              if (page['bodyTruncated'] == true) const ListTile(title: LText('Response truncated')),
              if (page['redirectNotFollowed'] == true) const ListTile(title: LText('Redirect not followed')),
              for (final tech in (page['technologies'] as List? ?? []))
                ListTile(title: Text(tech['name'] as String), subtitle: Text("${tech['layer']} / ${tech['confidence']}\n${tech['evidence']}")),
            ]),
        const Divider(),
        const LText('Security observations'),
        if (visible.isEmpty) const LText('No matching observations. This does not establish security.'),
        for (final f in visible)
          ExpansionTile(title: Text(f.title), subtitle: Text('${f.severity} | ${f.url}'),
            children: [ListTile(title: const LText('Evidence'), subtitle: SelectableText(f.evidence)),
              ListTile(title: const LText('Remediation'), subtitle: SelectableText(f.remediation))]),
      ]),
    );
  }
}
