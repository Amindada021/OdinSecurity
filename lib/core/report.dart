import 'dart:convert';
import 'dart:typed_data';
import 'package:pdf/pdf.dart';
import 'package:pdf/widgets.dart' as pw;
import 'history.dart';

class ReportFinding {
  final String url, id, title, severity, evidence, remediation;
  const ReportFinding(this.url, this.id, this.title, this.severity, this.evidence, this.remediation);
  String get key => '$url\n$id';
}

class ReportSummary {
  final ScanRecord record;
  ReportSummary(this.record);
  static const severities = ['critical', 'high', 'medium', 'low', 'info'];
  static const limitation = 'Observations are not proof of exploitable vulnerabilities. Compare only equivalent sessions and coverage; absence is not proof of a fix. Reports may contain sensitive route names.';

  List<ReportFinding> get findings => [
    for (final page in record.pages)
      for (final item in page['observations'] as List)
        ReportFinding(page['url'] as String, item['id'] as String,
          item['title'] as String, item['severity'] as String,
          item['evidence'] as String, item['remediation'] as String),
  ];

  Map<String, int> get counts => {
    for (final severity in severities)
      severity: findings.where((f) => f.severity == severity).length,
  };

  String get overview => 'Pages: ${record.pages.length} | Observations: ${record.observationCount} | Failed: ${record.failedCount} | Cancelled: ${record.cancelled}';

  Set<String> get comparableUrls {
    final groups = <String, List<Map<String, dynamic>>>{};
    for (final page in record.pages) {
      groups.putIfAbsent(page['url'] as String, () => []).add(page);
    }
    return {
      for (final entry in groups.entries)
        if (entry.value.length == 1 &&
            (entry.value.single['statusCode'] as int) >= 200 &&
            (entry.value.single['statusCode'] as int) < 300 &&
            entry.value.single['bodyTruncated'] == false &&
            entry.value.single['redirectNotFollowed'] == false)
          entry.key,
    };
  }

  Map<String, int> get uniquePageStatuses {
    final counts = <String, int>{};
    final statuses = <String, int>{};
    for (final page in record.pages) {
      final url = page['url'] as String;
      counts.update(url, (n) => n + 1, ifAbsent: () => 1);
      statuses[url] = page['statusCode'] as int;
    }
    return {for (final entry in statuses.entries) if (counts[entry.key] == 1) entry.key: entry.value};
  }

  ReportComparison compare(ReportSummary previous) {
    final shared = comparableUrls.intersection(previous.comparableUrls);
    final current = {for (final f in findings) if (shared.contains(f.url)) f.key: f};
    final old = {for (final f in previous.findings) if (shared.contains(f.url)) f.key: f};
    final before = previous.uniquePageStatuses;
    final after = uniquePageStatuses;
    final beforeRoutes = previous.record.pages.map((p) => p['url'] as String).toSet();
    final afterRoutes = record.pages.map((p) => p['url'] as String).toSet();
    final statusChanges = [for (final entry in after.entries)
      if (before.containsKey(entry.key) && before[entry.key] != entry.value)
        PageStatusChange(entry.key, before[entry.key]!, entry.value)];
    return ReportComparison(shared.length,
      current.values.where((f) => !old.containsKey(f.key)).toList(),
      old.values.where((f) => !current.containsKey(f.key)).toList(), statusChanges: statusChanges,
      baselineOnly: beforeRoutes.difference(afterRoutes).length,
      currentOnly: afterRoutes.difference(beforeRoutes).length);
  }

  String exportHtml() {
    String esc(Object? value) => const HtmlEscape().convert(value?.toString() ?? '');
    final out = StringBuffer('''<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>Odin Security Report</title><style>body{font:16px system-ui,sans-serif;margin:2rem;max-width:1000px;color:#16232d}h1,h2{color:#08675a}article{border:1px solid #cbd5e1;padding:1rem;margin:1rem 0;overflow-wrap:anywhere}p{white-space:pre-wrap}small{color:#475569}</style></head><body><h1>Odin Security Report</h1>''');
    out.write('<p>${esc(record.finishedAt.toIso8601String())}</p><p>${esc(overview)}</p>');
    out.write('<p>${esc(limitation)}</p><h2>Severity summary</h2><ul>');
    for (final entry in counts.entries) {
      out.write('<li>${esc(entry.key)}: ${entry.value}</li>');
    }
    out.write('</ul><h2>Pages and technology observations</h2>');
    for (final page in record.pages) {
      out.write('<article><h3>${esc(page['url'])}</h3><p>HTTP ${esc(page['statusCode'])}; truncated: ${esc(page['bodyTruncated'])}; redirect not followed: ${esc(page['redirectNotFollowed'])}</p>');
      for (final tech in (page['technologies'] as List? ?? [])) {
        out.write('<p>${esc(tech['name'])} (${esc(tech['layer'])}, ${esc(tech['confidence'])}): ${esc(tech['evidence'])}</p>');
      }
      out.write('</article>');
    }
    out.write('<h2>Security observations</h2>');
    for (final f in findings) {
      out.write('<article><h3>${esc(f.severity.toUpperCase())}: ${esc(f.title)}</h3><small>${esc(f.url)} | ${esc(f.id)}</small><p>Evidence: ${esc(f.evidence)}</p><p>Remediation: ${esc(f.remediation)}</p></article>');
    }
    out.write('</body></html>');
    return out.toString();
  }

  // Fixed built-in PDF fonts are used; the HTML/JSON versions preserve Unicode.
  Future<Uint8List> exportPdf() async {
    String ascii(Object? value) => (value?.toString() ?? '').replaceAll(RegExp(r'[^\x20-\x7e]'), ' ');
    final doc = pw.Document();
    final widgets = <pw.Widget>[];
    void line(Object? value, {bool heading = false}) {
      final s = ascii(value);
      // Bound each non-spanning widget so even long URLs cannot overflow a page.
      for (var i = 0; i < s.length; i += 90) {
        final end = i + 90 < s.length ? i + 90 : s.length;
        widgets.add(pw.Padding(padding: const pw.EdgeInsets.only(bottom: 3),
          child: pw.Text(s.substring(i, end), style: pw.TextStyle(fontSize: heading ? 12 : 9,
            fontWeight: heading ? pw.FontWeight.bold : pw.FontWeight.normal))));
      }
    }
    line('Odin Security Report', heading: true);
    line(record.finishedAt.toIso8601String());
    line(overview);
    line(limitation);
    line('Severity summary', heading: true);
    line(counts.entries.map((e) => '${e.key}: ${e.value}').join(' | '));
    line('Pages and technology observations', heading: true);
    for (final page in record.pages) {
      line(page['url'], heading: true);
      line("HTTP ${page['statusCode']}; truncated: ${page['bodyTruncated']}; redirect not followed: ${page['redirectNotFollowed']}");
      for (final tech in (page['technologies'] as List? ?? [])) {
        line("${tech['name']} (${tech['layer']}, ${tech['confidence']}): ${tech['evidence']}");
      }
    }
    line('Security observations', heading: true);
    for (final f in findings) {
      line('${f.severity.toUpperCase()}: ${f.title}', heading: true);
      line(f.url);
      line('Evidence: ${f.evidence}');
      line('Remediation: ${f.remediation}');
    }
    doc.addPage(pw.MultiPage(pageFormat: PdfPageFormat.a4, maxPages: 200,
      build: (_) => widgets));
    return doc.save();
  }
}

class PageStatusChange {
  final String url;
  final int before, after;
  const PageStatusChange(this.url, this.before, this.after);
}

class ReportComparison {
  final int comparablePages;
  final List<ReportFinding> added, notObserved;
  final List<PageStatusChange> statusChanges;
  final int baselineOnly, currentOnly;
  const ReportComparison(this.comparablePages, this.added, this.notObserved,
    {this.statusChanges = const [], this.baselineOnly = 0, this.currentOnly = 0});
}
