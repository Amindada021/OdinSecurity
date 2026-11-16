import 'package:flutter_test/flutter_test.dart';
import 'package:odin_security/core/history.dart';
import 'package:odin_security/core/report.dart';

Map<String, dynamic> page(String url, List<String> ids, {int status = 200, bool truncated = false}) => {
  'url': url, 'statusCode': status, 'bodyTruncated': truncated, 'redirectNotFollowed': false,
  'technologies': [],
  'observations': [for (final id in ids) {'id': id, 'title': '<script>$id</script>', 'severity': 'low',
    'evidence': 'Test & evidence', 'remediation': 'Review'}],
};

ScanRecord record(List<Map<String, dynamic>> pages) => ScanRecord(
  finishedAt: DateTime.utc(2026, 1, 1), failedCount: 0, cancelled: false, pages: pages);

void main() {
  test('severity totals and HTML encoding', () {
    final report = ReportSummary(record([page('https://example.test', ['a'])]));
    expect(report.counts['low'], 1);
    expect(report.counts['critical'], 0);
    final html = report.exportHtml();
    expect(html, contains('&lt;script&gt;a&lt;'));
    expect(html, isNot(contains('<script>')));
    expect(html, contains('Test &amp; evidence'));
  });
  test('compare shared successfully scanned pages only', () {
    final old = ReportSummary(record([page('https://example.test/a', ['old']), page('https://example.test/b', ['skip'])]));
    final current = ReportSummary(record([page('https://example.test/a', ['new']), page('https://example.test/b', [], status: 403)]));
    final diff = current.compare(old);
    expect(diff.comparablePages, 1);
    expect(diff.added.map((f) => f.id), ['new']);
    expect(diff.notObserved.map((f) => f.id), ['old']);
  });
  test('truncated and duplicate routes cannot establish comparable coverage', () {
    final a = 'https://example.test/a';
    final b = 'https://example.test/b';
    final old = ReportSummary(record([page(a, ['old']), page(b, ['old'])]));
    final current = ReportSummary(record([page(a, [], truncated: true), page(b, []), page(b, [])]));
    expect(current.compare(old).comparablePages, 0);
  });
  test('PDF encodes a document without network access', () async {
    final bytes = await ReportSummary(record([page('https://example.test', ['a'])])).exportPdf();
    expect(String.fromCharCodes(bytes.take(5)), '%PDF-');
  });
}
