import 'package:flutter_test/flutter_test.dart';
import 'package:odin_security/core/project.dart';
import 'package:odin_security/core/scan_policy.dart';
import 'package:odin_security/core/traffic_journal.dart';

void main() {
  test('log excludes query values and other projects, reapplies current exclusions', () {
    final journal = TrafficJournal();
    final project = SecurityProject(name: 'Fixture', url: 'https://example.test');
    final other = SecurityProject(name: 'Other', url: 'https://example.test');
    journal.record(project, Uri.parse('https://example.test/report?token=secret'), source: 'manual', method: 'GET', elapsedMs: 10, status: 200);
    journal.record(project, Uri.parse('https://outside.test/'), source: 'manual', method: 'GET', elapsedMs: 1);
    expect(journal.forProject(project, ScanPolicy()).single.route.toString(), 'https://example.test/report');
    expect(journal.forProject(project, ScanPolicy()).single.hadQuery, isTrue);
    expect(journal.forProject(other, ScanPolicy()), isEmpty);
    expect(journal.forProject(project, ScanPolicy(excludedPaths: ['/report'])), isEmpty);
  });
  test('session journal is bounded and clears project only', () {
    final journal = TrafficJournal();
    final project = SecurityProject(name: 'Fixture', url: 'https://example.test');
    for (var i = 0; i < 250; i++) {
      journal.record(project, project.startUrl, source: 'passive', method: 'GET', elapsedMs: i);
    }
    expect(journal.forProject(project, ScanPolicy()).length, TrafficJournal.limit);
    expect(journal.forProject(project, ScanPolicy()).first.elapsedMs, 249);
    journal.clear(project.id);
    expect(journal.forProject(project, ScanPolicy()), isEmpty);
  });
}
