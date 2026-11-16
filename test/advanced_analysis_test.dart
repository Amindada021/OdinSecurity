import 'package:flutter_test/flutter_test.dart';
import 'package:odin_security/core/data_analysis.dart';
import 'package:odin_security/core/project.dart';
import 'package:odin_security/core/scan_policy.dart';
import 'package:odin_security/core/traffic_filter.dart';
import 'package:odin_security/core/traffic_journal.dart';

void main() {
  test('position statistics, repetition and hex bit balance', () {
    final report = TokenSampleAnalyzer.analyze('00\n00\nff\nff');
    expect(report.adjacentDuplicates, 2);
    expect(report.hexOneBitRatio, 0.5);
    expect(report.positions.first.shannonEntropy, closeTo(1, 0.0001));
    expect(report.positions.first.empiricalMinEntropy, closeTo(1, 0.0001));
    expect(report.adjacentDifferenceRatio, closeTo(1/3, 0.0001));
  });
  test('traffic filters combine method, status and timing without payloads', () {
    final p = SecurityProject(name: 'Fixture', url: 'https://example.test');
    final log = TrafficJournal();
    log.record(p, p.startUrl.resolve('/one'), source: 'manual', method: 'GET', status: 200, elapsedMs: 50);
    log.record(p, p.startUrl.resolve('/two'), source: 'manual', method: 'GET', status: 404, elapsedMs: 200);
    log.record(p, p.startUrl.resolve('/three'), source: 'manual', method: 'HEAD', status: 404, elapsedMs: 300);
    final entries = log.forProject(p, ScanPolicy());
    final found = const TrafficFilter(method: 'GET', statusClass: 4, minElapsedMs: 100).apply(entries);
    expect(found.single.route.path, '/two');
    expect(const TrafficFilter(sort: TrafficSort.slowest).apply(entries).first.route.path, '/three');
  });
}
