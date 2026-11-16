import 'package:flutter_test/flutter_test.dart';
import 'package:odin_security/core/crawl_checkpoint.dart';
import 'package:odin_security/core/project.dart';
import 'package:odin_security/core/scan_policy.dart';

void main() {
  final project = SecurityProject(name: 'Fixture', url: 'https://example.test');
  final start = project.startUrl, next = project.startUrl.resolve('/next');
  test('roundtrip keeps only eligible routes and attempted count', () {
    final record = CrawlCheckpoint(start, '', [start, next], [next], 1);
    final restored = CrawlCheckpoint.fromJson(record.toJson());
    expect(restored.pending, [next]);
    expect(restored.attempted, 1);
    expect(() => restored.validate(project, ScanPolicy(), start, ''), returnsNormally);
    expect(() => restored.validate(project, ScanPolicy(), start, 'different'), throwsStateError);
    expect(() => restored.validate(project, ScanPolicy(excludedPaths: ['/next']), start, ''), throwsStateError);
    expect(() => restored.validate(project, ScanPolicy(maxPages: 1), start, ''), throwsStateError);
  });
  test('out-of-scope and query-bearing checkpoint entries are refused', () {
    for (final bad in [Uri.parse('https://other.test'), start.resolve('/next?q=private')]) {
      expect(() => CrawlCheckpoint(start, '', [start, bad], [bad], 1), throwsFormatException);
    }
  });
}
