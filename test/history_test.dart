import 'package:flutter_test/flutter_test.dart';
import 'package:odin_security/core/history.dart';
import 'package:odin_security/core/passive_scan.dart';
import 'package:odin_security/core/security_checks.dart';
import 'project_storage_test.dart' show MemoryStorage;

void main() {
  test('report preserves findings and is round-trippable', () async {
    final record = ScanRecord.fromPages([
      PassiveScanResult(url: Uri.parse('https://example.test/?token=fixture'), statusCode: 200,
        links: [], technologies: [], bodyTruncated: false, redirectNotFollowed: false,
        findings: [const SecurityFinding('test', 'Example', Severity.info, 'Evidence', 'Fix')]),
    ]);
    final repo = HistoryRepository(MemoryStorage());
    await repo.append('project', record);
    final restored = (await repo.load('project')).single;
    expect(restored.observationCount, 1);
    expect(restored.exportJson(), contains('Evidence'));
    expect(restored.exportJson(), isNot(contains('token=fixture')));
  });
  test('history is bounded and project isolated', () async {
    final repo = HistoryRepository(MemoryStorage());
    for (var i = 0; i < 22; i++) { await repo.append('a', ScanRecord.fromPages([])); }
    expect((await repo.load('a')).length, 20);
    expect(await repo.load('b'), isEmpty);
  });
}
