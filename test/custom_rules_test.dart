import 'package:flutter_test/flutter_test.dart';
import 'package:odin_security/core/custom_rules.dart';
import 'package:odin_security/core/fingerprint.dart';
import 'project_storage_test.dart' show MemoryStorage;

void main() {
  test('validates literal allowlisted rules without capturing header values', () {
    final rules = CustomHeaderRules.parse('x-content-type-options|contains|nosniff\nstrict-transport-security|present');
    final results = CustomHeaderRules.inspect(rules, HttpObservation(headers: {'X-Content-Type-Options': ['NoSniff']}, body: ''));
    expect(results.single.id, 'custom.strict-transport-security.present');
    expect(results.single.evidence, contains('values omitted'));
    expect(CustomHeaderRules.inspect(rules, HttpObservation(headers: {
      'X-Content-Type-Options': ['nosniff'], 'strict-transport-security': ['max-age=123']
    }, body: '')), isEmpty);
  });
  test('rejects sensitive headers, duplicates, unsupported modes', () {
    for (final input in [
      'authorization|present', 'set-cookie|present', 'x-frame-options|regex|.*',
      'x-frame-options|contains|', 'cache-control|present\ncache-control|present',
    ]) {
      expect(() => CustomHeaderRules.parse(input), throwsFormatException);
    }
  });
  test('rules persist per project; invalid save preserves prior configuration', () async {
    final repo = CustomRuleRepository(MemoryStorage());
    await repo.save('a', 'cache-control|contains|no-store');
    expect((await repo.load('a')).single.line, 'cache-control|contains|no-store');
    expect(await repo.load('b'), isEmpty);
    await expectLater(repo.save('a', 'cookie|present'), throwsFormatException);
    expect((await repo.load('a')).single.header, 'cache-control');
  });
}
