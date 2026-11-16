import 'package:flutter_test/flutter_test.dart';
import 'package:odin_security/core/project.dart';
import 'package:odin_security/core/regression_audit.dart';
import 'package:odin_security/core/scan_policy.dart';

void main() {
  final project = SecurityProject(name: 'Fixture', url: 'https://example.test');
  final policy = ScanPolicy(excludedPaths: ['/excluded']);
  final cases = RegressionAudit.parse(project, policy, '401 https://example.test/private\n200 https://example.test/status');

  test('rejects unscoped, unsafe and duplicate cases before requests', () {
    for (final input in [
      '200 https://other.test/', '200 https://example.test/excluded',
      '200 https://example.test/?x=1', '700 https://example.test/', 
      '200 https://example.test/a\n403 https://example.test/a',
    ]) {
      expect(() => RegressionAudit.parse(project, policy, input), throwsFormatException);
    }
  });
  test('requires consent, observes status differences and waits between cases', () async {
    var calls = 0, waits = 0;
    final audit = RegressionAudit(probe: (_, _, _) async => ++calls == 1 ? 403 : 200,
      wait: (_) async { waits++; });
    await expectLater(audit.run(project, policy, cases, authorized: false, cancelled: () => false), throwsStateError);
    expect(calls, 0);
    final result = await audit.run(project, policy, cases, authorized: true, cancelled: () => false);
    expect(result.results.map((r) => r.passed), [false, true]);
    expect(waits, 1);
    expect(result.stopped, false);
  });
  test('stops on throttling, cancel, and transport error without retries', () async {
    var calls = 0;
    final audit = RegressionAudit(probe: (_, _, _) async { calls++; return 429; }, wait: (_) async {});
    final result = await audit.run(project, policy, cases, authorized: true, cancelled: () => false);
    expect(result.stopped, true);
    expect(calls, 1);
    final cancelled = await audit.run(project, policy, cases, authorized: true, cancelled: () => true);
    expect(cancelled.results, isEmpty);
    expect(calls, 1);
    final failure = RegressionAudit(probe: (_, _, _) async { throw StateError('fixture'); });
    expect((await failure.run(project, policy, cases, authorized: true, cancelled: () => false)).stopped, true);
  });
}
