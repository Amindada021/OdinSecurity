import 'package:flutter_test/flutter_test.dart';
import 'package:odin_security/core/assessment_queue.dart';
import 'package:odin_security/core/project.dart';
import 'package:odin_security/core/scan_policy.dart';

void main() {
  final p = SecurityProject(name: 'Fixture', url: 'https://example.test/a',
    additionalUrls: ['https://example.test/b', 'https://other.test']);
  final policy = ScanPolicy();
  test('only exact approved registered HTTPS targets are accepted', () {
    expect(() => AssessmentQueue.validate(p, policy, [p.startUrl], authorized: false), throwsStateError);
    expect(() => AssessmentQueue.validate(p, policy, [p.startUrl.resolve('/unknown')], authorized: true), throwsStateError);
    expect(() => AssessmentQueue.validate(p, ScanPolicy(excludedPaths: ['/a']), [p.startUrl], authorized: true), throwsStateError);
  });
  test('parallel mode never runs same-origin requests together and stops on a rate limit', () async {
    final started = <Uri>[];
    final active = <Uri>{};
    var overlap = false;
    final results = await AssessmentQueue.run(p, policy, p.targets, authorized: true, parallel: true,
      cancelled: () => false, wait: (_) async {}, fetch: (u) async {
        expect(active.any((a) => SecurityProject.sameOrigin(a, u)), isFalse);
        active.add(u); started.add(u);
        if (active.length == 2) overlap = true;
        await Future<void>.delayed(Duration.zero);
        active.remove(u);
        return u == p.startUrl ? 429 : 200;
      });
    expect(overlap, isTrue);
    expect(started.length, 2);
    expect(results.length, 2);
  });
  test('cancelled queue sends nothing', () async {
    final results = await AssessmentQueue.run(p, policy, p.targets, authorized: true, parallel: false,
      cancelled: () => true, fetch: (_) async => throw StateError('not called'));
    expect(results, isEmpty);
  });
}
