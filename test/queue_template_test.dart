import 'package:flutter_test/flutter_test.dart';
import 'package:odin_security/core/auth.dart';
import 'package:odin_security/core/project.dart';
import 'package:odin_security/core/scan_policy.dart';
import 'package:odin_security/core/queue_template.dart';
import 'package:odin_security/core/assessment_queue.dart';

void main() {
  final p = SecurityProject(name: 'Fixture', url: 'https://example.test/a', additionalUrls: ['https://other.test/b']);
  final policy = ScanPolicy();
  test('template has no credentials or authorization and revalidates scope', () {
    final saved = QueueTemplate(p, policy, p.targets, true, 5);
    expect(saved.toJson().keys.toSet(), {'targets', 'parallel', 'minutes'});
    expect(QueueTemplate.fromJson(p, policy, saved.toJson()).targets, p.targets);
    expect(() => QueueTemplate.fromJson(p, ScanPolicy(excludedPaths: ['/a']), saved.toJson()), throwsStateError);
    expect(() => QueueTemplate(p, policy, p.targets, true, 2), throwsFormatException);
  });
  test('static identity must match target and exact name', () {
    final identity = AuthProfile(mode: AuthMode.bearer, target: p.startUrl, name: 'test', secret: 'fixture');
    final login = AuthProfile(mode: AuthMode.formLogin, target: p.startUrl, name: 'login', secret: 'fixture', loginUrl: 'https://example.test/login');
    expect(QueueIdentity.eligible(p.startUrl, [identity, login]), [identity]);
    expect(QueueIdentity.resolve(p.startUrl, 'test', [identity]), identity);
    expect(() => QueueIdentity.resolve(p.targets.last, 'test', [identity]), throwsStateError);
    expect(() => QueueIdentity.resolve(p.startUrl, 'missing', [identity]), throwsStateError);
  });
  test('authenticated rejection stops later queue work', () async {
    final results = await AssessmentQueue.run(p, policy, p.targets, authorized: true, parallel: false,
      cancelled: () => false, authenticated: (_) => true, fetch: (_) async => 401);
    expect(results, hasLength(1));
  });
}
