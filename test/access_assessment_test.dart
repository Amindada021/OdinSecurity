import 'package:flutter_test/flutter_test.dart';
import 'package:odin_security/core/access_assessment.dart';
import 'package:odin_security/core/auth.dart';
import 'package:odin_security/core/project.dart';
import 'package:odin_security/core/scan_policy.dart';

class FakeProbe implements AccessProbe {
  final int allowedStatus;
  int calls = 0;
  FakeProbe(this.allowedStatus);
  @override
  Future<int> status(SecurityProject project, Uri endpoint, AuthProfile identity) async { calls++; return allowedStatus; }
}

void main() {
  final project = SecurityProject(name: 'fixture', url: 'https://example.test/');
  AuthProfile identity(String name) => AuthProfile(name: name, target: project.startUrl, mode: AuthMode.bearer,
    secret: 'fixture', validationUrl: 'https://example.test/me', validationMarker: name);
  test('status comparison distinguishes expected, review and inconclusive', () {
    expect(AccessAssessmentResult.classify(200, 403), AccessOutcome.expected);
    expect(AccessAssessmentResult.classify(200, 200), AccessOutcome.unexpectedSuccess);
    expect(AccessAssessmentResult.classify(302, 200), AccessOutcome.inconclusive);
  });
  test('failed control stops before second identity', () async {
    final probe = FakeProbe(403);
    final result = await AccessAssessment(probe: probe).run(project: project, endpoint: Uri.parse('https://example.test/reports'),
      expectedAllowed: identity('admin'), expectedDenied: identity('reader'), policy: ScanPolicy(), authorized: true);
    expect(probe.calls, 1);
    expect(result.expectedDeniedStatus, 0);
  });
  test('no consent, repeated identity, and external endpoint make no requests', () async {
    final probe = FakeProbe(200);
    final check = AccessAssessment(probe: probe);
    for (final endpoint in ['https://other.test/reports', 'https://example.test/delete']) {
      await expectLater(check.run(project: project, endpoint: Uri.parse(endpoint), expectedAllowed: identity('admin'),
        expectedDenied: identity('reader'), policy: ScanPolicy(), authorized: true), throwsStateError);
    }
    await expectLater(check.run(project: project, endpoint: project.startUrl, expectedAllowed: identity('admin'),
      expectedDenied: identity('admin'), policy: ScanPolicy(), authorized: true), throwsStateError);
    await expectLater(check.run(project: project, endpoint: project.startUrl, expectedAllowed: identity('admin'),
      expectedDenied: identity('reader'), policy: ScanPolicy(), authorized: false), throwsStateError);
    expect(probe.calls, 0);
  });
}
