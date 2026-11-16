import 'package:flutter_test/flutter_test.dart';
import 'package:odin_security/core/cors_audit.dart';
import 'package:odin_security/core/project.dart';
import 'package:odin_security/core/scan_policy.dart';

class FixtureProbe implements CorsProbe {
  int calls = 0;
  @override
  Future<CorsMetadata> inspect(Uri endpoint) async {
    calls++;
    return const CorsMetadata(204, [CorsAudit.testOrigin], ['true'], ['GET']);
  }
}

void main() {
  test('classify preflight evidence without claiming exploitability', () {
    expect(CorsAuditResult.classify(const CorsMetadata(204, [CorsAudit.testOrigin], ['true'], ['GET'])).outcome, CorsOutcome.testOriginWithCredentials);
    expect(CorsAuditResult.classify(const CorsMetadata(200, ['*'], [], ['GET'])).outcome, CorsOutcome.wildcard);
    expect(CorsAuditResult.classify(const CorsMetadata(200, ['https://trusted.example'], [], [])).outcome, CorsOutcome.notAdvertised);
    expect(CorsAuditResult.classify(const CorsMetadata(302, [CorsAudit.testOrigin], ['true'], [])).outcome, CorsOutcome.inconclusive);
    expect(CorsAuditResult.classify(const CorsMetadata(200, ['*', CorsAudit.testOrigin], [], [])).outcome, CorsOutcome.inconclusive);
  });
  test('one probe only after scope, authorization and exclusion validation', () async {
    final project = SecurityProject(name: 'Fixture', url: 'https://example.test');
    final probe = FixtureProbe();
    final audit = CorsAudit(probe: probe);
    final policy = ScanPolicy(excludedPaths: ['/private']);
    await expectLater(audit.run(project, project.startUrl, policy, authorized: false), throwsStateError);
    for (final url in ['https://other.test', 'http://example.test', 'https://example.test:8443',
      'https://example.test/private/records', 'https://example.test/delete', 'https://example.test/?token=abc']) {
      await expectLater(audit.run(project, Uri.parse(url), policy, authorized: true), throwsStateError);
    }
    expect(probe.calls, 0);
    final result = await audit.run(project, project.startUrl, policy, authorized: true);
    expect(result.outcome, CorsOutcome.testOriginWithCredentials);
    expect(result.getAdvertised, isTrue);
    expect(probe.calls, 1);
  });
}
