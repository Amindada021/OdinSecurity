import 'package:flutter_test/flutter_test.dart';
import 'package:odin_security/core/fingerprint.dart';
import 'package:odin_security/core/security_checks.dart';

void main() {
  final detector = TechnologyDetector();
  test('additional technologies remain separated by layer', () {
    final results = detector.detect(HttpObservation(headers: {'Server': ['openresty'], 'X-Powered-By': ['FastAPI']},
      body: '<link href="/_app/immutable/a.css">'));
    expect(results.any((r) => r.name == 'OpenResty' && r.layer == TechnologyLayer.server), isTrue);
    expect(results.any((r) => r.name == 'FastAPI (likely)' && r.layer == TechnologyLayer.backend), isTrue);
    expect(results.any((r) => r.name == 'SvelteKit' && r.layer == TechnologyLayer.frontend), isTrue);
  });
  test('verbose framework response is a sanitized diagnostic observation', () {
    final findings = PassiveSecurityChecks().inspect(Uri.parse('https://example.test/'),
      HttpObservation(headers: {'Content-Type': ['text/html'], 'Set-Cookie': ['session=secret; Secure']},
        body: 'Django version: 1.2 Traceback fixture contains private data'));
    expect(findings.any((r) => r.id == 'framework.debug'), isTrue);
    expect(findings.any((r) => r.id == 'cookie.httponly'), isTrue);
    expect(findings.map((r) => r.evidence).join(), isNot(contains('secret')));
    expect(findings.map((r) => r.evidence).join(), isNot(contains('private data')));
  });
  test('CSRF cookies are not treated like session cookies', () {
    final findings = PassiveSecurityChecks().inspect(Uri.parse('https://example.test/'),
      HttpObservation(headers: {'Set-Cookie': ['XSRF-TOKEN=fixture; Secure']}, body: ''));
    expect(findings.any((r) => r.id == 'cookie.httponly'), isFalse);
  });
}
