import 'package:flutter_test/flutter_test.dart';
import 'package:odin_security/core/fingerprint.dart';
import 'package:odin_security/core/security_checks.dart';

void main() {
  test('missing protection is reported without cookie value', () {
    final findings = PassiveSecurityChecks().inspect(Uri.parse('https://example.test/'),
      HttpObservation(headers: {'Content-Type': ['text/html'], 'Set-Cookie': ['session=secret_fixture']}, body: ''));
    expect(findings.any((f) => f.id == 'header.hsts'), isTrue);
    expect(findings.any((f) => f.id == 'header.csp'), isTrue);
    expect(findings.any((f) => f.id == 'cookie.secure'), isTrue);
    expect(findings.map((f) => f.evidence).join(), isNot(contains('secret_fixture')));
  });
  test('JSON is not flagged for missing page CSP', () {
    final findings = PassiveSecurityChecks().inspect(Uri.parse('https://api.example.test/'),
      HttpObservation(headers: {'content-type': ['application/json']}, body: '{}'));
    expect(findings.any((f) => f.id == 'header.csp'), isFalse);
  });
}
