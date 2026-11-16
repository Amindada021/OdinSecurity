import 'package:flutter_test/flutter_test.dart';
import 'package:odin_security/core/fingerprint.dart';
import 'package:odin_security/core/header_policy_checks.dart';

void main() {
  final url = Uri.parse('https://example.test/');
  List<String> ids(Map<String, List<String>> headers, {int status = 200, bool auth = false}) =>
    HeaderPolicyChecks.inspect(url, HttpObservation(headers: headers, body: ''), status: status, identityHeadersSent: auth).map((f) => f.id).toList();

  test('HSTS distinguishes disabled, malformed, and positive lifetime', () {
    expect(ids({'Strict-Transport-Security': ['max-age=0']}), ['header.hsts.disabled']);
    expect(ids({'Strict-Transport-Security': ['max-age=bad']}), ['header.hsts.invalid']);
    expect(ids({'Strict-Transport-Security': ['max-age=3600; includeSubDomains']}), isEmpty);
  });
  test('shared caching signal only when identity was sent and successful response opts in', () {
    expect(ids({'cache-control': ['public, max-age=60']}, auth: true), ['cache.auth.shared']);
    expect(ids({'cache-control': ['s-maxage=60']}, auth: true), ['cache.auth.shared']);
    expect(ids({'cache-control': ['public, private']}, auth: true), isEmpty);
    expect(ids({'cache-control': ['public, no-store']}, auth: true), isEmpty);
    expect(ids({'cache-control': ['custom="x, public"']}, auth: true), isEmpty);
    expect(ids({'cache-control': ['public']}), isEmpty);
    expect(ids({'cache-control': ['public']}, auth: true, status: 403), isEmpty);
  });
  test('observes downgrade without retaining redirect location or cookie names', () {
    final findings = HeaderPolicyChecks.inspect(url, HttpObservation(headers: {
      'location': ['http://example.test/?secret=hidden'],
      'set-cookie': ['__Host-fixture=secret; SameSite=None; Domain=example.test; Path=/wrong'],
    }, body: ''), status: 302);
    expect(findings.map((f) => f.id), containsAll(['transport.redirect.http', 'cookie.samesite.none.insecure', 'cookie.prefix.invalid']));
    expect(findings.map((f) => f.evidence).join(' '), isNot(contains('hidden')));
    expect(findings.map((f) => f.evidence).join(' '), isNot(contains('__Host-fixture')));
    expect(ids({'set-cookie': ['__Host-good=opaque; Secure; Path=/; SameSite=None']}), isEmpty);
  });
}
