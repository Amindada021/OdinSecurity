import 'package:flutter_test/flutter_test.dart';
import 'package:odin_security/core/csp_review.dart';
import 'package:odin_security/core/fingerprint.dart';

void main() {
  Iterable<String> ids(Map<String,List<String>> headers) =>
    CspReview.inspect(HttpObservation(headers: headers, body: '')).map((r) => r.id);
  test('review broad script sources, duplicate directives and omitted controls', () {
    final found = ids({'content-security-policy': ["script-src * 'unsafe-inline'; script-src 'self'"]});
    expect(found, containsAll(['csp.duplicate.directive','csp.inline.review','csp.script.broad','csp.base.review','csp.object.review']));
  });
  test('nonce/hash policy does not label inline or broad sources without context', () {
    final found = ids({'content-security-policy': ["script-src 'nonce-fixture' 'unsafe-inline' https:; base-uri 'none'; object-src 'none'"]});
    expect(found, isEmpty);
  });
  test('multiple policies and report-only are not treated as one effective policy', () {
    expect(ids({'content-security-policy': ["script-src *", "script-src 'none'"]}), ['csp.multiple.review']);
    expect(ids({'content-security-policy-report-only': ["script-src 'none'"]}), ['csp.report.only']);
  });
}
