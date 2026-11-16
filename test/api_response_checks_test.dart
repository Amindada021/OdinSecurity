import 'package:flutter_test/flutter_test.dart';
import 'package:odin_security/core/api_response_checks.dart';
import 'package:odin_security/core/fingerprint.dart';

void main() {
  HttpObservation response(String body, {String type = 'application/json'}) =>
    HttpObservation(headers: {'content-type': [type]}, body: body);
  test('nested API fields produce sanitized evidence', () {
    final findings = ApiResponseChecks.inspect(response('{"data":[{"passwordHash":"fixture-value","client_secret":"fixture-value"}],"refreshToken":"fixture-value","errors":[{"extensions":{"stacktrace":["fixture-value"]}}]}'),
      status: 200, truncated: false);
    expect(findings.map((f) => f.id), ['api.json.secret.fields', 'api.json.stacktrace', 'api.json.token.fields']);
    expect(findings.every((f) => !f.evidence.contains('fixture-value')), isTrue);
  });
  test('ordinary JSON, empty fields, truncated and non-JSON responses are ignored', () {
    expect(ApiResponseChecks.inspect(response('{"clientSecret":null,"privateKey":"","stackTrace":[],"name":"test"}'), status: 200, truncated: false), isEmpty);
    expect(ApiResponseChecks.inspect(response('{"privateKey":"fixture"}'), status: 200, truncated: true), isEmpty);
    expect(ApiResponseChecks.inspect(response('{"privateKey":"fixture"}', type: 'text/html'), status: 200, truncated: false), isEmpty);
  });
  test('problem JSON bad serialization and bodyless statuses', () {
    expect(ApiResponseChecks.inspect(response('{', type: 'application/problem+json; charset=utf-8'), status: 500, truncated: false).single.id, 'api.json.invalid');
    expect(ApiResponseChecks.inspect(response(''), status: 204, truncated: false), isEmpty);
  });
}
