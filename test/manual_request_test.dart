import 'package:flutter_test/flutter_test.dart';
import 'package:odin_security/core/manual_request.dart';
import 'package:odin_security/core/project.dart';

void main() {
  final p = SecurityProject(name: 'Fixture', url: 'https://example.test/');
  test('manual reads require consent and exact scope', () {
    expect(() => ManualRequestClient.validate(p, Uri.parse('https://example.test/path'), 'GET', true), returnsNormally);
    expect(() => ManualRequestClient.validate(p, Uri.parse('https://other.test/path'), 'GET', true), throwsStateError);
    expect(() => ManualRequestClient.validate(p, p.startUrl, 'GET', false), throwsStateError);
    expect(() => ManualRequestClient.validate(p, p.startUrl, 'DELETE', true), throwsFormatException);
  });
  test('write requests need staging approval, HTTPS, and exact origin', () {
    final options = ManualRequestOptions(content: ManualContent.json, body: '{"name":"fixture"}');
    expect(() => ManualRequestClient.validate(p, p.startUrl, 'POST', true, options: options), throwsFormatException);
    expect(() => ManualRequestClient.validate(p, p.startUrl, 'POST', true, options: options, stagingConfirmed: true), returnsNormally);
    expect(() => ManualRequestClient.validate(p, p.startUrl, 'GET', true, options: options), throwsFormatException);
    expect(() => ManualRequestClient.validate(p, p.startUrl, 'OPTIONS', true), returnsNormally);
    final insecure = SecurityProject(name: 'Fixture', url: 'http://example.test/');
    expect(() => ManualRequestClient.validate(insecure, insecure.startUrl, 'PATCH', true, stagingConfirmed: true), throwsFormatException);
  });
  test('custom options are immutable, bounded and reject credential or transport headers', () {
    final source = {'Cache-Control': 'no-cache'};
    final options = ManualRequestOptions(headers: source);
    source['Cache-Control'] = 'other';
    expect(options.headers['cache-control'], 'no-cache');
    expect(() => options.headers.remove('cache-control'), throwsUnsupportedError);
    expect(() => ManualRequestOptions.parse('Authorization: secret', ManualContent.none, ''), throwsFormatException);
    expect(() => ManualRequestOptions.parse('Cache-Control: a\r\nHost: other.test', ManualContent.none, ''), throwsFormatException);
    expect(() => ManualRequestOptions.parse('Cache-Control: a\ncache-control: b', ManualContent.none, ''), throwsFormatException);
    expect(() => ManualRequestOptions(content: ManualContent.json, body: '{'), throwsFormatException);
    expect(() => ManualRequestOptions(content: ManualContent.text, body: List.filled(32769, 'a').join()), throwsFormatException);
  });
  test('credential-bearing response headers are not displayed', () {
    final headers = ManualRequestClient.safeHeaders({'Set-Cookie': ['test=secret'], 'Content-Type': ['text/plain'], 'Location': ['https://test/?token=secret']});
    expect(headers['Set-Cookie'], ['[redacted]']);
    expect(headers['Content-Type'], ['text/plain']);
    expect(headers['Location'], ['[redacted]']);
  });
}
