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
  test('credential-bearing response headers are not displayed', () {
    final headers = ManualRequestClient.safeHeaders({'Set-Cookie': ['test=secret'], 'Content-Type': ['text/plain'], 'Location': ['https://test/?token=secret']});
    expect(headers['Set-Cookie'], ['[redacted]']);
    expect(headers['Content-Type'], ['text/plain']);
    expect(headers['Location'], ['[redacted]']);
  });
}
