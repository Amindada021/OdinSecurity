import 'package:flutter_test/flutter_test.dart';
import 'package:odin_security/core/auth.dart';
import 'package:odin_security/core/quick_scan_credential.dart';

void main() {
  final https = Uri.parse('https://api.example.test/v1');
  test('empty value means anonymous scan', () {
    expect(QuickScanCredential.parse(https, ''), isNull);
  });
  test('raw or Bearer-prefixed credentials are scoped to HTTPS origin', () {
    for (final input in ['header.payload.signature', 'Bearer header.payload.signature']) {
      final profile = QuickScanCredential.parse(https, input)!;
      final session = Authenticator.manual(profile);
      expect(session.headersFor(https)['Authorization'], 'Bearer header.payload.signature');
      expect(session.headersFor(Uri.parse('https://api.example.test/v2'))['Authorization'], 'Bearer header.payload.signature');
      expect(session.headersFor(Uri.parse('http://api.example.test/v1')), isEmpty);
      expect(session.headersFor(Uri.parse('https://other.example.test/v1')), isEmpty);
      expect(session.headersFor(Uri.parse('https://api.example.test:8443/v1')), isEmpty);
    }
  });
  test('invalid input is rejected without exposing it', () {
    expect(() => QuickScanCredential.parse(Uri.parse('http://example.test'), 'abc'), throwsFormatException);
    expect(() => QuickScanCredential.parse(https, 'abc\r\nInjected: value'), throwsFormatException);
    expect(() => QuickScanCredential.parse(https, 'abc def'), throwsFormatException);
  });
}
