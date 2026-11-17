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
  test('manual raw, cookie, API key and custom credential modes', () {
    for (final entry in [
      (TokenDelivery.raw, 'Authorization', 'fixture'),
      (TokenDelivery.apiKey, 'X-Test', 'fixture'),
      (TokenDelivery.customHeader, 'X-Test', 'fixture'),
      (TokenDelivery.cookie, 'Cookie', 'sid=fixture'),
    ]) {
      final p = QuickScanCredential.parse(https, entry.$3, delivery: entry.$1, headerName: 'X-Test')!;
      final result = Authenticator.manual(p);
      expect(result.headersFor(https)[entry.$2], entry.$3);
      expect(result.headersFor(Uri.parse('https://outside.test')), isEmpty);
    }
  });
  test('invalid input is rejected without exposing it', () {
    expect(() => QuickScanCredential.parse(Uri.parse('http://example.test'), 'abc'), throwsFormatException);
    expect(() => QuickScanCredential.parse(https, 'abc\r\nInjected: value'), throwsFormatException);
    expect(() => QuickScanCredential.parse(https, 'abc def'), throwsFormatException);
  });
}
