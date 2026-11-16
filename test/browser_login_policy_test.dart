import 'package:flutter_test/flutter_test.dart';
import 'package:odin_security/core/auth.dart';
import 'package:odin_security/core/browser_login_policy.dart';

void main() {
  final target = Uri.parse('https://example.test/panel');
  test('browser rejects external origin, port and plaintext', () {
    expect(BrowserLoginPolicy.allows(target, Uri.parse('https://example.test/login')), isTrue);
    for (final url in ['http://example.test/login', 'https://other.test/login', 'https://example.test:444/login']) {
      expect(BrowserLoginPolicy.allows(target, Uri.parse(url)), isFalse);
    }
  });
  test('cookie import rejects header injection and duplicate names', () {
    expect(BrowserLoginPolicy.cookieHeader([const MapEntry('sid', 'fixture')]), 'sid=fixture');
    expect(() => BrowserLoginPolicy.cookieHeader([const MapEntry('sid', 'fixture\r\nX-Other: x')]), throwsFormatException);
    expect(() => BrowserLoginPolicy.cookieHeader([const MapEntry('sid', 'a'), const MapEntry('sid', 'b')]), throwsFormatException);
  });
  test('imported cookie sent only on its path and origin', () {
    final session = Authenticator.manual(AuthProfile(mode: AuthMode.cookie, target: target, secret: 'sid=fixture', cookiePath: '/panel'));
    expect(session.headersFor(Uri.parse('https://example.test/panel/items'))['Cookie'], 'sid=fixture');
    expect(session.headersFor(Uri.parse('https://example.test/panel2')), isEmpty);
    expect(session.headersFor(Uri.parse('https://other.test/panel')), isEmpty);
  });
}
