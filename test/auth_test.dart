import 'dart:io';
import 'package:flutter_test/flutter_test.dart';
import 'package:odin_security/core/auth.dart';
import 'package:odin_security/core/project.dart';

void main() {
  final origin = Uri.parse('https://api.example.test/');
  test('bearer credentials never cross origin or port', () {
    final session = Authenticator.manual(AuthProfile(mode: AuthMode.bearer, target: origin, secret: 'test-token'));
    expect(session.headersFor(origin)['Authorization'], 'Bearer test-token');
    for (final url in ['https://other.example.test/', 'http://api.example.test/', 'https://api.example.test:8443/']) {
      expect(session.headersFor(Uri.parse(url)), isEmpty);
    }
  });
  test('authentication refuses cleartext HTTP and cross-origin login', () {
    expect(() => AuthProfile(mode: AuthMode.basic, target: Uri.parse('http://example.test'), secret: 'secret'), throwsFormatException);
    expect(() => AuthProfile(mode: AuthMode.jsonLogin, target: origin, secret: 'test', loginUrl: 'https://evil.test/login'), throwsFormatException);
  });
  test('custom token path requires a nonempty string', () {
    expect(Authenticator.extractToken('{"data":{"jwt":"test"}}', 'data.jwt'), 'test');
    expect(() => Authenticator.extractToken('{"data":{}}', 'data.jwt'), throwsFormatException);
  });
  test('cookie scope respects path', () {
    final cookie = Cookie('session', 'fixture')..path = '/api';
    final session = AuthSession(origin, {}, [cookie]);
    expect(session.headersFor(Uri.parse('https://api.example.test/api/v1'))['Cookie'], 'session=fixture');
    expect(session.headersFor(Uri.parse('https://api.example.test/api2')), isEmpty);
  });
  test('no authorization prevents login', () async {
    final p = SecurityProject(name: 'test', url: origin.toString());
    final a = AuthProfile(mode: AuthMode.bearer, target: origin, secret: 'fixture');
    await expectLater(Authenticator().authenticate(p, a, authorized: false), throwsStateError);
  });
}
