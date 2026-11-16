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
  test('session cookie max age expires relative to session creation', () {
    final start = DateTime.utc(2026, 1, 1);
    final cookie = Cookie('session', 'fixture')..path = '/'..maxAge = 5;
    final session = AuthSession(origin, {}, [cookie], '/', start);
    expect(session.headersFor(origin, at: start.add(const Duration(seconds: 4)))['Cookie'], 'session=fixture');
    expect(session.headersFor(origin, at: start.add(const Duration(seconds: 5))), isEmpty);
  });
  test('token expiry removes credentials even during a long session', () {
    final end = DateTime.utc(2026, 1, 1);
    final session = AuthSession(origin, {'Authorization': 'Bearer fixture'}, const [], '/', null, end);
    expect(session.headersFor(origin, at: end), isEmpty);
    expect(session.expectsCredentials, isTrue);
  });
  test('login and validation are both checked against exclusions before transport', () async {
    final p = SecurityProject(name: 'test', url: origin.toString());
    final a = AuthProfile(mode: AuthMode.jsonLogin, target: origin, secret: 'fixture',
      loginUrl: origin.resolve('/login').toString(), validationUrl: origin.resolve('/verify').toString(), validationMarker: 'fixture');
    await expectLater(Authenticator().authenticate(p, a, authorized: true, permits: (url) => url.path != '/login'), throwsStateError);
    await expectLater(Authenticator().authenticate(p, a, authorized: true, permits: (url) => url.path != '/verify'), throwsStateError);
  });
  test('no authorization prevents login', () async {
    final p = SecurityProject(name: 'test', url: origin.toString());
    final a = AuthProfile(mode: AuthMode.bearer, target: origin, secret: 'fixture');
    await expectLater(Authenticator().authenticate(p, a, authorized: false), throwsStateError);
  });
}
