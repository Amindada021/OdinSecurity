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
  test('token transport handles raw, prefixed and custom headers without duplication', () {
    expect(Authenticator.tokenHeaders('Bearer test-token', TokenDelivery.bearer), {'Authorization': 'Bearer test-token'});
    expect(Authenticator.tokenHeaders('test-token', TokenDelivery.bearer), {'Authorization': 'Bearer test-token'});
    expect(Authenticator.tokenHeaders('Bearer test-token', TokenDelivery.raw), {'Authorization': 'test-token'});
    expect(Authenticator.tokenHeaders('fixture', TokenDelivery.apiKey), {'X-API-Key': 'fixture'});
    expect(Authenticator.tokenHeaders('fixture', TokenDelivery.customHeader, headerName: 'X-Session'), {'X-Session': 'fixture'});
    expect(() => Authenticator.tokenHeaders('fixture\r\nX: injected', TokenDelivery.bearer), throwsFormatException);
    expect(() => Authenticator.tokenHeaders('fixture', TokenDelivery.customHeader, headerName: 'Host'), throwsFormatException);
  });
  test('configured login delivery is serialized and legacy profiles default to bearer', () {
    final p = AuthProfile(mode: AuthMode.jsonLogin, target: origin, secret: 'fixture',
      loginUrl: origin.resolve('/login').toString(), tokenPath: 'data.token',
      tokenDelivery: TokenDelivery.customHeader, headerName: 'X-Session');
    final json = p.toJson();
    expect(AuthProfile.fromJson(json).tokenDelivery, TokenDelivery.customHeader);
    json.remove('tokenDelivery');
    expect(AuthProfile.fromJson(json).tokenDelivery, TokenDelivery.bearer);
    expect(Authenticator.tokenHeaders(Authenticator.extractToken('{"data":{"token":"Bearer fixture"}}', 'data.token'), TokenDelivery.bearer),
      {'Authorization': 'Bearer fixture'});
  });
  test('authentication refuses cleartext HTTP and cross-origin login', () {
    expect(() => AuthProfile(mode: AuthMode.basic, target: Uri.parse('http://example.test'), secret: 'secret'), throwsFormatException);
    expect(() => AuthProfile(mode: AuthMode.jsonLogin, target: origin, secret: 'test', loginUrl: 'https://evil.test/login'), throwsFormatException);
  });
  test('explicit HTTP session is ephemeral and scoped to exact origin', () {
    final http = Uri.parse('http://example.test:2020');
    final p = AuthProfile(mode: AuthMode.bearer, target: http, secret: 'fixture', allowInsecureHttp: true);
    final session = Authenticator.manual(p);
    expect(session.headersFor(http)['Authorization'], 'Bearer fixture');
    expect(session.headersFor(Uri.parse('http://example.test:2021')), isEmpty);
    expect(session.headersFor(Uri.parse('https://example.test:2020')), isEmpty);
    expect(session.headersFor(Uri.parse('http://other.test:2020')), isEmpty);
    expect(p.toJson, throwsStateError);
    expect(AuthSession(http, {'Authorization': 'fixture'}).headersFor(http), isEmpty);
    final secure = Cookie('secure', 'fixture')..secure = true;
    final normal = Cookie('session', 'fixture');
    expect(AuthSession(http, {}, [secure, normal], '/', null, null, true).headersFor(http)['Cookie'], 'session=fixture');
    expect(() => AuthProfile(mode: AuthMode.jsonLogin, target: http, secret: 'fixture',
      loginUrl: 'http://other.test:2020/login', allowInsecureHttp: true), throwsFormatException);
  });
  test('explicit HTTP JSON login exchanges credentials on local test server', () async {
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    addTearDown(() => server.close(force: true));
    final http = Uri.parse('http://127.0.0.1:${server.port}');
    server.listen((request) async {
      await request.drain<void>();
      request.response.headers.contentType = ContentType.json;
      request.response.write('{"data":{"token":"fixture-token"}}');
      await request.response.close();
    });
    final profile = AuthProfile(mode: AuthMode.jsonLogin, target: http,
      secret: 'fixture', username: 'test', loginUrl: http.resolve('/login').toString(),
      tokenPath: 'data.token', allowInsecureHttp: true);
    final session = await Authenticator().authenticate(
      SecurityProject(name: 'Loopback', url: http.toString()), profile, authorized: true);
    expect(session.headersFor(http)['Authorization'], 'Bearer fixture-token');
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
