import 'package:flutter_test/flutter_test.dart';
import 'package:odin_security/core/auth.dart';
import 'package:odin_security/core/browser_login_policy.dart';
import 'package:odin_security/core/project.dart';
import 'package:odin_security/core/scan_policy.dart';

void main() {
  test('HTTP opt-in accepts only the exact target origin', () {
    final target = Uri.parse('http://example.test:2020');
    final project = SecurityProject(name: 'Test', url: target.toString());
    final policy = ScanPolicy();
    expect(() => BrowserLoginPolicy.loginUrl(project, target, '/login', policy), throwsFormatException);
    final login = BrowserLoginPolicy.loginUrl(project, target, '/login', policy, allowInsecureHttp: true);
    expect(login, target.resolve('/login'));
    expect(BrowserLoginPolicy.allowsNavigation(target, login, target.resolve('/dashboard'), policy, allowInsecureHttp: true), isTrue);
    expect(BrowserLoginPolicy.allowsNavigation(target, login, Uri.parse('http://example.test:2021'), policy, allowInsecureHttp: true), isFalse);
    expect(() => BrowserLoginPolicy.loginUrl(project, target, 'http://other.test/login', policy, allowInsecureHttp: true), throwsFormatException);
    expect(BrowserLoginPolicy.assessmentStart(target, target.resolve('/dashboard'), policy, allowInsecureHttp: true), target.resolve('/dashboard'));
  });
  final target = Uri.parse('https://example.test/panel');
  test('browser rejects external origin, port and plaintext', () {
    expect(BrowserLoginPolicy.allows(target, Uri.parse('https://example.test/login')), isTrue);
    for (final url in ['http://example.test/login', 'https://other.test/login', 'https://example.test:444/login']) {
      expect(BrowserLoginPolicy.allows(target, Uri.parse(url)), isFalse);
    }
  });
  test('automatic login admits the explicit browser-only HTTPS origin without changing assessment scope', () {
    final project = SecurityProject(name: 'Example', url: 'https://example.test',
      additionalUrls: ['https://api.example.test']);
    final policy = ScanPolicy(excludedPaths: ['/blocked']);
    final start = project.startUrl;
    expect(BrowserLoginPolicy.loginUrl(project, start, '/login', policy), Uri.parse('https://example.test/login'));
    final login = BrowserLoginPolicy.loginUrl(project, start, 'https://login.example.test/sign-in', policy);
    expect(login, Uri.parse('https://login.example.test/sign-in'));
    expect(project.contains(login), isFalse);
    expect(BrowserLoginPolicy.allowsNavigation(start, login, login, policy), isTrue);
    expect(BrowserLoginPolicy.assessmentStart(start, login, policy), start);
    final api = project.additionalUrls.single;
    expect(BrowserLoginPolicy.loginUrl(project, api, login.toString(), policy), login);
    expect(() => BrowserLoginPolicy.loginUrl(project, login, '/sign-in', policy), throwsFormatException);
    expect(BrowserLoginPolicy.allowsNavigation(start, login, Uri.parse('https://outside.test'), policy), isFalse);
    expect(BrowserLoginPolicy.allowsNavigation(start, login, Uri.parse('https://example.test/blocked'), policy), isFalse);
    for (final raw in ['http://example.test/login', '/blocked', '//outside.test/login', 'https://user@outside.test/login', 'https://outside.test/login?code=secret', 'https://outside.test/blocked']) {
      expect(() => BrowserLoginPolicy.loginUrl(project, start, raw, policy), throwsFormatException);
    }
  });
  test('root quick scan begins at the signed-in page without query secrets', () {
    final root = Uri.parse('https://example.test');
    final current = Uri.parse('https://example.test/dashboard?code=fixture#fragment');
    final policy = ScanPolicy();
    expect(BrowserLoginPolicy.assessmentStart(root, current, policy), Uri.parse('https://example.test/dashboard'));
    expect(BrowserLoginPolicy.assessmentStart(target, current, policy), target);
    expect(BrowserLoginPolicy.assessmentStart(root, Uri.parse('https://else.test/private'), policy), root);
    expect(BrowserLoginPolicy.assessmentStart(root, Uri.parse('https://example.test/logout'), policy), root);
    expect(BrowserLoginPolicy.assessmentStart(root, current, ScanPolicy(excludedPaths: ['/dashboard'])), root);
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
