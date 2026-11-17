import 'dart:convert';
import 'package:flutter_test/flutter_test.dart';
import 'package:odin_security/core/auth.dart';
import 'package:odin_security/core/login_network_capture.dart';
import 'package:odin_security/core/scan_policy.dart';

void main() {
  final login = Uri.parse('https://panel.example.test/login');
  final target = Uri.parse('https://api.example.test');
  String event(String url, String body, {String source = 'fetch'}) => jsonEncode({
    'url': url, 'method': 'POST', 'status': 200, 'contentType': 'application/json',
    'body': body, 'source': source, 'truncated': false,
  });

  test('captures a scoped cross-subdomain JSON response and strips query secrets', () {
    final item = LoginNetworkResponse.fromBridge(
      event('https://api.example.test/v1/login?code=private#secret',
        '{"data":{"token":"abc123"}}'),
      login: login, target: target, policy: ScanPolicy(),
    );
    expect(item, isNotNull);
    expect(item!.url.toString(), 'https://api.example.test/v1/login');
    expect(item.tokens.single.path, 'data.token');
    expect(item.tokens.single.value, 'abc123');
    final profile = AuthProfile(mode: AuthMode.bearer, target: target,
      secret: item.tokens.single.value);
    expect(Authenticator.manual(profile).headersFor(target)['Authorization'],
      'Bearer abc123');
  });

  test('never imports third-party or excluded response into the inspector', () {
    expect(LoginNetworkResponse.fromBridge(
      event('https://attacker.test/token', '{"token":"abc123"}'),
      login: login, target: target), isNull);
    expect(LoginNetworkResponse.fromBridge(
      event('http://api.example.test/v1/login', '{"token":"abc123"}'),
      login: login, target: target), isNull);
    expect(LoginNetworkResponse.fromBridge(
      event('https://api.example.test/blocked', '{"token":"abc123"}'),
      login: login, target: target,
      policy: ScanPolicy(excludedPaths: ['/blocked'])), isNull);
    expect(LoginNetworkResponse.fromBridge(
      event('https://user:pw@api.example.test/v1/login', '{"token":"abc123"}'),
      login: login, target: target), isNull);
  });

  test('rejects oversized or malformed data and request-body fields are not modeled', () {
    expect(LoginNetworkResponse.fromBridge('{not-json',
      login: login, target: target), isNull);
    expect(LoginNetworkResponse.fromBridge(
      event('https://api.example.test/v1/login', 'x' * 35000),
      login: login, target: target), isNull);
    final item = LoginNetworkResponse.fromBridge(
      event('https://api.example.test/v1/login', '{}', source: 'xhr'),
      login: login, target: target);
    expect(item, isNotNull);
    expect(item!.tokens, isEmpty);
  });

  test('token extraction is opt-in and ignores irrelevant fields', () {
    final candidates = LoginTokenCandidate.fromJsonBody(
      '{"message":"ok","data":{"sessionId":"deadbeef",'
      '"access_token":"Bearer sample.token","csrfToken":"not-a-bearer"}}');
    expect(candidates.map((candidate) => candidate.path).toList(),
      ['data.sessionId', 'data.access_token']);
    expect(LoginTokenCandidate.fromJsonBody(
      '{"token":"bad\\r\\nvalue"}'), isEmpty);
    expect(LoginTokenCandidate.fromJsonBody(
      '{"token":123}'), isEmpty);
  });

  test('injected script installs fetch/XHR hooks and does not capture request bodies', () {
    expect(loginNetworkInstrumentation, contains('window.fetch'));
    expect(loginNetworkInstrumentation, contains('XMLHttpRequest.prototype.send'));
    expect(loginNetworkInstrumentation, isNot(contains('requestBody')));
    expect(loginNetworkInstrumentation, contains('response.clone()'));
  });
}
