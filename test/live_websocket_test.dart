import 'dart:io';
import 'package:flutter_test/flutter_test.dart';
import 'package:odin_security/core/auth.dart';
import 'package:odin_security/core/live_websocket.dart';
import 'package:odin_security/core/project.dart';
import 'package:odin_security/core/scan_policy.dart';

class FixtureRequest implements HttpClientRequest {
  @override
  bool followRedirects = true;
  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

class FixtureClient implements HttpClient {
  final request = FixtureRequest();
  int calls = 0;
  @override
  Future<HttpClientRequest> openUrl(String method, Uri url) async {
    calls++;
    return request;
  }
  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

void main() {
  final project = SecurityProject(name: 'Fixture', url: 'https://example.test');
  final policy = ScanPolicy(excludedPaths: ['/private']);
  test('WSS maps to exact HTTPS origin, consent and exclusions', () {
    final endpoint = Uri.parse('wss://example.test/messages');
    expect(LiveWebSocket.validate(project, policy, endpoint, authorized: true),
      Uri.parse('https://example.test/messages'));
    expect(() => LiveWebSocket.validate(project, policy, endpoint, authorized: false), throwsStateError);
    expect(() => LiveWebSocket.validate(project, policy, Uri.parse('ws://example.test/messages'), authorized: true), throwsFormatException);
    expect(() => LiveWebSocket.validate(project, policy, Uri.parse('wss://other.test/messages'), authorized: true), throwsStateError);
    expect(() => LiveWebSocket.validate(project, policy, Uri.parse('wss://example.test:8443/messages'), authorized: true), throwsStateError);
    expect(() => LiveWebSocket.validate(project, policy, Uri.parse('wss://example.test/private'), authorized: true), throwsStateError);
  });
  test('upgrade adapter disables redirects and rejects any altered request before transport', () async {
    final delegate = FixtureClient();
    final target = Uri.parse('https://example.test/messages?q=1');
    final client = ScopedUpgradeClient(delegate, target);
    final request = await client.openUrl('GET', target);
    expect(request.followRedirects, isFalse);
    await expectLater(client.openUrl('GET', Uri.parse('https://other.test/messages?q=1')), throwsStateError);
    await expectLater(client.openUrl('GET', target.replace(query: 'q=2')), throwsStateError);
    await expectLater(client.openUrl('POST', target), throwsStateError);
    expect(delegate.calls, 1);
  });
  test('saved identity must be static and match the origin', () {
    final endpoint = Uri.parse('wss://example.test/messages');
    final auth = AuthProfile(mode: AuthMode.bearer, target: Uri.parse('https://other.test'), secret: 'fixture');
    expect(() => LiveWebSocket.validate(project, policy, endpoint, authorized: true, auth: auth), throwsStateError);
    final conflicting = AuthProfile(mode: AuthMode.apiKey, target: project.startUrl, headerName: 'Sec-WebSocket-Key', secret: 'fixture');
    expect(() => LiveWebSocket.validate(project, policy, endpoint, authorized: true, auth: conflicting), throwsFormatException);
  });
  test('payload is omitted by default; text preview is bounded and binary data not retained', () {
    final info = SocketMessageMetadata.fromMessage('سلام');
    expect(info.bytes, 8);
    expect(info.preview, isNull);
    final long = SocketMessageMetadata.fromMessage(List.filled(5000, 'a').join(), includePreview: true);
    expect(long.bytes, 5000);
    expect(long.preview!.length, 4096);
    final binary = SocketMessageMetadata.fromMessage([1, 2, 3], includePreview: true);
    expect(binary.text, isFalse);
    expect(binary.bytes, 3);
    expect(binary.preview, isNull);
  });
}
