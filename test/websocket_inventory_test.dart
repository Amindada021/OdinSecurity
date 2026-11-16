import 'package:flutter_test/flutter_test.dart';
import 'package:odin_security/core/project.dart';
import 'package:odin_security/core/scan_policy.dart';
import 'package:odin_security/core/websocket_inventory.dart';

void main() {
  final project = SecurityProject(name: 'Fixture', url: 'https://example.test');
  final policy = ScanPolicy(excludedPaths: ['/excluded']);
  test('imports scoped handshake metadata without query or payload', () {
    final result = WebSocketInventory.parse(project, policy, '''
{"log":{"entries":[
{"request":{"url":"wss://example.test/chat?token=secret"},"response":{"status":101},"_webSocketMessages":[{"type":"send","data":"secret"},{"type":"receive","data":"secret"},{"type":"unknown"}]},
{"request":{"url":"https://example.test/socket"},"response":{"status":101,"headers":[{"name":"Upgrade","value":"websocket"}]}},
{"request":{"url":"wss://other.test/chat"},"response":{"status":101}},
{"request":{"url":"wss://example.test/excluded"},"response":{"status":101}},
{"request":{"url":"https://example.test/normal"},"response":{"status":200}},
{"request":{"url":"https://example.test/other-upgrade"},"response":{"status":101}}
]}}''');
    expect(result.length, 2);
    expect(result.first.url.toString(), 'wss://example.test/chat');
    expect(result.first.sent, 1);
    expect(result.first.received, 1);
    expect(result.first.unknown, 1);
    expect(result.last.framesAvailable, false);
  });
  test('rejects malformed HAR and credential-bearing URL', () {
    expect(() => WebSocketInventory.parse(project, policy, '{}'), throwsFormatException);
    final result = WebSocketInventory.parse(project, policy,
      '{"log":{"entries":[{"request":{"url":"wss://user:secret@example.test/chat"}}]}}');
    expect(result, isEmpty);
  });
}
