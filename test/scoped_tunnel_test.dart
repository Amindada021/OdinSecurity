import 'dart:convert';
import 'package:flutter_test/flutter_test.dart';
import 'package:odin_security/core/project.dart';
import 'package:odin_security/core/scan_policy.dart';
import 'package:odin_security/core/scoped_tunnel.dart';

void main() {
  final target = Uri.parse('https://example.test');
  final expected = 'Basic ' + base64Encode(utf8.encode('odin:fixture'));
  String header(String authority, {String method = 'CONNECT', String? auth, String extra = ''}) =>
    '$method $authority HTTP/1.1\r\nProxy-Authorization: ' + (auth ?? expected) + '\r\n$extra\r\n';

  test('CONNECT permits only explicit authority and session credentials', () {
    expect(TunnelHandshake.accepts(header('example.test:443'), target, expected), isTrue);
    expect(TunnelHandshake.accepts(header('other.test:443'), target, expected), isFalse);
    expect(TunnelHandshake.accepts(header('example.test:8443'), target, expected), isFalse);
    expect(TunnelHandshake.accepts(header('example.test:443', method: 'GET'), target, expected), isFalse);
    expect(TunnelHandshake.accepts(header('example.test:443', auth: 'Basic invalid'), target, expected), isFalse);
  });
  test('rejects URL, path, duplicate auth, malformed authority and extra payload', () {
    expect(TunnelHandshake.accepts(header('https://example.test:443'), target, expected), isFalse);
    expect(TunnelHandshake.accepts(header('example.test:443/path'), target, expected), isFalse);
    expect(TunnelHandshake.accepts(header('user@example.test:443'), target, expected), isFalse);
    expect(TunnelHandshake.accepts(header('example.test:443', extra: 'Proxy-Authorization: $expected\r\n'), target, expected), isFalse);
    expect(TunnelHandshake.accepts(header('example.test:443') + 'extra', target, expected), isFalse);
  });
  test('tunnel cannot bypass consent, exact scope or path exclusions', () {
    final project = SecurityProject(name: 'Fixture', url: 'https://example.test');
    expect(() => ScopedTunnel.validate(project, target, ScanPolicy(), true), returnsNormally);
    expect(() => ScopedTunnel.validate(project, target, ScanPolicy(), false), throwsStateError);
    expect(() => ScopedTunnel.validate(project, Uri.parse('https://third.test'), ScanPolicy(), true), throwsStateError);
    expect(() => ScopedTunnel.validate(project, target, ScanPolicy(excludedPaths: ['/private']), true), throwsStateError);
  });
}
