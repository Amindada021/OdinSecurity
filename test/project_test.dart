import 'package:flutter_test/flutter_test.dart';
import 'package:odin_security/core/project.dart';
import 'package:odin_security/core/passive_scan.dart';

void main() {
  test('scope is exact scheme host and port', () {
    final p = SecurityProject(name: 'Demo', url: 'https://example.test/panel');
    expect(p.contains(Uri.parse('https://example.test/api')), isTrue);
    expect(p.contains(Uri.parse('https://api.example.test/')), isFalse);
    expect(p.contains(Uri.parse('https://example.test:444/')), isFalse);
    expect(p.contains(Uri.parse('http://example.test/')), isFalse);
  });

  test('rejects embedded secrets and invalid URLs', () {
    for (final value in ['file:///etc/passwd', 'https://user:secret@example.test', 'https://example.test/?token=secret', 'not a URL']) {
      expect(() => SecurityProject(name: 'Demo', url: value), throwsFormatException);
    }
  });

  test('scan without authorization cannot make a request', () async {
    final p = SecurityProject(name: 'Demo', url: 'https://example.test');
    await expectLater(PassiveScanner().scan(p, authorized: false), throwsStateError);
  });
}
