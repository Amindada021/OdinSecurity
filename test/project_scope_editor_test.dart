import 'package:flutter_test/flutter_test.dart';
import 'package:odin_security/core/project.dart';

void main() {
  test('multi-target editor normalizes, deduplicates and retains project identity', () {
    final initial = SecurityProject(name: 'Accounting', url: 'https://panel.example.test');
    final next = SecurityProject(id: initial.id, name: 'Accounting QA', url: initial.startUrl.toString(),
      additionalUrls: SecurityProject.parseTargetLines(' https://api.example.test \r\nhttps://admin.example.test\nhttps://api.example.test\n'));
    expect(next.id, initial.id);
    expect(next.targets.length, 3);
    expect(next.contains(Uri.parse('https://api.example.test/v1')), isTrue);
    expect(next.contains(Uri.parse('https://other.example.test')), isFalse);
    expect(next.contains(Uri.parse('http://api.example.test')), isFalse);
  });
  test('invalid, credential-bearing and excessive entries rejected', () {
    for (final value in ['https://user:secret@example.test', 'https://example.test/?key=secret', 'https://*.example.test', 'file:///tmp']) {
      expect(() => SecurityProject.parseTargetLines(value), throwsFormatException);
    }
    expect(() => SecurityProject.parseTargetLines(List.generate(31, (i) => 'https://host$i.example.test').join('\n')), throwsFormatException);
  });
}
