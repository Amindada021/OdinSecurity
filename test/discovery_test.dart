import 'package:flutter_test/flutter_test.dart';
import 'package:odin_security/core/discovery.dart';

void main() {
  test('only safe same-origin links are discovered and deduplicated', () {
    final root = Uri.parse('https://example.test/');
    final urls = LinkDiscovery.extract(root, '''
<a href="/about">A</a><a href="/about#x">B</a><a href="https://other.test/">Other</a>
<a href="/account/logout">Logout</a><a href="/invoice/delete">Delete</a>
<a href="/list?token=fixture">Query</a><a href="/logo.png">Logo</a>
<form action="/submit"></form><a href="/docs">Docs</a>
''');
    expect(urls.map((u) => u.path), ['/about', '/docs']);
  });
  test('DOM parsing respects base and ignores comments and script text', () {
    final root = Uri.parse('https://example.test/');
    final urls = LinkDiscovery.extract(root, '''
      <base href="/docs/">
      <!-- <a href="/hidden">Hidden</a> -->
      <script>const sample = '<a href="/fake">Fake</a>';</script>
      <a href=guide>Guide</a>
    ''');
    expect(urls.map((u) => u.path), ['/docs/guide']);
    expect(LinkDiscovery.extract(root, '<base href="https://other.test/"><a href="guide">Guide</a>'), isEmpty);
  });
  test('cross-port and cross-protocol links are rejected', () {
    final origin = Uri.parse('https://example.test/');
    expect(LinkDiscovery.eligible(origin, Uri.parse('https://example.test:444/a')), isFalse);
    expect(LinkDiscovery.eligible(origin, Uri.parse('http://example.test/a')), isFalse);
  });
}
