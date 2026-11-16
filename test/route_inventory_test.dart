import 'dart:convert';
import 'package:flutter_test/flutter_test.dart';
import 'package:odin_security/core/project.dart';
import 'package:odin_security/core/route_inventory.dart';
import 'package:odin_security/core/scan_policy.dart';

void main() {
  final project = SecurityProject(name: 'Fixture', url: 'https://panel.example.test',
    additionalUrls: ['https://api.example.test']);
  final policy = ScanPolicy(excludedPaths: ['/private']);
  test('browser captures rendered links and API metadata with strict scope', () {
    final snapshot = jsonEncode({'page': 'https://panel.example.test/dashboard', 'routes': [
      {'source': 'link', 'url': 'https://panel.example.test/reports?secret=123#token'},
      {'source': 'fetch', 'url': 'https://api.example.test/v1/invoices?auth=secret'},
      {'source': 'fetch', 'url': 'https://api.example.test/v1/invoices'},
      {'source': 'fetch', 'url': 'https://api.example.test/private/record'},
      {'source': 'fetch', 'url': 'https://third.test/v1'},
      {'source': 'fetch', 'url': 'https://user:password@api.example.test/v1'},
      {'source': 'fetch', 'url': 'https://api.example.test:444/v1'},
    ]});
    final found = RouteInventory.fromBrowser(project, policy, Uri.parse('https://panel.example.test/dashboard'), jsonEncode(snapshot));
    expect(found.map((r) => r.url.toString()), [
      'https://panel.example.test/dashboard', 'https://panel.example.test/reports', 'https://api.example.test/v1/invoices',
    ]);
    expect(found.last.source, 'fetch');
  });
  test('captures only scoped form actions and script destinations', () {
    final snapshot = jsonEncode({'page': 'https://panel.example.test/dashboard', 'routes': [
      {'source': 'form-post', 'url': 'https://api.example.test/v1/save?token=secret', 'input': 'secret'},
      {'source': 'form-get', 'url': 'https://panel.example.test/search?q=private'},
      {'source': 'script', 'url': 'https://panel.example.test/static/app.js?v=123'},
      {'source': 'form-post', 'url': 'https://outside.test/action'},
      {'source': 'script', 'url': 'https://api.example.test/private/a.js'},
    ]});
    final found = RouteInventory.fromBrowser(project, policy, Uri.parse('https://panel.example.test/dashboard'), snapshot);
    expect(found.map((r) => r.source), ['document', 'form-post', 'form-get', 'script']);
    expect(found[1].url.toString(), 'https://api.example.test/v1/save');
    expect(found[2].url.toString(), 'https://panel.example.test/search');
    expect(found[3].url.toString(), 'https://panel.example.test/static/app.js');
  });
  test('navigation markers cannot promote parameterized anchors to automatic candidates', () {
    final found = RouteInventory.fromBrowser(project, policy, Uri.parse('https://panel.example.test/dashboard'),
      jsonEncode({'page': 'https://panel.example.test/dashboard', 'routes': [
        {'source': 'navigation', 'url': 'https://panel.example.test/test?x=1'},
        {'source': 'navigation', 'url': 'https://panel.example.test/other#section'},
        {'source': 'navigation', 'url': 'https://panel.example.test/reports'}
      ]}));
    expect(found.map((r) => r.source), ['document', 'navigation']);
    expect(found.last.url.toString(), 'https://panel.example.test/reports');
  });
  test('reject snapshot from different page', () {
    expect(() => RouteInventory.fromBrowser(project, policy, Uri.parse('https://panel.example.test/dashboard'),
      jsonEncode({'page': 'https://panel.example.test/reports', 'routes': []})), throwsFormatException);
  });
  test('HAR is offline and discards sensitive metadata', () {
    final source = jsonEncode({'log': {'entries': [
      {'request': {'method': 'POST', 'url': 'https://api.example.test/v1/orders?token=secret',
        'headers': [{'name': 'Authorization', 'value': 'Bearer private'}], 'postData': {'text': 'password'}}},
      {'request': {'method': 'GET', 'url': 'https://api.example.test/private/data'}},
      {'request': {'method': 'GET', 'url': 'https://outside.test/path'}},
    ]}});
    final found = RouteInventory.fromHar(project, policy, source);
    expect(found.single.source, 'POST');
    expect(found.single.url.toString(), 'https://api.example.test/v1/orders');
  });
  test('cap and deduplicate inventory', () {
    final source = jsonEncode({'log': {'entries': List.generate(400, (i) =>
      {'request': {'method': 'GET', 'url': 'https://api.example.test/item/$i'}})}});
    final found = RouteInventory.fromHar(project, policy, source);
    expect(found.length, RouteInventory.maxEntries);
    expect(RouteInventory.merge(found, found).length, RouteInventory.maxEntries);
  });
}
