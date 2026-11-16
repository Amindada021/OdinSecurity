import 'package:flutter_test/flutter_test.dart';
import 'package:odin_security/core/project.dart';
import 'package:odin_security/core/rendered_navigation.dart';
import 'package:odin_security/core/route_inventory.dart';
import 'package:odin_security/core/scan_policy.dart';

void main() {
  test('only queryless scoped read-only anchors become candidates', () {
    final p = SecurityProject(name: 'Fixture', url: 'https://example.test', additionalUrls: ['https://api.example.test']);
    final policy = ScanPolicy(excludedPaths: ['/private']);
    RouteObservation row(String url, String source) => RouteObservation(Uri.parse(url), source);
    final candidates = RenderedNavigation.candidates(p, policy, p.startUrl, p.startUrl, [
      row('https://example.test/', 'navigation'),
      row('https://example.test/reports', 'navigation'),
      row('https://example.test/reports', 'navigation'),
      row('https://example.test/private', 'navigation'),
      row('https://example.test/delete', 'navigation'),
      row('https://example.test/search?q=x', 'navigation'),
      row('https://example.test/search#fragment', 'navigation'),
      row('https://example.test/form', 'form-get'),
      row('https://example.test/unknown', 'link'),
      row('https://api.example.test/reports', 'navigation'),
    ]);
    expect(candidates.map((u) => u.toString()), ['https://example.test/reports']);
  });
  test('next wave excludes attempted routes and obeys remaining budget', () {
    final p = SecurityProject(name: 'Fixture', url: 'https://example.test');
    final routes = ['/done', '/new1', '/new2'].map((path) => RouteObservation(p.startUrl.resolve(path), 'navigation'));
    final result = RenderedNavigation.candidates(p, ScanPolicy(maxPages: 12), p.startUrl, p.startUrl, routes,
      attempted: [p.startUrl.resolve('/done')], remaining: 1);
    expect(result.map((u) => u.path), ['/new1']);
    expect(RenderedNavigation.candidates(p, ScanPolicy(), p.startUrl, p.startUrl, routes, remaining: 0), isEmpty);
  });
  test('candidate count is capped by configured policy', () {
    final p = SecurityProject(name: 'Fixture', url: 'https://example.test');
    final routes = List.generate(8, (i) => RouteObservation(p.startUrl.resolve('/page$i'), 'navigation'));
    expect(RenderedNavigation.candidates(p, ScanPolicy(maxPages: 2), p.startUrl, p.startUrl, routes).length, 2);
    expect(RenderedNavigation.candidates(p, ScanPolicy(), p.startUrl, p.startUrl, routes).length, 5);
  });
}
