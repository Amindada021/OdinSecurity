import 'package:flutter_test/flutter_test.dart';
import 'package:odin_security/core/browser_traffic.dart';
import 'package:odin_security/core/project.dart';
import 'package:odin_security/core/scan_policy.dart';

void main() {
  final project = SecurityProject(name: 'Fixture', url: 'https://example.test', additionalUrls: ['https://api.example.test']);
  final policy = ScanPolicy(excludedPaths: ['/private']);
  Map<String, Object> row(String url, String method) => {
    'route': url, 'method': method, 'hadQuery': false, 'mainFrame': false, 'at': 1000,
  };
  test('native snapshots are re-scoped and only metadata is accepted', () {
    final result = BrowserTraffic.parse(project, policy, [
      row('https://example.test/home', 'GET'),
      row('https://api.example.test/orders', 'POST'),
      row('https://example.test/?key=secret', 'GET'),
      row('https://example.test/private', 'GET'),
      row('https://outside.test/', 'GET'),
      row('http://example.test/', 'GET'),
      row('https://example.test/', 'UNKNOWN'),
    ]);
    expect(result.map((r) => r.method), ['GET', 'POST']);
    expect(result.last.route.host, 'api.example.test');
  });
  test('rejects invalid or oversized snapshots', () {
    expect(() => BrowserTraffic.parse(project, policy, {}), throwsFormatException);
    expect(() => BrowserTraffic.parse(project, policy, List.filled(201, null)), throwsFormatException);
  });
}
