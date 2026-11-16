import 'dart:convert';
import 'package:flutter_test/flutter_test.dart';
import 'package:odin_security/core/har_traffic.dart';
import 'package:odin_security/core/project.dart';
import 'package:odin_security/core/scan_policy.dart';

void main() {
  test('HAR metrics use scoped sanitized URL metadata, not content', () {
    final project = SecurityProject(name: 'Test fixture', url: 'https://example.test');
    final raw = jsonEncode({'log': {'entries': [
      {'request': {'method': 'GET', 'url': 'https://example.test/report?secret=private', 'headers': [{'name':'Authorization','value':'private'}]},
        'response': {'status': 503, 'bodySize': 400, 'content': {'text':'private'}}, 'time': 1200},
      {'request': {'method':'GET','url':'https://example.test/a'}, 'response': {'status': 404, 'bodySize': -1}, 'time': -1},
      {'request': {'method':'GET','url':'https://outside.test/a'}, 'response': {'status': 500}, 'time': 2000},
      {'request': {'method':'GET','url':'https://example.test/private/a'}, 'response': {'status': 500}, 'time': 2000},
    ]}});
    final report = HarTrafficAnalyzer.parse(project, ScanPolicy(excludedPaths: ['/private']), raw);
    expect(report.entries.length, 2);
    expect(report.entries.first.route.url.toString(), 'https://example.test/report');
    expect(report.serverErrors, 1);
    expect(report.clientErrors, 1);
    expect(report.slow, 1);
    expect(report.entries.last.responseBytes, isNull);
    expect(report.entries.last.elapsedMs, isNull);
    expect(report.routes.length, 2);
  });
}
