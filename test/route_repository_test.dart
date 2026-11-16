import 'package:flutter_test/flutter_test.dart';
import 'package:odin_security/core/project.dart';
import 'package:odin_security/core/route_inventory.dart';
import 'package:odin_security/core/route_repository.dart';
import 'package:odin_security/core/scan_policy.dart';
import 'project_storage_test.dart' show MemoryStorage;

void main() {
  test('saved routes are deduplicated, stripped and scoped again after edits', () async {
    final repository = RouteRepository(MemoryStorage());
    final project = SecurityProject(name: 'Fixture', url: 'https://example.test',
      additionalUrls: ['https://api.example.test']);
    final policy = ScanPolicy();
    await repository.save(project, policy, [
      RouteObservation(Uri.parse('https://api.example.test/report?token=secret'), 'GET'),
      RouteObservation(Uri.parse('https://api.example.test/report'), 'GET'),
      RouteObservation(Uri.parse('https://example.test/private'), 'POST'),
      RouteObservation(Uri.parse('https://other.test/'), 'GET'),
    ]);
    final records = await repository.load(project, policy);
    expect(records.length, 2);
    expect(records.first.url.hasQuery, isFalse);
    final edited = SecurityProject(id: project.id, name: project.name, url: project.startUrl.toString());
    expect((await repository.load(edited, policy)).single.source, 'POST');
    expect(await repository.load(edited, ScanPolicy(excludedPaths: ['/private'])), isEmpty);
  });
  test('only known read-only routes open inspector', () {
    for (final source in ['POST','DELETE','fetch','xmlhttprequest','form-get','form-post','script']) {
      expect(RouteRepository.canOpenInspector(RouteObservation(Uri.parse('https://example.test/report'), source)), isFalse);
    }
    expect(RouteRepository.canOpenInspector(RouteObservation(Uri.parse('https://example.test/report'), 'GET')), isTrue);
    expect(RouteRepository.canOpenInspector(RouteObservation(Uri.parse('https://example.test/delete'), 'GET')), isFalse);
  });
}
