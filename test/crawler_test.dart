import 'package:flutter_test/flutter_test.dart';
import 'package:odin_security/core/auth.dart';
import 'package:odin_security/core/crawler.dart';
import 'package:odin_security/core/passive_scan.dart';
import 'package:odin_security/core/project.dart';

class FakeScanner extends PassiveScanner {
  final urls = <Uri>[];
  @override
  Future<PassiveScanResult> scanWithSession(SecurityProject project, Uri url, {required bool authorized, AuthSession? session}) async {
    urls.add(url);
    return PassiveScanResult(url: url, statusCode: 200, links: [url.resolve('/about'), Uri.parse('https://other.test/a')], findings: [], technologies: [], bodyTruncated: false, redirectNotFollowed: false);
  }
}

void main() {
  test('page cap and scope prevent further requests', () async {
    final project = SecurityProject(name: 'Fixture', url: 'https://example.test');
    final fake = FakeScanner();
    final result = await SiteCrawler(scanner: fake).run(project, project.startUrl, authorized: true, maxPages: 1);
    expect(result.pages.length, 1);
    expect(fake.urls, [project.startUrl]);
  });
  test('pre-cancelled crawl does not fetch', () async {
    final project = SecurityProject(name: 'Fixture', url: 'https://example.test');
    final fake = FakeScanner();
    final flag = CancellationFlag()..cancel();
    final result = await SiteCrawler(scanner: fake).run(project, project.startUrl, authorized: true, cancellation: flag);
    expect(result.cancelled, isTrue);
    expect(fake.urls, isEmpty);
  });
}
