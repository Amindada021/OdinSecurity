import 'dart:async';
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
  test('pauses and resumes between requests without repeating first page', () async {
    final project = SecurityProject(name: 'Fixture', url: 'https://example.test');
    final fake = FakeScanner();
    final flag = CancellationFlag();
    final paused = Completer<void>();
    final future = SiteCrawler(scanner: fake, wait: (_) async {}).run(project, project.startUrl,
      authorized: true, cancellation: flag, maxPages: 3, onProgress: (count) {
        if (count == 1) { flag.pause(); paused.complete(); }
      });
    await paused.future;
    await Future<void>.delayed(Duration.zero);
    expect(fake.urls, [project.startUrl]);
    flag.resume();
    final report = await future;
    expect(report.pages.length, 2);
    expect(fake.urls, [project.startUrl, project.startUrl.resolve('/about')]);
  });
  test('cancel wakes a paused crawl and sends no more requests', () async {
    final project = SecurityProject(name: 'Fixture', url: 'https://example.test');
    final fake = FakeScanner();
    final flag = CancellationFlag();
    final paused = Completer<void>();
    final future = SiteCrawler(scanner: fake, wait: (_) async {}).run(project, project.startUrl,
      authorized: true, cancellation: flag, onProgress: (count) {
        if (count == 1) { flag.pause(); paused.complete(); }
      });
    await paused.future;
    flag.cancel();
    final report = await future;
    expect(report.cancelled, true);
    expect(fake.urls.length, 1);
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
