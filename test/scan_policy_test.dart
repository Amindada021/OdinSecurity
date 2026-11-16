import 'package:flutter_test/flutter_test.dart';
import 'package:odin_security/core/auth.dart';
import 'package:odin_security/core/crawler.dart';
import 'package:odin_security/core/passive_scan.dart';
import 'package:odin_security/core/project.dart';
import 'package:odin_security/core/scan_policy.dart';
import 'project_storage_test.dart' show MemoryStorage;

class RateLimitedScanner extends PassiveScanner {
  int count = 0;
  @override
  Future<PassiveScanResult> scanWithSession(SecurityProject project, Uri url, {required bool authorized, AuthSession? session}) async {
    count++;
    return PassiveScanResult(url: url, statusCode: 429, links: [url.resolve('/other')], findings: [], technologies: [], bodyTruncated: false, redirectNotFollowed: false);
  }
}
void main() {
  test('prefix exclusions have path segment boundaries and persist', () async {
    final policy = ScanPolicy(maxPages: 4, delayMs: 1500, excludedPaths: ['/payment']);
    expect(policy.permits(Uri.parse('https://example.test/payment/123')), isFalse);
    expect(policy.permits(Uri.parse('https://example.test/payments')), isTrue);
    final repo = ScanPolicyRepository(MemoryStorage());
    await repo.save('fixture', policy);
    expect((await repo.load('fixture')).maxPages, 4);
    expect((await repo.load('fixture')).excludedPaths, ['/payment']);
    expect((await repo.load('other')).excludedPaths, isEmpty);
  });
  test('rate limited response ends crawl without following further links', () async {
    final p = SecurityProject(name: 'fixture', url: 'https://example.test/');
    final scanner = RateLimitedScanner();
    final result = await SiteCrawler(scanner: scanner).run(p, p.startUrl, authorized: true);
    expect(scanner.count, 1);
    expect(result.stopReason, 'rate_limited');
  });
  test('excluded target is rejected before network request', () async {
    final p = SecurityProject(name: 'fixture', url: 'https://example.test/payment');
    final scanner = RateLimitedScanner();
    await expectLater(SiteCrawler(scanner: scanner).run(p, p.startUrl, authorized: true,
      policy: ScanPolicy(excludedPaths: ['/payment'])), throwsStateError);
    expect(scanner.count, 0);
  });
}
