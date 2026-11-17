import 'package:flutter_test/flutter_test.dart';
import 'package:odin_security/core/asset_discovery.dart';
import 'package:odin_security/core/auth.dart';
import 'package:odin_security/core/crawler.dart';
import 'package:odin_security/core/fingerprint.dart';
import 'package:odin_security/core/passive_scan.dart';
import 'package:odin_security/core/project.dart';
import 'package:odin_security/core/scan_policy.dart';

class ContentChain extends PassiveScanner {
  @override
  Future<PassiveScanResult> scanWithSession(SecurityProject project, Uri url,
      {required bool authorized, AuthSession? session}) async {
    final n = int.tryParse(url.pathSegments.lastOrNull ?? '') ?? 0;
    return PassiveScanResult(url: url, statusCode: 200,
      links: n < 40 ? [url.resolve('/page/${n + 1}')] : [], findings: [],
      technologies: [], bodyTruncated: false, redirectNotFollowed: false);
  }
}

void main() {
  test('zero has no request ceiling and finite budgets stop with pending reasons', () async {
    final p = SecurityProject(name: 'Fixture', url: 'https://example.test/');
    final counts = <int>[];
    final unlimited = await SiteCrawler(scanner: ContentChain(), wait: (_) async {}).run(p, p.startUrl,
      authorized: true, policy: ScanPolicy(maxRequests: 0), onRequests: counts.add);
    expect(unlimited.pages.length, 41);
    expect(counts.last, 41);
    final limited = await SiteCrawler(scanner: ContentChain(), wait: (_) async {}).run(p, p.startUrl,
      authorized: true, policy: ScanPolicy(maxRequests: 5));
    expect(limited.pages.length, 5);
    expect(limited.stopReason, 'request_budget');
    expect(limited.coverage['uncheckedRoutes'], isNotEmpty);
  });

  test('HTML, CSS and JavaScript assets preserve provenance and exact origin', () {
    final page = Uri.parse('https://example.test/catalog/');
    final html = AssetDiscovery.fromHtml(page,
      '<link rel="stylesheet" href="/assets/site.css"><script src="/assets/app.js"></script>'
      '<img src="/images/cover.webp"><a href="/guide.pdf">Guide</a>'
      '<a href="https://example.test:8443/secret.pdf">Other port</a>');
    expect(html.map((ref) => ref.kind), containsAll(['stylesheet', 'script', 'image', 'document']));
    expect(html.any((ref) => ref.url.port == 8443), false);
    expect(AssetDiscovery.fromText(page.resolve('/assets/site.css'), 'a{background:url(../images/a.png)}', css: true)
      .single.url.path, '/images/a.png');
    expect(AssetDiscovery.fromText(page, 'const file="/guide.pdf";').single.source, contains('JavaScript'));
  });

  test('technology public roots respect URL mappings and directory evidence', () {
    final root = Uri.parse('https://example.test/');
    final dirs = AssetDiscovery.publicDirectories(root,
      [const TechnologyFinding('ASP.NET Core', TechnologyLayer.backend, Confidence.medium, 'fixture')], []);
    expect(dirs.any((ref) => ref.url.path == '/css/'), true);
    expect(dirs.any((ref) => ref.url.path.contains('wwwroot')), false);
    expect(AssetDiscovery.directoryListing('<title>Index of /assets/</title><a href="a.css">a.css</a>'), true);
    expect(AssetDiscovery.directoryListing('<title>Home</title><a href="/assets/">Assets</a>'), false);
    expect(AssetDiscovery.sensitive(root.resolve('/appsettings.Production.json')), true);
  });
}
