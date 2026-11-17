import 'dart:convert';
import 'dart:io';
import 'package:flutter_test/flutter_test.dart';
import 'package:odin_security/core/auth.dart';
import 'package:odin_security/core/browser_login_policy.dart';
import 'package:odin_security/core/crawl_checkpoint.dart';
import 'package:odin_security/core/crawler.dart';
import 'package:odin_security/core/discovery.dart';
import 'package:odin_security/core/file_access.dart';
import 'package:odin_security/core/history.dart';
import 'package:odin_security/core/passive_scan.dart';
import 'package:odin_security/core/project.dart';
import 'package:odin_security/core/report.dart';
import 'package:odin_security/core/scan_policy.dart';

class FixtureScanner extends PassiveScanner {
  final PassiveScanResult Function(Uri) respond;
  final urls = <Uri>[];
  FixtureScanner(this.respond);
  @override
  Future<PassiveScanResult> scanWithSession(SecurityProject project, Uri url,
      {required bool authorized, AuthSession? session}) async {
    urls.add(url);
    return respond(url);
  }
}

PassiveScanResult page(Uri url, {List<Uri> links = const [], List<Uri> files = const [],
    int status = 200, bool truncated = false, bool login = false, String? retryAfter}) =>
  PassiveScanResult(url: url, statusCode: status, links: links, fileLinks: files,
    findings: const [], technologies: const [], bodyTruncated: truncated,
    redirectNotFollowed: false, loginPage: login, retryAfter: retryAfter);

void main() {
  final project = SecurityProject(name: 'Fixture', url: 'https://example.test/');
  final root = project.startUrl;

  test('truncated HTML prefix retains canonical links, files and safe GET forms', () {
    const body = '<a href="/a/../film#details">film</a><a href="/film">duplicate</a>'
      '<form method="GET" action="/browse"></form><form action="/search"><input name="q"></form>'
      '<form method="POST" action="/post"></form><a href="/guide.pdf">PDF</a>'
      '<img src="/cover.webp"><video><source src="/play.m3u8"></video>'
      '<a href="/export/report">Export</a><a href="/signed.mp4?token=secret">Signed</a>'
      '<script>incomplete';
    expect(LinkDiscovery.extract(root, body).map((u) => u.path), ['/film', '/browse']);
    expect(LinkDiscovery.extract(root, body, files: true).map((u) => u.path),
      ['/guide.pdf', '/cover.webp', '/play.m3u8', '/export/report']);
  });

  test('signed file links are inventoried with query values removed', () {
    final paths = LinkDiscovery.queryFilePaths(root, '<a href="/movie.mp4?token=fixture-secret">Movie</a>');
    expect(paths.single.toString(), 'https://example.test/movie.mp4');
    expect(paths.single.hasQuery, false);
  });

  test('browser snapshot never replays signed URLs or transfers other origins', () {
    final snapshot = jsonEncode({'page': root.toString(), 'rows': [
      {'url': root.resolve('/rendered').toString(), 'file': false},
      {'url': root.resolve('/rendered').toString(), 'file': false},
      {'url': root.resolve('/file.pdf').toString(), 'file': true},
      {'url': root.resolve('/redacted.mp4').toString(), 'file': true, 'query': true},
      {'url': root.resolve('/signed?token=secret').toString(), 'file': true},
      {'url': 'https://example.test:8443/private', 'file': false},
      {'url': 'https://login.example.test/account', 'file': false},
    ]});
    final observed = BrowserLoginPolicy.observedUrls(snapshot, root, root, ScanPolicy());
    expect(observed.routes.map((u) => u.path), ['/rendered']);
    expect(observed.files.map((u) => u.path), ['/file.pdf']);
    expect(observed.queryFiles.map((u) => u.path), ['/redacted.mp4']);
  });

  test('truncated one-page report is incomplete even with zero failures', () async {
    final scanner = FixtureScanner((url) => page(url, truncated: true));
    final result = await SiteCrawler(scanner: scanner, wait: (_) async {}).run(project, root, authorized: true);
    expect(result.failedCount, 0);
    expect(result.coverage['incomplete'], true);
    expect(result.coverage['truncated'], 1);
    expect(result.coverage['warnings'], contains('Scan incomplete; site security has not been established.'));
  });

  test('discovered media is inventory only and budget includes observed routes', () async {
    final media = root.resolve('/film.mp4');
    final scanner = FixtureScanner((url) => page(url, links: [root.resolve('/other')], files: [media]));
    final result = await SiteCrawler(scanner: scanner, wait: (_) async {}).run(project, root,
      authorized: true, policy: ScanPolicy(maxPages: 2), observedRoutes: [root.resolve('/rendered')]);
    expect(scanner.urls, [root, root.resolve('/rendered')]);
    expect(result.files.single['url'], media.toString());
    expect(result.files.single['outcome'], 'Not checked');
    expect(result.coverage['requests'], 2);
    expect(result.coverage['incomplete'], true);
  });

  test('429 stops immediately and preserves Retry-After without retrying', () async {
    final scanner = FixtureScanner((url) => page(url, status: 429, retryAfter: '120'));
    final result = await SiteCrawler(scanner: scanner, wait: (_) async {}).run(project, root,
      authorized: true, observedRoutes: [root.resolve('/next')]);
    expect(scanner.urls, [root]);
    expect(result.stopReason, 'rate_limited');
    expect(result.coverage['retryAfter'], '120');
  });

  test('login HTML cannot validate a marker or an authenticated crawl', () async {
    expect(Authenticator.validationMatches(200, '<form><input type="password">fixture</form>', 'fixture'), false);
    expect(Authenticator.loginRedirect(302, '/account/login?next=/'), true);
    expect(Authenticator.looksLikeLogin('<article>Film</article><dialog><input type="password"></dialog>'), false);
    final scanner = FixtureScanner((url) => page(url, login: true));
    final result = await SiteCrawler(scanner: scanner, wait: (_) async {}).run(project, root,
      authorized: true, auth: AuthProfile(mode: AuthMode.bearer, target: root, secret: 'fixture'));
    expect(result.stopReason, 'authentication_rejected');
  });

  test('checkpoint retains total requests including file and auth requests', () {
    final next = root.resolve('/next');
    final saved = CrawlCheckpoint(root, '', [root, next], [next], 1, requestCount: 4);
    expect(CrawlCheckpoint.fromJson(saved.toJson()).requestCount, 4);
    // Inapplicable cookie paths are processed without sending a request.
    expect(CrawlCheckpoint(root, '', [root, next], [next], 1, requestCount: 0).requestCount, 0);
  });

  test('report roundtrips coverage and escapes file inventory', () {
    final record = ScanRecord.fromPages([page(root, truncated: true)],
      files: [{'url': 'https://example.test/<file>.pdf', 'outcome': 'Not checked'}],
      coverage: {'discovered': 5, 'requests': 1, 'incomplete': true, 'authentication': 'Session not independently verified'});
    final loaded = ScanRecord.fromJson(record.toJson());
    final report = ReportSummary(loaded);
    expect(report.incomplete, true);
    expect(loaded.coverage['discovered'], 5);
    expect(report.exportHtml(), contains('&lt;file&gt;.pdf'));
    expect(report.exportHtml(), contains('Scan incomplete; site security has not been established.'));
    final legacy = record.toJson()..remove('coverage');
    expect(ScanRecord.fromJson(legacy).coverage, isEmpty);
  });

  test('protected validation consumes the only request and does not scan a page', () async {
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    addTearDown(() => server.close(force: true));
    final url = Uri.parse('http://127.0.0.1:${server.port}/');
    final local = SecurityProject(name: 'Loopback', url: url.toString());
    final paths = <String>[];
    server.listen((request) async {
      paths.add(request.uri.path);
      request.response.write('fixture-user');
      await request.response.close();
    });
    final scanner = FixtureScanner((target) => page(target));
    final result = await SiteCrawler(scanner: scanner, wait: (_) async {}).run(local, url,
      authorized: true, policy: ScanPolicy(maxPages: 1),
      auth: AuthProfile(mode: AuthMode.bearer, target: url, secret: 'fixture', allowInsecureHttp: true,
        validationUrl: url.resolve('/protected').toString(), validationMarker: 'fixture-user'));
    expect(paths, ['/protected']);
    expect(scanner.urls, isEmpty);
    expect(result.coverage['requests'], 1);
    expect(result.stopReason, 'page_budget');
    expect(result.coverage['authentication'], 'Session verified by protected URL and expected marker');
  });

  test('file HEAD and media prefix neither follow redirects nor expose credentials to CDN', () async {
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    final cdn = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    addTearDown(() => server.close(force: true));
    addTearDown(() => cdn.close(force: true));
    final url = Uri.parse('http://127.0.0.1:${server.port}/');
    final methods = <String>[], ranges = <String?>[];
    var cdnRequests = 0;
    cdn.listen((request) async { cdnRequests++; await request.response.close(); });
    server.listen((request) async {
      methods.add(request.method);
      ranges.add(request.headers.value('range'));
      request.response.statusCode = 302;
      request.response.headers.set('location', 'http://127.0.0.1:${cdn.port}/video.mp4');
      await request.response.close();
    });
    final session = Authenticator.manual(AuthProfile(mode: AuthMode.bearer, target: url,
      secret: 'fixture', allowInsecureHttp: true));
    expect((await checkLinkedFile(url.resolve('/file.pdf'), session)).outcome, 'Unconfirmed');
    expect((await checkLinkedFile(url.resolve('/video.mp4'), session, movie: true)).outcome, 'Unconfirmed');
    expect(methods, ['HEAD', 'GET']);
    expect(ranges, [null, 'bytes=0-511']);
    expect(cdnRequests, 0);
  });
}
