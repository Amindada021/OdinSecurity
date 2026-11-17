import 'dart:async';
import 'dart:collection';
import 'auth.dart';
import 'file_access.dart';
import 'discovery.dart';
import 'passive_scan.dart';
import 'project.dart';
import 'scan_policy.dart';
import 'crawl_checkpoint.dart';

/// Cooperative job control. Pause/cancel take effect between HTTP calls.
/// Cancelling a paused job also wakes its pending wait.
class CancellationFlag {
  bool _cancelled = false;
  Completer<void>? _pause;
  bool get cancelled => _cancelled;
  bool get paused => _pause != null;

  void pause() {
    if (!_cancelled) _pause ??= Completer<void>();
  }

  void resume() {
    final pending = _pause;
    _pause = null;
    pending?.complete();
  }

  void cancel() {
    _cancelled = true;
    resume();
  }

  Future<void> waitIfPaused() async {
    while (!_cancelled && _pause != null) {
      await _pause!.future;
    }
  }
}

class CrawlResult {
  final List<PassiveScanResult> pages;
  final int failedCount;
  final bool cancelled;
  final String stopReason;
  final List<Map<String, dynamic>> files;
  final Map<String, dynamic> coverage;
  const CrawlResult(this.pages, this.failedCount, this.cancelled,
      [this.stopReason = 'completed', this.files = const [], this.coverage = const {}]);
}

/// Bounded, sequential, read-only traversal of observed same-origin routes.
class SiteCrawler {
  final PassiveScanner scanner;
  final Future<void> Function(Duration) wait;
  SiteCrawler({PassiveScanner? scanner, Future<void> Function(Duration)? wait})
    : scanner = scanner ?? PassiveScanner(),
      wait = wait ?? ((duration) => Future<void>.delayed(duration));

  Future<CrawlResult> run(SecurityProject project, Uri start, {
    required bool authorized,
    AuthProfile? auth,
    int maxPages = 12,
    Map<Uri, bool> moviePurchases = const {},
    Iterable<Uri> observedRoutes = const [],
    Iterable<Uri> observedFiles = const [],
    Iterable<Uri> observedQueryFilePaths = const [],
    ScanPolicy? policy,
    CancellationFlag? cancellation,
    void Function(int count)? onProgress,
    void Function(String tag, String message, String detail)? onEvent,
    CrawlCheckpoint? resumeFrom,
    Future<void> Function(CrawlCheckpoint?)? onCheckpoint,
  }) async {
    if (!authorized || !project.contains(start) || !LinkDiscovery.eligible(start, start)) {
      throw StateError('Unauthorized target.');
    }
    final settings = policy ?? ScanPolicy(maxPages: maxPages);
    maxPages = settings.maxPages;
    if (!settings.permits(start)) throw StateError('The start URL is excluded by scan policy.');
    if (auth != null && !SecurityProject.sameOrigin(auth.target, start)) throw StateError('Credential origin mismatch.');
    final identity = auth?.name ?? '';
    resumeFrom?.validate(project, settings, start, identity);
    final queue = Queue<Uri>.of(resumeFrom?.pending ?? [start]);
    final seen = <Uri>{...(resumeFrom?.seen ?? [start])};
    final discovered = <Uri>{...seen.map(LinkDiscovery.canonical)};
    final checked = <Uri>{
      if (resumeFrom != null) ...resumeFrom.seen.where((url) => !resumeFrom.pending.contains(url)).map(LinkDiscovery.canonical),
    };
    final skipped = <String, int>{};
    final htmlExclusions = <String, int>{};
    final rejected = <Uri>{};
    final warnings = <String>{};
    final pages = <PassiveScanResult>[];
    final files = <Uri, Map<String, dynamic>>{};
    final pendingFiles = Queue<Uri>();
    final queryPaths = <Uri>{};
    var authTruncated = 0;
    var attempted = resumeFrom?.requestCount ?? 0;
    var pageAttempted = resumeFrom?.attempted ?? 0;
    var failed = 0, serverErrors = 0;
    var stopReason = 'completed';
    var authentication = auth == null ? 'No credentials selected' : 'Session not independently verified';
    String? retryAfter;
    AuthSession? session;
    final elapsed = Stopwatch()..start();
    const timeBudget = Duration(minutes: 3);

    void skip(Uri url, String reason) {
      if (rejected.add(url)) skipped.update(reason, (n) => n + 1, ifAbsent: () => 1);
    }
    bool allowed(Uri url) {
      if (!SecurityProject.sameOrigin(start, url) || !project.contains(url)) { skip(url, 'Outside selected origin'); return false; }
      if (!settings.permits(url)) { skip(url, 'Excluded by scan policy'); return false; }
      if (!LinkDiscovery.safeMediaTarget(start, url)) { skip(url, 'Unsafe or query-bearing URL'); return false; }
      return true;
    }
    void discover(Uri raw, {bool file = false, String source = 'Observed browser route'}) {
      final url = LinkDiscovery.canonical(raw);
      if (discovered.length >= 1000 && !discovered.contains(url)) {
        warnings.add('Discovery inventory limit reached');
        return;
      }
      discovered.add(url);
      if (!allowed(url)) return;
      if (file || LinkDiscovery.isFile(url)) {
        if (files.containsKey(url)) return;
        if (files.length + queryPaths.length >= 100) { skip(url, 'File inventory limit'); return; }
        final media = LinkDiscovery.isMedia(url);
        files[url] = {'url': url.toString(), 'source': source,
          'media': media, 'outcome': 'Not checked'};
        // Unknown download routes may also be media: automatic discovery is
        // inventory only. Only explicit movie samples are fetched as media.
        if (!media && !RegExp(r'(^|/)(download|export)(/|$)', caseSensitive: false).hasMatch(url.path)) {
          pendingFiles.add(url);
        }
        return;
      }
      if (!LinkDiscovery.eligible(start, url)) { skip(url, 'Not a readable page route'); return; }
      if (seen.contains(url) || seen.any((item) => LinkDiscovery.canonical(item) == url)) return;
      if (seen.length >= maxPages) { skip(url, 'Page queue limit'); return; }
      seen.add(url);
      queue.add(url);
    }
    void inventoryQuery(Uri path) {
      // The caller has already removed query values. Never enqueue this path.
      if (queryPaths.length + files.length >= 100) { warnings.add('File inventory limit reached'); return; }
      if (!allowed(path)) return;
      queryPaths.add(path);
    }
    Future<void> checkpoint() async {
      // Checkpoints retain only page traversal. Request count includes every
      // login/validation/file request, so resuming cannot reset the budget.
      await onCheckpoint?.call(queue.isEmpty || attempted >= maxPages ? null :
        CrawlCheckpoint(start, identity, seen, queue, pageAttempted, requestCount: attempted));
    }
    CrawlResult finish() {
      final truncated = pages.where((p) => p.bodyTruncated).length + authTruncated;
      final unchecked = discovered.difference(checked).length + queryPaths.length;
      final incomplete = (auth != null && authentication != 'Session verified by protected URL and expected marker') || (pages.isNotEmpty && pages.every((p) => p.links.isEmpty)) || stopReason != 'completed' || failed > 0 || truncated > 0 || unchecked > 0 ||
          warnings.isNotEmpty || pages.any((p) => p.redirectNotFollowed);
      if (truncated > 0) warnings.add('Response body was truncated; coverage is limited.');
      if (pages.length <= 1 && truncated > 0) warnings.add('Scan incomplete; site security has not been established.');
      if (pages.isNotEmpty && pages.every((p) => p.links.isEmpty)) {
        warnings.add('No readable page links found in received HTML; rendered routes may be required.');
      }
      return CrawlResult(List.unmodifiable(pages), failed, cancellation?.cancelled == true,
        stopReason, [...files.values, for (final path in queryPaths) {
          'url': path.toString(), 'queryRedacted': true, 'outcome': 'Query URL recorded without parameters; not requested',
          'source': 'Observed signed or query-bearing file link', 'media': LinkDiscovery.isMedia(path),
        }], {
          'incomplete': incomplete, 'discovered': discovered.length + queryPaths.length, 'checked': checked.length,
          'requests': attempted, 'unchecked': unchecked, 'skipped': skipped,
          'htmlExclusions': htmlExclusions, 'truncated': truncated, 'authentication': authentication, 'stopReason': stopReason,
          'warnings': warnings.toList(), if (retryAfter != null) 'retryAfter': retryAfter,
          'inventoryScope': 'Observed queryless URLs only; signed/query URLs are not replayed',
        });
    }
    Future<bool> ready() async {
      if (cancellation?.paused == true) {
        elapsed.stop(); await cancellation!.waitIfPaused(); elapsed.start();
      }
      if (cancellation?.cancelled == true) { stopReason = 'cancelled'; return false; }
      if (elapsed.elapsed >= timeBudget) { stopReason = 'time_budget'; return false; }
      if (attempted >= maxPages) { stopReason = 'page_budget'; return false; }
      if (attempted > 0) await wait(Duration(milliseconds: settings.delayMs));
      if (cancellation?.paused == true) {
        elapsed.stop(); await cancellation!.waitIfPaused(); elapsed.start();
      }
      if (cancellation?.cancelled == true) { stopReason = 'cancelled'; return false; }
      if (elapsed.elapsed >= timeBudget) { stopReason = 'time_budget'; return false; }
      return true;
    }
    bool responseStops(int status, {String? retry}) {
      if (status == 429) {
        retryAfter = retry;
        stopReason = 'rate_limited';
        warnings.add('Rate limited; no retries were sent. Respect Retry-After before starting another scan.');
        return true;
      }
      serverErrors = status >= 500 ? serverErrors + 1 : 0;
      if (serverErrors >= 2) { stopReason = 'server_errors'; return true; }
      return false;
    }

    for (final entry in moviePurchases.entries) {
      final url = LinkDiscovery.canonical(entry.key);
      if (!allowed(url)) throw StateError('Movie URL outside scan scope.');
      if (files.containsKey(url)) {
        if (files[url]!['purchased'] != entry.value) throw StateError('Conflicting movie sample groups.');
        continue;
      }
      if (files.length >= 30) throw StateError('Too many movie samples.');
      discovered.add(url);
      files[url] = {'url': url.toString(), 'purchased': entry.value, 'media': true,
        'outcome': 'Not checked', 'access': 'Unknown', 'fullPlaybackVerified': false};
      pendingFiles.add(url);
    }
    if (moviePurchases.isNotEmpty && (auth == null || auth.mode == AuthMode.none)) {
      throw StateError('A signed-in session is required for the movie check.');
    }
    for (final route in observedRoutes) { discover(route); }
    for (final file in observedFiles) { discover(file, file: true); }
    for (final path in observedQueryFilePaths) { inventoryQuery(path); }
    if (auth != null) {
      final authRequests = Queue<Uri>.of([
        if (auth.isLogin) Uri.parse(auth.loginUrl),
        if (auth.validationUrl.isNotEmpty) Uri.parse(auth.validationUrl),
      ]);
      try {
        session = await Authenticator().authenticate(project, auth, authorized: authorized,
          permits: settings.permits, beforeRequest: () async {
            if (!await ready()) throw const AuthenticationException('Request budget or job control stopped authentication');
            attempted++;
            final url = LinkDiscovery.canonical(authRequests.removeFirst());
            discovered.add(url);
            checked.add(url);
          });
        authentication = session.verification;
      } on AuthenticationException catch (e) {
        authentication = e.reason;
        if (e.reason == 'Protected URL response truncated; session unverified') authTruncated++;
        if (e.reason == 'rate_limited') { responseStops(429, retry: e.retryAfter); }
        else if (stopReason == 'completed') { stopReason = 'authentication_rejected'; }
        await checkpoint();
        return finish();
      } catch (_) {
        authentication = 'Authentication request failed; session unverified';
        stopReason = 'authentication_rejected';
        failed++;
        await checkpoint();
        return finish();
      }
    }
    await checkpoint();
    var fileTurn = false;
    while (queue.isNotEmpty || pendingFiles.isNotEmpty) {
      if (!await ready()) break;
      final isFile = pendingFiles.isNotEmpty && (fileTurn || queue.isEmpty);
      final next = isFile ? pendingFiles.removeFirst() : queue.removeFirst();
      fileTurn = !isFile;
      if (!isFile) pageAttempted++;
      if (session?.expectsCredentials == true && session!.headersFor(next).isEmpty) {
        skip(next, 'Outside applicable session path or session expired');
        authentication = 'Credentials do not apply to every discovered route; review session scope or expiry';
        if (isFile) files[next]!['outcome'] = 'Outside session scope';
        await checkpoint();
        continue;
      }
      attempted++;
      checked.add(LinkDiscovery.canonical(next));
      // URLs in this queue are queryless; no response bodies or credentials are logged.
      final address = '${next.origin}${next.path}';
      onEvent?.call('SCAN', '', address);
      try {
        if (isFile) {
          final row = files[next]!;
          final movie = row.containsKey('purchased');
          final check = await checkLinkedFile(next, session, movie: movie);
          row['status'] = check.status;
          row['outcome'] = check.outcome;
          if (movie) row['access'] = check.outcome == 'Access denied' ? 'Denied' :
            check.outcome == 'Media bytes returned' ? 'Allowed sample only' : 'Unknown';
          if (responseStops(check.status, retry: check.retryAfter)) break;
        } else {
          final page = await scanner.scanWithSession(project, next, authorized: authorized, session: session);
          pages.add(page);
          if (page.links.length >= 300 || page.fileLinks.length >= 100 ||
              page.queryFilePaths.length >= 100 || page.discoveryExclusions.containsKey('HTML discovery inspection limit')) {
            warnings.add('Discovery inventory limit reached');
          }
          for (final entry in page.discoveryExclusions.entries) {
            htmlExclusions.update(entry.key, (n) => n + entry.value, ifAbsent: () => entry.value);
          }
          onEvent?.call('HTTP', '', '${page.statusCode} $address');
          for (final finding in page.findings) { onEvent?.call('FOUND', finding.severity.name, finding.id); }
          onProgress?.call(pages.length);
          if (responseStops(page.statusCode, retry: page.retryAfter)) break;
          if (session?.expectsCredentials == true &&
              (page.statusCode == 401 || page.statusCode == 403 || page.loginPage)) {
            authentication = page.loginPage ? 'Sign-in page or login redirect received' : 'Access rejected (HTTP ${page.statusCode})';
            stopReason = 'authentication_rejected';
            break;
          }
          if (page.statusCode >= 200 && page.statusCode < 300 && !page.loginPage) {
            for (final link in page.links) { discover(link, source: address); }
            for (final file in page.fileLinks) { discover(file, file: true, source: address); }
            for (final path in page.queryFilePaths) { inventoryQuery(path); }
            if (page.bodyTruncated) onEvent?.call('WARN', 'Response body was truncated; coverage is limited.', address);
          }
        }
      } catch (_) {
        failed++;
        if (isFile) files[next]!['outcome'] = 'Request failed';
        onEvent?.call('WARN', 'Request failed', address);
      } finally { await checkpoint(); }
    }
    await checkpoint();
    return finish();
  }
}
