import 'dart:async';
import 'dart:collection';
import 'auth.dart';
import 'asset_discovery.dart';
import 'security_checks.dart';
import 'fingerprint.dart';
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
    int maxPages = 100,
    int? maxRequests,
    Map<Uri, bool> moviePurchases = const {},
    Iterable<Uri> observedRoutes = const [],
    Iterable<Uri> observedFiles = const [],
    Iterable<Uri> observedQueryFilePaths = const [],
    ScanPolicy? policy,
    CancellationFlag? cancellation,
    void Function(int count)? onProgress,
    void Function(int count)? onRequests,
    void Function(String tag, String message, String detail)? onEvent,
    CrawlCheckpoint? resumeFrom,
    Future<void> Function(CrawlCheckpoint?)? onCheckpoint,
  }) async {
    if (!authorized || !project.contains(start) || !LinkDiscovery.eligible(start, start)) {
      throw StateError('Unauthorized target.');
    }
    final settings = policy ?? ScanPolicy(maxRequests: maxRequests ?? maxPages);
    if (!settings.permits(start)) throw StateError('The start URL is excluded by scan policy.');
    if (auth != null && !SecurityProject.sameOrigin(auth.target, start)) throw StateError('Credential origin mismatch.');
    final identity = auth?.name ?? '';
    resumeFrom?.validate(project, settings, start, identity);
    final queue = Queue<Uri>.of(resumeFrom?.pending ?? [start]);
    final seen = <Uri>{...(resumeFrom?.seen ?? [start])};
    final seenCanonical = <Uri>{...seen.map(LinkDiscovery.canonical)};
    final discovered = <Uri>{...seenCanonical};
    final checked = <Uri>{
      if (resumeFrom != null) ...resumeFrom.seen.where((url) => !resumeFrom.pending.contains(url)).map(LinkDiscovery.canonical),
    };
    final skipped = <String, int>{};
    final htmlExclusions = <String, int>{};
    final rejected = <Uri>{};
    final warnings = <String>{};
    final pages = <PassiveScanResult>[];
    final files = <Uri, Map<String, dynamic>>{};
    final pendingFiles = <Uri>[];
    var filesDirty = true;
    final requestKeys = <String>{...(resumeFrom?.requestKeys ?? const <String>[])};
    final uncheckedReasons = <Uri, String>{};
    final directories = <Uri>{};
    final queryPaths = <Uri>{};
    var authTruncated = 0;
    var attempted = resumeFrom?.requestCount ?? 0;
    onRequests?.call(attempted);
    var pageAttempted = resumeFrom?.attempted ?? 0;
    var failed = 0, serverErrors = 0;
    var stopReason = 'completed';
    var authentication = auth == null ? 'No credentials selected' : 'Session not independently verified';
    String? retryAfter;
    AuthSession? session;
    var lastRequestAt = DateTime.fromMillisecondsSinceEpoch(0);

    void skip(Uri url, String reason) {
      uncheckedReasons[url] = reason;
      if (rejected.add(url)) skipped.update(reason, (n) => n + 1, ifAbsent: () => 1);
    }
    bool allowed(Uri url) {
      if (!SecurityProject.sameOrigin(start, url) || !project.contains(url)) { skip(url, 'Outside selected origin'); return false; }
      if (!settings.permits(url)) { skip(url, 'Excluded by scan policy'); return false; }
      if (!LinkDiscovery.safeMediaTarget(start, url)) { skip(url, 'Unsafe or query-bearing URL'); return false; }
      return true;
    }
    void discover(Uri raw, {bool file = false, String source = 'Observed browser route', String? kind, bool directory = false}) {
      final url = LinkDiscovery.canonical(raw);
      discovered.add(url);
      if (!allowed(url)) return;
      if (file || LinkDiscovery.isFile(url) || AssetDiscovery.sensitive(url) || AssetDiscovery.textAsset(url)) {
        if (files.containsKey(url)) {
          if (directory) { files[url]!['directory'] = true; files[url]!['kind'] = 'directory'; }
          return;
        }
        final media = LinkDiscovery.isMedia(url);
        files[url] = {'url': url.toString(), 'source': source,
          'media': media, 'outcome': 'Not checked', 'kind': kind ?? AssetDiscovery.kind(url),
          'directory': directory, 'access': 'Unknown', 'scanContext': auth == null ? 'anonymous' : 'credentialed'};
        // Automatic media probes use HEAD; only owner-supplied samples read bytes.
        pendingFiles.add(url);
        filesDirty = true;
        return;
      }
      if (!LinkDiscovery.eligible(start, url)) { skip(url, 'Not a readable page route'); return; }
      if (!seenCanonical.add(url)) return;
      seen.add(url);
      queue.add(url);
    }
    void inventoryQuery(Uri path) {
      // The caller has already removed query values. Never enqueue this path.
      if (!allowed(path)) return;
      queryPaths.add(path);
    }
    Future<void> checkpoint() async {
      // Checkpoints retain only page traversal. Request count includes every
      // login/validation/file request, so resuming cannot reset the budget.
      await onCheckpoint?.call(queue.isEmpty || settings.exhausted(attempted) || seen.length > 10000 || requestKeys.length > 10000 ? null :
        CrawlCheckpoint(start, identity, seen, queue, pageAttempted, requestCount: attempted, requestKeys: requestKeys.toList()));
    }
    CrawlResult finish() {
      final truncated = pages.where((p) => p.bodyTruncated).length + authTruncated + files.values.where((row) => row['bodyTruncated'] == true).length;
      final fullyChecked = <Uri>{
        for (final page in pages)
          if (page.statusCode >= 200 && page.statusCode < 300 && !page.bodyTruncated && !page.loginPage && !page.redirectNotFollowed) LinkDiscovery.canonical(page.url),
        for (final entry in files.entries)
          if (entry.value['status'] is int && (entry.value['status'] as int) >= 200 &&
              (entry.value['status'] as int) < 300 && entry.value['bodyTruncated'] != true) entry.key,
      };
      final unchecked = discovered.difference(checked).length + queryPaths.length;
      for (final url in discovered.difference(checked)) {
        uncheckedReasons.putIfAbsent(url, () => stopReason != 'completed' ? stopReason : 'Not requested');
      }
      final incomplete = (auth != null && authentication != 'Session verified by protected URL and expected marker') || (pages.isNotEmpty && pages.every((p) => p.links.isEmpty)) || stopReason != 'completed' || failed > 0 || truncated > 0 || unchecked > 0 ||
          warnings.isNotEmpty || pages.any((p) => p.redirectNotFollowed);
      if (truncated > 0) warnings.add('Response body was truncated; coverage is limited.');
      if (pages.length <= 1 && truncated > 0) warnings.add('Scan incomplete; site security has not been established.');
      if (pages.isNotEmpty && pages.every((p) => p.links.isEmpty)) {
        warnings.add('No readable page links found in received HTML; rendered routes may be required.');
      }
      session?.validationResponse = null;
      return CrawlResult(List.unmodifiable(pages), failed, cancellation?.cancelled == true,
        stopReason, [...files.values, for (final path in queryPaths) {
          'url': path.toString(), 'queryRedacted': true, 'outcome': 'Query URL recorded without parameters; not requested',
          'source': 'Observed signed or query-bearing file link', 'media': LinkDiscovery.isMedia(path),
          'kind': AssetDiscovery.kind(path), 'reason': 'Query parameters redacted; URL not replayed',
        }], {
          'incomplete': incomplete, 'discovered': discovered.length + queryPaths.length, 'checked': checked.length,
          'requests': attempted, 'maxRequests': settings.maxRequests, 'unchecked': unchecked, 'skipped': skipped,
          'pagesDiscovered': seen.length, 'pagesChecked': pages.length,
          'scanContext': auth == null || auth.mode == AuthMode.none ? 'anonymous' : 'credentialed',
          'identityLabel': identity, 'sessionVerified': authentication == 'Session verified by protected URL and expected marker',
          'coveragePercent': discovered.isEmpty && queryPaths.isEmpty ? 0 : (fullyChecked.intersection(discovered).length * 100 / (discovered.length + queryPaths.length)),
          'coverageBasis': 'Observed candidate URLs only; not the whole site',
          'uncheckedRoutes': [for (final entry in uncheckedReasons.entries) {'url': entry.key.toString().split('?').first, 'reason': entry.value},
            for (final path in queryPaths) {'url': path.toString(), 'reason': 'Query parameters redacted; URL not replayed'}],
          'htmlExclusions': htmlExclusions, 'truncated': truncated, 'authentication': authentication, 'stopReason': stopReason,
          'warnings': warnings.toList(), if (retryAfter != null) 'retryAfter': retryAfter,
          'inventoryScope': 'Observed queryless URLs only; signed/query URLs are not replayed',
        });
    }
    Future<bool> ready() async {
      await cancellation?.waitIfPaused();
      if (cancellation?.cancelled == true) { stopReason = 'cancelled'; return false; }
      if (settings.exhausted(attempted)) { stopReason = 'request_budget'; return false; }
      final gap = DateTime.now().difference(lastRequestAt).inMilliseconds;
      if (attempted > 0 && gap < settings.delayMs) await wait(Duration(milliseconds: settings.delayMs - gap));
      await cancellation?.waitIfPaused();
      if (cancellation?.cancelled == true) { stopReason = 'cancelled'; return false; }
      return true;
    }
    Future<bool> begin(Uri url, String method, {bool anonymous = false}) async {
      final key = '${anonymous || session == null ? 'anonymous' : 'session'} $method ${LinkDiscovery.canonical(url)}';
      if (requestKeys.contains(key)) return false;
      if (!await ready()) return false;
      requestKeys.add(key);
      attempted++;
      lastRequestAt = DateTime.now();
      checked.add(LinkDiscovery.canonical(url));
      uncheckedReasons.remove(LinkDiscovery.canonical(url));
      onRequests?.call(attempted);
      return true;
    }
    Map<String, dynamic> findingJson(SecurityFinding item) => {
      'id': item.id, 'title': item.title, 'severity': item.severity.name,
      'certainty': item.certainty.name, 'evidence': item.evidence, 'remediation': item.remediation,
    };
    void addReference(AssetReference ref) => discover(ref.url, file: true, source: ref.source, kind: ref.kind, directory: ref.directory);
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
      discovered.add(url);
      files[url] = {'url': url.toString(), 'purchased': entry.value, 'media': true,
        'outcome': 'Not checked', 'kind': 'video', 'access': 'Unknown', 'fullPlaybackVerified': false};
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
            lastRequestAt = DateTime.now();
            onRequests?.call(attempted);
            final url = LinkDiscovery.canonical(authRequests.removeFirst());
            requestKeys.add('session ${auth.isLogin && url.toString() == auth.loginUrl ? 'POST' : 'GET'} $url');
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
    while (queue.isNotEmpty || pendingFiles.isNotEmpty) {
      if (!await ready()) break;
      // Content pages precede assets; explicit owner samples follow the first page.
      int priority(Uri url) {
        final row = files[url]!;
        if (row.containsKey('purchased')) return -1;
        return row['directory'] == true || row['kind'] == 'script' || row['kind'] == 'stylesheet' ? 0 :
          row['kind'] == 'image' || row['kind'] == 'decorative' ? 2 : 1;
      }
      final isFile = pendingFiles.isNotEmpty && (queue.isEmpty ||
          (pages.isNotEmpty && files[pendingFiles.first]!.containsKey('purchased')));
      if (isFile && filesDirty) {
        pendingFiles.sort((a, b) => priority(a).compareTo(priority(b)));
        filesDirty = false;
      }
      final next = isFile ? pendingFiles.removeAt(0) : queue.removeFirst();
      if (!isFile) pageAttempted++;
      if (session?.expectsCredentials == true && session!.headersFor(next).isEmpty) {
        skip(next, 'Outside applicable session path or session expired');
        authentication = 'Credentials do not apply to every discovered route; review session scope or expiry';
        if (isFile) files[next]!['outcome'] = 'Outside session scope';
        await checkpoint();
        continue;
      }
      final movieSample = isFile && files[next]!.containsKey('purchased');
      final validation = session?.validationResponse;
      final cached = !isFile && validation != null && LinkDiscovery.canonical(validation.url) == LinkDiscovery.canonical(next) ? validation : null;
      if (cached == null && !await begin(next, isFile && !movieSample ? 'HEAD' : 'GET')) {
        if (stopReason != 'completed') {
          if (!isFile) { queue.addFirst(next); pageAttempted--; }
          else { pendingFiles.insert(0, next); }
          break;
        }
        await checkpoint();
        continue;
      }
      // URLs in this queue are queryless; no response bodies or credentials are logged.
      final address = '${next.origin}${next.path}';
      onEvent?.call('SCAN', '', address);
      try {
        if (isFile) {
          final row = files[next]!;
          if (movieSample) {
            final check = await checkLinkedFile(next, session, movie: true);
            row['status'] = check.status;
            row['contentType'] = check.contentType;
            row['sizeBytes'] = check.sizeBytes;
            row['outcome'] = check.outcome;
            row['access'] = check.outcome == 'Access denied' ? 'Denied' :
              check.outcome == 'Media bytes returned' ? 'Allowed sample only' : 'Unknown';
            if (responseStops(check.status, retry: check.retryAfter)) break;
          } else {
            final metadata = await inspectAsset(next, session);
            row.addAll({'status': metadata.status, 'outcome': metadata.outcome,
              'contentType': metadata.contentType, 'sizeBytes': metadata.sizeBytes,
              'findings': metadata.findings.map(findingJson).toList(),
              'sessionStatus': session == null ? null : metadata.status});
            if (responseStops(metadata.status, retry: metadata.retryAfter)) break;
            final success = metadata.status >= 200 && metadata.status < 300;
            if (session?.expectsCredentials == true && success) {
              if (await begin(next, 'HEAD', anonymous: true)) {
                final anonymous = await inspectAsset(next, null);
                row['anonymousStatus'] = anonymous.status;
                row['access'] = anonymous.status >= 200 && anonymous.status < 300 &&
                    anonymous.contentType == metadata.contentType && !anonymous.contentType.contains('html')
                  ? 'Public metadata' : [401, 403].contains(anonymous.status) || anonymous.loginPage
                    ? 'Session-only metadata' : 'Unknown';
                if (responseStops(anonymous.status, retry: anonymous.retryAfter)) break;
              } else if (stopReason != 'completed') {
                row['reason'] = 'Anonymous comparison not performed: $stopReason';
                uncheckedReasons[next] = row['reason'] as String;
              }
            } else {
              if (session?.expectsCredentials != true) row['anonymousStatus'] = metadata.status;
              row['access'] = session?.expectsCredentials != true && success && !metadata.contentType.contains('html') ? 'Public metadata' :
                metadata.outcome == 'Access denied' ? 'Denied' : 'Unknown';
            }
            final inspectText = row['directory'] == true || row['kind'] == 'script' || row['kind'] == 'stylesheet';
            if (inspectText && (success || metadata.status == 405 || metadata.status == 501)) {
              if (await begin(next, 'GET')) {
                final text = await inspectAsset(next, session, readText: true);
                row['textStatus'] = text.status;
                row['headStatus'] = row['status'];
                row['status'] = text.status;
                if (!success) { row['contentType'] = text.contentType; row['sizeBytes'] = text.sizeBytes; }
                row['outcome'] = text.outcome;
                row['bodyTruncated'] = text.truncated;
                row['directoryListing'] = text.listing;
                row['findings'] = {for (final finding in [...metadata.findings, ...text.findings]) finding.id: findingJson(finding)}.values.toList();
                if (text.truncated) warnings.add('Asset text response truncated; referenced assets may be missing.');
                if (responseStops(text.status, retry: text.retryAfter)) break;
                for (final ref in text.references) { addReference(ref); }
                for (final link in text.pageLinks) { discover(link, source: 'Directory index: ${next.path}'); }
                if (session?.expectsCredentials == true && text.loginPage) {
                  authentication = 'Sign-in page or login redirect received';
                  stopReason = 'authentication_rejected';
                  break;
                }
              } else if (stopReason != 'completed') {
                row['reason'] = 'Referenced text not inspected: $stopReason';
                uncheckedReasons[next] = row['reason'] as String;
              }
            }
          }
        } else {
          final page = cached == null
              ? await scanner.scanWithSession(project, next, authorized: authorized, session: session)
              : scanner.inspectObservation(next, HttpObservation(headers: cached.headers, body: cached.body),
                  statusCode: cached.status, truncated: false, bodyBytes: cached.byteCount, identityHeadersSent: true);
          if (cached != null) session?.validationResponse = null;
          pages.add(page);
          if (page.assets.length >= 1000 || page.links.length >= 1000 || page.fileLinks.length >= 100 ||
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
            for (final ref in page.assets) { addReference(ref); }
            for (final ref in AssetDiscovery.publicDirectories(next, page.technologies, page.assets)) {
              if (directories.add(ref.url)) addReference(ref);
            }
            for (final link in page.links) { discover(link, source: address); }
            for (final file in page.fileLinks) { discover(file, file: true, source: address); }
            for (final path in page.queryFilePaths) { inventoryQuery(path); }
            if (page.bodyTruncated) onEvent?.call('WARN', 'Response body was truncated; coverage is limited.', address);
          }
        }
      } catch (_) {
        failed++;
        if (isFile) files[next]!['outcome'] = 'Request failed';
        uncheckedReasons[next] = 'Request failed';
        onEvent?.call('WARN', 'Request failed', address);
      } finally { await checkpoint(); }
    }
    await checkpoint();
    return finish();
  }
}
