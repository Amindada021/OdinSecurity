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
  const CrawlResult(this.pages, this.failedCount, this.cancelled, [this.stopReason = 'completed', this.files = const []]);
}

/// A deliberately bounded, same-origin HTML traversal. No guessed paths,
/// active exploit payloads, forms, query URLs, or automatic redirects.
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
    ScanPolicy? policy,
    CancellationFlag? cancellation,
    void Function(int count)? onProgress,
    void Function(String tag, String message, String detail)? onEvent,
    CrawlCheckpoint? resumeFrom,
    Future<void> Function(CrawlCheckpoint?)? onCheckpoint,
  }) async {
    if (!authorized || !project.contains(start) || !LinkDiscovery.eligible(start, start) || start.hasFragment) throw StateError('Unauthorized target.');
    final settings = policy ?? ScanPolicy(maxPages: maxPages);
    maxPages = settings.maxPages;
    if (!settings.permits(start)) throw StateError('The start URL is excluded by scan policy.');
    if (auth != null && !SecurityProject.sameOrigin(auth.target, start)) throw StateError('Credential origin mismatch.');
    final identity = auth?.name ?? '';
    resumeFrom?.validate(project, settings, start, identity);
    await cancellation?.waitIfPaused();
    if (cancellation?.cancelled == true) return const CrawlResult([], 0, true, 'cancelled');
    onEvent?.call('INFO', 'Scan running', start.origin);
    final session = auth == null ? null : await Authenticator().authenticate(project, auth, authorized: authorized, permits: settings.permits);
    final queue = Queue<Uri>.of(resumeFrom?.pending ?? [start]);
    final seen = <Uri>{...(resumeFrom?.seen ?? [start])};
    final files = <Uri, Map<String, dynamic>>{};
    final pendingFiles = Queue<Uri>();
    if (moviePurchases.isNotEmpty && (session == null || !session.expectsCredentials)) {
      throw StateError('A signed-in session is required for the movie check.');
    }
    for (final entry in moviePurchases.entries) {
      final url = entry.key;
      if (!LinkDiscovery.safeMediaTarget(start, url) || !project.contains(url) || !settings.permits(url)) {
        throw StateError('Movie URL outside scan scope.');
      }
      files[url] = {'url': url.toString(), 'purchased': entry.value, 'outcome': 'Not checked'};
      pendingFiles.add(url);
    }
    var fileTurn = pendingFiles.isNotEmpty;
    var attempted = resumeFrom?.attempted ?? 0;
    Future<void> checkpoint() async {
      if (onCheckpoint != null) {
        await onCheckpoint(queue.isEmpty || attempted >= maxPages ? null : CrawlCheckpoint(start, identity, seen, queue, attempted));
      }
    }
    await checkpoint();
    final pages = <PassiveScanResult>[];
    var failed = 0;
    var serverErrors = 0;
    var stopReason = 'completed';
    final elapsed = Stopwatch()..start();
    const timeBudget = Duration(minutes: 3);
    Future<void> waitForResume() async {
      if (cancellation?.paused != true) return;
      elapsed.stop();
      await cancellation!.waitIfPaused();
      elapsed.start();
    }
    while ((queue.isNotEmpty || pendingFiles.isNotEmpty) && attempted < maxPages &&
        cancellation?.cancelled != true && elapsed.elapsed < timeBudget) {
      await waitForResume();
      if (cancellation?.cancelled == true || elapsed.elapsed >= timeBudget) break;
      if (attempted > 0) await wait(Duration(milliseconds: settings.delayMs));
      await waitForResume();
      if (cancellation?.cancelled == true || elapsed.elapsed >= timeBudget) break;
      if (pendingFiles.isNotEmpty && (fileTurn || queue.isEmpty)) {
        final file = pendingFiles.removeFirst();
        final row = files[file]!;
        fileTurn = pendingFiles.isNotEmpty && moviePurchases.containsKey(pendingFiles.first);
        attempted++;
        onEvent?.call('SCAN', 'Linked files', file.toString());
        try {
          final check = await checkLinkedFile(file, session, movie: moviePurchases.containsKey(file));
          row['status'] = check.status;
          row['outcome'] = check.outcome;
          onEvent?.call('INFO', check.outcome, file.toString());
          if (check.status == 429) { stopReason = 'rate_limited'; break; }
          serverErrors = check.status >= 500 ? serverErrors + 1 : 0;
          if (serverErrors >= 2) { stopReason = 'server_errors'; break; }
        } catch (_) {
          row['outcome'] = 'Request failed';
        } finally {
          await checkpoint();
        }
        continue;
      }
      final next = queue.removeFirst();
      if (session != null && session.expectsCredentials && session.headersFor(next).isEmpty) {
        queue.addFirst(next);
        stopReason = 'authentication_rejected';
        break;
      }
      attempted++;
      final address = '${next.origin}${next.path}';
      onEvent?.call('SCAN', '', address);
      try {
        final page = await scanner.scanWithSession(project, next, authorized: authorized, session: session);
        pages.add(page);
        onEvent?.call('HTTP', '', '${page.statusCode} $address');
        for (final finding in page.findings) {
          onEvent?.call('FOUND', finding.severity.name, finding.id);
        }
        onProgress?.call(pages.length);
        if (page.statusCode == 429) {
          stopReason = 'rate_limited';
          break;
        }
        serverErrors = page.statusCode >= 500 ? serverErrors + 1 : 0;
        if (serverErrors >= 2) {
          stopReason = 'server_errors';
          break;
        }
        if (page.statusCode == 401 || page.statusCode == 403) {
          if (session != null) { stopReason = 'authentication_rejected'; break; }
        } else if (page.statusCode >= 200 && page.statusCode < 300) {
          for (final file in page.fileLinks) {
            if (files.length >= 100) break;
            if (!SecurityProject.sameOrigin(start, file) || !project.contains(file) ||
                !settings.permits(file) || files.containsKey(file)) continue;
            files[file] = {'url': file.toString(), 'source': address, 'outcome': 'Not checked'};
            pendingFiles.add(file);
          }
          fileTurn = true;
          for (final link in page.links) {
            if (seen.length >= maxPages) break;
            if (!link.hasFragment && LinkDiscovery.eligible(start, link) && project.contains(link) && settings.permits(link) && seen.add(link)) queue.add(link);
          }
        }
      } catch (_) {
        onEvent?.call('WARN', 'Request failed', address);
        failed++;
        onProgress?.call(pages.length);
      } finally {
        await checkpoint();
      }
    }
    if (cancellation?.cancelled == true) stopReason = 'cancelled';
    else if (elapsed.elapsed >= timeBudget && stopReason == 'completed') stopReason = 'time_budget';
    else if (attempted >= maxPages && stopReason == 'completed') stopReason = 'page_budget';
    return CrawlResult(List.unmodifiable(pages), failed, cancellation?.cancelled == true, stopReason, files.values.toList());
  }
}
