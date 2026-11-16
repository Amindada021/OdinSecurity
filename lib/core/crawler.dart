import 'dart:async';
import 'dart:collection';
import 'auth.dart';
import 'discovery.dart';
import 'passive_scan.dart';
import 'project.dart';
import 'scan_policy.dart';

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
  const CrawlResult(this.pages, this.failedCount, this.cancelled, [this.stopReason = 'completed']);
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
    ScanPolicy? policy,
    CancellationFlag? cancellation,
    void Function(int count)? onProgress,
  }) async {
    if (!authorized || !project.contains(start) || !LinkDiscovery.eligible(start, start) || start.hasFragment) throw StateError('Unauthorized target.');
    final settings = policy ?? ScanPolicy(maxPages: maxPages);
    maxPages = settings.maxPages;
    if (!settings.permits(start)) throw StateError('The start URL is excluded by scan policy.');
    if (auth != null && !SecurityProject.sameOrigin(auth.target, start)) throw StateError('Credential origin mismatch.');
    await cancellation?.waitIfPaused();
    if (cancellation?.cancelled == true) return const CrawlResult([], 0, true, 'cancelled');
    final session = auth == null ? null : await Authenticator().authenticate(project, auth, authorized: authorized, permits: settings.permits);
    final queue = Queue<Uri>()..add(start);
    final seen = <Uri>{start};
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
    while (queue.isNotEmpty && pages.length + failed < maxPages &&
        cancellation?.cancelled != true && elapsed.elapsed < timeBudget) {
      await waitForResume();
      if (cancellation?.cancelled == true || elapsed.elapsed >= timeBudget) break;
      if (pages.isNotEmpty || failed > 0) await wait(Duration(milliseconds: settings.delayMs));
      await waitForResume();
      if (cancellation?.cancelled == true || elapsed.elapsed >= timeBudget) break;
      final next = queue.removeFirst();
      if (session != null && session.expectsCredentials && session.headersFor(next).isEmpty) {
        stopReason = 'authentication_rejected';
        break;
      }
      try {
        final page = await scanner.scanWithSession(project, next, authorized: authorized, session: session);
        pages.add(page);
        onProgress?.call(pages.length + failed);
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
          for (final link in page.links) {
            if (seen.length >= maxPages) break;
            if (LinkDiscovery.eligible(start, link) && project.contains(link) && settings.permits(link) && seen.add(link)) queue.add(link);
          }
        }
      } catch (_) {
        failed++;
        onProgress?.call(pages.length + failed);
      }
    }
    if (cancellation?.cancelled == true) stopReason = 'cancelled';
    else if (elapsed.elapsed >= timeBudget && stopReason == 'completed') stopReason = 'time_budget';
    else if (pages.length + failed >= maxPages && stopReason == 'completed') stopReason = 'page_budget';
    return CrawlResult(List.unmodifiable(pages), failed, cancellation?.cancelled == true, stopReason);
  }
}
