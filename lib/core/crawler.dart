import 'dart:collection';
import 'auth.dart';
import 'discovery.dart';
import 'passive_scan.dart';
import 'project.dart';
import 'scan_policy.dart';

class CancellationFlag {
  bool cancelled = false;
  void cancel() => cancelled = true;
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
  SiteCrawler({PassiveScanner? scanner}) : scanner = scanner ?? PassiveScanner();

  Future<CrawlResult> run(SecurityProject project, Uri start, {
    required bool authorized,
    AuthProfile? auth,
    int maxPages = 12,
    ScanPolicy? policy,
    CancellationFlag? cancellation,
    void Function(int count)? onProgress,
  }) async {
    if (!authorized || !project.contains(start)) throw StateError('Unauthorized target.');
    final settings = policy ?? ScanPolicy(maxPages: maxPages);
    maxPages = settings.maxPages;
    if (!settings.permits(start)) throw StateError('The start URL is excluded by scan policy.');
    if (auth != null && !SecurityProject.sameOrigin(auth.target, start)) throw StateError('Credential origin mismatch.');
    if (cancellation?.cancelled == true) return const CrawlResult([], 0, true, 'cancelled');
    final session = auth == null ? null : await Authenticator().authenticate(project, auth, authorized: authorized);
    final queue = Queue<Uri>()..add(start);
    final seen = <Uri>{start};
    final pages = <PassiveScanResult>[];
    var failed = 0;
    var serverErrors = 0;
    var stopReason = 'completed';
    final deadline = DateTime.now().add(const Duration(minutes: 3));
    while (queue.isNotEmpty && pages.length + failed < maxPages &&
        cancellation?.cancelled != true && DateTime.now().isBefore(deadline)) {
      final next = queue.removeFirst();
      if (pages.isNotEmpty || failed > 0) await Future<void>.delayed(Duration(milliseconds: settings.delayMs));
      if (cancellation?.cancelled == true || !DateTime.now().isBefore(deadline)) break;
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
    else if (!DateTime.now().isBefore(deadline) && stopReason == 'completed') stopReason = 'time_budget';
    else if (pages.length + failed >= maxPages && stopReason == 'completed') stopReason = 'page_budget';
    return CrawlResult(List.unmodifiable(pages), failed, cancellation?.cancelled == true, stopReason);
  }
}
