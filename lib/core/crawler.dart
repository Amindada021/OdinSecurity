import 'dart:collection';
import 'auth.dart';
import 'discovery.dart';
import 'passive_scan.dart';
import 'project.dart';

class CancellationFlag {
  bool cancelled = false;
  void cancel() => cancelled = true;
}

class CrawlResult {
  final List<PassiveScanResult> pages;
  final int failedCount;
  final bool cancelled;
  const CrawlResult(this.pages, this.failedCount, this.cancelled);
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
    CancellationFlag? cancellation,
    void Function(int count)? onProgress,
  }) async {
    if (!authorized || !project.contains(start)) throw StateError('Unauthorized target.');
    if (maxPages < 1 || maxPages > 30) throw ArgumentError.value(maxPages);
    if (auth != null && !SecurityProject.sameOrigin(auth.target, start)) throw StateError('Credential origin mismatch.');
    if (cancellation?.cancelled == true) return const CrawlResult([], 0, true);
    final session = auth == null ? null : await Authenticator().authenticate(project, auth, authorized: authorized);
    final queue = Queue<Uri>()..add(start);
    final seen = <Uri>{start};
    final pages = <PassiveScanResult>[];
    var failed = 0;
    final deadline = DateTime.now().add(const Duration(minutes: 3));
    while (queue.isNotEmpty && pages.length + failed < maxPages &&
        cancellation?.cancelled != true && DateTime.now().isBefore(deadline)) {
      final next = queue.removeFirst();
      if (pages.isNotEmpty || failed > 0) await Future<void>.delayed(const Duration(seconds: 1));
      if (cancellation?.cancelled == true) break;
      try {
        final page = await scanner.scanWithSession(project, next, authorized: authorized, session: session);
        pages.add(page);
        if (page.statusCode == 401 || page.statusCode == 403) {
          if (session != null) break;
        } else if (page.statusCode >= 200 && page.statusCode < 300) {
          for (final link in page.links) {
            if (seen.length >= maxPages) break;
            if (LinkDiscovery.eligible(start, link) && project.contains(link) && seen.add(link)) queue.add(link);
          }
        }
      } catch (_) {
        failed++;
      }
      onProgress?.call(pages.length + failed);
    }
    return CrawlResult(List.unmodifiable(pages), failed, cancellation?.cancelled == true);
  }
}
