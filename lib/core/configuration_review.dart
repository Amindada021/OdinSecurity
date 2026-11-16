import 'project.dart';
import 'scan_policy.dart';
import 'tls_audit.dart';
import 'passive_scan.dart';
import 'cors_audit.dart';
import 'security_checks.dart';

class ConfigurationReviewResult {
  final TlsAuditResult tls;
  final PassiveScanResult? page;
  final CorsAuditResult? cors;
  final String stop;
  const ConfigurationReviewResult(this.tls, this.page, this.cors, this.stop);
  List<SecurityFinding> get findings => page?.findings ?? const [];
}

/// Explicitly authorized, anonymous configuration review of a single registered
/// HTTPS route: trusted handshake, one GET and optional fixed CORS preflight.
/// No URL generation, payload mutation, identity guessing or exploit attempts.
class ConfigurationReview {
  final Future<TlsAuditResult> Function(Uri) tls;
  final Future<PassiveScanResult> Function(Uri) read;
  final Future<CorsAuditResult> Function(Uri) preflight;
  final Future<void> Function(Duration) wait;
  ConfigurationReview({required this.tls, required this.read, required this.preflight,
      Future<void> Function(Duration)? wait}) : wait = wait ?? Future<void>.delayed;

  static void validate(SecurityProject project, ScanPolicy policy, Uri target, bool authorized, bool cors) {
    if (!authorized || !project.targets.contains(target) || target.scheme != 'https' ||
        !policy.permits(target) || target.hasQuery || target.hasFragment ||
        target.userInfo.isNotEmpty || target.toString().length > 2048 ||
        policy.maxPages < (cors ? 2 : 1)) throw StateError('Invalid configuration review.');
  }

  Future<ConfigurationReviewResult> run(SecurityProject project, ScanPolicy policy, Uri target,
      {required bool authorized, required bool includeCors, required bool Function() cancelled}) async {
    validate(project, policy, target, authorized, includeCors);
    const notStarted = TlsAuditResult(TlsStatus.unavailable);
    if (cancelled()) return const ConfigurationReviewResult(notStarted, null, null, 'cancelled');
    TlsAuditResult transport;
    try { transport = await tls(target); } catch (_) { return const ConfigurationReviewResult(notStarted, null, null, 'tls_failed'); }
    if (transport.status != TlsStatus.trusted) return ConfigurationReviewResult(transport, null, null, 'tls_failed');
    if (cancelled()) return ConfigurationReviewResult(transport, null, null, 'cancelled');
    await wait(Duration(milliseconds: policy.delayMs));
    if (cancelled()) return ConfigurationReviewResult(transport, null, null, 'cancelled');
    PassiveScanResult page;
    try { page = await read(target); } catch (_) { return ConfigurationReviewResult(transport, null, null, 'read_failed'); }
    if (cancelled()) return ConfigurationReviewResult(transport, page, null, 'cancelled');
    if (!includeCors) return ConfigurationReviewResult(transport, page, null, 'completed');
    if (page.statusCode < 200 || page.statusCode >= 300 || page.redirectNotFollowed) {
      return ConfigurationReviewResult(transport, page, null, 'control_not_successful');
    }
    await wait(Duration(milliseconds: policy.delayMs));
    if (cancelled()) return ConfigurationReviewResult(transport, page, null, 'cancelled');
    try {
      final cors = await preflight(target);
      return ConfigurationReviewResult(transport, page, cors, cancelled() ? 'cancelled' : 'completed');
    } catch (_) { return ConfigurationReviewResult(transport, page, null, 'preflight_failed'); }
  }
}
