import 'fingerprint.dart';
import 'security_checks.dart';
import 'header_policy_checks.dart';
import 'csp_review.dart';
import 'frame_protection_review.dart';

/// Observes the already-received response before user-facing redaction.
/// Findings are fixed configuration messages; raw cookies, URLs, header values
/// and response bodies never appear in the output. No follow-up request.
class ManualResponseReview {
  static const relevantHeaders = {
    'content-type', 'strict-transport-security', 'content-security-policy',
    'content-security-policy-report-only', 'x-frame-options', 'x-content-type-options',
    'referrer-policy', 'permissions-policy', 'x-powered-by', 'x-aspnet-version',
    'access-control-allow-origin', 'access-control-allow-credentials', 'x-debug-token',
    'x-debug-token-link', 'set-cookie', 'cache-control', 'location',
  };

  static List<SecurityFinding> inspect(Uri route, int status, Map<String,List<String>> headers,
      {required bool identityHeadersSent}) {
    if (status < 100 || status > 599) return const [];
    final selected = <String,List<String>>{};
    var size = 0, count = 0;
    for (final entry in headers.entries) {
      final name = entry.key.toLowerCase();
      if (!relevantHeaders.contains(name)) continue;
      for (final value in entry.value) {
        size += value.length;
        count++;
        if (count > 200 || size > 65536 || value.length > 16384) {
          return const [SecurityFinding('manual.review.limit','Header review incomplete',
            Severity.info,'Response header review exceeded processing limits',
            'Review the server configuration manually.')];
        }
        selected.putIfAbsent(name,()=>[]).add(value);
      }
    }
    final observation = HttpObservation(headers:selected,body:'');
    final html = observation.header('content-type').toLowerCase().contains('text/html');
    return List.unmodifiable([
      ...PassiveSecurityChecks().inspect(route, observation),
      ...HeaderPolicyChecks.inspect(route, observation, status:status, identityHeadersSent:identityHeadersSent),
      if (html && status >= 200 && status < 300) ...CspReview.inspect(observation),
      if (status >= 200 && status < 300) ...FrameProtectionReview.inspect(observation),
    ]);
  }
}
