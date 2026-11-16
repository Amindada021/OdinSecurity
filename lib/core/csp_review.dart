import 'fingerprint.dart';
import 'security_checks.dart';

/// Conservative passive signals from a single enforcing policy. Multiple or
/// malformed policies are reported for review rather than merged incorrectly.
class CspReview {
  static List<SecurityFinding> inspect(HttpObservation observation) {
    final values = observation.headers['content-security-policy'] ?? const <String>[];
    if (values.isEmpty) {
      if (observation.header('content-security-policy-report-only').isNotEmpty) {
        return const [SecurityFinding('csp.report.only', 'Only report-only CSP observed', Severity.info,
          'An enforcing CSP header was not observed; policy contents omitted',
          'Verify whether an enforcing policy is appropriate. Report-only policies do not enforce restrictions.')];
      }
      return const [];
    }
    final findings = <SecurityFinding>[];
    if (values.length != 1 || values.single.length > 16384 || values.single.contains(',')) {
      return const [SecurityFinding('csp.multiple.review', 'Multiple or complex CSP policies require review', Severity.info,
        'Policy combination not evaluated; values omitted', 'Review effective restrictions across all enforcing policies.')];
    }
    final directives = <String, List<String>>{};
    var duplicate = false;
    for (final segment in values.single.split(';')) {
      final tokens = segment.trim().split(RegExp(r'\s+')).where((t) => t.isNotEmpty).toList();
      if (tokens.isEmpty) continue;
      final name = tokens.first.toLowerCase();
      if (directives.containsKey(name)) { duplicate = true; continue; }
      directives[name] = tokens.skip(1).toList();
    }
    if (duplicate) findings.add(const SecurityFinding('csp.duplicate.directive', 'Duplicate CSP directive observed', Severity.info,
      'An enforcing policy repeats a directive; values omitted', 'Review policy ordering and remove ambiguous duplicate directives.'));
    final scripts = directives['script-src-elem'] ?? directives['script-src'] ?? directives['default-src'];
    if (scripts != null) {
      final lower = scripts.map((s) => s.toLowerCase()).toList();
      final constrained = lower.any((s) => s.startsWith("'nonce-") || s.startsWith("'sha256-") ||
        s.startsWith("'sha384-") || s.startsWith("'sha512-") || s == "'strict-dynamic'");
      if (!constrained && lower.contains("'unsafe-inline'")) findings.add(const SecurityFinding('csp.inline.review',
        'CSP script inline allowance observed', Severity.info, 'Effective script directive includes unsafe-inline without an observed nonce/hash; values omitted',
        'Review whether inline scripts can be removed or restricted with nonces or hashes.'));
      if (!constrained && lower.any((s) => ['*', 'http:', 'https:'].contains(s))) findings.add(const SecurityFinding('csp.script.broad',
        'Broad CSP script source observed', Severity.info, 'Script directive contains a wildcard or scheme-wide source; values omitted',
        'Review and restrict script sources to the intended trusted origins.'));
    }
    if (!directives.containsKey('base-uri')) findings.add(const SecurityFinding('csp.base.review',
      'CSP base-uri not declared', Severity.info, 'Single observed enforcing policy has no base-uri directive',
      'Review whether base URL restrictions are appropriate for this HTML application.'));
    if (!directives.containsKey('object-src')) findings.add(const SecurityFinding('csp.object.review',
      'CSP object-src not explicitly declared', Severity.info, 'Single observed enforcing policy has no explicit object-src directive',
      'Review effective object embedding policy, including default-src fallback.'));
    return List.unmodifiable(findings);
  }
}
