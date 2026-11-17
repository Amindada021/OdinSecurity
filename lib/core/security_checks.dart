import 'fingerprint.dart';

enum Severity { info, low, medium, high, critical }

enum FindingCertainty { possible, observed, confirmed }

class SecurityFinding {
  final String id, title, evidence, remediation;
  final Severity severity;
  final FindingCertainty certainty;
  const SecurityFinding(this.id, this.title, this.severity, this.evidence, this.remediation, {this.certainty = FindingCertainty.possible});
}

/// Header/metadata observations only. They are configuration signals,
/// not proof of exploitable vulnerabilities.
class PassiveSecurityChecks {
  List<SecurityFinding> inspect(Uri url, HttpObservation observation) {
    final result = <SecurityFinding>[];
    final html = observation.header('content-type').toLowerCase().contains('text/html');
    final csp = observation.header('content-security-policy').toLowerCase();
    if (url.scheme == 'http') {
      result.add(const SecurityFinding('transport.http', 'Unencrypted HTTP endpoint', Severity.medium, 'Target URL uses HTTP', 'Serve the endpoint over HTTPS.'));
    } else if (observation.header('strict-transport-security').isEmpty) {
      result.add(const SecurityFinding('header.hsts', 'HSTS not observed', Severity.low, 'Strict-Transport-Security header absent', 'Consider an appropriate HSTS policy after verifying HTTPS coverage.'));
    }
    if (html && csp.isEmpty) {
      result.add(const SecurityFinding('header.csp', 'Content Security Policy not observed', Severity.low, 'CSP response header absent', 'Define a context-appropriate Content-Security-Policy.'));
    }
    if (html && observation.header('x-frame-options').isEmpty && !csp.contains('frame-ancestors')) {
      result.add(const SecurityFinding('header.frame', 'Frame protection not observed', Severity.low, 'No frame-ancestors or X-Frame-Options header', 'Restrict framing where embedding is not required.'));
    }
    if (observation.header('x-content-type-options').toLowerCase() != 'nosniff') {
      result.add(const SecurityFinding('header.nosniff', 'MIME sniffing protection not observed', Severity.info, 'X-Content-Type-Options: nosniff absent', 'Consider nosniff on responses.'));
    }
    if (observation.header('x-powered-by').isNotEmpty || observation.header('x-aspnet-version').isNotEmpty) {
      result.add(const SecurityFinding('header.disclosure', 'Technology information exposed', Severity.info, 'Framework identification header present', 'Remove unnecessary framework disclosure headers.'));
    }
    final body = observation.body.toLowerCase();
    if (html && csp.isNotEmpty && csp.contains("'unsafe-eval'")) {
      result.add(const SecurityFinding('header.csp.eval', 'CSP permits unsafe-eval', Severity.low, 'CSP contains unsafe-eval token', 'Review whether dynamic evaluation is needed; remove it where feasible.'));
    }
    if (html && observation.header('referrer-policy').isEmpty) {
      result.add(const SecurityFinding('header.referrer', 'Referrer-Policy not observed', Severity.info, 'Referrer-Policy header absent', 'Review referrer sharing for sensitive pages.'));
    }
    if (observation.header('access-control-allow-origin').trim() == '*' &&
        observation.header('access-control-allow-credentials').trim().toLowerCase() == 'true') {
      result.add(const SecurityFinding('cors.inconsistent', 'Inconsistent CORS configuration', Severity.info, 'Wildcard origin together with credentialed CORS', 'Review allowed origins and credential settings; browsers reject this combination for credentialed requests.'));
    }
    if (html && (body.contains('developer exception page') && body.contains('asp.net core') ||
        body.contains('django version:') && body.contains('traceback') ||
        body.contains('whoops!') && body.contains('stack trace') ||
        body.contains('werkzeug debugger') && body.contains('traceback'))) {
      result.add(const SecurityFinding('framework.debug', 'Verbose framework error indicators', Severity.medium, 'Response resembles a development traceback page; details omitted', 'Disable developer error pages in production and review exposed diagnostic information.'));
    }
    if (observation.header('x-debug-token').isNotEmpty && observation.header('x-debug-token-link').isNotEmpty) {
      result.add(const SecurityFinding('framework.profiler', 'Framework profiler headers observed', Severity.info, 'Debug-token response headers present; values omitted', 'Verify development profiler is not enabled for untrusted production users.'));
    }
    final cookies = observation.headers['set-cookie'] ?? const <String>[];
    var insecure = false, missingHttpOnly = false, missingSameSite = false;
    for (final value in cookies) {
      final pieces = value.split(';');
      final name = pieces.first.split('=').first.trim().toLowerCase();
      final attrs = pieces.skip(1).map((part) => part.trim().toLowerCase()).toList();
      final sensitive = RegExp(r'(session|auth|jwt|token|sid)').hasMatch(name) &&
          !RegExp(r'(csrf|xsrf)').hasMatch(name);
      if (url.scheme == 'https' && !attrs.contains('secure')) insecure = true;
      if (sensitive && !attrs.contains('httponly')) missingHttpOnly = true;
      if (sensitive && !attrs.any((a) => a.startsWith('samesite='))) missingSameSite = true;
    }
    if (insecure) result.add(const SecurityFinding('cookie.secure', 'Cookie without Secure attribute', Severity.low, 'Set-Cookie without Secure (value omitted)', 'Evaluate the cookie purpose and set Secure for sensitive cookies.'));
    if (missingHttpOnly) result.add(const SecurityFinding('cookie.httponly', 'Possible session cookie without HttpOnly', Severity.low, 'Session-like cookie name and no HttpOnly attribute; value omitted', 'Confirm cookie usage and apply HttpOnly when client-side access is unnecessary.'));
    if (missingSameSite) result.add(const SecurityFinding('cookie.samesite', 'Possible session cookie without explicit SameSite', Severity.info, 'Session-like cookie lacks explicit SameSite; value omitted', 'Review cross-site flows and configure an appropriate SameSite policy.'));
    return List.unmodifiable(result);
  }
}
