import 'fingerprint.dart';

enum Severity { info, low, medium, high, critical }

class SecurityFinding {
  final String id, title, evidence, remediation;
  final Severity severity;
  const SecurityFinding(this.id, this.title, this.severity, this.evidence, this.remediation);
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
    final cookies = observation.headers['set-cookie'] ?? const <String>[];
    for (final value in cookies) {
      final attrs = value.split(';').skip(1).map((part) => part.trim().toLowerCase()).toList();
      if (url.scheme == 'https' && !attrs.contains('secure')) {
        result.add(const SecurityFinding('cookie.secure', 'Cookie without Secure attribute', Severity.low, 'Set-Cookie without Secure (value omitted)', 'Evaluate the cookie purpose and set Secure for sensitive cookies.'));
        break;
      }
    }
    return List.unmodifiable(result);
  }
}
