import 'fingerprint.dart';
import 'security_checks.dart';

/// Additional passive configuration observations. Raw header or cookie values
/// are never included in evidence; no additional network requests are made.
class HeaderPolicyChecks {
  static Map<String, List<String?>> _directives(Iterable<String> values, String separator) {
    final result = <String, List<String?>>{};
    for (final value in values) {
      var quoted = false, escaped = false;
      final segment = StringBuffer();
      void add() {
        final text = segment.toString().trim();
        segment.clear();
        if (text.isEmpty) return;
        final index = text.indexOf('=');
        final name = (index < 0 ? text : text.substring(0, index)).trim().toLowerCase();
        final raw = index < 0 ? null : text.substring(index + 1).trim();
        if (name.isNotEmpty) result.putIfAbsent(name, () => []).add(raw);
      }
      for (final char in value.split('')) {
        if (escaped) { segment.write(char); escaped = false; continue; }
        if (quoted && char == '\\') { segment.write(char); escaped = true; continue; }
        if (char == '"') quoted = !quoted;
        if (char == separator && !quoted) { add(); } else { segment.write(char); }
      }
      add();
    }
    return result;
  }

  static int? _seconds(String? value) {
    if (value == null) return null;
    var digits = value.trim();
    if (digits.length >= 2 && digits.startsWith('"') && digits.endsWith('"')) {
      digits = digits.substring(1, digits.length - 1);
    }
    if (digits.isEmpty || !RegExp(r'^[0-9]+$').hasMatch(digits)) return null;
    return int.tryParse(digits);
  }

  static List<SecurityFinding> inspect(Uri url, HttpObservation observation, {
    required int status, bool identityHeadersSent = false,
  }) {
    final findings = <SecurityFinding>[];
    final hsts = observation.headers['strict-transport-security'] ?? const <String>[];
    if (url.scheme == 'https' && hsts.isNotEmpty) {
      final maxAge = _directives(hsts, ';')['max-age'];
      final seconds = maxAge?.length == 1 && hsts.length == 1 ? _seconds(maxAge!.single) : null;
      if (seconds == null) {
        findings.add(const SecurityFinding('header.hsts.invalid', 'HSTS policy requires review', Severity.info,
          'Missing, malformed or ambiguous max-age directive; values omitted', 'Ensure one valid HSTS response header.'));
      } else if (seconds == 0) {
        findings.add(const SecurityFinding('header.hsts.disabled', 'HSTS policy has zero lifetime', Severity.low,
          'HSTS max-age is zero', 'Set an appropriate positive lifetime after confirming HTTPS coverage.'));
      }
    }
    if (identityHeadersSent && status >= 200 && status < 300) {
      final cache = _directives(observation.headers['cache-control'] ?? const <String>[], ',');
      final sharedAge = cache['s-maxage'];
      final explicitSharedAge = sharedAge != null && sharedAge.any((value) => _seconds(value) != null);
      if (!cache.containsKey('no-store') && !cache.containsKey('private') &&
          (cache.containsKey('public') || explicitSharedAge)) {
        findings.add(const SecurityFinding('cache.auth.shared', 'Shared-cache directive on credentialed response', Severity.low,
          'Saved identity headers were sent and Cache-Control permits shared caching; values omitted',
          'Confirm the response is safe to share across users. For sensitive personalized data, use suitable private/no-store policies.'));
      }
    }
    if (url.scheme == 'https' && [301, 302, 303, 307, 308].contains(status)) {
      final locations = observation.headers['location'] ?? const <String>[];
      if (locations.length == 1) {
        final destination = Uri.tryParse(locations.single);
        if (destination != null && url.resolveUri(destination).scheme == 'http') {
          findings.add(const SecurityFinding('transport.redirect.http', 'HTTPS redirects to HTTP', Severity.low,
            'Redirect destination uses HTTP; URL omitted and not followed', 'Keep redirects on HTTPS.'));
        }
      }
    }
    var sameSiteNone = false, prefixMismatch = false;
    for (final cookie in observation.headers['set-cookie'] ?? const <String>[]) {
      final parts = cookie.split(';');
      final index = parts.first.indexOf('=');
      if (index <= 0) continue;
      final name = parts.first.substring(0, index).trim();
      final attributes = _directives(parts.skip(1), ';');
      final secure = attributes.containsKey('secure');
      final sameSite = attributes['samesite']?.last?.toLowerCase();
      if (sameSite == 'none' && !secure) sameSiteNone = true;
      if ((name.startsWith('__Secure-') && (!secure || url.scheme != 'https')) ||
          (name.startsWith('__Host-') && (!secure || url.scheme != 'https' ||
            attributes.containsKey('domain') || attributes['path']?.last != '/'))) {
        prefixMismatch = true;
      }
    }
    if (sameSiteNone) findings.add(const SecurityFinding('cookie.samesite.none.insecure', 'SameSite=None cookie without Secure', Severity.info,
      'A cookie declares SameSite=None but omits Secure; name and value omitted',
      'Review cross-site cookie configuration; modern browsers can reject this combination.'));
    if (prefixMismatch) findings.add(const SecurityFinding('cookie.prefix.invalid', 'Cookie prefix constraints not met', Severity.info,
      'A prefixed cookie omits required restrictions; name and value omitted',
      'Verify Secure and, for host-prefixed cookies, Path=/ without Domain.'));
    return List.unmodifiable(findings);
  }
}
