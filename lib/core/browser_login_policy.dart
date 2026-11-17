import 'project.dart';
import 'scan_policy.dart';
import 'discovery.dart';

class BrowserLoginPolicy {
  static bool allows(Uri target, Uri candidate, {bool allowInsecureHttp = false}) =>
      (target.scheme == 'https' || (allowInsecureHttp && target.scheme == 'http')) &&
      candidate.userInfo.isEmpty && SecurityProject.sameOrigin(target, candidate);

  /// The user may enter a separate HTTPS sign-in origin for this run.
  /// It is browser-only: never expand the project's assessment scope or
  /// read session cookies from anything other than the selected target.
  static Uri loginUrl(SecurityProject project, Uri target, String raw, ScanPolicy policy, {bool allowInsecureHttp = false}) {
    final value = raw.trim();
    final uri = SecurityProject.parseTarget(value.startsWith('/') && !value.startsWith('//')
        ? target.resolve(value).toString() : value);
    final transportAllowed = (target.scheme == 'https' && uri.scheme == 'https') ||
        (allowInsecureHttp && target.scheme == 'http' && allows(target, uri, allowInsecureHttp: true));
    if (!transportAllowed ||
        !project.contains(target) ||
        !policy.permits(target) || !policy.permits(uri)) {
      throw const FormatException('Enter a permitted HTTPS sign-in URL.');
    }
    return uri;
  }

  static bool allowsNavigation(Uri target, Uri login, Uri candidate, ScanPolicy? policy, {bool allowInsecureHttp = false}) =>
      (allows(target, candidate, allowInsecureHttp: allowInsecureHttp) ||
        (target.scheme == 'https' && allows(login, candidate))) &&
      (policy == null || policy.permits(candidate));

  /// If a root website was selected, begin at the page reached after login.
  /// Query strings and fragments may contain authorization codes: never scan them.
  static Uri assessmentStart(Uri target, Uri current, ScanPolicy? policy, {bool allowInsecureHttp = false}) {
    if ((target.path.isEmpty || target.path == '/') && allows(target, current, allowInsecureHttp: allowInsecureHttp)) {
      final withoutQuery = Uri.parse(current.toString().split(RegExp(r'[?#]')).first);
      if ((policy == null || policy.permits(withoutQuery)) && LinkDiscovery.eligible(target, withoutQuery)) {
        return withoutQuery;
      }
    }
    return target;
  }

  /// Cookie values are imported only from the app's own WebView on explicit
  /// user action. Reject header injection and ambiguous duplicate cookie names.
  static String cookieHeader(Iterable<MapEntry<String, String>> cookies) {
    final seen = <String>{};
    final parts = <String>[];
    for (final cookie in cookies) {
      if (!RegExp(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$").hasMatch(cookie.key) ||
          cookie.value.contains(RegExp(r'[\r\n;\x00-\x1f\x7f]')) ||
          !seen.add(cookie.key)) {
        throw const FormatException('Unsupported or ambiguous cookie values.');
      }
      parts.add('${cookie.key}=${cookie.value}');
    }
    if (parts.isEmpty) throw const FormatException('No session cookies found for the selected URL.');
    final joined = parts.join('; ');
    if (joined.length > 16384) throw const FormatException('Cookie header is too large.');
    return joined;
  }
}
