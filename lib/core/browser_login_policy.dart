import 'project.dart';

class BrowserLoginPolicy {
  static bool allows(Uri target, Uri candidate) =>
      target.scheme == 'https' && candidate.scheme == 'https' &&
      candidate.userInfo.isEmpty && SecurityProject.sameOrigin(target, candidate);

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
