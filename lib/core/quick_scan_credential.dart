import 'auth.dart';

/// Session-only credential for automatic GET assessment. Never persisted.
class QuickScanCredential {
  static AuthProfile? parse(Uri target, String raw) {
    if (raw.trim().isEmpty) return null;
    if (target.scheme != 'https' || target.userInfo.isNotEmpty ||
        raw.contains(RegExp(r'[\r\n]')) || raw.length > 16384) {
      throw const FormatException('Invalid quick scan token.');
    }
    var token = raw.trim();
    token = token.replaceFirst(RegExp(r'^Bearer[ \t]+', caseSensitive: false), '');
    if (!RegExp(r'^[A-Za-z0-9._~+/-]+=*$').hasMatch(token)) {
      throw const FormatException('Invalid quick scan token.');
    }
    return AuthProfile(mode: AuthMode.bearer, target: target, secret: token, name: 'Quick scan token');
  }
}
