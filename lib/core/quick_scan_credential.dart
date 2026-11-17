import 'auth.dart';

/// Session-only credentials for automatic assessment. Never persisted.
class QuickScanCredential {
  static AuthProfile? parse(Uri target, String raw, {
    TokenDelivery delivery = TokenDelivery.bearer, String headerName = 'X-API-Key',
  }) {
    if (raw.trim().isEmpty) return null;
    if (target.scheme != 'https' || target.userInfo.isNotEmpty ||
        raw.contains(RegExp(r'[^\x20-\x7e]')) || raw.length > 16384) {
      throw const FormatException('Invalid quick scan token.');
    }
    if (delivery == TokenDelivery.cookie) {
      return AuthProfile(mode: AuthMode.cookie, target: target, secret: raw.trim(), name: 'Quick scan cookie',
        cookiePath: target.path.isEmpty ? '/' : target.path);
    }
    Authenticator.tokenHeaders(raw, delivery, headerName: headerName);
    return AuthProfile(mode: AuthMode.bearer, target: target, secret: raw.trim(), name: 'Quick scan token',
      tokenDelivery: delivery, headerName: headerName);
  }
}
