import 'project.dart';

class OAuthGrant {
  static const redirectScheme = 'com.odin.odin_security';
  static const redirectUri = '$redirectScheme:/oauth2redirect';
  final String clientId, authorizationEndpoint, tokenEndpoint, refreshToken;
  final List<String> scopes;
  final DateTime? expiresAt;

  OAuthGrant({required this.clientId, required this.authorizationEndpoint, required this.tokenEndpoint,
    required List<String> scopes, this.refreshToken = '', this.expiresAt}) : scopes = List.unmodifiable(scopes) {
    if (clientId.trim().isEmpty || clientId.length > 512 || scopes.isEmpty || scopes.length > 20 ||
        scopes.any((scope) => scope.isEmpty || scope.length > 256 || scope.contains(RegExp(r'\s')))) {
      throw const FormatException('Invalid OAuth public client or scopes.');
    }
    final authorization = SecurityProject.parseTarget(authorizationEndpoint);
    final token = SecurityProject.parseTarget(tokenEndpoint);
    if (authorization.scheme != 'https' || token.scheme != 'https' ||
        !SecurityProject.sameOrigin(authorization, token)) {
      throw const FormatException('OAuth endpoints must share one HTTPS provider origin.');
    }
    if (refreshToken.contains(RegExp(r'[\r\n]'))) throw const FormatException('Invalid refresh token.');
  }

  bool needsRefresh(DateTime now) => expiresAt != null &&
      !expiresAt!.isAfter(now.add(const Duration(seconds: 60)));
  bool expired(DateTime now) => expiresAt != null && !expiresAt!.isAfter(now);

  OAuthGrant rotated({String? newRefreshToken, DateTime? expiresAt}) => OAuthGrant(
    clientId: clientId, authorizationEndpoint: authorizationEndpoint, tokenEndpoint: tokenEndpoint,
    scopes: scopes, refreshToken: newRefreshToken == null || newRefreshToken.isEmpty ? refreshToken : newRefreshToken,
    expiresAt: expiresAt,
  );

  Map<String, dynamic> toJson() => {
    'clientId': clientId, 'authorizationEndpoint': authorizationEndpoint, 'tokenEndpoint': tokenEndpoint,
    'scopes': scopes, 'refreshToken': refreshToken, 'expiresAt': expiresAt?.toUtc().toIso8601String(),
  };

  factory OAuthGrant.fromJson(Map<String, dynamic> data) => OAuthGrant(
    clientId: data['clientId'] as String, authorizationEndpoint: data['authorizationEndpoint'] as String,
    tokenEndpoint: data['tokenEndpoint'] as String, scopes: (data['scopes'] as List).cast<String>(),
    refreshToken: data['refreshToken'] as String? ?? '', expiresAt: DateTime.tryParse(data['expiresAt'] as String? ?? ''),
  );
}
