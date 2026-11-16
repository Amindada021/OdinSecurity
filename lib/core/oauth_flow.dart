import 'package:flutter_appauth/flutter_appauth.dart';
import 'auth.dart';
import 'oauth_grant.dart';

class OAuthFlow {
  final FlutterAppAuth client;
  OAuthFlow({FlutterAppAuth? client}) : client = client ?? const FlutterAppAuth();

  AuthorizationServiceConfiguration _configuration(OAuthGrant grant) => AuthorizationServiceConfiguration(
    authorizationEndpoint: grant.authorizationEndpoint,
    tokenEndpoint: grant.tokenEndpoint,
  );

  Future<AuthProfile> signIn(AuthProfile draft) async {
    final grant = draft.oauth;
    if (grant == null) throw StateError('OAuth configuration required.');
    final response = await client.authorizeAndExchangeCode(AuthorizationTokenRequest(
      grant.clientId, OAuthGrant.redirectUri, serviceConfiguration: _configuration(grant),
      scopes: grant.scopes,
    ));
    return _apply(draft, grant, response);
  }

  Future<AuthProfile> refresh(AuthProfile profile) async {
    final grant = profile.oauth;
    if (grant == null || grant.refreshToken.isEmpty) throw StateError('No refresh token is available.');
    final response = await client.token(TokenRequest(
      grant.clientId, OAuthGrant.redirectUri, serviceConfiguration: _configuration(grant),
      refreshToken: grant.refreshToken,
    ));
    return _apply(profile, grant, response);
  }

  AuthProfile _apply(AuthProfile profile, OAuthGrant grant, TokenResponse response) {
    final token = response.accessToken;
    if (token == null || token.isEmpty ||
        (response.tokenType != null && response.tokenType!.toLowerCase() != 'bearer')) {
      throw StateError('Provider did not return a supported bearer token.');
    }
    return AuthProfile.fromJson({
      ...profile.toJson(), 'secret': token,
      'oauth': grant.rotated(newRefreshToken: response.refreshToken,
        expiresAt: response.accessTokenExpirationDateTime).toJson(),
    });
  }
}
