import 'package:flutter_test/flutter_test.dart';
import 'package:odin_security/core/oauth_grant.dart';
import 'package:odin_security/core/auth.dart';

void main() {
  OAuthGrant grant({DateTime? expiresAt, String refresh = 'fixture'}) => OAuthGrant(
    clientId: 'public-test', authorizationEndpoint: 'https://id.example.test/authorize',
    tokenEndpoint: 'https://id.example.test/token', scopes: ['openid'], refreshToken: refresh, expiresAt: expiresAt);
  test('OAuth requires HTTPS endpoints on one provider origin', () {
    expect(() => OAuthGrant(clientId: 'fixture', authorizationEndpoint: 'https://id.example.test/authorize',
      tokenEndpoint: 'http://id.example.test/token', scopes: ['openid']), throwsFormatException);
    expect(() => OAuthGrant(clientId: 'fixture', authorizationEndpoint: 'https://id.example.test/authorize',
      tokenEndpoint: 'https://other.test/token', scopes: ['openid']), throwsFormatException);
  });
  test('rotating refresh tokens preserve previous token when omitted', () {
    final g = grant();
    expect(g.rotated().refreshToken, 'fixture');
    expect(g.rotated(newRefreshToken: 'replacement').refreshToken, 'replacement');
    expect(g.rotated(expiresAt: DateTime.utc(2030)).expiresAt, DateTime.utc(2030));
  });
  test('expiry is enforced and OAuth token remains bound to API origin', () {
    final past = grant(expiresAt: DateTime.utc(2020));
    final origin = Uri.parse('https://api.example.test/');
    expect(past.needsRefresh(DateTime.utc(2021)), isTrue);
    final a = AuthProfile(name: 'fixture', mode: AuthMode.bearer, target: origin, secret: 'test', oauth: past);
    expect(() => Authenticator.manual(a), throwsStateError);
    final live = AuthProfile.fromJson({...a.toJson(), 'oauth': grant().toJson()});
    expect(Authenticator.manual(live).headersFor(Uri.parse('https://id.example.test/')), isEmpty);
    expect(Authenticator.manual(live).headersFor(origin)['Authorization'], 'Bearer test');
  });
}
