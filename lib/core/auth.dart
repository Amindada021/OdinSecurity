import 'dart:convert';
import 'dart:io';
import 'package:html/parser.dart' as html;

import 'project.dart';
import 'discovery.dart';
import 'oauth_grant.dart';

enum AuthMode { none, basic, bearer, cookie, apiKey, jsonLogin, formLogin }

enum TokenDelivery { bearer, raw, apiKey, customHeader, cookie }

/// Bound to exactly one origin. Cleartext is an explicit, session-only exception.
class AuthProfile {
  final AuthMode mode;
  final TokenDelivery tokenDelivery;
  final OAuthGrant? oauth;
  final bool allowInsecureHttp;
  final Uri target;
  final String name, username, secret, headerName, loginUrl, usernameField, passwordField, tokenPath, validationUrl, validationMarker, cookiePath;
  AuthProfile({
    required this.mode, required this.target, this.oauth, this.allowInsecureHttp = false, this.name = 'Default', this.validationUrl = '', this.validationMarker = '', this.cookiePath = '/', this.username = '', this.secret = '',
    this.headerName = 'X-API-Key', this.loginUrl = '', this.usernameField = 'username',
    this.passwordField = 'password', this.tokenPath = '', this.tokenDelivery = TokenDelivery.bearer,
  }) {
    if (allowInsecureHttp && (target.scheme != 'http' || oauth != null)) throw const FormatException('Invalid cleartext opt-in.');
    if (oauth != null && (mode != AuthMode.bearer || tokenDelivery != TokenDelivery.bearer)) throw const FormatException('OAuth requires a bearer profile.');
    if (name.trim().isEmpty || name.length > 80) throw const FormatException('Enter a profile name (1–80 characters).');
    if (validationUrl.isNotEmpty || validationMarker.isNotEmpty) {
      if (mode == AuthMode.none || validationUrl.isEmpty || validationMarker.length > 512) {
        throw const FormatException('Provide a validation URL when using an expected response marker.');
      }
      final verification = SecurityProject.parseTarget(validationUrl);
      if (!LinkDiscovery.safeMediaTarget(target, verification) || (verification.scheme != 'https' && !allowInsecureHttp)) {
        throw const FormatException('Validation URL must be on the credential HTTPS origin.');
      }
    }
    if (mode == AuthMode.cookie && (!cookiePath.startsWith('/') || cookiePath.contains(RegExp(r'[\r\n?#]')))) {
      throw const FormatException('Invalid cookie path.');
    }
    if (mode == AuthMode.cookie && validationUrl.isNotEmpty && !AuthSession.matchesPath(cookiePath, Uri.parse(validationUrl).path)) {
      throw const FormatException('Validation path must be within the cookie scope.');
    }
    if (mode != AuthMode.none && ((target.scheme != 'https' && !(allowInsecureHttp && target.scheme == 'http')) || target.userInfo.isNotEmpty)) {
      throw const FormatException('Authentication requires an HTTPS target.');
    }
    if (mode != AuthMode.none && secret.isEmpty) throw const FormatException('Enter the credential.');
    for (final value in [username, secret, headerName, usernameField, passwordField, tokenPath]) {
      if (value.contains(RegExp(r'[\r\n]'))) throw const FormatException('Invalid credential or header.');
    }
    if ((mode == AuthMode.apiKey || tokenDelivery == TokenDelivery.apiKey || tokenDelivery == TokenDelivery.customHeader) &&
        (!RegExp(r'^[A-Za-z0-9-]+$').hasMatch(headerName) ||
         ['host', 'content-length', 'transfer-encoding', 'connection', 'cookie', 'authorization', 'proxy-authorization', 'upgrade'].contains(headerName.toLowerCase()))) {
      throw const FormatException('Invalid API key header.');
    }
    if (isLogin && tokenDelivery == TokenDelivery.cookie && tokenPath.isNotEmpty) {
      throw const FormatException('Cookie login must not specify a JSON token path.');
    }
    if (mode == AuthMode.bearer && tokenDelivery == TokenDelivery.cookie) {
      throw const FormatException('Use cookie authentication for cookie headers.');
    }
    if (mode == AuthMode.basic && username.contains(':')) throw const FormatException('Basic username must not contain a colon.');
    if (isLogin) {
      final login = SecurityProject.parseTarget(loginUrl);
      if (!SecurityProject.sameOrigin(target, login)) throw const FormatException('Login URL must share the authentication origin.');
      if (usernameField.trim().isEmpty || passwordField.trim().isEmpty || usernameField == passwordField) {
        throw const FormatException('Provide distinct login field names.');
      }
    }
  }

  bool get isLogin => mode == AuthMode.jsonLogin || mode == AuthMode.formLogin;

  Map<String, dynamic> toJson() {
    if (allowInsecureHttp) throw StateError('Cleartext credentials cannot be saved.');
    return {
    'mode': mode.name, 'tokenDelivery': tokenDelivery.name, 'oauth': oauth?.toJson(), 'target': target.toString(), 'name': name, 'validationUrl': validationUrl, 'validationMarker': validationMarker, 'cookiePath': cookiePath, 'username': username, 'secret': secret,
    'headerName': headerName, 'loginUrl': loginUrl, 'usernameField': usernameField,
    'passwordField': passwordField, 'tokenPath': tokenPath,
    };
  }

  factory AuthProfile.fromJson(Map<String, dynamic> data) => AuthProfile(
    mode: AuthMode.values.byName(data['mode'] as String),
    tokenDelivery: TokenDelivery.values.byName(data['tokenDelivery'] as String? ?? 'bearer'),
    oauth: data['oauth'] == null ? null : OAuthGrant.fromJson(Map<String, dynamic>.from(data['oauth'] as Map)),
    name: data['name'] as String? ?? 'Default', validationUrl: data['validationUrl'] as String? ?? '', validationMarker: data['validationMarker'] as String? ?? '', cookiePath: data['cookiePath'] as String? ?? '/',
    target: SecurityProject.parseTarget(data['target'] as String),
    username: data['username'] as String? ?? '', secret: data['secret'] as String? ?? '',
    headerName: data['headerName'] as String? ?? 'X-API-Key',
    loginUrl: data['loginUrl'] as String? ?? '',
    usernameField: data['usernameField'] as String? ?? 'username',
    passwordField: data['passwordField'] as String? ?? 'password',
    tokenPath: data['tokenPath'] as String? ?? '',
  );
}

class AuthenticationException implements Exception {
  final String reason;
  final String? retryAfter;
  const AuthenticationException(this.reason, {this.retryAfter});
  @override
  String toString() => reason;
}

class AuthSession {
  // Credential presence never establishes an authenticated identity.
  String verification = 'Session not independently verified';
  final Uri origin;
  final Map<String, String> _headers;
  final List<Cookie> _cookies;
  final String rawCookiePath;
  final DateTime createdAt;
  final DateTime? expiresAt;
  final bool allowInsecureHttp;
  AuthSession(this.origin, Map<String, String> headers, [List<Cookie> cookies = const [], this.rawCookiePath = '/', DateTime? createdAt, this.expiresAt, this.allowInsecureHttp = false])
      : _headers = Map.unmodifiable(headers), _cookies = List.unmodifiable(cookies), createdAt = createdAt ?? DateTime.now();

  bool get expectsCredentials => _headers.isNotEmpty || _cookies.isNotEmpty;

  static bool matchesPath(String path, String candidate) {
    final targetPath = candidate.isEmpty ? '/' : candidate;
    return targetPath == path || targetPath.startsWith(path.endsWith('/') ? path : '$path/');
  }

  Map<String, String> headersFor(Uri url, {DateTime? at}) {
    final now = at ?? DateTime.now();
    if (!SecurityProject.sameOrigin(origin, url) || (url.scheme != 'https' && !(allowInsecureHttp && url.scheme == 'http')) ||
        (expiresAt != null && !expiresAt!.isAfter(now))) return {};
    final headers = Map<String, String>.of(_headers);
    if (!matchesPath(rawCookiePath, url.path)) headers.remove('Cookie');
    final cookies = _cookies.where((c) {
      final domain = c.domain?.replaceFirst(RegExp(r'^\.'), '').toLowerCase();
      final path = c.path ?? '/';
      final targetPath = url.path.isEmpty ? '/' : url.path;
      return (!c.secure || url.scheme == 'https') &&
          (domain == null || domain == url.host.toLowerCase()) &&
          (c.maxAge != null ? c.maxAge! > 0 && now.difference(createdAt).inSeconds < c.maxAge! :
            c.expires == null || c.expires!.isAfter(now)) &&
          (targetPath == path || targetPath.startsWith(path.endsWith('/') ? path : '$path/'));
    }).map((c) => '${c.name}=${c.value}').join('; ');
    if (cookies.isNotEmpty) headers['Cookie'] = cookies;
    return headers;
  }
}

class Authenticator {
  static bool looksLikeLogin(String body) {
    final document = html.parse(body);
    final fields = document.querySelectorAll('input[type="password"]');
    final title = document.querySelector('title')?.text ?? '';
    final loginTitle = RegExp(r'login|sign[ -]?in|ورود', caseSensitive: false).hasMatch(title);
    if (fields.isEmpty) return loginTitle && document.querySelector('form') != null;
    // Many signed-in pages retain a hidden global sign-in dialog. Its presence
    // alone is not evidence that the document is a login response.
    final embedded = document.querySelectorAll(
      'dialog input[type="password"],[hidden] input[type="password"],'
      '[aria-hidden="true"] input[type="password"],.modal input[type="password"],'
      '[role="dialog"] input[type="password"],header input[type="password"],nav input[type="password"]');
    if (fields.every(embedded.contains)) return false;
    if (loginTitle) return true;
    return document.querySelector('article,video,[itemtype*="Movie"]') == null;
  }

  static bool loginRedirect(int status, String? location) => status >= 300 && status < 400 &&
      location != null && RegExp(r'(^|[/_.-])(login|signin|sign-in|log-in|authorize)([/_.?&#-]|$)',
        caseSensitive: false).hasMatch(Uri.tryParse(location)?.path ?? '');

  // Do not persist arbitrary server header text in reports.
  static String? safeRetryAfter(String? value) {
    if (value == null) return null;
    if (RegExp(r'^\d{1,9}$').hasMatch(value)) return value;
    try { return HttpDate.parse(value).toUtc().toIso8601String(); } catch (_) { return null; }
  }

  /// Normalize only the selected token transport. Never duplicate Bearer.
  static Map<String, String> tokenHeaders(String value, TokenDelivery delivery, {String headerName = 'X-API-Key'}) {
    if (value.length > 16384 || value.contains(RegExp(r'[^\x20-\x7e]'))) {
      throw const FormatException('Invalid token response.');
    }
    var token = value.trim();
    if (delivery == TokenDelivery.bearer || delivery == TokenDelivery.raw) {
      token = token.replaceFirst(RegExp(r'^Bearer[ ]+', caseSensitive: false), '');
    }
    if (token.isEmpty || (delivery == TokenDelivery.bearer || delivery == TokenDelivery.raw) &&
        !RegExp(r'^[A-Za-z0-9._~+/-]+=*$').hasMatch(token)) {
      throw const FormatException('Invalid token response.');
    }
    switch (delivery) {
      case TokenDelivery.bearer: return {'Authorization': 'Bearer $token'};
      case TokenDelivery.raw: return {'Authorization': token};
      case TokenDelivery.apiKey:
      case TokenDelivery.customHeader:
        if (!RegExp(r'^[A-Za-z0-9-]+$').hasMatch(headerName) ||
            ['host', 'content-length', 'transfer-encoding', 'connection', 'cookie',
              'authorization', 'proxy-authorization', 'upgrade'].contains(headerName.toLowerCase())) {
          throw const FormatException('Invalid API key header.');
        }
        return {headerName: token};
      case TokenDelivery.cookie: throw const FormatException('Use cookie authentication for cookie headers.');
    }
  }

  static AuthSession manual(AuthProfile profile) {
    if (profile.oauth?.expired(DateTime.now()) == true) throw StateError('OAuth access token expired; refresh or sign in again.');
    final headers = <String, String>{};
    switch (profile.mode) {
      case AuthMode.none: break;
      case AuthMode.basic:
        headers['Authorization'] = 'Basic ${base64Encode(utf8.encode('${profile.username}:${profile.secret}'))}';
        break;
      case AuthMode.bearer: headers.addAll(tokenHeaders(profile.secret, profile.tokenDelivery, headerName: profile.headerName)); break;
      case AuthMode.cookie: headers['Cookie'] = profile.secret; break;
      case AuthMode.apiKey: headers[profile.headerName] = profile.secret; break;
      case AuthMode.jsonLogin:
      case AuthMode.formLogin: throw StateError('Login requires a network session.');
    }
    return AuthSession(profile.target, headers, const [], profile.cookiePath, null, profile.oauth?.expiresAt, profile.allowInsecureHttp);
  }

  static String extractToken(String jsonBody, String path) {
    dynamic value = jsonDecode(jsonBody);
    for (final key in path.split('.')) {
      if (value is! Map || !value.containsKey(key)) throw const FormatException('Token response field was not found.');
      value = value[key];
    }
    if (value is! String || value.isEmpty || value.contains(RegExp(r'[\r\n]'))) {
      throw const FormatException('Invalid token response.');
    }
    return value;
  }

  /// Validate every configured authentication endpoint before any network call.
  static void validateScope(SecurityProject project, AuthProfile profile, {required bool authorized, bool Function(Uri)? permits}) {
    if (!authorized || !project.contains(profile.target)) throw StateError('Authentication target is not authorized.');
    for (final raw in [if (profile.isLogin) profile.loginUrl, if (profile.validationUrl.isNotEmpty) profile.validationUrl]) {
      final url = SecurityProject.parseTarget(raw);
      if (!project.contains(url) || !SecurityProject.sameOrigin(profile.target, url) ||
          (permits != null && !permits(url))) throw StateError('Authentication endpoint is outside permitted scope.');
    }
  }

  Future<AuthSession> authenticate(SecurityProject project, AuthProfile profile, {required bool authorized, bool Function(Uri)? permits, Future<void> Function()? beforeRequest}) async {
    validateScope(project, profile, authorized: authorized, permits: permits);
    if (!profile.isLogin) {
      final session = manual(profile);
      await _validateIfConfigured(profile, session, beforeRequest);
      return session;
    }
    final client = HttpClient()..connectionTimeout = const Duration(seconds: 10);
    try {
      await beforeRequest?.call();
      final session = await _login(client, profile).timeout(const Duration(seconds: 25));
      await _validateIfConfigured(profile, session, beforeRequest);
      return session;
    } finally {
      client.close(force: true);
    }
  }

  static bool validationMatches(int status, String body, String expectedMarker) =>
      status >= 200 && status < 300 && !looksLikeLogin(body) && expectedMarker.isNotEmpty && body.contains(expectedMarker);

  Future<void> _validateIfConfigured(AuthProfile profile, AuthSession session,
      Future<void> Function()? beforeRequest) async {
    if (profile.validationUrl.isEmpty) return;
    final url = SecurityProject.parseTarget(profile.validationUrl);
    final client = HttpClient()..connectionTimeout = const Duration(seconds: 10);
    try {
      await beforeRequest?.call();
      await _verify(client, url, session, profile.validationMarker).timeout(const Duration(seconds: 15));
    } finally {
      client.close(force: true);
    }
  }

  Future<void> _verify(HttpClient client, Uri url, AuthSession session, String marker) async {
    final headers = session.headersFor(url);
    if (headers.isEmpty) throw const AuthenticationException('Session credentials do not apply to the protected URL');
    final request = await client.getUrl(url);
    request.followRedirects = false;
    headers.forEach((key, value) => request.headers.set(key, value));
    final response = await request.close();
    final status = response.statusCode;
    if (status == 429) throw AuthenticationException('rate_limited',
      retryAfter: safeRetryAfter(response.headers.value('retry-after')));
    if (status == 401) throw const AuthenticationException('Protected URL returned HTTP 401');
    if (status == 403) throw const AuthenticationException('Protected URL returned HTTP 403');
    if (status >= 300 && status < 400) throw AuthenticationException(
      loginRedirect(status, response.headers.value('location'))
        ? 'Protected URL redirected to sign-in' : 'Protected URL redirected; session unverified');
    if (status < 200 || status >= 300) throw const AuthenticationException('Protected URL failed; session unverified');
    final body = <int>[];
    var truncated = false;
    await for (final chunk in response) {
      final remaining = 256 * 1024 - body.length;
      body.addAll(chunk.take(remaining));
      if (chunk.length > remaining) { truncated = true; break; }
    }
    final text = utf8.decode(body, allowMalformed: true);
    if (looksLikeLogin(text)) throw const AuthenticationException('Protected URL returned a sign-in page');
    if (truncated) throw const AuthenticationException('Protected URL response truncated; session unverified');
    if (marker.isNotEmpty && !validationMatches(status, text, marker)) {
      throw const AuthenticationException('Expected session marker was not found');
    }
    session.verification = marker.isEmpty
        ? 'Protected URL responded; identity not independently verified'
        : 'Session verified by protected URL and expected marker';
  }

  Future<AuthSession> _login(HttpClient client, AuthProfile profile) async {
    final url = SecurityProject.parseTarget(profile.loginUrl);
    final req = await client.postUrl(url);
    req.followRedirects = false;
    final fields = {profile.usernameField: profile.username, profile.passwordField: profile.secret};
    if (profile.mode == AuthMode.jsonLogin) {
      req.headers.contentType = ContentType.json;
      req.write(jsonEncode(fields));
    } else {
      req.headers.contentType = ContentType('application', 'x-www-form-urlencoded');
      req.write(Uri(queryParameters: fields).query);
    }
    final response = await req.close();
    // Redirects are never automatically followed. A redirect with a session
    // cookie can be a valid login, but protected target validation is separate.
    if (response.statusCode == 429) throw AuthenticationException('rate_limited', retryAfter: safeRetryAfter(response.headers.value('retry-after')));
    if (response.statusCode < 200 || response.statusCode >= 400) throw const AuthenticationException('Login failed; session unverified');
    final headers = <String, String>{};
    final cookies = <Cookie>[];
    if (profile.tokenPath.isNotEmpty) {
      final body = <int>[];
      await for (final chunk in response) {
        if (body.length + chunk.length > 256 * 1024) throw StateError('Login response too large.');
        body.addAll(chunk);
      }
      headers.addAll(tokenHeaders(extractToken(utf8.decode(body), profile.tokenPath), profile.tokenDelivery, headerName: profile.headerName));
    } else {
      final path = url.path;
      final defaultPath = path.lastIndexOf('/') <= 0 ? '/' : path.substring(0, path.lastIndexOf('/'));
      for (final cookie in response.cookies) {
        cookie.path ??= defaultPath;
        // More conservative than a browser: never send credentials across origins.
        cookies.add(cookie);
      }
      // Drain at most 256 KiB, then the login client's finally closes the socket.
      var length = 0;
      await for (final chunk in response) {
        length += chunk.length;
        if (length > 256 * 1024) break;
      }
      if (cookies.isEmpty) throw StateError('No session cookie returned.');
    }
    return AuthSession(profile.target, headers, cookies, '/', null, null, profile.allowInsecureHttp);
  }
}
