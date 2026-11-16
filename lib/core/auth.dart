import 'dart:convert';
import 'dart:io';

import 'project.dart';

enum AuthMode { none, basic, bearer, cookie, apiKey, jsonLogin, formLogin }

/// Bound to exactly one HTTPS origin. Profile values are secret vault data.
class AuthProfile {
  final AuthMode mode;
  final Uri target;
  final String username, secret, headerName, loginUrl, usernameField, passwordField, tokenPath;
  AuthProfile({
    required this.mode, required this.target, this.username = '', this.secret = '',
    this.headerName = 'X-API-Key', this.loginUrl = '', this.usernameField = 'username',
    this.passwordField = 'password', this.tokenPath = '',
  }) {
    if (mode != AuthMode.none && (target.scheme != 'https' || target.userInfo.isNotEmpty)) {
      throw const FormatException('Authentication requires an HTTPS target.');
    }
    if (mode != AuthMode.none && secret.isEmpty) throw const FormatException('Enter the credential.');
    for (final value in [username, secret, headerName, usernameField, passwordField, tokenPath]) {
      if (value.contains(RegExp(r'[\r\n]'))) throw const FormatException('Invalid credential or header.');
    }
    if (mode == AuthMode.apiKey &&
        (!RegExp(r'^[A-Za-z0-9-]+$').hasMatch(headerName) ||
         ['host', 'content-length', 'transfer-encoding', 'connection', 'cookie', 'authorization', 'proxy-authorization', 'upgrade'].contains(headerName.toLowerCase()))) {
      throw const FormatException('Invalid API key header.');
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

  Map<String, dynamic> toJson() => {
    'mode': mode.name, 'target': target.toString(), 'username': username, 'secret': secret,
    'headerName': headerName, 'loginUrl': loginUrl, 'usernameField': usernameField,
    'passwordField': passwordField, 'tokenPath': tokenPath,
  };

  factory AuthProfile.fromJson(Map<String, dynamic> data) => AuthProfile(
    mode: AuthMode.values.byName(data['mode'] as String),
    target: SecurityProject.parseTarget(data['target'] as String),
    username: data['username'] as String? ?? '', secret: data['secret'] as String? ?? '',
    headerName: data['headerName'] as String? ?? 'X-API-Key',
    loginUrl: data['loginUrl'] as String? ?? '',
    usernameField: data['usernameField'] as String? ?? 'username',
    passwordField: data['passwordField'] as String? ?? 'password',
    tokenPath: data['tokenPath'] as String? ?? '',
  );
}

class AuthSession {
  final Uri origin;
  final Map<String, String> _headers;
  final List<Cookie> _cookies;
  AuthSession(this.origin, Map<String, String> headers, [List<Cookie> cookies = const []])
      : _headers = Map.unmodifiable(headers), _cookies = List.unmodifiable(cookies);

  Map<String, String> headersFor(Uri url) {
    if (!SecurityProject.sameOrigin(origin, url) || url.scheme != 'https') return {};
    final headers = Map<String, String>.of(_headers);
    final now = DateTime.now();
    final cookies = _cookies.where((c) {
      final domain = c.domain?.replaceFirst(RegExp(r'^\.'), '').toLowerCase();
      final path = c.path ?? '/';
      final targetPath = url.path.isEmpty ? '/' : url.path;
      return (domain == null || domain == url.host.toLowerCase()) &&
          (c.expires == null || c.expires!.isAfter(now)) &&
          (c.maxAge == null || c.maxAge! > 0) &&
          (targetPath == path || targetPath.startsWith(path.endsWith('/') ? path : '$path/'));
    }).map((c) => '${c.name}=${c.value}').join('; ');
    if (cookies.isNotEmpty) headers['Cookie'] = cookies;
    return headers;
  }
}

class Authenticator {
  static AuthSession manual(AuthProfile profile) {
    final headers = <String, String>{};
    switch (profile.mode) {
      case AuthMode.none: break;
      case AuthMode.basic:
        headers['Authorization'] = 'Basic ${base64Encode(utf8.encode('${profile.username}:${profile.secret}'))}';
        break;
      case AuthMode.bearer: headers['Authorization'] = 'Bearer ${profile.secret}'; break;
      case AuthMode.cookie: headers['Cookie'] = profile.secret; break;
      case AuthMode.apiKey: headers[profile.headerName] = profile.secret; break;
      case AuthMode.jsonLogin:
      case AuthMode.formLogin: throw StateError('Login requires a network session.');
    }
    return AuthSession(profile.target, headers);
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

  Future<AuthSession> authenticate(SecurityProject project, AuthProfile profile, {required bool authorized}) async {
    if (!authorized || !project.contains(profile.target)) throw StateError('Authentication target is not authorized.');
    if (!profile.isLogin) return manual(profile);
    final client = HttpClient()..connectionTimeout = const Duration(seconds: 10);
    try {
      return await _login(client, profile).timeout(const Duration(seconds: 25));
    } finally {
      client.close(force: true);
    }
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
    if (response.statusCode < 200 || response.statusCode >= 400) throw StateError('Login failed.');
    final headers = <String, String>{};
    final cookies = <Cookie>[];
    if (profile.tokenPath.isNotEmpty) {
      final body = <int>[];
      await for (final chunk in response) {
        if (body.length + chunk.length > 256 * 1024) throw StateError('Login response too large.');
        body.addAll(chunk);
      }
      headers['Authorization'] = 'Bearer ${extractToken(utf8.decode(body), profile.tokenPath)}';
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
    return AuthSession(profile.target, headers, cookies);
  }
}
