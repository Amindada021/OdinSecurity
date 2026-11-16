import 'dart:convert';
import 'dart:io';
import 'auth.dart';
import 'project.dart';

class ManualResponse {
  final int status;
  final Map<String, List<String>> headers;
  final String body;
  final bool truncated;
  const ManualResponse(this.status, this.headers, this.body, this.truncated);
}

/// Explicitly initiated GET/HEAD inspection for project-approved origins.
/// No automatic redirect, retry, or sensitive header persistence.
class ManualRequestClient {
  static const maxBytes = 64 * 1024;

  static void validate(SecurityProject project, Uri target, String method, bool authorized) {
    if (!authorized || !project.contains(target)) throw StateError('Request outside authorized project scope.');
    if (!['GET', 'HEAD'].contains(method)) throw const FormatException('Only GET and HEAD are supported.');
    if (target.hasFragment || target.userInfo.isNotEmpty || target.toString().length > 2048) throw const FormatException('Invalid target URL.');
  }

  static Map<String, List<String>> safeHeaders(Map<String, List<String>> headers) => {
    for (final e in headers.entries)
      e.key: ['set-cookie', 'cookie', 'authorization', 'proxy-authorization', 'www-authenticate', 'location', 'x-api-key'].contains(e.key.toLowerCase()) ? const ['[redacted]'] : List.of(e.value),
  };

  Future<ManualResponse> send(SecurityProject project, Uri target, String method, {
    required bool authorized, AuthProfile? auth,
  }) async {
    validate(project, target, method, authorized);
    if (auth != null && !SecurityProject.sameOrigin(auth.target, target)) {
      throw StateError('Credential origin mismatch.');
    }
    final session = auth == null ? null : await Authenticator().authenticate(project, auth, authorized: authorized);
    final client = HttpClient()..connectionTimeout = const Duration(seconds: 10);
    try {
      return await _send(client, target, method, session).timeout(const Duration(seconds: 25));
    } finally {
      client.close(force: true);
    }
  }

  Future<ManualResponse> _send(HttpClient client, Uri target, String method, AuthSession? session) async {
    final req = await client.openUrl(method, target);
    req.followRedirects = false;
    session?.headersFor(target).forEach((key, value) => req.headers.set(key, value));
    final res = await req.close();
    final headers = <String, List<String>>{};
    res.headers.forEach((key, values) => headers[key] = List.of(values));
    final body = <int>[];
    var truncated = false;
    await for (final chunk in res) {
      final remaining = maxBytes - body.length;
      if (chunk.length > remaining) { body.addAll(chunk.take(remaining)); truncated = true; break; }
      body.addAll(chunk);
    }
    return ManualResponse(res.statusCode, safeHeaders(headers), utf8.decode(body, allowMalformed: true), truncated);
  }
}
