import 'dart:convert';
import 'dart:io';
import 'auth.dart';
import 'project.dart';
import 'scan_policy.dart';
import 'traffic_journal.dart';

enum ManualAccept {
  any('*/*'), json('application/json'), html('text/html'), text('text/plain');
  final String value;
  const ManualAccept(this.value);
}

class ManualResponse {
  final int status;
  final Map<String, List<String>> headers;
  final String body;
  final bool truncated;
  final int elapsedMs, bodyBytes;
  const ManualResponse(this.status, this.headers, this.body, this.truncated, {this.elapsedMs = 0, this.bodyBytes = 0});
}

/// Explicitly initiated GET/HEAD inspection for project-approved origins.
/// No automatic redirect, retry, or sensitive header persistence.
class ManualRequestClient {
  static const maxBytes = 64 * 1024;

  static void validate(SecurityProject project, Uri target, String method, bool authorized, {ScanPolicy? policy}) {
    if (!authorized || !project.contains(target) || (policy != null && !policy.permits(target))) throw StateError('Request outside authorized project scope.');
    if (!['GET', 'HEAD'].contains(method)) throw const FormatException('Only GET and HEAD are supported.');
    if (target.hasFragment || target.userInfo.isNotEmpty || target.toString().length > 2048) throw const FormatException('Invalid target URL.');
  }

  // An allowlist avoids exposing arbitrary custom authentication headers.
  static const visibleHeaders = {
    'content-type', 'content-length', 'content-encoding', 'cache-control',
    'date', 'expires', 'age', 'vary', 'server', 'strict-transport-security',
    'x-content-type-options', 'x-frame-options', 'referrer-policy',
    'access-control-allow-origin', 'access-control-allow-methods',
    'access-control-allow-credentials', 'allow', 'retry-after',
  };

  static Map<String, List<String>> safeHeaders(Map<String, List<String>> headers) => {
    for (final e in headers.entries)
      e.key: visibleHeaders.contains(e.key.toLowerCase()) ? List.of(e.value) : const ['[redacted]'],
  };

  Future<ManualResponse> send(SecurityProject project, Uri target, String method, {
    required bool authorized, AuthProfile? auth, ScanPolicy? policy, ManualAccept accept = ManualAccept.any,
  }) async {
    validate(project, target, method, authorized, policy: policy);
    if (auth != null && !SecurityProject.sameOrigin(auth.target, target)) {
      throw StateError('Credential origin mismatch.');
    }
    final session = auth == null ? null : await Authenticator().authenticate(project, auth, authorized: authorized);
    final client = HttpClient()..connectionTimeout = const Duration(seconds: 10);
    final timer = Stopwatch()..start();
    try {
      final result = await _send(client, target, method, session, accept).timeout(const Duration(seconds: 25));
      TrafficJournal.shared.record(project, target, source: 'manual', method: method,
        status: result.status, capturedBytes: result.bodyBytes, elapsedMs: result.elapsedMs, truncated: result.truncated);
      return result;
    } catch (_) {
      TrafficJournal.shared.record(project, target, source: 'manual', method: method, elapsedMs: timer.elapsedMilliseconds);
      rethrow;
    } finally {
      client.close(force: true);
    }
  }

  Future<ManualResponse> _send(HttpClient client, Uri target, String method, AuthSession? session, ManualAccept accept) async {
    final timer = Stopwatch()..start();
    final req = await client.openUrl(method, target);
    req.followRedirects = false;
    req.headers.set(HttpHeaders.acceptHeader, accept.value);
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
    return ManualResponse(res.statusCode, safeHeaders(headers), utf8.decode(body, allowMalformed: true), truncated,
      elapsedMs: timer.elapsedMilliseconds, bodyBytes: body.length);
  }
}
