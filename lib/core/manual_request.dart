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

enum ManualContent { none, json, text }

/// Ephemeral, explicitly entered request content. Never persisted in history.
class ManualRequestOptions {
  static const maxBodyBytes = 32 * 1024;
  static const allowedHeaders = {'cache-control', 'if-none-match', 'if-modified-since',
    'accept-language', 'x-requested-with'};
  final Map<String, String> headers;
  final ManualContent content;
  final String body;
  const ManualRequestOptions.empty() : headers = const {}, content = ManualContent.none, body = '';

  ManualRequestOptions({Map<String, String> headers = const {}, this.content = ManualContent.none, this.body = ''})
    : headers = Map.unmodifiable(headers.map((key, value) => MapEntry(key.toLowerCase(), value))) {
    if (headers.length > 8 || headers.length != this.headers.length) {
      throw const FormatException('Too many or duplicate request headers.');
    }
    for (final entry in this.headers.entries) {
      if (!allowedHeaders.contains(entry.key) || entry.value.length > 512 ||
          entry.value.codeUnits.any((c) => c < 32 || c > 126)) {
        throw const FormatException('Unsupported request header.');
      }
    }
    if (utf8.encode(body).length > maxBodyBytes || (content == ManualContent.none && body.isNotEmpty)) {
      throw const FormatException('Invalid request body.');
    }
    if (content == ManualContent.json) jsonDecode(body);
  }

  factory ManualRequestOptions.parse(String lines, ManualContent content, String body) {
    final headers = <String, String>{};
    for (final line in lines.split('\n')) {
      if (line.trim().isEmpty) continue;
      final colon = line.indexOf(':');
      if (colon <= 0) throw const FormatException('Expected Name: value.');
      final name = line.substring(0, colon).trim().toLowerCase();
      if (headers.containsKey(name)) throw const FormatException('Duplicate request header.');
      headers[name] = line.substring(colon + 1).trim();
    }
    if (lines.contains('\r')) throw const FormatException('Invalid header line.');
    return ManualRequestOptions(headers: headers, content: content, body: body);
  }

  int get bodyBytes => utf8.encode(body).length;
  bool get hasCustomInput => headers.isNotEmpty || content != ManualContent.none;
}

class ManualResponse {
  final int status;
  final Map<String, List<String>> headers;
  final String body;
  final bool truncated;
  final int elapsedMs, bodyBytes;
  const ManualResponse(this.status, this.headers, this.body, this.truncated, {this.elapsedMs = 0, this.bodyBytes = 0});
}

/// Explicitly initiated requests for project-approved origins.
/// No automatic redirect, retry, or sensitive header persistence.
class ManualRequestClient {
  static const maxBytes = 64 * 1024;
  static const readMethods = ['GET', 'HEAD', 'OPTIONS'];
  static const writeMethods = ['POST', 'PUT', 'PATCH', 'DELETE'];
  static const methods = [...readMethods, ...writeMethods];
  static const bodyMethods = ['POST', 'PUT', 'PATCH'];

  static void validate(SecurityProject project, Uri target, String method, bool authorized, {ScanPolicy? policy, bool stagingConfirmed = false, ManualRequestOptions options = const ManualRequestOptions.empty()}) {
    if (!authorized || !project.contains(target) || (policy != null && !policy.permits(target))) throw StateError('Request outside authorized project scope.');
    if (!readMethods.contains(method) &&
        !(writeMethods.contains(method) && stagingConfirmed && target.scheme == 'https')) {
      throw const FormatException('Write requests require explicit HTTPS staging confirmation.');
    }
    if (!bodyMethods.contains(method) && options.content != ManualContent.none) {
      throw const FormatException('This method does not support a request body.');
    }
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
    ManualRequestOptions options = const ManualRequestOptions.empty(), bool stagingConfirmed = false,
  }) async {
    validate(project, target, method, authorized, policy: policy, options: options, stagingConfirmed: stagingConfirmed);
    if (auth != null && !SecurityProject.sameOrigin(auth.target, target)) {
      throw StateError('Credential origin mismatch.');
    }
    if (auth != null && auth.mode == AuthMode.apiKey && (options.headers.containsKey(auth.headerName.toLowerCase()) ||
        ['accept', 'content-type'].contains(auth.headerName.toLowerCase()))) {
      throw StateError('Custom header conflicts with saved identity.');
    }
    final session = auth == null ? null : await Authenticator().authenticate(project, auth, authorized: authorized, permits: policy?.permits);
    final client = HttpClient()..connectionTimeout = const Duration(seconds: 10);
    final timer = Stopwatch()..start();
    try {
      final result = await _send(client, target, method, session, accept, options).timeout(const Duration(seconds: 25));
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

  Future<ManualResponse> _send(HttpClient client, Uri target, String method, AuthSession? session, ManualAccept accept, ManualRequestOptions options) async {
    final timer = Stopwatch()..start();
    final identityHeaders = session?.headersFor(target) ?? const <String, String>{};
    if (session?.expectsCredentials == true && identityHeaders.isEmpty) throw StateError('Saved identity is not applicable.');
    final req = await client.openUrl(method, target);
    req.followRedirects = false;
    req.headers.set(HttpHeaders.acceptHeader, accept.value);
    identityHeaders.forEach((key, value) => req.headers.set(key, value));
    options.headers.forEach((name, value) => req.headers.set(name, value));
    if (options.content != ManualContent.none) {
      req.headers.contentType = options.content == ManualContent.json ? ContentType.json : ContentType.text;
      final bytes = utf8.encode(options.body);
      req.contentLength = bytes.length;
      req.add(bytes);
    }
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
