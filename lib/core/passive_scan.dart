import 'dart:convert';
import 'dart:io';

import 'fingerprint.dart';
import 'project.dart';
import 'auth.dart';

class PassiveScanResult {
  final int statusCode;
  final List<TechnologyFinding> technologies;
  final bool bodyTruncated;
  final bool redirectNotFollowed;
  const PassiveScanResult({
    required this.statusCode,
    required this.technologies,
    required this.bodyTruncated,
    required this.redirectNotFollowed,
  });
}

/// Fetches only the single, explicitly approved starting URL.
/// No crawling, redirects, or vulnerability probes yet.
class PassiveScanner {
  static const maxBytes = 256 * 1024;
  final TechnologyDetector detector;
  PassiveScanner({TechnologyDetector? detector}) : detector = detector ?? TechnologyDetector();

  Future<PassiveScanResult> scan(SecurityProject project, {required bool authorized, Uri? target, AuthProfile? auth}) async {
    if (!authorized) throw StateError('Explicit authorization is required.');
    final url = target ?? project.startUrl;
    if (!project.contains(url)) throw StateError('Target is outside scope.');
    if (auth != null && !SecurityProject.sameOrigin(auth.target, url)) throw StateError('Select the matching credential origin.');
    final session = auth == null ? null : await Authenticator().authenticate(project, auth, authorized: authorized);
    final client = HttpClient()
      ..connectionTimeout = const Duration(seconds: 10)
      ..userAgent = 'OdinSecurity/0.1 Passive';

    try {
      return await _fetch(client, url, session).timeout(const Duration(seconds: 25));
    } finally {
      client.close(force: true);
    }
  }

  Future<PassiveScanResult> _fetch(HttpClient client, Uri url, AuthSession? session) async {
    final request = await client.getUrl(url);
    request.followRedirects = false;
    request.headers.set(HttpHeaders.acceptHeader, 'text/html, application/json;q=0.9, */*;q=0.1');
    session?.headersFor(url).forEach((key, value) => request.headers.set(key, value));
    final response = await request.close();
    final headers = <String, List<String>>{};
    response.headers.forEach((name, values) => headers[name] = List.of(values));
    final bytes = <int>[];
    var truncated = false;
    await for (final chunk in response) {
      final remaining = maxBytes - bytes.length;
      if (chunk.length > remaining) {
        bytes.addAll(chunk.take(remaining));
        truncated = true;
        break;
      }
      bytes.addAll(chunk);
    }

    final technologies = detector.detect(HttpObservation(
      headers: headers,
      body: utf8.decode(bytes, allowMalformed: true),
    ));

    return PassiveScanResult(
      statusCode: response.statusCode,
      technologies: technologies,
      bodyTruncated: truncated,
      redirectNotFollowed: response.isRedirect,
    );
  }
}
