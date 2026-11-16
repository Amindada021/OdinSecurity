import 'dart:convert';
import 'dart:io';

import 'fingerprint.dart';
import 'project.dart';

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
/// No crawling, credential handling, redirects, or vulnerability probes yet.
class PassiveScanner {
  static const maxBytes = 256 * 1024;
  final TechnologyDetector detector;
  PassiveScanner({TechnologyDetector? detector}) : detector = detector ?? TechnologyDetector();

  Future<PassiveScanResult> scan(SecurityProject project, {required bool authorized}) async {
    if (!authorized) throw StateError('Explicit authorization is required.');
    final client = HttpClient()
      ..connectionTimeout = const Duration(seconds: 10)
      ..userAgent = 'OdinSecurity/0.1 Passive';

    try {
      return await _fetch(client, project).timeout(const Duration(seconds: 25));
    } finally {
      client.close(force: true);
    }
  }

  Future<PassiveScanResult> _fetch(HttpClient client, SecurityProject project) async {
    final request = await client.getUrl(project.startUrl);
    request.followRedirects = false;
    request.headers.set(HttpHeaders.acceptHeader, 'text/html, application/json;q=0.9, */*;q=0.1');
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
