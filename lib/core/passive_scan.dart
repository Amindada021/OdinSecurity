import 'dart:convert';
import 'dart:io';

import 'fingerprint.dart';
import 'project.dart';
import 'auth.dart';
import 'discovery.dart';
import 'security_checks.dart';

class PassiveScanResult {
  final Uri url;
  final int statusCode;
  final List<Uri> links;
  final List<SecurityFinding> findings;
  final List<TechnologyFinding> technologies;
  final bool bodyTruncated;
  final bool redirectNotFollowed;
  const PassiveScanResult({
    required this.url,
    required this.statusCode,
    required this.links,
    required this.findings,
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
    return scanWithSession(project, url, authorized: authorized, session: session);
  }

  Future<PassiveScanResult> scanWithSession(SecurityProject project, Uri url, {required bool authorized, AuthSession? session}) async {
    if (!authorized || !project.contains(url)) throw StateError('Target outside authorized scope.');
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

    final observation = HttpObservation(headers: headers, body: utf8.decode(bytes, allowMalformed: true));
    final technologies = detector.detect(observation);
    final isHtml = observation.header('content-type').toLowerCase().contains('text/html');

    return PassiveScanResult(
      url: url,
      statusCode: response.statusCode,
      findings: PassiveSecurityChecks().inspect(url, observation),
      links: isHtml && response.statusCode >= 200 && response.statusCode < 300 ? LinkDiscovery.extract(url, observation.body) : [],
      technologies: technologies,
      bodyTruncated: truncated,
      redirectNotFollowed: response.isRedirect,
    );
  }
}
