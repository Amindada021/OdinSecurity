import 'dart:convert';
import 'dart:io';

import 'fingerprint.dart';
import 'project.dart';
import 'auth.dart';
import 'discovery.dart';
import 'security_checks.dart';
import 'custom_rules.dart';
import 'header_policy_checks.dart';
import 'html_security_checks.dart';
import 'tls_audit.dart';
import 'traffic_journal.dart';

class PassiveScanResult {
  final Uri url;
  final int statusCode;
  final List<Uri> links;
  final List<SecurityFinding> findings;
  final List<TechnologyFinding> technologies;
  final bool bodyTruncated;
  final bool redirectNotFollowed;
  final int bodyBytes;
  const PassiveScanResult({
    required this.url,
    required this.statusCode,
    required this.links,
    required this.findings,
    required this.technologies,
    required this.bodyTruncated,
    required this.redirectNotFollowed,
    this.bodyBytes = 0,
  });
}

/// Fetches only the single, explicitly approved starting URL.
/// No crawling, redirects, or vulnerability probes yet.
class PassiveScanner {
  static const maxBytes = 256 * 1024;
  final TechnologyDetector detector;
  final List<HeaderRule> customRules;
  PassiveScanner({TechnologyDetector? detector, List<HeaderRule> customRules = const []}) :
    detector = detector ?? TechnologyDetector(), customRules = List.unmodifiable(customRules);

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

    final timer = Stopwatch()..start();
    try {
      final result = await _fetch(client, url, session).timeout(const Duration(seconds: 25));
      TrafficJournal.shared.record(project, url, source: 'passive', method: 'GET',
        status: result.statusCode, capturedBytes: result.bodyBytes, elapsedMs: timer.elapsedMilliseconds, truncated: result.bodyTruncated);
      return result;
    } catch (_) {
      TrafficJournal.shared.record(project, url, source: 'passive', method: 'GET', elapsedMs: timer.elapsedMilliseconds);
      rethrow;
    } finally {
      client.close(force: true);
    }
  }

  Future<PassiveScanResult> _fetch(HttpClient client, Uri url, AuthSession? session) async {
    final request = await client.getUrl(url);
    request.followRedirects = false;
    request.headers.set(HttpHeaders.acceptHeader, 'text/html, application/json;q=0.9, */*;q=0.1');
    final identityHeaders = session?.headersFor(url) ?? const <String, String>{};
    identityHeaders.forEach((key, value) => request.headers.set(key, value));
    final response = await request.close();
    final certificate = response.certificate;
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
      findings: List.unmodifiable([
        ...PassiveSecurityChecks().inspect(url, observation),
        ...HeaderPolicyChecks.inspect(url, observation, status: response.statusCode, identityHeadersSent: identityHeaders.isNotEmpty),
        if (isHtml && !truncated && response.statusCode >= 200 && response.statusCode < 300) ...HtmlSecurityChecks.inspect(url, observation.body),
        if (response.statusCode >= 200 && response.statusCode < 300) ...CustomHeaderRules.inspect(customRules, observation),
        if (certificate != null) ...CertificateChecks.inspect(certificate.startValidity, certificate.endValidity, DateTime.now()),
      ]),
      links: isHtml && response.statusCode >= 200 && response.statusCode < 300 ? LinkDiscovery.extract(url, observation.body) : [],
      technologies: technologies,
      bodyTruncated: truncated,
      bodyBytes: bytes.length,
      redirectNotFollowed: response.isRedirect,
    );
  }
}
