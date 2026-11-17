import 'dart:convert';
import 'dart:io';

import 'fingerprint.dart';
import 'asset_discovery.dart';
import 'project.dart';
import 'auth.dart';
import 'scan_policy.dart';
import 'discovery.dart';
import 'security_checks.dart';
import 'custom_rules.dart';
import 'metadata_rule_program.dart';
import 'header_policy_checks.dart';
import 'csp_review.dart';
import 'frame_protection_review.dart';
import 'html_security_checks.dart';
import 'api_response_checks.dart';
import 'tls_audit.dart';
import 'traffic_journal.dart';

class PassiveScanResult {
  final Uri url;
  final int statusCode;
  final List<Uri> links, fileLinks, queryFilePaths;
  final List<SecurityFinding> findings;
  final List<TechnologyFinding> technologies;
  final bool bodyTruncated;
  final bool redirectNotFollowed;
  final int bodyBytes;
  final bool loginPage, moviePage;
  final String? retryAfter;
  final Map<String, int> discoveryExclusions;
  final List<AssetReference> assets;
  final bool directoryListing;
  const PassiveScanResult({
    required this.url,
    required this.statusCode,
    required this.links,
    this.fileLinks = const [],
    this.queryFilePaths = const [],
    required this.findings,
    required this.technologies,
    required this.bodyTruncated,
    required this.redirectNotFollowed,
    this.bodyBytes = 0,
    this.loginPage = false,
    this.moviePage = false,
    this.retryAfter,
    this.discoveryExclusions = const {},
    this.assets = const [],
    this.directoryListing = false,
  });
}

/// Fetches only the single, explicitly approved starting URL.
/// No crawling, redirects, or vulnerability probes yet.
class PassiveScanner {
  static const maxBytes = 256 * 1024;
  static const maxHtmlBytes = 2 * 1024 * 1024;
  final TechnologyDetector detector;
  final List<HeaderRule> customRules;
  final MetadataRuleProgram? metadataProgram;
  PassiveScanner({TechnologyDetector? detector, List<HeaderRule> customRules = const [], this.metadataProgram}) :
    detector = detector ?? TechnologyDetector(), customRules = List.unmodifiable(customRules);

  /// Both configured rule families consume the already acquired response.
  /// Legacy header checks retain their successful-response-only behavior.
  List<SecurityFinding> inspectConfiguredRules(HttpObservation observation, int status) =>
    List.unmodifiable([
      if (status >= 200 && status < 300) ...CustomHeaderRules.inspect(customRules, observation),
      if (metadataProgram != null) ...metadataProgram!.inspect(observation, status),
    ]);

  Future<PassiveScanResult> scan(SecurityProject project, {required bool authorized, Uri? target, AuthProfile? auth, bool Function(Uri)? permits, ScanPolicy? policy, void Function(int)? onRequests}) async {
    if (!authorized) throw StateError('Explicit authorization is required.');
    final url = target ?? project.startUrl;
    if (!project.contains(url) || (policy != null && !policy.permits(url)) || (permits != null && !permits(url))) throw StateError('Target is outside scope.');
    if (auth != null && !SecurityProject.sameOrigin(auth.target, url)) throw StateError('Select the matching credential origin.');
    final settings = policy ?? ScanPolicy();
    var requests = 0;
    Future<void> beforeRequest() async {
      if (settings.exhausted(requests)) throw StateError('Request budget exhausted.');
      if (requests > 0) await Future<void>.delayed(Duration(milliseconds: settings.delayMs));
      requests++;
      onRequests?.call(requests);
    }
    final session = auth == null ? null : await Authenticator().authenticate(project, auth,
      authorized: authorized, permits: (candidate) => settings.permits(candidate) && (permits?.call(candidate) ?? true),
      beforeRequest: beforeRequest);
    final cached = session?.validationResponse;
    if (cached != null && LinkDiscovery.canonical(cached.url) == LinkDiscovery.canonical(url)) {
      session?.validationResponse = null;
      return inspectObservation(url, HttpObservation(headers: cached.headers, body: cached.body),
        statusCode: cached.status, truncated: false, bodyBytes: cached.byteCount, identityHeadersSent: true);
    }
    await beforeRequest();
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
    final identityHeaders = session?.headersFor(url) ?? const <String, String>{};
    if (session?.expectsCredentials == true && identityHeaders.isEmpty) {
      throw StateError('Saved identity has no applicable credentials for this URL.');
    }
    final request = await client.getUrl(url);
    request.followRedirects = false;
    request.headers.set(HttpHeaders.acceptHeader, 'text/html, application/json;q=0.9, */*;q=0.1');
    identityHeaders.forEach((key, value) => request.headers.set(key, value));
    final response = await request.close();
    final certificate = response.certificate;
    final headers = <String, List<String>>{};
    response.headers.forEach((name, values) => headers[name] = List.of(values));
    final htmlResponse = (response.headers.contentType?.mimeType ?? '').contains('html');
    final byteLimit = htmlResponse ? maxHtmlBytes : maxBytes;
    final bytes = <int>[];
    var truncated = false;
    await for (final chunk in response) {
      final remaining = byteLimit - bytes.length;
      if (chunk.length > remaining) {
        bytes.addAll(chunk.take(remaining));
        truncated = true;
        break;
      }
      bytes.addAll(chunk);
    }

    if (response.statusCode == 206) {
      final total = RegExp(r'/([0-9]+)$').firstMatch(response.headers.value('content-range') ?? '');
      if (total == null || (int.tryParse(total.group(1)!) ?? bytes.length + 1) > bytes.length) truncated = true;
    }
    final observation = HttpObservation(headers: headers, body: utf8.decode(bytes, allowMalformed: true));
    return inspectObservation(url, observation, statusCode: response.statusCode,
      truncated: truncated, bodyBytes: bytes.length, redirectNotFollowed: response.isRedirect,
      identityHeadersSent: identityHeaders.isNotEmpty, certificateStart: certificate?.startValidity,
      certificateEnd: certificate?.endValidity);
  }

  PassiveScanResult inspectObservation(Uri url, HttpObservation observation, {
    required int statusCode, required bool truncated, required int bodyBytes,
    bool redirectNotFollowed = false, bool identityHeadersSent = false,
    DateTime? certificateStart, DateTime? certificateEnd,
  }) {
    final technologies = detector.detect(observation);
    final isHtml = observation.header('content-type').toLowerCase().contains('text/html');

    return PassiveScanResult(
      url: url,
      statusCode: statusCode,
      findings: List.unmodifiable([
        ...PassiveSecurityChecks().inspect(url, observation),
        ...AssetDiscovery.findings(url, status: statusCode, contentType: observation.header('content-type'),
          listing: isHtml && AssetDiscovery.directoryListing(observation.body), complete: !truncated),
        ...ApiResponseChecks.inspect(observation, status: statusCode, truncated: truncated),
        ...HeaderPolicyChecks.inspect(url, observation, status: statusCode, identityHeadersSent: identityHeadersSent),
        if (isHtml && statusCode >= 200 && statusCode < 300) ...CspReview.inspect(observation),
        if (statusCode >= 200 && statusCode < 300) ...FrameProtectionReview.inspect(observation),
        if (isHtml && !truncated && statusCode >= 200 && statusCode < 300) ...HtmlSecurityChecks.inspect(url, observation.body),
        ...inspectConfiguredRules(observation, statusCode),
        if (certificateStart != null && certificateEnd != null) ...CertificateChecks.inspect(certificateStart, certificateEnd, DateTime.now()),
      ]),
      links: isHtml && statusCode >= 200 && statusCode < 300 ? LinkDiscovery.extract(url, observation.body, limit: 1000) : [],
      fileLinks: isHtml && statusCode >= 200 && statusCode < 300
          ? LinkDiscovery.extract(url, observation.body, files: true, limit: 1000) : const [],
      queryFilePaths: isHtml && statusCode >= 200 && statusCode < 300
          ? LinkDiscovery.queryFilePaths(url, observation.body) : const [],
      discoveryExclusions: isHtml ? LinkDiscovery.exclusions(url, observation.body) : const {},
      assets: isHtml && statusCode >= 200 && statusCode < 300
          ? AssetDiscovery.fromHtml(url, observation.body) : const [],
      directoryListing: isHtml && AssetDiscovery.directoryListing(observation.body),
      technologies: technologies,
      bodyTruncated: truncated,
      bodyBytes: bodyBytes,
      redirectNotFollowed: redirectNotFollowed,
      moviePage: isHtml && (RegExp(r'<(video|audio)\b', caseSensitive: false).hasMatch(observation.body) ||
          LinkDiscovery.extract(url, observation.body, files: true).any(LinkDiscovery.isMedia)),
      loginPage: Authenticator.looksLikeLogin(observation.body) ||
          Authenticator.loginRedirect(statusCode, observation.header('location')),
      retryAfter: Authenticator.safeRetryAfter(observation.header('retry-after')),
    );
  }
}
