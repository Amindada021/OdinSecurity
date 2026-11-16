import 'dart:io';
import 'discovery.dart';
import 'project.dart';
import 'scan_policy.dart';

enum CorsOutcome { notAdvertised, wildcard, testOriginAllowed, testOriginWithCredentials, inconclusive }

class CorsMetadata {
  final int status;
  final List<String> origins, credentials, methods;
  const CorsMetadata(this.status, this.origins, this.credentials, this.methods);
}

class CorsAuditResult {
  final int status;
  final CorsOutcome outcome;
  final bool getAdvertised;
  const CorsAuditResult(this.status, this.outcome, this.getAdvertised);

  static CorsAuditResult classify(CorsMetadata data) {
    final status = data.status;
    if (status < 200 || status >= 300 || data.origins.length > 1 ||
        data.credentials.length > 1 || data.origins.any((v) => v.contains(','))) {
      return CorsAuditResult(status, CorsOutcome.inconclusive, false);
    }
    final origin = data.origins.isEmpty ? '' : data.origins.single.trim();
    final credentials = data.credentials.length == 1 && data.credentials.single.trim() == 'true';
    final getAdvertised = data.methods.expand((v) => v.split(',')).any((v) => v.trim() == 'GET');
    final outcome = origin == CorsAudit.testOrigin
      ? (credentials ? CorsOutcome.testOriginWithCredentials : CorsOutcome.testOriginAllowed)
      : origin == '*' ? CorsOutcome.wildcard : CorsOutcome.notAdvertised;
    return CorsAuditResult(status, outcome, getAdvertised);
  }
}

abstract interface class CorsProbe {
  Future<CorsMetadata> inspect(Uri endpoint);
}

class HttpCorsProbe implements CorsProbe {
  @override
  Future<CorsMetadata> inspect(Uri endpoint) async {
    final client = HttpClient()..connectionTimeout = const Duration(seconds: 10);
    try {
      return await _inspect(client, endpoint).timeout(const Duration(seconds: 20));
    } finally {
      client.close(force: true);
    }
  }

  Future<CorsMetadata> _inspect(HttpClient client, Uri endpoint) async {
    final request = await client.openUrl('OPTIONS', endpoint);
    request.followRedirects = false;
    request.headers.set('Origin', CorsAudit.testOrigin);
    request.headers.set('Access-Control-Request-Method', 'GET');
    // No cookies, authorization, custom payload, or actual cross-origin GET.
    final response = await request.close();
    return CorsMetadata(response.statusCode,
      List.of(response.headers['access-control-allow-origin'] ?? const []),
      List.of(response.headers['access-control-allow-credentials'] ?? const []),
      List.of(response.headers['access-control-allow-methods'] ?? const []));
    // Only response headers are inspected. The enclosing client is closed.
  }
}

/// One unauthenticated preflight request to one explicitly approved endpoint.
/// No discovery, repeated probes, actual cross-origin data access, or bypass.
class CorsAudit {
  static const testOrigin = 'https://odin-security.invalid';
  final CorsProbe probe;
  CorsAudit({CorsProbe? probe}) : probe = probe ?? HttpCorsProbe();

  Future<CorsAuditResult> run(SecurityProject project, Uri endpoint, ScanPolicy policy, {required bool authorized}) async {
    if (!authorized || endpoint.scheme != 'https' || !project.contains(endpoint) ||
        !policy.permits(endpoint) || endpoint.hasFragment || !LinkDiscovery.eligible(endpoint, endpoint)) {
      throw StateError('Select an authorized read-only HTTPS endpoint.');
    }
    return CorsAuditResult.classify(await probe.inspect(endpoint));
  }
}
