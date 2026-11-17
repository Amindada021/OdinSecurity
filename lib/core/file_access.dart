import 'dart:io';
import 'dart:convert';
import 'auth.dart';
import 'asset_discovery.dart';
import 'discovery.dart';
import 'security_checks.dart';

/// The caller checks scope, policy and the shared crawl budget before each request.
Future<({int status, String outcome, String? retryAfter, String contentType, int? sizeBytes})> checkLinkedFile(Uri url, AuthSession? session, {bool movie = false}) async {
  final client = HttpClient()..connectionTimeout = const Duration(seconds: 8);
  Future<({int status, String outcome, String? retryAfter, String contentType, int? sizeBytes})> read() async {
    final headers = session?.headersFor(url) ?? const <String, String>{};
    if (session?.expectsCredentials == true && headers.isEmpty) {
      return (status: 0, outcome: 'Outside session scope', retryAfter: null, contentType: '', sizeBytes: null);
    }
    final request = await client.openUrl(movie ? 'GET' : 'HEAD', url);
    request.followRedirects = false;
    headers.forEach((key, value) => request.headers.set(key, value));
    if (movie) request.headers.set(HttpHeaders.rangeHeader, 'bytes=0-511');
    final response = await request.close();
    final status = response.statusCode;
    final retry = Authenticator.safeRetryAfter(response.headers.value('retry-after'));
    final contentType = response.headers.contentType?.mimeType.toLowerCase() ?? '';
    final sizeBytes = response.contentLength < 0 ? null : response.contentLength;
    ({int status, String outcome, String? retryAfter, String contentType, int? sizeBytes}) result(String outcome) =>
      (status: status, outcome: outcome, retryAfter: retry, contentType: contentType, sizeBytes: sizeBytes);
    if (status == 401 || status == 403) return result('Access denied');
    if (status != 200 && status != 206) return result('Unconfirmed');
    if (!movie) {
      final type = response.headers.contentType?.mimeType.toLowerCase() ?? '';
      return result(type.contains('html') || type.contains('json') ? 'Unconfirmed' : 'File metadata available');
    }
    final bytes = <int>[];
    await for (final chunk in response) {
      bytes.addAll(chunk.take(512 - bytes.length));
      if (bytes.length == 512) break;
    }
    final type = response.headers.contentType?.mimeType.toLowerCase() ?? '';
    final sample = latin1.decode(bytes).trimLeft().toLowerCase();
    final looksLikeError = sample.startsWith('<!doctype html') || sample.startsWith('<html') ||
        sample.startsWith('{') || sample.startsWith('[') || type.contains('html') || type.contains('json');
    if (movie) {
      if (looksLikeError) return result('Unconfirmed');
      if (sample.startsWith('#extm3u') || sample.contains('<mpd')) {
        return result('Playlist returned');
      }
      final iso = bytes.length >= 12 && latin1.decode(bytes.sublist(4, 8)) == 'ftyp';
      final ebml = bytes.length >= 4 && bytes[0] == 0x1a && bytes[1] == 0x45 && bytes[2] == 0xdf && bytes[3] == 0xa3;
      final segment = bytes.length > 376 && bytes[0] == 0x47 && bytes[188] == 0x47 && bytes[376] == 0x47;
      return result(iso || ebml || segment ? 'Media bytes returned' : 'Unconfirmed');
    }
    return result('Unconfirmed');
  }
  try {
    return await read().timeout(const Duration(seconds: 12));
  } finally {
    client.close(force: true);
  }
}

/// No response body is retained in a probe result. A HEAD response establishes
/// metadata accessibility only. Text discovery uses one separately budgeted GET.
class AssetProbeResult {
  final int status;
  final String outcome, contentType;
  final int? sizeBytes;
  final String? retryAfter;
  final bool truncated, listing, loginPage;
  final List<AssetReference> references;
  final List<Uri> pageLinks;
  final List<SecurityFinding> findings;
  const AssetProbeResult({required this.status, required this.outcome,
    this.contentType = '', this.sizeBytes, this.retryAfter, this.truncated = false,
    this.listing = false, this.loginPage = false, this.references = const [],
    this.pageLinks = const [], this.findings = const []});
}

Future<AssetProbeResult> inspectAsset(Uri url, AuthSession? session, {bool readText = false}) async {
  final client = HttpClient()..connectionTimeout = const Duration(seconds: 8);
  Future<AssetProbeResult> read() async {
    final headers = session?.headersFor(url) ?? const <String, String>{};
    if (session?.expectsCredentials == true && headers.isEmpty) {
      return const AssetProbeResult(status: 0, outcome: 'Outside session scope');
    }
    final request = await client.openUrl(readText ? 'GET' : 'HEAD', url);
    request.followRedirects = false;
    headers.forEach((key, value) => request.headers.set(key, value));
    const limit = 256 * 1024;
    if (readText) request.headers.set(HttpHeaders.rangeHeader, 'bytes=0-${limit - 1}');
    final response = await request.close();
    final status = response.statusCode;
    final type = response.headers.contentType?.mimeType.toLowerCase() ?? '';
    final retry = Authenticator.safeRetryAfter(response.headers.value('retry-after'));
    final rawSize = response.contentLength;
    final total = RegExp(r'/([0-9]+)$').firstMatch(response.headers.value('content-range') ?? '');
    final size = total == null ? (rawSize >= 0 ? rawSize : null) : int.tryParse(total.group(1)!);
    final redirectLogin = Authenticator.loginRedirect(status, response.headers.value('location'));
    final success = status >= 200 && status < 300;
    if (!readText || !success) {
      return AssetProbeResult(status: status, outcome: status == 401 || status == 403 ? 'Access denied' :
          success && !type.contains('html') ? 'File metadata available' : 'Unconfirmed',
        contentType: type, sizeBytes: size, retryAfter: retry, loginPage: redirectLogin,
        findings: AssetDiscovery.findings(url, status: status, contentType: type, listing: false, complete: false));
    }
    // Never read binary media/archives, even if a server ignores Range.
    if (!(type.contains('html') || type.contains('css') || type.contains('javascript') ||
          type.contains('json') || type.startsWith('text/'))) {
      return AssetProbeResult(status: status, outcome: 'Binary body not downloaded', contentType: type,
        sizeBytes: size, retryAfter: retry);
    }
    final bytes = <int>[];
    var truncated = response.statusCode == 206;
    await for (final chunk in response) {
      final remaining = limit - bytes.length;
      bytes.addAll(chunk.take(remaining));
      if (chunk.length > remaining) { truncated = true; break; }
    }
    if (response.statusCode == 206 && size != null && bytes.length >= size) truncated = false;
    final text = utf8.decode(bytes, allowMalformed: true);
    final htmlBody = type.contains('html');
    final listing = htmlBody && AssetDiscovery.directoryListing(text);
    final login = htmlBody && Authenticator.looksLikeLogin(text);
    return AssetProbeResult(status: status, outcome: login ? 'Sign-in page received' : listing ? 'Directory listing observed' : 'Bounded text inspected',
      contentType: type, sizeBytes: size, retryAfter: retry, truncated: truncated,
      listing: listing, loginPage: login,
      references: login ? const [] : htmlBody ? AssetDiscovery.fromHtml(url, text) :
        AssetDiscovery.fromText(url, text, css: type.contains('css') || url.path.toLowerCase().endsWith('.css')),
      pageLinks: listing && !login ? LinkDiscovery.extract(url, text, limit: 1000) : const [],
      findings: login ? const [] : AssetDiscovery.findings(url, status: status, contentType: type, listing: listing, complete: !truncated));
  }
  try { return await read().timeout(const Duration(seconds: 15)); }
  finally { client.close(force: true); }
}
