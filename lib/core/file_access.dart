import 'dart:io';
import 'dart:convert';
import 'auth.dart';

/// The caller checks scope, policy and the shared crawl budget before each request.
Future<({int status, String outcome, String? retryAfter})> checkLinkedFile(Uri url, AuthSession? session, {bool movie = false}) async {
  final client = HttpClient()..connectionTimeout = const Duration(seconds: 8);
  Future<({int status, String outcome, String? retryAfter})> read() async {
    final headers = session?.headersFor(url) ?? const <String, String>{};
    if (session?.expectsCredentials == true && headers.isEmpty) {
      return (status: 0, outcome: 'Outside session scope', retryAfter: null);
    }
    final request = await client.openUrl(movie ? 'GET' : 'HEAD', url);
    request.followRedirects = false;
    headers.forEach((key, value) => request.headers.set(key, value));
    if (movie) request.headers.set(HttpHeaders.rangeHeader, 'bytes=0-511');
    final response = await request.close();
    final status = response.statusCode;
    final retry = Authenticator.safeRetryAfter(response.headers.value('retry-after'));
    ({int status, String outcome, String? retryAfter}) result(String outcome) =>
      (status: status, outcome: outcome, retryAfter: retry);
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
