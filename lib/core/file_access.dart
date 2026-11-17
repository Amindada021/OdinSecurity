import 'dart:io';
import 'dart:convert';
import 'auth.dart';

/// The caller checks scope, policy and the shared crawl budget before each GET.
Future<({int status, String outcome})> checkLinkedFile(Uri url, AuthSession? session, {bool movie = false}) async {
  final client = HttpClient()..connectionTimeout = const Duration(seconds: 8);
  Future<({int status, String outcome})> read() async {
    final headers = session?.headersFor(url) ?? const <String, String>{};
    if (session?.expectsCredentials == true && headers.isEmpty) {
      return (status: 0, outcome: 'Outside session scope');
    }
    final request = await client.getUrl(url);
    request.followRedirects = false;
    headers.forEach((key, value) => request.headers.set(key, value));
    request.headers.set(HttpHeaders.rangeHeader, 'bytes=0-511');
    final response = await request.close();
    final status = response.statusCode;
    if (status == 401 || status == 403) return (status: status, outcome: 'Access denied');
    if (status != 200 && status != 206) return (status: status, outcome: 'Unconfirmed');
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
      if (looksLikeError) return (status: status, outcome: 'Unconfirmed');
      if (sample.startsWith('#extm3u') || sample.contains('<mpd')) {
        return (status: status, outcome: 'Playlist returned');
      }
      final iso = bytes.length >= 12 && latin1.decode(bytes.sublist(4, 8)) == 'ftyp';
      final ebml = bytes.length >= 4 && bytes[0] == 0x1a && bytes[1] == 0x45 && bytes[2] == 0xdf && bytes[3] == 0xa3;
      final segment = bytes.length > 376 && bytes[0] == 0x47 && bytes[188] == 0x47 && bytes[376] == 0x47;
      return (status: status, outcome: iso || ebml || segment ? 'Media bytes returned' : 'Unconfirmed');
    }
    final fileType = type.startsWith('image/') || type.startsWith('audio/') || type.startsWith('video/') ||
        const {'application/pdf', 'application/zip', 'application/octet-stream', 'text/csv',
          'application/msword', 'application/gzip', 'application/vnd.rar', 'application/x-7z-compressed'}.contains(type) ||
        type.startsWith('application/vnd.openxmlformats') || type.startsWith('application/vnd.ms-') ||
        (response.headers['content-disposition'] ?? const <String>[]).any((v) => v.toLowerCase().startsWith('attachment')) ||
        (type == 'text/plain' && url.path.toLowerCase().endsWith('.txt'));
    return (status: status, outcome: bytes.isNotEmpty && fileType && !looksLikeError ? 'File accessible' : 'Unconfirmed');
  }
  try {
    return await read().timeout(const Duration(seconds: 12));
  } finally {
    client.close(force: true);
  }
}
