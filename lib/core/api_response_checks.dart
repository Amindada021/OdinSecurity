import 'dart:convert';
import 'fingerprint.dart';
import 'security_checks.dart';

/// Passive structured JSON observations. No extra request, payload injection,
/// secret extraction or retention. Field values never appear in findings.
class ApiResponseChecks {
  static const maxNodes = 5000;
  static const maxDepth = 24;
  static const maxBytes = 256 * 1024;

  static bool isJson(String contentType) {
    final media = contentType.split(';').first.trim().toLowerCase();
    return media == 'application/json' || media.endsWith('+json');
  }

  static List<SecurityFinding> inspect(HttpObservation observation, {
      required int status, required bool truncated}) {
    if (truncated || !isJson(observation.header('content-type')) ||
        observation.body.length > maxBytes || utf8.encode(observation.body).length > maxBytes ||
        status == 204 || status == 304) return const [];
    Object? root;
    try { root = jsonDecode(observation.body); } on FormatException {
      return const [SecurityFinding('api.json.invalid', 'Declared JSON could not be parsed', Severity.info,
        'Complete response declares a JSON media type but could not be parsed as JSON',
        'Check response serialization and content-type declarations.')];
    }
    final pending = <(Object?, int)>[(root, 0)];
    var visited = 0;
    var secret = false, trace = false, token = false;
    bool populated(Object? value) => value is String && value.trim().isNotEmpty ||
      value is List && value.isNotEmpty || value is Map && value.isNotEmpty;
    while (pending.isNotEmpty && visited < maxNodes) {
      final (node, depth) = pending.removeLast();
      visited++;
      if (depth >= maxDepth) continue;
      if (node is Map) {
        for (final entry in node.entries) {
          final key = entry.key.toString().toLowerCase().replaceAll(RegExp(r'[^a-z0-9]'), '');
          final value = entry.value;
          if (populated(value)) {
            if (['passwordhash', 'privatekey', 'clientsecret', 'connectionstring', 'signingkey'].contains(key)) secret = true;
            if (['accesstoken', 'refreshtoken', 'idtoken'].contains(key)) token = true;
            if (['stacktrace', 'exceptionstacktrace'].contains(key)) trace = true;
          }
          if ((value is Map || value is List) && pending.length < maxNodes) pending.add((value, depth + 1));
        }
      } else if (node is List) {
        for (final item in node) {
          if ((item is Map || item is List) && pending.length < maxNodes) pending.add((item, depth + 1));
        }
      }
    }
    final result = <SecurityFinding>[];
    if (secret) result.add(const SecurityFinding('api.json.secret.fields', 'Potentially sensitive internal JSON fields', Severity.medium,
      'Response includes populated fields named like internal credentials or key material; names and values omitted',
      'Review the response DTO and authorization. Remove internal fields from client-facing responses.'));
    if (trace) result.add(const SecurityFinding('api.json.stacktrace', 'Stack trace field in JSON response', Severity.low,
      'Response contains a populated stack trace-like field; contents omitted',
      'Return sanitized errors and retain internal diagnostics in protected server logs.'));
    if (token) result.add(const SecurityFinding('api.json.token.fields', 'Token-like response fields observed', Severity.info,
      'Response contains populated token-like JSON fields; values omitted',
      'Confirm the response is an intended authentication exchange and not cached or exposed to unrelated clients.'));
    return List.unmodifiable(result);
  }
}
