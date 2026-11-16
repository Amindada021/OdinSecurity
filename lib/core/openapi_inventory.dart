import 'dart:convert';

enum ApiSecurityDeclaration { unspecified, anonymousAllowed, authRequired, invalid }

class ApiOperation {
  final String method, path, title;
  final ApiSecurityDeclaration security;
  final bool httpDeclared, authErrorDocumented;
  const ApiOperation(this.method, this.path, this.title, {
    this.security = ApiSecurityDeclaration.unspecified,
    this.httpDeclared = false, this.authErrorDocumented = false,
  });
}

class OpenApiInventory {
  static const methods = {'get', 'head', 'options', 'post', 'put', 'patch', 'delete', 'trace'};
  static const maxBytes = 1024 * 1024;

  /// Evaluate the declaration, not runtime authorization. An empty security
  /// array or empty requirement object explicitly permits anonymous access.
  static ApiSecurityDeclaration declaration(Object? raw, Set<String> schemes, {required bool present}) {
    if (!present) return ApiSecurityDeclaration.unspecified;
    if (raw is! List) return ApiSecurityDeclaration.invalid;
    if (raw.isEmpty) return ApiSecurityDeclaration.anonymousAllowed;
    var anonymous = false;
    for (final requirement in raw) {
      if (requirement is! Map) return ApiSecurityDeclaration.invalid;
      if (requirement.isEmpty) anonymous = true;
      for (final entry in requirement.entries) {
        if (!schemes.contains(entry.key) || entry.value is! List ||
            !(entry.value as List).every((scope) => scope is String)) return ApiSecurityDeclaration.invalid;
      }
    }
    return anonymous ? ApiSecurityDeclaration.anonymousAllowed : ApiSecurityDeclaration.authRequired;
  }

  static bool _httpDeclared(Map document, Map path, Map operation, bool swagger) {
    if (swagger) {
      final schemes = operation['schemes'] ?? document['schemes'];
      return schemes is List && schemes.any((value) => value is String && value.toLowerCase() == 'http');
    }
    final servers = operation['servers'] ?? path['servers'] ?? document['servers'];
    return servers is List && servers.any((server) {
      if (server is! Map || server['url'] is! String) return false;
      return (server['url'] as String).trim().toLowerCase().startsWith('http://');
    });
  }

  /// Offline import only: never resolves remote references or calls endpoints.
  List<ApiOperation> parse(String source) {
    if (source.length > maxBytes || utf8.encode(source).length > maxBytes) throw const FormatException('Specification exceeds 1 MiB.');
    final document = jsonDecode(source);
    if (document is! Map || (document['openapi'] == null && document['swagger'] == null)) {
      throw const FormatException('Expected Swagger/OpenAPI JSON.');
    }
    final swagger = document['swagger'] != null;
    final definitions = swagger ? document['securityDefinitions'] :
      (document['components'] is Map ? (document['components'] as Map)['securitySchemes'] : null);
    final schemes = definitions is Map ? definitions.keys.whereType<String>().toSet() : <String>{};
    final paths = document['paths'];
    if (paths is! Map) throw const FormatException('No paths object.');
    final result = <ApiOperation>[];
    for (final entry in paths.entries) {
      final path = entry.key;
      final pathItem = entry.value;
      if (path is! String || !path.startsWith('/') || path.startsWith('//') || path.length > 2048 || pathItem is! Map) continue;
      for (final operation in pathItem.entries) {
        final key = operation.key.toString().toLowerCase();
        final details = operation.value;
        if (!methods.contains(key) || details is! Map) continue;
        final title = (details['summary'] ?? details['operationId'] ?? '').toString();
        final securitySource = details.containsKey('security') ? details : document;
        final security = declaration(securitySource['security'], schemes, present: securitySource.containsKey('security'));
        final responses = details['responses'];
        result.add(ApiOperation(key.toUpperCase(), path, title,
          security: security, httpDeclared: _httpDeclared(document, pathItem, details, swagger),
          authErrorDocumented: responses is Map && (responses.containsKey('401') || responses.containsKey('403'))));
        if (result.length >= 2000) return List.unmodifiable(result);
      }
    }
    return List.unmodifiable(result);
  }
}
