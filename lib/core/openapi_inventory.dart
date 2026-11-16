import 'dart:convert';

class ApiOperation {
  final String method, path, title;
  const ApiOperation(this.method, this.path, this.title);
}

class OpenApiInventory {
  static const methods = {'get', 'head', 'options', 'post', 'put', 'patch', 'delete', 'trace'};

  /// Offline import only: never resolves remote references or calls endpoints.
  List<ApiOperation> parse(String source) {
    if (source.length > 1024 * 1024) throw const FormatException('Specification exceeds 1 MiB.');
    final document = jsonDecode(source);
    if (document is! Map || (document['openapi'] == null && document['swagger'] == null)) {
      throw const FormatException('Expected Swagger/OpenAPI JSON.');
    }
    final paths = document['paths'];
    if (paths is! Map) throw const FormatException('No paths object.');
    final result = <ApiOperation>[];
    for (final entry in paths.entries) {
      final path = entry.key;
      if (path is! String || !path.startsWith('/') || path.startsWith('//') || entry.value is! Map) continue;
      for (final operation in (entry.value as Map).entries) {
        final key = operation.key.toString().toLowerCase();
        if (!methods.contains(key) || operation.value is! Map) continue;
        final details = operation.value as Map;
        final title = details['summary'] ?? details['operationId'] ?? '';
        result.add(ApiOperation(key.toUpperCase(), path, title.toString()));
        if (result.length >= 2000) return List.unmodifiable(result);
      }
    }
    return List.unmodifiable(result);
  }
}
