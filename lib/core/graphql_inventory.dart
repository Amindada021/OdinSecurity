import 'dart:convert';

enum GraphQlOperation { query, mutation, subscription }

class GraphQlField {
  final GraphQlOperation operation;
  final String rootType, name;
  final int argumentCount;
  const GraphQlField(this.operation, this.rootType, this.name, this.argumentCount);
}

class GraphQlInventory {
  static const maxChars = 1024 * 1024;
  static const maxFields = 300;
  static final _identifier = RegExp(r'^[_A-Za-z][_0-9A-Za-z]*$');

  /// Reads an existing, sanitized introspection response locally.
  /// No query creation, network access or automatic operation execution.
  static List<GraphQlField> parse(String text) {
    if (text.length > maxChars) throw const FormatException('Input too large.');
    final json = jsonDecode(text);
    if (json is! Map) throw const FormatException('Expected JSON object.');
    final data = json['data'];
    final schema = data is Map ? data['__schema'] : json['__schema'];
    if (schema is! Map || schema['types'] is! List) {
      throw const FormatException('Invalid introspection schema.');
    }
    final types = <String, Map>{};
    for (final type in schema['types'] as List) {
      if (type is Map && type['name'] is String) {
        final name = type['name'] as String;
        if (_identifier.hasMatch(name)) types[name] = type;
      }
    }
    final result = <GraphQlField>[];
    final seen = <String>{};
    for (final operation in GraphQlOperation.values) {
      final root = schema['${operation.name}Type'];
      if (root == null) continue;
      if (root is! Map || root['name'] is! String) {
        throw const FormatException('Invalid operation root.');
      }
      final name = root['name'] as String;
      final fields = types[name]?['fields'];
      if (!_identifier.hasMatch(name) || fields is! List) {
        throw const FormatException('Missing root field definitions.');
      }
      for (final field in fields) {
        if (field is! Map || field['name'] is! String || field['args'] is! List) {
          throw const FormatException('Invalid field definition.');
        }
        final fieldName = field['name'] as String;
        if (!_identifier.hasMatch(fieldName)) throw const FormatException('Invalid field name.');
        if (!seen.add('${operation.name}:$fieldName')) continue;
        if (result.length >= maxFields) throw const FormatException('Too many fields.');
        result.add(GraphQlField(operation, name, fieldName, (field['args'] as List).length));
      }
    }
    return List.unmodifiable(result);
  }
}
