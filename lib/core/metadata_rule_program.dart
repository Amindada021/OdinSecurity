import 'dart:convert';
import 'fingerprint.dart';
import 'security_checks.dart';

/// Bounded interpreter for declarative metadata rules. No executable code,
/// network, file access, sensitive headers, or response body access.
class MetadataRuleProgram {
  static const schema = 'odin.security.metadata.v1';
  static const headers = {
    'content-type', 'strict-transport-security', 'content-security-policy',
    'x-frame-options', 'x-content-type-options', 'referrer-policy',
    'permissions-policy', 'cache-control',
  };
  final List<_Rule> _rules;
  MetadataRuleProgram._(this._rules);

  factory MetadataRuleProgram.parse(String source) {
    if (source.length > 16000) throw const FormatException('Program too large.');
    final decoded = jsonDecode(source);
    if (decoded is! Map || decoded.length != 2 || decoded['schema'] != schema ||
        decoded['rules'] is! List) throw const FormatException('Invalid program.');
    final records = decoded['rules'] as List;
    if (records.isEmpty || records.length > 20) throw const FormatException('Invalid rule count.');
    final ids = <String>{};
    final rules = <_Rule>[];
    for (final row in records) {
      if (row is! Map || row.length != 3 || row['id'] is! String ||
          !RegExp(r'^[a-z][a-z0-9-]{0,39}$').hasMatch(row['id'] as String) ||
          !ids.add(row['id'] as String) || !['all','any'].contains(row['match']) ||
          row['conditions'] is! List) throw const FormatException('Invalid rule.');
      final conditions = row['conditions'] as List;
      if (conditions.isEmpty || conditions.length > 8) throw const FormatException('Invalid conditions.');
      rules.add(_Rule(row['id'] as String, row['match'] == 'all',
        List.unmodifiable(conditions.map(_Condition.parse))));
    }
    return MetadataRuleProgram._(List.unmodifiable(rules));
  }

  int get ruleCount => _rules.length;

  /// Evaluate a synthetic response, never a network request. Only public
  /// metadata headers from the same allowlist are accepted in fixtures.
  List<SecurityFinding> preview(String source) {
    if (source.length > 16000) throw const FormatException('Fixture too large.');
    final json = jsonDecode(source);
    if (json is! Map || json.length != 2 || json['status'] is! int || json['headers'] is! Map) {
      throw const FormatException('Invalid fixture.');
    }
    final fields = json['headers'] as Map;
    if (fields.length > headers.length) throw const FormatException('Invalid fixture headers.');
    final checked = <String,List<String>>{};
    for (final entry in fields.entries) {
      if (entry.key is! String || !headers.contains(entry.key) || entry.value is! List) {
        throw const FormatException('Unsupported fixture header.');
      }
      final values = entry.value as List;
      if (values.isEmpty || values.length > 20 || values.any((v) => v is! String ||
          v.length > 4096 || v.contains(RegExp(r'[\r\n\x00]')))) {
        throw const FormatException('Invalid fixture values.');
      }
      checked[entry.key as String] = List<String>.from(values);
    }
    return inspect(HttpObservation(headers:checked, body:''), json['status'] as int);
  }

  List<SecurityFinding> inspect(HttpObservation observation, int status) {
    if (status < 100 || status > 599) throw const FormatException('Invalid HTTP status.');
    // Extract only permitted metadata. If the selected header budget is
    // exceeded, report incomplete rather than falsely marking a header absent.
    final sanitized = <String,List<String>>{};
    var size = 0, count = 0;
    for (final name in headers) {
      final values = observation.headers[name];
      if (values == null) continue;
      for (final value in values) {
        size += value.length;
        count++;
        if (count > 200 || size > 65536 || value.length > 16384) {
          return const [SecurityFinding('program.review.limit','Metadata program review incomplete',
            Severity.info,'Selected headers exceeded the processing budget',
            'Review response metadata manually.')];
        }
      }
      sanitized[name] = List<String>.of(values);
    }
    final metadata = HttpObservation(headers:sanitized,body:'');
    final result = <SecurityFinding>[];
    for (final rule in _rules) {
      final matched = rule.all
        ? rule.conditions.every((c) => c.test(metadata, status))
        : rule.conditions.any((c) => c.test(metadata, status));
      if (matched) result.add(SecurityFinding('program.' + rule.id,
        'Metadata rule matched: ' + rule.id, Severity.info,
        'Configured conditions matched; raw values omitted',
        'Review the expected configuration. A match is not proof of a vulnerability.'));
    }
    return List.unmodifiable(result);
  }
}

class _Rule {
  final String id;
  final bool all;
  final List<_Condition> conditions;
  const _Rule(this.id, this.all, this.conditions);
}

class _Condition {
  final String op, header, value;
  final int min, max;
  const _Condition(this.op, {this.header = '', this.value = '', this.min = 0, this.max = 0});
  static _Condition parse(dynamic row) {
    if (row is! Map || row['op'] is! String) throw const FormatException('Invalid condition.');
    final op = row['op'] as String;
    if (op == 'statusRange') {
      final min = row['min'], max = row['max'];
      if (row.length != 3 || min is! int || max is! int || min < 100 || max > 599 || min > max) {
        throw const FormatException('Invalid status range.');
      }
      return _Condition(op, min: min, max: max);
    }
    final header = row['header'];
    if (header is! String || !MetadataRuleProgram.headers.contains(header)) {
      throw const FormatException('Unsupported header.');
    }
    if (['headerPresent','headerAbsent'].contains(op) && row.length == 2) {
      return _Condition(op, header: header);
    }
    final value = row['value'];
    if (op == 'headerEquals' && row.length == 3 && value is String &&
        value.isNotEmpty && value.length <= 160 && !value.contains(RegExp(r'[\x00-\x1f\x7f]'))) {
      return _Condition(op, header: header, value: value);
    }
    throw const FormatException('Unsupported condition.');
  }
  bool test(HttpObservation observation, int status) => switch (op) {
    'statusRange' => status >= min && status <= max,
    'headerPresent' => observation.headers.containsKey(header),
    'headerAbsent' => !observation.headers.containsKey(header),
    'headerEquals' => observation.header(header).trim().toLowerCase() == value.toLowerCase(),
    _ => false,
  };
}
