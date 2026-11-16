import 'dart:convert';

class ContractCaseResult {
  final int index;
  final bool expected, accepted;
  const ContractCaseResult(this.index, this.expected, this.accepted);
  bool get passed => expected == accepted;
}

/// Runs purely local synthetic scalar input cases against a declared contract.
/// Values are not returned, sent, persisted or executed.
class ContractMatrix {
  static List<ContractCaseResult> run(String source) {
    if (source.length > 16000) throw const FormatException('Matrix too large.');
    final json = jsonDecode(source);
    if (json is! Map || json.length != 3 || json['schema'] != 'odin.security.contract.v1' ||
        json['contract'] is! Map || json['cases'] is! List) {
      throw const FormatException('Invalid matrix.');
    }
    final contract = json['contract'] as Map;
    final kind = contract['kind'], min = contract['min'], max = contract['max'];
    if (contract.length != 3 || !['string','integer'].contains(kind) ||
        min is! int || max is! int || min > max ||
        (kind == 'string' && (min < 0 || max > 4096)) ||
        (kind == 'integer' && (min < -2147483648 || max > 2147483647))) {
      throw const FormatException('Invalid contract.');
    }
    final cases = json['cases'] as List;
    if (cases.isEmpty || cases.length > 100) throw const FormatException('Invalid case count.');
    final result = <ContractCaseResult>[];
    for (var i = 0; i < cases.length; i++) {
      final row = cases[i];
      if (row is! Map || row.length != 2 || !row.containsKey('value') || row['expected'] is! bool) {
        throw const FormatException('Invalid case.');
      }
      final value = row['value'];
      if (value != null && value is! String && value is! num && value is! bool) {
        throw const FormatException('Only scalar samples supported.');
      }
      final accepted = kind == 'string'
        ? value is String && value.runes.length >= min && value.runes.length <= max
        : value is int && value >= min && value <= max;
      result.add(ContractCaseResult(i + 1, row['expected'] as bool, accepted));
    }
    return List.unmodifiable(result);
  }
}
