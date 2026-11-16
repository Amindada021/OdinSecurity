import 'dart:convert';
import 'project.dart';
import 'scan_policy.dart';
import 'security_checks.dart';

class ExternalFinding {
  final Uri route;
  final String source, code;
  final Severity reportedSeverity;
  const ExternalFinding(this.route, this.source, this.code, this.reportedSeverity);
}

/// Normalized, unverified external scanner findings. No tool execution,
/// exploit/evidence text, request/response bytes, or automatic confirmation.
class ExternalFindings {
  static final _identifier = RegExp(r'^[a-zA-Z0-9_.:-]{1,80}$');
  static List<ExternalFinding> parse(SecurityProject project, ScanPolicy policy, String input, {required bool authorized}) {
    if (!authorized || input.length > 262144) throw StateError('Import approval or limit required.');
    final decoded = jsonDecode(input);
    if (decoded is! List || decoded.length > 500) throw const FormatException('Invalid findings.');
    final result = <ExternalFinding>[];
    final seen = <String>{};
    for (final row in decoded) {
      if (row is! Map || row.length != 4 || row['url'] is! String || row['source'] is! String ||
          row['code'] is! String || row['severity'] is! String) throw const FormatException('Invalid finding.');
      final raw = row['url'] as String, source = row['source'] as String, code = row['code'] as String;
      if (raw.length > 2048 || !_identifier.hasMatch(source) || !_identifier.hasMatch(code)) {
        throw const FormatException('Invalid finding identifier.');
      }
      final validSeverities = Severity.values.where((s) => s.name == row['severity']).toList();
      if (validSeverities.length != 1) throw const FormatException('Invalid severity.');
      final severity = validSeverities.single;
      final full = Uri.tryParse(raw), route = Uri.tryParse(raw.split(RegExp(r'[?#]')).first);
      if (full == null || route == null || full.userInfo.isNotEmpty || route.scheme != 'https' ||
          !project.contains(route) || !policy.permits(route)) continue;
      final key = route.toString() + '\u0000' + source + '\u0000' + code + '\u0000' + severity.name;
      if (seen.add(key)) result.add(ExternalFinding(route, source, code, severity));
    }
    return List.unmodifiable(result);
  }
}
