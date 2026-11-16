import 'fingerprint.dart';
import 'project_storage.dart';
import 'security_checks.dart';

enum HeaderRuleMode { present, contains }

class HeaderRule {
  final String header, expected;
  final HeaderRuleMode mode;
  const HeaderRule._(this.header, this.mode, this.expected);
  String get key => 'custom.$header.${mode.name}';
  String get line => mode == HeaderRuleMode.present ? '$header|present' : '$header|contains|$expected';
}

class CustomHeaderRules {
  static const limit = 20;
  static const allowedHeaders = {
    'strict-transport-security', 'content-security-policy', 'x-content-type-options',
    'x-frame-options', 'referrer-policy', 'permissions-policy', 'cross-origin-resource-policy',
    'cross-origin-opener-policy', 'cross-origin-embedder-policy', 'cache-control',
    'content-type', 'x-permitted-cross-domain-policies',
  };

  /// Only an allowlisted public security/configuration header. No executable
  /// scripts, regular expressions, arbitrary sensitive headers or probes.
  static List<HeaderRule> parse(String text) {
    if (text.length > 5000) throw const FormatException('Rules exceed limit.');
    final rules = <HeaderRule>[];
    final keys = <String>{};
    for (final raw in text.split(RegExp(r'\r?\n'))) {
      if (raw.trim().isEmpty) continue;
      final parts = raw.split('|').map((p) => p.trim()).toList();
      if (parts.length < 2 || !allowedHeaders.contains(parts[0].toLowerCase())) {
        throw const FormatException('Unsupported header.');
      }
      final header = parts[0].toLowerCase();
      final HeaderRule rule;
      if (parts[1] == 'present' && parts.length == 2) {
        rule = HeaderRule._(header, HeaderRuleMode.present, '');
      } else if (parts[1] == 'contains' && parts.length == 3 && parts[2].isNotEmpty &&
          parts[2].length <= 160 && !parts[2].contains(RegExp(r'[\x00-\x1f\x7f]'))) {
        rule = HeaderRule._(header, HeaderRuleMode.contains, parts[2]);
      } else {
        throw const FormatException('Invalid rule.');
      }
      if (!keys.add(rule.key)) throw const FormatException('Duplicate rule header or mode.');
      rules.add(rule);
      if (rules.length > limit) throw const FormatException('Too many rules.');
    }
    return List.unmodifiable(rules);
  }

  static List<SecurityFinding> inspect(List<HeaderRule> rules, HttpObservation observed) {
    final findings = <SecurityFinding>[];
    for (final rule in rules) {
      final actual = observed.header(rule.header);
      final passed = rule.mode == HeaderRuleMode.present ? actual.trim().isNotEmpty :
        actual.toLowerCase().contains(rule.expected.toLowerCase());
      if (!passed) {
        findings.add(SecurityFinding(rule.key, 'Custom header rule not met: ${rule.header}', Severity.info,
          'Configured ${rule.mode.name} condition not observed; values omitted',
          'Review the intended policy for this endpoint. A rule mismatch alone does not establish a vulnerability.'));
      }
    }
    return List.unmodifiable(findings);
  }
}

class CustomRuleRepository {
  final ProjectStorage storage;
  CustomRuleRepository(this.storage);
  String _key(String projectId) => 'odin_security.custom_headers.v1.$projectId';
  Future<List<HeaderRule>> load(String projectId) async =>
    CustomHeaderRules.parse(await storage.read(_key(projectId)) ?? '');
  Future<void> save(String projectId, String source) async {
    final checked = CustomHeaderRules.parse(source);
    await storage.write(_key(projectId), checked.map((r) => r.line).join('\n'));
  }
}
