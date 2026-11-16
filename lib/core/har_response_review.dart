import 'dart:convert';
import 'project.dart';
import 'scan_policy.dart';
import 'fingerprint.dart';
import 'security_checks.dart';
import 'header_policy_checks.dart';
import 'csp_review.dart';
import 'frame_protection_review.dart';
import 'html_security_checks.dart';
import 'api_response_checks.dart';
import 'custom_rules.dart';
import 'metadata_rule_program.dart';

class ImportedResponseReview {
  final Uri route;
  final int status;
  final bool bodyReviewed;
  final List<SecurityFinding> findings;
  final List<TechnologyFinding> technologies;
  const ImportedResponseReview(this.route, this.status, this.bodyReviewed, this.findings, this.technologies);
}

/// Offline review of responses exported by an authorized browser/tool.
/// No proxy, network transmission, replay, raw headers, credentials or bodies
/// in the returned records. Query parameters are never retained.
class HarResponseReview {
  static const maxInput = 1024 * 1024;
  static const maxEntries = 100;
  static const maxBody = 64 * 1024;
  static const allowedHeaders = {
    'content-type','server','x-powered-by','x-aspnet-version','strict-transport-security',
    'content-security-policy','content-security-policy-report-only','x-frame-options',
    'x-content-type-options','referrer-policy','permissions-policy','cache-control',
    'access-control-allow-origin','access-control-allow-credentials',
  };

  static List<ImportedResponseReview> parse(SecurityProject project, ScanPolicy policy, String input,
      {required bool authorized, required bool includeBody, List<HeaderRule> rules = const [], MetadataRuleProgram? program}) {
    if (!authorized || input.length > maxInput) throw StateError('Explicit offline review approval or size limit.');
    final raw = jsonDecode(input);
    if (raw is! Map || raw['log'] is! Map || raw['log']['entries'] is! List) throw const FormatException('Invalid HAR.');
    final entries = raw['log']['entries'] as List;
    if (entries.length > maxEntries) throw const FormatException('Split HAR into smaller captures.');
    final result = <ImportedResponseReview>[];
    for (final entry in entries) {
      if (entry is! Map || entry['request'] is! Map || entry['response'] is! Map) continue;
      final request = entry['request'] as Map, response = entry['response'] as Map;
      final url = request['url'];
      if (url is! String || url.length > 2048) continue;
      final candidate = Uri.tryParse(url);
      final route = Uri.tryParse(url.split(RegExp(r'[?#]')).first);
      if (candidate == null || route == null || candidate.userInfo.isNotEmpty ||
          route.scheme != 'https' || !project.contains(route) || !policy.permits(route)) continue;
      final status = response['status'], fields = response['headers'];
      if (status is! int || status < 100 || status > 599 || fields is! List ||
          fields.isEmpty || fields.length > 200) continue;
      final headers = <String,List<String>>{};
      for (final field in fields) {
        if (field is! Map || field['name'] is! String || field['value'] is! String) continue;
        final name = (field['name'] as String).toLowerCase(), value = field['value'] as String;
        if (!allowedHeaders.contains(name) || value.length > 16384 || value.contains(RegExp(r'[\r\n\x00]'))) continue;
        headers.putIfAbsent(name, () => []).add(value);
      }
      if (headers.isEmpty) continue;
      final content = response['content'];
      String body = '';
      var reviewed = false;
      if (includeBody && content is Map && content['encoding'] == null && content['text'] is String &&
          (content['text'] as String).length <= maxBody) {
        body = content['text'] as String;
        reviewed = true;
      }
      final obs = HttpObservation(headers: headers, body: body);
      final html = obs.header('content-type').toLowerCase().contains('text/html');
      final findings = <SecurityFinding>[
        ...PassiveSecurityChecks().inspect(route, obs),
        ...HeaderPolicyChecks.inspect(route, obs, status: status),
        if (program != null) ...program.inspect(obs, status),
        if (html && status >= 200 && status < 300) ...CspReview.inspect(obs),
        if (status >= 200 && status < 300) ...FrameProtectionReview.inspect(obs),
        if (reviewed && html && status >= 200 && status < 300) ...HtmlSecurityChecks.inspect(route, body),
        if (reviewed) ...ApiResponseChecks.inspect(obs, status: status, truncated: false),
        if (status >= 200 && status < 300) ...CustomHeaderRules.inspect(rules.where((r) => allowedHeaders.contains(r.header)).toList(), obs),
      ];
      result.add(ImportedResponseReview(route, status, reviewed, List.unmodifiable(findings),
        TechnologyDetector().detect(obs)));
    }
    return List.unmodifiable(result);
  }
}
