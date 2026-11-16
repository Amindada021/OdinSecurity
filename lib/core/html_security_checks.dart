import 'package:html/parser.dart' as html;
import 'project.dart';
import 'security_checks.dart';

/// HTML structure observations only. Never executes scripts, submits forms,
/// fetches subresources or includes literal HTML/URLs/field values in evidence.
class HtmlSecurityChecks {
  static List<SecurityFinding> inspect(Uri page, String body) {
    final document = html.parse(body);
    final baseValue = document.querySelector('base[href]')?.attributes['href'];
    final base = _resolve(page, baseValue) ?? page;
    final findings = <SecurityFinding>[];
    var mixed = false, insecureForm = false, passwordGet = false;
    var externalPasswordForm = false, externalScriptWithoutIntegrity = false;

    for (final node in document.querySelectorAll('script[src], iframe[src], embed[src], object[data], link[href]')) {
      if (node.localName == 'link' &&
          !(node.attributes['rel'] ?? '').toLowerCase().split(RegExp(r'\s+')).contains('stylesheet')) continue;
      final target = _resolve(base, node.attributes[node.localName == 'object' ? 'data' : node.localName == 'link' ? 'href' : 'src']);
      if (target == null) continue;
      if (page.scheme == 'https' && target.scheme == 'http') mixed = true;
      if (node.localName == 'script' && !SecurityProject.sameOrigin(page, target) &&
          (node.attributes['integrity'] ?? '').trim().isEmpty) externalScriptWithoutIntegrity = true;
    }
    for (final form in document.querySelectorAll('form')) {
      final rawAction = form.attributes['action'];
      final target = rawAction == null || rawAction.trim().isEmpty ? page : _resolve(base, rawAction);
      final password = form.querySelectorAll('input').any((input) =>
        (input.attributes['type'] ?? '').toLowerCase() == 'password' && !input.attributes.containsKey('disabled'));
      final method = (form.attributes['method'] ?? 'get').trim().toLowerCase();
      if (password && method != 'post' && method != 'dialog') passwordGet = true;
      if (method == 'dialog') continue;
      if (target != null && page.scheme == 'https' && target.scheme == 'http') insecureForm = true;
      if (password && target != null && !SecurityProject.sameOrigin(page, target)) externalPasswordForm = true;
    }
    if (mixed) findings.add(const SecurityFinding('html.mixed.active', 'HTTP subresource reference on HTTPS page', Severity.low,
      'Parsed HTML references an HTTP script, stylesheet, frame or embedded resource; URL omitted',
      'Use HTTPS resource URLs; browsers may block mixed active content.'));
    if (insecureForm) findings.add(const SecurityFinding('html.form.http', 'Form targets an HTTP endpoint', Severity.medium,
      'Parsed HTTPS document contains an HTTP form action; values omitted; no form submitted',
      'Serve form submission targets over HTTPS.'));
    if (passwordGet) findings.add(const SecurityFinding('html.form.password.get', 'Password field in a GET form', Severity.medium,
      'A form containing an enabled password input defaults to or declares GET; no form submitted',
      'Use HTTPS POST for credential submission and avoid credentials in URLs.'));
    if (externalPasswordForm) findings.add(const SecurityFinding('html.form.password.external', 'Cross-origin password form destination', Severity.info,
      'A password form points to a different origin; URL omitted',
      'Verify the destination is an intended, trusted identity provider.'));
    if (externalScriptWithoutIntegrity) findings.add(const SecurityFinding('html.script.external.integrity', 'External script without integrity metadata', Severity.info,
      'Cross-origin script reference lacks an integrity attribute; URL omitted',
      'For immutable third-party scripts, review Subresource Integrity and trusted hosting.'));
    return List.unmodifiable(findings);
  }

  static Uri? _resolve(Uri base, String? raw) {
    if (raw == null || raw.trim().isEmpty || raw.length > 2048) return null;
    try {
      final uri = base.resolve(raw.trim());
      return ['http', 'https'].contains(uri.scheme) && uri.hasAuthority && uri.userInfo.isEmpty ? uri : null;
    } on FormatException { return null; }
  }
}
