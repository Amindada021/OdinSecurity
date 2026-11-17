import 'dart:convert';
import 'project.dart';
import 'scan_policy.dart';
import 'discovery.dart';

class BrowserLoginPolicy {
  /// Read only URLs in the currently rendered document. Redact signed file
  /// links for inventory only; never replay the redacted path. No navigation.
  static const observedSnapshot = r'''(() => {
    const rows = [];
    for (const node of document.querySelectorAll('a[href],link[href],script[src],img[src],audio[src],video[src],source[src],form[action]')) {
      if (rows.length >= 300) break;
      if (node.tagName === 'FORM' && (node.method.toLowerCase() !== 'get' || node.querySelector('[name]'))) continue;
      try {
        const url = new URL(node.href || node.src || node.action, document.baseURI);
        if (url.username || url.password || !['http:', 'https:'].includes(url.protocol)) continue;
        const query = !!url.search;
        url.hash = '';
        url.search = '';
        rows.push({url: url.href, query, file: ['SCRIPT','IMG','AUDIO','VIDEO','SOURCE'].includes(node.tagName) ||
          (node.tagName === 'LINK' && ['stylesheet','icon','preload','modulepreload'].some(rel => node.relList.contains(rel))) || node.hasAttribute('download')});
      } catch (_) {}
    }
    return JSON.stringify({page: location.href, rows});
  })()''';

  static ({List<Uri> routes, List<Uri> files, List<Uri> queryFiles}) observedUrls(Object raw, Uri target, Uri current, ScanPolicy? policy) {
    if (raw is! String || raw.length > 1024 * 1024) throw const FormatException('Invalid browser snapshot.');
    dynamic parsed = jsonDecode(raw);
    if (parsed is String) parsed = jsonDecode(parsed);
    if (parsed is! Map || parsed['page'] != current.toString() || parsed['rows'] is! List) {
      throw const FormatException('Page changed during capture.');
    }
    final routes = <Uri>{}, files = <Uri>{}, queryFiles = <Uri>{};
    for (final row in (parsed['rows'] as List).take(300)) {
      if (row is! Map || row['url'] is! String) continue;
      final uri = Uri.tryParse(row['url'] as String);
      if (uri == null || !LinkDiscovery.safeMediaTarget(target, uri) ||
          (policy != null && !policy.permits(uri))) continue;
      final clean = LinkDiscovery.canonical(uri);
      if (row['query'] == true) {
        if (row['file'] == true || LinkDiscovery.isFile(clean)) queryFiles.add(clean);
        continue;
      }
      if (row['file'] == true || LinkDiscovery.isFile(clean)) { files.add(clean); }
      else if (LinkDiscovery.eligible(target, clean)) { routes.add(clean); }
    }
    return (routes: routes.toList(), files: files.toList(), queryFiles: queryFiles.toList());
  }

  static bool allows(Uri target, Uri candidate, {bool allowInsecureHttp = false}) =>
      (target.scheme == 'https' || (allowInsecureHttp && target.scheme == 'http')) &&
      candidate.userInfo.isEmpty && SecurityProject.sameOrigin(target, candidate);

  /// The user may enter a separate HTTPS sign-in origin for this run.
  /// It is browser-only: never expand the project's assessment scope or
  /// read session cookies from anything other than the selected target.
  static Uri loginUrl(SecurityProject project, Uri target, String raw, ScanPolicy policy, {bool allowInsecureHttp = false}) {
    final value = raw.trim();
    final uri = SecurityProject.parseTarget(value.startsWith('/') && !value.startsWith('//')
        ? target.resolve(value).toString() : value);
    final transportAllowed = (target.scheme == 'https' && uri.scheme == 'https') ||
        (allowInsecureHttp && target.scheme == 'http' && allows(target, uri, allowInsecureHttp: true));
    if (!transportAllowed ||
        !project.contains(target) ||
        !policy.permits(target) || !policy.permits(uri)) {
      throw const FormatException('Enter a permitted HTTPS sign-in URL.');
    }
    return uri;
  }

  static bool allowsNavigation(Uri target, Uri login, Uri candidate, ScanPolicy? policy, {bool allowInsecureHttp = false}) =>
      (allows(target, candidate, allowInsecureHttp: allowInsecureHttp) ||
        (target.scheme == 'https' && allows(login, candidate))) &&
      (policy == null || policy.permits(candidate));

  /// If a root website was selected, begin at the page reached after login.
  /// Query strings and fragments may contain authorization codes: never scan them.
  static Uri assessmentStart(Uri target, Uri current, ScanPolicy? policy, {bool allowInsecureHttp = false}) {
    if ((target.path.isEmpty || target.path == '/') && allows(target, current, allowInsecureHttp: allowInsecureHttp)) {
      final withoutQuery = Uri.parse(current.toString().split(RegExp(r'[?#]')).first);
      if ((policy == null || policy.permits(withoutQuery)) && LinkDiscovery.eligible(target, withoutQuery)) {
        return withoutQuery;
      }
    }
    return target;
  }

  /// Cookie values are imported only from the app's own WebView on explicit
  /// user action. Reject header injection and ambiguous duplicate cookie names.
  static String cookieHeader(Iterable<MapEntry<String, String>> cookies) {
    final seen = <String>{};
    final parts = <String>[];
    for (final cookie in cookies) {
      if (!RegExp(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$").hasMatch(cookie.key) ||
          cookie.value.contains(RegExp(r'[\r\n;\x00-\x1f\x7f]')) ||
          !seen.add(cookie.key)) {
        throw const FormatException('Unsupported or ambiguous cookie values.');
      }
      parts.add('${cookie.key}=${cookie.value}');
    }
    if (parts.isEmpty) throw const FormatException('No session cookies found for the selected URL.');
    final joined = parts.join('; ');
    if (joined.length > 16384) throw const FormatException('Cookie header is too large.');
    return joined;
  }
}
