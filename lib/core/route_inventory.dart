import 'dart:convert';
import 'project.dart';
import 'scan_policy.dart';

class RouteObservation {
  final Uri url;
  final String source;
  const RouteObservation(this.url, this.source);
  String get key => '$source\n$url';
}

/// Only URL metadata is retained. No requests are sent by this class,
/// and query strings/fragments, headers, bodies and cookies are discarded.
class RouteInventory {
  static const maxEntries = 300;
  static const maxInput = 1024 * 1024;
  static const sources = {'document', 'link', 'fetch', 'xmlhttprequest', 'form-get', 'form-post', 'script'};
  static const methods = {'GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'PATCH', 'DELETE', 'TRACE', 'CONNECT'};

  static Uri? scopedUrl(SecurityProject project, ScanPolicy policy, Object? raw) {
    if (raw is! String || raw.length > 2048) return null;
    try {
      final uri = Uri.tryParse(raw);
      if (uri == null || !project.contains(uri) || uri.userInfo.isNotEmpty ||
          !['http', 'https'].contains(uri.scheme)) return null;
      final clean = Uri.parse(raw.split(RegExp(r'[?#]')).first);
      if (!project.contains(clean) || !policy.permits(clean)) return null;
      return clean;
    } on FormatException {
      return null;
    }
  }

  static List<RouteObservation> fromBrowser(SecurityProject project, ScanPolicy policy, Uri page, Object result) {
    if (!project.contains(page) || !policy.permits(page)) throw const FormatException('Page outside scope.');
    if (result is! String || result.length > maxInput || utf8.encode(result).length > maxInput) throw const FormatException('Invalid browser snapshot.');
    dynamic parsed = jsonDecode(result);
    // Android can return a JSON-encoded string rather than a JSON object.
    if (parsed is String) parsed = jsonDecode(parsed);
    if (parsed is! Map || parsed['routes'] is! List) throw const FormatException('Invalid browser snapshot.');
    final actual = scopedUrl(project, policy, parsed['page']);
    final expected = scopedUrl(project, policy, page.toString());
    if (actual == null || actual != expected) throw const FormatException('Page changed during capture.');
    final records = <String, RouteObservation>{};
    void add(RouteObservation value) {
      if (records.length < maxEntries) records[value.key] = value;
    }
    add(RouteObservation(actual, 'document'));
    for (final row in parsed['routes'] as List) {
      if (row is! Map || !sources.contains(row['source'])) continue;
      final url = scopedUrl(project, policy, row['url']);
      if (url != null) add(RouteObservation(url, row['source'] as String));
      if (records.length >= maxEntries) break;
    }
    return List.unmodifiable(records.values);
  }

  static List<RouteObservation> fromHar(SecurityProject project, ScanPolicy policy, String source) {
    if (source.length > maxInput || utf8.encode(source).length > maxInput) throw const FormatException('HAR exceeds 1 MiB.');
    final parsed = jsonDecode(source);
    if (parsed is! Map || parsed['log'] is! Map || parsed['log']['entries'] is! List) {
      throw const FormatException('Expected HAR JSON.');
    }
    final records = <String, RouteObservation>{};
    for (final entry in parsed['log']['entries'] as List) {
      if (entry is! Map || entry['request'] is! Map) continue;
      final request = entry['request'] as Map;
      final method = request['method'];
      if (method is! String || !methods.contains(method)) continue;
      final url = scopedUrl(project, policy, request['url']);
      if (url == null) continue;
      final item = RouteObservation(url, method);
      records[item.key] = item;
      if (records.length >= maxEntries) break;
    }
    return List.unmodifiable(records.values);
  }

  static List<RouteObservation> merge(Iterable<RouteObservation> existing, Iterable<RouteObservation> added) {
    final records = <String, RouteObservation>{};
    for (final item in [...existing, ...added]) {
      if (records.length >= maxEntries) break;
      records[item.key] = item;
    }
    return List.unmodifiable(records.values);
  }

  /// Read only rendered anchors, form destinations, script URLs and Fetch/XHR resource timing metadata.
  /// Do not read storage, form fields, cookies, headers or response data.
  static const browserSnapshot = r'''
(() => {
  const clean = value => {
    try {
      const url = new URL(value, location.href);
      if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) return null;
      url.search = '';
      url.hash = '';
      const result = url.href;
      return result.length <= 2048 ? result : null;
    } catch (_) { return null; }
  };
  const routes = [];
  const add = (url, source) => {
    const value = clean(url);
    if (value && routes.length < 299) routes.push({url: value, source});
  };
  for (const anchor of Array.from(document.querySelectorAll('a[href]')).slice(0, 100)) {
    add(anchor.href, 'link');
  }
  for (const form of Array.from(document.querySelectorAll('form')).slice(0, 60)) {
    const method = form.method.toLowerCase();
    if (method === 'get' || method === 'post') add(form.action, 'form-' + method);
  }
  for (const script of Array.from(document.querySelectorAll('script[src]')).slice(0, 20)) {
    add(script.src, 'script');
  }
  for (const entry of performance.getEntriesByType('resource').filter(
      entry => entry.initiatorType === 'fetch' || entry.initiatorType === 'xmlhttprequest').slice(-119)) {
    if (entry.initiatorType === 'fetch' || entry.initiatorType === 'xmlhttprequest') {
      add(entry.name, entry.initiatorType);
    }
  }
  return JSON.stringify({page: clean(location.href), routes});
})()
''';
}
