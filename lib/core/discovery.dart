import 'package:html/parser.dart' as html;
import 'project.dart';

class LinkDiscovery {
  static final _unsafe = RegExp(r'(^|[-_/\.])(logout|logoff|signout|sign-out|delete|remove|destroy|cancel|pay|payment|checkout|purchase|unsubscribe|reset|revoke|send|submit|edit|create|update)([-_/\.]|$)', caseSensitive: false);
  static final _asset = RegExp(r'\.(woff2?|css|js)$', caseSensitive: false);
  static final _download = RegExp(r'(^|[-_/\.])(export|download)([-_/\.]|$)', caseSensitive: false);
  static final _file = RegExp(r'\.(pdf|zip|rar|7z|gz|docx?|xlsx?|pptx?|odt|csv|txt|png|jpe?g|gif|svg|webp|ico|mp[34]|wav|webm|mkv|mov|m3u8|mpd)$', caseSensitive: false);
  static final _media = RegExp(r'\.(mp[34]|wav|webm|mkv|mov|m3u8|mpd|ts)$', caseSensitive: false);

  /// Never turn a signed/query URL into a different, queryless request.
  static Uri canonical(Uri url) => url.removeFragment().normalizePath()
      .replace(path: url.normalizePath().path.isEmpty ? '/' : url.normalizePath().path);

  static bool safeMediaTarget(Uri root, Uri url) =>
      SecurityProject.sameOrigin(root, url) && !url.hasFragment && !url.hasQuery &&
      url.toString().length <= 2048 && !_unsafe.hasMatch(url.pathSegments.join('/'));

  static bool isFile(Uri url) => _file.hasMatch(url.path) || _download.hasMatch(url.pathSegments.join('/'));
  static bool isMedia(Uri url) => _media.hasMatch(url.path);

  static bool eligible(Uri root, Uri url) => safeMediaTarget(root, url) &&
      !isFile(url) && !_asset.hasMatch(url.path);

  /// Signed file links remain visible as redacted inventory entries. The
  /// queryless path is never used as a replacement HTTP request.
  static List<Uri> queryFilePaths(Uri page, String body) {
    final document = html.parse(body);
    final found = <Uri>{};
    Uri base;
    try { base = page.resolve(document.querySelector('base[href]')?.attributes['href'] ?? ''); }
    on FormatException { return const []; }
    if (!SecurityProject.sameOrigin(page, base)) return const [];
    for (final node in document.querySelectorAll('a[href],img[src],audio[src],video[src],source[src]')) {
      final raw = node.attributes['href'] ?? node.attributes['src'] ?? '';
      if (raw.length > 8192) continue;
      try {
        final url = base.resolve(raw);
        if (!url.hasQuery || !SecurityProject.sameOrigin(page, url)) continue;
        if (!isFile(url) && !node.attributes.containsKey('download') && node.localName == 'a') continue;
        final redacted = canonical(Uri.parse(url.removeFragment().toString().split('?').first));
        if (safeMediaTarget(page, redacted)) found.add(redacted);
      } on FormatException { continue; }
      if (found.length >= 100) break;
    }
    return found.toList();
  }

  /// Counts exclusions in each received HTML prefix, without retaining raw
  /// URLs or query values. Repeated references in one response count once.
  static Map<String, int> exclusions(Uri page, String body) {
    final document = html.parse(body);
    final counts = <String, int>{};
    final seen = <String>{};
    void count(String reason) => counts.update(reason, (n) => n + 1, ifAbsent: () => 1);
    Uri base;
    try { base = page.resolve(document.querySelector('base[href]')?.attributes['href'] ?? ''); }
    on FormatException { return {'Invalid base URL': 1}; }
    if (!SecurityProject.sameOrigin(page, base)) return {'External base URL': 1};
    for (final node in document.querySelectorAll('a[href],img[src],audio[src],video[src],source[src],form[action]')) {
      final raw = (node.attributes['href'] ?? node.attributes['src'] ?? node.attributes['action'] ?? '').trim();
      if (!seen.add(raw)) continue;
      if (seen.length > 1000) { count('HTML discovery inspection limit'); break; }
      if (node.localName == 'form' &&
          ((node.attributes['method'] ?? 'get').toLowerCase() != 'get' || node.querySelector('[name]') != null)) {
        count('Form not submitted'); continue;
      }
      if (raw.isEmpty || raw.startsWith('#')) { count('Empty or fragment-only reference'); continue; }
      if (raw.length > 8192) { count('URL too long'); continue; }
      try {
        final url = base.resolve(raw);
        if (!SecurityProject.sameOrigin(page, url)) { count('Outside selected origin'); }
        else if (url.hasQuery) { count('Query URL not replayed'); }
        else if (_unsafe.hasMatch(url.pathSegments.join('/'))) { count('Potentially mutating route'); }
        else if (_asset.hasMatch(url.path)) { count('Non-navigation resource'); }
      } on FormatException { count('Invalid URL'); }
    }
    return counts;
  }

  /// DOM parsing also works on the received prefix of a truncated response.
  /// Forms are inventoried only as empty, queryless GET destinations; no fields
  /// are read or submitted. POST forms and potentially mutating routes stay out.
  static List<Uri> extract(Uri page, String body, {int limit = 50, bool files = false}) {
    if (limit <= 0) return const [];
    final document = html.parse(body);
    final found = <Uri>{};
    final href = document.querySelector('base[href]')?.attributes['href'];
    Uri base = page;
    if (href != null) {
      try { base = page.resolve(href); } on FormatException { return const []; }
      if (!SecurityProject.sameOrigin(page, base)) return const [];
    }
    final selector = files
        ? 'a[href],img[src],audio[src],video[src],source[src]'
        : 'a[href],form[action]';
    for (final node in document.querySelectorAll(selector)) {
      if (node.localName == 'form' &&
          ((node.attributes['method'] ?? 'get').toLowerCase() != 'get' ||
           node.querySelector('[name]') != null)) continue;
      final raw = (node.attributes['href'] ?? node.attributes['src'] ?? node.attributes['action'] ?? '').trim();
      if (raw.isEmpty || raw.startsWith('#') || raw.length > 2048) continue;
      try {
        final resolved = canonical(base.resolve(raw));
        if (!safeMediaTarget(page, resolved)) continue;
        final resource = isFile(resolved) || node.attributes.containsKey('download') ||
            const {'img', 'audio', 'video', 'source'}.contains(node.localName);
        if (files ? resource : !resource && eligible(page, resolved)) found.add(resolved);
      } on FormatException {
        continue;
      }
      if (found.length >= limit) break;
    }
    return found.toList(growable: false);
  }
}
