import 'package:html/parser.dart' as html;
import 'project.dart';

class LinkDiscovery {
  // Intentionally read-only: anchors only, no forms, no script execution,
  // query links, fragments, or paths that look like state-changing actions.
  static final _unsafe = RegExp(r'(^|[-_/\.])(logout|logoff|signout|sign-out|delete|remove|destroy|cancel|pay|payment|checkout|purchase|unsubscribe|reset|revoke|send|submit|edit|create|update)([-_/\.]|$)', caseSensitive: false);
  static final _asset = RegExp(r'\.(png|jpg|jpeg|gif|svg|ico|pdf|zip|rar|mp4|woff2?|css|js)$', caseSensitive: false);

  static final _download = RegExp(r'(^|[-_/\.])(export|download)([-_/\.]|$)', caseSensitive: false);
  static final _file = RegExp(r'\.(pdf|zip|rar|7z|gz|docx?|xlsx?|pptx?|odt|csv|txt|png|jpe?g|gif|svg|webp|ico|mp[34]|wav|webm|mkv|mov|m3u8|mpd)$', caseSensitive: false);

  static bool safeMediaTarget(Uri root, Uri url) =>
      SecurityProject.sameOrigin(root, url) && !url.hasFragment && !url.hasQuery &&
      url.toString().length <= 2048 && !_unsafe.hasMatch(url.pathSegments.join('/'));

  static bool eligible(Uri root, Uri url) {
    if (!SecurityProject.sameOrigin(root, url) || url.hasQuery || url.userInfo.isNotEmpty) return false;
    final path = url.pathSegments.join('/');
    return !_unsafe.hasMatch(path) && !_download.hasMatch(path) && !_asset.hasMatch(path) && url.toString().length <= 2048;
  }

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
    for (final anchor in document.querySelectorAll(files ? 'a[href],img[src],video[src],video source[src]' : 'a[href]')) {
      final raw = (anchor.attributes['href'] ?? anchor.attributes['src'] ?? '').trim();
      if (raw.isEmpty || raw.startsWith('#') || raw.length > 2048) continue;
      try {
        final resolved = base.resolve(raw).removeFragment();
        if (files) {
          final path = resolved.pathSegments.join('/');
          if (SecurityProject.sameOrigin(page, resolved) && !resolved.hasQuery &&
              resolved.toString().length <= 2048 && !_unsafe.hasMatch(path) &&
              (anchor.localName == 'video' || anchor.localName == 'source' || _file.hasMatch(path) || _download.hasMatch(path) || anchor.attributes.containsKey('download'))) {
            found.add(resolved);
          }
        } else if (eligible(page, resolved) && !_file.hasMatch(resolved.path) && !anchor.attributes.containsKey('download')) {
          found.add(resolved);
        }
      } on FormatException {
        continue;
      }
      if (found.length >= limit) break;
    }
    return found.toList(growable: false);
  }
}
