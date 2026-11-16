import 'package:html/parser.dart' as html;
import 'project.dart';

class LinkDiscovery {
  // Intentionally read-only: anchors only, no forms, no script execution,
  // query links, fragments, or paths that look like state-changing actions.
  static final _unsafe = RegExp(r'(^|[-_/\.])(logout|logoff|signout|sign-out|delete|remove|destroy|cancel|pay|payment|checkout|purchase|unsubscribe|reset|revoke|send|submit|export|download|edit|create|update)([-_/\.]|$)', caseSensitive: false);
  static final _asset = RegExp(r'\.(png|jpg|jpeg|gif|svg|ico|pdf|zip|rar|mp4|woff2?|css|js)$', caseSensitive: false);

  static bool eligible(Uri root, Uri url) {
    if (!SecurityProject.sameOrigin(root, url) || url.hasQuery || url.userInfo.isNotEmpty) return false;
    final path = url.pathSegments.join('/');
    return !_unsafe.hasMatch(path) && !_asset.hasMatch(path) && url.toString().length <= 2048;
  }

  static List<Uri> extract(Uri page, String body, {int limit = 50}) {
    if (limit <= 0) return const [];
    final document = html.parse(body);
    final found = <Uri>{};
    final href = document.querySelector('base[href]')?.attributes['href'];
    Uri base = page;
    if (href != null) {
      try { base = page.resolve(href); } on FormatException { return const []; }
      if (!SecurityProject.sameOrigin(page, base)) return const [];
    }
    for (final anchor in document.querySelectorAll('a[href]')) {
      final raw = anchor.attributes['href']!.trim();
      if (raw.isEmpty || raw.startsWith('#') || raw.length > 2048) continue;
      try {
        final resolved = base.resolve(raw).removeFragment();
        if (eligible(page, resolved)) found.add(resolved);
      } on FormatException {
        continue;
      }
      if (found.length >= limit) break;
    }
    return found.toList(growable: false);
  }
}
