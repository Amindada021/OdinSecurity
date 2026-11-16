import 'project.dart';

class LinkDiscovery {
  // Intentionally read-only: anchors only, no forms, no script execution,
  // query links, fragments, or paths that look like state-changing actions.
  static final _href = RegExp(r'<a\b[^>]*\bhref\s*=\s*["\x27]([^"\x27<>]+)["\x27]', caseSensitive: false);
  static final _unsafe = RegExp(r'(^|[-_/\.])(logout|logoff|signout|sign-out|delete|remove|destroy|cancel|pay|payment|checkout|purchase|unsubscribe|reset|revoke|send|submit|export|download|edit|create|update)([-_/\.]|$)', caseSensitive: false);
  static final _asset = RegExp(r'\.(png|jpg|jpeg|gif|svg|ico|pdf|zip|rar|mp4|woff2?|css|js)$', caseSensitive: false);

  static bool eligible(Uri root, Uri url) {
    if (!SecurityProject.sameOrigin(root, url) || url.hasQuery || url.userInfo.isNotEmpty) return false;
    final path = url.pathSegments.join('/');
    return !_unsafe.hasMatch(path) && !_asset.hasMatch(path) && url.toString().length <= 2048;
  }

  static List<Uri> extract(Uri page, String body, {int limit = 50}) {
    final found = <Uri>{};
    for (final match in _href.allMatches(body)) {
      final raw = match.group(1)!.trim();
      if (raw.isEmpty || raw.startsWith('#') || raw.contains('&amp;')) continue;
      try {
        final resolved = page.resolve(raw).removeFragment();
        if (eligible(page, resolved)) found.add(resolved);
      } on FormatException {
        continue;
      }
      if (found.length >= limit) break;
    }
    return found.toList(growable: false);
  }
}
