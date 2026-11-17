import 'package:html/parser.dart' as html;
import 'discovery.dart';
import 'fingerprint.dart';
import 'security_checks.dart';

class AssetReference {
  final Uri url;
  final String source, kind;
  final bool directory;
  const AssetReference(this.url, this.source, this.kind, {this.directory = false});
  int get priority => directory || kind == 'stylesheet' || kind == 'script' ? 0 :
      kind == 'document' || kind == 'download' || kind == 'video' ? 1 : 2;
}

/// Public static roots are technology hints, not filesystem paths or proof
/// of exposure. ASP.NET Core's wwwroot is normally served at the URL root.
class AssetDiscovery {
  static final _static = RegExp(r'\.(css|m?js|map|woff2?|ttf|otf|eot|png|jpe?g|gif|svg|webp|avif|ico|pdf|zip|rar|7z|csv|txt|mp4|webm|mkv|mov|m3u8|mpd|ts)$', caseSensitive: false);
  static final _sensitive = RegExp(r'(^|/)(\.env(?:\.[^/]*)?|web\.config|appsettings(?:\.[^/]+)?\.json|[^/]+\.(sql|bak|old|backup|pfx|pem|key))$', caseSensitive: false);
  static bool sensitive(Uri url) => _sensitive.hasMatch(url.pathSegments.join('/'));
  static bool textAsset(Uri url) => RegExp(r'\.(css|m?js)$', caseSensitive: false).hasMatch(url.path);
  static String kind(Uri url) {
    final p = url.path.toLowerCase();
    if (p.endsWith('.css')) return 'stylesheet';
    if (RegExp(r'\.m?js$').hasMatch(p)) return 'script';
    if (RegExp(r'\.(woff2?|ttf|otf|eot|ico)$').hasMatch(p)) return 'decorative';
    if (RegExp(r'\.(png|jpe?g|gif|svg|webp|avif)$').hasMatch(p)) return 'image';
    if (LinkDiscovery.isMedia(url)) return 'video';
    if (p.endsWith('.pdf')) return 'document';
    return 'download';
  }

  static Uri? resolve(Uri page, String raw) {
    if (raw.isEmpty || raw.startsWith('#') || raw.length > 2048) return null;
    try {
      final url = LinkDiscovery.canonical(page.resolve(raw.replaceAll(r'\/', '/')));
      return LinkDiscovery.safeMediaTarget(page, url) ? url : null;
    } on FormatException { return null; }
  }

  static List<AssetReference> fromHtml(Uri page, String body) {
    final document = html.parse(body);
    final result = <Uri, AssetReference>{};
    final base = resolve(page, document.querySelector('base[href]')?.attributes['href'] ?? page.toString());
    if (base == null) return const [];
    void add(String raw, String source, {bool force = false}) {
      final url = resolve(base, raw.trim());
      if (url != null && (force || _static.hasMatch(url.path) || sensitive(url) || LinkDiscovery.isFile(url))) {
        if (result.length < 1000) result.putIfAbsent(url, () => AssetReference(url, source, kind(url)));
      }
    }
    for (final node in document.querySelectorAll('a[href],link[href],script[src],img[src],video[src],audio[src],source[src],video[poster],img[srcset],source[srcset]')) {
      final raw = node.attributes['src'] ?? node.attributes['href'] ?? '';
      final tag = node.localName;
      final forced = const {'img', 'video', 'audio', 'source', 'script'}.contains(tag) ||
          node.attributes.containsKey('download') ||
          (tag == 'link' && (node.attributes['rel'] ?? '').split(' ').any(const {'stylesheet', 'icon', 'preload', 'modulepreload'}.contains));
      add(raw, 'HTML $tag: ${page.path}', force: forced);
      if (node.attributes['poster'] != null) add(node.attributes['poster']!, 'HTML poster: ${page.path}', force: true);
      for (final item in (node.attributes['srcset'] ?? '').split(',')) {
        add(item.trim().split(RegExp(r'\s+')).first, 'HTML srcset: ${page.path}', force: true);
      }
      if (result.length >= 1000) break;
    }
    for (final style in document.querySelectorAll('style,[style]')) {
      for (final ref in fromText(base, style.attributes['style'] ?? style.text, css: true)) {
        if (result.length < 1000) result.putIfAbsent(ref.url, () => ref);
      }
    }
    // Parse literal URLs only, never execute scripts or synthesize IDs/routes.
    for (final script in document.querySelectorAll('script:not([src])')) {
      for (final ref in fromText(page, script.text)) {
        if (result.length < 1000) result.putIfAbsent(ref.url, () => ref);
      }
    }
    return result.values.toList();
  }

  static List<AssetReference> fromText(Uri page, String text, {bool css = false}) {
    final result = <Uri, AssetReference>{};
    final pattern = css
        ? RegExp(r'''(?:url\(\s*|@import\s+)["']?([^\s"'()]+)''', caseSensitive: false)
        : RegExp(r'''["']([^\s"'<>`]{1,2048})["']''');
    for (final match in pattern.allMatches(text)) {
      final url = resolve(page, match.group(1)!);
      if (url == null || !(css || _static.hasMatch(url.path) || sensitive(url) || LinkDiscovery.isFile(url))) continue;
      result.putIfAbsent(url, () => AssetReference(url, '${css ? 'CSS' : 'JavaScript literal'}: ${page.path}', kind(url)));
      if (result.length >= 1000) break;
    }
    return result.values.toList();
  }

  static List<AssetReference> publicDirectories(Uri page, Iterable<TechnologyFinding> technologies,
      Iterable<AssetReference> observed) {
    final paths = <String, String>{};
    for (final tech in technologies) {
      final roots = switch (tech.name) {
        'ASP.NET Core' => ['/css/', '/js/', '/images/', '/lib/'],
        'ASP.NET (legacy)' || 'ASP.NET Framework' => ['/Content/', '/Scripts/'],
        'WordPress' => ['/wp-content/uploads/', '/wp-content/themes/', '/wp-content/plugins/', '/wp-includes/'],
        'Laravel' => ['/build/assets/', '/storage/'],
        'PHP' => ['/assets/', '/uploads/'],
        'Next.js' => ['/_next/static/'],
        'React' || 'Angular' || 'Vue' => ['/assets/'],
        _ => <String>[],
      };
      for (final path in roots) { paths[path] = 'Technology public root: ${tech.name}'; }
    }
    for (final ref in observed) {
      if (ref.url.pathSegments.length < 2) continue;
      final parent = ref.url.resolve('.');
      if (parent.path != '/') paths.putIfAbsent(parent.path, () => 'Observed asset directory: ${ref.url.path}');
      if (paths.length >= 24) break;
    }
    return [for (final entry in paths.entries)
      if (resolve(page, entry.key) case final Uri url)
        AssetReference(url, entry.value, 'directory', directory: true)];
  }

  static bool directoryListing(String body) {
    final document = html.parse(body);
    final title = document.querySelector('title')?.text ?? '';
    final heading = document.querySelector('h1')?.text ?? '';
    final index = RegExp(r'index of|directory listing|directory of', caseSensitive: false).hasMatch('$title $heading');
    final iis = body.contains('[To Parent Directory]') && document.querySelector('pre') != null;
    return (index || iis) && document.querySelector('a[href]') != null;
  }

  static List<SecurityFinding> findings(Uri url, {required int status, required String contentType,
      required bool listing, required bool complete}) => [
    if (status >= 200 && status < 300 && listing)
      const SecurityFinding('asset.directory_listing', 'Directory listing observed', Severity.medium,
        'Directory index structure and entry links observed in the bounded response; filenames and contents omitted.',
        'Disable directory indexes where unnecessary and review the intended public files.', certainty: FindingCertainty.observed),
    if (status >= 200 && status < 300 && sensitive(url) && !contentType.contains('html'))
      SecurityFinding('asset.sensitive_candidate', 'Potentially sensitive file endpoint responded', Severity.medium,
        'Observed sensitive-looking filename returned HTTP $status; MIME $contentType. Contents omitted; exposure is unconfirmed.',
        'Confirm the response is the intended file rather than a fallback page, and remove unintended public deployment or backup files.'),
  ];
}
