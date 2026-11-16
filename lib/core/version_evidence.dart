/// Extracts only constrained, public version declarations. This is observed
/// server/page metadata, not a verified installed package or patch level.
class VersionEvidence {
  static final _numeric = RegExp(r'^[0-9]{1,9}(?:\.[0-9]{1,9}){1,3}$');
  static final _meta = RegExp(r'<meta\b[^>]{0,1024}>', caseSensitive: false);
  static final _attribute = RegExp(r'''([a-zA-Z][a-zA-Z0-9:_-]*)\s*=\s*(?:"([^"]*)"|'([^']*)')''');

  static String? _unique(Iterable<String> versions) {
    final values = versions.where((v) => _numeric.hasMatch(v)).toSet();
    return values.length == 1 ? values.single : null;
  }

  static String? _banner(List<String> headers, String product) {
    final pattern = RegExp('(?:^|[\\s;(])' + RegExp.escape(product) +
        r'/([0-9]{1,9}(?:\.[0-9]{1,9}){1,3})(?=$|[\s;)])', caseSensitive: false);
    return _unique(headers.where((v) => v.length <= 4096).expand((v) =>
      pattern.allMatches(v).map((m) => m.group(1)!)));
  }

  static String? _generator(String body, String product) {
    final values = <String>[];
    final expected = RegExp('^' + RegExp.escape(product) +
        r'\s+([0-9]{1,9}(?:\.[0-9]{1,9}){1,3})$', caseSensitive: false);
    for (final meta in _meta.allMatches(body).take(200)) {
      final attrs = <String, String>{};
      var duplicate = false;
      for (final match in _attribute.allMatches(meta.group(0)!)) {
        final key = match.group(1)!.toLowerCase();
        if (attrs.containsKey(key)) duplicate = true;
        attrs[key] = match.group(2) ?? match.group(3)!;
      }
      if (duplicate || attrs['name']?.toLowerCase() != 'generator') continue;
      final version = expected.firstMatch(attrs['content']?.trim() ?? '')?.group(1);
      if (version != null) values.add(version);
    }
    return _unique(values);
  }

  static String? forTechnology(String name, Map<String, List<String>> headers, String body) {
    final server = headers['server'] ?? const <String>[];
    final powered = headers['x-powered-by'] ?? const <String>[];
    final serverProducts = {'Nginx':'nginx','Apache':'apache','IIS':'Microsoft-IIS',
      'OpenResty':'openresty','Tomcat':'Tomcat','Jetty':'Jetty','Caddy':'Caddy',
      'Gunicorn':'gunicorn','Uvicorn':'uvicorn','LiteSpeed':'LiteSpeed'};
    final component = serverProducts[name];
    if (component != null) return _banner(server, component);
    if (name == 'PHP') return _banner(powered, 'PHP');
    if (name == 'ASP.NET (legacy)') return _unique(headers['x-aspnet-version'] ?? const <String>[]);
    if (name == 'WordPress' || name == 'Joomla' || name == 'Drupal' || name == 'Ghost') return _generator(body, name);
    return null;
  }
}
