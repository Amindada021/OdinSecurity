import 'dart:convert';

/// A local, user-supplied advisory association, not a vulnerability verdict.
class AdvisoryMatch {
  final String id, product, source;
  final List<String> affectedVersions;
  const AdvisoryMatch(this.id, this.product, this.source, this.affectedVersions);
}

class AdvisoryCatalog {
  final List<AdvisoryMatch> entries;
  const AdvisoryCatalog._(this.entries);
  static final _version = RegExp(r'^[0-9]+(?:\.[0-9]+){0,3}$');
  static bool supportedVersion(String value) => value.length <= 40 && _version.hasMatch(value);
  static String _product(String value) => value.trim().toLowerCase();

  factory AdvisoryCatalog.parse(String json) {
    if (json.length > 1024 * 1024) throw const FormatException('Catalog too large.');
    final decoded = jsonDecode(json);
    if (decoded is! List || decoded.length > 500) throw const FormatException('Invalid catalog.');
    final result = <AdvisoryMatch>[];
    for (final row in decoded) {
      if (row is! Map<String, dynamic>) throw const FormatException('Invalid advisory.');
      final id = row['id'], product = row['product'], source = row['source'], affected = row['affectedVersions'];
      if (id is! String || !RegExp(r'^CVE-[0-9]{4}-[0-9]{4,}$').hasMatch(id) || id.length > 32 ||
          product is! String || product.trim().isEmpty || product.length > 120 ||
          source is! String || source.length > 1024 || affected is! List || affected.isEmpty || affected.length > 200) {
        throw const FormatException('Invalid advisory.');
      }
      final uri = Uri.tryParse(source);
      if (uri == null || uri.scheme != 'https' || uri.host.isEmpty || uri.userInfo.isNotEmpty ||
          uri.hasQuery || uri.hasFragment) throw const FormatException('Invalid source.');
      if (affected.any((v) => v is! String || !supportedVersion(v))) throw const FormatException('Unsupported version.');
      result.add(AdvisoryMatch(id, product.trim(), source, List<String>.unmodifiable(affected.cast<String>())));
    }
    return AdvisoryCatalog._(List.unmodifiable(result));
  }

  List<AdvisoryMatch> match(String product, String version) {
    if (product.trim().isEmpty || !supportedVersion(version)) throw const FormatException('Enter a known product and numeric version.');
    // Literal matching intentionally avoids guessing version equivalence, prereleases
    // and distribution-specific backports.
    return List.unmodifiable(entries.where((a) =>
        _product(a.product) == _product(product) && a.affectedVersions.contains(version)));
  }
}
