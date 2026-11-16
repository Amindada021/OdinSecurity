import 'dart:convert';

/// Explicit vendor-provided interval using exactly three canonical numeric
/// components. No prereleases, platform backports, or inferred equivalence.
class AdvisoryVersionRange {
  final String introduced, fixed;
  const AdvisoryVersionRange._(this.introduced, this.fixed);

  static List<int>? _parts(String v) {
    final match = RegExp(r'^(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})$').firstMatch(v);
    return match == null ? null : [for (var i = 1; i <= 3; i++) int.parse(match.group(i)!)];
  }

  static int _compare(List<int> a, List<int> b) {
    for (var i = 0; i < 3; i++) {
      final cmp = a[i].compareTo(b[i]);
      if (cmp != 0) return cmp;
    }
    return 0;
  }

  factory AdvisoryVersionRange.fromJson(dynamic row) {
    if (row is! Map<String, dynamic> || row.length != 2 || row['introduced'] is! String ||
        row['fixed'] is! String) throw const FormatException('Invalid interval.');
    final start = row['introduced'] as String, end = row['fixed'] as String;
    final a = _parts(start), b = _parts(end);
    if (a == null || b == null || _compare(a, b) >= 0) throw const FormatException('Invalid interval bounds.');
    return AdvisoryVersionRange._(start, end);
  }

  bool contains(String version) {
    final v = _parts(version);
    return v != null && _compare(v, _parts(introduced)!) >= 0 && _compare(v, _parts(fixed)!) < 0;
  }
}

/// A local, user-supplied advisory association, not a vulnerability verdict.
class AdvisoryMatch {
  final String id, product, source;
  final List<String> affectedVersions;
  final List<AdvisoryVersionRange> ranges;
  const AdvisoryMatch(this.id, this.product, this.source, this.affectedVersions, [this.ranges = const []]);
  bool affects(String version) => affectedVersions.contains(version) || ranges.any((r) => r.contains(version));
}

class InventoryAdvisoryResult {
  final String product, version;
  final List<AdvisoryMatch> matches;
  const InventoryAdvisoryResult(this.product, this.version, this.matches);
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
      final id = row['id'], product = row['product'], source = row['source'];
      final affected = row.containsKey('affectedVersions') ? row['affectedVersions'] : <String>[];
      final ranges = row.containsKey('ranges') ? row['ranges'] : <dynamic>[];
      if (id is! String || !RegExp(r'^CVE-[0-9]{4}-[0-9]{4,}$').hasMatch(id) || id.length > 32 ||
          product is! String || product.trim().isEmpty || product.length > 120 ||
          source is! String || source.length > 1024 || affected is! List || affected.length > 200 ||
          ranges is! List || ranges.length > 20 || affected.isEmpty && ranges.isEmpty) {
        throw const FormatException('Invalid advisory.');
      }
      final uri = Uri.tryParse(source);
      if (uri == null || uri.scheme != 'https' || uri.host.isEmpty || uri.userInfo.isNotEmpty ||
          uri.hasQuery || uri.hasFragment) throw const FormatException('Invalid source.');
      if (affected.any((v) => v is! String || !supportedVersion(v))) throw const FormatException('Unsupported version.');
      result.add(AdvisoryMatch(id, product.trim(), source, List<String>.unmodifiable(affected.cast<String>()),
        List.unmodifiable(ranges.map(AdvisoryVersionRange.fromJson))));
    }
    return AdvisoryCatalog._(List.unmodifiable(result));
  }

  List<AdvisoryMatch> match(String product, String version) {
    if (product.trim().isEmpty || product.length > 120 || !supportedVersion(version)) {
      throw const FormatException('Enter a known product and numeric version.');
    }
    return List.unmodifiable(entries.where((a) => _product(a.product) == _product(product) && a.affects(version)));
  }

  List<InventoryAdvisoryResult> reviewInventory(String json) {
    if (json.length > 65536) throw const FormatException('Inventory too large.');
    final decoded = jsonDecode(json);
    if (decoded is! List || decoded.isEmpty || decoded.length > 100) throw const FormatException('Invalid inventory.');
    final result = <InventoryAdvisoryResult>[];
    var total = 0;
    final seen = <String>{};
    for (final row in decoded) {
      if (row is! Map<String, dynamic> || row.length != 2 || row['product'] is! String || row['version'] is! String) {
        throw const FormatException('Invalid inventory row.');
      }
      final product = (row['product'] as String).trim(), version = row['version'] as String;
      final matches = match(product, version);
      if (!seen.add(_product(product) + '\u0000' + version)) throw const FormatException('Duplicate inventory row.');
      total += matches.length;
      if (total > 500) throw const FormatException('Too many matches; split inventory.');
      result.add(InventoryAdvisoryResult(product, version, matches));
    }
    return List.unmodifiable(result);
  }
}
