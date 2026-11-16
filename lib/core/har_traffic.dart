import 'dart:convert';
import 'project.dart';
import 'route_inventory.dart';
import 'scan_policy.dart';

class HarTrafficEntry {
  final RouteObservation route;
  final int? status;
  final double? elapsedMs;
  final int? responseBytes;
  const HarTrafficEntry(this.route, this.status, this.elapsedMs, this.responseBytes);
}

class HarTrafficReport {
  final List<HarTrafficEntry> entries;
  final bool capped;
  const HarTrafficReport(this.entries, this.capped);

  int get clientErrors => entries.where((e) => (e.status ?? 0) >= 400 && (e.status ?? 0) < 500).length;
  int get serverErrors => entries.where((e) => (e.status ?? 0) >= 500).length;
  int get slow => entries.where((e) => (e.elapsedMs ?? 0) >= 1000).length;
  List<RouteObservation> get routes => RouteInventory.merge([], entries.map((e) => e.route));
}

class HarTrafficAnalyzer {
  static const entryLimit = 1000;
  static int? _status(Object? value) => value is int && value >= 100 && value <= 599 ? value : null;
  static int? _bytes(Object? value) => value is int && value >= 0 && value <= 0x7fffffff ? value : null;
  static double? _elapsed(Object? value) => value is num && value.isFinite && value >= 0 && value <= 86400000 ? value.toDouble() : null;

  /// Offline, bounded, scope-filtered summary of an explicitly imported HAR.
  /// Only request method, sanitized route, status, total timing and reported
  /// response body size are retained. No raw HTTP fields or bodies.
  static HarTrafficReport parse(SecurityProject project, ScanPolicy policy, String raw) {
    if (raw.length > RouteInventory.maxInput || utf8.encode(raw).length > RouteInventory.maxInput) {
      throw const FormatException('HAR exceeds 1 MiB.');
    }
    final parsed = jsonDecode(raw);
    if (parsed is! Map || parsed['log'] is! Map || parsed['log']['entries'] is! List) {
      throw const FormatException('Expected HAR JSON.');
    }
    final records = <HarTrafficEntry>[];
    var capped = false;
    for (final row in parsed['log']['entries'] as List) {
      if (row is! Map || row['request'] is! Map) continue;
      final request = row['request'] as Map;
      final method = request['method'];
      if (method is! String || !RouteInventory.methods.contains(method)) continue;
      final url = RouteInventory.scopedUrl(project, policy, request['url']);
      if (url == null) continue;
      if (records.length >= entryLimit) { capped = true; break; }
      final response = row['response'];
      records.add(HarTrafficEntry(RouteObservation(url, method),
        response is Map ? _status(response['status']) : null,
        _elapsed(row['time']),
        response is Map ? _bytes(response['bodySize']) : null));
    }
    return HarTrafficReport(List.unmodifiable(records), capped);
  }
}
