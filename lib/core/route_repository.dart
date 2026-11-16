import 'dart:convert';
import 'discovery.dart';
import 'project.dart';
import 'project_storage.dart';
import 'route_inventory.dart';
import 'scan_policy.dart';

/// Explicitly saved metadata, not a raw traffic log. Current project scope and
/// exclusions are reapplied on every load and save.
class RouteRepository {
  final ProjectStorage storage;
  RouteRepository(this.storage);
  String _key(String projectId) => 'odin_security.routes.v1.$projectId';

  static RouteObservation? clean(SecurityProject project, ScanPolicy policy, Object? source, Object? raw) {
    if (source is! String || !(RouteInventory.sources.contains(source) || RouteInventory.methods.contains(source))) return null;
    final url = RouteInventory.scopedUrl(project, policy, raw);
    return url == null ? null : RouteObservation(url, source);
  }

  Future<List<RouteObservation>> load(SecurityProject project, ScanPolicy policy) async {
    final raw = await storage.read(_key(project.id));
    if (raw == null) return [];
    if (raw.length > RouteInventory.maxInput) throw const FormatException('Saved routes exceed limit.');
    final data = jsonDecode(raw);
    if (data is! List) throw const FormatException('Invalid saved routes.');
    final records = <String, RouteObservation>{};
    for (final row in data) {
      if (row is! Map) continue;
      final route = clean(project, policy, row['source'], row['url']);
      if (route != null) records[route.key] = route;
      if (records.length >= RouteInventory.maxEntries) break;
    }
    return List.unmodifiable(records.values);
  }

  Future<List<RouteObservation>> save(SecurityProject project, ScanPolicy policy, Iterable<RouteObservation> routes) async {
    final records = <String, RouteObservation>{};
    for (final route in routes) {
      final next = clean(project, policy, route.source, route.url.toString());
      if (next != null) records[next.key] = next;
      if (records.length >= RouteInventory.maxEntries) break;
    }
    await storage.write(_key(project.id), jsonEncode([
      for (final route in records.values) {'source': route.source, 'url': route.url.toString()},
    ]));
    return List.unmodifiable(records.values);
  }

  Future<List<RouteObservation>> append(SecurityProject project, ScanPolicy policy, List<RouteObservation> routes) async =>
    save(project, policy, [...await load(project, policy), ...routes]);

  static bool canOpenInspector(RouteObservation route) =>
    ['GET', 'HEAD', 'document', 'link'].contains(route.source) &&
    !route.url.hasFragment && LinkDiscovery.eligible(route.url, route.url);
}
