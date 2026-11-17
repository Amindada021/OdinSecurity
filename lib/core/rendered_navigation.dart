import 'discovery.dart';
import 'project.dart';
import 'route_inventory.dart';
import 'scan_policy.dart';

/// Candidate routes from queryless rendered anchors only. No forms, scripts,
/// resource requests, guessed URLs, external origins or automatic redirects.
class RenderedNavigation {
  static String routeKey(Uri url) => url.replace(path: url.path.isEmpty ? '/' : url.path).toString();

  static List<Uri> candidates(SecurityProject project, ScanPolicy policy, Uri origin,
      Uri current, Iterable<RouteObservation> observed, {Iterable<Uri> attempted = const [], int? remaining}) {
    final routes = <Uri>{};
    final currentPath = current.path.isEmpty ? '/' : current.path;
    final previous = attempted.map((url) => routeKey(url)).toSet();
    if (remaining != null && remaining <= 0) return const [];
    final cap = remaining ?? (policy.unlimited ? null : policy.maxRequests);
    for (final item in observed) {
      final target = item.url;
      if (item.source != 'navigation' || previous.contains(routeKey(target)) || target == current ||
          (SecurityProject.sameOrigin(current, target) && !current.hasQuery && !current.hasFragment &&
            (target.path.isEmpty ? '/' : target.path) == currentPath) || target.scheme != 'https' ||
          target.hasFragment || !project.contains(target) || !policy.permits(target) ||
          !LinkDiscovery.eligible(origin, target)) continue;
      if (!previous.add(routeKey(target))) continue;
      routes.add(target);
      if (cap != null && routes.length >= cap) break;
    }
    return List.unmodifiable(routes);
  }
}
