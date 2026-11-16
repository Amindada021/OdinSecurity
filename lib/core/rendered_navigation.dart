import 'discovery.dart';
import 'project.dart';
import 'route_inventory.dart';
import 'scan_policy.dart';

/// Candidate routes from queryless rendered anchors only. No forms, scripts,
/// resource requests, guessed URLs, external origins or automatic redirects.
class RenderedNavigation {
  static const maxPages = 5;

  static List<Uri> candidates(SecurityProject project, ScanPolicy policy, Uri origin,
      Uri current, Iterable<RouteObservation> observed) {
    final routes = <Uri>{};
    final currentPath = current.path.isEmpty ? '/' : current.path;
    final cap = policy.maxPages < maxPages ? policy.maxPages : maxPages;
    for (final item in observed) {
      final target = item.url;
      if (item.source != 'navigation' || target == current ||
          (SecurityProject.sameOrigin(current, target) && !current.hasQuery && !current.hasFragment &&
            (target.path.isEmpty ? '/' : target.path) == currentPath) || target.scheme != 'https' ||
          target.hasFragment || !project.contains(target) || !policy.permits(target) ||
          !LinkDiscovery.eligible(origin, target)) continue;
      routes.add(target);
      if (routes.length >= cap) break;
    }
    return List.unmodifiable(routes);
  }
}
