import 'project.dart';
import 'route_inventory.dart';
import 'scan_policy.dart';

class BrowserTrafficRow {
  final Uri route;
  final String method;
  final bool hadQuery, mainFrame;
  final DateTime at;
  const BrowserTrafficRow(this.route, this.method, this.hadQuery, this.mainFrame, this.at);
}

class BrowserTraffic {
  static const limit = 200;
  static const methods = {'GET','HEAD','OPTIONS','POST','PUT','PATCH','DELETE'};

  /// Defensively validate the native snapshot again at the Dart boundary.
  static List<BrowserTrafficRow> parse(SecurityProject project, ScanPolicy policy, Object? payload) {
    if (payload is! List || payload.length > limit) throw const FormatException('Invalid browser traffic snapshot.');
    final result = <BrowserTrafficRow>[];
    for (final row in payload) {
      if (row is! Map || row['method'] is! String || !methods.contains(row['method']) ||
          row['hadQuery'] is! bool || row['mainFrame'] is! bool || row['at'] is! int) continue;
      final raw = row['route'];
      final uri = raw is String ? Uri.tryParse(raw) : null;
      if (uri == null || uri.scheme != 'https' || uri.hasQuery || uri.hasFragment) continue;
      final scoped = RouteInventory.scopedUrl(project, policy, raw);
      final at = row['at'] as int;
      if (scoped == null || at < 0 || at > 8640000000000000) continue;
      result.add(BrowserTrafficRow(scoped, row['method'] as String, row['hadQuery'] as bool,
        row['mainFrame'] as bool, DateTime.fromMillisecondsSinceEpoch(at, isUtc: true)));
    }
    return List.unmodifiable(result);
  }
}
