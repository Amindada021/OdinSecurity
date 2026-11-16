import 'dart:async';
import 'project.dart';
import 'scan_policy.dart';

class TrafficEntry {
  final String projectId, source, method;
  final Uri route;
  final bool hadQuery, truncated;
  final int? status, capturedBytes;
  final int elapsedMs;
  final DateTime at;

  const TrafficEntry({
    required this.projectId, required this.source, required this.method,
    required this.route, required this.hadQuery, required this.truncated,
    required this.status, required this.capturedBytes, required this.elapsedMs, required this.at,
  });
}

/// Bounded session-only log of requests sent by Odin Security itself.
/// No interception of other applications, headers, bodies or credentials.
class TrafficJournal {
  static final shared = TrafficJournal();
  static const limit = 200;
  final _items = <TrafficEntry>[];
  final _changes = StreamController<void>.broadcast();
  Stream<void> get changes => _changes.stream;

  void record(SecurityProject project, Uri url, {required String source, required String method,
      int? status, int? capturedBytes, required int elapsedMs, bool truncated = false}) {
    if (!project.contains(url) || url.userInfo.isNotEmpty || url.toString().length > 2048 ||
        !['manual', 'passive', 'cors'].contains(source) || !['GET', 'HEAD', 'OPTIONS'].contains(method)) return;
    final route = Uri.tryParse(url.toString().split(RegExp(r'[?#]')).first);
    if (route == null || !project.contains(route)) return;
    _items.insert(0, TrafficEntry(projectId: project.id, source: source, method: method,
      route: route, hadQuery: url.hasQuery, truncated: truncated, status: status,
      capturedBytes: capturedBytes, elapsedMs: elapsedMs, at: DateTime.now()));
    if (_items.length > limit) _items.removeLast();
    _changes.add(null);
  }

  List<TrafficEntry> forProject(SecurityProject project, ScanPolicy policy) => List.unmodifiable(
    _items.where((e) => e.projectId == project.id && project.contains(e.route) && policy.permits(e.route)));

  void clear(String projectId) {
    _items.removeWhere((e) => e.projectId == projectId);
    _changes.add(null);
  }
}
