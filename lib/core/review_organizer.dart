import 'dart:convert';
import 'project.dart';
import 'project_storage.dart';
import 'route_inventory.dart';
import 'scan_policy.dart';

enum ReviewStatus { open, resolved, falsePositive }

class ReviewItem {
  final Uri route;
  final String title, note;
  final ReviewStatus status;
  const ReviewItem(this.route, this.title, this.note, this.status);
}

/// User-authored review notes, not captured traffic. Scope is rechecked
/// whenever the project is opened. Rejects route queries; callers must use sanitized notes.
class ReviewOrganizer {
  static const limit = 100;
  final ProjectStorage storage;
  ReviewOrganizer(this.storage);
  String _key(SecurityProject p) => 'odin_security.review.v1.${p.id}';

  static ReviewItem prepare(SecurityProject project, ScanPolicy policy, String route,
      String title, String note, ReviewStatus status) {
    final target = SecurityProject.parseTarget(route);
    final clean = RouteInventory.scopedUrl(project, policy, target.toString());
    final heading = title.trim(), body = note.trim();
    if (clean == null || heading.isEmpty || heading.length > 120 || body.length > 2000) {
      throw const FormatException('Invalid review item.');
    }
    return ReviewItem(clean, heading, body, status);
  }

  Future<List<ReviewItem>> load(SecurityProject project, ScanPolicy policy) async {
    final raw = await storage.read(_key(project));
    if (raw == null) return [];
    if (raw.length > RouteInventory.maxInput) throw const FormatException('Review storage exceeds limit.');
    final list = jsonDecode(raw);
    if (list is! List || list.length > limit) throw const FormatException('Invalid review list.');
    final result = <ReviewItem>[];
    for (final row in list) {
      if (row is! Map) continue;
      try {
        result.add(prepare(project, policy, row['route'] as String, row['title'] as String, row['note'] as String,
          ReviewStatus.values.byName(row['status'] as String)));
      } catch (_) {
        // Stale scope or invalid records are never surfaced.
      }
    }
    return List.unmodifiable(result);
  }

  Future<void> save(SecurityProject project, ScanPolicy policy, List<ReviewItem> items) async {
    if (items.length > limit) throw const FormatException('Too many review items.');
    final checked = items.map((item) => prepare(project, policy, item.route.toString(), item.title, item.note, item.status));
    await storage.write(_key(project), jsonEncode([
      for (final item in checked) {'route': item.route.toString(), 'title': item.title, 'note': item.note, 'status': item.status.name},
    ]));
  }
}
