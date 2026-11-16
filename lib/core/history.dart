import 'dart:convert';
import 'passive_scan.dart';
import 'advisory_review.dart';
import 'project_storage.dart';

class ScanRecord {
  final DateTime finishedAt;
  final int failedCount;
  final bool cancelled;
  final List<Map<String, dynamic>> pages;

  ScanRecord({required this.finishedAt, required this.failedCount, required this.cancelled, required this.pages});

  factory ScanRecord.fromPages(List<PassiveScanResult> results, {int failedCount = 0, bool cancelled = false}) => ScanRecord(
    finishedAt: DateTime.now().toUtc(), failedCount: failedCount, cancelled: cancelled,
    pages: results.map((page) => <String, dynamic>{
      'url': page.url.removeFragment().replace(query: '').toString(),
      'statusCode': page.statusCode,
      'bodyTruncated': page.bodyTruncated,
      'redirectNotFollowed': page.redirectNotFollowed,
      'technologies': page.technologies.map((tech) => {
        'name': tech.name, 'layer': tech.layer.name, 'confidence': tech.confidence.name, 'evidence': tech.evidence,
        if (tech.observedVersion != null) 'observedVersion': tech.observedVersion,
      }).toList(),
      'observations': page.findings.map((finding) => {
        'id': finding.id, 'title': finding.title, 'severity': finding.severity.name,
        'evidence': finding.evidence, 'remediation': finding.remediation,
      }).toList(),
    }).toList(),
  );

  Map<String, dynamic> toJson() => {
    'finishedAt': finishedAt.toIso8601String(), 'failedCount': failedCount, 'cancelled': cancelled, 'pages': pages,
  };

  factory ScanRecord.fromJson(Map<String, dynamic> data) => ScanRecord(
    finishedAt: DateTime.parse(data['finishedAt'] as String), failedCount: data['failedCount'] as int,
    cancelled: data['cancelled'] as bool,
    pages: (data['pages'] as List<dynamic>).map((p) => Map<String, dynamic>.from(p as Map)).toList(),
  );

  /// Candidate inventory from sanitized version declarations only. Older
  /// records without declared versions remain readable.
  List<Map<String, String>> declaredInventory() {
    final result = <Map<String, String>>[];
    final seen = <String>{};
    for (final page in pages) {
      final tech = page['technologies'];
      if (tech is! List) continue;
      for (final row in tech) {
        if (row is! Map) continue;
        final name = row['name'], version = row['observedVersion'];
        if (name is! String || name.trim().isEmpty || name.length > 120 || version is! String ||
            !AdvisoryCatalog.supportedVersion(version)) continue;
        if (!seen.add(name.toLowerCase() + '\u0000' + version)) continue;
        result.add({'product': name, 'version': version});
      }
    }
    return List.unmodifiable(result);
  }

  int get observationCount => pages.fold(0, (sum, page) => sum + (page['observations'] as List).length);
  String exportJson() => const JsonEncoder.withIndent('  ').convert({'schemaVersion': 1, ...toJson()});
}

class HistoryRepository {
  final ProjectStorage storage;
  HistoryRepository(this.storage);
  static const maxRecords = 20;
  String _key(String projectId) => 'odin_security.history.v1.$projectId';

  Future<List<ScanRecord>> load(String projectId) async {
    final raw = await storage.read(_key(projectId));
    if (raw == null) return [];
    return (jsonDecode(raw) as List<dynamic>).map((r) => ScanRecord.fromJson(Map<String, dynamic>.from(r as Map))).toList();
  }

  Future<List<ScanRecord>> append(String projectId, ScanRecord record) async {
    final existing = await load(projectId);
    final updated = [record, ...existing].take(maxRecords).toList();
    await storage.write(_key(projectId), jsonEncode(updated.map((r) => r.toJson()).toList()));
    return updated;
  }
}
