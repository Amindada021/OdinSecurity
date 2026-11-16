import 'dart:convert';
import 'discovery.dart';
import 'project.dart';
import 'project_storage.dart';
import 'scan_policy.dart';

/// No request/response payloads or credentials are persisted. Only previously
/// observed eligible queryless routes and the selected identity name.
class CrawlCheckpoint {
  final Uri start;
  final String identity;
  final List<Uri> seen, pending;
  final int attempted;
  CrawlCheckpoint(this.start, this.identity, Iterable<Uri> seen, Iterable<Uri> pending, this.attempted)
      : seen = List.unmodifiable(seen), pending = List.unmodifiable(pending) {
    if (this.seen.length > 30 || this.pending.length > 30 || attempted < 0 ||
        attempted + this.pending.length != this.seen.length ||
        this.seen.toSet().length != this.seen.length || this.pending.toSet().length != this.pending.length ||
        !this.seen.contains(start) || !this.seen.toSet().containsAll(this.pending) ||
        this.seen.any((url) => url.hasFragment || !LinkDiscovery.eligible(start, url))) {
      throw const FormatException('Invalid crawl checkpoint.');
    }
  }

  void validate(SecurityProject project, ScanPolicy policy, Uri expectedStart, String expectedIdentity) {
    if (start != expectedStart || identity != expectedIdentity || !project.contains(start) ||
        !policy.permits(start) || seen.length > policy.maxPages ||
        pending.any((url) => !project.contains(url) || !policy.permits(url))) {
      throw StateError('Checkpoint no longer matches project, identity or scan policy.');
    }
  }

  Map<String, dynamic> toJson() => {
    'start': start.toString(), 'identity': identity, 'attempted': attempted,
    'seen': seen.map((url) => url.toString()).toList(),
    'pending': pending.map((url) => url.toString()).toList(),
  };

  factory CrawlCheckpoint.fromJson(Map<String, dynamic> json) => CrawlCheckpoint(
    Uri.parse(json['start'] as String), json['identity'] as String,
    (json['seen'] as List).cast<String>().map(Uri.parse),
    (json['pending'] as List).cast<String>().map(Uri.parse), json['attempted'] as int);
}

class CrawlCheckpointRepository {
  final ProjectStorage storage;
  CrawlCheckpointRepository(this.storage);
  String _key(String id) => 'odin_security.crawl_checkpoint.v1.$id';

  Future<CrawlCheckpoint?> load(String projectId) async {
    final raw = await storage.read(_key(projectId));
    if (raw == null || raw == 'null') return null;
    if (raw.length > 150000) throw const FormatException('Checkpoint too large.');
    return CrawlCheckpoint.fromJson(Map<String, dynamic>.from(jsonDecode(raw) as Map));
  }

  Future<void> save(String projectId, CrawlCheckpoint? value) =>
    storage.write(_key(projectId), jsonEncode(value?.toJson()));
}
