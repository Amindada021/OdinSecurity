import 'dart:convert';
import 'auth.dart';
import 'project_storage.dart';

class ScanPolicy {
  final int maxRequests, delayMs;
  final List<String> excludedPaths;

  // maxPages remains a source/JSON migration alias for existing tools.
  int get maxPages => maxRequests;
  bool get unlimited => maxRequests == 0;
  bool allowsCount(int count) => unlimited || count <= maxRequests;
  bool exhausted(int used) => !unlimited && used >= maxRequests;

  ScanPolicy({int? maxRequests, int? maxPages, this.delayMs = 1000,
      List<String> excludedPaths = const []})
      : maxRequests = maxRequests ?? maxPages ?? 100,
        excludedPaths = List.unmodifiable(excludedPaths.map((p) => p.trim())) {
    if (this.maxRequests < 0 || delayMs < 500 || delayMs > 10000) {
      throw const FormatException('Max Requests must be a nonnegative integer; delay 500–10000 ms required.');
    }
    if (this.excludedPaths.length > 100 || this.excludedPaths.any((p) => !p.startsWith('/') ||
        p.contains(RegExp(r'[?#\r\n]')) || p.length > 512)) {
      throw const FormatException('Exclusions must be absolute URL paths.');
    }
  }

  ScanPolicy get quickDefaults => this;

  bool permits(Uri uri) {
    // Compare decoded path segments conservatively, including encoded separators.
    final path = '/${uri.pathSegments.join('/')}';
    return !excludedPaths.any((p) => AuthSession.matchesPath(p, path));
  }

  Map<String, dynamic> toJson() => {
    'maxRequests': maxRequests, 'maxPages': maxRequests, 'delayMs': delayMs, 'excludedPaths': excludedPaths,
  };

  factory ScanPolicy.fromJson(Map<String, dynamic> data) => ScanPolicy(
    maxRequests: (data['maxRequests'] ?? (data['maxPages'] == 12 ? 100 : data['maxPages']) ?? 100) as int,
    delayMs: data['delayMs'] as int,
    excludedPaths: (data['excludedPaths'] as List<dynamic>).cast<String>(),
  );
}

class ScanPolicyRepository {
  final ProjectStorage storage;
  ScanPolicyRepository(this.storage);
  String _key(String id) => 'odin_security.policy.v1.$id';
  Future<ScanPolicy> load(String id) async {
    final raw = await storage.read(_key(id));
    return raw == null ? ScanPolicy() : ScanPolicy.fromJson(Map<String, dynamic>.from(jsonDecode(raw) as Map));
  }
  Future<void> save(String id, ScanPolicy policy) => storage.write(_key(id), jsonEncode(policy.toJson()));
}
