import 'dart:convert';
import 'auth.dart';
import 'project_storage.dart';

class ScanPolicy {
  final int maxPages, delayMs;
  final List<String> excludedPaths;

  ScanPolicy({this.maxPages = 12, this.delayMs = 1000, List<String> excludedPaths = const []})
      : excludedPaths = List.unmodifiable(excludedPaths.map((p) => p.trim())) {
    if (maxPages < 1 || maxPages > 30 || delayMs < 500 || delayMs > 10000) {
      throw const FormatException('Page cap 1–30 and delay 500–10000 ms required.');
    }
    if (this.excludedPaths.length > 100 || this.excludedPaths.any((p) => !p.startsWith('/') ||
        p.contains(RegExp(r'[?#\r\n]')) || p.length > 512)) {
      throw const FormatException('Exclusions must be absolute URL paths.');
    }
  }

  /// Quick scanning uses conservative defaults without relaxing saved restrictions.
  ScanPolicy get quickDefaults => ScanPolicy(
    maxPages: maxPages < 12 ? maxPages : 12,
    delayMs: delayMs > 1000 ? delayMs : 1000,
    excludedPaths: excludedPaths,
  );

  bool permits(Uri uri) {
    // Compare decoded path segments conservatively, including encoded separators.
    final path = '/${uri.pathSegments.join('/')}';
    return !excludedPaths.any((p) => AuthSession.matchesPath(p, path));
  }

  Map<String, dynamic> toJson() => {
    'maxPages': maxPages, 'delayMs': delayMs, 'excludedPaths': excludedPaths,
  };

  factory ScanPolicy.fromJson(Map<String, dynamic> data) => ScanPolicy(
    maxPages: data['maxPages'] as int,
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
