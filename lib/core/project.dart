import 'dart:math';

class SecurityProject {
  final String id;
  final String name;
  final Uri startUrl;
  final List<Uri> additionalUrls;

  SecurityProject({String? id, required String name, required String url, List<String> additionalUrls = const []})
      : id = id ?? _newId(),
        name = name.trim(),
        startUrl = parseTarget(url),
        additionalUrls = List.unmodifiable(additionalUrls.map(parseTarget)) {
    if (this.name.isEmpty) throw const FormatException('Enter a project name.');
    if (!RegExp(r'^[a-f0-9]{32}$').hasMatch(this.id)) throw const FormatException('Invalid project ID.');
  }

  static String _newId() {
    final random = Random.secure();
    return List.generate(16, (_) => random.nextInt(256).toRadixString(16).padLeft(2, '0')).join();
  }

  static Uri parseTarget(String raw) {
    final uri = Uri.tryParse(raw.trim());
    if (uri == null || !['http', 'https'].contains(uri.scheme) ||
        !uri.hasAuthority || uri.host.isEmpty || uri.host.contains('*') || uri.userInfo.isNotEmpty ||
        uri.hasFragment || uri.hasQuery) {
      throw const FormatException('Enter an HTTP(S) URL without credentials, query or fragment.');
    }
    if (uri.port < 1 || uri.port > 65535) throw const FormatException('Invalid port.');
    return uri;
  }

  /// Accept one exact target URL per line. No wildcard or implicit subdomains.
  static List<String> parseTargetLines(String raw) {
    final result = <String>{};
    for (final line in raw.split(RegExp(r'\r?\n'))) {
      if (line.trim().isNotEmpty) result.add(parseTarget(line).toString());
      if (result.length > 30) throw const FormatException('Enter up to 30 additional targets.');
    }
    return result.toList();
  }

  List<Uri> get targets => List.unmodifiable({startUrl, ...additionalUrls});

  static bool sameOrigin(Uri a, Uri b) =>
      b.userInfo.isEmpty && a.scheme == b.scheme &&
      a.host.toLowerCase() == b.host.toLowerCase() && a.port == b.port;

  bool contains(Uri candidate) => targets.any((target) => sameOrigin(target, candidate));

  Map<String, dynamic> toJson() => {
    'id': id, 'name': name, 'url': startUrl.toString(),
    'additionalUrls': additionalUrls.map((u) => u.toString()).toList(),
  };

  factory SecurityProject.fromJson(Map<String, dynamic> json) => SecurityProject(
    id: json['id'] as String, name: json['name'] as String,
    url: json['url'] as String,
    additionalUrls: (json['additionalUrls'] as List<dynamic>? ?? []).cast<String>(),
  );
}
