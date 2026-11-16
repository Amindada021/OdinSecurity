class SecurityProject {
  final String name;
  final Uri startUrl;
  SecurityProject({required String name, required String url})
      : name = name.trim(),
        startUrl = parseTarget(url) {
    if (this.name.isEmpty) throw const FormatException('Enter a project name.');
  }

  static Uri parseTarget(String raw) {
    final uri = Uri.tryParse(raw.trim());
    if (uri == null ||
        !['http', 'https'].contains(uri.scheme) ||
        !uri.hasAuthority ||
        uri.host.isEmpty ||
        uri.userInfo.isNotEmpty ||
        uri.hasFragment ||
        uri.hasQuery) {
      throw const FormatException('Enter an HTTP(S) URL without credentials, query or fragment.');
    }
    if (uri.port < 1 || uri.port > 65535) {
      throw const FormatException('Invalid port.');
    }
    return uri;
  }

  bool contains(Uri candidate) =>
      candidate.scheme == startUrl.scheme &&
      candidate.host.toLowerCase() == startUrl.host.toLowerCase() &&
      candidate.port == startUrl.port &&
      candidate.userInfo.isEmpty;
}
