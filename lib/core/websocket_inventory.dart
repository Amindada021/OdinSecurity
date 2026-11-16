import 'dart:convert';
import 'project.dart';
import 'route_inventory.dart';
import 'scan_policy.dart';

class WebSocketObservation {
  final Uri url;
  final int? handshakeStatus;
  final int sent, received, unknown;
  final bool framesAvailable;
  const WebSocketObservation(this.url, this.handshakeStatus, this.sent, this.received, this.unknown, this.framesAvailable);
}

class WebSocketInventory {
  static const maxConnections = 100;
  static const maxFrames = 2000;

  /// Read saved HAR metadata, including optional nonstandard frame arrays.
  /// No connection, message replay, token extraction or payload retention.
  static List<WebSocketObservation> parse(SecurityProject project, ScanPolicy policy, String source) {
    if (source.length > RouteInventory.maxInput || utf8.encode(source).length > RouteInventory.maxInput) {
      throw const FormatException('HAR exceeds limit.');
    }
    final data = jsonDecode(source);
    if (data is! Map || data['log'] is! Map || data['log']['entries'] is! List) {
      throw const FormatException('Expected HAR JSON.');
    }
    final result = <WebSocketObservation>[];
    for (final entry in data['log']['entries'] as List) {
      if (entry is! Map || entry['request'] is! Map) continue;
      final request = entry['request'] as Map;
      final raw = request['url'];
      if (raw is! String || raw.length > 2048) continue;
      final uri = Uri.tryParse(raw);
      if (uri == null || uri.userInfo.isNotEmpty || !uri.hasAuthority) continue;
      final response = entry['response'];
      final status = response is Map && response['status'] is int ? response['status'] as int : null;
      final frames = entry['_webSocketMessages'];
      final isSocket = ['ws', 'wss'].contains(uri.scheme);
      final headers = response is Map ? response['headers'] : null;
      final websocketUpgrade = headers is List && headers.any((header) =>
        header is Map && header['name'] is String && header['value'] is String &&
        (header['name'] as String).toLowerCase() == 'upgrade' &&
        (header['value'] as String).toLowerCase().trim() == 'websocket');
      if (!isSocket && !(status == 101 && (websocketUpgrade || frames is List))) continue;
      final equivalent = uri.replace(scheme: switch (uri.scheme) {'ws' => 'http', 'wss' => 'https', _ => uri.scheme});
      final clean = RouteInventory.scopedUrl(project, policy, equivalent.toString());
      if (clean == null) continue;
      final route = clean.replace(scheme: clean.scheme == 'https' ? 'wss' : 'ws');
      var sent = 0, received = 0, unknown = 0;
      if (frames is List) {
        if (frames.length > maxFrames) throw const FormatException('Too many frame entries.');
        for (final frame in frames) {
          if (frame is! Map) { unknown++; continue; }
          final direction = frame['type'];
          if (direction == 'send' || direction == 'sent') {
            sent++;
          } else if (direction == 'receive' || direction == 'received') {
            received++;
          } else {
            unknown++;
          }
        }
      }
      if (result.length >= maxConnections) throw const FormatException('Too many connections.');
      result.add(WebSocketObservation(route, status != null && status >= 100 && status <= 599 ? status : null,
        sent, received, unknown, frames is List));
    }
    return List.unmodifiable(result);
  }
}
