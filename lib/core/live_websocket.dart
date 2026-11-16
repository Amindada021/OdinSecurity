import 'dart:convert';
import 'dart:io';

import 'auth.dart';
import 'project.dart';
import 'scan_policy.dart';

/// Only allows the exact pre-approved HTTPS upgrade request and never follows
/// redirects. The Dart WebSocket client calls openUrl during its handshake.
class ScopedUpgradeClient implements HttpClient {
  final HttpClient delegate;
  final Uri destination;
  ScopedUpgradeClient(this.delegate, this.destination);

  @override
  Future<HttpClientRequest> openUrl(String method, Uri url) async {
    // The SDK may represent absent query/fragment as empty components.
    String path(Uri value) => value.path.isEmpty ? '/' : value.path;
    if (method != 'GET' || !SecurityProject.sameOrigin(destination, url) ||
        path(url) != path(destination) || url.query != destination.query || url.fragment.isNotEmpty) {
      throw StateError('Unexpected upgrade destination.');
    }
    final request = await delegate.openUrl(method, url);
    request.followRedirects = false;
    return request;
  }

  @override
  void close({bool force = false}) => delegate.close(force: force);

  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

class SocketMessageMetadata {
  final bool text;
  final int bytes;
  final String? preview;
  const SocketMessageMetadata(this.text, this.bytes, this.preview);

  factory SocketMessageMetadata.fromMessage(dynamic message, {bool includePreview = false}) {
    if (message is String) {
      final bytes = utf8.encode(message);
      return SocketMessageMetadata(true, bytes.length,
        includePreview ? utf8.decode(bytes.take(4096).toList(), allowMalformed: true) : null);
    }
    if (message is List<int>) return SocketMessageMetadata(false, message.length, null);
    throw const FormatException('Unsupported WebSocket message.');
  }
}

class LiveWebSocket {
  static const maxMessages = 100;
  static const maxOutgoingMessages = 10;
  static const maxOutgoingBytes = 4096;

  /// Only an individually approved text message on a staging connection.
  static int validateOutgoing(String message, {required bool staging, required bool confirmed, required int sent}) {
    if (!staging || !confirmed || sent < 0 || sent >= maxOutgoingMessages) {
      throw StateError('Manual staging message approval or budget required.');
    }
    if (message.isEmpty || message.length > maxOutgoingBytes) throw const FormatException('Invalid message size.');
    final bytes = utf8.encode(message).length;
    if (bytes > maxOutgoingBytes) throw const FormatException('Invalid message size.');
    return bytes;
  }

  static const maxObservedBytes = 256 * 1024;
  static const sessionDuration = Duration(seconds: 45);

  static Uri validate(SecurityProject project, ScanPolicy policy, Uri target, {required bool authorized, AuthProfile? auth}) {
    if (!authorized) throw StateError('Connection approval required.');
    if (target.scheme != 'wss' || !target.hasAuthority || target.host.isEmpty ||
        target.userInfo.isNotEmpty || target.hasFragment || target.toString().length > 2048) {
      throw const FormatException('Enter a valid WSS URL.');
    }
    final mapped = target.replace(scheme: 'https');
    if (!project.contains(mapped) || !policy.permits(mapped)) throw StateError('Outside project scope.');
    if (auth != null && (!SecurityProject.sameOrigin(auth.target, mapped) || auth.isLogin)) {
      throw StateError('Use a saved static identity on the exact origin.');
    }
    if (auth != null && auth.mode == AuthMode.apiKey &&
        (auth.headerName.toLowerCase().startsWith('sec-websocket-') ||
         ['cache-control', 'origin'].contains(auth.headerName.toLowerCase()))) {
      throw const FormatException('Identity conflicts with WebSocket handshake.');
    }
    return mapped;
  }

  Future<WebSocket> connect(SecurityProject project, ScanPolicy policy, Uri target, {
      required bool authorized, AuthProfile? auth}) async {
    final mapped = validate(project, policy, target, authorized: authorized, auth: auth);
    final headers = auth == null ? null : Authenticator.manual(auth).headersFor(mapped);
    if (auth != null && auth.mode != AuthMode.none && (headers == null || headers.isEmpty)) {
      throw StateError('Identity is not applicable to this path.');
    }
    final delegate = HttpClient()..connectionTimeout = const Duration(seconds: 10);
    final client = ScopedUpgradeClient(delegate, mapped);
    var expired = false;
    try {
      final socket = await WebSocket.connect(target.toString(), headers: headers,
        customClient: client, compression: CompressionOptions.compressionOff)
        .then((socket) async {
          if (expired) {
            await socket.close();
            throw StateError('Upgrade expired.');
          }
          return socket;
        }).timeout(const Duration(seconds: 15), onTimeout: () {
          expired = true;
          throw StateError('Upgrade timed out.');
        });
      return socket;
    } finally {
      // Successful upgrades detach their socket from the HTTP client.
      client.close(force: true);
    }
  }
}
