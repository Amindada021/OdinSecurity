import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'project.dart';
import 'scan_policy.dart';

class TunnelHandshake {
  static const maxHeader = 8192;

  static bool accepts(String header, Uri target, String expectedAuthorization) {
    if (header.length > maxHeader || !header.endsWith('\r\n\r\n') ||
        header.codeUnits.any((c) => c > 126 || (c < 32 && c != 13 && c != 10 && c != 9))) return false;
    final lines = header.substring(0, header.length - 4).split('\r\n');
    final first = RegExp(r'^CONNECT ([^\s/?#@]+) HTTP/1\.[01]$').firstMatch(lines.first);
    if (first == null || target.scheme != 'https') return false;
    final authority = first.group(1)!;
    if (!RegExp(r'^(?:\[[0-9a-fA-F:.]+\]|[a-zA-Z0-9.-]+):[0-9]{1,5}$').hasMatch(authority)) return false;
    final requested = Uri.tryParse('https://$authority');
    if (requested == null || !SecurityProject.sameOrigin(target, requested)) return false;
    String? authorization;
    for (final line in lines.skip(1)) {
      final colon = line.indexOf(':');
      if (colon <= 0 || !RegExp(r'^[a-zA-Z0-9-]+$').hasMatch(line.substring(0, colon))) return false;
      if (line.substring(0, colon).toLowerCase() == 'proxy-authorization') {
        if (authorization != null) return false;
        authorization = line.substring(colon + 1).trim();
      }
    }
    return authorization == expectedAuthorization;
  }
}

/// CONNECT only, bound to loopback, one approved origin, no TLS termination.
class ScopedTunnel {
  static const sessionLimit = Duration(seconds: 90);
  static const maxPeers = 3;
  static const maxAttempts = 12;
  static const maxBytesPerPeer = 2 * 1024 * 1024;
  final Uri target;
  final String password;
  final ServerSocket _server;
  final Set<_TunnelPeer> _peers = {};
  final _events = StreamController<void>.broadcast();
  Timer? _timer;
  StreamSubscription<Socket>? _listener;
  bool _closed = false;
  int attempts = 0, connections = 0, sentBytes = 0, receivedBytes = 0;

  ScopedTunnel._(this.target, this.password, this._server);

  int get port => _server.port;
  bool get closed => _closed;
  int get active => _peers.length;
  Stream<void> get changes => _events.stream;

  static void validate(SecurityProject project, Uri target, ScanPolicy policy, bool authorized) {
    if (!authorized || target.scheme != 'https' || !project.contains(target) ||
        target.userInfo.isNotEmpty || target.hasQuery || target.hasFragment ||
        policy.excludedPaths.isNotEmpty || !policy.permits(target)) {
      throw StateError('Explicit HTTPS origin approval without path exclusions required.');
    }
  }

  static Future<ScopedTunnel> start(SecurityProject project, Uri target, ScanPolicy policy, {required bool authorized}) async {
    validate(project, target, policy, authorized);
    final random = Random.secure();
    final password = base64UrlEncode(List<int>.generate(24, (_) => random.nextInt(256)));
    final server = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0, shared: false);
    final session = ScopedTunnel._(target, password, server);
    session._listener = server.listen(session._accept, onError: (Object _) => session.stop());
    session._timer = Timer(sessionLimit, session.stop);
    return session;
  }

  void _notify() {
    if (!_events.isClosed) _events.add(null);
  }

  void _accept(Socket local) {
    if (_closed || _peers.length >= maxPeers || attempts >= maxAttempts) {
      local.destroy();
      return;
    }
    attempts++;
    final peer = _TunnelPeer(this, local);
    _peers.add(peer);
    peer.start();
    _notify();
  }

  void stop() {
    if (_closed) return;
    _closed = true;
    _timer?.cancel();
    unawaited(_listener?.cancel());
    unawaited(_server.close().then<void>((_) {}));
    for (final peer in _peers.toList()) { peer.close(); }
    _notify();
    unawaited(_events.close());
  }
}

class _TunnelPeer {
  final ScopedTunnel owner;
  final Socket local;
  Socket? remote;
  StreamSubscription<Uint8List>? input, output;
  Timer? deadline;
  final List<int> pending = [];
  bool ended = false, ready = false;
  int bytes = 0;

  _TunnelPeer(this.owner, this.local);

  void start() {
    deadline = Timer(const Duration(seconds: 10), close);
    unawaited(local.done.then<void>((_) {}, onError: (Object _) => close()));
    input = local.listen(onLocal, onError: (Object _) => close(), onDone: close, cancelOnError: true);
  }

  void onLocal(Uint8List data) {
    if (ended) return;
    if (ready) {
      if (!count(data.length, outgoing: true)) return;
      remote!.add(data);
      return;
    }
    if (pending.length + data.length > TunnelHandshake.maxHeader) { close(); return; }
    pending.addAll(data);
    if (pending.length < 4) return;
    final last = pending.length;
    if (pending[last - 4] != 13 || pending[last - 3] != 10 ||
        pending[last - 2] != 13 || pending[last - 1] != 10) return;
    input?.pause();
    final header = ascii.decode(pending, allowInvalid: true);
    pending.clear();
    final expected = 'Basic ' + base64Encode(utf8.encode('odin:' + owner.password));
    if (!TunnelHandshake.accepts(header, owner.target, expected)) {
      unawaited(reject());
      return;
    }
    unawaited(connect());
  }

  Future<void> reject() async {
    try {
      local.add(ascii.encode('HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="Odin"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n'));
      await local.flush().timeout(const Duration(seconds: 1));
    } catch (_) { /* no request data is retained */ }
    close();
  }

  Future<void> connect() async {
    try {
      final socket = await Socket.connect(owner.target.host, owner.target.port, timeout: const Duration(seconds: 8));
      if (ended || owner.closed) { socket.destroy(); return; }
      remote = socket;
      unawaited(socket.done.then<void>((_) {}, onError: (Object _) => close()));
      deadline?.cancel();
      local.add(ascii.encode('HTTP/1.1 200 Connection Established\r\n\r\n'));
      await local.flush().timeout(const Duration(seconds: 2));
      if (ended || owner.closed) { socket.destroy(); return; }
      ready = true;
      owner.connections++;
      owner._notify();
      output = socket.listen((data) {
        if (ended || !count(data.length, outgoing: false)) return;
        local.add(data);
      }, onError: (Object _) => close(), onDone: close, cancelOnError: true);
      input?.resume();
    } catch (_) { close(); }
  }

  bool count(int length, {required bool outgoing}) {
    bytes += length;
    if (bytes > ScopedTunnel.maxBytesPerPeer) { close(); return false; }
    if (outgoing) { owner.sentBytes += length; } else { owner.receivedBytes += length; }
    owner._notify();
    return true;
  }

  void close() {
    if (ended) return;
    ended = true;
    deadline?.cancel();
    pending.clear();
    unawaited(input?.cancel());
    unawaited(output?.cancel());
    local.destroy();
    remote?.destroy();
    owner._peers.remove(this);
    owner._notify();
  }
}
