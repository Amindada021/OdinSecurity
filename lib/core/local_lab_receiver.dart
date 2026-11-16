import 'dart:async';
import 'dart:io';
import 'test_fixtures.dart';

class LocalLabEvent {
  final String method;
  final DateTime time;
  const LocalLabEvent(this.method, this.time);
}

/// Non-public laboratory receiver. No DNS listener, external bind, forwarding,
/// source addresses, request headers, body logging, or remote callbacks.
class LocalLabReceiver {
  static const maxEvents = 10;
  static const lifetime = Duration(minutes: 2);
  final _events = <LocalLabEvent>[];
  final _changes = StreamController<void>.broadcast();
  HttpServer? _server;
  Timer? _expiry;
  String? _label;
  bool _starting = false, _disposed = false;

  List<LocalLabEvent> get events => List.unmodifiable(_events);
  Stream<void> get changes => _changes.stream;
  Uri? get endpoint {
    final s = _server;
    return s == null ? null : Uri(scheme: 'http', host: '127.0.0.1', port: s.port, path: '/lab/' + _label!);
  }

  Future<void> start({required bool approved}) async {
    if (!approved || _disposed || _server != null || _starting) throw StateError('Local listener approval required.');
    _starting = true;
    try {
      final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0, shared: false);
      if (_disposed) { await server.close(force: true); return; }
      _events.clear();
      _label = LabInteractionReview.newLabel();
      _server = server;
      _expiry = Timer(lifetime, () { unawaited(stop()); });
      server.listen(_handle, onError: (Object _) { unawaited(stop()); });
      _notify();
    } finally { _starting = false; }
  }

  void _notify() { if (!_disposed) _changes.add(null); }

  Future<void> _handle(HttpRequest request) async {
    final approved = _server != null && request.connectionInfo?.remoteAddress.isLoopback == true &&
      request.uri.path == '/lab/' + (_label ?? '') && !request.uri.hasQuery &&
      request.uri.fragment.isEmpty && ['GET','HEAD'].contains(request.method) &&
      request.contentLength <= 0 && request.headers.value(HttpHeaders.transferEncodingHeader) == null &&
      _events.length < maxEvents;
    try {
      if (approved) {
        _events.add(LocalLabEvent(request.method, DateTime.now().toUtc()));
        request.response.statusCode = HttpStatus.noContent;
        _notify();
      } else {
        request.response.statusCode = HttpStatus.notFound;
      }
      request.response.persistentConnection = false;
      await request.response.close();
    } catch (_) { /* No payload or exception details retained. */ }
    if (_events.length >= maxEvents) await stop();
  }

  Future<void> stop() async {
    _expiry?.cancel();
    _expiry = null;
    final server = _server;
    _server = null;
    _label = null;
    _notify();
    await server?.close(force: true);
  }

  Future<void> dispose() async {
    _disposed = true;
    await stop();
    await _changes.close();
  }
}
