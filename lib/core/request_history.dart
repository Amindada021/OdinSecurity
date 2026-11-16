import 'manual_request.dart';

/// Session-local metadata only; never keeps query values, request headers,
/// credentials, response headers or response content.
class RequestRecord {
  final String method, route;
  final bool hadQuery, authenticated, customized;
  final ManualAccept accept;
  final int status, elapsedMs, bodyBytes;
  final bool truncated;
  final DateTime at;

  const RequestRecord({
    required this.method, required this.route, required this.hadQuery,
    required this.authenticated, required this.accept, required this.status,
    required this.elapsedMs, required this.bodyBytes, required this.truncated,
    required this.at, this.customized = false,
  });

  factory RequestRecord.fromResponse(Uri url, String method, ManualAccept accept, bool authenticated, ManualResponse result, {DateTime? at, bool customized = false}) {
    if (url.userInfo.isNotEmpty) throw const FormatException('Credential-bearing URLs cannot be recorded.');
    final route = url.toString().split(RegExp(r'[?#]')).first;
    return RequestRecord(method: method, route: route, hadQuery: url.hasQuery,
      authenticated: authenticated, accept: accept, status: result.status,
      elapsedMs: result.elapsedMs, bodyBytes: result.bodyBytes, truncated: result.truncated,
      at: at ?? DateTime.now(), customized: customized);
  }

  bool comparableTo(RequestRecord other) => !hadQuery && !other.hadQuery && !customized && !other.customized &&
    ManualRequestClient.readMethods.contains(method) &&
    route == other.route && method == other.method && accept == other.accept &&
    authenticated == other.authenticated;
}

class RequestHistory {
  static const limit = 20;
  final List<RequestRecord> _records = [];
  List<RequestRecord> get records => List.unmodifiable(_records);
  void add(RequestRecord record) {
    _records.insert(0, record);
    if (_records.length > limit) _records.removeLast();
  }
  void clear() => _records.clear();
}
