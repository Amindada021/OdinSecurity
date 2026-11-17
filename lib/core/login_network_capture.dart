import 'dart:convert';
import 'package:odin_security/core/project.dart';
import 'package:odin_security/core/scan_policy.dart';

/// An in-memory view of a page's fetch/XHR response. Not a full packet capture.
/// Request bodies, request headers, cookies and URL query strings are excluded.
class LoginNetworkResponse {
  final Uri url;
  final String method, contentType, body, source;
  final int status;
  final bool truncated;

  const LoginNetworkResponse({
    required this.url, required this.method, required this.status,
    required this.contentType, required this.body, required this.source,
    required this.truncated,
  });

  static LoginNetworkResponse? fromBridge(String raw, {
    required Uri login, required Uri target, ScanPolicy? policy,
  }) {
    if (raw.length > 40000) return null;
    try {
      final decoded = jsonDecode(raw);
      if (decoded is! Map) return null;
      final uri = Uri.tryParse(decoded['url'] as String? ?? '');
      if (uri == null || uri.userInfo.isNotEmpty ||
          !['https', 'http'].contains(uri.scheme) ||
          !(SecurityProject.sameOrigin(login, uri) ||
            SecurityProject.sameOrigin(target, uri)) ||
          (policy != null && !policy.permits(uri))) return null;
      final contentType = decoded['contentType'];
      final text = decoded['body'];
      final status = decoded['status'];
      final method = decoded['method'];
      final source = decoded['source'];
      if (contentType is! String || text is! String || status is! int ||
          status < 0 || status > 599 || method is! String ||
          !RegExp(r'^[A-Z]{3,8}$').hasMatch(method) ||
          (source != 'fetch' && source != 'xhr') ||
          text.length > 32768) return null;
      final stripped = Uri.parse(uri.toString().split(RegExp(r'[?#]')).first);
      return LoginNetworkResponse(
        url: stripped, method: method, status: status,
        contentType: contentType.substring(0, contentType.length > 100 ? 100 : contentType.length),
        body: text, source: source, truncated: decoded['truncated'] == true,
      );
    } catch (_) {
      return null;
    }
  }

  List<LoginTokenCandidate> get tokens => LoginTokenCandidate.fromJsonBody(body);
}

class LoginTokenCandidate {
  final String path, value;
  const LoginTokenCandidate(this.path, this.value);

  static List<LoginTokenCandidate> fromJsonBody(String body) {
    dynamic decoded;
    try { decoded = jsonDecode(body); } catch (_) { return const []; }
    final matches = <LoginTokenCandidate>[];
    const names = {'token', 'accesstoken', 'access_token', 'sessionid', 'session_id',
      'bearertoken', 'bearer_token', 'jwt'};
    void visit(dynamic node, String path, int depth) {
      if (depth > 8 || matches.length >= 12) return;
      if (node is Map) {
        for (final entry in node.entries) {
          if (entry.key is! String) continue;
          final key = entry.key as String;
          final next = path.isEmpty ? key : '$path.$key';
          final value = entry.value;
          if (names.contains(key.toLowerCase()) && value is String &&
              value.isNotEmpty && value.length <= 16384 &&
              RegExp(r'^[A-Za-z0-9._~+/-]+=*$').hasMatch(
                value.replaceFirst(RegExp(r'^Bearer +', caseSensitive: false), ''))) {
            matches.add(LoginTokenCandidate(next, value));
          } else if (value is Map || value is List) {
            visit(value, next, depth + 1);
          }
        }
      } else if (node is List) {
        for (var i = 0; i < node.length && i < 10; i++) {
          visit(node[i], '$path[$i]', depth + 1);
        }
      }
    }
    visit(decoded, '', 0);
    return matches;
  }
}

/// Executed after the login document loads and before the user submits login.
/// Captures fetch/XHR *responses* from then onward (not all browser traffic).
/// No request bodies/headers, query strings, or passwords are passed to Flutter.
const loginNetworkInstrumentation = r'''
(function () {
  if (window.__odinNetworkActive) return;
  window.__odinNetworkActive = true;
  var LIMIT = 32000;
  function permittedType(type) {
    return /json|text\/plain|text\/html|application\/problem/i.test(type || '');
  }
  function report(source, url, method, status, contentType, body, truncated) {
    try {
      if (!window.OdinLoginNetwork) return;
      window.OdinLoginNetwork.postMessage(JSON.stringify({
        source: source, url: String(url || ''), method: String(method || 'GET').toUpperCase(),
        status: status, contentType: String(contentType || ''),
        body: String(body || '').slice(0, LIMIT), truncated: !!truncated
      }));
    } catch (_) {}
  }
  async function inspectFetch(response, url, method) {
    try {
      var contentType = response.headers.get('content-type') || '';
      if (!permittedType(contentType)) return;
      var clone = response.clone();
      if (!clone.body || !clone.body.getReader) return;
      var reader = clone.body.getReader();
      var decoder = new TextDecoder();
      var text = '';
      var truncated = false;
      try {
        while (true) {
          var next = await reader.read();
          if (next.done) break;
          text += decoder.decode(next.value, {stream: true});
          if (text.length > LIMIT) { truncated = true; break; }
        }
        if (!truncated) text += decoder.decode();
      } finally {
        if (truncated) try { await reader.cancel(); } catch (_) {}
      }
      report('fetch', response.url || url, method, response.status,
             contentType, text, truncated);
    } catch (_) {}
  }
  if (typeof window.fetch === 'function') {
    var oldFetch = window.fetch;
    window.fetch = function(input, init) {
      var url = typeof input === 'string' ? input : (input && input.url) || '';
      var method = (init && init.method) || (input && input.method) || 'GET';
      var promise = oldFetch.apply(this, arguments);
      Promise.resolve(promise).then(function(response) {
        inspectFetch(response, url, method);
      }).catch(function() {});
      return promise;
    };
  }
  if (window.XMLHttpRequest && XMLHttpRequest.prototype) {
    var oldOpen = XMLHttpRequest.prototype.open;
    var oldSend = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.open = function(method, url) {
      this.__odinMeta = {method: String(method).toUpperCase(), url: String(url)};
      return oldOpen.apply(this, arguments);
    };
    XMLHttpRequest.prototype.send = function() {
      var xhr = this;
      xhr.addEventListener('loadend', function() {
        try {
          var type = xhr.getResponseHeader('content-type') || '';
          if (!permittedType(type) || (xhr.responseType && xhr.responseType !== 'text')) return;
          var value = xhr.responseText || '';
          report('xhr', xhr.responseURL || (xhr.__odinMeta && xhr.__odinMeta.url),
            (xhr.__odinMeta && xhr.__odinMeta.method) || 'GET',
            xhr.status, type, value, value.length > LIMIT);
        } catch (_) {}
      }, {once: true});
      return oldSend.apply(this, arguments);
    };
  }
})();
''';
