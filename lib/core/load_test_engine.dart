import 'dart:async';
import 'dart:collection';
import 'dart:convert';
import 'dart:io';
import 'dart:math' as math;
import 'load_test_policy.dart';
import 'project.dart';

class LabPermitVerifier {
  static bool privateAddress(InternetAddress a) {
    final b = a.rawAddress;
    return a.isLoopback || (b.length == 4 && (b[0] == 10 || b[0] == 192 && b[1] == 168 ||
      b[0] == 172 && b[1] >= 16 && b[1] <= 31)) || (b.length == 16 && (b[0] & 0xfe) == 0xfc);
  }
  static bool allowedAddress(InternetAddress a) {
    final b = a.rawAddress;
    if (a.isLinkLocal || a.isMulticast) return false;
    if (a.isLoopback) return true;
    if (b.length == 4) return b[0] != 0 && b[0] < 224 &&
      !(b[0] == 100 && b[1] >= 64 && b[1] <= 127) &&
      !(b[0] == 198 && (b[1] == 18 || b[1] == 19));
    // Reject unspecified and IPv4-mapped addresses rather than interpreting
    // them differently at the policy and transport layers.
    return b.length == 16 && b.any((v) => v != 0) &&
      !(b.take(10).every((v) => v == 0) && b[10] == 255 && b[11] == 255);
  }

  static HttpClient pinnedClient(Uri origin, InternetAddress address, {int users = 1, int timeoutSeconds = 5}) {
    final client = HttpClient()
      ..findProxy = (_) => 'DIRECT'
      ..connectionTimeout = Duration(seconds: timeoutSeconds)
      ..maxConnectionsPerHost = users
      ..idleTimeout = const Duration(seconds: 3)
      ..userAgent = 'OdinSecurity/LaboratoryLoadTest';
    client.connectionFactory = (uri, proxyHost, proxyPort) {
      if (proxyHost != null || proxyPort != null || !SecurityProject.sameOrigin(origin, uri)) {
        throw StateError('Proxy or cross-origin connection refused.');
      }
      return Socket.startConnect(address, uri.port);
    };
    return client;
  }

  Future<LabPermit> verify(SecurityProject project, Uri target, {required bool authorized,
      void Function(HttpClient)? onClient, bool Function(Uri)? permits}) async {
    SecurityProject.parseTarget(target.toString());
    if (!authorized || !project.contains(target) || !(permits?.call(target) ?? true)) throw const FormatException('Ownership authorization is required.');
    final resolved = await InternetAddress.lookup(target.host).timeout(const Duration(seconds: 5));
    if (resolved.isEmpty || resolved.any((address) => !allowedAddress(address))) {
      throw const FormatException('The server address is outside permitted laboratory networking.');
    }
    final pinned = resolved.first;
    if (target.scheme != 'https' && !(target.scheme == 'http' && pinned.isLoopback)) {
      throw const FormatException('HTTPS is required except for a loopback laboratory.');
    }
    final random = math.Random.secure();
    final nonce = base64UrlEncode(List<int>.generate(24, (_) => random.nextInt(256))).replaceAll('=', '');
    final uri = Uri.parse('${target.origin}/.well-known/odin-load-test').replace(queryParameters: {'challenge': nonce});
    if (!(permits?.call(uri) ?? true)) throw const FormatException('The permit endpoint is excluded by project policy.');
    final client = pinnedClient(target, pinned);
    onClient?.call(client);
    Future<LabPermit> acquire() async {
      final request = await client.getUrl(uri);
      request.followRedirects = false;
      request.headers.set('Accept', 'application/json');
      final response = await request.close();
      if (response.statusCode == 429 || response.statusCode == 503) {
        throw LabCooldown(response.statusCode, retryAfter(response.headers.value('retry-after')));
      }
      if (response.statusCode != 200 || response.headers.contentType?.mimeType != 'application/json') {
        throw const FormatException('Publish the administrator laboratory permit endpoint first.');
      }
      final bytes = <int>[];
      await for (final chunk in response) {
        if (bytes.length + chunk.length > 16384) throw const FormatException('Laboratory permit response is too large.');
        bytes.addAll(chunk);
      }
      final json = jsonDecode(utf8.decode(bytes));
      if (json is! Map) throw const FormatException('Invalid administrator permit.');
      final permit = LabPermit.fromVerifiedResponse(Map<String, dynamic>.from(json), target, pinned, nonce, DateTime.now().toUtc());
      if (permit.environment == 'local' && !privateAddress(pinned)) {
        throw const FormatException('A local permit cannot authorize a public server.');
      }
      return permit;
    }
    try { return await acquire().timeout(const Duration(seconds: 10)); }
    finally { client.close(force: true); }
  }

  static DateTime retryAfter(String? header) {
    final now = DateTime.now().toUtc();
    final seconds = int.tryParse(header ?? '');
    if (seconds != null && seconds >= 0) return seconds <= 31536000
        ? now.add(Duration(seconds: seconds)) : DateTime.utc(9999, 12, 31);
    try {
      final date = HttpDate.parse(header ?? '').toUtc();
      if (date.isAfter(now)) return date;
    } catch (_) { /* Invalid Retry-After uses the laboratory cooldown. */ }
    return now.add(const Duration(seconds: 60));
  }
}

class LabCooldown implements Exception {
  final int status;
  final DateTime until;
  const LabCooldown(this.status, this.until);
  @override
  String toString() => 'Server requested a cooldown (HTTP $status).';
}

class LoadTestControl {
  String? reason;
  void Function()? _abort;
  bool get stopped => reason != null;
  void stop([String why = 'manual_stop']) {
    reason ??= why;
    _abort?.call();
  }
}

class LoadSnapshot {
  final int sent, successful, failed, cancelled, inFlight;
  final double elapsedSeconds, averageMs, p95Ms, p99Ms, rps;
  final Map<String, int> statuses;
  const LoadSnapshot({required this.sent, required this.successful, required this.failed,
    required this.cancelled, required this.inFlight, required this.elapsedSeconds, required this.averageMs,
    required this.p95Ms, required this.p99Ms, required this.rps, required this.statuses});
  Map<String, dynamic> toJson() => {'sent': sent, 'successful': successful, 'failed': failed,
    'cancelled': cancelled, 'inFlight': inFlight, 'elapsedSeconds': elapsedSeconds, 'averageMs': averageMs,
    'p95Ms': p95Ms, 'p99Ms': p99Ms, 'rps': rps, 'statuses': statuses};
  factory LoadSnapshot.fromJson(Map<String, dynamic> j) => LoadSnapshot(sent: j['sent'] as int,
    successful: j['successful'] as int, failed: j['failed'] as int, cancelled: j['cancelled'] as int,
    inFlight: j['inFlight'] as int, elapsedSeconds: (j['elapsedSeconds'] as num).toDouble(),
    averageMs: (j['averageMs'] as num).toDouble(), p95Ms: (j['p95Ms'] as num).toDouble(),
    p99Ms: (j['p99Ms'] as num).toDouble(), rps: (j['rps'] as num).toDouble(),
    statuses: Map<String, int>.from(j['statuses'] as Map));
}

class LoadTestResult {
  final LoadTestConfig config;
  final Map<String, dynamic> permit;
  final DateTime startedAt, finishedAt;
  final String reason;
  final LoadSnapshot summary;
  final List<LoadSnapshot> samples;
  final DateTime? cooldownUntil;
  const LoadTestResult({required this.config, required this.permit, required this.startedAt,
    required this.finishedAt, required this.reason, required this.summary, required this.samples, this.cooldownUntil});
  Map<String, dynamic> toJson() => {'schemaVersion': 1, 'config': config.toJson(), 'permit': permit,
    'startedAt': startedAt.toIso8601String(), 'finishedAt': finishedAt.toIso8601String(), 'reason': reason,
    'summary': summary.toJson(), 'samples': samples.map((v) => v.toJson()).toList(),
    'cooldownUntil': cooldownUntil?.toIso8601String(), 'verificationRequests': 1,
    'latencyMetric': 'Time to response headers; 1 ms quantile resolution; timeouts and cancellations counted separately.',
    'scope': 'Single client, GET, exact opt-in local/staging endpoint; no production or distributed traffic.'};
  factory LoadTestResult.fromJson(Map<String, dynamic> j) => LoadTestResult(
    config: LoadTestConfig.fromJson(Map<String, dynamic>.from(j['config'] as Map)),
    permit: Map<String, dynamic>.from(j['permit'] as Map), startedAt: DateTime.parse(j['startedAt'] as String),
    finishedAt: DateTime.parse(j['finishedAt'] as String), reason: j['reason'] as String,
    summary: LoadSnapshot.fromJson(Map<String, dynamic>.from(j['summary'] as Map)),
    samples: (j['samples'] as List).map((v) => LoadSnapshot.fromJson(Map<String, dynamic>.from(v as Map))).toList(),
    cooldownUntil: j['cooldownUntil'] == null ? null : DateTime.parse(j['cooldownUntil'] as String));
}

class LoadTestEngine {
  static bool _active = false;
  static final Map<String, DateTime> _cooldowns = {};
  Future<LoadTestResult> run(SecurityProject project, LoadTestConfig config, {
    required bool authorized, required LoadTestControl control, DateTime? blockedUntil,
    void Function(LabPermit)? onPermit, void Function(LoadSnapshot)? onUpdate, bool Function(Uri)? permits,
  }) async {
    if (_active) throw StateError('Another laboratory load test is already active.');
    final remembered = _cooldowns[config.target.origin];
    if (remembered?.isAfter(DateTime.now()) == true) throw LabCooldown(429, remembered!);
    _active = true;
    try {
      final result = await _run(project, config, authorized: authorized, control: control,
        blockedUntil: blockedUntil, onPermit: onPermit, onUpdate: onUpdate, permits: permits);
      if (result.cooldownUntil != null) _cooldowns[config.target.origin] = result.cooldownUntil!;
      return result;
    } on LabCooldown catch (e) {
      _cooldowns[config.target.origin] = e.until;
      rethrow;
    } finally { control._abort = null; _active = false; }
  }

  Future<LoadTestResult> _run(SecurityProject project, LoadTestConfig config, {
    required bool authorized, required LoadTestControl control, DateTime? blockedUntil,
    void Function(LabPermit)? onPermit, void Function(LoadSnapshot)? onUpdate, bool Function(Uri)? permits,
  }) async {
    config.validate();
    if (blockedUntil?.isAfter(DateTime.now()) == true) throw LabCooldown(429, blockedUntil!);
    if (control.stopped) throw StateError('Test cancelled before verification.');
    // Never accept a caller-created permit as authority. Revalidate on every run.
    final permit = await LabPermitVerifier().verify(project, config.target, authorized: authorized, permits: permits,
      onClient: (client) { control._abort = () => client.close(force: true); if (control.stopped) client.close(force: true); });
    if (control.stopped) throw StateError('Test cancelled before traffic generation.');
    permit.validate(config, project, DateTime.now().toUtc());
    onPermit?.call(permit);
    final address = InternetAddress(permit.pinnedAddress);
    final client = LabPermitVerifier.pinnedClient(config.target, address, users: config.users, timeoutSeconds: config.timeoutSeconds);
    final activeRequests = <HttpClientRequest>{};
    final tasks = <Future<void>>{};
    var sent = 0, successful = 0, failed = 0, cancelled = 0, inFlight = 0;
    var latencyCount = 0, sumLatencyMs = 0.0;
    final histogram = SplayTreeMap<int, int>();
    final statuses = <String, int>{};
    final rolling = Queue<({double ms, bool failed})>();
    final samples = <LoadSnapshot>[];
    final started = DateTime.now().toUtc();
    final clock = Stopwatch()..start();
    var tokens = config.rampSeconds == 0 ? 1.0 : 0.0;
    var lastTickMs = 0, lastPublishMs = 0, lastCompleted = 0;
    DateTime? cooldown;
    final done = Completer<void>();
    Timer? scheduler;
    void abort() {
      scheduler?.cancel();
      for (final request in activeRequests.toList()) { request.abort(); }
      client.close(force: true);
      if (!done.isCompleted) done.complete();
    }
    control._abort = abort;
    double percentile(double q) {
      if (latencyCount == 0) return 0;
      final rank = (latencyCount * q).ceil();
      var n = 0;
      for (final entry in histogram.entries) { n += entry.value; if (n >= rank) return entry.key.toDouble(); }
      return histogram.lastKey()!.toDouble();
    }
    LoadSnapshot snapshot({bool finalSample = false}) {
      final now = clock.elapsedMilliseconds;
      final completed = successful + failed;
      final interval = now - lastPublishMs;
      final value = LoadSnapshot(sent: sent, successful: successful, failed: failed, cancelled: cancelled,
        inFlight: inFlight, elapsedSeconds: now / 1000, averageMs: latencyCount == 0 ? 0 : sumLatencyMs / latencyCount,
        p95Ms: percentile(.95), p99Ms: percentile(.99),
        rps: finalSample ? (now == 0 ? 0 : completed * 1000 / now) : interval <= 0 ? 0 : (completed - lastCompleted) * 1000 / interval,
        statuses: Map.unmodifiable(statuses));
      lastPublishMs = now; lastCompleted = completed;
      return value;
    }
    void record(String status, double? ms, bool error) {
      statuses.update(status, (n) => n + 1, ifAbsent: () => 1);
      if (error) { failed++; } else { successful++; }
      if (ms != null) {
        latencyCount++; sumLatencyMs += ms;
        histogram.update(ms.round(), (n) => n + 1, ifAbsent: () => 1);
      }
      rolling.add((ms: ms ?? config.timeoutSeconds * 1000.0, failed: error));
      if (rolling.length > 100) rolling.removeFirst();
      if (rolling.length >= permit.minimumSamples && !control.stopped) {
        final latencies = rolling.map((row) => row.ms).toList()..sort();
        final p95 = latencies[(latencies.length * .95).ceil() - 1];
        if (p95 >= permit.stopLatencyMs || rolling.where((row) => row.failed).length * 100 / rolling.length >= permit.stopErrorPercent) {
          control.stop('severe_degradation');
        }
      }
    }
    Future<void> request() async {
      HttpClientRequest? open;
      final timer = Stopwatch()..start();
      var classified = false;
      Future<void> perform() async {
        open = await client.getUrl(config.target);
        if (control.stopped || classified) { open!.abort(); throw StateError('cancelled'); }
        activeRequests.add(open!);
        open!.followRedirects = false;
        open!.cookies.clear();
        open!.headers.removeAll(HttpHeaders.cookieHeader);
        open!.headers.set('Accept', 'application/json, text/plain;q=0.9');
        // No credentials, request bodies, redirects, proxies or automatic retry.
        final response = await open!.close();
        final latency = timer.elapsedMicroseconds / 1000;
        final status = response.statusCode;
        if (classified) return;
        if (control.stopped) { classified = true; cancelled++; return; }
        classified = true;
        if (status == 429 || status == 503) {
          cooldown = LabPermitVerifier.retryAfter(response.headers.value('retry-after'));
          control.stop(status == 429 ? 'rate_limited' : 'service_unavailable');
        }
        record('$status', latency, status < 200 || status >= 300);
        if (control.stopped) return;
        var discarded = 0;
        await for (final chunk in response) { discarded += chunk.length; if (discarded >= 4096) break; }
      }
      try {
        await perform().timeout(Duration(seconds: config.timeoutSeconds), onTimeout: () {
          open?.abort();
          throw TimeoutException('Laboratory request timeout.');
        });
      } catch (e) {
        if (!classified) {
          classified = true;
          if (control.stopped) { cancelled++; }
          else { record(e is TimeoutException ? 'timeout' : 'network_error', null, true); }
        }
      } finally {
        if (open != null) activeRequests.remove(open);
        inFlight--;
      }
    }
    void publish(LoadSnapshot value) {
      try { onUpdate?.call(value); }
      catch (_) { control.stop('dashboard_unavailable'); }
    }
    void tick() {
      if (control.stopped) { abort(); return; }
      if (clock.elapsedMilliseconds >= config.durationSeconds * 1000) { control.stop('duration_completed'); return; }
      if (!permit.expiresAt.isAfter(DateTime.now().toUtc())) { control.stop('permit_expired'); return; }
      if (sent >= permit.maxTotalRequests) { control.stop('request_budget'); return; }
      final now = clock.elapsedMilliseconds;
      if (now - lastPublishMs >= 1000) { final value = snapshot(); samples.add(value); publish(value); }
      if (control.stopped) return;
      final ramp = config.rampSeconds == 0 ? 1.0 : math.min(1.0, (now + 10) / (config.rampSeconds * 1000));
      final users = math.max(1, (config.users * ramp).ceil());
      final rps = config.rps * ramp;
      tokens = math.min(1.0, tokens + rps * (now - lastTickMs) / 1000).toDouble();
      lastTickMs = now;
      if (inFlight >= users || tokens < 1.0) return;
      // At most one token is retained: no queued traffic or catch-up bursts.
      tokens -= 1.0;
      sent++; inFlight++;
      late final Future<void> task;
      task = request().whenComplete(() { tasks.remove(task); });
      tasks.add(task);
    }
    try {
      scheduler = Timer.periodic(const Duration(milliseconds: 10), (_) {
        try { tick(); } catch (_) { control.stop('engine_error'); }
      });
      await done.future;
      await Future.wait(tasks.toList());
      final tail = snapshot();
      samples.add(tail); publish(tail);
      final finalValue = snapshot(finalSample: true);
      return LoadTestResult(config: config, permit: permit.toJson(), startedAt: started,
        finishedAt: DateTime.now().toUtc(), reason: control.reason ?? 'completed', summary: finalValue,
        samples: List.unmodifiable(samples), cooldownUntil: cooldown);
    } finally {
      scheduler?.cancel(); client.close(force: true); control._abort = null; clock.stop();
    }
  }
}
