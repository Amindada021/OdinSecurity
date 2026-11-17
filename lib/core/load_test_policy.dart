import 'dart:io';
import 'dart:math' as math;
import 'project.dart';

class LoadTestConfig {
  final Uri target;
  final int users, durationSeconds, timeoutSeconds, rampSeconds;
  final double rps;
  const LoadTestConfig({required this.target, this.users = 2, this.rps = 2,
    this.durationSeconds = 30, this.timeoutSeconds = 5, this.rampSeconds = 5});
  void validate() {
    SecurityProject.parseTarget(target.toString());
    if (users < 1 || users > 50 || !rps.isFinite || rps < 0.1 || rps > 100 ||
        durationSeconds < 1 || durationSeconds > 600 || timeoutSeconds < 1 || timeoutSeconds > 30 ||
        rampSeconds < 0 || rampSeconds > durationSeconds || (rps * durationSeconds).ceil() > 30000) {
      throw const FormatException('Settings exceed the laboratory safety envelope.');
    }
  }
  Map<String, dynamic> toJson() => {'target': target.toString(), 'users': users, 'rps': rps,
    'durationSeconds': durationSeconds, 'timeoutSeconds': timeoutSeconds, 'rampSeconds': rampSeconds};
  factory LoadTestConfig.fromJson(Map<String, dynamic> j) => LoadTestConfig(
    target: SecurityProject.parseTarget(j['target'] as String), users: j['users'] as int,
    rps: (j['rps'] as num).toDouble(), durationSeconds: j['durationSeconds'] as int,
    timeoutSeconds: j['timeoutSeconds'] as int, rampSeconds: j['rampSeconds'] as int);
}

enum LoadRisk { low, moderate, high, disruption }

/// Supplied by the administrator's opt-in endpoint, never editable in the UI.
/// Runtime authority comes from the engine re-fetching this policy from the
/// pinned server with a fresh nonce; history/caller-created objects are not authority.
class LabPermit {
  final Uri origin;
  final String environment, permitId, pinnedAddress;
  final List<String> allowedPaths;
  final DateTime expiresAt, verifiedAt;
  final int maxUsers, maxDurationSeconds, maxTimeoutSeconds, maxTotalRequests;
  final int capacityUsers, baselineLatencyMs, stopLatencyMs, minimumSamples;
  final double maxRps, capacityRps, stopErrorPercent;
  const LabPermit._({required this.origin, required this.environment, required this.permitId,
    required this.pinnedAddress, required this.allowedPaths, required this.expiresAt, required this.verifiedAt,
    required this.maxUsers, required this.maxRps, required this.maxDurationSeconds,
    required this.maxTimeoutSeconds, required this.maxTotalRequests, required this.capacityUsers,
    required this.capacityRps, required this.baselineLatencyMs, required this.stopLatencyMs,
    required this.stopErrorPercent, required this.minimumSamples});

  // The verifier calls this only after acquiring the policy from the pinned
  // target over trusted HTTPS, or from a loopback address over HTTP.
  static LabPermit fromVerifiedResponse(Map<String, dynamic> j, Uri target,
      InternetAddress pinned, String nonce, DateTime now) {
    int integer(String key, int min, int max) {
      final v = j[key];
      if (v is! int || v < min || v > max) throw const FormatException('Invalid administrator policy limits.');
      return v;
    }
    double number(String key, double min, double max) {
      final v = j[key];
      if (v is! num || !v.isFinite || v < min || v > max) throw const FormatException('Invalid administrator policy limits.');
      return v.toDouble();
    }
    if (j['schemaVersion'] != 1 || j['purpose'] != 'odinsecurity-load-test' || j['challenge'] != nonce ||
        !const {'local', 'staging'}.contains(j['environment']) || j['origin'] != target.origin ||
        j['permitId'] is! String || !RegExp(r'^[a-zA-Z0-9._-]{1,80}$').hasMatch(j['permitId'] as String)) {
      throw const FormatException('The server did not issue a valid local/staging permit.');
    }
    final expiry = DateTime.tryParse(j['expiresAt'] as String? ?? '');
    if (expiry == null || !expiry.isAfter(now) || expiry.difference(now) > const Duration(hours: 1)) {
      throw const FormatException('The laboratory permit is expired or too long-lived.');
    }
    final ips = j['allowedAddresses'];
    if (ips is! List || ips.length > 16 || !ips.contains(pinned.address)) {
      throw const FormatException('The pinned server address is not approved by its administrator.');
    }
    final paths = j['allowedPaths'];
    if (paths is! List || paths.isEmpty || paths.length > 20 || paths.any((path) => path is! String ||
        !path.startsWith('/') || path.startsWith('//') || path.length > 1024 ||
        path.contains(RegExp(r'[?#\r\n*]')) || target.resolve(path).path != path)) {
      throw const FormatException('The administrator must authorize exact read-only paths.');
    }
    final baseline = integer('baselineLatencyMs', 1, 30000);
    final stop = integer('stopLatencyMs', baseline, 30000);
    return LabPermit._(origin: Uri.parse(target.origin), environment: j['environment'] as String,
      permitId: j['permitId'] as String, pinnedAddress: pinned.address,
      allowedPaths: List.unmodifiable(paths.cast<String>()), expiresAt: expiry.toUtc(), verifiedAt: now.toUtc(),
      maxUsers: integer('maxConcurrentUsers', 1, 50), maxRps: number('maxRps', 0.1, 100),
      maxDurationSeconds: integer('maxDurationSeconds', 1, 600), maxTimeoutSeconds: integer('maxTimeoutSeconds', 1, 30),
      maxTotalRequests: integer('maxTotalRequests', 1, 30000), capacityUsers: integer('capacityUsers', 1, 1000000),
      capacityRps: number('capacityRps', 0.1, 1000000), baselineLatencyMs: baseline, stopLatencyMs: stop,
      stopErrorPercent: number('stopErrorPercent', 1, 50), minimumSamples: integer('minimumSamples', 5, 100));
  }

  void validate(LoadTestConfig config, SecurityProject project, DateTime now) {
    config.validate();
    if (!project.contains(config.target) || !SecurityProject.sameOrigin(origin, config.target) ||
        !allowedPaths.contains(config.target.path.isEmpty ? '/' : config.target.path) ||
        !expiresAt.isAfter(now) || config.users > maxUsers || config.rps > maxRps ||
        config.durationSeconds > maxDurationSeconds || config.timeoutSeconds > maxTimeoutSeconds ||
        (config.rps * config.durationSeconds).ceil() > maxTotalRequests ||
        expiresAt.difference(now).inSeconds < config.durationSeconds) {
      throw const FormatException('Settings exceed the administrator permit or its remaining lifetime.');
    }
  }

  LoadRisk risk(LoadTestConfig config, {double? observedLatencyMs}) {
    final latencyFactor = math.max(1.0, (observedLatencyMs ?? baselineLatencyMs) / baselineLatencyMs);
    final pressure = math.max(config.rps / capacityRps, config.users / capacityUsers) * latencyFactor;
    return pressure < 0.35 ? LoadRisk.low : pressure < 0.65 ? LoadRisk.moderate :
      pressure < 1.0 ? LoadRisk.high : LoadRisk.disruption;
  }

  Map<String, dynamic> toJson() => {'origin': origin.toString(), 'environment': environment, 'permitId': permitId,
    'pinnedAddress': pinnedAddress, 'allowedPaths': allowedPaths, 'expiresAt': expiresAt.toIso8601String(),
    'verifiedAt': verifiedAt.toIso8601String(), 'maxConcurrentUsers': maxUsers, 'maxRps': maxRps,
    'maxDurationSeconds': maxDurationSeconds, 'maxTimeoutSeconds': maxTimeoutSeconds,
    'maxTotalRequests': maxTotalRequests, 'capacityUsers': capacityUsers, 'capacityRps': capacityRps,
    'baselineLatencyMs': baselineLatencyMs, 'stopLatencyMs': stopLatencyMs,
    'stopErrorPercent': stopErrorPercent, 'minimumSamples': minimumSamples};
}
