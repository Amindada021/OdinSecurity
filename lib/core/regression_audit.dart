import 'discovery.dart';
import 'manual_request.dart';
import 'project.dart';
import 'scan_policy.dart';

class RegressionCase {
  final Uri endpoint;
  final int expectedStatus;
  const RegressionCase(this.endpoint, this.expectedStatus);
}

class RegressionResult {
  final RegressionCase check;
  final int actualStatus;
  const RegressionResult(this.check, this.actualStatus);
  bool get passed => actualStatus == check.expectedStatus;
}

class RegressionRun {
  final List<RegressionResult> results;
  final bool stopped;
  const RegressionRun(this.results, this.stopped);
}

typedef RegressionProbe = Future<int> Function(SecurityProject project, Uri endpoint, ScanPolicy policy);

/// Explicit, unauthenticated HEAD regression checks on known read-only routes.
/// No target generation, payload mutation, redirects, or response body retention.
class RegressionAudit {
  static const maxCases = 10;
  final RegressionProbe probe;
  final Future<void> Function(Duration) wait;
  RegressionAudit({RegressionProbe? probe, Future<void> Function(Duration)? wait})
    : probe = probe ?? _probe, wait = wait ?? ((duration) => Future<void>.delayed(duration));

  static Future<int> _probe(SecurityProject project, Uri endpoint, ScanPolicy policy) async =>
    (await ManualRequestClient().send(project, endpoint, 'HEAD', authorized: true, policy: policy)).status;

  static void _validate(SecurityProject project, ScanPolicy policy, RegressionCase check) {
    final endpoint = check.endpoint;
    if (!project.contains(endpoint) || !policy.permits(endpoint) ||
        !LinkDiscovery.eligible(endpoint, endpoint) || endpoint.hasQuery ||
        endpoint.hasFragment || endpoint.scheme != 'https' ||
        check.expectedStatus < 100 || check.expectedStatus > 599) {
      throw const FormatException('Invalid regression case.');
    }
  }

  static List<RegressionCase> parse(SecurityProject project, ScanPolicy policy, String input) {
    if (input.length > 22000) throw const FormatException('Input too large.');
    final cases = <RegressionCase>[];
    final seen = <Uri>{};
    for (final line in input.split(RegExp(r'\r?\n'))) {
      if (line.trim().isEmpty) continue;
      final parts = line.trim().split(RegExp(r'\s+'));
      if (parts.length != 2) throw const FormatException('Expected status and URL.');
      final status = int.tryParse(parts[0]);
      if (status == null) throw const FormatException('Invalid status.');
      final endpoint = SecurityProject.parseTarget(parts[1]);
      final check = RegressionCase(endpoint, status);
      _validate(project, policy, check);
      if (!seen.add(endpoint)) throw const FormatException('Duplicate endpoint.');
      cases.add(check);
      if (cases.length > maxCases || !policy.allowsCount(cases.length)) throw const FormatException('Case limit.');
    }
    if (cases.isEmpty) throw const FormatException('No cases.');
    return List.unmodifiable(cases);
  }

  Future<RegressionRun> run(SecurityProject project, ScanPolicy policy, List<RegressionCase> cases,
    {required bool authorized, required bool Function() cancelled}) async {
    if (!authorized) throw StateError('Explicit authorization required.');
    if (cases.isEmpty || cases.length > maxCases || !policy.allowsCount(cases.length)) {
      throw const FormatException('Case limit.');
    }
    final snapshot = List<RegressionCase>.unmodifiable(cases);
    final unique = <Uri>{};
    for (final check in snapshot) {
      _validate(project, policy, check);
      if (!unique.add(check.endpoint)) throw const FormatException('Duplicate endpoint.');
    }
    final results = <RegressionResult>[];
    for (final check in snapshot) {
      if (cancelled()) break;
      if (results.isNotEmpty) await wait(Duration(milliseconds: policy.delayMs));
      if (cancelled()) break;
      final int actual;
      try {
        actual = await probe(project, check.endpoint, policy);
      } catch (_) {
        break; // Never retry or continue after a transport failure.
      }
      results.add(RegressionResult(check, actual));
      if (actual == 429 || actual >= 500) break;
    }
    return RegressionRun(List.unmodifiable(results), results.length != snapshot.length);
  }
}
