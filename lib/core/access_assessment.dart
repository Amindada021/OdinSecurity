import 'auth.dart';
import 'discovery.dart';
import 'passive_scan.dart';
import 'project.dart';
import 'scan_policy.dart';

enum AccessOutcome { expected, unexpectedSuccess, inconclusive }

class AccessAssessmentResult {
  final int expectedAllowedStatus, expectedDeniedStatus;
  final AccessOutcome outcome;
  const AccessAssessmentResult(this.expectedAllowedStatus, this.expectedDeniedStatus, this.outcome);

  static AccessOutcome classify(int allowed, int denied) {
    if (allowed < 200 || allowed >= 300) return AccessOutcome.inconclusive;
    if (denied >= 200 && denied < 300) return AccessOutcome.unexpectedSuccess;
    if ([401, 403, 404].contains(denied)) return AccessOutcome.expected;
    return AccessOutcome.inconclusive;
  }
}

abstract interface class AccessProbe {
  Future<int> status(SecurityProject project, Uri endpoint, AuthProfile identity);
}

class ScopedAccessProbe implements AccessProbe {
  @override
  Future<int> status(SecurityProject project, Uri endpoint, AuthProfile identity) async {
    final page = await PassiveScanner().scan(project, authorized: true, target: endpoint, auth: identity);
    return page.statusCode;
  }
}

/// Explicit authorization test of ONE known read-only URL with TWO test users.
/// Does not discover object IDs, modify requests, try guessed URLs, or retain
/// response bodies. A 2xx from the denied profile is only a review signal.
class AccessAssessment {
  final AccessProbe probe;
  AccessAssessment({AccessProbe? probe}) : probe = probe ?? ScopedAccessProbe();

  Future<AccessAssessmentResult> run({
    required SecurityProject project, required Uri endpoint, required AuthProfile expectedAllowed,
    required AuthProfile expectedDenied, required ScanPolicy policy, required bool authorized,
  }) async {
    if (!authorized || !project.contains(endpoint) || !policy.permits(endpoint) ||
        !LinkDiscovery.eligible(endpoint, endpoint) || endpoint.hasFragment) {
      throw StateError('Endpoint is outside authorized read-only scope.');
    }
    if (expectedAllowed.name.trim().toLowerCase() == expectedDenied.name.trim().toLowerCase() ||
        expectedAllowed.mode == AuthMode.none || expectedDenied.mode == AuthMode.none ||
        !SecurityProject.sameOrigin(expectedAllowed.target, endpoint) ||
        !SecurityProject.sameOrigin(expectedDenied.target, endpoint) ||
        expectedAllowed.validationUrl.isEmpty || expectedDenied.validationUrl.isEmpty) {
      throw StateError('Two distinct verified test identities from this origin are required.');
    }
    for (final identity in [expectedAllowed, expectedDenied]) {
      Authenticator.validateScope(project, identity, authorized: authorized, permits: policy.permits);
    }
    final allowed = await probe.status(project, endpoint, expectedAllowed);
    if (allowed < 200 || allowed >= 300) {
      // A failing control makes the comparison meaningless. Do not send
      // the second request or treat the result as a vulnerability.
      return AccessAssessmentResult(allowed, 0, AccessOutcome.inconclusive);
    }
    await Future<void>.delayed(Duration(milliseconds: policy.delayMs));
    final denied = await probe.status(project, endpoint, expectedDenied);
    return AccessAssessmentResult(allowed, denied, AccessAssessmentResult.classify(allowed, denied));
  }
}
