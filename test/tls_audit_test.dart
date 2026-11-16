import 'package:flutter_test/flutter_test.dart';
import 'package:odin_security/core/project.dart';
import 'package:odin_security/core/scan_policy.dart';
import 'package:odin_security/core/security_checks.dart';
import 'package:odin_security/core/tls_audit.dart';

class FakeTlsProbe implements TlsProbe {
  int calls = 0;
  @override
  Future<TlsAuditResult> connect(Uri target) async {
    calls++;
    return const TlsAuditResult(TlsStatus.handshakeRejected);
  }
}

void main() {
  final now = DateTime.utc(2026, 1, 1);
  final start = now.subtract(const Duration(days: 10));
  test('certificate expiry thresholds', () {
    expect(CertificateChecks.inspect(start, now.add(const Duration(days: 31)), now), isEmpty);
    expect(CertificateChecks.inspect(start, now.add(const Duration(days: 30)), now).single.severity, Severity.low);
    expect(CertificateChecks.inspect(start, now.add(const Duration(days: 7)), now).single.severity, Severity.medium);
    expect(CertificateChecks.inspect(start, now, now).single.severity, Severity.high);
    expect(CertificateChecks.inspect(now.add(const Duration(days: 1)), now.add(const Duration(days: 30)), now).single.id, 'tls.validity');
  });
  test('requires authorization, exact origin and exclusions before probe', () async {
    final project = SecurityProject(name: 'Fixture', url: 'https://example.test');
    final probe = FakeTlsProbe();
    final audit = TlsAudit(probe: probe);
    final policy = ScanPolicy(excludedPaths: ['/private']);
    expect(() => audit.run(project, project.startUrl, policy, authorized: false), throwsStateError);
    for (final raw in ['http://example.test', 'https://other.test', 'https://example.test:8443', 'https://example.test/private', 'https://example.test/?token=x']) {
      expect(() => audit.run(project, Uri.parse(raw), policy, authorized: true), throwsStateError);
    }
    expect(probe.calls, 0);
    expect((await audit.run(project, project.startUrl, policy, authorized: true)).status, TlsStatus.handshakeRejected);
    expect(probe.calls, 1);
  });
}
