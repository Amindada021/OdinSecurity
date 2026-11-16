import 'dart:io';
import 'project.dart';
import 'scan_policy.dart';
import 'security_checks.dart';

enum TlsStatus { trusted, handshakeRejected, unavailable }

class TlsAuditResult {
  final TlsStatus status;
  final DateTime? validFrom, validUntil;
  const TlsAuditResult(this.status, {this.validFrom, this.validUntil});
}

class CertificateChecks {
  static List<SecurityFinding> inspect(DateTime start, DateTime end, DateTime now) {
    final evidence = 'Certificate validity ends ${end.toUtc().toIso8601String()}';
    if (now.isBefore(start) || !now.isBefore(end)) {
      return [SecurityFinding('tls.validity', 'Certificate outside validity period', Severity.high, evidence,
        'Check the server certificate and system time; renew or replace the certificate.')];
    }
    final remaining = end.difference(now);
    if (remaining <= const Duration(days: 7)) {
      return [SecurityFinding('tls.expiring', 'Certificate expires within 7 days', Severity.medium, evidence,
        'Renew promptly and verify automatic renewal.')];
    }
    if (remaining <= const Duration(days: 30)) {
      return [SecurityFinding('tls.expiring', 'Certificate expires within 30 days', Severity.low, evidence,
        'Verify certificate renewal before expiry.')];
    }
    return [];
  }
}

abstract interface class TlsProbe {
  Future<TlsAuditResult> connect(Uri target);
}

class TrustedTlsProbe implements TlsProbe {
  @override
  Future<TlsAuditResult> connect(Uri target) async {
    SecureSocket? socket;
    try {
      // Standard system trust and hostname validation. No bad-certificate
      // override, no HTTP request, no credentials and no protocol downgrade.
      socket = await SecureSocket.connect(target.host, target.port, timeout: const Duration(seconds: 10));
      final certificate = socket.peerCertificate;
      if (certificate == null) return const TlsAuditResult(TlsStatus.unavailable);
      return TlsAuditResult(TlsStatus.trusted, validFrom: certificate.startValidity, validUntil: certificate.endValidity);
    } on HandshakeException {
      return const TlsAuditResult(TlsStatus.handshakeRejected);
    } catch (_) {
      return const TlsAuditResult(TlsStatus.unavailable);
    } finally {
      socket?.destroy();
    }
  }
}

class TlsAudit {
  final TlsProbe probe;
  TlsAudit({TlsProbe? probe}) : probe = probe ?? TrustedTlsProbe();

  Future<TlsAuditResult> run(SecurityProject project, Uri target, ScanPolicy policy, {required bool authorized}) {
    if (!authorized || target.scheme != 'https' || !project.contains(target) ||
        !policy.permits(target) || target.hasQuery || target.hasFragment) {
      throw StateError('Authorized scoped HTTPS target required.');
    }
    return probe.connect(target);
  }
}
