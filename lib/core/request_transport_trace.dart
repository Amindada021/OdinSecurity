import 'dart:io';

/// An observation of the actual peer on a normally validated HTTPS response.
/// Does not contain private keys, raw certificate bytes, or TLS session secrets.
class PeerCertificateSummary {
  final DateTime validFrom, validUntil;
  final String subject, issuer;
  const PeerCertificateSummary({
    required this.validFrom, required this.validUntil,
    required this.subject, required this.issuer,
  });

  factory PeerCertificateSummary.fromCertificate(X509Certificate certificate) =>
    PeerCertificateSummary(validFrom: certificate.startValidity.toUtc(),
      validUntil: certificate.endValidity.toUtc(),
      subject: displayName(certificate.subject), issuer: displayName(certificate.issuer));

  static String displayName(String value) {
    final cleaned = value.replaceAll(RegExp(r'[\x00-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]'), ' ').trim();
    return cleaned.length <= 512 ? cleaned : cleaned.substring(0, 512);
  }
}

/// Cumulative timestamps on one actual request (not separate DNS/TLS timings).
/// No additional network connection and no TLS trust override.
class RequestTransportTrace {
  final int openedMs, headersMs, completedMs;
  final bool https;
  final PeerCertificateSummary? certificate;
  RequestTransportTrace({required this.openedMs, required this.headersMs,
      required this.completedMs, required this.https, this.certificate}) {
    if (openedMs < 0 || headersMs < openedMs || completedMs < headersMs ||
        (!https && certificate != null)) {
      throw const FormatException('Invalid transport trace.');
    }
  }

  int get responseHeadersWaitMs => headersMs - openedMs;
  int get bodyReadMs => completedMs - headersMs;

  /// Journal keeps timings and requested scheme only; no certificate names or dates.
  RequestTransportTrace get metadataOnly => RequestTransportTrace(openedMs: openedMs,
    headersMs: headersMs, completedMs: completedMs, https: https);
}
