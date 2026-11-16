import 'package:flutter/material.dart';
import 'core/request_transport_trace.dart';
import 'core/tls_audit.dart';
import 'localized.dart';

class RequestTransportTraceView extends StatelessWidget {
  final RequestTransportTrace trace;
  const RequestTransportTraceView({super.key, required this.trace});
  @override
  Widget build(BuildContext context) {
    final cert = trace.certificate;
    return ExpansionTile(
      title: const LText('Request transport trace'),
      subtitle: Text(trace.https ? 'HTTPS' : 'HTTP'),
      children: [
        ListTile(title: const LText('Connection/open request'), trailing: Text(uiNumber(context, trace.openedMs) + ' ms')),
        ListTile(title: const LText('Request to response headers'), trailing: Text(uiNumber(context, trace.responseHeadersWaitMs) + ' ms')),
        ListTile(title: const LText('Response body read'), trailing: Text(uiNumber(context, trace.bodyReadMs) + ' ms')),
        ListTile(title: const LText('Total'), trailing: Text(uiNumber(context, trace.completedMs) + ' ms')),
        const LText('Timings describe request phases, not separate DNS or TLS handshake timings.'),
        if (cert != null) ...[
          const LText('TLS peer certificate from this response'),
          ListTile(title: const LText('Certificate subject'), subtitle: SelectableText(cert.subject)),
          ListTile(title: const LText('Certificate issuer'), subtitle: SelectableText(cert.issuer)),
          ListTile(title: const LText('Certificate validity'), subtitle: Text(cert.validFrom.toIso8601String() + '\n' + cert.validUntil.toIso8601String())),
          for (final finding in CertificateChecks.inspect(cert.validFrom, cert.validUntil, DateTime.now()))
            ListTile(title: Text(finding.title), subtitle: Text(finding.remediation)),
        ] else if (trace.https) const LText('Peer certificate details unavailable in this view.'),
      ],
    );
  }
}
