import 'package:flutter/material.dart';
import 'localized.dart';
import 'core/project.dart';
import 'core/scan_policy.dart';
import 'core/tls_audit.dart';

class TlsAuditScreen extends StatefulWidget {
  final SecurityProject project;
  final Uri target;
  final ScanPolicy policy;
  const TlsAuditScreen({super.key, required this.project, required this.target, required this.policy});
  @override
  State<TlsAuditScreen> createState() => _TlsAuditScreenState();
}

class _TlsAuditScreenState extends State<TlsAuditScreen> {
  bool authorized = false, busy = false;
  TlsAuditResult? result;
  String? error;
  Future<void> run() async {
    if (!authorized || busy) return;
    setState(() { busy = true; result = null; error = null; });
    try {
      final value = await TlsAudit().run(widget.project, widget.target, widget.policy, authorized: authorized);
      if (mounted) setState(() => result = value);
    } catch (_) {
      if (mounted) setState(() => error = 'Cannot audit this target.');
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final value = result;
    final status = switch (value?.status) {
      TlsStatus.trusted => 'TLS connection accepted by system trust.',
      TlsStatus.handshakeRejected => 'TLS handshake rejected. Possible certificate or protocol incompatibility; inspect server configuration.',
      TlsStatus.unavailable => 'TLS connection unavailable; no conclusion about certificate validity.',
      null => '',
    };
    return Scaffold(appBar: AppBar(title: const LText('TLS certificate audit')),
      body: ListView(padding: const EdgeInsets.all(16), children: [
        Text(widget.target.origin),
        const LText('One trusted TLS handshake to this exact host and port. No HTTP request or credentials. This does not enumerate TLS versions or cipher suites.'),
        CheckboxListTile(value: authorized, title: const LText('I authorize this TLS connection.'), onChanged: busy ? null : (v) => setState(() => authorized = v ?? false)),
        FilledButton(onPressed: busy || !authorized ? null : run, child: const LText('Check TLS')),
        if (busy) const LinearProgressIndicator(),
        if (error != null) LText(error!),
        if (value != null) ...[
          LText(status, style: Theme.of(context).textTheme.titleMedium),
          if (value.validFrom != null) Text('Valid from: ${value.validFrom!.toUtc().toIso8601String()}'),
          if (value.validUntil != null) Text('Valid until: ${value.validUntil!.toUtc().toIso8601String()}'),
          if (value.validFrom != null && value.validUntil != null)
            for (final finding in CertificateChecks.inspect(value.validFrom!, value.validUntil!, DateTime.now()))
              ListTile(title: Text(finding.title), subtitle: Text(finding.remediation), trailing: LText(finding.severity.name)),
        ],
      ]));
  }
}
