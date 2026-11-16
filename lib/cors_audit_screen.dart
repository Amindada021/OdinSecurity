import 'package:flutter/material.dart';
import 'localized.dart';
import 'core/cors_audit.dart';
import 'core/project.dart';
import 'core/scan_policy.dart';

class CorsAuditScreen extends StatefulWidget {
  final SecurityProject project;
  final Uri target;
  final ScanPolicy policy;
  const CorsAuditScreen({super.key, required this.project, required this.target, required this.policy});
  @override
  State<CorsAuditScreen> createState() => _CorsAuditScreenState();
}

class _CorsAuditScreenState extends State<CorsAuditScreen> {
  late final TextEditingController endpoint;
  bool authorized = false, busy = false;
  CorsAuditResult? result;
  String? error;

  @override
  void initState() {
    super.initState();
    endpoint = TextEditingController(text: widget.target.toString());
  }

  @override
  void dispose() {
    endpoint.dispose();
    super.dispose();
  }

  Future<void> run() async {
    if (!authorized || busy) return;
    setState(() { busy = true; authorized = false; result = null; error = null; });
    try {
      final next = await CorsAudit().run(widget.project, Uri.parse(endpoint.text.trim()), widget.policy, authorized: true);
      if (mounted) setState(() => result = next);
    } catch (_) {
      if (mounted) setState(() => error = 'Could not inspect the endpoint. Check HTTPS, scope, exclusions and connectivity.');
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final data = result;
    final message = switch (data?.outcome) {
      CorsOutcome.testOriginWithCredentials => 'Review required: the test origin and credentialed CORS were advertised.',
      CorsOutcome.testOriginAllowed => 'The test origin was advertised; review the intended origin allowlist.',
      CorsOutcome.wildcard => 'Wildcard origin advertised. Public APIs may legitimately use this policy.',
      CorsOutcome.notAdvertised => 'The test origin was not advertised in this response.',
      CorsOutcome.inconclusive => 'Inconclusive response. Check server behavior and configuration.',
      null => '',
    };
    return Scaffold(appBar: AppBar(title: const LText('CORS configuration audit')),
      body: ListView(padding: const EdgeInsets.all(16), children: [
        const LText('One unauthenticated OPTIONS preflight to the selected read-only HTTPS endpoint. No credentials, redirect, or actual cross-origin GET.'),
        const Text('Test origin: https://odin-security.invalid'),
        TextField(controller: endpoint, enabled: !busy, keyboardType: TextInputType.url,
          decoration: const InputDecoration(label: LText('Endpoint URL (no query)')),
          onChanged: (_) => setState(() { authorized = false; result = null; })),
        CheckboxListTile(value: authorized, title: const LText('I authorize this exact preflight.'), onChanged: busy ? null : (v) => setState(() => authorized = v ?? false)),
        FilledButton(onPressed: busy || !authorized ? null : run, child: const LText('Check CORS')),
        if (busy) const LinearProgressIndicator(),
        if (error != null) LText(error!),
        if (data != null) ...[
          Text('HTTP ${data.status}', style: Theme.of(context).textTheme.titleLarge),
          LText(message),
          Text('GET explicitly advertised: ${data.getAdvertised ? "yes" : "no"}'),
          const LText('A preflight is a configuration observation, not proof that a browser can read private data. Confirm the expected policy on the server.'),
        ],
      ]));
  }
}
