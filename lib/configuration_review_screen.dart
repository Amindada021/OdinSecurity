import 'package:flutter/material.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'core/configuration_review.dart';
import 'core/project.dart';
import 'core/scan_policy.dart';
import 'core/tls_audit.dart';
import 'core/passive_scan.dart';
import 'core/cors_audit.dart';
import 'core/custom_rules.dart';
import 'core/metadata_program_settings.dart';
import 'core/project_storage.dart';
import 'localized.dart';

class ConfigurationReviewScreen extends StatefulWidget {
  final SecurityProject project;
  final ScanPolicy policy;
  const ConfigurationReviewScreen({super.key, required this.project, required this.policy});
  @override
  State<ConfigurationReviewScreen> createState() => _ConfigurationReviewScreenState();
}
class _ConfigurationReviewScreenState extends State<ConfigurationReviewScreen> {
  Uri? target;
  bool authorized = false, includeCors = false, running = false, stopped = false, failed = false;
  ConfigurationReviewResult? result;

  Future<void> run() async {
    if (!authorized || target == null || running) return;
    final endpoint = target!, cors = includeCors;
    setState(() { running = true; stopped = false; failed = false; result = null; authorized = false; });
    try {
      final storage = PreferencesStorage(await SharedPreferences.getInstance());
      final rules = await CustomRuleRepository(storage).load(widget.project.id);
      final program = (await MetadataProgramRepository(storage).load(widget.project.id)).activeProgram;
      final review = ConfigurationReview(
        tls: (u) => TlsAudit().run(widget.project, u, widget.policy, authorized: true),
        read: (u) => PassiveScanner(customRules: rules, metadataProgram: program).scan(widget.project, target: u, authorized: true, permits: widget.policy.permits),
        preflight: (u) => CorsAudit().run(widget.project, u, widget.policy, authorized: true));
      final data = await review.run(widget.project, widget.policy, endpoint, authorized: true,
        includeCors: cors, cancelled: () => stopped || !mounted);
      if (mounted) setState(() => result = data);
    } catch (_) { if (mounted) setState(() => failed = true); }
    finally { if (mounted) setState(() => running = false); }
  }
  @override
  void dispose() { stopped = true; super.dispose(); }
  @override
  Widget build(BuildContext context) => Scaffold(
    appBar: AppBar(title: const LText('Configuration review suite')),
    body: ListView(padding: const EdgeInsets.all(16), children: [
      const LText('One registered HTTPS route: trusted TLS handshake, one anonymous GET and optional fixed CORS preflight. No exploit payloads or redirects.'),
      DropdownButtonFormField<Uri>(initialValue: target, isExpanded: true,
        decoration: const InputDecoration(label: LText('Target')),
        items: [for(final u in widget.project.targets.where((u) => u.scheme == 'https' && widget.policy.permits(u)))
          DropdownMenuItem(value: u, child: Text(u.toString(), overflow: TextOverflow.ellipsis))],
        onChanged: running ? null : (u) => setState(() { target = u; authorized = false; result = null; })),
      CheckboxListTile(value: includeCors, title: const LText('Include one CORS preflight'),
        onChanged: running || widget.policy.maxPages < 2 ? null : (v) => setState(() { includeCors = v ?? false; authorized = false; result = null; })),
      CheckboxListTile(value: authorized, title: const LText('I authorize these exact assessments.'),
        onChanged: running || target == null ? null : (v) => setState(() => authorized = v ?? false)),
      FilledButton(onPressed: running || !authorized ? null : run, child: const LText('Start configuration review')),
      if (running) ...[
        const LinearProgressIndicator(),
        OutlinedButton(onPressed: stopped ? null : () => setState(() => stopped = true), child: const LText('Stop')),
      ],
      if (failed) const LText('Could not complete the review.'),
      if (result != null) ...[
        Text('TLS: ' + result!.tls.status.name),
        if (result!.page != null) Text('GET: HTTP ' + result!.page!.statusCode.toString()),
        if (result!.cors != null) Text('CORS: ' + result!.cors!.outcome.name),
        Text(result!.stop),
        const LText('Configuration observations are review signals, not proof of exploitation.'),
        for (final finding in result!.findings) ListTile(title: Text(finding.title), subtitle: Text(finding.remediation), trailing: LText(finding.severity.name)),
      ],
    ]),
  );
}
