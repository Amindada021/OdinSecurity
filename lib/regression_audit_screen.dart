import 'package:flutter/material.dart';
import 'core/project.dart';
import 'core/regression_audit.dart';
import 'core/scan_policy.dart';
import 'localized.dart';

class RegressionAuditScreen extends StatefulWidget {
  final SecurityProject project;
  final ScanPolicy policy;
  const RegressionAuditScreen({super.key, required this.project, required this.policy});
  @override
  State<RegressionAuditScreen> createState() => _RegressionAuditScreenState();
}

class _RegressionAuditScreenState extends State<RegressionAuditScreen> {
  final source = TextEditingController();
  List<RegressionCase>? cases;
  RegressionRun? result;
  bool authorized = false, busy = false, cancelled = false, invalid = false;

  @override
  void dispose() { cancelled = true; source.dispose(); super.dispose(); }

  void prepare() {
    try {
      final parsed = RegressionAudit.parse(widget.project, widget.policy, source.text);
      setState(() { cases = parsed; invalid = false; result = null; authorized = false; });
    } catch (_) {
      setState(() { cases = null; invalid = true; result = null; authorized = false; });
    }
  }

  Future<void> run() async {
    final selected = cases;
    if (!authorized || busy || selected == null) return;
    setState(() { busy = true; cancelled = false; authorized = false; result = null; invalid = false; });
    try {
      final report = await RegressionAudit().run(widget.project, widget.policy, selected,
        authorized: true, cancelled: () => cancelled || !mounted);
      if (mounted) setState(() => result = report);
    } catch (_) {
      if (mounted) setState(() => invalid = true);
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  @override
  Widget build(BuildContext context) => Scaffold(
    appBar: AppBar(title: const LText('Security regression audit')),
    body: ListView(padding: const EdgeInsets.all(16), children: [
      const LText('Enter expected HTTP status and a known HTTPS read-only URL on each line. Up to 10 unauthenticated HEAD checks. No request is sent during preparation.'),
      TextField(controller: source, enabled: !busy, maxLines: 6, autocorrect: false, enableSuggestions: false,
        decoration: const InputDecoration(hintText: '401 https://example.test/api/profile'),
        onChanged: (_) => setState(() { cases = null; result = null; authorized = false; invalid = false; })),
      OutlinedButton(onPressed: busy ? null : prepare, child: const LText('Review audit cases')),
      if (invalid) const LText('Invalid cases or excluded routes. Check scope and limits.'),
      if (cases != null) ...[
        for (final item in cases!) ListTile(title: SelectableText(item.endpoint.toString(), textDirection: TextDirection.ltr), trailing: Text('HEAD ${item.expectedStatus}')),
        CheckboxListTile(value: authorized, title: const LText('I authorize these exact read-only checks.'), onChanged: busy ? null : (v) => setState(() => authorized = v ?? false)),
        FilledButton(onPressed: authorized && !busy ? run : null, child: const LText('Run regression audit')),
      ],
      if (busy) ...[
        const LinearProgressIndicator(),
        OutlinedButton(onPressed: cancelled ? null : () => setState(() => cancelled = true), child: const LText('Stop')),
      ],
      if (result != null) ...[
        if (result!.stopped) const LText('Audit stopped before all checks completed. No retries were sent.'),
        for (final row in result!.results) ListTile(
          leading: Icon(row.passed ? Icons.check_circle_outline : Icons.warning_amber),
          title: Text(row.check.endpoint.toString()),
          subtitle: Text('${row.check.expectedStatus} → ${row.actualStatus}'),
          trailing: LText(row.passed ? 'Expected status' : 'Review status difference')),
        const LText('HEAD responses can differ from GET responses. A status difference is not proof of a vulnerability.'),
      ],
    ]),
  );
}
