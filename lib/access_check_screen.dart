import 'package:flutter/material.dart';
import 'localized.dart';
import 'core/access_assessment.dart';
import 'core/auth.dart';
import 'core/project.dart';
import 'core/scan_policy.dart';

class AccessCheckScreen extends StatefulWidget {
  final SecurityProject project;
  final Uri target;
  final List<AuthProfile> profiles;
  final ScanPolicy policy;
  const AccessCheckScreen({super.key, required this.project, required this.target, required this.profiles, required this.policy});
  @override
  State<AccessCheckScreen> createState() => _AccessCheckScreenState();
}
class _AccessCheckScreenState extends State<AccessCheckScreen> {
  late final TextEditingController url;
  String allowed = '', denied = '';
  bool authorized = false, busy = false;
  AccessAssessmentResult? result;
  String? error;
  List<AuthProfile> get identities => widget.profiles.where((p) =>
    SecurityProject.sameOrigin(p.target, widget.target) && p.validationUrl.isNotEmpty).toList();

  @override
  void initState() { super.initState(); url = TextEditingController(text: widget.target.toString()); }
  @override
  void dispose() { url.dispose(); super.dispose(); }

  Future<void> run() async {
    if (!authorized || busy || allowed.isEmpty || denied.isEmpty || allowed == denied) return;
    setState(() { busy = true; result = null; error = null; });
    try {
      final endpoint = SecurityProject.parseTarget(url.text.trim());
      final data = await AccessAssessment().run(project: widget.project, endpoint: endpoint,
        expectedAllowed: identities.firstWhere((p) => p.name == allowed),
        expectedDenied: identities.firstWhere((p) => p.name == denied),
        policy: widget.policy, authorized: authorized);
      if (mounted) setState(() => result = data);
    } catch (_) {
      if (mounted) setState(() => error = 'Could not compare access. Check the allowed URL, validation endpoints and identity configuration.');
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  Widget identityDropdown(String label, String value, ValueChanged<String> update) => DropdownButtonFormField<String>(
    initialValue: value, decoration: InputDecoration(label: LText(label)),
    items: [const DropdownMenuItem(value: '', child: LText('Select test identity')), ...identities.map((p) => DropdownMenuItem(value: p.name, child: Text(p.name)))],
    onChanged: busy ? null : (v) => setState(() { update(v ?? ''); authorized = false; result = null; }),
  );

  @override
  Widget build(BuildContext context) {
    final data = result;
    return Scaffold(appBar: AppBar(title: const LText('Access control comparison')),
      body: ListView(padding: const EdgeInsets.all(16), children: [
        const LText('Choose an explicitly allowed, read-only endpoint and two test accounts. Configure a protected verification endpoint and response marker for both accounts first.'),
        if (identities.length < 2) const LText('At least two validated test identities are required.'),
        TextField(controller: url, enabled: !busy, decoration: const InputDecoration(label: LText('Exact HTTPS endpoint')), onChanged: (_) => setState(() { authorized = false; result = null; })),
        identityDropdown('Expected allowed identity', allowed, (v) => allowed = v),
        identityDropdown('Expected denied identity', denied, (v) => denied = v),
        CheckboxListTile(value: authorized, title: const LText('I authorize this read-only comparison using my test accounts.'),
          onChanged: busy ? null : (v) => setState(() => authorized = v ?? false)),
        FilledButton(onPressed: !busy && authorized && allowed.isNotEmpty && denied.isNotEmpty && allowed != denied ? run : null, child: const LText('Compare access')),
        if (busy) const LinearProgressIndicator(),
        if (error != null) LText(error!),
        if (data != null) ...[
          Text('Expected allowed: HTTP ${data.expectedAllowedStatus}'),
          Text(data.expectedDeniedStatus == 0 ? 'Expected denied: not tested' : 'Expected denied: HTTP ${data.expectedDeniedStatus}'),
          const Divider(),
          LText(switch (data.outcome) {
            AccessOutcome.expected => 'Observed expected response statuses.',
            AccessOutcome.unexpectedSuccess => 'Review: denied identity also returned a successful status. This alone does not prove unauthorized data access.',
            AccessOutcome.inconclusive => 'Inconclusive. Verify the expected allowed endpoint and identities.',
          }),
          const LText('Only response status codes are shown; no response body or credentials are saved.'),
        ],
      ]),
    );
  }
}
