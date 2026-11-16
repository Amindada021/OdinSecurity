import 'package:flutter/material.dart';
import 'core/har_response_review.dart';
import 'core/custom_rules.dart';
import 'core/project.dart';
import 'core/scan_policy.dart';
import 'localized.dart';

class HarResponseReviewScreen extends StatefulWidget {
  final SecurityProject project;
  final ScanPolicy policy;
  const HarResponseReviewScreen({super.key, required this.project, required this.policy});
  @override
  State<HarResponseReviewScreen> createState() => _HarResponseReviewScreenState();
}
class _HarResponseReviewScreenState extends State<HarResponseReviewScreen> {
  final source = TextEditingController(), pack = TextEditingController();
  bool approved = false, includeBody = false, failed = false;
  List<ImportedResponseReview>? results;
  @override
  void dispose() { source.dispose(); pack.dispose(); super.dispose(); }
  void review() {
    try {
      final rules = pack.text.trim().isEmpty ? <HeaderRule>[] : CustomHeaderRules.parse(HeaderRulePack.decode(pack.text));
      if (rules.any((r) => !HarResponseReview.allowedHeaders.contains(r.header))) throw const FormatException('Unsupported capture rule.');
      final result = HarResponseReview.parse(widget.project, widget.policy, source.text,
        authorized: approved, includeBody: includeBody, rules: rules);
      source.clear(); pack.clear();
      setState(() { results = result; approved = false; failed = false; });
    } catch (_) { setState(() { results = null; failed = true; approved = false; }); }
  }
  @override
  Widget build(BuildContext context) => Scaffold(
    appBar: AppBar(title: const LText('Offline HTTPS response review')),
    body: ListView(padding: const EdgeInsets.all(16), children: [
      const LText('Paste an authorized sanitized HAR containing response headers. Remove tokens, cookies, personal data and unnecessary contents before import. Missing headers in the export can cause false observations.'),
      TextField(controller: source, maxLines: 7, autocorrect: false, enableSuggestions: false,
        onChanged: (_) => setState(() { approved = false; results = null; failed = false; }),
        decoration: const InputDecoration(label: LText('Sanitized HAR JSON'))),
      TextField(controller: pack, maxLines: 4, autocorrect: false, enableSuggestions: false,
        onChanged: (_) => setState(() { approved = false; results = null; failed = false; }),
        decoration: const InputDecoration(label: LText('Optional compatible rule pack JSON'))),
      CheckboxListTile(value: includeBody, title: const LText('Also analyze sanitized text response bodies offline'),
        onChanged: (v) => setState(() { includeBody = v ?? false; approved = false; results = null; })),
      CheckboxListTile(value: approved, title: const LText('I confirm this is an authorized sanitized capture.'),
        onChanged: (v) => setState(() => approved = v ?? false)),
      FilledButton(onPressed: approved ? review : null, child: const LText('Analyze imported responses')),
      if (failed) const LText('Invalid or oversized capture.'),
      if (results != null) ...[
        Text(uiNumber(context, results!.length)),
        const LText('Results are offline observations, not evidence of a live TLS interception.'),
        for (final row in results!) ExpansionTile(title: Text(row.route.toString()), subtitle: Text('HTTP ' + row.status.toString()),
          children: [
            if (!row.bodyReviewed) const LText('Headers only; body not reviewed.'),
            for (final tech in row.technologies) ListTile(title: Text(tech.name), subtitle: Text(tech.observedVersion ?? tech.evidence)),
            for (final finding in row.findings) ListTile(title: Text(finding.title), subtitle: Text(finding.remediation), trailing: LText(finding.severity.name)),
          ]),
      ],
    ]),
  );
}
