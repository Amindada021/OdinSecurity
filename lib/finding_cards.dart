import 'package:flutter/material.dart';
import 'core/finding_explanations.dart';
import 'core/technology_explanations.dart';
import 'localized.dart';

Color severityColor(BuildContext context, String severity) => switch (severity) {
  'critical' || 'high' => Theme.of(context).colorScheme.error,
  'medium' => Colors.orange.shade800,
  'low' => Theme.of(context).colorScheme.tertiary,
  _ => Theme.of(context).colorScheme.primary,
};

class SeverityBadge extends StatelessWidget {
  final String severity;
  const SeverityBadge(this.severity, {super.key});
  @override
  Widget build(BuildContext context) {
    final color = severityColor(context, severity);
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 9, vertical: 5),
      decoration: BoxDecoration(color: color.withValues(alpha: .14), borderRadius: BorderRadius.circular(9)),
      child: LText(severity, style: TextStyle(color: color, fontWeight: FontWeight.w600, fontSize: 12)),
    );
  }
}

class FindingTile extends StatelessWidget {
  final String id, title, severity, evidence, remediation;
  final String? url;
  const FindingTile({super.key, required this.id, required this.title, required this.severity,
    required this.evidence, required this.remediation, this.url});
  @override
  Widget build(BuildContext context) {
    final fa = Localizations.localeOf(context).languageCode == 'fa';
    final copy = explainFinding(id, title, remediation, persian: fa);
    return Card(
      clipBehavior: Clip.antiAlias,
      child: ExpansionTile(
        leading: Icon(Icons.shield_outlined, color: severityColor(context, severity)),
        title: Text(copy.title, style: const TextStyle(fontWeight: FontWeight.w600)),
        subtitle: Padding(padding: const EdgeInsets.only(top: 6), child: Text(copy.meaning)),
        trailing: Row(mainAxisSize: MainAxisSize.min, children: [SeverityBadge(severity), const Icon(Icons.expand_more)]),
        expandedCrossAxisAlignment: CrossAxisAlignment.start,
        childrenPadding: const EdgeInsets.fromLTRB(16, 0, 16, 16),
        children: [
          if (url != null) SelectableText(url!, textDirection: TextDirection.ltr),
          const SizedBox(height: 8),
          LText('Remediation', style: Theme.of(context).textTheme.titleSmall),
          SelectableText(copy.advice),
          const SizedBox(height: 8),
          LText('Evidence', style: Theme.of(context).textTheme.titleSmall),
          SelectableText(evidence, textDirection: TextDirection.ltr),
        ],
      ),
    );
  }
}

class TechnologyTile extends StatelessWidget {
  final String name, layer, confidence, evidence;
  final String? version;
  const TechnologyTile({super.key, required this.name, required this.layer, required this.confidence, required this.evidence, this.version});
  @override
  Widget build(BuildContext context) {
    final fa = Localizations.localeOf(context).languageCode == 'fa';
    return ListTile(
      leading: const Icon(Icons.layers_outlined),
      title: Text(name, style: const TextStyle(fontWeight: FontWeight.w600)),
      subtitle: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Text(explainTechnology(name, persian: fa)),
        Text('${tr(context, layer)} · ${tr(context, 'Confidence')}: ${tr(context, confidence)}'),
        if (version != null) Text('${tr(context, 'Declared version')}: $version'),
        Text(evidence, textDirection: TextDirection.ltr),
      ]),
    );
  }
}
