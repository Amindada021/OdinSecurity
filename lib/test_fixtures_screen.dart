import 'package:flutter/material.dart';
import 'core/test_fixtures.dart';
import 'localized.dart';

class TestFixturesScreen extends StatefulWidget {
  const TestFixturesScreen({super.key});
  @override
  State<TestFixturesScreen> createState() => _TestFixturesScreenState();
}
class _TestFixturesScreenState extends State<TestFixturesScreen> {
  final template = TextEditingController(text: '{"sample":"[VALUE]"}');
  final values = TextEditingController(), events = TextEditingController();
  String label = LabInteractionReview.newLabel();
  List<String>? variants;
  List<LabInteraction>? matches;
  bool badVariants = false, badEvents = false;
  @override
  void dispose() { template.dispose(); values.dispose(); events.dispose(); super.dispose(); }
  void render() {
    try {
      final data = FixtureVariants.render(template.text, values.text.split('\n').map((v) => v.trim()).where((v) => v.isNotEmpty));
      setState(() { variants = data; badVariants = false; });
    } catch (_) { setState(() { variants = null; badVariants = true; }); }
  }
  void correlate() {
    try {
      final data = LabInteractionReview.match(label, events.text);
      setState(() { matches = data; badEvents = false; });
    } catch (_) { setState(() { matches = null; badEvents = true; }); }
  }
  @override
  Widget build(BuildContext context) => Scaffold(
    appBar: AppBar(title: const LText('Offline test fixtures')),
    body: ListView(padding: const EdgeInsets.all(16), children: [
      const LText('Generate synthetic text variants locally. No automatic requests are sent. Use non-secret sample values.'),
      TextField(controller: template, maxLines: 4, onChanged: (_) => setState(() { variants = null; badVariants = false; }),
        decoration: const InputDecoration(label: LText('Template with one [VALUE] marker'))),
      TextField(controller: values, maxLines: 5, onChanged: (_) => setState(() { variants = null; badVariants = false; }),
        decoration: const InputDecoration(label: LText('Sample values, one per line'))),
      FilledButton(onPressed: render, child: const LText('Preview variants')),
      if (badVariants) const LText('Invalid fixture input.'),
      if (variants != null) for (final value in variants!) ListTile(title: SelectableText(value, textDirection: TextDirection.ltr)),
      const Divider(),
      const LText('Offline lab interaction review'),
      const LText('Generate a local correlation label and paste sanitized event metadata from your own test collector. This is not a callback server or proof of origin.'),
      SelectableText(label, textDirection: TextDirection.ltr),
      OutlinedButton(onPressed: () => setState(() { label = LabInteractionReview.newLabel(); matches = null; events.clear(); badEvents = false; }),
        child: const LText('New correlation label')),
      TextField(controller: events, maxLines: 6, onChanged: (_) => setState(() { matches = null; badEvents = false; }),
        decoration: const InputDecoration(label: LText('Lab events JSON'), hintText: '[{"label":"<32 hex characters>","protocol":"https","observedAt":"2026-01-01T00:00:00Z"}]')),
      FilledButton(onPressed: correlate, child: const LText('Match event labels')),
      if (badEvents) const LText('Invalid event metadata.'),
      if (matches != null) ...[
        Text(uiNumber(context, matches!.length)),
        for (final event in matches!) ListTile(title: Text(event.protocol), subtitle: Text(event.observedAt.toIso8601String())),
      ],
    ]),
  );
}
