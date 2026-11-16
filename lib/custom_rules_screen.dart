import 'package:flutter/material.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'core/custom_rules.dart';
import 'core/project_storage.dart';
import 'localized.dart';

class CustomRulesScreen extends StatefulWidget {
  final String projectId;
  const CustomRulesScreen({super.key, required this.projectId});
  @override
  State<CustomRulesScreen> createState() => _CustomRulesScreenState();
}

class _CustomRulesScreenState extends State<CustomRulesScreen> {
  final source = TextEditingController();
  bool busy = true, failed = false;
  CustomRuleRepository? repository;
  @override
  void initState() { super.initState(); load(); }
  @override
  void dispose() { source.dispose(); super.dispose(); }

  Future<void> load() async {
    try {
      final repo = CustomRuleRepository(PreferencesStorage(await SharedPreferences.getInstance()));
      final rules = await repo.load(widget.projectId);
      if (mounted) setState(() { repository = repo; source.text = rules.map((r) => r.line).join('\n'); });
    } catch (_) {
      if (mounted) setState(() => failed = true);
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  Future<void> save() async {
    final repo = repository;
    if (repo == null || busy) return;
    setState(() { busy = true; failed = false; });
    try {
      await repo.save(widget.projectId, source.text);
      if (mounted) Navigator.of(context).pop();
    } catch (_) {
      if (mounted) setState(() => failed = true);
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  @override
  Widget build(BuildContext context) => Scaffold(
    appBar: AppBar(title: const LText('Custom scan rules')),
    body: ListView(padding: const EdgeInsets.all(16), children: [
      const LText('Define up to 20 literal header rules, one per line. Rules apply to successful responses in this project and never send additional requests. Do not include secrets.'),
      const SelectableText('x-content-type-options|contains|nosniff\nstrict-transport-security|present', textDirection: TextDirection.ltr),
      TextField(controller: source, enabled: !busy && repository != null, maxLines: 8, autocorrect: false, enableSuggestions: false,
        decoration: const InputDecoration(label: LText('Header rules'))),
      const LText('Supported headers'),
      SelectableText(CustomHeaderRules.allowedHeaders.join('\n'), textDirection: TextDirection.ltr),
      if (busy) const LinearProgressIndicator(),
      if (failed) const LText('Invalid rules or storage error.'),
      FilledButton(onPressed: busy || repository == null ? null : save, child: const LText('Save')),
    ]),
  );
}
