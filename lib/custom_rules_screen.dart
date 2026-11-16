import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
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

  Future<void> importPack() async {
    var pack = '';
    final mode = await showDialog<String>(context: context, builder: (ctx) => AlertDialog(
      title: const LText('Import rule pack'),
      content: SingleChildScrollView(child: TextField(maxLines: 6, autocorrect: false, enableSuggestions: false,
        onChanged: (value) => pack = value, decoration: const InputDecoration(label: LText('Rule pack JSON')))),
      actions: [
        TextButton(onPressed: () => Navigator.pop(ctx), child: const LText('Cancel')),
        TextButton(onPressed: () => Navigator.pop(ctx, 'replace'), child: const LText('Replace draft')),
        TextButton(onPressed: () => Navigator.pop(ctx, 'merge'), child: const LText('Merge into draft')),
      ],
    ));
    if (!mounted || mode == null || busy) return;
    try {
      final draft = mode == 'replace' ? HeaderRulePack.import(pack) : HeaderRulePack.merge(source.text, pack);
      setState(() { source.text = draft; failed = false; });
    } catch (_) { setState(() => failed = true); }
  }

  Future<void> exportPack() async {
    try {
      final data = HeaderRulePack.export(source.text);
      if (!mounted) return;
      await showDialog<void>(context: context, builder: (ctx) => AlertDialog(
        title: const LText('Export rule pack'),
        content: SingleChildScrollView(child: SelectableText(data, textDirection: TextDirection.ltr)),
        actions: [
          TextButton(onPressed: () async { await Clipboard.setData(ClipboardData(text: data)); if (ctx.mounted) Navigator.pop(ctx); },
            child: const LText('Copy')),
          TextButton(onPressed: () => Navigator.pop(ctx), child: const LText('Cancel')),
        ],
      ));
    } catch (_) { if (mounted) setState(() => failed = true); }
  }

  @override
  Widget build(BuildContext context) => Scaffold(
    appBar: AppBar(title: const LText('Custom scan rules')),
    body: ListView(padding: const EdgeInsets.all(16), children: [
      const LText('Define up to 20 literal header rules, one per line. Rules apply to successful responses in this project and never send additional requests. Do not include secrets.'),
      const SelectableText('x-content-type-options|contains|nosniff\nstrict-transport-security|present', textDirection: TextDirection.ltr),
      TextField(controller: source, enabled: !busy && repository != null, maxLines: 8, autocorrect: false, enableSuggestions: false,
        decoration: const InputDecoration(label: LText('Header rules'))),
      OutlinedButton(onPressed: busy || repository == null ? null : importPack, child: const LText('Import rule pack')),
      OutlinedButton(onPressed: busy || repository == null ? null : exportPack, child: const LText('Export rule pack')),
      const LText('Imported rules are drafts until saved. Duplicate rules are rejected.'),
      const LText('Supported headers'),
      SelectableText(CustomHeaderRules.allowedHeaders.join('\n'), textDirection: TextDirection.ltr),
      if (busy) const LinearProgressIndicator(),
      if (failed) const LText('Invalid rules or storage error.'),
      FilledButton(onPressed: busy || repository == null ? null : save, child: const LText('Save')),
    ]),
  );
}
