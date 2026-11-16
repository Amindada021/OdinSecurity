import 'package:flutter/material.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'core/metadata_program_settings.dart';
import 'core/project_storage.dart';
import 'core/security_checks.dart';
import 'localized.dart';

class MetadataProgramScreen extends StatefulWidget {
  final String projectId;
  const MetadataProgramScreen({super.key, required this.projectId});
  @override
  State<MetadataProgramScreen> createState() => _MetadataProgramScreenState();
}

class _MetadataProgramScreenState extends State<MetadataProgramScreen> {
  static const sample = '{"schema":"odin.security.metadata.v1","rules":[{"id":"missing-hsts","match":"all","conditions":[{"op":"statusRange","min":200,"max":299},{"op":"headerAbsent","header":"strict-transport-security"}]}]}';
  final source = TextEditingController();
  final fixture = TextEditingController(text:'{"status":200,"headers":{"content-type":["application/json"]}}');
  bool busy = true, enabled = false, failed = false, saved = false;
  MetadataProgramRepository? repository;
  List<SecurityFinding>? matches;
  int? ruleCount;

  @override
  void initState() { super.initState(); load(); }

  Future<void> load() async {
    try {
      final repo = MetadataProgramRepository(PreferencesStorage(await SharedPreferences.getInstance()));
      final settings = await repo.load(widget.projectId);
      if (mounted) setState(() {
        repository = repo; source.text = settings.source; enabled = settings.enabled;
      });
    } catch (_) { if (mounted) setState(() => failed = true); }
    finally { if (mounted) setState(() => busy = false); }
  }

  @override
  void dispose() { source.dispose(); fixture.dispose(); super.dispose(); }

  void resetPreview() { matches = null; ruleCount = null; failed = false; saved = false; }

  void preview() {
    try {
      final settings = MetadataProgramSettings(enabled:true,source:source.text);
      final program = settings.draftProgram!;
      final result = program.preview(fixture.text);
      setState(() { matches = result; ruleCount = program.ruleCount; failed = false; });
    } catch (_) { setState(() { matches = null; ruleCount = null; failed = true; }); }
  }

  Future<void> save() async {
    final repo = repository;
    if (repo == null || busy) return;
    setState(() { busy = true; failed = false; saved = false; });
    try {
      await repo.save(widget.projectId,MetadataProgramSettings(enabled:enabled,source:source.text));
      if (mounted) setState(() => saved = true);
    } catch (_) { if (mounted) setState(() => failed = true); }
    finally { if (mounted) setState(() => busy = false); }
  }

  @override
  Widget build(BuildContext context) => Scaffold(
    appBar: AppBar(title: const LText('Project metadata rules')),
    body: ListView(padding: const EdgeInsets.all(16), children: [
      const LText('Save a project-only declarative metadata program. It runs on existing scanner responses, not additional requests. No credentials or scripts.'),
      if (busy) const LinearProgressIndicator(),
      CheckboxListTile(value:enabled,title:const LText('Enable rules for project scans'),
        onChanged:busy || repository == null ? null : (v)=>setState(() { enabled=v??false; resetPreview(); })),
      TextField(controller:source,enabled:!busy && repository!=null,maxLength:16000,maxLines:8,
        autocorrect:false,enableSuggestions:false,textDirection:TextDirection.ltr,
        onChanged:(_)=>setState(resetPreview),decoration:const InputDecoration(label:LText('Metadata program JSON'))),
      OutlinedButton(onPressed:busy || repository==null || source.text.trim().isNotEmpty ? null :
        ()=>setState(() { source.text=sample; resetPreview(); }),child:const LText('Load example into empty draft')),
      const LText('Preview against a synthetic HTTP response; this does not test a live server.'),
      TextField(controller:fixture,enabled:!busy && repository!=null,maxLength:16000,maxLines:5,
        autocorrect:false,enableSuggestions:false,textDirection:TextDirection.ltr,
        onChanged:(_)=>setState(resetPreview),decoration:const InputDecoration(label:LText('Synthetic response metadata JSON'))),
      OutlinedButton(onPressed:busy || repository==null ? null : preview,child:const LText('Preview metadata rules')),
      if (matches!=null) ...[
        Text(uiNumber(context,matches!.where((f)=>f.id!='program.review.limit').length)+' / '+uiNumber(context,ruleCount!)),
        for(final row in matches!) ListTile(title:Text(row.title),subtitle:Text(row.evidence)),
      ],
      if (failed) const LText('Invalid rules, fixture or storage error.'),
      if (saved) const LText('Project rule settings saved.'),
      FilledButton(onPressed:busy || repository==null ? null : save,child:const LText('Save')),
    ]),
  );
}
