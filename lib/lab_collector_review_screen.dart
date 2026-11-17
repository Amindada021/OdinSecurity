import 'package:flutter/material.dart';
import 'core/lab_collector_review.dart';
import 'core/test_fixtures.dart';
import 'core/project.dart';
import 'core/scan_policy.dart';
import 'core/manual_request.dart';
import 'core/auth.dart';
import 'localized.dart';

class LabCollectorReviewScreen extends StatefulWidget {
  final SecurityProject project;
  final ScanPolicy policy;
  const LabCollectorReviewScreen({super.key, required this.project, required this.policy});
  @override
  State<LabCollectorReviewScreen> createState() => _LabCollectorReviewScreenState();
}
class _LabCollectorReviewScreenState extends State<LabCollectorReviewScreen> {
  final bearer = TextEditingController();
  Uri? target;
  @override
  void dispose() { bearer.dispose(); super.dispose(); }
  String label = LabInteractionReview.newLabel();
  bool authorized = false, running = false, failed = false;
  List<LabInteraction>? matches;
  Future<void> review() async {
    if (!authorized || running || target == null) return;
    final endpoint = target!, selectedLabel = label, secret = bearer.text;
    bearer.clear();
    setState(() { authorized = false; running = true; failed = false; matches = null; });
    try {
      if (secret.isNotEmpty && !RegExp(r'^[A-Za-z0-9_-]{32,128}$').hasMatch(secret)) throw const FormatException('Invalid lab bearer.');
      final auth = secret.isEmpty ? null : AuthProfile(mode:AuthMode.bearer, target:endpoint, secret:secret);
      final client = ManualRequestClient();
      final result = await LabCollectorReview(read: (u) => client.send(widget.project, u, 'GET',
        authorized:true, policy:widget.policy, accept:ManualAccept.json, auth:auth)).fetch(
          widget.project, widget.policy, endpoint, selectedLabel, authorized:true);
      if (mounted) setState(() => matches = result);
    } catch (_) { if (mounted) setState(() => failed = true); }
    finally { if (mounted) setState(() => running = false); }
  }
  @override
  Widget build(BuildContext context) => Scaffold(
    appBar: AppBar(title: const LText('Remote lab metadata review')),
    body: ListView(padding: const EdgeInsets.all(16), children: [
      const LText('Select your own registered HTTPS collector’s sanitized JSON export endpoint. One GET retrieves metadata with optional private collector bearer authentication; label matching runs locally. No automated probes.'),
      DropdownButtonFormField<Uri>(initialValue: target, isExpanded:true,
        decoration: const InputDecoration(label:LText('Collector export endpoint')),
        items: [for(final u in widget.project.targets.where((u)=>u.scheme=='https' && widget.policy.permits(u)))
          DropdownMenuItem(value:u,child:Text(u.toString(),overflow:TextOverflow.ellipsis))],
        onChanged:running?null:(u)=>setState(() {target=u;bearer.clear();authorized=false;matches=null;})),
      TextField(controller:bearer, enabled:!running, obscureText:true, autocorrect:false, enableSuggestions:false,
        onChanged:(_)=>setState(() {authorized=false;matches=null;}),
        decoration:const InputDecoration(label:LText('Private collector bearer (optional)'))),
      const LText('Correlation label'),
      SelectableText(label,textDirection:TextDirection.ltr),
      OutlinedButton(onPressed:running?null:()=>setState(() {label=LabInteractionReview.newLabel();authorized=false;matches=null;}),
        child:const LText('New correlation label')),
      const SelectableText('[{"label":"<label>","protocol":"https","observedAt":"2026-01-01T00:00:00Z"}]',textDirection:TextDirection.ltr),
      CheckboxListTile(value:authorized,title:const LText('I authorize this exact request.'),
        onChanged:running||target==null?null:(v)=>setState(()=>authorized=v??false)),
      FilledButton(onPressed:running||!authorized?null:review,child:const LText('Fetch sanitized events once')),
      if(running) const LinearProgressIndicator(),
      if(failed) const LText('Collector response invalid or unavailable.'),
      if(matches!=null) ...[
        Text(uiNumber(context,matches!.length)),
        for(final event in matches!) ListTile(title:Text(event.protocol),subtitle:Text(event.observedAt.toLocal().toString())),
        const LText('Matches are correlation only, not proof of vulnerability or source attribution.'),
      ],
    ]),
  );
}
