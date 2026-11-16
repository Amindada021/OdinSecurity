import 'package:flutter/material.dart';
import 'core/project.dart';
import 'core/scan_policy.dart';
import 'core/external_findings.dart';
import 'core/security_checks.dart';
import 'localized.dart';

class ExternalFindingsScreen extends StatefulWidget {
  final SecurityProject project;
  final ScanPolicy policy;
  const ExternalFindingsScreen({super.key, required this.project, required this.policy});
  @override
  State<ExternalFindingsScreen> createState() => _ExternalFindingsScreenState();
}
class _ExternalFindingsScreenState extends State<ExternalFindingsScreen> {
  final source = TextEditingController();
  bool approved = false, failed = false;
  Severity? severity;
  List<ExternalFinding>? results;
  @override
  void dispose() { source.dispose(); super.dispose(); }
  void review() {
    try {
      final found = ExternalFindings.parse(widget.project, widget.policy, source.text, authorized:approved);
      source.clear();
      setState(() {results=found; approved=false; failed=false; severity=null;});
    } catch (_) { setState(() {results=null;failed=true;approved=false;}); }
  }
  @override
  Widget build(BuildContext context) => Scaffold(
    appBar: AppBar(title:const LText('External assessment findings')),
    body: ListView(padding:const EdgeInsets.all(16),children:[
      const LText('Import normalized sanitized findings from an authorized external assessment. Only scoped routes, tool/rule identifiers and reported severity are retained. These findings are not independently confirmed.'),
      const SelectableText('[{"url":"https://example.test/test","source":"fixture","code":"CHECK-1","severity":"info"}]',textDirection:TextDirection.ltr),
      TextField(controller: source,maxLines:7,autocorrect:false,enableSuggestions:false,
        onChanged:(_)=>setState(() {approved=false;results=null;failed=false;}),
        decoration:const InputDecoration(label:LText('Normalized findings JSON'))),
      CheckboxListTile(value:approved,title:const LText('I confirm this is an authorized sanitized capture.'),
        onChanged:(v)=>setState(()=>approved=v??false)),
      FilledButton(onPressed:approved?review:null,child:const LText('Import findings')),
      if(failed) const LText('Invalid finding import.'),
      if(results!=null) ...[
        Text(uiNumber(context,results!.length)),
        DropdownButtonFormField<Severity>(key:ValueKey(severity),initialValue:severity, hint:const LText('All'),
          decoration:const InputDecoration(label:LText('Reported severity')),
          items:[const DropdownMenuItem<Severity>(value:null,child:LText('All')),
            for(final s in Severity.values) DropdownMenuItem(value:s,child:LText(s.name))],
          onChanged:(v)=>setState(()=>severity=v)),
        for(final row in results!.where((r)=>severity==null||r.reportedSeverity==severity))
          ListTile(title:Text(row.source+' / '+row.code),subtitle:Text(row.route.toString()),trailing:LText(row.reportedSeverity.name)),
      ],
    ]),
  );
}
