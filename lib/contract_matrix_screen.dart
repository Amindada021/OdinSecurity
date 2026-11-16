import 'package:flutter/material.dart';
import 'core/contract_matrix.dart';
import 'localized.dart';

class ContractMatrixScreen extends StatefulWidget {
  const ContractMatrixScreen({super.key});
  @override
  State<ContractMatrixScreen> createState() => _ContractMatrixScreenState();
}

class _ContractMatrixScreenState extends State<ContractMatrixScreen> {
  final source = TextEditingController(text:
    '{"schema":"odin.security.contract.v1","contract":{"kind":"integer","min":1,"max":10},"cases":[{"value":0,"expected":false},{"value":1,"expected":true},{"value":10,"expected":true},{"value":11,"expected":false},{"value":"1","expected":false}]}');
  List<ContractCaseResult>? results;
  bool failed = false;
  @override
  void dispose() { source.dispose(); super.dispose(); }
  void run() {
    try {
      final rows = ContractMatrix.run(source.text);
      setState(() { results = rows; failed = false; });
    } catch (_) { setState(() { results = null; failed = true; }); }
  }
  @override
  Widget build(BuildContext context) => Scaffold(
    appBar: AppBar(title: const LText('Local contract test matrix')),
    body: ListView(padding: const EdgeInsets.all(16), children: [
      const LText('Run up to 100 synthetic scalar cases against a local length or integer range contract. No requests are sent.'),
      TextField(controller: source, maxLines: 8, autocorrect: false, enableSuggestions: false,
        onChanged: (_) => setState(() { results = null; failed = false; }),
        decoration: const InputDecoration(label: LText('Contract and cases JSON'))),
      FilledButton(onPressed: run, child: const LText('Run local cases')),
      if (failed) const LText('Invalid contract or cases.'),
      if (results != null) ...[
        Text(uiNumber(context, results!.where((r) => r.passed).length) + ' / ' + uiNumber(context, results!.length)),
        for (final row in results!) ListTile(
          leading: Icon(row.passed ? Icons.check_circle_outline : Icons.error_outline),
          title: Text(uiNumber(context, row.index)),
          subtitle: LText(row.accepted ? 'Input accepted by local contract' : 'Input rejected by local contract'),
          trailing: LText(row.passed ? 'Expected result' : 'Unexpected result')),
      ],
    ]),
  );
}
