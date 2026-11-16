import 'package:flutter/material.dart';
import 'core/manual_request.dart';
import 'core/representation_matrix.dart';
import 'core/project.dart';
import 'core/scan_policy.dart';
import 'localized.dart';

class RepresentationMatrixScreen extends StatefulWidget {
  final SecurityProject project;
  final ScanPolicy policy;
  const RepresentationMatrixScreen({super.key, required this.project, required this.policy});
  @override
  State<RepresentationMatrixScreen> createState() => _RepresentationMatrixScreenState();
}
class _RepresentationMatrixScreenState extends State<RepresentationMatrixScreen> {
  Uri? target;
  final values = <ManualAccept>{};
  final expected = <ManualAccept,int>{};
  bool authorized = false, running = false, stopped = false, failed = false;
  List<RepresentationObservation>? results;
  Future<void> run() async {
    if (target == null || !authorized || running || values.isEmpty) return;
    final endpoint = target!;
    final modes = List<ManualAccept>.of(values);
    final assertions = Map<ManualAccept,int>.from(expected);
    setState(() { running = true; stopped = false; authorized = false; failed = false; results = null; });
    try {
      final client = ManualRequestClient();
      final matrix = RepresentationMatrix(send: (accept) => client.send(widget.project, endpoint, 'GET',
        authorized: true, policy: widget.policy, accept: accept));
      final data = await matrix.run(widget.project, widget.policy, endpoint, modes, authorized: true, cancelled: () => stopped || !mounted, expected: assertions);
      if (mounted) setState(() => results = data);
    } catch (_) { if (mounted) setState(() => failed = true); }
    finally { if (mounted) setState(() => running = false); }
  }
  @override
  void dispose() { stopped = true; super.dispose(); }
  @override
  Widget build(BuildContext context) => Scaffold(
    appBar: AppBar(title: const LText('Representation test matrix')),
    body: ListView(padding: const EdgeInsets.all(16), children: [
      const LText('On an isolated authorized test route, compare ordinary fixed Accept headers. Up to four anonymous GET requests; no custom payload or response content retained.'),
      DropdownButtonFormField<Uri>(initialValue: target, isExpanded: true,
        decoration: const InputDecoration(label: LText('Target')),
        items: [for(final u in widget.project.targets.where((u) => u.scheme == 'https' && widget.policy.permits(u)))
          DropdownMenuItem(value: u, child: Text(u.toString(), overflow: TextOverflow.ellipsis))],
        onChanged: running ? null : (u) => setState(() { target = u; authorized = false; results = null; })),
      for (final mode in ManualAccept.values) ...[
        CheckboxListTile(value: values.contains(mode), title: Text(mode.value),
          onChanged: running || (!values.contains(mode) && values.length >= widget.policy.maxPages) ? null :
            (v) => setState(() { if (v == true) { values.add(mode); } else { values.remove(mode); expected.remove(mode); } authorized = false; results = null; })),
        if (values.contains(mode)) DropdownButtonFormField<int>(key: ValueKey(mode), initialValue: expected[mode] ?? 0,
          decoration: const InputDecoration(label: LText('Expected status (optional)')),
          items: [const DropdownMenuItem(value: 0, child: LText('No expectation')),
            for (final code in [200,204,400,401,403,404,406,415,422]) DropdownMenuItem(value: code, child: Text(code.toString()))],
          onChanged: running ? null : (v) => setState(() { if (v == null || v == 0) { expected.remove(mode); } else { expected[mode] = v; } authorized = false; results = null; })),
      ],
      CheckboxListTile(value: authorized, title: const LText('I authorize these exact assessments.'),
        onChanged: running || target == null || values.isEmpty ? null : (v) => setState(() => authorized = v ?? false)),
      FilledButton(onPressed: running || !authorized ? null : run, child: const LText('Run representation matrix')),
      if (running) ...[
        const LinearProgressIndicator(),
        OutlinedButton(onPressed: stopped ? null : () => setState(() => stopped = true), child: const LText('Stop')),
      ],
      if (failed) const LText('Matrix stopped after a transport error.'),
      if (results != null) ...[
        const LText('Status, captured size and timing are diagnostic, not vulnerability proof.'),
        for (final item in results!) ListTile(title: Text(item.accept.value),
          subtitle: Text('HTTP ' + item.status.toString() + ' · ' + item.elapsedMs.toString() + ' ms' + (item.expectedStatus == null ? '' : '\n' + tr(context, 'Expected status (optional)') + ': ' + item.expectedStatus.toString() + ' · ' + tr(context, item.matchesExpectation! ? 'Matches expectation' : 'Differs from expectation'))),
          trailing: Text(item.bodyBytes.toString() + (item.truncated ? '+ B' : ' B'))),
      ],
    ]),
  );
}
