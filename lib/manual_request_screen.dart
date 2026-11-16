import 'package:flutter/material.dart';
import 'localized.dart';
import 'core/auth.dart';
import 'core/manual_request.dart';
import 'core/project.dart';
import 'core/request_history.dart';
import 'core/request_review.dart';
import 'core/scan_policy.dart';

class ManualRequestScreen extends StatefulWidget {
  final SecurityProject project;
  final Uri target;
  final AuthProfile? auth;
  final ScanPolicy policy;
  final String initialMethod;
  const ManualRequestScreen({super.key, required this.project, required this.target, this.auth, required this.policy, this.initialMethod = 'GET'});
  @override
  State<ManualRequestScreen> createState() => _ManualRequestScreenState();
}
class _ManualRequestScreenState extends State<ManualRequestScreen> {
  late final TextEditingController url;
  bool authorized = false, busy = false, useAuth = false;
  String method = 'GET';
  ManualAccept accept = ManualAccept.any;
  ManualResponse? response;
  String? error;
  final history = RequestHistory();
  final sinceLast = Stopwatch();
  @override
  void initState() {
    super.initState();
    url = TextEditingController(text: widget.target.toString());
    method = widget.initialMethod == 'HEAD' ? 'HEAD' : 'GET';
  }

  @override
  void dispose() { url.dispose(); super.dispose(); }

  Future<void> send() async {
    if (!authorized || busy) return;
    final raw = url.text.trim();
    final chosenMethod = method;
    final chosenAccept = accept;
    final chosenAuth = useAuth ? widget.auth : null;
    setState(() { busy = true; authorized = false; error = null; response = null; });
    try {
      final review = RequestReview.prepare(widget.project, raw, chosenMethod, chosenAccept, widget.policy, auth: chosenAuth);
      final approved = await showDialog<bool>(context: context, barrierDismissible: false, builder: (context) => AlertDialog(
        title: const LText('Review pending request'),
        content: SingleChildScrollView(child: Column(crossAxisAlignment: CrossAxisAlignment.start, mainAxisSize: MainAxisSize.min, children: [
          const LText('Nothing has been sent. Review the exact destination and request settings.'),
          const SizedBox(height: 12),
          SelectableText('${review.method} ${review.target}', textDirection: TextDirection.ltr),
          const SizedBox(height: 8),
          Text('Accept: ${review.accept.value}', textDirection: TextDirection.ltr),
          LText(review.authenticated ? 'Saved identity will be applied to its exact origin.' : 'No saved identity will be applied.'),
          const LText('Redirects will not be followed.'),
        ])),
        actions: [
          TextButton(onPressed: () => Navigator.of(context).pop(false), child: const LText('Drop request')),
          FilledButton(onPressed: () => Navigator.of(context).pop(true), child: const LText('Forward request')),
        ],
      ));
      if (!mounted || approved != true) return;
      review.validate(widget.project, widget.policy, approved: true, auth: chosenAuth);
      final endpoint = review.target;
      if (sinceLast.isRunning) {
        final remaining = widget.policy.delayMs - sinceLast.elapsedMilliseconds;
        if (remaining > 0) await Future<void>.delayed(Duration(milliseconds: remaining));
      }
      if (!mounted) return;
      final result = await ManualRequestClient().send(widget.project, endpoint, review.method,
        authorized: true, auth: chosenAuth, policy: widget.policy, accept: review.accept);
      if (mounted) setState(() {
        response = result;
        history.add(RequestRecord.fromResponse(endpoint, chosenMethod, chosenAccept, chosenAuth != null, result));
      });
    } catch (_) {
      if (mounted) setState(() => error = 'Request failed. Check scope, exclusions, credential origin and connectivity.');
    } finally {
      sinceLast..reset()..start();
      if (mounted) setState(() => busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final data = response;
    final records = history.records;
    final previous = records.length >= 2 && records[0].comparableTo(records[1]) ? records[1] : null;
    return Scaffold(
      appBar: AppBar(title: const LText('Request inspector')),
      body: ListView(padding: const EdgeInsets.all(16), children: [
        const LText('Manually send authorized GET or HEAD requests. Each send requires consent. Response content is visible only for the latest request and is not stored.'),
        DropdownButtonFormField<String>(initialValue: method, items: ['GET', 'HEAD'].map((m) => DropdownMenuItem(value: m, child: Text(m))).toList(), onChanged: busy ? null : (v) => setState(() { method = v!; authorized = false; })),
        TextField(controller: url, enabled: !busy, keyboardType: TextInputType.url, decoration: const InputDecoration(label: LText('Request URL')), onChanged: (_) => setState(() => authorized = false)),
        DropdownButtonFormField<ManualAccept>(initialValue: accept, decoration: const InputDecoration(label: LText('Accept')), items: ManualAccept.values.map((value) => DropdownMenuItem(value: value, child: Text(value.value))).toList(),
          onChanged: busy ? null : (value) => setState(() { accept = value!; authorized = false; })),
        if (widget.auth != null) CheckboxListTile(value: useAuth, title: const LText('Use saved credentials for their exact origin'), onChanged: busy ? null : (v) => setState(() { useAuth = v ?? false; authorized = false; })),
        CheckboxListTile(value: authorized, title: const LText('I authorize this exact request.'), onChanged: busy ? null : (v) => setState(() => authorized = v ?? false)),
        FilledButton(onPressed: busy || !authorized ? null : send, child: const LText('Review request')),
        if (busy) const LinearProgressIndicator(),
        if (error != null) LText(error!),
        if (data != null) ...[
          Text('HTTP ${data.status}', style: Theme.of(context).textTheme.titleLarge),
          Text('${data.elapsedMs} ms | ${data.bodyBytes} captured bytes'),
          if (previous != null) ...[
            const LText('Previous comparable request (same route, method, Accept and auth setting)'),
            Text('Status: ${previous.status} → ${data.status} | Time: ${previous.elapsedMs} → ${data.elapsedMs} ms'),
            if (!previous.truncated && !data.truncated) Text('Captured bytes: ${previous.bodyBytes} → ${data.bodyBytes}'),
            const LText('Differences are diagnostic observations, not proof of a vulnerability.'),
          ],
          const LText('Response headers (unrecognized values redacted)'),
          SelectableText(data.headers.entries.map((e) => '${e.key}: ${e.value.join(', ')}').join('\n')),
          const Divider(),
          if (data.truncated) const LText('Response truncated to 64 KiB.'),
          const LText('Response body'),
          SelectableText(data.body),
        ],
        const Divider(),
        Row(children: [
          Expanded(child: Text('${tr(context, 'Session history')} (${uiNumber(context, records.length)})')),
          TextButton(onPressed: records.isEmpty || busy ? null : () => setState(() { history.clear(); response = null; }), child: const LText('Clear')),
        ]),
        const LText('Only route, method, status, timing and captured size are retained in memory. Query values are omitted; paths can still be sensitive.'),
        for (final record in records) ListTile(
          title: Text('${record.method} ${record.route}'),
          subtitle: Text('${record.status} | ${record.elapsedMs} ms | ${record.bodyBytes} bytes${record.truncated ? "+" : ""}${record.hadQuery ? " | query omitted" : ""}'),
        ),
      ]),
    );
  }
}
