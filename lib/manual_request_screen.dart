import 'package:flutter/material.dart';
import 'localized.dart';
import 'finding_cards.dart';
import 'core/auth.dart';
import 'core/manual_request.dart';
import 'core/project.dart';
import 'core/request_history.dart';
import 'core/request_workspace.dart';
import 'core/request_review.dart';
import 'core/scan_policy.dart';
import 'request_transport_trace_view.dart';
import 'response_matrix_analysis_view.dart';
import 'core/response_matrix_analysis.dart';

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
  final headers = TextEditingController(), body = TextEditingController();
  ManualContent content = ManualContent.none;
  bool stagingConfirmed = false;
  bool get writes => ManualRequestClient.writeMethods.contains(method);
  void invalidate() { authorized = false; stagingConfirmed = false; }
  bool authorized = false, busy = false, useAuth = false;
  String method = 'GET';
  ManualAccept accept = ManualAccept.any;
  ManualResponse? response;
  String? error;
  late final RequestWorkspace workspace;
  RequestHistory get history => workspace.active.history;
  final sinceLast = Stopwatch();
  @override
  void initState() {
    super.initState();
    url = TextEditingController(text: widget.target.toString());
    workspace = RequestWorkspace(widget.target.toString(), initialMethod: widget.initialMethod);
    method = workspace.active.method;
  }

  void saveDraft() {
    final tab = workspace.active;
    tab.url = url.text;
    tab.method = method;
    tab.accept = accept;
    tab.headers = headers.text;
    tab.content = content;
    tab.body = body.text;
    tab.useAuth = useAuth;
    tab.response = response;
    tab.error = error;
  }

  void loadDraft() {
    final tab = workspace.active;
    url.text = tab.url;
    method = tab.method;
    accept = tab.accept;
    headers.text = tab.headers;
    content = tab.content;
    body.text = tab.body;
    useAuth = tab.useAuth;
    response = tab.response;
    error = tab.error;
    invalidate();
  }

  void switchTab(int id) {
    if (busy || workspace.active.id == id) return;
    setState(() { saveDraft(); workspace.select(id); loadDraft(); });
  }

  void addTab() {
    if (busy || !workspace.canAdd) return;
    setState(() { saveDraft(); workspace.add(); loadDraft(); });
  }

  void closeTab() {
    if (busy || !workspace.canClose) return;
    setState(() { workspace.closeActive(); loadDraft(); });
  }

  @override
  void dispose() { url.dispose(); headers.dispose(); body.dispose(); super.dispose(); }

  Future<void> send() async {
    if (!authorized || busy || (writes && !stagingConfirmed)) return;
    final raw = url.text.trim();
    final chosenMethod = method;
    final chosenAccept = accept;
    final chosenAuth = useAuth ? widget.auth : null;
    final chosenStaging = stagingConfirmed;
    setState(() { busy = true; invalidate(); error = null; response = null; workspace.active.response = null; });
    try {
      final options = ManualRequestOptions.parse(headers.text, content, body.text);
      final review = RequestReview.prepare(widget.project, raw, chosenMethod, chosenAccept, widget.policy,
        auth: chosenAuth, options: options, stagingConfirmed: chosenStaging);
      final approved = await showDialog<bool>(context: context, barrierDismissible: false, builder: (context) => AlertDialog(
        title: const LText('Review pending request'),
        content: SingleChildScrollView(child: Column(crossAxisAlignment: CrossAxisAlignment.start, mainAxisSize: MainAxisSize.min, children: [
          const LText('Nothing has been sent. Review the exact destination and request settings.'),
          const SizedBox(height: 12),
          SelectableText('${review.method} ${review.target}', textDirection: TextDirection.ltr),
          const SizedBox(height: 8),
          Text('Accept: ${review.accept.value}', textDirection: TextDirection.ltr),
          LText(review.authenticated ? 'Saved identity will be applied to its exact origin.' : 'No saved identity will be applied.'),
          if (review.stagingConfirmed) const LText('Warning: this request may change or delete test data.'),
          for (final header in review.options.headers.entries)
            SelectableText('${header.key}: ${header.value}', textDirection: TextDirection.ltr),
          if (review.options.content != ManualContent.none) ...[
            Text('${review.options.content.name} | ${review.options.bodyBytes} bytes'),
            SelectableText(review.options.body, textDirection: TextDirection.ltr),
          ],
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
        authorized: true, auth: chosenAuth, policy: widget.policy, accept: review.accept,
        options: review.options, stagingConfirmed: review.stagingConfirmed);
      if (mounted) setState(() {
        response = result;
        history.add(RequestRecord.fromResponse(endpoint, chosenMethod, chosenAccept, chosenAuth != null, result, customized: review.options.hasCustomInput));
      });
    } catch (_) {
      if (mounted) setState(() => error = 'Request failed. Check scope, exclusions, credential origin and connectivity.');
    } finally {
      sinceLast..reset()..start();
      if (mounted) setState(() => busy = false);
    }
  }

  void compareHistory(RequestRecord anchor) {
    final group = history.comparableGroup(anchor);
    if (group.length < 2) return;
    // Put the chosen record first so it becomes the initial reference.
    final ordered = [anchor, ...group.where((r)=>!identical(r,anchor))];
    final metrics = ordered.map((r)=>ResponseMetrics(status:r.status,bodyBytes:r.bodyBytes,
      elapsedMs:r.elapsedMs,truncated:r.truncated)).toList();
    Navigator.of(context).push(MaterialPageRoute(builder:(_)=>Scaffold(
      appBar:AppBar(title:const LText('Compare request history')),
      body:ListView(padding:const EdgeInsets.all(16),children:[
        const LText('Equivalent read-only requests in this tab. No requests are replayed.'),
        ResponseMatrixAnalysisView(samples:metrics,labels:ordered.map((r)=>r.at.toLocal().toIso8601String()).toList()),
      ]),
    )));
  }

  @override
  Widget build(BuildContext context) {
    final data = response;
    final records = history.records;
    final previous = records.length >= 2 && records[0].comparableTo(records[1]) ? records[1] : null;
    return Scaffold(
      appBar: AppBar(title: const LText('Request inspector')),
      body: ListView(padding: const EdgeInsets.all(16), children: [
        Wrap(spacing: 6, runSpacing: 6, children: [
          for (final tab in workspace.tabs)
            ChoiceChip(label: Text('${tr(context, 'Request')} ${uiNumber(context, tab.id)}'),
              selected: workspace.active.id == tab.id, onSelected: busy ? null : (_) => switchTab(tab.id)),
          IconButton(onPressed: busy || !workspace.canAdd ? null : addTab,
            tooltip: tr(context, 'New request tab'), icon: const Icon(Icons.add)),
          IconButton(onPressed: busy || !workspace.canClose ? null : closeTab,
            tooltip: tr(context, 'Close current request tab'), icon: const Icon(Icons.close)),
        ]),
        const LText('Up to five independent request tabs are kept in memory. Each send requires fresh consent; closing the inspector discards all tabs.'),
        const LText('Write methods require HTTPS staging confirmation. Only the latest response in each tab is retained.'),
        DropdownButtonFormField<String>(key: ValueKey('method-${workspace.active.id}'), initialValue: method, items: ManualRequestClient.methods.map((m) => DropdownMenuItem(value: m, child: Text(m))).toList(), onChanged: busy ? null : (v) => setState(() { method = v!; invalidate(); if (!ManualRequestClient.bodyMethods.contains(method)) { content = ManualContent.none; body.clear(); } })),
        TextField(controller: url, enabled: !busy, maxLength: 2048, keyboardType: TextInputType.url, decoration: const InputDecoration(label: LText('Request URL')), onChanged: (_) => setState(invalidate)),
        DropdownButtonFormField<ManualAccept>(key: ValueKey('accept-${workspace.active.id}'), initialValue: accept, decoration: const InputDecoration(label: LText('Accept')), items: ManualAccept.values.map((value) => DropdownMenuItem(value: value, child: Text(value.value))).toList(),
          onChanged: busy ? null : (value) => setState(() { accept = value!; invalidate(); })),
        TextField(controller: headers, enabled: !busy, maxLength: 4096, minLines: 2, maxLines: 5,
          decoration: const InputDecoration(label: LText('Custom headers (one Name: value per line)'),
            helper: LText('Allowed: Cache-Control, If-None-Match, If-Modified-Since, Accept-Language, X-Requested-With')),
          onChanged: (_) => setState(invalidate)),
        if (ManualRequestClient.bodyMethods.contains(method)) ...[
          DropdownButtonFormField<ManualContent>(key: ValueKey('content-${workspace.active.id}'), initialValue: content, decoration: const InputDecoration(label: LText('Request content')),
            items: ManualContent.values.map((v) => DropdownMenuItem(value: v, child: Text(v.name))).toList(),
            onChanged: busy ? null : (v) => setState(() { content = v!; if (content == ManualContent.none) body.clear(); invalidate(); })),
          if (content != ManualContent.none) TextField(controller: body, enabled: !busy, maxLength: 32768, minLines: 4, maxLines: 12,
            textDirection: TextDirection.ltr, decoration: const InputDecoration(label: LText('Request body (max 32 KiB)')),
            onChanged: (_) => setState(invalidate)),
        ],
        if (writes) CheckboxListTile(value: stagingConfirmed, title: const LText('This is an authorized HTTPS staging endpoint; I accept possible test data changes.'),
          onChanged: busy ? null : (v) => setState(() { stagingConfirmed = v ?? false; authorized = false; })),
        if (widget.auth != null) CheckboxListTile(value: useAuth, title: const LText('Use saved credentials for their exact origin'), onChanged: busy ? null : (v) => setState(() { useAuth = v ?? false; invalidate(); })),
        CheckboxListTile(value: authorized, title: const LText('I authorize this exact request.'), onChanged: busy ? null : (v) => setState(() => authorized = v ?? false)),
        FilledButton(onPressed: busy || !authorized || (writes && !stagingConfirmed) ? null : send, child: const LText('Review request')),
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
          if (data.trace != null) RequestTransportTraceView(trace: data.trace!),
          ExpansionTile(title: const LText('Response security observations'),
            subtitle: Text(uiNumber(context, data.observations.length)),
            children: [
              const LText('Passive configuration observations from this response only; no additional requests.'),
              for (final finding in data.observations) FindingTile(id: finding.id, title: finding.title, severity: finding.severity.name, evidence: finding.evidence, remediation: finding.remediation),
            ]),
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
          TextButton(onPressed: records.isEmpty || busy ? null : () => setState(() { history.clear(); response = null; workspace.active.response = null; }), child: const LText('Clear')),
        ]),
        const LText('Only route, method, status, timing and captured size are retained in memory. Query values are omitted; paths can still be sensitive.'),
        for (final record in records) ListTile(
          title: Text('${record.method} ${record.route}'),
          trailing: !busy && history.comparableGroup(record).length>1 ? IconButton(
            icon:const Icon(Icons.compare_arrows),tooltip:tr(context,'Compare request history'),
            onPressed:()=>compareHistory(record)) : null,
          subtitle: Text('${record.status} | ${record.elapsedMs} ms | ${record.bodyBytes} bytes${record.truncated ? "+" : ""}${record.hadQuery ? " | query omitted" : ""}'),
        ),
      ]),
    );
  }
}
