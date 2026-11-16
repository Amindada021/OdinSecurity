import 'package:flutter/material.dart';
import 'core/auth.dart';
import 'core/manual_request.dart';
import 'core/project.dart';

class ManualRequestScreen extends StatefulWidget {
  final SecurityProject project;
  final Uri target;
  final AuthProfile? auth;
  const ManualRequestScreen({super.key, required this.project, required this.target, this.auth});
  @override
  State<ManualRequestScreen> createState() => _ManualRequestScreenState();
}
class _ManualRequestScreenState extends State<ManualRequestScreen> {
  late final TextEditingController url;
  bool authorized = false, busy = false, useAuth = false;
  String method = 'GET';
  ManualResponse? response;
  String? error;
  @override
  void initState() {
    super.initState();
    url = TextEditingController(text: widget.target.toString());
  }

  @override
  void dispose() { url.dispose(); super.dispose(); }

  Future<void> send() async {
    if (!authorized || busy) return;
    setState(() { busy = true; error = null; response = null; });
    try {
      final result = await ManualRequestClient().send(widget.project, Uri.parse(url.text.trim()), method,
        authorized: authorized, auth: useAuth ? widget.auth : null);
      if (mounted) setState(() => response = result);
    } catch (_) {
      if (mounted) setState(() => error = 'Request failed. Check scope, credential origin and connectivity.');
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final data = response;
    return Scaffold(
      appBar: AppBar(title: const Text('Request inspector')),
      body: ListView(padding: const EdgeInsets.all(16), children: [
        const Text('Manually send an authorized GET or HEAD. Responses may contain sensitive data; they are not saved to history.'),
        DropdownButtonFormField<String>(initialValue: method, items: ['GET', 'HEAD'].map((m) => DropdownMenuItem(value: m, child: Text(m))).toList(), onChanged: busy ? null : (v) => setState(() { method = v!; authorized = false; })),
        TextField(controller: url, enabled: !busy, keyboardType: TextInputType.url, decoration: const InputDecoration(labelText: 'Request URL'), onChanged: (_) => setState(() => authorized = false)),
        if (widget.auth != null) CheckboxListTile(value: useAuth, title: const Text('Use saved credentials for their exact origin'), onChanged: busy ? null : (v) => setState(() { useAuth = v ?? false; authorized = false; })),
        CheckboxListTile(value: authorized, title: const Text('I authorize this exact request.'), onChanged: busy ? null : (v) => setState(() => authorized = v ?? false)),
        FilledButton(onPressed: busy || !authorized ? null : send, child: const Text('Send request')),
        if (busy) const LinearProgressIndicator(),
        if (error != null) Text(error!),
        if (data != null) ...[
          Text('HTTP ${data.status}', style: Theme.of(context).textTheme.titleLarge),
          const Text('Response headers'),
          SelectableText(data.headers.entries.map((e) => '${e.key}: ${e.value.join(', ')}').join('\n')),
          const Divider(),
          if (data.truncated) const Text('Response truncated to 64 KiB.'),
          const Text('Response body'),
          SelectableText(data.body),
        ],
      ]),
    );
  }
}
