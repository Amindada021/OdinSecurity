import 'package:flutter/material.dart';
import 'core/scheduled_check.dart';
import 'core/project.dart';
import 'core/scan_policy.dart';
import 'localized.dart';

class ScheduledCheckScreen extends StatefulWidget {
  final SecurityProject project;
  final ScanPolicy policy;
  const ScheduledCheckScreen({super.key, required this.project, required this.policy});
  @override
  State<ScheduledCheckScreen> createState() => _ScheduledCheckScreenState();
}
class _ScheduledCheckScreenState extends State<ScheduledCheckScreen> {
  Uri? target;
  int minutes = 15;
  bool approved = false, busy = false, failed = false;
  Map<String, dynamic> status = {};
  bool get active => ['pending', 'running'].contains(status['state']);
  @override
  void initState() { super.initState(); refresh(); }
  Future<void> refresh() async {
    setState(() { busy = true; failed = false; });
    try {
      final data = await ScheduledCheck.status();
      if (mounted) setState(() => status = data);
    } catch (_) { if (mounted) setState(() => failed = true); }
    finally { if (mounted) setState(() => busy = false); }
  }
  Future<void> schedule() async {
    if (target == null || !approved || busy || active) return;
    setState(() { busy = true; failed = false; });
    try {
      await ScheduledCheck.schedule(widget.project, widget.policy, target!, minutes, authorized: approved);
      if (mounted) { setState(() => approved = false); await refresh(); }
    } catch (_) { if (mounted) setState(() => failed = true); }
    finally { if (mounted) setState(() => busy = false); }
  }
  Future<void> cancel() async {
    setState(() { busy = true; failed = false; approved = false; });
    try { await ScheduledCheck.cancelProject(widget.project.id); if (mounted) await refresh(); }
    catch (_) { if (mounted) setState(() => failed = true); }
    finally { if (mounted) setState(() => busy = false); }
  }
  @override
  Widget build(BuildContext context) => Scaffold(
    appBar: AppBar(title: const LText('Android scheduled HEAD check')),
    body: ListView(padding: const EdgeInsets.all(16), children: [
      const LText('Schedule one anonymous HTTPS HEAD check of a registered target. Android may delay or interrupt it. No credentials, redirects, retries, or recurring jobs.'),
      DropdownButtonFormField<Uri>(initialValue: target, isExpanded: true,
        decoration: const InputDecoration(label: LText('Target')),
        items: [for (final u in widget.project.targets.where((u) => u.scheme == 'https' && widget.policy.permits(u)))
          DropdownMenuItem(value: u, child: Text(u.toString(), overflow: TextOverflow.ellipsis))],
        onChanged: busy || active ? null : (u) => setState(() { target = u; approved = false; })),
      DropdownButtonFormField<int>(initialValue: minutes,
        decoration: const InputDecoration(label: LText('Start after (minutes)')),
        items: [for (final n in ScheduledCheck.delays) DropdownMenuItem(value: n, child: Text(uiNumber(context,n)))],
        onChanged: busy || active ? null : (n) => setState(() { minutes = n ?? 15; approved = false; })),
      CheckboxListTile(value: approved, title: const LText('I authorize this exact request even when the app is closed.'),
        onChanged: busy || active || target == null ? null : (v) => setState(() => approved = v ?? false)),
      FilledButton(onPressed: busy || failed || active || !approved ? null : schedule, child: const LText('Schedule background check')),
      OutlinedButton(onPressed: busy ? null : refresh, child: const LText('Refresh status')),
      if (busy) const LinearProgressIndicator(),
      if (failed) const LText('Scheduled check unavailable. Refresh and retry.'),
      if (status['project'] == widget.project.id) ...[
        LText('Scheduled check status'),
        Text(status['state']?.toString() ?? '—'),
        Text(status['target']?.toString() ?? ''),
        if (status['due'] is int) Text(DateTime.fromMillisecondsSinceEpoch(status['due'] as int).toLocal().toString()),
        if (status['status'] is int && (status['status'] as int) > 0) Text('HTTP ' + status['status'].toString()),
        if (active) OutlinedButton(onPressed: busy ? null : cancel, child: const LText('Cancel')),
      ] else if (active) const LText('Another project already has a scheduled check.'),
    ]),
  );
}
