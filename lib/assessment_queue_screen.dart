import 'dart:async';
import 'package:flutter/material.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'core/assessment_queue.dart';
import 'core/custom_rules.dart';
import 'core/passive_scan.dart';
import 'core/project.dart';
import 'core/project_storage.dart';
import 'core/scan_policy.dart';
import 'core/history.dart';
import 'localized.dart';

class AssessmentQueueScreen extends StatefulWidget {
  final SecurityProject project;
  final ScanPolicy policy;
  const AssessmentQueueScreen({super.key, required this.project, required this.policy});
  @override
  State<AssessmentQueueScreen> createState() => _AssessmentQueueScreenState();
}

class _AssessmentQueueScreenState extends State<AssessmentQueueScreen> with WidgetsBindingObserver {
  final targets = <Uri>{};
  final observations = <QueueObservation>[];
  bool authorized = false, parallel = false, running = false, cancelled = false, failed = false;
  int minutes = 0;
  Timer? timer;
  bool get locked => running || timer != null;
  @override
  void initState() { super.initState(); WidgetsBinding.instance.addObserver(this); }
  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    timer?.cancel(); cancelled = true;
    super.dispose();
  }
  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state != AppLifecycleState.resumed && locked) stop();
  }
  void stop() {
    timer?.cancel();
    setState(() { timer = null; cancelled = true; authorized = false; });
  }
  void schedule() {
    if (locked || !authorized || targets.isEmpty) return;
    try {
      AssessmentQueue.validate(widget.project, widget.policy, targets, authorized: authorized);
    } catch (_) { setState(() => failed = true); return; }
    setState(() { observations.clear(); failed = false; cancelled = false; });
    if (minutes == 0) { unawaited(run()); return; }
    setState(() => timer = Timer(Duration(minutes: minutes), () {
      if (!mounted) return;
      setState(() => timer = null);
      if (ModalRoute.of(context)?.isCurrent != true || WidgetsBinding.instance.lifecycleState != AppLifecycleState.resumed) { stop(); return; }
      unawaited(run());
    }));
  }
  Future<void> run() async {
    if (!mounted || cancelled || !authorized || running) return;
    final snapshot = targets.toList();
    final useParallel = parallel;
    setState(() { running = true; authorized = false; });
    final pages = <PassiveScanResult>[];
    try {
      final storage = PreferencesStorage(await SharedPreferences.getInstance());
      final rules = await CustomRuleRepository(storage).load(widget.project.id);
      final scanner = PassiveScanner(customRules: rules);
      await AssessmentQueue.run(widget.project, widget.policy, snapshot, authorized: true, parallel: useParallel,
        cancelled: () => cancelled || !mounted,
        fetch: (u) async {
          final page = await scanner.scan(widget.project, target: u, authorized: true, permits: widget.policy.permits);
          pages.add(page);
          return page.statusCode;
        }, onCompleted: (item) { if (mounted) setState(() => observations.add(item)); });
      if (mounted && observations.isNotEmpty) {
        await HistoryRepository(storage).append(widget.project.id, ScanRecord.fromPages(pages,
          failedCount: observations.where((o) => o.status == null).length, cancelled: cancelled));
      }
    } catch (_) { if (mounted) setState(() => failed = true); }
    finally { if (mounted) setState(() => running = false); }
  }
  @override
  Widget build(BuildContext context) => Scaffold(
    appBar: AppBar(title: const LText('Foreground assessment queue')),
    body: ListView(padding: const EdgeInsets.all(16), children: [
      const LText('Choose up to three registered HTTPS targets. Anonymous single-page assessments only. Leaving the screen or backgrounding cancels pending work; running requests may finish.'),
      for (final target in widget.project.targets.where((u) => u.scheme == 'https' && widget.policy.permits(u)))
        CheckboxListTile(title: Text(target.toString()), value: targets.contains(target),
          onChanged: locked || !targets.contains(target) && (targets.length >= AssessmentQueue.maxTargets || targets.length >= widget.policy.maxPages) ? null :
            (value) => setState(() { if (value == true) { targets.add(target); } else { targets.remove(target); } authorized = false; })),
      CheckboxListTile(value: parallel, title: const LText('Allow two different origins in parallel'),
        onChanged: locked ? null : (v) => setState(() { parallel = v ?? false; authorized = false; })),
      DropdownButtonFormField<int>(initialValue: minutes, decoration: const InputDecoration(label: LText('Start after (minutes)')),
        items: [for (final n in [0, 1, 5, 15]) DropdownMenuItem(value: n, child: Text(uiNumber(context, n)))],
        onChanged: locked ? null : (v) => setState(() { minutes = v ?? 0; authorized = false; })),
      CheckboxListTile(value: authorized, title: const LText('I authorize these exact assessments.'),
        onChanged: locked ? null : (v) => setState(() => authorized = v ?? false)),
      FilledButton(onPressed: locked || !authorized || targets.isEmpty ? null : schedule, child: const LText('Start or schedule queue')),
      if (locked) ...[
        const LinearProgressIndicator(),
        if (timer != null) const LText('Waiting in foreground'),
        OutlinedButton(onPressed: cancelled ? null : stop, child: const LText('Stop')),
      ],
      if (failed) const LText('Queue could not complete.'),
      for (final entry in observations) ListTile(title: Text(entry.target.toString()), trailing: Text(entry.status?.toString() ?? '—')),
      if (!locked && observations.isNotEmpty && !failed) const LText('Completed responses saved to scan history; unstarted targets are not assessed.'),
    ]),
  );
}
