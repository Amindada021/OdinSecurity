import 'dart:async';
import 'package:flutter/material.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'core/assessment_queue.dart';
import 'core/queue_template.dart';
import 'core/auth.dart';
import 'core/auth_vault.dart';
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
  bool loading = true, templateError = false, templateSaved = false;
  List<AuthProfile> profiles = [];
  final identities = <Uri, String>{};
  Timer? timer;
  bool get locked => loading || running || timer != null;
  @override
  void initState() { super.initState(); WidgetsBinding.instance.addObserver(this); unawaited(loadTemplate()); }

  Future<void> loadTemplate() async {
    try {
      final storage = PreferencesStorage(await SharedPreferences.getInstance());
      final saved = await QueueTemplateRepository(storage).load(widget.project, widget.policy);
      final available = await AuthVault().loadProfiles(widget.project.id);
      if (!mounted) return;
      setState(() {
        profiles = available;
        if (saved != null) { targets.addAll(saved.targets); parallel = saved.parallel; minutes = saved.minutes; }
        authorized = false;
      });
    } catch (_) { if (mounted) setState(() => templateError = true); }
    finally { if (mounted) setState(() => loading = false); }
  }

  Future<void> saveTemplate() async {
    if (locked || targets.isEmpty) return;
    setState(() { loading = true; templateError = false; templateSaved = false; authorized = false; });
    try {
      final storage = PreferencesStorage(await SharedPreferences.getInstance());
      await QueueTemplateRepository(storage).save(widget.project,
        QueueTemplate(widget.project, widget.policy, targets, parallel, minutes));
      if (mounted) setState(() => templateSaved = true);
    } catch (_) { if (mounted) setState(() => templateError = true); }
    finally { if (mounted) setState(() => loading = false); }
  }
  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    timer?.cancel(); cancelled = true;
    super.dispose();
  }
  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state != AppLifecycleState.resumed && (running || timer != null)) stop();
  }
  void stop() {
    timer?.cancel();
    setState(() { timer = null; cancelled = true; authorized = false; });
  }
  void schedule() {
    if (locked || !authorized || targets.isEmpty) return;
    try {
      AssessmentQueue.validate(widget.project, widget.policy, targets, authorized: authorized);
      for (final target in targets) { QueueIdentity.resolve(target, identities[target] ?? '', profiles); }
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
    final selectedNames = Map<Uri, String>.from(identities);
    setState(() { running = true; authorized = false; });
    final pages = <PassiveScanResult>[];
    try {
      final storage = PreferencesStorage(await SharedPreferences.getInstance());
      final rules = await CustomRuleRepository(storage).load(widget.project.id);
      final scanner = PassiveScanner(customRules: rules);
      // Re-load vault at execution time; never persist or export credentials.
      final available = await AuthVault().loadProfiles(widget.project.id);
      final selected = <Uri, AuthProfile?>{for (final u in snapshot) u: QueueIdentity.resolve(u, selectedNames[u] ?? '', available)};
      await AssessmentQueue.run(widget.project, widget.policy, snapshot, authorized: true, parallel: useParallel,
        cancelled: () => cancelled || !mounted,
        fetch: (u) async {
          final page = await scanner.scan(widget.project, target: u, authorized: true, permits: widget.policy.permits, auth: selected[u]);
          pages.add(page);
          return page.statusCode;
        }, authenticated: (u) => selected[u] != null, onCompleted: (item) { if (mounted) setState(() => observations.add(item)); });
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
      const LText('Choose up to three registered HTTPS targets and optionally a matching saved static identity per target. No automatic login. Leaving the screen or backgrounding cancels pending work.'),
      if (loading) const LinearProgressIndicator(),
      if (templateError) const LText('Template or identity loading failed. Review settings before use.'),
      for (final target in widget.project.targets.where((u) => u.scheme == 'https' && widget.policy.permits(u))) ...[
        CheckboxListTile(title: Text(target.toString()), value: targets.contains(target),
          onChanged: locked || !targets.contains(target) && (targets.length >= AssessmentQueue.maxTargets || targets.length >= widget.policy.maxPages) ? null :
            (value) => setState(() { if (value == true) { targets.add(target); } else { targets.remove(target); identities.remove(target); } authorized = false; })),
        if (targets.contains(target) && QueueIdentity.eligible(target, profiles).isNotEmpty)
          DropdownButtonFormField<String>(key: ValueKey(target), initialValue: identities[target] ?? '', isExpanded: true,
            decoration: const InputDecoration(label: LText('Identity for this target')),
            items: [const DropdownMenuItem(value: '', child: LText('Anonymous')),
              for (final profile in QueueIdentity.eligible(target, profiles)) DropdownMenuItem(value: profile.name, child: Text(profile.name))],
            onChanged: locked ? null : (value) => setState(() { identities[target] = value ?? ''; authorized = false; })),
      ],
      CheckboxListTile(value: parallel, title: const LText('Allow two different origins in parallel'),
        onChanged: locked ? null : (v) => setState(() { parallel = v ?? false; authorized = false; })),
      DropdownButtonFormField<int>(initialValue: minutes, decoration: const InputDecoration(label: LText('Start after (minutes)')),
        items: [for (final n in [0, 1, 5, 15]) DropdownMenuItem(value: n, child: Text(uiNumber(context, n)))],
        onChanged: locked ? null : (v) => setState(() { minutes = v ?? 0; authorized = false; })),
      OutlinedButton(onPressed: locked || targets.isEmpty ? null : saveTemplate, child: const LText('Save queue template')),
      if (templateSaved) const LText('Template saved without identities or authorization.'),
      const LText('Saved static profiles may perform their configured session verification. An expired or unavailable profile stops the assessment.'),
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
