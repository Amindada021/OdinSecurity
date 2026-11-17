import 'dart:async';
import 'dart:convert';
import 'dart:math' as math;
import 'dart:typed_data';
import 'package:flutter/material.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'core/load_test_engine.dart';
import 'core/load_test_policy.dart';
import 'core/load_test_report.dart';
import 'core/project.dart';
import 'core/scan_policy.dart';
import 'core/project_storage.dart';
import 'core/report_file_saver.dart';
import 'localized.dart';

class LoadTestScreen extends StatefulWidget {
  final SecurityProject project;
  final Uri target;
  final ScanPolicy policy;
  const LoadTestScreen({super.key, required this.project, required this.target, required this.policy});
  @override
  State<LoadTestScreen> createState() => _LoadTestScreenState();
}

class _LoadTestScreenState extends State<LoadTestScreen> with WidgetsBindingObserver {
  late final TextEditingController target;
  final users = TextEditingController(text: '2'), rps = TextEditingController(text: '2');
  final duration = TextEditingController(text: '30'), timeout = TextEditingController(text: '5'), ramp = TextEditingController(text: '5');
  late final Future<LoadTestRepository> repository;
  LabPermit? permit;
  LoadTestControl? control;
  LoadSnapshot? live;
  LoadTestResult? result;
  List<LoadTestResult> history = [];
  final timeline = <LoadSnapshot>[];
  bool authorized = false, busy = false, loading = true, saving = false;
  String? error;
  DateTime? cooldown;
  int? baseline;
  Timer? clock;
  static const background = Color(0xff080f1c), panel = Color(0xff101d30), accent = Color(0xff3de4cf);

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    target = TextEditingController(text: widget.target.toString());
    repository = SharedPreferences.getInstance().then((prefs) => LoadTestRepository(PreferencesStorage(prefs)));
    restore();
    clock = Timer.periodic(const Duration(seconds: 1), (_) {
      if (mounted && cooldown != null) setState(() {});
    });
  }
  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state != AppLifecycleState.resumed) control?.stop('app_backgrounded');
  }
  @override
  void dispose() {
    control?.stop('screen_closed');
    WidgetsBinding.instance.removeObserver(this);
    clock?.cancel();
    for (final field in [target, users, rps, duration, timeout, ramp]) { field.dispose(); }
    super.dispose();
  }
  String normalize(String value) => value.trim().replaceAllMapped(RegExp('[۰-۹٠-٩]'), (match) {
    final code = match[0]!.codeUnitAt(0);
    return (code >= 0x6f0 ? code - 0x6f0 : code - 0x660).toString();
  });
  LoadTestConfig configuration() => LoadTestConfig(target: SecurityProject.parseTarget(target.text),
    users: int.parse(normalize(users.text)), rps: double.parse(normalize(rps.text)),
    durationSeconds: int.parse(normalize(duration.text)), timeoutSeconds: int.parse(normalize(timeout.text)),
    rampSeconds: int.parse(normalize(ramp.text)));
  Future<void> restore() async {
    try {
      final repo = await repository;
      final records = await repo.load(widget.project.id);
      final config = await repo.loadConfig(widget.project.id);
      if (!mounted) return;
      if (config != null && widget.project.contains(config.target)) {
        target.text = config.target.toString(); users.text = '${config.users}'; rps.text = '${config.rps}';
        duration.text = '${config.durationSeconds}'; timeout.text = '${config.timeoutSeconds}'; ramp.text = '${config.rampSeconds}';
      }
      final blocked = await repo.cooldown(SecurityProject.parseTarget(target.text).origin);
      if (mounted) setState(() { history = records; cooldown = blocked; });
    } catch (_) {
      if (mounted) setState(() => error = 'Could not restore load-test history or settings.');
    } finally { if (mounted) setState(() => loading = false); }
  }
  bool get coolingDown => cooldown?.isAfter(DateTime.now()) == true;
  String? validation() {
    try {
      final config = configuration(); config.validate();
      if (!widget.project.contains(config.target) || !widget.policy.permits(config.target)) return 'Target is outside this project.';
      permit?.validate(config, widget.project, DateTime.now().toUtc());
      return null;
    } catch (_) { return 'Check laboratory settings and administrator limits.'; }
  }
  Future<void> changedTarget() async {
    setState(() { permit = null; authorized = false; error = null; cooldown = null; });
    final raw = target.text;
    try {
      final origin = SecurityProject.parseTarget(raw).origin;
      final blocked = await (await repository).cooldown(origin);
      if (mounted && target.text == raw) setState(() => cooldown = blocked);
    } catch (_) { /* A partial target is not sent anywhere. */ }
  }
  Future<void> handleFailure(Object failure, Uri selected) async {
    if (failure is LabCooldown) {
      try { await (await repository).setCooldown(selected.origin, failure.until); } catch (_) { /* keep in-memory block */ }
      if (mounted) setState(() { cooldown = failure.until; error = 'Server cooldown is active. Respect Retry-After before restarting.'; });
    } else if (mounted) {
      setState(() => error = failure is FormatException ? failure.message : 'Load test could not finish. Check the laboratory permit and connection.');
    }
  }
  Future<void> verify() async {
    if (busy || !authorized || coolingDown) return;
    Uri selected;
    try { selected = SecurityProject.parseTarget(target.text); }
    catch (_) { setState(() => error = 'Enter a valid laboratory URL.'); return; }
    setState(() { busy = true; error = null; });
    try {
      final value = await LabPermitVerifier().verify(widget.project, selected, authorized: authorized, permits: widget.policy.permits);
      if (mounted && selected.toString() == target.text.trim()) setState(() => permit = value);
    } catch (e) { await handleFailure(e, selected); }
    finally { if (mounted) setState(() => busy = false); }
  }
  Future<void> run() async {
    if (busy || permit == null || !authorized || validation() != null || coolingDown) return;
    final config = configuration();
    final flag = LoadTestControl();
    setState(() { busy = true; error = null; result = null; live = null; baseline = null; timeline.clear(); control = flag; });
    try {
      final repo = await repository;
      final blocked = await repo.cooldown(config.target.origin);
      await repo.saveConfig(widget.project.id, config);
      final value = await LoadTestEngine().run(widget.project, config, authorized: authorized,
        control: flag, blockedUntil: blocked, permits: widget.policy.permits,
        onPermit: (fresh) { if (mounted) setState(() => permit = fresh); },
        onUpdate: (snapshot) { if (mounted) setState(() { live = snapshot; timeline.add(snapshot); }); });
      // Cooldown is installed before any history write can fail.
      if (mounted) setState(() { result = value; live = value.summary; cooldown = value.cooldownUntil; });
      try {
        final records = await repo.save(widget.project.id, value);
        if (mounted) setState(() => history = records);
      } catch (_) {
        if (mounted) setState(() => error = 'Could not save load-test history; the current report is still available.');
      }
    } catch (e) { await handleFailure(e, config.target); }
    finally { if (mounted) setState(() { busy = false; control = null; authorized = false; }); }
  }
  Future<void> export(String type, LoadTestResult item) async {
    setState(() => saving = true);
    try {
      final report = LoadTestReport(item);
      final Uint8List bytes = type == 'pdf' ? await report.exportPdf() : Uint8List.fromList(utf8.encode(report.exportJson()));
      final ok = await ReportFileSaver.save(fileName: 'OdinSecurity-Load-${item.startedAt.millisecondsSinceEpoch}.$type', extension: type, bytes: bytes);
      if (mounted && ok) ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: LText('Report saved.')));
    } catch (_) {
      if (mounted) setState(() => error = 'Could not save the load-test report.');
    } finally { if (mounted) setState(() => saving = false); }
  }
  Widget card(Widget child) => Container(margin: const EdgeInsets.only(bottom: 14), padding: const EdgeInsets.all(16),
    decoration: BoxDecoration(color: panel, borderRadius: BorderRadius.circular(16), border: Border.all(color: accent.withValues(alpha: .2))), child: child);
  Widget metric(String label, String value, {Color color = accent}) => SizedBox(width: math.min(145.0, (MediaQuery.sizeOf(context).width - 78) / 2).toDouble(), child: Column(
    crossAxisAlignment: CrossAxisAlignment.start, children: [LText(label, style: const TextStyle(color: Colors.white70, fontSize: 12)),
      const SizedBox(height: 6), SizedBox(height: 30, child: FittedBox(fit: BoxFit.scaleDown, alignment: Alignment.centerLeft,
        child: Text(value, style: TextStyle(color: color, fontSize: 24, fontFamily: 'monospace', fontWeight: FontWeight.bold))))]));
  Widget field(TextEditingController controller, String label) => TextField(controller: controller, enabled: !busy && !loading,
    keyboardType: const TextInputType.numberWithOptions(decimal: true), style: const TextStyle(color: Colors.white),
    decoration: InputDecoration(label: LText(label, style: const TextStyle(fontSize: 12)), border: const OutlineInputBorder()), onChanged: (_) => setState(() => error = null));
  Color riskColor(LoadRisk risk) => switch (risk) {
    LoadRisk.low => Colors.greenAccent, LoadRisk.moderate => Colors.yellowAccent,
    LoadRisk.high => Colors.orangeAccent, LoadRisk.disruption => Colors.redAccent,
  };
  String riskLabel(LoadRisk risk) => switch (risk) {
    LoadRisk.low => 'Low risk', LoadRisk.moderate => 'Moderate pressure',
    LoadRisk.high => 'High pressure', LoadRisk.disruption => 'Service disruption risk',
  };

  @override
  Widget build(BuildContext context) {
    LoadTestConfig? config;
    try { config = configuration(); config.validate(); } catch (_) { config = null; }
    final risk = permit == null || config == null ? null : permit!.risk(config, observedLatencyMs: control != null ? live?.p95Ms : null);
    final value = live;
    final invalid = validation();
    final previous = baseline != null && baseline! < history.length ? history[baseline!] : null;
    final report = result == null ? null : LoadTestReport(result!);
    return PopScope(canPop: control == null, onPopInvokedWithResult: (didPop, _) {
      if (!didPop) setState(() => control?.stop('screen_closed'));
    }, child: Theme(data: ThemeData.dark(useMaterial3: true).copyWith(scaffoldBackgroundColor: background,
      colorScheme: ColorScheme.fromSeed(seedColor: accent, brightness: Brightness.dark)), child: Scaffold(
      appBar: AppBar(title: const LText('Server resilience laboratory'), backgroundColor: background),
      body: ListView(padding: const EdgeInsets.all(16), children: [
        card(Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          const Row(children: [Icon(Icons.monitor_heart_outlined, color: accent), SizedBox(width: 10), Expanded(child: LText('Local / staging load test', style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold)))]),
          const SizedBox(height: 8), const LText('Requires a fresh server administrator permit. Production targets are not supported.'),
          const SizedBox(height: 16),
          TextField(controller: target, enabled: !busy && !loading, autocorrect: false,
            style: const TextStyle(fontFamily: 'monospace'), decoration: const InputDecoration(label: LText('Target URL'), border: OutlineInputBorder()),
            onChanged: (_) => unawaited(changedTarget())),
          const SizedBox(height: 12),
          LayoutBuilder(builder: (context, box) {
            final width = box.maxWidth > 540 ? (box.maxWidth - 24) / 3 : (box.maxWidth - 12) / 2;
            return Wrap(spacing: 12, runSpacing: 12, children: [
              for (final pair in [(users, 'Concurrent Users'), (rps, 'Requests Per Second'), (duration, 'Test Duration (s)'),
                (timeout, 'Request Timeout (s)'), (ramp, 'Ramp-up Duration (s)')]) SizedBox(width: width, child: field(pair.$1, pair.$2)),
            ]);
          }),
          CheckboxListTile(contentPadding: EdgeInsets.zero, value: authorized,
            title: const LText('I own or administer this laboratory server and authorize this test.'),
            onChanged: busy || loading ? null : (v) => setState(() => authorized = v ?? false)),
          if (loading) const LinearProgressIndicator(),
          if (coolingDown) Text('${tr(context, 'Cooldown until')}: ${cooldown!.toLocal()}', style: const TextStyle(color: Colors.orangeAccent)),
          Wrap(spacing: 10, runSpacing: 10, children: [
            OutlinedButton.icon(onPressed: busy || loading || !authorized || coolingDown ? null : verify,
              icon: const Icon(Icons.verified_user_outlined), label: const LText('Verify laboratory permit')),
            FilledButton.icon(onPressed: busy || loading || !authorized || permit == null || invalid != null || coolingDown ? null : run,
              icon: const Icon(Icons.play_arrow), label: const LText('Start load test')),
            if (control != null) FilledButton.icon(style: FilledButton.styleFrom(backgroundColor: Colors.red.shade700),
              onPressed: () => setState(() => control?.stop()), icon: const Icon(Icons.stop), label: const LText('Stop immediately')),
          ]),
          if (busy) const Padding(padding: EdgeInsets.only(top: 12), child: LinearProgressIndicator()),
          if (error != null) Padding(padding: const EdgeInsets.only(top: 10), child: LText(error!, style: const TextStyle(color: Colors.orangeAccent))),
          if (!busy && invalid != null) Padding(padding: const EdgeInsets.only(top: 8), child: LText(invalid, style: const TextStyle(color: Colors.orangeAccent))),
        ])),
        card(Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Row(children: [Icon(Icons.speed, color: risk == null ? Colors.grey : riskColor(risk)), const SizedBox(width: 10),
            Expanded(child: LText(risk == null ? 'Verify the server permit to calculate risk.' : riskLabel(risk),
              style: TextStyle(color: risk == null ? Colors.white70 : riskColor(risk), fontWeight: FontWeight.bold, fontSize: 18)))]),
          const SizedBox(height: 8), const LText('Risk uses declared server capacity and observed response latency. Red warns of disruption; administrator ceilings remain mandatory.'),
          if (permit != null) ...[
            const SizedBox(height: 10), Text('${permit!.environment} · ${permit!.permitId} · ${permit!.pinnedAddress}', style: const TextStyle(fontFamily: 'monospace', color: accent)),
            Text('${tr(context, 'Administrator ceilings')}: ${permit!.maxUsers} users · ${permit!.maxRps} RPS · ${permit!.maxDurationSeconds}s · ${permit!.maxTotalRequests} requests'),
            Text('${tr(context, 'Declared capacity')}: ${permit!.capacityUsers} users · ${permit!.capacityRps} RPS · ${permit!.baselineLatencyMs} ms'),
          ],
        ])),
        card(Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          const LText('Live performance dashboard', style: TextStyle(fontSize: 18, color: accent)), const SizedBox(height: 16),
          Wrap(spacing: 14, runSpacing: 16, children: [
            metric('Total Requests', '${value?.sent ?? 0}'), metric('Successful Requests', '${value?.successful ?? 0}', color: Colors.greenAccent),
            metric('Failed Requests', '${value?.failed ?? 0}', color: Colors.orangeAccent), metric('Cancelled requests', '${value?.cancelled ?? 0}', color: Colors.white60),
            metric('Average Response Time', '${(value?.averageMs ?? 0).toStringAsFixed(1)} ms'),
            metric('P95 / P99 Latency', '${(value?.p95Ms ?? 0).round()} / ${(value?.p99Ms ?? 0).round()} ms'),
            metric('Requests Per Second', (value?.rps ?? 0).toStringAsFixed(2)), metric('Elapsed Time', '${(value?.elapsedSeconds ?? 0).toStringAsFixed(1)} s'),
            metric('Active requests', '${value?.inFlight ?? 0}'),
          ]),
          const SizedBox(height: 12), const LText('Latency is measured to response headers. Timeouts and cancellations are counted separately.'),
          const SizedBox(height: 16), const LText('Live Performance Chart'),
          SizedBox(height: 170, child: CustomPaint(painter: _LoadChart(List.of(timeline), latency: true), child: const SizedBox.expand())),
          const LText('P95 latency (ms)'),
          SizedBox(height: 110, child: CustomPaint(painter: _LoadChart(List.of(timeline), latency: false), child: const SizedBox.expand())),
          const LText('Completed requests per second'), const SizedBox(height: 12), const LText('HTTP Status Codes'),
          Wrap(spacing: 8, runSpacing: 4, children: [for (final entry in (value?.statuses ?? <String, int>{}).entries)
            Chip(label: Text('${entry.key}: ${entry.value}'), side: BorderSide(color: entry.key == '429' || entry.key == '503' ? Colors.orangeAccent : accent.withValues(alpha: .3)))]),
        ])),
        if (result != null && report != null) card(Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Text('${tr(context, 'Stop reason')}: ${tr(context, result!.reason)}', style: const TextStyle(fontSize: 18, color: accent)),
          Wrap(spacing: 10, children: [for (final type in ['json', 'pdf']) OutlinedButton.icon(
            onPressed: saving || busy ? null : () => export(type, result!), icon: const Icon(Icons.download), label: Text(type.toUpperCase()))]),
          const SizedBox(height: 8), const LText('Resilience recommendations'),
          for (final text in report.recommendations) Padding(padding: const EdgeInsets.only(top: 8), child: LText(text)),
          const SizedBox(height: 12), LText(LoadTestReport.limitation, style: const TextStyle(color: Colors.white60)),
          if (history.isNotEmpty) DropdownButtonFormField<int>(key: ValueKey('${result!.startedAt}.$baseline'), initialValue: baseline, isExpanded: true,
            decoration: const InputDecoration(label: LText('Comparison baseline')),
            items: [for (var i = 0; i < history.length; i++) if (history[i].startedAt != result!.startedAt)
              DropdownMenuItem(value: i, child: Text(history[i].startedAt.toLocal().toString()))], onChanged: busy ? null : (v) => setState(() => baseline = v)),
          if (previous != null) ...[
            LText(report.comparableTo(previous) ? 'Equivalent configuration; server and network state must also match.' : 'Configurations differ; differences are descriptive only.'),
            for (final entry in report.differences(previous).entries) Text('${tr(context, entry.key)}: ${entry.value >= 0 ? '+' : ''}${entry.value.toStringAsFixed(2)}'),
          ],
        ])),
        card(Column(crossAxisAlignment: CrossAxisAlignment.start, children: [const LText('Load-test history', style: TextStyle(color: accent, fontSize: 18)),
          for (final item in history) ListTile(title: Text(item.config.target.toString()),
            subtitle: Text('${item.startedAt.toLocal()} · ${item.summary.sent} requests · ${item.reason}'),
            trailing: const Icon(Icons.chevron_right, color: accent),
            onTap: busy ? null : () => setState(() { result = item; live = item.summary; timeline..clear()..addAll(item.samples); baseline = null; })),
        ])),
        _setupGuide(),
      ]),
    )));
  }
  Widget _setupGuide() => card(ExpansionTile(tilePadding: EdgeInsets.zero, title: const LText('Administrator setup'), children: [
    const LText('Serve JSON at /.well-known/odin-load-test on the target origin. Echo the challenge query value. Declare local or staging, exact allowed GET paths, approved server IP addresses, expiry, capacity and hard ceilings. The app re-verifies the permit before every run. HTTPS is mandatory outside loopback.'),
    const SizedBox(height: 10),
    SelectableText(const JsonEncoder.withIndent('  ').convert({
      'schemaVersion': 1, 'purpose': 'odinsecurity-load-test', 'challenge': '<echo request query challenge>',
      'origin': 'https://staging.example.test', 'environment': 'staging', 'permitId': 'staging-admin-v1',
      'allowedAddresses': ['<actual pinned server IP>'], 'allowedPaths': ['/load-test/health'],
      'expiresAt': '<UTC ISO time, valid for the run, at most one hour from now>',
      'maxConcurrentUsers': 10, 'maxRps': 20, 'maxDurationSeconds': 120, 'maxTimeoutSeconds': 10,
      'maxTotalRequests': 2400, 'capacityUsers': 5, 'capacityRps': 10, 'baselineLatencyMs': 100,
      'stopLatencyMs': 2000, 'stopErrorPercent': 20, 'minimumSamples': 20,
    }), style: const TextStyle(fontFamily: 'monospace', fontSize: 11), textDirection: TextDirection.ltr),
    const SizedBox(height: 10), const LText('Application envelope: at most 50 concurrent users, 100 RPS, 600 seconds, 30-second timeout and 30,000 requests. The administrator may authorize lower ceilings. No credentials, proxies, redirects or retries are used.'),
  ]));
}

class _LoadChart extends CustomPainter {
  final List<LoadSnapshot> samples;
  final bool latency;
  _LoadChart(this.samples, {required this.latency});
  @override
  void paint(Canvas canvas, Size size) {
    final grid = Paint()..color = const Color(0xff20364c)..strokeWidth = 1;
    for (var row = 1; row <= 4; row++) {
      final y = size.height * row / 5;
      canvas.drawLine(Offset(0, y), Offset(size.width, y), grid);
    }
    if (samples.length < 2) return;
    final maxTime = math.max(1.0, samples.last.elapsedSeconds);
    final maxValue = samples.map((s) => latency ? s.p95Ms : s.rps).fold<double>(1, (a, b) => a > b ? a : b);
    final path = Path();
    for (var i = 0; i < samples.length; i++) {
      final x = samples[i].elapsedSeconds / maxTime * size.width;
      final y = size.height - (latency ? samples[i].p95Ms : samples[i].rps) / maxValue * (size.height - 20);
      if (i == 0) { path.moveTo(x, y); } else { path.lineTo(x, y); }
    }
    canvas.drawPath(path, Paint()..color = latency ? const Color(0xff3de4cf) : const Color(0xffb795ff)..strokeWidth = 2..style = PaintingStyle.stroke);
    final label = TextPainter(text: TextSpan(text: '${maxValue.toStringAsFixed(1)} ${latency ? 'ms' : 'RPS'}',
      style: const TextStyle(color: Colors.white60, fontSize: 10)), textDirection: TextDirection.ltr)..layout();
    label.paint(canvas, const Offset(4, 2));
    final startTime = TextPainter(text: const TextSpan(text: '0s', style: TextStyle(color: Colors.white54, fontSize: 9)),
      textDirection: TextDirection.ltr)..layout();
    final endTime = TextPainter(text: TextSpan(text: '${maxTime.toStringAsFixed(1)}s',
      style: const TextStyle(color: Colors.white54, fontSize: 9)), textDirection: TextDirection.ltr)..layout();
    startTime.paint(canvas, Offset(4, size.height - startTime.height));
    endTime.paint(canvas, Offset(size.width - endTime.width - 4, size.height - endTime.height));
  }
  @override
  bool shouldRepaint(covariant _LoadChart oldDelegate) => oldDelegate.samples != samples || oldDelegate.latency != latency;
}
