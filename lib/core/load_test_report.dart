import 'dart:convert';
import 'dart:typed_data';
import 'package:pdf/pdf.dart';
import 'package:pdf/widgets.dart' as pw;
import 'load_test_engine.dart';
import 'load_test_policy.dart';
import 'project_storage.dart';

class LoadTestRepository {
  final ProjectStorage storage;
  LoadTestRepository(this.storage);
  String _key(String id) => 'odin_security.load_history.v1.$id';
  static const cooldownKey = 'odin_security.load_cooldowns.v1';
  Future<List<LoadTestResult>> load(String id) async {
    final raw = await storage.read(_key(id));
    if (raw == null) return [];
    return (jsonDecode(raw) as List).take(20).map((row) => LoadTestResult.fromJson(Map<String, dynamic>.from(row as Map))).toList();
  }
  Future<List<LoadTestResult>> save(String id, LoadTestResult result) async {
    if (result.cooldownUntil != null) await setCooldown(result.config.target.origin, result.cooldownUntil!);
    final rows = [result, ...await load(id)].take(20).toList();
    await storage.write(_key(id), jsonEncode(rows.map((row) => row.toJson()).toList()));
    return rows;
  }
  Future<void> saveConfig(String id, LoadTestConfig config) => storage.write('${_key(id)}.config', jsonEncode(config.toJson()));
  Future<LoadTestConfig?> loadConfig(String id) async {
    final raw = await storage.read('${_key(id)}.config');
    return raw == null ? null : LoadTestConfig.fromJson(Map<String, dynamic>.from(jsonDecode(raw) as Map));
  }
  Future<Map<String, dynamic>> _cooldowns() async {
    final raw = await storage.read(cooldownKey);
    if (raw == null) return {};
    return Map<String, dynamic>.from(jsonDecode(raw) as Map);
  }
  Future<DateTime?> cooldown(String origin) async {
    final value = (await _cooldowns())[origin];
    return value is String ? DateTime.tryParse(value) : null;
  }
  Future<void> setCooldown(String origin, DateTime until) async {
    final rows = await _cooldowns();
    rows.removeWhere((key, value) => value is! String || DateTime.tryParse(value)?.isAfter(DateTime.now()) != true);
    final old = DateTime.tryParse(rows[origin] as String? ?? '');
    rows[origin] = old != null && old.isAfter(until) ? old.toIso8601String() : until.toUtc().toIso8601String();
    await storage.write(cooldownKey, jsonEncode(rows));
  }
}

class LoadTestReport {
  final LoadTestResult result;
  LoadTestReport(this.result);
  static const limitation = 'This bounded single-client laboratory test does not prove DDoS resistance or production capacity. Latency measures time to response headers, not a complete download. Quantiles use 1 ms buckets; timeouts and cancellations are reported separately. Server CPU, memory and database metrics require independent server monitoring.';
  List<String> get recommendations => [
    if (result.summary.sent == 0) 'No test requests were emitted before stopping; no resilience conclusion is possible.',
    if ((result.summary.statuses['429'] ?? 0) > 0)
      'Rate limiting was observed. Review its threshold and Retry-After behavior with server logs; a 429 alone does not validate all rate-limiting policies.',
    if ((result.summary.statuses['503'] ?? 0) > 0)
      'Service unavailable was observed. Review worker queues, connection pools, upstream health and graceful load shedding.',
    if (result.reason == 'severe_degradation' || result.summary.p95Ms > ((result.permit['baselineLatencyMs'] as num?) ?? 1) * 2)
      'Latency or error thresholds were exceeded. Profile slow queries, blocking work, pool saturation and cache behavior before increasing load.',
    if ((result.summary.statuses['timeout'] ?? 0) > 0)
      'Inspect request timeouts alongside server-side traces. Timed-out requests are not included in the completed-response latency histogram.',
    if (result.summary.failed == 0 && result.summary.successful > 0)
      'No failure was observed at this load. Increase laboratory stages only within the administrator permit; this does not establish the server failure threshold.',
    'Compare runs with identical endpoint, configuration, permit thresholds, server state and network conditions. Correlate results with server telemetry.',
  ];
  bool comparableTo(LoadTestResult previous) => jsonEncode(result.config.toJson()) == jsonEncode(previous.config.toJson()) &&
      ['environment', 'pinnedAddress', 'capacityRps', 'capacityUsers', 'baselineLatencyMs', 'stopLatencyMs', 'stopErrorPercent',
        'maxConcurrentUsers', 'maxRps', 'maxDurationSeconds', 'maxTimeoutSeconds', 'maxTotalRequests', 'minimumSamples']
        .every((key) => result.permit[key] == previous.permit[key]);
  Map<String, double> differences(LoadTestResult previous) => {
    'Average response time (ms)': result.summary.averageMs - previous.summary.averageMs,
    'P95 latency (ms)': result.summary.p95Ms - previous.summary.p95Ms,
    'P99 latency (ms)': result.summary.p99Ms - previous.summary.p99Ms,
    'Achieved RPS': result.summary.rps - previous.summary.rps,
    'Failure rate (%)': errorPercent(result.summary) - errorPercent(previous.summary),
  };
  static double errorPercent(LoadSnapshot s) => s.successful + s.failed == 0 ? 0 : s.failed * 100 / (s.successful + s.failed);
  String exportJson() => const JsonEncoder.withIndent('  ').convert({...result.toJson(),
    'recommendations': recommendations, 'limitations': limitation});
  Future<Uint8List> exportPdf() async {
    final doc = pw.Document();
    final widgets = <pw.Widget>[];
    void line(String text, {bool heading = false}) {
      final clean = text.replaceAll(RegExp(r'[^\x20-\x7e]'), ' ');
      for (var offset = 0; offset < clean.length; offset += 90) {
        widgets.add(pw.Padding(padding: const pw.EdgeInsets.only(bottom: 4), child: pw.Text(
          clean.substring(offset, offset + 90 < clean.length ? offset + 90 : clean.length),
          style: pw.TextStyle(fontSize: heading ? 14 : 9, fontWeight: heading ? pw.FontWeight.bold : pw.FontWeight.normal))));
      }
    }
    line('OdinSecurity - Server Resilience & Load Test', heading: true);
    line('Target: ${result.config.target}');
    line('Environment: ${result.permit['environment']}; permit: ${result.permit['permitId']}');
    line('Started: ${result.startedAt.toIso8601String()}; finished: ${result.finishedAt.toIso8601String()}');
    line('Stop reason: ${result.reason}');
    line('Configuration: ${jsonEncode(result.config.toJson())}');
    line('Administrator policy: ${jsonEncode(result.permit)}');
    line('Total: ${result.summary.sent}; successful: ${result.summary.successful}; failed: ${result.summary.failed}; cancelled: ${result.summary.cancelled}');
    line('Average: ${result.summary.averageMs.toStringAsFixed(1)} ms; P95: ${result.summary.p95Ms} ms; P99: ${result.summary.p99Ms} ms; achieved RPS: ${result.summary.rps.toStringAsFixed(2)}');
    line('HTTP/error counts: ${jsonEncode(result.summary.statuses)}');
    if (result.cooldownUntil != null) line('Do not restart before: ${result.cooldownUntil!.toIso8601String()}');
    line('Recommendations', heading: true);
    for (final recommendation in recommendations) { line(recommendation); }
    line(limitation);
    if (result.samples.length > 1) {
      line('Performance timeline', heading: true);
      final maxTime = result.samples.last.elapsedSeconds;
      final maxLatency = result.samples.map((row) => row.p95Ms).fold<double>(1, (a, b) => a > b ? a : b);
      widgets.add(pw.SizedBox(height: 130, child: pw.Chart(
        grid: pw.CartesianGrid(xAxis: pw.FixedAxis([0, maxTime / 2, maxTime]), yAxis: pw.FixedAxis([0, maxLatency / 2, maxLatency])),
        datasets: [pw.LineDataSet(color: PdfColors.teal, drawPoints: false,
          data: result.samples.map((row) => pw.PointChartValue(row.elapsedSeconds, row.p95Ms)).toList())],
      )));
      line('P95 response-header latency (ms) by elapsed seconds.');
    }
    doc.addPage(pw.MultiPage(pageFormat: PdfPageFormat.a4, maxPages: 30, build: (_) => widgets));
    return doc.save();
  }
}
