import 'manual_request.dart';
import 'project.dart';
import 'scan_policy.dart';
import 'response_matrix_analysis.dart';

class RepresentationObservation {
  final ManualAccept accept;
  final int status, bodyBytes, elapsedMs;
  final bool truncated;
  final int? expectedStatus;
  const RepresentationObservation(this.accept, this.status, this.bodyBytes, this.elapsedMs, this.truncated, {this.expectedStatus});
  ResponseMetrics get metrics => ResponseMetrics(status:status,bodyBytes:bodyBytes,elapsedMs:elapsedMs,
    truncated:truncated,expectedStatus:expectedStatus);
  bool? get matchesExpectation => expectedStatus == null ? null : status == expectedStatus;
}

class RepresentationMatrix {
  final Future<ManualResponse> Function(ManualAccept) send;
  final Future<void> Function(Duration) wait;
  RepresentationMatrix({required this.send, Future<void> Function(Duration)? wait})
    : wait = wait ?? Future<void>.delayed;

  static void validate(SecurityProject project, ScanPolicy policy, Uri target, Iterable<ManualAccept> values, bool authorized) {
    final modes = values.toList();
    if (!authorized || target.scheme != 'https' || !project.targets.contains(target) || !policy.permits(target) ||
        target.hasQuery || target.hasFragment || target.userInfo.isNotEmpty || target.toString().length > 2048 ||
        modes.isEmpty || !policy.allowsCount(modes.length) || modes.toSet().length != modes.length ||
        modes.length > ManualAccept.values.length) throw StateError('Invalid representation matrix.');
  }

  /// Only fixed, ordinary Accept values on an explicit staging GET route.
  /// Never retains response bodies, custom payloads, or credentials.
  Future<List<RepresentationObservation>> run(SecurityProject project, ScanPolicy policy, Uri target,
      Iterable<ManualAccept> values, {required bool authorized, required bool Function() cancelled, Map<ManualAccept,int> expected = const {}, void Function(RepresentationObservation)? onCompleted}) async {
    final modes = List<ManualAccept>.of(values);
    validate(project, policy, target, modes, authorized);
    if (expected.entries.any((e) => !modes.contains(e.key) || e.value < 100 || e.value > 599)) throw const FormatException('Invalid status expectation.');
    final assertions = Map<ManualAccept,int>.unmodifiable(expected);
    final result = <RepresentationObservation>[];
    for (final mode in modes) {
      if (cancelled()) break;
      if (result.isNotEmpty) await wait(Duration(milliseconds: policy.delayMs));
      if (cancelled()) break;
      final response = await send(mode);
      final checked = ResponseMetrics(status: response.status, bodyBytes: response.bodyBytes,
        elapsedMs: response.elapsedMs, truncated: response.truncated, expectedStatus: assertions[mode]);
      final item = RepresentationObservation(mode, checked.status, checked.bodyBytes, checked.elapsedMs,
        checked.truncated, expectedStatus: checked.expectedStatus);
      result.add(item);
      onCompleted?.call(item);
      if (response.status == 429 || response.status >= 500 || [401,403].contains(response.status) ||
          response.status >= 300 && response.status < 400) break;
    }
    return List.unmodifiable(result);
  }
}
