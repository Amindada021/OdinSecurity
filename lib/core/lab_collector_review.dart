import 'manual_request.dart';
import 'project.dart';
import 'scan_policy.dart';
import 'test_fixtures.dart';

/// Fetches explicitly approved sanitized event metadata from a registered
/// operator-managed HTTPS collector. No event generation, target injection,
/// polling or forwarding. The label never leaves this client.
class LabCollectorReview {
  final Future<ManualResponse> Function(Uri) read;
  LabCollectorReview({required this.read});
  static void validate(SecurityProject project, ScanPolicy policy, Uri collector, String label, bool authorized) {
    if (!authorized || !project.targets.contains(collector) || !policy.permits(collector) ||
        collector.scheme != 'https' || collector.hasQuery || collector.hasFragment ||
        collector.userInfo.isNotEmpty || collector.toString().length > 2048 ||
        !LabInteractionReview.tokenPattern.hasMatch(label)) {
      throw StateError('Invalid collector review.');
    }
  }

  Future<List<LabInteraction>> fetch(SecurityProject project, ScanPolicy policy, Uri collector, String label,
      {required bool authorized}) async {
    validate(project, policy, collector, label, authorized);
    final response = await read(collector);
    if (response.status != 200 || response.truncated || response.bodyBytes > 65536 ||
        !response.headers.entries.any((e) => e.key.toLowerCase() == 'content-type' &&
          e.value.any((v) => v.split(';').first.trim().toLowerCase() == 'application/json'))) {
      throw StateError('Collector did not return complete JSON metadata.');
    }
    return LabInteractionReview.match(label, response.body);
  }
}
