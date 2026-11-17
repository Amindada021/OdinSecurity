import 'project.dart';
import 'scan_policy.dart';

class QueueObservation {
  final Uri target;
  final int? status;
  const QueueObservation(this.target, this.status);
}

/// A foreground-only bounded batch of explicitly registered GET
/// assessments. Parallelism is at most two, and never on the same origin.
class AssessmentQueue {
  static const maxTargets = 3;
  static List<Uri> validate(SecurityProject project, ScanPolicy policy, Iterable<Uri> proposed, {required bool authorized}) {
    if (!authorized) throw StateError('Approval required.');
    final targets = proposed.toList();
    if (targets.isEmpty || targets.length > maxTargets || !policy.allowsCount(targets.length) ||
        targets.toSet().length != targets.length || targets.any((u) =>
          u.scheme != 'https' || !project.targets.contains(u) || !policy.permits(u))) {
      throw StateError('Invalid queue.');
    }
    return List.unmodifiable(targets);
  }

  static Future<List<QueueObservation>> run(SecurityProject project, ScanPolicy policy, Iterable<Uri> proposed,
      {required bool authorized, required bool parallel, required bool Function() cancelled,
      required Future<int> Function(Uri) fetch, Future<void> Function(Duration)? wait,
      void Function(QueueObservation)? onCompleted, bool Function(Uri)? authenticated}) async {
    final pending = validate(project, policy, proposed, authorized: authorized).toList();
    final result = <QueueObservation>[];
    final delay = wait ?? ((Duration value) => Future<void>.delayed(value));
    while (pending.isNotEmpty && !cancelled()) {
      final first = pending.removeAt(0);
      final batch = [first];
      if (parallel) {
        final other = pending.indexWhere((u) => !SecurityProject.sameOrigin(first, u));
        if (other >= 0) batch.add(pending.removeAt(other));
      }
      final completed = await Future.wait(batch.map((u) async {
        if (cancelled()) return null;
        int? status;
        try { status = await fetch(u); } catch (_) { /* No response payload retained here. */ }
        final item = QueueObservation(u, status);
        onCompleted?.call(item);
        return item;
      }));
      result.addAll(completed.whereType<QueueObservation>());
      // Do not start another batch after rate limiting or a server error.
      if (completed.whereType<QueueObservation>().any((o) => o.status == null || o.status == 429 || o.status! >= 500 ||
          (authenticated?.call(o.target) == true && [401, 403].contains(o.status)))) break;
      if (pending.isNotEmpty && !cancelled()) await delay(Duration(milliseconds: policy.delayMs));
    }
    return List.unmodifiable(result);
  }
}
