import 'dart:convert';
import 'auth.dart';
import 'assessment_queue.dart';
import 'project.dart';
import 'project_storage.dart';
import 'scan_policy.dart';

class QueueTemplate {
  final List<Uri> targets;
  final bool parallel;
  final int minutes;
  QueueTemplate(SecurityProject project, ScanPolicy policy, Iterable<Uri> targets, this.parallel, this.minutes)
      : targets = AssessmentQueue.validate(project, policy, targets, authorized: true) {
    if (![0, 1, 5, 15].contains(minutes)) throw const FormatException('Invalid delay.');
  }
  Map<String, dynamic> toJson() => {
    'targets': targets.map((u) => u.toString()).toList(),
    'parallel': parallel, 'minutes': minutes,
  };
  factory QueueTemplate.fromJson(SecurityProject project, ScanPolicy policy, Map<String, dynamic> json) {
    if (json.length != 3 || json['targets'] is! List || json['parallel'] is! bool || json['minutes'] is! int) {
      throw const FormatException('Invalid queue template.');
    }
    final targets = json['targets'] as List;
    if (targets.length > AssessmentQueue.maxTargets || targets.any((v) => v is! String)) {
      throw const FormatException('Invalid targets.');
    }
    return QueueTemplate(project, policy, targets.cast<String>().map(SecurityProject.parseTarget),
      json['parallel'] as bool, json['minutes'] as int);
  }
}

class QueueTemplateRepository {
  final ProjectStorage storage;
  QueueTemplateRepository(this.storage);
  String _key(String id) => 'odin_security.queue_template.v1.' + id;
  Future<void> save(SecurityProject project, QueueTemplate template) =>
    storage.write(_key(project.id), jsonEncode(template.toJson()));
  Future<QueueTemplate?> load(SecurityProject project, ScanPolicy policy) async {
    final data = await storage.read(_key(project.id));
    if (data == null) return null;
    if (data.length > 8192) throw const FormatException('Invalid template.');
    return QueueTemplate.fromJson(project, policy, Map<String, dynamic>.from(jsonDecode(data) as Map));
  }
}

/// Static profiles only. A selected identity that does not match must fail
/// closed rather than silently falling back to an unauthenticated request.
class QueueIdentity {
  static List<AuthProfile> eligible(Uri target, Iterable<AuthProfile> profiles) =>
    List.unmodifiable(profiles.where((p) => p.mode != AuthMode.none && !p.isLogin &&
      SecurityProject.sameOrigin(p.target, target)));
  static AuthProfile? resolve(Uri target, String name, Iterable<AuthProfile> profiles) {
    if (name.isEmpty) return null;
    final found = eligible(target, profiles).where((p) => p.name == name).toList();
    if (found.length != 1) throw StateError('Identity unavailable for target.');
    return found.single;
  }
}
