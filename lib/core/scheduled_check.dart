import 'package:flutter/services.dart';
import 'package:flutter/foundation.dart';
import 'project.dart';
import 'scan_policy.dart';

class ScheduledCheck {
  static const channel = MethodChannel('odin/scheduled-check');
  static const delays = [15, 60, 180];
  static void validate(SecurityProject project, ScanPolicy policy, Uri target, int minutes, {required bool authorized}) {
    if (!authorized || !delays.contains(minutes) || target.scheme != 'https' ||
        !project.targets.contains(target) || !policy.permits(target) || target.hasQuery || target.hasFragment ||
        target.userInfo.isNotEmpty || target.toString().length > 2048) throw StateError('Invalid scheduled check.');
  }
  static Future<void> schedule(SecurityProject project, ScanPolicy policy, Uri target, int minutes, {required bool authorized}) async {
    validate(project, policy, target, minutes, authorized: authorized);
    await channel.invokeMethod<void>('schedule', {'project':project.id, 'target':target.toString(), 'minutes':minutes});
  }
  static Future<Map<String, dynamic>> status() async =>
    await channel.invokeMapMethod<String, dynamic>('status') ?? {};
  static Future<void> cancelProject(String projectId) async {
    if (kIsWeb || defaultTargetPlatform != TargetPlatform.android) return;
    await channel.invokeMethod<void>('cancel', {'project':projectId});
  }
}
