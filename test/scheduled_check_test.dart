import 'package:flutter_test/flutter_test.dart';
import 'package:odin_security/core/scheduled_check.dart';
import 'package:odin_security/core/project.dart';
import 'package:odin_security/core/scan_policy.dart';

void main() {
  test('one explicitly authorized registered HTTPS target and fixed delay', () {
    final project = SecurityProject(name:'Fixture', url:'https://example.test/a');
    final policy = ScanPolicy();
    expect(() => ScheduledCheck.validate(project, policy, project.startUrl, 15, authorized:true), returnsNormally);
    expect(() => ScheduledCheck.validate(project, policy, project.startUrl, 15, authorized:false), throwsStateError);
    expect(() => ScheduledCheck.validate(project, policy, project.startUrl.resolve('/b'), 15, authorized:true), throwsStateError);
    expect(() => ScheduledCheck.validate(project, ScanPolicy(excludedPaths:['/a']), project.startUrl, 15, authorized:true), throwsStateError);
    expect(() => ScheduledCheck.validate(project, policy, project.startUrl, 1, authorized:true), throwsStateError);
  });
}
