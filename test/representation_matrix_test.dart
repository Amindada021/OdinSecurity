import 'package:flutter_test/flutter_test.dart';
import 'package:odin_security/core/manual_request.dart';
import 'package:odin_security/core/representation_matrix.dart';
import 'package:odin_security/core/project.dart';
import 'package:odin_security/core/scan_policy.dart';

void main() {
  final project = SecurityProject(name:'Fixture', url:'https://example.test/a');
  final policy = ScanPolicy();
  test('requires exact target, approval and unique bounded values', () {
    expect(() => RepresentationMatrix.validate(project, policy, project.startUrl, [ManualAccept.json], false), throwsStateError);
    expect(() => RepresentationMatrix.validate(project, policy, project.startUrl.resolve('/other'), [ManualAccept.json], true), throwsStateError);
    expect(() => RepresentationMatrix.validate(project, policy, project.startUrl, [ManualAccept.json, ManualAccept.json], true), throwsStateError);
  });
  test('stop after rate limit, results retain only metadata', () async {
    final called = <ManualAccept>[];
    final matrix = RepresentationMatrix(send: (accept) async {
      called.add(accept);
      return ManualResponse(429, {}, 'fixture body', false, bodyBytes:12);
    }, wait: (_) async {});
    final results = await matrix.run(project, policy, project.startUrl, [ManualAccept.json, ManualAccept.html], authorized:true, cancelled:()=>false);
    expect(called, [ManualAccept.json]);
    expect(results.single.status, 429);
    expect(results.single.bodyBytes, 12);
  });
}
