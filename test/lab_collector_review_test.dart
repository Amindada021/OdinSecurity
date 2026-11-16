import 'dart:convert';
import 'package:flutter_test/flutter_test.dart';
import 'package:odin_security/core/lab_collector_review.dart';
import 'package:odin_security/core/manual_request.dart';
import 'package:odin_security/core/project.dart';
import 'package:odin_security/core/scan_policy.dart';
import 'package:odin_security/core/test_fixtures.dart';

void main() {
  final p=SecurityProject(name:'Fixture',url:'https://collector.example.test/events');
  final label=LabInteractionReview.newLabel();
  final source=jsonEncode([{'label':label,'protocol':'https','observedAt':'2026-01-01T00:00:00Z'}]);
  test('one exact endpoint and local label correlation', () async {
    var calls=0;
    final review=LabCollectorReview(read:(u) async {
      calls++;
      expect(u,p.startUrl);
      expect(u.query,isEmpty);
      return ManualResponse(200,{'content-type':['application/json']},source,false,bodyBytes:source.length);
    });
    final result=await review.fetch(p,ScanPolicy(),p.startUrl,label,authorized:true);
    expect(result,hasLength(1));expect(calls,1);
    await expectLater(review.fetch(p,ScanPolicy(),p.startUrl.resolve('/else'),label,authorized:true),throwsStateError);
    expect(calls,1);
  });
  test('incomplete or non-JSON responses fail closed', () async {
    final review=LabCollectorReview(read:(_) async=>ManualResponse(200,{'content-type':['text/html']},source,false));
    await expectLater(review.fetch(p,ScanPolicy(),p.startUrl,label,authorized:true),throwsStateError);
  });
}
