import 'dart:convert';
import 'package:flutter_test/flutter_test.dart';
import 'package:odin_security/core/response_matrix_analysis.dart';

void main() {
  ResponseMetrics metric(int status,int bytes,int ms,{bool truncated=false,int? expected})=>
    ResponseMetrics(status:status,bodyBytes:bytes,elapsedMs:ms,truncated:truncated,expectedStatus:expected);
  String document(List cases)=>jsonEncode({'schema':'odin.security.response-metrics.v1','cases':cases});
  final valid={'status':200,'bodyBytes':100,'elapsedMs':20,'truncated':false};
  test('signed deltas, tolerance and baseline choice',(){
    final samples=[metric(200,1000,200),metric(200,1200,250),metric(404,800,600,expected:200)];
    final rows=ResponseMatrixAnalysis.compare(samples,0,sizeTolerance:200,timeToleranceMs:50);
    expect(rows[1].sizeDelta,200);
    expect(rows[1].differs,isFalse);
    expect(rows[2].statusChanged,isTrue);
    expect(rows[2].sizeDelta,-200);
    expect(rows[2].timeDeltaMs,400);
    expect(rows[2].sample.matchesExpectation,isFalse);
    expect(ResponseMatrixAnalysis.compare(samples,2).first.timeDeltaMs,-400);
  });
  test('truncated response sizes are never compared',(){
    final rows=ResponseMatrixAnalysis.compare([metric(200,100,20),metric(200,10,20,truncated:true)],0);
    expect(rows.last.sizeDelta,isNull);
    expect(rows.last.differs,isFalse);
    expect(ResponseMatrixAnalysis.compare([metric(200,100,20,truncated:true),metric(200,10,20)],0).last.sizeDelta,isNull);
  });
  test('strict parser rejects raw content and invalid metrics',(){
    expect(ResponseMatrixAnalysis.parse(document([valid])).single.bodyBytes,100);
    expect(()=>ResponseMatrixAnalysis.parse(document([{...valid,'body':'fixture'}])),throwsFormatException);
    expect(()=>ResponseMatrixAnalysis.parse(document([{...valid,'status':999}])),throwsFormatException);
    expect(()=>ResponseMatrixAnalysis.parse(document([{...valid,'elapsedMs':-1}])),throwsFormatException);
    expect(()=>ResponseMatrixAnalysis.parse(document([{...valid,'expectedStatus':null}])),throwsFormatException);
    expect(()=>ResponseMatrixAnalysis.parse(document(List.filled(101,valid))),throwsFormatException);
    expect(()=>ResponseMatrixAnalysis.compare([metric(200,0,0)],1),throwsFormatException);
  });
}
