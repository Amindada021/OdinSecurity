import 'package:flutter_test/flutter_test.dart';
import 'package:odin_security/core/fingerprint.dart';
import 'package:odin_security/core/frame_protection_review.dart';
import 'package:odin_security/core/html_security_checks.dart';

void main(){
  List<String> inspect(Map<String,List<String>> headers)=>FrameProtectionReview.inspect(
    HttpObservation(headers:{'content-type':['text/html'],...headers},body:'')).map((f)=>f.id).toList();
  test('recognized restrictive headers have no extra frame observation',(){
    expect(inspect({'x-frame-options':['DENY'],'content-security-policy':["frame-ancestors 'none'"]}),isEmpty);
  });
  test('ambiguous, broad and report-only policies are distinct',(){
    expect(inspect({'x-frame-options':['ALLOW-FROM fixture'],'content-security-policy':["frame-ancestors *"]}),
      containsAll(['frame.xfo.invalid','frame.csp.broad']));
    expect(inspect({'content-security-policy':["frame-ancestors 'none' *"]}),contains('frame.csp.ambiguous'));
    expect(inspect({'content-security-policy-report-only':["frame-ancestors 'none'"]}),contains('frame.report.only'));
    expect(inspect({'content-security-policy':["frame-ancestors 'none'","default-src 'self'"]}),contains('frame.csp.complex'));
  });
  test('markup observations do not execute or include inline contents',(){
    final result=HtmlSecurityChecks.inspect(Uri.parse('https://example.test'),'''
      <iframe srcdoc="fixture-secret"></iframe>
      <iframe srcdoc="fixture-secret" sandbox="allow-scripts allow-same-origin"></iframe>
      <meta http-equiv="Content-Security-Policy" content="frame-ancestors 'none'">
    ''');
    expect(result.map((f)=>f.id),containsAll(['html.dom.srcdoc.sandbox','html.dom.sandbox.combination','html.frame.meta']));
    expect(result.every((f)=>!f.evidence.contains('fixture-secret')),isTrue);
  });
}
