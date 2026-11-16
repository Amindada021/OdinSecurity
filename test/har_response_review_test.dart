import 'dart:convert';
import 'package:flutter_test/flutter_test.dart';
import 'package:odin_security/core/har_response_review.dart';
import 'package:odin_security/core/custom_rules.dart';
import 'package:odin_security/core/metadata_rule_program.dart';
import 'package:odin_security/core/project.dart';
import 'package:odin_security/core/scan_policy.dart';

void main() {
  final p = SecurityProject(name:'Fixture', url:'https://example.test');
  Map<String,dynamic> entry(String url) => {'request':{'url':url,'headers':[{'name':'Authorization','value':'fixture-secret'}]},
    'response':{'status':200,'headers':[{'name':'Content-Type','value':'text/html'},{'name':'Server','value':'nginx/1.2.3'},
      {'name':'Set-Cookie','value':'session=fixture-secret'}],
      'content':{'text':'<html><form action="http://example.test"><input type="password"></form></html>'}}};
  test('scoped sanitized response review never returns query or raw values', () {
    final raw = jsonEncode({'log':{'entries':[entry('https://example.test/a?q=fixture-secret'),entry('https://other.test/a')]}});
    final result = HarResponseReview.parse(p,ScanPolicy(),raw,authorized:true,includeBody:true);
    expect(result,hasLength(1));
    expect(result.single.route.query,isEmpty);
    expect(result.single.bodyReviewed,isTrue);
    expect(result.single.findings.map((r)=>r.id),contains('html.form.http'));
    expect(result.single.technologies.first.observedVersion,'1.2.3');
    expect(result.single.findings.every((r)=>!r.evidence.contains('fixture-secret')),isTrue);
  });
  test('compatible declarative rules run on imported response metadata', () {
    final raw = jsonEncode({'log':{'entries':[entry('https://example.test/a')]}});
    final rules=CustomHeaderRules.parse('strict-transport-security|present');
    final found=HarResponseReview.parse(p,ScanPolicy(),raw,authorized:true,includeBody:false,rules:rules);
    expect(found.single.findings.map((r)=>r.id),contains('custom.strict-transport-security.present'));
  });
  test('metadata program combines status and missing header in scoped HAR', () {
    final program=MetadataRuleProgram.parse('{"schema":"odin.security.metadata.v1","rules":[{"id":"missing-hsts","match":"all","conditions":[{"op":"statusRange","min":200,"max":299},{"op":"headerAbsent","header":"strict-transport-security"}]}]}');
    final raw=jsonEncode({'log':{'entries':[entry('https://example.test/a'),entry('https://other.test/a')]}});
    final results=HarResponseReview.parse(p,ScanPolicy(),raw,authorized:true,includeBody:false,program:program);
    expect(results,hasLength(1));
    expect(results.single.findings.map((r)=>r.id),contains('program.missing-hsts'));
  });
  test('body inspection is opt-in and scope exclusions apply', () {
    final raw = jsonEncode({'log':{'entries':[entry('https://example.test/a')]}});
    expect(HarResponseReview.parse(p,ScanPolicy(),raw,authorized:true,includeBody:false).single.bodyReviewed,isFalse);
    expect(HarResponseReview.parse(p,ScanPolicy(excludedPaths:['/a']),raw,authorized:true,includeBody:true),isEmpty);
    expect(()=>HarResponseReview.parse(p,ScanPolicy(),raw,authorized:false,includeBody:false),throwsStateError);
  });
}
