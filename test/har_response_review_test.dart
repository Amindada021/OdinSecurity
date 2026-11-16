import 'dart:convert';
import 'package:flutter_test/flutter_test.dart';
import 'package:odin_security/core/har_response_review.dart';
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
  test('body inspection is opt-in and scope exclusions apply', () {
    final raw = jsonEncode({'log':{'entries':[entry('https://example.test/a')]}});
    expect(HarResponseReview.parse(p,ScanPolicy(),raw,authorized:true,includeBody:false).single.bodyReviewed,isFalse);
    expect(HarResponseReview.parse(p,ScanPolicy(excludedPaths:['/a']),raw,authorized:true,includeBody:true),isEmpty);
    expect(()=>HarResponseReview.parse(p,ScanPolicy(),raw,authorized:false,includeBody:false),throwsStateError);
  });
}
