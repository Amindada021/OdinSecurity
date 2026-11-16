import 'dart:convert';
import 'package:flutter_test/flutter_test.dart';
import 'package:odin_security/core/external_findings.dart';
import 'package:odin_security/core/project.dart';
import 'package:odin_security/core/scan_policy.dart';
import 'package:odin_security/core/security_checks.dart';

void main() {
  final project=SecurityProject(name:'Fixture',url:'https://example.test');
  Map<String,String> row(String url)=>{'url':url,'source':'fixture','code':'check.1','severity':'medium'};
  test('scope and query sanitization plus deduplication',(){
    final raw=jsonEncode([row('https://example.test/a?secret=x'),row('https://example.test/a?secret=y'),row('https://other.test/a')]);
    final result=ExternalFindings.parse(project,ScanPolicy(),raw,authorized:true);
    expect(result,hasLength(1));expect(result.single.route.query,isEmpty);
    expect(result.single.reportedSeverity,Severity.medium);
    expect(ExternalFindings.parse(project,ScanPolicy(excludedPaths:['/a']),raw,authorized:true),isEmpty);
  });
  test('reject raw evidence or unknown severity and require authorization',(){
    expect(()=>ExternalFindings.parse(project,ScanPolicy(),jsonEncode([{...row('https://example.test'),'evidence':'restricted'}]),authorized:true),throwsFormatException);
    expect(()=>ExternalFindings.parse(project,ScanPolicy(),jsonEncode([{...row('https://example.test'),'severity':'unknown'}]),authorized:true),throwsFormatException);
    expect(()=>ExternalFindings.parse(project,ScanPolicy(),'[]',authorized:false),throwsStateError);
  });
}
