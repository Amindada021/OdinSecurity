import 'package:flutter_test/flutter_test.dart';
import 'package:odin_security/core/request_transport_trace.dart';
import 'package:odin_security/core/project.dart';
import 'package:odin_security/core/scan_policy.dart';
import 'package:odin_security/core/traffic_journal.dart';

void main() {
  final cert = PeerCertificateSummary(subject:'CN=fixture',issuer:'CN=lab',
    validFrom:DateTime.utc(2026),validUntil:DateTime.utc(2027));

  test('cumulative phase timing is monotonic and correct', () {
    final trace = RequestTransportTrace(openedMs:10,headersMs:40,completedMs:55,https:true,certificate:cert);
    expect(trace.responseHeadersWaitMs,30);
    expect(trace.bodyReadMs,15);
    expect(trace.certificate,cert);
    expect(()=>RequestTransportTrace(openedMs:40,headersMs:10,completedMs:55,https:true),throwsFormatException);
    expect(()=>RequestTransportTrace(openedMs:0,headersMs:1,completedMs:2,https:false,certificate:cert),throwsFormatException);
  });

  test('certificate display removes control and direction characters and bounds size', () {
    expect(PeerCertificateSummary.displayName('CN=a\n\u202e'), 'CN=a');
    expect(PeerCertificateSummary.displayName(List.filled(600,'a').join()).length,512);
  });

  test('session journal retains only bounded timing metadata, not certificate names', () {
    final project = SecurityProject(name:'Fixture',url:'https://example.test');
    final journal = TrafficJournal();
    final trace = RequestTransportTrace(openedMs:1,headersMs:2,completedMs:3,https:true,certificate:cert);
    journal.record(project,project.startUrl,source:'manual',method:'GET',elapsedMs:3,status:200,trace:trace);
    final saved=journal.forProject(project,ScanPolicy()).single.trace!;
    expect(saved.https,isTrue);
    expect(saved.completedMs,3);
    expect(saved.certificate,isNull);
    journal.record(project,project.startUrl,source:'manual',method:'GET',elapsedMs:4,status:200,trace:trace);
    expect(journal.forProject(project,ScanPolicy()).first.trace,isNull);
  });
}
