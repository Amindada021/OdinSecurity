import 'package:flutter_test/flutter_test.dart';
import 'package:odin_security/core/configuration_review.dart';
import 'package:odin_security/core/project.dart';
import 'package:odin_security/core/scan_policy.dart';
import 'package:odin_security/core/tls_audit.dart';
import 'package:odin_security/core/passive_scan.dart';
import 'package:odin_security/core/cors_audit.dart';

void main() {
  final p = SecurityProject(name:'Fixture', url:'https://example.test/a');
  final policy = ScanPolicy();
  PassiveScanResult page(int code) => PassiveScanResult(url:p.startUrl, statusCode:code, links:[], findings:[], technologies:[], bodyTruncated:false, redirectNotFollowed:false);
  test('runs only approved stages and stops before preflight on failed control', () async {
    final called = <String>[];
    final suite = ConfigurationReview(tls: (_) async { called.add('tls'); return const TlsAuditResult(TlsStatus.trusted); },
      read: (_) async { called.add('get'); return page(429); },
      preflight: (_) async { called.add('cors'); return const CorsAuditResult(200,CorsOutcome.wildcard,true); }, wait: (_) async {});
    final result = await suite.run(p, policy, p.startUrl, authorized:true, includeCors:true, cancelled:() => false);
    expect(result.stop, 'control_not_successful');
    expect(called, ['tls','get']);
  });
  test('rejected TLS and cancellation stop all later work', () async {
    final suite = ConfigurationReview(tls: (_) async => const TlsAuditResult(TlsStatus.handshakeRejected),
      read: (_) async => throw StateError('unexpected'), preflight: (_) async => throw StateError('unexpected'), wait: (_) async {});
    expect((await suite.run(p,policy,p.startUrl,authorized:true,includeCors:true,cancelled:()=>false)).stop, 'tls_failed');
    expect((await suite.run(p,policy,p.startUrl,authorized:true,includeCors:true,cancelled:()=>true)).stop, 'cancelled');
    expect(() => ConfigurationReview.validate(p,policy,p.startUrl.resolve('/other'),true,false), throwsStateError);
    expect(() => ConfigurationReview.validate(p,ScanPolicy(maxPages:1),p.startUrl,true,true), throwsStateError);
  });
}
