import 'package:flutter_test/flutter_test.dart';
import 'package:odin_security/core/manual_response_review.dart';

void main() {
  final route=Uri.parse('https://example.test/');
  test('actual header observations do not reveal raw cookies or redirect values', () {
    final rows=ManualResponseReview.inspect(route,302,{
      'Set-Cookie':['session=fixture-secret; SameSite=None'],
      'Location':['http://example.test/?token=fixture-secret'],
    },identityHeadersSent:false);
    expect(rows.map((r)=>r.id),containsAll(['cookie.secure','cookie.samesite.none.insecure','transport.redirect.http']));
    expect(rows.every((r)=>![r.title,r.evidence,r.remediation].any((s)=>s.contains('fixture-secret'))),isTrue);
  });
  test('shared cache is only noted when identity was sent', () {
    final headers={'Cache-Control':['public, max-age=120']};
    expect(ManualResponseReview.inspect(route,200,headers,identityHeadersSent:true).map((r)=>r.id),contains('cache.auth.shared'));
    expect(ManualResponseReview.inspect(route,200,headers,identityHeadersSent:false).map((r)=>r.id),isNot(contains('cache.auth.shared')));
  });
  test('excessive relevant header values fail closed with incomplete observation', () {
    final rows=ManualResponseReview.inspect(route,200,{'Set-Cookie':[List.filled(17000,'x').join()]},identityHeadersSent:false);
    expect(rows.single.id,'manual.review.limit');
  });
}
