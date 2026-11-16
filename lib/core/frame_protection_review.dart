import 'fingerprint.dart';
import 'security_checks.dart';

/// Passive header-only review. Never creates or loads a framing page.
class FrameProtectionReview {
  static List<SecurityFinding> inspect(HttpObservation observation) {
    final contentType=observation.header('content-type').split(';').first.trim().toLowerCase();
    if(contentType!='text/html' && contentType!='application/xhtml+xml') return const [];
    final findings=<SecurityFinding>[];
    final xfo=observation.headers['x-frame-options']??const <String>[];
    final policies=observation.headers['content-security-policy']??const <String>[];
    final reportOnly=observation.headers['content-security-policy-report-only']??const <String>[];
    final headers=[...xfo,...policies,...reportOnly];
    if(headers.length>200 || headers.any((v)=>v.length>16384) ||
        headers.fold<int>(0,(sum,v)=>sum+v.length)>65536) {
      return const [SecurityFinding('frame.review.limit','Framing review incomplete',Severity.info,
        'Frame policy header budget exceeded','Review framing configuration manually.')];
    }
    bool hasFrameDirective(String policy)=>policy.split(';').any((part)=>
      part.trim().split(RegExp(r'\s+')).first.toLowerCase()=='frame-ancestors');
    if(xfo.isNotEmpty && (xfo.length!=1 || !['deny','sameorigin'].contains(xfo.single.trim().toLowerCase()))) {
      findings.add(const SecurityFinding('frame.xfo.invalid','X-Frame-Options requires review',Severity.info,
        'Nonstandard, duplicate or ambiguous frame header; values omitted',
        'Use a valid DENY or SAMEORIGIN header when appropriate; review enforcing CSP.'));
    }
    if(policies.any(hasFrameDirective) && (policies.length!=1 || policies.single.contains(','))) {
      findings.add(const SecurityFinding('frame.csp.complex','Complex framing policy requires review',Severity.info,
        'Multiple or combined CSP policies contain a framing directive; effective policy not inferred',
        'Review effective frame-ancestors policy in the intended browsers.'));
      return List.unmodifiable(findings);
    }
    if(policies.length==1) {
      final directives=policies.single.split(';').map((p)=>p.trim().split(RegExp(r'\s+'))).where((p)=>
        p.isNotEmpty && p.first.toLowerCase()=='frame-ancestors').toList();
      if(directives.length>1 || (directives.length==1 && (directives.single.length<2 ||
          directives.single.skip(1).any((s)=>s.toLowerCase()=="'none'") && directives.single.length!=2))) {
        findings.add(const SecurityFinding('frame.csp.ambiguous','Frame-ancestors directive requires review',Severity.info,
          'Empty, duplicate or ambiguous framing directive; values omitted',
          'Declare one unambiguous frame-ancestors directive.'));
      } else if(directives.length==1 && directives.single.skip(1).any((s)=>['*','http:','https:'].contains(s.toLowerCase()))) {
        findings.add(const SecurityFinding('frame.csp.broad','Broad framing source observed',Severity.info,
          'Framing directive contains wildcard or scheme-wide source; values omitted',
          'Restrict framing to intended origins. Verify actual browser behavior.'));
      }
    }
    if(!policies.any(hasFrameDirective) && reportOnly.any(hasFrameDirective)) {
      findings.add(const SecurityFinding('frame.report.only','Framing directive is report-only',Severity.info,
        'Frame-ancestors is present only in report-only policy, not an enforcing CSP',
        'Review whether enforcing frame-ancestors or another appropriate protection is needed.'));
    }
    return List.unmodifiable(findings);
  }
}
