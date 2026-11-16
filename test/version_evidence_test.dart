import 'package:flutter_test/flutter_test.dart';
import 'package:odin_security/core/fingerprint.dart';
import 'package:odin_security/core/version_evidence.dart';

void main() {
  test('constrained version declarations on recognized headers', () {
    final observation = HttpObservation(headers: {'Server':['nginx/1.25.3'], 'X-Powered-By':['PHP/8.2.14']}, body: '');
    final findings = TechnologyDetector().detect(observation);
    expect(findings.singleWhere((f) => f.name == 'Nginx').observedVersion, '1.25.3');
    expect(findings.singleWhere((f) => f.name == 'PHP').observedVersion, '8.2.14');
  });
  test('conflicting and distribution-suffixed banners not guessed', () {
    expect(VersionEvidence.forTechnology('Nginx', {'server':['nginx/1.2.3', 'nginx/1.2.4']}, ''), isNull);
    expect(VersionEvidence.forTechnology('Nginx', {'server':['nginx/1.2.3-custom']}, ''), isNull);
    expect(VersionEvidence.forTechnology('PHP', {'x-powered-by':['notPHP/8.1.0']}, ''), isNull);
  });
  test('generator recognizes only exact public version declaration', () {
    final body = '<meta content="WordPress 6.4.3" name="generator">';
    expect(VersionEvidence.forTechnology('WordPress', {}, body), '6.4.3');
    expect(VersionEvidence.forTechnology('WordPress', {}, '<meta name="generator" content="WordPress 6.4.3 secret">'), isNull);
    expect(VersionEvidence.forTechnology('WordPress', {}, '<meta name="generator" content="WordPress 6.4.3" content="WordPress 6.4.4">'), isNull);
  });
}
