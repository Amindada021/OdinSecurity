import 'package:flutter_test/flutter_test.dart';
import 'package:odin_security/core/fingerprint.dart';

void main() {
  final detector = TechnologyDetector();

  test('independent CMS, backend and server layers', () {
    final findings = detector.detect(HttpObservation(
      headers: {'Server': ['nginx'], 'X-Powered-By': ['PHP/8.3']},
      body: '<meta name="generator" content="WordPress 6"><script src="/wp-content/a.js"></script>',
    ));
    expect(findings.any((f) => f.name == 'WordPress' && f.layer == TechnologyLayer.cms), isTrue);
    expect(findings.any((f) => f.name == 'PHP' && f.layer == TechnologyLayer.backend), isTrue);
    expect(findings.any((f) => f.name == 'Nginx' && f.layer == TechnologyLayer.server), isTrue);
  });

  test('Next.js does not imply a Node backend', () {
    final findings = detector.detect(HttpObservation(
      headers: {'x-powered-by': ['Next.js']},
      body: '<script src="/_next/static/chunk.js"></script>',
    ));
    expect(findings.single.name, 'Next.js');
    expect(findings.single.layer, TechnologyLayer.frontend);
  });

  test('ASP.NET Core and Python are evidence-based', () {
    expect(detector.detect(HttpObservation(headers: {'server': ['Kestrel']}, body: '')).any((f) => f.name == 'ASP.NET Core'), isTrue);
    expect(detector.detect(HttpObservation(headers: {'server': ['uvicorn']}, body: '')).any((f) => f.name == 'Python (likely)'), isTrue);
  });

  test('unknown is not guessed', () {
    expect(detector.detect(HttpObservation(headers: {}, body: '<html>hello</html>')), isEmpty);
  });

  test('cookie values are not copied into evidence', () {
    final findings = detector.detect(HttpObservation(headers: {'Set-Cookie': ['PHPSESSID=secret123']}, body: ''));
    expect(findings.single.evidence, isNot(contains('secret123')));
  });
}
