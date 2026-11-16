import 'package:flutter_test/flutter_test.dart';
import 'package:odin_security/core/advisory_review.dart';

void main() {
  const fixture = '[{"id":"CVE-2099-1234","product":"fixture","source":"https://example.test/advisory","affectedVersions":["1.2.0"]}]';
  test('only exact product and known version matches', () {
    final catalog = AdvisoryCatalog.parse(fixture);
    expect(catalog.match('FIXTURE', '1.2.0').single.id, 'CVE-2099-1234');
    expect(catalog.match('fixture', '1.2.1'), isEmpty);
    expect(catalog.match('fixture', '1.2'), isEmpty);
    expect(catalog.match('unknown', '1.2.0'), isEmpty);
    expect(() => catalog.match('fixture', '1.2.0-beta'), throwsFormatException);
  });
  test('invalid source and malformed advisory are refused', () {
    expect(() => AdvisoryCatalog.parse(fixture.replaceFirst('https:', 'file:')), throwsFormatException);
    expect(() => AdvisoryCatalog.parse(fixture.replaceFirst('CVE-2099-1234', 'unknown')), throwsFormatException);
    expect(() => AdvisoryCatalog.parse('{}'), throwsFormatException);
  });
}
