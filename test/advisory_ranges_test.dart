import 'dart:convert';
import 'package:flutter_test/flutter_test.dart';
import 'package:odin_security/core/advisory_review.dart';

void main() {
  final row = {'id':'CVE-2099-1234','product':'fixture/pkg','source':'https://example.test/advisory',
    'ranges':[{'introduced':'1.2.0','fixed':'1.10.0'}]};
  final catalog = AdvisoryCatalog.parse(jsonEncode([row]));
  test('numeric comparison with inclusive start and exclusive end', () {
    expect(catalog.match('fixture/pkg', '1.1.9'), isEmpty);
    expect(catalog.match('fixture/pkg', '1.2.0'), hasLength(1));
    expect(catalog.match('fixture/pkg', '1.9.12'), hasLength(1));
    expect(catalog.match('fixture/pkg', '1.10.0'), isEmpty);
    expect(catalog.match('fixture/pkg', '1.2'), isEmpty);
    expect(catalog.match('pkg', '1.2.0'), isEmpty);
  });
  test('malformed range rejected', () {
    expect(() => AdvisoryCatalog.parse(jsonEncode([{...row,'ranges':[{'introduced':'1.2.0','fixed':'1.1.0'}]}])), throwsFormatException);
    expect(() => AdvisoryCatalog.parse(jsonEncode([{...row,'ranges':[{'introduced':'1.02.0','fixed':'2.0.0'}]}])), throwsFormatException);
  });
  test('bulk inventory preserves zero-match components', () {
    final inventory = jsonEncode([{'product':'fixture/pkg','version':'1.3.0'},{'product':'other','version':'2.0.0'}]);
    final result = catalog.reviewInventory(inventory);
    expect(result, hasLength(2));
    expect(result.first.matches, hasLength(1));
    expect(result.last.matches, isEmpty);
    expect(() => catalog.reviewInventory(jsonEncode(List.filled(2, {'product':'fixture/pkg','version':'1.3.0'}))), throwsFormatException);
  });
}
