import 'package:flutter_test/flutter_test.dart';
import 'package:odin_security/core/custom_rules.dart';
import 'package:odin_security/core/fingerprint.dart';

void main() {
  test('literal equals and absence checks, with omitted values', () {
    const source = 'x-powered-by|absent\nx-content-type-options|equals|nosniff';
    final rules = CustomHeaderRules.parse(source);
    expect(HeaderRulePack.decode(HeaderRulePack.encode(source)), source);
    expect(HeaderRulePack.encode(source), contains('odin.security.headers.v2'));
    expect(CustomHeaderRules.inspect(rules, HttpObservation(headers: {'x-content-type-options':['NoSniff']}, body: '')), isEmpty);
    final result = CustomHeaderRules.inspect(rules, HttpObservation(headers: {'x-powered-by':['fixture-private'],'x-content-type-options':['nosniff; other']}, body: ''));
    expect(result, hasLength(2));
    expect(result.every((r) => !r.evidence.contains('fixture-private')), isTrue);
    expect(() => CustomHeaderRules.parse('authorization|absent'), throwsFormatException);
  });
}
