import 'dart:convert';
import 'package:flutter_test/flutter_test.dart';
import 'package:odin_security/core/metadata_rule_program.dart';
import 'package:odin_security/core/fingerprint.dart';

void main() {
  String program(List conditions, {String match = 'all'}) => jsonEncode({
    'schema': MetadataRuleProgram.schema,
    'rules': [{'id':'fixture','match':match,'conditions':conditions}],
  });
  final observation = HttpObservation(headers: {'content-type':['application/json']}, body:'private-fixture');
  final conditions = [
    {'op':'statusRange','min':200,'max':299},
    {'op':'headerAbsent','header':'strict-transport-security'},
  ];
  test('all versus any, with no raw evidence', () {
    final all = MetadataRuleProgram.parse(program(conditions));
    expect(all.inspect(observation,200).single.id,'program.fixture');
    expect(all.inspect(observation,404),isEmpty);
    expect(MetadataRuleProgram.parse(program(conditions,match:'any')).inspect(observation,404),hasLength(1));
    expect(all.inspect(observation,200).single.evidence,isNot(contains('private-fixture')));
  });
  test('exact allowed header comparison', () {
    final p = MetadataRuleProgram.parse(program([{'op':'headerEquals','header':'content-type','value':'APPLICATION/JSON'}]));
    expect(p.inspect(observation,200),hasLength(1));
  });
  test('reject unknown operations, sensitive headers and oversized rule lists', () {
    for (final c in [
      {'op':'shell','value':'fixture'},
      {'op':'headerPresent','header':'set-cookie'},
      {'op':'statusRange','min':300,'max':200},
    ]) {
      expect(()=>MetadataRuleProgram.parse(program([c])),throwsFormatException);
    }
    expect(()=>MetadataRuleProgram.parse(program(List.filled(9,conditions.first))),throwsFormatException);
  });
}
