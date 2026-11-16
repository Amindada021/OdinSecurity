import 'package:flutter_test/flutter_test.dart';
import 'package:odin_security/core/graphql_inventory.dart';

void main() {
  test('reads query, mutation, and subscription names offline', () {
    final result = GraphQlInventory.parse('''
{"data":{"__schema":{
"queryType":{"name":"Query"},"mutationType":{"name":"Mutation"},"subscriptionType":{"name":"Subscription"},
"types":[
{"name":"Query","fields":[{"name":"items","args":[{"name":"id"}]}]},
{"name":"Mutation","fields":[{"name":"updateItem","args":[]}]},
{"name":"Subscription","fields":[{"name":"itemChanged","args":[]}]},
{"name":"Item","fields":[{"name":"title","args":[]}]}
]}}}''');
    expect(result.map((f) => f.operation), GraphQlOperation.values);
    expect(result.map((f) => f.name), ['items', 'updateItem', 'itemChanged']);
    expect(result.first.argumentCount, 1);
  });
  test('rejects malformed and oversized responses', () {
    expect(() => GraphQlInventory.parse('{}'), throwsFormatException);
    expect(() => GraphQlInventory.parse('{"__schema":{"queryType":{"name":"Query"},"types":[]}}'), throwsFormatException);
    expect(() => GraphQlInventory.parse(List.filled(GraphQlInventory.maxChars + 1, 'x').join()), throwsFormatException);
  });
}
