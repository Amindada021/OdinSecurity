import 'dart:convert';
import 'package:flutter_test/flutter_test.dart';
import 'package:odin_security/core/contract_matrix.dart';

void main() {
  String matrix(String kind, int min, int max, List cases) => jsonEncode({
    'schema':'odin.security.contract.v1','contract':{'kind':kind,'min':min,'max':max},'cases':cases,
  });
  test('inclusive integer boundaries, strict types and mismatch reporting', () {
    final rows = ContractMatrix.run(matrix('integer',1,10,[
      {'value':0,'expected':false},{'value':1,'expected':true},
      {'value':10,'expected':true},{'value':11,'expected':true},
      {'value':'1','expected':false},{'value':null,'expected':false},
    ]));
    expect(rows.map((r)=>r.passed),[true,true,true,false,true,true]);
  });
  test('string length counts Unicode code points', () {
    expect(ContractMatrix.run(matrix('string',1,1,[{'value':'😀','expected':true}])).single.passed,isTrue);
  });
  test('reject non-scalars, invalid contracts and oversized matrices', () {
    expect(()=>ContractMatrix.run(matrix('string',-1,3,[{'value':'a','expected':true}])),throwsFormatException);
    expect(()=>ContractMatrix.run(matrix('integer',1,3,[{'value':{},'expected':false}])),throwsFormatException);
    expect(()=>ContractMatrix.run(matrix('integer',1,3,List.filled(101,{'value':1,'expected':true}))),throwsFormatException);
  });
}
