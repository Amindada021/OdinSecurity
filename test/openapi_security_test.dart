import 'dart:convert';
import 'package:flutter_test/flutter_test.dart';
import 'package:odin_security/core/openapi_inventory.dart';

void main() {
  test('operation-level auth overrides root and unknown schemes are flagged', () {
    final source = jsonEncode({
      'openapi': '3.0.3',
      'components': {'securitySchemes': {'bearer': {'type': 'http', 'scheme': 'bearer'}}},
      'security': [{'bearer': []}],
      'servers': [{'url': 'https://example.test'}],
      'paths': {
        '/protected': {'get': {'responses': {'401': {}}}},
        '/public': {'get': {'security': []}},
        '/optional': {'get': {'security': [{}, {'bearer': []}]}},
        '/invalid': {'get': {'security': [{'other': []}]}},
        '/legacy': {'servers': [{'url': 'http://example.test'}], 'get': {}},
        '/overridden': {'servers': [{'url': 'http://example.test'}], 'get': {'servers': [{'url': 'https://example.test'}]}},
      }
    });
    final ops = OpenApiInventory().parse(source);
    expect(ops.map((o) => o.security), [
      ApiSecurityDeclaration.authRequired, ApiSecurityDeclaration.anonymousAllowed,
      ApiSecurityDeclaration.anonymousAllowed, ApiSecurityDeclaration.invalid,
      ApiSecurityDeclaration.authRequired, ApiSecurityDeclaration.authRequired,
    ]);
    expect(ops.first.authErrorDocumented, isTrue);
    expect(ops[4].httpDeclared, isTrue);
    expect(ops[5].httpDeclared, isFalse);
  });
  test('Swagger without auth declaration is distinct from anonymous override', () {
    final source = jsonEncode({'swagger': '2.0', 'schemes': ['http'], 'paths': {
      '/one': {'get': {}}, '/two': {'get': {'security': [], 'schemes': ['https']}},
    }});
    final ops = OpenApiInventory().parse(source);
    expect(ops.first.security, ApiSecurityDeclaration.unspecified);
    expect(ops.first.httpDeclared, isTrue);
    expect(ops.last.security, ApiSecurityDeclaration.anonymousAllowed);
    expect(ops.last.httpDeclared, isFalse);
  });
}
