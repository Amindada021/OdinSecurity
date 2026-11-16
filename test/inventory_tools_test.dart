import 'package:flutter_test/flutter_test.dart';
import 'package:odin_security/core/openapi_inventory.dart';
import 'package:odin_security/core/offline_tools.dart';

void main() {
  test('inventory lists declared methods without resolving remote refs', () {
    final items = OpenApiInventory().parse('{"openapi":"3.0.3","paths":{"/invoices":{"get":{"summary":"List"},"post":{},"parameters":[]},"//evil.test":{"get":{}}}}');
    expect(items.map((item) => item.method), ['GET', 'POST']);
    expect(items.first.path, '/invoices');
  });
  test('invalid specification is rejected', () {
    expect(() => OpenApiInventory().parse('{"paths":{}}'), throwsFormatException);
  });
  test('Base64 and URL round trip Unicode', () {
    const phrase = 'حسابران & Odin';
    expect(OfflineTools.decodeBase64(OfflineTools.encodeBase64(phrase)), phrase);
    expect(OfflineTools.decodeUrl(OfflineTools.encodeUrl(phrase)), phrase);
  });
  test('JWT decoding reports unverified', () {
    expect(OfflineTools.inspectJwt('eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.fixture'), contains('"verified": false'));
  });
}
