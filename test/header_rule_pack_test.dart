import 'dart:convert';
import 'package:flutter_test/flutter_test.dart';
import 'package:odin_security/core/custom_rules.dart';

void main() {
  test('versioned rule pack roundtrip and merge', () {
    const a = 'strict-transport-security|present';
    const b = 'x-content-type-options|contains|nosniff';
    expect(HeaderRulePack.decode(HeaderRulePack.encode(a)), a);
    expect(HeaderRulePack.merge(a, HeaderRulePack.encode(b)), a + '\n' + b);
    expect(() => HeaderRulePack.merge(a, HeaderRulePack.encode(a)), throwsFormatException);
  });
  test('never imports scripts, arbitrary headers, embedded lines or unknown formats', () {
    String pack(String rule) => jsonEncode({'schema': 'odin.security.headers.v1', 'rules': [rule]});
    expect(() => HeaderRulePack.decode(pack('authorization|present')), throwsFormatException);
    expect(() => HeaderRulePack.decode(pack('content-type|present\nx-frame-options|present')), throwsFormatException);
    expect(() => HeaderRulePack.decode('{"schema":"other","rules":[]}'), throwsFormatException);
    expect(() => HeaderRulePack.decode('{"schema":"odin.security.headers.v1","rules":[],"script":"x"}'), throwsFormatException);
  });
}
