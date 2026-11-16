import 'dart:convert';
import 'package:flutter_test/flutter_test.dart';
import 'package:odin_security/core/test_fixtures.dart';

void main() {
  test('bounded literal synthetic variants', () {
    expect(FixtureVariants.render('sample [VALUE]', ['alpha', 'beta']), ['sample alpha', 'sample beta']);
    expect(() => FixtureVariants.render('[VALUE][VALUE]', ['a']), throwsFormatException);
    expect(() => FixtureVariants.render('[VALUE]', List.filled(21, 'a')), throwsFormatException);
  });
  test('offline correlation accepts only exact labels and sanitized metadata', () {
    final label = LabInteractionReview.newLabel();
    final other = LabInteractionReview.newLabel();
    expect(LabInteractionReview.tokenPattern.hasMatch(label), isTrue);
    Map<String, String> event(String value) => {'label': value, 'protocol': 'https', 'observedAt': '2026-01-01T00:00:00Z'};
    final matches = LabInteractionReview.match(label, jsonEncode([event(other), event(label)]));
    expect(matches.single.protocol, 'https');
    expect(() => LabInteractionReview.match(label, jsonEncode([{...event(label), 'body':'private'}])), throwsFormatException);
  });
}
