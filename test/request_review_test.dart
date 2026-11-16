import 'package:flutter_test/flutter_test.dart';
import 'package:odin_security/core/manual_request.dart';
import 'package:odin_security/core/project.dart';
import 'package:odin_security/core/request_review.dart';
import 'package:odin_security/core/scan_policy.dart';

void main() {
  final project = SecurityProject(name: 'Fixture', url: 'https://example.test/');
  final policy = ScanPolicy(excludedPaths: ['/private']);
  test('review locks the exact URL, method, and Accept', () {
    final review = RequestReview.prepare(project, 'https://example.test/items?page=2', 'GET', ManualAccept.json, policy);
    expect(review.target.query, 'page=2');
    expect(review.method, 'GET');
    expect(review.accept, ManualAccept.json);
    expect(review.authenticated, false);
    expect(() => review.validate(project, policy, approved: false), throwsStateError);
    expect(() => review.validate(project, policy, approved: true), returnsNormally);
  });
  test('review rejects out of scope and excluded routes', () {
    expect(() => RequestReview.prepare(project, 'https://other.test/', 'GET', ManualAccept.any, policy), throwsStateError);
    expect(() => RequestReview.prepare(project, 'https://example.test/private/items', 'GET', ManualAccept.any, policy), throwsStateError);
    expect(() => RequestReview.prepare(project, 'https://example.test/', 'POST', ManualAccept.any, policy), throwsFormatException);
  });
  test('a new scope policy invalidates an already reviewed request', () {
    final review = RequestReview.prepare(project, 'https://example.test/items', 'HEAD', ManualAccept.any, policy);
    expect(() => review.validate(project, ScanPolicy(excludedPaths: ['/items']), approved: true), throwsStateError);
  });
}
