import 'package:flutter_test/flutter_test.dart';
import 'package:odin_security/core/manual_request.dart';
import 'package:odin_security/core/project.dart';
import 'package:odin_security/core/request_history.dart';
import 'package:odin_security/core/scan_policy.dart';

void main() {
  const response = ManualResponse(200, {'secret': ['private']}, 'private response', false, elapsedMs: 50, bodyBytes: 16);
  RequestRecord record(String url, {String method = 'GET', bool auth = false, ManualAccept accept = ManualAccept.any}) =>
    RequestRecord.fromResponse(Uri.parse(url), method, accept, auth, response);

  test('history strips query and fragment values and avoids comparing query requests', () {
    final item = record('https://example.test/path?token=secret#fragment');
    expect(item.route, 'https://example.test/path');
    expect(item.hadQuery, isTrue);
    expect(item.comparableTo(record('https://example.test/path')), isFalse);
  });
  test('compare only equivalent request settings', () {
    final first = record('https://example.test/path');
    expect(first.comparableTo(record('https://example.test/path')), isTrue);
    expect(first.comparableTo(record('https://example.test/path', auth: true)), isFalse);
    expect(first.comparableTo(record('https://example.test/path', method: 'HEAD')), isFalse);
    expect(first.comparableTo(record('https://example.test/path', accept: ManualAccept.json)), isFalse);
  });
  test('manual writes and custom input are not comparable automatically', () {
    final ordinary = record('https://example.test/path');
    final custom = RequestRecord.fromResponse(Uri.parse('https://example.test/path'), 'GET', ManualAccept.any, false, response, customized: true);
    final write = record('https://example.test/path', method: 'POST');
    expect(ordinary.comparableTo(custom), isFalse);
    expect(write.comparableTo(write), isFalse);
  });
  test('comparison groups include only equivalent retained entries', () {
    final history=RequestHistory();
    final anchor=record('https://example.test/path');
    final same=record('https://example.test/path');
    history.add(anchor);
    history.add(record('https://example.test/path?key=fixture'));
    history.add(record('https://example.test/path',auth:true));
    history.add(same);
    expect(history.comparableGroup(anchor),[same,anchor]);
    expect(history.comparableGroup(record('https://example.test/path')),isEmpty);
    history.clear();
    expect(history.comparableGroup(anchor),isEmpty);
  });
  test('bounded newest-first session history', () {
    final history = RequestHistory();
    for (var i = 0; i < 30; i++) {
      history.add(record('https://example.test/path/$i'));
    }
    expect(history.records.length, RequestHistory.limit);
    expect(history.records.first.route, 'https://example.test/path/29');
    history.clear();
    expect(history.records, isEmpty);
  });
  test('manual requests respect scan exclusions and custom headers are redacted', () {
    final project = SecurityProject(name: 'Fixture', url: 'https://example.test');
    expect(() => ManualRequestClient.validate(project, Uri.parse('https://example.test/private/record'), 'GET', true,
      policy: ScanPolicy(excludedPaths: ['/private'])), throwsStateError);
    final headers = ManualRequestClient.safeHeaders({'X-Custom-Auth': ['secret'], 'Content-Type': ['application/json']});
    expect(headers['X-Custom-Auth'], ['[redacted]']);
    expect(headers['Content-Type'], ['application/json']);
  });
}
