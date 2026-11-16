import 'package:flutter_test/flutter_test.dart';
import 'package:odin_security/core/manual_request.dart';
import 'package:odin_security/core/request_workspace.dart';

void main() {
  test('tabs hold independent drafts, responses and histories', () {
    final workspace = RequestWorkspace('https://example.test/', initialMethod: 'HEAD');
    final first = workspace.active;
    first.url = 'https://example.test/items';
    first.body = 'fixture';
    first.response = const ManualResponse(200, {}, 'sample', false);
    expect(workspace.add(), isTrue);
    final second = workspace.active;
    expect(second.method, 'GET');
    expect(second.body, isEmpty);
    expect(second.response, isNull);
    expect(identical(first.history, second.history), isFalse);
    workspace.select(first.id);
    expect(workspace.active.method, 'HEAD');
    expect(workspace.active.url, 'https://example.test/items');
    expect(workspace.active.response!.status, 200);
  });

  test('tab limit, close and unique IDs', () {
    final workspace = RequestWorkspace('https://example.test/');
    expect(workspace.closeActive(), isFalse);
    for (var i = 1; i < RequestWorkspace.limit; i++) {
      expect(workspace.add(), isTrue);
    }
    expect(workspace.add(), isFalse);
    final oldId = workspace.active.id;
    expect(workspace.closeActive(), isTrue);
    expect(workspace.tabs.any((tab) => tab.id == oldId), isFalse);
    expect(workspace.add(), isTrue);
    expect(workspace.active.id, greaterThan(oldId));
  });
}
