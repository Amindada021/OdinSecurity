import 'package:flutter_test/flutter_test.dart';
import 'package:odin_security/core/html_security_checks.dart';

void main() {
  final page = Uri.parse('https://example.test/account');
  test('HTML evidence detects insecure form and active resource patterns without retaining URLs', () {
    final result = HtmlSecurityChecks.inspect(page, '''
      <script src="http://cdn.example.test/fixture.js?secret=private"></script>
      <form action="http://example.test/login"><input type="password" value="private"></form>
      <form action="https://sso.example.test/session" method="post"><input type="password"></form>
    ''');
    expect(result.map((f) => f.id), containsAll([
      'html.mixed.active', 'html.form.http', 'html.form.password.get',
      'html.form.password.external', 'html.script.external.integrity',
    ]));
    expect(result.every((f) => !f.evidence.contains('private') && !f.evidence.contains('example.test')), isTrue);
  });
  test('HTML parser ignores comments and script text, safe local POST and SRI', () {
    final result = HtmlSecurityChecks.inspect(page, '''
      <!-- <form action="http://other.test"><input type=password></form> -->
      <script>const snippet = '<iframe src="http://other.test"></iframe>';</script>
      <form method=post action=/login><input type=password></form>
      <script src="https://cdn.example.test/script.js" integrity="sha384-fixture"></script>
    ''');
    expect(result, isEmpty);
  });
  test('form and resource targets resolve against document base', () {
    final result = HtmlSecurityChecks.inspect(page, '''
      <base href="http://example.test/assets/">
      <script src=app.js></script>
      <form method=post action=login><input type=password></form>
    ''');
    expect(result.map((f) => f.id), containsAll(['html.mixed.active', 'html.form.http']));
  });
}
