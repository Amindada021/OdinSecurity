import 'package:flutter_test/flutter_test.dart';
import 'package:odin_security/core/finding_explanations.dart';
import 'package:odin_security/core/technology_explanations.dart';

void main() {
  test('built-in observations have localized explanations and recommendations', () {
    final en = explainFinding('header.hsts', 'HSTS not observed', 'Enable HSTS', persian: false);
    final fa = explainFinding('header.hsts', 'HSTS not observed', 'Enable HSTS', persian: true);
    expect(en.title, 'HSTS not observed');
    expect(en.meaning, contains('HTTPS'));
    expect(fa.title, contains('مشاهده نشد'));
    expect(fa.meaning, contains('مرورگر'));
    expect(fa.advice, contains('سیاست'));
    expect(explainTechnology('ASP.NET Core', persian: true), contains('دات‌نت'));
    expect(explainTechnology('ASP.NET Core', persian: false), contains('.NET'));
  });
  test('custom observations retain original title and recommendation', () {
    final copy = explainFinding('custom.example', 'Custom title', 'Custom advice', persian: true);
    expect(copy.title, 'Custom title');
    expect(copy.advice, 'Custom advice');
    expect(copy.meaning, isNotEmpty);
  });
}
