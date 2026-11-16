import 'package:flutter_test/flutter_test.dart';
import 'package:odin_security/core/data_analysis.dart';
import 'package:odin_security/core/offline_tools.dart';

void main() {
  test('bounded line comparer identifies inserted and removed lines', () {
    final diff = TextDiff.compare('a\nb\nc', 'a\nx\nc');
    expect(diff.map((row) => row.kind), [DiffKind.same, DiffKind.removed, DiffKind.added, DiffKind.same]);
    expect(diff[1].text, 'b');
    expect(diff[2].text, 'x');
    expect(() => TextDiff.compare(List.filled(301, 'x').join('\n'), ''), throwsFormatException);
  });
  test('sample report counts duplicates and positional changes', () {
    final result = TokenSampleAnalyzer.analyze('aaaa\naaaa\naaba');
    expect(result.count, 3);
    expect(result.unique, 2);
    expect(result.duplicates, 1);
    expect(result.varyingPositions, [3]);
    expect(result.observedCharacterEntropy, greaterThan(0));
    expect(TokenSampleAnalyzer.analyze('aaa\naaa').observedCharacterEntropy, 0);
    expect(() => TokenSampleAnalyzer.analyze('single'), throwsFormatException);
  });
  test('hex and HTML escaping remain offline', () {
    expect(OfflineTools.decodeHex(OfflineTools.encodeHex('سلام')), 'سلام');
    expect(() => OfflineTools.decodeHex('xyz'), throwsFormatException);
    expect(OfflineTools.encodeHtml('<tag>'), '&lt;tag&gt;');
  });
}
