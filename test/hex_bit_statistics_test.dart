import 'package:flutter_test/flutter_test.dart';
import 'package:odin_security/core/bit_statistics.dart';

void main() {
  test('simple balanced and constant samples', () {
    final report = HexBitAnalyzer.analyze(['00', 'ff'])!;
    expect(report.bitsPerSample, 8);
    expect(report.oneRatio, 0.5);
    expect(report.frequencyChiSquare, 0);
    expect(report.adjacentBitChangeRatio, 1);
    expect(report.withinSampleTransitionRatio, 0);
    final constant = HexBitAnalyzer.analyze(['00', '00'])!;
    expect(constant.frequencyChiSquare, 16);
    expect(constant.adjacentBitChangeRatio, 0);
    expect(HexBitAnalyzer.mostBiased(constant, limit: 2).map((p) => p.index), [1, 2]);
  });
  test('alternating within one sample is measured in display bit order', () {
    final report = HexBitAnalyzer.analyze(['aa', 'aa'])!;
    expect(report.withinSampleTransitionRatio, 1);
    expect(report.positions.first.ratio, 1);
    expect(report.positions[1].ratio, 0);
  });
  test('unequal or unsupported input does not produce bit statistics', () {
    expect(HexBitAnalyzer.analyze(['a', 'b']), isNull);
    expect(HexBitAnalyzer.analyze(['00', '0000']), isNull);
    expect(HexBitAnalyzer.analyze(['zz', '00']), isNull);
  });
}
