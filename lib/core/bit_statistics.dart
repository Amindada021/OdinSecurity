import 'dart:math';

class BitPosition {
  final int index, ones, samples;
  const BitPosition(this.index, this.ones, this.samples);
  double get ratio => ones / samples;
  double get absoluteBias => (ratio - 0.5).abs();
}

class BitStatistics {
  final int sampleCount, bitsPerSample, totalBits, ones, transitions, comparablePairs, changedBits;
  final List<BitPosition> positions;
  const BitStatistics(this.sampleCount, this.bitsPerSample, this.totalBits, this.ones, this.transitions,
    this.comparablePairs, this.changedBits, this.positions);
  double get oneRatio => ones / totalBits;
  double get frequencyChiSquare {
    final difference = 2 * ones - totalBits;
    return difference * difference / totalBits;
  }
  double? get adjacentBitChangeRatio => comparablePairs == 0 ? null : changedBits / comparablePairs;
  double? get withinSampleTransitionRatio => bitsPerSample < 2 ? null : transitions / (sampleCount * (bitsPerSample - 1));
}

/// Only fixed-width explicitly hexadecimal, synthetic sample input. The
/// descriptive statistics do not certify randomness or estimate secret entropy.
class HexBitAnalyzer {
  static BitStatistics? analyze(List<String> samples) {
    if (samples.length < 2 || samples.length > 1000 || samples.first.isEmpty ||
        samples.first.length > 512 || samples.first.length.isOdd ||
        samples.any((v) => v.length != samples.first.length || !RegExp(r'^[0-9a-fA-F]+$').hasMatch(v))) return null;
    final width = samples.first.length * 4;
    final positionOnes = List<int>.filled(width, 0);
    var ones = 0, transitions = 0, changed = 0;
    List<int>? previous;
    for (final sample in samples) {
      final current = <int>[];
      for (final code in sample.codeUnits) {
        final value = int.parse(String.fromCharCode(code), radix: 16);
        for (var shift = 3; shift >= 0; shift--) {
          current.add((value >> shift) & 1);
        }
      }
      for (var i = 0; i < width; i++) {
        ones += current[i];
        positionOnes[i] += current[i];
        if (i > 0 && current[i] != current[i - 1]) transitions++;
        if (previous != null && current[i] != previous[i]) changed++;
      }
      previous = current;
    }
    return BitStatistics(samples.length, width, samples.length * width, ones, transitions,
      (samples.length - 1) * width, changed,
      List.unmodifiable([for (var i = 0; i < width; i++) BitPosition(i + 1, positionOnes[i], samples.length)]));
  }

  static List<BitPosition> mostBiased(BitStatistics report, {int limit = 32}) {
    if (limit < 1 || limit > 128) throw RangeError.range(limit, 1, 128);
    final result = report.positions.toList()..sort((a, b) {
      final comparison = b.absoluteBias.compareTo(a.absoluteBias);
      return comparison == 0 ? a.index.compareTo(b.index) : comparison;
    });
    return List.unmodifiable(result.take(min(limit, result.length)));
  }
}
