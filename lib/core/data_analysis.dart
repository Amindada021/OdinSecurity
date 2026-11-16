import 'dart:math';

enum DiffKind { same, removed, added }

class DiffLine {
  final DiffKind kind;
  final String text;
  const DiffLine(this.kind, this.text);
}

class TextDiff {
  static const maxChars = 65536;
  static const maxLines = 300;

  /// Bounded line LCS. Does not access network or save either input.
  static List<DiffLine> compare(String left, String right) {
    if (left.length > maxChars || right.length > maxChars) throw const FormatException('Input too large.');
    final a = left.split('\n'), b = right.split('\n');
    if (a.length > maxLines || b.length > maxLines) throw const FormatException('Too many lines.');
    final dp = List.generate(a.length + 1, (_) => List<int>.filled(b.length + 1, 0));
    for (var i = a.length - 1; i >= 0; i--) {
      for (var j = b.length - 1; j >= 0; j--) {
        dp[i][j] = a[i] == b[j] ? 1 + dp[i + 1][j + 1] : max(dp[i + 1][j], dp[i][j + 1]);
      }
    }
    final result = <DiffLine>[];
    var i = 0, j = 0;
    while (i < a.length || j < b.length) {
      if (i < a.length && j < b.length && a[i] == b[j]) {
        result.add(DiffLine(DiffKind.same, a[i++])); j++;
      } else if (i < a.length && (j == b.length || dp[i + 1][j] >= dp[i][j + 1])) {
        result.add(DiffLine(DiffKind.removed, a[i++]));
      } else {
        result.add(DiffLine(DiffKind.added, b[j++]));
      }
    }
    return List.unmodifiable(result);
  }
}

class PositionStatistics {
  final int position, observations, distinct;
  final double shannonEntropy, empiricalMinEntropy;
  const PositionStatistics(this.position, this.observations, this.distinct, this.shannonEntropy, this.empiricalMinEntropy);
}

class SampleReport {
  final int count, unique, minLength, maxLength, distinctCharacters;
  final double observedCharacterEntropy;
  final List<int> varyingPositions;
  final List<PositionStatistics> positions;
  final int adjacentDuplicates;
  final double? adjacentDifferenceRatio, hexOneBitRatio;
  const SampleReport({required this.count, required this.unique, required this.minLength,
    required this.maxLength, required this.distinctCharacters, required this.observedCharacterEntropy,
    required this.varyingPositions, this.positions = const [], this.adjacentDuplicates = 0,
    this.adjacentDifferenceRatio, this.hexOneBitRatio});
  int get duplicates => count - unique;
}

class TokenSampleAnalyzer {
  static const maxChars = 65536;
  static const maxSamples = 1000;
  static const maxLength = 512;

  /// Descriptive statistics on manually supplied synthetic samples only.
  /// Character frequency entropy is NOT a cryptographic unpredictability test.
  static SampleReport analyze(String input) {
    if (input.length > maxChars) throw const FormatException('Input too large.');
    final tokens = input.split(RegExp(r'\r?\n')).where((s) => s.isNotEmpty).toList();
    if (tokens.length < 2 || tokens.length > maxSamples || tokens.any((s) => s.length > maxLength)) {
      throw const FormatException('Enter 2–1000 samples, up to 512 characters each.');
    }
    final frequencies = <int, int>{};
    final positionCounts = List.generate(maxLength, (_) => <int, int>{});
    var adjacentDuplicates = 0, compared = 0, differences = 0, oneBits = 0, hexBits = 0;
    List<int>? previous;
    final hex = RegExp(r'^[0-9a-fA-F]+
    var minLength = maxLength, longest = 0, total = 0;
    for (final token in tokens) {
      final units = token.runes.toList();
      if (previous != null && previous.length == units.length) {
        var equal = true;
        for (var i = 0; i < units.length; i++) {
          compared++;
          if (previous[i] != units[i]) { differences++; equal = false; }
        }
        if (equal) adjacentDuplicates++;
      }
      previous = units;
      if (allHex) {
        for (final unit in token.codeUnits) {
          final nibble = int.parse(String.fromCharCode(unit), radix: 16);
          for (var bit = 0; bit < 4; bit++) { oneBits += (nibble >> bit) & 1; hexBits++; }
        }
      }
      minLength = min(minLength, units.length);
      longest = max(longest, units.length);
      total += units.length;
      for (var i = 0; i < units.length; i++) {
        frequencies.update(units[i], (n) => n + 1, ifAbsent: () => 1);
        positionCounts[i].update(units[i], (n) => n + 1, ifAbsent: () => 1);
      }
    }
    var entropy = 0.0;
    for (final count in frequencies.values) {
      final probability = count / total;
      entropy -= probability * log(probability) / ln2;
    }
    final positions = <PositionStatistics>[];
    for (var i = 0; i < minLength; i++) {
      final counts = positionCounts[i].values;
      final n = counts.fold<int>(0, (sum, count) => sum + count);
      var shannon = 0.0, peak = 0.0;
      for (final count in counts) {
        final p = count / n;
        shannon -= p * log(p) / ln2;
        peak = max(peak, p);
      }
      positions.add(PositionStatistics(i + 1, n, counts.length, shannon, -log(peak) / ln2));
    }
    return SampleReport(count: tokens.length, unique: tokens.toSet().length,
      minLength: minLength, maxLength: longest, distinctCharacters: frequencies.length,
      observedCharacterEntropy: entropy,
      varyingPositions: List.unmodifiable([for (var i = 0; i < minLength; i++) if (positionCounts[i].length > 1) i + 1]),
      positions: List.unmodifiable(positions), adjacentDuplicates: adjacentDuplicates,
      adjacentDifferenceRatio: compared == 0 ? null : differences / compared,
      hexOneBitRatio: hexBits == 0 ? null : oneBits / hexBits);
  }
}
);
    final allHex = tokens.every((s) => s.length.isEven && hex.hasMatch(s));
    var minLength = maxLength, longest = 0, total = 0;
    for (final token in tokens) {
      final units = token.runes.toList();
      minLength = min(minLength, units.length);
      longest = max(longest, units.length);
      total += units.length;
      for (var i = 0; i < units.length; i++) {
        frequencies.update(units[i], (n) => n + 1, ifAbsent: () => 1);
        positionSets[i].add(units[i]);
      }
    }
    var entropy = 0.0;
    for (final count in frequencies.values) {
      final probability = count / total;
      entropy -= probability * log(probability) / ln2;
    }
    return SampleReport(count: tokens.length, unique: tokens.toSet().length,
      minLength: minLength, maxLength: longest, distinctCharacters: frequencies.length,
      observedCharacterEntropy: entropy,
      varyingPositions: List.unmodifiable([for (var i = 0; i < minLength; i++) if (positionSets[i].length > 1) i + 1]));
  }
}
