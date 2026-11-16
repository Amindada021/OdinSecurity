import 'dart:convert';
import 'dart:math';

/// Generates local synthetic test text from a single literal marker. No URLs,
/// transport, payload dictionary or batch request sending are implemented here.
class FixtureVariants {
  static List<String> render(String template, Iterable<String> values) {
    const marker = '[VALUE]';
    if (template.length > 4096 || marker.allMatches(template).length != 1) {
      throw const FormatException('Use exactly one [VALUE] marker.');
    }
    final data = values.toList();
    if (data.isEmpty || data.length > 20 || data.any((v) => v.isEmpty || v.length > 128 ||
        v.contains(RegExp(r'[\x00-\x1f\x7f]')))) throw const FormatException('Invalid sample values.');
    return List.unmodifiable(data.map((v) => template.replaceFirst(marker, v)));
  }
}

class LabInteraction {
  final String protocol;
  final DateTime observedAt;
  const LabInteraction(this.protocol, this.observedAt);
}

/// Offline correlation with user-provided, sanitized interaction metadata.
/// This does not operate a callback server or prove which component sent an event.
class LabInteractionReview {
  static final tokenPattern = RegExp(r'^[a-f0-9]{32}$');
  static String newLabel() {
    final random = Random.secure();
    return List.generate(16, (_) => random.nextInt(256).toRadixString(16).padLeft(2, '0')).join();
  }
  static List<LabInteraction> match(String label, String source) {
    if (!tokenPattern.hasMatch(label) || source.length > 65536) throw const FormatException('Invalid data.');
    final raw = jsonDecode(source);
    if (raw is! List || raw.length > 200) throw const FormatException('Invalid event list.');
    final result = <LabInteraction>[];
    for (final row in raw) {
      if (row is! Map<String, dynamic> || row.length != 3 ||
          row['label'] is! String || !tokenPattern.hasMatch(row['label'] as String) ||
          !['dns', 'http', 'https'].contains(row['protocol']) || row['observedAt'] is! String) {
        throw const FormatException('Invalid event.');
      }
      final at = DateTime.tryParse(row['observedAt'] as String);
      if (at == null || !at.isUtc) throw const FormatException('Use a UTC timestamp.');
      if (row['label'] == label) result.add(LabInteraction(row['protocol'] as String, at));
    }
    result.sort((a, b) => a.observedAt.compareTo(b.observedAt));
    return List.unmodifiable(result);
  }
}
