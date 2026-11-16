import 'dart:convert';
import 'metadata_rule_program.dart';
import 'project_storage.dart';

/// One atomic project-scoped document. Disabled drafts are retained but
/// never applied. Invalid source is rejected even when disabled.
class MetadataProgramSettings {
  final bool enabled;
  final String source;
  final MetadataRuleProgram? _parsed;

  MetadataProgramSettings({required this.enabled, required String source})
    : source = source.trim(), _parsed = source.trim().isEmpty ? null : MetadataRuleProgram.parse(source.trim()) {
    if (source.length > 16000 || (enabled && _parsed == null)) {
      throw const FormatException('Invalid program settings.');
    }
  }

  MetadataRuleProgram? get draftProgram => _parsed;
  MetadataRuleProgram? get activeProgram => enabled ? _parsed : null;

  String encode() => jsonEncode({'schema':'odin.security.metadata-settings.v1',
    'enabled':enabled,'source':source});

  factory MetadataProgramSettings.decode(String raw) {
    if (raw.length > 100000) throw const FormatException('Settings too large.');
    final json = jsonDecode(raw);
    if (json is! Map || json.length != 3 || json['schema'] != 'odin.security.metadata-settings.v1' ||
        json['enabled'] is! bool || json['source'] is! String) {
      throw const FormatException('Invalid stored program.');
    }
    return MetadataProgramSettings(enabled:json['enabled'] as bool,source:json['source'] as String);
  }
}

class MetadataProgramRepository {
  final ProjectStorage storage;
  MetadataProgramRepository(this.storage);
  String _key(String projectId) => 'odin_security.metadata_program.v1.' + projectId;

  Future<MetadataProgramSettings> load(String projectId) async {
    final raw = await storage.read(_key(projectId));
    return raw == null ? MetadataProgramSettings(enabled:false,source:'') : MetadataProgramSettings.decode(raw);
  }

  Future<void> save(String projectId, MetadataProgramSettings settings) =>
    storage.write(_key(projectId), settings.encode());
}
