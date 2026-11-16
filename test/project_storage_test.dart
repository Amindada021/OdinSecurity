import 'package:flutter_test/flutter_test.dart';
import 'package:odin_security/core/project.dart';
import 'package:odin_security/core/project_storage.dart';

class MemoryStorage implements ProjectStorage {
  final values = <String, String>{};
  @override
  Future<String?> read(String key) async => values[key];
  @override
  Future<void> write(String key, String value) async { values[key] = value; }
}

void main() {
  test('projects and additional scopes survive repository recreation', () async {
    final storage = MemoryStorage();
    final project = SecurityProject(name: 'Demo', url: 'https://panel.example.test', additionalUrls: ['https://api.example.test']);
    await ProjectRepository(storage).save([project]);
    final restored = (await ProjectRepository(storage).load()).single;
    expect(restored.id, project.id);
    expect(restored.name, project.name);
    expect(restored.contains(Uri.parse('https://api.example.test/v1')), isTrue);
    expect(restored.contains(Uri.parse('https://other.example.test')), isFalse);
  });

  test('duplicate projects fail instead of silently overwriting', () async {
    final repo = ProjectRepository(MemoryStorage());
    final p = SecurityProject(name: 'Demo', url: 'https://example.test');
    await expectLater(repo.save([p, p]), throwsStateError);
  });
}
