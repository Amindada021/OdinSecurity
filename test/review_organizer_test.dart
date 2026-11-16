import 'package:flutter_test/flutter_test.dart';
import 'package:odin_security/core/project.dart';
import 'package:odin_security/core/review_organizer.dart';
import 'package:odin_security/core/scan_policy.dart';
import 'project_storage_test.dart' show MemoryStorage;

void main() {
  test('saves explicit notes per project and reapplies scope policy', () async {
    final organizer = ReviewOrganizer(MemoryStorage());
    final project = SecurityProject(name: 'Fixture', url: 'https://example.test');
    final policy = ScanPolicy();
    final item = ReviewOrganizer.prepare(project, policy, 'https://example.test/report', 'Review status', 'Check expected access', ReviewStatus.open);
    await organizer.save(project, policy, [item]);
    final stored = (await organizer.load(project, policy)).single;
    expect(stored.title, item.title);
    expect(stored.note, item.note);
    expect(stored.status, ReviewStatus.open);
    expect(await organizer.load(project, ScanPolicy(excludedPaths: ['/report'])), isEmpty);
    expect(await organizer.load(SecurityProject(name: 'Other', url: project.startUrl.toString()), policy), isEmpty);
  });
  test('rejects credentials, queries, out-of-scope targets and empty titles', () {
    final project = SecurityProject(name: 'Fixture', url: 'https://example.test');
    for (final route in ['https://other.test/report', 'https://example.test/report?token=secret', 'https://user:secret@example.test/']) {
      expect(() => ReviewOrganizer.prepare(project, ScanPolicy(), route, 'Review', '', ReviewStatus.open), throwsFormatException);
    }
    expect(() => ReviewOrganizer.prepare(project, ScanPolicy(), project.startUrl.toString(), '', '', ReviewStatus.open), throwsFormatException);
  });
}
