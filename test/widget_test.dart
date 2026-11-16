import 'package:flutter_test/flutter_test.dart';
import 'package:odin_security/main.dart';
import 'package:odin_security/core/project_storage.dart';
import 'project_storage_test.dart' show MemoryStorage;

void main() {
  testWidgets('project list shows branded empty state', (tester) async {
    await tester.pumpWidget(OdinSecurityApp(repository: ProjectRepository(MemoryStorage())));
    await tester.pumpAndSettle();
    expect(find.text('Odin Security'), findsOneWidget);
    expect(find.text('New project'), findsOneWidget);
  });
}
