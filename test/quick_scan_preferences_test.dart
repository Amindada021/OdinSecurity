import 'package:flutter_test/flutter_test.dart';
import 'package:odin_security/core/auth.dart';
import 'package:odin_security/core/api_login_preferences.dart';
import 'package:odin_security/core/quick_scan_preferences.dart';
import 'project_storage_test.dart' show MemoryStorage;

void main() {
  test('project quick scan choice and separate login site survive restart', () async {
    final store = MemoryStorage();
    final repo = QuickScanPreferencesRepository(store);
    const project = 'project-a';
    await repo.save(project, const QuickScanPreferences(
      target: 'https://api.example.test',
      method: 'browser',
      loginUrl: 'https://panel.example.test/login',
      delivery: TokenDelivery.raw,
      headerName: 'X-Security-Key',
    ));
    final loaded = await QuickScanPreferencesRepository(store).load(project);
    expect(loaded.target, 'https://api.example.test');
    expect(loaded.method, 'browser');
    expect(loaded.loginUrl, 'https://panel.example.test/login');
    expect(loaded.delivery, TokenDelivery.raw);
    expect(loaded.headerName, 'X-Security-Key');
    expect((await repo.load('different-project')).method, 'public');
    expect(store.values[repo.key(project)], isNot(contains('password')));
    expect(store.values[repo.key(project)], isNot(contains('secret-token-value')));
  });

  test('saved identity choice is only a reference; the secret never enters UI preferences', () async {
    final store = MemoryStorage();
    final repo = QuickScanPreferencesRepository(store);
    await repo.save('project-a', const QuickScanPreferences(
      target: 'https://api.example.test', method: 'saved',
      identityName: 'My test account',
    ));
    final loaded = await repo.load('project-a');
    expect(loaded.method, 'saved');
    expect(loaded.identityName, 'My test account');
    expect(store.values[repo.key('project-a')], isNot(contains('abc-private-token')));
  });

  test('panel size is bounded and survives screens and relaunch', () async {
    final store = MemoryStorage();
    final repo = LoginPanelPreferencesRepository(store);
    expect(await repo.load('a'), 0.45);
    await repo.save('a', 0.65);
    expect(await LoginPanelPreferencesRepository(store).load('a'), 0.65);
    expect(await repo.load('b'), 0.45);
    await repo.save('a', 100);
    expect(await repo.load('a'), 0.74);
    await repo.save('a', -10);
    expect(await repo.load('a'), 0.20);
  });

  test('API login endpoint and field mapping persist per target without passwords', () async {
    final store = MemoryStorage();
    final repo = ApiLoginPreferencesRepository(store);
    final target = Uri.parse('https://api.example.test');
    const config = ApiLoginPreferences(
      loginUrl: 'https://api.example.test/v1/account/login',
      usernameField: 'mobile', passwordField: 'password',
      tokenPath: 'data.token', mode: AuthMode.jsonLogin,
      delivery: TokenDelivery.bearer,
    );
    await repo.save('project-a', target, config);
    final loaded = await ApiLoginPreferencesRepository(store).load('project-a', target);
    expect(loaded.loginUrl, config.loginUrl);
    expect(loaded.usernameField, 'mobile');
    expect(loaded.tokenPath, 'data.token');
    expect(loaded.delivery, TokenDelivery.bearer);
    expect((await repo.load('project-a', Uri.parse('https://other.example.test'))).loginUrl, '');
    final stored = store.values[repo.key('project-a', target)]!;
    expect(stored, isNot(contains('user-password')));
    expect(stored, isNot(contains('user-token-secret')));
  });

  test('corrupt persisted config fails closed to defaults', () async {
    final store = MemoryStorage();
    final repo = QuickScanPreferencesRepository(store);
    await store.write(repo.key('p'), '{invalid-json');
    expect((await repo.load('p')).method, 'public');
    await store.write(repo.key('p'),
        '{"method":"bad","target":"https://admin@api.example.test",'
        '"loginUrl":"https://panel.example.test/login?code=secret"}');
    final recovered = await repo.load('p');
    expect(recovered.method, 'public');
    expect(recovered.target, '');
    expect(recovered.loginUrl, '/login');
  });
}
