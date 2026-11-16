import 'package:flutter_test/flutter_test.dart';
import 'package:odin_security/core/metadata_program_settings.dart';
import 'package:odin_security/core/project_storage.dart';
import 'package:odin_security/core/passive_scan.dart';
import 'package:odin_security/core/custom_rules.dart';
import 'package:odin_security/core/fingerprint.dart';
import 'package:odin_security/core/history.dart';

class MemoryStorage implements ProjectStorage {
  final data=<String,String>{};
  @override
  Future<String?> read(String key) async=>data[key];
  @override
  Future<void> write(String key,String value) async { data[key]=value; }
}

void main() {
  const valid='{"schema":"odin.security.metadata.v1","rules":[{"id":"missing-hsts","match":"all","conditions":[{"op":"statusRange","min":200,"max":299},{"op":"headerAbsent","header":"strict-transport-security"}]},{"id":"server-error","match":"all","conditions":[{"op":"statusRange","min":500,"max":599}]}]}';
  final fixture=HttpObservation(headers:{'content-type':['application/json'],'authorization':['fixture-secret']},body:'fixture-secret');
  test('default disabled, explicit enablement and isolation across projects',() async {
    final repo=MetadataProgramRepository(MemoryStorage());
    expect((await repo.load('a')).activeProgram,isNull);
    await repo.save('a', MetadataProgramSettings(enabled:true,source:valid));
    expect((await repo.load('a')).activeProgram!.ruleCount,2);
    expect((await repo.load('b')).activeProgram,isNull);
    await repo.save('a',MetadataProgramSettings(enabled:false,source:valid));
    final disabled=await repo.load('a');
    expect(disabled.activeProgram,isNull);
    expect(disabled.draftProgram!.ruleCount,2);
    expect(disabled.source,valid);
  });
  test('invalid settings cannot overwrite existing validated program',() async {
    final repo=MetadataProgramRepository(MemoryStorage());
    await repo.save('a',MetadataProgramSettings(enabled:true,source:valid));
    expect(()=>MetadataProgramSettings(enabled:true,source:''),throwsFormatException);
    expect(()=>MetadataProgramSettings(enabled:false,source:'{"script":"x"}'),throwsFormatException);
    expect((await repo.load('a')).source,valid);
  });
  test('preview evaluates synthetic metadata only',() {
    final program=MetadataProgramSettings(enabled:true,source:valid).activeProgram!;
    expect(program.preview('{"status":200,"headers":{}}').single.id,'program.missing-hsts');
    expect(program.preview('{"status":503,"headers":{}}').single.id,'program.server-error');
    expect(()=>program.preview('{"status":200,"headers":{"authorization":["fixture-secret"]}}'),throwsFormatException);
    expect(()=>program.preview('{"status":600,"headers":{}}'),throwsFormatException);
  });
  test('existing scanner combines legacy and metadata results; history preserves fixed observations',() {
    final program=MetadataProgramSettings(enabled:true,source:valid).activeProgram!;
    final scanner=PassiveScanner(customRules:CustomHeaderRules.parse('x-content-type-options|present'),metadataProgram:program);
    final results=scanner.inspectConfiguredRules(fixture,200);
    expect(results.map((r)=>r.id),containsAll(['custom.x-content-type-options.present','program.missing-hsts']));
    expect(scanner.inspectConfiguredRules(fixture,503).single.id,'program.server-error');
    final page=PassiveScanResult(url:Uri.parse('https://example.test/'),statusCode:200,links:[],
      findings:results,technologies:[],bodyTruncated:false,redirectNotFollowed:false);
    final saved=ScanRecord.fromPages([page]);
    expect(saved.pages.single['observations'].toString(),contains('program.missing-hsts'));
    expect(saved.pages.single['observations'].toString(),isNot(contains('fixture-secret')));
  });
  test('oversized relevant response header produces incomplete review, not false absence',() {
    final program=MetadataProgramSettings(enabled:true,source:valid).activeProgram!;
    final observation=HttpObservation(headers:{'cache-control':[List.filled(17000,'x').join()]},body:'');
    expect(program.inspect(observation,200).single.id,'program.review.limit');
  });
}
