import 'package:flutter/material.dart';
import 'core/response_matrix_analysis.dart';
import 'response_matrix_analysis_view.dart';
import 'localized.dart';

class ResponseMetricsScreen extends StatefulWidget {
  const ResponseMetricsScreen({super.key});
  @override
  State<ResponseMetricsScreen> createState()=>_ResponseMetricsScreenState();
}
class _ResponseMetricsScreenState extends State<ResponseMetricsScreen> {
  final source=TextEditingController(text:'{"schema":"odin.security.response-metrics.v1","cases":[{"status":200,"bodyBytes":1200,"elapsedMs":100,"truncated":false,"expectedStatus":200},{"status":200,"bodyBytes":1250,"elapsedMs":120,"truncated":false},{"status":404,"bodyBytes":260,"elapsedMs":510,"truncated":false,"expectedStatus":200}]}');
  List<ResponseMetrics>? results;
  bool failed=false;
  @override
  void dispose(){source.dispose();super.dispose();}
  void analyze() {
    try {
      final data=ResponseMatrixAnalysis.parse(source.text);
      setState((){results=data;failed=false;});
    } catch(_){setState((){results=null;failed=true;});}
  }
  @override
  Widget build(BuildContext context)=>Scaffold(
    appBar:AppBar(title:const LText('Offline response metrics')),
    body:ListView(padding:const EdgeInsets.all(16),children:[
      const LText('Paste up to 100 sanitized response metric rows. Do not include URLs, request or response content, headers or credentials. No network calls.'),
      TextField(controller:source,maxLength:65536,maxLines:8,autocorrect:false,enableSuggestions:false,
        textDirection:TextDirection.ltr,decoration:const InputDecoration(label:LText('Response metrics JSON')),
        onChanged:(_)=>setState((){results=null;failed=false;})),
      FilledButton(onPressed:analyze,child:const LText('Compare response metrics')),
      if(failed) const LText('Invalid response metrics document.'),
      if(results!=null) ResponseMatrixAnalysisView(key:ObjectKey(results),samples:results!),
    ]),
  );
}
