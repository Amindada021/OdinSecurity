import 'package:flutter/material.dart';
import 'core/response_matrix_analysis.dart';
import 'localized.dart';

enum _MatrixFilter { all, differences, unexpected }

class ResponseMatrixAnalysisView extends StatefulWidget {
  final List<ResponseMetrics> samples;
  final List<String>? labels;
  const ResponseMatrixAnalysisView({super.key,required this.samples,this.labels});
  @override
  State<ResponseMatrixAnalysisView> createState()=>_ResponseMatrixAnalysisViewState();
}

class _ResponseMatrixAnalysisViewState extends State<ResponseMatrixAnalysisView> {
  int baseline=0,sizeTolerance=1024,timeTolerance=250;
  _MatrixFilter filter=_MatrixFilter.all;
  String label(int index)=>widget.labels?[index] ?? (tr(context,'Case')+' '+uiNumber(context,index+1));
  String signed(int value)=>(value>0?'+':'')+uiNumber(context,value);
  @override
  void didUpdateWidget(covariant ResponseMatrixAnalysisView oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (baseline>=widget.samples.length) baseline=0;
  }
  @override
  Widget build(BuildContext context) {
    if(widget.samples.isEmpty) return const SizedBox.shrink();
    final all=ResponseMatrixAnalysis.compare(widget.samples,baseline,
      sizeTolerance:sizeTolerance,timeToleranceMs:timeTolerance);
    final shown=all.where((r)=>switch(filter) {
      _MatrixFilter.all=>true,
      _MatrixFilter.differences=>r.differs,
      _MatrixFilter.unexpected=>r.sample.matchesExpectation==false,
    });
    return Column(crossAxisAlignment:CrossAxisAlignment.start,children:[
      const LText('Response comparison'),
      const LText('Compare captured response metadata with a reference case. Timing differences are diagnostic and can vary naturally; no vulnerability is inferred.'),
      DropdownButtonFormField<int>(key:ValueKey('baseline-'+baseline.toString()),initialValue:baseline,
        isExpanded:true,decoration:const InputDecoration(label:LText('Reference case')),
        items:[for(var i=0;i<widget.samples.length;i++) DropdownMenuItem(value:i,child:Text(label(i)))],
        onChanged:(v)=>setState(()=>baseline=v??0)),
      DropdownButtonFormField<int>(initialValue:sizeTolerance,
        decoration:const InputDecoration(label:LText('Size tolerance (bytes)')),
        items:[for(final n in [0,256,1024,4096]) DropdownMenuItem(value:n,child:Text(uiNumber(context,n)))],
        onChanged:(v)=>setState(()=>sizeTolerance=v??1024)),
      DropdownButtonFormField<int>(initialValue:timeTolerance,
        decoration:const InputDecoration(label:LText('Timing tolerance (ms)')),
        items:[for(final n in [0,100,250,1000]) DropdownMenuItem(value:n,child:Text(uiNumber(context,n)))],
        onChanged:(v)=>setState(()=>timeTolerance=v??250)),
      DropdownButtonFormField<_MatrixFilter>(initialValue:filter,
        decoration:const InputDecoration(label:LText('Comparison filter')),
        items:const [
          DropdownMenuItem(value:_MatrixFilter.all,child:LText('All cases')),
          DropdownMenuItem(value:_MatrixFilter.differences,child:LText('Differences outside tolerance')),
          DropdownMenuItem(value:_MatrixFilter.unexpected,child:LText('Unexpected status only')),
        ],
        onChanged:(v)=>setState(()=>filter=v??_MatrixFilter.all)),
      Text(uiNumber(context,shown.length)+' / '+uiNumber(context,all.length)),
      for(final row in shown) ListTile(
        leading:Icon(row.index==baseline?Icons.flag_outlined:row.differs?Icons.compare_arrows:Icons.check_circle_outline),
        title:Text(label(row.index)),
        subtitle:Column(crossAxisAlignment:CrossAxisAlignment.start,children:[
          Text('HTTP '+uiNumber(context,row.sample.status)+' · '+uiNumber(context,row.sample.elapsedMs)+' ms · '+
            uiNumber(context,row.sample.bodyBytes)+(row.sample.truncated?'+ B':' B')),
          if(row.index==baseline) const LText('Reference case'),
          if(row.index!=baseline) ...[
            if(row.statusChanged) const LText('Status changed'),
            Text(tr(context,'Timing difference')+': '+signed(row.timeDeltaMs)+' ms'),
            if(row.sizeDelta==null) const LText('Size not comparable (truncated response)')
            else Text(tr(context,'Size difference')+': '+signed(row.sizeDelta!)+' B'),
          ],
          if(row.sample.expectedStatus!=null) Text(tr(context,'Expected status (optional)')+': '+
            uiNumber(context,row.sample.expectedStatus!)+' · '+
            tr(context,row.sample.matchesExpectation!?'Matches expectation':'Differs from expectation')),
        ]),
      ),
    ]);
  }
}
