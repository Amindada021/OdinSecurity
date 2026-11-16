import 'manual_request.dart';
import 'request_history.dart';

/// Session-only independent editor state. Never serialize this object.
class RequestTab {
  final int id;
  String url, method, headers = '', body = '';
  ManualAccept accept = ManualAccept.any;
  ManualContent content = ManualContent.none;
  bool useAuth = false;
  ManualResponse? response;
  String? error;
  final history = RequestHistory();

  RequestTab(this.id, this.url, {this.method = 'GET'});
}

class RequestWorkspace {
  static const limit = 5;
  final String initialUrl;
  final List<RequestTab> _tabs = [];
  int _nextId = 1;
  late RequestTab _active;

  RequestWorkspace(this.initialUrl, {String initialMethod = 'GET'}) {
    _active = RequestTab(_nextId++, initialUrl, method: initialMethod == 'HEAD' ? 'HEAD' : 'GET');
    _tabs.add(_active);
  }

  List<RequestTab> get tabs => List.unmodifiable(_tabs);
  RequestTab get active => _active;
  bool get canAdd => _tabs.length < limit;
  bool get canClose => _tabs.length > 1;

  void select(int id) {
    _active = _tabs.firstWhere((tab) => tab.id == id);
  }

  bool add() {
    if (!canAdd) return false;
    _active = RequestTab(_nextId++, initialUrl);
    _tabs.add(_active);
    return true;
  }

  bool closeActive() {
    if (!canClose) return false;
    final index = _tabs.indexOf(_active);
    _tabs.removeAt(index);
    _active = _tabs[index > 0 ? index - 1 : 0];
    return true;
  }
}
