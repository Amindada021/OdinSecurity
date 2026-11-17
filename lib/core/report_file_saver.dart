import 'dart:typed_data';
import 'package:file_picker/file_picker.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

/// Saves the generated report and verifies the Android document was populated.
class ReportFileSaver {
  static const channel = MethodChannel('odin/report-export');
  static const _mime = {
    'pdf': 'application/pdf',
    'json': 'application/json',
    'html': 'text/html',
  };

  static Future<bool> save({required String fileName, required String extension, required Uint8List bytes}) async {
    final mime = _mime[extension];
    if (bytes.isEmpty || mime == null || !fileName.endsWith('.$extension')) {
      throw const FormatException('Invalid report.');
    }
    if (!kIsWeb && defaultTargetPlatform == TargetPlatform.android) {
      final written = await channel.invokeMethod<int>('save', {
        'fileName': fileName, 'mime': mime, 'bytes': bytes,
      });
      if (written == null) return false;
      if (written != bytes.length) throw StateError('Report was not fully written.');
      return true;
    }
    final path = await FilePicker.platform.saveFile(
      fileName: fileName, bytes: bytes, type: FileType.custom, allowedExtensions: [extension],
    );
    return path != null;
  }
}
