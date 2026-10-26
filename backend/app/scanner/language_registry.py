from .languages.python.analyzer import PythonAnalyzer
from .languages.javascript.analyzer import JavaScriptAnalyzer


_ANALYZERS = [PythonAnalyzer(), JavaScriptAnalyzer()]


def analyzer_for(file_path: str):
    lower = file_path.lower()
    for analyzer in _ANALYZERS:
        if lower.endswith(analyzer.extensions):
            return analyzer
    return None
