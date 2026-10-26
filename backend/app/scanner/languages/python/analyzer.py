from ...capability_extractor import analyze_file
from ...ir.capabilities import CapabilityIR
from ..base import LanguageAnalyzer, LanguageAnalysis


class PythonAnalyzer(LanguageAnalyzer):
    language = "python"
    extensions = (".py",)

    def analyze(self, file_path: str, text: str) -> LanguageAnalysis:
        result = analyze_file(file_path, text)
        capabilities = []
        for finding in result.ast_findings:
            capabilities.append(CapabilityIR(
                agent=file_path,
                ai_provider=result.ai_providers[0] if result.ai_providers else None,
                source={"file": file_path, "line": finding.line},
                ai_controlled=finding.ai_controlled,
                operation=finding.operation,
                target=finding.function_name,
                data_flow=list(finding.capability_chain or []),
                confidence=finding.control_confidence,
                category=finding.category,
                language=self.language,
            ))
        return LanguageAnalysis(self.language, True, file_path, capabilities, result)
