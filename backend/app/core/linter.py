import ast
import re
from typing import Dict, List, Optional, Tuple


class LintResult:
    """Standardized validation outcome container."""

    def __init__(self, is_valid: bool, message: str, safety_warnings: Optional[List[str]] = None):
        self.is_valid = is_valid
        self.message = message
        self.safety_warnings = safety_warnings or []

    @property
    def status(self) -> str:
        return "suggested" if self.is_valid else "failed_lint"

    def to_report_string(self) -> str:
        prefix = "PASS" if self.is_valid else "FAIL"
        report = f"{prefix}: {self.message}"
        if self.safety_warnings:
            report += f" | Safety Warnings: {'; '.join(self.safety_warnings)}"
        return report


class PatchLinter:
    """
    Validates syntax and security properties of LLM-generated source code patches.
    """

    # Insecure functions that should not be introduced by an AI remediation patch
    DANGEROUS_CALL_PATTERNS = [
        (r"\beval\s*\(", "Use of eval() detected"),
        (r"\bexec\s*\(", "Use of exec() detected"),
        (r"\bos\.system\s*\(", "Insecure os.system() invocation detected"),
        (r"\bsubprocess\.(?:Popen|call|run)\s*\([^)]*shell\s*=\s*True", "subprocess call with shell=True detected"),
        (r"dangerouslySetInnerHTML", "Insecure React dangerouslySetInnerHTML detected"),
    ]

    @classmethod
    def validate(cls, language: str, code: str) -> LintResult:
        """
        Executes language syntax parsing followed by an AST/regex safety scan.
        """
        if not code or not code.strip():
            return LintResult(False, "Generated code patch is completely empty.")

        lang = (language or "other").lower().strip()

        # Step 1: Language-specific syntax and grammar check
        if lang == "python":
            syntax_ok, err_msg = cls._lint_python(code)
        elif lang in ("javascript", "typescript", "js", "ts"):
            syntax_ok, err_msg = cls._lint_javascript(code)
        elif lang in ("json",):
            syntax_ok, err_msg = cls._lint_json(code)
        else:
            syntax_ok, err_msg = True, f"No parser configured for '{lang}'; structural checks skipped."

        if not syntax_ok:
            return LintResult(False, err_msg)

        # Step 2: Safety & anti-pattern scanning
        safety_warnings = cls._scan_safety_antipatterns(code)

        return LintResult(True, err_msg, safety_warnings=safety_warnings)

    @classmethod
    def _lint_python(cls, code: str) -> Tuple[bool, str]:
        """Validates Python syntax by constructing an Abstract Syntax Tree."""
        try:
            tree = ast.parse(code)
            # Scan for invalid AST structures or empty bodies
            if not tree.body:
                return False, "Python AST generated an empty body."
            return True, "Python AST syntax parse passed."
        except SyntaxError as e:
            return False, f"Python SyntaxError [Line {e.lineno}, Col {e.offset}]: {e.msg}"
        except Exception as exc:
            return False, f"Python AST parsing exception: {str(exc)}"

    @classmethod
    def _lint_javascript(cls, code: str) -> Tuple[bool, str]:
        """
        Validates JS/TS grammar using lexical comment/string stripping
        and bracket-stack balancing.
        """
        # Strip block comments, line comments, and string literals
        clean_code = re.sub(r"/\*[\s\S]*?\*/|//.*?$|(?<!\\)(['\"]).*?(?<!\\)\1|`[\s\S]*?`", "", code, flags=re.MULTILINE)

        stack = []
        brackets = {")": "(", "}": "{", "]": "["}

        for idx, char in enumerate(clean_code):
            if char in brackets.values():
                stack.append(char)
            elif char in brackets.keys():
                if not stack or stack.pop() != brackets[char]:
                    return False, f"JavaScript structural parse error: Unbalanced bracket '{char}' around character offset {idx}."

        if stack:
            return False, f"JavaScript structural parse error: Unclosed bracket '{stack[-1]}' remaining at end of file."

        return True, "JavaScript structural syntax check passed."

    @classmethod
    def _lint_json(cls, code: str) -> Tuple[bool, str]:
        import json
        try:
            json.loads(code)
            return True, "Valid JSON."
        except json.JSONDecodeError as e:
            return False, f"JSON syntax error: {e.msg} at line {e.lineno}"

    @classmethod
    def _scan_safety_antipatterns(cls, code: str) -> List[str]:
        """Detects whether the LLM fix accidentally introduced new high-risk vulnerabilities."""
        warnings = []
        for pattern, description in cls.DANGEROUS_CALL_PATTERNS:
            if re.search(pattern, code, re.IGNORECASE):
                warnings.append(description)
        return warnings