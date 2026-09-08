from __future__ import annotations

import ast
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str
    line: int
    message: str
    remediation: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


class SecurityVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.findings: list[Finding] = []

    def visit_Call(self, node: ast.Call) -> None:
        name = _call_name(node.func)
        rules = {
            "eval": ("S001", "high", "Avoid eval on untrusted data; use a parser or explicit allowlist."),
            "exec": ("S002", "high", "Avoid exec; use explicit program logic."),
            "pickle.loads": ("S003", "high", "Never deserialize untrusted pickle data; use JSON with schema validation."),
            "subprocess.call": ("S004", "medium", "Use argument lists, validation, and shell=False."),
            "subprocess.run": ("S004", "medium", "Use argument lists, validation, and shell=False."),
        }
        if name in rules:
            rule, severity, remediation = rules[name]
            if name.startswith("subprocess") and not any(k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True for k in node.keywords):
                pass
            else:
                self.findings.append(Finding(rule, severity, node.lineno, f"Potentially unsafe call: {name}", remediation))
        self.generic_visit(node)


def _call_name(node: ast.expr) -> str:
    if isinstance(node, ast.Name): return node.id
    if isinstance(node, ast.Attribute): return f"{_call_name(node.value)}.{node.attr}"
    return ""


def review_source(source: str) -> list[Finding]:
    visitor = SecurityVisitor()
    visitor.visit(ast.parse(source))
    return visitor.findings


def review_file(path: str | Path) -> list[Finding]:
    return review_source(Path(path).read_text(encoding="utf-8"))
