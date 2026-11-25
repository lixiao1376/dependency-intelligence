"""Static source scanner for Python and JavaScript/TypeScript imports and usages."""

from __future__ import annotations

import ast
import re
from pathlib import Path

from .models import CodeUsage


IGNORED_DIRECTORIES = {
    ".git", ".hg", ".mypy_cache", ".pytest_cache", ".tox", ".venv",
    "__pycache__", "build", "dist", "node_modules", "venv",
}
JS_SUFFIXES = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}


def _snippet(lines: list[str], line: int) -> str:
    if 1 <= line <= len(lines):
        return lines[line - 1].strip()[:240]
    return ""


def _attribute_name(node: ast.AST, aliases: dict[str, str]) -> str | None:
    parts: list[str] = []
    cursor = node
    while isinstance(cursor, ast.Attribute):
        parts.append(cursor.attr)
        cursor = cursor.value
    if isinstance(cursor, ast.Name) and cursor.id in aliases:
        return ".".join([aliases[cursor.id], *reversed(parts)])
    return None


def scan_python(path: Path, import_names: set[str], root: Path) -> list[CodeUsage]:
    try:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
    except (OSError, UnicodeDecodeError, SyntaxError):
        return []

    lines = source.splitlines()
    aliases: dict[str, str] = {}
    import_lines: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for item in node.names:
                root_name = item.name.split(".", 1)[0]
                if root_name in import_names:
                    aliases[item.asname or root_name] = item.name
                    import_lines.add(node.lineno)
        elif isinstance(node, ast.ImportFrom) and node.module:
            module_root = node.module.split(".", 1)[0]
            if module_root in import_names:
                for item in node.names:
                    if item.name != "*":
                        aliases[item.asname or item.name] = f"{node.module}.{item.name}"
                    import_lines.add(node.lineno)

    results: list[CodeUsage] = []
    seen: set[tuple[int, str]] = set()
    for node in ast.walk(tree):
        symbol: str | None = None
        if isinstance(node, ast.Attribute):
            symbol = _attribute_name(node, aliases)
        elif isinstance(node, ast.Name) and node.id in aliases and node.lineno not in import_lines:
            symbol = aliases[node.id]
        if symbol and (node.lineno, symbol) not in seen:
            seen.add((node.lineno, symbol))
            results.append(
                CodeUsage(
                    file=str(path.relative_to(root)),
                    line=node.lineno,
                    symbol=symbol,
                    snippet=_snippet(lines, node.lineno),
                    language="python",
                )
            )
    return results


def scan_javascript(path: Path, packages: set[str], root: Path) -> list[CodeUsage]:
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return []
    lines = source.splitlines()
    local_symbols: dict[str, str] = {}
    import_line_numbers: set[int] = set()

    for number, line in enumerate(lines, 1):
        for package in packages:
            escaped = re.escape(package)
            named = re.search(rf"import\s*\{{([^}}]+)\}}\s*from\s*['\"]{escaped}['\"]", line)
            default = re.search(rf"import\s+([A-Za-z_$][\w$]*)\s+from\s*['\"]{escaped}['\"]", line)
            namespace = re.search(rf"import\s+\*\s+as\s+([A-Za-z_$][\w$]*)\s+from\s*['\"]{escaped}['\"]", line)
            required = re.search(rf"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\(['\"]{escaped}['\"]\)", line)
            if named:
                for part in named.group(1).split(","):
                    pieces = re.split(r"\s+as\s+", part.strip())
                    original, local = pieces[0], pieces[-1]
                    if original:
                        local_symbols[local] = f"{package}.{original}"
                import_line_numbers.add(number)
            for match in (default, namespace, required):
                if match:
                    local_symbols[match.group(1)] = package
                    import_line_numbers.add(number)

    results: list[CodeUsage] = []
    seen: set[tuple[int, str]] = set()
    for number, line in enumerate(lines, 1):
        if number in import_line_numbers:
            continue
        for local, canonical in local_symbols.items():
            for match in re.finditer(rf"\b{re.escape(local)}(?:\.([A-Za-z_$][\w$]*))?", line):
                symbol = f"{canonical}.{match.group(1)}" if match.group(1) else canonical
                if (number, symbol) not in seen:
                    seen.add((number, symbol))
                    results.append(
                        CodeUsage(
                            file=str(path.relative_to(root)),
                            line=number,
                            symbol=symbol,
                            snippet=line.strip()[:240],
                            language="javascript",
                        )
                    )
    return results


def scan_project(project_path: str, import_names: list[str], package: str, max_files: int = 5000) -> list[CodeUsage]:
    root = Path(project_path).resolve()
    python_names = {name.split(".", 1)[0] for name in import_names if name}
    python_names.add(package.replace("-", "_").split("/", 1)[-1])
    js_packages = {package}
    results: list[CodeUsage] = []
    inspected = 0
    for path in root.rglob("*"):
        if inspected >= max_files:
            break
        if not path.is_file() or any(part in IGNORED_DIRECTORIES for part in path.parts):
            continue
        if path.suffix == ".py":
            inspected += 1
            results.extend(scan_python(path, python_names, root))
        elif path.suffix in JS_SUFFIXES:
            inspected += 1
            results.extend(scan_javascript(path, js_packages, root))
    return sorted(results, key=lambda item: (item.file, item.line, item.symbol))

