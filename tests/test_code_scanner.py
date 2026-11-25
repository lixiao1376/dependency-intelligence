from app.code_scanner import scan_project


def test_python_scanner_tracks_import_aliases_and_direct_imports(tmp_path):
    source = tmp_path / "service.py"
    source.write_text(
        "import pydantic as pd\n"
        "from pydantic import validator as check\n\n"
        "class User(pd.BaseModel):\n"
        "    @check('name')\n"
        "    def valid(cls, value): return value\n",
        encoding="utf-8",
    )

    usages = scan_project(str(tmp_path), ["pydantic"], "pydantic")
    symbols = {usage.symbol for usage in usages}

    assert "pydantic.BaseModel" in symbols
    assert "pydantic.validator" in symbols
    assert all(usage.file == "service.py" for usage in usages)


def test_javascript_scanner_tracks_named_imports(tmp_path):
    source = tmp_path / "page.tsx"
    source.write_text(
        "import { createRoot as mount } from 'react-dom/client';\n"
        "const root = mount(node);\n",
        encoding="utf-8",
    )

    usages = scan_project(str(tmp_path), ["react-dom/client"], "react-dom/client")

    assert any(usage.symbol == "react-dom/client.createRoot" for usage in usages)

