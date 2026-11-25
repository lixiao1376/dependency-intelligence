from app.evidence import _change_excerpts, _github_repo


def test_repository_is_extracted_from_project_urls():
    assert _github_repo(["git+https://github.com/pydantic/pydantic.git"]) == "pydantic/pydantic"


def test_change_excerpt_extracts_signal_and_code_symbol():
    excerpts, symbols, signals = _change_excerpts(
        "## Changes\n- Breaking change: `parse_obj` was removed and replaced by `model_validate`."
    )

    assert excerpts
    assert symbols == ["model_validate", "parse_obj"]
    assert {"breaking", "removed", "renamed"} <= set(signals)

