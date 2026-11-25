from app.versioning import in_upgrade_range, parse_version, stable_versions


def test_versions_are_normalized_and_sorted():
    assert str(parse_version("v2.1.0")) == "2.1.0"
    assert [str(item) for item in stable_versions(["2.0.0rc1", "1.9.0", "2.0.0"])] == [
        "1.9.0",
        "2.0.0",
    ]


def test_upgrade_range_excludes_current_and_newer_versions():
    assert in_upgrade_range("1.5.0", "1.0.0", "2.0.0")
    assert not in_upgrade_range("1.0.0", "1.0.0", "2.0.0")
    assert not in_upgrade_range("2.1.0", "1.0.0", "2.0.0")

