"""Release-preparation checks that avoid brittle prose matching."""

from __future__ import annotations

import re
from pathlib import Path

from version import __version__


ROOT = Path(__file__).resolve().parents[1]


def read(relative_path: str) -> str:
    return (ROOT / relative_path).read_text(encoding="utf-8")


def test_readme_has_required_portfolio_sections():
    headings = {
        line.removeprefix("## ").strip().casefold()
        for line in read("README.md").splitlines()
        if line.startswith("## ")
    }
    required = {
        "screenshot or dashboard preview",
        "key features",
        "how netguard works",
        "architecture",
        "browser-only mode",
        "current-session workflow",
        "requirements",
        "installation",
        "running netguard",
        "using the dashboard",
        "detection rules",
        "development mode",
        "database and privacy",
        "reports and exports",
        "testing",
        "project structure",
        "known limitations",
        "ethical and legal use",
        "troubleshooting",
        "future improvements",
        "license",
        "author / student project note",
    }
    assert required <= headings


def test_documentation_and_community_files_exist():
    required_paths = (
        "README.md",
        "LICENSE",
        "SECURITY.md",
        "CONTRIBUTING.md",
        "config.example.env",
        "requirements.txt",
        "requirements-dev.txt",
        "docs/api.md",
        "docs/architecture.md",
        "docs/detection_rules.md",
        "docs/installation.md",
        "docs/testing_lab_setup.md",
        "docs/release_checklist.md",
        "docs/screenshots/README.md",
        ".github/ISSUE_TEMPLATE/bug_report.md",
        ".github/ISSUE_TEMPLATE/feature_request.md",
        ".github/pull_request_template.md",
    )
    assert all((ROOT / path).is_file() for path in required_paths)


def test_runtime_and_development_requirements_are_separated():
    runtime = read("requirements.txt").casefold()
    development = read("requirements-dev.txt").casefold()
    for dependency in ("scapy", "fpdf2", "flask", "psutil"):
        assert dependency in runtime
    assert "pyside6" not in runtime
    assert "matplotlib" not in runtime
    assert "pytest" not in runtime
    assert "-r requirements.txt" in development
    assert "pytest" in development
    assert not re.search(r"(file:|https?://|[a-z]:\\\\)", runtime)


def test_repository_has_no_maintained_desktop_mode():
    assert not (ROOT / "main.py").exists()
    assert not list((ROOT / "gui").glob("**/*.py"))
    assert not list((ROOT / "gui").glob("**/*.qss"))


def test_version_is_consistent_across_release_surfaces():
    assert re.fullmatch(r"\d+\.\d+\.\d+", __version__)
    assert f"Version: **{__version__}**" in read("README.md")
    assert "from version import __version__" in read("app.py")
    assert "from version import __version__" in read("reports/pdf_generator.py")
    assert "from version import __version__" in read("webapp/__init__.py")


def test_gitignore_covers_private_and_generated_artifacts():
    ignore = read(".gitignore")
    required_patterns = (
        ".venv/",
        "venv/",
        "__pycache__/",
        "*.py[cod]",
        ".pytest_cache/",
        "pytest-*/",
        ".pytest-*/",
        ".env",
        "logs/",
        "data/*",
        "*.db",
        "*.db-*",
        "exports/",
        "*.csv",
        "*.pdf",
        "*.pcap",
        "*.pcapng",
        ".idea/",
        ".vscode/",
    )
    assert all(pattern in ignore for pattern in required_patterns)
    for protected in (
        "database/migrations.py",
        "webapp/templates",
        "webapp/static",
        "docs/",
        "tests/",
    ):
        assert protected not in ignore


def test_public_source_and_docs_have_no_personal_absolute_paths_or_guids():
    public_files = [
        *ROOT.glob("*.py"),
        *ROOT.glob("*.md"),
        *ROOT.glob("*.txt"),
        *ROOT.glob("*.env"),
        *ROOT.glob("application/**/*.py"),
        *ROOT.glob("capture/**/*.py"),
        *ROOT.glob("core/**/*.py"),
        *ROOT.glob("database/**/*.py"),
        *ROOT.glob("detection/**/*.py"),
        *ROOT.glob("docs/**/*.md"),
        *ROOT.glob("reports/**/*.py"),
        *ROOT.glob("webapp/**/*.py"),
        *ROOT.glob("webapp/**/*.html"),
        *ROOT.glob("webapp/**/*.js"),
    ]
    personal_path = re.compile(r"(?i)([a-z]:\\(?:users|home)\\|/home/[^/\s]+)")
    adapter_guid = re.compile(
        r"(?i)NPF_\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
        r"[0-9a-f]{4}-[0-9a-f]{12}\}"
    )
    for path in public_files:
        content = path.read_text(encoding="utf-8")
        assert personal_path.search(content) is None, path
        assert adapter_guid.search(content) is None, path


def test_public_text_has_no_common_mojibake_sequences():
    markers = ("\u00e2\u20ac\u201d", "\u00e2\u20ac\u201c", "\u00c3\u2014", "\u00c2\u00b7", "\ufffd")
    paths = [
        *ROOT.glob("*.md"),
        *ROOT.glob("docs/**/*.md"),
        *ROOT.glob("webapp/**/*.html"),
        *ROOT.glob("webapp/**/*.js"),
    ]
    for path in paths:
        content = path.read_text(encoding="utf-8")
        assert not any(marker in content for marker in markers), path


def test_readme_documents_entry_points_and_localhost():
    readme = read("README.md")
    normalized = " ".join(readme.split())
    for value in (
        "python app.py",
        "http://127.0.0.1:5000",
        "pip install -r requirements.txt",
    ):
        assert value in readme
    assert "downloaded before starting another capture" in normalized


def test_virtualbox_guide_does_not_promise_vm_unicast_visibility():
    guide = read("docs/testing_lab_setup.md")
    normalized = " ".join(guide.split())
    assert "does not guarantee" in normalized
    assert "VM-to-VM" not in normalized or "unicast" in normalized
    assert "mirrored/TAP/SPAN" in normalized
    assert "examples, not live NetGuard product data" in normalized


def test_export_and_api_documentation_preserve_payload_exclusion():
    documentation = read("docs/api.md")
    for route in (
        "/api/v1/status",
        "/api/v1/current-session",
        "/api/v1/database/summary",
        "/api/v1/current-session/export/csv",
        "/api/v1/current-session/report/pdf",
    ):
        assert route in documentation
    assert "No CSV contains a payload column" in documentation
    assert not list(ROOT.glob("docs/**/*.csv"))


def test_markdown_relative_links_resolve():
    link_pattern = re.compile(r"\[[^\]]+\]\(([^)]+)\)")
    for path in [ROOT / "README.md", *ROOT.glob("docs/**/*.md")]:
        for target in link_pattern.findall(path.read_text(encoding="utf-8")):
            if (
                "://" in target
                or target.startswith("#")
                or "<" in target
                or target.startswith("mailto:")
            ):
                continue
            link_path = (path.parent / target.split("#", 1)[0]).resolve()
            assert link_path.exists(), f"Broken link in {path}: {target}"


def test_example_configuration_contains_no_secret_or_machine_identity():
    example = read("config.example.env")
    windows_profile_prefix = "C:" + "\\Users\\"
    assert "NETGUARD_HOST=127.0.0.1" in example
    assert "NETGUARD_RETENTION_ENABLED=false" in example
    assert windows_profile_prefix not in example
    assert "\\Device\\NPF_" not in example
    assert not re.search(r"(?i)(password|api_key|secret)=", example)
