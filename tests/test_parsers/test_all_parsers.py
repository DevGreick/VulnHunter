from pathlib import Path

from vulnhunter.models import Ecosystem
from vulnhunter.parsers import parse_file

FIXTURES = Path(__file__).parent.parent / "fixtures"


def test_parse_requirements_valid() -> None:
    deps = parse_file(FIXTURES / "requirements_valid.txt")
    assert len(deps) >= 2
    names = {d.name.lower() for d in deps}
    assert "flask" in names
    assert "requests" in names
    for d in deps:
        assert d.ecosystem == Ecosystem.PYPI


def test_parse_requirements_empty() -> None:
    deps = parse_file(FIXTURES / "requirements_empty.txt")
    assert len(deps) == 0


def test_parse_package_json() -> None:
    deps = parse_file(FIXTURES / "package_valid.json")
    assert len(deps) >= 3
    names = {d.name.lower() for d in deps}
    assert "express" in names
    assert "lodash" in names
    assert "jest" in names
    for d in deps:
        assert d.ecosystem == Ecosystem.NPM
        assert not d.version.startswith("^")
        assert not d.version.startswith("~")


def test_parse_pom_xml() -> None:
    deps = parse_file(FIXTURES / "pom_valid.xml")
    assert len(deps) >= 2
    versions = {d.version for d in deps}
    assert "6.2.2" in versions
    for d in deps:
        assert d.ecosystem == Ecosystem.MAVEN


def test_parse_composer_json() -> None:
    deps = parse_file(FIXTURES / "composer_valid.json")
    names = {d.name.lower() for d in deps}
    assert "guzzlehttp/guzzle" in names
    assert "monolog/monolog" in names
    assert "php" not in names
    for d in deps:
        assert d.ecosystem == Ecosystem.PACKAGIST


def test_parse_gemfile_lock() -> None:
    deps = parse_file(FIXTURES / "Gemfile.lock")
    assert len(deps) >= 2
    names = {d.name.lower() for d in deps}
    assert "rack" in names
    assert "sinatra" in names
    for d in deps:
        assert d.ecosystem == Ecosystem.RUBYGEMS


def test_parse_go_mod() -> None:
    deps = parse_file(FIXTURES / "go.mod")
    assert len(deps) >= 2
    names = {d.name.lower() for d in deps}
    assert "github.com/gin-gonic/gin" in names
    assert "golang.org/x/crypto" in names
    for d in deps:
        assert d.ecosystem == Ecosystem.GO
        assert not d.version.startswith("v")
