# tests/test_parsers.py
from pathlib import Path
import pytest
from src.parsers import DependencyParser
from src.models import Dependency

TEST_INPUT_DIR = Path(__file__).parent / "test_inputs"

def test_parse_requirements_txt_valid():
    parser = DependencyParser(str(TEST_INPUT_DIR / "requirements_valid.txt"))
    dependencies = parser.extract_dependencies()
    assert len(dependencies) == 2
    assert Dependency(name="flask", version="2.0.1") in dependencies
    assert Dependency(name="requests", version="2.25.1") in dependencies

def test_parse_requirements_txt_empty():
    parser = DependencyParser(str(TEST_INPUT_DIR / "requirements_empty.txt"))
    dependencies = parser.extract_dependencies()
    assert len(dependencies) == 0

def test_parse_requirements_txt_various():
    parser = DependencyParser(str(TEST_INPUT_DIR / "requirements_various.txt"))
    dependencies = parser.extract_dependencies()
    expected = [
        Dependency(name="click", version="7.0"),
        Dependency(name="Django", version="3.2"),
        Dependency(name="numpy", version="1.20"),
        Dependency(name="scipy", version="1.5.0")
    ]
    assert len(dependencies) == len(expected)
    for dep in expected:
        assert dep in dependencies

def test_parse_pom_xml_valid():
    parser = DependencyParser(str(TEST_INPUT_DIR / "pom_valid.xml"))
    dependencies = parser.extract_dependencies()
    expected = [
        Dependency(name="spring-core", version="5.3.8"),
        Dependency(name="guava", version="30.1-jre")
    ]
    assert len(dependencies) == len(expected)
    for dep in expected:
        assert dep in dependencies

def test_parse_pom_xml_empty_deps():
    parser = DependencyParser(str(TEST_INPUT_DIR / "pom_empty_deps.xml"))
    dependencies = parser.extract_dependencies()
    assert len(dependencies) == 0

def test_parse_pom_xml_with_properties():
    parser = DependencyParser(str(TEST_INPUT_DIR / "pom_with_properties.xml"))
    dependencies = parser.extract_dependencies()
    expected = [
        Dependency(name="spring-context", version="5.2.5.RELEASE")
    ]
    assert len(dependencies) == len(expected)
    for dep in expected:
        assert dep in dependencies

def test_parse_package_json_valid():
    parser = DependencyParser(str(TEST_INPUT_DIR / "package_valid.json"))
    dependencies = parser.extract_dependencies()
    expected = [
        Dependency(name="express", version="4.17.1"),
        Dependency(name="lodash", version="4.17.20"),
        Dependency(name="jest", version="26.6.3")
    ]
    assert len(dependencies) == len(expected)
    for dep in expected:
        assert dep in dependencies

def test_parse_package_json_empty_deps():
    parser = DependencyParser(str(TEST_INPUT_DIR / "package_empty_deps.json"))
    dependencies = parser.extract_dependencies()
    assert len(dependencies) == 0

def test_parse_composer_json_valid():
    parser = DependencyParser(str(TEST_INPUT_DIR / "composer_valid.json"))
    dependencies = parser.extract_dependencies()

    # O parser atual é bem agressivo na limpeza de versões do composer.json
    # "2.0.*" se torna "2.0"
    # "^3.0" se torna "3.0"
    # "^9.5" se torna "9.5"
    expected_normalized = [
        Dependency(name="monolog/monolog", version="2.0"),
        Dependency(name="slim/slim", version="3.0"),
        Dependency(name="phpunit/phpunit", version="9.5")
    ]
    assert len(dependencies) == len(expected_normalized)
    for dep in expected_normalized:
        assert dep in dependencies

def test_parse_gemfile_lock_valid():
    parser = DependencyParser(str(TEST_INPUT_DIR / "gemfile_lock_valid.lock"))
    dependencies = parser.extract_dependencies()
    expected_minimal = [
        Dependency(name="actionmailer", version="6.1.3.2"),
        Dependency(name="actionpack", version="6.1.3.2"),
        Dependency(name="concurrent-ruby", version="1.1.9")
    ]
    # O parser atual para Gemfile.lock é bem simples e só pega gems de nível superior na seção GEM
    assert len(dependencies) == len(expected_minimal)
    for dep in expected_minimal:
        assert dep in dependencies

def test_parse_go_mod_valid():
    parser = DependencyParser(str(TEST_INPUT_DIR / "go_mod_valid.mod"))
    dependencies = parser.extract_dependencies()
    expected = [
        Dependency(name="github.com/gin-gonic/gin", version="1.7.1"),
        Dependency(name="github.com/stretchr/testify", version="1.7.0"),
        Dependency(name="rsc.io/quote", version="1.5.2")
    ]
    # Se este teste falhar com 0 dependências, verifique o _parse_go_mod
    # e o conteúdo de tests/test_inputs/go_mod_valid.mod.
    # A lógica atual do _parse_go_mod que forneci deve funcionar com o exemplo de go_mod_valid.mod.
    assert len(dependencies) == len(expected)
    for dep in expected:
        assert dep in dependencies

def test_non_existent_file():
    with pytest.raises(FileNotFoundError):
        DependencyParser(str(TEST_INPUT_DIR / "non_existent_file.txt"))
