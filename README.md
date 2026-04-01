<p align="center">
  <img src="logo.png" alt="VulnHunter logo" width="200">
</p>

<p align="center">
  <strong>Offline vulnerability scanner for project dependencies.</strong>
  <br>
  No API calls, no cloud — just raw CVE hunting on your machine.
</p>

<p align="center">
  <img alt="Python Version" src="https://img.shields.io/badge/Python-3.10%2B-blue">
  <img alt="Offline Support" src="https://img.shields.io/badge/Offline-Yes-brightgreen">
  <img alt="License" src="https://img.shields.io/badge/License-MIT-yellow">
  <img alt="SARIF" src="https://img.shields.io/badge/SARIF-2.1.0-purple">
</p>

<p align="center">
  <a href="#-english">English</a> · <a href="#-português">Português</a>
</p>

---

## 🇺🇸 English

### What it does

VulnHunter scans dependency files across six ecosystems, queries a local vulnerability database (OSV + NVD fallback), and reports known CVEs — completely offline after the initial data download.

| Ecosystem | File | Transitive support |
|---|---|---|
| Python | `requirements.txt` | `pipdeptree` |
| Node.js | `package.json` | `npm ls` |
| Java | `pom.xml` | `mvn dependency:tree` |
| PHP | `composer.json` | `composer show` |
| Ruby | `Gemfile.lock` | built-in |
| Go | `go.mod` | `go list -m` |

### Why offline?

- **Air-gapped environments**: Government, defense, banking — where tools can't phone home.
- **Zero latency**: No network round-trips, instant results.
- **Privacy**: Your dependency tree never leaves your machine.
- **No rate limits**: Scan as much as you want.

### Data sources

| Source | Role | Coverage |
|---|---|---|
| **OSV.dev** (Google) | Primary | PyPI, npm, Maven, Packagist, RubyGems, Go |
| **NVD** (NIST) | Fallback | CPE-based matching across all ecosystems |

### Quick start

```bash
# Install
git clone https://github.com/DevGreick/VulnHunter && cd VulnHunter
pip install -e .

# Download vulnerability data (requires internet, one-time)
vulnhunter db update

# Scan a project
vulnhunter scan /path/to/project

# Scan with SARIF output for GitHub Code Scanning
vulnhunter scan . --format sarif --output results.sarif
```

### CLI reference

```
vulnhunter scan [OPTIONS] PATHS...
  --format, -f    table | json | sarif (default: table)
  --output, -o    Output file path (required for json/sarif)
  --severity, -s  Minimum severity filter: critical, high, medium, low
  --ignore-file   Path to .vulnignore (default: .vulnignore)
  --db            Path to vulnerability database
  --verbose, -v   Enable debug logging

vulnhunter db update [OPTIONS]
  --ecosystem, -e   Ecosystems to update (e.g., PyPI npm)
  --all             Download all ecosystems
  --source          osv | nvd | both (default: osv)

vulnhunter db info
```

### Selective database download

```bash
vulnhunter db update                          # auto-detect from project files
vulnhunter db update --ecosystem PyPI npm     # explicit selection
vulnhunter db update --all                    # everything
vulnhunter db update --source both            # OSV + NVD
```

### Output formats

**Table** (default) — colored terminal output with severity grouping:
```
┌──────────────────────────────────────────────┐
│           VulnHunter Scan Results            │
├──────────┬─────────┬──────────┬──────────────┤
│ Package  │ Version │ Severity │ CVE          │
├──────────┼─────────┼──────────┼──────────────┤
│ flask    │ 2.0.1   │ HIGH     │ CVE-2023-XXX │
│ requests │ 2.25.1  │ CRITICAL │ CVE-2023-YYY │
└──────────┴─────────┴──────────┴──────────────┘
```

**JSON** — machine-readable report:
```bash
vulnhunter scan . --format json --output reports/report.json
```

**SARIF 2.1.0** — integrates with GitHub Code Scanning, VS Code, and other SARIF-compatible tools:
```bash
vulnhunter scan . --format sarif --output results.sarif
```

### Ignoring vulnerabilities

Create a `.vulnignore` file:

```
# Ignore globally
CVE-2023-0001

# Ignore only for a specific package
CVE-2023-0002 requests

# Ignore for namespaced packages
CVE-2023-0003 guzzlehttp/guzzle
```

### Preparing for transitive analysis

For complete dependency tree scanning, ensure dependencies are installed:

| Ecosystem | Command |
|---|---|
| Python | `pip install -r requirements.txt` (in a venv) |
| Node.js | `npm install` |
| Java | `mvn dependency:resolve` |
| PHP | `composer install` |
| Go | `go mod download` |
| Ruby | `bundle install` |

> VulnHunter only **reads** files and runs inspection commands. It never modifies your project.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | No vulnerabilities found |
| `1` | Vulnerabilities found (useful for CI gates) |

### Security

Built with OWASP best practices and secure-by-default design. NVD API key is read exclusively from the `NVD_API_KEY` environment variable.

### Known limitations

- Accuracy depends on OSV/NVD data freshness — run `db update` regularly.
- CPE matching (NVD) can produce false positives for uncommon package names.
- Version comparison uses Python's `packaging.version` — exotic version schemes may not parse.
- Static analysis only: does not analyze how dependencies are used in code.

---

## 🇧🇷 Português

### O que faz

VulnHunter escaneia arquivos de dependência em seis ecossistemas, consulta um banco de vulnerabilidades local (OSV + NVD como fallback) e reporta CVEs conhecidas — completamente offline após o download inicial dos dados.

| Ecossistema | Arquivo | Suporte transitivo |
|---|---|---|
| Python | `requirements.txt` | `pipdeptree` |
| Node.js | `package.json` | `npm ls` |
| Java | `pom.xml` | `mvn dependency:tree` |
| PHP | `composer.json` | `composer show` |
| Ruby | `Gemfile.lock` | nativo |
| Go | `go.mod` | `go list -m` |

### Por que offline?

- **Ambientes air-gapped**: Governo, defesa, bancos — onde ferramentas não podem se comunicar externamente.
- **Zero latência**: Sem round-trips de rede, resultados instantâneos.
- **Privacidade**: Sua árvore de dependências nunca sai da sua máquina.
- **Sem rate limits**: Escaneie o quanto quiser.

### Fontes de dados

| Fonte | Papel | Cobertura |
|---|---|---|
| **OSV.dev** (Google) | Primária | PyPI, npm, Maven, Packagist, RubyGems, Go |
| **NVD** (NIST) | Fallback | Matching via CPE em todos os ecossistemas |

### Início rápido

```bash
# Instalar
git clone https://github.com/DevGreick/VulnHunter && cd VulnHunter
pip install -e .

# Baixar dados de vulnerabilidades (requer internet, uma vez)
vulnhunter db update

# Escanear um projeto
vulnhunter scan /caminho/do/projeto

# Escanear com saída SARIF para GitHub Code Scanning
vulnhunter scan . --format sarif --output results.sarif
```

### Referência CLI

```
vulnhunter scan [OPÇÕES] CAMINHOS...
  --format, -f    table | json | sarif (padrão: table)
  --output, -o    Caminho do arquivo de saída (obrigatório para json/sarif)
  --severity, -s  Filtro de severidade mínima: critical, high, medium, low
  --ignore-file   Caminho para .vulnignore (padrão: .vulnignore)
  --db            Caminho para o banco de vulnerabilidades
  --verbose, -v   Habilitar logging de debug

vulnhunter db update [OPÇÕES]
  --ecosystem, -e   Ecossistemas para atualizar (ex: PyPI npm)
  --all             Baixar todos os ecossistemas
  --source          osv | nvd | both (padrão: osv)

vulnhunter db info
```

### Download seletivo do banco

```bash
vulnhunter db update                          # auto-detecção pelos arquivos do projeto
vulnhunter db update --ecosystem PyPI npm     # seleção explícita
vulnhunter db update --all                    # tudo
vulnhunter db update --source both            # OSV + NVD
```

### Formatos de saída

**Table** (padrão) — saída colorida no terminal com agrupamento por severidade.

**JSON** — relatório legível por máquina:
```bash
vulnhunter scan . --format json --output reports/report.json
```

**SARIF 2.1.0** — integra com GitHub Code Scanning, VS Code e outras ferramentas compatíveis:
```bash
vulnhunter scan . --format sarif --output results.sarif
```

### Ignorando vulnerabilidades

Crie um arquivo `.vulnignore`:

```
# Ignorar globalmente
CVE-2023-0001

# Ignorar apenas para um pacote específico
CVE-2023-0002 requests

# Ignorar para pacotes com namespace
CVE-2023-0003 guzzlehttp/guzzle
```

### Preparação para análise transitiva

Para escaneamento completo da árvore de dependências, garanta que as dependências estão instaladas:

| Ecossistema | Comando |
|---|---|
| Python | `pip install -r requirements.txt` (em uma venv) |
| Node.js | `npm install` |
| Java | `mvn dependency:resolve` |
| PHP | `composer install` |
| Go | `go mod download` |
| Ruby | `bundle install` |

> VulnHunter apenas **lê** arquivos e executa comandos de inspeção. Ele nunca modifica seu projeto.

### Códigos de saída

| Código | Significado |
|---|---|
| `0` | Nenhuma vulnerabilidade encontrada |
| `1` | Vulnerabilidades encontradas (útil para gates de CI) |

### Segurança

Construído com boas práticas OWASP e design secure-by-default. A API key do NVD é lida exclusivamente da variável de ambiente `NVD_API_KEY`.

### Limitações conhecidas

- Precisão depende da atualização dos dados OSV/NVD — execute `db update` regularmente.
- Matching por CPE (NVD) pode gerar falsos positivos para pacotes incomuns.
- Comparação de versões usa `packaging.version` do Python — esquemas exóticos podem não ser parseados.
- Análise estática apenas: não analisa como as dependências são usadas no código.

---

## License

MIT License — see [LICENSE](LICENSE) for details.

## Author

Built by [DevGreick](https://github.com/DevGreick)

<div align="right">
  <a href="https://buymeacoffee.com/devgreick" target="_blank">
    <img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me a Coffee" width="120">
  </a>
</div>
