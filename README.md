<p align="center">
  <img src="logo.png" alt="VulnHunter" width="180">
</p>

<h1 align="center">VulnHunter</h1>

<p align="center">
  <strong>Your dependencies have secrets. VulnHunter finds them.</strong>
  <br>
  Offline vulnerability scanner with AI-powered triage — no cloud, no API calls, no data leaves your machine.
</p>

<p align="center">
  <img alt="Python" src="https://img.shields.io/badge/Python-3.8%2B-3776AB?logo=python&logoColor=white">
  <img alt="License" src="https://img.shields.io/badge/License-MIT-green">
  <img alt="Offline" src="https://img.shields.io/badge/100%25-Offline-00e5ff">
  <img alt="AI Triage" src="https://img.shields.io/badge/AI_Triage-Ollama-ff6f00?logo=ai&logoColor=white">
  <img alt="SARIF" src="https://img.shields.io/badge/SARIF-2.1.0-8b5cf6">
  <img alt="Ecosystems" src="https://img.shields.io/badge/Ecosystems-7-00e5ff">
</p>

<p align="center">
  <a href="https://devgreick.github.io/VulnHunter">Docs</a> · <a href="#-quick-start">Quick Start</a> · <a href="#-ai-triage">AI Triage</a> · <a href="#-português-br">Português</a>
</p>

---

## What makes VulnHunter different

Most vulnerability scanners send your dependency tree to a cloud service. VulnHunter does everything locally:

- **Scans 7 ecosystems** — Python, Node.js, Go, Rust, Java, PHP, Ruby
- **AI triage via Ollama** — a local LLM reads your code and tells you which CVEs are actually exploitable in your context
- **Zero network after setup** — works in air-gapped, government, and banking environments
- **Secrets stay safe** — API keys stored in your OS keyring, never in config files

---

## Quick Start

```bash
# Install
pip install vulnhunter

# Interactive setup (detects Ollama, configures AI, sets language)
vulnhunter init

# Scan your project
vulnhunter scan .

# Scan with AI triage
vulnhunter scan . --ai-triage
```

That's it. Three commands from zero to vulnerability report.

---

## AI Triage

Regular scanners dump a list of CVEs and leave you guessing. VulnHunter's AI triage reads your actual source code, correlates it with each CVE, and answers the question that matters: **is this vulnerability reachable in my code?**

```bash
vulnhunter scan . --ai-triage
```

```
╭──────────────── AI Triage Results ────────────────╮
│ CVE            │ Package  │ Risk     │ Action      │
├────────────────┼──────────┼──────────┼─────────────┤
│ CVE-2023-XXXX  │ flask    │ HIGH     │ Upgrade now │
│ CVE-2023-YYYY  │ requests │ LOW      │ Not exposed │
╰────────────────┴──────────┴──────────┴─────────────╯
```

Runs entirely on your machine via [Ollama](https://ollama.com). Recommended models:

| Model | Use case |
|---|---|
| `phi3:3.8b` | Fast triage, low resources |
| `mistral` | Best speed/accuracy balance |
| `llama3:8b` | Deep analysis, best results |

---

## Setup Wizard

`vulnhunter init` launches an interactive wizard with selectable menus (no typos):

- Detects your system language (EN/PT-BR)
- Finds running Ollama and available models
- Lets you pick a model from a list with size and tier info
- Stores your NVD API key securely in the OS keyring

---

## Supported Ecosystems

| Ecosystem | Files | Transitive Deps |
|---|---|---|
| **Python** | `requirements.txt` · `Pipfile.lock` · `poetry.lock` · `uv.lock` | `pipdeptree` |
| **Node.js** | `package-lock.json` · `yarn.lock` · `pnpm-lock.yaml` | `npm ls` |
| **Go** | `go.sum` · `go.mod` | `go mod graph` |
| **Rust** | `Cargo.lock` | Built-in |
| **Java** | `pom.xml` · `build.gradle` | `mvn dependency:tree` |
| **PHP** | `composer.lock` | `composer show` |
| **Ruby** | `Gemfile.lock` | `bundle list` |

---

## Data Sources

| Source | Role | Coverage |
|---|---|---|
| **OSV.dev** (Google) | Primary | PyPI, npm, Maven, Packagist, RubyGems, Go |
| **NVD** (NIST) | Fallback | CPE-based matching across all ecosystems |

Database is updated weekly via GitHub Actions. Download once, scan forever:

```bash
vulnhunter db download    # Pre-built database (fastest)
vulnhunter db update      # Build from OSV/NVD sources
vulnhunter db info        # Check database stats
```

---

## Output Formats

**Table** — colored terminal output with severity grouping (default)

**JSON** — machine-readable report
```bash
vulnhunter scan . -f json -o report.json
```

**SARIF 2.1.0** — GitHub Code Scanning, VS Code SARIF Viewer
```bash
vulnhunter scan . -f sarif -o results.sarif
```

---

## CLI Reference

```
vulnhunter init                          Setup wizard
vulnhunter scan [PATHS] [OPTIONS]        Scan for vulnerabilities
  --ai-triage                            Enable AI analysis
  --model MODEL                          Override AI model
  -f, --format [table|json|sarif]        Output format
  -o, --output FILE                      Save report to file
  -s, --severity [critical|high|...]     Minimum severity filter
  --ignore-file FILE                     Path to .vulnignore
  -v, --verbose                          Debug logging

vulnhunter db update [OPTIONS]           Update vulnerability database
  --ecosystem ECOSYSTEMS                 Select specific ecosystems
  --all                                  Download all ecosystems
  --source [osv|nvd|both]                Data source

vulnhunter db download                   Download pre-built database
vulnhunter db info                       Show database stats

vulnhunter config                        View current settings
vulnhunter config set-nvd-key            Save NVD API key to keyring
vulnhunter config remove-nvd-key         Remove NVD API key from keyring
```

---

## CI/CD Integration

```yaml
# .github/workflows/vulnhunter.yml
name: Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install vulnhunter
      - run: vulnhunter db download
      - run: vulnhunter scan . -f sarif -o results.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

---

## Ignoring Vulnerabilities

Create a `.vulnignore` file:

```
# Ignore globally
CVE-2023-0001

# Ignore for a specific package
CVE-2023-0002 requests

# Ignore namespaced packages
CVE-2023-0003 guzzlehttp/guzzle
```

---

## Security

- API keys stored in OS keyring via `keyring` — never in plaintext
- No data exfiltration — all scanning and AI analysis happens locally
- OWASP best practices in every module
- Input validation, parameterized queries, no `eval`/`exec`
- Exit code `1` on vulnerabilities found — use as CI gate

---

## Known Limitations

- Accuracy depends on OSV/NVD data freshness — run `db update` regularly
- CPE matching (NVD) can produce false positives for uncommon package names
- AI triage is suggestive — always validate critical findings manually
- Static analysis only — does not execute code or analyze runtime behavior

---

---

## Português (BR)

<p align="center">
  <strong>Suas dependências têm segredos. O VulnHunter encontra.</strong>
  <br>
  Scanner offline de vulnerabilidades com triagem por IA — sem cloud, sem chamadas de API, nenhum dado sai da sua máquina.
</p>

### O que torna o VulnHunter diferente

A maioria dos scanners de vulnerabilidade envia sua árvore de dependências para um serviço na nuvem. O VulnHunter faz tudo localmente:

- **Escaneia 7 ecossistemas** — Python, Node.js, Go, Rust, Java, PHP, Ruby
- **Triagem com IA via Ollama** — uma LLM local lê seu código e diz quais CVEs são realmente exploráveis no seu contexto
- **Zero rede após o setup** — funciona em ambientes air-gapped, governo e bancos
- **Segredos protegidos** — chaves de API armazenadas no keyring do sistema, nunca em arquivos de config

### Início Rápido

```bash
# Instalar
pip install vulnhunter

# Setup interativo (detecta Ollama, configura IA, define idioma)
vulnhunter init

# Escanear seu projeto
vulnhunter scan .

# Escanear com triagem por IA
vulnhunter scan . --ai-triage
```

Só isso. Três comandos do zero ao relatório de vulnerabilidades.

### Triagem com IA

Scanners comuns despejam uma lista de CVEs e te deixam adivinhando. A triagem do VulnHunter lê seu código-fonte real, correlaciona com cada CVE e responde a pergunta que importa: **essa vulnerabilidade é alcançável no meu código?**

```bash
vulnhunter scan . --ai-triage
```

Roda inteiramente na sua máquina via [Ollama](https://ollama.com). Modelos recomendados:

| Modelo | Uso |
|---|---|
| `phi3:3.8b` | Triagem rápida, poucos recursos |
| `mistral` | Melhor equilíbrio velocidade/precisão |
| `llama3:8b` | Análise profunda, melhores resultados |

### Wizard de Setup

`vulnhunter init` abre um wizard interativo com menus selecionáveis (sem erros de digitação):

- Detecta o idioma do sistema (EN/PT-BR)
- Encontra Ollama rodando e modelos disponíveis
- Permite escolher modelo de uma lista com tamanho e tier
- Armazena sua API key do NVD com segurança no keyring do sistema

### Ecossistemas Suportados

| Ecossistema | Arquivos | Deps Transitivas |
|---|---|---|
| **Python** | `requirements.txt` · `Pipfile.lock` · `poetry.lock` · `uv.lock` | `pipdeptree` |
| **Node.js** | `package-lock.json` · `yarn.lock` · `pnpm-lock.yaml` | `npm ls` |
| **Go** | `go.sum` · `go.mod` | `go mod graph` |
| **Rust** | `Cargo.lock` | Nativo |
| **Java** | `pom.xml` · `build.gradle` | `mvn dependency:tree` |
| **PHP** | `composer.lock` | `composer show` |
| **Ruby** | `Gemfile.lock` | `bundle list` |

### Fontes de Dados

| Fonte | Papel | Cobertura |
|---|---|---|
| **OSV.dev** (Google) | Primária | PyPI, npm, Maven, Packagist, RubyGems, Go |
| **NVD** (NIST) | Fallback | Matching via CPE em todos os ecossistemas |

Banco atualizado semanalmente via GitHub Actions. Baixe uma vez, escaneie sempre:

```bash
vulnhunter db download    # Banco pré-construído (mais rápido)
vulnhunter db update      # Construir a partir das fontes OSV/NVD
vulnhunter db info        # Ver estatísticas do banco
```

### Formatos de Saída

**Table** — saída colorida no terminal com agrupamento por severidade (padrão)

**JSON** — relatório legível por máquina
```bash
vulnhunter scan . -f json -o report.json
```

**SARIF 2.1.0** — GitHub Code Scanning, VS Code SARIF Viewer
```bash
vulnhunter scan . -f sarif -o results.sarif
```

### Referência CLI

```
vulnhunter init                          Wizard de configuração
vulnhunter scan [CAMINHOS] [OPÇÕES]      Escanear vulnerabilidades
  --ai-triage                            Ativar análise com IA
  --model MODELO                         Sobrescrever modelo de IA
  -f, --format [table|json|sarif]        Formato de saída
  -o, --output ARQUIVO                   Salvar relatório em arquivo
  -s, --severity [critical|high|...]     Filtro de severidade mínima
  --ignore-file ARQUIVO                  Caminho para .vulnignore
  -v, --verbose                          Log de debug

vulnhunter db update [OPÇÕES]            Atualizar banco de vulnerabilidades
  --ecosystem ECOSSISTEMAS               Selecionar ecossistemas específicos
  --all                                  Baixar todos os ecossistemas
  --source [osv|nvd|both]                Fonte de dados

vulnhunter db download                   Baixar banco pré-construído
vulnhunter db info                       Ver estatísticas do banco

vulnhunter config                        Ver configurações atuais
vulnhunter config set-nvd-key            Salvar API key do NVD no keyring
vulnhunter config remove-nvd-key         Remover API key do NVD do keyring
```

### Integração CI/CD

```yaml
# .github/workflows/vulnhunter.yml
name: Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install vulnhunter
      - run: vulnhunter db download
      - run: vulnhunter scan . -f sarif -o results.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

### Ignorando Vulnerabilidades

Crie um arquivo `.vulnignore`:

```
# Ignorar globalmente
CVE-2023-0001

# Ignorar para um pacote específico
CVE-2023-0002 requests

# Ignorar pacotes com namespace
CVE-2023-0003 guzzlehttp/guzzle
```

### Segurança

- Chaves de API no keyring do sistema via `keyring` — nunca em texto puro
- Zero exfiltração de dados — todo scan e análise de IA acontece localmente
- Boas práticas OWASP em todos os módulos
- Validação de input, queries parametrizadas, sem `eval`/`exec`
- Exit code `1` quando vulnerabilidades são encontradas — use como gate de CI

### Limitações Conhecidas

- Precisão depende da atualização dos dados OSV/NVD — execute `db update` regularmente
- Matching por CPE (NVD) pode gerar falsos positivos para pacotes incomuns
- Triagem com IA é sugestiva — sempre valide findings críticos manualmente
- Análise estática apenas — não executa código nem analisa comportamento em runtime

---

## License

MIT License. See [LICENSE](LICENSE) for details.

## Author

Built by [DevGreick](https://github.com/DevGreick)
