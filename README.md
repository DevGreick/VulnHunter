<p align="center">
  <img src="logo.png" alt="VulnHunter logo" width="200">
</p>

<p align="center">
  <strong>Scanner de vulnerabilidades offline para dependências de projetos.</strong>
  <br>
  Sem chamadas de API, sem nuvem, apenas caça a CVEs na sua máquina.
</p>

<p align="center">
  <img alt="Python Version" src="https://img.shields.io/badge/Python-3.10%2B-blue">
  <img alt="Offline Support" src="https://img.shields.io/badge/Offline-Yes-brightgreen">
  <img alt="License" src="https://img.shields.io/badge/License-MIT-yellow">
</p>

## O que ele faz

O VulnHunter escaneia arquivos de dependência de ecossistemas comuns como:

* Python (`requirements.txt`)
* Java (`pom.xml`)
* Node.js (`package.json`)
* PHP (`composer.json`)
* Ruby (`Gemfile.lock`)
* Go (`go.mod`)

Ele então verifica cada dependência (incluindo a versão) contra uma Base de Dados Nacional de Vulnerabilidades (NVD) convertida localmente, utilizando um índice de alias personalizado de Common Platform Enumeration (CPE) para melhorar a precisão da correspondência com CVEs conhecidas.

## Por que offline?

* **Sem internet? Sem problemas:** Escaneie em qualquer lugar, a qualquer hora.
* **Resultados mais rápidos:** A ausência de atraso de rede significa varreduras mais rápidas.
* **Privacidade e Segurança Aprimoradas:** Ideal para ambientes isolados (air-gapped) ou restritos; os dados do seu projeto e dependências nunca saem da sua máquina.
* **Sem Limites de Taxa de API:** Escaneamento ilimitado sem se preocupar com cotas de serviços externos.

## Funcionalidades

* Detecta CVEs conhecidas nas dependências do seu projeto (diretas e transitivas).
* Usa feeds da NVD convertidos localmente, eliminando a necessidade de acesso constante à API após o download inicial dos dados.
* Suporte integrado para múltiplas linguagens de programação e seus formatos comuns de manifesto de dependência.
* Resolvedor de alias CPE personalizado para melhorar a precisão na correspondência de nomes de dependências com nomes de produtos da NVD.
* Saída de interface de linha de comando limpa e informativa, detalhando bibliotecas vulneráveis, versões e CVEs associados.
* Gera um relatório JSON rico em detalhes para fácil integração com outras ferramentas ou para arquivamento.
* Permite ignorar CVEs específicos globalmente ou por pacote através de um arquivo `.vulnignore`.

## Preparando o Projeto Alvo para Análise Transitiva

Para a análise transitiva mais precisa, é crucial que o projeto alvo **tenha suas dependências devidamente instaladas ou resolvidas em seu ecossistema *antes* de executar o VulnHunter.** Isso permite que as ferramentas específicas de cada linguagem descubram a árvore de dependências completa.

* **Node.js**: Execute `npm install`.
* **Java (Maven)**: Execute `mvn clean install` ou `mvn dependency:resolve`.
* **PHP (Composer)**: Execute `composer install`.
* **Python**: É melhor ter um ambiente virtual ativo com as dependências instaladas via `pip install -r requirements.txt`.
* **Go**: Execute `go mod tidy` e/ou `go mod download`.
* **Ruby**: Execute `bundle install`.

**Nota Importante:** O VulnHunter **lê** esses arquivos e usa ferramentas de CLI para inspecionar o ambiente; ele **não executa nenhum comando de instalação ou modifica seus arquivos de projeto.**

## Como usar

1.  **Clone o Repositório:**
    ```bash
    git clone [https://github.com/DevGreick/VulnHunter](https://github.com/DevGreick/VulnHunter)
    cd VulnHunter
    ```

2.  **Configure seu Ambiente e Instale as Dependências:**
    Recomenda-se o uso de um ambiente virtual Python.
    ```bash
    python3 -m venv .venv
    source .venv/bin/activate  # No Windows use: .venv\Scripts\activate
    pip install -r requirements.txt
    ```

3.  **Atualize os Dados Locais da NVD e CPE:**
    Este passo requer acesso à internet e pode levar vários minutos, especialmente na primeira vez.
    ```bash
    python3 -m scan --update-nvd
    ```
    Este comando popula o diretório `data/` com os arquivos processados necessários.

4.  **Execute a Análise em seu Projeto:**
    Aponte o VulnHunter para o diretório do seu projeto:
    ```bash
    python3 -m scan --dir caminho/para/seu/projeto
    ```
    Ou para arquivos específicos:
    ```bash
    python3 -m scan --dir ./projeto/requirements.txt ./outro/projeto/pom.xml
    ```
    Para mais detalhes, use o nível de log `DEBUG`:
    ```bash
    python3 -m scan --dir caminho/para/seu/projeto --log-level DEBUG
    ```

5.  **Revise os Resultados:**
    As vulnerabilidades encontradas serão impressas no console. Um relatório JSON (`report.json`) também será gerado no diretório `reports/`.

## Ajuda da CLI

Para ver todas as opções de linha de comando disponíveis, execute:
```bash
python3 -m scan --help
```

## Ignorando Vulnerabilidades

Crie um arquivo `.vulnignore` no diretório de onde você executa o comando `scan`, ou especifique um caminho customizado com `--ignore-file`.

O formato é uma regra por linha:

* `CVE-YYYY-XXXXX`: Ignora esta CVE para todos os pacotes.
* `CVE-YYYY-ZZZZZ nome-do-pacote`: Ignora esta CVE apenas para o pacote especificado.
* Linhas começando com `#` são comentários.

Exemplo de conteúdo `.vulnignore`:
```
# Ignorar esta CVE globalmente
CVE-2023-0001

# Ignorar esta CVE apenas para o pacote 'requests'
CVE-2023-0002 requests
```

## Estrutura do Relatório

O scanner gera um relatório JSON (padrão: `reports/report.json`) contendo uma lista de vulnerabilidades encontradas.

Exemplo de saída JSON (`reports/report.json`):
```json
[
  {
    "name": "flask",
    "version": "2.0.1",
    "cve_id": "CVE-2023-30861",
    "severity": "HIGH",
    "summary": "Uma vulnerabilidade no Flask versões anteriores a X.Y.Z permite..."
  },
  {
    "name": "requests",
    "version": "2.19.1",
    "cve_id": "CVE-2023-32681",
    "severity": "MEDIUM",
    "summary": "A biblioteca Requests antes de A.B.C é suscetível a..."
  }
]
```

## Requisitos

* Python 3.10+
* Acesso à internet é necessário **apenas** para a configuração inicial dos dados (`--update-nvd`).
* Funciona em Linux, macOS e Windows (garanta que as ferramentas de build de cada linguagem estejam no seu PATH).
