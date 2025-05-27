<p align="center">
  <img src="logo.png" alt="VulnHunter logo" width="200">
</p>

<p align="center">
  <strong>Offline vulnerability scanner for project dependencies.</strong>
  <br>
  No API calls, no cloud, just raw CVE hunting on your machine.
</p>

<p align="center">
  <img alt="Python Version" src="https://img.shields.io/badge/Python-3.10%2B-blue">
  <img alt="Offline Support" src="https://img.shields.io/badge/Offline-Yes-brightgreen">
  <img alt="License" src="https://img.shields.io/badge/License-MIT-yellow">
</p>

## What it does

VulnHunter scans dependency files from common ecosystems like:

* Python (`requirements.txt`)
* Java (`pom.xml`)
* Node.js (`package.json`)
* PHP (`composer.json`)
* Ruby (`Gemfile.lock`)
* Go (`go.mod`)

It then checks each dependency (including version) against a locally converted National Vulnerability Database (NVD), utilizing a custom Common Platform Enumeration (CPE) alias index to improve matching accuracy against known CVEs.

## Why offline?

* **No internet? No problem:** Scan anywhere, anytime.
* **Faster results:** Zero network delay means quicker scans.
* **Enhanced Privacy & Security:** Ideal for air-gapped or restricted environments; your project data and dependencies never leave your machine.
* **No API Rate Limits:** Unlimited scanning without worrying about external service quotas.

## Features

* Detects known CVEs in your project's dependencies (both direct and transitive).
* Uses locally converted NVD feeds, eliminating the need for constant API access after initial data download.
* Built-in support for multiple programming languages and their common dependency manifest formats.
* Custom CPE alias resolver to improve accuracy in matching dependencies to NVD product names (e.g., correctly identifying "flask", "guzzlehttp/guzzle").
* Clean and informative command-line interface output, detailing vulnerable libraries, versions, and associated CVEs.
* Generates a JSON report rich in detail for easy integration with other tools or for archiving.
* Modular Python codebase, leveraging Pydantic V2 for data validation, `argparse` for CLI, and `logging` for detailed execution tracing.
* Allows ignoring specific CVEs globally or per-package via a `.vulnignore` file.

## Preparing the Target Project for Transitive Analysis

VulnHunter is designed to detect vulnerabilities in both direct dependencies (those explicitly listed in your manifest file) and transitive dependencies (dependencies of your dependencies).

For the most accurate transitive analysis, **it's** crucial that the target **project has its dependencies properly installed or resolved within its ecosystem *before* running VulnHunter.** This allows VulnHunter's language-specific tools to discover the complete dependency tree.

Here are common preparation steps for each ecosystem:

* **Node.js**: Run `npm install` or `yarn install` in your project directory. This generates `package-lock.json`/`yarn.lock` and the `node_modules/` directory, which are essential for full tree analysis.
* **Java (Maven)**: Ensure dependencies are resolved. Running `mvn clean install` (builds the project and downloads dependencies) or `mvn dependency:resolve` is recommended. `mvn dependency:tree` can be used to inspect the tree.
* **PHP (Composer)**: Run `composer install` in your project directory. This creates/updates `composer.lock` and installs packages into the `vendor/` directory.
* **Python**: While `pipdeptree` (used by VulnHunter) can often work in a clean environment if packages are installed globally or in a virtual environment, it's best to have an active virtual environment with all project dependencies installed via `pip install -r requirements.txt`.
* **Go**: Run `go mod tidy` and/or `go mod download` to ensure your `go.mod` file is consistent and all necessary modules are downloaded to the local cache.
* **Ruby**: Run `bundle install`. This will ensure your `Gemfile.lock` is up-to-date and all gems are installed.

**Important Note:** VulnHunter **reads** these files and uses CLI tools to inspect the environment; it **does not run any install commands or modify your project files or environment in any way.** Your project remains completely untouched by the scanning process itself.

## How to use

1.  **Clone the Repository:**
    ```bash
    git clone [https://github.com/DevGreick/VulnHunter](https://github.com/DevGreick/VulnHunter)
    cd VulnHunter
    ```

2.  **Set Up Your Environment and Install Dependencies:**
    It's highly recommended to use a Python virtual environment.
    ```bash
    python3 -m venv .venv
    source .venv/bin/activate  # On Windows use: .venv\Scripts\activate
    pip install -r requirements.txt
    ```
    (Ensure the `requirements.txt` file for VulnHunter itself is present in the cloned repository).

3.  **Update Local NVD and CPE Data:**
    This step requires internet access and downloads and processes the necessary vulnerability data. It may take several minutes, especially on the first run. Subsequent updates are typically faster.
    ```bash
    python3 -m scan --update-nvd
    ```
    This command populates the `data/` directory with processed NVD feeds (`nvd_cve_rebuilt.json`) and the CPE alias index (`data/cpe/cpe_alias_index.json`).

4.  **Run the Scan on Your Project:**
    Point VulnHunter to the directory of your project:
    ```bash
    python3 -m scan --dir path/to/your/project
    ```
    You can also scan specific dependency manifest files or multiple paths:
    ```bash
    python3 -m scan --dir ./your/project/requirements.txt ./another/project/pom.xml
    ```
    To test with the input files included in this repository:
    ```bash
    python3 -m scan --dir inputs/
    ```
    For more detailed output during the scan, use the `--log-level DEBUG` option:
    ```bash
    python3 -m scan --dir path/to/your/project --log-level DEBUG
    ```

5.  **Review the Results:**
    Vulnerabilities found will be printed to the console. A JSON report named `report.json` will also be generated in a `reports/` directory within your VulnHunter folder.

    Example console output snippet:
    ```
    ## Language: PYTHON

      ### Library: flask@2.0.1
        Severity: HIGH
          - CVE-2023-30861
    ```

6.  **Ignoring Vulnerabilities (Optional):**
    You can manage false positives or intentionally accepted risks by creating a `.vulnignore` file. See the "Ignoring CVEs" section below or run `python3 -m scan --help` for the detailed format.

## CLI Help

To see all available command-line options and their descriptions, run:
```bash
python3 -m scan --help
```
This will display an output similar to the following (the exact output may vary slightly based on your `argparse` setup):
```
usage: scan.py [-h] [--dir PATH [PATH ...]] [--update-nvd] [--nvd FILE_PATH] [--cpe-index FILE_PATH] [--log-level {DEBUG,INFO,WARNING,ERROR,CRITICAL}] [--ignore-file FILE_PATH]

Scans project dependency files for known vulnerabilities using local NVD data.

Scan Options:
  --dir PATH [PATH ...]
                        One or more project directories or specific dependency files to scan.
                        The script recursively searches for known dependency files within directories.
                        (e.g., ./my_project, ./requirements.txt)
  --update-nvd          Force an update of local NVD and CPE data from official sources before any scanning.
                        Requires internet access and may take several minutes. This process also rebuilds
                        the necessary local data files (e.g., data/nvd_cve_rebuilt.json, data/cpe/cpe_alias_index.json).

Data Path Options:
  --nvd FILE_PATH       Path to the preprocessed (rebuilt) NVD JSON data file used for the analysis.
                        (Default: data/nvd_cve_rebuilt.json)
  --cpe-index FILE_PATH
                        Path to the CPE alias index JSON file, used to improve product name matching during analysis.
                        (Default: data/cpe/cpe_alias_index.json)

General Options:
  --log-level {DEBUG,INFO,WARNING,ERROR,CRITICAL}
                        Set the logging level for the scan script.
                        (Default: INFO)
  --ignore-file FILE_PATH
                        Path to the file containing rules to ignore specific vulnerabilities.
                        (Default: ./.vulnignore)
  -h, --help            show this help message and exit

Usage Examples:
  python3 -m scan --dir path/to/your/project         (Scan a project directory)
  python3 -m scan --dir ./req.txt ./proj/pom.xml   (Scan specific files)
  python3 -m scan --update-nvd                         (Only update local NVD/CPE data)
  python3 -m scan --dir . --update-nvd               (Update data, then scan current directory)

Supported dependency files:
  requirements.txt (Python), package.json (JavaScript), pom.xml (Java),
  composer.json (PHP), Gemfile.lock (Ruby), go.mod (Go)

Ignoring Vulnerabilities:
  Create a file named '.vulnignore' in the current directory.
  Each line can ignore a CVE globally or for a specific package:
    CVE-YYYY-XXXXX                # Ignores this CVE everywhere
    CVE-YYYY-ZZZZZ package-name   # Ignores CVE only for package-name (case-insensitive)
    # Lines starting with # are comments.
```

## Requirements

* Python 3.10+ (or your specified version, e.g., 3.13+ if strictly needed)
* Internet access is **only** required for the initial data setup (`--update-nvd`) and for the language-specific tools (like `mvn`, `npm`, `composer`, `go`) to download project dependencies if they are not already present.
* Works on Linux, macOS, and Windows (ensure language-specific build tools/CLIs are in your PATH).

## Ideal use cases

* **DevSecOps Pipelines:** Integrate into your CI/CD for automated dependency checking.
* **On-Prem Security Audits:** Scan projects within your network without external exposure.
* **CI Environments without External Connectivity:** After initial data setup, scans can run fully offline.
* **Manual Review of Open Source Software:** Quickly assess the known vulnerability posture of third-party libraries.
* **Security-Conscious Developers:** Gain insights into the security of your application stack.

## Ignoring CVEs

To ignore specific vulnerabilities, create a `.vulnignore` file in the directory where you run the `scan` command, or specify a custom path using the `--ignore-file` option.

The format is one rule per line:

* `CVE-YYYY-XXXXX` : Ignores this CVE for all packages.
* `CVE-YYYY-ZZZZZ package-name` : Ignores this CVE only for the specified `package-name`. Package names are treated case-insensitively.
* Lines starting with `#` are treated as comments and ignored.

Example `.vulnignore` content:
```
# Ignore this CVE globally
CVE-2023-0001

# Ignore this CVE only for the 'requests' package
CVE-2023-0002 requests

# Ignore another CVE for a package with a slash in its name
CVE-2023-0003 vendor/some-package
```

## Report Structure

The scanner generates a JSON report (default: `reports/report.json`) containing a list of found vulnerabilities. Each item in the list represents a unique vulnerability found in a specific version of a dependency.

Example JSON output (`reports/report.json`):
```json
[
  {
    "name": "flask",
    "version": "2.0.1",
    "cve_id": "CVE-2023-30861",
    "severity": "HIGH",
    "summary": "A vulnerability in Flask versions prior to X.Y.Z allows..."
  },
  {
    "name": "requests",
    "version": "2.19.1",
    "cve_id": "CVE-2023-32681",
    "severity": "MEDIUM",
    "summary": "Requests library before A.B.C is susceptible to..."
  },
  {
    "name": "werkzeug",
    "version": "3.0.4",
    "cve_id": "CVE-2024-49767",
    "severity": "HIGH",
    "summary": "Werkzeug could allow a remote attacker to..."
  }
]
```
*(Note: Summaries are illustrative and will come from the NVD data.)*

## Known Limitations

* **Accuracy of NVD Data:** The scanner's effectiveness is directly tied to the quality, completeness, and timeliness of the locally stored NVD data. Ensure you run `--update-nvd` regularly.
* **CPE Matching Complexity:** Mapping dependency names to official CPEs in the NVD can be challenging. While VulnHunter uses an alias index and heuristics, some mismatches (false positives or false negatives) can occur, especially for less common packages or unconventional naming.
* **Dependency Resolution Environment:** For accurate transitive dependency analysis, the environment where VulnHunter (and its underlying tools like `pipdeptree`, `mvn`, `npm`) runs should closely mirror the project's intended build/runtime environment, with dependencies correctly installed or resolvable.
* **Version Parsing:** While `packaging.version` is robust, extremely unconventional version strings might not be parsed or compared correctly.
* **Static Analysis Only:** VulnHunter performs static analysis of declared dependencies. It does not analyze how dependencies are used in code, nor does it detect vulnerabilities in your custom application code.

Like any vulnerability scanner, VulnHunter strives for high accuracy. However, results should always be reviewed, especially for critical vulnerabilities. Community feedback, issue reports for false positives/negatives, or suggestions to improve detection are highly welcome and help improve accuracy for everyone.

## License

This project is licensed under the MIT License - see the `LICENSE` file for details.

## Author

Built by [DevGreick](https://github.com/DevGreick)

*Cyber gunslinger style, because CVE hunting shouldn’t be boring.*
