# VulnHunter

<p align="center">
  <img src="logo.png" alt="VulnHunter logo" width="200">
</p>

Offline vulnerability scanner for project dependencies.
No API calls, no cloud, just raw CVE hunting on your machine.

![Python](https://img.shields.io/badge/Python-3.13%2B-blue)
![Status](https://img.shields.io/badge/Offline-Yes-brightgreen)
![License](https://img.shields.io/badge/License-MIT-yellow)

## What it does

VulnHunter scans dependency files from common ecosystems like:

* Python (`requirements.txt`)
* Java (`pom.xml`)
* Node.js (`package.json`)
* PHP (`composer.json`)
* Ruby (`Gemfile.lock`)
* Go (`go.mod`)

And checks each dependency/version against a locally converted NVD database, using a custom CPE alias index to improve accuracy.

## Why offline?

* No internet? No problem.
* Faster results with zero network delay
* Ideal for air-gapped or restricted environments
* Your data never leaves your machine

## Features

* Detects known CVEs in your dependencies
* Uses locally converted NVD feeds (no API required)
* Built-in support for multiple languages and formats
* Custom CPE alias resolver (flask, guzzle, etc)
* Clean CLI output: name, version, CVEs found
* Modular Python codebase (Pydantic v2, argparse, logging)

## How to use

1. Set up your environment and install dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate  # On Windows use: .venv\Scripts\activate
pip install -r requirements.txt
```

Note: Make sure to have a `requirements.txt` file in your repository containing: `requests`, `packaging`, `pydantic`, `pytest`.

2. Update local NVD and CPE data:

```bash
python3 -m scan --update-nvd
```

This command downloads and processes NVD feeds and the CPE dictionary. It requires internet access and may take several minutes on the first run.

3. Run the scan on your project:

```bash
python3 -m scan --dir path/to/your/project
```

You can also scan specific files or multiple paths:

```bash
python3 -m scan --dir ./your/requirements.txt ./another/project/pom.xml
```

Or use the test input files included in this repository:

```bash
python3 -m scan --dir inputs/
```

4. Review the results:

Check the console output for a summary and detailed list of vulnerabilities. A `reports/report.json` file will also be generated.

Example:

```
## Language: PYTHON

  ### Library: flask@2.3.3
    Severity: CRITICAL
      - CVE-2023-12345
    Severity: MEDIUM
      - CVE-2022-99999
```

5. Optional: Manage false positives

Create a `.vulnignore` file in the project root to ignore specific CVEs. See the format by running:

```bash
python3 -m scan --help
```

## CLI help

To see all available options:

```bash
python3 -m scan --help
```

Expected output:

```
usage: scan.py [-h] --dir DIR [--nvd NVD_PATH] [--cpe_index CPE_INDEX]

optional arguments:
  -h, --help            show this help message and exit
  --dir DIR             Directory containing dependency files
  --nvd NVD_PATH        Path to the NVD JSON file (default: data/nvd_cve_rebuilt.json)
  --cpe_index CPE_INDEX Path to the CPE alias index file (default: data/cpe/cpe_alias_index.json)
```

## Requirements

* Python 3.13+
* Internet access only required for `--update-nvd`
* Works on Linux, macOS and Windows

## Ideal use cases

* DevSecOps pipelines
* On-prem security audits
* CI environments without external connectivity
* Manual review of open source software
* Anyone who wants to know if their stack is full of ticking bombs

## Ignoring CVEs

To ignore specific vulnerabilities, create a `.vulnignore` file in the scan directory.

Example:

```
CVE-2023-12345
CVE-2022-99999
```

You can also use `--help` to see full syntax and options.

## Report structure

Example JSON output (`reports/report.json`):

```json
{
  "project": "inputs/requirements.txt",
  "dependencies": [
    {
      "name": "flask",
      "version": "2.3.3",
      "vulnerabilities": [
        {
          "cve_id": "CVE-2023-12345",
          "severity": "CRITICAL",
          "description": "Arbitrary code execution"
        }
      ]
    }
  ]
}
```

## Known limitations

Like any vulnerability scanner, VulnHunter strives for high accuracy,
however, results should always be reviewed manually, especially for critical vulnerabilities,
some false positives or undetected CVEs may occur depending on the structure of the dependency files or how packages are named.

If you identify a false positive or have a suggestion to improve detection, please open an issue community feedback helps improve accuracy for everyone.

## License

MIT License

## Author

Built by [DevGreick](https://github.com/DevGreick)
Cyber gunslinger style, because CVE hunting shouldn’t be boring
