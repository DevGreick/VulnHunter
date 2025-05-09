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

And checks each dependency/version against a **locally converted NVD database**, using a custom CPE alias index to improve accuracy.

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

1. Update the NVD data and convert it to minimal format:

```bash
python3 -m scan --update-nvd
```

2. Run the scan on your dependency files:

```bash
python3 -m scan --dir path/to/your/project
```

3. Example result:

```
## Language: PYTHON

  ### Library: flask@2.3.3
    Severity: CRITICAL
      - CVE-2023-12345
    Severity: MEDIUM
      - CVE-2022-99999
```

## CLI help

To see all available options:

```bash
python3.13 -m scan --help
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
* No internet access needed during scan
* Works on Linux, macOS and Windows

## Ideal use cases

* DevSecOps pipelines
* On-prem security audits
* CI environments without external connectivity
* Manual review of open source software
* Anyone who wants to know if their stack is full of ticking bombs

## License

MIT License

## Author

Built by [DevGreick](https://github.com/DevGreick)
Cyber gunslinger style, because CVE hunting shouldn’t be boring
