# VulnHunter

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
python3.13 scripts/update_nvd.py --convert
```

2. Run the scan on your dependency files:

```bash
python3.13 scan.py --dir inputs/
```

3. Example result:

```
Package: flask@2.3.3
CVE: CVE-2023-12345 - Critical - Arbitrary code execution
CVE: CVE-2022-99999 - Medium - Denial of Service
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
