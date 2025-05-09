# VulnHunter

<p align="center">
  <img src="logo.png" alt="VulnHunter logo" width="200">
</p>

Offline vulnerability scanner for project dependencies.
No API calls, no cloud, just raw CVE hunting on your machine.

---

## 🚀 What it does

VulnHunter scans dependency files from common ecosystems:

* Python (`requirements.txt`)
* Java (`pom.xml`)
* Node.js (`package.json`)
* PHP (`composer.json`)
* Ruby (`Gemfile.lock`)
* Go (`go.mod`)

It matches each dependency/version against a **locally converted NVD database**, using a custom **CPE alias index** to improve accuracy.

---

## 🔒 Why choose VulnHunter?

* 🚫 **No live internet calls during scans** — All lookups are local
* 📦 **Offline-ready** — Just download the CVE data once, then scan offline
* ⚡ **Fast scans** — Zero network delay
* 🛡️ **Secure by design** — No external APIs at runtime
* 🧱 **Ideal for air-gapped or restricted systems**

---

## ⚙️ How it works

1. 🔄 **Update vulnerability data** *(first-time setup or periodic refresh)*
   Downloads and converts the NVD JSON feeds + CPE dictionary:

   ```bash
   python3 scripts/update_nvd.py --convert
   ```

2. 🔍 **Run scans locally**
   Once data is downloaded, all scanning is done offline:

   ```bash
   python3 -m scan --dir path/to/your/dependencies/
   ```

---

## ✨ Features

* Detects known CVEs in your dependencies
* Uses **locally converted** NVD feeds (no live API)
* Built-in support for multiple languages and formats
* Custom CPE alias resolver (`flask`, `guzzle`, etc)
* Clean CLI output: package name, version, CVEs found
* Modular Python codebase (Pydantic v2, argparse, logging)

---

## 🧪 How to use

1. Create a virtual environment and install requirements:

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   pip install -r requirements.txt
   ```

2. Update local CVE and CPE data (requires internet):

   ```bash
   python3 -m scan --update-nvd
   ```

3. Run the scan on your project:

   ```bash
   python3 -m scan --dir path/to/your/project
   ```

   You can also scan multiple files or test data:

   ```bash
   python3 -m scan --dir ./requirements.txt ./pom.xml
   python3 -m scan --dir inputs/
   ```

4. Review the results:

   * CLI output includes severity and CVEs
   * JSON report is saved at `reports/report.json`

   Example output:

   ```
   ## Language: PYTHON

     ### Library: flask@2.3.3
       Severity: CRITICAL
         - CVE-2023-12345
       Severity: MEDIUM
         - CVE-2022-99999
   ```

5. Optional: Ignore known issues via `.vulnignore`

   Create a `.vulnignore` file in your repo root to suppress specific CVEs.
   Use `--help` for syntax:

   ```bash
   python3 -m scan --help
   ```

---

## 🧰 CLI Help

Run `--help` to see all available options:

```bash
python3 -m scan --help
```

```
usage: scan.py [-h] --dir DIR [--nvd NVD_PATH] [--cpe_index CPE_INDEX]

optional arguments:
  -h, --help            show this help message and exit
  --dir DIR             Directory or files to scan
  --nvd NVD_PATH        Path to the NVD JSON file (default: data/nvd_cve_rebuilt.json)
  --cpe_index CPE_INDEX Path to the CPE alias index (default: data/cpe/cpe_alias_index.json)
```

---

## 📦 Requirements

* Python 3.13+
* Internet access required **only once** for `--update-nvd`
* Compatible with Linux, macOS and Windows

---

## 🧠 Ideal use cases

* DevSecOps pipelines
* CI environments without internet
* On-prem or isolated networks
* Secure software supply chain analysis
* Manual audit of legacy/open source stacks

---

## 📄 License

MIT License

---

## 👤 Author

Built by [DevGreick](https://github.com/DevGreick)
Cyber gunslinger style  because CVE hunting shouldn’t be boring.
