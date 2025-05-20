# WPAUDIT - Advanced WordPress Security Auditing Suite

Welcome to the official WPAUDIT documentation! This comprehensive guide provides an in-depth overview of WPAUDIT, a powerful **WordPress security audit tool** designed for ethical hackers, penetration testers, and security professionals. Learn about its advanced features, setup, and effective usage for conducting thorough **WordPress vulnerability scanning** and **WordPress penetration testing**.

## Overview

WPAUDIT is a hyper-configurable, modular **WordPress security auditing suite** engineered to automate and streamline the process of identifying vulnerabilities and security weaknesses in WordPress installations. As a leading **automated WordPress security** tool, WPAUDIT empowers users to perform detailed security assessments, making it an essential utility for any **WordPress penetration testing tool** kit, especially when operating on platforms like **Kali Linux**. Its modular architecture allows for highly customized scans tailored to specific target environments and auditing requirements.

## Key Features of WPAUDIT - Your Expert WordPress Vulnerability Scanner

*   **Modular Scan Phases:** Executes distinct security checks in sequence (Preflight, Nmap, WPScan, REST API Analysis, Parameter Fuzzing, Nuclei, SQLMap, Exploit Intel).
*   **Configurable Profiles:** Supports different scan profiles (`default`, `stealth`, `aggressive`) for varying levels of intensity and stealthiness.
*   **Flexible Configuration:** Uses YAML/JSON configuration files for detailed control over tool paths, API keys, scan parameters, and output settings.
*   **Command-Line Overrides:** Allows overriding specific configuration settings directly via CLI arguments for quick adjustments.
*   **Phase Skipping:** Users can choose to skip specific scan phases.
*   **Tool Dependency Checking:** Verifies the presence and configuration of required external tools before starting the scan.
*   **State Management:** Tracks scan progress and findings, saving the state incrementally.
*   **Reporting:** Generates a console summary, a comprehensive JSON state file, and an interactive HTML report for easy analysis and sharing.
*   **Interactive Mode:** Optionally prompts the user for confirmation before potentially intrusive actions, ensuring control over the scan.
*   **Cross-Platform Compatibility:** While optimized for environments like **Kali Linux**, WPAUDIT is a Python-based tool and can run on various operating systems where Python and the external tools are supported.

## Technical Architecture: How WPAUDIT Works

WPAUDIT operates through a coordinated system of core components and specialized scanner modules:

*   **`main.py` (Orchestrator):** The central script that parses command-line arguments, loads configurations, initializes the scan state, and sequentially executes the defined scan phases.
*   **`core/` Modules:**
    *   `config_loader.py`: Manages loading and merging of YAML configuration files.
    *   `state.py`: Handles the `ScanState` object, which stores all findings, metadata, and progress throughout the scan. It supports saving and loading the state.
    *   `tool_checker.py`: Verifies the availability and (optionally) versions of required external command-line tools.
    *   `tool_runner.py`: A robust wrapper for executing external tools, managing timeouts, and capturing output.
    *   `utils.py`: Contains various helper functions used across the application.
*   **`modules/` Directory:** Contains individual Python scripts for each scan phase or specific tool integration (e.g., `nmap_scanner.py`, `wpscan_auditor.py`, `wp_analyzer/` sub-package for detailed WordPress checks). Each module typically has a `run_scan` or `run_analysis` function called by `main.py`.
*   **`reporting/` Directory:**
    *   `generator.py`: Responsible for creating the text summary and HTML reports from the final `ScanState`.
    *   `report_template.html`: A Jinja2 template used to render the HTML report.
*   **`config/` Directory:** Contains default configuration files (`default_config.yaml`) that users can adapt.

The scan proceeds through phases defined in `main.py`, with each phase potentially updating the shared `ScanState` object. This state is saved periodically and at the end of the scan, forming the basis for the final reports.

## Understanding Scan Profiles

WPAUDIT offers scan profiles (`default`, `stealth`, `aggressive`) to tailor the scan intensity and techniques:

*   **`default`**: A balanced profile suitable for most initial assessments, providing good coverage without being overly intrusive.
*   **`stealth`**: Designed for less noisy scans. This profile typically uses passive techniques where possible, makes fewer requests, employs slower timings for tools like Nmap, and may use a more restricted set of Nuclei templates. Ideal when trying to minimize the scan's footprint or avoid detection by WAFs/IPS.
*   **`aggressive`**: A comprehensive and potentially noisy profile. It enables more checks, deeper fuzzing (if configured), scans all TCP ports with Nmap using more intrusive scripts, and utilizes a broader set of Nuclei templates. This profile provides the most thorough assessment but should be used with caution and only with explicit authorization due to its potential impact on the target system.

Each profile in `config.yaml` allows customization of options for Nmap (`nmap_options`, `nmap_ports`, `nmap_scripts`), WPScan (`wpscan_options`), Nuclei (`nuclei_templates`), SQLMap (`sqlmap_options_profile`, `sqlmap_tamper_scripts_profile`), and other modules, giving you fine-grained control over the tools' behavior within each profile.

## The ScanState Object

Throughout its execution, WPAUDIT maintains a central `ScanState` object (managed by `core/state.py`). This object is crucial as it serves as the live repository for:

*   **Scan Metadata:** Information about the target (URL, IP), scan start/end times, and the configuration profile used.
*   **Tool Check Results:** Status of required external tools (e.g., if Nmap was found and its version).
*   **Module Findings:** All data collected by each executed module is stored here, typically organized by module name (e.g., `findings['nmap_results']`, `findings['wpscan_results']`, `findings['wp_analyzer']['security_headers_analysis']`).
*   **Actionable Intelligence:** Lists of critical alerts, summary points for quick review, and detailed remediation suggestions.
*   **Tool Errors:** Any errors encountered during the execution of external tools.

The entire `ScanState` is saved as a JSON file (e.g., `wpaudit_state_target_timestamp_FULL_REPORT.json`) in the configured output directory. This file allows for:
*   Detailed post-scan analysis and data mining.
*   Auditing the scan process itself.
*   Potentially resuming scans or re-processing data in future versions of WPAUDIT.
*   Feeding data into other security information and event management (SIEM) systems or reporting tools.

## Prerequisites

### Software:
*   **Python:** Version 3.7 or higher.
*   **Python Libraries:** `PyYAML`, `requests` (Install via `pip install -r requirements.txt`).

### External Tools Integration:
WPAUDIT seamlessly integrates with a suite of industry-standard security tools. For optimal performance, especially on systems like **Kali Linux for ethical hacking**, ensure these are installed and correctly configured (accessible in your system's PATH or specified in `config.yaml`):
*   **Nmap:** Essential for network discovery, port scanning, and service version detection.
*   **WPScan:** The core **WordPress vulnerability scanner** for identifying issues in WordPress core, plugins, and themes. (A WPScan API token is highly recommended for up-to-date vulnerability data).
*   **Nuclei:** Powerful template-based scanner for finding a wide range of vulnerabilities using community-curated templates.
*   **SQLMap:** The leading tool for detecting and exploiting SQL injection flaws.
*   **SearchSploit:** Command-line interface for Exploit-DB, used to find relevant public exploits.
*   **Metasploit Framework (msfconsole):** For leveraging exploit modules and auxiliary tools (use with extreme caution and authorization).
*   **Subfinder:** For efficient passive subdomain enumeration.
*   **ffuf:** Fast web fuzzer used for directory and path bruteforcing.
*   **Arjun:** HTTP parameter discovery suite.
*   *(Other tools might be implicitly required by specific modules - refer to module code if needed. WPAUDIT is designed to be a comprehensive WordPress security audit tool.)*

## Installation Guide for WPAUDIT

Follow these steps to get WPAUDIT up and running on your system.

### General Setup

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/ihuzaifashoukat/wpaudit
    cd wpaudit # Or your project directory name
    ```
2.  **Install Python dependencies (Recommended: Use a Virtual Environment):**
    It's highly recommended to use a Python virtual environment to manage dependencies and avoid conflicts with system-wide packages.
    *   Create a virtual environment:
        ```bash
        python3 -m venv venv 
        ```
        (Replace `venv` with your preferred environment name if desired)
    *   Activate the virtual environment:
        *   On Linux/macOS:
            ```bash
            source venv/bin/activate
            ```
        *   On Windows:
            ```bash
            .\venv\Scripts\activate
            ```
    *   Install dependencies:
        ```bash
        pip install -r requirements.txt
        ```
3.  **Install External Tools:** WPAUDIT relies on several external security tools. Ensure they are installed and accessible in your system's PATH, or their paths are correctly specified in your `config.yaml`. Refer to the "External Tools Integration" section for a list of tools. Installation methods vary by OS and tool.

4.  **Configure:**
    *   Copy or rename `config/default_config.yaml` to `config/config.yaml` (or use a custom path).
    *   Edit the configuration file (`config.yaml`) to:
        *   Set the correct paths for the external tools if they are not in your system's PATH.
        *   Add your WPScan API token under `api_keys`.
        *   Adjust profile settings and other parameters as needed.

### Kali Linux Specific Setup

Kali Linux has specific considerations for Python package management and comes with many security tools pre-installed or easily available.

1.  **Clone the repository (if not already done):**
    ```bash
    git clone https://github.com/ihuzaifashoukat/wpaudit
    cd wpaudit
    ```

2.  **Set up Python Virtual Environment (Highly Recommended on Kali):**
    Kali Linux uses an "externally managed" Python environment. To avoid issues, always use a virtual environment for Python projects.
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```
    Your terminal prompt should change to indicate the virtual environment is active (e.g., `(venv) user@kali:~/wpaudit$`).

3.  **Install Python Dependencies:**
    With the virtual environment activated:
    ```bash
    pip install -r requirements.txt
    ```

4.  **Install/Verify External Tools on Kali Linux:**
    Many tools are available via `apt`. You can try to install them using:
    ```bash
    sudo apt update
    sudo apt install -y nmap wpscan nuclei sqlmap exploitdb metasploit-framework subfinder ffuf arjun
    ```
    **Notes on Kali Tool Installation:**
    *   `wpscan`: The command `apt install wpscan` should work on most up-to-date Kali systems. If it doesn't, or if you need a newer version than what `apt` provides, you can install/update it using RubyGems:
        ```bash
        sudo apt install -y ruby ruby-dev build-essential
        sudo gem install wpscan
        ```
    *   `searchsploit`: This tool is part of the `exploitdb` package. The command `sudo apt install -y exploitdb` should install it. If you encounter issues or want the very latest version, you can clone it directly: `git clone https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb` (and then add `/opt/exploitdb` to your PATH or symlink `searchsploit`).
    *   `nuclei`, `subfinder`, `ffuf`, `arjun`: These are often Go-based tools. If not available via `apt` or if you need the latest versions, you might need to download their precompiled binaries from their official GitHub release pages or install them using `go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest` (requires Go to be installed: `sudo apt install golang-go`).
    *   Always verify that the tools are correctly installed and accessible in your PATH. WPAUDIT's `tool_paths` in `config.yaml` can be used to specify direct paths if needed.
    *   `metasploit-framework` is a large package and might take time to install.

5.  **Configure WPAUDIT:**
    Proceed with the configuration steps mentioned in the "General Setup" (copying `default_config.yaml` to `config.yaml` and editing it).

## Usage

Run the main script from the project's root directory:

```bash
python main.py <target_url> [options]
```

**Arguments:**

*   `target_url`: (Required) The target WordPress URL (e.g., `http://example-wp.com`).

**Common Options:**

*   `--config <path/to/config.yaml>`: Specify a custom configuration file.
*   `--profile <profile_name>`: Select a scan profile (`default`, `stealth`, `aggressive`). Default is `default`.
*   `--skip-phases <phase1> <phase2> ...`: List of phases to skip (e.g., `--skip-phases nmap sqlmap`).
*   `--wpscan-api-token <token>`: Override the WPScan API token from the config file.
*   `--wordlist <path/to/wordlist>`: Override the wordlist path for WPScan password attacks.
*   `--interactive` / `--no-interactive`: Enable/disable interactive prompts (overrides config).
*   `--sqlmap-targets <url1> <url2> ...`: Provide specific URLs for SQLMap to test, in addition to those found by Nuclei.
*   `--output-dir <path/to/output>`: Override the output directory specified in the config.

**Examples:**

*   **Basic Scan (Default Profile):**
    ```bash
    python main.py https://targetwordpress.com
    ```
*   **Aggressive Scan with Custom Config:**
    ```bash
    python main.py https://targetwordpress.com --profile aggressive --config config/my_aggressive_scan.yaml
    ```
*   **Skip Nmap and SQLMap:**
    ```bash
    python main.py https://targetwordpress.com --skip-phases nmap sqlmap
    ```
*   **Override WPScan Token and Output Directory:**
    ```bash
    python main.py https://targetwordpress.com --wpscan-api-token YOUR_TOKEN --output-dir /tmp/scan_results
    ```

## Configuration

The primary configuration is managed through a YAML file (e.g., `config/config.yaml`, based on `config/default_config.yaml`). Key sections include:
*   `tool_paths`: Paths to external tool executables.
*   `api_keys`: API keys for services like WPScan.
*   `output_dir`: Directory to store scan results and reports.
*   `interactive_prompts`: Enable/disable user confirmation prompts.
*   `scan_profiles`: Defines settings for `default`, `stealth`, and `aggressive` profiles, controlling parameters for each tool/phase.
*   `wordlist_path`: Default path to the wordlist for password attacks.

Refer to `config/default_config.yaml` for detailed structure and options.

## Scan Phases

The tool executes the following phases in order (unless skipped):

1.  **Preflight:** Initial checks (e.g., target reachability, basic WordPress detection).
2.  **Nmap:** Performs network scanning using Nmap based on the selected profile's configuration.
3.  **WPScan:** Runs WPScan to identify WordPress version, themes, plugins, users, and known vulnerabilities.
4.  **REST API / Parameter Fuzzing (wp_analyzer):** Analyzes the WordPress REST API endpoints and potentially fuzzes parameters (details depend on `wp_analyzer.py` implementation).
5.  **Nuclei:** Executes Nuclei scans using WordPress-related templates to find vulnerabilities. Hints for potential SQL injection points might be gathered here.
6.  **SQLMap:** Attempts to detect and exploit SQL injection vulnerabilities using SQLMap, potentially using hints from Nuclei or user-provided targets.
7.  **Exploit Intel:** Gathers information about potential exploits for discovered vulnerabilities (details depend on `exploit_intel.py` implementation).

## Output and Reporting

WPAUDIT provides comprehensive reporting to detail the findings of your **WordPress security audit**:
*   **Console Output:** Real-time feedback and progress updates during the scan.
*   **JSON State File:** A detailed JSON file (`wpaudit_state_<hostname>_<timestamp>.json`) is saved in the output directory. This file contains all raw data, findings, and configurations from each module, serving as a complete record of the **WordPress vulnerability scanning** process.
*   **Text Summary Report:** A human-readable summary (`wpaudit_summary_<hostname>_<timestamp>.txt`) highlighting key findings and critical alerts.
*   **HTML Report:** An interactive HTML report (`wpaudit_report_<hostname>_<timestamp>.html`) offering a structured and user-friendly view of the scan results, ideal for sharing and analysis.

## Contributing to WPAUDIT

We welcome contributions to WPAUDIT! If you're interested in improving this **WordPress penetration testing tool**, please consider the following:
*   **Reporting Bugs:** Submit detailed bug reports via the project's issue tracker. Include steps to reproduce, WPAUDIT version, Python version, OS, and relevant logs.
*   **Suggesting Features:** Propose new features or enhancements that would benefit the **automated WordPress security** capabilities of WPAUDIT. Explain the use case and potential benefits.
*   **Submitting Pull Requests:** Fork the repository, make your changes in a separate feature branch, and submit a pull request with a clear description of your contributions. Please adhere to the existing coding style (e.g., PEP 8 for Python) and ensure your changes are well-tested. Adding unit tests for new functionality is highly encouraged.


## Troubleshooting Common Issues

*   **Tool Not Found Errors:**
    *   Ensure the external tool (e.g., Nmap, WPScan) is installed correctly and its executable is in your system's PATH.
    *   Alternatively, specify the full path to the tool's executable in your `config.yaml` under the `tool_paths` section.
    *   Verify the tool key name in `config.yaml` matches the one used internally by WPAUDIT (see `core/tool_checker.py`).
*   **WPScan API Key Issues:**
    *   If WPScan vulnerability data seems limited, ensure you have a valid WPScan API token specified in `config.yaml` (`api_keys.wpscan`) or via the `--wpscan-api-token` CLI argument.
    *   Check the WPScan dashboard to ensure your API key is active and has not exceeded its quota.
*   **Permission Denied Errors:**
    *   Some tools or operations (like Nmap SYN scans or writing to certain directories) may require root/administrator privileges. Run WPAUDIT with `sudo` if necessary and appropriate for your environment, but understand the security implications.
    *   Ensure WPAUDIT has write permissions to the specified `output_dir`.
*   **Python Dependency Errors:**
    *   Make sure all Python libraries listed in `requirements.txt` are installed in your Python environment (`pip install -r requirements.txt`).
*   **Scan Hangs or Times Out:**
    *   Increase tool-specific timeouts in `config.yaml` (e.g., `wpscan_timeout`, `nuclei_timeout`) if scanning a slow or complex target.
    *   Check network connectivity to the target.
    *   A WAF or IPS might be blocking or rate-limiting requests; consider using a "stealth" profile or adjusting rate limits.

## Roadmap / Future Enhancements

WPAUDIT is an evolving project. Potential future enhancements include:
*   **Advanced Reporting:** More report formats (e.g., CSV, XML), customizable report templates, and integration with vulnerability management platforms.
*   **Scan Resumption:** Ability to resume interrupted scans from the last saved state.
*   **Plugin/Theme Specific Checks:** Deeper analysis of specific popular plugins/themes for known misconfigurations or vulnerabilities beyond what WPScan/Nuclei cover.
*   **Enhanced WAF/IPS Evasion Techniques:** More sophisticated options for stealthy scanning.
*   **Automated Exploit Chaining (Highly Experimental):** Exploring safe ways to test if combined vulnerabilities could lead to greater impact.

## License

WPAUDIT is released under the [MIT License](LICENSE.txt). Please see the `LICENSE.txt` file for full details.

This tool is intended for legal and ethical use only. The developers assume no liability and are not responsible for any misuse or damage caused by this program. Always ensure you have explicit, written authorization before performing any security testing on a target system.
