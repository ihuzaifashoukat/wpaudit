# OmegaScythe Dominator - Project Wiki

Welcome to the OmegaScythe Dominator wiki! This document provides an overview of the project, its features, setup, and usage.

## Overview

OmegaScythe Dominator is a hyper-configurable security auditing suite specifically designed for WordPress websites. It automates various scanning and analysis phases to identify potential vulnerabilities and security weaknesses. The tool is built with modularity in mind, allowing users to customize scans based on their needs and the target environment.

## Features

*   **Modular Scan Phases:** Executes distinct security checks in sequence (Preflight, Nmap, WPScan, REST API Analysis, Parameter Fuzzing, Nuclei, SQLMap, Exploit Intel).
*   **Configurable Profiles:** Supports different scan profiles (`default`, `stealth`, `aggressive`) for varying levels of intensity and stealthiness.
*   **Flexible Configuration:** Uses YAML/JSON configuration files for detailed control over tool paths, API keys, scan parameters, and output settings.
*   **Command-Line Overrides:** Allows overriding specific configuration settings directly via CLI arguments for quick adjustments.
*   **Phase Skipping:** Users can choose to skip specific scan phases.
*   **Tool Dependency Checking:** Verifies the presence and configuration of required external tools before starting the scan.
*   **State Management:** Tracks scan progress and findings, saving the state incrementally.
*   **Reporting:** Generates both a summary report and a detailed full report (JSON format) containing all collected information.
*   **Interactive Mode:** Optionally prompts the user for confirmation before potentially intrusive actions.

## Prerequisites

### Software:
*   **Python:** Version 3.7 or higher.
*   **Python Libraries:** `PyYAML`, `requests` (Install via `pip install -r requirements.txt`).

### External Tools:
The suite relies on several external security tools. Ensure these are installed and accessible in your system's PATH or provide paths in the configuration file:
*   **Nmap:** For network discovery and port scanning.
*   **WPScan:** For WordPress-specific vulnerability scanning. (Requires an API token for full vulnerability data, configurable).
*   **Nuclei:** For template-based vulnerability scanning.
*   **SQLMap:** For automated SQL injection detection and exploitation.
*   *(Other tools might be implicitly required by specific modules - refer to module code if needed)*

## Installation

1.  **Clone the repository:**
    ```bash
    git clone <repository_url>
    cd omegascythe-dominator # Or your project directory name
    ```
2.  **Install Python dependencies:**
    ```bash
    pip install -r requirements.txt
    ```
3.  **Install External Tools:** Follow the installation instructions for Nmap, WPScan, Nuclei, and SQLMap for your operating system.
4.  **Configure:**
    *   Copy or rename `config/default_config.yaml` to `config/config.yaml` (or use a custom path).
    *   Edit the configuration file (`config.yaml`) to:
        *   Set the correct paths for the external tools if they are not in your system's PATH.
        *   Add your WPScan API token under `api_keys`.
        *   Adjust profile settings and other parameters as needed.

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

*   **Console Output:** Provides real-time feedback during the scan.
*   **State File:** A JSON file (`scan_state_<hostname>_<timestamp>.json`) is saved in the output directory, containing all collected data from each module. This file is updated after each phase.
*   **Summary Report:** A human-readable summary report (`scan_summary_<hostname>_<timestamp>.txt` or similar) is generated at the end of the scan in the output directory.

## Contributing

*(Placeholder: Add contribution guidelines if the project is open to contributions - e.g., reporting bugs, suggesting features, submitting pull requests)*

## License

*(Placeholder: Specify the project's license, e.g., MIT, GPL, Apache 2.0)*
