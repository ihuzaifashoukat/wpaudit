import subprocess
import json
import os
import re
import sys # For stdout writing
from urllib.parse import urlparse
from core.tool_runner import run_command # Not used directly now, but keep import?
from core.utils import get_scan_filename_prefix, sanitize_filename

def run_scan(state, config, target_urls=None): # Added target_urls
    """
    Runs WPScan audit based on the selected profile against single or multiple targets.
    """
    primary_target_url = state.get_full_state()["scan_metadata"]["target_info"]["url"]
    profile_name = state.get_full_state()["scan_config_used"].get("profile_name", "default")
    profile = config.get("scan_profiles", {}).get(profile_name, config.get("scan_profiles", {}).get("default", {})) # Ensure profile is dict
    api_token = config.get("api_keys", {}).get("wpscan")

    # Determine targets to scan
    targets_to_scan = []
    if target_urls and isinstance(target_urls, list) and len(target_urls) > 0:
        targets_to_scan = target_urls
        target_log_str = f"{len(targets_to_scan)} URLs (including discovered subdomains)"
    else:
        targets_to_scan = [primary_target_url]
        target_log_str = primary_target_url

    print(f"\n[*] Phase 2: WordPress Security Audit (WPScan) for {target_log_str} [Profile: {profile_name}]")
    # Initialize results structure to hold per-target findings
    state.update_module_findings("wpscan_results", {
        "profile": profile_name,
        "targets": {}, # Store results keyed by target URL
        "overall_status": "Running"
    })

    base_scan_prefix = get_scan_filename_prefix(state, config) # Prefix for the whole scan run
    wpscan_timeout = config.get("wpscan_timeout", 3600)
    any_target_failed = False
    any_vulns_found = False

    for i, current_target_url in enumerate(targets_to_scan):
        print(f"\n    Scanning WPScan target {i+1}/{len(targets_to_scan)}: {current_target_url}")
        target_results = {"status": "Running", "data": None, "log_path": None, "json_path": None, "error": None}
        state.update_module_findings("wpscan_results", {"targets": {current_target_url: target_results}}) # Update state for this target

        # Generate unique filenames for this target
        sanitized_target_host = sanitize_filename(urlparse(current_target_url).netloc)
        wpscan_json_output = f"{base_scan_prefix}_wpscan_{sanitized_target_host}.json"
        wpscan_log_output = f"{base_scan_prefix}_wpscan_{sanitized_target_host}.log"
        target_results["log_path"] = wpscan_log_output
        target_results["json_path"] = wpscan_json_output

        command = [
            "wpscan", "--url", current_target_url,
            "--format", "json", "--output", wpscan_json_output,
            "--user-agent", config.get("default_user_agent", "OmegaScytheDominator"), # Use .get
        ] # Corrected: Removed extra bracket
        if api_token:
            command.extend(["--api-token", api_token])
        else:
            print("    [!] WPScan API token not configured. Vulnerability data limited/outdated.")

        wpscan_cli_options_str = profile.get("wpscan_options", "") # Use .get
        # Substitute wordlist path
        if "{WORDLIST_PATH}" in wpscan_cli_options_str:
            wordlist_actual_path = config.get("wordlist_path")
            if wordlist_actual_path and os.path.exists(wordlist_actual_path):
                wpscan_cli_options_str = wpscan_cli_options_str.replace("{WORDLIST_PATH}", wordlist_actual_path)
                print(f"        [i] Using wordlist for WPScan: {wordlist_actual_path}")
            else:
                print(f"    [!] WPScan wordlist placeholder used, but path '{wordlist_actual_path}' invalid/not set. Removing password attack options.")
                wpscan_cli_options_str = re.sub(r'--wordlist\s+\S*', '', wpscan_cli_options_str).strip()
                wpscan_cli_options_str = re.sub(r'--password-attack\s+\S+', '', wpscan_cli_options_str).strip()

        if wpscan_cli_options_str: command.extend(wpscan_cli_options_str.split())

        print(f"        Executing: {' '.join(command)}")
        proc_status = None
        err_msg = None

        try:
            # Use Popen for live logging to file and console
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, universal_newlines=True, errors='ignore')
            with open(wpscan_log_output, 'w', errors='ignore') as log_file:
                for line in process.stdout:
                    sys.stdout.write(line) # Show progress
                    log_file.write(line)
            process.wait(timeout=wpscan_timeout)
            proc_status = process.returncode

            if (proc_status == 0 or proc_status == 5) and \
               os.path.exists(wpscan_json_output) and os.path.getsize(wpscan_json_output) > 0:
                print(f"        [+] WPScan audit completed for {current_target_url}. JSON: {wpscan_json_output}")
                wpscan_data = None
                try:
                    with open(wpscan_json_output, 'r', errors='ignore') as f:
                        wpscan_data = json.load(f)
                    target_results["data"] = wpscan_data
                    target_results["status"] = "Completed"
                    if proc_status == 5:
                        any_vulns_found = True
                        target_results["vulnerabilities_found"] = True
                        state.add_critical_alert(f"WPScan found vulnerabilities on {current_target_url}!")
                        state.add_summary_point(f"[!] WPScan found vulnerabilities on {current_target_url}!")
                except json.JSONDecodeError as e:
                     err_msg = f"WPScan completed but failed to parse JSON output: {e}. Check log: {wpscan_log_output}"
                     print(f"    [-] {err_msg}")
                     target_results["error"] = err_msg
                     target_results["status"] = "Completed with JSON Error"
                     state.add_tool_error(f"{current_target_url}: {err_msg}")
                     any_target_failed = True

            else:
                err_msg = f"WPScan audit failed or no JSON output for {current_target_url}. RC: {proc_status}. Check log: {wpscan_log_output}"
                print(f"    [-] {err_msg}")
                target_results["error"] = err_msg
                target_results["status"] = "Failed"
                state.add_critical_alert(f"WPScan audit error for {current_target_url}.")
                state.add_tool_error(f"{current_target_url}: {err_msg}")
                any_target_failed = True

        except subprocess.TimeoutExpired:
            err_msg = f"WPScan audit timed out after {wpscan_timeout} seconds for {current_target_url}."
            print(f"    [-] {err_msg}")
            target_results["error"] = err_msg
            target_results["status"] = "Timeout"
            state.add_critical_alert(err_msg)
            state.add_tool_error(err_msg)
            any_target_failed = True
        except Exception as e:
            err_msg = f"WPScan audit exception for {current_target_url}: {str(e)[:150]}"
            print(f"    [-] {err_msg}")
            target_results["error"] = err_msg
            target_results["status"] = "Exception"
            state.add_critical_alert(err_msg)
            state.add_tool_error(err_msg)
            any_target_failed = True
        finally:
            # Update state for the current target within the loop
            current_findings = state.get_module_findings("wpscan_results", {})
            current_findings.setdefault("targets", {})[current_target_url] = target_results
            state.update_module_findings("wpscan_results", current_findings)
            state.save_state() # Save state after each target attempt


    # Determine overall status after scanning all targets
    final_status = "Completed"
    if any_target_failed: final_status = "Completed with Errors"
    if any_vulns_found: final_status += " (Vulnerabilities Found)"

    current_findings = state.get_module_findings("wpscan_results", {})
    current_findings["overall_status"] = final_status
    state.update_module_findings("wpscan_results", current_findings)

    state.add_summary_point(f"WPScan phase finished for {len(targets_to_scan)} target(s). Status: {final_status}")
    state.mark_phase_executed("wpscan")
    state.save_state() # Final save for the phase
