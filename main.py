#!/usr/bin/env python3

import argparse
import sys
import os
import importlib # To dynamically import modules
from datetime import datetime
from urllib.parse import urlparse, urljoin
import requests # Added for target validation
# Suppress InsecureRequestWarning for target validation HEAD requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# --- Core Imports ---
# Assume current directory is omegascythe_dominator/ when running main.py
# If running from elsewhere, adjust Python path or use absolute imports
try:
    from core.config_loader import load_configuration
    from core.state import ScanState
    from core.tool_checker import check_phase_tools # Combined tool check function
    from core.utils import print_dominator_banner, sanitize_filename, user_confirm, get_target_ip
    from reporting.generator import generate_summary_report, save_full_report
except ImportError as e:
     print(f"[!!!] Failed to import core components. Is the script structure correct and are you running from the right directory? Error: {e}")
     sys.exit(1)


# --- Module Mapping ---
# Maps phase names to the module file and the function to call within that module
PHASE_MODULE_MAP = {
    "preflight": {"module": "modules.preflight", "function": "run_checks"},
    "subdomain_scan": {"module": "modules.subdomain_scanner", "function": "run_scan"}, # Added
    "nmap": {"module": "modules.nmap_scanner", "function": "run_scan"},
    "wpscan": {"module": "modules.wpscan_auditor", "function": "run_scan"},
    # The 'restapi' phase (and others previously grouped under wp_analyzer) now uses the refactored package
    "restapi": {"module": "modules.wp_analyzer.analyzer", "function": "run_analysis"},
    "param_fuzz": {"module": "modules.parameter_finder", "function": "run_scan"}, # Updated to use new module
    "directory_bruteforce": {"module": "modules.directory_bruteforcer", "function": "run_scan"}, # Added
    "nuclei": {"module": "modules.nuclei_scanner", "function": "run_scan"},
    "sqlmap": {"module": "modules.sqlmap_injector", "function": "run_scan"},
    "exploit_intel": {"module": "modules.exploit_intel.gatherer", "function": "run_scan"}, # Refactored
}


def main():
    print_dominator_banner()

    parser = argparse.ArgumentParser(
        description="OmegaScythe Dominator - Hyper-Configurable WordPress Security Auditing Suite.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("target_url", help="Target WordPress URL (e.g., http://example.com)")
    parser.add_argument("--config", help="Path to a YAML/JSON configuration file.")
    parser.add_argument("--profile", choices=["default", "stealth", "aggressive"], default="default",
                        help="Scan profile to use (default: default). Overridden by config file settings for the profile.")
    parser.add_argument("--skip-phases", nargs='*', choices=list(PHASE_MODULE_MAP.keys()),
                        default=[], help="List of phases to skip.")
    # Allow overriding specific config values via CLI
    parser.add_argument("--wpscan-api-token", help="WPScan API Token (overrides config).")
    parser.add_argument("--wordlist", help="Path to wordlist for WPScan password attacks (overrides config).")
    parser.add_argument("--interactive", dest='interactive_prompts_cli', action='store_true', help="Enable interactive prompts.")
    parser.add_argument("--no-interactive", dest='interactive_prompts_cli', action='store_false', help="Disable interactive prompts.")
    parser.set_defaults(interactive_prompts_cli=None)
    parser.add_argument("--sqlmap-targets", nargs='*', help="Explicit URL(s) for SQLMap (supplements Nuclei hints).")
    parser.add_argument("--output-dir", help="Override output directory path (overrides config).")

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)
    args = parser.parse_args()

    # --- 1. Load Configuration ---
    config = load_configuration(args.config)

    # Override config with specific CLI args if provided
    if args.wpscan_api_token: config["api_keys"]["wpscan"] = args.wpscan_api_token
    if args.wordlist: config["wordlist_path"] = args.wordlist
    if args.interactive_prompts_cli is not None: config["interactive_prompts"] = args.interactive_prompts_cli
    if args.output_dir: config["output_dir"] = args.output_dir


    # --- 2. Initialize Scan State ---
    target_url = args.target_url
    if not target_url.startswith(("http://", "https://")):
        print("[!] Target URL does not start with http/https. Prepending https://")
        target_url = "https://" + target_url
    parsed_url = urlparse(target_url)
    hostname = parsed_url.netloc
    target_ip = get_target_ip(hostname) # Resolve IP early
    sanitized_hostname = sanitize_filename(hostname)

    target_info = {
        "url": target_url, "hostname": hostname, "ip": target_ip,
        "sanitized_hostname": sanitized_hostname
    }
    config_used_info = {
        "source_file": args.config if args.config and os.path.exists(args.config) else "Default Config Only",
        "profile_name": args.profile,
        # Optionally store a subset of actual settings used, avoid storing secrets like API keys
        "settings_subset": {
             "output_dir": config["output_dir"],
             "profile_options_keys": list(config["scan_profiles"].get(args.profile,{}).keys()), # Just keys for brevity
             "interactive": config["interactive_prompts"]
             }
    }
    state = ScanState(target_info, config_used_info)
    state.save_state() # Initial save

    # --- 3. Determine Phases and Check Tools ---
    phases_to_run_set = set(PHASE_MODULE_MAP.keys()) - set(args.skip_phases)
    # Define order explicitly if needed, otherwise dict order (Python 3.7+) is usually fine
    ordered_phases = ['preflight', 'subdomain_scan', 'nmap', 'wpscan', 'restapi', 'param_fuzz', 'directory_bruteforce', 'nuclei', 'sqlmap', 'exploit_intel'] # Added directory_bruteforce
    phases_to_run = [p for p in ordered_phases if p in phases_to_run_set]

    state.update_module_findings("scan_metadata", {"phases_requested": phases_to_run}) # Log requested phases

    critical_tools_ok = check_phase_tools(phases_to_run, config, state)
    state.save_state() # Save tool check results

    if not critical_tools_ok:
        print("\n[!!!] CRITICAL tools required for the selected scan phases are missing or misconfigured.")
        if not user_confirm("Attempt to continue with limited functionality?", config):
            print("[!] Exiting due to missing critical tools.")
            sys.exit(1)
        else:
             print("[!] Proceeding with missing tools. Scan results will be incomplete.")


    # --- 4. Execute Scan Phases ---
    print("\n--- Starting Scan Phases ---")
    executed_wp_analyzer = False # Flag to run wp_analyzer only once even if multiple phases map to it
    # Use sets for unique items
    expanded_target_urls = {target_url} # Validated URLs (primary + subdomains with http/s)
    discovered_paths_for_fuzzing = set() # Interesting paths from directory brute-force
    discovered_urls_with_params = set() # URLs with params from parameter_finder

    for phase_name in phases_to_run:
        if phase_name not in PHASE_MODULE_MAP:
            print(f"[!] Unknown phase '{phase_name}' defined in order. Skipping.")
            continue

        # Special handling for wp_analyzer containing multiple conceptual phases (Now only restapi)
        # Note: param_fuzz is now a separate module
        if phase_name == "restapi": # Check only for restapi now
            if executed_wp_analyzer: continue # Already ran the module
            module_info = PHASE_MODULE_MAP["restapi"] # Use the restapi entry point
            executed_wp_analyzer = True
            effective_phase_name_log = "wp_analyzer (restapi)" # Log specific name
        else:
            module_info = PHASE_MODULE_MAP[phase_name]
            effective_phase_name_log = phase_name


        module_path = module_info["module"]
        function_name = module_info["function"]

        # Check if critical tools for *this specific phase* are okay before running
        # (More granular check than the initial one)
        # This requires a more detailed map or logic in check_phase_tools/state
        # For now, rely on the initial check and user confirmation

        print(f"\n--- Running Phase: {effective_phase_name_log} ---")
        try:
            module = importlib.import_module(module_path)
            run_func = getattr(module, function_name)

            # Prepare arguments for the function (most need state and config)
            kwargs = {'state': state, 'config': config}

            # --- Pass Expanded Targets to Relevant Modules ---
            # Define which phases should receive various discovered items
            # For Nuclei and SQLMap, we can pass a combined list of general URLs, paths, and URLs with params
            if phase_name in ["nuclei", "sqlmap"]:
                # Combine all discovered entry points for comprehensive scanning
                combined_targets_for_phase = set(expanded_target_urls) # Start with validated base URLs
                # Add interesting paths found by ffuf, appended to base URLs
                # This needs careful construction to avoid too many invalid URLs
                # For now, let's assume modules like Nuclei/SQLMap are smart enough if given base URLs and paths separately,
                # or we refine this to construct full URLs from paths.
                # A simpler approach for now: pass the sets directly and let modules decide.
                kwargs['target_urls'] = list(expanded_target_urls) # Validated http/s URLs
                kwargs['discovered_paths'] = list(discovered_paths_for_fuzzing) # Paths like /admin, /backup.zip
                kwargs['urls_with_params'] = list(discovered_urls_with_params) # Full URLs that Arjun found params for

                if phase_name == "sqlmap":
                    kwargs['user_targets'] = args.sqlmap_targets # Keep passing CLI targets separately for SQLMap

            elif phase_name in ["nmap", "wpscan", "directory_bruteforce", "parameter_finder"]:
                # These tools typically operate on base URLs or hostnames
                kwargs['target_urls'] = list(expanded_target_urls)


            # --- Execute Phase ---
            run_func(**kwargs) # Execute the phase function

            # --- Collect and Validate Subdomains After subdomain_scan ---
            if phase_name == "subdomain_scan":
                sub_results = state.get_module_findings("subdomain_scanner", {})
                current_discovered_subdomains = sub_results.get("subdomains_found", [])
                if current_discovered_subdomains:
                    print(f"[+] Collected {len(current_discovered_subdomains)} subdomains. Validating protocols...")
                    validated_subdomain_urls_from_scan = set()
                    validation_timeout = config.get("subdomain_validation_timeout", 5)
                    request_headers = {"User-Agent": config.get('default_user_agent', 'OmegaScytheDominator')}

                    for sub_domain in current_discovered_subdomains:
                        is_validated_sub = False
                        for protocol in ["https://", "http://"]:
                            try:
                                test_url = f"{protocol}{sub_domain}"
                                response = requests.head(test_url, timeout=validation_timeout, verify=False, allow_redirects=True, headers=request_headers)
                                if 200 <= response.status_code < 400:
                                    final_url = response.url # Use the URL after redirects
                                    expanded_target_urls.add(final_url)
                                    is_validated_sub = True
                                    print(f"    -> Validated & Added: {final_url}")
                                    # Prefer HTTPS if both work, but set logic handles duplicates.
                                    # If we want to be more selective, add logic here.
                                    break # Found a working protocol for this subdomain
                            except requests.exceptions.RequestException:
                                pass
                    print(f"    Expanded target URL set now contains {len(expanded_target_urls)} unique URLs after subdomain validation.")

            # --- Collect findings from directory_bruteforcer ---
            elif phase_name == "directory_bruteforce":
                dirb_results = state.get_module_findings("directory_bruteforcer", {})
                findings_summary = dirb_results.get("findings_summary", [])
                for finding in findings_summary:
                    # We are interested in the full URL found by ffuf
                    if finding.get("url"):
                         discovered_paths_for_fuzzing.add(finding.get("url"))
                if discovered_paths_for_fuzzing:
                    print(f"[+] Collected {len(discovered_paths_for_fuzzing)} interesting URLs/paths from Directory Bruteforcer.")

            # --- Collect findings from parameter_finder ---
            elif phase_name == "param_fuzz": # This is the parameter_finder module now
                param_results = state.get_module_findings("parameter_finder", {})
                found_params_dict = param_results.get("found_parameters", {})
                for url_with_param, params_list in found_params_dict.items():
                    if params_list: # Ensure there are actual parameters
                        discovered_urls_with_params.add(url_with_param)
                if discovered_urls_with_params:
                    print(f"[+] Collected {len(discovered_urls_with_params)} URLs with parameters from Parameter Finder.")

        except ImportError as e:
             print(f"[!!!] Failed to import module '{module_path}' for phase '{phase_name}'. Skipping. Error: {e}")
             state.add_tool_error(f"Import Error for phase {phase_name}: {e}")
        except AttributeError as e:
             print(f"[!!!] Failed to find function '{function_name}' in module '{module_path}' for phase '{phase_name}'. Skipping. Error: {e}")
             state.add_tool_error(f"Attribute Error for phase {phase_name}: {e}")
        except Exception as e:
             print(f"[!!!] Unexpected error executing phase '{phase_name}'. Error: {e}")
             import traceback
             traceback.print_exc() # Print full traceback for debugging
             state.add_tool_error(f"Runtime Error in phase {phase_name}: {e}")
             # Decide whether to continue or halt on phase error
             if not user_confirm(f"Phase '{phase_name}' encountered an error. Continue with next phases?", config):
                 print("[!] Halting scan due to phase error.")
                 break # Stop processing phases
        finally:
             # Save state after each phase attempt (success or failure)
             state.save_state()


    # --- 5. Finalize and Report ---
    print("\n--- Scan Phases Completed ---")
    state.finalize_scan()
    save_full_report(state, config) # Save final state
    generate_summary_report(state, config)


if __name__ == "__main__":
    try:
        # Check Python version?
        if sys.version_info < (3, 7):
             print("[!] OmegaScythe requires Python 3.7 or higher.")
             sys.exit(1)
        # Check external libraries early?
        try:
             import yaml
             import requests
        except ImportError as e:
             print(f"[!!!] Missing required Python library: {e}. Please install dependencies using 'pip install -r requirements.txt'.")
             sys.exit(1)

        main()
    except KeyboardInterrupt:
        print("\n\n[!] OmegaScythe Dominator scan aborted by user.")
        # Attempt final save if state object exists? Difficult to guarantee state here.
        sys.exit(0)
    except Exception as e: # Catch broad exceptions in main setup/teardown
        print(f"\n[!!!] A critical unexpected error occurred in main execution: {e}")
        import traceback
        traceback.print_exc()
        # Attempt save if state object exists?
        sys.exit(1)
