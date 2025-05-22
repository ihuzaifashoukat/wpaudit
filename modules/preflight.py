import json
import os
import re
import requests # Needs requests library
from urllib.parse import urlparse
from core.tool_runner import run_command # Import from core

def run_checks(state, config):
    """
    Performs pre-flight checks like robots.txt and optional WAF detection.
    """
    target_url = state.get_full_state()["scan_metadata"]["target_info"]["url"]
    print(f"\n[*] Phase 0: Pre-flight Checks for {target_url}")
    
    _check_robots(state, config, target_url)
    _check_waf(state, config, target_url)
    
    state.mark_phase_executed("preflight")
    state.save_state() # Save after phase completion

def _check_robots(state, config, target_url):
    """Checks robots.txt"""
    module_key = "robots_txt_info"
    state.update_module_findings(module_key, {"status": "Not Checked", "url": None, "content": None, "disallowed_paths": []})

    robots_url = urlparse(target_url)._replace(path="robots.txt", query="", fragment="").geturl()
    state.update_module_findings(module_key, {"url": robots_url}) # Update with URL

    print(f"    Checking robots.txt: {robots_url}")
    try:
        response = requests.get(robots_url, timeout=config.get("requests_timeout", 15), headers={"User-Agent": config["default_user_agent"]})
        if response.status_code == 200:
            content = response.text
            print(f"    [+] robots.txt found.")
            disallowed = []
            for line in content.splitlines():
                if line.strip().lower().startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    if path: disallowed.append(path)

            state.update_module_findings(module_key, {"status": "Found", "content": content, "disallowed_paths": disallowed})
            if disallowed: print(f"    [i] Disallowed paths found: {disallowed[:3]}{'...' if len(disallowed)>3 else ''}")
            if config["respect_robots_txt"] and disallowed:
                print(f"    [!] WARNING: 'respect_robots_txt' is True. Scans may be limited.")
                state.add_summary_point("robots.txt found with Disallow. 'respect_robots_txt' enabled.")
        else:
            print(f"    [-] robots.txt not found or error (Status: {response.status_code}).")
            state.update_module_findings(module_key, {"status": f"Not Found/Error ({response.status_code})"})
    except requests.exceptions.RequestException as e:
        print(f"    [-] Error fetching robots.txt: {e}")
        state.update_module_findings(module_key, {"status": f"Request Error: {e}"})
    except Exception as e: # Catch other potential errors
        print(f"    [-] Unexpected error checking robots.txt: {e}")
        state.update_module_findings(module_key, {"status": f"Unexpected Error: {e}"})

def _check_waf(state, config, target_url):
    """Checks for WAF using Wafw00f if enabled and available."""
    module_key = "waf_info"
    state.update_module_findings(module_key, {"status": "Not Checked"})

    if not config.get("enable_waf_detection", True):
        print("    [i] WAF detection is disabled in configuration.")
        state.update_module_findings(module_key, {"status": "Disabled in Config"})
        return

    wafw00f_check_status = state.get_full_state()["tool_checks"].get("wafw00f", {}).get("status", "Not Found")
    if not wafw00f_check_status.startswith("Found"):
        print(f"    [i] Wafw00f tool status is '{wafw00f_check_status}'. Skipping WAF detection.")
        state.update_module_findings(module_key, {"status": "Skipped (Tool Check Status: " + wafw00f_check_status + ")"})
        return

    print(f"\n    Attempting WAF detection using Wafw00f for {target_url}...")
    state.update_module_findings(module_key, {"status": "Running Wafw00f"})

    # Wafw00f requires the target without path usually, just the base URL
    parsed_target = urlparse(target_url)
    base_target_for_waf = f"{parsed_target.scheme}://{parsed_target.netloc}"

    command = ["wafw00f", base_target_for_waf, "-a", "-f", "json"]
    waf_timeout = config.get("wafw00f_timeout", 300)
    waf_proc_output = run_command(command, "Wafw00f", config, timeout=waf_timeout) # Get stdout

    if waf_proc_output:
        try:
            # Use a non-greedy regex to better isolate JSON from potential surrounding text/banner.
            json_match = re.search(r'(\[.*?\]|\{.*?\})', waf_proc_output, re.DOTALL)
            if json_match:
                json_text_original = json_match.group(1)
                # Attempt to remove null bytes as they can cause JSONDecodeError and might not print.
                json_text_cleaned = json_text_original.replace('\x00', '')

                if not json_text_cleaned.strip():
                    print(f"    [-] Wafw00f: Extracted JSON part was empty or only whitespace after cleaning null bytes. Original Raw segment (first 100 chars): '{json_text_original[:100]}'... Full Raw output (first 300 chars): '{waf_proc_output[:300]}'")
                    state.update_module_findings(module_key, {"error": "Cleaned JSON part was empty", "raw_json_part": json_text_original, "raw_output": waf_proc_output})
                else:
                    waf_data_list = json.loads(json_text_cleaned) # Try parsing cleaned JSON
                    waf_data = waf_data_list[0] if isinstance(waf_data_list, list) and waf_data_list else (waf_data_list if isinstance(waf_data_list, dict) else {})
                    state.update_module_findings(module_key, {"data": waf_data}) # Store parsed data

                    if waf_data.get("firewall") and waf_data["firewall"] not in ["None", "Generic"]:
                        waf_name = waf_data['firewall']
                        manu = waf_data.get('manufacturer', 'N/A')
                        print(f"    [+] WAF Detected: {waf_name} (Manufacturer: {manu})")
                        status_msg = f"Detected: {waf_name}"
                        state.update_module_findings(module_key, {"status": status_msg})
                        state.add_critical_alert(f"WAF Detected: {waf_name}. May affect scans/exploitation.")
                        state.add_summary_point(f"WAF Detected: {waf_name}.")
                    else:
                        print("    [i] No specific WAF explicitly identified by Wafw00f.")
                        state.update_module_findings(module_key, {"status": "Not Detected or Unknown by Wafw00f"})
            else: # json_match is None
                 raw_output_snippet = waf_proc_output[:300]
                 error_msg = "No valid JSON found in Wafw00f output."
                 detailed_error = "No JSON structure (starting with { or [ and ending with } or ]) was found."

                 # Check for known non-JSON error patterns from Wafw00f
                 if "404 Hack Not Found" in waf_proc_output:
                     error_msg = "Wafw00f returned a '404 Hack Not Found' error."
                     detailed_error = "This typically indicates Wafw00f encountered an issue probing the target, or the target itself returned this unique error."
                 elif "Could not connect to" in waf_proc_output: # Example of another pattern
                     error_msg = "Wafw00f reported a connection issue."
                     detailed_error = "Wafw00f failed to connect to the target URL."
                 # Add more known patterns if necessary

                 print(f"    [-] Wafw00f: {error_msg} Raw output snippet: {raw_output_snippet}")
                 state.update_module_findings(module_key, {
                     "error": error_msg,
                     "detailed_error": detailed_error,
                     "raw_output": waf_proc_output
                 })

        except json.JSONDecodeError as jde:
            # json_text_cleaned would be defined if we reached the json.loads(json_text_cleaned) line
            problematic_text_snippet = json_text_cleaned[:300] if 'json_text_cleaned' in locals() and json_text_cleaned is not None else "N/A (json_text_cleaned not available or None)"
            
            print(f"    [-] Wafw00f: Could not decode JSON output (even after attempting to clean null bytes).")
            print(f"        Text that failed parsing (first 300 chars): '{problematic_text_snippet}'")
            print(f"        JSONDecodeError details: {jde}")
            # Show full raw output only if it provides more context or is short
            if len(waf_proc_output) < 350 or \
               ('json_text_cleaned' in locals() and json_text_cleaned is not None and problematic_text_snippet != waf_proc_output[:300]) or \
               ('json_text_cleaned' not in locals() or json_text_cleaned is None):
                 print(f"        Full Wafw00f raw output (first 300 chars): {waf_proc_output[:300]}")
            elif problematic_text_snippet == waf_proc_output[:300] and len(waf_proc_output) >=350 :
                 print(f"        (Full Wafw00f raw output starts with the same text as 'Text that failed parsing')")

            state.update_module_findings(module_key, {
                "error": "JSON Decode Error after cleaning",
                "failed_json_text": json_text_cleaned if 'json_text_cleaned' in locals() and json_text_cleaned is not None else "N/A",
                "raw_output": waf_proc_output,
                "json_decode_exception": str(jde)
            })
        except Exception as e:
            print(f"    [-] Wafw00f: Error processing output: {e}")
            state.update_module_findings(module_key, {"error": str(e), "raw_output": waf_proc_output})
    else:
        # run_command already printed error, just update state
        print("    [-] Wafw00f scan failed or produced no output (check tool_errors in report).")
        # Add specific error from tool_errors if available, otherwise generic
        tool_errors = state.get_full_state()["tool_errors"]
        waf_err = "Wafw00f Error or No Output"
        for err in reversed(tool_errors):
            if "Wafw00f" in err:
                 waf_err = err
                 break
        state.update_module_findings(module_key, {"status": waf_err})
