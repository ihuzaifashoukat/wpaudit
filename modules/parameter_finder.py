import os
import json
from core.tool_runner import run_command
from core.utils import get_scan_filename_prefix, user_confirm

def run_scan(state, config):
    """
    Discovers hidden HTTP parameters using Arjun.
    """
    target_info = state.get_full_state()["scan_metadata"]["target_info"]
    target_url = target_info.get("url")
    module_findings_key = "parameter_finder"

    if not config.get("enable_parameter_finding", False):
        print("    [i] Parameter finding (Arjun) disabled in configuration. Skipping.")
        state.update_module_findings(module_findings_key, {"status": "Disabled in Config", "target_url": target_url})
        state.mark_phase_executed("param_fuzz")
        state.save_state()
        return

    if not target_url:
        print("    [!] Target URL not available. Skipping Parameter Finder.")
        state.update_module_findings(module_findings_key, {"status": "Skipped (No Target URL)"})
        state.mark_phase_executed("param_fuzz")
        state.save_state()
        return

    arjun_check_status = state.get_full_state().get("tool_checks", {}).get("arjun", {}).get("status", "Not Found")
    if not (arjun_check_status.startswith("Found") or arjun_check_status == "Check Skipped (No Version Cmd)"):
        print(f"    [!] Arjun tool not found or check failed (Status: {arjun_check_status}). Skipping parameter finding.")
        state.update_module_findings(module_findings_key, {"status": f"Skipped (Arjun Status: {arjun_check_status})", "target_url": target_url})
        state.mark_phase_executed("param_fuzz")
        state.save_state()
        return

    print(f"\n[*] Phase Parameter Finding: Running Arjun against {target_url}")
    
    module_findings = {
        "target_url": target_url,
        "status": "Starting",
        "results_file": None,
        "console_log": None,
        "found_parameters": {},
        "error": None
    }
    state.update_module_findings(module_findings_key, module_findings)

    if not user_confirm(f"Proceed with Arjun parameter finding on {target_url}? This can generate significant traffic.", config):
        print("    [i] Skipping Arjun scan as per user confirmation.")
        module_findings["status"] = "Skipped (User Declined)"
        state.update_module_findings(module_findings_key, module_findings)
        state.mark_phase_executed("param_fuzz")
        state.save_state()
        return

    module_findings["status"] = "Running Arjun"
    state.update_module_findings(module_findings_key, module_findings)

    # Run Arjun tool
    arjun_success, arjun_json_output_file, arjun_console_log = _run_arjun_tool(state, config, target_url)
    module_findings["console_log"] = arjun_console_log

    if arjun_success and arjun_json_output_file:
        module_findings["status"] = "Parsing Results"
        module_findings["results_file"] = arjun_json_output_file
        state.update_module_findings(module_findings_key, module_findings)
        
        found_parameters = _parse_arjun_results(arjun_json_output_file)
        module_findings["found_parameters"] = found_parameters
        
        if found_parameters:
            module_findings["status"] = "Completed (Parameters Found)"
            # Log a brief example
            example_url_count = len(found_parameters)
            example_url_key = list(found_parameters.keys())[0] if found_parameters else None
            example_params_list = found_parameters.get(example_url_key, [])[:3] if example_url_key else []
            
            summary_msg = f"Arjun discovered parameters for {example_url_count} URL(s)."
            if example_url_key:
                 summary_msg += f" Example: {example_url_key} -> {example_params_list}..."
            print(f"    [+] {summary_msg} See {arjun_json_output_file}")
            state.add_summary_point(summary_msg)

            # Make findings available for other tools (e.g. SQLMap, XSS checker)
            # This structure is already good: {"url1": ["param1", "param2"], "url2": ["paramA"]}
            # No specific action needed here if other tools know to look for "parameter_finder" findings.

        else:
            module_findings["status"] = "Completed (No Parameters Found)"
            print("    [i] Arjun completed but did not report finding any new parameters from JSON output.")
            
    elif arjun_success and not arjun_json_output_file: # Arjun ran but output file is missing/empty
        module_findings["status"] = "Arjun Completed (No Output File)"
        error_detail = f"Arjun ran successfully but output file was not found or empty: {arjun_json_output_file}"
        module_findings["error"] = error_detail
        state.add_tool_error(f"Arjun: Output file missing/empty - {arjun_json_output_file if arjun_json_output_file else 'Path not available'}")
        print(f"    [!] {error_detail}")
    else: # Arjun command failed or execution error
        module_findings["status"] = "Arjun Failed"
        error_detail = f"Arjun execution failed. Check console log: {arjun_console_log if arjun_console_log else 'Not available'}"
        module_findings["error"] = error_detail
        state.add_tool_error(f"Arjun execution failed. See {arjun_console_log if arjun_console_log else 'console log (path not available)'}")
        print(f"    [-] {error_detail}")

    state.update_module_findings(module_findings_key, module_findings)
    state.mark_phase_executed("param_fuzz")
    state.save_state()

def _parse_arjun_results(arjun_json_file_path):
    """
    Parses the JSON output file from Arjun and returns a dictionary of found parameters.
    Arjun's -oJ output is typically one JSON object per line, where each object
    is a dictionary with the URL as the key and a list of parameters as the value.
    Example: {"http://example.com/search": ["q", "category"]}
    Or sometimes: {"url": "http://example.com/search", "params": ["q", "category"], "method": "GET"}
    """
    found_parameters = {}
    if not arjun_json_file_path or not os.path.exists(arjun_json_file_path):
        print("    [-] Arjun JSON results file not found or not provided for parsing.")
        return found_parameters

    try:
        with open(arjun_json_file_path, 'r', errors='ignore') as f:
            for line_number, line in enumerate(f, 1):
                line_content = line.strip()
                if not line_content: continue
                
                try:
                    data = json.loads(line_content)
                    
                    # Primary expected format: { "url": ["param1", "param2"] }
                    if isinstance(data, dict):
                        for url_key, params_list in data.items():
                            if url_key.startswith("http") and isinstance(params_list, list):
                                # Ensure all params are strings, filter out non-strings if any
                                valid_params = [str(p) for p in params_list if isinstance(p, (str, int, float))]
                                if valid_params:
                                    found_parameters[url_key] = found_parameters.get(url_key, []) + valid_params
                                # This format usually has one URL per JSON object/line
                                break 
                        else: # If the loop didn't break, try alternative structure
                            # Alternative format: {"url": "...", "params": [...], "method": "..."}
                            if "url" in data and "params" in data and isinstance(data["params"], list):
                                url = data["url"]
                                params = data["params"]
                                valid_params = [str(p) for p in params if isinstance(p, (str, int, float))]
                                if url and valid_params:
                                    found_parameters[url] = found_parameters.get(url, []) + valid_params
                                    
                except json.JSONDecodeError:
                    if line_content: # Only print warning if the line wasn't just whitespace
                        print(f"    [-] Skipping invalid JSON line {line_number} in Arjun output: {line_content[:100]}...")
                    continue
        
        # Clean up duplicates within each URL's list of parameters and sort
        for url_key in found_parameters:
            found_parameters[url_key] = sorted(list(set(found_parameters[url_key])))
        
        if found_parameters:
            print(f"    [i] Parsed parameters for {len(found_parameters)} URL(s) from Arjun output.")
        else:
            print("    [i] No parameters parsed from Arjun JSON output (file might be empty or format unexpected).")

    except Exception as e:
        print(f"    [-] Error processing Arjun JSON results file '{arjun_json_file_path}': {e}")
    
    return found_parameters

def _run_arjun_tool(state, config, target_url):
    """
    Constructs and runs the Arjun command, returning paths to output files and success status.
    """
    base_filename = get_scan_filename_prefix(state, config)
    # Ensure tool_logs directory exists under the main output_dir
    tool_logs_dir = os.path.join(config.get("output_dir", "omegascythe_overlord_reports"), "tool_logs")
    os.makedirs(tool_logs_dir, exist_ok=True)
    
    arjun_output_json_file = os.path.join(tool_logs_dir, f"{os.path.basename(base_filename)}_arjun_results.json")
    arjun_console_log_file = os.path.join(tool_logs_dir, f"{os.path.basename(base_filename)}_arjun_console.log")

    # Arjun command construction
    # Expects 'arjun_options' to be a string in config, like "-t 10 -m GET POST"
    # And 'arjun_timeout' for timeout value
    
    arjun_options_str = config.get("arjun_options", "-t 10 -m GET") # Default options
    cli_options = arjun_options_str.split() # Split the string into a list of options

    command = ["arjun", "-u", target_url, "-oJ", arjun_output_json_file] + cli_options

    arjun_timeout = config.get("arjun_timeout", 1800) # Default 30 mins

    print(f"    Executing Arjun: {' '.join(command)}")
    
    process_obj = run_command(command, "Arjun", config, timeout=arjun_timeout, return_proc=True, log_file_path=arjun_console_log_file)

    if process_obj and hasattr(process_obj, 'returncode') and process_obj.returncode == 0:
        # Arjun sometimes exits 0 even if it encounters issues like host not resolving.
        # Check if output file has content.
        if os.path.exists(arjun_output_json_file) and os.path.getsize(arjun_output_json_file) > 0:
            print(f"    [+] Arjun command completed successfully. Output: {arjun_output_json_file}")
            return True, arjun_output_json_file, arjun_console_log_file
        elif os.path.exists(arjun_output_json_file): # File exists but is empty
            print(f"    [i] Arjun command completed (RC=0) but output file '{arjun_output_json_file}' is empty. This might indicate no parameters found or an issue with the target.")
            return True, arjun_output_json_file, arjun_console_log_file # Still success, but parser will find nothing
        else: # File does not exist
            print(f"    [!] Arjun command succeeded (RC=0) but output file '{arjun_output_json_file}' was not created.")
            return False, None, arjun_console_log_file 
    elif process_obj and hasattr(process_obj, 'returncode'):
        print(f"    [-] Arjun command failed. RC: {process_obj.returncode}. Check console log: {arjun_console_log_file}")
        return False, None, arjun_console_log_file
    else: 
        print(f"    [-] Arjun execution failed to start or was interrupted (e.g., timeout). Check console log: {arjun_console_log_file if os.path.exists(arjun_console_log_file) else 'not created'}")
        return False, None, arjun_console_log_file if os.path.exists(arjun_console_log_file) else None
