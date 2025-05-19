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

    if not config.get("enable_parameter_finding", False):
        print("[i] Parameter finding disabled in configuration. Skipping.")
        state.update_module_findings("parameter_finder", {"status": "Disabled in Config"})
    state.mark_phase_executed("param_fuzz") # Mark the conceptual phase
    # state.save_state() # Save state will be called at the end of run_scan
    return

def _parse_arjun_results(arjun_json_file_path):
    """
    Parses the JSON output file from Arjun and returns a dictionary of found parameters.
    """
    found_parameters = {}
    if not arjun_json_file_path or not os.path.exists(arjun_json_file_path):
        print("    [-] Arjun JSON results file not found or not provided for parsing.")
        return found_parameters

    try:
        with open(arjun_json_file_path, 'r', errors='ignore') as f:
            for line_number, line in enumerate(f, 1):
                line_content = line.strip()
                if not line_content: # Skip empty lines
                    continue
                try:
                    data = json.loads(line_content)
                    # Arjun's output can be a dictionary where keys are URLs
                    # or a list of dictionaries (less common for -oJ).
                    # This handles the common case where the top-level key is the URL.
                    if isinstance(data, dict):
                        for key, value in data.items():
                            if key.startswith("http") and isinstance(value, list): # Assume key is URL, value is list of params
                                found_parameters[key] = found_parameters.get(key, []) + value
                                # Arjun -oJ usually has one URL object per line, so break after finding it.
                                break 
                            # Handle another common Arjun structure: {"url": "...", "params": [...]}
                            elif "params" in data and "url" in data and isinstance(data["params"], list):
                                url = data["url"]
                                params = data["params"]
                                if url and params:
                                     found_parameters[url] = found_parameters.get(url, []) + params
                                break # Found the expected structure for this line
                    # else: (handle if data is a list, though less common for -oJ line-by-line)
                    #    pass
                except json.JSONDecodeError:
                    if line_content: # Only print warning if the line wasn't just whitespace
                        print(f"    [-] Skipping invalid JSON line {line_number} in Arjun output: {line_content[:100]}...")
                    continue
        
        # Clean up duplicates within each URL's list of parameters
        for url in found_parameters:
            found_parameters[url] = sorted(list(set(found_parameters[url])))
        
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
    arjun_output_json_file = os.path.join(config.get("output_dir", "."), "tool_logs", f"{os.path.basename(base_filename)}_arjun_results.json")
    arjun_console_log_file = os.path.join(config.get("output_dir", "."), "tool_logs", f"{os.path.basename(base_filename)}_arjun_console.log")
    os.makedirs(os.path.dirname(arjun_output_json_file), exist_ok=True) # Ensure dir exists

    # Arjun command construction - allowing more flexible options from config
    # Example: config could have arjun: { options: ["-t", "10", "--stable"], threads: 15, wordlist: "/path/to/list" }
    arjun_config = config.get("arjun_tool_options", {}) # Renamed for clarity
    
    default_options = ["-t", "10"] # Default threads
    cli_options = arjun_config.get("options", []) # List of options like ["--stable", "-d", "example.com"]
    
    # Specific configurable parameters override general options if provided
    if "threads" in arjun_config:
        # Remove existing -t if present, then add new one
        cli_options = [opt for opt in cli_options if opt != "-t" and not opt.startswith("-t")]
        cli_options.extend(["-t", str(arjun_config["threads"])])
    elif not any(opt.startswith("-t") for opt in cli_options): # Add default threads if not specified
        cli_options.extend(default_options)

    if "wordlist" in arjun_config and arjun_config["wordlist"]:
        cli_options.extend(["-w", arjun_config["wordlist"]])
    
    # Ensure no duplicate flags if user provides them in 'options' and also as specific keys
    # This simple approach assumes user config is sensible. More robust parsing could be added.

    command = [
        "arjun",
        "-u", target_url,
        "-oJ", arjun_output_json_file # Output in JSON format
    ] + cli_options

    arjun_timeout = arjun_config.get("timeout", 1800) # Default 30 mins from arjun_config

    print(f"    Executing Arjun: {' '.join(command)}")
    
    # User confirmation is handled in the main run_scan before calling this helper
    process_obj = run_command(command, "Arjun", config, timeout=arjun_timeout, return_proc=True, log_file_path=arjun_console_log_file)

    if process_obj and hasattr(process_obj, 'returncode') and process_obj.returncode == 0:
        if os.path.exists(arjun_output_json_file) and os.path.getsize(arjun_output_json_file) > 0:
            return True, arjun_output_json_file, arjun_console_log_file
        else:
            print(f"    [!] Arjun command succeeded (RC=0) but output file '{arjun_output_json_file}' is missing or empty.")
            return False, None, arjun_console_log_file # Command success, but no output file
    elif process_obj and hasattr(process_obj, 'returncode'):
        print(f"    [-] Arjun command failed. RC: {process_obj.returncode}. Check console log: {arjun_console_log_file}")
        return False, None, arjun_console_log_file # Command failed
    else: # Process object itself is None, e.g., timeout or other run_command internal error
        print(f"    [-] Arjun execution failed to start or was interrupted. Check console log: {arjun_console_log_file if os.path.exists(arjun_console_log_file) else 'not created'}")
        return False, None, arjun_console_log_file if os.path.exists(arjun_console_log_file) else None


    if state.get_full_state()["tool_checks"].get("arjun", {}).get("status") != "Found":
        print("[!] Arjun tool not found or check failed. Skipping parameter finding.")
        state.update_module_findings("parameter_finder", {"status": "Skipped (Arjun Missing)"})
    state.mark_phase_executed("param_fuzz")
    # state.save_state() # Save state will be called at the end of run_scan
    return

    print(f"\n[*] Phase Parameter Finding: Running Arjun against {target_url}")
    
    # Initial state update for the module
    module_findings = {
        "target_url": target_url,
        "status": "Starting",
        "results_file": None,
        "console_log": None,
        "found_parameters": {},
        "error": None
    }
    state.update_module_findings("parameter_finder", module_findings)

    if not user_confirm("Proceed with Arjun parameter finding? This can generate significant traffic.", config):
        print("[i] Skipping Arjun scan as per user confirmation.")
        module_findings["status"] = "Skipped (User Declined)"
        state.update_module_findings("parameter_finder", module_findings)
        state.mark_phase_executed("param_fuzz")
        state.save_state()
        return

    module_findings["status"] = "Running Arjun"
    state.update_module_findings("parameter_finder", module_findings)

    # Run Arjun tool
    arjun_success, arjun_json_output_file, arjun_console_log = _run_arjun_tool(state, config, target_url)
    module_findings["console_log"] = arjun_console_log

    if arjun_success and arjun_json_output_file:
        module_findings["status"] = "Parsing Results"
        module_findings["results_file"] = arjun_json_output_file
        state.update_module_findings("parameter_finder", module_findings)
        
        found_parameters = _parse_arjun_results(arjun_json_output_file)
        module_findings["found_parameters"] = found_parameters
        
        if found_parameters:
            module_findings["status"] = "Completed (Parameters Found)"
            state.add_summary_point(f"Arjun discovered parameters for {len(found_parameters)} URL(s). See {arjun_json_output_file}")
            # Log a brief example
            example_url = list(found_parameters.keys())[0]
            example_params = found_parameters[example_url][:3]
            print(f"    [+] Arjun discovered parameters for {len(found_parameters)} URL(s). Example: {example_url} -> {example_params}...")
        else:
            module_findings["status"] = "Completed (No Parameters Found)"
            print("    [i] Arjun completed but did not report finding any new parameters from JSON output.")
            
    elif arjun_success and not arjun_json_output_file: # Arjun ran but output file is missing/empty
        module_findings["status"] = "Arjun Completed (No Output File)"
        module_findings["error"] = f"Arjun ran successfully but output file was not found or empty: {arjun_json_output_file}"
        state.add_tool_error(f"Arjun: Output file missing/empty - {arjun_json_output_file}")
    else: # Arjun command failed or execution error
        module_findings["status"] = "Arjun Failed"
        module_findings["error"] = f"Arjun execution failed. Check console log: {arjun_console_log}"
        # Tool error should have been logged by _run_arjun_tool or run_command
        state.add_tool_error(f"Arjun execution failed. See {arjun_console_log}")


    state.update_module_findings("parameter_finder", module_findings)
    state.mark_phase_executed("param_fuzz")
    state.save_state()
