import os
import json
from core.tool_runner import run_command
from core.utils import get_scan_filename_prefix, user_confirm

def run_scan(state, config):
    """
    Performs directory and file brute-forcing using ffuf.
    """
    target_info = state.get_full_state()["scan_metadata"]["target_info"]
    target_url = target_info.get("url")

    if not config.get("enable_directory_bruteforce", False):
        print("[i] Directory/File brute-forcing disabled in configuration. Skipping.")
        state.update_module_findings("directory_bruteforcer", {"status": "Disabled in Config"})
        state.mark_phase_executed("directory_bruteforce")
        state.save_state()
        return

    if state.get_full_state()["tool_checks"].get("ffuf", {}).get("status") != "Found":
        print("[!] ffuf tool not found or check failed. Skipping directory/file brute-forcing.")
        state.update_module_findings("directory_bruteforcer", {"status": "Skipped (ffuf Missing)"})
        state.mark_phase_executed("directory_bruteforce")
        state.save_state()
        return

    wordlist_path = config.get("directory_bruteforce_wordlist")
    if not wordlist_path or not os.path.exists(wordlist_path):
        print(f"[!] Wordlist for directory brute-forcing not found or not specified ('{wordlist_path}'). Skipping.")
        state.update_module_findings("directory_bruteforcer", {"status": f"Skipped (Wordlist Missing: {wordlist_path})"})
        state.mark_phase_executed("directory_bruteforce")
        state.save_state()
        return

    print(f"\n[*] Phase Directory Brute-force: Running ffuf against {target_url}")
    state.update_module_findings("directory_bruteforcer", {
        "target_url": target_url,
        "wordlist": wordlist_path,
        "status": "Running ffuf",
        "results_file": None,
        "findings_summary": [] # Store key findings (e.g., non-404 status codes)
    })

    base_filename = get_scan_filename_prefix(state, config)
    ffuf_output_json_file = f"{base_filename}_ffuf_results.json" # For structured results
    ffuf_console_log_file = f"{base_filename}_ffuf_console.log" # For raw console output

    # Basic ffuf command structure - highly configurable
    ffuf_options = config.get("ffuf_options", "-mc 200,204,301,302,307,401,403 -fc 404 -fr '/^$/'").split() # Sensible defaults
    command = [
        "ffuf",
        "-u", f"{target_url.rstrip('/')}/FUZZ", # Standard FUZZ keyword placement
        "-w", wordlist_path,
        "-o", ffuf_output_json_file, # JSON output for parsing
        "-of", "json" # Output format
    ] + ffuf_options

    # Add recursion options if configured
    recursion_depth = config.get("ffuf_recursion_depth")
    if recursion_depth and isinstance(recursion_depth, int) and recursion_depth > 0:
        command.extend(["-recursion", "-recursion-depth", str(recursion_depth)])
        print(f"    [i] Enabling ffuf recursion (depth: {recursion_depth})")

    # Add extensions if configured
    extensions = config.get("ffuf_extensions")
    if extensions and isinstance(extensions, list):
        ext_str = ",".join(extensions)
        command.extend(["-e", ext_str])
        print(f"    [i] Adding extensions: {ext_str}")


    ffuf_timeout = config.get("ffuf_timeout", 1800) # Default 30 mins

    print(f"    Executing: {' '.join(command)}") # Log the command being run
    if not user_confirm("Proceed with ffuf directory/file brute-forcing? This can be intensive.", config):
        print("[i] Skipping ffuf scan as per user confirmation.")
        state.update_module_findings("directory_bruteforcer", {"status": "Skipped (User Declined)"})
        state.mark_phase_executed("directory_bruteforce")
        state.save_state()
        return

    # Use run_command with log_file_path for live console output logging
    # The return_proc=True will give us the Popen object from tool_runner
    process_obj = run_command(command, "ffuf", config, timeout=ffuf_timeout, return_proc=True, log_file_path=ffuf_console_log_file)

    findings_summary = []
    # Check process_obj.returncode after Popen has completed.
    # Also ensure the JSON output file was created, as ffuf might complete but fail to write if disk is full, etc.
    if process_obj and hasattr(process_obj, 'returncode') and process_obj.returncode == 0 and os.path.exists(ffuf_output_json_file):
        print(f"[+] ffuf completed. JSON results: {ffuf_output_json_file}, Console log: {ffuf_console_log_file}")
        state.update_module_findings("directory_bruteforcer", {"status": "Completed", "results_file": ffuf_output_json_file, "console_log": ffuf_console_log_file})
        # Parse JSON results to extract key findings for the state/summary
        try:
            with open(ffuf_output_json_file, 'r', errors='ignore') as f: # Added errors='ignore'
                ffuf_data = json.load(f)
            results = ffuf_data.get("results", [])
            for result in results:
                # Store interesting results (customize based on status, length, etc.)
                status = result.get("status")
                url = result.get("url")
                length = result.get("length")
                content_type = result.get("content-type")
                redirect = result.get("redirectlocation")

                # Example: Log non-404s, or specific interesting codes/content types
                if status != 404:
                    finding = {"url": url, "status": status, "length": length, "content-type": content_type}
                    if redirect: finding["redirect"] = redirect
                    findings_summary.append(finding)
                    # Add alerts/remediations based on findings if desired (e.g., exposed admin panel)
                    if status == 200 and any(p in url.lower() for p in ["admin", "login", "config", "backup", ".git", ".env"]):
                         state.add_critical_alert(f"Potential sensitive path found by ffuf: {url} (Status: {status})")

            state.update_module_findings("directory_bruteforcer", {"findings_summary": findings_summary})
            state.add_summary_point(f"ffuf found {len(findings_summary)} potentially interesting paths (non-404). See {ffuf_output_json_file}")
            print(f"    [i] Parsed {len(findings_summary)} potentially interesting results from ffuf JSON output.")

        except json.JSONDecodeError:
            print(f"    [-] Failed to parse ffuf JSON output: {ffuf_output_json_file}")
            state.add_tool_error(f"ffuf JSON parsing error for {ffuf_output_json_file}")
        except Exception as e:
            print(f"    [-] Error processing ffuf JSON results: {e}")
            state.add_tool_error(f"ffuf result processing error: {e}")

    elif process_obj and hasattr(process_obj, 'returncode'): # Check if Popen object exists and has returncode
        error_msg = f"ffuf failed. RC: {process_obj.returncode}. Check console log: {ffuf_console_log_file}"
        state.update_module_findings("directory_bruteforcer", {"status": "ffuf Failed", "error": error_msg, "console_log": ffuf_console_log_file})
        # stderr is not directly available from Popen object in this setup, it's merged into stdout and written to log
        state.add_tool_error(f"ffuf Failed: RC={process_obj.returncode}. See {ffuf_console_log_file}")
    else: # process_obj might be None if run_command had an early exception before Popen
        state.update_module_findings("directory_bruteforcer", {"status": "ffuf Execution Error", "console_log": ffuf_console_log_file if os.path.exists(ffuf_console_log_file) else "Log not created"})
        # Tool error already logged by run_command

    state.mark_phase_executed("directory_bruteforce")
    state.save_state()
