import subprocess
import json
import os
import re
from urllib.parse import unquote
import sys # For stdout writing
from urllib.parse import unquote, urlparse # Added urlparse
from core.tool_runner import run_command # Though not directly used for sqlmap's Popen
from core.utils import get_scan_filename_prefix, user_confirm, sanitize_filename

def run_scan(state, config, user_targets=None, target_urls=None): # Added target_urls from main.py
    """
    Runs SQLMap scan based on the selected profile and identified/provided targets.
    """
    primary_target_url = state.get_full_state()["scan_metadata"]["target_info"]["url"] # Keep for reference
    profile_name = state.get_full_state()["scan_config_used"].get("profile_name", "default")
    # profile = config.get("scan_profiles", {}).get(profile_name, config.get("scan_profiles", {}).get("default")) # Not directly used for sqlmap_options anymore

    print(f"\n[*] Phase SQLMap: SQL Injection Deep Dive [Profile: {profile_name}]")
    state.update_module_findings("sqlmap_results", {"status": "Initializing", "profile": profile_name, "targets_tested": [], "logs": {}, "vulnerable_targets": []})

    potential_sqli_targets = set()

    # 1. Add explicitly provided user targets (CLI)
    if user_targets:
        for t in user_targets:
            potential_sqli_targets.add(t)
            print(f"    [i] Added SQLMap target from CLI: {t}")

    # 2. Add targets inferred from Nuclei SQLi findings
    nuclei_findings = state.get_module_findings("nuclei_results", {}).get("findings", [])
    for finding in nuclei_findings:
        info = finding.get("info", {})
        tags = info.get("tags", [])
        tags_str = "".join(tags) if isinstance(tags, list) else str(tags)

        if "sql-injection" in finding.get("template-id", "") or "sqli" in tags_str:
            matched_url = finding.get("matched-at", finding.get("host"))
            if matched_url and matched_url not in potential_sqli_targets:
                potential_sqli_targets.add(matched_url)
                print(f"    [i] Added potential SQLi target from Nuclei: {matched_url}")

    # 3. Add validated URLs from subdomain scan (passed as target_urls)
    # These are broader targets; SQLMap will try to find injectable parameters.
    if target_urls:
        for t_url in target_urls:
            if t_url not in potential_sqli_targets:
                potential_sqli_targets.add(t_url)
                print(f"    [i] Added general target for SQLMap (from subdomain/main scan): {t_url}")

    # 4. Add URLs with parameters found by parameter_finder
    param_finder_results = state.get_module_findings("parameter_finder", {}).get("found_parameters", {})
    for url_with_params, params in param_finder_results.items():
        if params and url_with_params not in potential_sqli_targets: # Only add if it has params and not already added
            potential_sqli_targets.add(url_with_params) # SQLMap can often auto-detect parameters
            print(f"    [i] Added potential SQLi target from Parameter Finder: {url_with_params}")


    final_target_list = list(potential_sqli_targets)
    if not final_target_list:
        print("[i] No specific SQLi targets identified or provided. Skipping SQLMap.")
        state.update_module_findings("sqlmap_results", {"status": "Skipped (No Targets)"})
        state.mark_phase_executed("sqlmap")
        state.save_state()
        return

    prompt = f"SQLMap on {len(target_list)} target(s) with '{profile_name}' profile. INTRUSIVE/DESTRUCTIVE. Proceed?"
    if not user_confirm(prompt, config):
        print("[!] SQLMap execution cancelled by user.")
        state.update_module_findings("sqlmap_results", {"status": "Cancelled by user"})
        state.mark_phase_executed("sqlmap") # Mark as executed even if cancelled
        state.save_state()
        return

    state.update_module_findings("sqlmap_results", {"status": "Running"})
    sqlmap_log_dir = os.path.join(config["output_dir"], "sqlmap_logs")
    os.makedirs(sqlmap_log_dir, exist_ok=True)
    sqlmap_timeout = config.get("sqlmap_timeout_per_target", 7200)

    vulnerable_found_list = []

    for i, sqli_target_url in enumerate(target_list):
        print(f"\n    Testing SQLMap target {i+1}/{len(target_list)}: {sqli_target_url}")
        current_targets = state.get_module_findings("sqlmap_results").get("targets_tested", [])
        current_targets.append(sqli_target_url)
        state.update_module_findings("sqlmap_results", {"targets_tested": current_targets})


        # Use get_scan_filename_prefix to get the base for the overall scan run
        base_filename_for_run = get_scan_filename_prefix(state, config) # Overall scan prefix
        # Sanitize target URL for filename (use hostname primarily)
        parsed_sqli_url = urlparse(sqli_target_url)
        sanitized_target_host_part = sanitize_filename(parsed_sqli_url.netloc + parsed_sqli_url.path.replace("/", "_"))
        sqlmap_run_log_file = os.path.join(sqlmap_log_dir, f"{os.path.basename(base_filename_for_run)}_sqlmap_{sanitized_target_host_part[:50]}.log")

        command = ["sqlmap", "-u", sqli_target_url]
        # Get profile-specific or default options
        sqlmap_options_key = f"sqlmap_options_{profile_name}" # e.g., sqlmap_options_aggressive
        sqlmap_options_str = config.get(sqlmap_options_key, config.get("sqlmap_options_default", "--batch --random-agent"))
        sqlmap_cli_options = sqlmap_options_str.format(DEFAULT_USER_AGENT=config.get('default_user_agent', '')).split()
        command.extend(sqlmap_cli_options)

        # Control output directory to keep sessions separate per target if desired (can conflict with --batch sometimes)
        # sqlmap_session_output_dir = os.path.join(config["output_dir"], "sqlmap_sessions", f"{os.path.basename(base_filename)}_{sanitized_target_part}_sessiondata")
        # command.extend(["--output-dir", sqlmap_session_output_dir])


        print(f"      Executing: {' '.join(command)}")
        log_content_header = f"SQLMap run for: {sqli_target_url}\nProfile: {profile_name}\nCommand: {' '.join(command)}\n\n"
        log_path = None
        is_vulnerable = False
        error_msg = None

        try:
            with open(sqlmap_run_log_file, 'w', errors='ignore') as log_f:
                log_f.write(log_content_header)
                # Use Popen for streaming output
                process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, universal_newlines=True, errors='ignore')
                for line in process.stdout:
                    sys.stdout.write(line)
                    log_f.write(line)
                process.wait(timeout=sqlmap_timeout)
            log_path = sqlmap_run_log_file # Log file was created and written to

            # Check log content for vulnerability indicators
            with open(sqlmap_run_log_file, 'r', errors='ignore') as f_check:
                 log_text_for_check = f_check.read().lower()
            if any(kw in log_text_for_check for kw in ["sqlmap identified the following injection point(s)", "parameter '", "appears to be vulnerable", "identified", "is vulnerable", "retrieved", "fetched data"]): # Added more keywords
                 # More refined check needed, this is still broad
                 # Check if it specifically says "is vulnerable" for a parameter
                 param_vuln_match = re.search(r"parameter\s+'([^']+)'\s+is\s+vulnerable", log_text_for_check)
                 url_vuln_match = "appears to be vulnerable" in log_text_for_check
                 injection_point_match = "injection point(s)" in log_text_for_check

                 if param_vuln_match or url_vuln_match or injection_point_match:
                     is_vulnerable = True

            if is_vulnerable:
                print(f"      [+] VULNERABLE: SQLMap indicates potential vulnerability for {sqli_target_url}. Review log: {sqlmap_run_log_file}")
                vulnerable_found_list.append(sqli_target_url)
                state.add_critical_alert(f"SQLMap: VULNERABLE - {sqli_target_url}. REVIEW LOGS.")
                # Add remediation suggestion (might overwrite previous if ID isn't unique enough)
                vuln_id = f"sqli_{sanitize_filename(sqli_target_url)}"
                state.add_remediation_suggestion(vuln_id, {
                    "source": "SQLMap",
                    "description": f"SQLMap reported potential SQL injection vulnerability at URL (or parameters within): {sqli_target_url}. See log: {sqlmap_run_log_file}",
                    "severity": "critical", "tags": ["sqli", "database"],
                    "remediation": "Immediately investigate and fix the injection point(s). Implement parameterized queries/prepared statements server-side. Perform strict input validation and sanitization. Apply principle of least privilege to database user."
                 })

                # --- Attempt Dumping if Enabled and Vulnerable ---
                if config.get("sqlmap_enable_dumping", False):
                    print(f"      [*] Vulnerability found and dumping enabled. Attempting dump for {sqli_target_url}...")
                    # Use the same base options for the dump command for session reuse
                    dump_command = ["sqlmap", "-u", sqli_target_url] + sqlmap_cli_options
                    dump_options_str = config.get("sqlmap_dump_options", "--dump --exclude-sysdbs")
                    dump_command.extend(dump_options_str.split())

                    sqlmap_dump_log_file = os.path.join(sqlmap_log_dir, f"{os.path.basename(base_filename_for_run)}_sqlmap_dump_{sanitized_target_host_part[:50]}.log")
                    dump_log_content_header = f"SQLMap DUMP run for: {sqli_target_url}\nProfile: {profile_name}\nCommand: {' '.join(dump_command)}\n\n"
                    dump_error_msg = None
                    dump_log_path = None

                    try:
                        with open(sqlmap_dump_log_file, 'w', errors='ignore') as dump_log_f:
                            dump_log_f.write(dump_log_content_header)
                            dump_process = subprocess.Popen(dump_command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, universal_newlines=True, errors='ignore')
                            for line in dump_process.stdout:
                                sys.stdout.write(line) # Show dump progress
                                dump_log_f.write(line)
                            dump_process.wait(timeout=sqlmap_timeout) # Use same timeout for dump attempt
                        dump_log_path = sqlmap_dump_log_file
                        print(f"      [+] SQLMap dump attempt finished. Review log: {sqlmap_dump_log_file}")
                    except subprocess.TimeoutExpired:
                        dump_error_msg = f"{sqlmap_dump_log_file} (DUMP TIMED OUT after {sqlmap_timeout}s)"
                        print(f"      [-] SQLMap dump attempt timed out for {sqli_target_url}.")
                        state.add_tool_error(f"SQLMap Dump Timeout: {sqli_target_url}")
                    except Exception as e:
                        dump_error_msg = f"{sqlmap_dump_log_file} (DUMP ERROR: {e})"
                        print(f"      [-] SQLMap dump execution error for {sqli_target_url}: {e}")
                        state.add_tool_error(f"SQLMap Dump Error: {sqli_target_url} - {e}")
                    finally:
                        # Log dump attempt result
                        current_logs = state.get_module_findings("sqlmap_results").get("logs", {})
                        dump_log_key = f"{sqli_target_url}_dump"
                        current_logs[dump_log_key] = dump_error_msg if dump_error_msg else dump_log_path if dump_log_path else "Dump log creation failed"
                        state.update_module_findings("sqlmap_results", {"logs": current_logs})

            else:
                print(f"      [-] SQLMap did not definitively report an injection for {sqli_target_url}. Manual log review recommended.")

        except subprocess.TimeoutExpired:
            error_msg = f"{sqlmap_run_log_file} (CHECK TIMED OUT after {sqlmap_timeout}s)"
            print(f"      [-] SQLMap check timed out for {sqli_target_url}.")
            state.add_tool_error(f"SQLMap Check Timeout: {sqli_target_url}")
        except Exception as e:
            error_msg = f"{sqlmap_run_log_file} (CHECK ERROR: {e})"
            print(f"      [-] SQLMap check execution error for {sqli_target_url}: {e}")
            state.add_tool_error(f"SQLMap Check Error: {sqli_target_url} - {e}")
        finally:
            # Update log path in findings, even if error occurred
             current_logs = state.get_module_findings("sqlmap_results").get("logs", {})
             current_logs[sqli_target_url] = error_msg if error_msg else log_path if log_path else "Check log creation failed"
             state.update_module_findings("sqlmap_results", {"logs": current_logs})


    # Final update after loop
    final_status = state.get_module_findings("sqlmap_results").get("status", "Unknown")
    if final_status == "Running": final_status = "Completed" # Update status if it was still running
    state.update_module_findings("sqlmap_results", {"status": final_status, "vulnerable_targets": vulnerable_found_list})
    state.mark_phase_executed("sqlmap")
    state.save_state()
