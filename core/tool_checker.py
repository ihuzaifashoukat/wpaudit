import subprocess
import os
import re
from packaging.version import parse as parse_version, InvalidVersion

# Mapping from phase names to the tools they require.
# This helps determine which tools need checking based on selected phases.
# Mark tools as 'critical' if the phase cannot run without them.
PHASE_TOOL_DEPENDENCIES = {
    "subdomain_scan": [{"tool": "subfinder", "critical": True}],
    "nmap": [{"tool": "nmap", "critical": True}],
    "wpscan": [{"tool": "wpscan", "critical": True}],
    # wp_analyzer uses requests, not external tools directly checked here
    "restapi": [],
    "param_fuzz": [{"tool": "arjun", "critical": True}],
    "directory_bruteforce": [{"tool": "ffuf", "critical": True}],
    "nuclei": [{"tool": "nuclei", "critical": True}],
    "sqlmap": [{"tool": "sqlmap", "critical": False}], # SQLMap might be optional depending on findings
    "exploit_intel": [
        {"tool": "searchsploit", "critical": False}, # Exploit intel is useful but scan can proceed without
        {"tool": "msfconsole", "critical": False}
    ],
    # Preflight might check multiple things, but let's assume it needs basic commands if any
    "preflight": [],
}

# Tool name to the command used for version checking
TOOL_VERSION_COMMANDS = {
    "nmap": ["nmap", "--version"],
    "wpscan": ["wpscan", "--version"],
    "nuclei": ["nuclei", "-version"],
    "sqlmap": ["sqlmap", "--version"],
    "searchsploit": ["searchsploit", "--version"], # Changed from -v
    "msfconsole": ["msfconsole", "-v"],
    "subfinder": ["subfinder", "-version"],
    "ffuf": ["ffuf", "-V"],
    "arjun": ["arjun", "--version"],
    # Add other tools if needed
}

# Regex to extract version string (more specific per tool)
TOOL_VERSION_REGEX = {
    "nmap": r"Nmap version ([\d.]+)",
    "wpscan": r"([\d]+\.[\d]+\.[\d]+(?:\.\d+)?)", # Looks for X.Y.Z or X.Y.Z.A pattern anywhere, robust for WPScan
    "nuclei": r"Nuclei Engine Version:\s*v?([\d.]+)",
    "sqlmap": r"^([\d.]+)(?:#\w+)?", 
    "searchsploit": r"(\d+\.\d+\.\d+)", # Searchsploit -v often just prints version like "4.9.12" or similar in its banner
    "msfconsole": r"Framework Version:\s*([\d.]+)",
    "subfinder": r"Current Version:\s*v([\d.]+)",
    "ffuf": r"ffuf version:\s*v?([\d.]+(?:-dev)?)",
    "arjun": r"Arjun\s*v([\d.]+)" # Arjun vX.Y.Z
}

# Minimum required versions (optional, can be expanded)
MIN_TOOL_VERSIONS = {
    "nmap": "7.80",
    "wpscan": "3.8.0", # , adjust as features are used
    "nuclei": "2.5.0", # 
    "sqlmap": "1.5",   # 
     "subfinder": "2.4.0",
     "ffuf": "1.3.0",
    "arjun": "2.0"
}


def _check_single_tool(tool_key, config, state):
    """Checks a single tool's existence and version, including minimum version if specified."""
    tool_paths = config.get('tool_paths', {})
    command_base = TOOL_VERSION_COMMANDS.get(tool_key)

    if not command_base:
        print(f"    [?] No version command defined for tool '{tool_key}'. Skipping detailed check.")
        # Still record it as checked but with limited info
        result = {"status": "Check Skipped (No Version Cmd)", "path": tool_paths.get(tool_key, tool_key), "version": "N/A"}
        state.update_tool_check(tool_key, result)
        return result

    actual_command_path = tool_paths.get(tool_key, command_base[0])
    version_command = [actual_command_path] + command_base[1:]

    tool_check_result = {"status": "Not Found", "path": actual_command_path, "version": "N/A", "version_ok": None}

    try:
        print(f"    Checking for {tool_key} using: {' '.join(version_command)}")
        process = subprocess.run(version_command, capture_output=True, text=True, timeout=15, check=False, errors='ignore')
        
        output_for_regex = process.stdout + process.stderr # Some tools print version to stderr

        # Special handling for tools that might exit non-zero but are present
        # Arjun (RC=2), Searchsploit (RC=2 if using --version and it prints to stderr or has an issue)
        # SQLMap (RC!=0 but prints usage and version)
        is_present_despite_rc = False
        if tool_key == "arjun" and "Arjun" in output_for_regex: # Arjun prints its name even on RC=2
            is_present_despite_rc = True
        elif tool_key == "searchsploit" and ("Exploit Database" in output_for_regex or "Usage: searchsploit" in output_for_regex): # Searchsploit prints banner
            is_present_despite_rc = True
        elif tool_key == "sqlmap" and "usage: sqlmap" in output_for_regex.lower(): # SQLMap specific
             is_present_despite_rc = True


        if process.returncode == 0 or is_present_despite_rc:
            # Tool executed or considered present, try to parse version
            version_str = "Unknown"
            parsed_successfully = False
            
            version_regex_pattern = TOOL_VERSION_REGEX.get(tool_key)
            if version_regex_pattern:
                match = re.search(version_regex_pattern, output_for_regex, re.IGNORECASE)
                if match:
                    version_str = match.group(1).strip() # Ensure no leading/trailing whitespace
                    tool_check_result["version"] = version_str
                    # Status will be updated after min version check
                    parsed_successfully = True 
                else: # Regex defined but no match
                    print(f"      [?] {tool_key}: Specific version regex did not match. Output snippet: {output_for_regex[:100].strip()}")
            
            if not parsed_successfully: # No specific regex or it failed, try generic
                generic_patterns = [
                    r'version\s+v?([\d][\d.a-zA-Z-]+)', 
                    r'v([\d][\d.a-zA-Z-]+)', # Common for Go tools
                    r'([\d]+\.[\d]+\.[\d]+(?:\.[\d]+)?)' # General X.Y.Z or X.Y.Z.A
                ]
                for gp in generic_patterns:
                    generic_match = re.search(gp, output_for_regex, re.IGNORECASE)
                    if generic_match:
                        version_str = generic_match.group(1).strip()
                        tool_check_result["version"] = version_str
                        parsed_successfully = True
                        break
            
            if parsed_successfully:
                tool_check_result["status"] = "Found" # Base status if version string is found
            else:
                # If is_present_despite_rc was true, it means the tool ran but we couldn't get a version.
                # If process.returncode was 0, it also means it ran but no version string matched.
                tool_check_result["status"] = "Found (Version Unknown)"
                print(f"      [?] {tool_key}: Could not parse version string from output.")

            # Compare with minimum version if found and defined
            min_version_str = MIN_TOOL_VERSIONS.get(tool_key)
            if version_str != "Unknown" and min_version_str:
                try:
                    parsed_current_ver = parse_version(version_str)
                    parsed_min_ver = parse_version(min_version_str)
                    if parsed_current_ver >= parsed_min_ver:
                        tool_check_result["version_ok"] = True
                        tool_check_result["status"] = "Found (Version OK)"
                        print(f"      [+] Found {tool_key} (Version: {version_str} >= {min_version_str}) at {actual_command_path}")
                    else:
                        tool_check_result["version_ok"] = False
                        tool_check_result["status"] = "Found (Version Too Low)"
                        print(f"      [!] Found {tool_key} (Version: {version_str} < Required: {min_version_str}) at {actual_command_path}")
                except InvalidVersion:
                    tool_check_result["version_ok"] = "Parse Error"
                    print(f"      [?] Could not parse version '{version_str}' (tool) or '{min_version_str}' (min_req) for {tool_key} comparison.")
            elif version_str != "Unknown": # Version found, but no min_version defined for it
                 tool_check_result["version_ok"] = "Not Checked" # No minimum to check against
                 tool_check_result["status"] = "Found (Version OK)" # Assume OK if version found and no min specified
                 print(f"      [+] Found {tool_key} (Version: {version_str}) at {actual_command_path} (No minimum version specified).")
            # If version_str is "Unknown", status remains "Found (Version Unknown)" from above.
            
            # If the tool was considered present despite RC!=0, but version parsing failed, keep status as "Found (Version Unknown)"
            # If RC was 0 but parsing failed, it's also "Found (Version Unknown)"
            # If RC!=0 and is_present_despite_rc is False, this block is not reached.

        elif process.returncode != 0 and not is_present_despite_rc: # Genuine failure to execute or not found
             # Check if it's a "command not found" type of error or other execution error
             if "command not found" in output_for_regex.lower() or "no such file" in output_for_regex.lower():
                 tool_check_result["status"] = "Not Found"
                 print(f"      [-] {tool_key} command not found. Output: {output_for_regex[:100].strip()}")
             else: # Other execution error, but tool might be there
                 tool_check_result["status"] = "Error (Execution Failed)"
                 tool_check_result["version"] = f"Error RC={process.returncode}"
                 print(f"      [!] {tool_key} command execution failed (RC={process.returncode}). Output: {output_for_regex[:100].strip()}")
        # If process.returncode != 0 AND is_present_despite_rc is True, it's handled by the block above.
        # The status will be "Found (Version Unknown)" if parsing fails, or "Found (Version OK/Too Low)" if it succeeds.

    except FileNotFoundError:
        print(f"      [-] {tool_key} command '{actual_command_path}' not found in PATH or config.")
        tool_check_result["status"] = "Not Found"
    except subprocess.TimeoutExpired:
        print(f"      [-] {tool_key} version check timed out.")
        tool_check_result["status"] = "Timeout"
    except Exception as e:
        print(f"      [-] Error checking {tool_key}: {type(e).__name__} - {e}")
        tool_check_result["status"] = f"Error ({type(e).__name__})"

    state.add_tool_check_result(tool_key, tool_check_result) # Corrected method name
    return tool_check_result


def check_phase_tools(phases_to_run, config, state):
    """
    Checks if the necessary external tools for the selected phases are available.

    Args:
        phases_to_run (list): A list of phase names that are planned to be executed.
        config (dict): The loaded configuration dictionary.
        state (ScanState): The current scan state object.

    Returns:
        bool: True if all *critical* tools for the selected phases are found, False otherwise.
    """
    print("\n--- Checking Required Tools ---")
    tools_to_check = set()
    critical_tools_missing = False
    checked_tools = state.get_full_state().get("tool_checks", {}) # Get already checked tools if any

    # Determine unique set of tools required by the selected phases
    for phase in phases_to_run:
        dependencies = PHASE_TOOL_DEPENDENCIES.get(phase, [])
        for dep in dependencies:
            tools_to_check.add((dep["tool"], dep.get("critical", False))) # Store tool name and criticality

    if not tools_to_check:
        print("[i] No external tool checks required for the selected phases.")
        return True

    # Check each required tool
    for tool_key, is_critical in tools_to_check:
        if tool_key in checked_tools and checked_tools[tool_key].get("status") != "Not Found": # Re-check if previously "Not Found"
             print(f"    Skipping check for {tool_key} (already checked). Status: {checked_tools[tool_key]['status']}")
             # Check criticality based on more nuanced statuses
             if is_critical and not (checked_tools[tool_key]['status'].startswith("Found") or checked_tools[tool_key]['status'] == "Check Skipped (No Version Cmd)"):
                 critical_tools_missing = True
             continue

        result = _check_single_tool(tool_key, config, state)
        # Critical if not "Found (Version OK)", "Found (Version Unknown)", "Found (Version Cmd Error)", "Found (Version Too Low)" or "Check Skipped"
        # Essentially, critical if "Not Found", "Timeout", or "Error"
        is_missing_or_error = result["status"] in ["Not Found", "Timeout"] or "Error" in result["status"]
        is_version_too_low = result["status"] == "Found (Version Too Low)"

        if is_critical and is_missing_or_error:
            print(f"    [!!!] CRITICAL tool '{tool_key}' is missing or encountered an error during check ({result['status']})!")
            critical_tools_missing = True
        elif is_critical and is_version_too_low:
            print(f"    [!!!] CRITICAL tool '{tool_key}' version is too low ({result['version']})!")
            critical_tools_missing = True


    if critical_tools_missing:
        print("\n[!!!] One or more CRITICAL tools are missing, have errors, or version is too low.")
        return False
    else:
        print("[+] All critical tools seem to be available.")
        return True

# run_command function has been moved to core/tool_runner.py
