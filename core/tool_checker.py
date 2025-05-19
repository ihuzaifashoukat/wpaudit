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
    "sqlmap": ["sqlmap", "--version"], # Or sqlmap-dev if that's the command
    "searchsploit": ["searchsploit", "-v"], # Or --version
    "msfconsole": ["msfconsole", "-v"], # Or --version
    "subfinder": ["subfinder", "-version"],
    "ffuf": ["ffuf", "-V"],
    "arjun": ["arjun", "--version"],
    # Add other tools if needed
}

# Regex to extract version string (more specific per tool)
TOOL_VERSION_REGEX = {
    "nmap": r"Nmap version ([\d.]+)",
    "wpscan": r"WordPress Security Scanner version ([\d.]+)", # Or just find version number
    "nuclei": r"Nuclei Engine Version:\s*v([\d.]+)",
    "sqlmap": r"sqlmap version ([\d.]+)",
    "searchsploit": r"searchsploit (\d+\.\d+\.\d+)", # Example: searchsploit 4.9.12
    "msfconsole": r"Framework Version:\s*([\d.]+)", # Example: Framework Version: 6.0.0-dev-
    "subfinder": r"Subfinder version: v([\d.]+)",
    "ffuf": r"ffuf version:\s*v([\d.]+)",
    "arjun": r"Arjun v([\d.]+)"
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

        if process.returncode == 0 or (tool_key == "sqlmap" and process.returncode !=0 and "usage: sqlmap" in output_for_regex.lower()): # SQLMap --version exits non-zero but prints version
            # Tool executed, try to parse version
            tool_check_result["status"] = "Found (Version Unknown)" # Default if regex fails
            version_str = "Unknown"
            
            version_regex_pattern = TOOL_VERSION_REGEX.get(tool_key)
            if version_regex_pattern:
                match = re.search(version_regex_pattern, output_for_regex, re.IGNORECASE)
                if match:
                    version_str = match.group(1)
                    tool_check_result["version"] = version_str
                    tool_check_result["status"] = "Found" # Version successfully parsed
                else: # Regex defined but no match
                    print(f"      [?] {tool_key}: Version regex did not match output. Output snippet: {output_for_regex[:100].strip()}")
            else: # No specific regex, try generic
                generic_match = re.search(r'version\s+v?([\d][\d.a-zA-Z-]+)', output_for_regex, re.IGNORECASE) or \
                                re.search(r'v([\d][\d.a-zA-Z-]+)', output_for_regex, re.IGNORECASE) or \
                                re.search(r'([\d][\d.a-zA-Z-]+)', output_for_regex) # Fallback
                if generic_match:
                    version_str = generic_match.group(1)
                    tool_check_result["version"] = version_str
                    tool_check_result["status"] = "Found"

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
                    print(f"      [?] Could not parse version '{version_str}' or '{min_version_str}' for {tool_key} comparison.")
            elif version_str != "Unknown": # Version found, but no min_version defined
                 tool_check_result["version_ok"] = "Not Checked"
                 print(f"      [+] Found {tool_key} (Version: {version_str}) at {actual_command_path}")
            else: # Version still unknown
                 print(f"      [?] Found {tool_key} at {actual_command_path}, but version could not be determined from output.")
                 tool_check_result["status"] = "Found (Version Unknown)"


        elif process.returncode != 0 and ("command not found" not in output_for_regex.lower() and "no such file" not in output_for_regex.lower()):
             tool_check_result["status"] = "Found (Version Cmd Error)" # Tool likely exists, but version cmd failed
             tool_check_result["version"] = f"Error RC={process.returncode}"
             print(f"      [!] Found {tool_key} at {actual_command_path}, but version command failed (RC={process.returncode}). Assuming usable if critical.")
        else: # Command likely not found or other execution error
             print(f"      [-] {tool_key} not found or version command execution failed. RC={process.returncode}. Output: {output_for_regex[:100].strip()}")
             tool_check_result["status"] = "Not Found"

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
