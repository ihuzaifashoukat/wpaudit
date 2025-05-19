import subprocess
import os
import re

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

def _check_single_tool(tool_key, config, state):
    """Checks a single tool's existence and version."""
    tool_paths = config.get('tool_paths', {})
    command_base = TOOL_VERSION_COMMANDS.get(tool_key)

    if not command_base:
        print(f"    [?] No version command defined for tool '{tool_key}'. Skipping check.")
        return {"status": "Check Skipped", "path": "N/A", "version": "N/A"}

    actual_command_path = tool_paths.get(tool_key, command_base[0]) # Use configured path or default
    version_command = [actual_command_path] + command_base[1:]

    tool_check_result = {"status": "Not Found", "path": actual_command_path, "version": "N/A"}

    try:
        print(f"    Checking for {tool_key} using: {' '.join(version_command)}")
        # Use a short timeout for version checks
        process = subprocess.run(version_command, capture_output=True, text=True, timeout=15, check=False, errors='ignore')

        if process.returncode == 0 and process.stdout:
            tool_check_result["status"] = "Found"
            # Try to extract version (patterns vary greatly)
            version = "Unknown"
            output = process.stdout + process.stderr # Some tools print version to stderr
            # Common version patterns (add more as needed)
            match = re.search(r'version\s+([\d.]+)', output, re.IGNORECASE) or \
                    re.search(r'v([\d.]+)', output, re.IGNORECASE) or \
                    re.search(r'([\d.]+)', output) # Last resort: find any number.dot.number

            if match:
                version = match.group(1)
            tool_check_result["version"] = version
            print(f"      [+] Found {tool_key} (Version: {version}) at {actual_command_path}")
        elif process.returncode != 0 and "command not found" not in process.stderr.lower() and "no such file" not in process.stderr.lower():
             # Command exists but version check failed (e.g., wrong flag)
             tool_check_result["status"] = "Found (Version Check Failed)"
             tool_check_result["version"] = f"Error RC={process.returncode}"
             print(f"      [!] Found {tool_key} at {actual_command_path}, but version check failed (RC={process.returncode}). Assuming usable.")
        else:
            # Command likely not found
             print(f"      [-] {tool_key} not found or version check command failed.")
             tool_check_result["status"] = "Not Found"


    except FileNotFoundError:
        print(f"      [-] {tool_key} command '{actual_command_path}' not found in PATH or config.")
        tool_check_result["status"] = "Not Found"
    except subprocess.TimeoutExpired:
        print(f"      [-] {tool_key} version check timed out.")
        tool_check_result["status"] = "Timeout"
    except Exception as e:
        print(f"      [-] Error checking {tool_key}: {e}")
        tool_check_result["status"] = f"Error: {e}"

    state.update_tool_check(tool_key, tool_check_result)
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
        if tool_key in checked_tools:
             print(f"    Skipping check for {tool_key} (already checked). Status: {checked_tools[tool_key]['status']}")
             if is_critical and checked_tools[tool_key]['status'] != "Found":
                 critical_tools_missing = True
             continue # Don't re-check

        result = _check_single_tool(tool_key, config, state)
        if is_critical and result["status"] != "Found" and result["status"] != "Found (Version Check Failed)":
            print(f"    [!!!] CRITICAL tool '{tool_key}' is missing or failed check!")
            critical_tools_missing = True

    if critical_tools_missing:
        print("[!] One or more critical tools are missing.")
        return False
    else:
        print("[+] All critical tools seem to be available.")
        return True

# run_command function has been moved to core/tool_runner.py
