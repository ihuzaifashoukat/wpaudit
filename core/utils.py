import os
import re
from datetime import datetime

def print_dominator_banner():
    # (Same banner as before)
    print(r"""
  ___  __  __ _____    ___ ____   ___  ____  _____ __  __ ___ ____  _   _ _____ _   _  ____
 / _ \|  \/  | ____|  / _ \___ \ / _ \/ ___||  ___|  \/  |_ _/ ___|| | | | ____| \ | |/ ___|
| | | | |\/| |  _|   | | | | __) | | | \___ \| |_  | |\/| || |\___ \| |_| |  _| |  \| | |  _
| |_| | |  | | |___  | |_| |/ __/| |_| |___) |  _| | |  | || | ___) |  _  | |___| |\  | |_| |
 \___/|_|  |_|_____|  \___/_____(_)___/|____/|_|   |_|  |_|___|____/|_| |_|_____|_| \_|\____|
                      WPAUDIT - Hyper-Configurable WordPress Security Auditing Suite
    """)
    print("=" * 110)
    print("!! EXTREME WARNING: FOR ETHICAL, EDUCATIONAL, AND AUTHORIZED USE ONLY !!")
    print("!! UNAUTHORIZED SYSTEM ACCESS/SCANNING IS ILLEGAL AND UNETHICAL. !!")
    print("!! THIS TOOL CAN PERFORM HIGHLY INTRUSIVE AND POTENTIALLY DISRUPTIVE ACTIONS. !!")
    print("!! ENSURE YOU HAVE EXPLICIT, WRITTEN CONSENT AND FULLY UNDERSTAND THE IMPLICATIONS. !!")
    print("!! YOU ARE SOLELY RESPONSIBLE FOR YOUR ACTIONS. !!")
    print("=" * 110)

def create_output_directory(config: dict):
    """Creates the output directory specified in the config."""
    output_dir = config.get('output_dir', 'wpaudit_reports')
    if not os.path.exists(output_dir):
        try:
            os.makedirs(output_dir)
            print(f"[+] Created output directory: {output_dir}")
        except OSError as e:
            print(f"[!!!] CRITICAL ERROR: Could not create output directory '{output_dir}': {e}")
            return None # Indicate failure
    return output_dir

def sanitize_filename(filename_part: str, max_length=100):
    """Removes potentially problematic characters for filenames."""
    # Remove protocol, replace common separators with underscore
    sanitized = re.sub(r'^https?://', '', filename_part)
    sanitized = re.sub(r'[/:?=&% ]', '_', sanitized)
    # Remove any characters not generally safe for filenames
    sanitized = re.sub(r'[^\w.-]', '', sanitized)
    # Limit length
    return sanitized[:max_length]

def get_scan_filename_prefix(state, config: dict):
    """Generates the base filename prefix for reports and logs for the current scan."""
    output_dir = config.get('output_dir', 'wpaudit_reports')
    report_prefix = config.get('report_prefix', 'wpaudit_report')
    # Get hostname from state if available, otherwise use a placeholder
    target_info = state.get_full_state().get("scan_metadata", {}).get("target_info", {})
    hostname_part = target_info.get("sanitized_hostname")
    if not hostname_part: # Fallback if state not fully initialized yet
        parsed_url = urlparse(target_info.get("url","unknown"))
        hostname_part = sanitize_filename(parsed_url.netloc if parsed_url.netloc else "unknown_target")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S") # Generate fresh timestamp if needed? Or use scan start?
    # Using scan start time if available for consistency across files for the *same* run
    start_time_str = state.get_full_state().get("scan_metadata", {}).get("start_time")
    if start_time_str:
        try:
            start_dt = datetime.fromisoformat(start_time_str)
            timestamp = start_dt.strftime("%Y%m%d_%H%M%S")
        except ValueError: pass # Keep current timestamp if parsing fails

    return os.path.join(output_dir, f"{report_prefix}_{hostname_part}_{timestamp}")


def user_confirm(prompt_message, config):
    """Handles user confirmation based on interactive setting in config."""
    if not config.get("interactive_prompts", True):
        print(f"[!] Non-interactive mode: Assuming 'NO' for prompt: '{prompt_message}'")
        return False # Safer default for non-interactive critical actions

    while True:
        choice = input(f"[?] {prompt_message} (yes/NO): ").strip().lower()
        if choice == "yes":
            return True
        elif choice == "no" or choice == "":
            return False
        print("Please answer 'yes' or 'no'.")
