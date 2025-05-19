import json
from datetime import datetime
import os
import threading # To make state access potentially thread-safe if needed later

class ScanState:
    """
    Manages the state of the scan, holding findings and metadata.
    Uses a lock for basic thread safety on modifications.
    """
    def __init__(self, target_info: dict, config_used: dict):
        self._lock = threading.Lock()
        self._state = {
            "scan_metadata": {
                "start_time": datetime.now().isoformat(),
                "end_time": None,
                "target_info": target_info,
                "config_used": config_used,
                "report_file_prefix": self._generate_prefix(target_info, config_used)
            },
            "tool_checks": {},
            "phases_executed": [],
            "findings": {}, # Main findings grouped by module/tool
            "summary_points": [],
            "critical_alerts": [],
            "remediation_suggestions": {}, # Key: unique finding ID, Value: dict with details
            "tool_errors": []
        }
        self.output_dir = config_used.get('settings', {}).get('output_dir', 'omegascythe_dominator_reports')
        self._ensure_output_dir()


    def _generate_prefix(self, target_info, config_used):
        """Generates the unique file prefix for this scan run."""
        output_dir = config_used.get('settings', {}).get('output_dir', 'omegascythe_dominator_reports')
        report_prefix = config_used.get('settings', {}).get('report_prefix', 'osd_report')
        hostname = target_info.get("sanitized_hostname", "unknown_target")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return os.path.join(output_dir, f"{report_prefix}_{hostname}_{timestamp}")

    def _ensure_output_dir(self):
        """Creates the output directory if it doesn't exist."""
        if not os.path.exists(self.output_dir):
            try:
                os.makedirs(self.output_dir)
                print(f"[+] Created output directory: {self.output_dir}")
            except OSError as e:
                print(f"[!!!] CRITICAL ERROR: Could not create output directory '{self.output_dir}': {e}")
                # Depending on severity, you might want to exit or just log the error
                # sys.exit(1) # Uncomment to exit if directory creation fails


    def get_report_file_prefix(self):
        """Gets the base file path prefix for reports and logs for this run."""
        with self._lock:
            return self._state["scan_metadata"]["report_file_prefix"]

    def mark_phase_executed(self, phase_name: str):
        """Records that a phase has been executed."""
        with self._lock:
            if phase_name not in self._state["phases_executed"]:
                self._state["phases_executed"].append(phase_name)

    def add_tool_check_result(self, tool_key: str, result: dict):
        """Adds the result of a tool availability check."""
        with self._lock:
            self._state["tool_checks"][tool_key] = result

    def add_finding(self, module_key: str, data: dict):
        """Adds findings for a specific module/tool."""
        with self._lock:
            # Initialize the key if it doesn't exist
            if module_key not in self._state["findings"]:
                self._state["findings"][module_key] = {}
            # Append or update data - depends on how module data is structured
            # Simple update for now, might need merging logic later
            self._state["findings"][module_key].update(data)

    def update_module_findings(self, module_key: str, data: any):
        """ Overwrites or sets the findings data for a module. """
        with self._lock:
             self._state["findings"][module_key] = data

    def get_module_findings(self, module_key: str, default=None):
        """Retrieves findings for a specific module."""
        with self._lock:
            return self._state["findings"].get(module_key, default)

    def add_summary_point(self, message: str):
        """Adds a high-level summary point."""
        with self._lock:
            self._state["summary_points"].append(message)

    def add_critical_alert(self, message: str):
        """Adds a critical alert message."""
        with self._lock:
            self._state["critical_alerts"].append(message)

    def add_remediation_suggestion(self, finding_id: str, details: dict):
        """Adds a remediation suggestion linked to a finding ID."""
        with self._lock:
            # Ensure details has required fields like description, severity, remediation
            if "description" not in details or "severity" not in details:
                print(f"[!] Warning: Remediation suggestion for '{finding_id}' missing required fields.")
            self._state["remediation_suggestions"][finding_id] = details

    def add_tool_error(self, message: str):
        """Logs an error encountered while running a tool."""
        with self._lock:
            self._state["tool_errors"].append(message)

    def finalize_scan(self):
        """Marks the scan end time."""
        with self._lock:
            self._state["scan_metadata"]["end_time"] = datetime.now().isoformat()

    def get_full_state(self):
        """Returns a copy of the entire state dictionary."""
        with self._lock:
            # Return a deep copy to prevent external modification
            return copy.deepcopy(self._state)

    def save_state(self):
        """Saves the current state to the primary JSON report file."""
        filepath = f"{self.get_report_file_prefix()}_FULL_REPORT.json"
        current_state = self.get_full_state() # Get a thread-safe copy
        try:
            with open(filepath, 'w') as f:
                json.dump(current_state, f, indent=4, default=lambda o: '<not serializable>')
            # Optional: print confirmation only periodically or at the end
            # print(f"[+] Scan state saved: {filepath}")
        except Exception as e:
            print(f"[!] Error saving scan state to '{filepath}': {e}")

# Example usage
if __name__ == "__main__":
    # Mock config and target info
    mock_config_used = {"settings": {"output_dir": "test_state_reports", "report_prefix": "test_scan"}}
    mock_target_info = {"url": "http://example.com", "hostname": "example.com", "ip": "93.184.216.34", "sanitized_hostname": "example_com"}

    state = ScanState(mock_target_info, mock_config_used)
    state.mark_phase_executed("preflight")
    state.add_tool_check_result("nmap", {"status": "Found", "path": "/usr/bin/nmap"})
    state.add_finding("preflight", {"robots_txt_info": {"status": "Found", "disallowed_paths": ["/admin"]}})
    state.add_critical_alert("Found admin directory in robots.txt")
    state.add_remediation_suggestion("robots_admin", {"description": "Admin directory exposed in robots.txt", "severity": "low", "remediation": "Consider removing sensitive paths from robots.txt"})
    state.finalize_scan()
    state.save_state()

    print("\n--- Example Scan State ---")
    print(json.dumps(state.get_full_state(), indent=4, default=str))