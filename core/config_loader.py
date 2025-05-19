import yaml
import os
import copy # Use deepcopy for robust merging

DEFAULT_CONFIG_FILE = os.path.join(os.path.dirname(__file__), '..', 'config', 'default_config.yaml')

def merge_dicts(base, new):
    """Recursively merges dict 'new' into dict 'base'."""
    for key, value in new.items():
        if isinstance(value, dict) and key in base and isinstance(base[key], dict):
            merge_dicts(base[key], value)
        else:
            base[key] = value
    return base

def load_configuration(user_config_path=None):
    """
    Loads the default configuration and merges the user configuration file if provided.

    Args:
        user_config_path (str, optional): Path to the user's YAML/JSON config file. Defaults to None.

    Returns:
        dict: The final merged configuration dictionary.
        Returns default config if user path is invalid or file cannot be parsed.
    """
    # Load default configuration first
    config = {}
    try:
        with open(DEFAULT_CONFIG_FILE, 'r') as f:
            config = yaml.safe_load(f)
        print(f"[+] Loaded default configuration from: {DEFAULT_CONFIG_FILE}")
    except FileNotFoundError:
        print(f"[!!!] CRITICAL ERROR: Default configuration file not found at '{DEFAULT_CONFIG_FILE}'. Cannot proceed.")
        sys.exit(1)
    except Exception as e:
        print(f"[!!!] CRITICAL ERROR: Failed to parse default configuration file '{DEFAULT_CONFIG_FILE}': {e}")
        sys.exit(1)

    # Load user configuration if path is provided and valid
    if user_config_path and os.path.exists(user_config_path):
        try:
            with open(user_config_path, 'r') as f:
                if user_config_path.lower().endswith((".yaml", ".yml")):
                    user_config = yaml.safe_load(f)
                elif user_config_path.lower().endswith(".json"):
                    import json # Import locally if needed
                    user_config = json.load(f)
                else:
                    print(f"[!] Unsupported config file format: {user_config_path}. Using defaults only.")
                    user_config = None

            if user_config:
                # Use deepcopy to avoid modifying the original CONFIG object if loaded elsewhere
                merged_config = merge_dicts(copy.deepcopy(config), user_config)
                print(f"[+] Loaded and merged user configuration from: {user_config_path}")
                return merged_config
            else:
                # File loaded but parsing failed or format unsupported
                return config

        except Exception as e:
            print(f"[!] Error loading or merging user config file '{user_config_path}': {e}. Using defaults.")
            return config # Return default config on user config error
    else:
        if user_config_path: # Path given but not found
            print(f"[!] User config file not found: '{user_config_path}'. Using defaults.")
        else: # No user path given
            print("[i] No user configuration file specified. Using default settings.")
        return config # Return default config

# Example usage (for testing)
if __name__ == "__main__":
    # Assuming a 'user_config.yaml' exists in the parent 'config' directory for testing
    test_user_config = os.path.join(os.path.dirname(__file__), '..', 'config', 'user_config.yaml')
    if not os.path.exists(test_user_config):
         print(f"Creating dummy user config for test: {test_user_config}")
         dummy_conf = {"api_keys": {"wpscan": "DUMMY_KEY_FROM_USER"}, "output_dir": "test_reports"}
         with open(test_user_config, 'w') as f: yaml.dump(dummy_conf, f)

    final_config = load_configuration(test_user_config)
    print("\n--- Final Merged Configuration (Example) ---")
    print(yaml.dump(final_config, default_flow_style=False))

    print("\n--- Loading without user config ---")
    default_only_config = load_configuration()
    # print(yaml.dump(default_only_config, default_flow_style=False)) # Print if needed