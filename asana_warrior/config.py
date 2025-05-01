import os
import json
try:
    from appdirs import user_config_dir
except ImportError:
    def user_config_dir(app_name):
        # Fallback if appdirs is not installed
        return os.getcwd()

APP_NAME = "asana-warrior"

def get_config_path():
    config_dir = user_config_dir(APP_NAME)
    os.makedirs(config_dir, exist_ok=True)
    return os.path.join(config_dir, "config.json")

def load_config():
    path = get_config_path()
    if os.path.exists(path):
        with open(path, "r") as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return {}
    return {}

def save_config(config):
    path = get_config_path()
    with open(path, "w") as f:
        json.dump(config, f, indent=2)
