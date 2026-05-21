import json
import os
import sys
from datetime import datetime
from typing import Dict, Any, List, Union

try:
    # Python 3.9+
    from importlib.resources import files
except ImportError:
    # Python 3.8
    from importlib_resources import files  # pyright: ignore[reportMissingImports]


def get_resource_path(relative_path: str) -> str:
    """
    Get the absolute path to a resource, works for development and for PyInstaller.
    When running as a bundle, PyInstaller stores data files in a temporary
    folder and puts the path in `sys._MEIPASS`.
    
    For package data, this function will correctly locate files in the app/data directory.
    """
    try:
        # Use getattr to avoid linter warnings about _MEIPASS
        base_path = getattr(sys, "_MEIPASS", None)
        if base_path:
            # Running as PyInstaller bundle
            return os.path.join(base_path, relative_path)
        
        # Try to locate as package data first
        try:
            # For files in app/data directory
            if relative_path.startswith("data/"):
                data_file = files('app').joinpath(relative_path)
                if data_file.is_file():
                    return str(data_file)
        except Exception:
            pass
            
        # Fallback to current directory for development
        base_path = os.path.abspath(".")
        return os.path.join(base_path, relative_path)
    except Exception:
        base_path = os.path.abspath(".")
        return os.path.join(base_path, relative_path)


def timestamp() -> str:
    """Generate a timestamp string."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _generate_filename(domain: str, extension: str) -> str:
    """Helper to create a consistent filename."""
    safe_domain = domain.replace(".", "_")
    time_str = datetime.now().strftime("%Y%m%d%H%M%S")
    return f"output/report_{safe_domain}_{time_str}.{extension}"


# Reporting functions moved to app/modules/reporting.py
