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


def save_json_output(data: Dict[str, Any]) -> str:
    """Saves the report data to a JSON file."""
    domain = data.get("domain", "unknown")
    filename = _generate_filename(domain, "json")

    # Ensure output directory exists
    os.makedirs("output", exist_ok=True)

    try:
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
    except Exception as e:
        raise IOError(f"Failed to save JSON report to {filename}: {e}")

    return filename


def _format_section_content(
    title: str, value: Union[Dict, List, str, None], report_lines: List[str]
) -> None:
    """Format section content for text report."""
    if not value:
        report_lines.append("No data found or module skipped.")
        return

    if isinstance(value, dict) and "error" in value:
        report_lines.append(f"Error: {value['error']}")
        return
    if isinstance(value, dict) and "note" in value:
        report_lines.append(f"Note: {value['note']}")
        return

    # Custom formatters for specific modules
    if title == "open_ports":
        # Ensure value is a dict before accessing
        if isinstance(value, dict):
            ports_data = value.get("open_ports", {})
            if not ports_data:
                report_lines.append("No open ports found.")
            for port, banner in sorted(ports_data.items()):
                report_lines.append(f"  - Port {port:<5} | {banner or 'N/A'}")
        else:
            report_lines.append("Invalid data format for open ports.")
    elif title == "tech_stack":
        # Ensure value is a dict before accessing
        if isinstance(value, dict):
            # Handle the main tech_stack fields
            for k, v in value.items():
                if k != "security_headers":
                    report_lines.append(f"  - {k.replace('_', ' ').title()}: {v}")

            # Handle the security_headers sub-dictionary
            sec_headers = value.get("security_headers", {})
            if sec_headers:
                report_lines.append("  - Security Headers:")
                if "note" in sec_headers:
                    report_lines.append(f"    - {sec_headers['note']}")
                else:
                    for k, v in sorted(sec_headers.items()):
                        report_lines.append(f"    - {k}: {v}")
        else:
            report_lines.append("Invalid data format for tech stack.")
    elif title in ["subdomains", "paths_found"]:
        # Ensure value is a dict before accessing
        if isinstance(value, dict):
            found_items = value.get("found", [])
            if not found_items:
                report_lines.append("None found.")
            for item in found_items:
                if isinstance(item, dict) and "subdomain" in item:
                    # Fix for subdomain formatting:
                    ips_str = ", ".join(item.get("ips", ["N/A"]))
                    report_lines.append(f"  - {item['subdomain']:<40} | IPs: {ips_str}")
                elif isinstance(item, dict) and "path" in item:
                    report_lines.append(
                        f"  - {item['path']:<30} | Status: {item.get('status_code', 'N/A')} | Type: {item.get('content_type', 'N/A')}"
                    )
        else:
            report_lines.append("Invalid data format for subdomains/paths.")
    elif title == "social_links":
        if not value:
            report_lines.append("No social links found.")
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    report_lines.append(
                        f"  - {item.get('platform', 'Unknown'):<15} | {item.get('url', 'N/A')}"
                    )
                else:
                    report_lines.append(f"  - {item}")
        else:
            report_lines.append("Invalid data format for social links.")
    elif title == "vulnerabilities":
        # Ensure value is a dict before accessing
        if isinstance(value, dict):
            if not value:
                report_lines.append("No vulnerabilities found.")
            for tech, vulns in sorted(value.items()):
                report_lines.append(f"  - {tech}:")
                if isinstance(vulns, list):
                    for vuln in vulns:
                        if isinstance(vuln, dict):
                            source = vuln.get("source", "N/A")
                            report_lines.append(
                                f"    - [{vuln.get('id')}] {vuln.get('title')} (CVSS: {vuln.get('cvss_score', 'N/A')}) [Source: {source}]"
                            )
                        else:
                            report_lines.append(f"    - {vuln}")
                elif isinstance(vulns, dict) and "error" in vulns:
                    report_lines.append(f"    - Error: {vulns['error']}")
        else:
            report_lines.append("Invalid data format for vulnerabilities.")
    elif isinstance(value, dict):
        for k, v in value.items():
            if isinstance(v, list):
                report_lines.append(f"  - {k.replace('_', ' ').title()}:")
                for i in v:
                    report_lines.append(f"    - {i}")
            else:
                report_lines.append(f"  - {k.replace('_', ' ').title()}: {v}")
    elif isinstance(value, list):
        for item in value:
            report_lines.append(f"  - {item}")
    else:
        report_lines.append(str(value))


def save_text_report(data: Dict[str, Any]) -> str:
    """Saves the report data to a human-readable TXT file."""
    domain = data.get("domain", "unknown")
    filename = _generate_filename(domain, "txt")

    report_lines: List[str] = []

    # --- Build the report ---
    report_lines.append(f"OSINT Report for: {data.get('domain')}")
    report_lines.append(f"Generated on: {timestamp()}")

    # Add basic info first
    basic_info = {"Domain": data.get("domain"), "IP Address": data.get("ip_address")}
    report_lines.append(f"\n{'=' * 10} BASIC INFO {'=' * 10}\n")
    for key, value in basic_info.items():
        report_lines.append(f"  - {key}: {value}")

    # Order of sections
    section_order = [
        "whois",
        "dns",
        "geoip",
        "ssl_certificate",
        "tech_stack",
        "builtwith",
        "open_ports",
        "subdomains",
        "paths_found",
        "wayback_urls",
        "social_links",
        "reverse_ip",
        "breach_check",
        "vulnerabilities",
    ]

    for key in section_order:
        if key in data:
            report_lines.append(
                f"\n{'=' * 10} {key.replace('_', ' ').upper()} {'=' * 10}\n"
            )
            _format_section_content(key, data[key], report_lines)

    # Ensure output directory exists
    os.makedirs("output", exist_ok=True)

    try:
        with open(filename, "w", encoding="utf-8") as f:
            f.write("\n".join(report_lines))
    except Exception as e:
        raise IOError(f"Failed to save text report to {filename}: {e}")

    return filename


import csv
from io import StringIO

def save_csv_output(data: Dict[str, Any]) -> str:
    """Saves the report data to a set of CSV files (zipped) or a flattened CSV."""
    domain = data.get("domain", "unknown")
    filename = _generate_filename(domain, "csv")
    
    # Flattening complex JSON to CSV is tricky. 
    # For a CLI tool, a usable CSV usually focuses on specific lists like subdomains or vulnerabilities.
    # Here we will create a flattened key-value structure for high-level info
    # and maybe separate sections for lists if we were doing multi-file.
    # For simplicity in a single file, we'll use a specific format or just dump flattened keys.
    
    # Let's flatten the dictionary
    flat_data = []
    
    def flatten(x, name=''):
        if type(x) is dict:
            for a in x:
                flatten(x[a], name + a + '_')
        elif type(x) is list:
            for i, a in enumerate(x):
                flatten(a, name + str(i) + '_')
        else:
            flat_data.append((name[:-1], x))

    flatten(data)
    
    os.makedirs("output", exist_ok=True)
    try:
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["Key", "Value"])
            for row in flat_data:
                writer.writerow(row)
    except Exception as e:
         raise IOError(f"Failed to save CSV report to {filename}: {e}")
         
    return filename

import html

def save_html_output(data: Dict[str, Any]) -> str:
    """Saves the report data to a beautiful HTML file."""
    domain = data.get("domain", "unknown")
    filename = _generate_filename(domain, "html")
    
    os.makedirs("output", exist_ok=True)
    
    # Basic HTML structure with some styling
    # In a real app, you might use Jinja2, but here we'll construct a simple string
    # to avoid adding heavyweight dependencies if not needed.
    
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>ReconX Report - {html.escape(domain)}</title>
        <style>
            :root {{
                --primary: #4f46e5;
                --secondary: #ec4899;
                --bg: #f3f4f6;
                --card-bg: #ffffff;
                --text: #1f2937;
            }}
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: var(--bg); color: var(--text); margin: 0; padding: 20px; }}
            .container {{ max-width: 1200px; margin: 0 auto; }}
            header {{ text-align: center; margin-bottom: 40px; }}
            h1 {{ color: var(--primary); margin-bottom: 10px; }}
            .timestamp {{ color: #6b7280; font-size: 0.9em; }}
            .card {{ background: var(--card-bg); border-radius: 10px; padding: 25px; margin-bottom: 20px; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1); }}
            h2 {{ border-bottom: 2px solid #e5e7eb; padding-bottom: 10px; color: var(--text); margin-top: 0; }}
            
            .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }}
            .key-value {{ display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid #f3f4f6; }}
            .key {{ font-weight: 600; color: #4b5563; }}
            
            .tag {{ display: inline-block; padding: 2px 8px; border-radius: 9999px; font-size: 0.8em; font-weight: 600; background: #e0e7ff; color: #3730a3; margin-right: 5px; }}
            
            pre {{ background: #1f2937; color: #f9fafb; padding: 15px; border-radius: 8px; overflow-x: auto; }}
            
            /* Custom Scrollbar */
            ::-webkit-scrollbar {{ width: 8px; }}
            ::-webkit-scrollbar-track {{ background: #f1f1f1; }}
            ::-webkit-scrollbar-thumb {{ background: #888; border-radius: 4px; }}
            ::-webkit-scrollbar-thumb:hover {{ background: #555; }}
        </style>
    </head>
    <body>
        <div class="container">
            <header>
                <h1>🕵️ Modular ReconX Report</h1>
                <div class="timestamp">Target: <strong>{html.escape(domain)}</strong> | {timestamp()}</div>
            </header>
            
            <div class="card">
                <h2>📊 Executive Summary</h2>
                <div class="grid">
                    <div class="key-value"><span class="key">Target</span> <span>{html.escape(domain)}</span></div>
                    <div class="key-value"><span class="key">IP Address</span> <span>{html.escape(str(data.get('ip_address', 'N/A')))}</span></div>
                    <div class="key-value"><span class="key">Scan Time</span> <span>{timestamp()}</span></div>
                </div>
            </div>
    """
    
    # Loop through data and create cards for important sections
    # Excluding raw data keys if necessary
    exclude_keys = ["domain", "ip_address", "error"]
    
    for key, value in data.items():
        if key in exclude_keys:
            continue
            
        html_content += f'<div class="card"><h2>{html.escape(key.replace("_", " ").title())}</h2>'
        
        if isinstance(value, dict):
            # Special handling for certain nested dicts like open_ports
            if key == "open_ports" and "open_ports" in value:
                 # Flatten the inner ports dict
                 for p, banner in value["open_ports"].items():
                     banner_text = str(banner) if banner else "N/A"
                     html_content += f'<div class="key-value"><span class="key">Port {html.escape(str(p))}</span> <span>{html.escape(banner_text)}</span></div>'
            else:
                for k, v in value.items():
                    if isinstance(v, list):
                        html_content += f'<div class="key-value"><span class="key">{html.escape(str(k))}</span> <span>{len(v)} items</span></div>'
                        # html_content += f'<pre>{html.escape(json.dumps(v, indent=2))}</pre>' # Optional: detailed list view
                    else:
                        val_str = str(v)[:100] # Truncate long strings
                        html_content += f'<div class="key-value"><span class="key">{html.escape(str(k))}</span> <span>{html.escape(val_str)}</span></div>'
        elif isinstance(value, list):
            html_content += f'<p>Found {len(value)} items:</p><ul>'
            for item in value[:10]: # Show first 10 items to prevent HTML bloating
                if isinstance(item, dict):
                    display_str = str(item.get("subdomain") or item.get("url") or str(item))
                else:
                    display_str = str(item)
                html_content += f'<li>{html.escape(display_str)}</li>'
            if len(value) > 10:
                html_content += f'<li>...and {len(value)-10} more</li>'
            html_content += '</ul>'
        else:
             html_content += f'<p>{html.escape(str(value))}</p>'
             
        html_content += '</div>'

    html_content += """
        </div>
    </body>
    </html>
    """
    
    try:
        with open(filename, "w", encoding="utf-8") as f:
            f.write(html_content)
    except Exception as e:
        raise IOError(f"Failed to save HTML report to {filename}: {e}")
        
    return filename

def save_report(data: Dict[str, Any], output_format: str = "json") -> str:
    """
    Dispatches to the correct save function based on the desired format.

    Args:
        data: The report data to save
        output_format: The output format ("json", "txt", "csv", "html")

    Returns:
        The path to the saved file

    Raises:
        ValueError: If an unsupported output format is specified
        IOError: If there's an error saving the file
    """
    if output_format == "txt":
        return save_text_report(data)
    elif output_format == "json":
        return save_json_output(data)
    elif output_format == "csv":
        return save_csv_output(data)
    elif output_format == "html":
        return save_html_output(data)
    else:
        raise ValueError(f"Unsupported output format: {output_format}")
