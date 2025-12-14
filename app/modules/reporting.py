import json
import os
import csv
import html
from typing import Dict, Any, List, Union
from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER, TA_LEFT

# Import helper functions from utils
try:
    from .utils import timestamp
except ImportError:
    # Fallback if run directly or circular import issues
    def timestamp() -> str:
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def _generate_filename(domain: str, extension: str) -> str:
    """Helper to create a consistent filename."""
    safe_domain = domain.replace(".", "_")
    time_str = datetime.now().strftime("%Y%m%d%H%M%S")
    return f"output/report_{safe_domain}_{time_str}.{extension}"

# --- PDF Generation ---
def save_pdf_output(data: Dict[str, Any]) -> str:
    """Saves the report data to a formal PDF file."""
    domain = data.get("domain", "unknown")
    filename = _generate_filename(domain, "pdf")
    os.makedirs("output", exist_ok=True)

    doc = SimpleDocTemplate(
        filename,
        pagesize=A4,
        rightMargin=72,
        leftMargin=72,
        topMargin=72,
        bottomMargin=72,
        title=f"ReconX Report - {domain}"
    )

    styles = getSampleStyleSheet()
    # Custom Styles
    styles.add(ParagraphStyle(name='TitleCustom', parent=styles['Title'], fontSize=24, spaceAfter=30, textColor=colors.HexColor('#4f46e5')))
    styles.add(ParagraphStyle(name='Heading2Custom', parent=styles['Heading2'], fontSize=16, spaceBefore=20, spaceAfter=10, textColor=colors.HexColor('#1f2937')))
    styles.add(ParagraphStyle(name='NormalCustom', parent=styles['Normal'], fontSize=10, leading=14))
    styles.add(ParagraphStyle(name='CodeCustom', parent=styles['Code'], fontSize=9, backColor=colors.whitesmoke, borderColor=colors.lightgrey, borderWidth=1, persistent=1))

    story = []

    # Title Page
    story.append(Paragraph("Modular ReconX Report", styles['TitleCustom']))
    story.append(Spacer(1, 12))
    story.append(Paragraph(f"Target: <b>{html.escape(domain)}</b>", styles['NormalCustom']))
    story.append(Paragraph(f"Generated on: {timestamp()}", styles['NormalCustom']))
    story.append(Spacer(1, 30))

    # Executive Summary Table
    story.append(Paragraph("Executive Summary", styles['Heading2Custom']))
    summary_data = [
        ["Target Domain", domain],
        ["IP Address", data.get('ip_address', 'N/A')],
        ["Scan Time", timestamp()],
        ["Total Modules", str(len(data) - 3)] # Approximate
    ]
    t = Table(summary_data, colWidths=[2.5*inch, 3.5*inch])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f3f4f6')),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
        ('TOPPADDING', (0, 0), (-1, -1), 12),
        ('GRID', (0, 0), (-1, -1), 1, colors.white)
    ]))
    story.append(t)
    story.append(Spacer(1, 20))

    # Report Content
    exclude_keys = ["domain", "ip_address", "error"]
    
    for key, value in data.items():
        if key in exclude_keys:
            continue
        
        # Section Title
        story.append(Paragraph(key.replace("_", " ").title(), styles['Heading2Custom']))
        
        # Section Content
        if isinstance(value, dict):
            # Special handling for ports
            if key == "open_ports" and "open_ports" in value:
                table_data = [["Port", "Service/Banner"]]
                for p, banner in value["open_ports"].items():
                    banner_clean = str(banner)[:50] + "..." if banner and len(str(banner)) > 50 else str(banner)
                    table_data.append([str(p), banner_clean or "N/A"])
                
                if len(table_data) > 1:
                    pt = Table(table_data, colWidths=[1*inch, 5*inch])
                    pt.setStyle(TableStyle([
                         ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e0e7ff')),
                         ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor('#3730a3')),
                         ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                    ]))
                    story.append(pt)
                else:
                    story.append(Paragraph("No open ports found.", styles['NormalCustom']))

            else:
                # Generic dictionary
                list_text = []
                for k, v in value.items():
                    val_str = str(v)
                    # Truncate very long values
                    if len(val_str) > 200: val_str = val_str[:200] + "..."
                    list_text.append(f"<b>{k}:</b> {html.escape(val_str)}")
                
                for line in list_text:
                    story.append(Paragraph(line, styles['NormalCustom']))
                    story.append(Spacer(1, 3))
        
        elif isinstance(value, list):
            items_to_show = value[:20] # Limit to 20 items in PDF to save pages
            
            bullet_points = []
            for item in items_to_show:
                if isinstance(item, dict):
                    display_str = str(item.get("subdomain") or item.get("url") or str(item))
                else:
                    display_str = str(item)
                bullet_points.append(Paragraph(f"• {html.escape(display_str)}", styles['NormalCustom']))
            
            for bp in bullet_points:
                story.append(bp)
            
            if len(value) > 20:
                story.append(Paragraph(f"<i>...and {len(value)-20} more items (see full JSON/HTML report)</i>", styles['NormalCustom']))
        
        else:
            story.append(Paragraph(str(value), styles['NormalCustom']))
            
        story.append(Spacer(1, 12))

    try:
        doc.build(story)
    except Exception as e:
        raise IOError(f"Failed to save PDF report to {filename}: {e}")

    return filename

# --- Existing Save Functions (Moved from utils.py) ---

def save_json_output(data: Dict[str, Any]) -> str:
    """Saves the report data to a JSON file."""
    domain = data.get("domain", "unknown")
    filename = _generate_filename(domain, "json")
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

    # Custom formatters copied verbatim from original utils.py logic
    if title == "open_ports":
        if isinstance(value, dict):
            ports_data = value.get("open_ports", {})
            if not ports_data:
                report_lines.append("No open ports found.")
            for port, banner in sorted(ports_data.items()):
                report_lines.append(f"  - Port {port:<5} | {banner or 'N/A'}")
        else:
            report_lines.append("Invalid data format for open ports.")
    elif title == "tech_stack":
        if isinstance(value, dict):
            for k, v in value.items():
                if k != "security_headers":
                    report_lines.append(f"  - {k.replace('_', ' ').title()}: {v}")
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
        if isinstance(value, dict):
            found_items = value.get("found", [])
            if not found_items:
                report_lines.append("None found.")
            for item in found_items:
                if isinstance(item, dict) and "subdomain" in item:
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
    
    report_lines.append(f"OSINT Report for: {data.get('domain')}")
    report_lines.append(f"Generated on: {timestamp()}")
    
    basic_info = {"Domain": data.get("domain"), "IP Address": data.get("ip_address")}
    report_lines.append(f"\n{'=' * 10} BASIC INFO {'=' * 10}\n")
    for key, value in basic_info.items():
        report_lines.append(f"  - {key}: {value}")
        
    section_order = [
        "whois", "dns", "geoip", "ssl_certificate", "tech_stack",
        "builtwith", "open_ports", "subdomains", "paths_found",
        "wayback_urls", "social_links", "reverse_ip", "breach_check",
        "vulnerabilities"
    ]
    
    for key in section_order:
        if key in data:
            report_lines.append(f"\n{'=' * 10} {key.replace('_', ' ').upper()} {'=' * 10}\n")
            _format_section_content(key, data[key], report_lines)
            
    os.makedirs("output", exist_ok=True)
    try:
        with open(filename, "w", encoding="utf-8") as f:
            f.write("\n".join(report_lines))
    except Exception as e:
        raise IOError(f"Failed to save text report to {filename}: {e}")
    return filename

def save_csv_output(data: Dict[str, Any]) -> str:
    """Saves the report data to a flattened CSV."""
    domain = data.get("domain", "unknown")
    filename = _generate_filename(domain, "csv")
    
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

def save_html_output(data: Dict[str, Any]) -> str:
    """Saves the report data to a beautiful HTML file."""
    domain = data.get("domain", "unknown")
    filename = _generate_filename(domain, "html")
    os.makedirs("output", exist_ok=True)
    
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>ReconX Report - {html.escape(domain)}</title>
        <style>
            :root {{ --primary: #4f46e5; --secondary: #ec4899; --bg: #f3f4f6; --card-bg: #ffffff; --text: #1f2937; }}
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
    
    exclude_keys = ["domain", "ip_address", "error"]
    for key, value in data.items():
        if key in exclude_keys: continue
        html_content += f'<div class="card"><h2>{html.escape(key.replace("_", " ").title())}</h2>'
        if isinstance(value, dict):
            if key == "open_ports" and "open_ports" in value:
                 for p, banner in value["open_ports"].items():
                     banner_text = str(banner) if banner else "N/A"
                     html_content += f'<div class="key-value"><span class="key">Port {html.escape(str(p))}</span> <span>{html.escape(banner_text)}</span></div>'
            else:
                for k, v in value.items():
                    if isinstance(v, list):
                        html_content += f'<div class="key-value"><span class="key">{html.escape(str(k))}</span> <span>{len(v)} items</span></div>'
                    else:
                        val_str = str(v)[:100]
                        html_content += f'<div class="key-value"><span class="key">{html.escape(str(k))}</span> <span>{html.escape(val_str)}</span></div>'
        elif isinstance(value, list):
            html_content += f'<p>Found {len(value)} items:</p><ul>'
            for item in value[:10]:
                display_str = str(item.get("subdomain") or item.get("url") or str(item))
                html_content += f'<li>{html.escape(display_str)}</li>'
            if len(value) > 10:
                html_content += f'<li>...and {len(value)-10} more</li>'
            html_content += '</ul>'
        else:
             html_content += f'<p>{html.escape(str(value))}</p>'
        html_content += '</div>'

    html_content += "</div></body></html>"
    try:
        with open(filename, "w", encoding="utf-8") as f:
            f.write(html_content)
    except Exception as e:
        raise IOError(f"Failed to save HTML report to {filename}: {e}")
    return filename

def save_report(data: Dict[str, Any], output_format: str = "json") -> str:
    """Dispatches to the correct save function."""
    if output_format == "txt":
        return save_text_report(data)
    elif output_format == "json":
        return save_json_output(data)
    elif output_format == "csv":
        return save_csv_output(data)
    elif output_format == "html":
        return save_html_output(data)
    elif output_format == "pdf":
        return save_pdf_output(data)
    else:
        raise ValueError(f"Unsupported output format: {output_format}")
