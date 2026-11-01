# update_db.py
import sqlite3
import json
import os
import glob
import argparse
from tqdm import tqdm

DB_PATH = "app/data/vulnerabilities.db"
NVD_DATA_DIR = "nvd_data"


def setup_database():
    """Create the database and tables if they don't exist."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Create vulnerabilities table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            cve_id TEXT NOT NULL,
            product TEXT NOT NULL,
            vendor TEXT NOT NULL,
            version TEXT NOT NULL,
            description TEXT,
            cvss_score REAL,
            link TEXT,
            PRIMARY KEY (cve_id, product, version)
        )
    """)
    
    # Create metadata table to track processed files
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS processed_files (
            filename TEXT PRIMARY KEY,
            mtime REAL
        )
    """)
    
    conn.commit()
    conn.close()
    print(f"Database '{DB_PATH}' is ready.")


def parse_cpe_string(cpe_uri):
    """
    Helper function to parse a CPE string into its components.
    Example: cpe:2.3:a:apache:http_server:2.4.39 -> ('apache', 'http_server', '2.4.39')
    """
    parts = cpe_uri.split(":")
    if len(parts) >= 6:
        vendor = parts[3]
        product = parts[4]
        version = parts[5]
        return vendor, product, version
    return None, None, None


def process_nvd_file(filepath, cursor):
    """Process one NVD JSON file and insert its data into the database."""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"Error reading {filepath}: {e}")
        return 0

    vulnerabilities_to_insert = []

    for entry in data.get("vulnerabilities", []):
        cve_item = entry.get("cve", {})
        cve_id = cve_item.get("id")

        # Get description
        description = ""
        if cve_item.get("descriptions"):
            for desc in cve_item["descriptions"]:
                if desc.get("lang") == "en":
                    description = desc.get("value")
                    break

        # Get CVSS score
        cvss_score = None
        if cve_item.get("metrics", {}).get("cvssMetricV31"):
            cvss_score = cve_item["metrics"]["cvssMetricV31"][0]["cvssData"].get(
                "baseScore"
            )

        # Get reference link
        link = ""
        if cve_item.get("references"):
            link = cve_item["references"][0].get("url")

        # Parse configuration to get affected software
        if cve_item.get("configurations"):
            for node_container in cve_item["configurations"]:
                for node in node_container.get("nodes", []):
                    for cpe_match in node.get("cpeMatch", []):
                        if cpe_match.get("vulnerable"):
                            cpe_uri = cpe_match.get("criteria")
                            vendor, product, version = parse_cpe_string(cpe_uri)
                            if vendor and product and version:
                                vulnerabilities_to_insert.append(
                                    (
                                        cve_id,
                                        product,
                                        vendor,
                                        version,
                                        description,
                                        cvss_score,
                                        link,
                                    )
                                )

    if vulnerabilities_to_insert:
        # Use INSERT OR REPLACE to update existing records
        cursor.executemany(
            """
            INSERT OR REPLACE INTO vulnerabilities 
            (cve_id, product, vendor, version, description, cvss_score, link)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
            vulnerabilities_to_insert,
        )
    
    return len(vulnerabilities_to_insert)


def main():
    """Main function to run the import process."""
    parser = argparse.ArgumentParser(description="Update vulnerability database from NVD JSON files.")
    parser.add_argument("--force", "-f", action="store_true", help="Force re-processing of all files.")
    args = parser.parse_args()

    setup_database()

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Find all .json files in the nvd_data directory
    json_files = glob.glob(os.path.join(NVD_DATA_DIR, "*.json"))
    
    if not json_files:
        print(f"No JSON files found in {NVD_DATA_DIR}. Please run download_data.py first.")
        return

    print(f"Found {len(json_files)} NVD JSON files.")
    
    files_to_process = []
    
    # Check which files need processing
    for filepath in json_files:
        filename = os.path.basename(filepath)
        mtime = os.path.getmtime(filepath)
        
        if args.force:
            files_to_process.append((filepath, filename, mtime))
            continue
            
        cursor.execute("SELECT mtime FROM processed_files WHERE filename = ?", (filename,))
        result = cursor.fetchone()
        
        if result is None or result[0] != mtime:
            files_to_process.append((filepath, filename, mtime))
    
    if not files_to_process:
        print("All files are up to date. Nothing to process.")
        conn.close()
        return

    print(f"Processing {len(files_to_process)} files...")

    # Use tqdm for a beautiful progress bar
    for filepath, filename, mtime in tqdm(files_to_process, desc="Updating database"):
        count = process_nvd_file(filepath, cursor)
        
        # Update processed_files table
        cursor.execute(
            "INSERT OR REPLACE INTO processed_files (filename, mtime) VALUES (?, ?)",
            (filename, mtime)
        )
        conn.commit() # Commit after each file to save progress

    conn.close()
    print("\n✅ Vulnerability data import completed!")


if __name__ == "__main__":
    main()
