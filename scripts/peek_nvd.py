# peek_nvd.py (version 2.1 - Smart)
import json

NVD_FILE_PATH = "nvd_data/nvdcve-2.0-2024.json"

print(f"Searching for good CVE samples from file: {NVD_FILE_PATH}\n")

try:
    with open(NVD_FILE_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    if data.get("vulnerabilities"):
        found_good_sample = False
        # Loop through the first few items to find a good example
        for vulnerability_entry in data["vulnerabilities"][:20]:  # Check first 20 items
            cve_item = vulnerability_entry.get("cve", {})

            # We look for CVEs that are NOT 'Rejected' and have configuration data
            if cve_item.get("vulnStatus") != "Rejected" and cve_item.get(
                "configurations"
            ):
                print("\nSuccessfully found a good CVE example:")
                print(json.dumps(cve_item, indent=4))
                found_good_sample = True
                break  # Stop loop after finding an example

        if not found_good_sample:
            print("Could not find a good CVE sample in the first 20 items.")
            # Just print the first one as fallback
            print(json.dumps(data["vulnerabilities"][0]["cve"], indent=4))

    else:
        print("Could not find 'vulnerabilities' in the JSON file.")

except FileNotFoundError:
    print(f"ERROR: File not found at '{NVD_FILE_PATH}'.")
except Exception as e:
    print(f"An error occurred while reading the JSON file: {e}")