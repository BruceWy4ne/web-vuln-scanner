import os
import subprocess
import json
import argparse
import csv
import matplotlib.pyplot as plt
import time
import multiprocessing
from urllib.parse import urlparse
from datetime import datetime

# Function to ensure URLs are properly formatted


def sanitize_url(website):
    if not website.startswith("http"):
        website = "https://" + website  # Ensure proper scheme
    return website.rstrip("/")  # Remove trailing slash

# Function to safely load JSON


def load_json(file_path):
    try:
        with open(file_path, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []

# Function to parse Nuclei output


def parse_nuclei(nuclei_file, results):
    data = load_json(nuclei_file)
    for entry in data:
        results.append({
            "website": entry.get("host", "Unknown"),
            "vulnerability": entry["info"].get("name", "Unknown"),
            "risk_level": entry["info"].get("severity", "Unknown").capitalize(),
            "description": entry["info"].get("description", "No description available")
        })

# Function to parse Wapiti output


def parse_wapiti(wapiti_file, results):
    data = load_json(wapiti_file)
    if not data:
        return

    target = data.get("infos", {}).get("target", "Unknown")
    vulnerabilities = data.get("vulnerabilities", {})

    for vuln_type, details in vulnerabilities.items():
        for detail in details:
            results.append({
                "website": target,
                "vulnerability": vuln_type,
                "risk_level": "High" if detail.get("level", 0) >= 3 else "Low",
                "description": detail.get("info", "No description available")
            })

# Function to parse Nikto output


def parse_nikto(nikto_file, website, results):
    data = load_json(nikto_file)
    if not data:
        return

    for vuln in data.get("vulnerabilities", []):
        results.append({
            "website": website,
            "vulnerability": vuln.get("id", "Unknown"),
            "risk_level": "Medium",
            "description": vuln.get("msg", "No description available")
        })

# Function to create structured report


def generate_report(results, output_file):
    with open(output_file, "w") as f:
        json.dump(results, f, indent=4)

# Function to run scans


def run_scans(website, output_dir, log_dir):
    sanitized_website = sanitize_url(website)
    domain = urlparse(sanitized_website).netloc
    website_dir = os.path.join(output_dir, domain)
    os.makedirs(website_dir, exist_ok=True)

    log_entry = {"website": domain, "nuclei": 0,
                 "wapiti": 0, "nikto": 0, "total": 0}

    results = []
    start_time = time.time()

    try:
        # Nuclei
        nuclei_output = os.path.join(website_dir, "nuclei_scan.json")
        t1 = time.time()
        subprocess.run(["nuclei", "-target", sanitized_website,
                       "-json-export", nuclei_output], check=False)
        log_entry["nuclei"] = round((time.time() - t1) / 60, 2)
        parse_nuclei(nuclei_output, results)

        # Wapiti
        wapiti_output = os.path.join(website_dir, "wapiti_scan.json")
        t2 = time.time()
        subprocess.run(["wapiti", "-u", sanitized_website, "-o",
                       wapiti_output, "-f", "json"], check=False)
        log_entry["wapiti"] = round((time.time() - t2) / 60, 2)
        parse_wapiti(wapiti_output, results)

        # Nikto - OWASP focused tuning
        nikto_output = os.path.join(website_dir, "nikto_scan.json")
        t3 = time.time()
        try:
            subprocess.run([
                "nikto", "-h", sanitized_website,
                "-Tuning", "124356bc",  # Only OWASP-relevant scans
                "-Format", "json", "-o", nikto_output
            ], timeout=900, check=False)
        except subprocess.TimeoutExpired:
            with open(os.path.join(log_dir, "nikto_delay.txt"), "a") as f:
                f.write(f"{domain}\n")
        log_entry["nikto"] = round((time.time() - t3) / 60, 2)
        parse_nikto(nikto_output, sanitized_website, results)

        combined_output = os.path.join(website_dir, "combined.json")
        generate_report(results, combined_output)

    except Exception as e:
        with open(os.path.join(log_dir, "skipped.txt"), "a") as f:
            f.write(f"{domain}\n")
        return

    log_entry["total"] = round((time.time() - start_time) / 60, 2)
    with open(os.path.join(log_dir, "time.txt"), "a") as f:
        f.write(
            f"{log_entry['website']}, {log_entry['nikto']} min, {log_entry['wapiti']} min, {log_entry['nuclei']} min, {log_entry['total']} min\n")

    print(f"{sanitized_website} scan complete. Results saved in {website_dir}.")

# Function to handle multi-threaded scanning using multiprocessing


def process_websites(websites, output_dir, max_processes):
    os.makedirs(output_dir, exist_ok=True)
    log_dir = os.path.join(output_dir, "log")
    os.makedirs(log_dir, exist_ok=True)

    # Initialize log files
    with open(os.path.join(log_dir, "time.txt"), "w") as f:
        f.write("website name, nikto, wapiti, nuclei, total\n")
    open(os.path.join(log_dir, "skipped.txt"), "w").close()
    open(os.path.join(log_dir, "nikto_delay.txt"), "w").close()

    with multiprocessing.Pool(processes=max_processes) as pool:
        pool.starmap(run_scans, [(site, output_dir, log_dir)
                     for site in websites])

    print("All scans completed.")


# main execution
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Run Nikto, Wapiti, and Nuclei scans.")
    parser.add_argument("-w", "--websites", required=True,
                        help="Path to a text file with websites.")
    parser.add_argument("-o", "--output-dir", required=True,
                        help="Directory to store scan results.")
    parser.add_argument("-t", "--threads", type=int,
                        default=5, help="Number of threads.")

    args = parser.parse_args()

    with open(args.websites, "r") as file:
        websites = [sanitize_url(line.strip())
                    for line in file.readlines() if line.strip()]

    print(
        f"Starting scans for {len(websites)} websites using {args.threads} processes...")

    start_time = time.time()
    process_websites(websites, args.output_dir, args.threads)
    end_time = time.time()

    execution_time = end_time - start_time
    with open(os.path.join(args.output_dir, "log", "execution_time.log"), "w") as f:
        f.write(f"Total execution time: {execution_time:.2f} seconds\n")

    print(f"Total execution time: {execution_time:.2f} seconds")
