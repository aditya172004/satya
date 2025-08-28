import requests
import pandas as pd
import json

# =========================
# CONFIG
# =========================
ABUSEIPDB_API_KEY = "d7db5e1a21ba39859876c33360bbf04cd4053320b79488e72450234196b992cd7ecfc8ba533821a2"   # <-- replace with your AbuseIPDB key
ABUSEIPDB_ENDPOINT = "https://api.abuseipdb.com/api/v2/check"
INPUT_FILE = "dashboard_data.csv"
OUTPUT_FILE = "api_enriched_threats.json"

# =========================
# FUNCTIONS
# =========================
def query_abuseipdb(ip):
    """Query AbuseIPDB for IP reputation details."""
    headers = {
        "Accept": "application/json",
        "Key": ABUSEIPDB_API_KEY
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }
    try:
        response = requests.get(ABUSEIPDB_ENDPOINT, headers=headers, params=params)
        if response.status_code == 200:
            data = response.json().get("data", {})
            return {
                "ip": ip,
                "abuseConfidenceScore": data.get("abuseConfidenceScore", "N/A"),
                "country": data.get("countryCode", "N/A"),
                "isp": data.get("isp", "N/A"),
                "usageType": data.get("usageType", "N/A"),
                "domain": data.get("domain", "N/A"),
                "totalReports": data.get("totalReports", 0),
                "lastReportedAt": data.get("lastReportedAt", "N/A"),
                "recommendedAction": "Block" if data.get("abuseConfidenceScore", 0) > 50 else "Monitor"
            }
        else:
            return {"ip": ip, "error": f"API error {response.status_code}"}
    except Exception as e:
        return {"ip": ip, "error": str(e)}

def process_dashboard_csv():
    """Extract malicious IPs from dashboard_data.csv and enrich with AbuseIPDB API."""
    df = pd.read_csv(INPUT_FILE)

    if "src_ip" not in df.columns or "Label" not in df.columns:
        raise ValueError("dashboard_data.csv must contain 'src_ip' and 'Label' columns")

    # Filter only malicious packets (exclude benign/normal)
    malicious_df = df[df["Label"].str.lower() != "benign"]

    ip_list = malicious_df["src_ip"].dropna().unique().tolist()

    print(f"[+] Found {len(ip_list)} unique malicious IPs to check")

    results = []
    for ip in ip_list:
        print(f"[+] Checking {ip} ...")
        result = query_abuseipdb(ip)
        results.append(result)

    # Save enriched results to JSON
    with open(OUTPUT_FILE, "w") as f:
        json.dump(results, f, indent=4)

    print(f"[✔] Enriched threat data saved to {OUTPUT_FILE}")

# =========================
# MAIN
# =========================
if __name__ == "__main__":
    process_dashboard_csv()

