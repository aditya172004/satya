#!/usr/bin/env python3
import pandas as pd
import matplotlib.pyplot as plt
from fpdf import FPDF
from fpdf.enums import XPos, YPos
import argparse
from datetime import datetime, timedelta


def generate_report(datafile, outfile, hours=24):
    df = pd.read_csv(datafile)
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    cutoff = datetime.now() - timedelta(hours=hours)
    df = df[df['timestamp'] >= cutoff]

    # Summary stats
    total_events = len(df)
    malicious = df[df['Label'] == "Attack"]
    benign = df[df['Label'] == "Benign"]
    summary = {
        "Total Events": total_events,
        "Malicious": len(malicious),
        "Benign": len(benign),
        "Unique Malicious IPs": malicious['src_ip'].nunique() if not malicious.empty else 0
    }

    # PDF setup
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("helvetica", "B", 16)
    pdf.cell(200, 10, "Threat Report", new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="C")

    pdf.set_font("helvetica", "", 12)
    for k, v in summary.items():
        pdf.cell(200, 10, f"{k}: {v}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    # Threats by type
    if "attack_type" in df.columns:
        counts = df['attack_type'].value_counts()
        if not counts.empty:
            plt.figure()
            counts.plot(kind="bar")
            plt.title("Threats by Type")
            plt.tight_layout()
            plt.savefig("chart1.png")
            plt.close()
            pdf.add_page()
            pdf.image("chart1.png", x=10, y=30, w=180)

    # Top Malicious IPs
    if not malicious.empty:
        ip_counts = malicious['src_ip'].value_counts().head(10)
        if not ip_counts.empty:
            plt.figure()
            ip_counts.plot(kind="bar")
            plt.title("Top Malicious IPs")
            plt.tight_layout()
            plt.savefig("chart2.png")
            plt.close()
            pdf.add_page()
            pdf.image("chart2.png", x=10, y=30, w=180)

    # Save PDF
    pdf.output(outfile)
    print(f"Report generated: {outfile}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", required=True, help="Path to CSV file")
    parser.add_argument("--out", required=True, help="Output PDF file")
    parser.add_argument("--window", type=int, default=24, help="Time window in hours")
    args = parser.parse_args()

    generate_report(args.data, args.out, args.window)

