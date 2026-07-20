#!/usr/bin/env python3
"""
OCI Storage Backup Report — one command
=======================================
Runs Oracle's official showoci.py, then runs the backup-frequency enricher on
its CSV output. You run ONE command; it does both steps.

READ-ONLY: showoci and the enricher only read. Nothing in OCI is modified.

Layout expected (all in the same folder, or point with flags):
    showoci.py                  <- Oracle's tool (from oci-python-sdk/examples/showoci)
    showoci_backup_freq.py      <- the enricher
    run_backup_report.py        <- this script

Usage:
    python3 run_backup_report.py --profile GOVCLOUD
    python3 run_backup_report.py --profile GOVCLOUD --region us-langley-1
    python3 run_backup_report.py --auth instance_principal

Output:
    report_*.csv        <- raw showoci CSVs
    report_*_freq.csv   <- same data + schedule_frequency column
"""

import argparse
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def find(name, override):
    """Locate a helper script: use override if given, else look next to this file."""
    if override:
        if not os.path.isfile(override):
            sys.exit(f"Not found: {override}")
        return override
    guess = os.path.join(HERE, name)
    if not os.path.isfile(guess):
        sys.exit(f"Could not find {name} next to this script ({HERE}). "
                 f"Pass its path explicitly.")
    return guess


def run(cmd, label):
    print(f"\n=== {label} ===", file=sys.stderr)
    print("  " + " ".join(cmd), file=sys.stderr)
    result = subprocess.run(cmd)
    if result.returncode != 0:
        sys.exit(f"{label} failed (exit {result.returncode}). Stopping.")


def main():
    p = argparse.ArgumentParser(description="Run showoci + backup-frequency enrichment in one go.")
    p.add_argument("--profile", default="DEFAULT", help="OCI config profile")
    p.add_argument("--auth", choices=["config", "instance_principal"], default="config")
    p.add_argument("--region", help="Limit to one region (default: all subscribed)")
    p.add_argument("--prefix", default="report", help="showoci CSV filename prefix (default: report)")
    p.add_argument("--dir", default=".", help="Where CSVs are written / read (default: current folder)")
    p.add_argument("--showoci", help="Path to showoci.py (default: look next to this script)")
    p.add_argument("--enricher", help="Path to showoci_backup_freq.py (default: next to this script)")
    p.add_argument("--config-file", help="OCI config file path")
    args = p.parse_args()

    showoci = find("showoci.py", args.showoci)
    enricher = find("showoci_backup_freq.py", args.enricher)

    os.makedirs(args.dir, exist_ok=True)
    # showoci writes to CWD, so run it from --dir
    prefix_path = os.path.join(args.dir, args.prefix)

    # ---- Step 1: showoci -> CSV ----
    showoci_cmd = ["python3", showoci, "-c", prefix_path]
    if args.auth == "instance_principal":
        showoci_cmd.append("-ip")
    else:
        showoci_cmd += ["-p", args.profile]
        if args.config_file:
            showoci_cmd += ["-cf", args.config_file]
    if args.region:
        showoci_cmd += ["-rg", args.region]
    run(showoci_cmd, "STEP 1: showoci (official Oracle reporting tool)")

    # ---- Step 2: enrich CSVs with backup frequency ----
    enrich_cmd = ["python3", enricher, "--dir", args.dir, "--auth", args.auth]
    if args.auth == "config":
        enrich_cmd += ["--profile", args.profile]
        if args.config_file:
            enrich_cmd += ["--config-file", args.config_file]
    run(enrich_cmd, "STEP 2: add backup schedule frequency")

    print("\n" + "=" * 60, file=sys.stderr)
    print("Done. Look for *_freq.csv in:", os.path.abspath(args.dir), file=sys.stderr)
    print("=" * 60, file=sys.stderr)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
