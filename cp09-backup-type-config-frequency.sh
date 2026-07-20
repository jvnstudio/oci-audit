#!/usr/bin/env python3
"""
showoci Backup-Frequency Enricher
=================================
Companion to Oracle's official `showoci.py` (examples/showoci in the
oci-python-sdk repo). showoci reports WHICH backup policy is assigned to each
volume / file system, but not the policy's SCHEDULE (frequency + retention).

This script reads showoci's CSV output and adds a `schedule_frequency` column
by resolving each referenced policy. It is strictly READ-ONLY: the only OCI
calls it makes are:
    - get_volume_backup_policy      (block/boot volume policies)
    - get_snapshot_policy           (file storage snapshot policies)
    - list_volume_backup_policies   (optional, to match by policy NAME)
No resource is ever created, changed, or deleted. Output is a new CSV.

SDK: https://github.com/oracle/oci-python-sdk

Workflow:
  1. Run showoci and export CSV, e.g.:
        python3 showoci.py -p GOVCLOUD -c report
     (produces report_*.csv, including a block-volume file and an fss file)

  2. Enrich the block-volume file:
        python3 showoci_backup_freq_enrich.py \
            --in report_block_volumes.csv \
            --kind block --profile GOVCLOUD \
            --out report_block_volumes_freq.csv

  3. Enrich the file-storage file:
        python3 showoci_backup_freq_enrich.py \
            --in report_file_storage.csv \
            --kind fss --profile GOVCLOUD \
            --out report_file_storage_freq.csv

If unsure which column holds the policy, run with --inspect to just print the
detected columns and exit (no OCI calls made).
"""

import argparse
import csv
import re
import sys

import oci


# --------------------------------------------------------------------------- #
# READ-ONLY guard (same philosophy as before: abort if a mutating call exists)
# --------------------------------------------------------------------------- #
_MUTATING_HINTS = ("create_", "update_", "delete_", "assign_", "remove_",
                   "put_", "post_", "attach_", "detach_", "change_",
                   "terminate_", "add_", "modify_", "restore_", "copy_")
_STDLIB_OK = {"add_argument"}


def _assert_read_only(source_path):
    try:
        src = open(source_path).read()
    except OSError:
        return
    for m in re.findall(r"\.([a-zA-Z_][a-zA-Z0-9_]*)\s*\(", src):
        if m in _STDLIB_OK:
            continue
        if any(m.startswith(h) for h in _MUTATING_HINTS):
            raise SystemExit(f"READ-ONLY GUARD: mutating call detected: '{m}'")


# --------------------------------------------------------------------------- #
# Auth
# --------------------------------------------------------------------------- #
def build_clients(args):
    if args.auth == "instance_principal":
        signer = oci.auth.signers.InstancePrincipalsSecurityTokenSigner()
        cfg = {"region": signer.region}
        bs = oci.core.BlockstorageClient(config=cfg, signer=signer)
        fss = oci.file_storage.FileStorageClient(config=cfg, signer=signer)
    else:
        cfg = oci.config.from_file(args.config_file, args.profile)
        bs = oci.core.BlockstorageClient(config=cfg)
        fss = oci.file_storage.FileStorageClient(config=cfg)
    if args.region:
        bs.base_client.set_region(args.region)
        fss.base_client.set_region(args.region)
    return bs, fss


# --------------------------------------------------------------------------- #
# Column auto-detection
# --------------------------------------------------------------------------- #
def detect_columns(headers):
    """Return dict with best-guess column names for policy id, policy name, ocid."""
    lower = {h.lower(): h for h in headers}

    def find(*patterns):
        for pat in patterns:
            for lh, orig in lower.items():
                if re.search(pat, lh):
                    return orig
        return None

    return {
        "policy_id":   find(r"policy.*id", r"backup_policy_id", r"snapshot_policy_id"),
        "policy_name": find(r"policy.*name", r"backup_policy", r"snapshot_policy"),
        "ocid":        find(r"^id$", r"volume_?id", r"file.?system.?id", r"\bocid\b"),
    }


# --------------------------------------------------------------------------- #
# Schedule formatting
# --------------------------------------------------------------------------- #
def fmt_block_schedule(s):
    parts = [f"type={s.backup_type}", f"period={s.period}"]
    if s.hour_of_day is not None: parts.append(f"hour={s.hour_of_day}")
    if s.day_of_week: parts.append(f"dow={s.day_of_week}")
    if s.day_of_month is not None: parts.append(f"dom={s.day_of_month}")
    if s.month: parts.append(f"month={s.month}")
    parts.append(f"retention_sec={s.retention_seconds}")
    if s.time_zone: parts.append(f"tz={s.time_zone}")
    return "; ".join(parts)


def fmt_fss_schedule(s):
    parts = [f"period={s.period}"]
    if s.hour_of_day is not None: parts.append(f"hour={s.hour_of_day}")
    if s.day_of_week: parts.append(f"dow={s.day_of_week}")
    if s.day_of_month is not None: parts.append(f"dom={s.day_of_month}")
    if s.month: parts.append(f"month={s.month}")
    if s.retention_duration_in_seconds is not None:
        parts.append(f"retention_sec={s.retention_duration_in_seconds}")
    if s.time_zone: parts.append(f"tz={s.time_zone}")
    return "; ".join(parts)


# --------------------------------------------------------------------------- #
# Policy resolution (cached)
# --------------------------------------------------------------------------- #
class Resolver:
    def __init__(self, bs, fss, kind):
        self.bs, self.fss, self.kind = bs, fss, kind
        self.cache = {}
        self._name_index = None  # lazy: name -> policy_id for block policies

    def _block_name_index(self, compartment_id=None):
        if self._name_index is None:
            self._name_index = {}
            try:
                pols = oci.pagination.list_call_get_all_results(
                    self.bs.list_volume_backup_policies
                ).data
                for p in pols:
                    self._name_index[p.display_name] = p.id
            except oci.exceptions.ServiceError:
                pass
        return self._name_index

    def by_id(self, policy_id):
        if not policy_id:
            return ""
        if policy_id in self.cache:
            return self.cache[policy_id]
        out = ""
        try:
            if self.kind == "block":
                pol = self.bs.get_volume_backup_policy(policy_id).data
                out = " | ".join(fmt_block_schedule(s) for s in pol.schedules) or "(no schedules)"
            else:
                pol = self.fss.get_snapshot_policy(policy_id).data
                out = " | ".join(fmt_fss_schedule(s) for s in (pol.schedules or [])) or "(no schedules)"
        except oci.exceptions.ServiceError as e:
            out = f"(unresolved: {e.code})"
        self.cache[policy_id] = out
        return out

    def by_name(self, name):
        if not name:
            return ""
        if self.kind != "block":
            return "(name-lookup only supported for block policies; provide policy id)"
        pid = self._block_name_index().get(name)
        return self.by_id(pid) if pid else "(policy name not found)"


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def main():
    p = argparse.ArgumentParser(description="Enrich showoci CSV with backup schedule frequency.")
    p.add_argument("--in", dest="infile", required=True, help="showoci CSV file")
    p.add_argument("--out", dest="outfile", help="output CSV (default: <in>_freq.csv)")
    p.add_argument("--kind", choices=["block", "fss"], required=True,
                   help="block = block/boot volume CSV; fss = file storage CSV")
    p.add_argument("--auth", choices=["config", "instance_principal"], default="config")
    p.add_argument("--config-file", default=oci.config.DEFAULT_LOCATION)
    p.add_argument("--profile", default="DEFAULT")
    p.add_argument("--region", help="Limit to one region (matches showoci region)")
    p.add_argument("--inspect", action="store_true",
                   help="Just print detected columns and exit (no OCI calls)")
    args = p.parse_args()

    _assert_read_only(__file__)

    with open(args.infile, newline="") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        headers = reader.fieldnames or []

    cols = detect_columns(headers)
    print("Detected columns:", file=sys.stderr)
    print(f"  policy_id   -> {cols['policy_id']}", file=sys.stderr)
    print(f"  policy_name -> {cols['policy_name']}", file=sys.stderr)
    print(f"  ocid        -> {cols['ocid']}", file=sys.stderr)

    if args.inspect:
        print("\nAll headers:", file=sys.stderr)
        for h in headers:
            print(f"    {h}", file=sys.stderr)
        return

    if not cols["policy_id"] and not cols["policy_name"]:
        raise SystemExit(
            "Could not find a policy id or policy name column. "
            "Run with --inspect to see headers, then map manually."
        )

    print("=" * 60, file=sys.stderr)
    print("READ-ONLY: get_volume_backup_policy / get_snapshot_policy only.",
          file=sys.stderr)
    print("=" * 60, file=sys.stderr)

    bs, fss = build_clients(args)
    resolver = Resolver(bs, fss, args.kind)

    out_headers = list(headers)
    if "schedule_frequency" not in out_headers:
        out_headers.append("schedule_frequency")

    enriched = 0
    for r in rows:
        freq = ""
        pid = r.get(cols["policy_id"]) if cols["policy_id"] else None
        if pid and pid.startswith("ocid1."):
            freq = resolver.by_id(pid)
        elif cols["policy_name"]:
            freq = resolver.by_name(r.get(cols["policy_name"], "").strip())
        r["schedule_frequency"] = freq or "NOT BACKED UP"
        if freq:
            enriched += 1

    outfile = args.outfile or re.sub(r"\.csv$", "", args.infile) + "_freq.csv"
    with open(outfile, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=out_headers)
        w.writeheader()
        w.writerows(rows)

    print(f"\nRows processed : {len(rows)}", file=sys.stderr)
    print(f"With schedule  : {enriched}", file=sys.stderr)
    print(f"Output written : {outfile}", file=sys.stderr)


if __name__ == "__main__":
    try:
        main()
    except oci.exceptions.ServiceError as e:
        print(f"OCI ServiceError: {e.status} {e.code} - {e.message}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(130)
