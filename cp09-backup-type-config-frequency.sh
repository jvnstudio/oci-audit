#!/usr/bin/env python3
"""
showoci Backup-Frequency Enricher (simple mode)
==============================================
Companion to Oracle's official showoci.py. It finds showoci's CSV files, figures
out which are volume vs file-storage on its own, and adds a `schedule_frequency`
column showing each backup policy's schedule + retention.

READ-ONLY: only get_volume_backup_policy / get_snapshot_policy /
list_volume_backup_policies are ever called. Nothing is modified. New CSVs are
written next to the originals with a _freq suffix.

SDK: https://github.com/oracle/oci-python-sdk

Usage (that's it):
    python3 showoci_backup_freq.py --profile GOVCLOUD

By default it scans the current folder for showoci CSVs. To point elsewhere:
    python3 showoci_backup_freq.py --profile GOVCLOUD --dir /path/to/showoci/output
"""

import argparse
import csv
import glob
import os
import re
import sys

import oci


# --------------------------------------------------------------------------- #
# READ-ONLY guard
# --------------------------------------------------------------------------- #
_MUTATING = ("create_", "update_", "delete_", "assign_", "remove_", "put_",
             "post_", "attach_", "detach_", "change_", "terminate_", "add_",
             "modify_", "restore_", "copy_")
_OK = {"add_argument"}


def _assert_read_only():
    try:
        src = open(__file__).read()
    except OSError:
        return
    for m in re.findall(r"\.([a-zA-Z_][a-zA-Z0-9_]*)\s*\(", src):
        if m not in _OK and any(m.startswith(h) for h in _MUTATING):
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
    return bs, fss


# --------------------------------------------------------------------------- #
# Detection
# --------------------------------------------------------------------------- #
def find_policy_column(headers):
    """Return (column_name, kind) or (None, None). kind = 'block' or 'fss'."""
    for h in headers:
        lh = h.lower()
        if "snapshot" in lh and "polic" in lh:
            return h, "fss"
    for h in headers:
        lh = h.lower()
        if "backup" in lh and "polic" in lh:
            return h, "block"
    # generic 'policy id' fallback -> assume block (most common)
    for h in headers:
        if re.search(r"polic.*id", h.lower()):
            return h, "block"
    return None, None


def looks_like_showoci_csv(path):
    try:
        with open(path, newline="") as f:
            headers = next(csv.reader(f), [])
    except (OSError, StopIteration):
        return None
    col, kind = find_policy_column(headers)
    return (col, kind, headers) if col else None


# --------------------------------------------------------------------------- #
# Schedule formatting
# --------------------------------------------------------------------------- #
def fmt_block(s):
    parts = [f"type={s.backup_type}", f"period={s.period}"]
    if s.hour_of_day is not None: parts.append(f"hour={s.hour_of_day}")
    if s.day_of_week: parts.append(f"dow={s.day_of_week}")
    if s.day_of_month is not None: parts.append(f"dom={s.day_of_month}")
    if s.month: parts.append(f"month={s.month}")
    parts.append(f"retention_sec={s.retention_seconds}")
    if s.time_zone: parts.append(f"tz={s.time_zone}")
    return "; ".join(parts)


def fmt_fss(s):
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
    def __init__(self, bs, fss):
        self.bs, self.fss, self.cache = bs, fss, {}
        self.name_index = None

    def _names(self):
        if self.name_index is None:
            self.name_index = {}
            try:
                for p in oci.pagination.list_call_get_all_results(
                        self.bs.list_volume_backup_policies).data:
                    self.name_index[p.display_name] = p.id
            except oci.exceptions.ServiceError:
                pass
        return self.name_index

    def resolve(self, value, kind):
        value = (value or "").strip()
        if not value:
            return "NOT BACKED UP"
        key = (value, kind)
        if key in self.cache:
            return self.cache[key]

        # value may be an OCID or a policy name
        pid = value
        if not value.startswith("ocid1.") and kind == "block":
            pid = self._names().get(value, "")

        out = "NOT BACKED UP"
        if pid.startswith("ocid1."):
            try:
                if kind == "block":
                    pol = self.bs.get_volume_backup_policy(pid).data
                    out = " | ".join(fmt_block(s) for s in pol.schedules) or "(no schedules)"
                else:
                    pol = self.fss.get_snapshot_policy(pid).data
                    out = " | ".join(fmt_fss(s) for s in (pol.schedules or [])) or "(no schedules)"
            except oci.exceptions.ServiceError as e:
                out = f"(unresolved: {e.code})"
        elif value and kind == "fss":
            out = "(need policy OCID for fss)"

        self.cache[key] = out
        return out


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def main():
    p = argparse.ArgumentParser(description="Add backup schedule frequency to showoci CSVs.")
    p.add_argument("--dir", default=".", help="Folder with showoci CSV files (default: current)")
    p.add_argument("--auth", choices=["config", "instance_principal"], default="config")
    p.add_argument("--config-file", default=oci.config.DEFAULT_LOCATION)
    p.add_argument("--profile", default="DEFAULT")
    args = p.parse_args()

    _assert_read_only()

    csv_files = sorted(glob.glob(os.path.join(args.dir, "*.csv")))
    csv_files = [f for f in csv_files if not f.endswith("_freq.csv")]
    targets = []
    for f in csv_files:
        info = looks_like_showoci_csv(f)
        if info:
            col, kind, headers = info
            targets.append((f, col, kind, headers))

    if not targets:
        raise SystemExit(
            f"No showoci CSVs with a backup/snapshot policy column found in '{args.dir}'.\n"
            f"Run showoci first, e.g.:  python3 showoci.py -p {args.profile} -c report"
        )

    print("=" * 60, file=sys.stderr)
    print("READ-ONLY: reads backup policies only, changes nothing.", file=sys.stderr)
    print(f"Found {len(targets)} storage CSV(s) to enrich:", file=sys.stderr)
    for f, col, kind, _ in targets:
        print(f"  {os.path.basename(f)}  [{kind}]  policy col: {col}", file=sys.stderr)
    print("=" * 60, file=sys.stderr)

    bs, fss = build_clients(args)
    resolver = Resolver(bs, fss)

    for path, col, kind, headers in targets:
        with open(path, newline="") as f:
            rows = list(csv.DictReader(f))
        out_headers = list(headers)
        if "schedule_frequency" not in out_headers:
            out_headers.append("schedule_frequency")
        done = 0
        for r in rows:
            freq = resolver.resolve(r.get(col), kind)
            r["schedule_frequency"] = freq
            if freq not in ("NOT BACKED UP",):
                done += 1
        out_path = re.sub(r"\.csv$", "_freq.csv", path)
        with open(out_path, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=out_headers)
            w.writeheader()
            w.writerows(rows)
        print(f"{os.path.basename(out_path)}: {len(rows)} rows, "
              f"{done} with a schedule.", file=sys.stderr)

    print("\nDone.", file=sys.stderr)


if __name__ == "__main__":
    try:
        main()
    except oci.exceptions.ServiceError as e:
        print(f"OCI ServiceError: {e.status} {e.code} - {e.message}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(130)
