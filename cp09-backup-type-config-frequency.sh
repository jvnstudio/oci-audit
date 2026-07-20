#!/usr/bin/env bash
#
# oci_backup_report_rewritten.sh
# ==========================
# OCI access uses only Oracle-maintained showoci.py and Oracle OCI CLI.
# All OCI commands are read-only list/get operations. Local CSV files are
# created or replaced.

set -Eeuo pipefail
IFS=$'\n\t'

PROFILE="DEFAULT"
AUTH="config"
REGION=""
ALL_REGIONS="false"
PREFIX="report"
OUTDIR="."
SHOWOCI=""
CONFIG_FILE=""
PYTHON_BIN="${PYTHON_BIN:-python3}"

usage() {
  cat <<'USAGE'
Usage: oci_backup_report_rewritten.sh [options]
  -p PROFILE      OCI config profile (default: DEFAULT)
  -i              Use instance-principal authentication
  -r REGION       Scan one region
  --all-regions   Scan every subscribed region
  -f FILE         OCI config file path (default: /.oci/config)
  -o DIR          Output directory (default: current directory)
  -x PREFIX       CSV filename stem (default: report)
  -s PATH         Path to showoci.py
  -h              Show help

Pass exactly one of -r REGION or --all-regions.
USAGE
}

ARGS=()
while (($#)); do
  case "$1" in
    --all-regions) ALL_REGIONS="true"; shift ;;
    --) shift; ARGS+=("$@"); break ;;
    *) ARGS+=("$1"); shift ;;
  esac
done
set -- "${ARGS[@]}"

while getopts ":p:ir:f:o:x:s:h" opt; do
  case "$opt" in
    p) PROFILE="$OPTARG" ;;
    i) AUTH="instance_principal" ;;
    r) REGION="$OPTARG" ;;
    f) CONFIG_FILE="$OPTARG" ;;
    o) OUTDIR="$OPTARG" ;;
    x) PREFIX="$OPTARG" ;;
    s) SHOWOCI="$OPTARG" ;;
    h) usage; exit 0 ;;
    :) echo "ERROR: -$OPTARG requires a value." >&2; exit 2 ;;
    \?) echo "ERROR: unknown option -$OPTARG" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ -z "$REGION" && "$ALL_REGIONS" != "true" ]]; then
  echo "ERROR: pass -r REGION or --all-regions." >&2
  exit 2
fi
if [[ -n "$REGION" && "$ALL_REGIONS" == "true" ]]; then
  echo "ERROR: use either -r REGION or --all-regions, not both." >&2
  exit 2
fi
if [[ ! "$PREFIX" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ || "$PREFIX" == "." || "$PREFIX" == ".." ]]; then
  echo "ERROR: prefix must use only letters, digits, dot, underscore, and hyphen." >&2
  exit 2
fi

command -v "$PYTHON_BIN" >/dev/null 2>&1 || { echo "ERROR: Python not found: $PYTHON_BIN" >&2; exit 1; }
command -v oci >/dev/null 2>&1 || { echo "ERROR: OCI CLI ('oci') is not installed." >&2; exit 1; }

mkdir -p -- "$OUTDIR"
OUTDIR="$(cd -- "$OUTDIR" && pwd -P)"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"

if [[ -z "$SHOWOCI" ]]; then
  for candidate in \
    "$HOME/oci-python-sdk/examples/showoci/showoci.py" \
    "$SCRIPT_DIR/showoci.py" \
    "$PWD/showoci.py"; do
    if [[ -f "$candidate" ]]; then
      SHOWOCI="$candidate"
      break
    fi
  done
fi
[[ -n "$SHOWOCI" && -f "$SHOWOCI" ]] || { echo "ERROR: showoci.py not found; use -s PATH." >&2; exit 1; }
SHOWOCI="$(cd -- "$(dirname -- "$SHOWOCI")" && pwd -P)/$(basename -- "$SHOWOCI")"

expand_path() {
  local path="$1"
  case "$path" in
    "~") printf '%s\n' "$HOME" ;;
    "~/"*) printf '%s/%s\n' "$HOME" "${path#~/}" ;;
    *) printf '%s\n' "$path" ;;
  esac
}

read_profile_value() {
  local file="$1" profile="$2" key="$3"
  "$PYTHON_BIN" - "$file" "$profile" "$key" <<'PYCFG'
import configparser
import os
import sys

file_name, profile, key = sys.argv[1:4]
parser = configparser.RawConfigParser()
try:
    with open(file_name, "r", encoding="utf-8") as stream:
        parser.read_file(stream)
except (OSError, configparser.Error):
    sys.exit(1)

# ConfigParser treats [DEFAULT] specially, so handle it explicitly.
if profile == "DEFAULT":
    value = parser.defaults().get(key)
else:
    value = parser.get(profile, key, fallback=None) if parser.has_section(profile) else None

if not value:
    sys.exit(0)

value = os.path.expandvars(os.path.expanduser(value.strip()))
if not os.path.isabs(value):
    value = os.path.join(os.path.dirname(os.path.realpath(file_name)), value)
print(os.path.realpath(value))
PYCFG
}

select_config_file() {
  if [[ -n "$CONFIG_FILE" ]]; then
    CONFIG_FILE="$(expand_path "$CONFIG_FILE")"
  else
    CONFIG_FILE="/.oci/config"
  fi
}

preflight_config_auth() {
  select_config_file

  if [[ ! -e "$CONFIG_FILE" ]]; then
    echo "ERROR: OCI config file does not exist: $CONFIG_FILE" >&2
    echo "       Default expected location: /.oci/config" >&2
    exit 1
  fi
  if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "ERROR: OCI config path is not a regular file: $CONFIG_FILE" >&2
    exit 1
  fi
  if [[ ! -r "$CONFIG_FILE" ]]; then
    echo "ERROR: OCI config file is not readable by user $(id -un): $CONFIG_FILE" >&2
    echo "Directory/file permissions:" >&2
    if command -v namei >/dev/null 2>&1; then
      namei -l "$CONFIG_FILE" >&2 || true
    else
      ls -ld "$(dirname -- "$CONFIG_FILE")" "$CONFIG_FILE" >&2 || true
    fi
    exit 1
  fi

  CONFIG_FILE="$($PYTHON_BIN - "$CONFIG_FILE" <<'PYPATH'
import os, sys
print(os.path.realpath(sys.argv[1]))
PYPATH
)"

  local key_file token_file
  key_file="$(read_profile_value "$CONFIG_FILE" "$PROFILE" key_file || true)"
  token_file="$(read_profile_value "$CONFIG_FILE" "$PROFILE" security_token_file || true)"

  if [[ -z "$key_file" && -z "$token_file" ]]; then
    echo "ERROR: profile [$PROFILE] was not found or has neither key_file nor security_token_file:" >&2
    echo "       $CONFIG_FILE" >&2
    exit 1
  fi

  for credential_file in "$key_file" "$token_file"; do
    [[ -z "$credential_file" ]] && continue
    credential_file="$(expand_path "$credential_file")"
    if [[ ! -e "$credential_file" ]]; then
      echo "ERROR: credential file referenced by profile [$PROFILE] does not exist:" >&2
      echo "       $credential_file" >&2
      exit 1
    fi
    if [[ ! -f "$credential_file" || ! -r "$credential_file" ]]; then
      echo "ERROR: credential file referenced by profile [$PROFILE] is not readable by $(id -un):" >&2
      echo "       $credential_file" >&2
      if command -v namei >/dev/null 2>&1; then
        namei -l "$credential_file" >&2 || true
      else
        ls -ld "$(dirname -- "$credential_file")" "$credential_file" >&2 || true
      fi
      exit 1
    fi
  done

  echo ">>> OCI authentication preflight passed." >&2
  echo "    user   : $(id -un) (uid=$(id -u))" >&2
  echo "    profile: $PROFILE" >&2
  echo "    config : $CONFIG_FILE" >&2
}

# Do not inherit a different config location such as /etc/oci/config.
unset OCI_CONFIG_FILE OCI_CLI_CONFIG_FILE 2>/dev/null || true

CLI_AUTH=()
SHOWOCI_AUTH=()
if [[ "$AUTH" == "instance_principal" ]]; then
  CLI_AUTH+=(--auth instance_principal)
  SHOWOCI_AUTH+=(-ip)
else
  preflight_config_auth
  export OCI_CONFIG_FILE="$CONFIG_FILE"
  export OCI_CLI_CONFIG_FILE="$CONFIG_FILE"
  CLI_AUTH+=(--profile "$PROFILE" --config-file "$CONFIG_FILE")
  SHOWOCI_AUTH+=(-t "$PROFILE" -cf "$CONFIG_FILE")
fi

# Pass auth to embedded Python without lossy whitespace splitting.
export OCI_REPORT_AUTH="$AUTH"
export OCI_REPORT_PROFILE="$PROFILE"
export OCI_REPORT_CONFIG_FILE="$CONFIG_FILE"

run_oci_json() {
  oci "$@" "${CLI_AUTH[@]}" --output json
}

REGION_LIST=()
if [[ "$ALL_REGIONS" == "true" ]]; then
  echo ">>> Enumerating subscribed regions ..." >&2
  REGION_JSON="$(run_oci_json iam region-subscription list --all)" || {
    echo "ERROR: unable to enumerate subscribed regions." >&2
    exit 1
  }
  mapfile -t REGION_LIST < <(
    REGION_JSON="$REGION_JSON" "$PYTHON_BIN" - <<'PY'
import json, os
payload = json.loads(os.environ["REGION_JSON"])
for row in payload.get("data", []):
    name = row.get("region-name")
    if name:
        print(name)
PY
  )
  ((${#REGION_LIST[@]})) || { echo "ERROR: no subscribed regions returned." >&2; exit 1; }
else
  REGION_LIST=("$REGION")
fi

printf '%s\n' "============================================================" >&2
printf ' OCI STORAGE BACKUP REPORT (showoci + OCI CLI, READ-ONLY)\n' >&2
printf ' auth       : %s\n' "$AUTH" >&2
printf ' profile    : %s\n' "$PROFILE" >&2
printf ' regions    : %s\n' "${REGION_LIST[*]}" >&2
printf ' showoci    : %s\n' "$SHOWOCI" >&2
printf ' output dir : %s\n' "$OUTDIR" >&2
printf '%s\n' "============================================================" >&2

# Remove only this run's generated aggregate files. Inventory files are emitted
# with region-specific prefixes and checked after each showoci run.
POLICY_CSV="$OUTDIR/${PREFIX}_backup_policy_schedules.csv"
FSS_POLICY_CSV="$OUTDIR/${PREFIX}_fss_snapshot_schedules.csv"
JOINED_CSV="$OUTDIR/${PREFIX}_storage_backup_joined.csv"
rm -f -- "$POLICY_CSV" "$FSS_POLICY_CSV" "$JOINED_CSV"

# STEP 1: showoci is the primary collector.
echo ">>> STEP 1: showoci inventory" >&2
INVENTORY_PREFIXES=()
for rg in "${REGION_LIST[@]}"; do
  inv_prefix="$OUTDIR/${PREFIX}_${rg}"
  INVENTORY_PREFIXES+=("$inv_prefix")
  echo "    [showoci] $rg" >&2

  # Remove stale files for this exact regional prefix before collection.
  find "$OUTDIR" -maxdepth 1 -type f -name "${PREFIX}_${rg}_*.csv" -delete

  "$PYTHON_BIN" "$SHOWOCI" "${SHOWOCI_AUTH[@]}" -rg "$rg" -a -csv "$inv_prefix"

  shopt -s nullglob
  generated=("${inv_prefix}"_*.csv)
  shopt -u nullglob
  if ((${#generated[@]} == 0)); then
    echo "ERROR: showoci produced no CSV files for region $rg." >&2
    exit 1
  fi
done

# STEP 2/2b workers. Custom Block policies are compartment-scoped; Oracle-
# defined policies are returned by listing without --compartment-id.
echo ">>> STEP 2: Block/Boot and FSS policy schedules" >&2
export POLICY_CSV FSS_POLICY_CSV
printf '%s\n' 'region,compartment_id,policy_id,policy_name,schedule_status,backup_type,period,hour_of_day,day_of_week,day_of_month,month,retention_seconds,time_zone,collection_status,collection_error' > "$POLICY_CSV"
printf '%s\n' 'region,compartment_id,policy_id,policy_name,schedule_status,period,hour_of_day,day_of_week,day_of_month,month,retention_seconds,time_zone,collection_status,collection_error' > "$FSS_POLICY_CSV"

overall_rc=0
for rg in "${REGION_LIST[@]}"; do
  echo "    [policy enrichment] $rg" >&2
  if ! REGION_ARG="$rg" "$PYTHON_BIN" - <<'PY'; then
import csv
import json
import os
import subprocess
import sys
from typing import Any

region = os.environ["REGION_ARG"]
block_csv = os.environ["POLICY_CSV"]
fss_csv = os.environ["FSS_POLICY_CSV"]
auth_mode = os.environ.get("OCI_REPORT_AUTH", "config")
profile = os.environ.get("OCI_REPORT_PROFILE", "DEFAULT")
config_file = os.environ.get("OCI_REPORT_CONFIG_FILE", "")

auth_args: list[str] = []
if auth_mode == "instance_principal":
    auth_args = ["--auth", "instance_principal"]
else:
    auth_args = ["--profile", profile]
    if config_file:
        auth_args += ["--config-file", config_file]


def run_oci(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["oci", *args, *auth_args, "--output", "json"],
        capture_output=True,
        text=True,
        check=False,
    )


def parse_data(result: subprocess.CompletedProcess[str]) -> list[dict[str, Any]]:
    payload = json.loads(result.stdout or "{}")
    data = payload.get("data", [])
    return data if isinstance(data, list) else []


def clean_error(result: subprocess.CompletedProcess[str]) -> str:
    return (result.stderr or result.stdout or "command failed").strip().replace("\n", " ")[:500]

rc = 0

# include-root gives us the tenancy root explicitly. ACCESSIBLE avoids claiming
# that inaccessible compartments were fully assessed.
comp_result = run_oci(
    "iam", "compartment", "list",
    "--compartment-id-in-subtree", "true",
    "--include-root",
    "--access-level", "ACCESSIBLE",
    "--all",
    "--region", region,
)
if comp_result.returncode != 0:
    msg = clean_error(comp_result)
    with open(block_csv, "a", newline="", encoding="utf-8") as fh:
        csv.writer(fh).writerow([region, "", "", "", "", "", "", "", "", "", "", "", "", "COMPARTMENT_LIST_FAILED", msg])
    with open(fss_csv, "a", newline="", encoding="utf-8") as fh:
        csv.writer(fh).writerow([region, "", "", "", "", "", "", "", "", "", "", "", "COMPARTMENT_LIST_FAILED", msg])
    sys.exit(3)

try:
    compartments = parse_data(comp_result)
except (json.JSONDecodeError, TypeError) as exc:
    msg = str(exc)[:500]
    with open(block_csv, "a", newline="", encoding="utf-8") as fh:
        csv.writer(fh).writerow([region, "", "", "", "", "", "", "", "", "", "", "", "", "COMPARTMENT_PARSE_ERROR", msg])
    with open(fss_csv, "a", newline="", encoding="utf-8") as fh:
        csv.writer(fh).writerow([region, "", "", "", "", "", "", "", "", "", "", "", "COMPARTMENT_PARSE_ERROR", msg])
    sys.exit(3)

compartment_ids: list[str] = []
for compartment in compartments:
    cid = compartment.get("id")
    state = compartment.get("lifecycle-state")
    if cid and state != "DELETED" and cid not in compartment_ids:
        compartment_ids.append(cid)

# ---- Block/Boot policies ----
seen_policy_ids: set[str] = set()
block_rows = 0
with open(block_csv, "a", newline="", encoding="utf-8") as fh:
    writer = csv.writer(fh)

    scopes: list[tuple[str, list[str]]] = [("ORACLE_DEFINED", [])]
    scopes.extend((cid, ["--compartment-id", cid]) for cid in compartment_ids)

    for compartment_id, scope_args in scopes:
        listed = run_oci(
            "bv", "volume-backup-policy", "list", "--all",
            "--region", region,
            *scope_args,
        )
        if listed.returncode != 0:
            writer.writerow([region, compartment_id, "", "", "", "", "", "", "", "", "", "", "", "LIST_FAILED", clean_error(listed)])
            rc = 3
            continue
        try:
            policies = parse_data(listed)
        except (json.JSONDecodeError, TypeError) as exc:
            writer.writerow([region, compartment_id, "", "", "", "", "", "", "", "", "", "", "", "LIST_PARSE_ERROR", str(exc)[:500]])
            rc = 3
            continue

        for policy in policies:
            pid = policy.get("id", "")
            if not pid or pid in seen_policy_ids:
                continue
            seen_policy_ids.add(pid)
            pname = policy.get("display-name", "")
            detail = run_oci(
                "bv", "volume-backup-policy", "get",
                "--policy-id", pid,
                "--region", region,
            )
            if detail.returncode != 0:
                writer.writerow([region, compartment_id, pid, pname, "", "", "", "", "", "", "", "", "", "LOOKUP_FAILED", clean_error(detail)])
                rc = 3
                continue
            try:
                data = json.loads(detail.stdout or "{}").get("data", {}) or {}
            except json.JSONDecodeError as exc:
                writer.writerow([region, compartment_id, pid, pname, "", "", "", "", "", "", "", "", "", "GET_PARSE_ERROR", str(exc)[:500]])
                rc = 3
                continue
            schedules = data.get("schedules", []) or []
            if not schedules:
                writer.writerow([region, compartment_id, pid, pname, "NO_SCHEDULES", "", "", "", "", "", "", "", "", "OK", ""])
                block_rows += 1
                continue
            for schedule in schedules:
                writer.writerow([
                    region, compartment_id, pid, pname, "HAS_SCHEDULE",
                    schedule.get("backup-type", ""),
                    schedule.get("period", ""),
                    schedule.get("hour-of-day", ""),
                    schedule.get("day-of-week", ""),
                    schedule.get("day-of-month", ""),
                    schedule.get("month", ""),
                    schedule.get("retention-seconds", ""),
                    schedule.get("time-zone", ""),
                    "OK", "",
                ])
                block_rows += 1

    if block_rows == 0 and rc == 0:
        writer.writerow([region, "", "", "", "", "", "", "", "", "", "", "", "", "NO_POLICIES_RETURNED", ""])

# ---- FSS snapshot policies ----
fss_rows = 0
with open(fss_csv, "a", newline="", encoding="utf-8") as fh:
    writer = csv.writer(fh)
    for compartment_id in compartment_ids:
        listed = run_oci(
            "fs", "snapshot-policy", "list",
            "--compartment-id", compartment_id,
            "--all",
            "--region", region,
        )
        if listed.returncode != 0:
            writer.writerow([region, compartment_id, "", "", "", "", "", "", "", "", "", "", "COMPARTMENT_LIST_FAILED", clean_error(listed)])
            rc = 3
            continue
        try:
            policies = parse_data(listed)
        except (json.JSONDecodeError, TypeError) as exc:
            writer.writerow([region, compartment_id, "", "", "", "", "", "", "", "", "", "", "LIST_PARSE_ERROR", str(exc)[:500]])
            rc = 3
            continue

        for policy in policies:
            pid = policy.get("id", "")
            pname = policy.get("display-name", "")
            schedules = policy.get("schedules", []) or []
            if not schedules:
                writer.writerow([region, compartment_id, pid, pname, "NO_SCHEDULES", "", "", "", "", "", "", "", "OK", ""])
                fss_rows += 1
                continue
            for schedule in schedules:
                writer.writerow([
                    region, compartment_id, pid, pname, "HAS_SCHEDULE",
                    schedule.get("period", ""),
                    schedule.get("hour-of-day", ""),
                    schedule.get("day-of-week", ""),
                    schedule.get("day-of-month", ""),
                    schedule.get("month", ""),
                    schedule.get("retention-duration-in-seconds", ""),
                    schedule.get("time-zone", ""),
                    "OK", "",
                ])
                fss_rows += 1

    if fss_rows == 0 and rc == 0:
        writer.writerow([region, "", "", "", "", "", "", "", "", "", "", "", "NO_POLICIES_RETURNED", ""])

sys.exit(rc)
PY
    overall_rc=3
  fi
done

# STEP 3: Join showoci inventory with regional policy schedules. The join is
# intentionally conservative: absence of a detected policy field is not called
# "not backed up" without verification.
echo ">>> STEP 3: joined resource-level report" >&2
export OUTDIR PREFIX JOINED_CSV POLICY_CSV FSS_POLICY_CSV
if ! "$PYTHON_BIN" - <<'PY'; then
import csv
import glob
import os
import re
import sys
from collections import defaultdict

outdir = os.environ["OUTDIR"]
prefix = os.environ["PREFIX"]
joined = os.environ["JOINED_CSV"]


def load_schedules(path: str, block: bool):
    by_id = defaultdict(list)
    by_name = defaultdict(list)
    if not os.path.isfile(path):
        return by_id, by_name
    with open(path, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            if row.get("collection_status") != "OK":
                continue
            status = row.get("schedule_status", "")
            if status not in {"HAS_SCHEDULE", "NO_SCHEDULES"}:
                continue
            details = []
            if block and row.get("backup_type"):
                details.append(f"type={row['backup_type']}")
            for field, label in (
                ("period", "period"), ("hour_of_day", "hour"),
                ("day_of_week", "dow"), ("day_of_month", "dom"),
                ("month", "month"), ("retention_seconds", "retention_sec"),
                ("time_zone", "tz"),
            ):
                if row.get(field):
                    details.append(f"{label}={row[field]}")
            entry = (status, "; ".join(details) or status)
            region = row.get("region", "")
            pid = row.get("policy_id", "").strip()
            pname = row.get("policy_name", "").strip()
            if pid:
                by_id[(region, pid)].append(entry)
            if pname:
                by_name[(region, pname)].append(entry)
    return by_id, by_name


block_id, block_name = load_schedules(os.environ["POLICY_CSV"], True)
fss_id, fss_name = load_schedules(os.environ["FSS_POLICY_CSV"], False)


def find_column(headers, patterns):
    for pattern in patterns:
        rx = re.compile(pattern, re.I)
        for header in headers:
            if rx.search(header or ""):
                return header
    return None


def classify(filename, headers):
    name = filename.lower()
    header_text = " ".join(headers).lower()
    if any(token in name for token in ("backup_policy_schedules", "fss_snapshot_schedules", "storage_backup_joined")):
        return None, None
    if "boot" in name and "backup" not in name:
        return "Boot Volume", "block"
    if "block" in name and "backup" not in name:
        return "Block Volume", "block"
    if any(token in name for token in ("filesystem", "file_system", "fss")) or "snapshot policy" in header_text:
        return "File System (FSS)", "fss"
    if any(token in name for token in ("bucket", "object_storage", "objectstorage")):
        return "Object Storage Bucket", "object"
    return None, None


def lookup(region, pid, pname, by_id, by_name):
    entries = by_id.get((region, pid)) if pid else None
    if not entries and pname:
        entries = by_name.get((region, pname))
    if not entries:
        return "UNKNOWN", ""
    statuses = "|".join(sorted({item[0] for item in entries}))
    details = " || ".join(item[1] for item in entries if item[1])
    return statuses, details

headers_out = [
    "region", "compartment", "resource_type", "resource_name", "resource_id",
    "assigned_policy_name", "assigned_policy_id", "protection_type",
    "schedule_status", "schedule_detail", "notes", "source_file",
]
rows_out = []

for path in sorted(glob.glob(os.path.join(outdir, f"{prefix}_*_*.csv"))):
    base = os.path.basename(path)
    resource_type, family = classify(base, [])
    try:
        with open(path, newline="", encoding="utf-8-sig") as fh:
            reader = csv.DictReader(fh)
            headers = reader.fieldnames or []
            resource_type, family = classify(base, headers)
            if not family:
                continue
            rows = list(reader)
    except (OSError, csv.Error):
        continue

    c_region = find_column(headers, [r"^region$", r"region.?name"])
    c_comp = find_column(headers, [r"compartment.*name", r"^compartment$"])
    c_name = find_column(headers, [r"display.?name", r"^name$", r"bucket.?name", r"resource.?name"])
    c_id = find_column(headers, [r"^id$", r"\bocid\b", r"volume.?id", r"file.?system.?id"])
    c_pid = find_column(headers, [r"backup.*policy.*id", r"snapshot.*policy.*id", r"policy.*id"])
    c_pname = find_column(headers, [r"backup.*policy.*name", r"snapshot.*policy.*name", r"policy.*name", r"backup.*policy$"])
    c_version = find_column(headers, [r"versioning"])
    c_replication = find_column(headers, [r"replicat"])
    c_retention = find_column(headers, [r"retention"])

    region_match = re.match(re.escape(prefix) + r"_([^_]+(?:-[^_]+)*)_", base)
    filename_region = region_match.group(1) if region_match else ""

    for row in rows:
        region = (row.get(c_region, "") if c_region else "") or filename_region
        compartment = row.get(c_comp, "") if c_comp else ""
        name = row.get(c_name, "") if c_name else ""
        rid = row.get(c_id, "") if c_id else ""
        pid = (row.get(c_pid, "") if c_pid else "").strip()
        pname = (row.get(c_pname, "") if c_pname else "").strip()

        if family == "object":
            controls = []
            for column, label in ((c_version, "versioning"), (c_retention, "retention"), (c_replication, "replication")):
                if column and row.get(column):
                    controls.append(f"{label}={row[column]}")
            rows_out.append([
                region, compartment, resource_type, name, rid, "", "",
                "object-storage-controls", "N/A", "; ".join(controls),
                "Object Storage does not use Block Volume backup policies; verify versioning, retention rules, and replication independently.",
                base,
            ])
            continue

        by_id, by_name = (block_id, block_name) if family == "block" else (fss_id, fss_name)
        if not pid and not pname:
            status, detail = "NO_POLICY_REFERENCE_DETECTED", ""
            note = "No policy reference was detected in this showoci row. Verify the source CSV and actual policy assignment before concluding that the resource is unprotected."
        else:
            status, detail = lookup(region, pid, pname, by_id, by_name)
            note = "" if status != "UNKNOWN" else "Policy reference did not resolve to a successfully collected schedule in the same region. Check permissions, collection status, and CSV column mapping."
        rows_out.append([
            region, compartment, resource_type, name, rid, pname, pid,
            "policy-based", status, detail, note, base,
        ])

with open(joined, "w", newline="", encoding="utf-8") as fh:
    writer = csv.writer(fh)
    writer.writerow(headers_out)
    writer.writerows(rows_out)

print(f"    joined rows: {len(rows_out)}", file=sys.stderr)
if not rows_out:
    print("    WARNING: no storage inventory rows matched recognized showoci CSV patterns.", file=sys.stderr)
    sys.exit(3)
PY
  overall_rc=3
fi

printf '%s\n' "============================================================" >&2
printf ' DONE. Files in: %s\n' "$OUTDIR" >&2
printf '   %s_<region>_*.csv\n' "$PREFIX" >&2
printf '   %s\n' "$(basename "$POLICY_CSV")" >&2
printf '   %s\n' "$(basename "$FSS_POLICY_CSV")" >&2
printf '   %s\n' "$(basename "$JOINED_CSV")" >&2
if ((overall_rc != 0)); then
  printf ' WARNING: one or more enrichment/join steps were incomplete.\n' >&2
  printf ' Review collection_status and collection_error before findings.\n' >&2
fi
printf '%s\n' "============================================================" >&2
exit "$overall_rc"
