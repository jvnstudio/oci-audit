#!/usr/bin/env bash
#
# oci_backup_report.sh
# ====================
# Produces a storage BACKUP report for an OCI tenancy using ONLY:
#   1. Oracle's official showoci.py   (which storage exists + assigned policies + backups taken)
#   2. Oracle's official OCI CLI      (each backup policy's full schedule: type/period/retention)
#
# READ-ONLY: only list/get operations are used. Nothing in OCI is modified.
# All output is written to CSV files.
#
# Requirements:
#   - python3 + oci SDK           (pip install oci)
#   - showoci.py                  (oci-python-sdk/examples/showoci)
#   - oci CLI                     (for policy schedule detail; optional)
#   - a configured ~/.oci/config profile, or instance principals on an OCI VM
#
# Usage:
#   ./oci_backup_report.sh -p GOVCLOUD
#   ./oci_backup_report.sh -p GOVCLOUD -r us-langley-1
#   ./oci_backup_report.sh -i                       # instance-principal auth
#   ./oci_backup_report.sh -p GOVCLOUD -s /path/to/showoci.py -o /path/to/output
#

set -euo pipefail

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
PROFILE="DEFAULT"
AUTH="config"          # config | instance_principal
REGION=""
PREFIX="report"
OUTDIR="."
SHOWOCI=""             # auto-detected if empty

usage() {
  cat <<EOF
Usage: $0 [options]
  -p PROFILE   OCI config profile name (default: DEFAULT)
  -i           Use instance-principal auth instead of config file
  -r REGION    Limit to one region (default: all subscribed)
  -o DIR       Output directory (default: current folder)
  -x PREFIX    CSV filename prefix (default: report)
  -s PATH      Path to showoci.py (default: auto-detect)
  -h           Show this help
EOF
  exit 0
}

# ---------------------------------------------------------------------------
# Parse args
# ---------------------------------------------------------------------------
while getopts "p:ir:o:x:s:h" opt; do
  case "$opt" in
    p) PROFILE="$OPTARG" ;;
    i) AUTH="instance_principal" ;;
    r) REGION="$OPTARG" ;;
    o) OUTDIR="$OPTARG" ;;
    x) PREFIX="$OPTARG" ;;
    s) SHOWOCI="$OPTARG" ;;
    h) usage ;;
    *) usage ;;
  esac
done

mkdir -p "$OUTDIR"

# ---------------------------------------------------------------------------
# Locate showoci.py
# ---------------------------------------------------------------------------
if [[ -z "$SHOWOCI" ]]; then
  for cand in "./showoci.py" "$(dirname "$0")/showoci.py" \
              "$HOME/oci-python-sdk/examples/showoci/showoci.py"; do
    if [[ -f "$cand" ]]; then SHOWOCI="$cand"; break; fi
  done
fi
if [[ -z "$SHOWOCI" || ! -f "$SHOWOCI" ]]; then
  echo "ERROR: showoci.py not found. Pass it with -s /path/to/showoci.py" >&2
  exit 1
fi

echo "============================================================" >&2
echo " OCI STORAGE BACKUP REPORT  (READ-ONLY)" >&2
echo "   profile : $PROFILE" >&2
echo "   auth    : $AUTH" >&2
echo "   region  : ${REGION:-all subscribed}" >&2
echo "   showoci : $SHOWOCI" >&2
echo "   output  : $OUTDIR/${PREFIX}_*.csv" >&2
echo "============================================================" >&2

# ---------------------------------------------------------------------------
# Build auth flags for showoci and CLI
# ---------------------------------------------------------------------------
SHOWOCI_AUTH=()
CLI_AUTH=()
if [[ "$AUTH" == "instance_principal" ]]; then
  SHOWOCI_AUTH+=("-ip")
  CLI_AUTH+=("--auth" "instance_principal")
else
  SHOWOCI_AUTH+=("-t" "$PROFILE")
  CLI_AUTH+=("--profile" "$PROFILE")
fi

SHOWOCI_REGION=()
[[ -n "$REGION" ]] && SHOWOCI_REGION+=("-rg" "$REGION")

# ---------------------------------------------------------------------------
# STEP 1 — showoci: storage inventory + assigned policies + backups taken
# ---------------------------------------------------------------------------
echo "" >&2
echo ">>> STEP 1: running showoci.py ..." >&2
python3 "$SHOWOCI" "${SHOWOCI_AUTH[@]}" "${SHOWOCI_REGION[@]}" \
  -a -csv "${OUTDIR}/${PREFIX}"
echo ">>> showoci CSVs written: ${OUTDIR}/${PREFIX}_*.csv" >&2

# ---------------------------------------------------------------------------
# STEP 2 — OCI CLI: dump every backup policy's full schedule (type/period/retention)
# ---------------------------------------------------------------------------
POLICY_CSV="${OUTDIR}/${PREFIX}_backup_policy_schedules.csv"

if command -v oci >/dev/null 2>&1; then
  echo "" >&2
  echo ">>> STEP 2: exporting backup POLICY SCHEDULES via OCI CLI ..." >&2

  # header
  echo "policy_id,policy_name,backup_type,period,hour_of_day,day_of_week,day_of_month,month,retention_seconds,time_zone" > "$POLICY_CSV"

  # List all volume backup policies (predefined + user), then expand each schedule.
  # j-based flattening via --query keeps it pure-CLI, no extra .py files.
  export POLICY_CSV
  export CLI_AUTH_STR="${CLI_AUTH[*]}"
  oci bv volume-backup-policy list "${CLI_AUTH[@]}" --all \
    --query "data[].{id:id,name:\"display-name\"}" --output json 2>/dev/null \
  | python3 -c '
import sys, json, csv, subprocess, os
try:
    policies = json.load(sys.stdin) or []
except Exception:
    policies = []
auth = os.environ.get("CLI_AUTH_STR","").split()
w = csv.writer(open(os.environ["POLICY_CSV"], "a", newline=""))
for pol in policies:
    pid = pol.get("id"); pname = pol.get("name","")
    try:
        out = subprocess.run(
            ["oci","bv","volume-backup-policy","get","--policy-id",pid,
             "--output","json",*auth],
            capture_output=True, text=True, check=True)
        data = json.loads(out.stdout).get("data",{})
    except Exception:
        continue
    for s in data.get("schedules",[]) or []:
        w.writerow([pid, pname,
            s.get("backup-type",""), s.get("period",""),
            s.get("hour-of-day",""), s.get("day-of-week",""),
            s.get("day-of-month",""), s.get("month",""),
            s.get("retention-seconds",""), s.get("time-zone","")])
' 2>/dev/null || echo "   (note: policy schedule export skipped — CLI query returned nothing)" >&2

  echo ">>> policy schedules written: $POLICY_CSV" >&2
else
  echo "" >&2
  echo ">>> STEP 2 SKIPPED: 'oci' CLI not installed." >&2
  echo "    showoci CSVs still contain volumes + assigned policy names + backups taken." >&2
  echo "    Install OCI CLI to also export full policy schedules." >&2
fi

echo "" >&2
echo "============================================================" >&2
echo " DONE. Report files in: $(cd "$OUTDIR" && pwd)" >&2
echo "   ${PREFIX}_*.csv                         (showoci: storage + backups)" >&2
[[ -f "$POLICY_CSV" ]] && echo "   ${PREFIX}_backup_policy_schedules.csv   (policy type/period/retention)" >&2
echo "============================================================" >&2
