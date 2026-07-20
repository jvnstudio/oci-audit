#!/usr/bin/env bash
#
# oci_backup_report.sh
# ====================
# Storage backup report for an OCI tenancy using ONLY:
#   1. showoci.py  (Oracle-MAINTAINED SDK example; NOT an official/supported
#      Oracle product) — storage inventory + assigned policies + backups taken
#   2. OCI CLI     (oci bv volume-backup-policy list/get) — each Block/Boot
#      Volume backup policy's full schedule: type/period/retention
#
# READ-ONLY AGAINST OCI: only list/get operations are used; no OCI resource is
# modified. NOTE: this script DOES create and may OVERWRITE local CSV files.
# The OCI read-only guarantee for Step 1 also depends on you supplying an
# unmodified, reviewed showoci.py.
#
# SCOPE LIMITS (be honest for audit use):
#   - Step 2 covers Block and Boot Volume policies ONLY. It does NOT cover
#     File Storage snapshot policies, Object Storage retention/versioning/
#     replication, ADB/Base DB backup config, or Recovery Service policies.
#   - A schedule proves INTENT, not that backups actually ran or are restorable.
#   - Policy schedules are emitted to a separate CSV; correlate them to
#     resources using the assigned policy id/name in showoci's CSVs.
#
# Requirements: python3 + oci SDK (showoci), oci CLI (Step 2), a configured
# ~/.oci/config profile OR instance principals on an OCI VM.
#
# Usage:
#   ./oci_backup_report.sh -p GOVCLOUD -r us-langley-1     # one region (recommended)
#   ./oci_backup_report.sh -p GOVCLOUD --all-regions       # iterate subscribed regions
#   ./oci_backup_report.sh -i -r us-langley-1              # instance-principal auth
#   ./oci_backup_report.sh -p GOVCLOUD -r us-langley-1 -f ~/.oci/config -s /path/showoci.py -o out

set -euo pipefail

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
PROFILE="DEFAULT"
AUTH="config"          # config | instance_principal
REGION=""
ALL_REGIONS="false"
PREFIX="report"
OUTDIR="."
SHOWOCI=""
CONFIG_FILE=""

usage() {
  cat <<EOF
Usage: $0 [options]
  -p PROFILE      OCI config profile name (default: DEFAULT)
  -i              Use instance-principal auth instead of config file
  -r REGION       Report a single region (recommended for consistent evidence)
  --all-regions   Iterate every subscribed region for Step 2 (stronger evidence)
  -f FILE         OCI config file path (default: ~/.oci/config)
  -o DIR          Output directory (default: current folder)
  -x PREFIX       CSV filename stem, no path (default: report)
  -s PATH         Path to showoci.py (default: auto-detect)
  -h              Show this help

You must pass EITHER -r REGION or --all-regions so that showoci scope and the
policy-schedule export scope match. Running neither is refused, because it would
produce a multi-region inventory with a single-region schedule export.
EOF
  exit 0
}

# ---------------------------------------------------------------------------
# Parse args (long option --all-regions handled manually)
# ---------------------------------------------------------------------------
ARGS=()
for a in "$@"; do
  case "$a" in
    --all-regions) ALL_REGIONS="true" ;;
    *) ARGS+=("$a") ;;
  esac
done
set -- "${ARGS[@]:-}"

while getopts "p:ir:f:o:x:s:h" opt; do
  case "$opt" in
    p) PROFILE="$OPTARG" ;;
    i) AUTH="instance_principal" ;;
    r) REGION="$OPTARG" ;;
    f) CONFIG_FILE="$OPTARG" ;;
    o) OUTDIR="$OPTARG" ;;
    x) PREFIX="$OPTARG" ;;
    s) SHOWOCI="$OPTARG" ;;
    h) usage ;;
    *) usage ;;
  esac
done

# ---------------------------------------------------------------------------
# Validate scope + prefix
# ---------------------------------------------------------------------------
if [[ -z "$REGION" && "$ALL_REGIONS" != "true" ]]; then
  echo "ERROR: pass -r REGION (single region) or --all-regions." >&2
  echo "       Refusing to run so inventory scope and schedule scope stay aligned." >&2
  exit 2
fi
if [[ -n "$REGION" && "$ALL_REGIONS" == "true" ]]; then
  echo "ERROR: use either -r REGION or --all-regions, not both." >&2
  exit 2
fi
if [[ "$PREFIX" != "$(basename "$PREFIX")" ]]; then
  echo "ERROR: -x prefix must be a filename stem with no path component." >&2
  exit 2
fi

mkdir -p "$OUTDIR"

# ---------------------------------------------------------------------------
# Locate showoci.py
# ---------------------------------------------------------------------------
if [[ -z "$SHOWOCI" ]]; then
  for cand in "./showoci.py" "$(dirname "$0")/showoci.py" \
              "$HOME/oci-python-sdk/examples/showoci/showoci.py"; do
    [[ -f "$cand" ]] && { SHOWOCI="$cand"; break; }
  done
fi
if [[ -z "$SHOWOCI" || ! -f "$SHOWOCI" ]]; then
  echo "ERROR: showoci.py not found. Pass it with -s /path/to/showoci.py" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Auth arrays
# ---------------------------------------------------------------------------
SHOWOCI_AUTH=(); CLI_AUTH=()
if [[ "$AUTH" == "instance_principal" ]]; then
  SHOWOCI_AUTH+=("-ip")
  CLI_AUTH+=("--auth" "instance_principal")
else
  SHOWOCI_AUTH+=("-t" "$PROFILE")
  CLI_AUTH+=("--profile" "$PROFILE")
  if [[ -n "$CONFIG_FILE" ]]; then
    SHOWOCI_AUTH+=("-cf" "$CONFIG_FILE")
    CLI_AUTH+=("--config-file" "$CONFIG_FILE")
  fi
fi

echo "============================================================" >&2
echo " OCI STORAGE BACKUP REPORT  (READ-ONLY AGAINST OCI)" >&2
echo "   profile     : $PROFILE" >&2
echo "   auth        : $AUTH" >&2
if [[ "$ALL_REGIONS" == "true" ]]; then
  echo "   region      : ALL SUBSCRIBED (Step 2 iterates)" >&2
else
  echo "   region      : $REGION" >&2
fi
echo "   showoci     : $SHOWOCI (Oracle-maintained SDK example; not a supported product)" >&2
echo "   output      : $OUTDIR/${PREFIX}_*.csv" >&2
echo "   note        : creates/overwrites local CSVs; Step 2 = Block/Boot Volume policies only" >&2
echo "============================================================" >&2

# ---------------------------------------------------------------------------
# Determine region list
# ---------------------------------------------------------------------------
REGION_LIST=()
if [[ "$ALL_REGIONS" == "true" ]]; then
  echo "" >&2; echo ">>> Enumerating subscribed regions ..." >&2
  if ! command -v oci >/dev/null 2>&1; then
    echo "ERROR: --all-regions needs the OCI CLI to list subscriptions." >&2
    exit 1
  fi
  # region subscription list is read-only
  _REG_JSON="$(oci iam region-subscription list "${CLI_AUTH[@]}" --output json 2>/dev/null || true)"
  mapfile -t REGION_LIST < <(REG_JSON="$_REG_JSON" python3 -c '
import os, json, sys
try:
    d = json.loads(os.environ.get("REG_JSON") or "{}")
except Exception:
    sys.exit(0)
rows = d.get("data", d) if isinstance(d, dict) else d
for r in (rows or []):
    name = r.get("region-name") if isinstance(r, dict) else r
    if name:
        print(name)
')
  if [[ ${#REGION_LIST[@]} -eq 0 ]]; then
    echo "ERROR: could not enumerate subscribed regions (auth/permission?)." >&2
    exit 1
  fi
  echo "    regions: ${REGION_LIST[*]}" >&2
else
  REGION_LIST=("$REGION")
fi

# ---------------------------------------------------------------------------
# STEP 1 — showoci inventory (per region so scope matches Step 2)
# ---------------------------------------------------------------------------
echo "" >&2; echo ">>> STEP 1: showoci inventory ..." >&2
for rg in "${REGION_LIST[@]}"; do
  echo "    [showoci] region $rg" >&2
  # Per-region prefix keeps evidence separable and scope-aligned with Step 2.
  python3 "$SHOWOCI" "${SHOWOCI_AUTH[@]}" -rg "$rg" -a \
    -csv "${OUTDIR}/${PREFIX}_${rg}"
done
echo ">>> showoci CSVs: ${OUTDIR}/${PREFIX}_<region>_*.csv" >&2

# ---------------------------------------------------------------------------
# STEP 2 — Block/Boot Volume backup policy schedules, PER REGION, with status
# ---------------------------------------------------------------------------
POLICY_CSV="${OUTDIR}/${PREFIX}_backup_policy_schedules.csv"

if ! command -v oci >/dev/null 2>&1; then
  echo "" >&2
  echo ">>> STEP 2 SKIPPED: 'oci' CLI not installed." >&2
  echo "    showoci CSVs still contain volumes + assigned policy names + backups taken." >&2
  echo "============================================================" >&2
  echo " DONE (Step 1 only). Files in: $(cd "$OUTDIR" && pwd)" >&2
  echo "============================================================" >&2
  exit 0
fi

echo "" >&2; echo ">>> STEP 2: backup POLICY SCHEDULES via OCI CLI (per region) ..." >&2

# Header includes region + explicit collection status columns.
echo "region,policy_id,policy_name,schedule_status,backup_type,period,hour_of_day,day_of_week,day_of_month,month,retention_seconds,time_zone,collection_status,collection_error" > "$POLICY_CSV"

# Export vars for the per-region Python worker.
export POLICY_CSV
export CLI_AUTH_STR="${CLI_AUTH[*]}"

overall_rc=0
for rg in "${REGION_LIST[@]}"; do
  echo "    [policies] region $rg" >&2
  REGION_ARG="$rg" python3 <<'PYEOF'
import os, sys, json, csv, subprocess

region   = os.environ["REGION_ARG"]
csv_path = os.environ["POLICY_CSV"]
auth     = os.environ.get("CLI_AUTH_STR", "").split()

def run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True)

# 1) list policies for THIS region (region explicitly passed)
list_cmd = ["oci", "bv", "volume-backup-policy", "list", "--all",
            "--region", region, "--output", "json", *auth]
r = run(list_cmd)

with open(csv_path, "a", newline="", encoding="utf-8") as fh:
    w = csv.writer(fh)

    if r.returncode != 0:
        err = (r.stderr or "").strip().replace("\n", " ")[:300] or "list failed"
        w.writerow([region, "", "", "", "", "", "", "", "", "", "", "",
                    "LIST_FAILED", err])
        sys.exit(3)

    try:
        policies = (json.loads(r.stdout or "{}") or {}).get("data", []) or []
    except json.JSONDecodeError as e:
        w.writerow([region, "", "", "", "", "", "", "", "", "", "", "",
                    "LIST_PARSE_ERROR", str(e)[:300]])
        sys.exit(3)

    if not policies:
        w.writerow([region, "", "", "", "", "", "", "", "", "", "", "",
                    "NO_POLICIES_RETURNED", ""])
        sys.exit(0)

    rc = 0
    for pol in policies:
        pid   = pol.get("id", "")
        pname = pol.get("display-name", "")

        g = run(["oci", "bv", "volume-backup-policy", "get",
                 "--policy-id", pid, "--region", region,
                 "--output", "json", *auth])
        if g.returncode != 0:
            err = (g.stderr or "").strip().replace("\n", " ")[:300] or "get failed"
            w.writerow([region, pid, pname, "", "", "", "", "", "", "", "", "",
                        "LOOKUP_FAILED", err])
            rc = 3
            continue

        try:
            data = (json.loads(g.stdout or "{}") or {}).get("data", {}) or {}
        except json.JSONDecodeError as e:
            w.writerow([region, pid, pname, "", "", "", "", "", "", "", "", "",
                        "GET_PARSE_ERROR", str(e)[:300]])
            rc = 3
            continue

        scheds = data.get("schedules", []) or []
        if not scheds:
            # preserve one row so "exists w/ zero schedules" is distinguishable
            w.writerow([region, pid, pname, "NO_SCHEDULES",
                        "", "", "", "", "", "", "", "", "OK", ""])
            continue

        for s in scheds:
            w.writerow([
                region, pid, pname, "HAS_SCHEDULE",
                s.get("backup-type", ""), s.get("period", ""),
                s.get("hour-of-day", ""), s.get("day-of-week", ""),
                s.get("day-of-month", ""), s.get("month", ""),
                s.get("retention-seconds", ""), s.get("time-zone", ""),
                "OK", "",
            ])
    sys.exit(rc)
PYEOF
  rc=$?
  [[ $rc -ne 0 ]] && overall_rc=$rc
done

echo ">>> policy schedules: $POLICY_CSV" >&2

echo "" >&2
echo "============================================================" >&2
echo " DONE. Files in: $(cd "$OUTDIR" && pwd)" >&2
echo "   ${PREFIX}_<region>_*.csv                 (showoci inventory + backups)" >&2
echo "   ${PREFIX}_backup_policy_schedules.csv    (Block/Boot policy schedules + status)" >&2
if [[ $overall_rc -ne 0 ]]; then
  echo "" >&2
  echo " WARNING: one or more collection steps failed. Check the" >&2
  echo "          collection_status column before drawing conclusions." >&2
fi
echo "============================================================" >&2
exit $overall_rc
