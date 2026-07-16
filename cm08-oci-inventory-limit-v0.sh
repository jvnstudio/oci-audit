#!/usr/bin/env bash
#
# oci-limits-audit.sh
# Read-only inventory of OCI service limits, usage, availability, and quota
# policies across a tenancy. Writes CSV evidence and prints an aligned table.
#
# IMPORTANT — what the labels DO and DO NOT mean:
#   A positive service limit is a RESOURCE ALLOWANCE set by Oracle. It is NOT
#   proof that a service is enabled, that a resource is provisioned, or that
#   physical/AD capacity exists. This script therefore reports FACTUAL limit
#   states, not "active service" conclusions:
#     POSITIVE-LIMIT       limit value is a number > 0
#     ZERO-LIMIT           limit value is exactly 0
#     NON-INTEGER-VALUE    value present but not a plain integer (e.g. 1.0)
#     NO-VALUE-RETURNED    limits value list returned nothing (see collect_status)
#
#   Usage/availability come from the OCI Resource Availability API, which does
#   NOT support every limit. Unreported fields are shown as NOT-REPORTED, never
#   silently treated as zero. OCI-reported "available" already accounts for
#   limits, usage, and applicable quotas — it is not simply (limit - usage).
#
#   The console LIMIT_VALUE column is the tenancy SERVICE LIMIT, not a quota.
#   Compartment quotas are listed separately (quotas.csv) and are NOT
#   reconciled to individual limits.
#
# This script is READ-ONLY against OCI. It only creates a local output dir/CSVs.
# OCI operations used: iam compartment list/get, iam region-subscription list,
#   limits service list, limits definition list, limits value list,
#   limits resource-availability get, limits quota list, limits quota get.
#
# Requires: OCI CLI (configured), jq
#
# Usage:
#   ./oci-limits-audit.sh [-t <tenancy_ocid>] [-r "us-langley-1,us-luke-1"] [-s <service>] [-o out_dir] [-a] [-p profile]
#
#   -t  Tenancy OCID   (default: resolved from profile config)
#   -r  Comma list of regions to scan (takes PRECEDENCE over -a; default: home region)
#   -s  Restrict to a single service (e.g. compute, block-storage, vcn)
#   -a  Scan ALL subscribed regions (ignored if -r is given)
#   -o  Output directory (default: ./oci-limits-<timestamp>)
#   -p  OCI CLI profile (default: DEFAULT)
#   -h  Help
#
set -euo pipefail

PROFILE="DEFAULT"
TENANCY=""
REGIONS=""
SERVICE_FILTER=""
ALL_REGIONS=false
OUT_DIR="./oci-limits-$(date +%Y%m%d-%H%M%S)"

usage() { grep '^#' "$0" | sed 's/^#//'; exit 0; }

while getopts "t:r:s:ao:p:h" opt; do
  case "$opt" in
    t) TENANCY="$OPTARG" ;;
    r) REGIONS="$OPTARG" ;;
    s) SERVICE_FILTER="$OPTARG" ;;
    a) ALL_REGIONS=true ;;
    o) OUT_DIR="$OPTARG" ;;
    p) PROFILE="$OPTARG" ;;
    h) usage ;;
    *) usage ;;
  esac
done

command -v oci >/dev/null 2>&1 || { echo "ERROR: OCI CLI not found." >&2; exit 1; }
command -v jq  >/dev/null 2>&1 || { echo "ERROR: jq not found." >&2; exit 1; }

# Command array (safe against spaces/metacharacters in profile name)
OCI=(oci --profile "$PROFILE")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# csv_field: emit a CSV-safe, always-quoted field (handles commas, quotes, newlines)
csv_field() {
  local s=${1-}
  s=${s//\"/\"\"}          # escape embedded quotes
  s=${s//$'\n'/ }          # flatten newlines so records stay single-line
  s=${s//$'\r'/ }
  printf '"%s"' "$s"
}

# classify_value: factual state for a limit value (no "active service" claim)
classify_value() {
  local v=${1-}
  if [[ "$v" =~ ^[0-9]+$ ]]; then
    if (( v > 0 )); then echo "POSITIVE-LIMIT"; else echo "ZERO-LIMIT"; fi
  elif [[ -z "$v" || "$v" == "null" ]]; then
    echo "NO-VALUE-RETURNED"
  else
    echo "NON-INTEGER-VALUE"
  fi
}

# Resolve tenancy OCID from the SELECTED profile's config (not first line anywhere)
if [[ -z "$TENANCY" ]]; then
  CFG="${OCI_CLI_CONFIG_FILE:-$HOME/.oci/config}"
  if [[ -f "$CFG" ]]; then
    # Extract tenancy from the [PROFILE] stanza only
    TENANCY=$(awk -v prof="[$PROFILE]" '
      $0==prof {inblk=1; next}
      /^\[/    {inblk=0}
      inblk && $1 ~ /^tenancy/ {sub(/^[^=]*=[[:space:]]*/,""); gsub(/[[:space:]]/,""); print; exit}
    ' "$CFG")
  fi
fi
[[ -z "$TENANCY" ]] && { echo "ERROR: Could not determine tenancy OCID for profile '$PROFILE'. Use -t." >&2; exit 1; }

# Confirm the OCID is the root tenancy (defensive; non-fatal)
if ! "${OCI[@]}" iam tenancy get --tenancy-id "$TENANCY" >/dev/null 2>&1; then
  echo "WARN: could not verify '$TENANCY' as a root tenancy (continuing)." >&2
fi

mkdir -p "$OUT_DIR"
echo "Profile : $PROFILE"
echo "Tenancy : $TENANCY"
echo "Output  : $OUT_DIR"

# Determine regions to scan. -r takes precedence over -a (documented above).
if [[ -n "$REGIONS" ]]; then
  IFS=',' read -r -a RAW <<< "$REGIONS"
  REGION_LIST=()
  for r in "${RAW[@]}"; do
    r="${r#"${r%%[![:space:]]*}"}"; r="${r%"${r##*[![:space:]]}"}"  # trim
    [[ -n "$r" ]] && REGION_LIST+=("$r")
  done
  $ALL_REGIONS && echo "NOTE: -r supplied; -a ignored."
elif $ALL_REGIONS; then
  mapfile -t REGION_LIST < <("${OCI[@]}" iam region-subscription list \
      --tenancy-id "$TENANCY" --all 2>/dev/null | jq -r '.data[]."region-name"')
else
  HOME_REGION=$("${OCI[@]}" iam region-subscription list --tenancy-id "$TENANCY" --all 2>/dev/null \
      | jq -r '.data[] | select(."is-home-region"==true) | ."region-name"')
  REGION_LIST=("$HOME_REGION")
fi
[[ ${#REGION_LIST[@]} -eq 0 ]] && { echo "ERROR: no regions resolved." >&2; exit 1; }

echo "Regions : ${REGION_LIST[*]}"
echo

# ---------------------------------------------------------------------------
# Per-region limits / usage / availability
# ---------------------------------------------------------------------------
LIMIT_HDR="service,limit_name,description,scope_type,availability_domain,limit_value,usage,available,limit_state,collect_status"

for REGION in "${REGION_LIST[@]}"; do
  echo "==================================================================="
  echo "REGION: $REGION"
  echo "==================================================================="
  ROCI=("${OCI[@]}" --region "$REGION")
  CSV="$OUT_DIR/limits-${REGION}.csv"
  echo "$LIMIT_HDR" > "$CSV"

  # Aligned console table. LIMIT_VALUE is the service limit, NOT a quota.
  TBL_FMT="%-22s %-32s %-8s %-11s %-12s %-12s %-18s\n"
  printf "$TBL_FMT" "SERVICE" "LIMIT" "SCOPE" "LIMIT_VALUE" "USAGE" "AVAILABLE" "LIMIT_STATE"
  printf "$TBL_FMT" "----------------------" "--------------------------------" \
         "--------" "-----------" "------------" "------------" "------------------"

  # 1. Services that expose limits
  if ! SERVICES=$("${ROCI[@]}" limits service list --compartment-id "$TENANCY" --all 2>/dev/null \
                  | jq -r '.data[].name'); then
    echo "  ERROR: could not list limit services in $REGION (access/API); skipping region." >&2
    continue
  fi

  for SVC in $SERVICES; do
    [[ -n "$SERVICE_FILTER" && "$SVC" != "$SERVICE_FILTER" ]] && continue
    echo "  -> service: $SVC"

    # 2. Limit definitions
    if ! DEFS=$("${ROCI[@]}" limits definition list --compartment-id "$TENANCY" \
                --service-name "$SVC" --all 2>/dev/null); then
      printf '%s,,%s,,,,,,,%s\n' "$SVC" "$(csv_field "definition list failed")" "ACCESS-OR-API-ERROR" >> "$CSV"
      continue
    fi

    jq -c '.data[]' <<< "$DEFS" | while read -r DEF; do
      LNAME=$(jq -r '.name'          <<< "$DEF")
      LDESC=$(jq -r '.description'   <<< "$DEF")
      LSCOPE=$(jq -r '."scope-type"' <<< "$DEF")

      # 3. Limit value(s) — capture success/failure distinctly
      if VALS=$("${ROCI[@]}" limits value list --compartment-id "$TENANCY" \
                --service-name "$SVC" --name "$LNAME" --all 2>/dev/null); then
        VAL_OK=1
      else
        VAL_OK=0; VALS='{"data":[]}'
      fi

      COUNT=$(jq '.data | length' <<< "$VALS")
      if [[ "$COUNT" -eq 0 ]]; then
        if [[ "$VAL_OK" -eq 1 ]]; then CSTAT="NO-DATA"; else CSTAT="ACCESS-OR-API-ERROR"; fi
        printf '%s,%s,%s,%s,,,,,%s,%s\n' \
          "$SVC" "$(csv_field "$LNAME")" "$(csv_field "$LDESC")" "$(csv_field "$LSCOPE")" \
          "NO-VALUE-RETURNED" "$CSTAT" >> "$CSV"
        printf "$TBL_FMT" "$SVC" "${LNAME:0:32}" "$LSCOPE" "-" "-" "-" "NO-VALUE-RETURNED"
        continue
      fi

      jq -c '.data[]' <<< "$VALS" | while read -r V; do
        AD=$(jq -r '."availability-domain" // ""' <<< "$V")
        LVAL=$(jq -r '.value // ""' <<< "$V")
        LSTATE=$(classify_value "$LVAL")

        # 4. Usage / availability. NOT supported for every limit -> NOT-REPORTED.
        if USE=$("${ROCI[@]}" limits resource-availability get \
                  --compartment-id "$TENANCY" --service-name "$SVC" \
                  --limit-name "$LNAME" ${AD:+--availability-domain "$AD"} 2>/dev/null); then
          USED=$(jq -r '.data.used // empty'      <<< "$USE")
          AVAIL=$(jq -r '.data.available // empty' <<< "$USE")
          RA_STAT="OK"
        else
          USED=""; AVAIL=""; RA_STAT="AVAILABILITY-NOT-REPORTED"
        fi
        USED_DISP=${USED:-NOT-REPORTED}
        AVAIL_DISP=${AVAIL:-NOT-REPORTED}

        printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
          "$SVC" "$(csv_field "$LNAME")" "$(csv_field "$LDESC")" "$(csv_field "$LSCOPE")" \
          "$(csv_field "$AD")" "$(csv_field "$LVAL")" "$(csv_field "$USED_DISP")" \
          "$(csv_field "$AVAIL_DISP")" "$LSTATE" "$RA_STAT" >> "$CSV"

        printf "$TBL_FMT" "$SVC" "${LNAME:0:32}" "${LSCOPE:0:8}" \
          "${LVAL:-"-"}" "${USED_DISP:0:12}" "${AVAIL_DISP:0:12}" "$LSTATE"
      done
    done
  done
  echo "  wrote: $CSV"
  echo
done

# ---------------------------------------------------------------------------
# Compartment quota policies (listed, NOT reconciled to individual limits)
# ---------------------------------------------------------------------------
echo "==================================================================="
echo "QUOTA POLICIES (compartment quotas — not reconciled to limits)"
echo "==================================================================="
QCSV="$OUT_DIR/quotas.csv"
echo "quota_name,description,compartment_id,lifecycle_state,statements" > "$QCSV"

QTBL_FMT="%-28s %-16s %s\n"
printf "$QTBL_FMT" "QUOTA" "LIFECYCLE-STATE" "STATEMENTS (truncated)"
printf "$QTBL_FMT" "----------------------------" "----------------" "----------------------"

if QLIST=$("${OCI[@]}" limits quota list --compartment-id "$TENANCY" --all 2>/dev/null); then
  jq -c '.data[]?' <<< "$QLIST" | while read -r Q; do
    QID=$(jq -r '.id'   <<< "$Q")
    QN=$(jq -r '.name'  <<< "$Q")
    QD=$(jq -r '.description' <<< "$Q")
    QC=$(jq -r '."compartment-id"' <<< "$Q")
    QS=$(jq -r '."lifecycle-state"' <<< "$Q")   # factual OCI lifecycle state
    STMT=$("${OCI[@]}" limits quota get --quota-id "$QID" 2>/dev/null \
           | jq -r '(.data.statements // []) | join(" | ")' || echo "")
    printf '%s,%s,%s,%s,%s\n' \
      "$(csv_field "$QN")" "$(csv_field "$QD")" "$(csv_field "$QC")" \
      "$(csv_field "$QS")" "$(csv_field "$STMT")" >> "$QCSV"
    printf "$QTBL_FMT" "${QN:0:28}" "$QS" "${STMT:0:60}"
  done
else
  echo "  ERROR: could not list quota policies (access/API)." >&2
fi
echo "  wrote: $QCSV"

echo
echo "Done. Results in: $OUT_DIR"
echo
echo "Label meanings (see header for detail):"
echo "  limit_state:  POSITIVE-LIMIT | ZERO-LIMIT | NON-INTEGER-VALUE | NO-VALUE-RETURNED"
echo "  usage/avail:  OCI-reported; NOT-REPORTED where the Resource Availability API"
echo "                does not support the limit. 'available' already reflects limits,"
echo "                usage, and applicable quotas — not simply limit minus usage."
echo "  lifecycle-state on a quota policy means the POLICY resource is ACTIVE; it does"
echo "  NOT prove each statement is valid or effective."
echo
echo "A POSITIVE-LIMIT is an ALLOWANCE, not proof a service is enabled, provisioned,"
echo "or has deployable AD/physical capacity."
