#!/usr/bin/env bash
#
# oci-limits-audit.sh  (CSV-writing fix)
# Read-only inventory of OCI service limits, usage, availability, and quota
# policies across a tenancy. Writes CSV evidence and prints an aligned table.
#
# WHAT WAS FIXED (why the CSV was empty / missing before):
#   * Removed `set -e`. The row-writing happened inside nested
#     `jq ... | while read` SUBSHELLS. Under `set -e` + `pipefail`, any
#     non-zero return anywhere in those pipelines (a jq hiccup, an oci call
#     that returns non-zero even with stderr suppressed, an unsupported
#     availability lookup) aborted the whole script BEFORE the CSV finished —
#     often before the "wrote: $CSV" line — with no visible error because
#     stderr was sent to /dev/null. Result: no file, or header-only file.
#   * Replaced pipe-into-while (`... | while read`) with process-substitution
#     (`while read ...; done < <(...)`) so loops run in the CURRENT shell,
#     not a subshell, and a single bad record can't silently drop the rest.
#   * Every oci/jq call now has an explicit fallback so one failure degrades
#     to a labelled row instead of killing the run.
#   * `set -u` kept (catches unset vars); `pipefail` kept only where safe.
#
# READ-ONLY against OCI. Creates a local output dir/CSVs only.
#
# Requires: OCI CLI (configured), jq
#
# Usage:
#   ./oci-limits-audit.sh [-t <tenancy_ocid>] [-r "us-langley-1,us-luke-1"] [-s <service>] [-o out_dir] [-a] [-p profile]
#     -t tenancy OCID  -r regions csv  -s single service  -a all regions
#     -o out dir       -p profile      -h help
#
set -uo pipefail   # NOTE: deliberately NO `-e`

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

OCI=(oci --profile "$PROFILE")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
csv_field() {
  local s=${1-}
  s=${s//\"/\"\"}
  s=${s//$'\n'/ }
  s=${s//$'\r'/ }
  printf '"%s"' "$s"
}

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

# Resolve tenancy from selected profile stanza
if [[ -z "$TENANCY" ]]; then
  CFG="${OCI_CLI_CONFIG_FILE:-$HOME/.oci/config}"
  if [[ -f "$CFG" ]]; then
    TENANCY=$(awk -v prof="[$PROFILE]" '
      $0==prof {inblk=1; next}
      /^\[/    {inblk=0}
      inblk && $1 ~ /^tenancy/ {sub(/^[^=]*=[[:space:]]*/,""); gsub(/[[:space:]]/,""); print; exit}
    ' "$CFG")
  fi
fi
# Cloud Shell fallback: if still empty, try the delegation-based CLI directly
if [[ -z "$TENANCY" ]]; then
  TENANCY=$("${OCI[@]}" iam compartment list --access-level ANY --limit 1 \
            --query 'data[0]."compartment-id"' --raw-output 2>/dev/null || true)
fi
[[ -z "$TENANCY" ]] && { echo "ERROR: Could not determine tenancy OCID for profile '$PROFILE'. Use -t." >&2; exit 1; }

if ! "${OCI[@]}" iam tenancy get --tenancy-id "$TENANCY" >/dev/null 2>&1; then
  echo "WARN: could not verify '$TENANCY' as a root tenancy (continuing)." >&2
fi

mkdir -p "$OUT_DIR"
echo "Profile : $PROFILE"
echo "Tenancy : $TENANCY"
echo "Output  : $OUT_DIR"

# Regions
if [[ -n "$REGIONS" ]]; then
  IFS=',' read -r -a RAW <<< "$REGIONS"
  REGION_LIST=()
  for r in "${RAW[@]}"; do
    r="${r#"${r%%[![:space:]]*}"}"; r="${r%"${r##*[![:space:]]}"}"
    [[ -n "$r" ]] && REGION_LIST+=("$r")
  done
  $ALL_REGIONS && echo "NOTE: -r supplied; -a ignored."
elif $ALL_REGIONS; then
  mapfile -t REGION_LIST < <("${OCI[@]}" iam region-subscription list \
      --tenancy-id "$TENANCY" --all 2>/dev/null | jq -r '.data[]."region-name"' 2>/dev/null)
else
  HOME_REGION=$("${OCI[@]}" iam region-subscription list --tenancy-id "$TENANCY" --all 2>/dev/null \
      | jq -r '.data[] | select(."is-home-region"==true) | ."region-name"' 2>/dev/null)
  REGION_LIST=("$HOME_REGION")
fi
[[ ${#REGION_LIST[@]} -eq 0 || -z "${REGION_LIST[0]:-}" ]] && { echo "ERROR: no regions resolved." >&2; exit 1; }

echo "Regions : ${REGION_LIST[*]}"
echo

LIMIT_HDR="service,limit_name,description,scope_type,availability_domain,limit_value,usage,available,limit_state,collect_status"

for REGION in "${REGION_LIST[@]}"; do
  echo "==================================================================="
  echo "REGION: $REGION"
  echo "==================================================================="
  ROCI=("${OCI[@]}" --region "$REGION")
  CSV="$OUT_DIR/limits-${REGION}.csv"
  echo "$LIMIT_HDR" > "$CSV"

  TBL_FMT="%-22s %-32s %-8s %-11s %-12s %-12s %-18s\n"
  printf "$TBL_FMT" "SERVICE" "LIMIT" "SCOPE" "LIMIT_VALUE" "USAGE" "AVAILABLE" "LIMIT_STATE"
  printf "$TBL_FMT" "----------------------" "--------------------------------" \
         "--------" "-----------" "------------" "------------" "------------------"

  SERVICES=$("${ROCI[@]}" limits service list --compartment-id "$TENANCY" --all 2>/dev/null \
             | jq -r '.data[].name' 2>/dev/null || true)
  if [[ -z "$SERVICES" ]]; then
    echo "  ERROR: could not list limit services in $REGION (access/API); skipping region." >&2
    echo "  (wrote header-only: $CSV)"
    continue
  fi

  # NOTE: iterate services via here-string (current shell), not a pipe
  while IFS= read -r SVC; do
    [[ -z "$SVC" ]] && continue
    [[ -n "$SERVICE_FILTER" && "$SVC" != "$SERVICE_FILTER" ]] && continue
    echo "  -> service: $SVC"

    DEFS=$("${ROCI[@]}" limits definition list --compartment-id "$TENANCY" \
           --service-name "$SVC" --all 2>/dev/null || true)
    if [[ -z "$DEFS" ]] || ! jq -e '.data' >/dev/null 2>&1 <<< "$DEFS"; then
      printf '%s,,%s,,,,,,,%s\n' "$SVC" "$(csv_field "definition list failed")" "ACCESS-OR-API-ERROR" >> "$CSV"
      continue
    fi

    # process-substitution keeps the loop in the current shell -> rows persist
    while IFS= read -r DEF; do
      [[ -z "$DEF" ]] && continue
      LNAME=$(jq -r '.name'          <<< "$DEF" 2>/dev/null || echo "")
      LDESC=$(jq -r '.description'   <<< "$DEF" 2>/dev/null || echo "")
      LSCOPE=$(jq -r '."scope-type"' <<< "$DEF" 2>/dev/null || echo "")
      [[ -z "$LNAME" ]] && continue

      if VALS=$("${ROCI[@]}" limits value list --compartment-id "$TENANCY" \
                --service-name "$SVC" --name "$LNAME" --all 2>/dev/null); then
        VAL_OK=1
      else
        VAL_OK=0; VALS='{"data":[]}'
      fi

      COUNT=$(jq '.data | length' <<< "$VALS" 2>/dev/null || echo 0)
      if [[ "${COUNT:-0}" -eq 0 ]]; then
        if [[ "$VAL_OK" -eq 1 ]]; then CSTAT="NO-DATA"; else CSTAT="ACCESS-OR-API-ERROR"; fi
        printf '%s,%s,%s,%s,,,,,%s,%s\n' \
          "$SVC" "$(csv_field "$LNAME")" "$(csv_field "$LDESC")" "$(csv_field "$LSCOPE")" \
          "NO-VALUE-RETURNED" "$CSTAT" >> "$CSV"
        printf "$TBL_FMT" "$SVC" "${LNAME:0:32}" "$LSCOPE" "-" "-" "-" "NO-VALUE-RETURNED"
        continue
      fi

      while IFS= read -r V; do
        [[ -z "$V" ]] && continue
        AD=$(jq -r '."availability-domain" // ""' <<< "$V" 2>/dev/null || echo "")
        LVAL=$(jq -r '.value // ""' <<< "$V" 2>/dev/null || echo "")
        LSTATE=$(classify_value "$LVAL")

        if USE=$("${ROCI[@]}" limits resource-availability get \
                  --compartment-id "$TENANCY" --service-name "$SVC" \
                  --limit-name "$LNAME" ${AD:+--availability-domain "$AD"} 2>/dev/null); then
          USED=$(jq -r '.data.used // empty'      <<< "$USE" 2>/dev/null || echo "")
          AVAIL=$(jq -r '.data.available // empty' <<< "$USE" 2>/dev/null || echo "")
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
      done < <(jq -c '.data[]' <<< "$VALS" 2>/dev/null)

    done < <(jq -c '.data[]' <<< "$DEFS" 2>/dev/null)
  done <<< "$SERVICES"

  echo "  wrote: $CSV"
  echo
done

# ---------------------------------------------------------------------------
# Quota policies
# ---------------------------------------------------------------------------
echo "==================================================================="
echo "QUOTA POLICIES (compartment quotas — not reconciled to limits)"
echo "==================================================================="
QCSV="$OUT_DIR/quotas.csv"
echo "quota_name,description,compartment_id,lifecycle_state,statements" > "$QCSV"

QTBL_FMT="%-28s %-16s %s\n"
printf "$QTBL_FMT" "QUOTA" "LIFECYCLE-STATE" "STATEMENTS (truncated)"
printf "$QTBL_FMT" "----------------------------" "----------------" "----------------------"

QLIST=$("${OCI[@]}" limits quota list --compartment-id "$TENANCY" --all 2>/dev/null || true)
if [[ -n "$QLIST" ]] && jq -e '.data' >/dev/null 2>&1 <<< "$QLIST"; then
  while IFS= read -r Q; do
    [[ -z "$Q" ]] && continue
    QID=$(jq -r '.id'   <<< "$Q" 2>/dev/null || echo "")
    QN=$(jq -r '.name'  <<< "$Q" 2>/dev/null || echo "")
    QD=$(jq -r '.description' <<< "$Q" 2>/dev/null || echo "")
    QC=$(jq -r '."compartment-id"' <<< "$Q" 2>/dev/null || echo "")
    QS=$(jq -r '."lifecycle-state"' <<< "$Q" 2>/dev/null || echo "")
    STMT=$("${OCI[@]}" limits quota get --quota-id "$QID" 2>/dev/null \
           | jq -r '(.data.statements // []) | join(" | ")' 2>/dev/null || echo "")
    printf '%s,%s,%s,%s,%s\n' \
      "$(csv_field "$QN")" "$(csv_field "$QD")" "$(csv_field "$QC")" \
      "$(csv_field "$QS")" "$(csv_field "$STMT")" >> "$QCSV"
    printf "$QTBL_FMT" "${QN:0:28}" "$QS" "${STMT:0:60}"
  done < <(jq -c '.data[]?' <<< "$QLIST" 2>/dev/null)
else
  echo "  ERROR: could not list quota policies (access/API)." >&2
fi
echo "  wrote: $QCSV"

echo
echo "Done. Results in: $OUT_DIR"
echo
echo "Label meanings:"
echo "  limit_state:  POSITIVE-LIMIT | ZERO-LIMIT | NON-INTEGER-VALUE | NO-VALUE-RETURNED"
echo "  usage/avail:  OCI-reported; NOT-REPORTED where the Resource Availability API"
echo "                does not support the limit. 'available' already reflects limits,"
echo "                usage, and applicable quotas — not simply limit minus usage."
echo
echo "A POSITIVE-LIMIT is an ALLOWANCE, not proof a service is enabled, provisioned,"
echo "or has deployable AD/physical capacity."
