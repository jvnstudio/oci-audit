#!/usr/bin/env bash
#==============================================================================
# oci_limits_quota_audit.sh                                       v1.0.0
#
# READ-ONLY audit of OCI service limits, resource availability, effective
# quotas, and quota policies. Mirrors the Console view:
#   Governance & Administration > Limits, Quotas and Usage
#
# Outputs (CSV, one set per run, per region):
#   1. limits_usage_<region>_<ts>.csv   service limit / used / available /
#                                       effective quota / % used / status
#   2. quota_policies_<ts>.csv          quota policies + statements
#   3. summary_<ts>.txt                 counts + WARN/CRITICAL rollup
#   4. errors_<ts>.log                  per-call failures (non-fatal)
#
# AUTH (auto-detected, in order):
#   1. OCI Cloud Shell delegation token   (instance_obo_user)
#   2. Instance principal                 (OCI_CLI_AUTH=instance_principal)
#   3. ~/.oci/config API key profile      (default or $OCI_CLI_PROFILE)
#
# REQUIRES: oci CLI, jq, awk, xargs (all present in OCI Cloud Shell)
#
# IAM: read-only. Minimum policy:
#   allow group <grp> to inspect limits in tenancy
#   allow group <grp> to read quotas in tenancy
#   allow group <grp> to inspect compartments in tenancy
#
# IMPORTANT ACCURACY NOTES
#   * The Limits API is TENANCY-SCOPED. GetResourceAvailability accepts ONLY
#     the root (tenancy) OCID as compartment-id. There is no per-compartment
#     "used" figure from this API -- per-compartment control is enforced by
#     quota POLICIES, which are reported separately in output #2.
#   * Not every limit supports availability data. Definitions are filtered on
#     is-resource-availability-supported; unsupported ones are emitted with
#     status NO_DATA rather than silently dropped.
#   * available + used does NOT always equal the service limit. When a quota
#     policy applies, availability is computed against effective-quota-value.
#     Both columns are emitted so the delta is visible.
#   * Limits are per-region. AD-scoped limits are emitted once per AD.
#==============================================================================

set -uo pipefail

VERSION="1.0.0"
TS="$(date -u +%Y%m%dT%H%M%SZ)"

#------------------------------------------------------------------------------
# Defaults (override via flags or environment)
#------------------------------------------------------------------------------
OUT_DIR="${OUT_DIR:-./oci_limits_audit_${TS}}"
REGIONS_MODE="current"          # current | all | csv list of region keys
SERVICE_FILTER=""               # csv list, e.g. compute,block-storage
PARALLEL="${PARALLEL:-8}"       # concurrent availability lookups
WARN_PCT="${WARN_PCT:-80}"
CRIT_PCT="${CRIT_PCT:-90}"
RETRIES="${RETRIES:-4}"
INCLUDE_DEPRECATED="false"
SKIP_QUOTAS="false"
UPLOAD_BUCKET="${UPLOAD_BUCKET:-}"      # optional Object Storage bucket name
UPLOAD_NAMESPACE="${UPLOAD_NAMESPACE:-}"
TENANCY_OCID="${TENANCY_OCID:-}"

usage() {
  cat <<EOF
oci_limits_quota_audit.sh v${VERSION}

  -t, --tenancy-id OCID   Tenancy OCID (default: auto-detect)
  -r, --regions MODE      current | all | us-ashburn-1,us-phoenix-1
  -s, --services LIST     Comma list of service names (default: all)
  -o, --out-dir DIR       Output directory (default: ${OUT_DIR})
  -p, --parallel N        Concurrent availability calls (default: ${PARALLEL})
      --warn-pct N        WARN threshold, default ${WARN_PCT}
      --crit-pct N        CRITICAL threshold, default ${CRIT_PCT}
      --include-deprecated
      --skip-quotas       Skip quota policy enumeration
      --upload-bucket B   Upload CSVs to this Object Storage bucket
  -h, --help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -t|--tenancy-id) TENANCY_OCID="$2"; shift 2;;
    -r|--regions)    REGIONS_MODE="$2"; shift 2;;
    -s|--services)   SERVICE_FILTER="$2"; shift 2;;
    -o|--out-dir)    OUT_DIR="$2"; shift 2;;
    -p|--parallel)   PARALLEL="$2"; shift 2;;
    --warn-pct)      WARN_PCT="$2"; shift 2;;
    --crit-pct)      CRIT_PCT="$2"; shift 2;;
    --include-deprecated) INCLUDE_DEPRECATED="true"; shift;;
    --skip-quotas)   SKIP_QUOTAS="true"; shift;;
    --upload-bucket) UPLOAD_BUCKET="$2"; shift 2;;
    -h|--help)       usage; exit 0;;
    *) echo "Unknown option: $1" >&2; usage; exit 2;;
  esac
done

#------------------------------------------------------------------------------
# Preflight
#------------------------------------------------------------------------------
for bin in oci jq awk xargs; do
  command -v "$bin" >/dev/null 2>&1 || { echo "FATAL: '$bin' not found in PATH" >&2; exit 1; }
done

mkdir -p "$OUT_DIR"
ERR_LOG="${OUT_DIR}/errors_${TS}.log"
: > "$ERR_LOG"

log()  { printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }
elog() { printf '[%s] %s\n' "$(date -u +%H:%M:%SZ)" "$*" >> "$ERR_LOG"; }

#------------------------------------------------------------------------------
# Auth detection
#------------------------------------------------------------------------------
detect_auth() {
  if [[ -n "${OCI_CLI_AUTH:-}" ]]; then
    log "Auth: honoring preset OCI_CLI_AUTH=${OCI_CLI_AUTH}"
    return
  fi
  local dtok="${OCI_CLI_DELEGATION_TOKEN_FILE:-/etc/oci/delegation_token}"
  if [[ -r "$dtok" ]]; then
    export OCI_CLI_AUTH="instance_obo_user"
    export OCI_CLI_DELEGATION_TOKEN_FILE="$dtok"
    log "Auth: Cloud Shell delegation token (instance_obo_user)"
  elif curl -s -m 2 -H "Authorization: Bearer Oracle" \
        http://169.254.169.254/opc/v2/instance/ >/dev/null 2>&1; then
    export OCI_CLI_AUTH="instance_principal"
    log "Auth: instance principal"
  else
    export OCI_CLI_AUTH="api_key"
    log "Auth: API key config profile (${OCI_CLI_PROFILE:-DEFAULT})"
  fi
}
detect_auth

resolve_tenancy() {
  [[ -n "$TENANCY_OCID" ]] && { log "Tenancy: $TENANCY_OCID (explicit)"; return; }
  if [[ -n "${OCI_TENANCY:-}" ]]; then
    TENANCY_OCID="$OCI_TENANCY"
  elif [[ -r "${HOME}/.oci/config" ]]; then
    TENANCY_OCID="$(awk -F'=' '/^[[:space:]]*tenancy[[:space:]]*=/{gsub(/[[:space:]]/,"",$2); print $2; exit}' "${HOME}/.oci/config")"
  fi
  [[ -n "$TENANCY_OCID" ]] || { echo "FATAL: cannot resolve tenancy OCID; pass --tenancy-id" >&2; exit 1; }
  log "Tenancy: $TENANCY_OCID"
}
resolve_tenancy

#------------------------------------------------------------------------------
# Helpers
#------------------------------------------------------------------------------
# oci_retry <args...> -> stdout JSON, non-zero on hard failure
oci_retry() {
  local attempt=1 tmp rc out
  tmp="$(mktemp)"
  while :; do
    if out="$(oci "$@" 2>"$tmp")"; then
      rm -f "$tmp"; printf '%s' "$out"; return 0
    fi
    rc=$?
    if grep -qiE '429|too ?many ?requests|TooManyRequests|ServiceUnavailable|timed? ?out|Connection aborted' "$tmp" \
       && (( attempt < RETRIES )); then
      sleep $(( attempt * attempt ))
      attempt=$(( attempt + 1 ))
      continue
    fi
    elog "CMD FAILED (rc=$rc): oci $* :: $(tr '\n' ' ' < "$tmp" | cut -c1-400)"
    rm -f "$tmp"
    return "$rc"
  done
}

# csv_escape <string>
csv_escape() {
  local s="${1-}"
  s="${s//\"/\"\"}"
  printf '"%s"' "$s"
}

#------------------------------------------------------------------------------
# Region list
#------------------------------------------------------------------------------
build_region_list() {
  case "$REGIONS_MODE" in
    all)
      oci_retry iam region-subscription list --tenancy-id "$TENANCY_OCID" \
        | jq -r '.data[]."region-name"' | sort
      ;;
    current)
      local r="${OCI_CLI_REGION:-${OCI_REGION:-}}"
      if [[ -z "$r" && -r "${HOME}/.oci/config" ]]; then
        r="$(awk -F'=' '/^[[:space:]]*region[[:space:]]*=/{gsub(/[[:space:]]/,"",$2); print $2; exit}' "${HOME}/.oci/config")"
      fi
      [[ -n "$r" ]] || { echo "FATAL: cannot determine current region" >&2; exit 1; }
      echo "$r"
      ;;
    *)
      echo "$REGIONS_MODE" | tr ',' '\n' | sed 's/[[:space:]]//g' | grep -v '^$'
      ;;
  esac
}

REGIONS=()
while IFS= read -r line; do [[ -n "$line" ]] && REGIONS+=("$line"); done < <(build_region_list)
log "Regions to audit: ${REGIONS[*]}"

#------------------------------------------------------------------------------
# Worker: fetch availability for one (region, service, limit, scope, ad)
# Reads a TAB-delimited task on $1..$5, emits one TAB-delimited result row.
#------------------------------------------------------------------------------
fetch_availability() {
  local region="$1" svc="$2" lname="$3" scope="$4" ad="$5" limval="$6" avail_supported="$7"

  local used="" avail="" fusage="" favail="" eqv=""

  if [[ "$avail_supported" == "true" ]]; then
    local args=(limits resource-availability get
                --compartment-id "$TENANCY_OCID"
                --service-name "$svc"
                --limit-name "$lname"
                --region "$region")
    [[ "$scope" == "AD" && -n "$ad" ]] && args+=(--availability-domain "$ad")

    local json
    if json="$(oci_retry "${args[@]}")"; then
      used="$(jq -r '.data.used            // empty' <<<"$json")"
      avail="$(jq -r '.data.available       // empty' <<<"$json")"
      fusage="$(jq -r '.data."fractional-usage"        // empty' <<<"$json")"
      favail="$(jq -r '.data."fractional-availability" // empty' <<<"$json")"
      eqv="$(jq -r '.data."effective-quota-value"      // empty' <<<"$json")"
    fi
  fi

  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$region" "$svc" "$lname" "$scope" "$ad" "$limval" \
    "$used" "$avail" "$fusage" "$favail" "$eqv"
}
export -f fetch_availability oci_retry elog
export TENANCY_OCID ERR_LOG RETRIES

#------------------------------------------------------------------------------
# MAIN: per-region limits enumeration
#------------------------------------------------------------------------------
LIMITS_CSVS=()

for REGION in "${REGIONS[@]}"; do
  log "=== Region: ${REGION} ==="

  # --- services -------------------------------------------------------------
  SVC_JSON="$(oci_retry limits service list --compartment-id "$TENANCY_OCID" \
                --region "$REGION" --all)" || { elog "service list failed in $REGION"; continue; }
  mapfile -t SERVICES < <(jq -r '.data[].name' <<<"$SVC_JSON" | sort -u)

  if [[ -n "$SERVICE_FILTER" ]]; then
    mapfile -t SERVICES < <(printf '%s\n' "${SERVICES[@]}" \
      | grep -Fx -f <(echo "$SERVICE_FILTER" | tr ',' '\n' | sed 's/[[:space:]]//g'))
  fi
  log "  services: ${#SERVICES[@]}"

  TASKS="$(mktemp)"

  for SVC in "${SERVICES[@]}"; do
    DEF_JSON="$(oci_retry limits definition list --compartment-id "$TENANCY_OCID" \
                  --service-name "$SVC" --region "$REGION" --all)" || continue
    VAL_JSON="$(oci_retry limits value list --compartment-id "$TENANCY_OCID" \
                  --service-name "$SVC" --region "$REGION" --all)" || VAL_JSON='{"data":[]}'

    jq -r -n --argjson defs "$DEF_JSON" --argjson vals "$VAL_JSON" \
            --arg svc "$SVC" --arg region "$REGION" --arg incdep "$INCLUDE_DEPRECATED" '
      ($vals.data // []) as $V
      | ($defs.data // [])[]
      | select($incdep == "true" or (."is-deprecated" // false) == false)
      | . as $d
      | ($V | map(select(.name == $d.name))) as $m
      | (if ($m | length) > 0 then $m else [{"value": null, "availability-domain": null}] end)[]
      | [ $region, $svc, $d.name,
          ($d."scope-type" // ""),
          (."availability-domain" // ""),
          (if .value == null then "" else (.value|tostring) end),
          (($d."is-resource-availability-supported" // false)|tostring),
          (($d."are-quotas-supported" // false)|tostring),
          (($d."is-eligible-for-limit-increase" // false)|tostring),
          (($d.description // "") | gsub("[\t\n\r]"; " "))
        ] | @tsv
    ' >> "$TASKS" 2>>"$ERR_LOG"
  done

  TASK_COUNT="$(wc -l < "$TASKS" | tr -d ' ')"
  log "  limit rows to evaluate: ${TASK_COUNT}"

  # --- parallel availability lookups ---------------------------------------
  RESULTS="$(mktemp)"
  awk -F'\t' '{print $1"\t"$2"\t"$3"\t"$4"\t"$5"\t"$6"\t"$7}' "$TASKS" \
    | xargs -P "$PARALLEL" -I{} -d '\n' bash -c \
        'IFS=$'"'"'\t'"'"' read -r r s l sc ad lv av <<< "$1"; fetch_availability "$r" "$s" "$l" "$sc" "$ad" "$lv" "$av"' _ {} \
    > "$RESULTS" 2>>"$ERR_LOG"

  # --- merge metadata + availability into final CSV -------------------------
  OUT_CSV="${OUT_DIR}/limits_usage_${REGION}_${TS}.csv"
  LIMITS_CSVS+=("$OUT_CSV")

  {
    echo 'region,service_name,limit_name,scope_type,availability_domain,service_limit,used,available,fractional_usage,fractional_availability,effective_quota_value,pct_used,status,quotas_supported,eligible_for_increase,description'

    awk -F'\t' -v OFS='\t' 'NR==FNR{key=$1 SUBSEP $2 SUBSEP $3 SUBSEP $4 SUBSEP $5; meta[key]=$8"\t"$9"\t"$10; next}
      { key=$1 SUBSEP $2 SUBSEP $3 SUBSEP $4 SUBSEP $5;
        print $0, (key in meta ? meta[key] : "\t\t") }' "$TASKS" "$RESULTS" \
    | awk -F'\t' -v W="$WARN_PCT" -v C="$CRIT_PCT" '
      function esc(s) { gsub(/"/,"\"\"",s); return "\"" s "\"" }
      {
        region=$1; svc=$2; lname=$3; scope=$4; ad=$5; lim=$6;
        used=$7; avail=$8; fu=$9; fa=$10; eqv=$11;
        qs=$12; eli=$13; desc=$14;

        base = (eqv != "" ? eqv+0 : (lim != "" ? lim+0 : 0));
        pct=""; status="NO_DATA";

        if (used != "" && base > 0) {
          pct = sprintf("%.2f", (used+0) / base * 100);
          if (avail != "" && (avail+0) <= 0)      status="EXHAUSTED";
          else if (pct+0 >= C+0)                  status="CRITICAL";
          else if (pct+0 >= W+0)                  status="WARN";
          else                                    status="OK";
        } else if (used != "" && base == 0) {
          status = ((used+0) > 0 ? "OVER_ZERO_LIMIT" : "ZERO_LIMIT");
          pct = "";
        } else if (lim != "") {
          status = "NO_USAGE_DATA";
        }

        print esc(region) "," esc(svc) "," esc(lname) "," esc(scope) "," esc(ad) ","  \
              esc(lim) "," esc(used) "," esc(avail) "," esc(fu) "," esc(fa) ","      \
              esc(eqv) "," esc(pct) "," esc(status) "," esc(qs) "," esc(eli) "," esc(desc)
      }'
  } > "$OUT_CSV"

  log "  wrote $(( $(wc -l < "$OUT_CSV") - 1 )) rows -> $OUT_CSV"
  rm -f "$TASKS" "$RESULTS"
done

#------------------------------------------------------------------------------
# Quota policies (tenancy-wide; policies live in the root compartment)
#------------------------------------------------------------------------------
QUOTA_CSV="${OUT_DIR}/quota_policies_${TS}.csv"
if [[ "$SKIP_QUOTAS" != "true" ]]; then
  log "=== Quota policies ==="
  {
    echo 'quota_name,quota_id,compartment_id,lifecycle_state,time_created,description,statement_index,statement'
    if Q_JSON="$(oci_retry limits quota list --compartment-id "$TENANCY_OCID" --all)"; then
      while IFS=$'\t' read -r qid qname qstate qtime qdesc qcomp; do
        [[ -z "$qid" ]] && continue
        if QD="$(oci_retry limits quota get --quota-id "$qid")"; then
          jq -r --arg id "$qid" --arg n "$qname" --arg s "$qstate" --arg t "$qtime" \
                --arg d "$qdesc" --arg c "$qcomp" '
            (.data.statements // ["<no statements>"]) | to_entries[]
            | [$n,$id,$c,$s,$t,$d,(.key|tostring),(.value|gsub("[\n\r]";" "))] | @csv
          ' <<<"$QD"
        fi
      done < <(jq -r '.data[] | [.id, .name, ."lifecycle-state", ."time-created", (.description//""), ."compartment-id"] | @tsv' <<<"$Q_JSON")
    fi
  } > "$QUOTA_CSV"
  log "  wrote $(( $(wc -l < "$QUOTA_CSV") - 1 )) statement rows -> $QUOTA_CSV"
fi

#------------------------------------------------------------------------------
# Summary
#------------------------------------------------------------------------------
SUMMARY="${OUT_DIR}/summary_${TS}.txt"
{
  echo "OCI Limits / Quota / Usage Audit"
  echo "Generated (UTC) : ${TS}"
  echo "Tenancy         : ${TENANCY_OCID}"
  echo "Regions         : ${REGIONS[*]}"
  echo "Auth mode       : ${OCI_CLI_AUTH}"
  echo "Thresholds      : WARN>=${WARN_PCT}%  CRITICAL>=${CRIT_PCT}%"
  echo
  for f in "${LIMITS_CSVS[@]}"; do
    [[ -f "$f" ]] || continue
    echo "--- $(basename "$f") ---"
    awk -F'","' 'NR>1{gsub(/"/,"",$13); c[$13]++} END{for (k in c) printf "  %-16s %6d\n", k, c[k]}' "$f"
    echo
    echo "  Top utilization:"
    awk -F'","' 'NR>1{gsub(/"/,"",$12); gsub(/"/,"",$13);
                 if ($12 != "") printf "%8.2f  %s / %s %s\n", $12, $2, $3, $5}' "$f" \
      | sort -rn | head -20 | sed 's/^/    /'
    echo
  done
  ERRS="$(wc -l < "$ERR_LOG" | tr -d ' ')"
  echo "Non-fatal errors: ${ERRS} (see $(basename "$ERR_LOG"))"
} > "$SUMMARY"

cat "$SUMMARY"

#------------------------------------------------------------------------------
# Optional: push results to Object Storage (for scheduled/unattended runs)
#------------------------------------------------------------------------------
if [[ -n "$UPLOAD_BUCKET" ]]; then
  NS="$UPLOAD_NAMESPACE"
  [[ -z "$NS" ]] && NS="$(oci_retry os ns get | jq -r '.data')"
  log "Uploading to os://${NS}/${UPLOAD_BUCKET}/limits-audit/${TS}/"
  for f in "$OUT_DIR"/*; do
    oci_retry os object put --namespace "$NS" --bucket-name "$UPLOAD_BUCKET" \
      --name "limits-audit/${TS}/$(basename "$f")" --file "$f" --force >/dev/null \
      && log "  uploaded $(basename "$f")"
  done
fi

log "Done. Output: ${OUT_DIR}"
