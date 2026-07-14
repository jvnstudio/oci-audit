#!/usr/bin/env bash
#
# oci_backup_access_audit.sh
#
# WHO CAN ACCESS THE BACKUPS? — access-control companion to oci_backup_audit.sh
#
# Designed for OCI Cloud Shell (uses your existing delegation token — the same
# auth that makes `oci iam compartment list` work). No API keys needed.
#
# For each compartment it reports the access surface over backup data:
#   1. IAM policy statements that grant access to backup-bearing resources
#      (volume-backups, boot-volume-backups, file-family/snapshots, database
#       backups, object-storage buckets/objects)
#   2. Groups/principals named in those statements
#   3. Object Storage bypass vectors:
#        - buckets with public access (read/public)
#        - pre-authenticated requests (PARs) — time-limited URLs that skip IAM
#   4. Bucket visibility + whether versioning/retention protect the backup data
#
# READ-ONLY: every call is a list/get. Nothing is created, modified, or deleted.
#
# Usage:
#   ./oci_backup_access_audit.sh                 # all compartments
#   ./oci_backup_access_audit.sh -c <ocid>       # single compartment
#   ./oci_backup_access_audit.sh -r us-langley-1 # region override (GovCloud)
#
# Output: two timestamped CSVs (policy grants + object-storage exposure) +
#         console summary highlighting the risky findings.
#
set -uo pipefail

command -v oci >/dev/null 2>&1 || { echo "ERROR: oci CLI not found."; exit 1; }
command -v jq  >/dev/null 2>&1 || { echo "ERROR: jq not found."; exit 1; }

SINGLE_COMP=""
REGION_OVERRIDE=""
while getopts "c:r:h" opt; do
  case "$opt" in
    c) SINGLE_COMP="$OPTARG" ;;
    r) REGION_OVERRIDE="$OPTARG" ;;
    h) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "Use -h for help"; exit 1 ;;
  esac
done

REGION_ARG=()
[ -n "$REGION_OVERRIDE" ] && REGION_ARG=(--region "$REGION_OVERRIDE")
o() { oci "${REGION_ARG[@]}" "$@" 2>/dev/null; }

TS="$(date -u +%Y%m%dT%H%M%SZ)"
POL_OUT="oci_backup_access_policies_${TS}.csv"
OBJ_OUT="oci_backup_access_objstore_${TS}.csv"
echo "compartment_id,compartment_name,policy_name,statement,grantee,backup_resource_matched" > "$POL_OUT"
echo "compartment_id,compartment_name,bucket,public_access,par_count,par_details,versioning,retention_rules,risk" > "$OBJ_OUT"

# id -> name lookup, populated after enumeration
declare -A COMP_NAME

# $1 = target file; $2 = compartment id; remaining = fields.
# Auto-inserts the compartment name right after the id.
csvrow() {
  local file="$1"; shift
  local comp_id="$1"; shift
  local cname="${COMP_NAME[$comp_id]:-<unknown>}"
  local out=""
  local f
  for f in "$comp_id" "$cname" "$@"; do
    f="${f//\"/\"\"}"
    out+="\"${f}\","
  done
  echo "${out%,}" >> "$file"
}

# Keywords that indicate a statement touches backup-bearing resources
# (verb-agnostic; we match the resource-type / family words)
BACKUP_KEYWORDS='volume-backups|boot-volume-backups|backups|file-family|file-systems|mount-targets|objects|buckets|object-family|backup-family|databases|autonomous-database-family|db-backups|volume-family|database-family'

# ---------------------------------------------------------------------------
# Tenancy + compartments
# ---------------------------------------------------------------------------
TENANCY_ID="$(o iam compartment list --access-level ANY --limit 1 \
  --query 'data[0]."compartment-id"' --raw-output 2>/dev/null)"
echo "Region : ${REGION_OVERRIDE:-<cloud-shell-default>}"
echo "Tenancy: ${TENANCY_ID:-<unknown>}"
echo

if [ -n "$SINGLE_COMP" ]; then
  COMPS="$SINGLE_COMP"
  cn="$(o iam compartment get --compartment-id "$SINGLE_COMP" \
         --query 'data.name' --raw-output 2>/dev/null)"
  COMP_NAME["$SINGLE_COMP"]="${cn:-<unknown>}"
else
  comp_pairs="$(o iam compartment list --compartment-id-in-subtree true \
                  --access-level ANY --lifecycle-state ACTIVE --all \
                  --query 'data[].{id:id,name:name}' 2>/dev/null)"
  while IFS=$'\t' read -r cid cname; do
    [ -z "$cid" ] && continue
    COMP_NAME["$cid"]="$cname"
  done < <(echo "$comp_pairs" | jq -r '.[]? | [.id, .name] | @tsv' 2>/dev/null)

  COMPS="$(echo "$comp_pairs" | jq -r '.[]?.id' 2>/dev/null)"
  if [ -n "$TENANCY_ID" ]; then
    tname="$(o iam compartment get --compartment-id "$TENANCY_ID" \
              --query 'data.name' --raw-output 2>/dev/null)"
    COMP_NAME["$TENANCY_ID"]="${tname:-root}"
    COMPS="$TENANCY_ID"$'\n'"$COMPS"
  fi
fi
COMP_COUNT="$(printf '%s\n' "$COMPS" | grep -c . || true)"
[ "$COMP_COUNT" -eq 0 ] && { echo "ERROR: no compartments enumerated."; exit 1; }
echo "Auditing access surface across ${COMP_COUNT} compartment(s)..."
echo

RISK_PUBLIC=0
RISK_PAR=0
POLICY_HITS=0

# ---------------------------------------------------------------------------
# 1. IAM policy statements touching backup resources
# ---------------------------------------------------------------------------
audit_policies() {
  local comp="$1"
  local pols
  pols="$(o iam policy list --compartment-id "$comp" --all 2>/dev/null | jq -c '.data[]?' 2>/dev/null)"
  while IFS= read -r p; do
    [ -z "$p" ] && continue
    local pname stmts
    pname="$(echo "$p" | jq -r '.name')"
    # iterate statements
    echo "$p" | jq -r '.statements[]?' 2>/dev/null | while IFS= read -r stmt; do
      [ -z "$stmt" ] && continue
      if echo "$stmt" | grep -Eiq "$BACKUP_KEYWORDS"; then
        # extract grantee (group/dynamic-group name after 'to'/'allow ... to')
        local grantee matched
        grantee="$(echo "$stmt" | grep -oiE 'allow (any-user|group [^ ]+|dynamic-group [^ ]+|service [^ ]+)' | head -1)"
        [ -z "$grantee" ] && grantee="(see-statement)"
        matched="$(echo "$stmt" | grep -oiE "$BACKUP_KEYWORDS" | sort -u | paste -sd';' -)"
        csvrow "$POL_OUT" "$comp" "$pname" "$stmt" "$grantee" "$matched"
      fi
    done
  done <<< "$pols"
}

# ---------------------------------------------------------------------------
# 2. Object Storage exposure (public access + PARs + protection)
# ---------------------------------------------------------------------------
audit_objectstore() {
  local comp="$1"
  local ns
  ns="$(o os ns get --raw-output --query 'data' 2>/dev/null)"
  [ -z "$ns" ] && return

  local buckets
  buckets="$(o os bucket list --compartment-id "$comp" --namespace-name "$ns" --all 2>/dev/null | jq -r '.data[]?.name' 2>/dev/null)"
  while IFS= read -r b; do
    [ -z "$b" ] && continue
    local meta pub ver par_json par_count par_detail rr risk=""
    meta="$(o os bucket get --bucket-name "$b" --namespace-name "$ns" 2>/dev/null)"
    pub="$(echo "$meta" | jq -r '.data."public-access-type" // "NoPublicAccess"')"
    ver="$(echo "$meta" | jq -r '.data."versioning" // "Disabled"')"

    # Pre-authenticated requests (IAM bypass URLs)
    par_json="$(o os preauth-request list --bucket-name "$b" --namespace-name "$ns" --all 2>/dev/null)"
    par_count="$(echo "$par_json" | jq -r '.data | length // 0' 2>/dev/null)"
    par_count="${par_count:-0}"
    par_detail="$(echo "$par_json" | jq -r '[.data[]? | "\(.name):\(."access-type")"] | join("; ") // ""' 2>/dev/null)"

    # Retention rules (WORM/immutability protecting the backups)
    rr="$(o os retention-rule list --bucket-name "$b" --namespace-name "$ns" 2>/dev/null | jq -r '.data.items | length // 0' 2>/dev/null)"
    rr="${rr:-0}"

    # Risk flags
    [ "$pub" != "NoPublicAccess" ] && { risk+="PUBLIC-BUCKET "; RISK_PUBLIC=$((RISK_PUBLIC+1)); }
    [ "$par_count" -gt 0 ] && { risk+="HAS-PARs "; RISK_PAR=$((RISK_PAR+1)); }
    [ "$rr" -eq 0 ] && risk+="NO-WORM "
    [ -z "$risk" ] && risk="ok"

    csvrow "$OBJ_OUT" "$comp" "$b" "$pub" "$par_count" "$par_detail" "$ver" "$rr" "$(echo "$risk" | sed 's/ *$//')"
  done <<< "$buckets"
}

# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------
i=0
while IFS= read -r comp; do
  [ -z "$comp" ] && continue
  i=$((i+1))
  echo "[$i/$COMP_COUNT] $comp"
  audit_policies    "$comp"
  audit_objectstore "$comp"
done <<< "$COMPS"

# recompute counts from files (subshell loops above don't persist vars)
POLICY_HITS="$(($(wc -l < "$POL_OUT") - 1))"
RISK_PUBLIC="$(awk -F',' 'NR>1 && $4!="\"NoPublicAccess\""' "$OBJ_OUT" | grep -c . || true)"
RISK_PAR="$(awk -F',' 'NR>1 && $5!="\"0\"" && $5!="\"\""' "$OBJ_OUT" | grep -c . || true)"

echo
echo "======================================================================"
echo "BACKUP ACCESS SUMMARY"
echo "======================================================================"
echo "IAM statements granting access to backup resources : $POLICY_HITS"
echo "Object Storage buckets with PUBLIC access          : $RISK_PUBLIC"
echo "Object Storage buckets exposing PARs (IAM bypass)  : $RISK_PAR"
echo
if [ "$RISK_PUBLIC" -gt 0 ] || [ "$RISK_PAR" -gt 0 ]; then
  echo ">>> REVIEW THESE — potential unauthorized backup access:"
  # $2=comp_name $3=bucket $9=risk
  awk -F',' 'NR>1 {gsub(/"/,"",$2); gsub(/"/,"",$3); gsub(/"/,"",$9); if($9!="ok") printf "  [%-20s] bucket %-35s risk: %s\n", $2, $3, $9}' "$OBJ_OUT"
  echo
fi
echo "Policy grants report : $POL_OUT"
echo "Object-store report  : $OBJ_OUT"
echo
echo "NOTE: This shows the ACCESS SURFACE (who is granted access + bypass"
echo "vectors). It does not resolve group membership. To see actual humans,"
echo "cross-reference grantee groups with:  oci iam group list-users --group-id <id>"
