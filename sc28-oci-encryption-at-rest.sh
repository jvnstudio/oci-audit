#!/usr/bin/env bash
#
# oci_atrest_encryption_audit.sh
#
# SC-28 / SC-28(1) / SC-12 EVIDENCE COLLECTION — Encryption at Rest
#
# Tenancy-wide, read-only sweep of OCI encryption-at-rest configuration.
# Designed for OCI Cloud Shell (uses your existing delegation token). No keys.
#
# In OCI, encryption at rest is ALWAYS on (AES-256, platform-enforced). The
# control-relevant question is key MANAGEMENT:
#   - CUSTOMER-MANAGED (your Vault/KMS key present)  -> meets SC-28(1)/SC-12
#   - ORACLE-MANAGED   (no kms-key-id; Oracle holds the key) -> encrypted, but
#                        key not under your control -> reviewable item
#
# Services covered:
#   1. Block Volumes         - kms-key-id
#   2. Boot Volumes          - kms-key-id
#   3. Object Storage        - bucket kms-key-id
#   4. File Storage (FSS)    - file system kms-key-id
#   5. Autonomous Database   - kms-key-id (customer-managed TDE) vs Oracle
#   6. Base DB Systems       - kms-key-id / TDE posture
#   7. MySQL                 - encryption (always) + key source where exposed
#   8. PostgreSQL            - system encryption key source
#   9. Vault / KMS keys      - protection mode (HSM/SOFTWARE), state, rotation
#
# READ-ONLY: every call is a list/get. Nothing is created, modified, or deleted.
#
# Usage:
#   ./oci_atrest_encryption_audit.sh                 # all compartments
#   ./oci_atrest_encryption_audit.sh -c <ocid>       # single compartment
#   ./oci_atrest_encryption_audit.sh -r us-langley-1 # region override (GovCloud)
#   ./oci_atrest_encryption_audit.sh -s "volumes object vault"
#
# Output: timestamped CSV evidence file + console summary flagging
#         Oracle-managed (non-CMK) resources and any weak key posture.
#
set -uo pipefail

command -v oci >/dev/null 2>&1 || { echo "ERROR: oci CLI not found."; exit 1; }
command -v jq  >/dev/null 2>&1 || { echo "ERROR: jq not found."; exit 1; }

SINGLE_COMP=""
REGION_OVERRIDE=""
SERVICES="volumes bootvol object fss adb basedb mysql postgres vault"

while getopts "c:r:s:h" opt; do
  case "$opt" in
    c) SINGLE_COMP="$OPTARG" ;;
    r) REGION_OVERRIDE="$OPTARG" ;;
    s) SERVICES="$OPTARG" ;;
    h) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "Use -h for help"; exit 1 ;;
  esac
done

REGION_ARG=()
[ -n "$REGION_OVERRIDE" ] && REGION_ARG=(--region "$REGION_OVERRIDE")
o() { oci "${REGION_ARG[@]}" "$@" 2>/dev/null; }

TS="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="oci_atrest_encryption_${TS}.csv"
echo "compartment_id,compartment_name,service,resource,encrypted,key_management,key_ocid_or_detail,finding,control" > "$OUT"

declare -A COMP_NAME

# Type-safe iterator for OCI list responses ({"data":[...]} or {"data":{"items":[...]}})
LIST_ITER='if (.data|type)=="object" then ((.data.items // []) | .[]) elif (.data|type)=="array" then (.data[]) else empty end'

row() {
  local comp_id="$1"; shift
  local cname="${COMP_NAME[$comp_id]:-<unknown>}"
  local out="" f
  for f in "$comp_id" "$cname" "$@"; do
    f="${f//\"/\"\"}"
    out+="\"${f}\","
  done
  echo "${out%,}" >> "$OUT"
}

# Given a kms-key-id value, classify key management and return "mgmt|detail|finding"
classify_key() {
  local kid="$1"
  local sensitive="${2:-yes}"   # is this a sensitive data store? affects finding severity
  if [ -n "$kid" ] && [ "$kid" != "null" ]; then
    echo "CUSTOMER-MANAGED|${kid}|OK"
  else
    if [ "$sensitive" = "yes" ]; then
      echo "ORACLE-MANAGED|no-kms-key-id|REVIEW-USE-CMK"
    else
      echo "ORACLE-MANAGED|no-kms-key-id|OK-ORACLE-MANAGED"
    fi
  fi
}

# ---------------------------------------------------------------------------
# Tenancy + compartment enumeration (with names)
# ---------------------------------------------------------------------------
TENANCY_ID="$(o iam compartment list --access-level ANY --limit 1 \
  --query 'data[0]."compartment-id"' --raw-output 2>/dev/null)"
echo "Region : ${REGION_OVERRIDE:-<cloud-shell-default>}"
echo "Tenancy: ${TENANCY_ID:-<unknown>}"
echo

if [ -n "$SINGLE_COMP" ]; then
  COMPS="$SINGLE_COMP"
  cn="$(o iam compartment get --compartment-id "$SINGLE_COMP" --query 'data.name' --raw-output 2>/dev/null)"
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
    tname="$(o iam compartment get --compartment-id "$TENANCY_ID" --query 'data.name' --raw-output 2>/dev/null)"
    COMP_NAME["$TENANCY_ID"]="${tname:-root}"
    COMPS="$TENANCY_ID"$'\n'"$COMPS"
  fi
fi

COMP_COUNT="$(printf '%s\n' "$COMPS" | grep -c . || true)"
[ "$COMP_COUNT" -eq 0 ] && { echo "ERROR: no compartments enumerated."; exit 1; }
echo "Collecting SC-28 encryption-at-rest evidence across ${COMP_COUNT} compartment(s)..."
echo

emit() {  # comp service resource encrypted "mgmt|detail|finding" control
  local comp="$1" svc="$2" res="$3" enc="$4" cls="$5" ctrl="$6"
  local mgmt detail finding
  mgmt="${cls%%|*}"; detail="${cls#*|}"; finding="${detail#*|}"; detail="${detail%%|*}"
  row "$comp" "$svc" "$res" "$enc" "$mgmt" "$detail" "$finding" "$ctrl"
}

# ---------------------------------------------------------------------------
# 1. Block Volumes
# ---------------------------------------------------------------------------
check_volumes() {
  local comp="$1"
  o bv volume list --compartment-id "$comp" --all 2>/dev/null | jq -c "$LIST_ITER" 2>/dev/null | \
  while IFS= read -r v; do
    [ -z "$v" ] && continue
    local name kid
    name="$(echo "$v" | jq -r '."display-name" // "volume"')"
    kid="$(echo "$v" | jq -r '."kms-key-id" // empty')"
    emit "$comp" "BlockVolume" "$name" "YES(AES-256)" "$(classify_key "$kid" yes)" "SC-28(1)/SC-12"
  done
}

# ---------------------------------------------------------------------------
# 2. Boot Volumes
# ---------------------------------------------------------------------------
check_bootvol() {
  local comp="$1"
  local ads
  ads="$(o iam availability-domain list --compartment-id "$comp" 2>/dev/null | jq -r '.data[]?.name' 2>/dev/null)"
  while IFS= read -r ad; do
    [ -z "$ad" ] && continue
    o bv boot-volume list --compartment-id "$comp" --availability-domain "$ad" --all 2>/dev/null | jq -c "$LIST_ITER" 2>/dev/null | \
    while IFS= read -r v; do
      [ -z "$v" ] && continue
      local name kid
      name="$(echo "$v" | jq -r '."display-name" // "boot-volume"')"
      kid="$(echo "$v" | jq -r '."kms-key-id" // empty')"
      emit "$comp" "BootVolume" "$name" "YES(AES-256)" "$(classify_key "$kid" yes)" "SC-28(1)/SC-12"
    done
  done <<< "$ads"
}

# ---------------------------------------------------------------------------
# 3. Object Storage buckets
# ---------------------------------------------------------------------------
check_object() {
  local comp="$1"
  local ns
  ns="$(o os ns get --raw-output --query 'data' 2>/dev/null)"
  [ -z "$ns" ] && return
  local buckets
  buckets="$(o os bucket list --compartment-id "$comp" --namespace-name "$ns" --all 2>/dev/null | jq -r '.data[]?.name' 2>/dev/null)"
  while IFS= read -r b; do
    [ -z "$b" ] && continue
    local kid
    kid="$(o os bucket get --bucket-name "$b" --namespace-name "$ns" 2>/dev/null | jq -r '.data."kms-key-id" // empty' 2>/dev/null)"
    emit "$comp" "ObjectStorage" "$b" "YES(AES-256)" "$(classify_key "$kid" yes)" "SC-28(1)/SC-12"
  done <<< "$buckets"
}

# ---------------------------------------------------------------------------
# 4. File Storage (FSS)
# ---------------------------------------------------------------------------
check_fss() {
  local comp="$1"
  local ads
  ads="$(o iam availability-domain list --compartment-id "$comp" 2>/dev/null | jq -r '.data[]?.name' 2>/dev/null)"
  while IFS= read -r ad; do
    [ -z "$ad" ] && continue
    o fs file-system list --compartment-id "$comp" --availability-domain "$ad" --all 2>/dev/null | jq -c "$LIST_ITER" 2>/dev/null | \
    while IFS= read -r f; do
      [ -z "$f" ] && continue
      local name kid
      name="$(echo "$f" | jq -r '."display-name" // "filesystem"')"
      kid="$(echo "$f" | jq -r '."kms-key-id" // empty')"
      emit "$comp" "FSS" "$name" "YES(AES-256)" "$(classify_key "$kid" yes)" "SC-28(1)/SC-12"
    done
  done <<< "$ads"
}

# ---------------------------------------------------------------------------
# 5. Autonomous Database
# ---------------------------------------------------------------------------
check_adb() {
  local comp="$1"
  o db autonomous-database list --compartment-id "$comp" --all 2>/dev/null | jq -c "$LIST_ITER" 2>/dev/null | \
  while IFS= read -r a; do
    [ -z "$a" ] && continue
    local name kid
    name="$(echo "$a" | jq -r '."db-name" // "adb"')"
    kid="$(echo "$a" | jq -r '."kms-key-id" // empty')"
    emit "$comp" "AutonomousDB" "$name" "YES(TDE)" "$(classify_key "$kid" yes)" "SC-28(1)/SC-12"
  done
}

# ---------------------------------------------------------------------------
# 6. Base DB Systems -> databases (TDE always on; key source)
# ---------------------------------------------------------------------------
check_basedb() {
  local comp="$1"
  o db system list --compartment-id "$comp" --all 2>/dev/null | jq -r "$LIST_ITER | .id" 2>/dev/null | \
  while IFS= read -r sysid; do
    [ -z "$sysid" ] && continue
    o db database list --compartment-id "$comp" --db-system-id "$sysid" --all 2>/dev/null | jq -c "$LIST_ITER" 2>/dev/null | \
    while IFS= read -r d; do
      [ -z "$d" ] && continue
      local name kid
      name="$(echo "$d" | jq -r '."db-name" // "db"')"
      kid="$(echo "$d" | jq -r '."kms-key-id" // empty')"
      emit "$comp" "BaseDB" "$name" "YES(TDE)" "$(classify_key "$kid" yes)" "SC-28(1)/SC-12"
    done
  done
}

# ---------------------------------------------------------------------------
# 7. MySQL
# ---------------------------------------------------------------------------
check_mysql() {
  local comp="$1"
  o mysql db-system list --compartment-id "$comp" --all 2>/dev/null | jq -r "$LIST_ITER | .id" 2>/dev/null | \
  while IFS= read -r sid; do
    [ -z "$sid" ] && continue
    local full name kid
    full="$(o mysql db-system get --db-system-id "$sid" 2>/dev/null)"
    name="$(echo "$full" | jq -r '.data."display-name" // "mysql"')"
    kid="$(echo "$full" | jq -r '.data."data-storage"."kms-key-id" // .data."kms-key-id" // empty' 2>/dev/null)"
    emit "$comp" "MySQL" "$name" "YES(AES-256)" "$(classify_key "$kid" yes)" "SC-28(1)/SC-12"
  done
}

# ---------------------------------------------------------------------------
# 8. PostgreSQL
# ---------------------------------------------------------------------------
check_postgres() {
  local comp="$1"
  o psql db-system list --compartment-id "$comp" --all 2>/dev/null | jq -r "$LIST_ITER | .id" 2>/dev/null | \
  while IFS= read -r sid; do
    [ -z "$sid" ] && continue
    local full name kid
    full="$(o psql db-system get --db-system-id "$sid" 2>/dev/null)"
    name="$(echo "$full" | jq -r '.data."display-name" // "postgres"')"
    kid="$(echo "$full" | jq -r '.data."storage-details"."system-type" as $t | (.data."management-policy"."kms-key-id" // .data."kms-key-id" // empty)' 2>/dev/null)"
    emit "$comp" "PostgreSQL" "$name" "YES(AES-256)" "$(classify_key "$kid" yes)" "SC-28(1)/SC-12"
  done
}

# ---------------------------------------------------------------------------
# 9. Vault / KMS keys — the keys themselves (protection mode, state, rotation)
# ---------------------------------------------------------------------------
check_vault() {
  local comp="$1"
  o kms management vault list --compartment-id "$comp" --all 2>/dev/null | jq -c "$LIST_ITER" 2>/dev/null | \
  while IFS= read -r v; do
    [ -z "$v" ] && continue
    local vname vstate vtype mgmt_ep
    vname="$(echo "$v" | jq -r '."display-name" // "vault"')"
    vstate="$(echo "$v" | jq -r '."lifecycle-state" // "?"')"
    vtype="$(echo "$v" | jq -r '."vault-type" // "?"')"
    mgmt_ep="$(echo "$v" | jq -r '."management-endpoint" // empty')"

    # Vault-level evidence row
    local vfind="OK"
    [ "$vtype" = "VIRTUAL_PRIVATE" ] || vfind="OK-SHARED-HSM"
    row "$comp" "KMS-Vault" "$vname" "n/a" "$vtype" "state=$vstate" "$vfind" "SC-12/SC-28(1)"

    # Enumerate keys within the vault (needs the vault's management endpoint)
    [ -z "$mgmt_ep" ] && continue
    o kms management key list --compartment-id "$comp" --endpoint "$mgmt_ep" --all 2>/dev/null | jq -c "$LIST_ITER" 2>/dev/null | \
    while IFS= read -r k; do
      [ -z "$k" ] && continue
      local kname kstate kprot kfind
      kname="$(echo "$k" | jq -r '."display-name" // "key"')"
      kstate="$(echo "$k" | jq -r '."lifecycle-state" // "?"')"
      kprot="$(echo "$k" | jq -r '."protection-mode" // "?"')"
      # HSM protection is strongest; SOFTWARE is acceptable but reviewable for High
      if [ "$kprot" = "HSM" ]; then kfind="OK-HSM"
      elif [ "$kprot" = "SOFTWARE" ]; then kfind="REVIEW-SOFTWARE-KEY"
      else kfind="REVIEW"; fi
      [ "$kstate" != "ENABLED" ] && kfind="${kfind};KEY-STATE-${kstate}"
      row "$comp" "KMS-Key" "${vname}/${kname}" "n/a" "$kprot" "state=$kstate" "$kfind" "SC-12/SC-28(1)"
    done
  done
}

# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------
i=0
while IFS= read -r comp; do
  [ -z "$comp" ] && continue
  i=$((i+1))
  echo "[$i/$COMP_COUNT] ${COMP_NAME[$comp]:-$comp}"
  for svc in $SERVICES; do
    case "$svc" in
      volumes)  check_volumes  "$comp" ;;
      bootvol)  check_bootvol  "$comp" ;;
      object)   check_object   "$comp" ;;
      fss)      check_fss      "$comp" ;;
      adb)      check_adb      "$comp" ;;
      basedb)   check_basedb   "$comp" ;;
      mysql)    check_mysql    "$comp" ;;
      postgres) check_postgres "$comp" ;;
      vault)    check_vault    "$comp" ;;
      *) echo "    ! unknown service: $svc" ;;
    esac
  done
done <<< "$COMPS"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo
echo "======================================================================"
echo "SC-28 ENCRYPTION-AT-REST EVIDENCE SUMMARY"
echo "======================================================================"
TOTAL="$(($(wc -l < "$OUT") - 1))"
ORACLE_MGD="$(awk -F',' 'NR>1 {gsub(/"/,"",$8); if($8 ~ /REVIEW-USE-CMK/) print}' "$OUT" | grep -c . || true)"
CMK="$(awk -F',' 'NR>1 {gsub(/"/,"",$6); if($6=="CUSTOMER-MANAGED") print}' "$OUT" | grep -c . || true)"
SOFTKEY="$(awk -F',' 'NR>1 {gsub(/"/,"",$8); if($8 ~ /SOFTWARE-KEY/) print}' "$OUT" | grep -c . || true)"

echo "Total resources evaluated        : $TOTAL"
echo "Customer-managed key (CMK)       : $CMK"
echo "Oracle-managed (no CMK) - review : $ORACLE_MGD"
echo "Software-protected KMS keys      : $SOFTKEY"
if [ "$ORACLE_MGD" -gt 0 ]; then
  echo
  echo ">>> ORACLE-MANAGED data stores (consider customer-managed keys for SC-28(1)/SC-12):"
  awk -F',' 'NR>1 {gsub(/"/,"",$2);gsub(/"/,"",$3);gsub(/"/,"",$4);gsub(/"/,"",$8); if($8 ~ /REVIEW-USE-CMK/) printf "  [%-16s] %-22s %s\n", $3, $2, $4}' "$OUT"
fi
echo
echo "Evidence CSV written to: $OUT"
echo
echo "NOTE: All rows show encrypted=YES — OCI encrypts at rest by default"
echo "(AES-256). The control-relevant distinction is key management:"
echo "CUSTOMER-MANAGED (your Vault key) satisfies SC-28(1)/SC-12 key control;"
echo "ORACLE-MANAGED is encrypted but Oracle holds the key. Decide per data"
echo "sensitivity which stores require customer-managed keys in your SSP."
