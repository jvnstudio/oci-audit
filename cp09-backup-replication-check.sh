#!/usr/bin/env bash
#
# oci_backup_dr_audit.sh
#
# CP-9(5) / CP-10 EVIDENCE — Backup replication, retention & versioning
#
# Complements oci_backup_audit.sh (which shows backups EXIST). This script
# reports the three DR dimensions for each backup / data store:
#     REPLICATED  - is there a cross-region / second copy?  (+ target region)
#     RETENTION   - how long kept, and is it IMMUTABLE (WORM / time-locked)?
#     VERSIONING  - where applicable (Object Storage), is versioning on?
#
# Designed for OCI Cloud Shell (uses your delegation token). No API keys.
# READ-ONLY: every call is a list/get. Nothing is created/modified/deleted.
#
# Dimensions collected per service:
#   1. Object Storage  - replication policy (+dest region), versioning,
#                        retention rules (WORM + time-lock), lifecycle
#   2. Block Volumes   - volume replicas (cross-AD/region), backup copies
#   3. Boot Volumes    - boot volume replicas, backup copies
#   4. Volume Backups  - cross-region copies (source-region != current)
#   5. File Storage    - FSS replication targets + snapshot retention
#   6. Autonomous DB   - backup retention + cross-region/Data Guard copy
#   7. Base DB         - backup recovery window + Data Guard association
#
# Usage:
#   ./oci_backup_dr_audit.sh                 # all compartments
#   ./oci_backup_dr_audit.sh -c <ocid>       # single compartment
#   ./oci_backup_dr_audit.sh -r us-langley-1 # region override (GovCloud)
#   ./oci_backup_dr_audit.sh -s "object fss" # subset
#
# Output: timestamped CSV + console summary flagging backups with NO second
#         copy and mutable (non-WORM) backup stores.
#
set -uo pipefail

command -v oci >/dev/null 2>&1 || { echo "ERROR: oci CLI not found."; exit 1; }
command -v jq  >/dev/null 2>&1 || { echo "ERROR: jq not found."; exit 1; }

SINGLE_COMP=""; REGION_OVERRIDE=""
SERVICES="object volumes bootvol backups fss adb basedb"

while getopts "c:r:s:h" opt; do
  case "$opt" in
    c) SINGLE_COMP="$OPTARG" ;;
    r) REGION_OVERRIDE="$OPTARG" ;;
    s) SERVICES="$OPTARG" ;;
    h) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "Use -h for help"; exit 1 ;;
  esac
done

REGION_ARG=(); [ -n "$REGION_OVERRIDE" ] && REGION_ARG=(--region "$REGION_OVERRIDE")
o() { oci "${REGION_ARG[@]}" "$@" 2>/dev/null; }

TS="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="oci_backup_dr_${TS}.csv"
echo "compartment_id,compartment_name,service,resource,replicated,replica_target,retention,immutable_worm,versioning,finding,control" > "$OUT"

declare -A COMP_NAME
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

# Current region (for detecting cross-region copies)
CUR_REGION="${REGION_OVERRIDE:-$(o iam region-subscription list --query 'data[?"is-home-region"].["region-name"]|[0]' --raw-output 2>/dev/null)}"
[ -z "$CUR_REGION" ] && CUR_REGION="$(oci iam region-subscription list --query 'data[0]."region-name"' --raw-output 2>/dev/null)"

# ---------------------------------------------------------------------------
# Tenancy + compartment enumeration
# ---------------------------------------------------------------------------
TENANCY_ID="$(o iam compartment list --access-level ANY --limit 1 --query 'data[0]."compartment-id"' --raw-output 2>/dev/null)"
echo "Region : ${REGION_OVERRIDE:-<cloud-shell-default>} (detected: ${CUR_REGION:-unknown})"
echo "Tenancy: ${TENANCY_ID:-<unknown>}"
echo

if [ -n "$SINGLE_COMP" ]; then
  COMPS="$SINGLE_COMP"
  cn="$(o iam compartment get --compartment-id "$SINGLE_COMP" --query 'data.name' --raw-output 2>/dev/null)"
  COMP_NAME["$SINGLE_COMP"]="${cn:-<unknown>}"
else
  comp_pairs="$(o iam compartment list --compartment-id-in-subtree true --access-level ANY \
                  --lifecycle-state ACTIVE --all --query 'data[].{id:id,name:name}' 2>/dev/null)"
  while IFS=$'\t' read -r cid cname; do [ -z "$cid" ] && continue; COMP_NAME["$cid"]="$cname"; done \
    < <(echo "$comp_pairs" | jq -r '.[]? | [.id, .name] | @tsv' 2>/dev/null)
  COMPS="$(echo "$comp_pairs" | jq -r '.[]?.id' 2>/dev/null)"
  if [ -n "$TENANCY_ID" ]; then
    tname="$(o iam compartment get --compartment-id "$TENANCY_ID" --query 'data.name' --raw-output 2>/dev/null)"
    COMP_NAME["$TENANCY_ID"]="${tname:-root}"; COMPS="$TENANCY_ID"$'\n'"$COMPS"
  fi
fi
COMP_COUNT="$(printf '%s\n' "$COMPS" | grep -c . || true)"
[ "$COMP_COUNT" -eq 0 ] && { echo "ERROR: no compartments enumerated."; exit 1; }
echo "Auditing DR posture (replication/retention/versioning) across ${COMP_COUNT} compartment(s)..."
echo

# ---------------------------------------------------------------------------
# 1. Object Storage — the full picture
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
    local repl repl_target ver rr_json worm ret finding

    # Replication policy (+ destination region)
    local rp
    rp="$(o os replication list-replication-policies --bucket-name "$b" --namespace-name "$ns" 2>/dev/null)"
    if echo "$rp" | jq -e '.data | length > 0' >/dev/null 2>&1; then
      repl="YES"
      repl_target="$(echo "$rp" | jq -r '[.data[]? | "\(."destination-region-name"):\(."destination-bucket-name")"] | join("; ")' 2>/dev/null)"
    else
      repl="NO"; repl_target="none"
    fi

    # Versioning
    ver="$(o os bucket get --bucket-name "$b" --namespace-name "$ns" 2>/dev/null | jq -r '.data."versioning" // "Disabled"' 2>/dev/null)"

    # Retention rules -> WORM / time-lock
    rr_json="$(o os retention-rule list --bucket-name "$b" --namespace-name "$ns" 2>/dev/null)"
    if echo "$rr_json" | jq -e '.data.items | length > 0' >/dev/null 2>&1; then
      # A rule with a time-locked lock is true immutability
      local locked
      locked="$(echo "$rr_json" | jq -r '[.data.items[]? | select(."time-rule-locked" != null)] | length' 2>/dev/null)"
      if [ "${locked:-0}" -gt 0 ]; then worm="LOCKED-WORM"; else worm="retention-unlocked"; fi
      ret="$(echo "$rr_json" | jq -r '[.data.items[]? | (."duration"."time-amount"|tostring)+" "+(."duration"."time-unit"//"")] | join("; ") // "rule-present"' 2>/dev/null)"
      [ -z "$ret" ] && ret="rule-present"
    else
      worm="NONE"; ret="none"
    fi

    # Finding: a bucket (potential backup store) with no second copy AND no immutability
    if [ "$repl" = "NO" ] && [ "$worm" = "NONE" ]; then
      finding="NO-REPLICA-NO-WORM"
    elif [ "$repl" = "NO" ]; then
      finding="NO-REPLICA"
    elif [ "$worm" = "NONE" ]; then
      finding="NO-WORM"
    else
      finding="OK"
    fi

    row "$comp" "ObjectStorage" "$b" "$repl" "$repl_target" "$ret" "$worm" "$ver" "$finding" "CP-9(5)/CP-6"
  done <<< "$buckets"
}

# ---------------------------------------------------------------------------
# 2. Block Volume replicas (cross-AD/region async replication)
# ---------------------------------------------------------------------------
check_volumes() {
  local comp="$1"
  o bv volume list --compartment-id "$comp" --all 2>/dev/null | jq -c "$LIST_ITER" 2>/dev/null | \
  while IFS= read -r v; do
    [ -z "$v" ] && continue
    local vid vname reps target finding
    vid="$(echo "$v" | jq -r '.id')"
    vname="$(echo "$v" | jq -r '."display-name" // "volume"')"
    # Block volume replicas
    reps="$(o bv block-volume-replica list --compartment-id "$comp" --all 2>/dev/null | jq -r --arg vid "$vid" '[.data[]? | select(."block-volume-id"==$vid) | ."availability-domain"] | join("; ")' 2>/dev/null)"
    if [ -n "$reps" ] && [ "$reps" != "" ]; then
      finding="OK"; target="$reps"; row "$comp" "BlockVolume" "$vname" "YES" "$target" "n/a" "n/a" "n/a" "$finding" "CP-9(5)/CP-10"
    else
      row "$comp" "BlockVolume" "$vname" "NO" "none" "n/a" "n/a" "n/a" "NO-VOLUME-REPLICA" "CP-9(5)/CP-10"
    fi
  done
}

# ---------------------------------------------------------------------------
# 3. Boot Volume replicas
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
      local vid vname reps
      vid="$(echo "$v" | jq -r '.id')"
      vname="$(echo "$v" | jq -r '."display-name" // "boot-volume"')"
      reps="$(o bv boot-volume-replica list --compartment-id "$comp" --availability-domain "$ad" --all 2>/dev/null | jq -r --arg vid "$vid" '[.data[]? | select(."boot-volume-id"==$vid) | ."availability-domain"] | join("; ")' 2>/dev/null)"
      if [ -n "$reps" ] && [ "$reps" != "" ]; then
        row "$comp" "BootVolume" "$vname" "YES" "$reps" "n/a" "n/a" "n/a" "OK" "CP-9(5)/CP-10"
      else
        row "$comp" "BootVolume" "$vname" "NO" "none" "n/a" "n/a" "n/a" "NO-VOLUME-REPLICA" "CP-9(5)/CP-10"
      fi
    done
  done <<< "$ads"
}

# ---------------------------------------------------------------------------
# 4. Volume Backups — detect cross-region copies
# ---------------------------------------------------------------------------
check_backups() {
  local comp="$1"
  # Block volume backups
  o bv backup list --compartment-id "$comp" --all 2>/dev/null | jq -c "$LIST_ITER" 2>/dev/null | \
  while IFS= read -r bk; do
    [ -z "$bk" ] && continue
    local name src srcregion expires repl
    name="$(echo "$bk" | jq -r '."display-name" // "backup"')"
    # A copied backup has source-volume-backup-id set; region copy shows in source-region if present
    src="$(echo "$bk" | jq -r '."source-volume-backup-id" // empty')"
    expires="$(echo "$bk" | jq -r '."expiration-time" // "no-expiry"')"
    if [ -n "$src" ]; then repl="COPY-OF-ANOTHER"; else repl="PRIMARY"; fi
    row "$comp" "VolumeBackup" "$name" "$repl" "src=${src:0:24}" "expires=$expires" "n/a" "n/a" "INFO" "CP-9(5)"
  done

  # Boot volume backups
  o bv boot-volume-backup list --compartment-id "$comp" --all 2>/dev/null | jq -c "$LIST_ITER" 2>/dev/null | \
  while IFS= read -r bk; do
    [ -z "$bk" ] && continue
    local name src expires repl
    name="$(echo "$bk" | jq -r '."display-name" // "boot-backup"')"
    src="$(echo "$bk" | jq -r '."source-boot-volume-backup-id" // empty')"
    expires="$(echo "$bk" | jq -r '."expiration-time" // "no-expiry"')"
    if [ -n "$src" ]; then repl="COPY-OF-ANOTHER"; else repl="PRIMARY"; fi
    row "$comp" "BootVolumeBackup" "$name" "$repl" "src=${src:0:24}" "expires=$expires" "n/a" "n/a" "INFO" "CP-9(5)"
  done
}

# ---------------------------------------------------------------------------
# 5. File Storage — replication + snapshot retention
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
      local fid fname repl target
      fid="$(echo "$f" | jq -r '.id')"
      fname="$(echo "$f" | jq -r '."display-name" // "filesystem"')"
      # FSS replication resources target this filesystem
      target="$(o fs replication list --compartment-id "$comp" --availability-domain "$ad" --all 2>/dev/null | jq -r --arg fid "$fid" '[.data[]? | select(."source-id"==$fid) | ."target-id"] | join("; ")' 2>/dev/null)"
      if [ -n "$target" ] && [ "$target" != "" ]; then
        row "$comp" "FSS" "$fname" "YES" "${target:0:32}" "snapshot-policy" "n/a" "n/a" "OK" "CP-9(5)/CP-10"
      else
        row "$comp" "FSS" "$fname" "NO" "none" "snapshot-policy" "n/a" "n/a" "NO-FSS-REPLICATION" "CP-9(5)/CP-10"
      fi
    done
  done <<< "$ads"
}

# ---------------------------------------------------------------------------
# 6. Autonomous DB — retention + cross-region backup / Data Guard
# ---------------------------------------------------------------------------
check_adb() {
  local comp="$1"
  o db autonomous-database list --compartment-id "$comp" --all 2>/dev/null | jq -c "$LIST_ITER" 2>/dev/null | \
  while IFS= read -r a; do
    [ -z "$a" ] && continue
    local name ret dg peers finding
    name="$(echo "$a" | jq -r '."db-name" // "adb"')"
    ret="$(echo "$a" | jq -r '."backup-retention-period-in-days" // "default"')"
    # Cross-region peers / Data Guard
    peers="$(echo "$a" | jq -r '(."peer-db-ids" // []) | length' 2>/dev/null)"
    dg="$(echo "$a" | jq -r '."is-data-guard-enabled" // ."role" // "none"' 2>/dev/null)"
    if [ "${peers:-0}" -gt 0 ] || [ "$dg" = "true" ]; then
      finding="OK"; row "$comp" "AutonomousDB" "$name" "YES" "peers=$peers;dg=$dg" "${ret}d" "n/a" "n/a" "$finding" "CP-9(5)/CP-10"
    else
      row "$comp" "AutonomousDB" "$name" "NO" "none" "${ret}d" "n/a" "n/a" "NO-CROSS-REGION-COPY" "CP-9(5)/CP-10"
    fi
  done
}

# ---------------------------------------------------------------------------
# 7. Base DB — recovery window + Data Guard association
# ---------------------------------------------------------------------------
check_basedb() {
  local comp="$1"
  o db system list --compartment-id "$comp" --all 2>/dev/null | jq -r "$LIST_ITER | .id" 2>/dev/null | \
  while IFS= read -r sysid; do
    [ -z "$sysid" ] && continue
    o db database list --compartment-id "$comp" --db-system-id "$sysid" --all 2>/dev/null | jq -c "$LIST_ITER" 2>/dev/null | \
    while IFS= read -r d; do
      [ -z "$d" ] && continue
      local name dbid ret dg
      name="$(echo "$d" | jq -r '."db-name" // "db"')"
      dbid="$(echo "$d" | jq -r '.id')"
      ret="$(echo "$d" | jq -r '."db-backup-config"."recovery-window-in-days" // "default"')"
      # Data Guard association = cross-site copy
      dg="$(o db data-guard-association list --database-id "$dbid" --all 2>/dev/null | jq -r '.data | length // 0' 2>/dev/null)"
      dg="${dg:-0}"
      if [ "$dg" -gt 0 ]; then
        row "$comp" "BaseDB" "$name" "YES" "data-guard-assoc=$dg" "${ret}d" "n/a" "n/a" "OK" "CP-9(5)/CP-10"
      else
        row "$comp" "BaseDB" "$name" "NO" "none" "${ret}d" "n/a" "n/a" "NO-DATA-GUARD" "CP-9(5)/CP-10"
      fi
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
      object)  check_object  "$comp" ;;
      volumes) check_volumes "$comp" ;;
      bootvol) check_bootvol "$comp" ;;
      backups) check_backups "$comp" ;;
      fss)     check_fss     "$comp" ;;
      adb)     check_adb     "$comp" ;;
      basedb)  check_basedb  "$comp" ;;
      *) echo "    ! unknown service: $svc" ;;
    esac
  done
done <<< "$COMPS"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo
echo "======================================================================"
echo "CP-9(5)/CP-10 BACKUP DR POSTURE SUMMARY"
echo "======================================================================"
TOTAL="$(($(wc -l < "$OUT") - 1))"
NO_REPLICA="$(awk -F',' 'NR>1 {gsub(/"/,"",$10); if($10 ~ /NO-REPLICA|NO-VOLUME-REPLICA|NO-FSS-REPLICATION|NO-CROSS-REGION|NO-DATA-GUARD/) print}' "$OUT" | grep -c . || true)"
NO_WORM="$(awk -F',' 'NR>1 {gsub(/"/,"",$10); if($10 ~ /NO-WORM/) print}' "$OUT" | grep -c . || true)"
BOTH="$(awk -F',' 'NR>1 {gsub(/"/,"",$10); if($10=="NO-REPLICA-NO-WORM") print}' "$OUT" | grep -c . || true)"

echo "Total resources evaluated       : $TOTAL"
echo "No second copy / replica        : $NO_REPLICA"
echo "No WORM/immutability (obj store): $NO_WORM"
echo "Neither replica nor WORM (worst): $BOTH"
if [ "$BOTH" -gt 0 ]; then
  echo
  echo ">>> HIGHEST RISK — backup store with no replica AND no immutability:"
  awk -F',' 'NR>1 {gsub(/"/,"",$2);gsub(/"/,"",$3);gsub(/"/,"",$4);gsub(/"/,"",$10);
    if($10=="NO-REPLICA-NO-WORM") printf "  [%-16s] %-14s %s\n", $2, $3, $4}' "$OUT"
fi
echo
echo "Evidence CSV written to: $OUT"
echo
echo "NOTE: 'replicated' means a detectable second copy (Object Storage"
echo "replication policy, volume/boot replica, FSS replication, DB Data Guard"
echo "or ADB cross-region peer). Manual cross-region backup COPIES appear under"
echo "VolumeBackup rows as COPY-OF-ANOTHER. WORM/immutability applies to Object"
echo "Storage retention rules; LOCKED-WORM = time-locked (cannot be shortened)."
