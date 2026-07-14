#!/usr/bin/env bash
#
# oci_backup_audit.sh
#
# Tenancy-wide backup / snapshot posture audit for OCI.
# Designed to run in OCI Cloud Shell, where the CLI is already authenticated
# with your delegation token (same auth that makes `oci iam compartment list`
# work). No API keys or config editing required.
#
# Reports, per service, whether backups/snapshots are configured, the
# frequency/schedule (from policy objects), and retention.
#
# Services: Block/Boot Volumes, Base DB, Autonomous DB, File Storage (FSS),
#           Object Storage (replication/lifecycle/WORM), MySQL, PostgreSQL.
#
# READ-ONLY: every call is a list/get. Nothing is created, modified, or deleted.
#
# Usage:
#   ./oci_backup_audit.sh                 # all compartments, all services
#   ./oci_backup_audit.sh -c <ocid>       # single compartment
#   ./oci_backup_audit.sh -r us-langley-1 # region override (GovCloud)
#   ./oci_backup_audit.sh -s "volumes db" # subset of services
#
# Output: timestamped CSV in the current directory + console summary.
#
set -uo pipefail

# ---------------------------------------------------------------------------
# Requirements
# ---------------------------------------------------------------------------
command -v oci  >/dev/null 2>&1 || { echo "ERROR: oci CLI not found."; exit 1; }
command -v jq   >/dev/null 2>&1 || { echo "ERROR: jq not found (preinstalled in Cloud Shell)."; exit 1; }

# ---------------------------------------------------------------------------
# Args
# ---------------------------------------------------------------------------
SINGLE_COMP=""
REGION_OVERRIDE=""
SERVICES="volumes db fss object mysql postgres"

while getopts "c:r:s:h" opt; do
  case "$opt" in
    c) SINGLE_COMP="$OPTARG" ;;
    r) REGION_OVERRIDE="$OPTARG" ;;
    s) SERVICES="$OPTARG" ;;
    h) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "Use -h for help"; exit 1 ;;
  esac
done

# Region flag passed to every call if overridden
REGION_ARG=()
[ -n "$REGION_OVERRIDE" ] && REGION_ARG=(--region "$REGION_OVERRIDE")

# In Cloud Shell the CLI already knows how to auth. We just call it.
# oci() wrapper adds region + suppresses stderr noise; errors handled per-call.
o() { oci "${REGION_ARG[@]}" "$@" 2>/dev/null; }

TS="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="oci_backup_audit_${TS}.csv"
echo "compartment_id,compartment_name,service,resource,backup_configured,frequency_schedule,retention,detail" > "$OUT"

# Compartment id -> name lookup (populated after enumeration)
declare -A COMP_NAME

# CSV-safe append. First arg is the compartment id; we auto-insert its
# human-readable name as the second field so every row is self-describing.
row() {
  local comp_id="$1"; shift
  local cname="${COMP_NAME[$comp_id]:-<unknown>}"
  local out=""
  local f
  for f in "$comp_id" "$cname" "$@"; do
    f="${f//\"/\"\"}"
    out+="\"${f}\","
  done
  echo "${out%,}" >> "$OUT"
}

# ---------------------------------------------------------------------------
# Tenancy + compartment enumeration
# ---------------------------------------------------------------------------
TENANCY_ID="$(o iam compartment list --access-level ANY --limit 1 \
  --query 'data[0]."compartment-id"' --raw-output 2>/dev/null)"
if [ -z "$TENANCY_ID" ] || [ "$TENANCY_ID" = "null" ]; then
  # fall back to configured tenancy
  TENANCY_ID="$(oci iam compartment list --all --raw-output \
    --query 'data[0]."compartment-id"' 2>/dev/null)"
fi
echo "Region : ${REGION_OVERRIDE:-<cloud-shell-default>}"
echo "Tenancy: ${TENANCY_ID:-<unknown>}"
echo

if [ -n "$SINGLE_COMP" ]; then
  COMPS="$SINGLE_COMP"
  # resolve its name directly
  cn="$(o iam compartment get --compartment-id "$SINGLE_COMP" \
         --query 'data.name' --raw-output 2>/dev/null)"
  COMP_NAME["$SINGLE_COMP"]="${cn:-<unknown>}"
else
  # Same call that works for you at the CLI. ANY access level, active only.
  # Pull id AND name together so we can label every row.
  comp_pairs="$(o iam compartment list \
                  --compartment-id-in-subtree true \
                  --access-level ANY \
                  --lifecycle-state ACTIVE \
                  --all \
                  --query 'data[].{id:id,name:name}' 2>/dev/null)"
  # Build the id->name map
  while IFS=$'\t' read -r cid cname; do
    [ -z "$cid" ] && continue
    COMP_NAME["$cid"]="$cname"
  done < <(echo "$comp_pairs" | jq -r '.[]? | [.id, .name] | @tsv' 2>/dev/null)

  COMPS="$(echo "$comp_pairs" | jq -r '.[]?.id' 2>/dev/null)"
  # include the tenancy root itself
  if [ -n "$TENANCY_ID" ]; then
    tname="$(o iam compartment get --compartment-id "$TENANCY_ID" \
              --query 'data.name' --raw-output 2>/dev/null)"
    COMP_NAME["$TENANCY_ID"]="${tname:-root}"
    COMPS="$TENANCY_ID"$'\n'"$COMPS"
  fi
fi

COMP_COUNT="$(printf '%s\n' "$COMPS" | grep -c . || true)"
if [ "$COMP_COUNT" -eq 0 ]; then
  echo "ERROR: no compartments enumerated. Test manually:"
  echo "  oci iam compartment list --compartment-id-in-subtree true --access-level ANY --all"
  exit 1
fi
echo "Auditing ${COMP_COUNT} compartment(s)..."
echo

# ---------------------------------------------------------------------------
# Service checks
# ---------------------------------------------------------------------------

check_volumes() {
  local comp="$1"

  # Map of backup-policy-id -> schedule summary (compartment-scoped user policies)
  local pol_json
  pol_json="$(o bv volume-backup-policy list --compartment-id "$comp" --all 2>/dev/null)"

  policy_sched() {  # $1 = policy id
    echo "$pol_json" | jq -r --arg id "$1" '
      .data[]? | select(.id==$id) |
      ([.schedules[]? | "\(."period")/type=\(."backup-type")/ret=\(."retention-seconds")s"] | join("; "))
      // "assigned-policy"' 2>/dev/null
  }

  # Block volumes
  local vols
  vols="$(o bv volume list --compartment-id "$comp" --all 2>/dev/null | jq -c '.data[]?' 2>/dev/null)"
  while IFS= read -r v; do
    [ -z "$v" ] && continue
    local vid vname asg pid freq
    vid="$(echo "$v" | jq -r '.id')"
    vname="$(echo "$v" | jq -r '."display-name"')"
    asg="$(o bv volume-backup-policy-assignment get-volume-backup-policy-asset-assignment \
             --asset-id "$vid" 2>/dev/null | jq -r '.data[0]."policy-id" // empty' 2>/dev/null)"
    if [ -n "$asg" ]; then
      freq="$(policy_sched "$asg")"
      row "$comp" "BlockVolume" "$vname" "YES" "${freq:-assigned-policy}" "see-schedule" "$asg"
    else
      row "$comp" "BlockVolume" "$vname" "NO" "none" "none" ""
    fi
  done <<< "$vols"

  # Boot volumes (need AD)
  local ads
  ads="$(o iam availability-domain list --compartment-id "$comp" 2>/dev/null | jq -r '.data[]?.name' 2>/dev/null)"
  while IFS= read -r ad; do
    [ -z "$ad" ] && continue
    local bvols
    bvols="$(o bv boot-volume list --compartment-id "$comp" --availability-domain "$ad" --all 2>/dev/null | jq -c '.data[]?' 2>/dev/null)"
    while IFS= read -r bv; do
      [ -z "$bv" ] && continue
      local bid bname asg freq
      bid="$(echo "$bv" | jq -r '.id')"
      bname="$(echo "$bv" | jq -r '."display-name"')"
      asg="$(o bv volume-backup-policy-assignment get-volume-backup-policy-asset-assignment \
               --asset-id "$bid" 2>/dev/null | jq -r '.data[0]."policy-id" // empty' 2>/dev/null)"
      if [ -n "$asg" ]; then
        freq="$(policy_sched "$asg")"
        row "$comp" "BootVolume" "$bname" "YES" "${freq:-assigned-policy}" "see-schedule" "$asg"
      else
        row "$comp" "BootVolume" "$bname" "NO" "none" "none" ""
      fi
    done <<< "$bvols"
  done <<< "$ads"
}

check_db() {
  local comp="$1"

  # Base DB systems -> databases -> auto backup config
  local systems
  systems="$(o db system list --compartment-id "$comp" --all 2>/dev/null | jq -r '.data[]?.id' 2>/dev/null)"
  while IFS= read -r sysid; do
    [ -z "$sysid" ] && continue
    local dbs
    dbs="$(o db database list --compartment-id "$comp" --db-system-id "$sysid" --all 2>/dev/null | jq -c '.data[]?' 2>/dev/null)"
    while IFS= read -r d; do
      [ -z "$d" ] && continue
      local dname en win ret
      dname="$(echo "$d" | jq -r '."db-name"')"
      en="$(echo "$d" | jq -r '."db-backup-config"."auto-backup-enabled" // false')"
      win="$(echo "$d" | jq -r '."db-backup-config"."auto-backup-window" // "default"')"
      ret="$(echo "$d" | jq -r '."db-backup-config"."recovery-window-in-days" // "default"')"
      if [ "$en" = "true" ]; then
        row "$comp" "BaseDB" "$dname" "YES" "daily-auto (window=$win)" "${ret}d" "$sysid"
      else
        row "$comp" "BaseDB" "$dname" "NO" "none" "none" "$sysid"
      fi
    done <<< "$dbs"
  done <<< "$systems"

  # Autonomous DB
  local adbs
  adbs="$(o db autonomous-database list --compartment-id "$comp" --all 2>/dev/null | jq -c '.data[]?' 2>/dev/null)"
  while IFS= read -r a; do
    [ -z "$a" ] && continue
    local aname en ret
    aname="$(echo "$a" | jq -r '."db-name"')"
    en="$(echo "$a" | jq -r '."is-automatic-backup-enabled" // false')"
    ret="$(echo "$a" | jq -r '."backup-retention-period-in-days" // "n/a"')"
    if [ "$en" = "true" ]; then
      row "$comp" "AutonomousDB" "$aname" "YES" "daily-auto" "${ret}d" ""
    else
      row "$comp" "AutonomousDB" "$aname" "NO" "none" "${ret}d" ""
    fi
  done <<< "$adbs"
}

check_fss() {
  local comp="$1"

  # Snapshot policies -> schedule summary
  local pol_json
  pol_json="$(o fs filesystem-snapshot-policy list --compartment-id "$comp" --all 2>/dev/null)"

  fss_sched() {  # $1 = policy id
    local pid="$1"
    o fs filesystem-snapshot-policy get --filesystem-snapshot-policy-id "$pid" 2>/dev/null \
      | jq -r '([.data.schedules[]? | "\(."period")(ret=\(."retention-duration-in-seconds")s)"] | join("; ")) // "assigned-policy"' 2>/dev/null
  }

  local ads
  ads="$(o iam availability-domain list --compartment-id "$comp" 2>/dev/null | jq -r '.data[]?.name' 2>/dev/null)"
  while IFS= read -r ad; do
    [ -z "$ad" ] && continue
    local fslist
    fslist="$(o fs file-system list --compartment-id "$comp" --availability-domain "$ad" --all 2>/dev/null | jq -c '.data[]?' 2>/dev/null)"
    while IFS= read -r fs; do
      [ -z "$fs" ] && continue
      local fid fname pid freq nsnap
      fid="$(echo "$fs" | jq -r '.id')"
      fname="$(echo "$fs" | jq -r '."display-name"')"
      pid="$(echo "$fs" | jq -r '."filesystem-snapshot-policy-id" // empty')"
      if [ -n "$pid" ]; then
        freq="$(fss_sched "$pid")"
        row "$comp" "FSS" "$fname" "YES" "${freq:-assigned-policy}" "see-schedule" "$pid"
      else
        nsnap="$(o fs snapshot list --file-system-id "$fid" --all 2>/dev/null | jq -r '.data | length // 0' 2>/dev/null)"
        nsnap="${nsnap:-0}"
        if [ "$nsnap" -gt 0 ]; then
          row "$comp" "FSS" "$fname" "MANUAL" "manual-only" "${nsnap} snapshots" ""
        else
          row "$comp" "FSS" "$fname" "NO" "none" "0 snapshots" ""
        fi
      fi
    done <<< "$fslist"
  done <<< "$ads"
}

check_object() {
  local comp="$1"
  local ns
  ns="$(o os ns get --raw-output --query 'data' 2>/dev/null)"
  [ -z "$ns" ] && return

  local buckets
  buckets="$(o os bucket list --compartment-id "$comp" --namespace-name "$ns" --all 2>/dev/null | jq -r '.data[]?.name' 2>/dev/null)"
  while IFS= read -r b; do
    [ -z "$b" ] && continue
    local has_repl="" has_lc="" has_rr="" parts="" cfg="NO" freq="n/a"

    o os replication list-replication-policies --bucket-name "$b" --namespace-name "$ns" 2>/dev/null \
      | jq -e '.data | length > 0' >/dev/null 2>&1 && has_repl="yes"
    o os object-lifecycle-policy get --bucket-name "$b" --namespace-name "$ns" 2>/dev/null \
      | jq -e '.data.items | length > 0' >/dev/null 2>&1 && has_lc="yes"
    o os retention-rule list --bucket-name "$b" --namespace-name "$ns" 2>/dev/null \
      | jq -e '.data.items | length > 0' >/dev/null 2>&1 && has_rr="yes"

    [ -n "$has_repl" ] && { parts+="replication "; freq="event-driven (replication)"; cfg="YES"; }
    [ -n "$has_lc" ]   && { parts+="lifecycle ";   cfg="YES"; }
    [ -n "$has_rr" ]   && { parts+="retention/WORM "; cfg="YES"; }
    [ -z "$parts" ] && parts="none"

    row "$comp" "ObjectStorage" "$b" "$cfg" "$freq" "$(echo "$parts" | sed 's/ *$//;s/ /; /g')" ""
  done <<< "$buckets"
}

check_mysql() {
  local comp="$1"
  local systems
  systems="$(o mysql db-system list --compartment-id "$comp" --all 2>/dev/null | jq -r '.data[]?.id' 2>/dev/null)"
  while IFS= read -r sid; do
    [ -z "$sid" ] && continue
    local full name en win ret
    full="$(o mysql db-system get --db-system-id "$sid" 2>/dev/null)"
    name="$(echo "$full" | jq -r '.data."display-name" // "unknown"')"
    en="$(echo "$full" | jq -r '.data."backup-policy"."is-enabled" // false')"
    win="$(echo "$full" | jq -r '.data."backup-policy"."window-start-time" // "default"')"
    ret="$(echo "$full" | jq -r '.data."backup-policy"."retention-in-days" // "default"')"
    if [ "$en" = "true" ]; then
      row "$comp" "MySQL" "$name" "YES" "daily-auto (window=$win)" "${ret}d" ""
    else
      row "$comp" "MySQL" "$name" "NO" "none" "none" ""
    fi
  done <<< "$systems"
}

check_postgres() {
  local comp="$1"
  local systems
  systems="$(o psql db-system list --compartment-id "$comp" --all 2>/dev/null | jq -r '.data.items[]?.id // (.data[]?.id)' 2>/dev/null)"
  while IFS= read -r sid; do
    [ -z "$sid" ] && continue
    local full name kind ret
    full="$(o psql db-system get --db-system-id "$sid" 2>/dev/null)"
    name="$(echo "$full" | jq -r '.data."display-name" // "unknown"')"
    kind="$(echo "$full" | jq -r '.data."backup-policy"."kind" // empty')"
    ret="$(echo "$full" | jq -r '.data."backup-policy"."retention-days" // "default"')"
    if [ -n "$kind" ]; then
      row "$comp" "PostgreSQL" "$name" "YES" "$kind" "${ret}d" ""
    else
      row "$comp" "PostgreSQL" "$name" "UNKNOWN" "check-console" "n/a" ""
    fi
  done <<< "$systems"
}

# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------
i=0
while IFS= read -r comp; do
  [ -z "$comp" ] && continue
  i=$((i+1))
  echo "[$i/$COMP_COUNT] $comp"
  for svc in $SERVICES; do
    case "$svc" in
      volumes)  check_volumes  "$comp" ;;
      db)       check_db       "$comp" ;;
      fss)      check_fss      "$comp" ;;
      object)   check_object   "$comp" ;;
      mysql)    check_mysql    "$comp" ;;
      postgres) check_postgres "$comp" ;;
      *) echo "    ! unknown service: $svc" ;;
    esac
  done
done <<< "$COMPS"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo
echo "======================================================================"
echo "SUMMARY"
echo "======================================================================"
TOTAL="$(($(wc -l < "$OUT") - 1))"
UNPROT="$(awk -F',' 'NR>1 && ($5=="\"NO\"" || $5=="\"UNKNOWN\"")' "$OUT")"
UNPROT_COUNT="$(printf '%s\n' "$UNPROT" | grep -c . || true)"
echo "Total resources evaluated : $TOTAL"
echo "Without backup configured : $UNPROT_COUNT"
if [ "$UNPROT_COUNT" -gt 0 ]; then
  echo
  echo "UNPROTECTED / NEEDS REVIEW:"
  # $2=comp_name  $3=service  $4=resource  $5=status
  printf '%s\n' "$UNPROT" | awk -F',' '{gsub(/"/,"",$2); gsub(/"/,"",$3); gsub(/"/,"",$4); gsub(/"/,"",$5); printf "  [%-14s] %-30s %-30s (%s)\n", $3, $2, $4, $5}'
fi
echo
echo "Full report written to: $OUT"
