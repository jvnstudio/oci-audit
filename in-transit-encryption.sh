#!/usr/bin/env bash
#
# oci_intransit_encryption_audit.sh
#
# SC-8 / SC-8(1) / SC-13 EVIDENCE COLLECTION — Encryption in Transit
#
# Tenancy-wide, read-only sweep of OCI in-transit encryption configuration.
# Designed for OCI Cloud Shell (uses your existing delegation token — the same
# auth that makes `oci iam compartment list` work). No API keys needed.
#
# Collects proof of TLS / in-transit encryption across:
#   1. Load Balancers         - TLS listeners, min TLS version, cipher suite, backend SSL
#   2. Network LBs            - listener protocol
#   3. Autonomous Database    - mTLS/TLS connection posture
#   4. Base DB Systems        - node/endpoint (native encryption confirmed at conn layer)
#   5. Object Storage buckets - public-access posture (HTTPS enforced by platform)
#   6. Block / Boot Volumes   - paravirtualized in-transit encryption flag on attachments
#   7. File Storage (FSS)     - in-transit encryption capability (mount-target export)
#   8. API Gateway            - deployment TLS / certificate posture
#   9. OKE clusters           - API server endpoint (TLS by platform)
#
# READ-ONLY: every call is a list/get. Nothing is created, modified, or deleted.
#
# Usage:
#   ./oci_intransit_encryption_audit.sh                 # all compartments
#   ./oci_intransit_encryption_audit.sh -c <ocid>       # single compartment
#   ./oci_intransit_encryption_audit.sh -r us-langley-1 # region override (GovCloud)
#   ./oci_intransit_encryption_audit.sh -s "lb db"      # subset
#
# Output: timestamped CSV evidence file + console summary flagging any
#         resource NOT enforcing TLS >= 1.2 or with encryption disabled.
#
set -uo pipefail

command -v oci >/dev/null 2>&1 || { echo "ERROR: oci CLI not found."; exit 1; }
command -v jq  >/dev/null 2>&1 || { echo "ERROR: jq not found."; exit 1; }

SINGLE_COMP=""
REGION_OVERRIDE=""
SERVICES="lb nlb adb basedb object volumes fss apigw oke"

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
OUT="oci_intransit_encryption_${TS}.csv"
echo "compartment_id,compartment_name,service,resource,tls_enabled,tls_min_version,cipher_or_detail,finding,control" > "$OUT"

declare -A COMP_NAME

# Type-safe iterator for OCI list responses. Different services/CLI versions
# return either {"data":[...]} or {"data":{"items":[...]}}. Naively writing
# `.data.items[]? // .data[]?` throws "cannot index array with string" when
# .data is an array. This filter checks the type first.
LIST_ITER='if (.data|type)=="object" then ((.data.items // []) | .[]) elif (.data|type)=="array" then (.data[]) else empty end'

# $1 = comp id; auto-inserts compartment name as field 2
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
echo "Collecting SC-8 in-transit encryption evidence across ${COMP_COUNT} compartment(s)..."
echo

# Weak TLS versions that should be flagged as findings
weak_tls() {  # $1 = version string; returns 0 if weak
  case "$1" in
    *1.0*|*1.1*|SSL*|"") return 0 ;;
    *) return 1 ;;
  esac
}

# ---------------------------------------------------------------------------
# 1. Load Balancers (classic / application LB)
# ---------------------------------------------------------------------------
check_lb() {
  local comp="$1"
  local lbs
  lbs="$(o lb load-balancer list --compartment-id "$comp" --all 2>/dev/null | jq -c '.data[]?' 2>/dev/null)"
  while IFS= read -r lb; do
    [ -z "$lb" ] && continue
    local lbname listeners
    lbname="$(echo "$lb" | jq -r '."display-name"')"
    # iterate listeners — guard: only if .listeners is an object
    echo "$lb" | jq -c 'if (.listeners|type)=="object" then (.listeners|to_entries[]) else empty end' 2>/dev/null | while IFS= read -r l; do
      local lname proto has_ssl minver ciphers finding
      lname="$(echo "$l" | jq -r '.key // "listener"' 2>/dev/null)"
      proto="$(echo "$l" | jq -r '.value.protocol // "?"' 2>/dev/null)"
      has_ssl="$(echo "$l" | jq -r '(.value | has("ssl-configuration")) and (.value."ssl-configuration" != null)' 2>/dev/null)"
      if [ "$has_ssl" = "true" ]; then
        # protocols may be an array; coerce safely regardless of type
        minver="$(echo "$l" | jq -r '(.value."ssl-configuration"."protocols") as $p | if ($p|type)=="array" then ($p|join(",")) elif $p==null then "managed" else ($p|tostring) end' 2>/dev/null)"
        ciphers="$(echo "$l" | jq -r '.value."ssl-configuration"."cipher-suite-name" // "default"' 2>/dev/null)"
        [ -z "$minver" ] && minver="managed"
        if echo "$minver" | grep -Eq 'TLSv1\.0|TLSv1\.1'; then
          finding="WEAK-TLS-VERSION"
        else
          finding="OK"
        fi
        row "$comp" "LoadBalancer" "${lbname}/${lname}" "YES" "$minver" "$ciphers" "$finding" "SC-8(1)"
      else
        # HTTP listener with no SSL = plaintext
        row "$comp" "LoadBalancer" "${lbname}/${lname}" "NO" "none" "protocol=$proto" "PLAINTEXT-LISTENER" "SC-8(1)"
      fi
    done
  done <<< "$lbs"
}

# ---------------------------------------------------------------------------
# 2. Network Load Balancers
# ---------------------------------------------------------------------------
check_nlb() {
  local comp="$1"
  local nlbs
  nlbs="$(o nlb network-load-balancer list --compartment-id "$comp" --all 2>/dev/null | jq -c "$LIST_ITER" 2>/dev/null)"
  while IFS= read -r n; do
    [ -z "$n" ] && continue
    local nid nname
    nid="$(echo "$n" | jq -r '.id')"
    nname="$(echo "$n" | jq -r '."display-name"')"
    local ls
    ls="$(o nlb listener list --network-load-balancer-id "$nid" --all 2>/dev/null | jq -c "$LIST_ITER" 2>/dev/null)"
    while IFS= read -r l; do
      [ -z "$l" ] && continue
      local lname proto
      lname="$(echo "$l" | jq -r '.name // "listener"')"
      proto="$(echo "$l" | jq -r '.protocol // "?"')"
      # NLB is L4 passthrough; TLS terminates at backend. Record protocol as evidence.
      row "$comp" "NetworkLB" "${nname}/${lname}" "passthrough" "backend-terminated" "protocol=$proto" "REVIEW-BACKEND-TLS" "SC-8(1)"
    done <<< "$ls"
  done <<< "$nlbs"
}

# ---------------------------------------------------------------------------
# 3. Autonomous Database (TLS/mTLS)
# ---------------------------------------------------------------------------
check_adb() {
  local comp="$1"
  local adbs
  adbs="$(o db autonomous-database list --compartment-id "$comp" --all 2>/dev/null | jq -c '.data[]?' 2>/dev/null)"
  while IFS= read -r a; do
    [ -z "$a" ] && continue
    local name mtls tls_only detail finding
    name="$(echo "$a" | jq -r '."db-name"')"
    mtls="$(echo "$a" | jq -r '."is-mtls-connection-required" // "unknown"')"
    # connection strings present => TLS profiles exist
    tls_only="$(echo "$a" | jq -r '(."connection-strings"."profiles" // []) | if type=="array" then (map(select(."tls-authentication"=="SERVER" or ."tls-authentication"=="MUTUAL")) | length) else 0 end' 2>/dev/null)"
    if [ "$mtls" = "true" ]; then
      detail="mTLS-required"; finding="OK"
    elif [ "$tls_only" != "0" ] && [ -n "$tls_only" ]; then
      detail="TLS-available(mTLS-optional)"; finding="OK-REVIEW"
    else
      detail="verify-connection-profile"; finding="REVIEW"
    fi
    row "$comp" "AutonomousDB" "$name" "YES" "TLS1.2+" "$detail" "$finding" "SC-8(1)/SC-13"
  done <<< "$adbs"
}

# ---------------------------------------------------------------------------
# 4. Base DB Systems (native network encryption / TCPS)
# ---------------------------------------------------------------------------
check_basedb() {
  local comp="$1"
  local systems
  systems="$(o db system list --compartment-id "$comp" --all 2>/dev/null | jq -c '.data[]?' 2>/dev/null)"
  while IFS= read -r s; do
    [ -z "$s" ] && continue
    local sname sid
    sname="$(echo "$s" | jq -r '."display-name"')"
    # Native Oracle Net encryption (NNE) or TLS is configured at sqlnet.ora level;
    # not fully exposed via API. Record presence as evidence pointer.
    row "$comp" "BaseDB" "$sname" "config-at-sqlnet" "TLS1.2/NNE" "verify sqlnet.ora ENCRYPTION_SERVER=REQUIRED" "MANUAL-EVIDENCE" "SC-8(1)"
  done <<< "$systems"
}

# ---------------------------------------------------------------------------
# 5. Object Storage (HTTPS enforced by platform; check public-access)
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
    local pub finding
    pub="$(o os bucket get --bucket-name "$b" --namespace-name "$ns" 2>/dev/null | jq -r '.data."public-access-type" // "NoPublicAccess"')"
    if [ "$pub" = "NoPublicAccess" ]; then
      finding="OK"
    else
      finding="PUBLIC-ACCESS-REVIEW"
    fi
    # All OS endpoints are HTTPS/TLS1.2 by platform; document that.
    row "$comp" "ObjectStorage" "$b" "YES" "TLS1.2 (platform-enforced HTTPS)" "public-access=$pub" "$finding" "SC-8/SC-13"
  done <<< "$buckets"
}

# ---------------------------------------------------------------------------
# 6. Block / Boot Volume attachments — paravirtualized in-transit encryption
# ---------------------------------------------------------------------------
check_volumes() {
  local comp="$1"
  # Block volume attachments carry the is-pv-encryption-in-transit-enabled flag
  local atts
  atts="$(o compute volume-attachment list --compartment-id "$comp" --all 2>/dev/null | jq -c '.data[]?' 2>/dev/null)"
  while IFS= read -r at; do
    [ -z "$at" ] && continue
    local vid inst enc finding
    vid="$(echo "$at" | jq -r '."volume-id"')"
    inst="$(echo "$at" | jq -r '."instance-id"')"
    enc="$(echo "$at" | jq -r '."is-pv-encryption-in-transit-enabled" // false')"
    if [ "$enc" = "true" ]; then
      finding="OK"
    else
      finding="IN-TRANSIT-ENC-DISABLED"
    fi
    row "$comp" "BlockVolumeAttach" "vol:${vid: -12}/inst:${inst: -12}" "$enc" "PV-in-transit" "attachment" "$finding" "SC-8(1)"
  done <<< "$atts"

  # Boot volume in-transit encryption is set at instance launch (is-pv-encryption-in-transit-enabled on instance)
  local insts
  insts="$(o compute instance list --compartment-id "$comp" --all 2>/dev/null | jq -c '.data[]?' 2>/dev/null)"
  while IFS= read -r i; do
    [ -z "$i" ] && continue
    local iname enc finding
    iname="$(echo "$i" | jq -r '."display-name"')"
    enc="$(echo "$i" | jq -r '."launch-options"."is-pv-encryption-in-transit-enabled" // false')"
    if [ "$enc" = "true" ]; then finding="OK"; else finding="BOOT-IN-TRANSIT-ENC-DISABLED"; fi
    row "$comp" "InstanceBootVol" "$iname" "$enc" "PV-in-transit" "launch-option" "$finding" "SC-8(1)"
  done <<< "$insts"
}

# ---------------------------------------------------------------------------
# 7. File Storage — in-transit encryption capability (mount targets)
# ---------------------------------------------------------------------------
check_fss() {
  local comp="$1"
  local ads
  ads="$(o iam availability-domain list --compartment-id "$comp" 2>/dev/null | jq -r '.data[]?.name' 2>/dev/null)"
  while IFS= read -r ad; do
    [ -z "$ad" ] && continue
    local mts
    mts="$(o fs mount-target list --compartment-id "$comp" --availability-domain "$ad" --all 2>/dev/null | jq -c '.data[]?' 2>/dev/null)"
    while IFS= read -r mt; do
      [ -z "$mt" ] && continue
      local mtname
      mtname="$(echo "$mt" | jq -r '."display-name"')"
      # FSS in-transit encryption is enforced by the oci-fss-utils mount helper (TLS).
      # API does not expose per-mount TLS state; record as evidence pointer.
      row "$comp" "FSS-MountTarget" "$mtname" "capable" "TLS (oci-fss-utils)" "verify mount uses in-transit encryption" "MANUAL-EVIDENCE" "SC-8(1)"
    done <<< "$mts"
  done <<< "$ads"
}

# ---------------------------------------------------------------------------
# 8. API Gateway — deployment TLS
# ---------------------------------------------------------------------------
check_apigw() {
  local comp="$1"
  local gws
  gws="$(o api-gateway gateway list --compartment-id "$comp" --all 2>/dev/null | jq -c "$LIST_ITER" 2>/dev/null)"
  while IFS= read -r g; do
    [ -z "$g" ] && continue
    local gname ep tls
    gname="$(echo "$g" | jq -r '."display-name"')"
    ep="$(echo "$g" | jq -r '.hostname // "n/a"')"
    ca="$(echo "$g" | jq -r '(."ca-bundles" // []) | if type=="array" then length else 0 end' 2>/dev/null)"
    # API Gateway endpoints are HTTPS/TLS by platform; certificate config is evidence.
    row "$comp" "APIGateway" "$gname" "YES" "TLS1.2+ (platform)" "endpoint=$ep;ca-bundles=$ca" "OK" "SC-8(1)"
  done <<< "$gws"
}

# ---------------------------------------------------------------------------
# 9. OKE clusters — API server endpoint
# ---------------------------------------------------------------------------
check_oke() {
  local comp="$1"
  local cls
  cls="$(o ce cluster list --compartment-id "$comp" --all 2>/dev/null | jq -c '.data[]?' 2>/dev/null)"
  while IFS= read -r c; do
    [ -z "$c" ] && continue
    local cname priv
    cname="$(echo "$c" | jq -r '.name')"
    priv="$(echo "$c" | jq -r '."endpoint-config"."is-public-ip-enabled" // "unknown"')"
    # Kubernetes API server is TLS by design; note public/private endpoint exposure.
    row "$comp" "OKE-Cluster" "$cname" "YES" "TLS1.2+ (k8s API)" "public-endpoint=$priv" "OK-REVIEW-EXPOSURE" "SC-8(1)"
  done <<< "$cls"
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
      lb)      check_lb      "$comp" ;;
      nlb)     check_nlb     "$comp" ;;
      adb)     check_adb     "$comp" ;;
      basedb)  check_basedb  "$comp" ;;
      object)  check_object  "$comp" ;;
      volumes) check_volumes "$comp" ;;
      fss)     check_fss     "$comp" ;;
      apigw)   check_apigw   "$comp" ;;
      oke)     check_oke     "$comp" ;;
      *) echo "    ! unknown service: $svc" ;;
    esac
  done
done <<< "$COMPS"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo
echo "======================================================================"
echo "SC-8 IN-TRANSIT ENCRYPTION EVIDENCE SUMMARY"
echo "======================================================================"
TOTAL="$(($(wc -l < "$OUT") - 1))"
# findings that need action: anything not OK / not a documented manual-evidence pointer
FINDINGS="$(awk -F',' 'NR>1 {gsub(/"/,"",$8); if($8 ~ /WEAK|PLAINTEXT|DISABLED|PUBLIC-ACCESS-REVIEW/) print}' "$OUT")"
FCOUNT="$(printf '%s\n' "$FINDINGS" | grep -c . || true)"
MANUAL="$(awk -F',' 'NR>1 {gsub(/"/,"",$8); if($8 ~ /MANUAL-EVIDENCE|REVIEW/) print}' "$OUT" | grep -c . || true)"

echo "Total resources evaluated       : $TOTAL"
echo "Hard findings (action required) : $FCOUNT"
echo "Manual-evidence / review items  : $MANUAL"
if [ "$FCOUNT" -gt 0 ]; then
  echo
  echo ">>> HARD FINDINGS — plaintext or weak TLS (fix before ATO):"
  printf '%s\n' "$FINDINGS" | awk -F',' '{gsub(/"/,"",$2);gsub(/"/,"",$3);gsub(/"/,"",$4);gsub(/"/,"",$8); printf "  [%-18s] %-22s %-30s -> %s\n", $3, $2, $4, $8}'
fi
echo
echo "Evidence CSV written to: $OUT"
echo
echo "NOTE: Rows marked MANUAL-EVIDENCE (Base DB sqlnet.ora, FSS mount options)"
echo "are not fully exposed via API. Capture supporting config screenshots or"
echo "sqlnet.ora / mount command output to complete the SC-8(1) evidence chain."
