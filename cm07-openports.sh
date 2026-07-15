#!/usr/bin/env bash
#
# oci_ppsm_ports_audit.sh
#
# CM-7 / CM-7(1) / PPSM EVIDENCE — Ports, Protocols & Services inventory
#
# Tenancy-wide, read-only sweep of the OCI network ingress/egress surface from
# both Security Lists and Network Security Groups (NSGs). Produces an
# authoritative port inventory with well-known-service annotation and a blank
# justification column for you to complete (PPSM registration / CM-7 baseline).
#
# Designed for OCI Cloud Shell (uses your existing delegation token). No keys.
#
# IMPORTANT — what is machine-collected vs. human-supplied:
#   * FACTS (collected): VCN, security-list/NSG, direction, protocol, port
#     range, source/dest CIDR or NSG, stateful/stateless.
#   * FUNCTION (annotated): well-known port -> service name (22=SSH, 443=HTTPS,
#     1521=Oracle DB, etc.). This is inference from IANA/common assignments,
#     NOT proof of what actually runs on the port.
#   * JUSTIFICATION (blank): only your org can attest business need. Left empty
#     for you to fill. This is the correct, assessor-defensible structure.
#
# READ-ONLY: every call is a list/get. Nothing is created, modified, or deleted.
#
# Usage:
#   ./oci_ppsm_ports_audit.sh                 # all compartments
#   ./oci_ppsm_ports_audit.sh -c <ocid>       # single compartment
#   ./oci_ppsm_ports_audit.sh -r us-langley-1 # region override (GovCloud)
#   ./oci_ppsm_ports_audit.sh -d ingress      # ingress only (default: both)
#
# Output: timestamped CSV inventory + console summary flagging wide-open
#         (0.0.0.0/0) exposure on sensitive ports.
#
set -uo pipefail

command -v oci >/dev/null 2>&1 || { echo "ERROR: oci CLI not found."; exit 1; }
command -v jq  >/dev/null 2>&1 || { echo "ERROR: jq not found."; exit 1; }

SINGLE_COMP=""
REGION_OVERRIDE=""
DIRECTION="both"   # both | ingress | egress

while getopts "c:r:d:h" opt; do
  case "$opt" in
    c) SINGLE_COMP="$OPTARG" ;;
    r) REGION_OVERRIDE="$OPTARG" ;;
    d) DIRECTION="$OPTARG" ;;
    h) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "Use -h for help"; exit 1 ;;
  esac
done

REGION_ARG=()
[ -n "$REGION_OVERRIDE" ] && REGION_ARG=(--region "$REGION_OVERRIDE")
o() { oci "${REGION_ARG[@]}" "$@" 2>/dev/null; }

TS="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="oci_ppsm_ports_${TS}.csv"
echo "compartment_id,compartment_name,vcn,rule_container,container_type,direction,stateless,protocol,port_range,source_or_dest,well_known_service,function,exposure_flag,justification" > "$OUT"

declare -A COMP_NAME
LIST_ITER='if (.data|type)=="object" then ((.data.items // []) | .[]) elif (.data|type)=="array" then (.data[]) else empty end'

# ---------------------------------------------------------------------------
# Well-known port -> "service|function" lookup (IANA + common cloud/OCI ports)
# ---------------------------------------------------------------------------
wellknown() {  # $1 = protocol number/name, $2 = single port (min of range)
  local proto="$1" port="$2"
  case "$proto" in
    1)  echo "ICMP|Network diagnostics/control (ping, path MTU)"; return ;;
    58) echo "ICMPv6|IPv6 diagnostics/control"; return ;;
  esac
  case "$port" in
    22)    echo "SSH|Secure shell / admin access" ;;
    23)    echo "Telnet|UNENCRYPTED remote access (should not be open)" ;;
    25)    echo "SMTP|Mail transfer" ;;
    53)    echo "DNS|Name resolution" ;;
    80)    echo "HTTP|Web (plaintext) - typically LB frontend or redirect" ;;
    110)   echo "POP3|Mail retrieval" ;;
    123)   echo "NTP|Time synchronization" ;;
    143)   echo "IMAP|Mail retrieval" ;;
    389)   echo "LDAP|Directory (plaintext)" ;;
    443)   echo "HTTPS|Web (TLS) - LB frontend / API endpoint" ;;
    445)   echo "SMB|Windows file sharing" ;;
    465)   echo "SMTPS|Mail transfer (TLS)" ;;
    587)   echo "SMTP-Submission|Mail submission (STARTTLS)" ;;
    636)   echo "LDAPS|Directory (TLS)" ;;
    993)   echo "IMAPS|Mail retrieval (TLS)" ;;
    995)   echo "POP3S|Mail retrieval (TLS)" ;;
    1433)  echo "MSSQL|Microsoft SQL Server" ;;
    1521)  echo "Oracle-DB|Oracle Net listener (TNS)" ;;
    1522)  echo "Oracle-DB-alt|Oracle Net listener (alt/ADB)" ;;
    2484)  echo "Oracle-TCPS|Oracle Net over TLS (TCPS)" ;;
    3306)  echo "MySQL|MySQL database" ;;
    3389)  echo "RDP|Windows Remote Desktop" ;;
    5432)  echo "PostgreSQL|PostgreSQL database" ;;
    5601)  echo "Kibana|Log/analytics UI" ;;
    6379)  echo "Redis|In-memory cache/data store" ;;
    8080)  echo "HTTP-alt|Alt web / app server" ;;
    8443)  echo "HTTPS-alt|Alt web (TLS) / mgmt console" ;;
    9000)  echo "App-9000|Common app/console port (verify)" ;;
    9200)  echo "Elasticsearch|Search/analytics API" ;;
    10250) echo "Kubelet|Kubernetes node agent API" ;;
    6443)  echo "K8s-API|Kubernetes API server (OKE)" ;;
    2049)  echo "NFS|File Storage (FSS) mount" ;;
    111)   echo "RPCbind|NFS portmapper (FSS)" ;;
    *)     echo "unassigned|VERIFY - not a standard well-known port" ;;
  esac
}

# Sensitive ports that should NOT be open to 0.0.0.0/0
is_sensitive_port() {  # $1 = min port
  case "$1" in
    22|23|3389|1521|1522|2484|3306|5432|1433|6379|9200|10250|6443|445|389) return 0 ;;
    *) return 1 ;;
  esac
}

# Map protocol number -> name
proto_name() {
  case "$1" in
    1) echo "ICMP" ;; 6) echo "TCP" ;; 17) echo "UDP" ;; 58) echo "ICMPv6" ;;
    all|"") echo "ALL" ;; *) echo "proto-$1" ;;
  esac
}

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
echo "Collecting CM-7/PPSM port inventory across ${COMP_COUNT} compartment(s)..."
echo

# ---------------------------------------------------------------------------
# Emit one CSV row from a normalized rule
# ---------------------------------------------------------------------------
emit_rule() {
  # args: comp vcn container ctype direction stateless proto_num portmin portmax peer
  local comp="$1" vcn="$2" container="$3" ctype="$4" dir="$5" stateless="$6"
  local pnum="$7" pmin="$8" pmax="$9" peer="${10}"

  local pname prange svc func exposure
  pname="$(proto_name "$pnum")"

  if [ -n "$pmin" ] && [ "$pmin" != "null" ]; then
    if [ "$pmin" = "$pmax" ] || [ -z "$pmax" ] || [ "$pmax" = "null" ]; then
      prange="$pmin"
    else
      prange="${pmin}-${pmax}"
    fi
    IFS='|' read -r svc func <<< "$(wellknown "$pnum" "$pmin")"
  else
    prange="ALL"
    if [ "$pname" = "ICMP" ] || [ "$pname" = "ICMPv6" ]; then
      IFS='|' read -r svc func <<< "$(wellknown "$pnum" 0)"
    else
      svc="ALL-PORTS"; func="Entire port range open for $pname - VERIFY tight scoping"
    fi
  fi

  # Exposure flag
  exposure="scoped"
  if [ "$peer" = "0.0.0.0/0" ] || [ "$peer" = "::/0" ]; then
    if [ "$dir" = "ingress" ]; then
      if [ "$prange" = "ALL" ]; then
        exposure="OPEN-ALL-PORTS-INTERNET"
      elif is_sensitive_port "$pmin"; then
        exposure="SENSITIVE-PORT-OPEN-INTERNET"
      else
        exposure="internet-facing"
      fi
    else
      exposure="egress-any"
    fi
  fi

  row "$comp" "$vcn" "$container" "$ctype" "$dir" "$stateless" "$pname" "$prange" "$peer" "$svc" "$func" "$exposure" ""
}

# Parse the tcp-options/udp-options structure to extract port min/max.
# OCI puts destination-port-range on ingress (the port being connected TO).
# Returns "min max" or "" if no port options (all ports).
extract_ports() {  # $1 = rule json, $2 = proto option key (tcp-options|udp-options)
  local rule="$1" key="$2"
  echo "$rule" | jq -r --arg k "$key" '
    (.[$k] // {}) as $opt |
    ($opt."destination-port-range" // $opt."source-port-range" // null) as $r |
    if $r == null then "ALL ALL"
    else "\($r.min) \($r.max)" end' 2>/dev/null
}

# ---------------------------------------------------------------------------
# Security Lists
# ---------------------------------------------------------------------------
check_seclists() {
  local comp="$1" vcnid="$2" vcnname="$3"
  o network security-list list --compartment-id "$comp" --vcn-id "$vcnid" --all 2>/dev/null | jq -c "$LIST_ITER" 2>/dev/null | \
  while IFS= read -r sl; do
    [ -z "$sl" ] && continue
    local slname
    slname="$(echo "$sl" | jq -r '."display-name" // "security-list"')"

    if [ "$DIRECTION" = "both" ] || [ "$DIRECTION" = "ingress" ]; then
      echo "$sl" | jq -c '."ingress-security-rules"[]?' 2>/dev/null | while IFS= read -r r; do
        [ -z "$r" ] && continue
        _emit_seclist_rule "$comp" "$vcnname" "$slname" "ingress" "$r"
      done
    fi
    if [ "$DIRECTION" = "both" ] || [ "$DIRECTION" = "egress" ]; then
      echo "$sl" | jq -c '."egress-security-rules"[]?' 2>/dev/null | while IFS= read -r r; do
        [ -z "$r" ] && continue
        _emit_seclist_rule "$comp" "$vcnname" "$slname" "egress" "$r"
      done
    fi
  done
}

_emit_seclist_rule() {
  local comp="$1" vcn="$2" slname="$3" dir="$4" r="$5"
  local proto stateless peer pkey ports pmin pmax
  proto="$(echo "$r" | jq -r '.protocol // "all"')"
  stateless="$(echo "$r" | jq -r '.["is-stateless"] // false')"
  if [ "$dir" = "ingress" ]; then
    peer="$(echo "$r" | jq -r '.source // "n/a"')"
  else
    peer="$(echo "$r" | jq -r '.destination // "n/a"')"
  fi

  # protocol: "6"=TCP "17"=UDP "1"=ICMP "all"
  case "$proto" in
    6)  pkey="tcp-options" ;;
    17) pkey="udp-options" ;;
    *)  pkey="" ;;
  esac

  if [ -n "$pkey" ]; then
    read -r pmin pmax <<< "$(extract_ports "$r" "$pkey")"
    [ "$pmin" = "ALL" ] && { pmin=""; pmax=""; }
    emit_rule "$comp" "$vcn" "$slname" "SecurityList" "$dir" "$stateless" "$proto" "$pmin" "$pmax" "$peer"
  else
    # ICMP or all-protocol
    emit_rule "$comp" "$vcn" "$slname" "SecurityList" "$dir" "$stateless" "$proto" "" "" "$peer"
  fi
}

# ---------------------------------------------------------------------------
# Network Security Groups (NSGs)
# ---------------------------------------------------------------------------
check_nsgs() {
  local comp="$1" vcnid="$2" vcnname="$3"
  o network nsg list --compartment-id "$comp" --vcn-id "$vcnid" --all 2>/dev/null | jq -c "$LIST_ITER" 2>/dev/null | \
  while IFS= read -r nsg; do
    [ -z "$nsg" ] && continue
    local nsgid nsgname
    nsgid="$(echo "$nsg" | jq -r '.id')"
    nsgname="$(echo "$nsg" | jq -r '."display-name" // "nsg"')"

    o network nsg rules list --nsg-id "$nsgid" --all 2>/dev/null | jq -c "$LIST_ITER" 2>/dev/null | \
    while IFS= read -r r; do
      [ -z "$r" ] && continue
      local dir proto stateless peer ptype pkey pmin pmax
      dir="$(echo "$r" | jq -r '.direction // "INGRESS"' | tr '[:upper:]' '[:lower:]')"
      [ "$DIRECTION" = "ingress" ] && [ "$dir" != "ingress" ] && continue
      [ "$DIRECTION" = "egress" ]  && [ "$dir" != "egress" ]  && continue

      proto="$(echo "$r" | jq -r '.protocol // "all"')"
      stateless="$(echo "$r" | jq -r '.["is-stateless"] // false')"
      # NSG peer can be a CIDR or another NSG
      ptype="$(echo "$r" | jq -r '.["source-type"] // .["destination-type"] // "CIDR_BLOCK"')"
      if [ "$dir" = "ingress" ]; then
        peer="$(echo "$r" | jq -r '.source // "n/a"')"
      else
        peer="$(echo "$r" | jq -r '.destination // "n/a"')"
      fi
      [ "$ptype" = "NETWORK_SECURITY_GROUP" ] && peer="NSG:${peer: -12}"

      case "$proto" in
        6)  pkey="tcp-options" ;;
        17) pkey="udp-options" ;;
        *)  pkey="" ;;
      esac
      if [ -n "$pkey" ]; then
        read -r pmin pmax <<< "$(extract_ports "$r" "$pkey")"
        [ "$pmin" = "ALL" ] && { pmin=""; pmax=""; }
        emit_rule "$comp" "$vcnname" "$nsgname" "NSG" "$dir" "$stateless" "$proto" "$pmin" "$pmax" "$peer"
      else
        emit_rule "$comp" "$vcnname" "$nsgname" "NSG" "$dir" "$stateless" "$proto" "" "" "$peer"
      fi
    done
  done
}

# ---------------------------------------------------------------------------
# Main loop — per compartment, enumerate VCNs, then seclists + NSGs
# ---------------------------------------------------------------------------
i=0
while IFS= read -r comp; do
  [ -z "$comp" ] && continue
  i=$((i+1))
  echo "[$i/$COMP_COUNT] ${COMP_NAME[$comp]:-$comp}"

  o network vcn list --compartment-id "$comp" --all 2>/dev/null | jq -c "$LIST_ITER" 2>/dev/null | \
  while IFS= read -r vcn; do
    [ -z "$vcn" ] && continue
    vcnid="$(echo "$vcn" | jq -r '.id')"
    vcnname="$(echo "$vcn" | jq -r '."display-name" // "vcn"')"
    check_seclists "$comp" "$vcnid" "$vcnname"
    check_nsgs     "$comp" "$vcnid" "$vcnname"
  done
done <<< "$COMPS"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo
echo "======================================================================"
echo "CM-7 / PPSM PORT INVENTORY SUMMARY"
echo "======================================================================"
TOTAL="$(($(wc -l < "$OUT") - 1))"
OPEN_ALL="$(awk -F',' 'NR>1 {gsub(/"/,"",$13); if($13=="OPEN-ALL-PORTS-INTERNET") print}' "$OUT" | grep -c . || true)"
SENS="$(awk -F',' 'NR>1 {gsub(/"/,"",$13); if($13=="SENSITIVE-PORT-OPEN-INTERNET") print}' "$OUT" | grep -c . || true)"
NETFACING="$(awk -F',' 'NR>1 {gsub(/"/,"",$13); if($13=="internet-facing") print}' "$OUT" | grep -c . || true)"

echo "Total rules inventoried            : $TOTAL"
echo "Internet-facing (0.0.0.0/0) rules  : $NETFACING"
echo "SENSITIVE port open to internet    : $SENS"
echo "ALL ports open to internet         : $OPEN_ALL"
if [ "$SENS" -gt 0 ] || [ "$OPEN_ALL" -gt 0 ]; then
  echo
  echo ">>> HIGH-RISK EXPOSURE — review before ATO (CM-7 least functionality):"
  awk -F',' 'NR>1 {gsub(/"/,"",$2);gsub(/"/,"",$3);gsub(/"/,"",$8);gsub(/"/,"",$9);gsub(/"/,"",$11);gsub(/"/,"",$13);
    if($13=="SENSITIVE-PORT-OPEN-INTERNET" || $13=="OPEN-ALL-PORTS-INTERNET")
      printf "  [%-14s] %-18s %s/%s (%s) -> %s\n", $2, $3, $8, $9, $11, $13}' "$OUT"
fi
echo
echo "Inventory CSV written to: $OUT"
echo
echo "NEXT STEP: complete the 'justification' column (last column) for each"
echo "rule. OCI provides the facts and well-known-service annotation; only your"
echo "org can attest the business need. Rows flagged 'unassigned' or 'VERIFY'"
echo "in the function column need confirmation of what actually listens there."
