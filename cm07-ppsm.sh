#!/usr/bin/env bash
#
# oci_restricted_ppsm_scan.sh
#
# CM-7 / PPSM RESTRICTED & PROHIBITED PORTS SCAN
#
# Scans the OCI network surface (Security Lists + NSGs, ingress + egress) for
# any rule that opens a RESTRICTED or PROHIBITED port/protocol, checked against:
#   (1) a built-in DoD/DISA-aligned restricted & prohibited PPS list, AND
#   (2) an optional custom list you supply (-x file) for org-specific ports.
#
# Findings are RANKED: a restricted port exposed to the internet (0.0.0.0/0)
# is CRITICAL; the same port scoped to an internal CIDR is still reported but
# lower severity. This supports CM-7 least-functionality and PPSM boundary
# compliance.
#
# Designed for OCI Cloud Shell (uses your delegation token). No API keys.
# READ-ONLY: every call is a list/get. Nothing is created/modified/deleted.
#
# IMPORTANT — authority note: the built-in list is aligned to commonly
# restricted/prohibited PPS (Telnet, FTP, TFTP, NetBIOS/SMB, r-services, SNMP
# v1/v2, plaintext LDAP, etc.). DISA's PPSM CAL is the authoritative source and
# changes over time; treat this as a strong default, verify against the current
# CAL, and extend via -x for your boundary's specifics.
#
# Usage:
#   ./oci_restricted_ppsm_scan.sh                  # built-in list, all comps
#   ./oci_restricted_ppsm_scan.sh -x custom.csv    # add custom restricted ports
#   ./oci_restricted_ppsm_scan.sh -c <ocid>        # single compartment
#   ./oci_restricted_ppsm_scan.sh -r us-langley-1  # region override (GovCloud)
#   ./oci_restricted_ppsm_scan.sh --list           # print built-in list and exit
#
# Custom list format (-x), CSV with header:
#   port,protocol,category,label,reason
#   e.g.  9999,TCP,RESTRICTED,LegacyApp,Deprecated internal app - migrate off
#   (protocol may be TCP, UDP, or ANY; port may be a single port or min-max)
#
# Output: timestamped findings CSV + console summary ranked by severity.
#
set -uo pipefail

command -v oci >/dev/null 2>&1 || { echo "ERROR: oci CLI not found."; exit 1; }
command -v jq  >/dev/null 2>&1 || { echo "ERROR: jq not found."; exit 1; }

SINGLE_COMP=""; REGION_OVERRIDE=""; DIRECTION="both"; CUSTOM=""; LIST_ONLY=0

# manual arg parse to allow long --list
ARGS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --list) LIST_ONLY=1; shift ;;
    -c) SINGLE_COMP="$2"; shift 2 ;;
    -r) REGION_OVERRIDE="$2"; shift 2 ;;
    -d) DIRECTION="$2"; shift 2 ;;
    -x) CUSTOM="$2"; shift 2 ;;
    -h) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) shift ;;
  esac
done

REGION_ARG=(); [ -n "$REGION_OVERRIDE" ] && REGION_ARG=(--region "$REGION_OVERRIDE")
o() { oci "${REGION_ARG[@]}" "$@" 2>/dev/null; }

TS="$(date -u +%Y%m%dT%H%M%SZ)"
declare -A COMP_NAME
LIST_ITER='if (.data|type)=="object" then ((.data.items // []) | .[]) elif (.data|type)=="array" then (.data[]) else empty end'

# ===========================================================================
# BUILT-IN RESTRICTED / PROHIBITED PPS LIST
# Format per entry: "port|proto|category|label|reason"
#   proto: TCP | UDP | ANY
#   category: PROHIBITED (should never be open) | RESTRICTED (conditional/controlled)
# ===========================================================================
BUILTIN_PPS=(
  # --- Cleartext / legacy remote access: PROHIBITED ---
  "23|TCP|PROHIBITED|Telnet|Cleartext remote login - prohibited; use SSH"
  "512|TCP|PROHIBITED|rexec|Berkeley r-exec - cleartext; prohibited"
  "513|TCP|PROHIBITED|rlogin|Berkeley r-login - cleartext; prohibited"
  "514|TCP|PROHIBITED|rsh|Berkeley r-shell - cleartext; prohibited"
  "1521|TCP|RESTRICTED|Oracle-DB|DB listener - restrict to app tiers, never internet"
  # --- File transfer: FTP/TFTP ---
  "20|TCP|RESTRICTED|FTP-data|Cleartext FTP data - use SFTP/FTPS"
  "21|TCP|RESTRICTED|FTP-control|Cleartext FTP control - use SFTP/FTPS"
  "69|UDP|PROHIBITED|TFTP|Trivial FTP - no auth, cleartext; prohibited"
  # --- Windows / NetBIOS / SMB ---
  "135|TCP|PROHIBITED|MS-RPC|MS RPC endpoint mapper - do not expose"
  "137|UDP|PROHIBITED|NetBIOS-ns|NetBIOS name service - do not expose"
  "138|UDP|PROHIBITED|NetBIOS-dgm|NetBIOS datagram - do not expose"
  "139|TCP|PROHIBITED|NetBIOS-ssn|NetBIOS session - do not expose"
  "445|TCP|PROHIBITED|SMB|SMB/CIFS - never expose across boundary"
  # --- Name / directory / mgmt in cleartext ---
  "161|UDP|RESTRICTED|SNMP|SNMP v1/v2 cleartext - use v3; restrict tightly"
  "162|UDP|RESTRICTED|SNMP-trap|SNMP trap cleartext - use v3"
  "389|TCP|RESTRICTED|LDAP|Cleartext LDAP - use LDAPS (636)"
  "5353|UDP|RESTRICTED|mDNS|Multicast DNS - do not route across boundary"
  # --- Remote desktop / VNC ---
  "3389|TCP|RESTRICTED|RDP|Remote Desktop - never internet-facing; bastion only"
  "5900|TCP|RESTRICTED|VNC|VNC remote desktop - often cleartext; restrict"
  "5800|TCP|RESTRICTED|VNC-http|VNC over HTTP - restrict"
  # --- Databases (restrict to app tiers) ---
  "1433|TCP|RESTRICTED|MSSQL|SQL Server - restrict to app tiers"
  "3306|TCP|RESTRICTED|MySQL|MySQL - restrict to app tiers"
  "5432|TCP|RESTRICTED|PostgreSQL|PostgreSQL - restrict to app tiers"
  "6379|TCP|RESTRICTED|Redis|Redis - no native auth by default; never expose"
  "27017|TCP|RESTRICTED|MongoDB|MongoDB - never expose across boundary"
  "9200|TCP|RESTRICTED|Elasticsearch|ES API - never expose; restrict"
  "11211|TCP|RESTRICTED|Memcached|Memcached - no auth; never expose (DDoS amp)"
  # --- Mail cleartext ---
  "25|TCP|RESTRICTED|SMTP|Cleartext SMTP - control relay; prefer 587/465 TLS"
  "110|TCP|RESTRICTED|POP3|Cleartext POP3 - use POP3S (995)"
  "143|TCP|RESTRICTED|IMAP|Cleartext IMAP - use IMAPS (993)"
  # --- Misc high-risk ---
  "111|TCP|RESTRICTED|RPCbind|Portmapper - restrict (FSS internal only)"
  "2049|TCP|RESTRICTED|NFS|NFS - internal only (FSS); never cross boundary"
  "5601|TCP|RESTRICTED|Kibana|Kibana UI - restrict; never internet-facing"
  "10250|TCP|RESTRICTED|Kubelet|Kubelet API - never expose"
  "6443|TCP|RESTRICTED|K8s-API|K8s API server - restrict to admin CIDRs"
)

if [ "$LIST_ONLY" = "1" ]; then
  echo "Built-in restricted/prohibited PPS list:"
  echo "PORT   PROTO  CATEGORY    LABEL           REASON"
  for e in "${BUILTIN_PPS[@]}"; do
    IFS='|' read -r p pr cat lbl rsn <<< "$e"
    printf "%-6s %-6s %-11s %-15s %s\n" "$p" "$pr" "$cat" "$lbl" "$rsn"
  done
  exit 0
fi

# ===========================================================================
# Build restricted lookup: assoc arrays keyed by "port|proto"
#   RESTRICTED_CAT["port|proto"]=CATEGORY
#   RESTRICTED_LBL / RESTRICTED_RSN / RESTRICTED_SRC (BUILTIN|CUSTOM)
# ===========================================================================
declare -A RCAT RLBL RRSN RSRC
load_entry() {
  local port="$1" proto="$2" cat="$3" lbl="$4" rsn="$5" src="$6"
  proto="$(echo "$proto" | tr '[:lower:]' '[:upper:]')"
  RCAT["${port}|${proto}"]="$cat"; RLBL["${port}|${proto}"]="$lbl"
  RRSN["${port}|${proto}"]="$rsn"; RSRC["${port}|${proto}"]="$src"
}
for e in "${BUILTIN_PPS[@]}"; do IFS='|' read -r p pr cat lbl rsn <<< "$e"; load_entry "$p" "$pr" "$cat" "$lbl" "$rsn" "BUILTIN"; done

if [ -n "$CUSTOM" ]; then
  [ -f "$CUSTOM" ] || { echo "ERROR: custom list not found: $CUSTOM"; exit 1; }
  # CSV: port,protocol,category,label,reason
  tail -n +2 "$CUSTOM" | while IFS=, read -r port proto cat lbl rsn; do :; done  # noop validate
  while IFS=, read -r port proto cat lbl rsn; do
    [ -z "$port" ] && continue
    [ "$port" = "port" ] && continue
    port="$(echo "$port" | tr -d '"' | xargs 2>/dev/null)"
    proto="$(echo "${proto:-ANY}" | tr -d '"' | xargs 2>/dev/null)"
    cat="$(echo "${cat:-RESTRICTED}" | tr -d '"' | xargs 2>/dev/null)"
    lbl="$(echo "${lbl:-custom}" | tr -d '"' | xargs 2>/dev/null)"
    rsn="$(echo "${rsn:-custom restricted port}" | tr -d '"')"
    load_entry "$port" "$proto" "$cat" "$lbl" "$rsn" "CUSTOM"
  done < <(tail -n +2 "$CUSTOM")
fi

OUT="oci_restricted_ppsm_findings_${TS}.csv"
echo "severity,compartment_id,compartment_name,vcn,rule_container,container_type,direction,protocol,port_range,matched_port,source_or_dest,category,label,list_source,reason,exposure" > "$OUT"

# --- helpers ---------------------------------------------------------------
proto_name() { case "$1" in 1) echo ICMP ;; 6) echo TCP ;; 17) echo UDP ;; 58) echo ICMPv6 ;; all|"") echo ANY ;; *) echo "proto-$1" ;; esac ; }
extract_ports() {
  local rule="$1" key="$2"
  echo "$rule" | jq -r --arg k "$key" '
    (.[$k] // {}) as $opt | ($opt."destination-port-range" // $opt."source-port-range" // null) as $r |
    if $r == null then "ALL ALL" else "\($r.min) \($r.max)" end' 2>/dev/null
}

csv_escape() { local s="$1"; s="${s//\"/\"\"}"; printf '"%s"' "$s"; }

# Given a proto name + port min/max, find any restricted match within the range.
# Emits finding rows. Because a rule may span a range (e.g. 1-65535), we test
# each restricted port for membership in [min,max].
check_against_restricted() {
  local comp="$1" vcn="$2" container="$3" ctype="$4" dir="$5" pname="$6" pmin="$7" pmax="$8" peer="$9"

  # Determine numeric range; if ALL ports, treat as 1-65535 for membership test
  local lo hi allports=0
  if [ -z "$pmin" ] || [ "$pmin" = "ALL" ] || [ "$pmin" = "null" ]; then lo=1; hi=65535; allports=1
  else lo="$pmin"; hi="${pmax:-$pmin}"; [ "$hi" = "ALL" ] && hi=65535; [ "$hi" = "null" ] && hi="$pmin"; fi

  # exposure
  local internet=0
  { [ "$peer" = "0.0.0.0/0" ] || [ "$peer" = "::/0" ]; } && internet=1

  # Iterate the restricted keys; match on proto (exact or ANY) and port membership
  local key rport rproto cat lbl rsn src sev exposure prange_disp
  for key in "${!RCAT[@]}"; do
    rport="${key%%|*}"; rproto="${key##*|}"
    # proto match: restricted ANY matches anything; else must equal rule proto,
    # but a rule with ANY protocol (pname=ANY) can carry any port -> match too
    if [ "$rproto" != "ANY" ] && [ "$pname" != "ANY" ] && [ "$rproto" != "$pname" ]; then continue; fi

    # port membership: restricted port may itself be a range "min-max"
    local rlo rhi
    if [[ "$rport" == *-* ]]; then rlo="${rport%-*}"; rhi="${rport#*-}"; else rlo="$rport"; rhi="$rport"; fi
    # overlap test between [lo,hi] and [rlo,rhi]
    if [ "$lo" -le "$rhi" ] && [ "$hi" -ge "$rlo" ]; then
      cat="${RCAT[$key]}"; lbl="${RLBL[$key]}"; rsn="${RRSN[$key]}"; src="${RSRC[$key]}"

      # severity ranking:
      #  CRITICAL: internet-exposed AND (PROHIBITED or restricted)
      #  HIGH    : PROHIBITED but internally scoped, OR restricted internet on non-prohibited
      #  MEDIUM  : RESTRICTED, internally scoped
      if [ "$internet" = "1" ]; then
        sev="CRITICAL"; exposure="INTERNET(0.0.0.0/0)"
      else
        if [ "$cat" = "PROHIBITED" ]; then sev="HIGH"; else sev="MEDIUM"; fi
        exposure="scoped:$peer"
      fi
      # An all-ports rule that sweeps in a prohibited port is worse -> bump note
      if [ "$allports" = "1" ]; then exposure="${exposure};rule-opens-ALL-ports"; fi

      if [ "$allports" = "1" ]; then prange_disp="ALL"; elif [ "$lo" = "$hi" ]; then prange_disp="$lo"; else prange_disp="${lo}-${hi}"; fi

      printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
        "$(csv_escape "$sev")" "$(csv_escape "$comp")" "$(csv_escape "${COMP_NAME[$comp]:-<unknown>}")" \
        "$(csv_escape "$vcn")" "$(csv_escape "$container")" "$(csv_escape "$ctype")" "$(csv_escape "$dir")" \
        "$(csv_escape "$pname")" "$(csv_escape "$prange_disp")" "$(csv_escape "$rport")" "$(csv_escape "$peer")" \
        "$(csv_escape "$cat")" "$(csv_escape "$lbl")" "$(csv_escape "$src")" "$(csv_escape "$rsn")" \
        "$(csv_escape "$exposure")" >> "$OUT"
    fi
  done
}

# --- compartment enumeration ------------------------------------------------
TENANCY_ID="$(o iam compartment list --access-level ANY --limit 1 --query 'data[0]."compartment-id"' --raw-output 2>/dev/null)"
echo "Region : ${REGION_OVERRIDE:-<cloud-shell-default>}"
echo "Tenancy: ${TENANCY_ID:-<unknown>}"
echo "Restricted entries loaded: ${#RCAT[@]} (built-in + custom)"
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
echo "Scanning ${COMP_COUNT} compartment(s) for restricted/prohibited ports..."
echo

# --- main scan --------------------------------------------------------------
i=0
while IFS= read -r comp; do
  [ -z "$comp" ] && continue
  i=$((i+1))
  echo "[$i/$COMP_COUNT] ${COMP_NAME[$comp]:-$comp}"

  o network vcn list --compartment-id "$comp" --all 2>/dev/null | jq -c "$LIST_ITER" 2>/dev/null | \
  while IFS= read -r vcn; do
    [ -z "$vcn" ] && continue
    vcnid="$(echo "$vcn" | jq -r '.id')"; vcnname="$(echo "$vcn" | jq -r '."display-name" // "vcn"')"

    # Security lists
    o network security-list list --compartment-id "$comp" --vcn-id "$vcnid" --all 2>/dev/null | jq -c "$LIST_ITER" 2>/dev/null | \
    while IFS= read -r sl; do
      [ -z "$sl" ] && continue
      slname="$(echo "$sl" | jq -r '."display-name" // "security-list"')"
      for d in ingress egress; do
        [ "$DIRECTION" != both ] && [ "$DIRECTION" != "$d" ] && continue
        echo "$sl" | jq -c ".\"${d}-security-rules\"[]?" 2>/dev/null | while IFS= read -r r; do
          [ -z "$r" ] && continue
          proto="$(echo "$r" | jq -r '.protocol // "all"')"; pname="$(proto_name "$proto")"
          if [ "$d" = ingress ]; then peer="$(echo "$r" | jq -r '.source // "n/a"')"; else peer="$(echo "$r" | jq -r '.destination // "n/a"')"; fi
          case "$proto" in 6) pkey=tcp-options ;; 17) pkey=udp-options ;; *) pkey="" ;; esac
          if [ -n "$pkey" ]; then read -r pmin pmax <<< "$(extract_ports "$r" "$pkey")"; else pmin="ALL"; pmax="ALL"; fi
          check_against_restricted "$comp" "$vcnname" "$slname" "SecurityList" "$d" "$pname" "$pmin" "$pmax" "$peer"
        done
      done
    done

    # NSGs
    o network nsg list --compartment-id "$comp" --vcn-id "$vcnid" --all 2>/dev/null | jq -c "$LIST_ITER" 2>/dev/null | \
    while IFS= read -r nsg; do
      [ -z "$nsg" ] && continue
      nsgid="$(echo "$nsg" | jq -r '.id')"; nsgname="$(echo "$nsg" | jq -r '."display-name" // "nsg"')"
      o network nsg rules list --nsg-id "$nsgid" --all 2>/dev/null | jq -c "$LIST_ITER" 2>/dev/null | \
      while IFS= read -r r; do
        [ -z "$r" ] && continue
        d="$(echo "$r" | jq -r '.direction // "INGRESS"' | tr '[:upper:]' '[:lower:]')"
        [ "$DIRECTION" != both ] && [ "$DIRECTION" != "$d" ] && continue
        proto="$(echo "$r" | jq -r '.protocol // "all"')"; pname="$(proto_name "$proto")"
        ptype="$(echo "$r" | jq -r '.["source-type"] // .["destination-type"] // "CIDR_BLOCK"')"
        if [ "$d" = ingress ]; then peer="$(echo "$r" | jq -r '.source // "n/a"')"; else peer="$(echo "$r" | jq -r '.destination // "n/a"')"; fi
        [ "$ptype" = NETWORK_SECURITY_GROUP ] && peer="NSG:${peer: -12}"
        case "$proto" in 6) pkey=tcp-options ;; 17) pkey=udp-options ;; *) pkey="" ;; esac
        if [ -n "$pkey" ]; then read -r pmin pmax <<< "$(extract_ports "$r" "$pkey")"; else pmin="ALL"; pmax="ALL"; fi
        check_against_restricted "$comp" "$vcnname" "$nsgname" "NSG" "$d" "$pname" "$pmin" "$pmax" "$peer"
      done
    done
  done
done <<< "$COMPS"

# --- summary ----------------------------------------------------------------
echo
echo "======================================================================"
echo "RESTRICTED / PROHIBITED PPS FINDINGS"
echo "======================================================================"
TOTAL="$(($(wc -l < "$OUT") - 1))"
CRIT="$(awk -F',' 'NR>1 && $1=="\"CRITICAL\""' "$OUT" | grep -c . || true)"
HIGH="$(awk -F',' 'NR>1 && $1=="\"HIGH\""' "$OUT" | grep -c . || true)"
MED="$(awk -F',' 'NR>1 && $1=="\"MEDIUM\""' "$OUT" | grep -c . || true)"
echo "Total findings : $TOTAL"
echo "  CRITICAL (restricted port internet-exposed) : $CRIT"
echo "  HIGH     (prohibited port, internal scope)  : $HIGH"
echo "  MEDIUM   (restricted port, internal scope)  : $MED"
if [ "$CRIT" -gt 0 ]; then
  echo
  echo ">>> CRITICAL — restricted/prohibited ports open to the internet:"
  awk -F',' 'NR>1 && $1=="\"CRITICAL\"" {gsub(/"/,"",$3);gsub(/"/,"",$5);gsub(/"/,"",$8);gsub(/"/,"",$10);gsub(/"/,"",$13);gsub(/"/,"",$11);
    printf "  [%-14s] %-18s %s port %s (%s) from %s\n",$3,$5,$8,$10,$13,$11}' "$OUT"
fi
if [ "$HIGH" -gt 0 ]; then
  echo
  echo ">>> HIGH — prohibited ports open (internal):"
  awk -F',' 'NR>1 && $1=="\"HIGH\"" {gsub(/"/,"",$3);gsub(/"/,"",$5);gsub(/"/,"",$10);gsub(/"/,"",$13);gsub(/"/,"",$11);
    printf "  [%-14s] %-18s port %s (%s) from %s\n",$3,$5,$10,$13,$11}' "$OUT"
fi
echo
echo "Findings CSV written to: $OUT"
echo
echo "AUTHORITY NOTE: built-in list is DoD/DISA-aligned but not a substitute for"
echo "the current PPSM CAL. Verify against your boundary's CAL and extend via -x."
echo "Run './$(basename "$0") --list' to see the built-in restricted entries."
