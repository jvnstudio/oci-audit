#!/usr/bin/env bash
#
# oci_ppsm_approval.sh
#
# CM-7 / PPSM PORT APPROVAL LIFECYCLE — generate baseline, reconcile drift,
# and read approval tags. Read-only against OCI; the only file it writes are
# your evidence CSVs.
#
# IMPORTANT — OCI has NO native "approved" flag on a port. Approval is an
# organizational record. This tool supports the real workflow:
#
#   1) generate  -> snapshot current rules into a baseline TEMPLATE with an
#                   approval_status column = PENDING-REVIEW and blank
#                   approval_id / justification. Take this to your CCB/PPSM,
#                   mark each row APPROVED or DENIED, fill approval_id +
#                   justification. The completed file is your APPROVED baseline.
#
#   2) reconcile -> compare LIVE rules against your approved baseline CSV and
#                   classify every rule:
#                     APPROVED         live rule matches an APPROVED baseline row
#                     UNAPPROVED-DRIFT live rule with no approved match (FINDING)
#                     MISSING          approved baseline row not implemented live
#                   This reconciliation IS the proof-of-approval evidence.
#
#   3) tags      -> read OCI defined tags on NSGs / security lists (e.g.
#                   PPSM.Status, PPSM.ApprovalID) as an approval attestation
#                   where you tag the container.
#
# Designed for OCI Cloud Shell (uses your delegation token). No API keys.
#
# Usage:
#   ./oci_ppsm_approval.sh generate                       # make baseline template
#   ./oci_ppsm_approval.sh reconcile -b approved_baseline.csv
#   ./oci_ppsm_approval.sh tags
#   Common flags: -c <comp-ocid>  -r <region>  -d ingress|egress|both
#
# READ-ONLY against OCI. Nothing is created/modified/deleted in the tenancy.
#
set -uo pipefail

command -v oci >/dev/null 2>&1 || { echo "ERROR: oci CLI not found."; exit 1; }
command -v jq  >/dev/null 2>&1 || { echo "ERROR: jq not found."; exit 1; }

MODE="${1:-}"
case "$MODE" in generate|reconcile|tags) shift ;; *)
  echo "Usage: $0 {generate|reconcile|tags} [options]"; echo "  -b baseline.csv (reconcile)  -c comp  -r region  -d direction"; exit 1 ;;
esac

SINGLE_COMP=""; REGION_OVERRIDE=""; DIRECTION="both"; BASELINE=""
while getopts "c:r:d:b:h" opt; do
  case "$opt" in
    c) SINGLE_COMP="$OPTARG" ;;
    r) REGION_OVERRIDE="$OPTARG" ;;
    d) DIRECTION="$OPTARG" ;;
    b) BASELINE="$OPTARG" ;;
    h) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) exit 1 ;;
  esac
done

REGION_ARG=(); [ -n "$REGION_OVERRIDE" ] && REGION_ARG=(--region "$REGION_OVERRIDE")
o() { oci "${REGION_ARG[@]}" "$@" 2>/dev/null; }

TS="$(date -u +%Y%m%dT%H%M%SZ)"
declare -A COMP_NAME
LIST_ITER='if (.data|type)=="object" then ((.data.items // []) | .[]) elif (.data|type)=="array" then (.data[]) else empty end'

# --- well-known port annotation (shared with inventory script) --------------
wellknown() {
  local proto="$1" port="$2"
  case "$proto" in 1) echo "ICMP|Network diagnostics"; return ;; 58) echo "ICMPv6|IPv6 diagnostics"; return ;; esac
  case "$port" in
    22) echo "SSH|Secure shell / admin" ;; 23) echo "Telnet|UNENCRYPTED remote access" ;;
    25) echo "SMTP|Mail transfer" ;; 53) echo "DNS|Name resolution" ;;
    80) echo "HTTP|Web plaintext (LB/redirect)" ;; 123) echo "NTP|Time sync" ;;
    389) echo "LDAP|Directory (plaintext)" ;; 443) echo "HTTPS|Web TLS (LB/API)" ;;
    445) echo "SMB|Windows file share" ;; 636) echo "LDAPS|Directory TLS" ;;
    1433) echo "MSSQL|SQL Server" ;; 1521) echo "Oracle-DB|Oracle Net (TNS)" ;;
    1522) echo "Oracle-DB-alt|Oracle Net (alt/ADB)" ;; 2484) echo "Oracle-TCPS|Oracle Net TLS" ;;
    3306) echo "MySQL|MySQL DB" ;; 3389) echo "RDP|Windows Remote Desktop" ;;
    5432) echo "PostgreSQL|PostgreSQL DB" ;; 6379) echo "Redis|Cache/data store" ;;
    8080) echo "HTTP-alt|Alt web/app" ;; 8443) echo "HTTPS-alt|Alt web TLS/mgmt" ;;
    9200) echo "Elasticsearch|Search API" ;; 10250) echo "Kubelet|K8s node agent" ;;
    6443) echo "K8s-API|Kubernetes API (OKE)" ;; 2049) echo "NFS|File Storage mount" ;;
    111) echo "RPCbind|NFS portmapper" ;;
    *) echo "unassigned|VERIFY - non-standard port" ;;
  esac
}
is_sensitive_port() { case "$1" in 22|23|3389|1521|1522|2484|3306|5432|1433|6379|9200|10250|6443|445|389) return 0 ;; *) return 1 ;; esac ; }
proto_name() { case "$1" in 1) echo ICMP ;; 6) echo TCP ;; 17) echo UDP ;; 58) echo ICMPv6 ;; all|"") echo ALL ;; *) echo "proto-$1" ;; esac ; }

extract_ports() {
  local rule="$1" key="$2"
  echo "$rule" | jq -r --arg k "$key" '
    (.[$k] // {}) as $opt |
    ($opt."destination-port-range" // $opt."source-port-range" // null) as $r |
    if $r == null then "ALL ALL" else "\($r.min) \($r.max)" end' 2>/dev/null
}

# --- compartment enumeration -------------------------------------------------
enumerate_comps() {
  TENANCY_ID="$(o iam compartment list --access-level ANY --limit 1 --query 'data[0]."compartment-id"' --raw-output 2>/dev/null)"
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
}

# --- normalize a rule into a stable key + fields -----------------------------
# Emits TSV: comp|vcn|container|ctype|dir|stateless|proto|prange|peer|svc|func|exposure
# The match key for reconciliation is: vcn|proto|prange|peer|dir  (identity of an opening)
emit_norm() {
  local comp="$1" vcn="$2" container="$3" ctype="$4" dir="$5" stateless="$6" pnum="$7" pmin="$8" pmax="$9" peer="${10}"
  local pname prange svc func exposure
  pname="$(proto_name "$pnum")"
  if [ -n "$pmin" ] && [ "$pmin" != "null" ] && [ "$pmin" != "ALL" ]; then
    if [ "$pmin" = "$pmax" ] || [ -z "$pmax" ] || [ "$pmax" = "null" ] || [ "$pmax" = "ALL" ]; then prange="$pmin"; else prange="${pmin}-${pmax}"; fi
    IFS='|' read -r svc func <<< "$(wellknown "$pnum" "$pmin")"
  else
    prange="ALL"
    if [ "$pname" = "ICMP" ] || [ "$pname" = "ICMPv6" ]; then IFS='|' read -r svc func <<< "$(wellknown "$pnum" 0)"; else svc="ALL-PORTS"; func="Entire $pname range - VERIFY"; fi
  fi
  exposure="scoped"
  if [ "$peer" = "0.0.0.0/0" ] || [ "$peer" = "::/0" ]; then
    if [ "$dir" = "ingress" ]; then
      if [ "$prange" = "ALL" ]; then exposure="OPEN-ALL-PORTS-INTERNET"
      elif is_sensitive_port "${pmin%%-*}"; then exposure="SENSITIVE-PORT-OPEN-INTERNET"
      else exposure="internet-facing"; fi
    else exposure="egress-any"; fi
  fi
  # tab-separated normalized record
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$comp" "$vcn" "$container" "$ctype" "$dir" "$stateless" "$pname" "$prange" "$peer" "$svc" "$func" "$exposure"
}

# --- collect all live rules as normalized TSV on stdout ----------------------
collect_live_rules() {
  local comp vcnid vcnname
  while IFS= read -r comp; do
    [ -z "$comp" ] && continue
    o network vcn list --compartment-id "$comp" --all 2>/dev/null | jq -c "$LIST_ITER" 2>/dev/null | \
    while IFS= read -r vcn; do
      [ -z "$vcn" ] && continue
      vcnid="$(echo "$vcn" | jq -r '.id')"; vcnname="$(echo "$vcn" | jq -r '."display-name" // "vcn"')"

      # Security lists
      o network security-list list --compartment-id "$comp" --vcn-id "$vcnid" --all 2>/dev/null | jq -c "$LIST_ITER" 2>/dev/null | \
      while IFS= read -r sl; do
        [ -z "$sl" ] && continue
        local slname; slname="$(echo "$sl" | jq -r '."display-name" // "security-list"')"
        for d in ingress egress; do
          [ "$DIRECTION" != both ] && [ "$DIRECTION" != "$d" ] && continue
          echo "$sl" | jq -c ".\"${d}-security-rules\"[]?" 2>/dev/null | while IFS= read -r r; do
            [ -z "$r" ] && continue
            local proto stateless peer pkey pmin pmax
            proto="$(echo "$r" | jq -r '.protocol // "all"')"
            stateless="$(echo "$r" | jq -r '.["is-stateless"] // false')"
            if [ "$d" = ingress ]; then peer="$(echo "$r" | jq -r '.source // "n/a"')"; else peer="$(echo "$r" | jq -r '.destination // "n/a"')"; fi
            case "$proto" in 6) pkey=tcp-options ;; 17) pkey=udp-options ;; *) pkey="" ;; esac
            if [ -n "$pkey" ]; then read -r pmin pmax <<< "$(extract_ports "$r" "$pkey")"; else pmin=""; pmax=""; fi
            emit_norm "$comp" "$vcnname" "$slname" "SecurityList" "$d" "$stateless" "$proto" "$pmin" "$pmax" "$peer"
          done
        done
      done

      # NSGs
      o network nsg list --compartment-id "$comp" --vcn-id "$vcnid" --all 2>/dev/null | jq -c "$LIST_ITER" 2>/dev/null | \
      while IFS= read -r nsg; do
        [ -z "$nsg" ] && continue
        local nsgid nsgname; nsgid="$(echo "$nsg" | jq -r '.id')"; nsgname="$(echo "$nsg" | jq -r '."display-name" // "nsg"')"
        o network nsg rules list --nsg-id "$nsgid" --all 2>/dev/null | jq -c "$LIST_ITER" 2>/dev/null | \
        while IFS= read -r r; do
          [ -z "$r" ] && continue
          local d proto stateless peer ptype pkey pmin pmax
          d="$(echo "$r" | jq -r '.direction // "INGRESS"' | tr '[:upper:]' '[:lower:]')"
          [ "$DIRECTION" != both ] && [ "$DIRECTION" != "$d" ] && continue
          proto="$(echo "$r" | jq -r '.protocol // "all"')"
          stateless="$(echo "$r" | jq -r '.["is-stateless"] // false')"
          ptype="$(echo "$r" | jq -r '.["source-type"] // .["destination-type"] // "CIDR_BLOCK"')"
          if [ "$d" = ingress ]; then peer="$(echo "$r" | jq -r '.source // "n/a"')"; else peer="$(echo "$r" | jq -r '.destination // "n/a"')"; fi
          [ "$ptype" = NETWORK_SECURITY_GROUP ] && peer="NSG:${peer: -12}"
          case "$proto" in 6) pkey=tcp-options ;; 17) pkey=udp-options ;; *) pkey="" ;; esac
          if [ -n "$pkey" ]; then read -r pmin pmax <<< "$(extract_ports "$r" "$pkey")"; else pmin=""; pmax=""; fi
          emit_norm "$comp" "$vcnname" "$nsgname" "NSG" "$d" "$stateless" "$proto" "$pmin" "$pmax" "$peer"
        done
      done
    done
  done <<< "$COMPS"
}

# reconciliation key from a normalized TSV line (fields: 2=vcn 7=proto 8=prange 9=peer 5=dir)
rec_key() { awk -F'\t' '{print $2"|"$7"|"$8"|"$9"|"$5}'; }
# reconciliation key from a baseline CSV line: cols compartment_name? We key on
# vcn|protocol|port_range|source_or_dest|direction — must match generate output order.

csv_escape() { local s="$1"; s="${s//\"/\"\"}"; printf '"%s"' "$s"; }

# ---------------------------------------------------------------------------
# MODE: generate
# ---------------------------------------------------------------------------
do_generate() {
  enumerate_comps
  OUT="oci_ppsm_baseline_template_${TS}.csv"
  echo "compartment_name,vcn,rule_container,container_type,direction,stateless,protocol,port_range,source_or_dest,well_known_service,function,exposure_flag,approval_status,approval_id,justification" > "$OUT"
  echo "Generating baseline template across ${COMP_COUNT} compartment(s)..." >&2
  collect_live_rules | while IFS=$'\t' read -r comp vcn container ctype dir stateless proto prange peer svc func exposure; do
    cname="${COMP_NAME[$comp]:-<unknown>}"
    printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
      "$(csv_escape "$cname")" "$(csv_escape "$vcn")" "$(csv_escape "$container")" "$(csv_escape "$ctype")" \
      "$(csv_escape "$dir")" "$(csv_escape "$stateless")" "$(csv_escape "$proto")" "$(csv_escape "$prange")" \
      "$(csv_escape "$peer")" "$(csv_escape "$svc")" "$(csv_escape "$func")" "$(csv_escape "$exposure")" \
      "$(csv_escape "PENDING-REVIEW")" "$(csv_escape "")" "$(csv_escape "")" >> "$OUT"
  done
  N="$(($(wc -l < "$OUT") - 1))"
  echo >&2
  echo "Baseline template written: $OUT  (${N} rules)" >&2
  echo "NEXT: review each row with your CCB/PPSM. Set approval_status to APPROVED" >&2
  echo "or DENIED, fill approval_id + justification. Save as your approved baseline," >&2
  echo "then run:  $0 reconcile -b <that-file>" >&2
}

# ---------------------------------------------------------------------------
# MODE: reconcile
# ---------------------------------------------------------------------------
do_reconcile() {
  [ -z "$BASELINE" ] && { echo "ERROR: reconcile needs -b <approved_baseline.csv>"; exit 1; }
  [ -f "$BASELINE" ] || { echo "ERROR: baseline file not found: $BASELINE"; exit 1; }
  enumerate_comps
  OUT="oci_ppsm_reconciliation_${TS}.csv"
  echo "status,vcn,rule_container,direction,protocol,port_range,source_or_dest,well_known_service,approval_status,approval_id,justification,note" > "$OUT"

  # Build approved-key set from baseline (only rows APPROVED)
  # Baseline columns (from generate): 1 comp_name,2 vcn,3 container,4 ctype,5 dir,6 stateless,7 proto,8 prange,9 peer,10 svc,11 func,12 exposure,13 approval_status,14 approval_id,15 justification
  local tmp_appr; tmp_appr="$(mktemp)"
  # strip header, keep APPROVED, build key vcn|proto|prange|peer|dir -> approval_id;justification
  tail -n +2 "$BASELINE" | python3 - "$tmp_appr" <<'PY'
import csv,sys
out=open(sys.argv[1],"w")
r=csv.reader(sys.stdin)
for row in r:
    if len(row)<15: continue
    (cname,vcn,cont,ctype,d,stl,proto,prange,peer,svc,func,exp,status,appid,just)=row[:15]
    if status.strip().upper()=="APPROVED":
        key="|".join([vcn,proto,prange,peer,d])
        out.write(key+"\t"+appid+"\t"+just+"\n")
out.close()
PY
  declare -A APPROVED_ID APPROVED_JUST APPROVED_SEEN
  while IFS=$'\t' read -r k aid just; do
    APPROVED_ID["$k"]="$aid"; APPROVED_JUST["$k"]="$just"; APPROVED_SEEN["$k"]=0
  done < "$tmp_appr"

  # Walk live rules, classify against approved set
  local live_tsv; live_tsv="$(mktemp)"
  collect_live_rules > "$live_tsv"

  while IFS=$'\t' read -r comp vcn container ctype dir stateless proto prange peer svc func exposure; do
    key="${vcn}|${proto^^}|${prange}|${peer}|${dir}"
    # note: live proto is name (TCP), baseline proto also name (TCP) -> both upper via generate's proto_name; normalize
    key="${vcn}|$(echo "$proto" | tr '[:lower:]' '[:upper:]')|${prange}|${peer}|${dir}"
    if [ -n "${APPROVED_ID[$key]+x}" ]; then
      APPROVED_SEEN["$key"]=1
      printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
        "$(csv_escape APPROVED)" "$(csv_escape "$vcn")" "$(csv_escape "$container")" "$(csv_escape "$dir")" \
        "$(csv_escape "$proto")" "$(csv_escape "$prange")" "$(csv_escape "$peer")" "$(csv_escape "$svc")" \
        "$(csv_escape APPROVED)" "$(csv_escape "${APPROVED_ID[$key]}")" "$(csv_escape "${APPROVED_JUST[$key]}")" \
        "$(csv_escape "matches approved baseline")" >> "$OUT"
    else
      printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
        "$(csv_escape UNAPPROVED-DRIFT)" "$(csv_escape "$vcn")" "$(csv_escape "$container")" "$(csv_escape "$dir")" \
        "$(csv_escape "$proto")" "$(csv_escape "$prange")" "$(csv_escape "$peer")" "$(csv_escape "$svc")" \
        "$(csv_escape "NOT-IN-BASELINE")" "$(csv_escape "")" "$(csv_escape "")" \
        "$(csv_escape "FINDING: live rule with no approved match [$exposure]")" >> "$OUT"
    fi
  done < "$live_tsv"

  # MISSING: approved baseline keys never seen live
  for key in "${!APPROVED_ID[@]}"; do
    if [ "${APPROVED_SEEN[$key]}" = "0" ]; then
      IFS='|' read -r bvcn bproto bprange bpeer bdir <<< "$key"
      printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
        "$(csv_escape MISSING)" "$(csv_escape "$bvcn")" "$(csv_escape "")" "$(csv_escape "$bdir")" \
        "$(csv_escape "$bproto")" "$(csv_escape "$bprange")" "$(csv_escape "$bpeer")" "$(csv_escape "")" \
        "$(csv_escape APPROVED)" "$(csv_escape "${APPROVED_ID[$key]}")" "$(csv_escape "${APPROVED_JUST[$key]}")" \
        "$(csv_escape "approved but not implemented live")" >> "$OUT"
    fi
  done

  rm -f "$tmp_appr" "$live_tsv"

  # Summary
  local nap ndrift nmiss
  nap="$(awk -F',' 'NR>1 && $1=="\"APPROVED\""' "$OUT" | grep -c . || true)"
  ndrift="$(awk -F',' 'NR>1 && $1=="\"UNAPPROVED-DRIFT\""' "$OUT" | grep -c . || true)"
  nmiss="$(awk -F',' 'NR>1 && $1=="\"MISSING\""' "$OUT" | grep -c . || true)"
  echo
  echo "======================================================================"
  echo "PPSM RECONCILIATION (proof of approval)"
  echo "======================================================================"
  echo "APPROVED (live matches baseline) : $nap"
  echo "UNAPPROVED-DRIFT (FINDINGS)      : $ndrift"
  echo "MISSING (approved, not live)     : $nmiss"
  if [ "$ndrift" -gt 0 ]; then
    echo
    echo ">>> UNAPPROVED PORTS OPEN LIVE — CM-7 findings, remediate or get approval:"
    awk -F',' 'NR>1 && $1=="\"UNAPPROVED-DRIFT\"" {gsub(/"/,"",$3);gsub(/"/,"",$5);gsub(/"/,"",$6);gsub(/"/,"",$7);gsub(/"/,"",$12);
      printf "  %-22s %s/%s from %s  (%s)\n",$3,$5,$6,$7,$12}' "$OUT"
  fi
  echo
  echo "Reconciliation evidence written to: $OUT"
}

# ---------------------------------------------------------------------------
# MODE: tags — read approval defined-tags off NSGs / security lists
# ---------------------------------------------------------------------------
do_tags() {
  enumerate_comps
  OUT="oci_ppsm_approval_tags_${TS}.csv"
  echo "compartment_name,vcn,container,container_type,defined_tags_ppsm,freeform_tags,has_approval_tag" > "$OUT"
  echo "Reading approval tags across ${COMP_COUNT} compartment(s)..." >&2
  while IFS= read -r comp; do
    [ -z "$comp" ] && continue
    o network vcn list --compartment-id "$comp" --all 2>/dev/null | jq -c "$LIST_ITER" 2>/dev/null | \
    while IFS= read -r vcn; do
      [ -z "$vcn" ] && continue
      vcnid="$(echo "$vcn" | jq -r '.id')"; vcnname="$(echo "$vcn" | jq -r '."display-name" // "vcn"')"
      for kind in security-list nsg; do
        o network "$kind" list --compartment-id "$comp" --vcn-id "$vcnid" --all 2>/dev/null | jq -c "$LIST_ITER" 2>/dev/null | \
        while IFS= read -r c; do
          [ -z "$c" ] && continue
          local cname_ ppsm free has
          cname_="$(echo "$c" | jq -r '."display-name" // "container"')"
          # pull any defined-tag namespace containing PPSM/Approval keys
          ppsm="$(echo "$c" | jq -r '(."defined-tags" // {}) | to_entries | map(.key as $ns | (.value|to_entries|map("\($ns).\(.key)=\(.value)"))) | flatten | map(select(test("PPSM|Approval|CM7|CCB";"i"))) | join("; ")' 2>/dev/null)"
          free="$(echo "$c" | jq -r '(."freeform-tags" // {}) | to_entries | map("\(.key)=\(.value)") | join("; ")' 2>/dev/null)"
          if [ -n "$ppsm" ] && [ "$ppsm" != "null" ]; then has="YES"; else has="NO"; ppsm=""; fi
          printf '%s,%s,%s,%s,%s,%s,%s\n' \
            "$(csv_escape "${COMP_NAME[$comp]:-<unknown>}")" "$(csv_escape "$vcnname")" "$(csv_escape "$cname_")" \
            "$(csv_escape "$kind")" "$(csv_escape "$ppsm")" "$(csv_escape "$free")" "$(csv_escape "$has")" >> "$OUT"
        done
      done
    done
  done <<< "$COMPS"
  local withtag
  withtag="$(awk -F',' 'NR>1 && $7=="\"YES\""' "$OUT" | grep -c . || true)"
  echo >&2
  echo "Approval-tag report written: $OUT" >&2
  echo "Containers with a PPSM/Approval defined-tag: $withtag" >&2
  echo "(Note: OCI cannot tag individual rules — only the list/NSG container.)" >&2
}

case "$MODE" in
  generate)  do_generate ;;
  reconcile) do_reconcile ;;
  tags)      do_tags ;;
esac
