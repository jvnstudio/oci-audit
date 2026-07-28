#!/usr/bin/env bash
###############################################################################
# oci_hw_sw_baseline.sh   v2.0
#
# PURPOSE
#   Read-only hardware and software component baseline across an OCI tenancy.
#   Emits per-domain CSVs plus a machine-readable collection ledger so that an
#   empty CSV can be distinguished from a failed collection.
#
# CONTROL MAPPING
#   CM-8   System Component Inventory        (primary)
#   CM-8(1) Updates During Installation      (re-run + diff)
#   CM-2   Baseline Configuration            (shape / image / version snapshot)
#   CM-6   Configuration Settings            (agent plugin posture)
#   SI-2   Flaw Remediation                  (OS + package versions, partial)
#   SA-22  Unsupported Components            (OS / DB / k8s version columns)
#
# EVIDENCE INTEGRITY
#   Every OCI operation is recorded in collection_status.csv as OK, EMPTY,
#   or FAILED with an exit code and error category. A CSV with zero rows is
#   only evidence of zero resources if the corresponding ledger rows are OK.
#   Exit code 3 == collection completed but coverage is INCOMPLETE.
#
# SAFETY
#   READ-ONLY. Only list/get operations are issued.
#
# AUTH
#   Default: whatever the ambient CLI is configured for. In OCI Cloud Shell the
#   CLI is pre-authenticated with a delegation token, so no flag is required.
#   To force a mode explicitly:
#     -a instance_obo_user   delegation token (Cloud Shell)
#     -a instance_principal  compute instance principal
#     -a security_token      session token (oci session authenticate)
#     -a api_key             config-file key pair
#   OCI_CLI_PROFILE and OCI_CLI_CONFIG_FILE are honored and passed explicitly
#   when set. They are never synthesized.
#
# USAGE
#   ./oci_hw_sw_baseline.sh
#   ./oci_hw_sw_baseline.sh -r "us-ashburn-1 us-phoenix-1"
#   ./oci_hw_sw_baseline.sh -c ocid1.compartment.oc2..xxxx
#   ./oci_hw_sw_baseline.sh -a instance_obo_user -p
#
# EXIT CODES
#   0  complete, no collection failures
#   2  usage / precondition error
#   3  completed with one or more collection failures (coverage INCOMPLETE)
###############################################################################

set -uo pipefail

VERSION="2.0"

#------------------------------------------------------------------------------
# Arguments
#------------------------------------------------------------------------------
REGIONS_ARG=""; SCOPE_COMPARTMENT=""; OUTDIR=""
WITH_PACKAGES=0; SKIP_VNICS=0; AUTH_MODE=""

usage() { sed -n '1,50p' "$0"; exit 0; }

while getopts ":r:c:o:a:pnh" opt; do
  case "$opt" in
    r) REGIONS_ARG="$OPTARG" ;;
    c) SCOPE_COMPARTMENT="$OPTARG" ;;
    o) OUTDIR="$OPTARG" ;;
    a) AUTH_MODE="$OPTARG" ;;
    p) WITH_PACKAGES=1 ;;
    n) SKIP_VNICS=1 ;;
    h) usage ;;
    \?) echo "Unknown option -$OPTARG" >&2; exit 2 ;;
    :)  echo "Option -$OPTARG requires an argument" >&2; exit 2 ;;
  esac
done

command -v oci >/dev/null 2>&1 || { echo "ERROR: oci CLI not found." >&2; exit 2; }
command -v jq  >/dev/null 2>&1 || { echo "ERROR: jq not found." >&2; exit 2; }

TS="$(date -u +%Y%m%d_%H%M%SZ)"

#------------------------------------------------------------------------------
# Working state (must exist before the first OCI call)
#------------------------------------------------------------------------------
TMPROOT="$(mktemp -d)"; trap 'rm -rf "$TMPROOT"' EXIT
ERRLOG="$TMPROOT/errors.log";            : > "$ERRLOG"
STATUS="$TMPROOT/collection_status.csv"
CALLERR="$TMPROOT/.call_stderr"
echo 'timestamp,region,compartment_ocid,service,operation,status,exit_code,error_category,label' > "$STATUS"

CUR_REGION="-"; CUR_CID="-"; CUR_CNAME="-"

#------------------------------------------------------------------------------
# Explicit CLI argument construction. Nothing is invented: a config file is
# passed only when the caller has set OCI_CLI_CONFIG_FILE.
#------------------------------------------------------------------------------
OCI_ARGS=()
[[ -n "$AUTH_MODE" ]] && OCI_ARGS+=(--auth "$AUTH_MODE")
[[ -z "$AUTH_MODE" && -n "${OCI_CLI_AUTH:-}" ]] && OCI_ARGS+=(--auth "$OCI_CLI_AUTH")
[[ -n "${OCI_CLI_PROFILE:-}" ]] && OCI_ARGS+=(--profile "$OCI_CLI_PROFILE")
if [[ -n "${OCI_CLI_CONFIG_FILE:-}" ]]; then
  [[ -r "$OCI_CLI_CONFIG_FILE" ]] || { echo "ERROR: OCI_CLI_CONFIG_FILE not readable: $OCI_CLI_CONFIG_FILE" >&2; exit 2; }
  OCI_ARGS+=(--config-file "$OCI_CLI_CONFIG_FILE")
fi
if (( ${#OCI_ARGS[@]} == 0 )); then
  AUTH_DESC="<ambient CLI configuration>"
else
  AUTH_DESC="${OCI_ARGS[*]}"
fi

#------------------------------------------------------------------------------
# Logging helpers
#------------------------------------------------------------------------------
log()  { printf '[%s] %s\n' "$(date -u +%H:%M:%SZ)" "$*"; }
warn() { printf '[%s] %s\n' "$(date -u +%H:%M:%SZ)" "$*" >> "$ERRLOG"; }

csvq() { local v="${1//\"/\"\"}"; printf '"%s"' "$v"; }

categorize() {
  local f="$1"
  if   grep -qi 'NotAuthorizedOrNotFound'                  "$f"; then echo AUTHZ_OR_ABSENT
  elif grep -qi 'NotAuthenticated\|authentication\|token'   "$f"; then echo AUTH_FAILURE
  elif grep -qi 'No such command\|Unrecognized\|Usage:\|no such option' "$f"; then echo UNSUPPORTED_CLI
  elif grep -qi 'ServiceUnavailable\|InternalServerError\|502\|503'     "$f"; then echo SERVICE_ERROR
  elif grep -qi 'TooManyRequests\|429\|rate'                "$f"; then echo THROTTLED
  elif grep -qi 'timed out\|timeout\|Connection'            "$f"; then echo TIMEOUT
  elif grep -qi 'InvalidParameter\|MissingParameter\|400'   "$f"; then echo INVALID_REQUEST
  elif grep -qi 'NotFound\|404'                             "$f"; then echo NOT_FOUND
  else echo UNCLASSIFIED
  fi
}

# ledger <status> <rc> <category> <label> <oci args...>
ledger() {
  local st="$1" rc="$2" cat="$3" label="$4"; shift 4
  local svc="${1:-}" op="" a
  shift || true
  for a in "$@"; do [[ "$a" == --* ]] && break; op="${op:+$op }$a"; done
  {
    printf '%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
      "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
      "$(csvq "$CUR_REGION")" "$(csvq "$CUR_CID")" \
      "$(csvq "$svc")" "$(csvq "$op")" "$st" "$rc" "$cat" "$(csvq "$label")"
  } >> "$STATUS"
}

#------------------------------------------------------------------------------
# oci_q - never aborts, but never disguises a failure as an empty result set.
#------------------------------------------------------------------------------
oci_q() {
  local label="$1"; shift
  local out rc ecat n
  : > "$CALLERR"
  out="$(oci "${OCI_ARGS[@]+"${OCI_ARGS[@]}"}" "$@" 2>"$CALLERR" </dev/null)"; rc=$?

  if (( rc != 0 )); then
    ecat="$(categorize "$CALLERR")"
    { echo "=== FAILED [$label] rc=$rc cat=$ecat :: oci $*"; cat "$CALLERR"; } >> "$ERRLOG"
    ledger FAILED "$rc" "$ecat" "$label" "$@"
    printf '{"data":[],"_collection_status":"FAILED"}'
    return 0
  fi

  [[ -s "$CALLERR" ]] && { echo "=== stderr [$label]"; cat "$CALLERR"; } >> "$ERRLOG"

  if [[ -z "${out//[[:space:]]/}" ]]; then
    ledger EMPTY 0 NONE "$label" "$@"
    printf '{"data":[],"_collection_status":"EMPTY_RESPONSE"}'
    return 0
  fi

  n="$(printf '%s' "$out" | jq -r '(.data.items? // .data // []) | if type=="array" then length else 1 end' 2>/dev/null)"
  [[ -z "$n" ]] && n=0
  ledger OK 0 NONE "$label ($n)" "$@"
  printf '%s' "$out"
}

# oci_capture <out_var> <rc_var> <label> <oci args...>
# Use where the caller must branch on the real exit status.
oci_capture() {
  local ov="$1" rv="$2" label="$3"; shift 3
  local result rc ecat
  : > "$CALLERR"
  result="$(oci "${OCI_ARGS[@]+"${OCI_ARGS[@]}"}" "$@" 2>"$CALLERR" </dev/null)"; rc=$?
  if (( rc != 0 )); then
    ecat="$(categorize "$CALLERR")"
    { echo "=== FAILED [$label] rc=$rc cat=$ecat :: oci $*"; cat "$CALLERR"; } >> "$ERRLOG"
    ledger FAILED "$rc" "$ecat" "$label" "$@"
    result='{"data":[],"_collection_status":"FAILED"}'
  else
    ledger OK 0 NONE "$label" "$@"
    [[ -z "${result//[[:space:]]/}" ]] && result='{"data":[]}'
  fi
  printf -v "$ov" '%s' "$result"
  printf -v "$rv" '%s' "$rc"
}

#------------------------------------------------------------------------------
# jq prelude
#   s()   scalar or ""            n()   numeric or ""
#   tri() three-state boolean: true | false | UNKNOWN (null) | NOT_RETURNED
#   dat   tolerates {"data":[...]} and {"data":{"items":[...]}}
#------------------------------------------------------------------------------
read -r -d '' JQP <<'JQEOF'
def s(k): (.[k] // "" | tostring);
def n(k): (.[k] // "" | tostring);
def tri(k):
  if (type == "object" and has(k))
  then (if .[k] == null then "UNKNOWN" else (.[k] | tostring) end)
  else "NOT_RETURNED" end;
def sub(k): (.[k] // {});
def arr(k): (.[k] // []);
def cnt(k): (arr(k) | length | tostring);
def dat: (.data.items? // .data // []);
JQEOF

# emit <outfile> <label> <jq filter> -- <oci args...>
# $r/$cn/$co are always bound. $x1/$x2 carry caller-supplied context and are
# passed as jq --arg values, never interpolated into the filter text.
X1=""; X2=""
emit() {
  local outfile="$1" label="$2" filter="$3"; shift 3
  oci_q "$label" "$@" \
    | jq -r --arg r "$CUR_REGION" --arg cn "$CUR_CNAME" --arg co "$CUR_CID" \
            --arg x1 "$X1" --arg x2 "$X2" \
         "$JQP $filter" >> "$OUTDIR/$outfile" 2>>"$ERRLOG"
}

#------------------------------------------------------------------------------
# Tenancy resolution
#------------------------------------------------------------------------------
TENANCY_OCID="${OCI_TENANCY:-}"
if [[ -z "$TENANCY_OCID" ]]; then
  TENANCY_OCID="$(oci_q "resolve tenancy" iam availability-domain list \
      --query 'data[0]."compartment-id"' --raw-output | tr -d '"[:space:]')"
fi
if [[ -z "$TENANCY_OCID" || "$TENANCY_OCID" == "null" ]]; then
  echo "ERROR: could not resolve tenancy OCID. Export OCI_TENANCY and retry." >&2
  echo "       See stderr detail in the temp error log." >&2
  cat "$ERRLOG" >&2
  exit 2
fi

TENANCY_NAME="$(oci_q "tenancy get" iam tenancy get --tenancy-id "$TENANCY_OCID" \
    | jq -r '.data.name // "tenancy"')"
[[ -z "$TENANCY_NAME" || "$TENANCY_NAME" == "null" ]] && TENANCY_NAME="tenancy"

[[ -z "$OUTDIR" ]] && OUTDIR="./oci_baseline_${TENANCY_NAME//[^A-Za-z0-9._-]/_}_${TS}"
mkdir -p "$OUTDIR" || { echo "ERROR: cannot create $OUTDIR" >&2; exit 2; }

#------------------------------------------------------------------------------
# CSV headers
#------------------------------------------------------------------------------
hdr() { printf '%s\n' "$2" > "$OUTDIR/$1"; }

# --- compute -----------------------------------------------------------------
hdr compute_instances.csv 'region,compartment_name,compartment_ocid,instance_name,instance_ocid,lifecycle_state,form_factor,shape,ocpus,memory_gb,gpu_count,gpu_description,local_disk_count,local_disk_gb,processor_description,network_bandwidth_gbps,availability_domain,fault_domain,launch_mode,platform_config_type,secure_boot,measured_boot,tpm_enabled,image_name,image_os,image_os_version,image_ocid,monitoring_agent_disabled,management_agent_disabled,plugins_enabled,time_created,freeform_tags'
hdr instance_vnics.csv    'region,compartment_name,instance_name,instance_ocid,vnic_name,vnic_ocid,private_ip,public_ip,mac_address,subnet_ocid,nsg_count,is_primary,skip_source_dest_check'
hdr images_in_use.csv     'region,image_ocid,image_name,operating_system,os_version,base_image_ocid,launch_mode,time_created,instance_count'
hdr dedicated_vm_hosts.csv 'region,compartment_name,compartment_ocid,host_name,host_ocid,lifecycle_state,dvh_shape,availability_domain,fault_domain,total_ocpus,remaining_ocpus,total_memory_gb,remaining_memory_gb,time_created'
# --- block storage -----------------------------------------------------------
hdr block_volumes.csv     'region,compartment_name,compartment_ocid,volume_name,volume_ocid,lifecycle_state,size_gb,vpus_per_gb,availability_domain,kms_key_ocid,auto_tune_enabled,time_created'
hdr boot_volumes.csv      'region,compartment_name,compartment_ocid,volume_name,volume_ocid,lifecycle_state,size_gb,vpus_per_gb,availability_domain,image_ocid,kms_key_ocid,time_created'
hdr volume_attachments.csv 'region,compartment_name,attachment_type,instance_ocid,volume_ocid,lifecycle_state,attachment_mode,is_read_only,is_shareable,pv_encryption_in_transit,time_created'
# --- file storage ------------------------------------------------------------
hdr fss_file_systems.csv  'region,compartment_name,compartment_ocid,fs_name,fs_ocid,lifecycle_state,availability_domain,metered_bytes,kms_key_ocid,is_clone,source_snapshot_ocid,is_targetable,replication_target_ocid,time_created'
hdr fss_mount_targets.csv 'region,compartment_name,compartment_ocid,mt_name,mt_ocid,lifecycle_state,availability_domain,subnet_ocid,export_set_ocid,private_ip_count,nsg_count,requested_throughput,time_created'
hdr fss_exports.csv       'region,compartment_name,export_ocid,lifecycle_state,export_set_ocid,file_system_ocid,path,export_option_count,is_idmap_groups_for_sys_auth,time_created'
# --- object storage ----------------------------------------------------------
hdr object_storage_buckets.csv 'region,compartment_name,compartment_ocid,namespace,bucket_name,storage_tier,public_access_type,versioning,object_events_enabled,replication_enabled,auto_tiering,kms_key_ocid,retention_rule_count,approximate_object_count,approximate_size_bytes,time_created'
# --- network -----------------------------------------------------------------
hdr network_vcns.csv      'region,compartment_name,compartment_ocid,vcn_name,vcn_ocid,lifecycle_state,cidr_blocks,ipv6_cidr_blocks,dns_label,default_route_table_ocid,default_security_list_ocid,time_created'
hdr network_subnets.csv   'region,compartment_name,compartment_ocid,subnet_name,subnet_ocid,lifecycle_state,vcn_ocid,cidr_block,availability_domain,prohibit_public_ip,prohibit_internet_ingress,route_table_ocid,security_list_count,dns_label,time_created'
hdr network_route_tables.csv 'region,compartment_name,compartment_ocid,rt_name,rt_ocid,lifecycle_state,vcn_ocid,route_rule_count,time_created'
hdr network_security_lists.csv 'region,compartment_name,compartment_ocid,sl_name,sl_ocid,lifecycle_state,vcn_ocid,ingress_rule_count,egress_rule_count,time_created'
hdr network_nsgs.csv      'region,compartment_name,compartment_ocid,nsg_name,nsg_ocid,lifecycle_state,vcn_ocid,time_created'
hdr network_gateways.csv  'region,compartment_name,compartment_ocid,gateway_type,gateway_name,gateway_ocid,lifecycle_state,vcn_ocid,detail,time_created'
hdr network_firewalls.csv 'region,compartment_name,compartment_ocid,nfw_name,nfw_ocid,lifecycle_state,policy_ocid,subnet_ocid,availability_domain,ipv4_address,nsg_count,time_created'
hdr load_balancers.csv    'region,compartment_name,compartment_ocid,lb_type,lb_name,lb_ocid,lifecycle_state,shape,min_bandwidth_mbps,max_bandwidth_mbps,is_private,ip_addresses,time_created'
# --- kubernetes / containers -------------------------------------------------
hdr oke_clusters.csv      'region,compartment_name,compartment_ocid,cluster_name,cluster_ocid,lifecycle_state,cluster_type,kubernetes_version,vcn_ocid,is_public_endpoint,pod_network,time_created'
hdr oke_node_pools.csv    'region,compartment_name,cluster_ocid,node_pool_name,node_pool_ocid,lifecycle_state,kubernetes_version,node_shape,node_ocpus,node_memory_gb,configured_node_count,node_image_name,node_image_ocid,cni_type'
hdr oke_virtual_node_pools.csv 'region,compartment_name,cluster_ocid,vnp_name,vnp_ocid,lifecycle_state,kubernetes_version,configured_size,pod_shape,taint_count,time_created'
hdr container_instances.csv 'region,compartment_name,compartment_ocid,ci_name,ci_ocid,lifecycle_state,shape,ocpus,memory_gb,container_count,availability_domain,time_created'
hdr containers.csv        'region,compartment_name,container_instance_ocid,container_name,container_ocid,lifecycle_state,image_url,availability_domain,fault_domain,time_created'
hdr functions.csv         'region,compartment_name,application_name,application_ocid,function_name,function_ocid,lifecycle_state,image,image_digest,memory_mb,timeout_seconds,shape,time_created'
# --- database ----------------------------------------------------------------
hdr db_systems.csv        'region,compartment_name,compartment_ocid,db_system_name,db_system_ocid,lifecycle_state,shape,cpu_core_count,node_count,memory_gb,data_storage_gb,database_edition,db_system_version,license_model,availability_domain,time_created'
hdr db_homes.csv          'region,compartment_name,compartment_ocid,db_home_name,db_home_ocid,lifecycle_state,db_version,db_system_ocid,vm_cluster_ocid,database_software_image_ocid,time_created'
hdr databases.csv         'region,compartment_name,db_home_ocid,db_name,db_unique_name,database_ocid,lifecycle_state,db_workload,character_set,ncharacter_set,pdb_name,time_created'
hdr exadata_infrastructure.csv 'region,compartment_name,compartment_ocid,infra_type,infra_name,infra_ocid,lifecycle_state,shape,compute_count,storage_count,total_storage_tb,availability_domain,time_created'
hdr vm_clusters.csv       'region,compartment_name,compartment_ocid,cluster_type,cluster_name,cluster_ocid,lifecycle_state,shape,cpu_core_count,memory_gb,gi_version,system_version,node_count,license_model,time_created'
hdr autonomous_databases.csv 'region,compartment_name,compartment_ocid,adb_display_name,adb_name,adb_ocid,lifecycle_state,db_version,db_workload,compute_model,compute_count,cpu_core_count,storage_tb,license_model,is_dedicated,container_db_ocid,time_created'
hdr autonomous_container_databases.csv 'region,compartment_name,compartment_ocid,acd_name,acd_ocid,lifecycle_state,db_version,patch_model,service_level_agreement_type,exadata_infrastructure_ocid,vm_cluster_ocid,time_created'
hdr mysql_db_systems.csv  'region,compartment_name,compartment_ocid,mysql_name,mysql_ocid,lifecycle_state,mysql_version,shape,data_storage_gb,is_highly_available,availability_domain,time_created'
hdr postgresql_db_systems.csv 'region,compartment_name,compartment_ocid,psql_name,psql_ocid,lifecycle_state,db_version,shape,instance_count,instance_ocpus,instance_memory_gb,time_created'
hdr nosql_tables.csv      'region,compartment_name,compartment_ocid,table_name,table_ocid,lifecycle_state,is_multi_region,table_limits,time_created'
# --- in-guest software -------------------------------------------------------
hdr os_managed_instances.csv 'region,compartment_name,managed_instance_name,managed_instance_ocid,inventory_source,status,os_name,os_version,kernel_version,architecture,agent_version,installed_packages,security_updates_available,bug_updates_available,other_updates_available,profile,lifecycle_environment'
hdr os_installed_packages.csv 'region,managed_instance_name,managed_instance_ocid,package_name,package_version,package_architecture,package_type,install_time'

#------------------------------------------------------------------------------
# Regions
#------------------------------------------------------------------------------
if [[ -n "$REGIONS_ARG" ]]; then
  # shellcheck disable=SC2206
  REGIONS=($REGIONS_ARG)
else
  mapfile -t REGIONS < <(oci_q "region-subscription list" iam region-subscription list \
      | jq -r 'dat | .[]? | .["region-name"] // empty' | sort -u)
fi
if (( ${#REGIONS[@]} == 0 )); then
  echo "ERROR: no regions resolved. Pass -r explicitly." >&2; exit 2
fi

#------------------------------------------------------------------------------
# Compartments
#------------------------------------------------------------------------------
ROOT="${SCOPE_COMPARTMENT:-$TENANCY_OCID}"
COMP_FILE="$TMPROOT/compartments.tsv"; : > "$COMP_FILE"

if [[ "$ROOT" == "$TENANCY_OCID" ]]; then
  printf '%s\t%s\n' "$TENANCY_OCID" "${TENANCY_NAME} (root)" >> "$COMP_FILE"
else
  oci_q "compartment get" iam compartment get --compartment-id "$ROOT" \
    | jq -r '.data | select(. != null) | [.id, .name] | @tsv' >> "$COMP_FILE"
fi

oci_q "compartment list (subtree)" iam compartment list \
    --compartment-id "$ROOT" --compartment-id-in-subtree true \
    --access-level ACCESSIBLE --lifecycle-state ACTIVE --all \
  | jq -r 'dat | .[]? | [.id, .name] | @tsv' >> "$COMP_FILE"

COMP_COUNT=$(wc -l < "$COMP_FILE" | tr -d ' ')
if (( COMP_COUNT == 0 )); then
  echo "ERROR: compartment enumeration returned nothing. Check ledger/errors." >&2
  cp "$STATUS" "$OUTDIR/collection_status.csv"; cp "$ERRLOG" "$OUTDIR/errors.log"
  exit 3
fi

log "Version      : $VERSION"
log "Tenancy      : $TENANCY_NAME"
log "Auth         : $AUTH_DESC"
log "Regions      : ${REGIONS[*]}"
log "Compartments : $COMP_COUNT"
log "Output       : $OUTDIR"
echo

###############################################################################
# Region loop
###############################################################################
for REGION in "${REGIONS[@]}"; do
  CUR_REGION="$REGION"
  log "===== Region: $REGION ====="
  RTMP="$TMPROOT/$REGION"; mkdir -p "$RTMP"
  : > "$RTMP/instances.jsonl"; : > "$RTMP/images.jsonl"

  mapfile -t ADS < <(oci_q "availability-domain list" iam availability-domain list \
      --compartment-id "$TENANCY_OCID" --region "$REGION" \
      | jq -r 'dat | .[]? | .name // empty')

  OS_NAMESPACE="$(oci_q "object-storage namespace get" os ns get --region "$REGION" \
      | jq -r '.data // "" | tostring')"

  while IFS=$'\t' read -r CID CNAME; do
    [[ -z "$CID" ]] && continue
    CUR_CID="$CID"; CUR_CNAME="$CNAME"
    R=(--compartment-id "$CID" --region "$REGION" --all)

    ############################ COMPUTE #####################################
    oci_q "compute instance list [$CNAME]" compute instance list "${R[@]}" \
      | jq -c --arg r "$REGION" --arg cn "$CNAME" --arg co "$CID" \
          'dat | .[]? | . + {_region:$r,_cname:$cn,_cocid:$co}' >> "$RTMP/instances.jsonl"

    emit dedicated_vm_hosts.csv "compute dedicated-vm-host list [$CNAME]" '
      dat | .[]? | [ $r,$cn,$co,
        s("display-name"), s("id"), s("lifecycle-state"),
        s("dedicated-vm-host-shape"), s("availability-domain"), s("fault-domain"),
        n("total-ocpus"), n("remaining-ocpus"),
        n("total-memory-in-gbs"), n("remaining-memory-in-gbs"),
        s("time-created") ] | @csv' \
      compute dedicated-vm-host list "${R[@]}"

    ############################ BLOCK STORAGE ###############################
    emit block_volumes.csv "bv volume list [$CNAME]" '
      dat | .[]? | [ $r,$cn,$co,
        s("display-name"), s("id"), s("lifecycle-state"),
        n("size-in-gbs"), n("vpus-per-gb"), s("availability-domain"),
        s("kms-key-id"), tri("is-auto-tune-enabled"), s("time-created") ] | @csv' \
      bv volume list "${R[@]}"

    emit volume_attachments.csv "compute volume-attachment list [$CNAME]" '
      dat | .[]? | [ $r,$cn,"BLOCK",
        s("instance-id"), s("volume-id"), s("lifecycle-state"),
        s("attachment-type"), tri("is-read-only"), tri("is-shareable"),
        tri("is-pv-encryption-in-transit-enabled"), s("time-created") ] | @csv' \
      compute volume-attachment list "${R[@]}"

    ############################ PER-AD RESOURCES ############################
    if (( ${#ADS[@]} > 0 )); then
      for AD in "${ADS[@]}"; do
        [[ -z "$AD" ]] && continue
        RAD=(--compartment-id "$CID" --availability-domain "$AD" --region "$REGION" --all)

        emit boot_volumes.csv "bv boot-volume list [$CNAME/$AD]" '
          dat | .[]? | [ $r,$cn,$co,
            s("display-name"), s("id"), s("lifecycle-state"),
            n("size-in-gbs"), n("vpus-per-gb"), s("availability-domain"),
            s("image-id"), s("kms-key-id"), s("time-created") ] | @csv' \
          bv boot-volume list "${RAD[@]}"

        emit volume_attachments.csv "compute boot-volume-attachment list [$CNAME/$AD]" '
          dat | .[]? | [ $r,$cn,"BOOT",
            s("instance-id"), s("boot-volume-id"), s("lifecycle-state"),
            "boot", "N/A", "N/A",
            tri("is-pv-encryption-in-transit-enabled"), s("time-created") ] | @csv' \
          compute boot-volume-attachment list "${RAD[@]}"

        emit fss_file_systems.csv "fs file-system list [$CNAME/$AD]" '
          dat | .[]? | [ $r,$cn,$co,
            s("display-name"), s("id"), s("lifecycle-state"),
            s("availability-domain"), n("metered-bytes"), s("kms-key-id"),
            tri("is-clone"), s("source-snapshot-id"), tri("is-targetable"),
            s("replication-target-id"), s("time-created") ] | @csv' \
          fs file-system list "${RAD[@]}"

        emit fss_mount_targets.csv "fs mount-target list [$CNAME/$AD]" '
          dat | .[]? | [ $r,$cn,$co,
            s("display-name"), s("id"), s("lifecycle-state"),
            s("availability-domain"), s("subnet-id"), s("export-set-id"),
            cnt("private-ip-ids"), cnt("nsg-ids"),
            n("requested-throughput"), s("time-created") ] | @csv' \
          fs mount-target list "${RAD[@]}"
      done
    fi

    emit fss_exports.csv "fs export list [$CNAME]" '
      dat | .[]? | [ $r,$cn,
        s("id"), s("lifecycle-state"), s("export-set-id"), s("file-system-id"),
        s("path"), cnt("export-options"),
        tri("is-idmap-groups-for-sys-auth"), s("time-created") ] | @csv' \
      fs export list "${R[@]}"

    ############################ OBJECT STORAGE ##############################
    if [[ -n "$OS_NAMESPACE" && "$OS_NAMESPACE" != "null" ]]; then
      while IFS=$'\t' read -r BNAME; do
        [[ -z "$BNAME" ]] && continue
        RRC="$(oci_q "os retention-rule list [$BNAME]" os retention-rule list \
                 --namespace-name "$OS_NAMESPACE" --bucket-name "$BNAME" --region "$REGION" \
               | jq -r '(.data.items? // .data // []) | length')"
        [[ -z "$RRC" ]] && RRC=0

        # --fields support varies by CLI version; fall back to a plain get.
        oci_capture BKT_JSON BKT_RC "os bucket get [$BNAME]" \
          os bucket get --namespace-name "$OS_NAMESPACE" --bucket-name "$BNAME" \
            --region "$REGION" --fields approximateCount --fields approximateSize
        if (( BKT_RC != 0 )); then
          oci_capture BKT_JSON BKT_RC "os bucket get (no --fields) [$BNAME]" \
            os bucket get --namespace-name "$OS_NAMESPACE" --bucket-name "$BNAME" \
              --region "$REGION"
        fi

        printf '%s' "$BKT_JSON" \
          | jq -r --arg r "$REGION" --arg cn "$CNAME" --arg co "$CID" --arg rr "$RRC" "$JQP"'
              (.data // {}) | select(. != {}) | [ $r,$cn,$co,
                s("namespace"), s("name"), s("storage-tier"),
                s("public-access-type"), s("versioning"),
                tri("object-events-enabled"), tri("replication-enabled"),
                s("auto-tiering"), s("kms-key-id"), $rr,
                n("approximate-count"), n("approximate-size"),
                s("time-created") ] | @csv' \
          >> "$OUTDIR/object_storage_buckets.csv" 2>>"$ERRLOG"
      done < <(oci_q "os bucket list [$CNAME]" os bucket list \
                 --namespace-name "$OS_NAMESPACE" "${R[@]}" \
               | jq -r 'dat | .[]? | .name // empty')
    fi

    ############################ NETWORK #####################################
    emit network_vcns.csv "network vcn list [$CNAME]" '
      dat | .[]? | [ $r,$cn,$co,
        s("display-name"), s("id"), s("lifecycle-state"),
        ((arr("cidr-blocks")) | join("|")), ((arr("ipv6-cidr-blocks")) | join("|")),
        s("dns-label"), s("default-route-table-id"), s("default-security-list-id"),
        s("time-created") ] | @csv' \
      network vcn list "${R[@]}"

    emit network_subnets.csv "network subnet list [$CNAME]" '
      dat | .[]? | [ $r,$cn,$co,
        s("display-name"), s("id"), s("lifecycle-state"), s("vcn-id"),
        s("cidr-block"), s("availability-domain"),
        tri("prohibit-public-ip-on-vnic"), tri("prohibit-internet-ingress"),
        s("route-table-id"), cnt("security-list-ids"), s("dns-label"),
        s("time-created") ] | @csv' \
      network subnet list "${R[@]}"

    emit network_route_tables.csv "network route-table list [$CNAME]" '
      dat | .[]? | [ $r,$cn,$co,
        s("display-name"), s("id"), s("lifecycle-state"), s("vcn-id"),
        cnt("route-rules"), s("time-created") ] | @csv' \
      network route-table list "${R[@]}"

    emit network_security_lists.csv "network security-list list [$CNAME]" '
      dat | .[]? | [ $r,$cn,$co,
        s("display-name"), s("id"), s("lifecycle-state"), s("vcn-id"),
        cnt("ingress-security-rules"), cnt("egress-security-rules"),
        s("time-created") ] | @csv' \
      network security-list list "${R[@]}"

    emit network_nsgs.csv "network nsg list [$CNAME]" '
      dat | .[]? | [ $r,$cn,$co,
        s("display-name"), s("id"), s("lifecycle-state"), s("vcn-id"),
        s("time-created") ] | @csv' \
      network nsg list "${R[@]}"

    emit network_gateways.csv "network internet-gateway list [$CNAME]" '
      dat | .[]? | [ $r,$cn,$co,"INTERNET_GATEWAY",
        s("display-name"), s("id"), s("lifecycle-state"), s("vcn-id"),
        ("enabled=" + (tri("is-enabled"))), s("time-created") ] | @csv' \
      network internet-gateway list "${R[@]}"

    emit network_gateways.csv "network nat-gateway list [$CNAME]" '
      dat | .[]? | [ $r,$cn,$co,"NAT_GATEWAY",
        s("display-name"), s("id"), s("lifecycle-state"), s("vcn-id"),
        ("nat_ip=" + s("nat-ip") + ";blocked=" + tri("block-traffic")),
        s("time-created") ] | @csv' \
      network nat-gateway list "${R[@]}"

    emit network_gateways.csv "network service-gateway list [$CNAME]" '
      dat | .[]? | [ $r,$cn,$co,"SERVICE_GATEWAY",
        s("display-name"), s("id"), s("lifecycle-state"), s("vcn-id"),
        ((arr("services")) | map(.["service-name"] // "") | join("|")),
        s("time-created") ] | @csv' \
      network service-gateway list "${R[@]}"

    emit network_gateways.csv "network local-peering-gateway list [$CNAME]" '
      dat | .[]? | [ $r,$cn,$co,"LOCAL_PEERING_GATEWAY",
        s("display-name"), s("id"), s("lifecycle-state"), s("vcn-id"),
        ("peering=" + s("peering-status") + ";peer_cidr=" + s("peer-advertised-cidr")),
        s("time-created") ] | @csv' \
      network local-peering-gateway list "${R[@]}"

    emit network_gateways.csv "network drg list [$CNAME]" '
      dat | .[]? | [ $r,$cn,$co,"DRG",
        s("display-name"), s("id"), s("lifecycle-state"), "",
        ("default_drg_route_tables=" + (sub("default-drg-route-tables") | keys | join("|"))),
        s("time-created") ] | @csv' \
      network drg list "${R[@]}"

    emit network_gateways.csv "network drg-attachment list [$CNAME]" '
      dat | .[]? | [ $r,$cn,$co,"DRG_ATTACHMENT",
        s("display-name"), s("id"), s("lifecycle-state"), s("vcn-id"),
        ("drg=" + s("drg-id") + ";type=" + (sub("network-details") | s("type"))),
        s("time-created") ] | @csv' \
      network drg-attachment list "${R[@]}"

    emit network_firewalls.csv "network-firewall list [$CNAME]" '
      dat | .[]? | [ $r,$cn,$co,
        s("display-name"), s("id"), s("lifecycle-state"),
        s("network-firewall-policy-id"), s("subnet-id"), s("availability-domain"),
        s("ipv4-address"), cnt("network-security-group-ids"), s("time-created") ] | @csv' \
      network-firewall network-firewall list "${R[@]}"

    emit load_balancers.csv "lb load-balancer list [$CNAME]" '
      dat | .[]? | [ $r,$cn,$co,"LBaaS",
        s("display-name"), s("id"), s("lifecycle-state"), s("shape-name"),
        (sub("shape-details") | n("minimum-bandwidth-in-mbps")),
        (sub("shape-details") | n("maximum-bandwidth-in-mbps")),
        tri("is-private"),
        ((arr("ip-addresses")) | map(.["ip-address"] // "") | join("|")),
        s("time-created") ] | @csv' \
      lb load-balancer list "${R[@]}"

    emit load_balancers.csv "nlb network-load-balancer list [$CNAME]" '
      dat | .[]? | [ $r,$cn,$co,"NLB",
        s("display-name"), s("id"), s("lifecycle-state"), "flexible","","",
        tri("is-private"),
        ((arr("ip-addresses")) | map(.["ip-address"] // "") | join("|")),
        s("time-created") ] | @csv' \
      nlb network-load-balancer list "${R[@]}"

    ############################ OKE #########################################
    emit oke_clusters.csv "ce cluster list [$CNAME]" '
      dat | .[]? | [ $r,$cn,$co,
        s("name"), s("id"), s("lifecycle-state"),
        (.type // "UNKNOWN"), s("kubernetes-version"), s("vcn-id"),
        (sub("endpoint-config") | tri("is-public-ip-enabled")),
        ((arr("cluster-pod-network-options")) | map(.["cni-type"] // "") | join("|")),
        (.["time-created"] // (sub("metadata") | .["time-created"]) // "") ] | @csv' \
      ce cluster list "${R[@]}"

    emit oke_node_pools.csv "ce node-pool list [$CNAME]" '
      dat | .[]? | [ $r,$cn,
        s("cluster-id"), s("name"), s("id"), s("lifecycle-state"),
        s("kubernetes-version"), s("node-shape"),
        (sub("node-shape-config") | n("ocpus")),
        (sub("node-shape-config") | n("memory-in-gbs")),
        ((.["node-config-details"]["size"] // .["quantity-per-subnet"] // "") | tostring),
        (sub("node-source") | s("source-name")),
        ((.["node-source"]["image-id"] // .["node-source-details"]["image-id"] // "") | tostring),
        (sub("node-config-details") | sub("node-pool-pod-network-option-details") | s("cni-type"))
      ] | @csv' \
      ce node-pool list "${R[@]}"

    emit oke_virtual_node_pools.csv "ce virtual-node-pool list [$CNAME]" '
      dat | .[]? | [ $r,$cn,
        s("cluster-id"), s("display-name"), s("id"), s("lifecycle-state"),
        s("kubernetes-version"), n("size"),
        (sub("pod-configuration") | s("shape")),
        cnt("taints"), s("time-created") ] | @csv' \
      ce virtual-node-pool list "${R[@]}"

    ############################ CONTAINERS ##################################
    emit container_instances.csv "container-instance list [$CNAME]" '
      dat | .[]? | [ $r,$cn,$co,
        s("display-name"), s("id"), s("lifecycle-state"), s("shape"),
        (sub("shape-config") | n("ocpus")), (sub("shape-config") | n("memory-in-gbs")),
        n("container-count"), s("availability-domain"), s("time-created") ] | @csv' \
      container-instances container-instance list "${R[@]}"

    emit containers.csv "container list [$CNAME]" '
      dat | .[]? | [ $r,$cn,
        s("container-instance-id"), s("display-name"), s("id"),
        s("lifecycle-state"), s("image-url"),
        s("availability-domain"), s("fault-domain"), s("time-created") ] | @csv' \
      container-instances container list "${R[@]}"

    ############################ FUNCTIONS ###################################
    while IFS=$'\t' read -r APPID APPNAME; do
      [[ -z "$APPID" ]] && continue
      X1="$APPNAME"; X2="$APPID"
      emit functions.csv "fn function list [$APPNAME]" '
        dat | .[]? | [ $r,$cn,$x1,$x2,
          s("display-name"), s("id"), s("lifecycle-state"),
          s("image"), s("image-digest"), n("memory-in-mbs"),
          n("timeout-in-seconds"), s("shape"), s("time-created") ] | @csv' \
        fn function list --application-id "$APPID" --region "$REGION" --all
      X1=""; X2=""
    done < <(oci_q "fn application list [$CNAME]" fn application list "${R[@]}" \
             | jq -r 'dat | .[]? | [.id, (.["display-name"] // "")] | @tsv')

    ############################ DATABASE ####################################
    emit db_systems.csv "db system list [$CNAME]" '
      dat | .[]? | [ $r,$cn,$co,
        s("display-name"), s("id"), s("lifecycle-state"), s("shape"),
        n("cpu-core-count"), n("node-count"), n("memory-size-in-gbs"),
        n("data-storage-size-in-gbs"), s("database-edition"), s("version"),
        s("license-model"), s("availability-domain"), s("time-created") ] | @csv' \
      db system list "${R[@]}"

    # Capture once, then both emit and iterate from the same payload. Using
    # tee into a process substitution here would race the summary phase.
    oci_capture DBH_JSON DBH_RC "db db-home list [$CNAME]" db db-home list "${R[@]}"
    printf '%s' "$DBH_JSON" \
      | jq -r --arg r "$REGION" --arg cn "$CNAME" --arg co "$CID" "$JQP"'
          dat | .[]? | [ $r,$cn,$co,
            s("display-name"), s("id"), s("lifecycle-state"),
            s("db-version"), s("db-system-id"), s("vm-cluster-id"),
            s("database-software-image-id"), s("time-created") ] | @csv' \
      >> "$OUTDIR/db_homes.csv" 2>>"$ERRLOG"

    while IFS=$'\t' read -r DBHID DBHNAME; do
      [[ -z "$DBHID" ]] && continue
      X1="$DBHID"
      emit databases.csv "db database list [$DBHNAME]" '
        dat | .[]? | [ $r,$cn,$x1,
          s("db-name"), s("db-unique-name"), s("id"), s("lifecycle-state"),
          s("db-workload"), s("character-set"), s("ncharacter-set"),
          s("pdb-name"), s("time-created") ] | @csv' \
        db database list --compartment-id "$CID" --db-home-id "$DBHID" \
          --region "$REGION" --all
      X1=""
    done < <(printf '%s' "$DBH_JSON" \
             | jq -r "$JQP"'dat | .[]? | [.id, (.["display-name"] // "")] | @tsv')

    emit exadata_infrastructure.csv "db cloud-exadata-infrastructure list [$CNAME]" '
      dat | .[]? | [ $r,$cn,$co,"CLOUD_EXADATA_INFRASTRUCTURE",
        s("display-name"), s("id"), s("lifecycle-state"), s("shape"),
        n("compute-count"), n("storage-count"), n("total-storage-size-in-gbs"),
        s("availability-domain"), s("time-created") ] | @csv' \
      db cloud-exadata-infrastructure list "${R[@]}"

    emit exadata_infrastructure.csv "db exadata-infrastructure list [$CNAME]" '
      dat | .[]? | [ $r,$cn,$co,"EXADATA_INFRASTRUCTURE_CC",
        s("display-name"), s("id"), s("lifecycle-state"), s("shape"),
        n("compute-count"), n("storage-count"), n("total-storage-size-in-gbs"),
        "", s("time-created") ] | @csv' \
      db exadata-infrastructure list "${R[@]}"

    emit vm_clusters.csv "db cloud-vm-cluster list [$CNAME]" '
      dat | .[]? | [ $r,$cn,$co,"CLOUD_VM_CLUSTER",
        s("display-name"), s("id"), s("lifecycle-state"), s("shape"),
        n("cpu-core-count"), n("memory-size-in-gbs"),
        s("gi-version"), s("system-version"), cnt("db-servers"),
        s("license-model"), s("time-created") ] | @csv' \
      db cloud-vm-cluster list "${R[@]}"

    emit vm_clusters.csv "db vm-cluster list [$CNAME]" '
      dat | .[]? | [ $r,$cn,$co,"VM_CLUSTER_CC",
        s("display-name"), s("id"), s("lifecycle-state"), s("shape"),
        n("cpus-enabled"), n("memory-size-in-gbs"),
        s("gi-version"), s("system-version"), cnt("db-servers"),
        s("license-model"), s("time-created") ] | @csv' \
      db vm-cluster list "${R[@]}"

    emit autonomous_databases.csv "db autonomous-database list [$CNAME]" '
      dat | .[]? | [ $r,$cn,$co,
        s("display-name"), s("db-name"), s("id"), s("lifecycle-state"),
        s("db-version"), s("db-workload"), s("compute-model"),
        n("compute-count"), n("cpu-core-count"), n("data-storage-size-in-tbs"),
        s("license-model"), tri("is-dedicated"),
        s("autonomous-container-database-id"), s("time-created") ] | @csv' \
      db autonomous-database list "${R[@]}"

    emit autonomous_container_databases.csv "db autonomous-container-database list [$CNAME]" '
      dat | .[]? | [ $r,$cn,$co,
        s("display-name"), s("id"), s("lifecycle-state"),
        s("db-version"), s("patch-model"), s("service-level-agreement-type"),
        s("cloud-autonomous-vm-cluster-id"), s("autonomous-vm-cluster-id"),
        s("time-created") ] | @csv' \
      db autonomous-container-database list "${R[@]}"

    emit mysql_db_systems.csv "mysql db-system list [$CNAME]" '
      dat | .[]? | [ $r,$cn,$co,
        s("display-name"), s("id"), s("lifecycle-state"),
        s("mysql-version"), s("shape-name"), n("data-storage-size-in-gbs"),
        tri("is-highly-available"), s("availability-domain"), s("time-created") ] | @csv' \
      mysql db-system list "${R[@]}"

    emit postgresql_db_systems.csv "psql db-system list [$CNAME]" '
      dat | .[]? | [ $r,$cn,$co,
        s("display-name"), s("id"), s("lifecycle-state"),
        s("db-version"), s("shape"), n("instance-count"),
        (sub("instance-ocpu-count") | tostring),
        (sub("instance-memory-size-in-gbs") | tostring),
        s("time-created") ] | @csv' \
      psql db-system list "${R[@]}"

    emit nosql_tables.csv "nosql table list [$CNAME]" '
      dat | .[]? | [ $r,$cn,$co,
        s("name"), s("id"), s("lifecycle-state"),
        tri("is-multi-region"), (sub("table-limits") | tostring),
        s("time-created") ] | @csv' \
      nosql table list "${R[@]}"

    ############################ OS MANAGEMENT ###############################
    # Fallback to legacy OS Management ONLY when the Hub call actually failed.
    # Zero Hub-managed instances is a valid result, not a reason to fall back.
    OSM_SRC="OS_MANAGEMENT_HUB"
    oci_capture OSM_JSON OSM_RC "os-management-hub managed-instance list [$CNAME]" \
      os-management-hub managed-instance list "${R[@]}"
    if (( OSM_RC != 0 )); then
      OSM_SRC="OS_MANAGEMENT_LEGACY"
      oci_capture OSM_JSON OSM_RC "os-management managed-instance list [$CNAME]" \
        os-management managed-instance list "${R[@]}"
      (( OSM_RC != 0 )) && OSM_SRC="UNAVAILABLE"
    fi

    printf '%s' "$OSM_JSON" \
      | jq -r --arg r "$REGION" --arg cn "$CNAME" --arg src "$OSM_SRC" "$JQP"'
          dat | .[]? | [ $r,$cn,
            s("display-name"), s("id"), $src, s("status"),
            s("os-name"), s("os-version"), s("os-kernel-version"),
            s("architecture"), s("agent-version"),
            n("installed-packages"), n("security-updates-available"),
            n("bug-updates-available"), n("other-updates-available"),
            (sub("profile") | tostring),
            (sub("lifecycle-environment") | s("display-name")) ] | @csv' \
      >> "$OUTDIR/os_managed_instances.csv" 2>>"$ERRLOG"

    if (( WITH_PACKAGES == 1 && OSM_RC == 0 )); then
      while IFS=$'\t' read -r MIID MINAME; do
        [[ -z "$MIID" ]] && continue
        if [[ "$OSM_SRC" == "OS_MANAGEMENT_HUB" ]]; then
          oci_capture PKG_JSON PKG_RC "osmh list-installed-packages [$MINAME]" \
            os-management-hub managed-instance list-installed-packages \
            --managed-instance-id "$MIID" --region "$REGION" --all
        else
          oci_capture PKG_JSON PKG_RC "osm list-packages [$MINAME]" \
            os-management managed-instance list-packages \
            --managed-instance-id "$MIID" --region "$REGION" --all
        fi
        printf '%s' "$PKG_JSON" \
          | jq -r --arg r "$REGION" --arg mn "$MINAME" --arg mi "$MIID" "$JQP"'
              dat | .[]? | [ $r,$mn,$mi,
                ((.["display-name"] // .name // "") | tostring),
                s("version"), s("architecture"), s("type"),
                s("install-time") ] | @csv' \
          >> "$OUTDIR/os_installed_packages.csv" 2>>"$ERRLOG"
      done < <(printf '%s' "$OSM_JSON" \
               | jq -r "$JQP"'dat | .[]? | [.id, (.["display-name"] // "")] | @tsv')
    fi

  done < "$COMP_FILE"

  CUR_CID="-"; CUR_CNAME="-"

  ############################ IMAGE RESOLUTION ##############################
  log "  resolving images..."
  while read -r IMG; do
    [[ -z "$IMG" || "$IMG" == "null" ]] && continue
    oci_q "compute image get" compute image get --image-id "$IMG" --region "$REGION" \
      | jq -c '.data | select(. != null) | {
          id:.id, name:(.["display-name"]//""), os:(.["operating-system"]//""),
          osv:(.["operating-system-version"]//""), base:(.["base-image-id"]//""),
          lm:(.["launch-mode"]//""), tc:(.["time-created"]//"") }' \
      >> "$RTMP/images.jsonl"
  done < <(jq -r '(.["image-id"] // .["source-details"]["image-id"] // empty)' \
              "$RTMP/instances.jsonl" 2>/dev/null | sort -u)

  jq -s 'map({key:.id, value:.}) | from_entries' "$RTMP/images.jsonl" \
     > "$RTMP/image_index.json" 2>>"$ERRLOG" || echo '{}' > "$RTMP/image_index.json"

  log "  writing compute baseline..."
  jq -r --slurpfile IDX "$RTMP/image_index.json" "$JQP"'
      ($IDX[0] // {}) as $img
      | (.["image-id"] // .["source-details"]["image-id"] // "") as $iid
      | ($img[$iid] // {}) as $i
      | (sub("shape-config"))  as $sc
      | (sub("platform-config")) as $pc
      | (sub("agent-config")) as $ac
      | [ ._region, ._cname, ._cocid,
          s("display-name"), s("id"), s("lifecycle-state"),
          (if   (.shape // "") | startswith("BM.") then "BARE_METAL"
           elif (.shape // "") | startswith("VM.") then "VM"
           else "OTHER" end),
          s("shape"),
          ($sc | n("ocpus")), ($sc | n("memory-in-gbs")),
          ($sc | n("gpus")), ($sc | s("gpu-description")),
          ($sc | n("local-disks")), ($sc | n("local-disks-total-size-in-gbs")),
          ($sc | s("processor-description")),
          ($sc | n("networking-bandwidth-in-gbps")),
          s("availability-domain"), s("fault-domain"), s("launch-mode"),
          ($pc | s("type")),
          ($pc | tri("is-secure-boot-enabled")),
          ($pc | tri("is-measured-boot-enabled")),
          ($pc | tri("is-trusted-platform-module-enabled")),
          ($i.name // ""), ($i.os // ""), ($i.osv // ""), $iid,
          ($ac | tri("is-monitoring-disabled")),
          ($ac | tri("is-management-disabled")),
          ([ ($ac | arr("plugins-config"))[]
             | select(((.["desired-state"] // .desiredState // "") | ascii_upcase) == "ENABLED")
             | (.name // "") ] | join("|")),
          s("time-created"),
          ((.["freeform-tags"] // {}) | to_entries | map("\(.key)=\(.value)") | join("|"))
        ] | @csv' "$RTMP/instances.jsonl" >> "$OUTDIR/compute_instances.csv" 2>>"$ERRLOG"

  jq -s --slurpfile IDX "$RTMP/image_index.json" --arg r "$REGION" '
      ($IDX[0] // {}) as $img
      | group_by(.["image-id"] // .["source-details"]["image-id"] // "")
      | map({ iid:(.[0]["image-id"] // .[0]["source-details"]["image-id"] // ""), n:length })
      | .[] | . as $g | ($img[$g.iid] // {}) as $i
      | [ $r, $g.iid, ($i.name//""), ($i.os//""), ($i.osv//""),
          ($i.base//""), ($i.lm//""), ($i.tc//""), ($g.n|tostring) ] | @csv' \
      "$RTMP/instances.jsonl" >> "$OUTDIR/images_in_use.csv" 2>>"$ERRLOG"

  ############################ VNICS #########################################
  if (( SKIP_VNICS == 0 )); then
    log "  collecting VNICs..."
    while IFS=$'\t' read -r IID INAME ICN; do
      [[ -z "$IID" ]] && continue
      oci_q "compute instance list-vnics [$INAME]" compute instance list-vnics \
          --instance-id "$IID" --region "$REGION" --all \
        | jq -r --arg r "$REGION" --arg cn "$ICN" --arg nm "$INAME" --arg id "$IID" "$JQP"'
            dat | .[]? | [ $r,$cn,$nm,$id,
              s("display-name"), s("id"), s("private-ip"), s("public-ip"),
              s("mac-address"), s("subnet-id"), cnt("nsg-ids"),
              tri("is-primary"), tri("skip-source-dest-check") ] | @csv' \
        >> "$OUTDIR/instance_vnics.csv" 2>>"$ERRLOG"
    done < <(jq -r 'select((.["lifecycle-state"] // "") != "TERMINATED")
                    | [.id, (.["display-name"] // ""), ._cname] | @tsv' \
                "$RTMP/instances.jsonl" 2>/dev/null)
  fi

  log "  region complete."
done

###############################################################################
# Ledger + summary
###############################################################################
cp "$STATUS" "$OUTDIR/collection_status.csv"
cp "$ERRLOG" "$OUTDIR/errors.log"

OPS_OK=$(awk -F',' 'NR>1 && $6=="OK"     {c++} END{print c+0}' "$STATUS")
OPS_EM=$(awk -F',' 'NR>1 && $6=="EMPTY"  {c++} END{print c+0}' "$STATUS")
OPS_FA=$(awk -F',' 'NR>1 && $6=="FAILED" {c++} END{print c+0}' "$STATUS")
OPS_TOT=$(( OPS_OK + OPS_EM + OPS_FA ))

RES_TOT=0
for f in "$OUTDIR"/*.csv; do
  [[ "$(basename "$f")" == "collection_status.csv" ]] && continue
  m=$(( $(wc -l < "$f") - 1 )); (( m < 0 )) && m=0
  RES_TOT=$(( RES_TOT + m ))
done

COVERAGE="COMPLETE"; (( OPS_FA > 0 )) && COVERAGE="INCOMPLETE"

SUM="$OUTDIR/summary.txt"
{
  echo "OCI Hardware & Software Baseline"
  echo "================================"
  echo "Collector    : $(basename "$0") v$VERSION (read-only)"
  echo "Tenancy      : $TENANCY_NAME"
  echo "Tenancy OCID : $TENANCY_OCID"
  echo "Auth         : $AUTH_DESC"
  echo "Collected    : $TS"
  echo "Regions      : ${REGIONS[*]}"
  echo "Compartments : $COMP_COUNT"
  echo "Packages     : $( (( WITH_PACKAGES == 1 )) && echo included || echo 'not collected (-p to enable)')"
  echo
  echo "Collection integrity"
  echo "--------------------"
  printf '  %-34s %s\n' "Total operations"        "$OPS_TOT"
  printf '  %-34s %s\n' "Successful operations"   "$OPS_OK"
  printf '  %-34s %s\n' "Empty responses"         "$OPS_EM"
  printf '  %-34s %s\n' "Failed operations"       "$OPS_FA"
  printf '  %-34s %s\n' "Resources inventoried"   "$RES_TOT"
  printf '  %-34s %s\n' "COVERAGE STATUS"         "$COVERAGE"
  if (( OPS_FA > 0 )); then
    echo
    echo "  Failures by category:"
    awk -F',' 'NR>1 && $6=="FAILED" {c[$8]++} END{for(k in c) printf "    %-22s %s\n", k, c[k]}' "$STATUS"
    echo
    echo "  A zero-row CSV is evidence of zero resources ONLY where the matching"
    echo "  collection_status.csv rows are OK. Reconcile before assertion."
  fi
  echo
  echo "Record counts"
  echo "-------------"
  for f in "$OUTDIR"/*.csv; do
    m=$(( $(wc -l < "$f") - 1 )); (( m < 0 )) && m=0
    printf '  %-38s %s\n' "$(basename "$f")" "$m"
  done
  echo
  echo "Control mapping"
  echo "---------------"
  echo "  CM-8  : compute, storage, file storage, object storage, network,"
  echo "          kubernetes, containers, functions, database CSVs"
  echo "  CM-2  : images_in_use, oke_node_pools, db_homes, vm_clusters"
  echo "  CM-6  : compute_instances plugin posture, network rule counts"
  echo "  SI-2  : os_managed_instances, os_installed_packages"
  echo "  SA-22 : image_os_version, db_version, kubernetes_version columns"
  echo
  echo "Known scope limits (state these in the evidence memo)"
  echo "-----------------------------------------------------"
  echo "  * In-guest package inventory requires Oracle Cloud Agent plus OS"
  echo "    Management Hub enrollment. Instances in compute_instances.csv that"
  echo "    are absent from os_managed_instances.csv are the CM-8 gap list."
  echo "  * platform_config_type is the platform configuration model, NOT a"
  echo "    firmware version. Firmware evidence requires in-guest or hardware"
  echo "    management sources not exposed by the instance summary."
  echo "  * configured_node_count is desired node-pool size, not running nodes."
  echo "  * Functions image tags are mutable; image_digest is authoritative and"
  echo "    is blank where the function was deployed by tag."
  echo "  * Rule-level detail (route rules, security list and NSG rules) is"
  echo "    counted, not enumerated. Rule content is CM-6 evidence, collected"
  echo "    separately."
  echo "  * FSS snapshots and Lustre file systems are not collected."
  echo "  * Object Storage lifecycle policies are not collected; retention"
  echo "    rules are counted only."
} > "$SUM"

echo
cat "$SUM"
echo
log "Done. Output: $OUTDIR"

if (( OPS_FA > 0 )); then
  log "COVERAGE INCOMPLETE - $OPS_FA failed operation(s). See collection_status.csv."
  exit 3
fi
exit 0
