#!/usr/bin/env bash
#
# oci_cost_usage_to_sharepoint.sh
#
# Read-only OCI cost/usage extraction plus CSV upload to SharePoint Online.
# Designed for OCI Cloud Shell.
#
# OCI operations:
#   - Usage API request-summarized-usages (read only)
#
# Microsoft operations:
#   - Microsoft Graph site/drive discovery (read only)
#   - Upload/overwrite CSV files in one SharePoint folder
#
# Required commands: python3, curl
# Required Python package: OCI Python SDK (`import oci`) -- ships with the OCI
# CLI, so it is already present in Cloud Shell.
#
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

SCRIPT_NAME="$(basename "$0")"
OUTPUT_DIR="${OUTPUT_DIR:-$HOME/oci-cost-usage-report}"
DAYS_BACK="${DAYS_BACK:-90}"
GRANULARITY="${GRANULARITY:-DAILY}"
OCI_QUERY_TYPE="${OCI_QUERY_TYPE:-COST}"
KEEP_ARCHIVE="${KEEP_ARCHIVE:-true}"
UPLOAD_TO_SHAREPOINT="${UPLOAD_TO_SHAREPOINT:-true}"
# By default, keep timestamped archives locally but do NOT upload them to
# SharePoint (a daily run would otherwise accumulate ~730 archive files/year in
# the library). Power BI only needs the two stable *_latest.csv files.
KEEP_LOCAL_ARCHIVE="${KEEP_LOCAL_ARCHIVE:-${KEEP_ARCHIVE}}"
UPLOAD_ARCHIVE_TO_SHAREPOINT="${UPLOAD_ARCHIVE_TO_SHAREPOINT:-false}"
# Guard against silently replacing the Power BI source with an empty report.
UPLOAD_EMPTY_REPORT="${UPLOAD_EMPTY_REPORT:-false}"
# Retain the timestamped raw OCI API response. Default false: treat it as
# temporary so a daily schedule doesn't accumulate raw billing-metadata files.
KEEP_RAW_JSON="${KEEP_RAW_JSON:-false}"
# OCI CLI/SDK settings. Honor Cloud Shell's preauthenticated environment:
# Cloud Shell sets OCI_CLI_CONFIG_FILE=/etc/oci/config, OCI_CLI_PROFILE=<region>,
# and OCI_CLI_AUTH=instance_obo_user (delegation-token auth), usually with no
# [DEFAULT] profile. Fall back to the classic defaults elsewhere.
OCI_PROFILE="${OCI_PROFILE:-${OCI_CLI_PROFILE:-DEFAULT}}"
OCI_AUTH="${OCI_AUTH:-${OCI_CLI_AUTH:-}}"
OCI_CONFIG_FILE="${OCI_CONFIG_FILE:-${OCI_CLI_CONFIG_FILE:-}}"

# Microsoft cloud endpoints. Defaults target commercial cloud.
# For GCC High / DoD, set:
#   GRAPH_HOST=graph.microsoft.us
#   LOGIN_HOST=login.microsoftonline.us
#   GRAPH_SCOPE=https://graph.microsoft.us/.default
GRAPH_HOST="${GRAPH_HOST:-graph.microsoft.com}"
LOGIN_HOST="${LOGIN_HOST:-login.microsoftonline.com}"
GRAPH_SCOPE="${GRAPH_SCOPE:-https://${GRAPH_HOST}/.default}"

# Stable filenames are intentionally overwritten so Power BI always sees the
# same source file. Timestamped copies can also be retained for audit history.
STABLE_CSV_NAME="${STABLE_CSV_NAME:-oci_cost_usage_latest.csv}"
STABLE_SUMMARY_NAME="${STABLE_SUMMARY_NAME:-oci_cost_summary_latest.csv}"

log()  { printf '[%s] %s\n' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
die()  { log "ERROR: $*"; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1"; }

# Track temp files/dirs so a failure at any point cleans up after itself.
TEMP_FILES=()
cleanup() {
  local f
  for f in "${TEMP_FILES[@]:-}"; do
    [[ -n "$f" && -e "$f" ]] && rm -rf "$f"
  done
}
trap cleanup EXIT

usage() {
  cat <<EOF
Usage:
  $SCRIPT_NAME [options]

Options:
  --days N                 Number of completed/partial UTC days to retrieve.
                           Default: $DAYS_BACK
  --start YYYY-MM-DD       Explicit UTC start date, inclusive.
  --end YYYY-MM-DD         Explicit UTC end date, exclusive.
  --output-dir PATH        Local output directory.
  --no-upload              Create CSV files but do not upload to SharePoint.
  --no-archive             Do not create timestamped local archive CSVs.
  --oci-auth METHOD        OCI auth: instance_obo_user, security_token,
                           instance_principal, resource_principal, api_key,
                           or empty for API-key. Default: inherits OCI_CLI_AUTH.
                           Current: $OCI_AUTH
  --profile NAME           OCI CLI/SDK profile. Default: $OCI_PROFILE
  -h, --help               Show help.

Required SharePoint environment variables when upload is enabled:
  MS_TENANT_ID             Microsoft Entra tenant ID
  MS_CLIENT_ID             App registration client ID
  MS_CLIENT_SECRET         App registration client secret
  SP_HOSTNAME              Example: contoso.sharepoint.com
  SP_SITE_PATH             Example: /sites/FinOps
  SP_LIBRARY_NAME          Example: Documents
  SP_FOLDER_PATH           Example: PowerBI/OCI (must already exist)

Optional:
  OCI_TENANCY_OCID         If omitted, discovered from OCI config.
  OCI_CONFIG_FILE          Explicit OCI config file.
  DAYS_BACK                Default lookback if --start/--end are omitted.
  GRANULARITY              HOURLY, DAILY, or MONTHLY. Default: DAILY.
  OCI_QUERY_TYPE           COST, USAGE, USAGE_ONLY, CREDIT, etc. Default: COST.
  GROUP_BY                 JSON array of grouping dimensions (default 4).
  MAX_GROUPBY              Max grouping dimensions allowed. Default: 4.
  UPLOAD_EMPTY_REPORT      Allow overwriting SharePoint with a 0-row report.
                           Default: false.
  KEEP_LOCAL_ARCHIVE       Keep timestamped local archive CSVs. Default: true.
  KEEP_RAW_JSON            Retain the timestamped raw OCI API response.
                           Default: false (treated as temporary).
  UPLOAD_ARCHIVE_TO_SHAREPOINT
                           Also upload archive CSVs to SharePoint. Default: false.
  GRAPH_HOST / LOGIN_HOST / GRAPH_SCOPE
                           Override for GCC High / DoD (graph.microsoft.us etc.).
EOF
}

START_DATE=""
END_DATE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --days)       DAYS_BACK="${2:?Missing value for --days}"; shift 2 ;;
    --start)      START_DATE="${2:?Missing value for --start}"; shift 2 ;;
    --end)        END_DATE="${2:?Missing value for --end}"; shift 2 ;;
    --output-dir) OUTPUT_DIR="${2:?Missing value for --output-dir}"; shift 2 ;;
    --no-upload)  UPLOAD_TO_SHAREPOINT=false; shift ;;
    --no-archive) KEEP_ARCHIVE=false; KEEP_LOCAL_ARCHIVE=false; shift ;;
    --oci-auth)   OCI_AUTH="${2:?Missing value for --oci-auth}"; shift 2 ;;
    --profile)    OCI_PROFILE="${2:?Missing value for --profile}"; shift 2 ;;
    -h|--help)    usage; exit 0 ;;
    *)            die "Unknown argument: $1" ;;
  esac
done

need python3
need curl

# Extraction uses the OCI Python SDK (not the CLI binary), so require the SDK.
if ! python3 -c 'import oci' >/dev/null 2>&1; then
  die "OCI Python SDK is required but unavailable. In Cloud Shell it ships with the CLI; verify with: python3 -c 'import oci; print(oci.__version__)'"
fi

# Normalize and validate boolean env vars so a typo like 'True' or 'yes' fails
# loudly instead of silently disabling (e.g.) the SharePoint upload.
normalize_bool() {
  local name="$1"
  local value="${!name,,}"
  case "$value" in
    true|false) printf -v "$name" '%s' "$value" ;;
    *) die "$name must be 'true' or 'false'; received: ${!name}" ;;
  esac
}
normalize_bool UPLOAD_TO_SHAREPOINT
normalize_bool KEEP_LOCAL_ARCHIVE
normalize_bool UPLOAD_ARCHIVE_TO_SHAREPOINT
normalize_bool UPLOAD_EMPTY_REPORT
normalize_bool KEEP_RAW_JSON

# Stable filenames go into both local paths and Graph upload URLs; keep them
# bare filenames to prevent directory traversal or accidental nested paths.
validate_filename() {
  local name="$1"
  local value="${!name}"
  [[ -n "$value" ]] || die "$name cannot be empty."
  [[ "$value" != */* && "$value" != *\\* ]] || die "$name must be a filename only, not a path: $value"
  [[ "$value" != "." && "$value" != ".." ]] || die "Invalid $name: $value"
}
validate_filename STABLE_CSV_NAME
validate_filename STABLE_SUMMARY_NAME
[[ "$STABLE_CSV_NAME" != "$STABLE_SUMMARY_NAME" ]] || die "Detail and summary stable filenames must differ."

# If archive upload is requested, ensure local archives are actually created.
if [[ "$UPLOAD_ARCHIVE_TO_SHAREPOINT" == "true" ]]; then
  KEEP_LOCAL_ARCHIVE=true
fi

[[ "$DAYS_BACK" =~ ^[0-9]+$ ]] || die "--days must be a positive integer."
(( DAYS_BACK > 0 )) || die "--days must be greater than zero."

mkdir -p "$OUTPUT_DIR"
RUN_TS="$(date -u +'%Y%m%dT%H%M%SZ')"

# Resolve the date window. OCI Usage API end time is exclusive.
if [[ -z "$START_DATE" ]]; then
  START_DATE="$(date -u -d "$((DAYS_BACK - 1)) days ago" +'%Y-%m-%d')"
fi
if [[ -z "$END_DATE" ]]; then
  END_DATE="$(date -u -d 'tomorrow' +'%Y-%m-%d')"
fi

# Validate query type against the values the Usage API accepts.
case "${OCI_QUERY_TYPE^^}" in
  COST|USAGE|USAGE_ONLY|CREDIT|EXPIREDCREDIT|ALLCREDIT)
    OCI_QUERY_TYPE="${OCI_QUERY_TYPE^^}" ;;
  *)
    die "Invalid OCI_QUERY_TYPE: $OCI_QUERY_TYPE (use COST, USAGE, USAGE_ONLY, CREDIT, EXPIREDCREDIT, or ALLCREDIT)." ;;
esac

# Normalize granularity so the value sent to the API is uppercase regardless of
# how the user exported it (e.g. GRANULARITY=daily).
GRANULARITY="${GRANULARITY^^}"

python3 - "$START_DATE" "$END_DATE" "$GRANULARITY" <<'PY'
import datetime as dt
import sys
start_text, end_text, granularity = sys.argv[1:4]
try:
    start = dt.date.fromisoformat(start_text)
    end = dt.date.fromisoformat(end_text)
except ValueError as exc:
    raise SystemExit(f"Invalid ISO date: {exc}")
if start >= end:
    raise SystemExit("Start date must be earlier than end date.")
days = (end - start).days
granularity = granularity.upper()
allowed = {"HOURLY", "DAILY", "MONTHLY"}
if granularity not in allowed:
    raise SystemExit(
        f"Unsupported GRANULARITY={granularity}. Use HOURLY, DAILY, or MONTHLY "
        "(TOTAL is not yet supported by the API)."
    )
if granularity == "HOURLY" and days > 1:
    raise SystemExit(f"HOURLY queries should not exceed 24 hours; requested {days} days.")
if granularity == "DAILY" and days > 90:
    raise SystemExit(
        f"DAILY queries cannot exceed 90 days; requested {days} days. "
        "Use a shorter window or GRANULARITY=MONTHLY."
    )
if granularity == "MONTHLY" and days > 366:
    raise SystemExit(
        f"MONTHLY queries cannot exceed roughly 12 months; requested {days} days."
    )
PY

START_TIME="${START_DATE}T00:00:00Z"
END_TIME="${END_DATE}T00:00:00Z"

# Cloud Shell normally uses ~/.oci/config, but this also supports environments
# where the OCI config was placed at /.oci/config.
detect_oci_config() {
  local candidate
  if [[ -n "${OCI_CONFIG_FILE:-}" ]]; then
    [[ -r "$OCI_CONFIG_FILE" ]] || die "OCI_CONFIG_FILE is not readable: $OCI_CONFIG_FILE"
    printf '%s\n' "$OCI_CONFIG_FILE"
    return
  fi

  for candidate in \
    "${OCI_CLI_CONFIG_FILE:-}" \
    "/etc/oci/config" \
    "$HOME/.oci/config" \
    "/.oci/config" \
    "/home/$(id -un)/.oci/config"
  do
    [[ -z "$candidate" ]] && continue
    if [[ -r "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return
    fi
  done

  die "No readable OCI config found. Checked OCI_CONFIG_FILE, OCI_CLI_CONFIG_FILE, /etc/oci/config, ~/.oci/config, and /.oci/config. Set OCI_CONFIG_FILE or OCI_TENANCY_OCID."
}

OCI_CONFIG_FILE_RESOLVED=""
# Cloud Shell exports the tenancy OCID; OCI_CLI_TENANCY is the documented CLI
# variable. Accept OCI_TENANCY too for compatibility.
if [[ -z "${OCI_TENANCY_OCID:-}" ]]; then
  OCI_TENANCY_OCID="${OCI_CLI_TENANCY:-${OCI_TENANCY:-}}"
fi
# Resolve a config file if one is available (used by the SDK for region/auth),
# even when the tenancy is already known from the environment.
if [[ -n "${OCI_CONFIG_FILE:-}" ]] || [[ -r "${OCI_CLI_CONFIG_FILE:-/nonexistent}" ]] \
   || [[ -r "/etc/oci/config" ]] || [[ -r "$HOME/.oci/config" ]] || [[ -r "/.oci/config" ]]; then
  OCI_CONFIG_FILE_RESOLVED="$(detect_oci_config 2>/dev/null || true)"
fi
if [[ -z "${OCI_TENANCY_OCID:-}" ]]; then
  [[ -n "$OCI_CONFIG_FILE_RESOLVED" ]] || OCI_CONFIG_FILE_RESOLVED="$(detect_oci_config)"
  OCI_TENANCY_OCID="$(
    python3 - "$OCI_CONFIG_FILE_RESOLVED" "$OCI_PROFILE" <<'PY'
import configparser
import sys
path, profile = sys.argv[1:3]
cfg = configparser.ConfigParser(interpolation=None)
with open(path, encoding="utf-8") as fh:
    cfg.read_file(fh)
if profile not in cfg:
    raise SystemExit(
        f"OCI profile [{profile}] was not found in {path}. "
        "In Cloud Shell set OCI_TENANCY_OCID or ensure OCI_CLI_PROFILE matches a section."
    )
tenancy = cfg[profile].get("tenancy", "").strip()
if not tenancy:
    raise SystemExit(f"No tenancy value found in [{profile}] of {path}")
print(tenancy)
PY
  )"
fi

if [[ -n "${OCI_TENANCY_OCID:-}" ]]; then
  [[ "$OCI_TENANCY_OCID" == ocid1.tenancy.* ]] || die "Invalid OCI tenancy OCID: $OCI_TENANCY_OCID"
else
  # Principal/delegation auth can obtain the tenancy from the signer at runtime.
  case "$OCI_AUTH" in
    instance_obo_user|instance_principal|resource_principal) : ;;
    *) die "Missing OCI tenancy OCID. Set OCI_TENANCY_OCID or OCI_CLI_TENANCY." ;;
  esac
fi

RAW_JSON="$OUTPUT_DIR/oci_cost_usage_raw_${RUN_TS}.json"
# The raw API response is temporary by default (it can contain more detailed
# billing metadata than the CSVs); retain only when explicitly requested.
if [[ "$KEEP_RAW_JSON" != "true" ]]; then
  TEMP_FILES+=("$RAW_JSON")
fi
LATEST_CSV="$OUTPUT_DIR/$STABLE_CSV_NAME"
SUMMARY_CSV="$OUTPUT_DIR/$STABLE_SUMMARY_NAME"
ARCHIVE_CSV="$OUTPUT_DIR/oci_cost_usage_${START_DATE}_to_${END_DATE}_${RUN_TS}.csv"
ARCHIVE_SUMMARY="$OUTPUT_DIR/oci_cost_summary_${START_DATE}_to_${END_DATE}_${RUN_TS}.csv"

# resourceId is a documented grouping dimension and gives resource-level
# granularity. resourceName is retained in the CSV when OCI returns it, but it
# may be blank for some services or charge types. The default grouping set is
# intentionally limited for predictable response size and Power BI performance;
# override with GROUP_BY.
GROUP_BY="${GROUP_BY:-[\"service\",\"compartmentName\",\"resourceId\",\"skuPartNumber\"]}"

# Validate GROUP_BY before building the request so a bad value fails fast
# instead of returning an opaque 400 from the API. The dimension cap is a design
# limit this script enforces (widely reported for the Usage API); raise
# MAX_GROUPBY if your tenancy accepts more and you need them.
MAX_GROUPBY="${MAX_GROUPBY:-4}"
[[ "$MAX_GROUPBY" =~ ^[1-9][0-9]*$ ]] || die "MAX_GROUPBY must be a positive integer."
MAX_GROUPBY="$MAX_GROUPBY" python3 - "$GROUP_BY" <<'PY'
import json
import os
import sys
allowed = {
    "tagNamespace", "tagKey", "tagValue",
    "service", "skuName", "skuPartNumber", "unit",
    "compartmentName", "compartmentPath", "compartmentId",
    "platform", "region", "logicalAd", "resourceId",
    "tenantId", "tenantName",
}
max_dims = int(os.environ["MAX_GROUPBY"])
try:
    dimensions = json.loads(sys.argv[1])
except json.JSONDecodeError as exc:
    raise SystemExit(f"GROUP_BY is not valid JSON: {exc}")
if not isinstance(dimensions, list):
    raise SystemExit("GROUP_BY must be a JSON array.")
if len(dimensions) > max_dims:
    raise SystemExit(
        f"GROUP_BY has {len(dimensions)} dimensions; this script limits grouping "
        f"to {max_dims} to control response size. Raise MAX_GROUPBY to override."
    )
invalid = sorted(set(dimensions) - allowed)
if invalid:
    raise SystemExit("Unsupported GROUP_BY dimensions: " + ", ".join(invalid))
PY

log "Extracting OCI $OCI_QUERY_TYPE data from $START_TIME through $END_TIME..."

# Extraction uses the OCI Python SDK rather than the CLI. Reason: the Usage API
# returns its pagination token in the opc-next-page HTTP RESPONSE HEADER. A CLI
# workflow that captures only the JSON response body cannot reliably obtain that
# token, so it cannot page past the first response. The SDK exposes the response
# headers directly, allowing every page to be retrieved and merged. The SDK
# ships with the OCI CLI, so it is present in Cloud Shell.
export OCI_CONFIG_FILE_RESOLVED OCI_PROFILE OCI_AUTH OCI_TENANCY_OCID \
       START_TIME END_TIME GRANULARITY OCI_QUERY_TYPE GROUP_BY RAW_JSON

python3 <<'PY'
import datetime as dt
import json
import os
import sys

try:
    import oci
except ImportError:
    raise SystemExit(
        "The OCI Python SDK is unavailable. Verify with: "
        "python3 -c 'import oci; print(oci.__version__)'"
    )

config_file = os.environ.get("OCI_CONFIG_FILE_RESOLVED", "").strip()
profile = os.environ.get("OCI_PROFILE", "DEFAULT")
auth = os.environ.get("OCI_AUTH", "").strip()

try:
    group_by = json.loads(os.environ["GROUP_BY"])
except json.JSONDecodeError as exc:
    raise SystemExit(f"GROUP_BY is invalid JSON: {exc}")

# Validate the auth method up front so an unknown value produces a clear error
# rather than a misleading downstream config/profile failure.
VALID_AUTH = {"", "api_key", "instance_obo_user", "instance_principal",
              "resource_principal", "security_token"}
if auth not in VALID_AUTH:
    raise SystemExit(f"Unsupported OCI authentication method for this script: {auth}")

# Load the OCI config. Principal-based auth (instance_principal,
# resource_principal) does not need a file-based user identity, so for those we
# tolerate an absent config and use region from the environment if present.
# For everything else, a config-load failure is fatal and surfaced verbatim so
# a bad profile/region isn't masked as a generic auth error.
def load_config():
    if config_file:
        try:
            return oci.config.from_file(file_location=config_file, profile_name=profile)
        except Exception as exc:
            raise SystemExit(f"Unable to load OCI profile [{profile}] from {config_file}: {exc}")
    if auth in {"instance_principal", "resource_principal"}:
        region = os.environ.get("OCI_CLI_REGION", "").strip()
        return {"region": region} if region else {}
    try:
        return oci.config.from_file(profile_name=profile)
    except Exception as exc:
        # instance_obo_user in Cloud Shell normally DOES have a config at
        # /etc/oci/config; if it's genuinely absent, we can still proceed with an
        # empty config because the delegation signer carries identity.
        if auth == "instance_obo_user":
            return {}
        raise SystemExit(
            f"Unable to load OCI profile [{profile}] from the default config location: {exc}"
        )

config = load_config()

signer = None
if auth == "instance_obo_user":
    # Cloud Shell delegation-token auth. This is the officially documented
    # pattern: read the delegation token and build the delegation-token signer,
    # then pass config={} + signer to the client.
    delegation_token_file = (
        os.environ.get("OCI_CLI_DELEGATION_TOKEN_FILE")
        or (config.get("delegation_token_file") if isinstance(config, dict) else None)
        or "/etc/oci/delegation_token"
    )
    if not os.path.isfile(os.path.expanduser(delegation_token_file)):
        raise SystemExit(
            "OCI_AUTH=instance_obo_user but the Cloud Shell delegation token is not "
            f"readable: {delegation_token_file}"
        )
    if not hasattr(oci.auth.signers, "InstancePrincipalsDelegationTokenSigner"):
        raise SystemExit(
            "This OCI SDK build lacks InstancePrincipalsDelegationTokenSigner; "
            "cannot use instance_obo_user. Check: python3 -c 'import oci; print(oci.__version__)'"
        )
    with open(os.path.expanduser(delegation_token_file), encoding="utf-8") as fh:
        delegation_token = fh.read().strip()
    signer = oci.auth.signers.InstancePrincipalsDelegationTokenSigner(
        delegation_token=delegation_token
    )
    if not isinstance(config, dict):
        config = {}
    # The delegation signer knows the tenancy; use it if we still lack one.
    if not os.environ.get("OCI_TENANCY_OCID") and getattr(signer, "tenancy_id", None):
        os.environ["OCI_TENANCY_OCID"] = signer.tenancy_id
elif auth == "instance_principal":
    signer = oci.auth.signers.InstancePrincipalsSecurityTokenSigner()
    if not isinstance(config, dict):
        config = {}
elif auth == "resource_principal":
    signer = oci.auth.signers.get_resource_principals_signer()
    if not isinstance(config, dict):
        config = {}
elif auth == "security_token":
    token_file = config.get("security_token_file")
    key_file = config.get("key_file")
    if not token_file or not key_file:
        raise SystemExit(
            "OCI_AUTH=security_token but security_token_file/key_file are missing "
            f"from profile [{profile}]."
        )
    with open(os.path.expanduser(token_file), encoding="utf-8") as fh:
        security_token = fh.read().strip()
    private_key = oci.signer.load_private_key_from_file(
        os.path.expanduser(key_file), config.get("pass_phrase")
    )
    signer = oci.auth.signers.SecurityTokenSigner(security_token, private_key)
elif auth in ("", "api_key"):
    signer = None  # default API-key signing carried in config
else:
    raise SystemExit(f"Unsupported OCI authentication method for this script: {auth}")

if signer is None and not config:
    raise SystemExit(
        "No usable OCI credentials: config is empty and no signer-based auth "
        "(instance_obo_user, instance_principal, resource_principal, security_token) was selected."
    )

client_kwargs = {}
if signer is not None:
    client_kwargs["signer"] = signer
client = oci.usage_api.UsageapiClient(config, **client_kwargs)

def parse_oci_time(value):
    # Model expects datetime objects; START_TIME/END_TIME are ...Z ISO strings.
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))

tenant_id = os.environ.get("OCI_TENANCY_OCID", "").strip()
if not tenant_id:
    tenant_id = getattr(signer, "tenancy_id", None) if signer is not None else None
if not tenant_id:
    tenant_id = config.get("tenancy") if isinstance(config, dict) else None
if not tenant_id:
    raise SystemExit(
        "Could not determine tenancy OCID from environment, signer, or config. "
        "Set OCI_TENANCY_OCID."
    )

details = oci.usage_api.models.RequestSummarizedUsagesDetails(
    tenant_id=tenant_id,
    time_usage_started=parse_oci_time(os.environ["START_TIME"]),
    time_usage_ended=parse_oci_time(os.environ["END_TIME"]),
    granularity=os.environ["GRANULARITY"],
    query_type=os.environ["OCI_QUERY_TYPE"],
    is_aggregate_by_time=False,
    group_by=group_by,
)

items = []
page = None
page_number = 0
seen_tokens = set()
# Explicit retry strategy for transient throttling (429) and 5xx. SDK operations
# do not retry by default. Degrade gracefully if a very old SDK lacks it.
retry_strategy = getattr(oci.retry, "DEFAULT_RETRY_STRATEGY", None)
while True:
    page_number += 1
    kwargs = {"page": page} if page else {}
    if retry_strategy is not None:
        kwargs["retry_strategy"] = retry_strategy
    response = client.request_summarized_usages(details, **kwargs)
    data = response.data
    if hasattr(data, "items"):
        page_items = data.items or []
    elif isinstance(data, list):
        page_items = data
    else:
        page_items = []
    items.extend(page_items)
    print(f"Retrieved OCI Usage API page {page_number}: {len(page_items)} row(s)",
          file=sys.stderr)

    # Prefer the SDK's parsed opc-next-page attribute; fall back to the raw
    # response header for older SDK builds. Both are the same token.
    next_page = getattr(response, "next_page", None)
    if not next_page:
        headers = getattr(response, "headers", None) or {}
        try:
            next_page = headers.get("opc-next-page")
        except Exception:
            next_page = None
    if next_page:
        next_page = str(next_page).strip()
    if not next_page:
        break
    if next_page in seen_tokens:
        raise SystemExit("OCI returned a repeated pagination token; stopping to avoid an infinite loop.")
    seen_tokens.add(next_page)
    page = next_page
    if page_number >= 200:
        raise SystemExit(
            "Stopped after 200 OCI Usage API pages; extraction may be incomplete. "
            "Narrow the query window or grouping and retry. Nothing was uploaded."
        )

serialized = [oci.util.to_dict(item) for item in items]
with open(os.environ["RAW_JSON"], "w", encoding="utf-8") as fh:
    json.dump({"data": {"items": serialized}}, fh, ensure_ascii=False)

print(f"Retrieved {len(items)} total row(s) across {page_number} page(s).",
      file=sys.stderr)
PY

[[ -s "$RAW_JSON" ]] || die "OCI returned no usable data. Verify Usage API permissions, OCI authentication, profile, and date range. See the README for the IAM policy that applies to your tenancy's access model."

# Convert OCI's JSON response to a stable Power BI-friendly schema.
CONVERT_OUTPUT="$(python3 - "$RAW_JSON" "$LATEST_CSV" "$SUMMARY_CSV" "$RUN_TS" <<'PY'
import csv
import datetime as dt
import json
import sys
from collections import defaultdict
from decimal import Decimal, InvalidOperation

raw_path, detail_path, summary_path, run_ts = sys.argv[1:5]

with open(raw_path, encoding="utf-8") as fh:
    payload = json.load(fh)

data = payload.get("data", payload)
if isinstance(data, dict):
    items = data.get("items", [])
elif isinstance(data, list):
    items = data
else:
    items = []

def first(row, *names, default=""):
    for name in names:
        if name in row and row[name] is not None:
            value = row[name]
            if isinstance(value, (dict, list)):
                return json.dumps(value, separators=(",", ":"), ensure_ascii=False)
            return value
    return default

def dec(value):
    try:
        if value in ("", None):
            return Decimal("0")
        return Decimal(str(value))
    except (InvalidOperation, ValueError):
        return Decimal("0")

fields = [
    "extract_utc",
    "usage_start_utc",
    "usage_end_utc",
    "service",
    "compartment_name",
    "compartment_id",
    "resource_name",
    "resource_id",
    "sku_name",
    "sku_part_number",
    "unit",
    "currency",
    "computed_quantity",
    "computed_amount",
    "attributed_cost",
    "subscription_id",
    "overage_flag",
    "is_correction",
    "tags_json",
]

extract_utc = dt.datetime.strptime(run_ts, "%Y%m%dT%H%M%SZ").replace(
    tzinfo=dt.timezone.utc
).isoformat().replace("+00:00", "Z")

normalized = []
for row in items:
    normalized.append({
        "extract_utc": extract_utc,
        "usage_start_utc": first(row, "time_usage_started", "time-usage-started", "timeUsageStarted"),
        "usage_end_utc": first(row, "time_usage_ended", "time-usage-ended", "timeUsageEnded"),
        "service": first(row, "service"),
        "compartment_name": first(row, "compartment_name", "compartment-name", "compartmentName"),
        "compartment_id": first(row, "compartment_id", "compartment-id", "compartmentId"),
        "resource_name": first(row, "resource_name", "resource-name", "resourceName"),
        "resource_id": first(row, "resource_id", "resource-id", "resourceId"),
        "sku_name": first(row, "sku_name", "sku-name", "skuName"),
        "sku_part_number": first(row, "sku_part_number", "sku-part-number", "skuPartNumber"),
        "unit": first(row, "unit"),
        "currency": first(row, "currency"),
        "computed_quantity": first(row, "computed_quantity", "computed-quantity", "computedQuantity", default=0),
        "computed_amount": first(row, "computed_amount", "computed-amount", "computedAmount", default=0),
        "attributed_cost": first(row, "attributed_cost", "attributed-cost", "attributedCost", default=0),
        "subscription_id": first(row, "subscription_id", "subscription-id", "subscriptionId"),
        "overage_flag": first(row, "overages_flag", "overage_flag", "overage-flag", "overageFlag", "overagesFlag"),
        "is_correction": first(row, "is_correction", "is-correction", "isCorrection"),
        "tags_json": first(row, "tags"),
    })

normalized.sort(key=lambda r: (
    str(r["usage_start_utc"]),
    str(r["service"]),
    str(r["compartment_name"]),
    str(r["resource_name"]),
    str(r["sku_name"]),
))

# Fail-fast guard against a field-mapping / schema mismatch: if OCI returned
# rows but every usage_start_utc is blank, the SDK-to-CSV key mapping does not
# match the response schema, and the CSV would be financially unusable. Stop
# before anything can be written or uploaded.
if normalized:
    populated_dates = sum(1 for r in normalized if r["usage_start_utc"])
    populated_amounts = sum(
        1 for r in normalized
        if r["computed_amount"] not in ("", None, 0, "0")
    )
    if populated_dates == 0:
        raise SystemExit(
            "OCI returned rows, but usage_start_utc is empty for every row. "
            "The SDK-to-CSV field mapping is incompatible with the received "
            "response schema; refusing to write unusable CSVs."
        )
    if populated_amounts == 0:
        print(
            "WARNING: computed_amount is zero or blank for every row. This may "
            "be legitimate (e.g. a USAGE query or zero-cost period), but verify "
            "the query type and source data.",
            file=sys.stderr,
        )

with open(detail_path, "w", newline="", encoding="utf-8-sig") as fh:
    writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(normalized)

summary = defaultdict(lambda: {
    "computed_quantity": Decimal("0"),
    "computed_amount": Decimal("0"),
    "attributed_cost": Decimal("0"),
    "row_count": 0,
})

for row in normalized:
    key = (
        row["usage_start_utc"],
        row["service"],
        row["compartment_name"],
        row["currency"],
        row["unit"],
    )
    bucket = summary[key]
    bucket["computed_quantity"] += dec(row["computed_quantity"])
    bucket["computed_amount"] += dec(row["computed_amount"])
    bucket["attributed_cost"] += dec(row["attributed_cost"])
    bucket["row_count"] += 1

summary_fields = [
    "extract_utc",
    "usage_start_utc",
    "service",
    "compartment_name",
    "currency",
    "unit",
    "computed_quantity",
    "computed_amount",
    "attributed_cost",
    "row_count",
]

with open(summary_path, "w", newline="", encoding="utf-8-sig") as fh:
    writer = csv.DictWriter(fh, fieldnames=summary_fields)
    writer.writeheader()
    for key in sorted(summary):
        usage_start, service, compartment, currency, unit = key
        values = summary[key]
        writer.writerow({
            "extract_utc": extract_utc,
            "usage_start_utc": usage_start,
            "service": service,
            "compartment_name": compartment,
            "currency": currency,
            "unit": unit,
            "computed_quantity": str(values["computed_quantity"]),
            "computed_amount": str(values["computed_amount"]),
            "attributed_cost": str(values["attributed_cost"]),
            "row_count": values["row_count"],
        })

print(f"detail_rows={len(normalized)}")
print(f"summary_rows={len(summary)}")
PY
)"
printf '%s\n' "$CONVERT_OUTPUT" >&2

DETAIL_ROW_COUNT="$(printf '%s\n' "$CONVERT_OUTPUT" | sed -n 's/^detail_rows=//p')"
if [[ "${DETAIL_ROW_COUNT:-0}" == "0" ]]; then
  log "WARNING: OCI returned zero cost/usage rows for $START_TIME through $END_TIME. CSVs will contain headers only."
  if [[ "$UPLOAD_TO_SHAREPOINT" == "true" && "$UPLOAD_EMPTY_REPORT" != "true" ]]; then
    die "Refusing to overwrite the SharePoint Power BI source with an empty report. This can be legitimate (no spend) or a transient permission/query problem. Set UPLOAD_EMPTY_REPORT=true to allow, or re-run --no-upload to inspect first."
  fi
fi

if [[ "$KEEP_LOCAL_ARCHIVE" == "true" ]]; then
  cp -f "$LATEST_CSV" "$ARCHIVE_CSV"
  cp -f "$SUMMARY_CSV" "$ARCHIVE_SUMMARY"
fi

MAX_SIMPLE_UPLOAD_BYTES=$((250 * 1024 * 1024))
check_upload_size() {
  local file="$1" size
  size="$(stat -c '%s' "$file")"
  if (( size > MAX_SIMPLE_UPLOAD_BYTES )); then
    die "File exceeds Microsoft Graph's 250 MB simple-upload limit ($size bytes): $file. A resumable upload session would be required."
  fi
}

upload_file_graph() {
  local local_file="$1"
  local remote_name="$2"
  local encoded_folder encoded_name upload_url http_code response_file

  check_upload_size "$local_file"

  encoded_folder="$(python3 -c 'import sys,urllib.parse; print(urllib.parse.quote(sys.argv[1].strip("/"), safe="/"))' "$SP_FOLDER_PATH")"
  encoded_name="$(python3 -c 'import sys,urllib.parse; print(urllib.parse.quote(sys.argv[1], safe=""))' "$remote_name")"

  if [[ -n "$encoded_folder" ]]; then
    upload_url="https://${GRAPH_HOST}/v1.0/drives/${DRIVE_ID}/root:/${encoded_folder}/${encoded_name}:/content"
  else
    upload_url="https://${GRAPH_HOST}/v1.0/drives/${DRIVE_ID}/root:/${encoded_name}:/content"
  fi

  response_file="$(mktemp)"
  TEMP_FILES+=("$response_file")
  http_code="$(
    curl --silent --show-error \
      --retry 5 --retry-delay 2 --retry-max-time 120 --retry-all-errors \
      --output "$response_file" \
      --write-out '%{http_code}' \
      --request PUT \
      --header "Authorization: Bearer $GRAPH_TOKEN" \
      --header "Content-Type: text/csv" \
      --data-binary "@$local_file" \
      "$upload_url"
  )"

  if [[ "$http_code" != "200" && "$http_code" != "201" ]]; then
    cat "$response_file" >&2 || true
    die "SharePoint upload failed for $remote_name (HTTP $http_code)."
  fi

  python3 - "$response_file" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as fh:
    item = json.load(fh)
print("Uploaded:", item.get("name", "unknown"))
print("SharePoint URL:", item.get("webUrl", "not returned"))
PY
}

if [[ "$UPLOAD_TO_SHAREPOINT" == "true" ]]; then
  : "${MS_TENANT_ID:?Set MS_TENANT_ID}"
  : "${MS_CLIENT_ID:?Set MS_CLIENT_ID}"
  : "${MS_CLIENT_SECRET:?Set MS_CLIENT_SECRET}"
  : "${SP_HOSTNAME:?Set SP_HOSTNAME, for example contoso.sharepoint.com}"
  : "${SP_SITE_PATH:?Set SP_SITE_PATH, for example /sites/FinOps}"
  : "${SP_LIBRARY_NAME:?Set SP_LIBRARY_NAME, for example Documents}"
  : "${SP_FOLDER_PATH:?Set SP_FOLDER_PATH, for example PowerBI/OCI}"

  log "Requesting Microsoft Graph app-only access token..."
  TOKEN_RESPONSE="$(
    MS_CLIENT_ID="$MS_CLIENT_ID" MS_CLIENT_SECRET="$MS_CLIENT_SECRET" \
    GRAPH_SCOPE="$GRAPH_SCOPE" python3 <<'PY' |
import os
import urllib.parse
payload = {
    "client_id": os.environ["MS_CLIENT_ID"],
    "client_secret": os.environ["MS_CLIENT_SECRET"],
    "scope": os.environ["GRAPH_SCOPE"],
    "grant_type": "client_credentials",
}
print(urllib.parse.urlencode(payload), end="")
PY
    curl --silent --show-error --fail \
      --retry 5 --retry-delay 2 --retry-max-time 60 --retry-all-errors \
      --request POST \
      --header 'Content-Type: application/x-www-form-urlencoded' \
      --data-binary @- \
      "https://${LOGIN_HOST}/${MS_TENANT_ID}/oauth2/v2.0/token"
  )"

  GRAPH_TOKEN="$(
    python3 -c 'import json,sys; print(json.load(sys.stdin).get("access_token",""))' <<<"$TOKEN_RESPONSE"
  )"
  [[ -n "$GRAPH_TOKEN" ]] || die "Microsoft Graph did not return an access token."
  unset TOKEN_RESPONSE MS_CLIENT_SECRET

  ENCODED_SITE_PATH="$(python3 -c 'import sys,urllib.parse; print(urllib.parse.quote(sys.argv[1].strip("/"), safe="/"))' "$SP_SITE_PATH")"
  SITE_RESPONSE_FILE="$(mktemp)"
  TEMP_FILES+=("$SITE_RESPONSE_FILE")
  SITE_HTTP_CODE="$(
    curl --silent --show-error \
      --retry 5 --retry-delay 2 --retry-max-time 60 --retry-all-errors \
      --output "$SITE_RESPONSE_FILE" \
      --write-out '%{http_code}' \
      --header "Authorization: Bearer $GRAPH_TOKEN" \
      "https://${GRAPH_HOST}/v1.0/sites/${SP_HOSTNAME}:/${ENCODED_SITE_PATH}"
  )"
  if [[ "$SITE_HTTP_CODE" != "200" ]]; then
    cat "$SITE_RESPONSE_FILE" >&2 || true
    die "Could not resolve SharePoint site (HTTP $SITE_HTTP_CODE). If using Sites.Selected, verify the app was explicitly granted access to this site (POST /sites/{id}/permissions) and that its assigned role permits writing."
  fi
  SITE_ID="$(
    python3 -c 'import json,sys; print(json.load(open(sys.argv[1],encoding="utf-8")).get("id",""))' "$SITE_RESPONSE_FILE"
  )"
  [[ -n "$SITE_ID" ]] || die "SharePoint response did not contain a site ID."

  DRIVES_RESPONSE_FILE="$(mktemp)"
  TEMP_FILES+=("$DRIVES_RESPONSE_FILE")
  DRIVES_HTTP_CODE="$(
    curl --silent --show-error \
      --retry 5 --retry-delay 2 --retry-max-time 60 --retry-all-errors \
      --output "$DRIVES_RESPONSE_FILE" \
      --write-out '%{http_code}' \
      --header "Authorization: Bearer $GRAPH_TOKEN" \
      "https://${GRAPH_HOST}/v1.0/sites/${SITE_ID}/drives"
  )"
  if [[ "$DRIVES_HTTP_CODE" != "200" ]]; then
    cat "$DRIVES_RESPONSE_FILE" >&2 || true
    die "Could not list SharePoint document libraries (HTTP $DRIVES_HTTP_CODE)."
  fi
  DRIVE_ID="$(
    python3 - "$DRIVES_RESPONSE_FILE" "$SP_LIBRARY_NAME" <<'PY'
import json
import sys
response_file, library_name = sys.argv[1:3]
with open(response_file, encoding="utf-8") as fh:
    payload = json.load(fh)
library = library_name.casefold()
for drive in payload.get("value", []):
    if str(drive.get("name", "")).casefold() == library:
        print(drive.get("id", ""))
        break
PY
  )"
  if [[ -z "$DRIVE_ID" ]]; then
    cat "$DRIVES_RESPONSE_FILE" >&2 || true
    die "SharePoint document library not found: $SP_LIBRARY_NAME"
  fi

  # Verify the target folder exists. The upload endpoint does not reliably
  # create missing parent folders, so a missing folder yields a confusing 404
  # on the PUT. Check once, up front, with a clear message.
  ENCODED_FOLDER_CHECK="$(python3 -c 'import sys,urllib.parse; print(urllib.parse.quote(sys.argv[1].strip("/"), safe="/"))' "$SP_FOLDER_PATH")"
  if [[ -n "$ENCODED_FOLDER_CHECK" ]]; then
    FOLDER_RESPONSE_FILE="$(mktemp)"
    TEMP_FILES+=("$FOLDER_RESPONSE_FILE")
    FOLDER_HTTP_CODE="$(
      curl --silent --show-error \
        --retry 5 --retry-delay 2 --retry-max-time 60 --retry-all-errors \
        --output "$FOLDER_RESPONSE_FILE" \
        --write-out '%{http_code}' \
        --header "Authorization: Bearer $GRAPH_TOKEN" \
        "https://${GRAPH_HOST}/v1.0/drives/${DRIVE_ID}/root:/${ENCODED_FOLDER_CHECK}"
    )"
    if [[ "$FOLDER_HTTP_CODE" != "200" ]]; then
      cat "$FOLDER_RESPONSE_FILE" >&2 || true
      die "SharePoint folder does not exist or is inaccessible: $SP_FOLDER_PATH (HTTP $FOLDER_HTTP_CODE). Create it in the '$SP_LIBRARY_NAME' library first."
    fi
    python3 - "$FOLDER_RESPONSE_FILE" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as fh:
    item = json.load(fh)
if not item.get("folder"):
    raise SystemExit("The configured SharePoint path exists but is not a folder.")
PY
  fi

  log "Uploading stable CSV files to SharePoint..."
  upload_file_graph "$LATEST_CSV" "$STABLE_CSV_NAME"
  upload_file_graph "$SUMMARY_CSV" "$STABLE_SUMMARY_NAME"

  if [[ "$UPLOAD_ARCHIVE_TO_SHAREPOINT" == "true" ]]; then
    [[ -f "$ARCHIVE_CSV" ]] || die "Archive upload requested but detail archive is missing: $ARCHIVE_CSV"
    [[ -f "$ARCHIVE_SUMMARY" ]] || die "Archive upload requested but summary archive is missing: $ARCHIVE_SUMMARY"
    upload_file_graph "$ARCHIVE_CSV" "$(basename "$ARCHIVE_CSV")"
    upload_file_graph "$ARCHIVE_SUMMARY" "$(basename "$ARCHIVE_SUMMARY")"
  fi
fi

DETAIL_ROWS="$(python3 -c 'import csv,sys; print(max(sum(1 for _ in csv.reader(open(sys.argv[1], encoding="utf-8-sig")))-1,0))' "$LATEST_CSV")"
SUMMARY_ROWS="$(python3 -c 'import csv,sys; print(max(sum(1 for _ in csv.reader(open(sys.argv[1], encoding="utf-8-sig")))-1,0))' "$SUMMARY_CSV")"

log "Completed successfully."
printf '\nOutput:\n'
printf '  Detail CSV:  %s (%s rows)\n' "$LATEST_CSV" "$DETAIL_ROWS"
printf '  Summary CSV: %s (%s rows)\n' "$SUMMARY_CSV" "$SUMMARY_ROWS"
printf '  Date window: %s through %s (end exclusive)\n' "$START_TIME" "$END_TIME"
