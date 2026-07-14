#!/usr/bin/env python3
"""
oci_backup_audit.py

Tenancy-wide backup / snapshot posture audit for OCI.
Designed to run in OCI Cloud Shell (uses the pre-configured CLI auth token).

Iterates all active compartments (subtree) and reports, per service:
  - Whether backups/snapshots are configured
  - The frequency / schedule (from the policy objects, not just backup lists)
  - Retention

Services covered:
  Block/Boot Volumes, Base DB Systems, Autonomous DB, File Storage (FSS),
  Object Storage (replication + lifecycle + retention), MySQL, PostgreSQL.

Output: console summary + timestamped CSV in the current dir.

Usage (in Cloud Shell):
    python3 oci_backup_audit.py                 # all compartments, all services
    python3 oci_backup_audit.py -c <ocid>       # single compartment (no subtree)
    python3 oci_backup_audit.py -s volumes db   # only selected services
    python3 oci_backup_audit.py --region us-langley-1   # override region

Auth: uses Cloud Shell delegation token by default. Falls back to config file
with --profile if run outside Cloud Shell.
"""

import argparse
import csv
import datetime
import os
import sys

try:
    import oci
except ImportError:
    sys.exit("ERROR: oci SDK not found. In Cloud Shell it's preinstalled; "
             "otherwise run: pip install oci")


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------
def get_config_and_signer(profile, region_override):
    """
    Prefer Cloud Shell delegation token. Fall back to ~/.oci/config profile.
    Returns (config_dict, signer_or_None).
    """
    delegation_path = os.environ.get("OCI_DELEGATION_TOKEN_FILE")
    if delegation_path and os.path.exists(delegation_path):
        with open(delegation_path) as f:
            token = f.read()
        # Tenancy comes from the instance principal env in Cloud Shell
        signer = oci.auth.signers.InstancePrincipalsDelegationTokenSigner(
            delegation_token=token
        )
        config = {"region": region_override or signer.region}
        # region may not be on signer in all SDK versions; fall back to env
        if not config["region"]:
            config["region"] = os.environ.get("OCI_REGION") or os.environ.get(
                "OCI_CLI_REGION", ""
            )
        return config, signer

    # Fallback: config file
    config = oci.config.from_file(profile_name=profile)
    if region_override:
        config["region"] = region_override
    return config, None


def client(klass, config, signer):
    if signer:
        return klass(config, signer=signer)
    return klass(config)


def tenancy_id(config, signer):
    if signer and getattr(signer, "tenancy_id", None):
        return signer.tenancy_id
    return config.get("tenancy") or os.environ.get("OCI_TENANCY")


# ---------------------------------------------------------------------------
# Compartments
# ---------------------------------------------------------------------------
def list_compartments(identity, root, subtree=True):
    comps = [root]  # include root/tenancy itself
    if not subtree:
        return comps
    try:
        resp = oci.pagination.list_call_get_all_results(
            identity.list_compartments,
            root,
            compartment_id_in_subtree=True,
            lifecycle_state="ACTIVE",
            access_level="ACCESSIBLE",
        )
        comps.extend([c.id for c in resp.data])
    except oci.exceptions.ServiceError as e:
        if e.status in (401, 403):
            print(f"  ! could not list compartments: authorization error – ensure the "
                  f"principal has 'inspect compartments' on the root compartment. "
                  f"({e.message})")
        else:
            print(f"  ! could not list compartments: {e.message}")
    return comps


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def safe(fn, *a, **k):
    """Call an SDK list/get and swallow auth/404/region errors gracefully."""
    try:
        return fn(*a, **k)
    except oci.exceptions.ServiceError as e:
        if e.status in (401, 403, 404):
            return None
        # 409/400 etc — surface once, keep going
        return None
    except Exception:
        return None


def add(rows, comp, service, resource, backup_configured, frequency, retention, detail=""):
    rows.append(
        {
            "compartment_id": comp,
            "service": service,
            "resource": resource,
            "backup_configured": backup_configured,
            "frequency_schedule": frequency,
            "retention": retention,
            "detail": detail,
        }
    )


# ---------------------------------------------------------------------------
# Service checks
# ---------------------------------------------------------------------------
def check_volumes(rows, comp, config, signer):
    bs = client(oci.core.BlockstorageClient, config, signer)

    # Backup policies (schedules) defined in this compartment
    pols = safe(bs.list_volume_backup_policies, compartment_id=comp)
    policy_sched = {}
    if pols and pols.data:
        for p in pols.data:
            scheds = []
            for s in (p.schedules or []):
                scheds.append(f"{s.period}/backup-type={s.backup_type}/retention={s.retention_seconds}s")
            policy_sched[p.id] = "; ".join(scheds) if scheds else "no-schedules"

    # Volumes and their policy assignment
    r = safe(oci.pagination.list_call_get_all_results, bs.list_volumes, compartment_id=comp)
    if r and r.data:
        for v in r.data:
            asg = safe(bs.get_volume_backup_policy_asset_assignment, asset_id=v.id)
            if asg and asg.data:
                pid = asg.data[0].policy_id
                freq = policy_sched.get(pid, "assigned-policy(external/default)")
                add(rows, comp, "BlockVolume", v.display_name, "YES", freq, "see-schedule", pid)
            else:
                add(rows, comp, "BlockVolume", v.display_name, "NO", "none", "none")

    # Boot volumes need AD; iterate ADs
    idc = client(oci.identity.IdentityClient, config, signer)
    tid = tenancy_id(config, signer)
    ads = safe(idc.list_availability_domains, compartment_id=tid)
    if ads and ads.data:
        for ad in ads.data:
            bv = safe(oci.pagination.list_call_get_all_results,
                      bs.list_boot_volumes, availability_domain=ad.name, compartment_id=comp)
            if bv and bv.data:
                for v in bv.data:
                    asg = safe(bs.get_volume_backup_policy_asset_assignment, asset_id=v.id)
                    if asg and asg.data:
                        pid = asg.data[0].policy_id
                        freq = policy_sched.get(pid, "assigned-policy(external/default)")
                        add(rows, comp, "BootVolume", v.display_name, "YES", freq, "see-schedule", pid)
                    else:
                        add(rows, comp, "BootVolume", v.display_name, "NO", "none", "none")


def check_db(rows, comp, config, signer):
    db = client(oci.database.DatabaseClient, config, signer)

    # Base DB systems -> databases -> auto backup config
    systems = safe(oci.pagination.list_call_get_all_results, db.list_db_systems, compartment_id=comp)
    if systems and systems.data:
        for sysd in systems.data:
            dbs = safe(oci.pagination.list_call_get_all_results,
                       db.list_databases, compartment_id=comp, db_system_id=sysd.id)
            if dbs and dbs.data:
                for d in dbs.data:
                    cfg = getattr(d, "db_backup_config", None)
                    if cfg and cfg.auto_backup_enabled:
                        window = getattr(cfg, "auto_backup_window", "default")
                        ret = getattr(cfg, "recovery_window_in_days", "default")
                        add(rows, comp, "BaseDB", d.db_name, "YES",
                            f"daily-auto (window={window})", f"{ret}d", sysd.display_name)
                    else:
                        add(rows, comp, "BaseDB", d.db_name, "NO", "none", "none", sysd.display_name)

    # Autonomous DB
    adbs = safe(oci.pagination.list_call_get_all_results,
                db.list_autonomous_databases, compartment_id=comp)
    if adbs and adbs.data:
        for a in adbs.data:
            auto = getattr(a, "is_automatic_backup_enabled", None)
            ret = getattr(a, "backup_retention_period_in_days", "n/a")
            add(rows, comp, "AutonomousDB", a.db_name,
                "YES" if auto else "NO",
                "daily-auto" if auto else "none",
                f"{ret}d")


def check_fss(rows, comp, config, signer):
    idc = client(oci.identity.IdentityClient, config, signer)
    fss = client(oci.file_storage.FileStorageClient, config, signer)
    tid = tenancy_id(config, signer)

    # Snapshot policies (schedules)
    pols = safe(oci.pagination.list_call_get_all_results,
                fss.list_filesystem_snapshot_policies, compartment_id=comp)
    pol_map = {}
    if pols and pols.data:
        for p in pols.data:
            full = safe(fss.get_filesystem_snapshot_policy, filesystem_snapshot_policy_id=p.id)
            scheds = []
            if full and full.data and full.data.schedules:
                for s in full.data.schedules:
                    scheds.append(f"{s.period}(retention={s.retention_duration_in_seconds}s)")
            pol_map[p.id] = "; ".join(scheds) if scheds else "no-schedules"

    ads = safe(idc.list_availability_domains, compartment_id=tid)
    if not (ads and ads.data):
        return
    for ad in ads.data:
        fs = safe(oci.pagination.list_call_get_all_results,
                  fss.list_file_systems, compartment_id=comp, availability_domain=ad.name)
        if fs and fs.data:
            for f in fs.data:
                pid = getattr(f, "filesystem_snapshot_policy_id", None)
                if pid:
                    add(rows, comp, "FSS", f.display_name, "YES",
                        pol_map.get(pid, "assigned-policy"), "see-schedule", pid)
                else:
                    # manual snapshots may still exist
                    snaps = safe(oci.pagination.list_call_get_all_results,
                                 fss.list_snapshots, file_system_id=f.id)
                    n = len(snaps.data) if snaps and snaps.data else 0
                    add(rows, comp, "FSS", f.display_name,
                        "MANUAL" if n else "NO",
                        "manual-only" if n else "none",
                        f"{n} snapshots")


def check_object(rows, comp, config, signer):
    os_client = client(oci.object_storage.ObjectStorageClient, config, signer)
    ns = safe(os_client.get_namespace)
    if not ns:
        return
    namespace = ns.data
    buckets = safe(oci.pagination.list_call_get_all_results,
                   os_client.list_buckets, namespace_name=namespace, compartment_id=comp)
    if not (buckets and buckets.data):
        return
    for b in buckets.data:
        name = b.name
        # Replication
        repl = safe(os_client.list_replication_policies, namespace_name=namespace, bucket_name=name)
        has_repl = bool(repl and repl.data)
        # Lifecycle
        lc = safe(os_client.get_object_lifecycle_policy, namespace_name=namespace, bucket_name=name)
        has_lc = bool(lc and lc.data and lc.data.items)
        # Retention rules (WORM / immutability)
        rr = safe(os_client.list_retention_rules, namespace_name=namespace, bucket_name=name)
        has_rr = bool(rr and rr.data and rr.data.items)

        configured = "YES" if (has_repl or has_lc or has_rr) else "NO"
        parts = []
        if has_repl:
            parts.append("replication")
        if has_lc:
            parts.append("lifecycle")
        if has_rr:
            parts.append("retention/WORM")
        add(rows, comp, "ObjectStorage", name, configured,
            "event-driven (replication)" if has_repl else "n/a",
            "; ".join(parts) if parts else "none")


def check_mysql(rows, comp, config, signer):
    my = client(oci.mysql.DbSystemClient, config, signer)
    systems = safe(oci.pagination.list_call_get_all_results, my.list_db_systems, compartment_id=comp)
    if systems and systems.data:
        for s in systems.data:
            full = safe(my.get_db_system, db_system_id=s.id)
            if full and full.data:
                bp = getattr(full.data, "backup_policy", None)
                if bp and getattr(bp, "is_enabled", False):
                    window = getattr(bp, "window_start_time", "default")
                    ret = getattr(bp, "retention_in_days", "default")
                    add(rows, comp, "MySQL", s.display_name, "YES",
                        f"daily-auto (window={window})", f"{ret}d")
                else:
                    add(rows, comp, "MySQL", s.display_name, "NO", "none", "none")


def check_postgres(rows, comp, config, signer):
    try:
        pg = client(oci.psql.PostgresqlClient, config, signer)
    except Exception:
        return
    systems = safe(oci.pagination.list_call_get_all_results, pg.list_db_systems, compartment_id=comp)
    if systems and systems.data:
        for s in systems.data:
            full = safe(pg.get_db_system, db_system_id=s.id)
            bp = getattr(full.data, "backup_policy", None) if full and full.data else None
            if bp:
                kind = getattr(bp, "kind", "?")
                ret = getattr(bp, "retention_days", "default")
                add(rows, comp, "PostgreSQL", s.display_name, "YES",
                    f"{kind}", f"{ret}d")
            else:
                add(rows, comp, "PostgreSQL", s.display_name, "UNKNOWN", "check-console", "n/a")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
SERVICE_MAP = {
    "volumes": check_volumes,
    "db": check_db,
    "fss": check_fss,
    "object": check_object,
    "mysql": check_mysql,
    "postgres": check_postgres,
}


def main():
    ap = argparse.ArgumentParser(description="OCI tenancy-wide backup posture audit")
    ap.add_argument("-c", "--compartment", help="Single compartment OCID (disables subtree)")
    ap.add_argument("-s", "--services", nargs="+", choices=SERVICE_MAP.keys(),
                    help="Subset of services to check (default: all)")
    ap.add_argument("-p", "--profile", default="DEFAULT", help="Config profile if not in Cloud Shell")
    ap.add_argument("--region", help="Override region (e.g. us-langley-1, us-luke-1 for GovCloud)")
    ap.add_argument("--no-subtree", action="store_true", help="Do not recurse compartments")
    args = ap.parse_args()

    config, signer = get_config_and_signer(args.profile, args.region)
    identity = client(oci.identity.IdentityClient, config, signer)
    tid = tenancy_id(config, signer)
    if not tid:
        sys.exit("ERROR: could not determine tenancy OCID.")

    print(f"Region : {config.get('region')}")
    print(f"Tenancy: {tid}\n")

    if args.compartment:
        comps = [args.compartment]
    else:
        comps = list_compartments(identity, tid, subtree=not args.no_subtree)
    print(f"Auditing {len(comps)} compartment(s)...\n")

    services = args.services or list(SERVICE_MAP.keys())
    rows = []

    for i, comp in enumerate(comps, 1):
        print(f"[{i}/{len(comps)}] {comp}")
        for svc in services:
            try:
                SERVICE_MAP[svc](rows, comp, config, signer)
            except Exception as e:
                print(f"    ! {svc} error: {e}")

    # Output
    ts = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    outfile = f"oci_backup_audit_{ts}.csv"
    fields = ["compartment_id", "service", "resource", "backup_configured",
              "frequency_schedule", "retention", "detail"]
    with open(outfile, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)

    # Console summary
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    total = len(rows)
    unprotected = [r for r in rows if r["backup_configured"] in ("NO", "UNKNOWN")]
    print(f"Total resources evaluated : {total}")
    print(f"Without backup configured : {len(unprotected)}")
    if unprotected:
        print("\nUNPROTECTED / NEEDS REVIEW:")
        for r in unprotected:
            print(f"  [{r['service']:14}] {r['resource']:40} ({r['backup_configured']})")
    print(f"\nFull report written to: {outfile}")


if __name__ == "__main__":
    main()
