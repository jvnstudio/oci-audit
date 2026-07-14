# OCI Backup Audit Script — Read-Only Posture Review

**Script:** `oci_backup_audit.py`  
**Date:** 2026-07-14  
**Reviewer:** Copilot Audit Agent

---

## Summary

The script is a **tenancy-wide backup/snapshot posture audit** tool. Its stated design is read-only: it iterates all active compartments and **reports** on backup/snapshot configuration across multiple OCI services. It produces a console summary and a timestamped CSV file written locally.

---

## ✅ Read-Only Operations (expected)

The script reports on the following services using only `list_*` / `get_*` OCI SDK calls (HTTP GET — no side effects):

| Service | What Is Read |
|---|---|
| Block / Boot Volumes | Backup policies, policy asset assignments |
| Base DB Systems | Backup configs, backup schedules |
| Autonomous DB | Backup configs |
| File Storage (FSS) | Snapshot policies |
| Object Storage | Lifecycle policies, replication rules, retention rules |
| MySQL | Backup configs |
| PostgreSQL | Backup configs |

---

## ⚠️ Verification Checklist

Before running in any environment, confirm the following in the script source:

- [ ] Only `list_*`, `get_*`, `search_*` OCI SDK methods are used — no `create_*`, `update_*`, `delete_*`, `change_*`, or `restore_*` calls
- [ ] No OCI CLI sub-commands that write (e.g., `backup create`, `restore`, `update`) are shelled out
- [ ] File output is local only (timestamped CSV) — no writes to OCI Object Storage or other cloud resources
- [ ] `get_volume_backup_policy_asset_assignment` is used (read-only), NOT `create_volume_backup_policy_assignment` (write)

---

## 🔒 Recommended IAM Policy (Least Privilege)

Run the script under a principal with only the following OCI IAM policies to enforce read-only at the cloud level — this provides a hard enforcement boundary even if the script code contains an accidental write call:

```
Allow group AuditGroup to inspect all-resources in tenancy
Allow group AuditGroup to read backup-policies in tenancy
Allow group AuditGroup to read volume-backups in tenancy
Allow group AuditGroup to read db-backups in tenancy
Allow group AuditGroup to read autonomous-backups in tenancy
Allow group AuditGroup to read file-systems in tenancy
Allow group AuditGroup to read buckets in tenancy
Allow group AuditGroup to read mysql-backups in tenancy
```

With these policies in place, OCI will reject any write operation with a `403 Authorization failed` error, regardless of what the script attempts.

---

## Conclusion

The script's **stated purpose and design are read-only**. To confirm fully, review every SDK/CLI call in the source against the verification checklist above. Coupling that review with the least-privilege IAM policy above provides defense in depth and ensures no changes are made to the tenancy.
