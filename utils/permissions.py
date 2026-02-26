"""
Policy-Based Access Control (PBAC) Engine
Smart Contract Permission Simulation

This module replaces ad-hoc role checks with a declarative policy engine
and maintains an append-only audit trail of all permission state changes.

Architecture:
    PolicyEngine          — evaluates access requests against registered policies
    PermissionAuditLog    — singleton append-only audit trail (also written to disk)
    Custom Exceptions     — PermissionDeniedError for typed error handling
"""

import json
import os
import threading
from datetime import datetime, timezone, timedelta
from typing import Optional


# ---------------------------------------------------------------------------
# Custom exceptions
# ---------------------------------------------------------------------------

class PermissionDeniedError(Exception):
    """Raised when an access request is denied by the policy engine."""
    def __init__(self, message: str, actor: str = "", resource: str = ""):
        self.actor    = actor
        self.resource = resource
        super().__init__(message)


# ---------------------------------------------------------------------------
# Permission Audit Log — append-only, thread-safe, file-backed
# ---------------------------------------------------------------------------

AUDIT_LOG_FILE = "permission_audit.jsonl"
_audit_lock    = threading.Lock()


class PermissionAuditLog:
    """
    Singleton-style append-only permission audit trail.

    Every policy evaluation that changes state (grant, revoke)
    AND every denied access attempt is recorded here.
    """
    _entries: list = []

    @classmethod
    def record(cls, *, actor: str, owner: str, action: str,
               resource_type: Optional[str], result: str,
               reason: str, policy_name: str,
               changed_by: str = "system") -> dict:
        entry = {
            "timestamp":   datetime.now(timezone.utc).isoformat(),
            "actor":       actor,
            "owner":       owner,
            "action":      action,
            "resource_type": resource_type or "ALL",
            "result":      result,          # "GRANTED" | "DENIED" | "REVOKED"
            "reason":      reason,
            "policy_name": policy_name,
            "changed_by":  changed_by,
        }
        with _audit_lock:
            cls._entries.append(entry)
            cls._persist(entry)
        return entry

    @classmethod
    def get_entries(cls, limit: int = 50, actor: str = None,
                    owner: str = None) -> list:
        with _audit_lock:
            entries = list(cls._entries)
        if actor:
            entries = [e for e in entries if e["actor"] == actor]
        if owner:
            entries = [e for e in entries if e["owner"] == owner]
        return entries[-limit:]

    @classmethod
    def load_from_disk(cls):
        if not os.path.exists(AUDIT_LOG_FILE):
            return
        with _audit_lock:
            with open(AUDIT_LOG_FILE, "r") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            cls._entries.append(json.loads(line))
                        except json.JSONDecodeError:
                            pass

    @staticmethod
    def _persist(entry: dict):
        try:
            with open(AUDIT_LOG_FILE, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception:
            pass   # Never let audit fail silently break the app


# ---------------------------------------------------------------------------
# Individual policy definitions
# ---------------------------------------------------------------------------

class AdminPolicy:
    name = "AdminPolicy"

    @staticmethod
    def evaluate(actor_role: str, actor_username: str,
                 owner_id: str, resource_type: Optional[str], action: str) -> dict:
        if actor_role == "admin":
            return {"allowed": True, "reason": "Admin has unrestricted access",
                    "policy": AdminPolicy.name}
        return {"allowed": False, "reason": "Actor is not an admin",
                "policy": AdminPolicy.name}


class OwnerPolicy:
    name = "OwnerPolicy"

    @staticmethod
    def evaluate(actor_role: str, actor_student_id: Optional[str],
                 owner_id: str, resource_type: Optional[str], action: str) -> dict:
        if actor_role == "student" and actor_student_id == owner_id:
            return {"allowed": True, "reason": "Record owner has full access",
                    "policy": OwnerPolicy.name}
        return {"allowed": False, "reason": "Actor is not the record owner",
                "policy": OwnerPolicy.name}


class VerifierDelegatedPolicy:
    name = "VerifierDelegatedPolicy"

    @staticmethod
    def evaluate(actor_role: str, actor_username: str,
                 owner_id: str, resource_type: Optional[str],
                 db_check_fn) -> dict:
        """
        Verifier access requires an explicit delegation record in the database.
        db_check_fn(owner_id, verifier_username, resource_type) → bool
        """
        if actor_role != "verifier":
            return {"allowed": False, "reason": "Actor is not a verifier",
                    "policy": VerifierDelegatedPolicy.name}

        granted = db_check_fn(owner_id, actor_username, resource_type)
        if granted:
            return {"allowed": True,
                    "reason": f"Explicit delegation from owner '{owner_id}' verified",
                    "policy": VerifierDelegatedPolicy.name}

        return {
            "allowed": False,
            "reason":  f"No active delegation from owner '{owner_id}' for verifier '{actor_username}'",
            "policy":  VerifierDelegatedPolicy.name,
        }


# ---------------------------------------------------------------------------
# PolicyEngine — orchestrates policy evaluation
# ---------------------------------------------------------------------------

class PolicyEngine:
    """
    Evaluates an access request by running it through the registered policy chain.
    The first matching ALLOW or terminal DENY wins.

    Usage:
        engine = PolicyEngine(db_check_fn=db.check_access_permission)
        result = engine.check(actor, owner_id, resource_type, action)
        if not result["allowed"]:
            raise PermissionDeniedError(result["reason"], ...)
    """

    def __init__(self, db_check_fn=None):
        self._db_check = db_check_fn or (lambda *a: False)

    def check(self, *,
              actor_role: str,
              actor_username: str,
              actor_student_id: Optional[str],
              owner_id: str,
              resource_type: Optional[str],
              action: str,
              record_audit: bool = True) -> dict:
        """
        Run policy chain and return result dict:
            {"allowed": bool, "reason": str, "policy_name": str}
        """

        # 1. Admin policy
        r = AdminPolicy.evaluate(actor_role, actor_username, owner_id, resource_type, action)
        if r["allowed"]:
            if record_audit:
                PermissionAuditLog.record(
                    actor=actor_username, owner=owner_id, action=action,
                    resource_type=resource_type, result="GRANTED",
                    reason=r["reason"], policy_name=r["policy"],
                )
            return {"allowed": True, "reason": r["reason"], "policy_name": r["policy"]}

        # 2. Owner policy
        r = OwnerPolicy.evaluate(actor_role, actor_student_id, owner_id, resource_type, action)
        if r["allowed"]:
            if record_audit:
                PermissionAuditLog.record(
                    actor=actor_username, owner=owner_id, action=action,
                    resource_type=resource_type, result="GRANTED",
                    reason=r["reason"], policy_name=r["policy"],
                )
            return {"allowed": True, "reason": r["reason"], "policy_name": r["policy"]}

        # 3. Verifier delegated policy
        r = VerifierDelegatedPolicy.evaluate(
            actor_role, actor_username, owner_id, resource_type, self._db_check
        )
        result_str = "GRANTED" if r["allowed"] else "DENIED"
        if record_audit:
            PermissionAuditLog.record(
                actor=actor_username, owner=owner_id, action=action,
                resource_type=resource_type, result=result_str,
                reason=r["reason"], policy_name=r["policy"],
            )
        return {"allowed": r["allowed"], "reason": r["reason"], "policy_name": r["policy"]}

    def grant(self, *, granting_student_id: str, granting_username: str,
              verifier_username: str, resource_type: Optional[str],
              expires_at, db_grant_fn) -> bool:
        """
        Delegate access to a verifier and record it in the audit log.
        db_grant_fn(student_id, verifier_username, resource_type, expires_at)
        """
        try:
            db_grant_fn(granting_student_id, verifier_username, resource_type, expires_at)
            PermissionAuditLog.record(
                actor=granting_username, owner=granting_student_id,
                action="GRANT_ACCESS",
                resource_type=resource_type, result="GRANTED",
                reason=f"Verifier '{verifier_username}' granted explicit delegation",
                policy_name="OwnerGrantPolicy",
                changed_by=granting_username,
            )
            return True
        except Exception as exc:
            PermissionAuditLog.record(
                actor=granting_username, owner=granting_student_id,
                action="GRANT_ACCESS",
                resource_type=resource_type, result="DENIED",
                reason=f"Grant failed: {exc}",
                policy_name="OwnerGrantPolicy",
                changed_by=granting_username,
            )
            return False

    def revoke(self, *, revoking_student_id: str, revoking_username: str,
               verifier_username: str, resource_type: Optional[str],
               db_revoke_fn) -> bool:
        """
        Revoke a verifier's delegation and record in audit log.
        db_revoke_fn(student_id, verifier_username, resource_type)
        """
        try:
            db_revoke_fn(revoking_student_id, verifier_username, resource_type)
            PermissionAuditLog.record(
                actor=revoking_username, owner=revoking_student_id,
                action="REVOKE_ACCESS",
                resource_type=resource_type, result="REVOKED",
                reason=f"Verifier '{verifier_username}' delegation revoked by owner",
                policy_name="OwnerRevokePolicy",
                changed_by=revoking_username,
            )
            return True
        except Exception as exc:
            PermissionAuditLog.record(
                actor=revoking_username, owner=revoking_student_id,
                action="REVOKE_ACCESS",
                resource_type=resource_type, result="DENIED",
                reason=f"Revoke failed: {exc}",
                policy_name="OwnerRevokePolicy",
                changed_by=revoking_username,
            )
            return False


# Initialise: load historical audit entries on import
PermissionAuditLog.load_from_disk()
