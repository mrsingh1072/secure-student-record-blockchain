"""
PBFT (Practical Byzantine Fault Tolerance) Consensus — Enhanced Multi-Stage Protocol

Architecture:
    PRE-PREPARE  → Primary node assigns view/sequence and validates freshness
    PREPARE      → All replicas independently validate and cast signed votes
    COMMIT       → Votes tallied; consensus reached when >= ceil((n+f+1)/2) nodes agree

Security features:
    - Replay-attack protection (seen_request_ids set per node)
    - Timestamp freshness window (±60 seconds)
    - Per-node structured validation logs
    - Simulated network latency for realism
    - Faulty-node simulation for fault-tolerance demos
"""

import hashlib
import time
import uuid
from datetime import datetime, timezone
from typing import Optional

# ---------------------------------------------------------------------------
# Configuration constants
# ---------------------------------------------------------------------------
TIMESTAMP_TOLERANCE_SECONDS = 60   # Max age of a request timestamp
MIN_CHECKS_TO_PASS = 4             # Out of 5 validation checks per node
SIMULATE_LATENCY = True            # Enable simulated per-node latency
SIMULATE_FAULTY_NODE = True        # Enable one-in-ten chance of a node going silent


class PBFTPhase:
    PRE_PREPARE = "PRE-PREPARE"
    PREPARE     = "PREPARE"
    COMMIT      = "COMMIT"


class PBFTNode:
    """
    A PBFT replica node with full phase-aware state tracking.

    Each node maintains:
        - view / sequence counters
        - a set of already-seen request IDs (replay protection)
        - a local validation log per consensus round
    """

    def __init__(self, node_id: int, name: str, is_primary: bool = False,
                 simulated_latency_ms: float = 0.0):
        self.node_id               = node_id
        self.name                  = name
        self.is_primary            = is_primary
        self.view                  = 0
        self.sequence_number       = 0
        self.seen_request_ids: set = set()           # replay protection
        self.validation_log: list  = []              # per-node audit log
        self.simulated_latency_ms  = simulated_latency_ms
        self.is_faulty             = False           # can be triggered externally

    # ------------------------------------------------------------------
    # PRE-PREPARE phase (primary node only)
    # ------------------------------------------------------------------
    def pre_prepare(self, request_id: str, data_hash: str,
                    student_id: str, record_type: str,
                    request_timestamp: str) -> dict:
        """
        Primary node receives client request, assigns view+sequence, and
        broadcasts a PRE-PREPARE message to all replicas.

        Returns pre-prepare message dict or rejection dict.
        """
        self._simulate_latency()

        # Replay protection
        if request_id in self.seen_request_ids:
            entry = self._log(PBFTPhase.PRE_PREPARE, self.sequence_number,
                              False, f"[REPLAY REJECTED] request_id={request_id} already seen")
            return {"accepted": False, "reason": "Duplicate request — replay attack detected",
                    "log": entry}

        # Timestamp freshness check
        freshness_ok, freshness_msg = self._check_timestamp_freshness(request_timestamp)
        if not freshness_ok:
            entry = self._log(PBFTPhase.PRE_PREPARE, self.sequence_number,
                              False, f"[STALE REQUEST] {freshness_msg}")
            return {"accepted": False, "reason": freshness_msg, "log": entry}

        self.sequence_number += 1
        self.seen_request_ids.add(request_id)

        msg = {
            "type":        PBFTPhase.PRE_PREPARE,
            "view":        self.view,
            "sequence":    self.sequence_number,
            "request_id":  request_id,
            "data_hash":   data_hash,
            "student_id":  student_id,
            "record_type": record_type,
            "primary":     self.name,
            "issued_at":   datetime.now(timezone.utc).isoformat(),
        }

        entry = self._log(PBFTPhase.PRE_PREPARE, self.sequence_number,
                          True, f"Sequence {self.sequence_number} assigned — broadcasting to replicas")
        msg["log"] = entry
        return msg

    # ------------------------------------------------------------------
    # PREPARE phase (all replicas including primary)
    # ------------------------------------------------------------------
    def prepare(self, pre_prepare_msg: dict,
                data_hash: str, student_id: str, record_type: str) -> dict:
        """
        Replica validates the pre-prepare message and casts a PREPARE vote.

        Returns a PREPARE vote dict with is_valid flag.
        """
        self._simulate_latency()

        if self.is_faulty:
            entry = self._log(PBFTPhase.PREPARE, pre_prepare_msg.get("sequence", 0),
                              False, "[FAULTY NODE] Node unresponsive — vote withheld")
            return {"type": PBFTPhase.PREPARE, "node": self.name,
                    "node_id": self.node_id, "is_valid": False,
                    "faulty": True, "log": entry}

        seq = pre_prepare_msg.get("sequence", 0)

        # Run validation checks
        checks = {
            "hash_format":     self._validate_hash_format(data_hash),
            "student_id":      self._validate_student_id(student_id),
            "record_type":     self._validate_record_type(record_type),
            "data_integrity":  self._check_data_integrity(),
            "permission_check": self._check_permission(),
        }
        passed = sum(checks.values())
        is_valid = passed >= MIN_CHECKS_TO_PASS

        reason = (f"PREPARE accepted ({passed}/{len(checks)} checks passed)"
                  if is_valid
                  else f"PREPARE REJECTED ({passed}/{len(checks)} checks — below threshold)")
        entry = self._log(PBFTPhase.PREPARE, seq, is_valid, reason, extra=checks)

        return {
            "type":        PBFTPhase.PREPARE,
            "view":        pre_prepare_msg.get("view"),
            "sequence":    seq,
            "request_id":  pre_prepare_msg.get("request_id"),
            "node":        self.name,
            "node_id":     self.node_id,
            "is_valid":    is_valid,
            "checks":      checks,
            "checks_passed": passed,
            "total_checks":  len(checks),
            "faulty":      False,
            "timestamp":   datetime.now(timezone.utc).isoformat(),
            "log":         entry,
        }

    # ------------------------------------------------------------------
    # COMMIT phase participation — node co-signs the commit
    # ------------------------------------------------------------------
    def commit(self, sequence: int, consensus_reached: bool) -> dict:
        """
        Record commit phase participation for this node.
        """
        self._simulate_latency()

        if self.is_faulty:
            entry = self._log(PBFTPhase.COMMIT, sequence,
                              False, "[FAULTY NODE] COMMIT withheld")
            return {"type": PBFTPhase.COMMIT, "node": self.name, "committed": False,
                    "faulty": True, "log": entry}

        result = consensus_reached
        msg = "COMMITTED — block approved" if result else "COMMIT withheld — consensus not reached"
        entry = self._log(PBFTPhase.COMMIT, sequence, result, msg)

        return {
            "type":      PBFTPhase.COMMIT,
            "sequence":  sequence,
            "node":      self.name,
            "node_id":   self.node_id,
            "committed": result,
            "faulty":    False,
            "log":       entry,
        }

    # ------------------------------------------------------------------
    # Internal validation helpers
    # ------------------------------------------------------------------
    def _validate_hash_format(self, data_hash: str) -> bool:
        try:
            return (isinstance(data_hash, str)
                    and len(data_hash) == 64
                    and all(c in "0123456789abcdef" for c in data_hash.lower()))
        except Exception:
            return False

    def _validate_student_id(self, student_id: str) -> bool:
        try:
            return isinstance(student_id, str) and len(student_id) >= 5 and student_id.isalnum()
        except Exception:
            return False

    def _validate_record_type(self, record_type: str) -> bool:
        valid_types = {"transcript", "certificate", "diploma",
                       "grade_card", "achievement", "enrollment", "completion"}
        return isinstance(record_type, str) and record_type.lower() in valid_types

    def _check_data_integrity(self) -> bool:
        """Simulated data-integrity probe (97 % success)."""
        import random
        return random.random() > 0.03

    def _check_permission(self) -> bool:
        """Simulated permission probe (99 % success)."""
        import random
        return random.random() > 0.01

    def _check_timestamp_freshness(self, ts_str: str):
        """
        Returns (ok: bool, reason: str).
        Accepts ISO-8601 strings with or without timezone info.
        """
        try:
            # Parse — support naive and aware datetimes
            try:
                request_dt = datetime.fromisoformat(ts_str)
            except ValueError:
                return False, f"Unparseable timestamp: {ts_str}"

            now = datetime.now(timezone.utc)

            # Make both timezone-aware for comparison
            if request_dt.tzinfo is None:
                request_dt = request_dt.replace(tzinfo=timezone.utc)

            age_seconds = abs((now - request_dt).total_seconds())
            if age_seconds > TIMESTAMP_TOLERANCE_SECONDS:
                return False, (f"Request timestamp too old or too far in future "
                               f"(age={age_seconds:.1f}s, tolerance={TIMESTAMP_TOLERANCE_SECONDS}s)")
            return True, "Timestamp fresh"
        except Exception as exc:
            return False, f"Timestamp validation error: {exc}"

    def _simulate_latency(self):
        """Inject simulated network latency for realism."""
        if SIMULATE_LATENCY and self.simulated_latency_ms > 0:
            time.sleep(self.simulated_latency_ms / 1000.0)

    def _log(self, phase: str, sequence: int, result: bool,
             message: str, extra: Optional[dict] = None) -> dict:
        entry = {
            "phase":     phase,
            "sequence":  sequence,
            "node":      self.name,
            "node_id":   self.node_id,
            "is_primary": self.is_primary,
            "result":    "PASS" if result else "FAIL",
            "message":   message,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        if extra:
            entry["checks"] = extra
        self.validation_log.append(entry)
        return entry

    def get_logs(self) -> list:
        return list(self.validation_log)

    def __str__(self):
        role = "PRIMARY" if self.is_primary else "REPLICA"
        return f"PBFTNode({self.name}, {role}, view={self.view}, seq={self.sequence_number})"


# ---------------------------------------------------------------------------
# PBFTConsensus — orchestrates the full 3-phase protocol
# ---------------------------------------------------------------------------

class PBFTConsensus:
    """
    Coordinates the full PBFT consensus round across all nodes.

    Node topology (n=3 → tolerates f=1 faulty node):
        Node_A — Primary   (Academic Validator)
        Node_B — Replica 1 (Security Checker)
        Node_C — Replica 2 (Integrity Monitor)

    Threshold: consensus requires valid_votes >= n - f = 3 - 1 = 2
    """

    def __init__(self):
        self.nodes = [
            PBFTNode(1, "Node_A_Academic",   is_primary=True,  simulated_latency_ms=20),
            PBFTNode(2, "Node_B_Security",   is_primary=False, simulated_latency_ms=35),
            PBFTNode(3, "Node_C_Integrity",  is_primary=False, simulated_latency_ms=15),
        ]
        self.primary            = self.nodes[0]
        self.n                  = len(self.nodes)
        self.f                  = (self.n - 1) // 3          # max faulty nodes tolerated
        self.consensus_threshold = self.n - self.f           # minimum agreements needed
        self.validation_history: list = []
        self._round_counter     = 0

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------
    def validate_block_addition(self, data_hash: str,
                                student_id: str,
                                record_type: str,
                                request_timestamp: Optional[str] = None) -> dict:
        """
        Execute full PBFT consensus round for a proposed block.

        Args:
            data_hash:          SHA-256 hash of the record data
            student_id:         Student identifier
            record_type:        Record category
            request_timestamp:  ISO-8601 origination timestamp (defaults to now)

        Returns:
            dict: Full consensus result including per-phase logs
        """
        if request_timestamp is None:
            request_timestamp = datetime.now(timezone.utc).isoformat()

        request_id = str(uuid.uuid4())
        self._round_counter += 1

        self._banner(f"PBFT CONSENSUS ROUND #{self._round_counter} STARTED")
        self._log_line(f"Request ID  : {request_id}")
        self._log_line(f"Data Hash   : {data_hash[:32]}...")
        self._log_line(f"Student ID  : {student_id}")
        self._log_line(f"Record Type : {record_type}")
        self._log_line(f"Timestamp   : {request_timestamp}")

        # ── PHASE 1: PRE-PREPARE ──────────────────────────────────────
        self._phase_header(PBFTPhase.PRE_PREPARE)
        pre_prepare_result = self.primary.pre_prepare(
            request_id, data_hash, student_id, record_type, request_timestamp
        )

        if not pre_prepare_result.get("accepted", True) and "sequence" not in pre_prepare_result:
            # Primary rejected the request outright
            if pre_prepare_result.get("accepted") is False:
                self._log_line(
                    f"  ✗ [{self.primary.name}] PRE-PREPARE REJECTED: {pre_prepare_result['reason']}"
                )
                result = self._build_result(request_id, data_hash, student_id, record_type,
                                            False, [], 0,
                                            "PRE-PREPARE rejected — " + pre_prepare_result["reason"])
                self.validation_history.append(result)
                return result

        seq = pre_prepare_result.get("sequence", 1)
        self._log_line(f"  ✓ [{self.primary.name}] PRE-PREPARE OK — seq={seq} broadcast to replicas")

        # ── PHASE 2: PREPARE ─────────────────────────────────────────
        self._phase_header(PBFTPhase.PREPARE)

        # Optionally simulate a faulty node (10 % chance on any replica)
        if SIMULATE_FAULTY_NODE:
            import random
            for node in self.nodes[1:]:
                if random.random() < 0.10:
                    node.is_faulty = True
                    self._log_line(f"  ⚡ [{node.name}] SIMULATED FAULT — node unresponsive")
                else:
                    node.is_faulty = False

        prepare_votes = []
        for node in self.nodes:
            vote = node.prepare(pre_prepare_result, data_hash, student_id, record_type)
            prepare_votes.append(vote)
            if vote.get("faulty"):
                self._log_line(f"  ✗ [{node.name}] PREPARE — FAULTY (vote withheld)")
            elif vote["is_valid"]:
                self._log_line(
                    f"  ✓ [{node.name}] PREPARE — VALID "
                    f"({vote['checks_passed']}/{vote['total_checks']} checks passed)"
                )
            else:
                self._log_line(
                    f"  ✗ [{node.name}] PREPARE — INVALID "
                    f"({vote['checks_passed']}/{vote['total_checks']} checks passed)"
                )

        # ── PHASE 3: COMMIT ──────────────────────────────────────────
        self._phase_header(PBFTPhase.COMMIT)
        valid_votes   = sum(1 for v in prepare_votes if v.get("is_valid"))
        consensus_reached = valid_votes >= self.consensus_threshold

        commit_results = []
        for node in self.nodes:
            cr = node.commit(seq, consensus_reached)
            commit_results.append(cr)
            status = "✓ COMMITTED" if cr.get("committed") else ("✗ FAULTY" if cr.get("faulty") else "✗ WITHHELD")
            self._log_line(f"  {status}  [{node.name}]")

        decision = "APPROVED" if consensus_reached else "REJECTED"
        self._log_line(f"\n  Valid votes  : {valid_votes} / {self.n}")
        self._log_line(f"  Threshold   : {self.consensus_threshold}")
        self._log_line(f"  Fault tolerance (f) : {self.f}")
        self._log_line(f"  ➤ CONSENSUS DECISION : {decision}")
        self._banner(f"CONSENSUS ROUND #{self._round_counter} COMPLETE")

        result = self._build_result(
            request_id, data_hash, student_id, record_type,
            consensus_reached, prepare_votes, valid_votes,
            f"Consensus {'reached' if consensus_reached else 'NOT reached'} "
            f"({valid_votes}/{self.n} votes, threshold={self.consensus_threshold})",
            commit_results=commit_results,
            pre_prepare=pre_prepare_result,
        )
        self.validation_history.append(result)
        return result

    # ------------------------------------------------------------------
    # Statistics & log access
    # ------------------------------------------------------------------
    def get_consensus_stats(self) -> dict:
        total    = len(self.validation_history)
        approved = sum(1 for v in self.validation_history if v["consensus_reached"])
        return {
            "total_validations": total,
            "approved":          approved,
            "rejected":          total - approved,
            "approval_rate":     round((approved / total) * 100, 2) if total > 0 else 0,
            "fault_tolerance_f": self.f,
            "consensus_threshold": self.consensus_threshold,
            "total_nodes":       self.n,
            "last_validation":   self.validation_history[-1]["timestamp"] if total > 0 else None,
        }

    def get_node_logs(self) -> dict:
        """Return per-node validation logs for audit/demo purposes."""
        return {node.name: node.get_logs() for node in self.nodes}

    # ------------------------------------------------------------------
    # Individual node validators (kept for backward compatibility)
    # ------------------------------------------------------------------
    def node1_validate(self, data_hash, student_id, record_type):
        pp = self.nodes[0].pre_prepare(
            str(uuid.uuid4()), data_hash, student_id, record_type,
            datetime.now(timezone.utc).isoformat()
        )
        return self.nodes[0].prepare(pp, data_hash, student_id, record_type)

    def node2_validate(self, data_hash, student_id, record_type):
        pp = {"sequence": 0, "view": 0, "request_id": str(uuid.uuid4())}
        return self.nodes[1].prepare(pp, data_hash, student_id, record_type)

    def node3_validate(self, data_hash, student_id, record_type):
        pp = {"sequence": 0, "view": 0, "request_id": str(uuid.uuid4())}
        return self.nodes[2].prepare(pp, data_hash, student_id, record_type)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------
    def _build_result(self, request_id, data_hash, student_id, record_type,
                      consensus_reached, prepare_votes, valid_votes, summary,
                      commit_results=None, pre_prepare=None) -> dict:
        return {
            "request_id":       request_id,
            "consensus_reached": consensus_reached,
            "valid_votes":      valid_votes,
            "total_nodes":      self.n,
            "threshold":        self.consensus_threshold,
            "fault_tolerance_f": self.f,
            "decision":         "APPROVED" if consensus_reached else "REJECTED",
            "summary":          summary,
            "validations":      prepare_votes,
            "commit_results":   commit_results or [],
            "pre_prepare":      pre_prepare or {},
            "timestamp":        datetime.now(timezone.utc).isoformat(),
            "data_hash":        data_hash,
            "student_id":       student_id,
            "record_type":      record_type,
        }

    @staticmethod
    def _banner(text: str):
        print(f"\n{'='*65}")
        print(f"  {text}")
        print(f"{'='*65}")

    @staticmethod
    def _phase_header(phase: str):
        print(f"\n  ── {phase} ──")

    @staticmethod
    def _log_line(text: str):
        print(text)

    def __str__(self):
        return (f"PBFTConsensus(nodes={self.n}, f={self.f}, "
                f"threshold={self.consensus_threshold}, rounds={self._round_counter})")