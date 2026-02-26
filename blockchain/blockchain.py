"""
Enhanced Blockchain — v2

New in this version:
  - add_block_safe(): validates chain integrity BEFORE each new block
  - is_chain_valid(): also verifies merkle_root and chain_id per block
  - detect_tamper(): forensic scan returning per-block discrepancy report
  - add_integrity_checkpoint(): stores cumulative SHA-256 every N blocks
  - Circuit breaker (_chain_locked): freezes all writes when tampering is detected
  - load_chain(): migrates legacy v1 blocks (no chain_id / merkle_root) transparently
"""

import hashlib
import json
import os
import time
from typing import Optional, List
from .block import Block, CHAIN_ID

CHECKPOINT_FILE    = "blockchain_checkpoints.json"
CHECKPOINT_EVERY_N = 10     # write a checkpoint after every 10th block


class BlockchainIntegrityError(Exception):
    """Raised when the chain has been tampered with or fails validation."""


class Blockchain:
    """
    Manages a linear chain of cryptographically-linked blocks.

    Key safety properties:
      (1) Every new block embeds the hash of its predecessor.
      (2) Every block header includes chain_id — foreign blocks are rejected.
      (3) The chain can be locked (circuit-breaker) on detected tampering.
      (4) Integrity checkpoints allow fast partial-verification.
    """

    def __init__(self, chain_file: str = "blockchain_data.json"):
        self.chain: List[Block] = []
        self.difficulty         = 4
        self.chain_file         = chain_file
        self._chain_locked      = False      # circuit-breaker flag

        if os.path.exists(self.chain_file):
            self.load_chain()
        else:
            self.create_genesis_block()

    # ------------------------------------------------------------------
    # Genesis
    # ------------------------------------------------------------------
    def create_genesis_block(self):
        genesis = Block(0, "Genesis Block — Secure Student Records", "0")
        genesis.mine_block(self.difficulty)
        self.chain.append(genesis)
        self.save_chain()
        print("✓ Genesis block created")

    # ------------------------------------------------------------------
    # Block addition
    # ------------------------------------------------------------------
    def add_block(self, data_hash: str) -> Block:
        """Legacy alias — calls add_block_safe internally."""
        return self.add_block_safe(data_hash)

    def add_block_safe(self, data_hash: str) -> Block:
        """
        Validates chain integrity BEFORE appending a new block.

        Raises:
            BlockchainIntegrityError: if the chain is locked or already tampered.
        """
        if self._chain_locked:
            raise BlockchainIntegrityError(
                "Chain is LOCKED due to detected tampering. "
                "No new blocks can be added until the integrity issue is resolved."
            )

        # Pre-flight integrity check
        if not self.is_chain_valid():
            self._chain_locked = True
            raise BlockchainIntegrityError(
                "Chain integrity check FAILED before block addition. "
                "Chain has been locked as a precaution."
            )

        previous_block = self.get_latest_block()
        new_index      = previous_block.index + 1
        new_block      = Block(new_index, data_hash, previous_block.hash)
        new_block.mine_block(self.difficulty)

        self.chain.append(new_block)
        self.save_chain()

        # Periodic checkpoint
        if new_index % CHECKPOINT_EVERY_N == 0:
            self.add_integrity_checkpoint()

        print(f"✓ Block #{new_index} added — hash={new_block.hash[:24]}...")
        return new_block

    # ------------------------------------------------------------------
    # Chain validation
    # ------------------------------------------------------------------
    def is_chain_valid(self) -> bool:
        """
        Full chain validation:
          (a) Each block's stored hash matches recomputed hash.
          (b) Each block's previous_hash links to the prior block's hash.
          (c) Each block's merkle_root is internally consistent.
          (d) chain_id is correct for every block (injection guard).
        """
        for i in range(1, len(self.chain)):
            curr = self.chain[i]
            prev = self.chain[i - 1]

            # (a) Hash consistency
            if curr.hash != curr.calculate_hash():
                print(f"  [INVALID] Block #{i}: stored hash ≠ recalculated hash")
                return False

            # (b) Chain linkage
            if curr.previous_hash != prev.hash:
                print(f"  [INVALID] Block #{i}: previous_hash ≠ Block #{i-1} hash")
                return False

            # (c) Merkle root
            expected_merkle = Block._compute_merkle_root([curr.data_hash])
            if curr.merkle_root != expected_merkle:
                print(f"  [INVALID] Block #{i}: merkle_root mismatch")
                return False

            # (d) chain_id guard
            if curr.chain_id != CHAIN_ID:
                print(f"  [INVALID] Block #{i}: foreign chain_id={curr.chain_id!r}")
                return False

        return True

    # ------------------------------------------------------------------
    # Tamper detection — forensic report
    # ------------------------------------------------------------------
    def detect_tamper(self) -> dict:
        """
        Scan every block and return a detailed forensic discrepancy report.

        Returns:
            dict: {
                "is_clean": bool,
                "discrepancies": [ {block_index, type, detail}, ... ]
            }
        """
        discrepancies = []

        for i in range(1, len(self.chain)):
            curr = self.chain[i]
            prev = self.chain[i - 1]

            if curr.hash != curr.calculate_hash():
                discrepancies.append({
                    "block_index": i,
                    "type":        "HASH_MISMATCH",
                    "detail":      f"Stored={curr.hash[:16]}... Expected={curr.calculate_hash()[:16]}...",
                })

            if curr.previous_hash != prev.hash:
                discrepancies.append({
                    "block_index": i,
                    "type":        "BROKEN_LINK",
                    "detail":      (f"previous_hash={curr.previous_hash[:16]}... "
                                   f"but Block #{i-1}.hash={prev.hash[:16]}..."),
                })

            expected_merkle = Block._compute_merkle_root([curr.data_hash])
            if curr.merkle_root != expected_merkle:
                discrepancies.append({
                    "block_index": i,
                    "type":        "MERKLE_ROOT_MISMATCH",
                    "detail":      f"Stored={curr.merkle_root[:16]}... Expected={expected_merkle[:16]}...",
                })

            if curr.chain_id != CHAIN_ID:
                discrepancies.append({
                    "block_index": i,
                    "type":        "FOREIGN_CHAIN_ID",
                    "detail":      f"chain_id={curr.chain_id!r}",
                })

        if discrepancies:
            self._chain_locked = True
            print(f"  [TAMPER DETECTED] {len(discrepancies)} discrepancy(ies) found — chain LOCKED")

        return {
            "is_clean":      len(discrepancies) == 0,
            "chain_locked":  self._chain_locked,
            "total_blocks":  len(self.chain),
            "scanned_blocks": len(self.chain) - 1,
            "discrepancies": discrepancies,
        }

    # ------------------------------------------------------------------
    # Integrity checkpoints
    # ------------------------------------------------------------------
    def add_integrity_checkpoint(self):
        """
        Compute and persist a checkpoint hash every CHECKPOINT_EVERY_N blocks.
        Hash = SHA-256 of last N block hashes concatenated.
        """
        tail  = self.chain[-CHECKPOINT_EVERY_N:]
        batch = "".join(b.hash for b in tail)
        cp_hash = hashlib.sha256(batch.encode()).hexdigest()
        checkpoint = {
            "block_range": [tail[0].index, tail[-1].index],
            "checkpoint_hash": cp_hash,
            "timestamp":   time.time(),
        }
        checkpoints = []
        if os.path.exists(CHECKPOINT_FILE):
            try:
                with open(CHECKPOINT_FILE, "r") as f:
                    checkpoints = json.load(f)
            except Exception:
                checkpoints = []
        checkpoints.append(checkpoint)
        with open(CHECKPOINT_FILE, "w") as f:
            json.dump(checkpoints, f, indent=2)
        print(f"  [Checkpoint] blocks {checkpoint['block_range'][0]}–{checkpoint['block_range'][1]} sealed")

    # ------------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------------
    def get_latest_block(self) -> Block:
        return self.chain[-1]

    def get_chain_length(self) -> int:
        return len(self.chain)

    def get_block_by_hash(self, data_hash: str) -> Optional[Block]:
        for block in self.chain:
            if block.data_hash == data_hash:
                return block
        return None

    def get_chain_info(self) -> dict:
        tamper_report = self.detect_tamper()
        return {
            "total_blocks":     len(self.chain),
            "is_valid":         tamper_report["is_clean"],
            "chain_locked":     self._chain_locked,
            "difficulty":       self.difficulty,
            "chain_id":         CHAIN_ID,
            "block_version":    "2.0",
            "genesis_hash":     self.chain[0].hash if self.chain else None,
            "latest_hash":      self.get_latest_block().hash if self.chain else None,
            "tamper_report":    tamper_report,
        }

    def unlock_chain_admin(self):
        """Admin-only emergency unlock after forensic review."""
        self._chain_locked = False
        print("[ADMIN] Chain manually unlocked — proceed with caution")

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------
    def save_chain(self):
        try:
            with open(self.chain_file, "w") as f:
                json.dump([b.to_dict() for b in self.chain], f, indent=2)
        except Exception as e:
            print(f"  [ERROR] Saving blockchain failed: {e}")

    def load_chain(self):
        """Load persisted chain; migrates legacy v1 blocks transparently."""
        try:
            with open(self.chain_file, "r") as f:
                chain_data = json.load(f)

            self.chain = [Block.from_dict(d) for d in chain_data]
            print(f"✓ Blockchain loaded — {len(self.chain)} block(s)")
        except Exception as e:
            print(f"  [ERROR] Loading blockchain: {e} — creating fresh genesis")
            self.chain = []
            self.create_genesis_block()

    def __str__(self):
        return (f"Blockchain(blocks={len(self.chain)}, locked={self._chain_locked}, "
                f"valid={self.is_chain_valid()})")