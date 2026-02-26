"""
Enhanced Block class for the secure student record blockchain.

New in v2:
  - chain_id embedded in hash computation (prevents cross-chain injection)
  - block_version header for structural integrity
  - merkle_root field (SHA-256 of the data_hash list)
  - compute_block_signature() — HMAC-SHA256 integrity seal
"""

import hashlib
import hmac
import json
import time
from datetime import datetime

BLOCK_VERSION = "2.0"
CHAIN_ID      = "SSRBC-MAIN-v2"       # Unique chain identifier


class Block:
    """
    A single immutable block in the blockchain.

    Hash formula includes chain_id and block_version so that
    blocks from a different chain cannot be injected.
    """

    def __init__(self, index: int, data_hash: str, previous_hash: str,
                 nonce: int = 0, merkle_root: str = None):
        self.index         = index
        self.timestamp     = time.time()
        self.data_hash     = data_hash
        self.previous_hash = previous_hash
        self.nonce         = nonce
        self.block_version = BLOCK_VERSION
        self.chain_id      = CHAIN_ID
        self.merkle_root   = merkle_root or self._compute_merkle_root([data_hash])
        self.hash          = self.calculate_hash()

    # ------------------------------------------------------------------
    # Core hashing
    # ------------------------------------------------------------------
    def calculate_hash(self) -> str:
        """
        Compute SHA-256 of all block fields including chain_id and version.
        Any change to any field produces a completely different hash.
        """
        block_string = (
            f"{self.chain_id}"
            f"|{self.block_version}"
            f"|{self.index}"
            f"|{self.timestamp}"
            f"|{self.data_hash}"
            f"|{self.previous_hash}"
            f"|{self.nonce}"
            f"|{self.merkle_root}"
        )
        return hashlib.sha256(block_string.encode("utf-8")).hexdigest()

    def compute_block_signature(self, secret: str = "SSRBC_INTEGRITY_KEY") -> str:
        """
        Return HMAC-SHA256 of the block's serialised header fields.
        Used during integrity checkpoints to verify block authenticity.
        """
        header = json.dumps({
            "chain_id":      self.chain_id,
            "block_version": self.block_version,
            "index":         self.index,
            "timestamp":     self.timestamp,
            "data_hash":     self.data_hash,
            "previous_hash": self.previous_hash,
            "nonce":         self.nonce,
            "merkle_root":   self.merkle_root,
        }, sort_keys=True)
        return hmac.new(
            secret.encode("utf-8"),
            header.encode("utf-8"),
            hashlib.sha256
        ).hexdigest()

    # ------------------------------------------------------------------
    # Proof-of-work mining
    # ------------------------------------------------------------------
    def mine_block(self, difficulty: int = 4):
        target = "0" * difficulty
        iteration = 0
        while not self.hash.startswith(target):
            self.nonce += 1
            self.hash   = self.calculate_hash()
            iteration  += 1
        print(f"  [Block #{self.index}] Mined in {iteration} iterations — {self.hash[:24]}...")

    # ------------------------------------------------------------------
    # Merkle root (single-leaf case; extendable to multi-tx)
    # ------------------------------------------------------------------
    @staticmethod
    def _compute_merkle_root(data_hashes: list) -> str:
        if not data_hashes:
            return hashlib.sha256(b"").hexdigest()
        current = data_hashes[:]
        while len(current) > 1:
            if len(current) % 2 != 0:
                current.append(current[-1])   # duplicate last for odd count
            current = [
                hashlib.sha256((current[i] + current[i + 1]).encode()).hexdigest()
                for i in range(0, len(current), 2)
            ]
        return current[0]

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------
    def to_dict(self) -> dict:
        return {
            "index":         self.index,
            "timestamp":     self.timestamp,
            "data_hash":     self.data_hash,
            "previous_hash": self.previous_hash,
            "nonce":         self.nonce,
            "block_version": self.block_version,
            "chain_id":      self.chain_id,
            "merkle_root":   self.merkle_root,
            "hash":          self.hash,
            "human_timestamp": datetime.fromtimestamp(self.timestamp).strftime("%Y-%m-%d %H:%M:%S"),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Block":
        b = cls.__new__(cls)
        b.index         = d["index"]
        b.timestamp     = d["timestamp"]
        b.data_hash     = d["data_hash"]
        b.previous_hash = d["previous_hash"]
        b.nonce         = d["nonce"]
        b.block_version = d.get("block_version", BLOCK_VERSION)
        b.chain_id      = d.get("chain_id", CHAIN_ID)
        b.merkle_root   = d.get("merkle_root") or Block._compute_merkle_root([d["data_hash"]])
        b.hash          = d["hash"]
        return b

    def __str__(self):
        return f"Block(#{self.index}, chain={self.chain_id}, hash={self.hash[:16]}...)"