"""
Singleton manager for blockchain and PBFT consensus instances

Ensures that blockchain and PBFT consensus are created once and reused
throughout the application lifecycle, preventing expensive re-initialization
and maintaining state consistency.
"""

import threading
from blockchain import Blockchain, PBFTConsensus
from utils.logger import get_logger
from utils.exceptions import BlockchainIntegrityError

logger = get_logger(__name__)

class SingletonMeta(type):
    """
    Thread-safe singleton metaclass
    """
    _instances = {}
    _lock = threading.Lock()

    def __call__(cls, *args, **kwargs):
        with cls._lock:
            if cls not in cls._instances:
                instance = super().__call__(*args, **kwargs)
                cls._instances[cls] = instance
        return cls._instances[cls]

class BlockchainManager(metaclass=SingletonMeta):
    """
    Singleton manager for blockchain instance
    """
    
    def __init__(self):
        self._blockchain = None
        self._lock = threading.Lock()
        self._initialized = False
    
    def get_blockchain(self):
        """Get the singleton blockchain instance"""
        if not self._initialized:
            with self._lock:
                if not self._initialized:
                    try:
                        self._blockchain = Blockchain()
                        # Validate blockchain on initialization
                        if not self._blockchain.is_chain_valid():
                            logger.error("Blockchain validation failed during initialization")
                            raise BlockchainIntegrityError("Invalid blockchain state detected")
                        
                        logger.info("Blockchain singleton initialized", 
                                  extra={"blocks": len(self._blockchain.chain)})
                        self._initialized = True
                    except Exception as e:
                        logger.error("Failed to initialize blockchain", extra={"error": str(e)})
                        raise BlockchainIntegrityError(f"Blockchain initialization failed: {e}")
        
        return self._blockchain
    
    def validate_chain(self):
        """Validate blockchain integrity"""
        if self._blockchain:
            return self._blockchain.is_chain_valid()
        return False

class PBFTManager(metaclass=SingletonMeta):
    """
    Singleton manager for PBFT consensus instance
    """
    
    def __init__(self):
        self._pbft_consensus = None
        self._lock = threading.Lock()
        self._initialized = False
    
    def get_consensus(self):
        """Get the singleton PBFT consensus instance"""
        if not self._initialized:
            with self._lock:
                if not self._initialized:
                    try:
                        self._pbft_consensus = PBFTConsensus()
                        logger.info("PBFT consensus singleton initialized", 
                                  extra={"nodes": len(self._pbft_consensus.nodes)})
                        self._initialized = True
                    except Exception as e:
                        logger.error("Failed to initialize PBFT consensus", extra={"error": str(e)})
                        raise
        
        return self._pbft_consensus
    
    def get_stats(self):
        """Get consensus statistics"""
        if self._pbft_consensus:
            return self._pbft_consensus.get_consensus_stats()
        return {"total_validations": 0}

# Global singleton instances
_blockchain_manager = BlockchainManager()
_pbft_manager = PBFTManager()

def get_blockchain():
    """Get the global blockchain singleton"""
    return _blockchain_manager.get_blockchain()

def get_pbft_consensus():
    """Get the global PBFT consensus singleton"""
    return _pbft_manager.get_consensus()

def validate_blockchain():
    """Validate blockchain integrity"""
    return _blockchain_manager.validate_chain()

def get_system_stats():
    """Get system statistics"""
    try:
        blockchain = get_blockchain()
        pbft = get_pbft_consensus()
        
        return {
            "blockchain": {
                "total_blocks": len(blockchain.chain),
                "is_valid": blockchain.is_chain_valid(),
                "latest_hash": blockchain.get_latest_block().hash if blockchain.chain else None
            },
            "consensus": _pbft_manager.get_stats()
        }
    except Exception as e:
        logger.error("Failed to get system stats", extra={"error": str(e)})
        raise