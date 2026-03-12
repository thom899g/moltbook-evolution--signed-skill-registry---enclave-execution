"""
Dual-Ledger Registry System
Implements immutable registry ledger + dynamic reputation layer using Firestore
"""
import hashlib
import json
import time
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
import logging

import firebase_admin
from firebase_admin import firestore, credentials
from google.cloud.firestore import Client, DocumentSnapshot
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from config.settings import settings

logger = logging.getLogger(__name__)

@dataclass
class RegistryEntry:
    """Immutable registry entry structure"""
    skill_id: str
    developer_pubkey: str  # PEM encoded
    code_hash: str  # SHA256
    metadata_hash: str  # SHA256 of skill metadata
    timestamp: str  # RFC3339
    merkle_proof: Optional[str] = None  # Path to Merkle root
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to Firestore-compatible dict"""
        return {
            "skill_id": self.skill_id,
            "developer_pubkey": self.developer_pubkey,
            "code_hash": self.code_hash,
            "metadata_hash": self.metadata_hash,
            "timestamp": self.timestamp,
            "merkle_proof": self.merkle_proof,
            "_immutable": True  # Flag for validation
        }

@dataclass
class ReputationData:
    """Dynamic reputation data structure"""
    skill_id: str
    score: float  # 0.0 to 1.0
    total_executions: int = 0
    successful_executions: int = 0
    violations: List[str] = None
    last_updated: str = None
    reporting_agents: List[str] = None
    
    def __post_init__(self):
        if self.violations is None:
            self.violations = []
        if self.reporting_agents is None:
            self.reporting_agents = []
        if self.last_updated is None:
            self.last_updated = datetime.utcnow().isoformat()
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

class MerkleTree:
    """Merkle tree implementation for transparency log"""
    
    def __init__(self, depth: int = 32):
        self.depth = depth
        self.leaves: List[bytes] = []
        self.root: Optional[bytes] = None
        
    def add_leaf(self, data: bytes) -> str:
        """Add a leaf and return its proof"""
        leaf_hash = hashlib.sha256(data).digest()
        self.leaves.append(leaf_hash)
        
        # Recalculate tree
        self._recalculate_tree()
        
        # Generate proof for this leaf
        proof = self._generate_proof(len(self.leaves) - 1)
        return proof.hex()
    
    def _recalculate_tree(self):
        """Recalculate the Merkle tree"""
        current_level = self.leaves.copy()
        
        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                if i + 1 < len(current_level):
                    combined = current_level[i] + current_level[i + 1]
                else:
                    combined = current_level[i] + current_level[i]
                next_level.append(hashlib.sha256(combined).digest())
            current_level = next_level
        
        self.root = current_level[0] if current_level else None
    
    def _generate_proof(self, leaf_index: int) -> bytes:
        """Generate Merkle proof for a leaf"""
        if leaf_index >= len(self.leaves):
            raise ValueError("Leaf index out of bounds")
        
        proof = b""
        current_index = leaf_index
        current_level = self.leaves.copy()
        
        while len(current_level) > 1:
            # Determine sibling position
            if current_index % 2 == 0:
                sibling_index = current_index + 1 if current_index + 1 < len(current_level) else current_index
            else:
                sibling_index = current_index - 1
            
            proof += current_level[sibling_index]
            
            # Move to parent level
            next_level = []
            for i in range(0, len(current_level), 2):
                if i + 1 < len(current_level):
                    combined = current_level[i] + current_level[i + 1]
                else:
                    combined = current_level[i] + current_level[i]
                next_level.append(hashlib.sha256(combined).digest())
            
            current_level = next_level
            current_index //= 2
        
        return proof
    
    def verify_proof(self, leaf: bytes, proof: bytes, root: bytes) -> bool:
        """Verify a Merkle proof"""
        current_hash = hashlib.sha256(leaf).digest()
        
        # Reconstruct using proof
        proof_chunks = [proof[i:i+32] for i in range(0, len(proof), 32)]
        
        for sibling in proof_chunks:
            # Determine order (we need to know if sibling is left or right)
            # For simplicity, we'll compare hashes to decide
            if current_hash < sibling:
                combined = current_hash + sibling
            else:
                combined = sibling + current_hash
            
            current_hash = hashlib.sha256(combined).digest()
        
        return current_hash == root

class DualLedgerRegistry:
    """Main registry class implementing dual-ledger architecture"""
    
    def __init__(self):
        self.firebase_app = None
        self.db: Optional[Client] = None
        self.merkle_tree = MerkleTree(depth=settings.merkle_tree_depth)
        self._init_firebase()
        
    def _init_firebase(self):
        """Initialize Firebase connection"""
        try:
            if not firebase_admin._apps:
                cred = credentials.Certificate(settings.firebase_credentials_path)
                self.firebase_app = firebase_admin.initialize_app(cred, {
                    'projectId': settings.firebase_project_id,
                })
            else:
                self.firebase_app = firebase_admin.get_app()
            
            self.db = firestore.client()
            logger.info("Firebase Firestore initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize Firebase: {e}")
            raise
    
    def register_skill(self, skill_id: str, developer_pubkey: str, 
                      code_hash: str, metadata: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Register a new skill in the immutable ledger
        
        Returns: (success, error_message_or_merkle_proof)
        """
        try:
            # Validate inputs
            if not self._validate_pubkey(developer_pubkey):
                return False, "Invalid public key format"
            
            if len(code_hash) != 64:  # SHA256 hex length
                return False, "Invalid code hash length"
            
            # Check for duplicate skill_id
            doc_ref = self.db.collection(settings.registry_firestore_collection).document(skill_id)
            if doc_ref.get().exists:
                return False, "Skill ID already exists"
            
            # Create metadata hash
            metadata_bytes = json.dumps(metadata, sort_keys=True).encode()
            metadata_hash = hashlib.sha256(metadata_bytes).hexdigest()
            
            # Create registry entry
            entry = RegistryEntry(
                skill_id=skill_id,
                developer_pubkey=developer_pubkey,
                code_hash=code_hash,
                metadata_hash=metadata_hash,
                timestamp=datetime.utcnow().isoformat()
            )
            
            # Add to Merkle tree
            entry_bytes = json.dumps(entry.to_dict(), sort_keys=True).encode()
            merkle_proof = self.merkle_tree.add_leaf(entry_bytes)
            entry.merkle_proof = merkle_proof
            
            # Store in Firestore (immutable ledger)
            doc_ref.set(entry.to_dict())
            
            # Initialize reputation entry
            rep_data = ReputationData(
                skill_id=skill_id,
                score=1.0,  # Start with perfect score
                total_executions=0,
                successful_executions=0
            )
            
            rep_ref = self.db.collection(settings.reputation_firestore_collection).document