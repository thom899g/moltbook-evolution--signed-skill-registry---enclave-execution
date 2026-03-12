"""
Moltbook Evolution - Configuration Management
Implements secure configuration with environment variable validation
"""
import os
import logging
from typing import Optional
from pydantic import BaseSettings, Field, validator
from cryptography.fernet import Fernet
import json

class Settings(BaseSettings):
    """Centralized configuration management with validation"""
    
    # Firebase Configuration
    firebase_project_id: str = Field(..., env="FIREBASE_PROJECT_ID")
    firebase_credentials_path: str = Field("credentials/firebase-key.json", env="FIREBASE_CREDENTIALS_PATH")
    
    # Security Configuration
    signature_algorithm: str = Field("Ed25519", env="SIGNATURE_ALGORITHM")
    merkle_tree_depth: int = Field(32, env="MERKLE_TREE_DEPTH")
    
    # Execution Environment
    default_isolation_backend: str = Field("WASM", env="DEFAULT_ISOLATION_BACKEND")
    max_execution_time_ms: int = Field(5000, env="MAX_EXECUTION_TIME_MS")
    memory_limit_mb: int = Field(256, env="MEMORY_LIMIT_MB")
    
    # Registry Settings
    registry_firestore_collection: str = Field("skill_registry", env="REGISTRY_COLLECTION")
    reputation_firestore_collection: str = Field("skill_reputation", env="REPUTATION_COLLECTION")
    
    # Consensus Settings
    consensus_enabled: bool = Field(True, env="CONSENSUS_ENABLED")
    raft_cluster_size: int = Field(3, env="RAFT_CLUSTER_SIZE")
    
    # Monitoring
    telemetry_enabled: bool = Field(True, env="TELEMETRY_ENABLED")
    anomaly_detection_threshold: float = Field(0.85, env="ANOMALY_THRESHOLD")
    
    # Emergency Contacts
    telegram_bot_token: Optional[str] = Field(None, env="TELEGRAM_BOT_TOKEN")
    telegram_chat_id: Optional[str] = Field(None, env="TELEGRAM_CHAT_ID")
    emergency_email: Optional[str] = Field(None, env="EMERGENCY_EMAIL")
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
    
    @validator("default_isolation_backend")
    def validate_isolation_backend(cls, v):
        valid_backends = {"WASM", "PROCESS", "SGX", "NITRO", "TRUSTZONE"}
        if v.upper() not in valid_backends:
            raise ValueError(f"Invalid isolation backend. Must be one of: {valid_backends}")
        return v.upper()
    
    @validator("anomaly_detection_threshold")
    def validate_threshold(cls, v):
        if not 0.5 <= v <= 1.0:
            raise ValueError("Anomaly threshold must be between 0.5 and 1.0")
        return v

class SecretManager:
    """Manages encryption keys and sensitive data"""
    
    def __init__(self, key_path: str = "secrets/encryption.key"):
        self.key_path = key_path
        self.fernet = self._load_or_create_key()
    
    def _load_or_create_key(self) -> Fernet:
        """Load existing key or create new one"""
        try:
            if os.path.exists(self.key_path):
                with open(self.key_path, "rb") as f:
                    key = f.read()
                return Fernet(key)
            else:
                # Create directory if it doesn't exist
                os.makedirs(os.path.dirname(self.key_path), exist_ok=True)
                key = Fernet.generate_key()
                with open(self.key_path, "wb") as f:
                    f.write(key)
                return Fernet(key)
        except Exception as e:
            logging.error(f"Failed to load/create encryption key: {e}")
            raise
    
    def encrypt(self, data: str) -> bytes:
        """Encrypt sensitive data"""
        return self.fernet.encrypt(data.encode())
    
    def decrypt(self, encrypted_data: bytes) -> str:
        """Decrypt sensitive data"""
        return self.fernet.decrypt(encrypted_data).decode()

# Global instances
settings = Settings()
secrets = SecretManager()

def validate_configuration() -> bool:
    """Validate all configuration and dependencies"""
    try:
        # Check Firebase credentials
        if not os.path.exists(settings.firebase_credentials_path):
            logging.error(f"Firebase credentials not found at {settings.firebase_credentials_path}")
            return False
        
        # Check required environment variables
        required_vars = ["FIREBASE_PROJECT_ID"]
        for var in required_vars:
            if not os.getenv(var):
                logging.error(f"Required environment variable {var} is not set")
                return False
        
        # Validate file permissions
        if os.path.exists(settings.firebase_credentials_path):
            import stat
            st = os.stat(settings.firebase_credentials_path)
            if st.st_mode & stat.S_IRWXO:  # Check if others can read/write/execute
                logging.warning("Firebase credentials have overly permissive permissions")
        
        logging.info("Configuration validation passed")
        return True
        
    except Exception as e:
        logging.error(f"Configuration validation failed: {e}")
        return False