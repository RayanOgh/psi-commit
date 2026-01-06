#!/usr/bin/env python3
"""
Append-only log with hash-chaining.
Provides tamper-evident commitment history.
"""

import json
import hashlib
import time
from pathlib import Path
from typing import Optional, List, Dict


class CommitmentLog:
    """
    Append-only log with hash chaining (like Git or blockchain).
    Each entry includes hash of previous entry, making tampering detectable.
    """
    
    GENESIS_HASH = hashlib.sha256(b"PSI-COMMIT-GENESIS-v1").hexdigest()
    
    def __init__(self, log_file: Optional[Path] = None):
        self.log_file = Path(log_file) if log_file else Path("commitments.log")
        self.entries: List[Dict] = []
        self.chain_hash = self.GENESIS_HASH
        
        if self.log_file.exists():
            self._load()
    
    def append(self, commitment: dict, metadata: Optional[dict] = None) -> str:
        """
        Append a commitment to the log.
        
        Args:
            commitment: The commitment dictionary
            metadata: Optional metadata (message preview, tags, etc.)
        
        Returns:
            Entry hash (can be used as entry ID)
        """
        entry = {
            "index": len(self.entries),
            "prev_hash": self.chain_hash,
            "timestamp": round(time.time(), 6),
            "commitment": commitment,
            "metadata": metadata or {}
        }
        
        # Compute hash of this entry
        entry_canonical = json.dumps(entry, sort_keys=True, separators=(',', ':'))
        self.chain_hash = hashlib.sha256(entry_canonical.encode()).hexdigest()
        entry["hash"] = self.chain_hash
        
        self.entries.append(entry)
        
        # Persist to disk
        self._append_to_file(entry)
        
        return self.chain_hash
    
    def verify_chain(self) -> bool:
        """
        Verify the entire chain is intact.
        
        Returns:
            True if chain is valid, False if tampering detected
        """
        prev_hash = self.GENESIS_HASH
        
        for entry in self.entries:
            # Check prev_hash matches
            if entry["prev_hash"] != prev_hash:
                return False
            
            # Recompute hash
            entry_copy = {k: v for k, v in entry.items() if k != "hash"}
            entry_canonical = json.dumps(entry_copy, sort_keys=True, separators=(',', ':'))
            actual_hash = hashlib.sha256(entry_canonical.encode()).hexdigest()
            
            if actual_hash != entry["hash"]:
                return False
            
            prev_hash = entry["hash"]
        
        return True
    
    def get_entry(self, entry_hash: str) -> Optional[dict]:
        """Get entry by hash."""
        for entry in self.entries:
            if entry["hash"] == entry_hash:
                return entry
        return None
    
    def get_entry_by_index(self, index: int) -> Optional[dict]:
        """Get entry by index."""
        if 0 <= index < len(self.entries):
            return self.entries[index]
        return None
    
    def _load(self):
        """Load log from disk."""
        self.entries = []
        
        with open(self.log_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line:
                    entry = json.loads(line)
                    self.entries.append(entry)
        
        # Update chain hash to latest
        if self.entries:
            self.chain_hash = self.entries[-1]["hash"]
    
    def _append_to_file(self, entry: dict):
        """Append entry to log file (one JSON object per line)."""
        with open(self.log_file, 'a') as f:
            f.write(json.dumps(entry, separators=(',', ':')) + '\n')
    
    def export_transcript(self, output_file: Optional[Path] = None) -> dict:
        """
        Export complete transcript for verification.
        
        Returns:
            Dictionary with all entries and verification status
        """
        transcript = {
            "version": "1.0",
            "genesis_hash": self.GENESIS_HASH,
            "chain_valid": self.verify_chain(),
            "entry_count": len(self.entries),
            "latest_hash": self.chain_hash,
            "entries": self.entries
        }
        
        if output_file:
            Path(output_file).write_text(json.dumps(transcript, indent=2))
        
        return transcript
    
    def __len__(self):
        return len(self.entries)
    
    def __iter__(self):
        return iter(self.entries)