#!/usr/bin/env python3
"""
OpenTimestamps integration for independent time attestation.
Anchors commitments to the Bitcoin blockchain.
"""

import hashlib
import json
import subprocess
from pathlib import Path
from typing import Optional, Union


def hash_commitment(commitment: Union[dict, str]) -> bytes:
    """Hash a commitment for timestamping."""
    if isinstance(commitment, dict):
        commitment_str = json.dumps(commitment, sort_keys=True, separators=(',', ':'))
    else:
        commitment_str = commitment
    return hashlib.sha256(commitment_str.encode('utf-8')).digest()


def create_timestamp(commitment: Union[dict, str], output_file: Optional[str] = None) -> str:
    """
    Create an OpenTimestamps proof for a commitment using the CLI.
    
    Args:
        commitment: The commitment dict or JSON string
        output_file: Path to save the .ots file (default: commitment_hash.ots)
    
    Returns:
        Path to the created .ots file
    
    Note:
        Requires `ots` command-line tool from opentimestamps-client.
        The timestamp takes a few hours to be confirmed in Bitcoin.
    """
    # Hash the commitment
    commitment_hash = hash_commitment(commitment)
    hash_hex = commitment_hash.hex()
    
    # Create a temp file with the commitment
    if isinstance(commitment, dict):
        commitment_str = json.dumps(commitment, sort_keys=True, separators=(',', ':'))
    else:
        commitment_str = commitment
    
    # Default output file
    if output_file is None:
        output_file = f"{hash_hex[:16]}.ots"
    
    # Write commitment to temp file
    temp_file = Path(output_file).with_suffix('.json')
    temp_file.write_text(commitment_str)
    
    # Run ots stamp command
    try:
        result = subprocess.run(
            ['ots', 'stamp', str(temp_file)],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode == 0:
            ots_file = str(temp_file) + '.ots'
            print(f"Timestamp created: {ots_file}")
            return ots_file
        else:
            print(f"Error: {result.stderr}")
            return None
            
    except FileNotFoundError:
        print("Error: 'ots' command not found.")
        print("The opentimestamps-client Python library doesn't include the CLI.")
        print("Using fallback: saving commitment hash for manual timestamping.")
        
        # Fallback: just save the hash
        hash_file = Path(output_file).with_suffix('.hash')
        hash_file.write_text(f"SHA256: {hash_hex}\nCommitment: {commitment_str}")
        print(f"Hash saved to: {hash_file}")
        print(f"You can manually timestamp at: https://opentimestamps.org")
        return str(hash_file)
        
    except subprocess.TimeoutExpired:
        print("Error: Timestamp request timed out")
        return None


def verify_timestamp(commitment: Union[dict, str], ots_file: str) -> dict:
    """
    Verify an OpenTimestamps proof using the CLI.
    
    Args:
        commitment: The original commitment
        ots_file: Path to the .ots file
    
    Returns:
        Dictionary with verification result
    """
    # Hash the commitment
    commitment_hash = hash_commitment(commitment)
    
    try:
        result = subprocess.run(
            ['ots', 'verify', ots_file],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if 'Bitcoin block' in result.stdout or 'Bitcoin block' in result.stderr:
            return {
                "valid": True,
                "status": "confirmed",
                "output": result.stdout + result.stderr
            }
        elif 'Pending' in result.stdout or 'pending' in result.stderr:
            return {
                "valid": True,
                "status": "pending",
                "message": "Timestamp not yet confirmed in Bitcoin"
            }
        else:
            return {
                "valid": False,
                "error": result.stderr or result.stdout
            }
            
    except FileNotFoundError:
        return {
            "valid": False,
            "error": "'ots' command not found. Install opentimestamps-client."
        }
    except subprocess.TimeoutExpired:
        return {
            "valid": False,
            "error": "Verification timed out"
        }


def info_timestamp(ots_file: str) -> dict:
    """
    Get information about a timestamp file.
    
    Args:
        ots_file: Path to the .ots file
    
    Returns:
        Dictionary with timestamp info
    """
    try:
        result = subprocess.run(
            ['ots', 'info', ots_file],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        return {
            "file": ots_file,
            "info": result.stdout,
            "error": result.stderr if result.returncode != 0 else None
        }
        
    except FileNotFoundError:
        return {
            "error": "'ots' command not found. Install opentimestamps-client."
        }