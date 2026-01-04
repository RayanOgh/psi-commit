#!/usr/bin/env python3
"""
PSI-COMMIT CLI
Command-line interface for creating and verifying commitments.
"""

import click
import json
import sys
from pathlib import Path
from psi_commit.core import seal, verify, serialize_commitment, __version__

@click.group()
@click.version_option(version=__version__)
def cli():
    """PSI-COMMIT: Cryptographic commitment scheme for verifiable decisions."""
    pass

@cli.command()
@click.argument('message')
@click.option('--context', default='default', help='Domain context for commitment')
@click.option('--output', '-o', type=click.Path(), help='Save to file instead of stdout')
@click.option('--key-file', type=click.Path(), help='Use existing key from file')
def commit(message, context, output, key_file):
    """Create a cryptographic commitment to MESSAGE."""
    
    # Load or generate key
    if key_file:
        key = Path(key_file).read_bytes()
        if len(key) != 32:
            click.echo(f"Error: Key file must contain exactly 32 bytes, got {len(key)}", err=True)
            sys.exit(1)
    else:
        key = None  # Will be generated
    
    # Create commitment
    commitment, key_used = seal(message, key=key, context=context)
    
    # Prepare output
    result = {
        "commitment": commitment,
        "key": key_used.hex(),
        "message_preview": message[:50] + "..." if len(message) > 50 else message
    }
    
    output_json = json.dumps(result, indent=2)
    
    if output:
        Path(output).write_text(output_json)
        click.echo(f"✓ Commitment saved to {output}")
        click.echo(f"✓ Keep your key safe: {key_used.hex()[:16]}...")
    else:
        click.echo(output_json)
    
    # Security warning
    if not key_file:
        click.echo("\n⚠️  IMPORTANT: Save your key! Without it, you cannot prove your commitment.", err=True)

@cli.command()
@click.argument('message')
@click.argument('key')
@click.argument('commitment-file', type=click.Path(exists=True))
def verify_cmd(message, key, commitment_file):
    """Verify MESSAGE matches COMMITMENT using KEY."""
    
    # Load commitment
    try:
        commitment_data = json.loads(Path(commitment_file).read_text())
        if "commitment" in commitment_data:
            commitment = commitment_data["commitment"]
        else:
            commitment = commitment_data
    except json.JSONDecodeError:
        click.echo("Error: Invalid JSON in commitment file", err=True)
        sys.exit(1)
    
    # Parse key
    try:
        key_bytes = bytes.fromhex(key)
    except ValueError:
        click.echo("Error: Key must be hex-encoded", err=True)
        sys.exit(1)
    
    # Verify
    try:
        is_valid = verify(message, key_bytes, commitment)
        
        if is_valid:
            click.echo("✓ VERIFIED: Commitment matches message and key")
            click.echo(f"  Domain: {commitment['domain']}")
            click.echo(f"  Message: {message[:100]}...")
            sys.exit(0)
        else:
            click.echo("✗ VERIFICATION FAILED: Commitment does not match", err=True)
            sys.exit(1)
    except Exception as e:
        click.echo(f"Error during verification: {e}", err=True)
        sys.exit(1)

@cli.command()
@click.argument('commitment-file', type=click.Path(exists=True))
def info(commitment_file):
    """Display information about a commitment."""
    
    try:
        data = json.loads(Path(commitment_file).read_text())
        if "commitment" in data:
            commitment = data["commitment"]
        else:
            commitment = data
        
        click.echo("Commitment Information:")
        click.echo(f"  Version: {commitment['v']}")
        click.echo(f"  Algorithm: {commitment['alg']}")
        click.echo(f"  Domain: {commitment['domain']}")
        click.echo(f"  Nonce: {commitment['nonce'][:16]}...{commitment['nonce'][-16:]}")
        click.echo(f"  MAC: {commitment['mac'][:16]}...{commitment['mac'][-16:]}")
        
        if "message_preview" in data:
            click.echo(f"  Message Preview: {data['message_preview']}")
        
    except Exception as e:
        click.echo(f"Error reading commitment: {e}", err=True)
        sys.exit(1)

@cli.command()
@click.option('--output', '-o', type=click.Path(), default='key.bin', help='Output file for key')
def genkey(output):
    """Generate a new 32-byte secret key."""
    import secrets
    
    key = secrets.token_bytes(32)
    Path(output).write_bytes(key)
    
    click.echo(f"✓ Generated new key: {output}")
    click.echo(f"  Key (hex): {key.hex()}")
    click.echo("\n⚠️  Keep this key secure! Anyone with it can forge commitments.")

if __name__ == '__main__':
    cli()
```

---

**Save it (Ctrl+S)** and tell me when it's done!

This is the command-line interface that lets you run commands like:
```
psi-commit commit "my message"
psi-commit verify "my message" <key> <commitment-file>