#!/usr/bin/env python3
"""
PSI-COMMIT CLI
Command-line interface for creating and verifying commitments.
"""

import click
import json
import sys
from pathlib import Path
from psi_commit.core import seal, verify, __version__


@click.group()
@click.version_option(version=__version__)
def cli():
    """PSI-COMMIT: Cryptographic commitment scheme for verifiable decisions."""
    pass


@cli.command()
@click.argument('message')
@click.option('--context', '-c', default='default', help='Domain context for commitment')
@click.option('--output', '-o', type=click.Path(), help='Save to file instead of stdout')
def commit(message, context, output):
    """Create a cryptographic commitment to MESSAGE."""
    
    # Create commitment
    commitment, key = seal(message, context=context)
    
    # Prepare output
    result = {
        "commitment": commitment,
        "key_hex": key.hex(),
        "message_preview": message[:50] + "..." if len(message) > 50 else message
    }
    
    output_json = json.dumps(result, indent=2)
    
    if output:
        Path(output).write_text(output_json)
        click.echo(f"Commitment saved to {output}")
        click.echo(f"Key (hex): {key.hex()}")
    else:
        click.echo(output_json)
    
    click.echo("\nIMPORTANT: Save your key! Without it, you cannot prove your commitment.", err=True)


@cli.command()
@click.argument('message')
@click.argument('key_hex')
@click.argument('commitment-file', type=click.Path(exists=True))
def verify_commit(message, key_hex, commitment_file):
    """Verify MESSAGE matches COMMITMENT using KEY."""
    
    # Load commitment
    try:
        data = json.loads(Path(commitment_file).read_text())
        if "commitment" in data:
            commitment = data["commitment"]
        else:
            commitment = data
    except json.JSONDecodeError:
        click.echo("Error: Invalid JSON in commitment file", err=True)
        sys.exit(1)
    
    # Decode key
    try:
        key = bytes.fromhex(key_hex)
    except ValueError:
        click.echo("Error: Invalid hex key", err=True)
        sys.exit(1)
    
    # Verify
    try:
        is_valid = verify(message, key, commitment)
        
        if is_valid:
            click.echo("VERIFIED: Commitment matches message and key")
            sys.exit(0)
        else:
            click.echo("FAILED: Commitment does not match", err=True)
            sys.exit(1)
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
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
    
    click.echo(f"Generated new key: {output}")
    click.echo(f"Key (hex): {key.hex()}")
    click.echo("\nKeep this key secure! Anyone with it can forge commitments.")


if __name__ == '__main__':
    cli()