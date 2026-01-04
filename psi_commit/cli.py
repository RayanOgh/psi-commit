#!/usr/bin/env python3
"""
PSI-COMMIT CLI
Command-line interface for creating and verifying commitments.
"""

import click
import json
import sys
from pathlib import Path
from psi_commit.core import seal, verify, canon, _b64e, log, __version__

@click.group()
@click.version_option(version=__version__)
def cli():
    """PSI-COMMIT: Cryptographic commitment scheme for verifiable decisions."""
    pass

@cli.command()
@click.argument('message')
@click.option('--context', '-c', default='psi-commit:v4', help='Context for domain separation')
@click.option('--output', '-o', type=click.Path(), help='Save to file instead of stdout')
@click.option('--no-canon', is_flag=True, help='Do not canonicalize the message')
def commit(message, context, output, no_canon):
    """Create a cryptographic commitment to MESSAGE."""
    
    # Canonicalize unless --no-canon is specified
    if not no_canon:
        message = canon(message)
    
    # Create commitment
    commitment, key = seal(message, ctx=context.encode('utf-8'))
    
    # Prepare output
    result = {
        "commitment": commitment,
        "key_b64": _b64e(key),
        "message_preview": message[:50] + "..." if len(message) > 50 else message,
        "canonicalized": not no_canon
    }
    
    output_json = json.dumps(result, indent=2)
    
    if output:
        Path(output).write_text(output_json)
        click.echo(f"Commitment saved to {output}")
        click.echo(f"Key (base64): {_b64e(key)}")
    else:
        click.echo(output_json)
    
    click.echo("\nIMPORTANT: Save your key! Without it, you cannot prove your commitment.", err=True)

@cli.command()
@click.argument('message')
@click.argument('key_b64')
@click.argument('commitment-file', type=click.Path(exists=True))
@click.option('--no-canon', is_flag=True, help='Do not canonicalize the message')
def verify(message, key_b64, commitment_file, no_canon):
    """Verify MESSAGE matches COMMITMENT using KEY."""
    from psi_commit.core import verify as verify_commitment, _b64d
    
    # Canonicalize unless --no-canon is specified
    if not no_canon:
        message = canon(message)
    
    # Load commitment
    try:
        data = json.loads(Path(commitment_file).read_text())
        if "commitment" in data:
            commitment = data["commitment"]
        else:
            commitment = Path(commitment_file).read_text()
    except json.JSONDecodeError:
        commitment = Path(commitment_file).read_text()
    
    # Decode key
    try:
        key = _b64d(key_b64)
    except Exception:
        click.echo("Error: Invalid base64 key", err=True)
        sys.exit(1)
    
    # Verify
    is_valid = verify_commitment(message, key, commitment)
    
    if is_valid:
        click.echo("VERIFIED: Commitment matches message and key")
    else:
        click.echo("FAILED: Commitment does not match", err=True)
        sys.exit(1)

@cli.command()
@click.argument('commitment-file', type=click.Path(exists=True))
def info(commitment_file):
    """Display information about a commitment."""
    from psi_commit.core import _b64d
    
    data = json.loads(Path(commitment_file).read_text())
    if "commitment" in data:
        commitment = json.loads(data["commitment"])
    else:
        commitment = json.loads(Path(commitment_file).read_text())
    
    click.echo("Commitment Information:")
    click.echo(f"  Version: {commitment['v']}")
    click.echo(f"  Algorithm: {commitment['algo']}")
    click.echo(f"  Context: {_b64d(commitment['ctx']).decode('utf-8')}")
    click.echo(f"  Salt: {commitment['salt'][:16]}...")
    click.echo(f"  MAC: {commitment['mac'][:16]}...")

if __name__ == '__main__':
    cli()